//! Refused WIM files (plan §10 "WIM parser" row; WU-5): each REQ-IMG-037
//! bullet and each REQ-IMG-038 variant, made by corrupting `WimBuilder`
//! output, plus random damage that must never panic.
//!
//! Every refusal must carry a known reason code and operator text
//! (REQ-IMG-022).

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-10, SI-11
// - SPEC: specs/os-images.md#REQ-IMG-022, #REQ-IMG-037, #REQ-IMG-038
// - SPEC: specs/standards/wim.md §2 to §8, §12
#![cfg(feature = "testkit")]

#[cfg(test)]
mod negative {
    use std::io::Cursor;

    use usgp_image::testkit::{BuildInfo, WimBuilder};
    use usgp_image::wim::xml::encode_utf16;
    use usgp_image::{Compression, NoProgress, WimError, WimLimits, WimSummary, check_wim};

    fn run_with(b: &[u8], limits: &WimLimits) -> Result<WimSummary, WimError> {
        let r = check_wim(
            &mut Cursor::new(b),
            u64::try_from(b.len()).unwrap(),
            limits,
            usgp_crypto::provider(),
            &mut NoProgress,
        );
        if let Err(e) = &r {
            // REQ-IMG-022: every refusal is named.
            assert!(WimError::REASON_CODES.contains(&e.reason_code()), "{e:?}");
            assert!(!e.operator_message().is_empty());
        }
        r
    }

    fn run(b: &[u8]) -> Result<WimSummary, WimError> {
        run_with(b, &WimLimits::DEFAULT)
    }

    fn built(b: WimBuilder) -> (Vec<u8>, BuildInfo) {
        b.build().unwrap()
    }

    fn one(c: Compression) -> (Vec<u8>, BuildInfo) {
        built(WimBuilder::new(c).image("a", "b"))
    }

    fn put(b: &mut [u8], at: u64, bytes: &[u8]) {
        let at = usize::try_from(at).unwrap();
        b[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn lookup_entry_at(info: &BuildInfo, k: u64) -> u64 {
        info.lookup.offset + 50 * k
    }

    fn reason(r: Result<WimSummary, WimError>) -> &'static str {
        r.unwrap_err().reason_code()
    }

    #[test]
    fn truncated_at_every_header_byte() {
        let (b, _) = one(Compression::Xpress);
        for n in 0..208 {
            assert_eq!(run(&b[..n]).unwrap_err(), WimError::TooShort, "len {n}");
        }
    }

    #[test]
    fn truncated_anywhere_is_refused() {
        let (b, _) = built(
            WimBuilder::new(Compression::Xpress)
                .image("a", "b")
                .integrity(true),
        );
        for n in (208..b.len()).step_by(37) {
            assert!(run(&b[..n]).is_err(), "len {n}");
        }
    }

    #[test]
    fn wrong_magic() {
        let (mut b, _) = one(Compression::None);
        b[4] = b'X';
        assert_eq!(run(&b).unwrap_err(), WimError::NotWim);
        assert_eq!(run(b"not a wim file at all").unwrap_err(), WimError::NotWim);
    }

    #[test]
    fn header_size_out_of_range() {
        for size in [0u32, 207, 209, 4096, u32::MAX] {
            let (mut b, _) = one(Compression::None);
            put(&mut b, 8, &size.to_le_bytes());
            assert_eq!(run(&b).unwrap_err(), WimError::HeaderSize { cb_size: size });
        }
    }

    #[test]
    fn header_resources_out_of_bounds() {
        let (b, info) = one(Compression::None);
        let len = b.len() as u64;
        // (header offset of the resource header, new offset, new size)
        let cases = [
            (48u64, len - 100, 900u64), // lookup past the end
            (48, 100, 50),              // lookup inside the header
            (72, len - 1, 2),           // XML past the end
            (124, len, 32),             // integrity past the end
            (96, len, 8),               // boot metadata past the end
            (48, u64::MAX - 10, 50),    // offset + size overflows
        ];
        for (at, offset, size) in cases {
            let mut c = b.clone();
            let flags = if at == 124 || at == 96 { 0 } else { 2 };
            let mut rh = [0u8; 24];
            rh[..7].copy_from_slice(&size.to_le_bytes()[..7]);
            rh[7] = flags;
            rh[8..16].copy_from_slice(&offset.to_le_bytes());
            rh[16..24].copy_from_slice(&size.to_le_bytes());
            put(&mut c, at, &rh);
            assert_eq!(reason(run(&c)), "wim_out_of_bounds", "{at} {offset} {size}");
        }
        let _ = info;
    }

    #[test]
    fn lookup_size_not_multiple_of_entry_size() {
        let (mut b, _) = one(Compression::None);
        let mut size = [0u8; 8];
        size.copy_from_slice(&b[48..56]);
        let s = u64::from_le_bytes(size) & 0x00ff_ffff_ffff_ffff;
        put(&mut b, 48, &(s - 1).to_le_bytes()[..7]);
        put(&mut b, 64, &(s - 1).to_le_bytes());
        assert_eq!(
            run(&b).unwrap_err(),
            WimError::Malformed {
                what: "lookup table size"
            }
        );
    }

    #[test]
    fn compressed_lookup_or_xml_refused() {
        for at in [55u64, 79] {
            let (mut b, _) = one(Compression::Xpress);
            put(&mut b, at, &[0x06]);
            assert_eq!(reason(run(&b)), "wim_malformed");
        }
    }

    #[test]
    fn resource_entry_out_of_bounds_and_overflow() {
        let (b, info) = one(Compression::None);
        let e = lookup_entry_at(&info, 1); // first file entry
        for offset in [b.len() as u64, 0, 100, u64::MAX] {
            let mut c = b.clone();
            put(&mut c, e + 8, &offset.to_le_bytes());
            assert_eq!(reason(run(&c)), "wim_out_of_bounds", "{offset}");
        }
    }

    #[test]
    fn count_mismatch_header_xml_metadata() {
        // Header says 2, file has 1.
        let (b, _) = built(
            WimBuilder::new(Compression::None)
                .image("a", "b")
                .image_count(2),
        );
        assert_eq!(
            run(&b).unwrap_err(),
            WimError::ImageCountMismatch {
                header: 2,
                xml: 1,
                metadata: 1
            }
        );
        // XML lists two images, the file has one.
        let (b, _) = built(WimBuilder::new(Compression::None).image("a", "b").xml_text(
            "<WIM><IMAGE INDEX=\"1\"><NAME>a</NAME></IMAGE><IMAGE INDEX=\"2\"><NAME>b</NAME></IMAGE></WIM>",
        ));
        assert_eq!(
            run(&b).unwrap_err(),
            WimError::ImageCountMismatch {
                header: 1,
                xml: 2,
                metadata: 1
            }
        );
        // A metadata entry loses its flag.
        let (mut b, info) = built(
            WimBuilder::new(Compression::None)
                .image("a", "b")
                .image("c", "d"),
        );
        put(&mut b, lookup_entry_at(&info, 1) + 7, &[0x00]);
        assert_eq!(
            run(&b).unwrap_err(),
            WimError::ImageCountMismatch {
                header: 2,
                xml: 2,
                metadata: 1
            }
        );
    }

    #[test]
    fn duplicate_zero_or_out_of_range_index() {
        let two = |xml: &str| {
            built(
                WimBuilder::new(Compression::None)
                    .image("a", "b")
                    .image("c", "d")
                    .xml_text(xml),
            )
            .0
        };
        assert_eq!(
            run(&two("<WIM><IMAGE INDEX=\"1\"><NAME>a</NAME></IMAGE><IMAGE INDEX=\"1\"><NAME>b</NAME></IMAGE></WIM>")).unwrap_err(),
            WimError::DuplicateIndex { index: 1 }
        );
        assert_eq!(
            run(&two("<WIM><IMAGE INDEX=\"0\"><NAME>a</NAME></IMAGE><IMAGE INDEX=\"1\"><NAME>b</NAME></IMAGE></WIM>")).unwrap_err(),
            WimError::XmlInvalid { reason: "INDEX out of range" }
        );
        assert_eq!(
            run(&two("<WIM><IMAGE INDEX=\"1\"><NAME>a</NAME></IMAGE><IMAGE INDEX=\"3\"><NAME>b</NAME></IMAGE></WIM>")).unwrap_err(),
            WimError::XmlInvalid { reason: "INDEX out of range" }
        );
    }

    #[test]
    fn xml_refusals() {
        let with = |x: Vec<u8>| {
            built(
                WimBuilder::new(Compression::None)
                    .image("a", "b")
                    .xml_bytes(x),
            )
            .0
        };
        let doc = |s: &str| with(encode_utf16(s));
        assert_eq!(
            run(&doc("<!DOCTYPE WIM [<!ENTITY x \"y\">]><WIM><IMAGE INDEX=\"1\"><NAME>&x;</NAME></IMAGE></WIM>")).unwrap_err(),
            WimError::XmlInvalid { reason: "DOCTYPE not allowed" }
        );
        let deep = format!(
            "<WIM><IMAGE INDEX=\"1\"><NAME>a</NAME>{}{}</IMAGE></WIM>",
            "<D>".repeat(64),
            "</D>".repeat(64)
        );
        assert_eq!(
            run(&doc(&deep)).unwrap_err(),
            WimError::XmlInvalid {
                reason: "nesting too deep"
            }
        );
        let mut odd = encode_utf16("<WIM><IMAGE INDEX=\"1\"><NAME>a</NAME></IMAGE></WIM>");
        odd.push(0);
        assert_eq!(
            run(&with(odd)).unwrap_err(),
            WimError::XmlInvalid {
                reason: "odd length"
            }
        );
        let no_bom =
            encode_utf16("<WIM><IMAGE INDEX=\"1\"><NAME>a</NAME></IMAGE></WIM>")[2..].to_vec();
        assert_eq!(
            run(&with(no_bom)).unwrap_err(),
            WimError::XmlInvalid {
                reason: "missing byte-order mark"
            }
        );
        let (b, _) = one(Compression::None);
        let small = WimLimits {
            max_xml_bytes: 64,
            ..WimLimits::DEFAULT
        };
        assert_eq!(run_with(&b, &small).unwrap_err(), WimError::XmlTooLarge);
    }

    #[test]
    fn integrity_mismatch() {
        let (b, _) = built(
            WimBuilder::new(Compression::Xpress)
                .image("a", "b")
                .integrity(true),
        );
        let mut c = b.clone();
        c[300] ^= 0x01;
        assert_eq!(
            run(&c).unwrap_err(),
            WimError::IntegrityMismatch { chunk: 0 }
        );
        // Multi-chunk table: damage in the third 10 MiB chunk.
        let (mut b, _) = built(
            WimBuilder::new(Compression::None)
                .image("a", "b")
                .zero_file(25 << 20)
                .integrity(true),
        );
        b[208 + (21 << 20)] = 1;
        assert_eq!(
            run(&b).unwrap_err(),
            WimError::IntegrityMismatch { chunk: 2 }
        );
    }

    #[test]
    fn integrity_table_malformed() {
        let (b, info) = built(
            WimBuilder::new(Compression::None)
                .image("a", "b")
                .integrity(true),
        );
        let t = info.integrity.unwrap().offset;
        // Entry count 2 for a one-chunk range.
        let mut c = b.clone();
        put(&mut c, t + 4, &2u32.to_le_bytes());
        assert_eq!(reason(run(&c)), "wim_malformed");
        // Chunk size 0.
        let mut c = b.clone();
        put(&mut c, t + 8, &0u32.to_le_bytes());
        assert_eq!(reason(run(&c)), "wim_malformed");
        // Table size field disagrees with the resource header.
        let mut c = b;
        put(&mut c, t, &33u32.to_le_bytes());
        assert_eq!(reason(run(&c)), "wim_malformed");
    }

    #[test]
    fn metadata_sha1_mismatch() {
        for c in [Compression::None, Compression::Xpress] {
            let (b, _) = built(
                WimBuilder::new(c)
                    .image("a", "b")
                    .image("c", "d")
                    .bad_metadata_hash(2),
            );
            assert_eq!(
                run(&b).unwrap_err(),
                WimError::MetadataHashMismatch { index: 2 }
            );
        }
    }

    #[test]
    fn damaged_compressed_metadata() {
        let (b, info) = one(Compression::Xpress);
        let m = info.metadata[0];
        assert_eq!(m.flags, 0x06);
        // Corrupt bytes inside the first chunk's Huffman table.
        let mut c = b.clone();
        let table_len = 8; // three chunks: two four-byte entries
        for i in 0..64 {
            c[usize::try_from(m.offset).unwrap() + table_len + i] = 0xff;
        }
        let e = run(&c).unwrap_err();
        assert!(
            matches!(
                e,
                WimError::Decode(_) | WimError::MetadataHashMismatch { .. }
            ),
            "{e:?}"
        );
        // A chunk-table entry pointing past the resource.
        let mut c = b.clone();
        put(&mut c, m.offset, &u32::MAX.to_le_bytes());
        assert_eq!(
            run(&c).unwrap_err(),
            WimError::OutOfBounds { what: "chunk" }
        );
        // Entries out of order.
        let mut c = b;
        put(&mut c, m.offset + 4, &1u32.to_le_bytes());
        assert_eq!(
            run(&c).unwrap_err(),
            WimError::OutOfBounds { what: "chunk" }
        );
    }

    #[test]
    fn raw_chunk_inside_compressed_resource_refused() {
        // OPEN-WIM-5: a compressed resource whose only chunk is stored at
        // its expanded size is refused, not guessed at.
        let (mut b, info) = one(Compression::Xpress);
        let e = lookup_entry_at(&info, 0);
        put(&mut b, e, &100u64.to_le_bytes()[..7]);
        put(&mut b, e + 16, &100u64.to_le_bytes());
        assert_eq!(run(&b).unwrap_err(), WimError::RawChunkNotSupported);
    }

    #[test]
    fn resource_entry_rules() {
        let (b, info) = one(Compression::None);
        let file = lookup_entry_at(&info, 1);
        // Compressed resource in an uncompressed file.
        let mut c = b.clone();
        put(&mut c, file + 7, &[0x04]);
        assert_eq!(reason(run(&c)), "wim_malformed");
        // Free and undefined resource flags.
        for f in [0x01u8, 0x20, 0x80] {
            let mut c = b.clone();
            put(&mut c, file + 7, &[f]);
            assert_eq!(reason(run(&c)), "wim_malformed", "{f:#x}");
        }
        // BOOT-008 / OBS-006: the recovery (.esd) resource flag 0x10 is an
        // unsupported compression, not damage.
        for f in [0x10u8, 0x14, 0x16] {
            let mut c = b.clone();
            put(&mut c, file + 7, &[f]);
            assert_eq!(
                run(&c).unwrap_err(),
                WimError::CompressionNotSupported,
                "{f:#x}"
            );
        }
        // Spanned resource flag, or another part number.
        let mut c = b.clone();
        put(&mut c, file + 7, &[0x08]);
        assert_eq!(run(&c).unwrap_err(), WimError::Spanned);
        let mut c = b.clone();
        put(&mut c, file + 24, &2u16.to_le_bytes());
        assert_eq!(run(&c).unwrap_err(), WimError::Spanned);
        // Uncompressed with stored != original.
        let mut c = b;
        let orig = info.files[0].original_size;
        put(&mut c, file + 16, &(orig + 1).to_le_bytes());
        assert_eq!(reason(run(&c)), "wim_malformed");
    }

    #[test]
    fn lzx_refused() {
        let (b, _) = built(
            WimBuilder::new(Compression::Xpress)
                .image("a", "b")
                .header_flags(0x0004_0082),
        );
        assert_eq!(run(&b).unwrap_err(), WimError::LzxNotSupported);
    }

    #[test]
    fn lzms_unknown_flag_refused() {
        // OBS-006: the recovery (.esd) header flags.
        for f in [0x0008_0082u32, 0x0001_0082, 0x0000_0082, 0x0006_0082] {
            let (b, _) = built(
                WimBuilder::new(Compression::Xpress)
                    .image("a", "b")
                    .header_flags(f),
            );
            assert_eq!(
                run(&b).unwrap_err(),
                WimError::CompressionNotSupported,
                "{f:#x}"
            );
        }
    }

    #[test]
    fn spanned_refused() {
        // OBS-017: parts carry header flag 0x08 and a total above 1.
        let (b, _) = built(
            WimBuilder::new(Compression::Xpress)
                .image("a", "b")
                .header_flags(0x0002_008a)
                .part(2, 7),
        );
        assert_eq!(run(&b).unwrap_err(), WimError::Spanned);
        let (b, _) = built(
            WimBuilder::new(Compression::None)
                .image("a", "b")
                .part(1, 2),
        );
        assert_eq!(run(&b).unwrap_err(), WimError::Spanned);
    }

    #[test]
    fn resource_only_refused() {
        let (b, _) = built(
            WimBuilder::new(Compression::None)
                .image("a", "b")
                .header_flags(0x90),
        );
        assert_eq!(run(&b).unwrap_err(), WimError::ResourceOnly);
    }

    #[test]
    fn metadata_only_refused() {
        let (b, _) = built(
            WimBuilder::new(Compression::None)
                .image("a", "b")
                .header_flags(0xa0),
        );
        assert_eq!(run(&b).unwrap_err(), WimError::MetadataOnly);
    }

    #[test]
    fn other_header_refusals() {
        let r = |b: WimBuilder| run(&b.build().unwrap().0).unwrap_err();
        let base = || WimBuilder::new(Compression::None).image("a", "b");
        assert_eq!(
            r(base().header_flags(0xc0)),
            WimError::HeaderFlagsNotSupported { flags: 0xc0 }
        );
        assert_eq!(r(base().image_count(0)), WimError::NoImages);
        assert_eq!(
            r(base().boot_index(2)),
            WimError::BadBootIndex { boot_index: 2 }
        );
        assert_eq!(
            r(WimBuilder::new(Compression::Xpress)
                .image("a", "b")
                .field_20(65536)),
            WimError::Malformed {
                what: "chunk size field"
            }
        );
        assert_eq!(
            r(base().image_count(5000)),
            WimError::LimitExceeded { what: "images" }
        );
    }

    #[test]
    fn limits_enforced() {
        let (b, _) = one(Compression::Xpress);
        let tight = WimLimits {
            max_metadata_bytes: 1000,
            ..WimLimits::DEFAULT
        };
        assert_eq!(
            run_with(&b, &tight).unwrap_err(),
            WimError::LimitExceeded { what: "metadata" }
        );
        let tight = WimLimits {
            max_lookup_bytes: 50,
            ..WimLimits::DEFAULT
        };
        assert_eq!(
            run_with(&b, &tight).unwrap_err(),
            WimError::LimitExceeded {
                what: "lookup table"
            }
        );
        let (b, _) = built(
            WimBuilder::new(Compression::None)
                .image("a", "b")
                .integrity(true),
        );
        let tight = WimLimits {
            max_integrity_bytes: 16,
            ..WimLimits::DEFAULT
        };
        assert_eq!(
            run_with(&b, &tight).unwrap_err(),
            WimError::LimitExceeded {
                what: "integrity table"
            }
        );
    }

    fn entry_bytes(b: &[u8], at: u64) -> [u8; 50] {
        let at = usize::try_from(at).unwrap();
        b[at..at + 50].try_into().unwrap()
    }

    fn two_images(c: Compression) -> (Vec<u8>, BuildInfo) {
        built(WimBuilder::new(c).image("a", "b").image("c", "d"))
    }

    #[test]
    fn repeated_metadata_range_refused() {
        // SEC-003 / BOOT-001: metadata entries naming the same bytes would
        // be decoded and hashed once per entry.
        for c in [Compression::None, Compression::Xpress] {
            let (b, info) = two_images(c);
            // Entry 2 = entry 1 exactly (same range, same hash). Metadata
            // hashes are not compared (BOOT-011); the shared range is.
            let mut d = b.clone();
            let e1 = entry_bytes(&b, lookup_entry_at(&info, 0));
            put(&mut d, lookup_entry_at(&info, 1), &e1);
            assert_eq!(run(&d).unwrap_err(), WimError::ResourceOverlap, "{c:?}");
            // Entry 2 points at entry 1's range but keeps its own hash.
            let mut d = b.clone();
            put(&mut d, lookup_entry_at(&info, 1), &e1[..24]);
            assert_eq!(run(&d).unwrap_err(), WimError::ResourceOverlap, "{c:?}");
            // Entry 2 starts inside entry 1's range.
            let mut d = b.clone();
            let m0 = info.metadata[0];
            let mut rh = info.metadata[1];
            rh.offset = m0.offset + 1;
            put(&mut d, lookup_entry_at(&info, 1), &rh.to_bytes());
            let e = run(&d).unwrap_err();
            assert!(
                matches!(
                    e,
                    WimError::ResourceOverlap | WimError::MetadataOrderNotSupported
                ),
                "{c:?} {e:?}"
            );
        }
    }

    #[test]
    fn file_resource_overlaps_refused() {
        let (b, info) = one(Compression::None);
        // The small file (lookup entry 2) moved into the lookup table, the
        // XML, or the first file resource.
        let file = lookup_entry_at(&info, 2);
        let size = info.files[1].stored_size;
        for offset in [
            info.lookup.offset,
            info.xml.offset - 1,
            info.files[0].offset + 1,
        ] {
            let mut c = b.clone();
            put(&mut c, file + 8, &offset.to_le_bytes());
            assert!(offset + size <= b.len() as u64);
            assert_eq!(run(&c).unwrap_err(), WimError::ResourceOverlap, "{offset}");
        }
        // Inside the integrity table.
        let (b, info) = built(
            WimBuilder::new(Compression::None)
                .image("a", "b")
                .integrity(true),
        );
        let mut c = b.clone();
        let t = info.integrity.unwrap();
        let mut rh = info.files[1];
        rh.offset = t.offset;
        rh.stored_size = t.stored_size;
        rh.original_size = t.stored_size;
        put(&mut c, lookup_entry_at(&info, 2), &rh.to_bytes());
        // The integrity hash covers the lookup table, so either refusal
        // proves the entry is never used.
        let e = run(&c).unwrap_err();
        assert!(
            matches!(
                e,
                WimError::ResourceOverlap | WimError::IntegrityMismatch { .. }
            ),
            "{e:?}"
        );
    }

    #[test]
    fn duplicate_file_hash_refused() {
        let (mut b, info) = one(Compression::Xpress);
        let h = entry_bytes(&b, lookup_entry_at(&info, 1));
        put(&mut b, lookup_entry_at(&info, 2) + 30, &h[30..50]);
        assert_eq!(run(&b).unwrap_err(), WimError::DuplicateResource);
    }

    #[test]
    fn metadata_out_of_offset_order_refused() {
        // BOOT-003: lookup order and offset order differ; which one names
        // the index is OPEN-WIM-6, so the file is refused.
        for c in [Compression::None, Compression::Xpress] {
            let (mut b, info) = two_images(c);
            let e1 = entry_bytes(&b, lookup_entry_at(&info, 0));
            let e2 = entry_bytes(&b, lookup_entry_at(&info, 1));
            put(&mut b, lookup_entry_at(&info, 0), &e2);
            put(&mut b, lookup_entry_at(&info, 1), &e1);
            assert_eq!(
                run(&b).unwrap_err(),
                WimError::MetadataOrderNotSupported,
                "{c:?}"
            );
        }
    }

    #[test]
    fn total_metadata_budget() {
        let (b, _) = built(
            WimBuilder::new(Compression::Xpress)
                .image("a", "b")
                .image("c", "d")
                .image("e", "f"),
        );
        // Each image's metadata is about 70 KB; three exceed 150 KB.
        let tight = WimLimits {
            max_metadata_total_bytes: 150_000,
            ..WimLimits::DEFAULT
        };
        assert_eq!(
            run_with(&b, &tight).unwrap_err(),
            WimError::LimitExceeded {
                what: "total metadata"
            }
        );
        assert!(run(&b).is_ok());
        // Relative bound: a metadata entry claiming more than 32 times the
        // file length is refused before any decoding.
        let (mut b, info) = one(Compression::Xpress);
        let claim = 33 * b.len() as u64;
        put(&mut b, lookup_entry_at(&info, 0) + 16, &claim.to_le_bytes());
        assert_eq!(
            run(&b).unwrap_err(),
            WimError::LimitExceeded {
                what: "total metadata"
            }
        );
    }

    #[test]
    fn boot_metadata_must_match_boot_image() {
        // BOOT-006 (derived, unconfirmed).
        let (good, info) = built(
            WimBuilder::new(Compression::Xpress)
                .image("a", "b")
                .image("c", "d")
                .boot_index(2),
        );
        assert_eq!(run(&good).unwrap().boot_index, 2);
        // Boot metadata names image 1 while the boot index says 2.
        let mut b = good.clone();
        put(&mut b, 96, &info.metadata[0].to_bytes());
        assert_eq!(
            run(&b).unwrap_err(),
            WimError::BadBootIndex { boot_index: 2 }
        );
        // Boot index 2 with no boot metadata.
        let mut b = good.clone();
        put(&mut b, 96, &[0u8; 24]);
        assert_eq!(
            run(&b).unwrap_err(),
            WimError::BadBootIndex { boot_index: 2 }
        );
        // BOOT-013: only the location is compared. The header slot's flag
        // byte may differ from the entry's (OBS-007 shows DISM writing
        // header-slot flags unlike the entry's); recorded, not refused.
        for f in [0x00u8, 0x02, 0x04] {
            let mut b = good.clone();
            put(&mut b, 96 + 7, &[f]);
            assert_eq!(run(&b).unwrap().boot_index, 2, "{f:#x}");
        }
        // Same offset, other sizes: refused.
        let m2 = info.metadata[1];
        for rh in [
            usgp_image::wim::reshdr::ResourceHeader {
                stored_size: m2.stored_size - 1,
                ..m2
            },
            usgp_image::wim::reshdr::ResourceHeader {
                original_size: m2.original_size + 1,
                ..m2
            },
        ] {
            let mut b = good.clone();
            put(&mut b, 96, &rh.to_bytes());
            assert_eq!(
                run(&b).unwrap_err(),
                WimError::BadBootIndex { boot_index: 2 },
                "{rh:?}"
            );
        }
        // Boot index 0 with boot metadata.
        let mut b = good;
        put(&mut b, 120, &0u32.to_le_bytes());
        assert_eq!(
            run(&b).unwrap_err(),
            WimError::Malformed {
                what: "boot metadata"
            }
        );
    }

    #[test]
    fn integrity_header_flags_must_be_zero() {
        // BOOT-009 / OBS-007.
        let (good, _) = built(
            WimBuilder::new(Compression::None)
                .image("a", "b")
                .integrity(true),
        );
        assert!(run(&good).is_ok());
        for f in [0x02u8, 0x04, 0x01] {
            let mut b = good.clone();
            put(&mut b, 124 + 7, &[f]);
            assert_eq!(
                run(&b).unwrap_err(),
                WimError::Malformed {
                    what: "integrity table resource"
                },
                "{f:#x}"
            );
        }
    }

    #[test]
    fn impossible_part_fields_malformed() {
        // BOOT-010.
        for (n, total) in [(0u16, 1u16), (1, 0), (3, 2), (0, 0)] {
            let (b, _) = built(
                WimBuilder::new(Compression::None)
                    .image("a", "b")
                    .part(n, total),
            );
            assert_eq!(
                run(&b).unwrap_err(),
                WimError::Malformed {
                    what: "part fields"
                },
                "{n}/{total}"
            );
        }
    }

    /// The first compressed file resource of more than one chunk, and its
    /// lookup entry offset.
    fn multi_chunk_file(
        info: &BuildInfo,
        images: u64,
    ) -> (usgp_image::wim::reshdr::ResourceHeader, u64) {
        let (j, rh) = info
            .files
            .iter()
            .enumerate()
            .find(|(_, r)| r.is_compressed() && r.original_size > 32768)
            .unwrap();
        (*rh, lookup_entry_at(info, images + j as u64))
    }

    #[test]
    fn file_chunk_tables_checked() {
        // BOOT-007: file resources are not decoded in M2, but their chunk
        // tables are checked.
        let (good, info) = one(Compression::Xpress);
        assert_eq!(run(&good).unwrap().raw_sized_file_chunks, 0);
        let (rh, _) = multi_chunk_file(&info, 1);
        // Entry 0 (end of chunk 0) = 0: an empty chunk.
        let mut b = good.clone();
        put(&mut b, rh.offset, &0u32.to_le_bytes());
        assert_eq!(
            run(&b).unwrap_err(),
            WimError::Malformed { what: "chunk size" }
        );
        // Past the stored data.
        let mut b = good.clone();
        put(
            &mut b,
            rh.offset,
            &u32::try_from(rh.stored_size).unwrap().to_le_bytes(),
        );
        assert_eq!(
            run(&b).unwrap_err(),
            WimError::OutOfBounds { what: "chunk" }
        );
        // Last chunk empty: entry 0 = all of the data.
        let mut b = good.clone();
        let data = u32::try_from(rh.stored_size - 4).unwrap();
        put(&mut b, rh.offset, &data.to_le_bytes());
        assert_eq!(
            run(&b).unwrap_err(),
            WimError::Malformed { what: "chunk size" }
        );
    }

    #[test]
    fn raw_sized_file_chunks_recorded_not_refused() {
        // OPEN-WIM-5: a file chunk stored at or above its expanded size is
        // counted (M2 does not decode file resources); the same in
        // metadata stays refused (raw_chunk_inside_compressed_resource_refused).
        let (mut b, info) = one(Compression::Xpress);
        let (rh, entry) = multi_chunk_file(&info, 1);
        // Shrink the original size so the last chunk expands to 1 byte.
        put(&mut b, entry + 16, &(32768u64 + 1).to_le_bytes());
        assert!(rh.stored_size > 4 + 2);
        let s = run(&b).unwrap();
        assert_eq!(s.raw_sized_file_chunks, 1);
    }

    #[test]
    fn random_damage_never_panics() {
        let (good, _) = built(
            WimBuilder::new(Compression::Xpress)
                .image("a", "b")
                .image("c", "d")
                .integrity(true),
        );
        let mut s: u64 = 0x1234_5678_9abc_def1;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..400 {
            let mut b = good.clone();
            for _ in 0..(1 + next() % 8) {
                let at = usize::try_from(next() % (b.len() as u64)).unwrap();
                b[at] = (next() & 0xff) as u8;
            }
            let _ = run(&b);
        }
        // Damage concentrated in the header and lookup table.
        for i in 0..400 {
            let mut b = good.clone();
            let at = if i % 2 == 0 {
                usize::try_from(next() % 208).unwrap()
            } else {
                b.len() - 1 - usize::try_from(next() % 2000).unwrap()
            };
            b[at] = (next() & 0xff) as u8;
            let _ = run(&b);
        }
    }
}
