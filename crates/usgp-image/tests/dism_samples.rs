//! Checks our parser against WIM files made by Microsoft's DISM in the
//! same workflow run (plan WU-W item 2; decision 0006), and our test
//! builder's layout against DISM's (`builder_matches_dism`).
//!
//! Contract: scripts/wim-samples/README.md, "Linux consumer". With the
//! `dism-samples` feature on, `USGP_WIM_SAMPLES` unset or not a directory
//! is a test **failure**, never a skip. Any `not-produced` row, missing
//! file or SHA-256 mismatch fails.
//!
//! Rows with expected `observe` (S11, S12: BOOT-011, BOOT-012) record
//! the parser's result without judging it, because what DISM writes there
//! is unobserved; a row with status `dism-refused` (DISM itself refused
//! the step, which is the observation) has no file and is printed.
//!
//! The samples are never committed (OPEN-PE-LIC); they exist only as a
//! workflow artifact.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-10
// - SPEC: specs/os-images.md#REQ-IMG-037, #REQ-IMG-038, #REQ-IMG-040,
//   #REQ-IMG-042
// - DECISION: docs/decisions/0006-wim-format-by-black-box-test-files.md
#![cfg(feature = "dism-samples")]

#[cfg(test)]
mod dism {
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::io::{BufReader, Read};
    use std::path::{Path, PathBuf};

    use usgp_crypto::CryptoProvider;
    use usgp_image::testkit::{WimBuilder, decode_resource};
    use usgp_image::wim::header::{WimHeader, parse_header};
    use usgp_image::wim::integrity::IntegrityTableHeader;
    use usgp_image::wim::lookup::{LookupEntry, parse_table};
    use usgp_image::wim::reshdr::ResourceHeader;
    use usgp_image::wim::xml::{BOM, parse_xml};
    use usgp_image::{Compression, NoProgress, WimError, WimLimits, WimSummary, check_wim};

    const ENV: &str = "USGP_WIM_SAMPLES";

    fn samples_dir() -> PathBuf {
        let dir = std::env::var_os(ENV).unwrap_or_else(|| {
            panic!("{ENV} is not set: the dism-samples tests need the wim-samples artifact")
        });
        let dir = PathBuf::from(dir);
        assert!(dir.is_dir(), "{ENV} is not a directory: {}", dir.display());
        dir
    }

    /// Tab-separated, UTF-8 without BOM, LF line ends, header row first.
    fn read_tsv(path: &Path, header: &[&str]) -> Vec<Vec<String>> {
        let text =
            std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(
            !text.starts_with('\u{feff}'),
            "{} has a BOM",
            path.display()
        );
        assert!(!text.contains('\r'), "{} has CR line ends", path.display());
        let mut lines = text.lines().filter(|l| !l.is_empty());
        let head: Vec<&str> = lines.next().expect("header row").split('\t').collect();
        assert_eq!(head, header, "{} header", path.display());
        lines
            .map(|l| {
                let row: Vec<String> = l.split('\t').map(str::to_owned).collect();
                assert_eq!(row.len(), header.len(), "{}: bad row {l:?}", path.display());
                row
            })
            .collect()
    }

    struct Row {
        id: String,
        file: String,
        bytes: u64,
        sha256: String,
        compression: String,
        images: u32,
        expected: String,
    }

    fn manifest(dir: &Path) -> Vec<Row> {
        let rows = read_tsv(
            &dir.join("manifest.tsv"),
            &[
                "id",
                "file",
                "bytes",
                "sha256",
                "compression",
                "images",
                "expected",
                "status",
            ],
        );
        assert!(!rows.is_empty(), "manifest.tsv has no rows");
        let mut out = Vec::new();
        for r in rows {
            let [
                id,
                file,
                bytes,
                sha256,
                compression,
                images,
                expected,
                status,
            ] = <[String; 8]>::try_from(r).unwrap();
            // README: S08's row (large job only) says it was not uploaded.
            if status == "produced (not uploaded)" {
                continue;
            }
            // README: an observation sample whose DISM step DISM refused.
            if status == "dism-refused" {
                assert_eq!(expected, "observe", "{id}: dism-refused on a judged row");
                println!("{id} {file}: DISM refused the sample step (see commands.log)");
                continue;
            }
            assert_eq!(status, "produced", "{id} {file}: status {status}");
            out.push(Row {
                id,
                file,
                bytes: bytes.parse().unwrap(),
                sha256,
                compression,
                images: images.parse().unwrap(),
                expected,
            });
        }
        out
    }

    /// `id` → (index, name, description) rows.
    fn editions(dir: &Path) -> BTreeMap<String, Vec<(u32, String, String)>> {
        let mut m: BTreeMap<String, Vec<(u32, String, String)>> = BTreeMap::new();
        for r in read_tsv(
            &dir.join("editions.tsv"),
            &["id", "index", "name", "description"],
        ) {
            let [id, index, name, description] = <[String; 4]>::try_from(r).unwrap();
            m.entry(id)
                .or_default()
                .push((index.parse().unwrap(), name, description));
        }
        m
    }

    fn sha256_hex(path: &Path) -> String {
        let mut f = BufReader::new(File::open(path).unwrap());
        let mut h = usgp_crypto::provider().sha256_hasher();
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let n = f.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        h.finish().to_hex()
    }

    fn check(path: &Path) -> Result<WimSummary, WimError> {
        let len = std::fs::metadata(path).unwrap().len();
        let mut f = BufReader::new(File::open(path).unwrap());
        check_wim(
            &mut f,
            len,
            &WimLimits::DEFAULT,
            usgp_crypto::provider(),
            &mut NoProgress,
        )
    }

    /// What a manifest row expects of the parser.
    enum Expect {
        Accept,
        Refuse(&'static str),
        /// Unobserved layout (S11, S12): the result is printed, not judged.
        Observe,
    }

    fn expected_reason(token: &str) -> Expect {
        match token {
            "accept" => Expect::Accept,
            "observe" => Expect::Observe,
            "refuse:lzx" => Expect::Refuse("wim_lzx_not_supported"),
            "refuse:spanned" => Expect::Refuse("wim_split_not_supported"),
            "refuse:compression-unsupported" => Expect::Refuse("wim_compression_not_supported"),
            other => panic!("unknown expected token {other:?}"),
        }
    }

    #[test]
    fn manifest_files_present_and_hashes_match() {
        let dir = samples_dir();
        for row in manifest(&dir) {
            let path = dir.join(&row.file);
            assert!(path.is_file(), "{}: {} missing", row.id, row.file);
            assert_eq!(
                std::fs::metadata(&path).unwrap().len(),
                row.bytes,
                "{} size",
                row.file
            );
            assert_eq!(sha256_hex(&path), row.sha256, "{} SHA-256", row.file);
        }
    }

    #[test]
    fn every_sample_meets_its_expectation() {
        let dir = samples_dir();
        let editions = editions(&dir);
        let rows = manifest(&dir);
        let mut accepted = 0;
        let mut refused = 0;
        for row in &rows {
            let path = dir.join(&row.file);
            let result = check(&path);
            match expected_reason(&row.expected) {
                Expect::Observe => match &result {
                    Ok(s) => println!(
                        "observe {} ({}): accepted, {} images, compression {}",
                        row.id,
                        row.file,
                        s.image_count,
                        s.compression.as_str()
                    ),
                    Err(e) => println!(
                        "observe {} ({}): refused {} ({e})",
                        row.id,
                        row.file,
                        e.reason_code()
                    ),
                },
                Expect::Accept => {
                    let s = result.unwrap_or_else(|e| {
                        panic!("{} ({}) refused: {} {e}", row.id, row.file, e.reason_code())
                    });
                    accepted += 1;
                    assert_eq!(s.image_count, row.images, "{} images", row.id);
                    let want = match row.compression.as_str() {
                        "none" => Compression::None,
                        "xpress" => Compression::Xpress,
                        other => panic!("{}: accept with compression {other}", row.id),
                    };
                    assert_eq!(s.compression, want, "{} compression", row.id);
                    let rows = editions
                        .get(&row.id)
                        .unwrap_or_else(|| panic!("{}: no editions.tsv rows", row.id));
                    let got: Vec<(u32, String, String)> = s
                        .editions
                        .iter()
                        .map(|e| (e.index, e.name.clone(), e.description.clone()))
                        .collect();
                    let mut want = rows.clone();
                    want.sort();
                    assert_eq!(got, want, "{} editions", row.id);
                    if row.id == "S05" {
                        assert!(s.has_integrity_table, "S05 integrity table");
                    }
                }
                Expect::Refuse(code) => {
                    refused += 1;
                    let e = result.err().unwrap_or_else(|| {
                        panic!("{} ({}) accepted, expected {code}", row.id, row.file)
                    });
                    assert_eq!(e.reason_code(), code, "{} ({})", row.id, row.file);
                }
            }
        }
        assert!(
            accepted > 0 && refused > 0,
            "manifest lacks accept or refuse rows"
        );
    }

    /// The structural facts the builder must share with DISM's output.
    #[derive(Debug, PartialEq, Eq)]
    struct Layout {
        magic_and_size: (u32, u32),
        version: u32,
        flags: u32,
        field_20: u32,
        part: (u16, u16),
        image_count: u32,
        lookup_flags: u8,
        xml_flags: u8,
        boot_metadata_zero: bool,
        boot_index: u32,
        integrity_flags: Option<u8>,
        integrity_chunk: Option<u32>,
        unused_zero: bool,
        first_resource_at: u64,
        xml_follows_lookup: bool,
        last_structure_ends_file: bool,
        metadata_first: bool,
        metadata_flags: Vec<u8>,
        metadata_part_and_count: Vec<(u16, u32)>,
        metadata_offsets_rise: bool,
        file_resource_before_each_metadata: bool,
        lookup_follows_last_metadata: bool,
        some_file_shared_by_every_image: bool,
        all_parts_one: bool,
        uncompressed_sizes_equal: bool,
        xml_bom: bool,
        xml_starts_with_wim: bool,
        xml_top_totalbytes_is_offset: bool,
        image_paths: Vec<Vec<String>>,
        names: Vec<(u32, String, String)>,
    }

    fn slice(b: &[u8], rh: &ResourceHeader) -> Vec<u8> {
        let s = usize::try_from(rh.offset).unwrap();
        let e = s + usize::try_from(rh.stored_size).unwrap();
        b[s..e].to_vec()
    }

    fn layout(b: &[u8]) -> Layout {
        let h: WimHeader = parse_header(b).unwrap();
        let len = u64::try_from(b.len()).unwrap();
        let compression = if h.flags & 0x2 != 0 {
            Compression::Xpress
        } else {
            Compression::None
        };
        let table = slice(b, &h.lookup);
        let scan = parse_table(&table, compression, len, 1024).unwrap();
        let entries: Vec<LookupEntry> = table
            .chunks(50)
            .map(|c| LookupEntry::parse(c).unwrap())
            .collect();
        let meta_n = scan.metadata.len();
        let xml_raw = slice(b, &h.xml);
        let xml = parse_xml(&xml_raw, &WimLimits::DEFAULT).unwrap();
        let text: String = char::decode_utf16(
            xml_raw[2..]
                .chunks(2)
                .map(|u| u16::from_le_bytes([u[0], u[1]])),
        )
        .map(Result::unwrap)
        .collect();
        let integrity = (!h.integrity.is_zero())
            .then(|| IntegrityTableHeader::parse(&slice(b, &h.integrity)).unwrap());
        let ends: Vec<u64> = [h.lookup, h.xml, h.integrity]
            .iter()
            .filter(|r| !r.is_zero())
            .map(|r| r.offset + r.stored_size)
            .collect();
        Layout {
            magic_and_size: (u32::from_le_bytes(b[0..4].try_into().unwrap()), h.cb_size),
            version: h.version,
            flags: h.flags,
            field_20: h.field_20,
            part: (h.part_number, h.total_parts),
            image_count: h.image_count,
            lookup_flags: h.lookup.flags,
            xml_flags: h.xml.flags,
            boot_metadata_zero: h.boot_metadata.is_zero(),
            boot_index: h.boot_index,
            integrity_flags: (!h.integrity.is_zero()).then_some(h.integrity.flags),
            integrity_chunk: integrity.map(|t| t.chunk_size),
            unused_zero: b[148..208].iter().all(|&x| x == 0),
            first_resource_at: entries.iter().map(|e| e.reshdr.offset).min().unwrap(),
            xml_follows_lookup: h.xml.offset == h.lookup.offset + h.lookup.stored_size,
            last_structure_ends_file: ends.iter().max() == Some(&len),
            metadata_first: entries[..meta_n].iter().all(|e| e.reshdr.is_metadata())
                && entries[meta_n..].iter().all(|e| !e.reshdr.is_metadata()),
            metadata_flags: scan.metadata.iter().map(|e| e.reshdr.flags).collect(),
            metadata_part_and_count: scan
                .metadata
                .iter()
                .map(|e| (e.part_number, e.ref_count))
                .collect(),
            metadata_offsets_rise: scan
                .metadata
                .windows(2)
                .all(|w| w[0].reshdr.offset < w[1].reshdr.offset),
            // Interleaving: each image's new file resources come right
            // before its metadata (OBS-009, S04).
            file_resource_before_each_metadata: {
                let mut prev_end = 0u64;
                scan.metadata.iter().all(|m| {
                    let ok = entries[meta_n..]
                        .iter()
                        .any(|f| f.reshdr.offset >= prev_end && f.reshdr.offset < m.reshdr.offset);
                    prev_end = m.reshdr.offset + m.reshdr.stored_size;
                    ok
                })
            },
            lookup_follows_last_metadata: scan
                .metadata
                .last()
                .is_some_and(|m| m.reshdr.offset + m.reshdr.stored_size == h.lookup.offset),
            some_file_shared_by_every_image: entries[meta_n..]
                .iter()
                .any(|e| e.ref_count == h.image_count),
            all_parts_one: entries.iter().all(|e| e.part_number == 1),
            uncompressed_sizes_equal: entries
                .iter()
                .filter(|e| !e.reshdr.is_compressed())
                .all(|e| e.reshdr.stored_size == e.reshdr.original_size),
            xml_bom: xml_raw.starts_with(&BOM),
            xml_starts_with_wim: text.starts_with("<WIM>") && text.ends_with("</WIM>"),
            xml_top_totalbytes_is_offset: xml.total_bytes == Some(h.xml.offset),
            image_paths: xml
                .images
                .iter()
                .map(|i| i.elements.iter().map(|l| l.path.clone()).collect())
                .collect(),
            names: xml
                .images
                .iter()
                .map(|i| (i.index, i.name.clone(), i.description.clone()))
                .collect(),
        }
    }

    fn dism_file(dir: &Path, rows: &[Row], id: &str) -> Vec<u8> {
        let row = rows
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("{id} not in manifest.tsv"));
        std::fs::read(dir.join(&row.file)).unwrap()
    }

    #[test]
    fn builder_matches_dism() {
        let dir = samples_dir();
        let rows = manifest(&dir);
        let editions = editions(&dir);
        for (id, compression, integrity) in [
            ("S01", Compression::None, false),
            ("S02", Compression::Xpress, false),
            ("S05", Compression::Xpress, true),
            // BOOT-005: 12 images (capture + 11 appends): metadata order,
            // interleaving, reference counts, metadata entries first.
            ("S04", Compression::Xpress, false),
        ] {
            let dism = layout(&dism_file(&dir, &rows, id));
            let mut b = WimBuilder::new(compression).integrity(integrity);
            for (_, name, desc) in editions.get(id).unwrap() {
                b = b.image(name, desc);
            }
            let (ours, _) = b.build().unwrap();
            let ours = layout(&ours);
            assert_eq!(ours, dism, "builder layout differs from DISM's {id}");
        }
    }

    /// Every compressed lookup entry of every XPRESS file, including each
    /// split part's own table (OBS-017), decoded by the product's resource
    /// reader and XPRESS decoder and compared with the entry's SHA-1
    /// (BOOT-004; also proves the strict refill rule of BOOT-002 accepts
    /// every DISM chunk). Split parts are refused by `check_wim`, so their
    /// tables are walked here directly.
    #[test]
    fn every_dism_compressed_resource_decodes() {
        let dir = samples_dir();
        let rows = manifest(&dir);
        let mut resources = 0u64;
        let mut chunks = 0u64;
        for row in rows.iter().filter(|r| r.compression == "xpress") {
            let b = std::fs::read(dir.join(&row.file)).unwrap();
            let h = parse_header(&b).unwrap();
            let table = slice(&b, &h.lookup);
            let mut in_file = 0;
            for raw in table.chunks(50) {
                let e = LookupEntry::parse(raw).unwrap();
                if !e.reshdr.is_compressed() {
                    continue;
                }
                let out = decode_resource(&b, &e.reshdr).unwrap_or_else(|err| {
                    panic!(
                        "{} offset {}: {} {err}",
                        row.file,
                        e.reshdr.offset,
                        err.reason_code()
                    )
                });
                assert_eq!(
                    u64::try_from(out.len()).unwrap(),
                    e.reshdr.original_size,
                    "{} offset {}",
                    row.file,
                    e.reshdr.offset
                );
                assert_eq!(
                    usgp_crypto::digest::legacy_sha1(&out).0,
                    e.sha1,
                    "{} offset {}: SHA-1",
                    row.file,
                    e.reshdr.offset
                );
                in_file += 1;
                chunks += e.reshdr.original_size.div_ceil(32768);
            }
            assert!(in_file > 0, "{}: no compressed resource", row.file);
            resources += in_file;
        }
        // R1 (OBS-011, OBS-012): 83 resources, 369 chunk instances over
        // S02, S04, S05, S09 and the seven S06 parts; later runs add more.
        assert!(resources >= 83 && chunks >= 369, "{resources} {chunks}");
        println!("decoded {resources} compressed resources, {chunks} chunks");
    }
}
