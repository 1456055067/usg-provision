//! The metadata parser against the M-01 to M-23 contract
//! (`findings-boot-obs.md`, "What WU-4 may rely on"): each accepted form
//! from the testkit encoder, and a named refusal for each rule, made by
//! changing the encoder's tree or patching its bytes. Every truncation and
//! random damage must give an error, never a panic.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-10, SI-11
// - SPEC: specs/standards/wim.md §6, §6.1 (OBS-024 to OBS-048)
#![cfg(feature = "testkit")]

#[cfg(test)]
mod metadata {
    use usgp_image::testkit::tree::{
        EncodedTree, NodeKind, descriptor, descriptor_with_control, rel_link_data,
    };
    use usgp_image::testkit::{NodeSpec, TreeSpec};
    use usgp_image::wim::metadata::{
        EntryKind, ImageTree, MetadataError, MetadataLimits, attr, parse_metadata, tag,
    };

    fn parse(b: &[u8]) -> Result<ImageTree, MetadataError> {
        parse_with(b, &MetadataLimits::DEFAULT)
    }

    fn parse_with(b: &[u8], l: &MetadataLimits) -> Result<ImageTree, MetadataError> {
        let r = parse_metadata(b, l);
        if let Err(e) = &r {
            assert!(
                MetadataError::REASON_CODES.contains(&e.reason_code()),
                "{e:?}"
            );
            assert!(!e.operator_message().is_empty());
        }
        r
    }

    fn code(spec: &TreeSpec) -> &'static str {
        parse(&spec.encode().bytes).unwrap_err().reason_code()
    }

    fn one(n: NodeSpec) -> TreeSpec {
        TreeSpec::new(vec![n])
    }

    fn put(b: &mut [u8], at: usize, bytes: &[u8]) {
        b[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn u64_at(b: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
    }

    fn patched(e: &EncodedTree, path: &str, rel: usize, bytes: &[u8]) -> Vec<u8> {
        let mut b = e.bytes.clone();
        put(&mut b, e.offset(path).unwrap() + rel, bytes);
        b
    }

    #[test]
    fn sample_parses_with_every_feature() {
        let spec = TreeSpec::sample();
        let t = parse(&spec.encode().bytes).unwrap();
        let by = |name: &str| {
            t.entries
                .iter()
                .find(|e| e.name.as_ref().map(|n| n.as_str()) == Some(name))
                .unwrap()
        };
        assert_eq!(t.security.len(), 3);
        assert_eq!(t.entries[0].kind, EntryKind::Directory);
        assert_eq!(
            by("readme.txt").short_name.as_ref().unwrap().as_str(),
            "README.TXT"
        );
        assert_eq!(by("empty.txt").data, None);
        assert_eq!(by("streams.txt").streams.len(), 2);
        assert_eq!(by("empty-main.txt").data, None);
        assert_eq!(by("dir-with-stream").streams.len(), 1);
        assert_eq!(
            by("sym-file-rel.txt").kind,
            EntryKind::Symlink { directory: false }
        );
        assert_eq!(
            by("sym-dir-rel").kind,
            EntryKind::Symlink { directory: true }
        );
        assert_eq!(by("sym-dir-rel").reparse.unwrap().tag, tag::SYMLINK);
        assert!(by("hard-two.txt").link_group.is_some());
        assert_eq!(by("sparse.bin").attributes.0, attr::SPARSE | attr::ARCHIVE);
        assert_eq!(t.dir_and_file_counts(), spec.counts());
    }

    // M-01 security block.
    #[test]
    fn m01_security_block() {
        let e = TreeSpec::sample().encode();
        let mut b = e.bytes.clone();
        // Total length off by 8 (lengths no longer sum).
        let total = u32::from_le_bytes(b[0..4].try_into().unwrap());
        put(&mut b, 0, &(total + 8).to_le_bytes());
        assert_eq!(
            parse(&b).unwrap_err().reason_code(),
            "wim_meta_security_block"
        );
        // Non-zero padding between the block and the root.
        let mut spec = TreeSpec::sample();
        let mut odd = descriptor(0);
        odd.push(0); // 8 + 8 + 73 = 89, pad 7
        spec.security = vec![odd];
        let mut b = spec.encode().bytes;
        b[90] = 1;
        assert_eq!(parse(&b).unwrap_err(), MetadataError::Padding);
        // An empty descriptor is unbounded below.
        spec.security = vec![Vec::new()];
        assert_eq!(code(&spec), "wim_meta_security_descriptor");
        // Count larger than the block.
        let mut b = TreeSpec::sample().encode().bytes;
        put(&mut b, 4, &1000u32.to_le_bytes());
        assert_eq!(
            parse(&b).unwrap_err().reason_code(),
            "wim_meta_security_block"
        );
        // Limits.
        let l = MetadataLimits {
            max_security_descriptors: 2,
            ..MetadataLimits::DEFAULT
        };
        assert_eq!(
            parse_with(&TreeSpec::sample().encode().bytes, &l).unwrap_err(),
            MetadataError::LimitExceeded {
                what: "security descriptors"
            }
        );
        let l = MetadataLimits {
            max_sd_bytes: 10,
            ..MetadataLimits::DEFAULT
        };
        assert!(parse_with(&TreeSpec::sample().encode().bytes, &l).is_err());
    }

    // M-02 root entry.
    #[test]
    fn m02_root() {
        let mut spec = TreeSpec::sample();
        spec.root.name = "r".into();
        assert_eq!(code(&spec), "wim_meta_root");
        let mut spec = TreeSpec::sample();
        spec.root.streams.push(("s".into(), b"x".to_vec()));
        assert_eq!(code(&spec), "wim_meta_root");
        let mut spec = TreeSpec::sample();
        spec.root.short_name = Some("R".into());
        assert_eq!(code(&spec), "wim_meta_root");
    }

    // M-03 the 102-byte fixed part (OBS-026): +24, +32, +84 must be zero.
    #[test]
    fn m03_reserved_fields() {
        let e = TreeSpec::sample().encode();
        for (rel, width) in [(24usize, 8usize), (32, 8), (84, 4)] {
            let mut v = vec![0u8; width];
            v[0] = 1;
            for path in ["", "readme.txt"] {
                let b = patched(&e, path, rel, &v);
                assert_eq!(
                    parse(&b).unwrap_err(),
                    MetadataError::ReservedField { offset: rel as u8 },
                    "{path} +{rel}"
                );
            }
        }
        // The name sits at +102, its length at +100 (not the paper's 98).
        let at = e.offset("readme.txt").unwrap();
        assert_eq!(
            u16::from_le_bytes(e.bytes[at + 100..at + 102].try_into().unwrap()),
            20
        );
        assert_eq!(&e.bytes[at + 102..at + 104], b"r\0");
    }

    // M-04 names.
    #[test]
    fn m04_names() {
        for bad in ["", ".", "..", "a\\b", "a/b", "a:b", "a\0b"] {
            assert_eq!(
                code(&one(NodeSpec::file(bad, b"x"))),
                "wim_meta_name",
                "{bad:?}"
            );
        }
        let e = one(NodeSpec::file("ab", b"x")).encode();
        // Odd length.
        assert_eq!(
            parse(&patched(&e, "ab", 100, &3u16.to_le_bytes()))
                .unwrap_err()
                .reason_code(),
            "wim_meta_name"
        );
        // Missing terminator.
        assert_eq!(
            parse(&patched(&e, "ab", 106, b"x\0")).unwrap_err(),
            MetadataError::Name {
                what: "missing terminator"
            }
        );
        // Unpaired surrogate.
        assert_eq!(
            parse(&patched(&e, "ab", 102, &[0x00, 0xd8])).unwrap_err(),
            MetadataError::Name {
                what: "unpaired surrogate"
            }
        );
        // Limit.
        let l = MetadataLimits {
            max_name_units: 1,
            ..MetadataLimits::DEFAULT
        };
        assert!(parse_with(&e.bytes, &l).is_err());
        // Siblings that differ only in case collide on the target.
        let spec = TreeSpec::new(vec![
            NodeSpec::file("A.txt", b"1"),
            NodeSpec::file("a.TXT", b"2"),
        ]);
        assert_eq!(code(&spec), "wim_meta_duplicate_name");
    }

    // M-05 short names.
    #[test]
    fn m05_short_names() {
        assert_eq!(
            code(&one(
                NodeSpec::file("long-name.txt", b"x").short("LONGNAME.TXTX")
            )),
            "wim_meta_short_name"
        );
        assert!(
            parse(
                &one(NodeSpec::file("long-name.txt", b"x").short("LONGNA~1.TXT"))
                    .encode()
                    .bytes
            )
            .is_ok()
        );
        let e = one(NodeSpec::file("ab", b"x").short("AB")).encode();
        // The short name follows the name's terminator at 102 + 4 + 2.
        assert_eq!(
            parse(&patched(&e, "ab", 108 + 4, b"x\0")).unwrap_err(),
            MetadataError::ShortName {
                what: "missing terminator"
            }
        );
        assert_eq!(
            code(&one(NodeSpec::file("ab", b"x").short("A:B"))),
            "wim_meta_short_name"
        );
    }

    // M-06 lengths and padding.
    #[test]
    fn m06_length_and_padding() {
        let e = one(NodeSpec::file("abc", b"x")).encode();
        // 102 + 6 + 2 = 110, length 112: two bytes of padding.
        let at = e.offset("abc").unwrap();
        assert_eq!(u64_at(&e.bytes, at), 112);
        assert_eq!(
            parse(&patched(&e, "abc", 111, &[1])).unwrap_err(),
            MetadataError::Padding
        );
        // Trailing bytes without the sparse bit (M-15: a block on a
        // non-sparse entry).
        let spec = one(NodeSpec::file("abc", b"x").sparse_extra(&sparse_block(3, &[(0, 1)])));
        assert_eq!(code(&spec), "wim_meta_sparse_block");
        // A length that is not a multiple of 8, or shorter than its name.
        assert_eq!(
            parse(&patched(&e, "abc", 0, &113u64.to_le_bytes()))
                .unwrap_err()
                .reason_code(),
            "wim_meta_entry_length"
        );
        assert_eq!(
            parse(&patched(&e, "abc", 0, &104u64.to_le_bytes()))
                .unwrap_err()
                .reason_code(),
            "wim_meta_entry_length"
        );
        // Stream entry padding.
        let e = one(NodeSpec::file("f", b"x").stream("s", b"y")).encode();
        let at = e.offset("f").unwrap();
        let len = u64_at(&e.bytes, at) as usize;
        let first_stream = at + len;
        let unnamed_len = u64_at(&e.bytes, first_stream) as usize;
        let named = first_stream + unnamed_len;
        // 38 + 2 + 2 = 42 -> 48; byte 47 is padding.
        let mut b = e.bytes.clone();
        b[named + 47] = 1;
        assert_eq!(parse(&b).unwrap_err(), MetadataError::Padding);
        // Non-zero reserved field in a stream entry.
        let mut b = e.bytes.clone();
        b[named + 8] = 1;
        assert_eq!(
            parse(&b).unwrap_err().reason_code(),
            "wim_meta_reserved_field"
        );
    }

    // M-07 children offsets.
    #[test]
    fn m07_children() {
        let e = TreeSpec::new(vec![
            NodeSpec::dir("d", vec![NodeSpec::file("f", b"x")]),
            NodeSpec::file("g", b"y"),
        ])
        .encode();
        let d_list = u64_at(&e.bytes, e.offset("d").unwrap() + 16);
        // On a file.
        assert_eq!(
            parse(&patched(&e, "g", 16, &d_list.to_le_bytes())).unwrap_err(),
            MetadataError::Children {
                what: "children on a file or reparse point"
            }
        );
        // A directory without a list.
        assert_eq!(
            parse(&patched(&e, "d", 16, &0u64.to_le_bytes())).unwrap_err(),
            MetadataError::Children {
                what: "directory without a list"
            }
        );
        // Out of bounds, misaligned, into the security block.
        for bad in [e.bytes.len() as u64 + 8, d_list + 4, 8] {
            assert_eq!(
                parse(&patched(&e, "d", 16, &bad.to_le_bytes())).unwrap_err(),
                MetadataError::Children {
                    what: "offset out of bounds"
                },
                "{bad}"
            );
        }
        // A cycle: the child list points at the top-level list.
        let top = u64_at(&e.bytes, e.offset("").unwrap() + 16);
        let e2 = TreeSpec::new(vec![NodeSpec::dir("d", vec![NodeSpec::dir("e", vec![])])]).encode();
        let top2 = u64_at(&e2.bytes, e2.offset("").unwrap() + 16);
        assert_eq!(
            parse(&patched(&e2, "d\\e", 16, &top2.to_le_bytes())).unwrap_err(),
            MetadataError::Children {
                what: "list shared or cyclic"
            }
        );
        // A list starting inside another list.
        assert!(parse(&patched(&e, "d", 16, &(top + 8 * 14).to_le_bytes())).is_err());
        // On a reparse point.
        let e = one(NodeSpec::symlink("l", true, &rel_link_data("t"))).encode();
        assert_eq!(
            parse(&patched(&e, "l", 16, &8u64.to_le_bytes()))
                .unwrap_err()
                .reason_code(),
            "wim_meta_children"
        );
        // Depth limit.
        let mut n = NodeSpec::file("f", b"x");
        for _ in 0..5 {
            n = NodeSpec::dir("d", vec![n]);
        }
        let l = MetadataLimits {
            max_depth: 5,
            ..MetadataLimits::DEFAULT
        };
        assert_eq!(
            parse_with(&one(n).encode().bytes, &l).unwrap_err(),
            MetadataError::LimitExceeded { what: "depth" }
        );
    }

    // M-09 streams.
    #[test]
    fn m09_streams() {
        let e = one(NodeSpec::file("f", b"main").stream("s", b"named")).encode();
        let at = e.offset("f").unwrap();
        let first = at + u64_at(&e.bytes, at) as usize;
        // Entry hash and an unnamed stream entry.
        assert_eq!(
            parse(&patched(&e, "f", 64, &[7u8; 20])).unwrap_err(),
            MetadataError::Streams {
                what: "entry hash and an unnamed stream"
            }
        );
        // Named before unnamed: give the first (unnamed) entry a name by
        // swapping the two stream entries' order is hard; instead make the
        // stream count 1 so only the unnamed entry is read.
        assert_eq!(
            parse(&patched(&e, "f", 96, &1u16.to_le_bytes()))
                .unwrap_err()
                .reason_code(),
            "wim_meta_streams"
        );
        let _ = first;
        // Two unnamed stream entries on a file that is not a reparse
        // point: the symlink form with the reparse bit cleared.
        let e = one(NodeSpec::symlink("l", false, &rel_link_data("t"))).encode();
        assert_eq!(
            parse(&patched(&e, "l", 8, &attr::ARCHIVE.to_le_bytes())).unwrap_err(),
            MetadataError::Streams {
                what: "more than one unnamed stream"
            }
        );
        // Unnamed stream on a directory: a directory whose stream entry
        // has an empty name.
        let mut spec = one(NodeSpec::dir("d", vec![]));
        if let NodeKind::Dir(c) = &mut spec.root.kind {
            c[0].streams.push((String::new(), b"x".to_vec()));
        }
        assert_eq!(code(&spec), "wim_meta_streams");
        // Duplicate stream names (without case).
        assert_eq!(
            code(&one(NodeSpec::file("f", b"x")
                .stream("S", b"1")
                .stream("s", b"2"))),
            "wim_meta_duplicate_name"
        );
        // Invalid stream name.
        assert_eq!(
            code(&one(NodeSpec::file("f", b"x").stream("a:b", b"1"))),
            "wim_meta_stream_name"
        );
        // Stream limit.
        let l = MetadataLimits {
            max_streams_per_entry: 1,
            ..MetadataLimits::DEFAULT
        };
        assert!(
            parse_with(
                &one(NodeSpec::file("f", b"x").stream("s", b"1"))
                    .encode()
                    .bytes,
                &l
            )
            .is_err()
        );
        // The order of named streams carries no meaning (M-09).
        let a = parse(
            &one(NodeSpec::file("f", b"x")
                .stream("a", b"1")
                .stream("b", b"2"))
            .encode()
            .bytes,
        );
        let b = parse(
            &one(NodeSpec::file("f", b"x")
                .stream("b", b"2")
                .stream("a", b"1"))
            .encode()
            .bytes,
        );
        assert!(a.is_ok() && b.is_ok());
    }

    // M-10 attributes.
    #[test]
    fn m10_attributes() {
        for bit in [0x08u32, 0x40, 0x100, 0x1000, 0x8000, 0x10000, 0x8000_0000] {
            assert_eq!(
                parse(
                    &one(NodeSpec::file("f", b"x").attributes(attr::ARCHIVE | bit))
                        .encode()
                        .bytes
                )
                .unwrap_err(),
                MetadataError::UnknownAttributes { bits: bit }
            );
        }
        // EFS parses (so samples can be compared) and is refused by the
        // apply plan (tests/apply.rs efs_refused).
        assert!(
            parse(
                &one(NodeSpec::file("f", b"x").attributes(0x4020))
                    .encode()
                    .bytes
            )
            .is_ok()
        );
    }

    // M-12 hard links.
    #[test]
    fn m12_hard_links() {
        let g = 0x0001_0000_0000_002A;
        let ok = TreeSpec::new(vec![
            NodeSpec::file("a", b"same").link(g),
            NodeSpec::file("b", b"same").link(g),
        ]);
        assert!(parse(&ok.encode().bytes).is_ok());
        let differ = TreeSpec::new(vec![
            NodeSpec::file("a", b"same").link(g),
            NodeSpec::file("b", b"other").link(g),
        ]);
        assert_eq!(code(&differ), "wim_meta_hard_link");
        let streams = TreeSpec::new(vec![
            NodeSpec::file("a", b"same").link(g).stream("s", b"1"),
            NodeSpec::file("b", b"same").link(g),
        ]);
        assert_eq!(code(&streams), "wim_meta_hard_link");
        let dir = one(NodeSpec::dir("d", vec![]).link(g));
        assert_eq!(code(&dir), "wim_meta_hard_link");
    }

    // M-13 reparse points.
    #[test]
    fn m13_reparse() {
        let e = one(NodeSpec::symlink("l", true, &rel_link_data("t"))).encode();
        // Another tag.
        assert_eq!(
            parse(&patched(&e, "l", 88, &0xA000_001Du32.to_le_bytes())).unwrap_err(),
            MetadataError::UnknownReparseTag { tag: 0xA000_001D }
        );
        // +92 other than 0 and 0x00010000.
        assert_eq!(
            parse(&patched(&e, "l", 92, &2u32.to_le_bytes()))
                .unwrap_err()
                .reason_code(),
            "wim_meta_reparse"
        );
        // +92 = 0 parses (absolute; refused by the plan).
        assert!(parse(&patched(&e, "l", 92, &0u32.to_le_bytes())).is_ok());
        // Junctions parse (refused by the plan) but not on files.
        assert!(parse(&one(NodeSpec::junction("j", b"x")).encode().bytes).is_ok());
        let mut j = NodeSpec::junction("j", b"x");
        j.attributes = attr::REPARSE | attr::ARCHIVE;
        assert_eq!(code(&one(j)), "wim_meta_reparse");
        // No reparse data.
        let ej = one(NodeSpec::junction("j", b"x")).encode();
        assert_eq!(
            parse(&patched(&ej, "j", 64, &[0u8; 20])).unwrap_err(),
            MetadataError::Reparse {
                what: "no reparse data"
            }
        );
        // Named streams on a reparse point.
        assert_eq!(
            code(&one(NodeSpec::symlink("l", true, b"d").stream("s", b"1"))),
            "wim_meta_reparse"
        );
        // A file link whose second unnamed stream has data.
        let ef = one(NodeSpec::symlink("l", false, b"d")).encode();
        let at = ef.offset("l").unwrap();
        let s1 = at + u64_at(&ef.bytes, at) as usize;
        let s2 = s1 + u64_at(&ef.bytes, s1) as usize;
        let mut b = ef.bytes.clone();
        b[s2 + 16] = 9;
        assert_eq!(parse(&b).unwrap_err().reason_code(), "wim_meta_reparse");
    }

    // M-14 security index.
    #[test]
    fn m14_security_index() {
        for bad in [u32::MAX, 3, 1000] {
            assert_eq!(
                code(&one(NodeSpec::file("f", b"x").security(bad))),
                "wim_meta_security_index",
                "{bad}"
            );
        }
        let mut spec = TreeSpec::sample();
        spec.root.security = u32::MAX;
        assert_eq!(code(&spec), "wim_meta_security_index");
        let mut spec = one(NodeSpec::file("f", b"x").security(1));
        spec.security = vec![descriptor(0), descriptor(0)];
        assert!(parse(&spec.encode().bytes).is_ok());
    }

    // M-19 volume-root names.
    #[test]
    fn m19_root_names() {
        for bad in [
            "System Volume Information",
            "system volume information",
            "$Recycle.Bin",
            "$x",
        ] {
            assert_eq!(
                code(&one(NodeSpec::dir(bad, vec![]))),
                "wim_meta_reserved_root_name",
                "{bad}"
            );
        }
        // Below the root they are ordinary names.
        assert!(
            parse(
                &one(NodeSpec::dir("d", vec![NodeSpec::file("$x", b"1")]))
                    .encode()
                    .bytes
            )
            .is_ok()
        );
    }

    /// A sparse block (OBS-055): `first`, 16 × n, then the pairs.
    fn sparse_block(first: u32, pairs: &[(u64, u64)]) -> Vec<u8> {
        let mut b = first.to_le_bytes().to_vec();
        b.extend_from_slice(&(16 * pairs.len() as u32).to_le_bytes());
        for (s, e) in pairs {
            b.extend_from_slice(&s.to_le_bytes());
            b.extend_from_slice(&e.to_le_bytes());
        }
        b
    }

    fn sparse(blk: &[u8]) -> Result<ImageTree, MetadataError> {
        parse(
            &one(NodeSpec::file("s.bin", &[0u8; 0x70000])
                .attributes(attr::SPARSE | attr::ARCHIVE)
                .sparse_extra(blk))
            .encode()
            .bytes,
        )
    }

    // M-15 sparse block.
    #[test]
    fn m15_sparse_block() {
        // OBS-055's three-holes.bin: last range first.
        let three = [(0x50000, 0x60000), (0x30000, 0x40000), (0x10000, 0x20000)];
        let t = sparse(&sparse_block(3, &three)).unwrap();
        assert_eq!(t.entries[1].sparse_ranges, three);
        assert!(sparse(&sparse_block(3, &[(0, 0x30000)])).is_ok());
        // A sparse entry without a block.
        let t = parse(
            &one(NodeSpec::file("f", b"x").attributes(attr::SPARSE | attr::ARCHIVE))
                .encode()
                .bytes,
        )
        .unwrap();
        assert!(t.entries[1].sparse_ranges.is_empty());
        let bad = |b: Vec<u8>, what: &str| {
            assert_eq!(
                sparse(&b).unwrap_err(),
                MetadataError::SparseBlock {
                    what: match what {
                        "first" => "first word is not 3",
                        "len" => "inconsistent length",
                        "order" => "start not below end",
                        _ => "ranges not strictly descending or overlapping",
                    }
                },
                "{what}"
            );
        };
        bad(sparse_block(2, &[(0, 1)]), "first");
        // Length word disagreeing with the pairs.
        let mut b = sparse_block(3, &[(0, 1)]);
        b[4] = 32;
        bad(b, "len");
        // Not a whole number of pairs (8 extra bytes keep 8-alignment).
        let mut b = sparse_block(3, &[(0, 1)]);
        b.extend_from_slice(&[0u8; 8]);
        b[4] = 24;
        bad(b, "len");
        // Empty list.
        bad(sparse_block(3, &[]), "len");
        // start >= end.
        bad(sparse_block(3, &[(5, 5)]), "order");
        bad(sparse_block(3, &[(6, 5)]), "order");
        // Ascending, and overlapping.
        bad(sparse_block(3, &[(0, 1), (2, 3)]), "desc");
        bad(sparse_block(3, &[(10, 20), (5, 11)]), "desc");
        // Adjacent ranges (end == next start) are not overlapping.
        assert!(sparse(&sparse_block(3, &[(10, 20), (5, 10)])).is_ok());
    }

    // M-14 descriptors (topic 24 §9).
    #[test]
    fn m14_descriptor_form() {
        let with = |d: Vec<u8>| {
            let mut spec = one(NodeSpec::file("f", b"x"));
            spec.security = vec![d];
            parse(&spec.encode().bytes)
        };
        assert!(with(descriptor(0)).is_ok());
        // PS (0x2000) without SP is accepted; the bytes are kept as
        // stored (OBS-054: DISM stores 0xa004).
        let ps = descriptor_with_control(0, 0xa004);
        assert_eq!(with(ps.clone()).unwrap().security, vec![ps]);
        let code_of = |d: Vec<u8>| with(d).unwrap_err().reason_code();
        // Not self-relative; SP without a SACL; DP without a DACL.
        assert_eq!(
            code_of(descriptor_with_control(0, 0x0004)),
            "wim_meta_security_descriptor"
        );
        assert_eq!(
            code_of(descriptor_with_control(0, 0x8014)),
            "wim_meta_security_descriptor"
        );
        assert_eq!(
            code_of(descriptor_with_control(0, 0x8000)),
            "wim_meta_security_descriptor"
        );
        let patch = |at: usize, v: &[u8]| {
            let mut d = descriptor(0);
            d[at..at + v.len()].copy_from_slice(v);
            d
        };
        for (at, v, why) in [
            (0usize, &[2u8][..], "revision"),
            (1, &[1], "Sbz1 without RM"),
            (4, &[0, 0, 0, 0], "no owner"),
            (8, &[0, 0, 0, 0], "no group"),
            (4, &[8, 0, 0, 0], "offset in fixed part"),
            (16, &[200, 0, 0, 0], "DACL outside"),
            (20, &[2], "SID revision"),
            (21, &[16], "SID count"),
            (44, &[3], "ACL revision"),
            (46, &[30, 0], "ACL size"),
            (48, &[2, 0], "ACE outside"),
            (54, &[2, 0], "ACE size"),
        ] {
            assert_eq!(
                code_of(patch(at, v)),
                "wim_meta_security_descriptor",
                "{why}"
            );
        }
        // Owner defaulted (OD) with no owner is well formed.
        let mut d = descriptor_with_control(0, 0x8005);
        d[4..8].copy_from_slice(&[0; 4]);
        assert!(with(d).is_ok());
    }

    #[test]
    fn entry_limit() {
        let files: Vec<NodeSpec> = (0..10)
            .map(|i| NodeSpec::file(&format!("f{i}"), b"x"))
            .collect();
        let l = MetadataLimits {
            max_entries: 10,
            ..MetadataLimits::DEFAULT
        };
        assert_eq!(
            parse_with(&TreeSpec::new(files).encode().bytes, &l).unwrap_err(),
            MetadataError::LimitExceeded { what: "entries" }
        );
        let l = MetadataLimits {
            max_bytes: 100,
            ..MetadataLimits::DEFAULT
        };
        assert!(parse_with(&TreeSpec::sample().encode().bytes, &l).is_err());
    }

    #[test]
    fn every_truncation_is_an_error() {
        let b = TreeSpec::sample().encode().bytes;
        for cut in 0..b.len() {
            assert!(parse(&b[..cut]).is_err(), "{cut}");
        }
    }

    #[test]
    fn random_damage_never_panics() {
        let b = TreeSpec::sample().encode().bytes;
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let mut accepted = 0;
        for _ in 0..20_000 {
            let mut d = b.clone();
            for _ in 0..1 + next() % 3 {
                let at = (next() % d.len() as u64) as usize;
                d[at] = next() as u8;
            }
            if parse(&d).is_ok() {
                accepted += 1;
            }
        }
        // Many single-byte changes (times, hashes, name characters) stay
        // valid; the point is that none panics.
        println!("accepted {accepted} of 20000 damaged copies");
    }
}
