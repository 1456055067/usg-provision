//! Applying synthetic images (plan WU-4, §10.1): the testkit builder's
//! trees applied through the verified chunk reader into `MemorySink` and
//! `DirSink`, the apply order, and a named refusal for every rule of the
//! M-01 to M-23 contract (`findings-boot-obs.md`, "What WU-4 may rely
//! on") that a synthetic file can show.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-7, SI-10,
//   SI-11
// - SPEC: specs/preinstall-env.md#REQ-PE-016, #REQ-PE-017
// - SPEC: specs/standards/wim.md §4, §6, §6.1
#![cfg(feature = "testkit")]

#[cfg(test)]
mod apply {
    use std::collections::HashMap;
    use std::ops::ControlFlow;

    use usgp_image::Compression;
    use usgp_image::apply::{
        ApplyContext, ApplyError, ApplyLimits, ApplyPlan, ApplyPreview, ApplyReport, ApplyRoot,
        ApplySink, DirSink, DirSinkGap, MemoryNodeKind, MemorySink, ReparseError, SinkOp,
        XmlCounts, apply, verify_pass,
    };
    use usgp_image::testkit::tree::{
        NodeKind, abs_link_data, descriptor, link_data, rel_link_data,
    };
    use usgp_image::testkit::{BuildInfo, MemoryChunks, NodeSpec, TreeSpec, WimBuilder};
    use usgp_image::wim::metadata::{MetadataError, attr, tag};
    use usgp_image::wim::names::ImagePath;
    use usgp_image::wim::reparse::prepare;
    use usgp_image::wim::reshdr::ResourceHeader;
    use usgp_image::{NoProgress, WimError};

    fn build(c: Compression, tree: TreeSpec) -> (Vec<u8>, BuildInfo) {
        WimBuilder::new(c)
            .tree_image("img", "desc", tree)
            .build()
            .unwrap()
    }

    fn limits() -> ApplyLimits {
        ApplyLimits::new(1 << 30)
    }

    /// The apply root used by these tests.
    fn root() -> ApplyRoot {
        ApplyRoot::parse("W:\\").unwrap()
    }

    fn ctx() -> ApplyContext {
        ApplyContext {
            header_flags: 0x80,
            root: root(),
        }
    }

    fn known(e: &ApplyError) {
        let c = e.reason_code();
        assert!(
            ApplyError::REASON_CODES.contains(&c)
                || WimError::REASON_CODES.contains(&c)
                || MetadataError::REASON_CODES.contains(&c)
                || ReparseError::REASON_CODES.contains(&c),
            "{e:?}"
        );
        assert!(!e.operator_message().is_empty());
    }

    fn verify_with(b: &[u8], index: u32, l: &ApplyLimits) -> Result<ApplyPreview, ApplyError> {
        let mut src = MemoryChunks::new(b.to_vec());
        let r = verify_pass(
            &mut src,
            index,
            &root(),
            l,
            &mut NoProgress,
            usgp_crypto::provider(),
        );
        if let Err(e) = &r {
            known(e);
        }
        r
    }

    fn apply_with(
        src: &mut MemoryChunks,
        index: u32,
        l: &ApplyLimits,
    ) -> (Result<ApplyReport, ApplyError>, MemorySink) {
        let mut sink = MemorySink::new();
        let r = apply(
            src,
            index,
            &root(),
            &mut sink,
            l,
            &mut NoProgress,
            usgp_crypto::provider(),
        );
        if let Err(e) = &r {
            known(e);
        }
        (r, sink)
    }

    fn apply_mem(b: &[u8]) -> (Result<ApplyReport, ApplyError>, MemorySink) {
        apply_with(&mut MemoryChunks::new(b.to_vec()), 1, &limits())
    }

    fn p(s: &str) -> ImagePath {
        ImagePath::parse(s).unwrap()
    }

    /// Checks every node of `spec` against the sink (REQ-PE-017 on
    /// synthetic trees).
    fn assert_matches(spec: &TreeSpec, sink: &MemorySink) {
        let mut stack = vec![(String::new(), &spec.root)];
        let mut paths = 0usize;
        let mut first_link: HashMap<u64, ImagePath> = HashMap::new();
        while let Some((path, n)) = stack.pop() {
            paths += 1;
            let ip = p(&path);
            let node = sink.node(&ip).unwrap_or_else(|| panic!("{path} missing"));
            assert_eq!(
                node.security.as_deref(),
                spec.security.get(n.security as usize).map(Vec::as_slice),
                "{path} descriptor"
            );
            let [c, a, w] = n.times;
            let t = node.times.unwrap_or_else(|| panic!("{path} times"));
            assert_eq!(
                (t.creation, t.last_access, t.last_write),
                (c, a, w),
                "{path}"
            );
            if path.is_empty() {
                // M-19: the root's attributes are not set (unspecified).
                assert_eq!(node.attributes, None);
            } else {
                assert_eq!(node.attributes.map(|a| a.0), Some(n.attributes), "{path}");
            }
            assert_eq!(
                sink.short_name(&ip).map(|s| s.as_str().to_owned()),
                n.short_name,
                "{path} short name"
            );
            let streams: Vec<(String, Vec<u8>)> = node
                .streams
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let mut want = n.streams.clone();
            want.sort();
            assert_eq!(streams, want, "{path} streams");
            if n.link != 0 {
                let first = first_link.entry(n.link).or_insert_with(|| ip.clone());
                assert!(sink.same_node(first, &ip), "{path} not linked");
            }
            match &n.kind {
                NodeKind::Dir(children) => {
                    assert_eq!(node.kind, MemoryNodeKind::Dir, "{path}");
                    for ch in children {
                        let cp = if path.is_empty() {
                            ch.name.clone()
                        } else {
                            format!("{path}\\{}", ch.name)
                        };
                        stack.push((cp, ch));
                    }
                }
                NodeKind::File(d) => {
                    assert_eq!(node.kind, MemoryNodeKind::File, "{path}");
                    assert_eq!(&node.data, d, "{path} data");
                    assert_eq!(node.reparse, None);
                }
                NodeKind::Symlink {
                    directory,
                    data,
                    field_92,
                } => {
                    let k = if *directory {
                        MemoryNodeKind::Dir
                    } else {
                        MemoryNodeKind::File
                    };
                    assert_eq!(node.kind, k, "{path}");
                    // M-13: copied or re-based by decision 0022.
                    let want = prepare(0x80, tag::SYMLINK, *field_92, data, &root()).unwrap();
                    assert_eq!(node.reparse.as_ref(), Some(&want), "{path}");
                    assert_eq!(want.rebased(), *field_92 == 0, "{path}");
                }
                NodeKind::Junction { data, field_92 } => {
                    assert_eq!(node.kind, MemoryNodeKind::Dir, "{path}");
                    let want = prepare(0x80, tag::JUNCTION, *field_92, data, &root()).unwrap();
                    assert_eq!(node.reparse.as_ref(), Some(&want), "{path}");
                }
            }
        }
        assert_eq!(sink.entries().count(), paths, "extra paths in the sink");
    }

    #[test]
    fn synthetic_tree_roundtrip() {
        for c in [Compression::None, Compression::Xpress] {
            let spec = TreeSpec::sample();
            let (b, _) = build(c, spec.clone());
            let preview = verify_with(&b, 1, &limits()).unwrap();
            assert_eq!(preview.xml_counts, XmlCounts::Match);
            let (r, sink) = apply_mem(&b);
            let report = r.unwrap();
            assert_eq!(report.preview, preview);
            assert_matches(&spec, &sink);
            // Hard links counted once, duplicates in full.
            let linked = b"three names, one file\n".len() as u64;
            let copy = b"same content in two places\n".len() as u64 * 10;
            assert!(preview.total_bytes >= linked + 2 * copy);
            assert_eq!(report.bytes_written, preview.total_bytes, "{c:?}");
        }
    }

    #[test]
    fn sibling_order_does_not_matter() {
        // M-17: the reader does not rely on sibling order (OBS-042).
        let mut spec = TreeSpec::sample();
        if let NodeKind::Dir(c) = &mut spec.root.kind {
            c.reverse();
        }
        let (b, _) = build(Compression::Xpress, spec.clone());
        let (r, sink) = apply_mem(&b);
        r.unwrap();
        assert_matches(&spec, &sink);
    }

    #[test]
    fn large_directory_and_many_chunk_metadata() {
        // M-17: 3000 entries in one directory; metadata over many chunks.
        let files: Vec<NodeSpec> = (0..3000)
            .map(|i| NodeSpec::file(&format!("f-{i:04}.txt"), format!("{i}\n").as_bytes()))
            .collect();
        let spec = TreeSpec::new(vec![NodeSpec::dir("many", files)]);
        let (b, info) = build(Compression::Xpress, spec.clone());
        assert!(info.metadata[0].original_size > 4 * 32768);
        assert!(info.metadata[0].is_compressed());
        let (r, sink) = apply_mem(&b);
        r.unwrap();
        assert_matches(&spec, &sink);
    }

    #[test]
    fn long_paths_within_the_limit() {
        // M-16: components are single entries; the full path is ours.
        let name = "d".repeat(100);
        let mut node = NodeSpec::file(&"f".repeat(100), b"deep\n");
        for _ in 0..6 {
            node = NodeSpec::dir(&name, vec![node]);
        }
        let (b, _) = build(Compression::None, TreeSpec::new(vec![node]));
        apply_mem(&b).0.unwrap();
        let mut l = limits();
        l.metadata.max_path_units = 300;
        assert_eq!(
            verify_with(&b, 1, &l).unwrap_err().reason_code(),
            "wim_meta_limit_exceeded"
        );
    }

    #[test]
    fn only_chosen_index_applied() {
        let a = TreeSpec::new(vec![NodeSpec::file("only-in-one.txt", b"one\n")]);
        let bt = TreeSpec::new(vec![NodeSpec::file("only-in-two.txt", b"two\n")]);
        let (b, _) = WimBuilder::new(Compression::Xpress)
            .tree_image("one", "d", a)
            .tree_image("two", "d", bt.clone())
            .build()
            .unwrap();
        let (r, sink) = apply_with(&mut MemoryChunks::new(b.clone()), 2, &limits());
        r.unwrap();
        assert_matches(&bt, &sink);
        for bad in [0, 3] {
            assert_eq!(
                verify_with(&b, bad, &limits()).unwrap_err(),
                ApplyError::ImageIndex {
                    index: bad,
                    image_count: 2
                }
            );
        }
    }

    #[test]
    fn apply_order() {
        let (b, _) = build(Compression::Xpress, TreeSpec::sample());
        let (r, sink) = apply_mem(&b);
        r.unwrap();
        let ops = sink.ops();
        let pos = |op: SinkOp| ops.iter().position(|(o, _)| *o == op).unwrap();
        let last = |op: SinkOp| ops.iter().rposition(|(o, _)| *o == op).unwrap();
        // Directories top-down, then files, data, links, reparse,
        // security, short names, attributes and times.
        assert!(last(SinkOp::CreateDir) < pos(SinkOp::CreateFile));
        assert!(last(SinkOp::CreateFile) < pos(SinkOp::Write));
        assert!(last(SinkOp::Write) < pos(SinkOp::HardLink));
        assert!(last(SinkOp::HardLink) < pos(SinkOp::SetReparse));
        assert!(last(SinkOp::SetReparse) < pos(SinkOp::SetSecurity));
        assert!(last(SinkOp::SetSecurity) < pos(SinkOp::SetShortName));
        assert!(last(SinkOp::SetShortName) < pos(SinkOp::SetAttributes));
        // Directories bottom-up: a directory's attributes come after those
        // of everything below it.
        let attrs: Vec<&ImagePath> = ops
            .iter()
            .filter(|(o, _)| *o == SinkOp::SetAttributes)
            .map(|(_, p)| p)
            .collect();
        for (i, a) in attrs.iter().enumerate() {
            for later in &attrs[i + 1..] {
                let below = later.components().len() > a.components().len()
                    && later.components().starts_with(a.components());
                assert!(!below, "{later:?} after its ancestor {a:?}");
            }
        }
        // The root's times are the last operation.
        assert_eq!(
            ops.last().map(|(o, p)| (*o, p.is_root())),
            Some((SinkOp::SetTimes, true))
        );
    }

    #[test]
    fn raw_chunks_at_any_position() {
        // M-21, OBS-046: chunks stored at 32768 bytes are raw, first,
        // last, in the middle and consecutive (as S14 entry 3030).
        let text = b"compressible text ".repeat(2000);
        let rand = |s| usgp_image::testkit::builder::pseudorandom(32768, s);
        let mut data = Vec::new();
        data.extend_from_slice(&rand(1));
        data.extend_from_slice(&rand(2));
        data.extend_from_slice(&text[..32768]);
        data.extend_from_slice(&rand(3));
        data.extend_from_slice(&text[..32768]);
        data.extend_from_slice(&rand(4));
        data.extend_from_slice(&text[..1000]);
        // OBS-057: a short final chunk that did not shrink (S17B shape).
        let mut tail = text[..32768].to_vec();
        tail.extend_from_slice(&usgp_image::testkit::builder::pseudorandom(5000, 9));
        let spec = TreeSpec::new(vec![
            NodeSpec::file("mixed.bin", &data),
            NodeSpec::file("short-tail.bin", &tail),
        ]);
        let (b, info) = WimBuilder::new(Compression::Xpress)
            .raw_chunks(true)
            .tree_image("img", "d", spec.clone())
            .build()
            .unwrap();
        for len in [data.len(), tail.len()] {
            let f = info
                .files
                .iter()
                .find(|r| r.original_size == len as u64)
                .unwrap();
            assert!(f.is_compressed(), "resource stored compressed");
        }
        let (r, sink) = apply_mem(&b);
        r.unwrap();
        assert_matches(&spec, &sink);
        // The M2 upload check still counts them, not refuses them.
        let s = usgp_image::check_wim(
            &mut std::io::Cursor::new(&b),
            b.len() as u64,
            &usgp_image::WimLimits::DEFAULT,
            usgp_crypto::provider(),
            &mut NoProgress,
        )
        .unwrap();
        assert_eq!(s.raw_sized_file_chunks, 5);
    }

    #[test]
    fn dir_sink_applies_portable_parts() {
        let dir = std::env::temp_dir().join(format!(
            "usgp-image-dirsink-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        let (b, _) = build(Compression::Xpress, TreeSpec::sample());
        let mut sink = DirSink::new(&dir).unwrap();
        // A second sink on a non-empty root is refused.
        std::fs::write(dir.join("x"), b"x").unwrap();
        assert!(DirSink::new(&dir).is_err());
        std::fs::remove_file(dir.join("x")).unwrap();
        apply(
            &mut MemoryChunks::new(b),
            1,
            &root(),
            &mut sink,
            &limits(),
            &mut NoProgress,
            usgp_crypto::provider(),
        )
        .unwrap();
        assert_eq!(std::fs::read(dir.join("readme.txt")).unwrap(), b"hello\n");
        assert_eq!(std::fs::read(dir.join("empty.txt")).unwrap(), b"");
        assert_eq!(
            std::fs::read(dir.join("links").join("sub").join("hard-three.txt")).unwrap(),
            b"three names, one file\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let a = std::fs::metadata(dir.join("links").join("hard-original.txt")).unwrap();
            let c = std::fs::metadata(dir.join("links").join("hard-two.txt")).unwrap();
            assert_eq!(a.ino(), c.ino());
            let m = std::fs::metadata(dir.join("big.txt")).unwrap();
            // FILETIME 3 is 300 ns after 1601-01-01; mtime is before 1970.
            assert!(m.mtime() < 0);
        }
        // Times, on every platform: a file's last write is applied
        // (TIMES[2] = 2023-01-01 00:00:00.1234567 UTC, OBS-034).
        let want = std::time::UNIX_EPOCH + std::time::Duration::new(1_672_531_200, 123_456_700);
        let file_mtime = std::fs::metadata(dir.join("readme.txt"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(file_mtime, want, "file last-write time");
        let u = sink.unsupported();
        assert!(u.contains(&(DirSinkGap::CreationTime, p("readme.txt"))));
        let links = p("links");
        if cfg!(windows) {
            // Directories are not opened on Windows: named gap, recorded.
            assert!(u.contains(&(DirSinkGap::DirectoryTimes, links.clone())));
            assert!(u.contains(&(DirSinkGap::DirectoryTimes, ImagePath::root())));
            assert!(!u.contains(&(DirSinkGap::DirectoryTimes, p("readme.txt"))));
        } else {
            // Directory times applied (bottom-up, after the children).
            let dir_mtime = std::fs::metadata(dir.join("links"))
                .unwrap()
                .modified()
                .unwrap();
            assert_eq!(dir_mtime, want, "directory last-write time");
            assert!(!u.iter().any(|(g, _)| *g == DirSinkGap::DirectoryTimes));
        }
        assert!(u.contains(&(DirSinkGap::Reparse, p("links\\sym-file-rel.txt"))));
        assert!(u.contains(&(DirSinkGap::Security, ImagePath::root())));
        assert!(u.contains(&(DirSinkGap::NamedStream, p("streams.txt"))));
        assert!(u.contains(&(DirSinkGap::ShortName, p("readme.txt"))));
        assert!(u.contains(&(DirSinkGap::Attributes, p("ro.txt"))));
        // No symbolic link is ever created.
        let l = std::fs::symlink_metadata(dir.join("links").join("sym-dir-rel")).unwrap();
        assert!(l.is_dir() && !l.file_type().is_symlink());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // ---- Product refusals at plan time (before any write). ----

    fn refused_before_any_write(spec: TreeSpec) -> ApplyError {
        let (b, _) = build(Compression::Xpress, spec);
        let v = verify_with(&b, 1, &limits()).unwrap_err();
        let (r, sink) = apply_mem(&b);
        assert_eq!(r.unwrap_err(), v);
        assert!(sink.ops().is_empty(), "sink touched before refusal");
        v
    }

    #[test]
    fn efs_refused() {
        // M-10, M-15, decision 0006 (OBS-040).
        let spec = TreeSpec::new(vec![
            NodeSpec::file("e.txt", b"x").attributes(attr::ENCRYPTED | attr::ARCHIVE),
        ]);
        assert_eq!(
            refused_before_any_write(spec),
            ApplyError::EncryptedNotSupported
        );
        let spec = TreeSpec::new(vec![
            NodeSpec::dir("d", vec![]).attributes(attr::DIRECTORY | attr::ENCRYPTED),
        ]);
        assert_eq!(
            refused_before_any_write(spec).reason_code(),
            "wim_efs_not_supported"
        );
    }

    #[test]
    fn links_and_junctions_copied_and_rebased_end_to_end() {
        // Decision 0022: rewritten (M = 0) links and junctions re-based
        // onto the apply root; others copied byte for byte.
        let spec = TreeSpec::new(vec![NodeSpec::dir(
            "links",
            vec![
                NodeSpec::file("target-file.txt", b"t\n"),
                NodeSpec::dir("target-dir", vec![]),
                NodeSpec::symlink(
                    "abs-file.txt",
                    false,
                    &abs_link_data("T:\\links\\target-file.txt", false),
                )
                .field_92(0),
                NodeSpec::symlink(
                    "abs-dir",
                    true,
                    &abs_link_data("T:\\links\\target-dir", false),
                )
                .field_92(0),
                NodeSpec::junction("junction", &abs_link_data("T:\\links\\target-dir", true))
                    .field_92(0),
                NodeSpec::junction("junction-out", &abs_link_data("T:\\outside-tree", true)),
                NodeSpec::symlink(
                    "abs-out.txt",
                    false,
                    &abs_link_data("Q:\\elsewhere\\x.txt", false),
                ),
                NodeSpec::symlink("rel-up.txt", false, &rel_link_data("..\\..\\x.txt")),
            ],
        )]);
        let (b, _) = build(Compression::Xpress, spec.clone());
        let (r, sink) = apply_mem(&b);
        r.unwrap();
        assert_matches(&spec, &sink);
        let j = sink
            .node(&p("links\\junction"))
            .unwrap()
            .reparse
            .clone()
            .unwrap();
        assert!(j.rebased());
        assert_eq!(j.tag(), tag::JUNCTION);
        assert_eq!(j.data(), abs_link_data("W:\\links\\target-dir", true));
        let out = sink
            .node(&p("links\\junction-out"))
            .unwrap()
            .reparse
            .clone()
            .unwrap();
        assert!(!out.rebased());
        assert_eq!(out.data(), abs_link_data("T:\\outside-tree", true));
        // Header rebuilt from the tag: length, Reserved 0.
        assert_eq!(&out.bytes()[..4], &tag::JUNCTION.to_le_bytes());
        assert_eq!(
            usize::from(u16::from_le_bytes([out.bytes()[4], out.bytes()[5]])),
            out.data().len()
        );
        assert_eq!(&out.bytes()[6..8], &[0, 0]);
    }

    #[test]
    fn rewritten_link_without_rp_fix_refused_before_any_write() {
        let spec = TreeSpec::new(vec![
            NodeSpec::symlink("abs", false, &abs_link_data("T:\\a", false)).field_92(0),
        ]);
        let (b, _) = WimBuilder::new(Compression::None)
            .header_flags(0)
            .tree_image("img", "d", spec)
            .build()
            .unwrap();
        let e = verify_with(&b, 1, &limits()).unwrap_err();
        assert_eq!(e, ApplyError::Reparse(ReparseError::RewrittenWithoutRpFix));
        let (r, sink) = apply_mem(&b);
        assert_eq!(r.unwrap_err(), e);
        assert!(sink.ops().is_empty());
        // Copied links need no RP_FIX.
        let spec = TreeSpec::new(vec![NodeSpec::symlink("rel", false, &rel_link_data("x"))]);
        let (b, _) = WimBuilder::new(Compression::None)
            .header_flags(0)
            .tree_image("img", "d", spec)
            .build()
            .unwrap();
        verify_with(&b, 1, &limits()).unwrap();
    }

    #[test]
    fn malformed_link_data_refused_by_the_verify_pass() {
        for (n, code) in [
            (
                NodeSpec::symlink("bad", false, b"short"),
                "wim_reparse_malformed",
            ),
            (
                NodeSpec::symlink("flags", false, &link_data("a", "a", Some(2))),
                "wim_reparse_symlink_flags",
            ),
            (
                NodeSpec::junction("dots", &link_data("\\??\\T:\\a\\..\\b", "x", None)),
                "wim_reparse_mount_point_dot_name",
            ),
            (
                NodeSpec::symlink("relrw", false, &rel_link_data("x")).field_92(0),
                "wim_reparse_rebase_relative",
            ),
        ] {
            let (b, _) = build(Compression::None, TreeSpec::new(vec![n]));
            assert_eq!(
                verify_with(&b, 1, &limits()).unwrap_err().reason_code(),
                code
            );
            let (r, sink) = apply_mem(&b);
            assert_eq!(r.unwrap_err().reason_code(), code);
            assert!(sink.ops().is_empty(), "{code}: written before refusal");
        }
    }

    #[test]
    fn sparse_range_beyond_the_file_refused() {
        // M-15: end beyond the file length.
        let mut blk = vec![3, 0, 0, 0, 16, 0, 0, 0];
        blk.extend_from_slice(&0u64.to_le_bytes());
        blk.extend_from_slice(&2000u64.to_le_bytes());
        let spec = TreeSpec::new(vec![
            NodeSpec::file("s.bin", &[0u8; 1000])
                .attributes(attr::SPARSE | attr::ARCHIVE)
                .sparse_extra(&blk),
        ]);
        let (b, _) = build(Compression::None, spec);
        assert_eq!(
            verify_with(&b, 1, &limits()).unwrap_err().reason_code(),
            "wim_meta_sparse_block"
        );
    }

    #[test]
    fn plan_refusals_from_resources() {
        let spec = TreeSpec::new(vec![NodeSpec::file("a.txt", b"content\n")]);
        let tree =
            usgp_image::wim::metadata::parse_metadata(&spec.encode().bytes, &Default::default())
                .unwrap();
        let hash = tree.entries[1].data.unwrap();
        // M-08: a non-zero hash without a lookup entry.
        assert_eq!(
            ApplyPlan::build(tree.clone(), &HashMap::new(), &limits(), &ctx()).unwrap_err(),
            ApplyError::ResourceMissing
        );
        // M-22: 8-byte tables above 2^32 are accepted (OBS-058); exactly
        // 2^32 is refused (threshold open).
        let big = ResourceHeader {
            stored_size: 1 << 20,
            flags: 0x04,
            offset: 208,
            original_size: 5 << 30,
        };
        let res = HashMap::from([(hash, big)]);
        assert!(ApplyPlan::build(tree.clone(), &res, &ApplyLimits::new(u64::MAX), &ctx()).is_ok());
        let exact = ResourceHeader {
            original_size: 1 << 32,
            ..big
        };
        let res = HashMap::from([(hash, exact)]);
        assert_eq!(
            ApplyPlan::build(tree.clone(), &res, &ApplyLimits::new(u64::MAX), &ctx()).unwrap_err(),
            ApplyError::ChunkTableWidthNotSupported
        );
        // Stored raw at the same size is fine; the target size is checked.
        let raw = ResourceHeader {
            flags: 0,
            stored_size: 5 << 30,
            ..big
        };
        let res = HashMap::from([(hash, raw)]);
        assert!(ApplyPlan::build(tree.clone(), &res, &ApplyLimits::new(u64::MAX), &ctx()).is_ok());
        assert_eq!(
            ApplyPlan::build(tree, &res, &ApplyLimits::new((5 << 30) - 1), &ctx()).unwrap_err(),
            ApplyError::LimitExceeded { what: "image size" }
        );
    }

    #[test]
    fn target_size_and_reparse_limits() {
        let (b, _) = build(Compression::Xpress, TreeSpec::sample());
        let need = verify_with(&b, 1, &limits()).unwrap().total_bytes;
        assert!(verify_with(&b, 1, &ApplyLimits::new(need)).is_ok());
        assert_eq!(
            verify_with(&b, 1, &ApplyLimits::new(need - 1)).unwrap_err(),
            ApplyError::LimitExceeded { what: "image size" }
        );
        let mut l = limits();
        l.max_reparse_bytes = 8;
        assert_eq!(
            verify_with(&b, 1, &l).unwrap_err(),
            ApplyError::LimitExceeded {
                what: "reparse data"
            }
        );
    }

    // ---- Content integrity (SI-7) ----

    #[test]
    fn tampered_chunk_fails_before_any_write() {
        let (b, info) = build(Compression::Xpress, TreeSpec::sample());
        for at in [0usize, info.files[0].offset as usize, b.len() - 1] {
            let mut src = MemoryChunks::new(b.clone());
            src.tamper(at);
            let (r, sink) = apply_with(&mut src, 1, &limits());
            assert_eq!(r.unwrap_err(), ApplyError::ContentIntegrity { chunk: 0 });
            assert!(sink.ops().is_empty());
            let mut src = MemoryChunks::new(b.clone());
            src.tamper(at);
            assert_eq!(
                verify_pass(
                    &mut src,
                    1,
                    &root(),
                    &limits(),
                    &mut NoProgress,
                    usgp_crypto::provider()
                )
                .unwrap_err(),
                ApplyError::ContentIntegrity { chunk: 0 }
            );
        }
        let mut src = MemoryChunks::new(b);
        src.make_unavailable(0);
        assert_eq!(
            apply_with(&mut src, 1, &limits()).0.unwrap_err(),
            ApplyError::ContentUnavailable { chunk: 0 }
        );
    }

    #[test]
    fn tamper_in_a_later_chunk_is_found_by_the_verify_pass() {
        // 9 MiB of pseudorandom data puts the file across two chunks.
        let big = usgp_image::testkit::builder::pseudorandom(9 << 20, 7);
        let spec = TreeSpec::new(vec![NodeSpec::file("big.bin", &big)]);
        let (b, _) = build(Compression::Xpress, spec);
        let mut src = MemoryChunks::new(b.clone());
        src.tamper((8 << 20) + 5);
        let e = verify_pass(
            &mut src,
            1,
            &root(),
            &limits(),
            &mut NoProgress,
            usgp_crypto::provider(),
        )
        .unwrap_err();
        assert_eq!(e, ApplyError::ContentIntegrity { chunk: 1 });
    }

    #[test]
    fn damaged_resource_refused_by_sha1() {
        // The chunk digests are taken after the damage (the signed
        // manifest matches), so only the WIM's own SHA-1 can see it.
        let (mut b, info) = build(Compression::None, TreeSpec::sample());
        let f = info.files[0];
        b[f.offset as usize] ^= 1;
        assert_eq!(
            verify_with(&b, 1, &limits()).unwrap_err(),
            ApplyError::ResourceHashMismatch
        );
    }

    #[test]
    fn progress_can_stop_the_pass() {
        let (b, _) = build(Compression::Xpress, TreeSpec::sample());
        let mut src = MemoryChunks::new(b);
        let mut n = 0u32;
        let mut stop = |_bytes: u64| {
            n += 1;
            if n > 3 {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        };
        let e = verify_pass(
            &mut src,
            1,
            &root(),
            &limits(),
            &mut stop,
            usgp_crypto::provider(),
        )
        .unwrap_err();
        assert_eq!(e, ApplyError::Wim(WimError::Stalled));
    }

    #[test]
    fn xml_counts_are_a_warning_only() {
        // M-23: DIRCOUNT and FILECOUNT never refuse; HARDLINKBYTES is never
        // read.
        let spec = TreeSpec::new(vec![NodeSpec::file("a.txt", b"a\n")]);
        let (b, _) = WimBuilder::new(Compression::None)
            .tree_image("img", "d", spec)
            .xml_text(
                "<WIM><IMAGE INDEX=\"1\"><DIRCOUNT>7</DIRCOUNT><FILECOUNT>1</FILECOUNT>\
                 <HARDLINKBYTES>999999</HARDLINKBYTES><NAME>img</NAME></IMAGE></WIM>",
            )
            .build()
            .unwrap();
        let v = verify_with(&b, 1, &limits()).unwrap();
        assert_eq!(
            v.xml_counts,
            XmlCounts::Mismatch {
                xml_dirs: Some(7),
                xml_files: Some(1),
                tree_dirs: 0,
                tree_files: 1
            }
        );
        apply_mem(&b).0.unwrap();
    }

    #[test]
    fn sink_failure_is_named_and_stops() {
        struct Fails(MemorySink);
        impl ApplySink for Fails {
            fn create_dir(&mut self, p: &ImagePath) -> usgp_image::apply::SinkResult {
                self.0.create_dir(p)
            }
            fn create_file(&mut self, p: &ImagePath) -> usgp_image::apply::SinkResult {
                self.0.create_file(p)
            }
            fn create_stream(
                &mut self,
                p: &ImagePath,
                s: &usgp_image::wim::names::StreamName,
            ) -> usgp_image::apply::SinkResult {
                self.0.create_stream(p, s)
            }
            fn write(
                &mut self,
                _p: &ImagePath,
                _s: Option<&usgp_image::wim::names::StreamName>,
                _o: u64,
                _d: &[u8],
            ) -> usgp_image::apply::SinkResult {
                Err(usgp_image::apply::SinkError::new(
                    SinkOp::Write,
                    std::io::ErrorKind::StorageFull,
                ))
            }
            fn hard_link(&mut self, a: &ImagePath, b: &ImagePath) -> usgp_image::apply::SinkResult {
                self.0.hard_link(a, b)
            }
            fn set_reparse(
                &mut self,
                p: &ImagePath,
                b: &usgp_image::apply::ReparseBuffer,
            ) -> usgp_image::apply::SinkResult {
                self.0.set_reparse(p, b)
            }
            fn set_security(&mut self, p: &ImagePath, sd: &[u8]) -> usgp_image::apply::SinkResult {
                self.0.set_security(p, sd)
            }
            fn set_short_name(
                &mut self,
                p: &ImagePath,
                n: &usgp_image::wim::names::ShortName,
            ) -> usgp_image::apply::SinkResult {
                self.0.set_short_name(p, n)
            }
            fn set_times(
                &mut self,
                p: &ImagePath,
                t: &usgp_image::wim::metadata::FileTimes,
            ) -> usgp_image::apply::SinkResult {
                self.0.set_times(p, t)
            }
            fn set_attributes(
                &mut self,
                p: &ImagePath,
                a: usgp_image::wim::metadata::Attributes,
            ) -> usgp_image::apply::SinkResult {
                self.0.set_attributes(p, a)
            }
        }
        let (b, _) = build(Compression::Xpress, TreeSpec::sample());
        let mut sink = Fails(MemorySink::new());
        let e = apply(
            &mut MemoryChunks::new(b),
            1,
            &root(),
            &mut sink,
            &limits(),
            &mut NoProgress,
            usgp_crypto::provider(),
        )
        .unwrap_err();
        assert_eq!(e.reason_code(), "apply_target_failed");
        assert!(
            !sink.0.ops().iter().any(|(o, _)| *o == SinkOp::HardLink),
            "continued after the failure"
        );
    }

    #[test]
    fn descriptors_are_applied_by_index() {
        // M-14: stored once, referenced by index.
        let mut spec = TreeSpec::new(vec![
            NodeSpec::file("a", b"a").security(2),
            NodeSpec::file("b", b"b").security(2),
            NodeSpec::file("c", b"c").security(1),
        ]);
        spec.security.push(descriptor(9));
        let (b, _) = build(Compression::None, spec.clone());
        let (r, sink) = apply_mem(&b);
        r.unwrap();
        assert_eq!(sink.node(&p("a")).unwrap().security, Some(descriptor(9)));
        assert_eq!(sink.node(&p("c")).unwrap().security, Some(descriptor(1)));
        assert_matches(&spec, &sink);
    }

    // ---- Robustness: random damage never panics. ----

    fn xorshift(s: &mut u64) -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }

    #[test]
    fn random_damage_to_a_whole_file_never_panics() {
        for c in [Compression::None, Compression::Xpress] {
            let (b, _) = build(c, TreeSpec::sample());
            let mut seed = 0x1234_5678_9abc_def0u64;
            let mut l = limits();
            l.max_total_bytes = 1 << 20;
            for _ in 0..300 {
                let mut d = b.clone();
                for _ in 0..1 + xorshift(&mut seed) % 4 {
                    let at = (xorshift(&mut seed) % d.len() as u64) as usize;
                    d[at] = xorshift(&mut seed) as u8;
                }
                let _ = verify_with(&d, 1, &l);
                let mut sink = MemorySink::with_limit(1 << 20);
                let _ = apply(
                    &mut MemoryChunks::new(d),
                    1,
                    &root(),
                    &mut sink,
                    &l,
                    &mut NoProgress,
                    usgp_crypto::provider(),
                );
            }
        }
    }

    #[test]
    fn every_truncation_of_a_whole_file_is_refused() {
        let (b, _) = build(Compression::None, TreeSpec::sample());
        for cut in (0..b.len()).step_by(97) {
            assert!(verify_with(&b[..cut], 1, &limits()).is_err(), "{cut}");
        }
    }
}
