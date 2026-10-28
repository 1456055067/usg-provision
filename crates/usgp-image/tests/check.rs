//! Accepted WIM files (plan §10 "WIM parser" row; WU-5): editions, many
//! images, integrity tables, PE image choice, progress and the rule that
//! the format's SHA-1 values are not the integrity control.
//!
//! Every file comes from our own `WimBuilder` (decision 0006).

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-7, SI-10
// - SPEC: specs/os-images.md#REQ-IMG-037, #REQ-IMG-040, #REQ-IMG-042,
//   #REQ-IMG-050, #REQ-IMG-051
// - SPEC: specs/preinstall-env.md#REQ-PE-004
#![cfg(feature = "testkit")]

#[cfg(test)]
mod check {
    use std::io::Cursor;
    use std::ops::ControlFlow;

    use usgp_image::chunks::ContentHasher;
    use usgp_image::testkit::{ImageSpec, WimBuilder, builder::pseudorandom};
    use usgp_image::{
        Compression, EditionInfo, NoProgress, WimError, WimLimits, WimSummary, check_pe, check_wim,
    };

    fn run(b: &[u8]) -> Result<WimSummary, WimError> {
        check_wim(
            &mut Cursor::new(b),
            u64::try_from(b.len()).unwrap(),
            &WimLimits::DEFAULT,
            usgp_crypto::provider(),
            &mut NoProgress,
        )
    }

    fn build(b: WimBuilder) -> Vec<u8> {
        b.build().unwrap().0
    }

    #[test]
    fn single_image_both_compressions() {
        for c in [Compression::None, Compression::Xpress] {
            let s = run(&build(WimBuilder::new(c).image("one", "first"))).unwrap();
            assert_eq!(s.image_count, 1);
            assert_eq!(s.compression, c);
            assert_eq!(s.boot_index, 0);
            assert!(!s.has_integrity_table);
            assert_eq!(s.version, 0x0001_0d00);
        }
    }

    #[test]
    fn editions_index_name_desc_size() {
        let s = run(&build(
            WimBuilder::new(Compression::Xpress)
                .image("Alpha & Co", "first <one>")
                .image("Beta", "second"),
        ))
        .unwrap();
        let first = s.editions.first().unwrap();
        assert_eq!(first.index, 1);
        assert_eq!(first.name, "Alpha & Co");
        assert_eq!(first.description, "first <one>");
        assert!(first.total_bytes.unwrap() > 40_000);
        assert_eq!(s.editions.get(1).unwrap().name, "Beta");
        assert_eq!(s.xml_image(2).unwrap().leaf("NAME"), Some("Beta"));
        assert!(s.xml_image(3).is_none());
    }

    #[test]
    fn twelve_images() {
        // REQ-IMG-042: more than 10 images, any can be chosen.
        let mut b = WimBuilder::new(Compression::Xpress);
        for i in 1..=12 {
            b = b.image(&format!("img-{i:02}"), &format!("description {i}"));
        }
        let s = run(&build(b)).unwrap();
        assert_eq!(s.image_count, 12);
        let idx: Vec<u32> = s.editions.iter().map(|e| e.index).collect();
        assert_eq!(idx, (1..=12).collect::<Vec<_>>());
        assert_eq!(s.editions.get(11).unwrap().name, "img-12");
    }

    #[test]
    fn missing_description_is_empty() {
        let s = run(&build(WimBuilder::new(Compression::None).image_spec(
            ImageSpec {
                name: "n".into(),
                description: None,
                files: vec![b"x".to_vec()],
            },
        )))
        .unwrap();
        assert_eq!(
            s.editions,
            vec![EditionInfo {
                index: 1,
                name: "n".into(),
                description: String::new(),
                total_bytes: Some(1),
            }]
        );
    }

    #[test]
    fn integrity_table_one_and_several_chunks() {
        for c in [Compression::None, Compression::Xpress] {
            let s = run(&build(WimBuilder::new(c).image("a", "b").integrity(true))).unwrap();
            assert!(s.has_integrity_table);
        }
        // 25 MiB of zeros: three 10 MiB integrity chunks, the last short.
        let (b, info) = WimBuilder::new(Compression::None)
            .image("a", "b")
            .zero_file(25 << 20)
            .integrity(true)
            .build()
            .unwrap();
        let t = info.integrity.unwrap();
        assert_eq!(t.stored_size, 12 + 3 * 20);
        assert!(run(&b).unwrap().has_integrity_table);
    }

    #[test]
    fn incompressible_resources_stored_raw_in_xpress_file() {
        // OBS-010: a resource that does not shrink has flag 0x04 clear.
        let (b, info) = WimBuilder::new(Compression::Xpress)
            .image_spec(ImageSpec {
                name: "r".into(),
                description: Some("raw".into()),
                files: vec![pseudorandom(70_000, 9), b"text ".repeat(10_000)],
            })
            .build()
            .unwrap();
        let flags: Vec<u8> = info.files.iter().map(|f| f.flags).collect();
        assert_eq!(flags, [0x00, 0x04]);
        assert!(info.metadata.iter().all(|m| m.flags == 0x06));
        run(&b).unwrap();
    }

    #[test]
    fn pe_single_image_ok() {
        let s = run(&build(
            WimBuilder::new(Compression::Xpress).image("pe", "pe"),
        ))
        .unwrap();
        assert_eq!(check_pe(&s), Ok(1));
    }

    #[test]
    fn pe_boot_index_names_one() {
        let s = run(&build(
            WimBuilder::new(Compression::Xpress)
                .image("a", "a")
                .image("b", "b")
                .boot_index(2),
        ))
        .unwrap();
        assert_eq!(s.boot_index, 2);
        assert_eq!(check_pe(&s), Ok(2));
    }

    #[test]
    fn pe_multi_no_boot_index_refused() {
        let s = run(&build(
            WimBuilder::new(Compression::None)
                .image("a", "a")
                .image("b", "b"),
        ))
        .unwrap();
        let e = check_pe(&s).unwrap_err();
        assert_eq!(e, WimError::PeNoUsableImage { image_count: 2 });
        assert_eq!(e.reason_code(), "pe_no_usable_image");
    }

    #[test]
    fn sha1_consistent_but_operator_digest_differs_refused() {
        // REQ-IMG-051: anyone can rewrite a WIM and recompute its SHA-1
        // values, so a changed file passes the format check. The product's
        // own SHA-256 (ContentHasher, compared with the operator's declared
        // digest at upload, plan §5.7) is what detects the change.
        let original = build(
            WimBuilder::new(Compression::Xpress)
                .image("a", "intended")
                .integrity(true),
        );
        let altered = build(
            WimBuilder::new(Compression::Xpress)
                .image("a", "tampered")
                .integrity(true),
        );
        run(&original).unwrap();
        run(&altered).unwrap();
        let digest = |b: &[u8]| {
            let mut h = ContentHasher::new(usgp_crypto::provider());
            h.update(b);
            h.finish().total
        };
        assert_ne!(digest(&original), digest(&altered));
    }

    #[test]
    fn progress_counts_and_can_stop() {
        let b = build(
            WimBuilder::new(Compression::Xpress)
                .image("a", "b")
                .integrity(true),
        );
        let mut total = 0u64;
        let mut count = |n: u64| {
            total += n;
            ControlFlow::Continue(())
        };
        check_wim(
            &mut Cursor::new(&b),
            u64::try_from(b.len()).unwrap(),
            &WimLimits::DEFAULT,
            usgp_crypto::provider(),
            &mut count,
        )
        .unwrap();
        assert!(total >= u64::try_from(b.len()).unwrap() / 2, "{total}");

        for stop_after in [0u64, 1, 3, 10] {
            let mut calls = 0u64;
            let mut stop = |_n: u64| {
                calls += 1;
                if calls > stop_after {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            };
            let r = check_wim(
                &mut Cursor::new(&b),
                u64::try_from(b.len()).unwrap(),
                &WimLimits::DEFAULT,
                usgp_crypto::provider(),
                &mut stop,
            );
            assert_eq!(r.unwrap_err(), WimError::Stalled);
        }
    }

    #[test]
    fn identical_metadata_at_distinct_ranges_accepted() {
        // BOOT-011: two images whose metadata content is identical (same
        // SHA-1) at distinct ranges are accepted; images map by position
        // and the overlap check bounds the work.
        for c in [Compression::None, Compression::Xpress] {
            let files = vec![
                pseudorandom(5000, 7),
                b"same tree, captured twice\n".repeat(2000),
            ];
            let spec = |name: &str| ImageSpec {
                name: name.to_owned(),
                description: None,
                files: files.clone(),
            };
            let (b, info) = WimBuilder::new(c)
                .image_spec(spec("first"))
                .image_spec(spec("second"))
                .identical_metadata(true)
                .build()
                .unwrap();
            let [m1, m2] = info.metadata[..] else {
                panic!("two metadata entries expected");
            };
            assert_ne!(m1.offset, m2.offset, "{c:?}");
            assert!(m1.offset + m1.stored_size <= m2.offset, "{c:?}");
            let at = |k: usize| usize::try_from(info.lookup.offset).unwrap() + 50 * k;
            assert_eq!(b[at(0) + 30..at(0) + 50], b[at(1) + 30..at(1) + 50]);
            let s = run(&b).unwrap();
            assert_eq!(s.image_count, 2, "{c:?}");
            let names: Vec<_> = s.editions.iter().map(|e| e.name.as_str()).collect();
            assert_eq!(names, ["first", "second"]);
        }
    }

    fn same_tree(name: &str) -> ImageSpec {
        ImageSpec {
            name: name.to_owned(),
            description: None,
            files: vec![
                pseudorandom(5000, 7),
                b"same tree, captured twice\n".repeat(2000),
            ],
        }
    }

    fn bytes_read(b: &[u8], limits: &WimLimits) -> (Result<WimSummary, WimError>, u64) {
        let mut total = 0u64;
        let mut count = |n: u64| {
            total += n;
            ControlFlow::Continue(())
        };
        let r = check_wim(
            &mut Cursor::new(b),
            u64::try_from(b.len()).unwrap(),
            limits,
            usgp_crypto::provider(),
            &mut count,
        );
        (r, total)
    }

    #[test]
    fn reused_metadata_entry_accepted() {
        // OBS-018 (S11A, S11B): two images name one metadata resource
        // through adjacent lookup entries equal in all 50 bytes. Accepted;
        // the resource is read, decoded and counted once (SEC-003). With 8
        // images the builder writes 4 such pairs (4 distinct resources,
        // 8 entries).
        for c in [Compression::None, Compression::Xpress] {
            for images in [2usize, 8] {
                let mut w = WimBuilder::new(c).reuse_metadata(true);
                let names: Vec<String> = (1..=images).map(|k| format!("img-{k}")).collect();
                for n in &names {
                    w = w.image_spec(same_tree(n));
                }
                let (b, info) = w.build().unwrap();
                let pairs: Vec<_> = info.metadata.chunks(2).collect();
                assert!(pairs.iter().all(|p| p[0] == p[1]), "{c:?}");
                assert!(pairs.windows(2).all(|w| w[0][0].offset < w[1][0].offset));
                let (r, read) = bytes_read(&b, &WimLimits::DEFAULT);
                let s = r.unwrap();
                assert_eq!(s.image_count, u32::try_from(images).unwrap());
                let got: Vec<_> = s.editions.iter().map(|e| e.name.clone()).collect();
                assert_eq!(got, names, "{c:?}");
                // Every byte at most once (a shared range is not re-read
                // per image), plus the header.
                let len = u64::try_from(b.len()).unwrap();
                assert!(read <= len + 208, "{c:?} {images}: read {read} of {len}");
                // The budget counts each shared range once: a total that
                // fits every distinct resource plus half of the smallest,
                // but not a count per image, is enough.
                let distinct: u64 = pairs.iter().map(|p| p[0].original_size).sum();
                let smallest = pairs.iter().map(|p| p[0].original_size).min().unwrap();
                let tight = WimLimits {
                    max_metadata_total_bytes: distinct + smallest / 2,
                    ..WimLimits::DEFAULT
                };
                assert!(distinct + smallest / 2 < 2 * distinct);
                assert!(bytes_read(&b, &tight).0.is_ok(), "{c:?} {images}");
            }
        }
    }

    #[test]
    fn reused_metadata_with_integrity_and_boot_index() {
        let (b, _) = WimBuilder::new(Compression::Xpress)
            .reuse_metadata(true)
            .image_spec(same_tree("one"))
            .image_spec(same_tree("two"))
            .integrity(true)
            .boot_index(2)
            .build()
            .unwrap();
        let s = run(&b).unwrap();
        assert!(s.has_integrity_table);
        assert_eq!(check_pe(&s), Ok(2));
    }

    #[test]
    fn moved_first_metadata_accepted_and_names_index_1() {
        // OBS-021 (S12A): entry 1's metadata written after every other
        // resource; the superseded copy stays in the file, unnamed
        // (OBS-022). Lookup order names the index.
        for c in [Compression::None, Compression::Xpress] {
            for images in [2usize, 3, 12] {
                let mut w = WimBuilder::new(c).move_first_metadata(true);
                for k in 1..=images {
                    w = w.image(&format!("img-{k}"), "d");
                }
                let (b, info) = w.build().unwrap();
                let moved = info.metadata[0];
                assert!(info.metadata[1..].iter().all(|m| m.offset < moved.offset));
                assert!(info.files.iter().all(|f| f.offset < moved.offset));
                assert_eq!(moved.offset + moved.stored_size, info.lookup.offset);
                let s = run(&b).unwrap();
                assert_eq!(s.editions[0].name, "img-1", "{c:?}");

                // The stale copy is never read for the check ...
                let stale = info.stale[0];
                let mut d = b.clone();
                let at = usize::try_from(stale.offset).unwrap();
                d[at..at + usize::try_from(stale.stored_size).unwrap()].fill(0x5a);
                assert!(run(&d).is_ok(), "{c:?} {images}: stale copy was read");
                // ... while the moved copy is image 1's.
                let mut d = b.clone();
                let at = usize::try_from(moved.offset + moved.stored_size / 2).unwrap();
                d[at] ^= 0xff;
                let e = run(&d).unwrap_err();
                assert!(
                    matches!(
                        e,
                        WimError::MetadataHashMismatch { index: 1 } | WimError::Decode(_)
                    ),
                    "{c:?} {images}: {e:?}"
                );
            }
        }
    }

    #[test]
    fn version_alone_is_not_refused() {
        // OBS-003: OPEN-WIM-2 stays open; the value is recorded only.
        let s = run(&build(
            WimBuilder::new(Compression::None)
                .image("a", "b")
                .version(0x0000_0e00),
        ))
        .unwrap();
        assert_eq!(s.version, 0x0000_0e00);
    }

    #[test]
    fn readonly_flag_accepted() {
        let s = run(&build(
            WimBuilder::new(Compression::Xpress)
                .image("a", "b")
                .header_flags(0x0002_0086),
        ))
        .unwrap();
        assert_eq!(s.compression, Compression::Xpress);
    }
}
