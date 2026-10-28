//! The decision 0022 rule (`findings-boot-obs-r4.md`, "The re-base
//! rule"): every copy, re-base and refuse case on synthetic buffers.
//! Expected re-based bytes are built here from the rule's text, not from
//! the product's encoder.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-10
// - SPEC: specs/standards/reparse-and-security-descriptors.md §2 to §5
// - DECISION: docs/decisions/0022-apply-rebases-rpfix-targets.md

#[cfg(test)]
mod reparse {
    use usgp_image::wim::reparse::{ApplyRoot, ReparseError, prepare};

    const SYMLINK: u32 = 0xA000_000C;
    const JUNCTION: u32 = 0xA000_0003;
    const RP_FIX: u32 = 0x80;
    const COPY: u32 = 0x0001_0000;

    fn u16s(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// A buffer with explicit fields: offsets and lengths in bytes, path
    /// buffer given raw.
    fn raw(fields: [u16; 4], flags: Option<u32>, path: &[u8]) -> Vec<u8> {
        let mut d: Vec<u8> = fields.iter().flat_map(|f| f.to_le_bytes()).collect();
        if let Some(f) = flags {
            d.extend_from_slice(&f.to_le_bytes());
        }
        d.extend_from_slice(path);
        d
    }

    /// DISM's layout (OBS-049): substitute at 0, NUL, print, NUL.
    fn dism(sub: &str, print: &str, flags: Option<u32>) -> Vec<u8> {
        let (s, p) = (u16s(sub), u16s(print));
        let mut path = s.clone();
        path.extend_from_slice(&[0, 0]);
        path.extend_from_slice(&p);
        path.extend_from_slice(&[0, 0]);
        let sl = s.len() as u16;
        raw([0, sl, sl + 2, p.len() as u16], flags, &path)
    }

    fn root(t: &str) -> ApplyRoot {
        ApplyRoot::parse(t).unwrap()
    }

    fn header(tag: u32, data: &[u8]) -> Vec<u8> {
        let mut b = tag.to_le_bytes().to_vec();
        b.extend_from_slice(&(data.len() as u16).to_le_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(data);
        b
    }

    // ---- 1. M = 0x00010000: copy ----

    #[test]
    fn copy_cases_keep_the_bytes_and_rebuild_the_header() {
        let cases = [
            (SYMLINK, dism("rel.txt", "rel.txt", Some(1))),
            (SYMLINK, dism("..\\..\\x.txt", "..\\..\\x.txt", Some(1))),
            // An out-of-tree absolute link in another layout (print first).
            (SYMLINK, {
                let (p, s) = (u16s("T:\\out\\t.txt"), u16s("\\??\\T:\\out\\t.txt"));
                let mut path = p.clone();
                path.extend_from_slice(&s);
                raw(
                    [p.len() as u16, s.len() as u16, 0, p.len() as u16],
                    Some(0),
                    &path,
                )
            }),
            (
                JUNCTION,
                dism("\\??\\T:\\outside-tree", "T:\\outside-tree", None),
            ),
            // A lower-case letter and a volume path are copied: only M = 0
            // is inspected for the target form.
            (JUNCTION, dism("\\??\\Volume{x}\\d", "", None)),
        ];
        for (t, b) in cases {
            for h in [0, RP_FIX] {
                let out = prepare(h, t, COPY, &b, &root("S:\\")).unwrap();
                assert!(!out.rebased());
                assert_eq!(out.data(), b.as_slice());
                assert_eq!(out.bytes(), header(t, &b).as_slice());
                assert_eq!(out.tag(), t);
            }
        }
    }

    #[test]
    fn copy_bounds_refused() {
        let r = root("S:");
        let m = |b: &[u8], t| prepare(RP_FIX, t, COPY, b, &r).unwrap_err();
        let mal = |e: ReparseError| assert_eq!(e.reason_code(), "wim_reparse_malformed", "{e:?}");
        // Shorter than the fixed part (12 symlink, 8 mount point).
        mal(m(&[0; 11], SYMLINK));
        mal(m(&[0; 7], JUNCTION));
        // Odd offset, odd length, name outside the buffer, odd buffer.
        mal(m(&raw([1, 2, 0, 2], Some(1), &u16s("ab")), SYMLINK));
        mal(m(&raw([0, 3, 0, 2], Some(1), &u16s("ab")), SYMLINK));
        mal(m(&raw([0, 6, 0, 2], Some(1), &u16s("ab")), SYMLINK));
        mal(m(&raw([0, 2, 0, 2], Some(1), &[b'a', 0, b'b']), SYMLINK));
        // More than 65535 bytes.
        mal(m(&vec![0u8; 65536], JUNCTION));
        // A name over 32760 characters.
        let long = "a".repeat(32761);
        mal(m(&dism(&long, "a", Some(1)), SYMLINK));
        // Symbolic link Flags other than 0 and 1.
        assert_eq!(
            m(&dism("a", "a", Some(2)), SYMLINK),
            ReparseError::SymlinkFlags
        );
        // Dot components in a mount point (allowed in symbolic links).
        for bad in ["\\??\\T:\\a\\..\\b", "\\??\\T:\\.\\b"] {
            assert_eq!(
                m(&dism(bad, "T:\\b", None), JUNCTION),
                ReparseError::MountPointDotName
            );
        }
        assert!(prepare(RP_FIX, SYMLINK, COPY, &dism("..\\a", "..\\a", Some(1)), &r).is_ok());
        // Other tags.
        assert_eq!(
            m(&dism("a", "a", None), 0xA000_001D),
            ReparseError::Unsupported
        );
    }

    // ---- 2. M = 0: re-base ----

    #[test]
    fn rebase_cases() {
        for (t, flags, head) in [(SYMLINK, Some(0), 12usize), (JUNCTION, None, 8)] {
            let b = dism(
                "\\??\\T:\\links\\target-dir",
                "T:\\links\\target-dir",
                flags,
            );
            for (r, want) in [
                ("S:\\", "S:\\links\\target-dir"),
                ("S:", "S:\\links\\target-dir"),
                (
                    "U:\\deep\\apply-here",
                    "U:\\deep\\apply-here\\links\\target-dir",
                ),
                (
                    "U:\\deep\\apply-here\\",
                    "U:\\deep\\apply-here\\links\\target-dir",
                ),
            ] {
                let out = prepare(RP_FIX, t, 0, &b, &root(r)).unwrap();
                assert!(out.rebased());
                let expect = dism(&format!("\\??\\{want}"), want, flags);
                assert_eq!(out.data(), expect.as_slice(), "{r}");
                // Data length = path buffer + 12 (link) or + 8 (mount point).
                assert_eq!(
                    out.data().len() - head,
                    (want.len() * 2 + 8) + 2 + want.len() * 2 + 2
                );
                assert_eq!(out.bytes(), header(t, &expect).as_slice());
            }
        }
    }

    #[test]
    fn rebase_refusals() {
        let r = root("S:");
        let good = |t| dism("\\??\\T:\\a\\b", "T:\\a\\b", (t == SYMLINK).then_some(0));
        let code = |h, t, m, b: &[u8]| prepare(h, t, m, b, &r).unwrap_err().reason_code();
        // (a) RP_FIX clear.
        assert_eq!(
            code(0, SYMLINK, 0, &good(SYMLINK)),
            "wim_reparse_rewritten_without_rp_fix"
        );
        // (b) relative Flags; another tag.
        assert_eq!(
            code(RP_FIX, SYMLINK, 0, &dism("\\??\\T:\\a", "T:\\a", Some(1))),
            "wim_reparse_rebase_relative"
        );
        assert_eq!(
            code(RP_FIX, 0xA000_001D, 0, &good(JUNCTION)),
            "wim_reparse_unsupported"
        );
        // Any other M.
        for m in [1u32, 2, 0x0002_0000, u32::MAX] {
            assert_eq!(
                code(RP_FIX, JUNCTION, m, &good(JUNCTION)),
                "wim_reparse_unsupported"
            );
        }
        // (c) layouts other than DISM's.
        let (s, p) = (u16s("\\??\\T:\\a"), u16s("T:\\a"));
        let (sl, pl) = (s.len() as u16, p.len() as u16);
        let cat = |parts: &[&[u8]]| parts.concat();
        let z: &[u8] = &[0, 0];
        for (fields, path, why) in [
            // Print first.
            ([pl + 2, sl, 0, pl], cat(&[&p, z, &s, z]), "print first"),
            // No NUL after the substitute.
            (
                [0, sl, sl, pl],
                cat(&[&s, &p, z]),
                "no NUL after substitute",
            ),
            // No NUL after the print name.
            ([0, sl, sl + 2, pl], cat(&[&s, z, &p]), "no NUL after print"),
            // Trailing bytes after the last NUL.
            ([0, sl, sl + 2, pl], cat(&[&s, z, &p, z, z]), "trailing"),
            // The NUL slots hold data.
            (
                [0, sl, sl + 2, pl],
                cat(&[&s, &[b'x', 0], &p, z]),
                "non-zero gap",
            ),
        ] {
            let b = raw(fields, None, &path);
            assert_eq!(
                code(RP_FIX, JUNCTION, 0, &b),
                "wim_reparse_rebase_layout",
                "{why}"
            );
        }
        // (d) target forms.
        for (sub, print, why) in [
            ("T:\\a", "T:\\a", "no \\??\\ prefix"),
            ("\\??\\Volume{1}\\a", "Volume{1}\\a", "not a drive letter"),
            ("\\??\\t:\\a", "t:\\a", "lower-case letter"),
            ("\\??\\1:\\a", "1:\\a", "digit"),
            ("\\??\\T:\\a", "U:\\a", "different D"),
            ("\\??\\T:\\a", "T:\\b", "different R"),
            ("\\??\\T:\\a", "", "empty print name"),
            ("\\??\\T:\\", "T:\\", "R is \\"),
            ("\\??\\T:", "T:", "no R"),
            ("\\??\\T:a", "T:a", "drive-relative R"),
            ("\\??\\T:\\a\\..\\b", "T:\\a\\..\\b", "dot-dot"),
            ("\\??\\T:\\a\\.\\b", "T:\\a\\.\\b", "dot"),
            ("\\??\\T:\\a\\\\b", "T:\\a\\\\b", "empty component"),
            ("\\??\\T:\\a\\", "T:\\a\\", "trailing backslash"),
            ("\\??\\T:\\a\0b", "T:\\a\0b", "NUL"),
        ] {
            let b = dism(sub, print, Some(0));
            assert_eq!(
                code(RP_FIX, SYMLINK, 0, &b),
                "wim_reparse_rebase_target",
                "{why}"
            );
        }
        // Too long after re-basing: a name over 32760 characters, and a
        // buffer over 65535 bytes.
        let deep = format!("T:\\{}", "a".repeat(16300));
        let b = dism(&format!("\\??\\{deep}"), &deep, Some(0));
        let long_root = root(&format!("S:\\{}", "r\\".repeat(100).trim_end_matches('\\')));
        assert!(prepare(RP_FIX, SYMLINK, 0, &b, &r).is_ok());
        assert_eq!(
            prepare(RP_FIX, SYMLINK, 0, &b, &long_root).unwrap_err(),
            ReparseError::RebaseTooLong
        );
        let deep = format!("T:\\{}", "a".repeat(32758));
        let b = dism(&format!("\\??\\{deep}"), "x", Some(0));
        assert_eq!(code(RP_FIX, SYMLINK, 0, &b), "wim_reparse_malformed");
    }
}
