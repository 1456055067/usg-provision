//! Shared invariants of the `zip_archive` and `cab_archive` targets
//! (`usgp-wincfg` `validate_archive_mode`, `extract_archive_mode`).
//!
//! Included by `#[path]` from both targets; not a target itself.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SI-7 (Software,
//   Firmware, and Information Integrity), SA-11 (Developer Testing and
//   Evaluation)
// - SPEC: specs/drivers.md#REQ-DRV-001, #REQ-DRV-006, #REQ-DRV-009
// - PKWARE APPNOTE 6.3.10; Microsoft Cabinet Format; RFC 1951

use std::collections::BTreeMap;

use usgp_wincfg::{
    ArchiveError, ArchiveKind, ArchiveLimits, ArchiveMode, ArchiveReport, ExtractSink, RelPath,
    extract_archive_mode, validate_archive_mode,
};

/// Every reason code `ArchiveError::reason` may return.
const REASONS: &[&str] = &[
    "read_failed",
    "sink_failed",
    "unknown_format",
    "truncated",
    "malformed",
    "encrypted",
    "multi_disk",
    "multi_cabinet",
    "patched_data",
    "zip_method_unsupported",
    "cab_compression_unsupported",
    "cab_version_unsupported",
    "bad_name",
    "duplicate_name",
    "path_conflict",
    "special_entry",
    "header_mismatch",
    "overlap",
    "limit_exceeded",
    "bad_deflate",
    "crc_mismatch",
    "cab_checksum",
    "size_mismatch",
    "no_inf_packages",
];

/// Small limits, so the limit paths are reachable with fuzz-sized input.
/// Every field is at most the default.
pub fn tight() -> ArchiveLimits {
    ArchiveLimits {
        max_archive_bytes: 1 << 20,
        max_entries: 8,
        max_expanded_bytes: 1 << 20,
        max_ratio_total: 50,
        max_ratio_entry: 100,
        max_entry_bytes: 256 * 1024,
        max_inf_bytes: 4096,
        max_name_bytes: 64,
        max_depth: 4,
    }
}

/// A sink that checks the order and shape of what it is given and keeps
/// only counts (no content).
#[derive(Default)]
struct CheckSink {
    /// Folded paths: `true` for a folder, `false` for a file.
    seen: BTreeMap<String, bool>,
    current: Option<(u64, u64)>,
    files: u32,
    written: u64,
}

fn fold(p: &RelPath) -> String {
    p.as_str().chars().flat_map(char::to_uppercase).collect()
}

fn check_path(p: &RelPath) {
    let s = p.as_str();
    assert!(!s.is_empty() && !s.starts_with('/'), "path not relative");
    for seg in s.split('/') {
        assert!(!seg.is_empty(), "empty segment");
        assert!(seg != "." && seg != "..", "dot segment escapes the folder");
        assert!(
            !seg.chars()
                .any(|c| c.is_control()
                    || matches!(c, ':' | '\\' | '<' | '>' | '"' | '|' | '?' | '*')),
            "reserved character in a segment"
        );
        assert!(
            !seg.ends_with('.') && !seg.ends_with(' '),
            "trailing dot or space"
        );
    }
}

impl CheckSink {
    fn parent_known(&self, p: &RelPath) {
        if let Some(parent) = p.parent() {
            assert_eq!(
                self.seen.get(&fold(&parent)),
                Some(&true),
                "parent folder not announced first"
            );
        }
    }
}

impl ExtractSink for CheckSink {
    fn create_dir(&mut self, path: &RelPath) -> std::io::Result<()> {
        check_path(path);
        assert!(self.current.is_none(), "folder inside an open file");
        self.parent_known(path);
        let prev = self.seen.insert(fold(path), true);
        assert!(prev.is_none(), "folder announced twice or over a file");
        Ok(())
    }

    fn begin_file(&mut self, path: &RelPath, size: u64) -> std::io::Result<()> {
        check_path(path);
        assert!(self.current.is_none(), "nested file");
        self.parent_known(path);
        let prev = self.seen.insert(fold(path), false);
        assert!(prev.is_none(), "file name repeats a folded name");
        self.current = Some((size, 0));
        Ok(())
    }

    fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        let (size, done) = self.current.as_mut().expect("write outside a file");
        *done = done.saturating_add(data.len() as u64);
        assert!(*done <= *size, "more bytes than declared");
        Ok(())
    }

    fn end_file(&mut self) -> std::io::Result<()> {
        let (size, done) = self.current.take().expect("end outside a file");
        assert_eq!(size, done, "file ended short");
        self.files += 1;
        self.written += done;
        Ok(())
    }
}

fn check_err(e: &ArchiveError) {
    assert!(
        REASONS.contains(&e.reason()),
        "unlisted reason {}",
        e.reason()
    );
    let _ = e.to_string();
    assert!(
        !matches!(e, ArchiveError::Io(_) | ArchiveError::Sink(_)),
        "in-memory read or sink failed"
    );
}

fn check_report(r: &ArchiveReport, magic: &[u8]) {
    let want = match magic {
        b"MSCF" => ArchiveKind::Cab,
        _ => ArchiveKind::Zip,
    };
    assert_eq!(r.kind, want, "kind does not match the signature");
    assert!(
        r.infs.windows(2).all(|w| w[0] < w[1]),
        "INF list not sorted and unique"
    );
    assert!(
        r.infs.iter().all(|p| {
            let n = p.file_name();
            n.len() > 4
                && n.get(n.len() - 4..)
                    .is_some_and(|e| e.eq_ignore_ascii_case(".inf"))
        }),
        "INF list holds a non-INF"
    );
    assert!(
        r.ignored_executables <= r.entries,
        "more executables than entries"
    );
    assert!(
        r.infs.len() as u64 <= u64::from(r.entries),
        "more INFs than entries"
    );
}

/// Runs both modes and both limit sets on `data`; returns the
/// driver-mode report with default limits, if accepted.
pub fn run(data: &[u8]) -> Option<ArchiveReport> {
    let len = data.len() as u64;
    let magic = data.get(..4).unwrap_or_default();
    let mut out = None;
    let mut accepted_default = false;
    for (li, lim) in [ArchiveLimits::default(), tight()].iter().enumerate() {
        let mut plain = None;
        for mode in [ArchiveMode::Plain, ArchiveMode::DriverPackages] {
            let v = validate_archive_mode(&data, len, lim, mode);
            let mut sink = CheckSink::default();
            let x = extract_archive_mode(&data, len, lim, mode, &mut sink);
            match (&v, &x) {
                (Ok(a), Ok(b)) => {
                    assert_eq!(a, b, "validate and extract disagree");
                    check_report(a, magic);
                    assert!(sink.current.is_none(), "file left open");
                    assert_eq!(
                        sink.written, a.expanded,
                        "expanded differs from bytes written"
                    );
                    assert!(sink.files <= a.entries, "more files than entries");
                }
                (Err(a), Err(b)) => {
                    check_err(a);
                    assert_eq!(a.reason(), b.reason(), "validate and extract disagree");
                }
                _ => panic!("validate and extract disagree on acceptance"),
            }
            match mode {
                ArchiveMode::Plain => plain = Some(v),
                ArchiveMode::DriverPackages => {
                    let p = plain.take().expect("plain ran first");
                    match (&p, &v) {
                        // The modes differ only in the INF rule.
                        (Ok(a), Ok(b)) => {
                            assert_eq!(a, b, "modes disagree on an accepted archive");
                            assert!(!b.infs.is_empty(), "driver archive without an INF package");
                        }
                        (Ok(a), Err(ArchiveError::NoInfPackages)) => {
                            assert!(a.infs.is_empty(), "INF packages listed but refused");
                        }
                        (Err(a), Err(b)) => assert_eq!(a.reason(), b.reason(), "modes disagree"),
                        _ => panic!("modes disagree beyond the INF rule"),
                    }
                    if v.is_ok() {
                        if li == 0 {
                            accepted_default = true;
                        } else {
                            // Tighter limits never accept more.
                            assert!(accepted_default, "tight limits accept more");
                        }
                    }
                    if li == 0 {
                        out = v.ok();
                    }
                }
            }
        }
    }
    out
}
