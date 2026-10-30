//! Fuzz target `zip_archive`: a whole ZIP file in memory, read as a driver
//! archive and as plain content (`usgp-wincfg` `validate_archive_mode`,
//! `extract_archive_mode`), with the default limits and with tight ones.
//!
//! Invariants (shared with `cab_archive`, `common/archive_checks.rs`):
//!
//! - no panic; every refusal has a listed reason code and is never a read
//!   or sink failure (the source and sink are in memory);
//! - validate and extract agree (same report, or the same reason);
//! - the sink sees only relative paths with no empty, `.` or `..` segment
//!   and no reserved character, each parent folder announced before
//!   anything inside it, no folded name twice, no nested file, exactly the
//!   declared bytes per file, and as many bytes in total as `expanded`;
//! - the report's kind matches the signature, its INF list is sorted,
//!   unique and holds only `.inf` paths, and is never longer than the
//!   entry count;
//! - driver mode and plain mode differ only in the INF rule
//!   (REQ-DRV-006): the same report, or driver mode refuses with
//!   `no_inf_packages` exactly when no INF package is listed;
//! - tighter limits never accept an archive the defaults refuse.
//!
//! An accepted input here also starts with `PK`, so it is read as ZIP.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SI-7, CM-7, SA-11
// - SPEC: specs/drivers.md#REQ-DRV-001, #REQ-DRV-006, #REQ-DRV-009
// - PKWARE APPNOTE 6.3.10 (specs/standards/zip-cab.md); RFC 1951

#[path = "common/archive_checks.rs"]
mod archive_checks;

use libfuzzer_sys::fuzz_target;
use usgp_wincfg::ArchiveKind;

fuzz_target!(|data: &[u8]| {
    if let Some(r) = archive_checks::run(data) {
        assert_eq!(r.kind, ArchiveKind::Zip, "ZIP target read another kind");
        assert!(data.starts_with(b"PK"), "accepted without a ZIP signature");
    }
});
