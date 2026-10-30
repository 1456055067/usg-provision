//! Fuzz target `cab_archive`: a whole Microsoft cabinet in memory, read as
//! a driver archive and as plain content (`usgp-wincfg`
//! `validate_archive_mode`, `extract_archive_mode`), with the default
//! limits and with tight ones.
//!
//! The first four octets are forced to `MSCF`, so every input reaches the
//! cabinet reader (the format switch is covered by `zip_archive`).
//!
//! Invariants: as `zip_archive` (`common/archive_checks.rs`), and an
//! accepted input is a cabinet.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SI-7, CM-7, SA-11
// - SPEC: specs/drivers.md#REQ-DRV-001, #REQ-DRV-006, #REQ-DRV-009
// - Microsoft Cabinet Format (specs/standards/zip-cab.md); RFC 1951 (MSZIP)

#[path = "common/archive_checks.rs"]
mod archive_checks;

use libfuzzer_sys::fuzz_target;
use usgp_wincfg::ArchiveKind;

fuzz_target!(|data: &[u8]| {
    let mut buf = b"MSCF".to_vec();
    buf.extend_from_slice(data.get(4..).unwrap_or_default());
    if let Some(r) = archive_checks::run(&buf) {
        assert_eq!(r.kind, ArchiveKind::Cab, "CAB target read another kind");
    }
});
