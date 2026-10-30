//! Fuzz target `zip_archive`: a ZIP archive (usgp-wincfg validate_archive/extract_archive).
//!
//! STUB (M4 WU-0): registered so the target list is fixed before the
//! parsers exist. M4 WU-12 wires it to the parser and states the
//! invariants (plan §2 WU-12); until then it only accepts input.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SA-11
// - SPEC: specs/drivers.md
// POAM: stub target; no parser is exercised until M4 WU-12 lands.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = data;
});
