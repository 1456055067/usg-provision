//! Fuzz target `content_manifest_v2`: a v2 (archive) content manifest (usgp-proto).
//!
//! STUB (M4 WU-4a, as WU-0): registered so the target list is fixed before the
//! parsers exist. M4 WU-12 (plan WU-4a) wires it to the parser and states the
//! invariants (plan §2 WU-12); until then it only accepts input.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SA-11
// - SPEC: specs/drivers.md#REQ-DRV-006, specs/agent-handoff.md
// POAM: stub target; no parser is exercised until M4 WU-12 lands.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = data;
});
