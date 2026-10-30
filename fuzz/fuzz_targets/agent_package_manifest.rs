//! Fuzz target `agent_package_manifest`: an agent package manifest (usgp-proto).
//!
//! STUB (M4 WU-0): registered so the target list is fixed before the
//! parsers exist. M4 WU-12 wires it to the parser and states the
//! invariants (plan §2 WU-12); until then it only accepts input.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SA-11
// - SPEC: specs/agent-handoff.md
// POAM: stub target; no parser is exercised until M4 WU-12 lands.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = data;
});
