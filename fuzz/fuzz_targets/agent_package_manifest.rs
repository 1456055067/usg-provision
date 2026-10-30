//! Fuzz target `agent_package_manifest`: `agent.json` from an agent
//! package (`usgp-proto` `AgentPackageManifestV1::from_json`).
//!
//! Invariants:
//!
//! - no panic; `TooLarge` exactly over `MAX_AGENT_MANIFEST_BYTES`,
//!   before parsing;
//! - an accepted manifest validates, names an `.exe` or `.msi` installer,
//!   has at most 32 arguments, 1 to 32 success exit codes and a timeout
//!   of 1 s to 6 h;
//! - it re-serializes and parses back to itself.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), CM-7, SA-11
// - SPEC: specs/agent-handoff.md#REQ-AGT-001
// - RFC 8259 (JSON)

use libfuzzer_sys::fuzz_target;
use usgp_proto::AgentPackageManifestV1;
use usgp_proto::agent_package::{AgentPackageManifestError, MAX_AGENT_TIMEOUT_S};
use usgp_proto::limits::MAX_AGENT_MANIFEST_BYTES;

fuzz_target!(|data: &[u8]| {
    match AgentPackageManifestV1::from_json(data) {
        Ok(m) => {
            assert!(data.len() <= MAX_AGENT_MANIFEST_BYTES);
            m.validate().expect("accepted manifest validates");
            assert!(m.installer_kind().is_some(), "installer kind unknown");
            assert!(m.args.len() <= 32, "too many arguments");
            assert!(
                (1..=32).contains(&m.success_exit_codes.len()),
                "exit code count"
            );
            assert!(
                (1..=MAX_AGENT_TIMEOUT_S).contains(&m.timeout_s),
                "timeout range"
            );
            let json = serde_json::to_vec(&m).expect("manifest serializes");
            let again = AgentPackageManifestV1::from_json(&json).expect("own JSON parses");
            assert_eq!(again, m, "manifest does not round-trip");
        }
        Err(AgentPackageManifestError::TooLarge { len }) => {
            assert_eq!(len, data.len());
            assert!(len > MAX_AGENT_MANIFEST_BYTES, "too large under the cap");
        }
        Err(e) => {
            assert!(
                data.len() <= MAX_AGENT_MANIFEST_BYTES,
                "parsed over the cap"
            );
            let _ = e.to_string();
        }
    }
});
