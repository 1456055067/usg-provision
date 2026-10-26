//! usgp-preboot-agent: agent that runs in the pre-boot environment on the target.
//!
//! Status: stub (M0). See docs/ARCHITECTURE.md.
//! Filled in: M3 (docs/ROADMAP.md section 3).

use std::process::ExitCode;

fn main() -> ExitCode {
    // COMPLIANCE MAPPING:
    // - NIST 800-53: SC-13 (Cryptographic Protection) - fail closed if the
    //   validated module is not in FIPS mode (docs/decisions/0001).
    match usgp_crypto::fips_status() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("usgp-preboot-agent: refusing to start: {e}");
            ExitCode::FAILURE
        }
    }
}
