//! Start-up test for the `usgp-cli` binary (QA, bootstrap run).
//!
//! Runs the built artifact as a child process and checks the fail-closed
//! FIPS start-up path (docs/decisions/0001, NIST 800-53 SC-13): on a FIPS
//! build the process must exit 0 and print nothing to stderr. A non-FIPS
//! build prints "refusing to start" and exits 1, failing this test.

use std::process::Command;

#[test]
fn starts_in_fips_mode_and_exits_zero() {
    let out = Command::new(env!("CARGO_BIN_EXE_usgp-cli"))
        .output()
        .expect("spawn usgp-cli");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "usgp-cli exited with {:?}; stderr: {stderr}",
        out.status.code()
    );
    assert!(stderr.is_empty(), "unexpected stderr output: {stderr}");
}
