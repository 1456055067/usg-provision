//! `--self-test`: the FIPS check, run alone (plan section 1.2(d) item 3;
//! decision 0018 item 6). Lab MT-2 records its output in Windows PE; the
//! Windows CI job runs it on the runner.
//!
//! It passes (exit 0) only if the module reports FIPS mode, a SHA-256
//! known answer matches, and the DRBG returns bytes. It needs no
//! configuration and no network.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-13 (Cryptographic Protection), SI-6 (Security and
//   Privacy Function Verification) - module status and known answer.
// - DECISION: docs/decisions/0001, 0018 item 6

use std::fmt::Write as _;

use usgp_crypto::CryptoProvider;

/// FIPS 180-4 example: SHA-256("abc").
const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

/// The result: whether it passed and the report to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfTest {
    /// Every check passed.
    pub passed: bool,
    /// One line per check.
    pub report: String,
}

/// Runs the checks.
#[must_use]
pub fn run(crypto: &dyn CryptoProvider) -> SelfTest {
    let mut report = String::new();
    let _ = writeln!(
        report,
        "usgp-preboot-agent {} self-test",
        crate::AGENT_VERSION
    );
    let fips = crypto.fips_status();
    let _ = writeln!(
        report,
        "fips mode: {}",
        match &fips {
            Ok(()) => "active".to_owned(),
            Err(e) => format!("NOT ACTIVE ({e})"),
        }
    );
    // POAM: the FIPS module's version is not exposed by usgp-crypto; the
    // lab record (MT-2) takes it from the build's pinned module version.
    let kat = crypto.sha256(b"abc").to_hex() == ABC_SHA256;
    let _ = writeln!(
        report,
        "sha-256 known answer: {}",
        if kat { "pass" } else { "FAIL" }
    );
    let mut b = [0u8; 32];
    let drbg = crypto.fill_random(&mut b).is_ok() && b != [0u8; 32];
    let _ = writeln!(report, "drbg: {}", if drbg { "pass" } else { "FAIL" });
    let passed = fips.is_ok() && kat && drbg;
    let _ = writeln!(report, "result: {}", if passed { "PASS" } else { "FAIL" });
    SelfTest { passed, report }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_on_the_build_host() {
        let t = run(usgp_crypto::provider());
        assert!(t.passed, "{}", t.report);
        assert!(t.report.contains("fips mode: active"));
    }
}
