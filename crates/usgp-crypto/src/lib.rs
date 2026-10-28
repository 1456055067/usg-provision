//! usgp-crypto: CryptoProvider, FIPS status, TLS config (only C dependency).
//!
//! This crate is the cryptographic boundary required by
//! docs/decisions/0001-fips-validated-crypto.md (with Amendment 1). It is the
//! only crate that may depend on `aws-lc-rs` (FIPS 140-3 validated AWS-LC
//! module) or `rustls`, and therefore the only crate with C build
//! dependencies. Every other crate reaches cryptography through the
//! [`CryptoProvider`] trait and the functions exported here.
//!
//! Status: M3. FIPS status, SHA-256 (one-shot and streaming), legacy SHA-1
//! for WIM format hashes, DRBG output, ECDSA P-384 signing keys with
//! domain-separated typed signatures ([`envelope`]), X.509 facts
//! ([`x509`]), and TLS server/client configurations with operator
//! client-certificate validation ([`tls`]). M3 adds HMAC-SHA-256 keys and
//! constant-time comparison ([`hmac`]) and a blocking TLS client for the
//! pre-boot agent ([`tls::BlockingClientTls`]). The `test-pki` feature adds a
//! test certificate hierarchy ([`test_pki`]); release builds never enable
//! it. AEAD is deferred to M4 (plan M2 section 1.2). See
//! docs/ARCHITECTURE.md.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-13 (Cryptographic Protection) - FIPS 140-3 validated
//   module; callers fail closed when FIPS mode is inactive.
// - NIST 800-53: CM-6 (Configuration Settings) - the FIPS configuration is
//   the only build configuration; there is no non-FIPS feature.
// - DECISION: docs/decisions/0001-fips-validated-crypto.md (Amendment 1)

pub mod crl;
pub mod digest;
pub mod envelope;
pub mod error;
pub mod hmac;
pub mod pem;
pub mod rand;
pub mod sign;
#[cfg(feature = "test-pki")]
pub mod test_pki;
pub mod tls;
pub mod x509;

pub use crl::{CrlFacts, CrlNumber, crl_facts};
pub use digest::{DigestAlgorithm, LegacySha1Hasher, Sha1Digest, Sha256Hasher};
pub use envelope::{sign_typed, verify_typed};
pub use error::CryptoError;
pub use hmac::{HmacKey, HmacTag, ct_eq, hmac_sha256};
pub use rand::fill_random;
pub use sign::{KeyId, SIGNATURE_ALGORITHM, SigningKey, VerifyingKey, verify_signing_input};
pub use usgp_common::Sha256Digest;
pub use x509::PeerCertificate;

/// Cryptographic operations for all usg-provision crates (decision 0001).
///
/// Digests and random bytes are reached through this trait so parsers can
/// take `&dyn CryptoProvider`. Signing goes through [`SigningKey`] and
/// [`envelope`]; TLS through [`tls`].
pub trait CryptoProvider: Send + Sync + 'static {
    /// Returns `Ok(())` only if the validated module is operating in FIPS
    /// mode.
    ///
    /// # Errors
    ///
    /// [`CryptoError::FipsModeInactive`] if either the module or the TLS
    /// provider reports that FIPS mode is not active.
    fn fips_status(&self) -> Result<(), CryptoError>;

    /// SHA-256 (FIPS 180-4) of `data`.
    ///
    /// Callers run [`CryptoProvider::fips_status`] at start-up and refuse
    /// to run if it fails, so this method has no error path.
    fn sha256(&self, data: &[u8]) -> Sha256Digest;

    /// A streaming SHA-256 hasher.
    fn sha256_hasher(&self) -> Sha256Hasher {
        Sha256Hasher::new()
    }

    /// A streaming SHA-1 hasher for format hashes only (WIM). Never an
    /// integrity decision; see [`LegacySha1Hasher`].
    fn legacy_sha1_hasher(&self) -> LegacySha1Hasher {
        LegacySha1Hasher::new()
    }

    /// Fills `buf` from the module's DRBG.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Random`] if the DRBG fails.
    fn fill_random(&self, buf: &mut [u8]) -> Result<(), CryptoError> {
        rand::fill_random(buf)
    }
}

/// The single provider, backed by the FIPS-validated module.
#[derive(Debug, Default, Clone, Copy)]
pub struct FipsProvider;

impl CryptoProvider for FipsProvider {
    fn fips_status(&self) -> Result<(), CryptoError> {
        // The module's own self-test and mode flag.
        aws_lc_rs::try_fips_mode().map_err(|_| CryptoError::FipsModeInactive {
            component: "aws-lc",
        })?;
        // The TLS provider must also be the FIPS configuration.
        if !rustls::crypto::default_fips_provider().fips() {
            return Err(CryptoError::FipsModeInactive {
                component: "rustls provider",
            });
        }
        Ok(())
    }

    fn sha256(&self, data: &[u8]) -> Sha256Digest {
        digest::sha256_fips(data)
    }
}

static PROVIDER: FipsProvider = FipsProvider;

/// Process-wide provider.
#[must_use]
pub fn provider() -> &'static FipsProvider {
    &PROVIDER
}

/// Checks FIPS mode through the process-wide provider.
///
/// Every binary calls this first in `main` and exits non-zero on error.
///
/// # Errors
///
/// [`CryptoError::FipsModeInactive`] if FIPS mode is not active.
pub fn fips_status() -> Result<(), CryptoError> {
    provider().fips_status()
}

/// SHA-256 of `data` through the process-wide provider.
#[must_use]
pub fn sha256(data: &[u8]) -> Sha256Digest {
    provider().sha256(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips_status_is_ok_on_build_host() {
        assert!(matches!(fips_status(), Ok(())));
    }

    #[test]
    fn trait_streaming_and_random() {
        let p: &dyn CryptoProvider = provider();
        let mut h = p.sha256_hasher();
        h.update(b"a");
        h.update(b"bc");
        assert_eq!(h.finish(), sha256(b"abc"));
        let mut s = p.legacy_sha1_hasher();
        s.update(b"abc");
        assert_eq!(s.finish(), digest::legacy_sha1(b"abc"));
        let mut buf = [0u8; 16];
        p.fill_random(&mut buf).unwrap();
    }

    #[test]
    fn provider_reports_fips() {
        let p: &dyn CryptoProvider = provider();
        assert!(matches!(p.fips_status(), Ok(())));
    }

    #[test]
    fn sha256_through_trait_and_free_fn_agree() {
        let p: &dyn CryptoProvider = provider();
        // FIPS 180-4 example "abc" (see digest.rs for the source).
        let want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(p.sha256(b"abc").to_hex(), want);
        assert_eq!(sha256(b"abc").to_hex(), want);
    }

    /// The refusal message the binaries print names the failing layer, so an
    /// operator can tell a module failure from a provider misconfiguration
    /// (SC-13 fail-closed diagnostics). Added by QA, bootstrap run.
    #[test]
    fn fips_inactive_error_names_component() {
        let module = CryptoError::FipsModeInactive {
            component: "aws-lc",
        };
        let tls = CryptoError::FipsModeInactive {
            component: "rustls provider",
        };
        assert_eq!(module.to_string(), "FIPS mode is not active in aws-lc");
        assert_eq!(
            tls.to_string(),
            "FIPS mode is not active in rustls provider"
        );
    }
}
