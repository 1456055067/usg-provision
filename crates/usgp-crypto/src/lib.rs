//! usgp-crypto: CryptoProvider, FIPS status, TLS config (only C dependency).
//!
//! This crate is the cryptographic boundary required by
//! docs/decisions/0001-fips-validated-crypto.md (with Amendment 1). It is the
//! only crate that may depend on `aws-lc-rs` (FIPS 140-3 validated AWS-LC
//! module) or `rustls`, and therefore the only crate with C build
//! dependencies. Every other crate reaches cryptography through the
//! [`CryptoProvider`] trait and the functions exported here.
//!
//! Status: stub (M0). Only the FIPS status check exists; digest, signature,
//! AEAD, and TLS configuration arrive in M1/M2. See docs/ARCHITECTURE.md.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-13 (Cryptographic Protection) - FIPS 140-3 validated
//   module; callers fail closed when FIPS mode is inactive.
// - NIST 800-53: CM-6 (Configuration Settings) - the FIPS configuration is
//   the only build configuration; there is no non-FIPS feature.
// - DECISION: docs/decisions/0001-fips-validated-crypto.md (Amendment 1)

pub mod error;

pub use error::CryptoError;

/// Cryptographic operations for all usg-provision crates (decision 0001).
///
/// M0 exposes only the FIPS status; digest, signature, AEAD, and TLS
/// methods are added in M1/M2.
pub trait CryptoProvider: Send + Sync + 'static {
    /// Returns `Ok(())` only if the validated module is operating in FIPS
    /// mode.
    ///
    /// # Errors
    ///
    /// [`CryptoError::FipsModeInactive`] if either the module or the TLS
    /// provider reports that FIPS mode is not active.
    fn fips_status(&self) -> Result<(), CryptoError>;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips_status_is_ok_on_build_host() {
        assert!(matches!(fips_status(), Ok(())));
    }

    #[test]
    fn provider_reports_fips() {
        let p: &dyn CryptoProvider = provider();
        assert!(matches!(p.fips_status(), Ok(())));
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
