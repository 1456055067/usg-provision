//! Errors returned by the crypto boundary.
//!
//! Error values never carry key material or other secrets.

/// Errors from `usgp-crypto`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// The validated module (or the TLS provider built on it) is not
    /// operating in FIPS mode.
    #[error("FIPS mode is not active in {component}")]
    FipsModeInactive {
        /// Which layer reported the failure (`"aws-lc"` or
        /// `"rustls provider"`).
        component: &'static str,
    },
}
