//! Errors returned by the crypto boundary.
//!
//! Error values never carry key material or other secrets. Reasons are
//! static strings or text produced by the TLS stack about public data
//! (certificates, CRLs, protocol state); input bytes are never echoed.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-11 (Error Handling) - errors name the failing step,
//   never the secret or the raw input.
// - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management) -
//   key errors carry no key bytes.

/// Errors from `usgp-crypto`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    /// The validated module (or the TLS provider built on it) is not
    /// operating in FIPS mode.
    #[error("FIPS mode is not active in {component}")]
    FipsModeInactive {
        /// Which layer reported the failure (`"aws-lc"`, `"rustls provider"`,
        /// `"tls server config"` or `"tls client config"`).
        component: &'static str,
    },

    /// The module's DRBG failed to produce output.
    #[error("the random bit generator failed")]
    Random,

    /// Key generation inside the module failed.
    #[error("key generation failed")]
    KeyGeneration,

    /// A private key could not be loaded. The key bytes are never included.
    #[error("private key rejected: {reason}")]
    KeyRejected {
        /// Why the key was refused.
        reason: &'static str,
    },

    /// A public key could not be loaded.
    #[error("public key rejected: {reason}")]
    PublicKeyRejected {
        /// Why the key was refused.
        reason: &'static str,
    },

    /// The module failed to produce a signature.
    #[error("signing failed")]
    Signing,

    /// A signature did not verify. No detail is given on purpose.
    #[error("signature verification failed")]
    SignatureInvalid,

    /// An HMAC tag did not verify, or a stored tag has the wrong length.
    /// No detail is given on purpose.
    #[error("message authentication code verification failed")]
    MacInvalid,

    /// A signed-message payload type is not acceptable.
    #[error("invalid payload type: {reason}")]
    PayloadType {
        /// Why the payload type was refused.
        reason: &'static str,
    },

    /// PEM input could not be decoded.
    #[error("invalid PEM for {what}: {reason}")]
    Pem {
        /// What was being decoded (for example `"certificate"`).
        what: &'static str,
        /// Why it was refused.
        reason: &'static str,
    },

    /// An input exceeded a project size limit (SI-10).
    #[error("{what} is larger than the limit of {limit} bytes")]
    InputTooLarge {
        /// What was too large.
        what: &'static str,
        /// The limit in bytes.
        limit: usize,
    },

    /// A certificate could not be parsed or does not meet our rules.
    #[error("certificate rejected: {reason}")]
    Certificate {
        /// Why the certificate was refused.
        reason: &'static str,
    },

    /// A configured certificate policy OID is not a valid OID.
    #[error("invalid certificate policy OID at position {index}")]
    PolicyOid {
        /// Zero-based position in the configured list.
        index: usize,
    },

    /// A TLS configuration could not be built.
    #[error("TLS configuration error: {reason}")]
    TlsConfig {
        /// Why the configuration was refused (text about public data only).
        reason: String,
    },

    /// DER encoding of a structure we built failed.
    #[error("DER encoding failed for {what}")]
    Encoding {
        /// What was being encoded.
        what: &'static str,
    },

    /// A CRL could not be parsed or does not meet our rules.
    #[error("CRL rejected: {reason}")]
    Crl {
        /// Why the CRL was refused.
        reason: &'static str,
    },

    /// An escrow input was refused before decryption (wrong key id, bad
    /// field length, bad account name). Never carries secret bytes.
    #[error("escrow refused: {reason}")]
    Escrow {
        /// Why the input was refused.
        reason: &'static str,
    },

    /// AEAD authentication failed. No detail is given on purpose.
    #[error("decryption failed")]
    DecryptionFailed,

    /// A requested password length is outside the accepted range.
    #[error("password length must be between {min} and {max}")]
    PasswordLength {
        /// Shortest accepted length.
        min: usize,
        /// Longest accepted length.
        max: usize,
    },
}
