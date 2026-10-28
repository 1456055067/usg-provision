//! TLS server and client configurations on the FIPS provider.
//!
//! Every TLS channel of the product is built here (decisions 0001, 0007,
//! 0011). No `rustls` type appears in the public API: callers get
//! [`ServerTls`] and [`ClientTls`] handles, a [`PeerCertificate`] for the
//! authenticated operator, and a [`TlsFailure`] with a stable class for the
//! audit record when a handshake is refused.
//!
//! Fixed settings (plan M2 section 5.4):
//!
//! - TLS 1.3 always; TLS 1.2 unless `min_version` is `1.3`.
//! - Cipher suites: TLS 1.3 `TLS_AES_256_GCM_SHA384`,
//!   `TLS_AES_128_GCM_SHA256`; TLS 1.2 ECDHE_ECDSA and ECDHE_RSA with
//!   AES_256_GCM_SHA384 and AES_128_GCM_SHA256. No ChaCha20.
//! - Groups: secp384r1, secp256r1.
//! - Signature schemes: ECDSA P-256/P-384, RSA-PSS and RSA PKCS#1 with
//!   SHA-256/384/512.
//! - No session tickets, no stateful resumption, no 0-RTT; ALPN
//!   `http/1.1` on the server.
//!
//! OPEN-TLS-1: the detailed SP 800-52r2 lists were not read; these are the
//! strictest settings the provider allows that meet the summary in
//! `specs/standards/http-tls.md` §7.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-8, SC-8(1) (Transmission Confidentiality and
//   Integrity) - TLS 1.2/1.3 with AEAD suites only.
// - NIST 800-53: SC-13 (Cryptographic Protection) - FIPS provider asserted
//   (`fips()`) when every configuration is built; fail closed.
// - NIST 800-53: SC-23 (Session Authenticity) - no resumption, so every
//   connection is a full handshake with fresh certificate validation.
// - NIST 800-53: IA-2, IA-5(2) (PKI-Based Authentication) - client
//   certificate path validation with CRLs (see server.rs).
// - SPEC: plan M2 section 5.4; specs/standards/http-tls.md §6, §7;
//   decisions 0001, 0007, 0011.
// - RFC 8446 §4.2.1 (versions), §9.1 (mandatory suites); RFC 5246.

use std::fmt;
use std::sync::{Arc, OnceLock};

use rustls::crypto::CryptoProvider;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::crypto::aws_lc_rs::{cipher_suite, kx_group};
use rustls::pki_types::{SignatureVerificationAlgorithm, alg_id};
use rustls::{SignatureScheme, SupportedProtocolVersion};

use crate::CryptoError;

mod blocking;
mod chain;
mod client;
mod device_server;
#[cfg(feature = "test-pki")]
pub(crate) mod memory;
mod server;
pub mod settings;
mod stream;

pub use blocking::{BlockingClientStream, BlockingClientTls};
pub use client::ClientTls;
pub use device_server::DeviceServerTls;
pub use server::{RefusedHandshake, ServerTls};
pub use settings::{
    ClientAlpn, ClientTlsSettings, DeviceServerTlsSettings, ServerTlsSettings, TlsMinVersion,
};
pub use stream::{ClientTlsStream, ServerTlsStream};

pub use crate::x509::PeerCertificate;

/// ALPN protocol id the API server offers (RFC 7301; HTTP/1.1 only, M2).
pub const ALPN_HTTP11: &[u8] = b"http/1.1";

/// Negotiated protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsProtocol {
    /// TLS 1.2 (RFC 5246).
    Tls12,
    /// TLS 1.3 (RFC 8446).
    Tls13,
}

impl TlsProtocol {
    pub(crate) fn from_rustls(v: rustls::ProtocolVersion) -> Option<Self> {
        match v {
            rustls::ProtocolVersion::TLSv1_2 => Some(Self::Tls12),
            rustls::ProtocolVersion::TLSv1_3 => Some(Self::Tls13),
            _ => None,
        }
    }
}

/// Why a TLS handshake was refused. The text form ([`Self::as_str`]) is
/// the `class` of the `auth.tls.failed` audit event (plan M2 section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TlsFailureClass {
    /// The certificate does not chain to a configured trust anchor, or a
    /// signature in the path does not verify.
    Untrusted,
    /// A certificate in the path is past its notAfter.
    Expired,
    /// A certificate in the path is before its notBefore.
    NotYetValid,
    /// A certificate in the path is revoked by a configured CRL.
    Revoked,
    /// A CRL needed for the path is past its nextUpdate (fail closed).
    CrlStale,
    /// No configured CRL covers a certificate in the path (fail closed).
    RevocationUnknown,
    /// The end entity's extended key usage excludes TLS client (or server)
    /// authentication, or (operator certificates) the extendedKeyUsage
    /// extension is absent.
    BadEku,
    /// A certificate has a critical extension we do not process
    /// (RFC 5280 §4.2).
    UnknownCriticalExt,
    /// The end entity asserts none of the acceptable policy OIDs.
    Policy,
    /// Any other certificate problem (encoding, name mismatch, ...).
    BadCertificate,
    /// A non-certificate protocol failure (version, suite, alert, ...).
    Protocol,
}

impl TlsFailureClass {
    /// Stable lowercase name for audit records.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Untrusted => "untrusted",
            Self::Expired => "expired",
            Self::NotYetValid => "not_yet_valid",
            Self::Revoked => "revoked",
            Self::CrlStale => "crl_stale",
            Self::RevocationUnknown => "revocation_unknown",
            Self::BadEku => "bad_eku",
            Self::UnknownCriticalExt => "unknown_critical_ext",
            Self::Policy => "policy",
            Self::BadCertificate => "bad_certificate",
            Self::Protocol => "protocol",
        }
    }

    /// True for certificate validity-period failures ([`Self::Expired`],
    /// [`Self::NotYetValid`]). The pre-boot agent shows these as "the
    /// device clock may be wrong", because the device's real-time clock is
    /// not trusted (plan M3 section 5, R-5).
    #[must_use]
    pub const fn is_time_related(self) -> bool {
        matches!(self, Self::Expired | Self::NotYetValid)
    }
}

impl fmt::Display for TlsFailureClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refused handshake: a stable class plus the TLS stack's description.
///
/// The detail is about public data (certificates, CRLs, protocol state);
/// it never contains key material.
#[derive(Debug, Clone, thiserror::Error)]
#[error("TLS handshake refused ({class}): {detail}")]
pub struct TlsFailure {
    /// Stable class for audit and metrics.
    pub class: TlsFailureClass,
    /// Human-readable detail.
    pub detail: String,
}

impl TlsFailure {
    pub(crate) fn from_rustls(err: &rustls::Error) -> Self {
        Self {
            class: classify(err),
            detail: err.to_string(),
        }
    }

    /// From the I/O error a tokio-rustls handshake returns: the TLS error
    /// inside it if there is one, otherwise a `protocol` failure naming the
    /// I/O error kind (for example the peer closing the connection).
    pub(crate) fn from_io(err: &std::io::Error) -> Self {
        match err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        {
            Some(tls) => Self::from_rustls(tls),
            None => Self {
                class: TlsFailureClass::Protocol,
                detail: format!("I/O during handshake: {}", err.kind()),
            },
        }
    }
}

/// Maps a rustls error to a failure class.
pub(crate) fn classify(err: &rustls::Error) -> TlsFailureClass {
    use rustls::CertificateError as C;
    match err {
        rustls::Error::InvalidCertificate(c) => match c {
            C::UnknownIssuer
            | C::BadSignature
            | C::UnsupportedSignatureAlgorithmContext { .. }
            | C::UnsupportedSignatureAlgorithmForPublicKeyContext { .. } => {
                TlsFailureClass::Untrusted
            }
            C::Expired | C::ExpiredContext { .. } => TlsFailureClass::Expired,
            C::NotValidYet | C::NotValidYetContext { .. } => TlsFailureClass::NotYetValid,
            C::Revoked => TlsFailureClass::Revoked,
            C::ExpiredRevocationList | C::ExpiredRevocationListContext { .. } => {
                TlsFailureClass::CrlStale
            }
            C::UnknownRevocationStatus => TlsFailureClass::RevocationUnknown,
            C::InvalidPurpose | C::InvalidPurposeContext { .. } => TlsFailureClass::BadEku,
            C::UnhandledCriticalExtension => TlsFailureClass::UnknownCriticalExt,
            // Raised only by our policy check (server.rs).
            C::ApplicationVerificationFailure => TlsFailureClass::Policy,
            // webpki reports an unrecognised critical extension through an
            // opaque error whose text is the variant name. The tls tests
            // pin this mapping so a dependency change cannot hide it.
            C::Other(other) if other.to_string() == "UnsupportedCriticalExtension" => {
                TlsFailureClass::UnknownCriticalExt
            }
            _ => TlsFailureClass::BadCertificate,
        },
        _ => TlsFailureClass::Protocol,
    }
}

pub(crate) fn protocol_versions(
    min: TlsMinVersion,
) -> &'static [&'static SupportedProtocolVersion] {
    static BOTH: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13, &rustls::version::TLS12];
    static TLS13_ONLY: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];
    match min {
        TlsMinVersion::Tls12 => BOTH,
        TlsMinVersion::Tls13 => TLS13_ONLY,
    }
}

/// Signature schemes we accept in handshakes, in preference order.
const ALLOWED_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

type Alg = &'static dyn SignatureVerificationAlgorithm;

fn allowed_key(alg: Alg) -> bool {
    let pk = alg.public_key_alg_id();
    pk == alg_id::ECDSA_P256 || pk == alg_id::ECDSA_P384 || pk == alg_id::RSA_ENCRYPTION
}

/// The provider's verification algorithms restricted to P-256/P-384 ECDSA
/// and RSA keys (no Ed25519, P-521 or ML-DSA), and to [`ALLOWED_SCHEMES`].
fn restricted_algorithms(base: &WebPkiSupportedAlgorithms) -> WebPkiSupportedAlgorithms {
    static ALL: OnceLock<Vec<Alg>> = OnceLock::new();
    static INNER: OnceLock<Vec<(SignatureScheme, Vec<Alg>)>> = OnceLock::new();
    static MAPPING: OnceLock<Vec<(SignatureScheme, &'static [Alg])>> = OnceLock::new();

    let all = ALL.get_or_init(|| {
        base.all
            .iter()
            .copied()
            .filter(|a| allowed_key(*a))
            .collect()
    });
    let inner = INNER.get_or_init(|| {
        ALLOWED_SCHEMES
            .iter()
            .filter_map(|scheme| {
                base.mapping
                    .iter()
                    .find(|(s, _)| s == scheme)
                    .map(|(s, algs)| {
                        let kept: Vec<Alg> =
                            algs.iter().copied().filter(|a| allowed_key(*a)).collect();
                        (*s, kept)
                    })
            })
            .filter(|(_, algs)| !algs.is_empty())
            .collect()
    });
    let mapping = MAPPING.get_or_init(|| {
        inner
            .iter()
            .map(|(s, algs)| (*s, algs.as_slice()))
            .collect()
    });
    WebPkiSupportedAlgorithms {
        all: all.as_slice(),
        mapping: mapping.as_slice(),
    }
}

/// The restricted FIPS provider shared by every configuration.
///
/// # Errors
///
/// [`CryptoError::FipsModeInactive`] if the module or the restricted
/// provider is not in FIPS mode.
pub(crate) fn tls_provider() -> Result<Arc<CryptoProvider>, CryptoError> {
    static PROVIDER: OnceLock<Arc<CryptoProvider>> = OnceLock::new();
    crate::fips_status()?;
    let p = PROVIDER.get_or_init(|| {
        let base = rustls::crypto::default_fips_provider();
        let algs = restricted_algorithms(&base.signature_verification_algorithms);
        Arc::new(CryptoProvider {
            cipher_suites: vec![
                cipher_suite::TLS13_AES_256_GCM_SHA384,
                cipher_suite::TLS13_AES_128_GCM_SHA256,
                cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ],
            kx_groups: vec![kx_group::SECP384R1, kx_group::SECP256R1],
            signature_verification_algorithms: algs,
            ..base
        })
    });
    if !p.fips() {
        return Err(CryptoError::FipsModeInactive {
            component: "rustls provider",
        });
    }
    Ok(Arc::clone(p))
}

fn config_err(e: impl fmt::Display) -> CryptoError {
    CryptoError::TlsConfig {
        reason: e.to_string(),
    }
}

/// An empty presented-certificate slot (test PKI's blocking acceptor).
#[cfg(feature = "test-pki")]
pub(crate) fn server_slot() -> server::PresentedSlot {
    server::PresentedSlot::default()
}

/// Builds a root store from a PEM bundle (at least one anchor).
fn root_store(pem_text: &[u8], what: &'static str) -> Result<rustls::RootCertStore, CryptoError> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in crate::pem::certificates(pem_text, what)? {
        roots.add(cert).map_err(config_err)?;
    }
    Ok(roots)
}

#[cfg(test)]
#[cfg(feature = "test-pki")]
mod tests;

#[cfg(test)]
mod provider_tests {
    use super::*;

    #[test]
    fn provider_is_fips_and_restricted() {
        let p = tls_provider().unwrap();
        assert!(p.fips());
        assert_eq!(p.cipher_suites.len(), 6);
        assert_eq!(p.kx_groups.len(), 2);
        let schemes: Vec<_> = p
            .signature_verification_algorithms
            .mapping
            .iter()
            .map(|(s, _)| *s)
            .collect();
        assert_eq!(schemes, ALLOWED_SCHEMES);
        for alg in p.signature_verification_algorithms.all {
            assert!(allowed_key(*alg), "{alg:?}");
        }
        assert!(!p.signature_verification_algorithms.all.is_empty());
        for (_, algs) in p.signature_verification_algorithms.mapping {
            assert!(algs.iter().all(|a| allowed_key(*a)));
        }
    }

    #[test]
    fn classes_have_stable_names() {
        assert_eq!(TlsFailureClass::CrlStale.to_string(), "crl_stale");
        assert_eq!(
            TlsFailureClass::UnknownCriticalExt.as_str(),
            "unknown_critical_ext"
        );
    }

    #[test]
    fn only_validity_period_classes_are_time_related() {
        assert!(TlsFailureClass::Expired.is_time_related());
        assert!(TlsFailureClass::NotYetValid.is_time_related());
        for c in [
            TlsFailureClass::Untrusted,
            TlsFailureClass::Revoked,
            TlsFailureClass::CrlStale,
            TlsFailureClass::RevocationUnknown,
            TlsFailureClass::BadEku,
            TlsFailureClass::UnknownCriticalExt,
            TlsFailureClass::Policy,
            TlsFailureClass::BadCertificate,
            TlsFailureClass::Protocol,
        ] {
            assert!(!c.is_time_related(), "{c}");
        }
    }
}
