//! TLS server configuration with operator client-certificate validation.
//!
//! Client certificates are validated by the WebPKI verifier (RFC 5280
//! path validation subset) against the configured trust anchors and CRLs:
//!
//! - a certificate is optional at the TLS layer, so a connection without
//!   one reaches HTTP and gets 401 there (plan M2 section 1.1);
//! - a certificate that is presented and invalid fails the handshake;
//! - revocation is checked for every certificate in the path (not only the
//!   end entity); unknown status is refused; a CRL past its nextUpdate is
//!   refused (fail closed);
//! - signatures, validity, basic constraints, path length, key usage, the
//!   `id-kp-clientAuth` EKU (when an EKU extension is present), name
//!   constraints and unrecognised critical extensions are checked by
//!   webpki;
//! - the end entity must carry an extendedKeyUsage extension listing
//!   `id-kp-clientAuth` (stricter than RFC 5280 §4.2.1.12, under which an
//!   absent extension means any purpose); checked inside the handshake
//!   right after path validation, class `bad_eku`;
//! - if acceptable policy OIDs are configured, the end entity must assert
//!   one of them (checked at the same point).
//!
//! Each connection gets its own `ServerConfig` (sharing the parsed key,
//! anchors and CRLs) whose verifier keeps the end-entity certificate the
//! client presented, so a refused handshake can still name it in the
//! audit record ([`RefusedHandshake::presented`]). It also records
//! whether the presented certificate chains to a configured trust anchor
//! ([`RefusedHandshake::chained_to_trust_anchor`]), so the audit budget
//! can tell our PKI's refused certificates from self-made ones (finding
//! SEC-012 / NIST-014; see `chain.rs`).

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-2 (Identification and Authentication), IA-5(2)
//   (PKI-Based Authentication) - RFC 5280 path validation subset, CRLs,
//   fail closed on unknown or stale revocation status.
// - NIST 800-53: AC-3 (Access Enforcement) - an invalid certificate never
//   reaches the HTTP layer.
// - NIST 800-53: SC-23 (Session Authenticity) - no session storage, no
//   tickets: every connection re-validates against the current CRLs.
// - NIST 800-53: SC-13 - `ServerConfig::fips()` asserted at build time
//   and for every per-connection configuration.
// - NIST 800-53: AU-3 (Content of Audit Records) - a refused handshake
//   carries the presented certificate's facts for "who".
// - NIST 800-53: AU-2, AU-12, AC-7 - a refused handshake says whether
//   the certificate chains to a configured anchor (audit budget split).
// - SPEC: plan M2 section 5.4; decision 0007; REQ-RBAC-005.
// - RFC 5280 §6.1 (subset), §6.3 (CRL), §4.2.1.4 (policies, exact match),
//   §4.2.1.12 (extended key usage).
// POAM: no RFC 5280 policy-tree processing (policy mapping, inhibit
// anyPolicy, explicit policy); exact OID match only.
// POAM: revocation by CRL files only; no OCSP and no CRL distribution
// point fetching. The server reloads CRL files by rebuilding this config.

use std::sync::{Arc, Mutex};

use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme,
    SupportedProtocolVersion,
};
use usgp_common::Sha256Digest;
use x509_cert::der::oid::ObjectIdentifier;

use tokio::io::{AsyncRead, AsyncWrite};

use super::chain::{Anchor, chains_to_anchor};
use super::settings::ServerTlsSettings;
use super::stream::ServerTlsStream;
use super::{ALPN_HTTP11, config_err, protocol_versions, root_store};
use crate::CryptoError;
use crate::pem;
use crate::x509::{PeerCertificate, parse_policy_oids};

/// A built TLS server configuration (immutable; rebuild to reload CRLs).
#[derive(Clone)]
pub struct ServerTls {
    /// Configuration without certificate capture (inspection and tests).
    config: Arc<ServerConfig>,
    parts: Arc<Parts>,
    acceptable_policies: Arc<[ObjectIdentifier]>,
}

/// Everything a per-connection configuration is built from.
struct Parts {
    provider: Arc<CryptoProvider>,
    versions: &'static [&'static SupportedProtocolVersion],
    webpki: Arc<dyn ClientCertVerifier>,
    certified: Arc<CertifiedKey>,
    /// Anchor names and keys for the chained-or-not probe.
    anchors: Arc<[Anchor]>,
}

/// The end-entity certificate a client presented on one connection, and
/// whether it chains to a configured trust anchor.
#[derive(Debug, Default)]
pub(crate) struct PresentedSlot(Mutex<Option<Presented>>);

/// What [`PresentedSlot`] holds.
#[derive(Debug, Clone)]
pub(crate) struct Presented {
    pub(crate) der: CertificateDer<'static>,
    pub(crate) chained: bool,
}

impl PresentedSlot {
    fn store(&self, cert: &CertificateDer<'_>, chained: bool) {
        if let Ok(mut g) = self.0.lock() {
            *g = Some(Presented {
                der: cert.clone().into_owned(),
                chained,
            });
        }
    }

    pub(crate) fn take(&self) -> Option<Presented> {
        self.0.lock().ok().and_then(|mut g| g.take())
    }
}

/// A refused handshake together with the certificate the client
/// presented, if it presented one (AU-3: "who" for `auth.tls.failed`).
#[derive(Debug, Clone)]
pub struct RefusedHandshake {
    failure: super::TlsFailure,
    presented_sha256: Option<Sha256Digest>,
    /// Boxed: keeps the `Err` variant small (clippy `result_large_err`).
    presented: Option<Box<PeerCertificate>>,
    chained: bool,
}

impl RefusedHandshake {
    pub(crate) fn new(failure: super::TlsFailure, presented: Option<Presented>) -> Self {
        let chained = presented.as_ref().is_some_and(|p| p.chained);
        let presented_der = presented.map(|p| p.der);
        let presented_sha256 = presented_der.as_ref().map(|d| crate::sha256(d.as_ref()));
        let presented = presented_der
            .and_then(|d| PeerCertificate::from_der(d.as_ref()).ok())
            .map(Box::new);
        Self {
            failure,
            presented_sha256,
            presented,
            chained,
        }
    }

    /// True if the client presented a certificate whose signature path
    /// leads to a configured client trust anchor (it was issued by our
    /// PKI, whatever made it fail: revoked, expired, wrong purpose,
    /// policy, ...). False if nothing was presented, or the certificate is
    /// self-made, from a foreign issuer, or does not parse.
    ///
    /// Only names and signatures are checked (`chain.rs`); this is an
    /// audit classification, never an authentication result.
    #[must_use]
    pub const fn chained_to_trust_anchor(&self) -> bool {
        self.chained
    }

    /// The class and detail of the refusal.
    #[must_use]
    pub const fn failure(&self) -> &super::TlsFailure {
        &self.failure
    }

    /// Facts of the end-entity certificate the client presented, if it
    /// presented one and it parses (it was **not** accepted: these are
    /// claims, not an authenticated identity).
    #[must_use]
    pub fn presented(&self) -> Option<&PeerCertificate> {
        self.presented.as_deref()
    }

    /// SHA-256 of the presented end-entity DER, also when it does not
    /// parse.
    #[must_use]
    pub const fn presented_sha256(&self) -> Option<&Sha256Digest> {
        self.presented_sha256.as_ref()
    }

    /// The failure alone.
    #[must_use]
    pub fn into_failure(self) -> super::TlsFailure {
        self.failure
    }
}

impl std::fmt::Display for RefusedHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.failure, f)
    }
}

impl std::error::Error for RefusedHandshake {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.failure)
    }
}

impl std::fmt::Debug for ServerTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerTls")
            .field("fips", &self.config.fips())
            .field("acceptable_policies", &self.acceptable_policies.len())
            .finish_non_exhaustive()
    }
}

impl ServerTls {
    /// Builds the server configuration.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::FipsModeInactive`] if FIPS mode is off or the
    ///   built configuration does not report `fips()`;
    /// - [`CryptoError::Pem`] / [`CryptoError::InputTooLarge`] for bad
    ///   inputs;
    /// - [`CryptoError::TlsConfig`] if no CRL is given, a CRL or anchor
    ///   does not parse, or the key does not match the certificate;
    /// - [`CryptoError::PolicyOid`] for a bad policy OID.
    pub fn new(settings: &ServerTlsSettings) -> Result<Self, CryptoError> {
        let provider = super::tls_provider()?;

        let chain = pem::certificates(&settings.cert_chain_pem, "server certificate chain")?;
        let mut key_der = pem::decode_secret(
            &settings.private_key_pem,
            pem::LABEL_PRIVATE_KEY,
            "server private key",
        )?;
        // rustls wraps the key in its own zeroizing buffer when loading it.
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::mem::take(&mut *key_der)));
        drop(key_der);
        // Loads the key in the FIPS module and checks it matches the
        // certificate (as `with_single_cert` does).
        let certified =
            Arc::new(CertifiedKey::from_der(chain, key, &provider).map_err(config_err)?);

        let roots = root_store(&settings.client_trust_anchors_pem, "client trust anchors")?;
        let anchors =
            pem::certificates(&settings.client_trust_anchors_pem, "client trust anchors")?
                .iter()
                .map(|c| {
                    Anchor::from_der(c.as_ref()).ok_or_else(|| CryptoError::TlsConfig {
                        reason: "a client trust anchor is not an X.509 certificate".to_string(),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
        let mut crls = Vec::new();
        for input in &settings.client_crls {
            crls.extend(pem::crls(input)?);
        }
        if crls.is_empty() {
            return Err(CryptoError::TlsConfig {
                reason: "at least one client CRL is required".to_string(),
            });
        }
        let acceptable: Arc<[ObjectIdentifier]> =
            parse_policy_oids(&settings.acceptable_policy_oids)?.into();

        // Defaults kept on purpose: revocation checked for the whole chain,
        // unknown revocation status denied.
        let webpki = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .allow_unauthenticated()
            .with_crls(crls)
            .enforce_revocation_expiration()
            .build()
            .map_err(config_err)?;

        let parts = Arc::new(Parts {
            provider,
            versions: protocol_versions(settings.min_version),
            webpki,
            certified,
            anchors: anchors.into(),
        });
        let config = build_config(&parts, &acceptable, None)?;
        Ok(Self {
            config: Arc::new(config),
            parts,
            acceptable_policies: acceptable,
        })
    }

    /// A configuration for one connection whose verifier records the
    /// presented end-entity certificate in `slot`.
    pub(crate) fn connection_config(
        &self,
        slot: &Arc<PresentedSlot>,
    ) -> Result<Arc<ServerConfig>, CryptoError> {
        build_config(
            &self.parts,
            &self.acceptable_policies,
            Some(Arc::clone(slot)),
        )
        .map(Arc::new)
    }

    /// True if the built configuration uses only FIPS-approved
    /// algorithms from the validated module (always true for a value that
    /// [`Self::new`] returned).
    #[must_use]
    pub fn is_fips(&self) -> bool {
        self.config.fips()
    }

    /// The configuration without certificate capture (unit tests inspect
    /// its settings; connections use [`Self::connection_config`]).
    #[cfg(all(test, feature = "test-pki"))]
    pub(crate) fn config(&self) -> Arc<ServerConfig> {
        Arc::clone(&self.config)
    }

    /// Runs the TLS handshake on `io` and returns the stream plus the
    /// operator certificate.
    ///
    /// `Ok((stream, None))` means no certificate was presented: the HTTP
    /// layer answers 401 and audits it. A presented certificate that fails
    /// validation (or the EKU or policy rule) is an `Err` with a stable
    /// class for the `auth.tls.failed` audit event. The caller applies the
    /// handshake timeout (for example `tokio::time::timeout`).
    ///
    /// Use [`Self::accept_with_presented`] to also learn which certificate
    /// a refused client presented.
    ///
    /// # Errors
    ///
    /// [`super::TlsFailure`] if the handshake is refused or fails.
    pub async fn accept<IO>(
        &self,
        io: IO,
    ) -> Result<(ServerTlsStream<IO>, Option<PeerCertificate>), super::TlsFailure>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        self.accept_with_presented(io)
            .await
            .map_err(RefusedHandshake::into_failure)
    }

    /// As [`Self::accept`], but a refusal also carries the facts of the
    /// end-entity certificate the client presented
    /// ([`RefusedHandshake::presented`], [`RefusedHandshake::presented_sha256`]).
    ///
    /// # Errors
    ///
    /// [`RefusedHandshake`] if the handshake is refused or fails.
    pub async fn accept_with_presented<IO>(
        &self,
        io: IO,
    ) -> Result<(ServerTlsStream<IO>, Option<PeerCertificate>), RefusedHandshake>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let slot = Arc::new(PresentedSlot::default());
        let config = self.connection_config(&slot).map_err(|e| {
            RefusedHandshake::new(
                super::TlsFailure {
                    class: super::TlsFailureClass::Protocol,
                    detail: format!("connection configuration: {e}"),
                },
                None,
            )
        })?;
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        let stream = match acceptor.accept(io).await {
            Ok(s) => s,
            Err(e) => {
                return Err(RefusedHandshake::new(
                    super::TlsFailure::from_io(&e),
                    slot.take(),
                ));
            }
        };
        let peers = stream.get_ref().1.peer_certificates();
        match self.peer_identity(peers) {
            Ok(peer) => Ok((ServerTlsStream::new(stream), peer)),
            Err(f) => {
                // The verifier accepted the path, so it chains.
                let presented = peers.and_then(<[_]>::first).map(|c| Presented {
                    der: c.clone().into_owned(),
                    chained: true,
                });
                Err(RefusedHandshake::new(f, presented))
            }
        }
    }

    /// The operator identity after a completed handshake.
    ///
    /// `Ok(None)` means no certificate was presented (the HTTP layer
    /// answers 401). The policy rule is re-checked here as a second
    /// barrier.
    pub(crate) fn peer_identity(
        &self,
        peer: Option<&[CertificateDer<'static>]>,
    ) -> Result<Option<PeerCertificate>, super::TlsFailure> {
        let Some(end_entity) = peer.and_then(<[_]>::first) else {
            return Ok(None);
        };
        let cert =
            PeerCertificate::from_der(end_entity.as_ref()).map_err(|e| super::TlsFailure {
                class: super::TlsFailureClass::BadCertificate,
                detail: e.to_string(),
            })?;
        if !cert.permits_client_auth() {
            return Err(super::TlsFailure {
                class: super::TlsFailureClass::BadEku,
                detail: "certificate has no extendedKeyUsage listing id-kp-clientAuth".to_string(),
            });
        }
        if !self.acceptable_policies.is_empty()
            && !cert.asserts_any_policy(&self.acceptable_policies)
        {
            return Err(super::TlsFailure {
                class: super::TlsFailureClass::Policy,
                detail: "certificate asserts no acceptable policy".to_string(),
            });
        }
        Ok(Some(cert))
    }
}

/// Builds a server configuration over `parts`.
fn build_config(
    parts: &Parts,
    acceptable: &Arc<[ObjectIdentifier]>,
    capture: Option<Arc<PresentedSlot>>,
) -> Result<ServerConfig, CryptoError> {
    let verifier = Arc::new(PolicyCheckingVerifier {
        inner: Arc::clone(&parts.webpki),
        acceptable: Arc::clone(acceptable),
        capture,
        anchors: Arc::clone(&parts.anchors),
        algorithms: parts.provider.signature_verification_algorithms,
    });
    let mut config = ServerConfig::builder_with_provider(Arc::clone(&parts.provider))
        .with_protocol_versions(parts.versions)
        .map_err(config_err)?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(Arc::clone(
            &parts.certified,
        ))));
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];

    if !config.fips() {
        return Err(CryptoError::FipsModeInactive {
            component: "tls server config",
        });
    }
    Ok(config)
}

/// WebPKI verifier plus the clientAuth EKU and acceptable-policy rules.
#[derive(Debug)]
struct PolicyCheckingVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    acceptable: Arc<[ObjectIdentifier]>,
    /// Where the presented end entity is kept (per-connection configs).
    capture: Option<Arc<PresentedSlot>>,
    /// For the chained-or-not probe on refusal.
    anchors: Arc<[Anchor]>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for PolicyCheckingVerifier {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let verified = match self
            .inner
            .verify_client_cert(end_entity, intermediates, now)
        {
            Ok(v) => v,
            Err(e) => {
                if let Some(slot) = &self.capture {
                    // SEC-012: refused, but is it from our PKI? Probe only
                    // on refusal, and only per-connection configs.
                    let inter: Vec<&[u8]> = intermediates.iter().map(AsRef::as_ref).collect();
                    let chained = chains_to_anchor(
                        &self.anchors,
                        &self.algorithms,
                        end_entity.as_ref(),
                        &inter,
                    );
                    slot.store(end_entity, chained);
                }
                return Err(e);
            }
        };
        // Path validated: any refusal from here on is a certificate that
        // chains to a configured anchor.
        if let Some(slot) = &self.capture {
            slot.store(end_entity, true);
        }
        let cert = PeerCertificate::from_der(end_entity.as_ref())
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        // IA-5(2), SEC-006: the TLS client purpose must be stated.
        if !cert.permits_client_auth() {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::InvalidPurpose,
            ));
        }
        if !self.acceptable.is_empty() && !cert.asserts_any_policy(&self.acceptable) {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
