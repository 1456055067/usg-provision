//! X.509 certificate facts for identity binding and audit (RFC 5280).
//!
//! [`PeerCertificate`] is parsed from a certificate the TLS stack has
//! already validated, and from operator-supplied certificates at enrolment.
//! It carries only public data. Operators are bound to a certificate by
//! [`PeerCertificate::sha256`], the SHA-256 of the end-entity DER (plan M2
//! section 1.1), never by name matching.

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-2 (Identification and Authentication) - one certificate
//   fingerprint maps to one operator (decision 0007).
// - NIST 800-53: AU-3 (Content of Audit Records) - subject, issuer and
//   serial for "who".
// - NIST 800-53: SI-10 (Information Input Validation) - DER length cap and
//   strict DER decoding; no panics on input.
// - NIST 800-53: IA-5(2) (PKI-Based Authentication) - an operator
//   certificate must carry the id-kp-clientAuth extended key usage.
// - RFC 5280 §4.1 (certificate fields), §4.2.1.4 (certificate policies),
//   §4.2.1.12 (extended key usage).

use std::fmt;
use std::time::SystemTime;

use usgp_common::Sha256Digest;
use x509_cert::Certificate;
use x509_cert::der::Decode;
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::ext::pkix::{CertificatePolicies, ExtendedKeyUsage};

use crate::CryptoError;
use crate::digest::hex_lower;
use crate::pem;

/// `id-kp-clientAuth` (RFC 5280 §4.2.1.12), dotted form.
pub const ID_KP_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";

/// Public facts about one certificate.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerCertificate {
    /// The certificate DER exactly as presented.
    pub der: Vec<u8>,
    /// SHA-256 of [`Self::der`]; the operator binding key.
    pub sha256: Sha256Digest,
    /// Subject DN in RFC 4514 text form.
    pub subject: String,
    /// Issuer DN in RFC 4514 text form.
    pub issuer: String,
    /// Serial number, lowercase hex, big-endian, no leading zero octets.
    pub serial: String,
    /// Start of validity (inclusive, RFC 5280 §4.1.2.5).
    pub not_before: SystemTime,
    /// End of validity (inclusive).
    pub not_after: SystemTime,
    /// Policy OIDs asserted in certificatePolicies, dotted form, in order.
    pub policies: Vec<String>,
    /// Purposes in the extendedKeyUsage extension, dotted form, in order;
    /// `None` if the extension is absent.
    pub extended_key_usage: Option<Vec<String>>,
}

impl PeerCertificate {
    /// Parses one DER certificate.
    ///
    /// This does **not** validate the certificate; validation is the TLS
    /// verifier's job. It only extracts facts.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InputTooLarge`] above 64 KiB, and
    /// [`CryptoError::Certificate`] if the DER does not decode or the
    /// certificatePolicies extension is malformed or repeated.
    pub fn from_der(der: &[u8]) -> Result<Self, CryptoError> {
        if der.len() > pem::MAX_CERT_DER_BYTES {
            return Err(CryptoError::InputTooLarge {
                what: "certificate",
                limit: pem::MAX_CERT_DER_BYTES,
            });
        }
        let cert = Certificate::from_der(der).map_err(|_| CryptoError::Certificate {
            reason: "not a DER X.509 certificate",
        })?;
        let tbs = &cert.tbs_certificate;
        let policies = match tbs.get::<CertificatePolicies>() {
            Ok(None) => Vec::new(),
            Ok(Some((_critical, p))) => {
                p.0.iter()
                    .map(|info| info.policy_identifier.to_string())
                    .collect()
            }
            Err(_) => {
                return Err(CryptoError::Certificate {
                    reason: "malformed or repeated certificatePolicies extension",
                });
            }
        };
        let extended_key_usage = match tbs.get::<ExtendedKeyUsage>() {
            Ok(None) => None,
            Ok(Some((_critical, eku))) => Some(eku.0.iter().map(ToString::to_string).collect()),
            Err(_) => {
                return Err(CryptoError::Certificate {
                    reason: "malformed or repeated extendedKeyUsage extension",
                });
            }
        };
        Ok(Self {
            der: der.to_vec(),
            sha256: crate::sha256(der),
            subject: tbs.subject.to_string(),
            issuer: tbs.issuer.to_string(),
            serial: hex_lower(tbs.serial_number.as_bytes()),
            not_before: tbs.validity.not_before.to_system_time(),
            not_after: tbs.validity.not_after.to_system_time(),
            policies,
            extended_key_usage,
        })
    }

    /// Parses the first certificate of a PEM bundle (for enrolment from a
    /// file).
    ///
    /// # Errors
    ///
    /// As [`Self::from_der`], plus [`CryptoError::Pem`].
    pub fn from_pem(pem_text: &[u8]) -> Result<Self, CryptoError> {
        let certs = pem::certificates(pem_text, "certificate")?;
        let first = certs.first().ok_or(CryptoError::Pem {
            what: "certificate",
            reason: "no CERTIFICATE block",
        })?;
        Self::from_der(first.as_ref())
    }

    /// True if any asserted policy is in `acceptable`.
    ///
    /// Exact OID match only: there is no policy-tree processing (policy
    /// mapping, inhibitAnyPolicy, requireExplicitPolicy), and anyPolicy
    /// matches only if it is itself listed.
    #[must_use]
    pub fn asserts_any_policy(&self, acceptable: &[ObjectIdentifier]) -> bool {
        self.policies
            .iter()
            .any(|p| acceptable.iter().any(|a| a.to_string() == *p))
    }
}

impl PeerCertificate {
    /// True if the extendedKeyUsage extension is present and lists
    /// `id-kp-clientAuth`.
    ///
    /// Stricter than RFC 5280 §4.2.1.12, under which an absent extension
    /// places no restriction: an operator certificate must state the TLS
    /// client purpose explicitly (IA-5(2)). `anyExtendedKeyUsage` alone
    /// is not enough.
    #[must_use]
    pub fn permits_client_auth(&self) -> bool {
        self.extended_key_usage
            .as_ref()
            .is_some_and(|eku| eku.iter().any(|p| p == ID_KP_CLIENT_AUTH))
    }

    /// The rule the API server applies in the handshake, for use before
    /// enrolling an operator certificate (so a certificate that can never
    /// log in is refused at enrolment).
    ///
    /// # Errors
    ///
    /// [`CryptoError::Certificate`] if [`Self::permits_client_auth`] is
    /// false.
    pub fn require_client_auth_eku(&self) -> Result<(), CryptoError> {
        if self.permits_client_auth() {
            Ok(())
        } else {
            Err(CryptoError::Certificate {
                reason: "no extendedKeyUsage extension listing id-kp-clientAuth",
            })
        }
    }
}

impl fmt::Debug for PeerCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerCertificate")
            .field("sha256", &self.sha256.to_hex())
            .field("subject", &self.subject)
            .field("issuer", &self.issuer)
            .field("serial", &self.serial)
            .field("policies", &self.policies)
            .field("extended_key_usage", &self.extended_key_usage)
            .finish_non_exhaustive()
    }
}

/// Parses configured policy OIDs (dotted decimal).
///
/// # Errors
///
/// [`CryptoError::PolicyOid`] naming the first bad position.
pub fn parse_policy_oids(oids: &[String]) -> Result<Vec<ObjectIdentifier>, CryptoError> {
    oids.iter()
        .enumerate()
        .map(|(index, s)| ObjectIdentifier::new(s).map_err(|_| CryptoError::PolicyOid { index }))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garbage_is_an_error() {
        assert!(PeerCertificate::from_der(&[]).is_err());
        assert!(PeerCertificate::from_der(&[0x30, 0x80]).is_err());
        assert!(matches!(
            PeerCertificate::from_der(&vec![0x30; pem::MAX_CERT_DER_BYTES + 1]),
            Err(CryptoError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn policy_oid_parsing() {
        let ok = parse_policy_oids(&["1.3.6.1.5.5.7.13.1".to_string()]).unwrap();
        assert_eq!(ok.len(), 1);
        let err = parse_policy_oids(&["1.3.6.1.5.5.7.13.1".into(), "not-an-oid".into()]);
        assert!(matches!(err, Err(CryptoError::PolicyOid { index: 1 })));
    }
}
