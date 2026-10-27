//! Test PKI: CAs, end-entity certificates and CRLs for tests only.
//!
//! Compiled only with the `test-pki` feature, which release binaries never
//! enable (plan M2 WU-1; CI checks the release feature set). Certificates
//! are built with `x509-cert` types and signed with our own
//! [`SigningKey`] (ECDSA P-384 with SHA-384) inside the validated module.
//! Nothing here is real PIV data (decision 0007).
//!
//! The policy and extension OIDs are the test-policy OIDs that RFC 7229
//! assigns for exactly this purpose, so they collide with no real policy.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation) - generated test
//   credentials for the mTLS negative-path tests.
// - NIST 800-53: CM-7 (Least Functionality) - behind a feature that
//   release builds do not enable.
// - RFC 5280 §4.1, §4.2, §5 (certificate and CRL profile); RFC 7229 (test
//   policy OIDs); RFC 7093 §2 method 1 (key identifiers).

use std::net::IpAddr;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::crl::{CertificateList, RevokedCert, TbsCertList};
use x509_cert::der::asn1::{BitString, Ia5String, OctetString, Uint, UtcTime};
use x509_cert::der::oid::{AssociatedOid, ObjectIdentifier};
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::certpolicy::PolicyInformation;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, CertificatePolicies, CrlNumber, ExtendedKeyUsage,
    KeyUsage, KeyUsages, SubjectAltName, SubjectKeyIdentifier,
};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::pem;
use crate::sign::SigningKey;
use crate::tls::{
    ClientAlpn, ClientTls, ClientTlsSettings, PeerCertificate, ServerTls, ServerTlsSettings,
    TlsFailure, TlsMinVersion, TlsProtocol,
};

/// RFC 7229 id-TEST-certPolicyOne: the "acceptable" policy in tests.
pub const POLICY_ACCEPTED: &str = "1.3.6.1.5.5.7.13.1";
/// RFC 7229 id-TEST-certPolicyTwo: a policy that is not acceptable.
pub const POLICY_OTHER: &str = "1.3.6.1.5.5.7.13.2";
/// RFC 7229 id-TEST-certPolicyEight, used as an extension id that no
/// implementation recognises (marked critical in one test certificate).
pub const UNKNOWN_CRITICAL_EXTENSION_OID: &str = "1.3.6.1.5.5.7.13.8";

/// ecdsa-with-SHA384 (RFC 5758 §3.2).
const ECDSA_WITH_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
/// id-kp-serverAuth (RFC 5280 §4.2.1.12).
const ID_KP_SERVER_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
/// id-kp-clientAuth (RFC 5280 §4.2.1.12).
const ID_KP_CLIENT_AUTH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
const UNKNOWN_EXT: ObjectIdentifier = ObjectIdentifier::new_unwrap(UNKNOWN_CRITICAL_EXTENSION_OID);

const DAY: Duration = Duration::from_secs(86_400);
const HOUR: Duration = Duration::from_secs(3_600);

fn enc(what: &'static str) -> impl Fn(x509_cert::der::Error) -> CryptoError {
    move |_| CryptoError::Encoding { what }
}

fn now_secs() -> SystemTime {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn utc(t: SystemTime) -> Result<Time, CryptoError> {
    Ok(Time::UtcTime(
        UtcTime::from_system_time(t).map_err(enc("time"))?,
    ))
}

fn sig_alg() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ECDSA_WITH_SHA384,
        parameters: None,
    }
}

fn ext<T: Encode + AssociatedOid>(value: &T, critical: bool) -> Result<Extension, CryptoError> {
    Ok(Extension {
        extn_id: T::OID,
        critical,
        extn_value: OctetString::new(value.to_der().map_err(enc("extension"))?)
            .map_err(enc("extension"))?,
    })
}

fn random_serial() -> Result<Vec<u8>, CryptoError> {
    let mut b = vec![0u8; 16];
    crate::rand::fill_random(&mut b)?;
    if let Some(first) = b.first_mut() {
        // Positive, and no leading zero octet to strip.
        *first = (*first & 0x3f) | 0x40;
    }
    Ok(b)
}

/// RFC 7093 §2 method 1: leftmost 160 bits of SHA-256 of the
/// subjectPublicKey bits.
fn key_identifier(spki: &SubjectPublicKeyInfoOwned) -> Vec<u8> {
    let digest = crate::sha256(spki.subject_public_key.raw_bytes());
    digest.0.iter().take(20).copied().collect()
}

fn sign_tbs(key: &SigningKey, tbs: &TbsCertificate) -> Result<Vec<u8>, CryptoError> {
    let tbs_der = tbs.to_der().map_err(enc("TBSCertificate"))?;
    let sig = key.sign_raw(&tbs_der)?;
    let cert = Certificate {
        tbs_certificate: tbs.clone(),
        signature_algorithm: sig_alg(),
        signature: BitString::from_bytes(&sig).map_err(enc("signature"))?,
    };
    cert.to_der().map_err(enc("Certificate"))
}

/// Which validity window a test certificate gets (relative to now).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Window {
    /// Valid from one hour ago for 30 days.
    Current,
    /// Ended one day ago.
    Expired,
    /// Starts in one day.
    NotYetValid,
}

/// Extended key usage of a test end-entity certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eku {
    /// `id-kp-clientAuth` only.
    ClientAuth,
    /// `id-kp-serverAuth` only.
    ServerAuth,
    /// No EKU extension.
    Absent,
}

/// What to put in a test end-entity certificate.
#[derive(Debug, Clone)]
pub struct LeafSpec {
    /// Subject common name.
    pub common_name: String,
    /// Validity window.
    pub window: Window,
    /// Extended key usage.
    pub eku: Eku,
    /// DNS names for subjectAltName.
    pub dns_names: Vec<String>,
    /// IP addresses for subjectAltName.
    pub ip_addresses: Vec<IpAddr>,
    /// Policy OIDs for certificatePolicies (none = no extension).
    pub policies: Vec<String>,
    /// Add a critical extension nobody recognises.
    pub unknown_critical_extension: bool,
}

impl LeafSpec {
    /// A current operator (client) certificate asserting
    /// [`POLICY_ACCEPTED`].
    #[must_use]
    pub fn client(common_name: &str) -> Self {
        Self {
            common_name: common_name.to_string(),
            window: Window::Current,
            eku: Eku::ClientAuth,
            dns_names: Vec::new(),
            ip_addresses: Vec::new(),
            policies: vec![POLICY_ACCEPTED.to_string()],
            unknown_critical_extension: false,
        }
    }

    /// A current server certificate for `localhost` and 127.0.0.1.
    #[must_use]
    pub fn server(common_name: &str) -> Self {
        Self {
            common_name: common_name.to_string(),
            window: Window::Current,
            eku: Eku::ServerAuth,
            dns_names: vec!["localhost".to_string()],
            ip_addresses: vec![IpAddr::from([127, 0, 0, 1])],
            policies: Vec::new(),
            unknown_critical_extension: false,
        }
    }
}

/// A test certificate authority.
pub struct TestCa {
    name: Name,
    key: SigningKey,
    cert_der: Vec<u8>,
    serial: Vec<u8>,
    ski: Vec<u8>,
    /// PEM of this CA and its parents up to (not including) the root.
    chain_pem: Vec<u8>,
}

impl std::fmt::Debug for TestCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestCa")
            .field("name", &self.name.to_string())
            .finish_non_exhaustive()
    }
}

impl TestCa {
    /// A self-signed root CA (valid for 10 years from one hour ago).
    ///
    /// # Errors
    ///
    /// [`CryptoError`] if key generation, signing or encoding fails.
    pub fn root(common_name: &str) -> Result<Self, CryptoError> {
        let key = SigningKey::generate()?;
        let name = Name::from_str(&format!("CN={common_name},O=usgp-test")).map_err(enc("name"))?;
        let spki = SubjectPublicKeyInfoOwned::from_der(key.verifying_key().spki_der())
            .map_err(enc("spki"))?;
        let ski = key_identifier(&spki);
        let serial = random_serial()?;
        let now = now_secs();
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&serial).map_err(enc("serial"))?,
            signature: sig_alg(),
            issuer: name.clone(),
            validity: Validity {
                not_before: utc(now - HOUR)?,
                not_after: utc(now + DAY * 3650)?,
            },
            subject: name.clone(),
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(vec![
                ext(
                    &BasicConstraints {
                        ca: true,
                        path_len_constraint: None,
                    },
                    true,
                )?,
                ext(&KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign), true)?,
                ext(
                    &SubjectKeyIdentifier(OctetString::new(ski.clone()).map_err(enc("ski"))?),
                    false,
                )?,
            ]),
        };
        let cert_der = sign_tbs(&key, &tbs)?;
        Ok(Self {
            name,
            key,
            cert_der,
            serial,
            ski,
            chain_pem: Vec::new(),
        })
    }

    /// An intermediate CA issued by `self` (path length 0).
    ///
    /// # Errors
    ///
    /// [`CryptoError`] if key generation, signing or encoding fails.
    pub fn intermediate(&self, common_name: &str) -> Result<Self, CryptoError> {
        let key = SigningKey::generate()?;
        let name = Name::from_str(&format!("CN={common_name},O=usgp-test")).map_err(enc("name"))?;
        let spki = SubjectPublicKeyInfoOwned::from_der(key.verifying_key().spki_der())
            .map_err(enc("spki"))?;
        let ski = key_identifier(&spki);
        let serial = random_serial()?;
        let now = now_secs();
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&serial).map_err(enc("serial"))?,
            signature: sig_alg(),
            issuer: self.name.clone(),
            validity: Validity {
                not_before: utc(now - HOUR)?,
                not_after: utc(now + DAY * 1825)?,
            },
            subject: name.clone(),
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(vec![
                ext(
                    &BasicConstraints {
                        ca: true,
                        path_len_constraint: Some(0),
                    },
                    true,
                )?,
                ext(&KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign), true)?,
                ext(
                    &SubjectKeyIdentifier(OctetString::new(ski.clone()).map_err(enc("ski"))?),
                    false,
                )?,
                ext(&self.aki()?, false)?,
            ]),
        };
        let cert_der = sign_tbs(&self.key, &tbs)?;
        let mut chain_pem = pem::encode_public(pem::LABEL_CERTIFICATE, &cert_der)?.into_bytes();
        chain_pem.extend_from_slice(&self.chain_pem);
        Ok(Self {
            name,
            key,
            cert_der,
            serial,
            ski,
            chain_pem,
        })
    }

    fn aki(&self) -> Result<AuthorityKeyIdentifier, CryptoError> {
        Ok(AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(self.ski.clone()).map_err(enc("aki"))?),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        })
    }

    /// Issues an end-entity certificate.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] if key generation, signing or encoding fails.
    pub fn issue(&self, spec: &LeafSpec) -> Result<TestCert, CryptoError> {
        let key = SigningKey::generate()?;
        let subject =
            Name::from_str(&format!("CN={},O=usgp-test", spec.common_name)).map_err(enc("name"))?;
        let spki = SubjectPublicKeyInfoOwned::from_der(key.verifying_key().spki_der())
            .map_err(enc("spki"))?;
        let serial = random_serial()?;
        let now = now_secs();
        let (nb, na) = match spec.window {
            Window::Current => (now - HOUR, now + DAY * 30),
            Window::Expired => (now - DAY * 30, now - DAY),
            Window::NotYetValid => (now + DAY, now + DAY * 30),
        };
        let mut exts = vec![
            ext(&KeyUsage(KeyUsages::DigitalSignature.into()), true)?,
            ext(&self.aki()?, false)?,
        ];
        match spec.eku {
            Eku::ClientAuth => exts.push(ext(&ExtendedKeyUsage(vec![ID_KP_CLIENT_AUTH]), false)?),
            Eku::ServerAuth => exts.push(ext(&ExtendedKeyUsage(vec![ID_KP_SERVER_AUTH]), false)?),
            Eku::Absent => {}
        }
        let mut names = Vec::new();
        for dns in &spec.dns_names {
            names.push(GeneralName::DnsName(
                Ia5String::new(dns).map_err(enc("dns name"))?,
            ));
        }
        for ip in &spec.ip_addresses {
            names.push(GeneralName::from(*ip));
        }
        if !names.is_empty() {
            exts.push(ext(&SubjectAltName(names), false)?);
        }
        if !spec.policies.is_empty() {
            let mut infos = Vec::new();
            for p in &spec.policies {
                infos.push(PolicyInformation {
                    policy_identifier: ObjectIdentifier::new(p)
                        .map_err(|_| CryptoError::PolicyOid { index: infos.len() })?,
                    policy_qualifiers: None,
                });
            }
            exts.push(ext(&CertificatePolicies(infos), false)?);
        }
        if spec.unknown_critical_extension {
            exts.push(Extension {
                extn_id: UNKNOWN_EXT,
                critical: true,
                // An ASN.1 NULL as the value.
                extn_value: OctetString::new(vec![0x05, 0x00]).map_err(enc("extension"))?,
            });
        }
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&serial).map_err(enc("serial"))?,
            signature: sig_alg(),
            issuer: self.name.clone(),
            validity: Validity {
                not_before: utc(nb)?,
                not_after: utc(na)?,
            },
            subject,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(exts),
        };
        let cert_der = sign_tbs(&self.key, &tbs)?;
        let mut chain_pem = pem::encode_public(pem::LABEL_CERTIFICATE, &cert_der)?.into_bytes();
        chain_pem.extend_from_slice(&self.chain_pem);
        Ok(TestCert {
            cert_der,
            serial,
            key,
            chain_pem,
        })
    }

    /// A v2 CRL signed by this CA (DER), revoking `revoked` serials.
    ///
    /// A current CRL has thisUpdate one hour ago and nextUpdate in 7 days;
    /// a `stale` one has nextUpdate one hour ago.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] if signing or encoding fails.
    pub fn crl(&self, revoked: &[&[u8]], stale: bool) -> Result<Vec<u8>, CryptoError> {
        self.crl_numbered(revoked, stale, 1)
    }

    /// As [`Self::crl`] with cRLNumber `number` (RFC 5280 §5.2.3).
    ///
    /// # Errors
    ///
    /// [`CryptoError`] if signing or encoding fails.
    pub fn crl_numbered(
        &self,
        revoked: &[&[u8]],
        stale: bool,
        number: u64,
    ) -> Result<Vec<u8>, CryptoError> {
        let now = now_secs();
        let (this_update, next_update) = if stale {
            (now - DAY * 2, now - HOUR)
        } else {
            (now - HOUR, now + DAY * 7)
        };
        let mut entries = Vec::new();
        for serial in revoked {
            entries.push(RevokedCert {
                serial_number: SerialNumber::new(serial).map_err(enc("serial"))?,
                revocation_date: utc(now - HOUR)?,
                crl_entry_extensions: None,
            });
        }
        let tbs = TbsCertList {
            version: Version::V2,
            signature: sig_alg(),
            issuer: self.name.clone(),
            this_update: utc(this_update)?,
            next_update: Some(utc(next_update)?),
            revoked_certificates: if entries.is_empty() {
                None
            } else {
                Some(entries)
            },
            crl_extensions: Some(vec![
                ext(
                    &CrlNumber(Uint::new(&number.to_be_bytes()).map_err(enc("crl number"))?),
                    false,
                )?,
                ext(&self.aki()?, false)?,
            ]),
        };
        let tbs_der = tbs.to_der().map_err(enc("TBSCertList"))?;
        let sig = self.key.sign_raw(&tbs_der)?;
        let crl = CertificateList {
            tbs_cert_list: tbs,
            signature_algorithm: sig_alg(),
            signature: BitString::from_bytes(&sig).map_err(enc("signature"))?,
        };
        crl.to_der().map_err(enc("CertificateList"))
    }

    /// The CA certificate DER.
    #[must_use]
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// The CA certificate as PEM.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Encoding`] (not expected).
    pub fn cert_pem(&self) -> Result<String, CryptoError> {
        pem::encode_public(pem::LABEL_CERTIFICATE, &self.cert_der)
    }

    /// The serial number octets.
    #[must_use]
    pub fn serial(&self) -> &[u8] {
        &self.serial
    }
}

/// A test end-entity certificate with its private key.
pub struct TestCert {
    cert_der: Vec<u8>,
    serial: Vec<u8>,
    key: SigningKey,
    chain_pem: Vec<u8>,
}

impl std::fmt::Debug for TestCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestCert")
            .field("sha256", &crate::sha256(&self.cert_der).to_hex())
            .finish_non_exhaustive()
    }
}

impl TestCert {
    /// The certificate DER.
    #[must_use]
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// The certificate followed by its issuing CAs (not the root), PEM.
    #[must_use]
    pub fn chain_pem(&self) -> Vec<u8> {
        self.chain_pem.clone()
    }

    /// The private key as PKCS#8 PEM.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] if serialisation fails.
    pub fn key_pem(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        self.key.to_pkcs8_pem()
    }

    /// The serial number octets.
    #[must_use]
    pub fn serial(&self) -> &[u8] {
        &self.serial
    }

    /// Parsed public facts.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] if parsing fails (not expected).
    pub fn peer_certificate(&self) -> Result<PeerCertificate, CryptoError> {
        PeerCertificate::from_der(&self.cert_der)
    }
}

/// CRL DER as PEM text.
///
/// # Errors
///
/// [`CryptoError::Encoding`] (not expected).
pub fn crl_pem(der: &[u8]) -> Result<String, CryptoError> {
    pem::encode_public(pem::LABEL_CRL, der)
}

/// A complete test hierarchy with one certificate per negative case.
///
/// ```text
/// root ─┬─ intermediate ─┬─ server (localhost, 127.0.0.1)
///       │                ├─ client (good; POLICY_ACCEPTED)
///       │                ├─ client_expired, client_not_yet_valid
///       │                ├─ client_server_eku (EKU serverAuth only)
///       │                ├─ client_no_eku (no EKU extension)
///       │                ├─ client_critical_ext
///       │                ├─ client_other_policy (POLICY_OTHER)
///       │                └─ client_revoked (on intermediate's CRL)
///       └─ revoked_intermediate (on root's CRL) ── client_under_revoked
/// untrusted_root ── client_untrusted
/// ```
#[derive(Debug)]
pub struct TestPki {
    /// The trust anchor.
    pub root: TestCa,
    /// Issues the server and operator certificates.
    pub intermediate: TestCa,
    /// An intermediate revoked on the root's CRL.
    pub revoked_intermediate: TestCa,
    /// A root the server does not trust.
    pub untrusted_root: TestCa,
    /// Server certificate (`localhost`, 127.0.0.1, serverAuth).
    pub server: TestCert,
    /// A valid operator certificate asserting [`POLICY_ACCEPTED`].
    pub client: TestCert,
    /// Past its notAfter.
    pub client_expired: TestCert,
    /// Before its notBefore.
    pub client_not_yet_valid: TestCert,
    /// EKU serverAuth only (no clientAuth).
    pub client_server_eku: TestCert,
    /// No EKU extension at all.
    pub client_no_eku: TestCert,
    /// Carries an unrecognised critical extension.
    pub client_critical_ext: TestCert,
    /// Asserts [`POLICY_OTHER`] only.
    pub client_other_policy: TestCert,
    /// Revoked on the intermediate's CRL.
    pub client_revoked: TestCert,
    /// Valid itself, issued by `revoked_intermediate`.
    pub client_under_revoked: TestCert,
    /// Issued by `untrusted_root`.
    pub client_untrusted: TestCert,
}

impl TestPki {
    /// Generates the whole hierarchy (fresh keys every call).
    ///
    /// # Errors
    ///
    /// [`CryptoError`] if any generation step fails.
    pub fn generate() -> Result<Self, CryptoError> {
        let root = TestCa::root("usgp test root")?;
        let intermediate = root.intermediate("usgp test operator ca")?;
        let revoked_intermediate = root.intermediate("usgp test revoked ca")?;
        let untrusted_root = TestCa::root("usgp untrusted root")?;
        let server = intermediate.issue(&LeafSpec::server("localhost"))?;
        let client = intermediate.issue(&LeafSpec::client("operator one"))?;
        let client_expired = intermediate.issue(&LeafSpec {
            window: Window::Expired,
            ..LeafSpec::client("operator expired")
        })?;
        let client_not_yet_valid = intermediate.issue(&LeafSpec {
            window: Window::NotYetValid,
            ..LeafSpec::client("operator future")
        })?;
        let client_server_eku = intermediate.issue(&LeafSpec {
            eku: Eku::ServerAuth,
            ..LeafSpec::client("operator server eku")
        })?;
        let client_no_eku = intermediate.issue(&LeafSpec {
            eku: Eku::Absent,
            ..LeafSpec::client("operator no eku")
        })?;
        let client_critical_ext = intermediate.issue(&LeafSpec {
            unknown_critical_extension: true,
            ..LeafSpec::client("operator critical ext")
        })?;
        let client_other_policy = intermediate.issue(&LeafSpec {
            policies: vec![POLICY_OTHER.to_string()],
            ..LeafSpec::client("operator other policy")
        })?;
        let client_revoked = intermediate.issue(&LeafSpec::client("operator revoked"))?;
        let client_under_revoked =
            revoked_intermediate.issue(&LeafSpec::client("operator under revoked ca"))?;
        let client_untrusted = untrusted_root.issue(&LeafSpec::client("operator untrusted"))?;
        Ok(Self {
            root,
            intermediate,
            revoked_intermediate,
            untrusted_root,
            server,
            client,
            client_expired,
            client_not_yet_valid,
            client_server_eku,
            client_no_eku,
            client_critical_ext,
            client_other_policy,
            client_revoked,
            client_under_revoked,
            client_untrusted,
        })
    }

    /// Current CRLs for every CA in the trusted hierarchy: the root's
    /// (revoking `revoked_intermediate`), the intermediate's (revoking
    /// `client_revoked`) and the revoked intermediate's (empty).
    ///
    /// # Errors
    ///
    /// [`CryptoError`] if signing fails.
    pub fn current_crls(&self) -> Result<Vec<Vec<u8>>, CryptoError> {
        Ok(vec![
            self.root
                .crl(&[self.revoked_intermediate.serial()], false)?,
            self.intermediate
                .crl(&[self.client_revoked.serial()], false)?,
            self.revoked_intermediate.crl(&[], false)?,
        ])
    }

    /// As [`Self::current_crls`] but the intermediate's CRL is stale.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] if signing fails.
    pub fn crls_with_stale_intermediate(&self) -> Result<Vec<Vec<u8>>, CryptoError> {
        Ok(vec![
            self.root
                .crl(&[self.revoked_intermediate.serial()], false)?,
            self.intermediate
                .crl(&[self.client_revoked.serial()], true)?,
            self.revoked_intermediate.crl(&[], false)?,
        ])
    }

    /// Server settings: our server certificate, anchors = root.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] if key serialisation fails.
    pub fn server_settings(
        &self,
        crls: Vec<Vec<u8>>,
        acceptable_policy_oids: Vec<String>,
        min_version: TlsMinVersion,
    ) -> Result<ServerTlsSettings, CryptoError> {
        Ok(ServerTlsSettings {
            cert_chain_pem: self.server.chain_pem(),
            private_key_pem: self.server.key_pem()?,
            min_version,
            client_trust_anchors_pem: self.root.cert_pem()?.into_bytes(),
            client_crls: crls,
            acceptable_policy_oids,
        })
    }

    /// Client settings trusting the root, presenting `cert` if given.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] if key serialisation fails.
    pub fn client_settings(
        &self,
        cert: Option<&TestCert>,
        min_version: TlsMinVersion,
    ) -> Result<ClientTlsSettings, CryptoError> {
        let (chain, key) = match cert {
            Some(c) => (Some(c.chain_pem()), Some(c.key_pem()?)),
            None => (None, None),
        };
        Ok(ClientTlsSettings {
            trust_anchors_pem: self.root.cert_pem()?.into_bytes(),
            client_cert_chain_pem: chain,
            client_key_pem: key,
            min_version,
            alpn: ClientAlpn::Http11,
        })
    }
}

/// Presents one fixed certificate chain and key.
#[derive(Debug)]
struct FixedClientCert(std::sync::Arc<rustls::sign::CertifiedKey>);

impl rustls::client::ResolvesClientCert for FixedClientCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<std::sync::Arc<rustls::sign::CertifiedKey>> {
        Some(std::sync::Arc::clone(&self.0))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// A client presenting `cert` **without** the local sanity checks
/// [`ClientTls::new`] performs on its own certificate (rustls refuses to
/// load, for example, a certificate with an unrecognised critical
/// extension). This lets tests send such a certificate to the server.
///
/// # Errors
///
/// [`CryptoError`] if the inputs do not decode.
pub fn client_tls_without_local_checks(
    pki: &TestPki,
    cert: &TestCert,
) -> Result<ClientTls, CryptoError> {
    let provider = crate::tls::tls_provider()?;
    let mut roots = rustls::RootCertStore::empty();
    for c in pem::certificates(pki.root.cert_pem()?.as_bytes(), "root")? {
        roots.add(c).map_err(|e| CryptoError::TlsConfig {
            reason: e.to_string(),
        })?;
    }
    let chain = pem::certificates(&cert.chain_pem, "client certificate chain")?;
    let mut key_der = cert.key.to_pkcs8_der()?;
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(std::mem::take(&mut *key_der).into());
    let signer =
        provider
            .key_provider
            .load_private_key(key)
            .map_err(|e| CryptoError::TlsConfig {
                reason: e.to_string(),
            })?;
    let certified = rustls::sign::CertifiedKey::new(chain, signer);
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| CryptoError::TlsConfig {
            reason: e.to_string(),
        })?
        .with_root_certificates(roots)
        .with_client_cert_resolver(std::sync::Arc::new(FixedClientCert(std::sync::Arc::new(
            certified,
        ))));
    config.resumption = rustls::client::Resumption::disabled();
    config.alpn_protocols = vec![crate::tls::ALPN_HTTP11.to_vec()];
    Ok(ClientTls::from_config(std::sync::Arc::new(config)))
}

/// Outcome of [`memory_handshake`].
#[derive(Debug)]
pub struct MemoryHandshake {
    /// What the server concluded: the operator certificate, `None` for no
    /// certificate, or the refusal.
    pub server: Result<Option<PeerCertificate>, TlsFailure>,
    /// On refusal, the end-entity certificate the client presented (as
    /// `ServerTls::accept_with_presented` reports it).
    pub presented: Option<PeerCertificate>,
    /// On refusal, whether the presented certificate chains to a
    /// configured trust anchor (`RefusedHandshake::chained_to_trust_anchor`).
    pub chained: bool,
    /// The client's error text, if the client failed.
    pub client_error: Option<String>,
    /// Negotiated version (server view).
    pub protocol: Option<TlsProtocol>,
    /// Negotiated cipher suite name (server view).
    pub cipher_suite: Option<String>,
    /// Negotiated ALPN protocol (server view).
    pub alpn: Option<Vec<u8>>,
    /// True if either side reports a resumed handshake.
    pub resumed: bool,
}

/// Runs one TLS handshake between `server` and `client` in memory, through
/// the same configuration, verifier and identity step as the network
/// acceptor.
///
/// # Errors
///
/// [`CryptoError::TlsConfig`] if `server_name` is invalid or a connection
/// cannot be created.
pub fn memory_handshake(
    server: &ServerTls,
    client: &ClientTls,
    server_name: &str,
) -> Result<MemoryHandshake, CryptoError> {
    let name = ClientTls::server_name(server_name)?;
    let out = crate::tls::memory::handshake(server, client.config(), name).map_err(|e| {
        CryptoError::TlsConfig {
            reason: e.to_string(),
        }
    })?;
    let resumed = [out.server_kind, out.client_kind]
        .iter()
        .any(|k| matches!(k, Some(rustls::HandshakeKind::Resumed)));
    Ok(MemoryHandshake {
        server: out.server,
        presented: out.presented,
        chained: out.chained,
        client_error: out.client_error.map(|e| e.to_string()),
        protocol: out.protocol,
        cipher_suite: out
            .cipher_suite
            .map(|s| s.as_str().map_or_else(|| format!("{s:?}"), str::to_string)),
        alpn: out.alpn,
        resumed,
    })
}
