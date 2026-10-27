//! Inputs for building TLS server and client configurations.
//!
//! Callers read files (with their own trusted-file checks) and pass bytes
//! here. Private keys arrive in [`Zeroizing`] buffers and are wiped when
//! the settings are dropped. `Debug` never prints key bytes.

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 (Configuration Settings) - minimum protocol version
//   is the only tunable protocol setting; everything else is fixed.
// - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management) -
//   TLS private keys zeroized; Debug redacted.
// - SPEC: plan M2 section 3.5 ([tls], [database]), section 5.4.

use std::fmt;
use std::str::FromStr;

use zeroize::Zeroizing;

use crate::CryptoError;

/// Lowest TLS version a configuration accepts. TLS 1.3 is always enabled
/// (SP 800-52r2 summary: support 1.2, support 1.3; `http-tls.md` §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsMinVersion {
    /// TLS 1.2 and TLS 1.3 (the default).
    #[default]
    Tls12,
    /// TLS 1.3 only.
    Tls13,
}

impl FromStr for TlsMinVersion {
    type Err = CryptoError;

    /// Accepts exactly `"1.2"` or `"1.3"` (config key `min_version`).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "1.2" => Ok(Self::Tls12),
            "1.3" => Ok(Self::Tls13),
            _ => Err(CryptoError::TlsConfig {
                reason: "min_version must be \"1.2\" or \"1.3\"".to_string(),
            }),
        }
    }
}

/// ALPN offered by a TLS client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAlpn {
    /// Offer `http/1.1` only (operator CLI to the API).
    Http11,
    /// Offer no ALPN (PostgreSQL negotiates TLS in-band).
    None,
}

/// Inputs for [`crate::tls::ServerTls`].
pub struct ServerTlsSettings {
    /// Server certificate chain, PEM, end entity first.
    pub cert_chain_pem: Vec<u8>,
    /// Server private key, PKCS#8 `PRIVATE KEY` PEM.
    pub private_key_pem: Zeroizing<Vec<u8>>,
    /// Lowest accepted TLS version.
    pub min_version: TlsMinVersion,
    /// Trust anchors for operator client certificates, PEM. Required.
    pub client_trust_anchors_pem: Vec<u8>,
    /// CRLs covering every CA that issues certificates in an operator's
    /// path (anchors included), each PEM or DER. At least one is required.
    pub client_crls: Vec<Vec<u8>>,
    /// If non-empty, the end-entity certificate must assert one of these
    /// policy OIDs (dotted decimal).
    pub acceptable_policy_oids: Vec<String>,
}

impl fmt::Debug for ServerTlsSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerTlsSettings")
            .field("cert_chain_pem_len", &self.cert_chain_pem.len())
            .field("private_key_pem", &"<redacted>")
            .field("min_version", &self.min_version)
            .field(
                "client_trust_anchors_pem_len",
                &self.client_trust_anchors_pem.len(),
            )
            .field("client_crls", &self.client_crls.len())
            .field("acceptable_policy_oids", &self.acceptable_policy_oids)
            .finish()
    }
}

/// Inputs for [`crate::tls::ClientTls`].
pub struct ClientTlsSettings {
    /// Trust anchors for the server certificate, PEM. Required.
    pub trust_anchors_pem: Vec<u8>,
    /// Client certificate chain, PEM, end entity first. Set together with
    /// [`Self::client_key_pem`] or not at all.
    pub client_cert_chain_pem: Option<Vec<u8>>,
    /// Client private key, PKCS#8 `PRIVATE KEY` PEM.
    pub client_key_pem: Option<Zeroizing<Vec<u8>>>,
    /// Lowest accepted TLS version.
    pub min_version: TlsMinVersion,
    /// ALPN to offer.
    pub alpn: ClientAlpn,
}

impl fmt::Debug for ClientTlsSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientTlsSettings")
            .field("trust_anchors_pem_len", &self.trust_anchors_pem.len())
            .field(
                "client_cert_chain_pem_len",
                &self.client_cert_chain_pem.as_ref().map(Vec::len),
            )
            .field(
                "client_key_pem",
                &self.client_key_pem.as_ref().map(|_| "<redacted>"),
            )
            .field("min_version", &self.min_version)
            .field("alpn", &self.alpn)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_version_parse() {
        assert_eq!(
            "1.2".parse::<TlsMinVersion>().unwrap(),
            TlsMinVersion::Tls12
        );
        assert_eq!(
            "1.3".parse::<TlsMinVersion>().unwrap(),
            TlsMinVersion::Tls13
        );
        for bad in ["", "1.1", "1.0", "1.2 ", "TLS1.3"] {
            assert!(bad.parse::<TlsMinVersion>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn debug_is_redacted() {
        let secret = b"-----BEGIN PRIVATE KEY-----\nSECRETSECRET\n".to_vec();
        let s = ServerTlsSettings {
            cert_chain_pem: vec![],
            private_key_pem: Zeroizing::new(secret.clone()),
            min_version: TlsMinVersion::Tls12,
            client_trust_anchors_pem: vec![],
            client_crls: vec![],
            acceptable_policy_oids: vec![],
        };
        let c = ClientTlsSettings {
            trust_anchors_pem: vec![],
            client_cert_chain_pem: None,
            client_key_pem: Some(Zeroizing::new(secret)),
            min_version: TlsMinVersion::Tls13,
            alpn: ClientAlpn::Http11,
        };
        for text in [format!("{s:?}"), format!("{c:?}")] {
            assert!(!text.contains("SECRET"), "{text}");
            assert!(!text.contains("BEGIN"), "{text}");
            assert!(text.contains("<redacted>"), "{text}");
        }
    }
}
