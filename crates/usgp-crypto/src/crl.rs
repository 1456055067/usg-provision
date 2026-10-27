//! CRL facts for reload decisions (RFC 5280 §5).
//!
//! [`crl_facts`] parses each CRL of a PEM bundle or DER file and returns
//! its issuer, `cRLNumber` and thisUpdate. The server uses them to refuse
//! a reloaded CRL set that would roll a CRL back: a CRL whose number is
//! lower than the one already loaded for the same issuer (finding
//! SEC-007). Nothing here validates the CRL's signature: the TLS stack
//! checks it against the issuing CA when it uses the CRL. The CRL files
//! themselves come from trusted, administrator-owned files.

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-5(2) (PKI-Based Authentication) - revocation data
//   cannot be silently rolled back to an older CRL.
// - NIST 800-53: SI-10 (Information Input Validation) - size cap, strict
//   DER decoding, cRLNumber at most 20 octets; no panics on input.
// - RFC 5280 §5.1.2.4 (thisUpdate), §5.2.3 (CRL number: monotonically
//   increasing, at most 20 octets).

use std::cmp::Ordering;
use std::fmt;
use std::time::SystemTime;

use x509_cert::crl::CertificateList;
use x509_cert::der::Decode;
use x509_cert::ext::pkix::CrlNumber as CrlNumberExt;

use crate::CryptoError;
use crate::digest::hex_lower;

/// Longest cRLNumber RFC 5280 §5.2.3 allows, in octets.
pub const MAX_CRL_NUMBER_OCTETS: usize = 20;

/// A cRLNumber: a non-negative integer, compared numerically.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CrlNumber(Vec<u8>);

impl CrlNumber {
    /// From big-endian octets (leading zero octets are ignored).
    ///
    /// # Errors
    ///
    /// [`CryptoError::Crl`] above [`MAX_CRL_NUMBER_OCTETS`] significant
    /// octets.
    pub fn from_be_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        let v = bytes.get(first..).unwrap_or_default();
        if v.len() > MAX_CRL_NUMBER_OCTETS {
            return Err(CryptoError::Crl {
                reason: "cRLNumber longer than 20 octets",
            });
        }
        Ok(Self(v.to_vec()))
    }
}

impl Ord for CrlNumber {
    fn cmp(&self, other: &Self) -> Ordering {
        // No leading zeros: a longer number is larger.
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.cmp(&other.0))
    }
}

impl PartialOrd for CrlNumber {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for CrlNumber {
    /// Lowercase hex, `0` for zero.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            f.write_str("0")
        } else {
            f.write_str(&hex_lower(&self.0))
        }
    }
}

impl fmt::Debug for CrlNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CrlNumber({self})")
    }
}

/// Public facts of one CRL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlFacts {
    /// Issuer DN in RFC 4514 text form (as [`crate::PeerCertificate`]).
    pub issuer: String,
    /// The cRLNumber extension, if present.
    pub number: Option<CrlNumber>,
    /// thisUpdate.
    pub this_update: SystemTime,
}

/// Facts of every CRL in `input` (a PEM bundle of `X509 CRL` blocks, or
/// one DER CRL), in order.
///
/// # Errors
///
/// [`CryptoError::InputTooLarge`], [`CryptoError::Pem`] as for loading
/// CRLs into the TLS configuration; [`CryptoError::Crl`] if a CRL does
/// not decode, or its cRLNumber is malformed, repeated or too long.
pub fn crl_facts(input: &[u8]) -> Result<Vec<CrlFacts>, CryptoError> {
    let mut out = Vec::new();
    for der in crate::pem::crls(input)? {
        let list = CertificateList::from_der(der.as_ref()).map_err(|_| CryptoError::Crl {
            reason: "not a DER X.509 CRL",
        })?;
        let tbs = &list.tbs_cert_list;
        let mut number = None;
        for ext in tbs.crl_extensions.iter().flatten() {
            if ext.extn_id != <CrlNumberExt as x509_cert::der::oid::AssociatedOid>::OID {
                continue;
            }
            if number.is_some() {
                return Err(CryptoError::Crl {
                    reason: "repeated cRLNumber extension",
                });
            }
            let n = CrlNumberExt::from_der(ext.extn_value.as_bytes()).map_err(|_| {
                CryptoError::Crl {
                    reason: "malformed cRLNumber extension",
                }
            })?;
            number = Some(CrlNumber::from_be_bytes(n.0.as_bytes())?);
        }
        out.push(CrlFacts {
            issuer: tbs.issuer.to_string(),
            number,
            this_update: tbs.this_update.to_system_time(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(b: &[u8]) -> CrlNumber {
        CrlNumber::from_be_bytes(b).unwrap()
    }

    #[test]
    fn numbers_compare_numerically() {
        assert!(n(&[1]) < n(&[2]));
        assert!(n(&[0xff]) < n(&[1, 0]));
        assert_eq!(n(&[0, 0, 5]), n(&[5]));
        assert_eq!(n(&[]), n(&[0]));
        assert_eq!(n(&[0x01, 0xa0]).to_string(), "01a0");
        assert_eq!(n(&[0]).to_string(), "0");
        assert!(CrlNumber::from_be_bytes(&[1; 21]).is_err());
        assert!(CrlNumber::from_be_bytes(&[0; 30]).is_ok());
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        for input in [&b""[..], b"\x30\x00", b"\x30\x03\x02\x01\x00", &[0xff; 64]] {
            assert!(crl_facts(input).is_err());
        }
    }
}
