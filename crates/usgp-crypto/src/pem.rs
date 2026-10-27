//! PEM decoding and encoding for keys, certificates and CRLs (RFC 7468).
//!
//! Private-key PEM is decoded straight into a [`Zeroizing`] buffer so the
//! DER key never sits in an unwiped allocation of ours. Public data
//! (certificates, CRLs, public keys) uses the rustls PEM reader.
//!
//! Every input is length-checked before it is parsed. The limits are
//! project limits (CM-6, SI-10), not product limits.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - size limits and
//   strict label checks before any parse.
// - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management) -
//   private keys decoded into zeroized buffers.
// - RFC 7468 §2, §10 (PKCS#8 "PRIVATE KEY"), §13 ("PUBLIC KEY"), §5
//   ("CERTIFICATE"), §6 ("X509 CRL").

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer};
use x509_cert::der::pem::{self, LineEnding};
use zeroize::Zeroizing;

use crate::CryptoError;

/// Largest private-key PEM accepted (64 KiB).
pub const MAX_KEY_PEM_BYTES: usize = 64 * 1024;
/// Largest certificate bundle PEM accepted (1 MiB).
pub const MAX_CERT_PEM_BYTES: usize = 1024 * 1024;
/// Largest single CRL input (PEM or DER) accepted (64 MiB).
pub const MAX_CRL_BYTES: usize = 64 * 1024 * 1024;
/// Largest single DER certificate accepted for parsing (64 KiB).
pub const MAX_CERT_DER_BYTES: usize = 64 * 1024;
/// Largest public-key PEM accepted (16 KiB).
pub const MAX_PUBLIC_KEY_PEM_BYTES: usize = 16 * 1024;

pub(crate) const LABEL_PRIVATE_KEY: &str = "PRIVATE KEY";
pub(crate) const LABEL_PUBLIC_KEY: &str = "PUBLIC KEY";
#[cfg(feature = "test-pki")]
pub(crate) const LABEL_CERTIFICATE: &str = "CERTIFICATE";
#[cfg(feature = "test-pki")]
pub(crate) const LABEL_CRL: &str = "X509 CRL";

fn check_len(what: &'static str, input: &[u8], limit: usize) -> Result<(), CryptoError> {
    if input.len() > limit {
        return Err(CryptoError::InputTooLarge { what, limit });
    }
    Ok(())
}

/// Decodes a single PEM block with `label` into a zeroized buffer.
///
/// Only one block is accepted; the label must match exactly.
pub(crate) fn decode_secret(
    input: &[u8],
    label: &'static str,
    what: &'static str,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    check_len(what, input, MAX_KEY_PEM_BYTES)?;
    // Decoded output is never longer than the encoded input.
    let mut buf = Zeroizing::new(vec![0u8; input.len()]);
    let (got_label, der) = pem::decode(input, &mut buf).map_err(|_| CryptoError::Pem {
        what,
        reason: "not a single well-formed PEM block",
    })?;
    if got_label != label {
        return Err(CryptoError::Pem {
            what,
            reason: "unexpected PEM label",
        });
    }
    Ok(Zeroizing::new(der.to_vec()))
}

/// Decodes a single public PEM block with `label`.
pub(crate) fn decode_public(
    input: &[u8],
    label: &'static str,
    what: &'static str,
    limit: usize,
) -> Result<Vec<u8>, CryptoError> {
    check_len(what, input, limit)?;
    let (got_label, der) = pem::decode_vec(input).map_err(|_| CryptoError::Pem {
        what,
        reason: "not a single well-formed PEM block",
    })?;
    if got_label != label {
        return Err(CryptoError::Pem {
            what,
            reason: "unexpected PEM label",
        });
    }
    Ok(der)
}

/// Encodes secret DER as PEM into a zeroized buffer (LF line endings).
pub(crate) fn encode_secret(
    label: &'static str,
    der: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let err = CryptoError::Encoding { what: "PEM" };
    let len = pem::encoded_len(label, LineEnding::LF, der).map_err(|_| err)?;
    let mut buf = Zeroizing::new(vec![0u8; len]);
    let written = pem::encode(label, LineEnding::LF, der, &mut buf)
        .map_err(|_| CryptoError::Encoding { what: "PEM" })?
        .len();
    buf.truncate(written);
    Ok(buf)
}

/// Encodes public DER as PEM text (LF line endings).
pub(crate) fn encode_public(label: &'static str, der: &[u8]) -> Result<String, CryptoError> {
    pem::encode_string(label, LineEnding::LF, der)
        .map_err(|_| CryptoError::Encoding { what: "PEM" })
}

/// All `CERTIFICATE` blocks in a PEM bundle, in order. At least one.
pub(crate) fn certificates(
    input: &[u8],
    what: &'static str,
) -> Result<Vec<CertificateDer<'static>>, CryptoError> {
    check_len(what, input, MAX_CERT_PEM_BYTES)?;
    let mut out = Vec::new();
    for item in CertificateDer::pem_slice_iter(input) {
        let cert = item.map_err(|_| CryptoError::Pem {
            what,
            reason: "malformed PEM certificate block",
        })?;
        check_len(what, cert.as_ref(), MAX_CERT_DER_BYTES)?;
        out.push(cert);
    }
    if out.is_empty() {
        return Err(CryptoError::Pem {
            what,
            reason: "no CERTIFICATE block",
        });
    }
    Ok(out)
}

/// CRLs from one input: either PEM (`X509 CRL` blocks, at least one) or a
/// single DER CRL.
pub(crate) fn crls(
    input: &[u8],
) -> Result<Vec<CertificateRevocationListDer<'static>>, CryptoError> {
    const WHAT: &str = "CRL";
    check_len(WHAT, input, MAX_CRL_BYTES)?;
    let trimmed = input.trim_ascii_start();
    if trimmed.starts_with(b"-----BEGIN") {
        let mut out = Vec::new();
        for item in CertificateRevocationListDer::pem_slice_iter(input) {
            out.push(item.map_err(|_| CryptoError::Pem {
                what: WHAT,
                reason: "malformed PEM CRL block",
            })?);
        }
        if out.is_empty() {
            return Err(CryptoError::Pem {
                what: WHAT,
                reason: "no X509 CRL block",
            });
        }
        Ok(out)
    } else if input.first() == Some(&0x30) {
        // DER SEQUENCE; the TLS stack parses and checks it in full.
        Ok(vec![CertificateRevocationListDer::from(input.to_vec())])
    } else {
        Err(CryptoError::Pem {
            what: WHAT,
            reason: "neither PEM nor DER",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_round_trip_and_label_check() {
        let der = [0x30u8, 0x03, 0x02, 0x01, 0x05];
        let pem_text = encode_secret(LABEL_PRIVATE_KEY, &der).unwrap();
        let back = decode_secret(&pem_text, LABEL_PRIVATE_KEY, "key").unwrap();
        assert_eq!(back.as_slice(), &der);
        let err = decode_secret(&pem_text, LABEL_PUBLIC_KEY, "key").unwrap_err();
        assert!(matches!(
            err,
            CryptoError::Pem {
                reason: "unexpected PEM label",
                ..
            }
        ));
    }

    #[test]
    fn oversized_inputs_refused_before_parse() {
        let big = vec![b'A'; MAX_KEY_PEM_BYTES + 1];
        assert!(matches!(
            decode_secret(&big, LABEL_PRIVATE_KEY, "key"),
            Err(CryptoError::InputTooLarge { .. })
        ));
        let big = vec![b'A'; MAX_CERT_PEM_BYTES + 1];
        assert!(matches!(
            certificates(&big, "certs"),
            Err(CryptoError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        for input in [
            &b""[..],
            b"-----BEGIN",
            b"\x30",
            b"hello",
            b"-----BEGIN X509 CRL-----\n!!\n",
        ] {
            let _ = decode_secret(input, LABEL_PRIVATE_KEY, "key");
            let _ = decode_public(input, LABEL_PUBLIC_KEY, "pub", 1024);
            let _ = certificates(input, "certs");
            let _ = crls(input);
        }
        assert!(certificates(b"", "certs").is_err());
        assert!(crls(b"hello").is_err());
    }
}
