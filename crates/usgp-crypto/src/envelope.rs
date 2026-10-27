//! Domain-separated signatures over typed payloads.
//!
//! The signed message is (plan M2 section 5.3):
//!
//! ```text
//! msg = "USGP-SIG-V1" || 0x0A || payload_type || 0x0A ||
//!       decimal(len(payload)) || 0x0A || payload
//! ```
//!
//! The payload type and length are inside the signature, so a signature
//! made for one document type (for example a content manifest) cannot be
//! replayed as another (a package manifest or an audit checkpoint). The
//! signature is over the exact payload bytes; nothing is canonicalised.
//! Verifiers check the signature before parsing the payload.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7(6) (Cryptographic Protection) - signed manifests.
// - NIST 800-53: AU-9(3) (Cryptographic Protection of Audit Information) -
//   signed audit checkpoints use the same construction.
// - NIST 800-53: SC-13 (Cryptographic Protection) - ECDSA P-384/SHA-384 in
//   the validated module.
// - NIST 800-53: SI-10 (Information Input Validation) - payload type syntax
//   and signature length checked before use.
// - SPEC: plan M2 section 5.3; FIPS 186-5 (ECDSA).

use crate::CryptoError;
use crate::sign::{SigningKey, VerifyingKey};

/// Version tag at the start of every signed message.
pub const DOMAIN_TAG: &[u8] = b"USGP-SIG-V1";

/// Longest payload type accepted (bytes).
pub const MAX_PAYLOAD_TYPE_LEN: usize = 128;

/// Checks a payload type: 1 to [`MAX_PAYLOAD_TYPE_LEN`] bytes of visible
/// ASCII (0x21 to 0x7E). No space or line feed can appear, so the message
/// framing is unambiguous.
///
/// # Errors
///
/// [`CryptoError::PayloadType`] if the type is empty, too long, or has any
/// other byte.
pub fn check_payload_type(payload_type: &str) -> Result<(), CryptoError> {
    if payload_type.is_empty() {
        return Err(CryptoError::PayloadType { reason: "empty" });
    }
    if payload_type.len() > MAX_PAYLOAD_TYPE_LEN {
        return Err(CryptoError::PayloadType { reason: "too long" });
    }
    if !payload_type.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(CryptoError::PayloadType {
            reason: "only visible ASCII is allowed",
        });
    }
    Ok(())
}

/// The exact bytes that are signed for (`payload_type`, `payload`).
///
/// # Errors
///
/// [`CryptoError::PayloadType`] if `payload_type` is not acceptable.
pub fn signed_message(payload_type: &str, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    check_payload_type(payload_type)?;
    let len = payload.len().to_string();
    let mut msg = Vec::with_capacity(
        DOMAIN_TAG
            .len()
            .saturating_add(payload_type.len())
            .saturating_add(len.len())
            .saturating_add(3)
            .saturating_add(payload.len()),
    );
    msg.extend_from_slice(DOMAIN_TAG);
    msg.push(b'\n');
    msg.extend_from_slice(payload_type.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(len.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(payload);
    Ok(msg)
}

/// Signs `payload` as a document of type `payload_type`.
///
/// Returns the DER ECDSA signature. Record it with
/// [`crate::sign::SIGNATURE_ALGORITHM`] and the key's
/// [`crate::sign::KeyId`].
///
/// # Errors
///
/// [`CryptoError::PayloadType`] or [`CryptoError::Signing`].
pub fn sign_typed(
    key: &SigningKey,
    payload_type: &str,
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let msg = signed_message(payload_type, payload)?;
    key.sign_raw(&msg)
}

/// Verifies `signature` over `payload` as a document of type
/// `payload_type`.
///
/// # Errors
///
/// [`CryptoError::PayloadType`] if the type is malformed, and
/// [`CryptoError::SignatureInvalid`] if the signature does not verify for
/// exactly this type, length and payload.
pub fn verify_typed(
    key: &VerifyingKey,
    payload_type: &str,
    payload: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let msg = signed_message(payload_type, payload)?;
    key.verify_raw(&msg, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_layout_is_exact() {
        let m = signed_message("t/x", b"ab").unwrap();
        assert_eq!(m, b"USGP-SIG-V1\nt/x\n2\nab");
        let m = signed_message("t", b"").unwrap();
        assert_eq!(m, b"USGP-SIG-V1\nt\n0\n");
    }

    #[test]
    fn payload_type_rules() {
        assert!(check_payload_type("application/vnd.usgp.content-manifest.v1+json").is_ok());
        for bad in ["", "a b", "a\nb", "é", "a\tb"] {
            assert!(check_payload_type(bad).is_err(), "{bad:?}");
        }
        let long = "a".repeat(MAX_PAYLOAD_TYPE_LEN + 1);
        assert!(check_payload_type(&long).is_err());
        let max = "a".repeat(MAX_PAYLOAD_TYPE_LEN);
        assert!(check_payload_type(&max).is_ok());
    }
}
