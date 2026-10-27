//! Domain-separated typed signatures (plan M2 section 5.3): a signature
//! binds the payload type, the length and the bytes.

use usgp_crypto::envelope::{DOMAIN_TAG, signed_message};
use usgp_crypto::{CryptoError, SigningKey, sign_typed, verify_typed};

const CONTENT: &str = "application/vnd.usgp.content-manifest.v1+json";
const PACKAGE: &str = "application/vnd.usgp.package-manifest.v1+json";
const CHECKPOINT: &str = "application/vnd.usgp.audit-checkpoint.v1";

fn invalid(r: Result<(), CryptoError>) -> bool {
    matches!(r, Err(CryptoError::SignatureInvalid))
}

#[test]
fn sign_and_verify() {
    let k = SigningKey::generate().unwrap();
    let payload = br#"{"schema":1}"#;
    let sig = sign_typed(&k, CONTENT, payload).unwrap();
    verify_typed(k.verifying_key(), CONTENT, payload, &sig).unwrap();
}

#[test]
fn tampered_payload_fails() {
    let k = SigningKey::generate().unwrap();
    let payload = br#"{"schema":1}"#.to_vec();
    let sig = sign_typed(&k, CONTENT, &payload).unwrap();
    for i in 0..payload.len() {
        let mut p = payload.clone();
        if let Some(b) = p.get_mut(i) {
            *b ^= 0x01;
        }
        assert!(invalid(verify_typed(k.verifying_key(), CONTENT, &p, &sig)));
    }
}

#[test]
fn other_type_fails_no_cross_replay() {
    let k = SigningKey::generate().unwrap();
    let payload = b"same bytes";
    let sig = sign_typed(&k, CONTENT, payload).unwrap();
    assert!(invalid(verify_typed(
        k.verifying_key(),
        PACKAGE,
        payload,
        &sig
    )));
    assert!(invalid(verify_typed(
        k.verifying_key(),
        CHECKPOINT,
        payload,
        &sig
    )));
}

#[test]
fn length_is_bound_truncation_and_extension_fail() {
    let k = SigningKey::generate().unwrap();
    let payload = b"0123456789";
    let sig = sign_typed(&k, CONTENT, payload).unwrap();
    assert!(invalid(verify_typed(
        k.verifying_key(),
        CONTENT,
        &payload[..9],
        &sig
    )));
    let mut longer = payload.to_vec();
    longer.push(b'0');
    assert!(invalid(verify_typed(
        k.verifying_key(),
        CONTENT,
        &longer,
        &sig
    )));
}

#[test]
fn type_and_payload_boundary_cannot_shift() {
    // Moving bytes between the type and the payload changes the message
    // because the length field and the separator are fixed by framing.
    let a = signed_message("a/b", b"\nc").unwrap();
    let b = signed_message("a/b\nc", b"");
    assert!(b.is_err(), "a line feed is not allowed in a type");
    let c = signed_message("a", b"/b\nc").unwrap();
    assert_ne!(a, c);
    assert!(a.starts_with(DOMAIN_TAG));
}

#[test]
fn tampered_or_oversized_signature_fails() {
    let k = SigningKey::generate().unwrap();
    let sig = sign_typed(&k, CONTENT, b"p").unwrap();
    let mut bad = sig.clone();
    if let Some(b) = bad.get_mut(10) {
        *b ^= 0x80;
    }
    assert!(invalid(verify_typed(
        k.verifying_key(),
        CONTENT,
        b"p",
        &bad
    )));
    assert!(invalid(verify_typed(k.verifying_key(), CONTENT, b"p", &[])));
    assert!(invalid(verify_typed(
        k.verifying_key(),
        CONTENT,
        b"p",
        &[0u8; 200]
    )));
}

#[test]
fn malformed_type_refused_on_both_sides() {
    let k = SigningKey::generate().unwrap();
    assert!(matches!(
        sign_typed(&k, "", b"p"),
        Err(CryptoError::PayloadType { .. })
    ));
    let sig = sign_typed(&k, CONTENT, b"p").unwrap();
    assert!(matches!(
        verify_typed(k.verifying_key(), "bad type", b"p", &sig),
        Err(CryptoError::PayloadType { .. })
    ));
}

#[test]
fn signatures_are_randomised_but_both_verify() {
    // ECDSA uses a fresh nonce per signature (FIPS 186-5).
    let k = SigningKey::generate().unwrap();
    let a = sign_typed(&k, CONTENT, b"p").unwrap();
    let b = sign_typed(&k, CONTENT, b"p").unwrap();
    assert_ne!(a, b);
    verify_typed(k.verifying_key(), CONTENT, b"p", &a).unwrap();
    verify_typed(k.verifying_key(), CONTENT, b"p", &b).unwrap();
}
