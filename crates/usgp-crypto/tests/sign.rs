//! Signing keys: generation, PKCS#8/SPKI round trips, key ids, redaction.
//! Plan M2 section 10, "Unit: crypto".

use usgp_crypto::{
    CryptoError, SIGNATURE_ALGORITHM, SigningKey, VerifyingKey, sign_typed, verify_typed,
};
use zeroize::Zeroizing;

const T: &str = "application/vnd.usgp.test.v1";

#[test]
fn keygen_pkcs8_pem_round_trip_keeps_key() {
    let k = SigningKey::generate().unwrap();
    let pem = k.to_pkcs8_pem().unwrap();
    assert!(pem.starts_with(b"-----BEGIN PRIVATE KEY-----\n"));
    let k2 = SigningKey::from_pkcs8_pem(&pem).unwrap();
    assert_eq!(k.key_id(), k2.key_id());
    assert_eq!(k.verifying_key(), k2.verifying_key());
    // A signature by the reloaded key verifies with the original public key.
    let sig = sign_typed(&k2, T, b"x").unwrap();
    verify_typed(k.verifying_key(), T, b"x", &sig).unwrap();
}

#[test]
fn pkcs8_der_round_trip() {
    let k = SigningKey::generate().unwrap();
    let der = k.to_pkcs8_der().unwrap();
    let k2 = SigningKey::from_pkcs8_der(&der).unwrap();
    assert_eq!(k.key_id(), k2.key_id());
}

#[test]
fn spki_pem_round_trip_and_key_id() {
    let k = SigningKey::generate().unwrap();
    let pem = k.verifying_key().to_spki_pem().unwrap();
    assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
    let v = VerifyingKey::from_spki_pem(pem.as_bytes()).unwrap();
    assert_eq!(&v, k.verifying_key());
    assert_eq!(v.key_id(), k.key_id());
    assert_eq!(v.key_id().0, usgp_crypto::sha256(v.spki_der()));
    assert_eq!(v.key_id().to_hex().len(), 64);
    assert_eq!(
        usgp_crypto::KeyId::from_hex(&v.key_id().to_hex()).unwrap(),
        v.key_id()
    );
}

#[test]
fn distinct_keys_have_distinct_ids() {
    let a = SigningKey::generate().unwrap();
    let b = SigningKey::generate().unwrap();
    assert_ne!(a.key_id(), b.key_id());
    let sig = sign_typed(&a, T, b"x").unwrap();
    assert!(matches!(
        verify_typed(b.verifying_key(), T, b"x", &sig),
        Err(CryptoError::SignatureInvalid)
    ));
}

#[test]
fn bad_private_keys_rejected_without_echo() {
    let garbage =
        Zeroizing::new(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n".to_vec());
    let err = SigningKey::from_pkcs8_pem(&garbage).unwrap_err();
    assert!(matches!(err, CryptoError::KeyRejected { .. }), "{err:?}");
    let wrong_label = Zeroizing::new(
        SigningKey::generate()
            .unwrap()
            .verifying_key()
            .to_spki_pem()
            .unwrap()
            .into_bytes(),
    );
    assert!(matches!(
        SigningKey::from_pkcs8_pem(&wrong_label),
        Err(CryptoError::Pem { .. })
    ));
    assert!(SigningKey::from_pkcs8_der(&Zeroizing::new(vec![])).is_err());
}

#[test]
fn debug_is_redacted() {
    let k = SigningKey::generate().unwrap();
    let pem = k.to_pkcs8_pem().unwrap();
    let der = k.to_pkcs8_der().unwrap();
    let text = format!("{k:?}");
    assert!(text.contains("<redacted>"), "{text}");
    assert!(text.contains(&k.key_id().to_hex()), "{text}");
    // No part of the PEM body or DER appears.
    let body = std::str::from_utf8(&pem).unwrap().lines().nth(1).unwrap();
    assert!(!text.contains(body));
    assert!(!text.contains(&format!("{:?}", der.as_slice())));
    let vtext = format!("{:?}", k.verifying_key());
    assert!(vtext.contains(SIGNATURE_ALGORITHM));
}

#[test]
fn algorithm_name() {
    assert_eq!(SIGNATURE_ALGORITHM, "ecdsa-p384-sha384");
}

/// `verify_signing_input` accepts exactly the bytes `sign_typed` signs and
/// refuses any framing fault or a raw message without the domain prefix
/// (plan M2 section 5.3; WU-6 server-side `SignatureVerifier`).
#[test]
fn verify_signing_input_checks_framing_and_signature() {
    use usgp_crypto::envelope::signed_message;
    use usgp_crypto::verify_signing_input;

    let k = SigningKey::generate().unwrap();
    let payload = b"{\"a\":1}";
    let sig = sign_typed(&k, T, payload).unwrap();
    let msg = signed_message(T, payload).unwrap();
    verify_signing_input(k.verifying_key(), &msg, &sig).unwrap();

    // Another key, or a changed payload, does not verify.
    let other = SigningKey::generate().unwrap();
    assert!(matches!(
        verify_signing_input(other.verifying_key(), &msg, &sig),
        Err(CryptoError::SignatureInvalid)
    ));
    let mut changed = msg.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(verify_signing_input(k.verifying_key(), &changed, &sig).is_err());

    // Framing faults are refused before any signature check.
    let framings: Vec<Vec<u8>> = vec![
        payload.to_vec(),                                                     // no prefix
        b"USGP-SIG-V2\napplication/vnd.usgp.test.v1\n7\n{\"a\":1}".to_vec(),  // wrong tag
        b"USGP-SIG-V1\napplication/vnd.usgp.test.v1\n8\n{\"a\":1}".to_vec(),  // length too big
        b"USGP-SIG-V1\napplication/vnd.usgp.test.v1\n6\n{\"a\":1}".to_vec(),  // length too small
        b"USGP-SIG-V1\napplication/vnd.usgp.test.v1\n07\n{\"a\":1}".to_vec(), // leading zero
        b"USGP-SIG-V1\napplication/vnd.usgp.test.v1\n+7\n{\"a\":1}".to_vec(), // sign
        b"USGP-SIG-V1\napplication/vnd.usgp.test.v1\n7{\"a\":1}".to_vec(),    // no separator
        b"USGP-SIG-V1\n\n7\n{\"a\":1}".to_vec(),                              // empty type
        b"USGP-SIG-V1\napp lication\n7\n{\"a\":1}".to_vec(),                  // space in type
        b"USGP-SIG-V1".to_vec(),
        Vec::new(),
    ];
    for f in framings {
        assert!(
            verify_signing_input(k.verifying_key(), &f, &sig).is_err(),
            "{:?}",
            String::from_utf8_lossy(&f)
        );
    }
    // An over-long type is refused without scanning the whole input.
    let mut long = b"USGP-SIG-V1\n".to_vec();
    long.extend(std::iter::repeat_n(b'a', 1000));
    long.extend_from_slice(b"\n1\nx");
    assert!(verify_signing_input(k.verifying_key(), &long, &sig).is_err());

    // The empty payload frames as length 0.
    let sig0 = sign_typed(&k, T, b"").unwrap();
    let msg0 = signed_message(T, b"").unwrap();
    verify_signing_input(k.verifying_key(), &msg0, &sig0).unwrap();
}
