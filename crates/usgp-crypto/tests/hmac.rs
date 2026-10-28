//! HMAC-SHA-256 (plan M3 WU-1): RFC 4231 vectors, key-length rules, tag
//! verification and constant-time comparison.

use usgp_crypto::hmac::{HMAC_KEY_FILE_LEN, HMAC_SHA256_LEN, MAX_HMAC_KEY_LEN, MIN_HMAC_KEY_LEN};
use usgp_crypto::{CryptoError, HmacKey, HmacTag, ct_eq, hmac_sha256};
use zeroize::Zeroizing;

/// RFC 4231 §4.2 to §4.8, HMAC-SHA-256 results. Test case 2 uses a
/// 4-byte key, below our 112-bit minimum; it is checked as a refusal in
/// [`short_keys_refused`].
#[test]
fn rfc4231_vectors() {
    let block_key = vec![0xaau8; 131];
    let cases: [(Vec<u8>, Vec<u8>, &str); 5] = [
        // Test case 1.
        (
            vec![0x0b; 20],
            b"Hi There".to_vec(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        ),
        // Test case 3.
        (
            vec![0xaa; 20],
            vec![0xdd; 50],
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        ),
        // Test case 4.
        (
            (1u8..=25).collect(),
            vec![0xcd; 50],
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        ),
        // Test case 6.
        (
            block_key.clone(),
            b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        ),
        // Test case 7.
        (
            block_key,
            b"This is a test using a larger than block-size key and a larger \
than block-size data. The key needs to be hashed before being used by the HMAC \
algorithm."
                .to_vec(),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
        ),
    ];
    for (i, (key, data, want)) in cases.iter().enumerate() {
        let k = HmacKey::from_bytes(key).unwrap();
        let tag = hmac_sha256(&k, data);
        assert_eq!(tag.to_hex(), *want, "case index {i}");
        assert_eq!(HmacTag::from_slice(tag.as_bytes()).unwrap().to_hex(), *want);
        // The method and the free function agree, and the tag verifies.
        assert_eq!(k.sign(data), tag);
        k.verify(data, tag.as_ref()).unwrap();
    }
}

/// RFC 4231 §4.6 (test case 5): the first 128 bits of the full tag.
#[test]
fn rfc4231_case5_truncated_prefix() {
    let k = HmacKey::from_bytes(&[0x0c; 20]).unwrap();
    let tag = hmac_sha256(&k, b"Test With Truncation");
    assert!(
        tag.to_hex().starts_with("a3b6167473100ee06e0c796c2955552b"),
        "{tag:?}"
    );
    // A truncated tag is not accepted by `verify` (we never truncate).
    assert!(matches!(
        k.verify(b"Test With Truncation", tag.as_bytes().get(..16).unwrap()),
        Err(CryptoError::MacInvalid)
    ));
}

#[test]
fn short_keys_refused() {
    // RFC 4231 test case 2's key "Jefe" is 32 bits.
    assert!(matches!(
        HmacKey::from_bytes(b"Jefe"),
        Err(CryptoError::KeyRejected { .. })
    ));
    assert!(HmacKey::from_bytes(&[]).is_err());
    assert!(HmacKey::from_bytes(&[1u8; MIN_HMAC_KEY_LEN - 1]).is_err());
    assert!(HmacKey::from_bytes(&[1u8; MIN_HMAC_KEY_LEN]).is_ok());
    assert!(HmacKey::from_bytes(&[1u8; MAX_HMAC_KEY_LEN + 1]).is_err());
}

#[test]
fn key_file_must_be_exactly_32_bytes() {
    assert_eq!(HMAC_KEY_FILE_LEN, 32);
    let ok = Zeroizing::new(vec![9u8; HMAC_KEY_FILE_LEN]);
    HmacKey::from_key_file(&ok).unwrap();
    for len in [0usize, 14, 31, 33, 64] {
        let bad = Zeroizing::new(vec![9u8; len]);
        assert!(
            matches!(
                HmacKey::from_key_file(&bad),
                Err(CryptoError::KeyRejected { .. })
            ),
            "len {len}"
        );
    }
    // A text editor's trailing newline is refused, not trimmed.
    let mut nl = vec![9u8; HMAC_KEY_FILE_LEN];
    nl.push(b'\n');
    assert!(HmacKey::from_key_file(&Zeroizing::new(nl)).is_err());
}

#[test]
fn generated_key_bytes_load_and_differ() {
    let a = HmacKey::generate_key_bytes().unwrap();
    let b = HmacKey::generate_key_bytes().unwrap();
    assert_eq!(a.len(), HMAC_KEY_FILE_LEN);
    // 2^-256 chance of a false failure.
    assert_ne!(*a, *b);
    let ka = HmacKey::from_key_file(&a).unwrap();
    let kb = HmacKey::from_key_file(&b).unwrap();
    assert_ne!(ka.sign(b"ABCDE-FGHJK"), kb.sign(b"ABCDE-FGHJK"));
    // The same key bytes give the same tag (lookup by HMAC works).
    let ka2 = HmacKey::from_key_file(&a).unwrap();
    assert_eq!(ka.sign(b"ABCDE-FGHJK"), ka2.sign(b"ABCDE-FGHJK"));
}

#[test]
fn verify_fails_closed() {
    let k = HmacKey::from_bytes(&[0x42; 32]).unwrap();
    let tag = k.sign(b"code");
    k.verify(b"code", tag.as_ref()).unwrap();
    // Different data.
    assert!(matches!(
        k.verify(b"cod3", tag.as_ref()),
        Err(CryptoError::MacInvalid)
    ));
    // Each single-bit flip of the tag.
    for i in 0..HMAC_SHA256_LEN {
        let mut bad = *tag.as_bytes();
        if let Some(b) = bad.get_mut(i) {
            *b ^= 0x01;
        }
        assert!(k.verify(b"code", &bad).is_err(), "byte {i}");
    }
    // Wrong lengths.
    assert!(k.verify(b"code", &[]).is_err());
    let mut long = tag.as_bytes().to_vec();
    long.push(0);
    assert!(k.verify(b"code", &long).is_err());
    // Another key.
    let other = HmacKey::from_bytes(&[0x43; 32]).unwrap();
    assert!(other.verify(b"code", tag.as_ref()).is_err());
}

#[test]
fn tag_from_slice_and_equality() {
    let k = HmacKey::from_bytes(&[0x11; 32]).unwrap();
    let tag = k.sign(b"x");
    let back = HmacTag::from_slice(tag.as_ref()).unwrap();
    assert_eq!(back, tag);
    assert_ne!(k.sign(b"y"), tag);
    assert!(matches!(
        HmacTag::from_slice(&[0u8; 31]),
        Err(CryptoError::MacInvalid)
    ));
    assert!(HmacTag::from_slice(&[0u8; 33]).is_err());
    assert!(HmacTag::from_slice(&[]).is_err());
    assert_eq!(tag.to_hex().len(), 64);
    assert!(format!("{tag:?}").contains(&tag.to_hex()));
}

#[test]
fn ct_eq_semantics() {
    assert!(ct_eq(b"", b""));
    assert!(ct_eq(b"same bytes", b"same bytes"));
    assert!(!ct_eq(b"same bytes", b"same bytez"));
    assert!(!ct_eq(b"Same bytes", b"same bytes"));
    assert!(!ct_eq(b"short", b"shorter"));
    assert!(!ct_eq(b"x", b""));
}

#[test]
fn debug_is_redacted() {
    let key_bytes = [0x5au8; 32];
    let k = HmacKey::from_bytes(&key_bytes).unwrap();
    let text = format!("{k:?}");
    assert!(text.contains("<redacted>"), "{text}");
    assert!(!text.contains("5a5a"), "{text}");
    assert!(!text.contains("90, 90"), "{text}");
}

#[test]
fn errors_carry_no_key_bytes() {
    let err = HmacKey::from_bytes(b"Jefe").unwrap_err().to_string();
    assert!(!err.contains("Jefe"), "{err}");
    let err = HmacKey::from_key_file(&Zeroizing::new(b"secret-secret-secret".to_vec()))
        .unwrap_err()
        .to_string();
    assert!(!err.contains("secret-secret"), "{err}");
}
