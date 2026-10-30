//! Administrator-password escrow: seal/open, binding, tamper, key handling.
//! Plan M4 section 10 ("Escrow") and WU-1.

use usgp_crypto::{
    CryptoError, CryptoProvider, EscrowContext, EscrowKey, EscrowPublicKey, SealedV1, escrow_open,
    escrow_seal, provider, random_password,
};
use zeroize::Zeroizing;

const CTX: EscrowContext<'static> = EscrowContext {
    job_id: [0xA5; 16],
    account: "administrator",
};

fn sealed(k: &EscrowKey, pt: &[u8]) -> Result<SealedV1, CryptoError> {
    escrow_seal(&k.public(), &CTX, pt)
}

#[test]
fn seal_then_open_round_trip() {
    let k = EscrowKey::generate().unwrap();
    let pw = random_password(24).unwrap();
    let s = sealed(&k, pw.as_bytes()).unwrap();
    assert_eq!(s.key_id, k.key_id());
    assert_eq!(s.eph_pub.len(), 97);
    assert_eq!(s.ct.len(), 24 + 16);
    let pt = escrow_open(&k, &CTX, &s).unwrap();
    assert_eq!(pt.as_slice(), pw.as_bytes());
}

#[test]
fn through_provider_trait() {
    let p: &dyn CryptoProvider = provider();
    let k = EscrowKey::generate().unwrap();
    let s = p.escrow_seal(&k.public(), &CTX, b"secret").unwrap();
    assert_eq!(p.escrow_open(&k, &CTX, &s).unwrap().as_slice(), b"secret");
}

#[test]
fn each_seal_is_fresh() {
    let k = EscrowKey::generate().unwrap();
    let a = sealed(&k, b"same").unwrap();
    let b = sealed(&k, b"same").unwrap();
    assert_ne!(a.eph_pub, b.eph_pub);
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.ct, b.ct);
}

#[test]
fn wrong_job_or_account_is_refused() {
    let k = EscrowKey::generate().unwrap();
    let s = sealed(&k, b"pw").unwrap();
    let other_job = EscrowContext {
        job_id: [0x5A; 16],
        ..CTX
    };
    assert!(matches!(
        escrow_open(&k, &other_job, &s),
        Err(CryptoError::DecryptionFailed)
    ));
    let other_acct = EscrowContext {
        account: "guest",
        ..CTX
    };
    assert!(matches!(
        escrow_open(&k, &other_acct, &s),
        Err(CryptoError::DecryptionFailed)
    ));
}

#[test]
fn wrong_key_is_refused() {
    let k = EscrowKey::generate().unwrap();
    let other = EscrowKey::generate().unwrap();
    let s = sealed(&k, b"pw").unwrap();
    // Key id mismatch is caught before decryption.
    assert!(matches!(
        escrow_open(&other, &CTX, &s),
        Err(CryptoError::Escrow { .. })
    ));
    // A forged key id still fails authentication.
    let mut forged = s.clone();
    forged.key_id = other.key_id();
    assert!(matches!(
        escrow_open(&other, &CTX, &forged),
        Err(CryptoError::DecryptionFailed)
    ));
}

#[test]
fn key_id_is_bound_into_kdf_and_aad() {
    // Relabelling a sealed blob under a different key id fails even with
    // the right private key (key id is in HKDF info and AAD).
    let k = EscrowKey::generate().unwrap();
    let mut s = sealed(&k, b"pw").unwrap();
    let mut id = s.key_id;
    id.0 = usgp_crypto::sha256(b"other");
    s.key_id = id;
    assert!(escrow_open(&k, &CTX, &s).is_err());
}

#[test]
fn every_flipped_bit_fails() {
    let k = EscrowKey::generate().unwrap();
    let s = sealed(&k, b"Pa55-word").unwrap();
    for i in 0..s.ct.len() * 8 {
        let mut t = s.clone();
        t.ct[i / 8] ^= 1 << (i % 8);
        assert!(matches!(
            escrow_open(&k, &CTX, &t),
            Err(CryptoError::DecryptionFailed)
        ));
    }
    for i in 0..s.nonce.len() * 8 {
        let mut t = s.clone();
        t.nonce[i / 8] ^= 1 << (i % 8);
        assert!(escrow_open(&k, &CTX, &t).is_err());
    }
    for i in 8..s.eph_pub.len() * 8 {
        let mut t = s.clone();
        t.eph_pub[i / 8] ^= 1 << (i % 8);
        assert!(escrow_open(&k, &CTX, &t).is_err());
    }
}

#[test]
fn malformed_fields_are_refused() {
    let k = EscrowKey::generate().unwrap();
    let s = sealed(&k, b"pw").unwrap();
    let mut t = s.clone();
    t.eph_pub.truncate(65);
    assert!(matches!(
        escrow_open(&k, &CTX, &t),
        Err(CryptoError::Escrow { .. })
    ));
    let mut t = s.clone();
    t.ct.truncate(16);
    assert!(matches!(
        escrow_open(&k, &CTX, &t),
        Err(CryptoError::Escrow { .. })
    ));
    let mut t = s.clone();
    t.ct = vec![0; 513];
    assert!(matches!(
        escrow_open(&k, &CTX, &t),
        Err(CryptoError::Escrow { .. })
    ));
}

#[test]
fn plaintext_and_account_limits() {
    let k = EscrowKey::generate().unwrap();
    let pk = k.public();
    assert!(escrow_seal(&pk, &CTX, b"").is_err());
    assert!(escrow_seal(&pk, &CTX, &[b'a'; 496]).is_ok());
    assert!(matches!(
        escrow_seal(&pk, &CTX, &[b'a'; 497]),
        Err(CryptoError::InputTooLarge { .. })
    ));
    for bad in ["", "admin\nistrator", &"a".repeat(257)] {
        let ctx = EscrowContext {
            account: bad,
            ..CTX
        };
        assert!(matches!(
            escrow_seal(&pk, &ctx, b"pw"),
            Err(CryptoError::Escrow { .. })
        ));
    }
}

#[test]
fn retired_key_reloaded_from_pem_still_opens() {
    let k = EscrowKey::generate().unwrap();
    let s = sealed(&k, b"old").unwrap();
    let pem = k.to_pkcs8_pem().unwrap();
    assert!(pem.starts_with(b"-----BEGIN PRIVATE KEY-----\n"));
    let reloaded = EscrowKey::from_pkcs8_pem(&pem).unwrap();
    assert_eq!(reloaded.key_id(), k.key_id());
    assert_eq!(escrow_open(&reloaded, &CTX, &s).unwrap().as_slice(), b"old");
    let der = k.to_pkcs8_der().unwrap();
    assert_eq!(
        EscrowKey::from_pkcs8_der(&der).unwrap().key_id(),
        k.key_id()
    );
}

#[test]
fn public_key_spki_round_trip_and_rejects() {
    let k = EscrowKey::generate().unwrap();
    let pk = EscrowPublicKey::from_spki_der(k.public().spki_der()).unwrap();
    assert_eq!(pk, k.public());
    assert_eq!(pk.key_id().0, usgp_crypto::sha256(pk.spki_der()));
    assert!(EscrowPublicKey::from_spki_der(b"junk").is_err());
    assert!(EscrowPublicKey::from_spki_der(&[0u8; 300]).is_err());
}

#[test]
fn bad_private_keys_are_refused() {
    assert!(EscrowKey::from_pkcs8_der(&Zeroizing::new(b"junk".to_vec())).is_err());
    assert!(
        EscrowKey::from_pkcs8_pem(&Zeroizing::new(b"-----BEGIN PUBLIC KEY-----\n".to_vec()))
            .is_err()
    );
    assert!(matches!(
        EscrowKey::from_pkcs8_der(&Zeroizing::new(vec![0u8; 65 * 1024])),
        Err(CryptoError::InputTooLarge { .. })
    ));
}

#[test]
fn debug_shows_no_secrets() {
    let k = EscrowKey::generate().unwrap();
    let s = sealed(&k, b"TopSecretPw").unwrap();
    let dbg = format!("{k:?} {:?} {s:?}", k.public());
    assert!(dbg.contains(&k.key_id().to_hex()));
    assert!(!dbg.contains("TopSecretPw"));
    assert!(!dbg.to_lowercase().contains("private"));
    // No raw byte arrays of key material or ciphertext.
    assert!(!dbg.contains('['));
    let err = escrow_open(
        &k,
        &EscrowContext {
            account: "x",
            ..CTX
        },
        &s,
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "decryption failed");
}
