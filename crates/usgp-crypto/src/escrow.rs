//! Administrator-password escrow: ECDH P-384, HKDF-SHA-384, AES-256-GCM.
//!
//! The device seals the generated local administrator password to the
//! server's escrow public key (plan M4 section 1.3):
//!
//! 1. generate an ephemeral P-384 key;
//! 2. `Z = ECDH(eph, escrow_pub)`;
//! 3. `K = HKDF-SHA-384(salt = job_id, IKM = Z,
//!    info = "USGP-ESCROW-V1" || key_id || eph_pub)`, 32 bytes;
//! 4. AES-256-GCM with a random 96-bit nonce and
//!    `AAD = "USGP-ESCROW-V1\n" || job_id || "\n" || account || "\n" || key_id`.
//!
//! `key_id` is the 64-character lowercase hex [`KeyId`] (SHA-256 of the
//! escrow key's SPKI DER) in both the HKDF info and the AAD. `eph_pub` is
//! the uncompressed SEC1 point (97 bytes). The derived key never leaves the
//! module as bytes: the HKDF output is turned straight into an AEAD key.
//!
//! The server opens with [`escrow_open`]; the plaintext is returned only in
//! a [`Zeroizing`] buffer. Nothing here logs or prints secrets: the
//! private key's `Debug` shows only its id.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management) -
//   one-purpose escrow key; ephemeral-static ECDH (SP 800-56A Rev 3,
//   C(1e,1s)); HKDF key derivation (SP 800-56C Rev 2).
// - NIST 800-53: SC-13 (Cryptographic Protection) - ECDH, HKDF and
//   AES-256-GCM (SP 800-38D) in the FIPS 140-3 validated module.
// - NIST 800-53: SC-28 (Protection of Information at Rest) - only the
//   ciphertext, ephemeral public key and nonce are stored.
// - NIST 800-53: IA-5(1) (Password-Based Authentication) - random
//   administrator password from the module DRBG.
// - NIST 800-53: SI-10 (Information Input Validation) - sealed fields are
//   length-checked before any cryptographic use.
// - SPEC: plan M4 section 1.3, section 3.3, section 5; decisions 0024, 0025.
// POAM: the shared secret Z is produced and held inside aws-lc-rs during
// `agree`; this crate cannot zeroize that buffer itself.

use std::fmt;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, ECDH_P384, PrivateKey, UnparsedPublicKey};
use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
use aws_lc_rs::hkdf::{HKDF_SHA384, Salt};
use zeroize::Zeroizing;

use crate::sign::{KeyId, VerifyingKey};
use crate::{CryptoError, pem};

/// Domain-separation label for HKDF info and AAD.
pub const ESCROW_LABEL: &[u8] = b"USGP-ESCROW-V1";

/// Length of an uncompressed P-384 SEC1 point (`0x04 || X || Y`).
pub const EPH_PUB_LEN: usize = 97;

/// GCM tag length.
pub const TAG_LEN: usize = 16;

/// Largest ciphertext (including tag) accepted; the device route limits
/// `ct` to 512 bytes (plan M4 section 3.1).
pub const MAX_CIPHERTEXT_LEN: usize = 512;

/// Largest plaintext that can be sealed.
pub const MAX_PLAINTEXT_LEN: usize = MAX_CIPHERTEXT_LEN - TAG_LEN;

/// Longest account name bound into the AAD.
pub const MAX_ACCOUNT_LEN: usize = 256;

/// What a sealed password is bound to.
#[derive(Debug, Clone, Copy)]
pub struct EscrowContext<'a> {
    /// The job id (16 raw bytes); the HKDF salt and part of the AAD.
    pub job_id: [u8; 16],
    /// The account the password belongs to (for example `administrator`).
    pub account: &'a str,
}

/// A sealed password (format version 1). All fields are public data.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedV1 {
    /// Id of the escrow key it was sealed to.
    pub key_id: KeyId,
    /// The ephemeral public key, uncompressed SEC1 (97 bytes).
    pub eph_pub: Vec<u8>,
    /// The 96-bit GCM nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext followed by the 16-byte tag.
    pub ct: Vec<u8>,
}

impl fmt::Debug for SealedV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedV1")
            .field("key_id", &self.key_id)
            .field("eph_pub_len", &self.eph_pub.len())
            .field("ct_len", &self.ct.len())
            .finish_non_exhaustive()
    }
}

/// The server's escrow public key (P-384 SPKI).
#[derive(Clone, PartialEq, Eq)]
pub struct EscrowPublicKey {
    // Same SPKI rules as signature keys: id-ecPublicKey, secp384r1,
    // uncompressed point on the curve.
    inner: VerifyingKey,
}

impl EscrowPublicKey {
    /// Loads a key from SubjectPublicKeyInfo DER (RFC 5480).
    ///
    /// # Errors
    ///
    /// [`CryptoError::PublicKeyRejected`] unless it is a P-384 EC key.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            inner: VerifyingKey::from_spki_der(der)?,
        })
    }

    /// Loads a key from a `PUBLIC KEY` PEM block.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Pem`], [`CryptoError::InputTooLarge`] or
    /// [`CryptoError::PublicKeyRejected`].
    pub fn from_spki_pem(pem_text: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self {
            inner: VerifyingKey::from_spki_pem(pem_text)?,
        })
    }

    /// The SubjectPublicKeyInfo DER.
    #[must_use]
    pub fn spki_der(&self) -> &[u8] {
        self.inner.spki_der()
    }

    /// SHA-256 of the SPKI DER.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.inner.key_id()
    }
}

impl fmt::Debug for EscrowPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EscrowPublicKey")
            .field("key_id", &self.key_id())
            .finish()
    }
}

/// The server's escrow private key (ECDH P-384). One purpose only.
pub struct EscrowKey {
    private: PrivateKey,
    public: EscrowPublicKey,
}

impl EscrowKey {
    /// Generates a new key inside the module.
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyGeneration`].
    pub fn generate() -> Result<Self, CryptoError> {
        let private = PrivateKey::generate(&ECDH_P384).map_err(|_| CryptoError::KeyGeneration)?;
        Self::from_private(private)
    }

    /// Loads a PKCS#8 DER key.
    ///
    /// # Errors
    ///
    /// [`CryptoError::InputTooLarge`] or [`CryptoError::KeyRejected`].
    pub fn from_pkcs8_der(der: &Zeroizing<Vec<u8>>) -> Result<Self, CryptoError> {
        if der.len() > pem::MAX_KEY_PEM_BYTES {
            return Err(CryptoError::InputTooLarge {
                what: "escrow key",
                limit: pem::MAX_KEY_PEM_BYTES,
            });
        }
        let private = PrivateKey::from_private_key_der(&ECDH_P384, der).map_err(|_| {
            CryptoError::KeyRejected {
                reason: "not a valid P-384 PKCS#8 key",
            }
        })?;
        Self::from_private(private)
    }

    /// Loads a `PRIVATE KEY` PEM block (PKCS#8).
    ///
    /// # Errors
    ///
    /// [`CryptoError::Pem`], [`CryptoError::InputTooLarge`] or
    /// [`CryptoError::KeyRejected`].
    pub fn from_pkcs8_pem(pem_text: &Zeroizing<Vec<u8>>) -> Result<Self, CryptoError> {
        let der = pem::decode_secret(pem_text, pem::LABEL_PRIVATE_KEY, "escrow key")?;
        Self::from_pkcs8_der(&der)
    }

    /// The key as PKCS#8 v1 DER, in a zeroized buffer.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Encoding`] (not expected for a valid key).
    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let doc: Pkcs8V1Der<'static> = self
            .private
            .as_der()
            .map_err(|_| CryptoError::Encoding { what: "escrow key" })?;
        Ok(Zeroizing::new(doc.as_ref().to_vec()))
    }

    /// The key as `PRIVATE KEY` PEM, in a zeroized buffer.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Encoding`].
    pub fn to_pkcs8_pem(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let der = self.to_pkcs8_der()?;
        pem::encode_secret(pem::LABEL_PRIVATE_KEY, &der)
    }

    /// The public half.
    #[must_use]
    pub fn public(&self) -> EscrowPublicKey {
        self.public.clone()
    }

    /// SHA-256 of the public key's SPKI DER.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.public.key_id()
    }

    fn from_private(private: PrivateKey) -> Result<Self, CryptoError> {
        let reject = || CryptoError::KeyRejected {
            reason: "not a valid P-384 key",
        };
        let spki: PublicKeyX509Der<'static> = private
            .compute_public_key()
            .map_err(|_| reject())?
            .as_der()
            .map_err(|_| reject())?;
        // Re-checks the curve: the FIPS build of the module does not verify
        // the curve of a loaded PKCS#8 key against the algorithm.
        let public = EscrowPublicKey::from_spki_der(spki.as_ref()).map_err(|_| reject())?;
        Ok(Self { private, public })
    }
}

impl fmt::Debug for EscrowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EscrowKey")
            .field("key_id", &self.key_id())
            .finish_non_exhaustive()
    }
}

/// Seals `plaintext` to `pk`, bound to `ctx`.
///
/// # Errors
///
/// [`CryptoError::Escrow`] for an empty or oversized plaintext or a bad
/// account name; [`CryptoError::KeyGeneration`] or [`CryptoError::Random`]
/// if the module fails.
pub fn escrow_seal(
    pk: &EscrowPublicKey,
    ctx: &EscrowContext<'_>,
    plaintext: &[u8],
) -> Result<SealedV1, CryptoError> {
    let eph = PrivateKey::generate(&ECDH_P384).map_err(|_| CryptoError::KeyGeneration)?;
    let mut nonce = [0u8; NONCE_LEN];
    crate::rand::fill_random(&mut nonce)?;
    seal_with(pk, ctx, plaintext, &eph, nonce)
}

fn seal_with(
    pk: &EscrowPublicKey,
    ctx: &EscrowContext<'_>,
    plaintext: &[u8],
    eph: &PrivateKey,
    nonce: [u8; NONCE_LEN],
) -> Result<SealedV1, CryptoError> {
    if plaintext.is_empty() {
        return Err(CryptoError::Escrow {
            reason: "plaintext is empty",
        });
    }
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(CryptoError::InputTooLarge {
            what: "escrow plaintext",
            limit: MAX_PLAINTEXT_LEN,
        });
    }
    let key_id = pk.key_id();
    let aad = build_aad(ctx, &key_id)?;
    let eph_pub = eph
        .compute_public_key()
        .map_err(|_| CryptoError::KeyGeneration)?
        .as_ref()
        .to_vec();
    if eph_pub.len() != EPH_PUB_LEN {
        return Err(CryptoError::KeyGeneration);
    }
    let key = derive_key(
        eph,
        UnparsedPublicKey::new(&ECDH_P384, pk.spki_der()),
        ctx,
        &key_id,
        &eph_pub,
    )?;
    let mut buf = Zeroizing::new(plaintext.to_vec());
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad.as_slice()),
        &mut *buf,
    )
    .map_err(|_| CryptoError::Escrow {
        reason: "encryption failed",
    })?;
    // `buf` now holds ciphertext; its drop still wipes the copy.
    Ok(SealedV1 {
        key_id,
        eph_pub,
        nonce,
        ct: buf.to_vec(),
    })
}

/// Opens `sealed` with `sk`, checking the binding to `ctx`.
///
/// # Errors
///
/// [`CryptoError::Escrow`] if the key id does not match or a field has the
/// wrong length; [`CryptoError::DecryptionFailed`] if authentication fails
/// (wrong key, context, or any modified byte). No detail is given.
pub fn escrow_open(
    sk: &EscrowKey,
    ctx: &EscrowContext<'_>,
    sealed: &SealedV1,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let key_id = sk.key_id();
    if sealed.key_id != key_id {
        return Err(CryptoError::Escrow {
            reason: "sealed to a different escrow key",
        });
    }
    if sealed.eph_pub.len() != EPH_PUB_LEN || sealed.eph_pub.first() != Some(&0x04) {
        return Err(CryptoError::Escrow {
            reason: "ephemeral key is not an uncompressed P-384 point",
        });
    }
    if sealed.ct.len() <= TAG_LEN || sealed.ct.len() > MAX_CIPHERTEXT_LEN {
        return Err(CryptoError::Escrow {
            reason: "ciphertext length out of range",
        });
    }
    let aad = build_aad(ctx, &key_id)?;
    let key = derive_key(
        &sk.private,
        UnparsedPublicKey::new(&ECDH_P384, sealed.eph_pub.as_slice()),
        ctx,
        &key_id,
        &sealed.eph_pub,
    )
    .map_err(|_| CryptoError::DecryptionFailed)?;
    let mut buf = Zeroizing::new(sealed.ct.clone());
    let len = key
        .open_in_place(
            Nonce::assume_unique_for_key(sealed.nonce),
            Aad::from(aad.as_slice()),
            &mut buf,
        )
        .map_err(|_| CryptoError::DecryptionFailed)?
        .len();
    buf.truncate(len);
    Ok(buf)
}

/// ECDH then HKDF-SHA-384 straight into an AES-256-GCM key.
fn derive_key<B: AsRef<[u8]>>(
    mine: &PrivateKey,
    peer: UnparsedPublicKey<B>,
    ctx: &EscrowContext<'_>,
    key_id: &KeyId,
    eph_pub: &[u8],
) -> Result<LessSafeKey, CryptoError> {
    let key_id_hex = key_id.to_hex();
    let err = CryptoError::Escrow {
        reason: "key agreement failed",
    };
    let unbound = agreement::agree(mine, &peer, (), |z| {
        let prk = Salt::new(HKDF_SHA384, &ctx.job_id).extract(z);
        let info: [&[u8]; 3] = [ESCROW_LABEL, key_id_hex.as_bytes(), eph_pub];
        let okm = prk.expand(&info, &AES_256_GCM).map_err(|_| ())?;
        Ok(UnboundKey::from(okm))
    })
    .map_err(|()| err)?;
    Ok(LessSafeKey::new(unbound))
}

fn build_aad(ctx: &EscrowContext<'_>, key_id: &KeyId) -> Result<Vec<u8>, CryptoError> {
    let account = ctx.account.as_bytes();
    if account.is_empty()
        || account.len() > MAX_ACCOUNT_LEN
        || account.iter().any(|&b| b == b'\n' || b.is_ascii_control())
    {
        return Err(CryptoError::Escrow {
            reason: "account name is empty, too long or has control characters",
        });
    }
    let key_id_hex = key_id.to_hex();
    let mut aad = Vec::with_capacity(
        ESCROW_LABEL.len() + 3 + ctx.job_id.len() + account.len() + key_id_hex.len(),
    );
    aad.extend_from_slice(ESCROW_LABEL);
    aad.push(b'\n');
    aad.extend_from_slice(&ctx.job_id);
    aad.push(b'\n');
    aad.extend_from_slice(account);
    aad.push(b'\n');
    aad.extend_from_slice(key_id_hex.as_bytes());
    Ok(aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CTX: EscrowContext<'static> = EscrowContext {
        job_id: [7u8; 16],
        account: "administrator",
    };

    fn scalar_key(byte: u8) -> PrivateKey {
        let mut s = [0u8; 48];
        s[47] = byte;
        s[0] = 0x01;
        PrivateKey::from_private_key(&ECDH_P384, &s).unwrap()
    }

    /// Our own known-answer vector: fixed static and ephemeral scalars and
    /// nonce. Guards the KDF inputs, AAD layout and AEAD from silent change.
    #[test]
    fn known_answer_vector() {
        let sk = EscrowKey::from_private(scalar_key(0x11)).unwrap();
        let eph = scalar_key(0x22);
        let sealed = seal_with(&sk.public(), &CTX, b"Pa55-word", &eph, [9u8; NONCE_LEN]).unwrap();
        assert_eq!(
            hex(&sealed.ct),
            KAT_CT,
            "escrow KAT changed: the wire format is fixed"
        );
        let pt = escrow_open(&sk, &CTX, &sealed).unwrap();
        assert_eq!(pt.as_slice(), b"Pa55-word");
    }

    const KAT_CT: &str = "e707a15e58751b7e44b7dbac8c4e762654bfdd2b39e56868c1";

    fn hex(b: &[u8]) -> String {
        use std::fmt::Write;
        b.iter().fold(String::new(), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
    }

    #[test]
    fn aad_layout() {
        let sk = EscrowKey::from_private(scalar_key(0x11)).unwrap();
        let aad = build_aad(&CTX, &sk.key_id()).unwrap();
        let mut want = b"USGP-ESCROW-V1\n".to_vec();
        want.extend_from_slice(&[7u8; 16]);
        want.extend_from_slice(b"\nadministrator\n");
        want.extend_from_slice(sk.key_id().to_hex().as_bytes());
        assert_eq!(aad, want);
    }
}
