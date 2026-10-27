//! ECDSA P-384 with SHA-384 signing keys and verifying keys.
//!
//! Keys are generated inside the validated module and stored as PKCS#8
//! (private) and SubjectPublicKeyInfo (public). A [`KeyId`] is the SHA-256
//! of the SPKI DER, so a rotated key always has a new id.
//!
//! There is no public "sign these bytes" method: signing for callers goes
//! through [`crate::envelope::sign_typed`], which binds the payload type and
//! length into the signed message (plan M2 section 5.3).

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management) -
//   keys generated in the module; private key buffers zeroized; Debug
//   redacted.
// - NIST 800-53: SC-13 (Cryptographic Protection) - ECDSA P-384/SHA-384 in
//   the FIPS 140-3 validated module.
// - NIST 800-53: SI-7(6) (Cryptographic Protection) - basis of signed
//   manifests and audit checkpoints.
// - FIPS 186-5 (ECDSA); RFC 5480 §2 (EC SubjectPublicKeyInfo);
//   RFC 5208/5958 (PKCS#8).
// - SPEC: plan M2 section 5.1, 5.2; ARCHITECTURE §7 (curve choice).
// POAM: private keys sit in files on the server host; no HSM (PKCS#11
// would need C). Plan M2 section 5.2.

use std::fmt;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{
    ECDSA_P384_SHA384_ASN1, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair, KeyPair, ParsedPublicKey,
};
use usgp_common::Sha256Digest;
use x509_cert::der::Decode;
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::spki::SubjectPublicKeyInfoRef;
use zeroize::Zeroizing;

use crate::CryptoError;
use crate::pem;

/// The signature algorithm name recorded next to every signature.
pub const SIGNATURE_ALGORITHM: &str = "ecdsa-p384-sha384";

/// Largest DER ECDSA P-384 signature accepted. A DER signature is at most
/// 2 + 2 * (2 + 49) = 104 bytes; anything longer is refused unparsed.
pub const MAX_SIGNATURE_LEN: usize = 104;

/// Largest SPKI DER accepted for a P-384 key (the real size is 120 bytes).
const MAX_SPKI_DER_LEN: usize = 256;

/// id-ecPublicKey (RFC 5480 §2.1.1).
const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// secp384r1 (RFC 5480 §2.1.1.1).
const SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// Key identifier: SHA-256 of the SubjectPublicKeyInfo DER.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId(pub Sha256Digest);

impl KeyId {
    /// Lowercase hex text form (64 characters).
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Parses the 64-hex-digit text form.
    ///
    /// # Errors
    ///
    /// [`usgp_common::digest::DigestParseError`] on bad length or characters.
    pub fn from_hex(text: &str) -> Result<Self, usgp_common::digest::DigestParseError> {
        Sha256Digest::from_hex(text).map(Self)
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({})", self.to_hex())
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// An ECDSA P-384 public key used to verify our signatures.
#[derive(Clone)]
pub struct VerifyingKey {
    spki_der: Vec<u8>,
    key_id: KeyId,
    parsed: ParsedPublicKey,
}

impl VerifyingKey {
    /// Loads a key from SubjectPublicKeyInfo DER (RFC 5480).
    ///
    /// Only id-ecPublicKey on secp384r1 with an uncompressed point is
    /// accepted.
    ///
    /// # Errors
    ///
    /// [`CryptoError::PublicKeyRejected`] for any other input.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, CryptoError> {
        let reject = |reason| CryptoError::PublicKeyRejected { reason };
        if der.len() > MAX_SPKI_DER_LEN {
            return Err(reject("SubjectPublicKeyInfo too long"));
        }
        let spki = SubjectPublicKeyInfoRef::from_der(der)
            .map_err(|_| reject("not a DER SubjectPublicKeyInfo"))?;
        if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
            return Err(reject("not an EC public key"));
        }
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
        if curve != Some(SECP384R1) {
            return Err(reject("curve is not P-384"));
        }
        let point = spki
            .subject_public_key
            .as_bytes()
            .ok_or(reject("public key bit string has unused bits"))?;
        // Uncompressed SEC1 point: 0x04 || X(48) || Y(48).
        if point.len() != 97 || point.first() != Some(&0x04) {
            return Err(reject("not an uncompressed P-384 point"));
        }
        let parsed = ParsedPublicKey::new(&ECDSA_P384_SHA384_ASN1, point)
            .map_err(|_| reject("point is not on the curve"))?;
        Ok(Self {
            spki_der: der.to_vec(),
            key_id: KeyId(crate::sha256(der)),
            parsed,
        })
    }

    /// Loads a key from a `PUBLIC KEY` PEM block (RFC 7468 §13).
    ///
    /// # Errors
    ///
    /// [`CryptoError::Pem`], [`CryptoError::InputTooLarge`] or
    /// [`CryptoError::PublicKeyRejected`].
    pub fn from_spki_pem(pem_text: &[u8]) -> Result<Self, CryptoError> {
        let der = pem::decode_public(
            pem_text,
            pem::LABEL_PUBLIC_KEY,
            "public key",
            pem::MAX_PUBLIC_KEY_PEM_BYTES,
        )?;
        Self::from_spki_der(&der)
    }

    /// The SubjectPublicKeyInfo DER.
    #[must_use]
    pub fn spki_der(&self) -> &[u8] {
        &self.spki_der
    }

    /// The key as `PUBLIC KEY` PEM text.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Encoding`] (not expected for a valid key).
    pub fn to_spki_pem(&self) -> Result<String, CryptoError> {
        pem::encode_public(pem::LABEL_PUBLIC_KEY, &self.spki_der)
    }

    /// SHA-256 of the SPKI DER.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Verifies a DER ECDSA signature over `message` exactly as given.
    pub(crate) fn verify_raw(&self, message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        if signature.len() > MAX_SIGNATURE_LEN {
            return Err(CryptoError::SignatureInvalid);
        }
        self.parsed
            .verify_sig(message, signature)
            .map_err(|_| CryptoError::SignatureInvalid)
    }
}

/// Longest decimal length field accepted in a signing input (`u64::MAX`
/// has 20 digits).
const MAX_LEN_DIGITS: usize = 20;

/// Verifies `signature` over a complete signing input that another layer
/// built (for example `usgp_proto::envelope::signing_input`), without
/// splitting it back into type and payload.
///
/// The framing is checked first (plan M2 section 5.3):
/// `"USGP-SIG-V1" 0x0A <payload type> 0x0A <decimal length> 0x0A <payload>`,
/// where the payload type passes
/// [`crate::envelope::check_payload_type`], the length has no leading
/// zeros, and exactly that many payload bytes follow. Only a well-framed
/// input is handed to the signature check, so this function accepts
/// nothing that [`crate::verify_typed`] would refuse, and a raw message
/// without the domain prefix can never verify.
///
/// # Errors
///
/// [`CryptoError::PayloadType`] if the payload type is malformed, and
/// [`CryptoError::SignatureInvalid`] for any other framing fault or a
/// signature that does not verify.
pub fn verify_signing_input(
    key: &VerifyingKey,
    signing_input: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    check_signing_input(signing_input)?;
    key.verify_raw(signing_input, signature)
}

/// Checks the framing of a signing input (see [`verify_signing_input`]).
fn check_signing_input(input: &[u8]) -> Result<(), CryptoError> {
    let bad = || CryptoError::SignatureInvalid;
    let rest = input
        .strip_prefix(crate::envelope::DOMAIN_TAG)
        .and_then(|r| r.strip_prefix(b"\n"))
        .ok_or_else(bad)?;
    // Payload type: up to MAX_PAYLOAD_TYPE_LEN bytes, then a line feed.
    let type_end = rest
        .iter()
        .take(crate::envelope::MAX_PAYLOAD_TYPE_LEN.saturating_add(1))
        .position(|&b| b == b'\n')
        .ok_or_else(bad)?;
    let (ty, rest) = rest.split_at_checked(type_end).ok_or_else(bad)?;
    let ty = std::str::from_utf8(ty).map_err(|_| CryptoError::PayloadType {
        reason: "only visible ASCII is allowed",
    })?;
    crate::envelope::check_payload_type(ty)?;
    let rest = rest.strip_prefix(b"\n").ok_or_else(bad)?;
    // Length: decimal digits without leading zeros, then a line feed.
    let len_end = rest
        .iter()
        .take(MAX_LEN_DIGITS.saturating_add(1))
        .position(|&b| b == b'\n')
        .ok_or_else(bad)?;
    let (digits, rest) = rest.split_at_checked(len_end).ok_or_else(bad)?;
    let canonical = !digits.is_empty()
        && digits.iter().all(u8::is_ascii_digit)
        && !(digits.len() > 1 && digits.first() == Some(&b'0'));
    if !canonical {
        return Err(bad());
    }
    let declared: usize = std::str::from_utf8(digits)
        .map_err(|_| bad())?
        .parse()
        .map_err(|_| bad())?;
    let payload = rest.strip_prefix(b"\n").ok_or_else(bad)?;
    if payload.len() != declared {
        return Err(bad());
    }
    Ok(())
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.spki_der == other.spki_der
    }
}

impl Eq for VerifyingKey {}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("alg", &SIGNATURE_ALGORITHM)
            .field("key_id", &self.key_id)
            .finish()
    }
}

/// An ECDSA P-384 private key, held inside the validated module.
///
/// The module frees and cleanses the key when this value is dropped. Our
/// own PKCS#8 buffers are [`Zeroizing`]. `Debug` shows the key id only.
pub struct SigningKey {
    pair: EcdsaKeyPair,
    verifying: VerifyingKey,
}

impl SigningKey {
    /// Generates a new key inside the module.
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyGeneration`] if the module fails.
    pub fn generate() -> Result<Self, CryptoError> {
        let pair = EcdsaKeyPair::generate(&ECDSA_P384_SHA384_ASN1_SIGNING)
            .map_err(|_| CryptoError::KeyGeneration)?;
        Self::from_pair(pair)
    }

    /// Loads a PKCS#8 DER private key (P-384 only).
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyRejected`] if the bytes are not a valid P-384
    /// PKCS#8 key. The error never contains key bytes.
    pub fn from_pkcs8_der(der: &Zeroizing<Vec<u8>>) -> Result<Self, CryptoError> {
        if der.len() > pem::MAX_KEY_PEM_BYTES {
            return Err(CryptoError::InputTooLarge {
                what: "private key",
                limit: pem::MAX_KEY_PEM_BYTES,
            });
        }
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_ASN1_SIGNING, der).map_err(|_| {
                CryptoError::KeyRejected {
                    reason: "not a valid P-384 PKCS#8 key",
                }
            })?;
        Self::from_pair(pair)
    }

    /// Loads a `PRIVATE KEY` PEM block (PKCS#8, RFC 7468 §10).
    ///
    /// The caller holds the file bytes in a [`Zeroizing`] buffer; the
    /// decoded DER is zeroized here.
    ///
    /// # Errors
    ///
    /// [`CryptoError::Pem`], [`CryptoError::InputTooLarge`] or
    /// [`CryptoError::KeyRejected`].
    pub fn from_pkcs8_pem(pem_text: &Zeroizing<Vec<u8>>) -> Result<Self, CryptoError> {
        let der = pem::decode_secret(pem_text, pem::LABEL_PRIVATE_KEY, "private key")?;
        Self::from_pkcs8_der(&der)
    }

    /// The private key as PKCS#8 DER, in a zeroized buffer.
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyGeneration`] if the module cannot serialise it.
    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        // The module's Document wipes its own copy on drop.
        let doc = self
            .pair
            .to_pkcs8v1()
            .map_err(|_| CryptoError::KeyGeneration)?;
        Ok(Zeroizing::new(doc.as_ref().to_vec()))
    }

    /// The private key as `PRIVATE KEY` PEM, in a zeroized buffer.
    ///
    /// # Errors
    ///
    /// [`CryptoError::KeyGeneration`] or [`CryptoError::Encoding`].
    pub fn to_pkcs8_pem(&self) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let der = self.to_pkcs8_der()?;
        pem::encode_secret(pem::LABEL_PRIVATE_KEY, &der)
    }

    /// The matching public key.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying
    }

    /// The key id (SHA-256 of the public key's SPKI DER).
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.verifying.key_id
    }

    /// Signs `message` exactly as given (DER ECDSA signature).
    ///
    /// Crate-private: callers sign through the domain-separated envelope;
    /// the test PKI uses this for X.509 bodies.
    pub(crate) fn sign_raw(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        // aws-lc-rs ignores the rng argument and uses the module DRBG.
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let sig = self
            .pair
            .sign(&rng, message)
            .map_err(|_| CryptoError::Signing)?;
        Ok(sig.as_ref().to_vec())
    }

    fn from_pair(pair: EcdsaKeyPair) -> Result<Self, CryptoError> {
        let spki = pair
            .public_key()
            .as_der()
            .map_err(|_| CryptoError::KeyGeneration)?;
        let verifying = VerifyingKey::from_spki_der(spki.as_ref())?;
        Ok(Self { pair, verifying })
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("alg", &SIGNATURE_ALGORITHM)
            .field("key_id", &self.verifying.key_id)
            .field("private", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_sign_verify_and_tamper() {
        let k = SigningKey::generate().unwrap();
        let sig = k.sign_raw(b"hello").unwrap();
        assert!(sig.len() <= MAX_SIGNATURE_LEN);
        k.verifying_key().verify_raw(b"hello", &sig).unwrap();
        assert!(k.verifying_key().verify_raw(b"hellp", &sig).is_err());
        let mut bad = sig.clone();
        if let Some(last) = bad.last_mut() {
            *last ^= 1;
        }
        assert!(k.verifying_key().verify_raw(b"hello", &bad).is_err());
        let long = vec![0u8; MAX_SIGNATURE_LEN + 1];
        assert!(k.verifying_key().verify_raw(b"hello", &long).is_err());
    }

    #[test]
    fn spki_is_p384_and_key_id_is_its_sha256() {
        let k = SigningKey::generate().unwrap();
        let spki = k.verifying_key().spki_der();
        assert_eq!(spki.len(), 120);
        assert_eq!(k.key_id().0, crate::sha256(spki));
    }

    #[test]
    fn non_p384_spki_rejected() {
        // A P-384 SPKI with the curve OID's last arc changed to P-256's
        // neighbour still parses as DER but must be refused.
        let k = SigningKey::generate().unwrap();
        let mut spki = k.verifying_key().spki_der().to_vec();
        // secp384r1 = 06 05 2B 81 04 00 22; change 0x22 -> 0x23 (secp521r1).
        let pos = spki
            .windows(7)
            .position(|w| w == [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22])
            .unwrap();
        spki[pos + 6] = 0x23;
        assert!(matches!(
            VerifyingKey::from_spki_der(&spki),
            Err(CryptoError::PublicKeyRejected {
                reason: "curve is not P-384"
            })
        ));
        assert!(VerifyingKey::from_spki_der(&[]).is_err());
        assert!(VerifyingKey::from_spki_der(&[0x30; 300]).is_err());
    }
}
