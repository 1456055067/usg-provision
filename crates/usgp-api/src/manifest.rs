//! Signing and verifying content and package manifests (plan M2 sections
//! 3.3 and 5.3).
//!
//! The signed bytes are the exact stored payload; the signature binds the
//! payload type and length (`usgp_crypto::sign_typed`). Stored manifests
//! are verified with the trusted content keys **every time they are used**
//! (served, or relied on for a download), before their payload is parsed
//! (decision 0011). Trusted keys come from files given at start-up, never
//! from the database (plan section 5.2).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7(6) (Cryptographic Protection) - signed manifests,
//   verified before use.
// - NIST 800-53: SC-13 (Cryptographic Protection) - ECDSA P-384/SHA-384 in
//   the FIPS module via usgp-crypto.
// - NIST 800-53: SC-12 - signing key is the `content` purpose key only.
// - SPEC: specs/os-images.md#REQ-IMG-050; specs/preinstall-env.md
//   #REQ-PE-008
// - Decision 0011; plan section 5.3 (domain-separated message)

use usgp_common::Sha256Digest;
use usgp_crypto::{CryptoError, KeyId, SigningKey, VerifyingKey, sign_typed, verify_signing_input};
use usgp_db::StoredManifest;
use usgp_proto::envelope::{EnvelopeError, SignatureVerifier};
use usgp_proto::{
    ContentManifestV1, PackageManifestV1, PayloadType, SignatureAlg, SignatureV1, SignedEnvelopeV1,
    SignedManifestError,
};

/// The content signing key and the keys trusted to verify content and
/// package manifests.
pub struct ContentKeys {
    signing: SigningKey,
    trusted: Vec<VerifyingKey>,
}

impl std::fmt::Debug for ContentKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentKeys")
            .field("signing_key_id", &self.signing.key_id())
            .field("trusted", &self.trusted.len())
            .finish()
    }
}

impl ContentKeys {
    /// `signing` signs new manifests. `trusted` are the public keys read
    /// from trusted files (current and earlier content keys); the
    /// signing key's own public key must be among them, so that the
    /// server can verify what it signs.
    ///
    /// # Errors
    ///
    /// [`crate::error::ApiInitError::KeyNotTrusted`] otherwise.
    pub fn new(
        signing: SigningKey,
        trusted: Vec<VerifyingKey>,
    ) -> Result<Self, crate::error::ApiInitError> {
        if !trusted.iter().any(|k| k == signing.verifying_key()) {
            return Err(crate::error::ApiInitError::KeyNotTrusted);
        }
        Ok(Self { signing, trusted })
    }

    /// The signing key id.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.signing.key_id()
    }

    /// Signs a payload.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] from the module.
    pub fn sign(&self, ty: PayloadType, payload: Vec<u8>) -> Result<StoredManifest, CryptoError> {
        let signature = sign_typed(&self.signing, ty.as_str(), &payload)?;
        Ok(StoredManifest {
            payload,
            signature,
            key_id: self.signing.key_id(),
        })
    }
}

impl SignatureVerifier for ContentKeys {
    fn verify(
        &self,
        key_id: &Sha256Digest,
        alg: SignatureAlg,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        alg == SignatureAlg::EcdsaP384Sha384
            && self
                .trusted
                .iter()
                .find(|k| k.key_id().0 == *key_id)
                .is_some_and(|k| verify_signing_input(k, message, signature).is_ok())
    }
}

/// The envelope for a stored manifest (what the API serves).
///
/// # Errors
///
/// [`EnvelopeError`] if the stored values are out of the envelope's
/// bounds.
pub fn envelope(ty: PayloadType, m: &StoredManifest) -> Result<SignedEnvelopeV1, EnvelopeError> {
    let sig = SignatureV1::new(
        m.key_id.0,
        SignatureAlg::EcdsaP384Sha384,
        m.signature.clone(),
    )?;
    SignedEnvelopeV1::new(ty, m.payload.clone(), vec![sig])
}

/// Verifies a stored content manifest with the trusted keys, then parses
/// it.
///
/// # Errors
///
/// [`SignedManifestError`] for a bad signature, an untrusted key, or an
/// invalid payload.
pub fn open_content(
    keys: &ContentKeys,
    m: &StoredManifest,
) -> Result<ContentManifestV1, SignedManifestError> {
    let env = envelope(PayloadType::ContentManifestV1, m)?;
    ContentManifestV1::open(&env, keys)
}

/// As [`open_content`] for a package manifest.
///
/// # Errors
///
/// [`SignedManifestError`].
pub fn open_package(
    keys: &ContentKeys,
    m: &StoredManifest,
) -> Result<PackageManifestV1, SignedManifestError> {
    let env = envelope(PayloadType::PackageManifestV1, m)?;
    PackageManifestV1::open(&env, keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_and_verifies_through_the_proto_envelope() {
        let k = SigningKey::generate().unwrap();
        let other = SigningKey::generate().unwrap();
        let keys = ContentKeys::new(
            SigningKey::from_pkcs8_der(&k.to_pkcs8_der().unwrap()).unwrap(),
            vec![k.verifying_key().clone()],
        )
        .unwrap();
        let m = keys
            .sign(PayloadType::PackageManifestV1, b"{\"x\":1}".to_vec())
            .unwrap();
        let env = envelope(PayloadType::PackageManifestV1, &m).unwrap();
        let v = env
            .verified_payload(PayloadType::PackageManifestV1, &keys)
            .unwrap();
        assert_eq!(v.bytes, b"{\"x\":1}");
        // The wrong type, a changed payload, or an untrusted key fail.
        assert!(
            env.verified_payload(PayloadType::ContentManifestV1, &keys)
                .is_err()
        );
        let mut bad = m.clone();
        bad.payload = b"{\"x\":2}".to_vec();
        let env = envelope(PayloadType::PackageManifestV1, &bad).unwrap();
        assert!(
            env.verified_payload(PayloadType::PackageManifestV1, &keys)
                .is_err()
        );
        let untrusted = ContentKeys::new(
            SigningKey::from_pkcs8_der(&other.to_pkcs8_der().unwrap()).unwrap(),
            vec![other.verifying_key().clone()],
        )
        .unwrap();
        let env = envelope(PayloadType::PackageManifestV1, &m).unwrap();
        assert!(
            env.verified_payload(PayloadType::PackageManifestV1, &untrusted)
                .is_err()
        );
        // The signing key must be trusted.
        assert!(ContentKeys::new(other, vec![k.verifying_key().clone()]).is_err());
    }
}
