//! Signed envelope for manifests (plan section 3.3) and the exact bytes a
//! signature covers (plan section 5.3).
//!
//! ```text
//! signing input = "USGP-SIG-V1" || 0x0A || payload_type || 0x0A ||
//!                 decimal(len(payload)) || 0x0A || payload
//! ```
//!
//! The payload type and length are bound into the signature, so a content
//! manifest signature cannot be replayed as a package manifest or as an
//! audit checkpoint. The payload is the exact stored manifest bytes; there
//! is no JSON canonicalisation.
//!
//! This crate does no cryptography (decision 0001). Signing and
//! verification are done by `usgp-crypto` (WU-1). That code must produce
//! the same signing input as [`signing_input`]; the golden vector in this
//! module's tests is the cross-check. Verification here is driven through
//! the [`SignatureVerifier`] trait, which callers implement with
//! `usgp-crypto` verifying keys loaded from trusted files, never from the
//! database (plan section 5.2).
//!
//! [`SignedEnvelopeV1::verified_payload`] checks a signature over the raw
//! payload bytes **before** anything parses them.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) and
//   SI-7(6) (Cryptographic Protection) - signed manifests; verify before
//   parse.
// - NIST 800-53: SC-13 (Cryptographic Protection) - ECDSA P-384/SHA-384
//   named; computed only in usgp-crypto (decision 0001).
// - NIST 800-53: SI-10 (Information Input Validation) - bounded envelope,
//   payload, signature count and signature size; strict base64.
// - SPEC: specs/os-images.md#REQ-IMG-050, specs/preinstall-env.md#REQ-PE-008
// - SPEC: specs/preinstall-env.md#REQ-PE-016 (signed job plan),
//   specs/boot-network.md#REQ-BOOT-067 (signed boot-policy list)
// - FIPS 186-5 (ECDSA); RFC 4648 §4 (base64, padded)

use std::fmt;

use base64ct::{Base64, Encoding};
use usgp_common::Sha256Digest;

use crate::limits::{
    MAX_ENVELOPE_BYTES, MAX_MANIFEST_PAYLOAD_BYTES, MAX_SIGNATURE_BYTES, MAX_SIGNATURES,
};

/// Domain-separation prefix of every signing input.
pub const SIGNATURE_DOMAIN: &[u8] = b"USGP-SIG-V1";

closed_enum!(
    /// Type of a signed payload; bound into the signing input.
    PayloadType, "payload type" {
        /// [`crate::content_manifest::ContentManifestV1`] JSON.
        ContentManifestV1 => "application/vnd.usgp.content-manifest.v1+json",
        /// [`crate::package_manifest::PackageManifestV1`] JSON.
        PackageManifestV1 => "application/vnd.usgp.package-manifest.v1+json",
        /// Audit checkpoint bytes (plan section 5.3:
        /// `seq(u64 BE) || record_hash || signed_at_us(i64 BE) || key_id`),
        /// built by `usgp-audit`. Never carried in a manifest envelope.
        AuditCheckpointV1 => "application/vnd.usgp.audit-checkpoint.v1",
        /// [`crate::job_plan::JobPlanV1`] JSON, signed with the plan key
        /// (M3 plan section 3.2).
        JobPlanV1 => "application/vnd.usgp.job-plan.v1+json",
        /// [`crate::boot_policy::BootPolicyV1`] JSON, signed with the
        /// boot-policy key (M3 plan section 3.6).
        BootPolicyV1 => "application/vnd.usgp.boot-policy.v1+json",
    }
);

closed_enum!(
    /// Signature algorithm.
    SignatureAlg, "signature algorithm" {
        /// ECDSA over P-384 with SHA-384, ASN.1 DER signature (FIPS 186-5).
        EcdsaP384Sha384 => "ecdsa-p384-sha384",
    }
);

/// The exact bytes a signature covers (plan section 5.3).
#[must_use]
pub fn signing_input(payload_type: PayloadType, payload: &[u8]) -> Vec<u8> {
    let ty = payload_type.as_str().as_bytes();
    let len = payload.len().to_string();
    let mut out =
        Vec::with_capacity(SIGNATURE_DOMAIN.len() + ty.len() + len.len() + payload.len() + 3);
    out.extend_from_slice(SIGNATURE_DOMAIN);
    out.push(b'\n');
    out.extend_from_slice(ty);
    out.push(b'\n');
    out.extend_from_slice(len.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(payload);
    out
}

/// Checks one signature. Implemented by callers with `usgp-crypto`.
///
/// Return `true` only if `key_id` names a key the caller trusts for this
/// purpose, `alg` is that key's algorithm, and `signature` verifies over
/// `message` with it. An unknown key is `false`, not an error.
pub trait SignatureVerifier {
    /// Verifies `signature` over `message`.
    fn verify(
        &self,
        key_id: &Sha256Digest,
        alg: SignatureAlg,
        message: &[u8],
        signature: &[u8],
    ) -> bool;
}

/// Envelope parse, build or verification errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// The envelope text is over [`MAX_ENVELOPE_BYTES`].
    #[error("signed envelope is {len} bytes; the limit is {MAX_ENVELOPE_BYTES}")]
    TooLarge {
        /// Length in bytes.
        len: usize,
    },
    /// The envelope is not JSON of the expected shape.
    #[error("signed envelope is not valid JSON of the expected shape")]
    Json(#[source] serde_json::Error),
    /// A base64 field is not canonical padded base64.
    #[error("signed envelope field {field} is not valid base64")]
    Base64 {
        /// The field.
        field: &'static str,
    },
    /// The payload is empty or over [`MAX_MANIFEST_PAYLOAD_BYTES`].
    #[error("signed payload is {len} bytes; it must be 1 to {MAX_MANIFEST_PAYLOAD_BYTES}")]
    PayloadSize {
        /// Length in bytes.
        len: usize,
    },
    /// No signatures, or more than [`MAX_SIGNATURES`].
    #[error("signed envelope has {count} signatures; it must have 1 to {MAX_SIGNATURES}")]
    SignatureCount {
        /// Number of signatures.
        count: usize,
    },
    /// A signature value is empty or over [`MAX_SIGNATURE_BYTES`].
    #[error("signature is {len} bytes; it must be 1 to {MAX_SIGNATURE_BYTES}")]
    SignatureSize {
        /// Length in bytes.
        len: usize,
    },
    /// The payload type is not the one the caller expects.
    #[error("signed payload type is {found}, expected {expected}")]
    WrongPayloadType {
        /// What the caller expects.
        expected: PayloadType,
        /// What the envelope says.
        found: PayloadType,
    },
    /// No signature verified with a trusted key.
    #[error("no signature verifies with a trusted key")]
    NoValidSignature,
}

/// One signature in an envelope.
#[derive(Clone, PartialEq, Eq, serde::Serialize)]
pub struct SignatureV1 {
    /// SHA-256 of the signing key's SubjectPublicKeyInfo DER.
    pub key_id: Sha256Digest,
    /// Algorithm.
    pub alg: SignatureAlg,
    /// Signature bytes (wire: `sig_b64`).
    #[serde(rename = "sig_b64", serialize_with = "ser_b64")]
    sig: Vec<u8>,
}

impl SignatureV1 {
    /// A signature value produced by `usgp-crypto`.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::SignatureSize`] if `sig` is empty or too large.
    pub fn new(
        key_id: Sha256Digest,
        alg: SignatureAlg,
        sig: Vec<u8>,
    ) -> Result<Self, EnvelopeError> {
        if sig.is_empty() || sig.len() > MAX_SIGNATURE_BYTES {
            return Err(EnvelopeError::SignatureSize { len: sig.len() });
        }
        Ok(Self { key_id, alg, sig })
    }

    /// The signature bytes.
    #[must_use]
    pub fn sig(&self) -> &[u8] {
        &self.sig
    }
}

impl fmt::Debug for SignatureV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureV1")
            .field("key_id", &self.key_id)
            .field("alg", &self.alg)
            .field("sig_len", &self.sig.len())
            .finish()
    }
}

fn ser_b64<S: serde::Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&Base64::encode_string(bytes))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SignatureWire {
    key_id: Sha256Digest,
    alg: SignatureAlg,
    sig_b64: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeWire {
    payload_type: PayloadType,
    payload_b64: String,
    signatures: Vec<SignatureWire>,
}

/// A signed payload: `{payload_type, payload_b64, signatures: [{key_id,
/// alg, sig_b64}]}` (plan section 3.3).
///
/// Every constructor and deserialization enforces the size and count
/// limits. Holding an envelope says nothing about its signatures; use
/// [`SignedEnvelopeV1::verified_payload`].
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "EnvelopeWire")]
pub struct SignedEnvelopeV1 {
    payload_type: PayloadType,
    #[serde(rename = "payload_b64", serialize_with = "ser_b64")]
    payload: Vec<u8>,
    signatures: Vec<SignatureV1>,
}

impl TryFrom<EnvelopeWire> for SignedEnvelopeV1 {
    type Error = EnvelopeError;

    fn try_from(w: EnvelopeWire) -> Result<Self, Self::Error> {
        // Bound the decoded size before decoding (4 base64 chars → 3 bytes).
        if w.payload_b64.len() / 4 * 3 > MAX_MANIFEST_PAYLOAD_BYTES + 3 {
            return Err(EnvelopeError::PayloadSize {
                len: w.payload_b64.len() / 4 * 3,
            });
        }
        if w.signatures.is_empty() || w.signatures.len() > MAX_SIGNATURES {
            return Err(EnvelopeError::SignatureCount {
                count: w.signatures.len(),
            });
        }
        let payload = Base64::decode_vec(&w.payload_b64).map_err(|_| EnvelopeError::Base64 {
            field: "payload_b64",
        })?;
        let mut signatures = Vec::with_capacity(w.signatures.len());
        for s in w.signatures {
            if s.sig_b64.len() / 4 * 3 > MAX_SIGNATURE_BYTES + 3 {
                return Err(EnvelopeError::SignatureSize {
                    len: s.sig_b64.len() / 4 * 3,
                });
            }
            let sig = Base64::decode_vec(&s.sig_b64)
                .map_err(|_| EnvelopeError::Base64 { field: "sig_b64" })?;
            signatures.push(SignatureV1::new(s.key_id, s.alg, sig)?);
        }
        Self::new(w.payload_type, payload, signatures)
    }
}

/// A payload whose signature has been verified.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedPayload<'a> {
    /// The exact signed payload bytes.
    pub bytes: &'a [u8],
    /// The key that verified it.
    pub key_id: Sha256Digest,
}

impl SignedEnvelopeV1 {
    /// Builds an envelope from a payload and signatures made over
    /// [`signing_input`]`(payload_type, &payload)`.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::PayloadSize`] or [`EnvelopeError::SignatureCount`].
    pub fn new(
        payload_type: PayloadType,
        payload: Vec<u8>,
        signatures: Vec<SignatureV1>,
    ) -> Result<Self, EnvelopeError> {
        if payload.is_empty() || payload.len() > MAX_MANIFEST_PAYLOAD_BYTES {
            return Err(EnvelopeError::PayloadSize { len: payload.len() });
        }
        if signatures.is_empty() || signatures.len() > MAX_SIGNATURES {
            return Err(EnvelopeError::SignatureCount {
                count: signatures.len(),
            });
        }
        Ok(Self {
            payload_type,
            payload,
            signatures,
        })
    }

    /// Parses envelope JSON, after checking its size.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::TooLarge`] before parsing; [`EnvelopeError::Json`]
    /// for shape errors (including every limit, which serde reports through
    /// the JSON error).
    pub fn from_json(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(EnvelopeError::TooLarge { len: bytes.len() });
        }
        serde_json::from_slice(bytes).map_err(EnvelopeError::Json)
    }

    /// Envelope JSON.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::Json`] if serialization fails (not expected for
    /// this type).
    pub fn to_json(&self) -> Result<Vec<u8>, EnvelopeError> {
        serde_json::to_vec(self).map_err(EnvelopeError::Json)
    }

    /// The payload type as stated (unverified).
    #[must_use]
    pub const fn payload_type(&self) -> PayloadType {
        self.payload_type
    }

    /// The signatures (unverified).
    #[must_use]
    pub fn signatures(&self) -> &[SignatureV1] {
        &self.signatures
    }

    /// Checks the payload type, then the signatures over
    /// [`signing_input`], and returns the payload bytes only if one
    /// signature verifies with a key the verifier trusts. Nothing parses
    /// the payload before this succeeds.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::WrongPayloadType`] or
    /// [`EnvelopeError::NoValidSignature`].
    pub fn verified_payload(
        &self,
        expected: PayloadType,
        verifier: &dyn SignatureVerifier,
    ) -> Result<VerifiedPayload<'_>, EnvelopeError> {
        if self.payload_type != expected {
            return Err(EnvelopeError::WrongPayloadType {
                expected,
                found: self.payload_type,
            });
        }
        let message = signing_input(self.payload_type, &self.payload);
        self.signatures
            .iter()
            .find(|s| verifier.verify(&s.key_id, s.alg, &message, &s.sig))
            .map(|s| VerifiedPayload {
                bytes: &self.payload,
                key_id: s.key_id,
            })
            .ok_or(EnvelopeError::NoValidSignature)
    }
}

impl fmt::Debug for SignedEnvelopeV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedEnvelopeV1")
            .field("payload_type", &self.payload_type)
            .field("payload_len", &self.payload.len())
            .field("signatures", &self.signatures)
            .finish()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Test verifier with no cryptography: accepts the tag
    /// `b"ok:" || key_id[0]` for trusted key ids. Real verification is in
    /// usgp-crypto.
    pub(crate) struct FakeVerifier {
        pub trusted: Vec<Sha256Digest>,
    }

    impl SignatureVerifier for FakeVerifier {
        fn verify(&self, key_id: &Sha256Digest, _: SignatureAlg, _: &[u8], sig: &[u8]) -> bool {
            self.trusted.contains(key_id) && sig == fake_sig(key_id)
        }
    }

    pub(crate) fn fake_sig(key_id: &Sha256Digest) -> Vec<u8> {
        let mut v = b"ok:".to_vec();
        v.push(key_id.0[0]);
        v
    }

    pub(crate) fn key(n: u8) -> Sha256Digest {
        Sha256Digest([n; 32])
    }

    #[test]
    fn signing_input_golden() {
        // Golden vector (plan section 5.3). usgp-crypto must build the same
        // bytes for the same (type, payload).
        let got = signing_input(PayloadType::ContentManifestV1, b"{\"a\":1}");
        let want: &[u8] =
            b"USGP-SIG-V1\napplication/vnd.usgp.content-manifest.v1+json\n7\n{\"a\":1}";
        assert_eq!(got, want);
        let pkg = signing_input(PayloadType::PackageManifestV1, b"{\"a\":1}");
        assert_ne!(got, pkg, "type is bound");
        let plan = signing_input(PayloadType::JobPlanV1, b"{\"a\":1}");
        assert_eq!(
            plan,
            b"USGP-SIG-V1\napplication/vnd.usgp.job-plan.v1+json\n7\n{\"a\":1}"
        );
        let policy = signing_input(PayloadType::BootPolicyV1, b"{\"a\":1}");
        assert!(policy.starts_with(b"USGP-SIG-V1\napplication/vnd.usgp.boot-policy.v1+json\n"));
        let longer = signing_input(PayloadType::ContentManifestV1, b"{\"a\":12}");
        assert!(
            longer.starts_with(b"USGP-SIG-V1\napplication/vnd.usgp.content-manifest.v1+json\n8\n")
        );
    }

    fn env(payload: &[u8], k: u8) -> SignedEnvelopeV1 {
        let sig =
            SignatureV1::new(key(k), SignatureAlg::EcdsaP384Sha384, fake_sig(&key(k))).unwrap();
        SignedEnvelopeV1::new(PayloadType::ContentManifestV1, payload.to_vec(), vec![sig]).unwrap()
    }

    #[test]
    fn json_round_trip_and_wire_shape() {
        let e = env(b"hello", 7);
        let json = String::from_utf8(e.to_json().unwrap()).unwrap();
        let want_key = key(7).to_hex();
        assert_eq!(
            json,
            format!(
                "{{\"payload_type\":\"application/vnd.usgp.content-manifest.v1+json\",\
                 \"payload_b64\":\"aGVsbG8=\",\"signatures\":[{{\"key_id\":\"{want_key}\",\
                 \"alg\":\"ecdsa-p384-sha384\",\"sig_b64\":\"b2s6Bw==\"}}]}}"
            )
        );
        assert_eq!(SignedEnvelopeV1::from_json(json.as_bytes()).unwrap(), e);
    }

    #[test]
    fn verify_before_parse() {
        let e = env(b"not even json", 7);
        let v = FakeVerifier {
            trusted: vec![key(7)],
        };
        let p = e
            .verified_payload(PayloadType::ContentManifestV1, &v)
            .unwrap();
        assert_eq!(p.bytes, b"not even json");
        assert_eq!(p.key_id, key(7));

        let untrusted = FakeVerifier {
            trusted: vec![key(8)],
        };
        assert!(matches!(
            e.verified_payload(PayloadType::ContentManifestV1, &untrusted),
            Err(EnvelopeError::NoValidSignature)
        ));
        assert!(matches!(
            e.verified_payload(PayloadType::PackageManifestV1, &v),
            Err(EnvelopeError::WrongPayloadType { .. })
        ));
    }

    #[test]
    fn any_trusted_signature_suffices_bad_ones_ignored() {
        let bad = SignatureV1::new(key(7), SignatureAlg::EcdsaP384Sha384, vec![1, 2]).unwrap();
        let good =
            SignatureV1::new(key(9), SignatureAlg::EcdsaP384Sha384, fake_sig(&key(9))).unwrap();
        let e = SignedEnvelopeV1::new(
            PayloadType::ContentManifestV1,
            b"p".to_vec(),
            vec![bad, good],
        )
        .unwrap();
        let v = FakeVerifier {
            trusted: vec![key(7), key(9)],
        };
        let p = e
            .verified_payload(PayloadType::ContentManifestV1, &v)
            .unwrap();
        assert_eq!(p.key_id, key(9));
    }

    #[test]
    fn limits() {
        assert!(matches!(
            SignedEnvelopeV1::new(PayloadType::ContentManifestV1, Vec::new(), vec![]),
            Err(EnvelopeError::PayloadSize { len: 0 })
        ));
        assert!(matches!(
            SignedEnvelopeV1::new(PayloadType::ContentManifestV1, b"x".to_vec(), vec![]),
            Err(EnvelopeError::SignatureCount { count: 0 })
        ));
        let sig = SignatureV1::new(key(1), SignatureAlg::EcdsaP384Sha384, vec![0; 104]).unwrap();
        assert!(matches!(
            SignedEnvelopeV1::new(
                PayloadType::ContentManifestV1,
                b"x".to_vec(),
                vec![sig; MAX_SIGNATURES + 1]
            ),
            Err(EnvelopeError::SignatureCount { count: 9 })
        ));
        assert!(matches!(
            SignatureV1::new(key(1), SignatureAlg::EcdsaP384Sha384, vec![0; 513]),
            Err(EnvelopeError::SignatureSize { len: 513 })
        ));
        assert!(matches!(
            SignatureV1::new(key(1), SignatureAlg::EcdsaP384Sha384, Vec::new()),
            Err(EnvelopeError::SignatureSize { len: 0 })
        ));
        assert!(matches!(
            SignedEnvelopeV1::from_json(&vec![b' '; MAX_ENVELOPE_BYTES + 1]),
            Err(EnvelopeError::TooLarge { .. })
        ));
    }

    #[test]
    fn strict_json() {
        let k = key(7).to_hex();
        let base = |extra_top: &str, payload: &str, sig: &str, ty: &str| {
            format!(
                "{{\"payload_type\":\"{ty}\",\"payload_b64\":\"{payload}\",\
                 \"signatures\":[{{\"key_id\":\"{k}\",\"alg\":\"ecdsa-p384-sha384\",\
                 \"sig_b64\":\"{sig}\"}}]{extra_top}}}"
            )
        };
        let ty = "application/vnd.usgp.content-manifest.v1+json";
        assert!(
            SignedEnvelopeV1::from_json(base("", "aGVsbG8=", "b2s6Bw==", ty).as_bytes()).is_ok()
        );
        for bad in [
            base(",\"x\":1", "aGVsbG8=", "b2s6Bw==", ty),
            base("", "aGVsbG8", "b2s6Bw==", ty), // missing padding
            base("", "aGVsbG8=\\n", "b2s6Bw==", ty),
            base("", "aGVs bG8=", "b2s6Bw==", ty),
            base("", "aGVsbG8=", "b2s6Bw==", "text/plain"),
            base("", "", "b2s6Bw==", ty), // empty payload
            base("", "aGVsbG8=", "", ty), // empty signature
            base(
                "",
                "aGVsbG8=",
                "b2s6Bw==",
                "application/vnd.usgp.content-manifest.v2+json",
            ),
        ] {
            assert!(
                SignedEnvelopeV1::from_json(bad.as_bytes()).is_err(),
                "{bad}"
            );
        }
        let unknown_sig_field = format!(
            "{{\"payload_type\":\"{ty}\",\"payload_b64\":\"aGVsbG8=\",\"signatures\":[{{\"key_id\":\"{k}\",\
             \"alg\":\"ecdsa-p384-sha384\",\"sig_b64\":\"b2s6Bw==\",\"x\":0}}]}}"
        );
        assert!(SignedEnvelopeV1::from_json(unknown_sig_field.as_bytes()).is_err());
        let bad_alg = format!(
            "{{\"payload_type\":\"{ty}\",\"payload_b64\":\"aGVsbG8=\",\"signatures\":[{{\"key_id\":\"{k}\",\
             \"alg\":\"ecdsa-p256-sha256\",\"sig_b64\":\"b2s6Bw==\"}}]}}"
        );
        assert!(SignedEnvelopeV1::from_json(bad_alg.as_bytes()).is_err());
    }

    #[test]
    fn debug_hides_bytes() {
        let e = env(b"payload-text", 7);
        let d = format!("{e:?}");
        assert!(!d.contains("payload-text"));
        assert!(d.contains("payload_len: 12"));
    }
}
