//! Package manifest, version 1 (plan section 3.3): what a Ready package
//! installs, signed by the server's content key when the package becomes
//! Ready.
//!
//! ```json
//! {"schema":1,"package_id":"…","revision":3,"name":"…",
//!  "image":{"content_sha256":"…","edition_index":1,"edition_name":"…",
//!           "facts":{"release":{"value":"windows-11","source":"declared"},
//!                    "edition":{"value":"enterprise","source":"declared"},
//!                    "architecture":{"value":"x64","source":"declared"}},
//!           "declared_by":"…","declared_audit_seq":42},
//!  "pe":{"content_sha256":"…","usable_index":1,
//!        "architecture":{"value":"x64","source":"declared"},
//!        "kit_version":{"value":"10.1.26100.1","source":"declared"}},
//!  "signed_at":…,"key_id":"…"}
//! ```
//!
//! Every fact carries its source, so the declared/verified distinction
//! (decision 0013 item 2) is part of the signed record. The operator who
//! declared the edition's facts and the audit record of that declaration
//! are named. As for the content manifest, the signed bytes are exactly
//! [`PackageManifestV1::to_payload`]'s output.
//!
//! Scope (which facts may make a package Ready) is decided by
//! `usgp-image::os_support` before signing; this type does not repeat it.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7(6) (Cryptographic Protection) - signed package
//   record.
// - NIST 800-53: AU-10 (Non-repudiation, basis) - declaring operator and
//   audit sequence bound into the signed record.
// - NIST 800-53: SI-10 (Information Input Validation) - strict parse.
// - SPEC: specs/os-images.md#REQ-IMG-001 (one edition and one PE),
//   #REQ-IMG-041 (edition by index), #REQ-IMG-043 (facts marked declared
//   or verified)
// - SPEC: specs/preinstall-env.md#REQ-PE-005 (PE architecture and kit
//   version, with source)
// - Decision 0013 items 2 and 4

use usgp_common::Sha256Digest;

use crate::SignedManifestError;
use crate::envelope::{PayloadType, SignatureVerifier, SignedEnvelopeV1};
use crate::facts::{Architecture, EditionFacts, Fact, KitVersion};
use crate::ids::{OperatorId, PackageId, UnixMicros};
use crate::limits::MAX_MANIFEST_PAYLOAD_BYTES;
use crate::names::{DisplayName, EditionIndex, WimText};

/// The only manifest schema version.
pub const SCHEMA_V1: u32 = 1;

/// The chosen image edition.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageImageV1 {
    /// SHA-256 of the image file.
    pub content_sha256: Sha256Digest,
    /// Chosen edition index.
    pub edition_index: EditionIndex,
    /// Edition name from the file.
    pub edition_name: WimText,
    /// Release, edition and architecture, each with its source.
    pub facts: EditionFacts,
    /// Operator who declared the facts.
    pub declared_by: OperatorId,
    /// Sequence number of the `edition.declared` audit record (at least 1).
    pub declared_audit_seq: u64,
}

/// The chosen PE kit.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagePeV1 {
    /// SHA-256 of the PE file.
    pub content_sha256: Sha256Digest,
    /// Index of the usable image in the PE file (REQ-PE-004).
    pub usable_index: EditionIndex,
    /// Processor architecture with its source.
    pub architecture: Fact<Architecture>,
    /// Kit version with its source.
    pub kit_version: Fact<KitVersion>,
}

/// Package manifest, version 1.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageManifestV1 {
    /// Always [`SCHEMA_V1`].
    pub schema: u32,
    /// Package identifier.
    pub package_id: PackageId,
    /// Package revision (at least 1); the same value as the `ETag`.
    pub revision: u64,
    /// Package name.
    pub name: DisplayName,
    /// Image edition.
    pub image: PackageImageV1,
    /// PE kit.
    pub pe: PackagePeV1,
    /// When the manifest was signed.
    pub signed_at: UnixMicros,
    /// Key id (SHA-256 of the SPKI DER) of the content signing key.
    pub key_id: Sha256Digest,
}

impl PackageManifestV1 {
    /// Checks every rule a v1 package manifest must meet beyond its types.
    ///
    /// # Errors
    ///
    /// [`SignedManifestError::UnsupportedSchema`] or
    /// [`SignedManifestError::Invalid`] naming the first rule broken.
    pub fn validate(&self) -> Result<(), SignedManifestError> {
        if self.schema != SCHEMA_V1 {
            return Err(SignedManifestError::UnsupportedSchema(self.schema));
        }
        if self.revision == 0 {
            return Err(SignedManifestError::Invalid("revision must be at least 1"));
        }
        if self.image.declared_audit_seq == 0 {
            return Err(SignedManifestError::Invalid(
                "image.declared_audit_seq must be at least 1",
            ));
        }
        Ok(())
    }

    /// The exact bytes to sign and store: compact JSON in field order.
    ///
    /// # Errors
    ///
    /// As [`PackageManifestV1::validate`]; [`SignedManifestError::TooLarge`]
    /// if the result is over [`MAX_MANIFEST_PAYLOAD_BYTES`].
    pub fn to_payload(&self) -> Result<Vec<u8>, SignedManifestError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(SignedManifestError::Json)?;
        if bytes.len() > MAX_MANIFEST_PAYLOAD_BYTES {
            return Err(SignedManifestError::TooLarge { len: bytes.len() });
        }
        Ok(bytes)
    }

    /// Parses and validates payload bytes (see
    /// [`crate::ContentManifestV1::from_payload`] for when to use it).
    ///
    /// # Errors
    ///
    /// [`SignedManifestError::TooLarge`] before parsing;
    /// [`SignedManifestError::Json`]; or as
    /// [`PackageManifestV1::validate`].
    pub fn from_payload(bytes: &[u8]) -> Result<Self, SignedManifestError> {
        if bytes.len() > MAX_MANIFEST_PAYLOAD_BYTES {
            return Err(SignedManifestError::TooLarge { len: bytes.len() });
        }
        let m: Self = serde_json::from_slice(bytes).map_err(SignedManifestError::Json)?;
        m.validate()?;
        Ok(m)
    }

    /// Verifies the envelope, then parses and validates the payload, then
    /// checks that `key_id` is the key that verified it.
    ///
    /// # Errors
    ///
    /// [`SignedManifestError::Envelope`] if verification fails (nothing is
    /// parsed); otherwise as [`PackageManifestV1::from_payload`], or
    /// [`SignedManifestError::KeyIdMismatch`].
    pub fn open(
        envelope: &SignedEnvelopeV1,
        verifier: &dyn SignatureVerifier,
    ) -> Result<Self, SignedManifestError> {
        let verified = envelope.verified_payload(PayloadType::PackageManifestV1, verifier)?;
        let m = Self::from_payload(verified.bytes)?;
        if m.key_id != verified.key_id {
            return Err(SignedManifestError::KeyIdMismatch);
        }
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::tests::{FakeVerifier, fake_sig, key};
    use crate::envelope::{SignatureAlg, SignatureV1};
    use crate::facts::{Edition, Release};

    fn sample() -> PackageManifestV1 {
        PackageManifestV1 {
            schema: 1,
            package_id: PackageId::parse("1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516").unwrap(),
            revision: 3,
            name: DisplayName::new("Field laptops").unwrap(),
            image: PackageImageV1 {
                content_sha256: Sha256Digest([0xaa; 32]),
                edition_index: EditionIndex::new(1).unwrap(),
                edition_name: WimText::new("Edition 1").unwrap(),
                facts: EditionFacts {
                    release: Fact::declared(Release::Windows11),
                    edition: Fact::declared(Edition::Enterprise),
                    architecture: Fact::verified(Architecture::X64),
                },
                declared_by: OperatorId::parse("2d0f9b81-3c4e-4f60-8b1c-d2e3f4051627").unwrap(),
                declared_audit_seq: 42,
            },
            pe: PackagePeV1 {
                content_sha256: Sha256Digest([0xcc; 32]),
                usable_index: EditionIndex::new(1).unwrap(),
                architecture: Fact::declared(Architecture::X64),
                kit_version: Fact::declared(KitVersion::parse("10.1.26100.1").unwrap()),
            },
            signed_at: UnixMicros::new(1_793_000_000_000_001).unwrap(),
            key_id: key(7),
        }
    }

    #[test]
    fn golden_payload() {
        let m = sample();
        let p = String::from_utf8(m.to_payload().unwrap()).unwrap();
        let a = "a".repeat(64);
        let c = "c".repeat(64);
        let k = "07".repeat(32);
        let want = format!(
            "{{\"schema\":1,\"package_id\":\"1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516\",\"revision\":3,\
             \"name\":\"Field laptops\",\"image\":{{\"content_sha256\":\"{a}\",\"edition_index\":1,\
             \"edition_name\":\"Edition 1\",\"facts\":{{\
             \"release\":{{\"value\":\"windows-11\",\"source\":\"declared\"}},\
             \"edition\":{{\"value\":\"enterprise\",\"source\":\"declared\"}},\
             \"architecture\":{{\"value\":\"x64\",\"source\":\"verified\"}}}},\
             \"declared_by\":\"2d0f9b81-3c4e-4f60-8b1c-d2e3f4051627\",\"declared_audit_seq\":42}},\
             \"pe\":{{\"content_sha256\":\"{c}\",\"usable_index\":1,\
             \"architecture\":{{\"value\":\"x64\",\"source\":\"declared\"}},\
             \"kit_version\":{{\"value\":\"10.1.26100.1\",\"source\":\"declared\"}}}},\
             \"signed_at\":1793000000000001,\"key_id\":\"{k}\"}}"
        );
        assert_eq!(p, want);
        assert_eq!(PackageManifestV1::from_payload(p.as_bytes()).unwrap(), m);
    }

    #[test]
    fn validation_and_strictness() {
        let mut m = sample();
        m.revision = 0;
        assert!(m.validate().is_err());
        let mut m = sample();
        m.image.declared_audit_seq = 0;
        assert!(m.validate().is_err());
        let mut m = sample();
        m.schema = 0;
        assert!(m.to_payload().is_err());

        let p = String::from_utf8(sample().to_payload().unwrap()).unwrap();
        // A fact without its source, or with an unknown source, is refused.
        let no_src = p.replacen(",\"source\":\"declared\"", "", 1);
        assert!(PackageManifestV1::from_payload(no_src.as_bytes()).is_err());
        let bad_src = p.replacen("\"declared\"", "\"assumed\"", 1);
        assert!(PackageManifestV1::from_payload(bad_src.as_bytes()).is_err());
        // There is no feature-update field (REQ-OS-008).
        let fu = p.replacen(
            "\"facts\":{",
            "\"facts\":{\"feature_update\":{\"value\":\"24H2\",\"source\":\"declared\"},",
            1,
        );
        assert!(PackageManifestV1::from_payload(fu.as_bytes()).is_err());
        let bad_kit = p.replace("10.1.26100.1", "10.01.26100.1");
        assert!(PackageManifestV1::from_payload(bad_kit.as_bytes()).is_err());
    }

    #[test]
    fn open_checks_type_and_key() {
        let m = sample();
        let sig =
            SignatureV1::new(key(7), SignatureAlg::EcdsaP384Sha384, fake_sig(&key(7))).unwrap();
        let env = SignedEnvelopeV1::new(
            PayloadType::PackageManifestV1,
            m.to_payload().unwrap(),
            vec![sig.clone()],
        )
        .unwrap();
        let v = FakeVerifier {
            trusted: vec![key(7)],
        };
        assert_eq!(PackageManifestV1::open(&env, &v).unwrap(), m);

        // The same payload labelled as a content manifest is not a package
        // manifest (type confusion refused before parsing).
        let wrong = SignedEnvelopeV1::new(
            PayloadType::ContentManifestV1,
            m.to_payload().unwrap(),
            vec![sig],
        )
        .unwrap();
        assert!(matches!(
            PackageManifestV1::open(&wrong, &v),
            Err(SignedManifestError::Envelope(_))
        ));
    }
}
