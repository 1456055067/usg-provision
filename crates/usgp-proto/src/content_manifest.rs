//! Content manifest, version 1 (plan section 3.3): what a Ready content
//! item (image file or PE kit) is, with its total digest and one SHA-256
//! per 8 MiB chunk, signed by the server's content key.
//!
//! ```json
//! {"schema":1,"kind":"image","content_id":"…","display_name":"…",
//!  "file_name":"…","size":…,"sha256":"…","chunk_size":8388608,
//!  "chunk_sha256":["…",…],
//!  "wim":{"compression":"xpress","image_count":12,"boot_index":0,
//!         "editions":[{"index":1,"name":"…","description":"…","total_bytes":…},…]},
//!  "ready_at":…,"key_id":"…"}
//! ```
//!
//! The signed bytes are exactly [`ContentManifestV1::to_payload`]'s output,
//! as stored; readers verify the envelope over those bytes and only then
//! parse them ([`ContentManifestV1::open`]). Field order is fixed by this
//! struct and there are no maps, so the encoding is deterministic.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7, SI-7(1), SI-7(6) - per-chunk reference digests,
//   signed; checked on every use (plan section 5.7).
// - NIST 800-53: SI-10 (Information Input Validation) - schema, size,
//   chunk count, edition list and text lengths validated on every parse.
// - SPEC: specs/os-images.md#REQ-IMG-050 (digest recorded at Ready, checked
//   on every use), #REQ-IMG-052 (ready content does not change)
// - SPEC: specs/os-images.md#REQ-IMG-040 (editions: index, name,
//   description, size)
// - SPEC: specs/preinstall-env.md#REQ-PE-008 (PE integrity)
// - FIPS 180-4 (SHA-256)

use usgp_common::Sha256Digest;

use crate::SignedManifestError;
use crate::envelope::{PayloadType, SignatureVerifier, SignedEnvelopeV1};
use crate::ids::{ContentId, UnixMicros};
use crate::limits::{CHUNK_SIZE, MAX_CONTENT_BYTES, MAX_IMAGES, MAX_MANIFEST_PAYLOAD_BYTES};
use crate::names::{DisplayName, EditionIndex, FileName, WimText};
use crate::status::{ContentKind, WimCompression};

/// The only manifest schema version.
pub const SCHEMA_V1: u32 = 1;

/// One edition (image) in the file, as the WIM XML records it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEdition {
    /// 1-based index.
    pub index: EditionIndex,
    /// Name from the file.
    pub name: WimText,
    /// Description from the file.
    pub description: WimText,
    /// Size the file states for the edition, if any.
    pub total_bytes: Option<u64>,
}

/// The checked WIM structure.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WimSummaryV1 {
    /// Resource compression (decision 0014).
    pub compression: WimCompression,
    /// Number of images, 1 to [`MAX_IMAGES`].
    pub image_count: u32,
    /// Header boot index; 0 means none (`specs/standards/wim.md` §2).
    pub boot_index: u32,
    /// One entry per image, indexes 1 to `image_count` in order.
    pub editions: Vec<ManifestEdition>,
}

/// Content manifest, version 1.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentManifestV1 {
    /// Always [`SCHEMA_V1`].
    pub schema: u32,
    /// Image file or PE kit.
    pub kind: ContentKind,
    /// Content identifier.
    pub content_id: ContentId,
    /// Operator-given name.
    pub display_name: DisplayName,
    /// Uploaded file name.
    pub file_name: FileName,
    /// Exact size in bytes, 1 to [`MAX_CONTENT_BYTES`].
    pub size: u64,
    /// SHA-256 of the whole file.
    pub sha256: Sha256Digest,
    /// Chunk size; always [`CHUNK_SIZE`] in v1.
    pub chunk_size: u64,
    /// SHA-256 of each chunk in order; the last chunk may be short.
    pub chunk_sha256: Vec<Sha256Digest>,
    /// WIM structure.
    pub wim: WimSummaryV1,
    /// When the content became Ready.
    pub ready_at: UnixMicros,
    /// Key id (SHA-256 of the SPKI DER) of the content signing key.
    pub key_id: Sha256Digest,
}

/// Number of chunks for `size` bytes (`ceil(size / CHUNK_SIZE)`).
#[must_use]
pub const fn chunk_count(size: u64) -> u64 {
    size.div_ceil(CHUNK_SIZE)
}

/// Length of chunk `i` (0-based) of content of `size` bytes, or `None`
/// past the end.
#[must_use]
pub fn chunk_len(size: u64, i: u64) -> Option<u64> {
    let start = i.checked_mul(CHUNK_SIZE)?;
    if start >= size {
        return None;
    }
    Some((size - start).min(CHUNK_SIZE))
}

impl ContentManifestV1 {
    /// Checks every rule a v1 content manifest must meet.
    ///
    /// # Errors
    ///
    /// [`SignedManifestError::UnsupportedSchema`] or
    /// [`SignedManifestError::Invalid`] naming the first rule broken.
    pub fn validate(&self) -> Result<(), SignedManifestError> {
        use SignedManifestError::Invalid;
        if self.schema != SCHEMA_V1 {
            return Err(SignedManifestError::UnsupportedSchema(self.schema));
        }
        if self.size == 0 || self.size > MAX_CONTENT_BYTES {
            return Err(Invalid("size must be 1 byte to 1 TiB"));
        }
        if self.chunk_size != CHUNK_SIZE {
            return Err(Invalid("chunk_size must be 8388608"));
        }
        let n = u64::try_from(self.chunk_sha256.len())
            .map_err(|_| Invalid("chunk_sha256 count does not match size"))?;
        if n != chunk_count(self.size) {
            return Err(Invalid("chunk_sha256 count does not match size"));
        }
        let w = &self.wim;
        if w.image_count == 0 || w.image_count > MAX_IMAGES {
            return Err(Invalid("wim.image_count must be 1 to 1024"));
        }
        if w.boot_index > w.image_count {
            return Err(Invalid("wim.boot_index is above wim.image_count"));
        }
        let listed = u32::try_from(w.editions.len())
            .map_err(|_| Invalid("wim.editions must list 1 to image_count in order"))?;
        if listed != w.image_count
            || !w
                .editions
                .iter()
                .zip(1u32..)
                .all(|(e, want)| e.index.get() == want)
        {
            return Err(Invalid("wim.editions must list 1 to image_count in order"));
        }
        Ok(())
    }

    /// The exact bytes to sign and store: compact JSON in field order.
    ///
    /// # Errors
    ///
    /// As [`ContentManifestV1::validate`]; [`SignedManifestError::TooLarge`]
    /// if the result is over [`MAX_MANIFEST_PAYLOAD_BYTES`].
    pub fn to_payload(&self) -> Result<Vec<u8>, SignedManifestError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(SignedManifestError::Json)?;
        if bytes.len() > MAX_MANIFEST_PAYLOAD_BYTES {
            return Err(SignedManifestError::TooLarge { len: bytes.len() });
        }
        Ok(bytes)
    }

    /// Parses and validates payload bytes. Use only on bytes whose
    /// signature has been verified, or on bytes read back from our own
    /// store for display; [`ContentManifestV1::open`] does both steps.
    ///
    /// # Errors
    ///
    /// [`SignedManifestError::TooLarge`] before parsing;
    /// [`SignedManifestError::Json`]; or as
    /// [`ContentManifestV1::validate`].
    pub fn from_payload(bytes: &[u8]) -> Result<Self, SignedManifestError> {
        if bytes.len() > MAX_MANIFEST_PAYLOAD_BYTES {
            return Err(SignedManifestError::TooLarge { len: bytes.len() });
        }
        let m: Self = serde_json::from_slice(bytes).map_err(SignedManifestError::Json)?;
        m.validate()?;
        Ok(m)
    }

    /// Verifies the envelope (payload type and a trusted signature), then
    /// parses and validates the payload, then checks that the manifest's
    /// `key_id` is the key that verified it.
    ///
    /// # Errors
    ///
    /// [`SignedManifestError::Envelope`] if verification fails (nothing
    /// is parsed); otherwise as [`ContentManifestV1::from_payload`], or
    /// [`SignedManifestError::KeyIdMismatch`].
    pub fn open(
        envelope: &SignedEnvelopeV1,
        verifier: &dyn SignatureVerifier,
    ) -> Result<Self, SignedManifestError> {
        let verified = envelope.verified_payload(PayloadType::ContentManifestV1, verifier)?;
        let m = Self::from_payload(verified.bytes)?;
        if m.key_id != verified.key_id {
            return Err(SignedManifestError::KeyIdMismatch);
        }
        Ok(m)
    }

    /// Expected length and digest of chunk `i` (0-based), or `None` past
    /// the end.
    #[must_use]
    pub fn chunk(&self, i: u64) -> Option<(u64, &Sha256Digest)> {
        let len = chunk_len(self.size, i)?;
        let idx = usize::try_from(i).ok()?;
        self.chunk_sha256.get(idx).map(|d| (len, d))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::envelope::tests::{FakeVerifier, fake_sig, key};
    use crate::envelope::{SignatureAlg, SignatureV1};

    pub(crate) fn sample(size: u64, images: u32) -> ContentManifestV1 {
        let n = usize::try_from(chunk_count(size)).unwrap();
        ContentManifestV1 {
            schema: 1,
            kind: ContentKind::Image,
            content_id: ContentId::parse("0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f").unwrap(),
            display_name: DisplayName::new("Win 11 Ent").unwrap(),
            file_name: FileName::new("install image.wim").unwrap(),
            size,
            sha256: Sha256Digest([0xaa; 32]),
            chunk_size: CHUNK_SIZE,
            chunk_sha256: vec![Sha256Digest([0xbb; 32]); n],
            wim: WimSummaryV1 {
                compression: WimCompression::Xpress,
                image_count: images,
                boot_index: 0,
                editions: (1..=images)
                    .map(|i| ManifestEdition {
                        index: EditionIndex::new(u64::from(i)).unwrap(),
                        name: WimText::new(format!("Edition {i}")).unwrap(),
                        description: WimText::new("d").unwrap(),
                        total_bytes: Some(1000),
                    })
                    .collect(),
            },
            ready_at: UnixMicros::new(1_793_000_000_000_000).unwrap(),
            key_id: key(7),
        }
    }

    #[test]
    fn chunk_math() {
        assert_eq!(chunk_count(1), 1);
        assert_eq!(chunk_count(CHUNK_SIZE), 1);
        assert_eq!(chunk_count(CHUNK_SIZE + 1), 2);
        assert_eq!(chunk_count(MAX_CONTENT_BYTES), 131_072);
        assert_eq!(chunk_len(CHUNK_SIZE + 5, 0), Some(CHUNK_SIZE));
        assert_eq!(chunk_len(CHUNK_SIZE + 5, 1), Some(5));
        assert_eq!(chunk_len(CHUNK_SIZE + 5, 2), None);
        assert_eq!(chunk_len(10, u64::MAX), None);
        let m = sample(CHUNK_SIZE + 5, 1);
        assert_eq!(m.chunk(1).map(|(l, _)| l), Some(5));
        assert!(m.chunk(2).is_none());
    }

    #[test]
    fn golden_payload() {
        let m = sample(5, 1);
        let p = String::from_utf8(m.to_payload().unwrap()).unwrap();
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let k = "07".repeat(32);
        let want = format!(
            "{{\"schema\":1,\"kind\":\"image\",\"content_id\":\"0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f\",\
             \"display_name\":\"Win 11 Ent\",\"file_name\":\"install image.wim\",\"size\":5,\
             \"sha256\":\"{a}\",\"chunk_size\":8388608,\"chunk_sha256\":[\"{b}\"],\
             \"wim\":{{\"compression\":\"xpress\",\"image_count\":1,\"boot_index\":0,\
             \"editions\":[{{\"index\":1,\"name\":\"Edition 1\",\"description\":\"d\",\"total_bytes\":1000}}]}},\
             \"ready_at\":1793000000000000,\"key_id\":\"{k}\"}}"
        );
        assert_eq!(p, want);
        assert_eq!(ContentManifestV1::from_payload(p.as_bytes()).unwrap(), m);
    }

    #[test]
    fn validation_rules() {
        let ok = sample(3 * CHUNK_SIZE, 12);
        assert!(ok.validate().is_ok());

        let mut m = ok.clone();
        m.schema = 2;
        assert!(matches!(
            m.validate(),
            Err(SignedManifestError::UnsupportedSchema(2))
        ));
        let mut m = ok.clone();
        m.size = 0;
        assert!(m.validate().is_err());
        let mut m = ok.clone();
        m.size = MAX_CONTENT_BYTES + 1;
        assert!(m.validate().is_err());
        let mut m = ok.clone();
        m.chunk_size = 4096;
        assert!(m.validate().is_err());
        let mut m = ok.clone();
        m.chunk_sha256.pop();
        assert!(m.validate().is_err());
        let mut m = ok.clone();
        m.size += 1; // now needs 4 chunks
        assert!(m.validate().is_err());
        let mut m = ok.clone();
        m.wim.boot_index = 13;
        assert!(m.validate().is_err());
        let mut m = ok.clone();
        m.wim.boot_index = 12;
        assert!(m.validate().is_ok());
        let mut m = ok.clone();
        m.wim.editions.swap(0, 1);
        assert!(m.validate().is_err());
        let mut m = ok.clone();
        m.wim.editions.pop();
        assert!(m.validate().is_err());
        let mut m = ok.clone();
        m.wim.image_count = 0;
        m.wim.editions.clear();
        assert!(m.validate().is_err());
    }

    #[test]
    fn strict_parse() {
        let p = String::from_utf8(sample(5, 1).to_payload().unwrap()).unwrap();
        let extra = p.replacen("{\"schema\":1,", "{\"schema\":1,\"x\":0,", 1);
        assert!(ContentManifestV1::from_payload(extra.as_bytes()).is_err());
        let lzx = p.replace("\"xpress\"", "\"lzx\"");
        assert!(ContentManifestV1::from_payload(lzx.as_bytes()).is_err());
        let dup = p.replacen("{\"schema\":1,", "{\"schema\":1,\"schema\":1,", 1);
        assert!(ContentManifestV1::from_payload(dup.as_bytes()).is_err());
        let trailing = format!("{p}x");
        assert!(ContentManifestV1::from_payload(trailing.as_bytes()).is_err());
        let zero_index = p.replace("\"index\":1", "\"index\":0");
        assert!(ContentManifestV1::from_payload(zero_index.as_bytes()).is_err());
        let big = vec![b' '; MAX_MANIFEST_PAYLOAD_BYTES + 1];
        assert!(matches!(
            ContentManifestV1::from_payload(&big),
            Err(SignedManifestError::TooLarge { .. })
        ));
    }

    fn seal(m: &ContentManifestV1, k: u8) -> SignedEnvelopeV1 {
        let sig =
            SignatureV1::new(key(k), SignatureAlg::EcdsaP384Sha384, fake_sig(&key(k))).unwrap();
        SignedEnvelopeV1::new(
            PayloadType::ContentManifestV1,
            m.to_payload().unwrap(),
            vec![sig],
        )
        .unwrap()
    }

    #[test]
    fn open_verifies_then_parses_then_checks_key() {
        let m = sample(CHUNK_SIZE * 2, 2);
        let v = FakeVerifier {
            trusted: vec![key(7), key(8)],
        };
        assert_eq!(ContentManifestV1::open(&seal(&m, 7), &v).unwrap(), m);
        // Signed by another trusted key than the one the manifest names.
        assert!(matches!(
            ContentManifestV1::open(&seal(&m, 8), &v),
            Err(SignedManifestError::KeyIdMismatch)
        ));
        // Untrusted signer: refused before parsing.
        let only8 = FakeVerifier {
            trusted: vec![key(8)],
        };
        assert!(matches!(
            ContentManifestV1::open(&seal(&m, 7), &only8),
            Err(SignedManifestError::Envelope(_))
        ));
    }
}
