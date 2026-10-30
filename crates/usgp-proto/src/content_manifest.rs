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
use crate::limits::{
    CHUNK_SIZE, MAX_ARCHIVE_INFS, MAX_CONTENT_BYTES, MAX_IMAGES, MAX_MANIFEST_PAYLOAD_BYTES,
};
use crate::names::{DisplayName, EditionIndex, FileName, RelPath, WimText};
use crate::status::{ArchiveFormat, ContentKind, ContentKindV2, WimCompression};

/// Schema version of [`ContentManifestV1`].
pub const SCHEMA_V1: u32 = 1;

/// Schema version of [`ContentManifestV2`].
pub const SCHEMA_V2: u32 = 2;

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

/// The size and chunk rules common to v1 and v2.
fn check_chunks(
    size: u64,
    chunk_size: u64,
    chunk_sha256: &[Sha256Digest],
) -> Result<(), SignedManifestError> {
    use SignedManifestError::Invalid;
    if size == 0 || size > MAX_CONTENT_BYTES {
        return Err(Invalid("size must be 1 byte to 1 TiB"));
    }
    if chunk_size != CHUNK_SIZE {
        return Err(Invalid("chunk_size must be 8388608"));
    }
    let n = u64::try_from(chunk_sha256.len())
        .map_err(|_| Invalid("chunk_sha256 count does not match size"))?;
    if n != chunk_count(size) {
        return Err(Invalid("chunk_sha256 count does not match size"));
    }
    Ok(())
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
        check_chunks(self.size, self.chunk_size, &self.chunk_sha256)?;
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

// ---------------------------------------------------------------------------
// Content manifest, version 2 (M4 plan WU-4a)
// ---------------------------------------------------------------------------
//
// Driver archives and agent packages are ZIP or CAB files, not WIMs, so
// they cannot meet v1's WIM summary. v2 keeps every v1 field except `wim`,
// which becomes `archive`, and has its own payload type: an archive
// manifest never verifies where an image manifest is expected, and v1
// verifiers stay as strict as before. Images and PE kits keep v1.
//
// ```json
// {"schema":2,"kind":"driver_archive","content_id":"…","display_name":"…",
//  "file_name":"…","size":…,"sha256":"…","chunk_size":8388608,
//  "chunk_sha256":["…",…],
//  "archive":{"format":"zip","entries":12,"expanded_bytes":…,
//             "infs":["net/e1d.inf",…]},
//  "ready_at":…,"key_id":"…"}
// ```

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7, SI-7(1), SI-7(6) - signed per-chunk and whole-file
//   digests of driver archives and agent packages; payload type keeps
//   archive and image manifests apart (decision 0011).
// - NIST 800-53: SI-10 (Information Input Validation) - schema, kind,
//   size, chunk count, entry count and INF list validated on every parse.
// - SPEC: specs/drivers.md#REQ-DRV-006 (INF list)
// - SPEC: specs/agent-handoff.md#REQ-AGT-001 (agent package)
// - SPEC: specs/os-images.md#REQ-IMG-050, #REQ-IMG-052
// - FIPS 180-4 (SHA-256)

/// The checked archive structure (from `usgp-wincfg`'s archive report).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveSummaryV1 {
    /// ZIP or CAB.
    pub format: ArchiveFormat,
    /// Number of entries in the archive (at least 1).
    pub entries: u32,
    /// Total expanded size of the entries, in bytes.
    pub expanded_bytes: u64,
    /// INF packages (relative paths ending in `.inf`): 1 to
    /// [`MAX_ARCHIVE_INFS`] for a driver archive, none for an agent
    /// package.
    pub infs: Vec<RelPath>,
}

/// Content manifest, version 2: a driver archive or agent package.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentManifestV2 {
    /// Always [`SCHEMA_V2`].
    pub schema: u32,
    /// Driver archive or agent package.
    pub kind: ContentKindV2,
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
    /// Chunk size; always [`CHUNK_SIZE`].
    pub chunk_size: u64,
    /// SHA-256 of each chunk in order; the last chunk may be short.
    pub chunk_sha256: Vec<Sha256Digest>,
    /// Archive structure.
    pub archive: ArchiveSummaryV1,
    /// When the content became Ready.
    pub ready_at: UnixMicros,
    /// Key id (SHA-256 of the SPKI DER) of the content signing key.
    pub key_id: Sha256Digest,
}

impl ContentManifestV2 {
    /// Checks every rule a v2 content manifest must meet.
    ///
    /// # Errors
    ///
    /// [`SignedManifestError::UnsupportedSchema`] or
    /// [`SignedManifestError::Invalid`] naming the first rule broken.
    pub fn validate(&self) -> Result<(), SignedManifestError> {
        use SignedManifestError::Invalid;
        if self.schema != SCHEMA_V2 {
            return Err(SignedManifestError::UnsupportedSchema(self.schema));
        }
        check_chunks(self.size, self.chunk_size, &self.chunk_sha256)?;
        let a = &self.archive;
        if a.entries == 0 {
            return Err(Invalid("archive.entries must be at least 1"));
        }
        match self.kind {
            ContentKindV2::DriverArchive => {
                if a.infs.is_empty() || a.infs.len() > MAX_ARCHIVE_INFS {
                    return Err(Invalid("archive.infs must list 1 to 4096 INF paths"));
                }
            }
            ContentKindV2::AgentPackage => {
                if !a.infs.is_empty() {
                    return Err(Invalid("archive.infs must be empty for an agent package"));
                }
            }
        }
        if !a.infs.iter().all(|p| p.has_extension(".inf")) {
            return Err(Invalid("archive.infs entries must end in .inf"));
        }
        for (i, p) in a.infs.iter().enumerate() {
            if a.infs.iter().take(i).any(|o| o.as_str() == p.as_str()) {
                return Err(Invalid("archive.infs must not list a path twice"));
            }
        }
        let listed = u32::try_from(a.infs.len())
            .map_err(|_| Invalid("archive.infs lists more paths than archive.entries"))?;
        if listed > a.entries {
            return Err(Invalid(
                "archive.infs lists more paths than archive.entries",
            ));
        }
        Ok(())
    }

    /// The exact bytes to sign and store: compact JSON in field order.
    ///
    /// # Errors
    ///
    /// As [`ContentManifestV2::validate`]; [`SignedManifestError::TooLarge`]
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
    /// store for display; [`ContentManifestV2::open`] does both steps.
    ///
    /// # Errors
    ///
    /// [`SignedManifestError::TooLarge`] before parsing;
    /// [`SignedManifestError::Json`]; or as
    /// [`ContentManifestV2::validate`].
    pub fn from_payload(bytes: &[u8]) -> Result<Self, SignedManifestError> {
        if bytes.len() > MAX_MANIFEST_PAYLOAD_BYTES {
            return Err(SignedManifestError::TooLarge { len: bytes.len() });
        }
        let m: Self = serde_json::from_slice(bytes).map_err(SignedManifestError::Json)?;
        m.validate()?;
        Ok(m)
    }

    /// Verifies the envelope (payload type `content-manifest.v2` and a
    /// trusted signature), then parses and validates the payload, then
    /// checks that the manifest's `key_id` is the key that verified it.
    ///
    /// # Errors
    ///
    /// [`SignedManifestError::Envelope`] if verification fails (nothing
    /// is parsed); otherwise as [`ContentManifestV2::from_payload`], or
    /// [`SignedManifestError::KeyIdMismatch`].
    pub fn open(
        envelope: &SignedEnvelopeV1,
        verifier: &dyn SignatureVerifier,
    ) -> Result<Self, SignedManifestError> {
        let verified = envelope.verified_payload(PayloadType::ContentManifestV2, verifier)?;
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

    pub(crate) fn sample_v2(size: u64, kind: ContentKindV2) -> ContentManifestV2 {
        let n = usize::try_from(chunk_count(size)).unwrap();
        let infs = match kind {
            ContentKindV2::DriverArchive => vec![
                RelPath::new("net/e1d.inf").unwrap(),
                RelPath::new("storage/iastor.INF").unwrap(),
            ],
            ContentKindV2::AgentPackage => Vec::new(),
        };
        ContentManifestV2 {
            schema: 2,
            kind,
            content_id: ContentId::parse("1b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f").unwrap(),
            display_name: DisplayName::new("NIC drivers").unwrap(),
            file_name: FileName::new("drivers.zip").unwrap(),
            size,
            sha256: Sha256Digest([0xaa; 32]),
            chunk_size: CHUNK_SIZE,
            chunk_sha256: vec![Sha256Digest([0xbb; 32]); n],
            archive: ArchiveSummaryV1 {
                format: ArchiveFormat::Zip,
                entries: 6,
                expanded_bytes: 4096,
                infs,
            },
            ready_at: UnixMicros::new(1_793_000_000_000_000).unwrap(),
            key_id: key(7),
        }
    }

    #[test]
    fn v2_golden_payload() {
        let m = sample_v2(5, ContentKindV2::DriverArchive);
        let p = String::from_utf8(m.to_payload().unwrap()).unwrap();
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let k = "07".repeat(32);
        let want = format!(
            "{{\"schema\":2,\"kind\":\"driver_archive\",\"content_id\":\"1b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f\",\
             \"display_name\":\"NIC drivers\",\"file_name\":\"drivers.zip\",\"size\":5,\
             \"sha256\":\"{a}\",\"chunk_size\":8388608,\"chunk_sha256\":[\"{b}\"],\
             \"archive\":{{\"format\":\"zip\",\"entries\":6,\"expanded_bytes\":4096,\
             \"infs\":[\"net/e1d.inf\",\"storage/iastor.INF\"]}},\
             \"ready_at\":1793000000000000,\"key_id\":\"{k}\"}}"
        );
        assert_eq!(p, want);
        assert_eq!(ContentManifestV2::from_payload(p.as_bytes()).unwrap(), m);
        let ag = sample_v2(CHUNK_SIZE + 1, ContentKindV2::AgentPackage);
        let p = ag.to_payload().unwrap();
        assert_eq!(ContentManifestV2::from_payload(&p).unwrap(), ag);
    }

    type MutateV2 = Box<dyn Fn(&mut ContentManifestV2)>;

    #[test]
    fn v2_validation_rules() {
        let ok = sample_v2(3 * CHUNK_SIZE, ContentKindV2::DriverArchive);
        assert!(ok.validate().is_ok());
        let cases: Vec<(&str, MutateV2)> = vec![
            ("schema 1", Box::new(|m| m.schema = 1)),
            ("size 0", Box::new(|m| m.size = 0)),
            ("size max", Box::new(|m| m.size = MAX_CONTENT_BYTES + 1)),
            ("chunk size", Box::new(|m| m.chunk_size = 4096)),
            ("chunk count", Box::new(|m| m.chunk_sha256.truncate(2))),
            ("no entries", Box::new(|m| m.archive.entries = 0)),
            ("no infs", Box::new(|m| m.archive.infs.clear())),
            (
                "too many infs",
                Box::new(|m| {
                    m.archive.entries = u32::MAX;
                    m.archive.infs = vec![RelPath::new("a.inf").unwrap(); MAX_ARCHIVE_INFS + 1];
                }),
            ),
            (
                "not inf",
                Box::new(|m| m.archive.infs.push(RelPath::new("a.sys").unwrap())),
            ),
            ("infs over entries", Box::new(|m| m.archive.entries = 1)),
            (
                "duplicate inf",
                Box::new(|m| {
                    m.archive.infs.push(RelPath::new("net/e1d.inf").unwrap());
                }),
            ),
            (
                "agent with infs",
                Box::new(|m| m.kind = ContentKindV2::AgentPackage),
            ),
        ];
        for (name, f) in cases {
            let mut m = ok.clone();
            f(&mut m);
            assert!(m.validate().is_err(), "{name}");
            assert!(m.to_payload().is_err(), "{name}");
        }
        let mut m = ok.clone();
        m.archive.infs = (0..MAX_ARCHIVE_INFS)
            .map(|i| RelPath::new(format!("d/{i}.inf")).unwrap())
            .collect();
        m.archive.entries = 5000;
        assert!(m.validate().is_ok());
        // Byte-exact: paths differing only in case are distinct.
        let mut m = ok.clone();
        m.archive.infs = vec![
            RelPath::new("a.inf").unwrap(),
            RelPath::new("A.inf").unwrap(),
        ];
        assert!(m.validate().is_ok());
        assert!(matches!(
            {
                let mut m = ok.clone();
                m.schema = 3;
                m.validate()
            },
            Err(SignedManifestError::UnsupportedSchema(3))
        ));
        assert_eq!(ok.chunk(2).map(|(l, _)| l), Some(CHUNK_SIZE));
        assert!(ok.chunk(3).is_none());
    }

    #[test]
    fn v2_strict_parse() {
        let p = String::from_utf8(
            sample_v2(5, ContentKindV2::DriverArchive)
                .to_payload()
                .unwrap(),
        )
        .unwrap();
        for bad in [
            p.replacen("{\"schema\":2,", "{\"schema\":2,\"x\":0,", 1),
            p.replace("\"zip\"", "\"tar\""),
            p.replace("\"driver_archive\"", "\"image\""),
            p.replace("net/e1d.inf", "../e1d.inf"),
            p.replacen("\"archive\":{", "\"archive\":{\"y\":1,", 1),
            p.replace("\"archive\"", "\"wim\""),
            format!("{p}x"),
        ] {
            assert!(
                ContentManifestV2::from_payload(bad.as_bytes()).is_err(),
                "{bad}"
            );
        }
        // A v1 payload is not a v2 manifest, and the reverse.
        let v1 = sample(5, 1).to_payload().unwrap();
        assert!(ContentManifestV2::from_payload(&v1).is_err());
        assert!(ContentManifestV1::from_payload(p.as_bytes()).is_err());
        let big = vec![b' '; MAX_MANIFEST_PAYLOAD_BYTES + 1];
        assert!(matches!(
            ContentManifestV2::from_payload(&big),
            Err(SignedManifestError::TooLarge { .. })
        ));
    }

    fn seal_v2(m: &ContentManifestV2, ty: PayloadType, k: u8) -> SignedEnvelopeV1 {
        let sig =
            SignatureV1::new(key(k), SignatureAlg::EcdsaP384Sha384, fake_sig(&key(k))).unwrap();
        SignedEnvelopeV1::new(ty, m.to_payload().unwrap(), vec![sig]).unwrap()
    }

    #[test]
    fn v2_open_is_domain_separated() {
        let m = sample_v2(CHUNK_SIZE * 2, ContentKindV2::AgentPackage);
        let v = FakeVerifier {
            trusted: vec![key(7), key(8)],
        };
        let env = seal_v2(&m, PayloadType::ContentManifestV2, 7);
        assert_eq!(ContentManifestV2::open(&env, &v).unwrap(), m);
        // Not accepted where a v1 (image) manifest is expected.
        assert!(matches!(
            ContentManifestV1::open(&env, &v),
            Err(SignedManifestError::Envelope(_))
        ));
        // A v2 payload signed under the v1 type is refused by v2.
        let wrong = seal_v2(&m, PayloadType::ContentManifestV1, 7);
        assert!(matches!(
            ContentManifestV2::open(&wrong, &v),
            Err(SignedManifestError::Envelope(_))
        ));
        assert!(matches!(
            ContentManifestV2::open(&seal_v2(&m, PayloadType::ContentManifestV2, 8), &v),
            Err(SignedManifestError::KeyIdMismatch)
        ));
    }

    #[test]
    fn schema_error_text_names_no_version() {
        let e = SignedManifestError::UnsupportedSchema(2).to_string();
        assert_eq!(e, "manifest schema 2 is not supported");
    }
}
