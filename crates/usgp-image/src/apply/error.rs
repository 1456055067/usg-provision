//! Why an image could not be applied (or verified for apply).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-11 (Error Handling) - one stable reason code per
//   refusal; fixed text and numbers only, never image content.
// - SPEC: specs/os-images.md#REQ-IMG-022 (named reasons)
// - SPEC: specs/progress.md (persistent, named job failures)

use std::fmt;

use super::sink::SinkError;
use crate::error::WimError;
use crate::wim::metadata::MetadataError;
use crate::wim::remote::ChunkReadError;
use crate::wim::reparse::ReparseError;

/// Why an apply or verify pass failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApplyError {
    /// The WIM file itself was refused (same reasons as the upload check).
    Wim(WimError),
    /// The chosen image's metadata was refused.
    Metadata(MetadataError),
    /// The requested image index is not in the file.
    ImageIndex {
        /// The index asked for.
        index: u32,
        /// Images in the file.
        image_count: u32,
    },
    /// The image holds an EFS-encrypted entry (decision 0006, OBS-040).
    EncryptedNotSupported,
    /// A link or junction is outside the decision 0022 rule (M-13).
    Reparse(ReparseError),
    /// An entry names content the lookup table does not hold (M-08).
    ResourceMissing,
    /// A compressed resource's original size is exactly 2^32, where the
    /// chunk-table width is not determined (OPEN-WIM-10, M-22).
    ChunkTableWidthNotSupported,
    /// A decoded resource does not have its lookup entry's SHA-1.
    ResourceHashMismatch,
    /// A size or count exceeds [`super::ApplyLimits`].
    LimitExceeded {
        /// Which limit (fixed text).
        what: &'static str,
    },
    /// A content chunk failed its SHA-256 check (SI-7).
    ContentIntegrity {
        /// 0-based content chunk number.
        chunk: u64,
    },
    /// A content chunk could not be obtained, had the wrong length, or
    /// has no reference digest.
    ContentUnavailable {
        /// 0-based content chunk number.
        chunk: u64,
    },
    /// The target refused an operation.
    Sink(SinkError),
}

impl ApplyError {
    /// The reason codes of this type's own variants. [`ApplyError::Wim`],
    /// [`ApplyError::Metadata`] and [`ApplyError::Reparse`] use
    /// [`WimError::REASON_CODES`], [`MetadataError::REASON_CODES`] and
    /// [`ReparseError::REASON_CODES`].
    pub const REASON_CODES: &'static [&'static str] = &[
        "wim_image_index_invalid",
        "wim_efs_not_supported",
        "wim_resource_missing",
        "wim_chunk_table_width_not_supported",
        "wim_resource_hash_mismatch",
        "apply_limit_exceeded",
        "content_integrity_failed",
        "content_unavailable",
        "apply_target_failed",
    ];

    /// Stable machine-readable reason.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Wim(e) => e.reason_code(),
            Self::Metadata(e) => e.reason_code(),
            Self::ImageIndex { .. } => "wim_image_index_invalid",
            Self::EncryptedNotSupported => "wim_efs_not_supported",
            Self::Reparse(e) => e.reason_code(),
            Self::ResourceMissing => "wim_resource_missing",
            Self::ChunkTableWidthNotSupported => "wim_chunk_table_width_not_supported",
            Self::ResourceHashMismatch => "wim_resource_hash_mismatch",
            Self::LimitExceeded { .. } => "apply_limit_exceeded",
            Self::ContentIntegrity { .. } => "content_integrity_failed",
            Self::ContentUnavailable { .. } => "content_unavailable",
            Self::Sink(_) => "apply_target_failed",
        }
    }

    /// Operator text: fixed words and computed numbers only.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::Wim(e) => e.operator_message(),
            Self::Metadata(e) => e.operator_message(),
            Self::ImageIndex { index, image_count } => {
                format!("image index {index} is not in the file ({image_count} images)")
            }
            Self::EncryptedNotSupported => {
                "image holds an encrypted (EFS) file, which is not supported".to_owned()
            }
            Self::Reparse(e) => e.to_string(),
            Self::ResourceMissing => {
                "image is damaged: a file names content the image does not hold".to_owned()
            }
            Self::ChunkTableWidthNotSupported => "image holds a compressed file of exactly \
                 4 GiB, whose layout is not determined"
                .to_owned(),
            Self::ResourceHashMismatch => {
                "image is damaged: file content does not match its hash".to_owned()
            }
            Self::LimitExceeded { what } => format!("image exceeds the limit for {what}"),
            Self::ContentIntegrity { chunk } => {
                format!("content chunk {chunk} failed its integrity check")
            }
            Self::ContentUnavailable { chunk } => {
                format!("content chunk {chunk} could not be obtained")
            }
            Self::Sink(e) => format!("writing to the target failed: {e}"),
        }
    }

    pub(crate) fn from_chunk(e: ChunkReadError) -> Self {
        match e {
            ChunkReadError::Integrity { chunk } => Self::ContentIntegrity { chunk },
            ChunkReadError::Length { chunk }
            | ChunkReadError::NoDigest { chunk }
            | ChunkReadError::Fetch { chunk, .. } => Self::ContentUnavailable { chunk },
        }
    }
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.operator_message())
    }
}

impl std::error::Error for ApplyError {}

impl From<WimError> for ApplyError {
    fn from(e: WimError) -> Self {
        Self::Wim(e)
    }
}

impl From<MetadataError> for ApplyError {
    fn from(e: MetadataError) -> Self {
        Self::Metadata(e)
    }
}

impl From<SinkError> for ApplyError {
    fn from(e: SinkError) -> Self {
        Self::Sink(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_codes_are_one_to_one() {
        let own = [
            ApplyError::ImageIndex {
                index: 2,
                image_count: 1,
            },
            ApplyError::EncryptedNotSupported,
            ApplyError::ResourceMissing,
            ApplyError::ChunkTableWidthNotSupported,
            ApplyError::ResourceHashMismatch,
            ApplyError::LimitExceeded { what: "x" },
            ApplyError::ContentIntegrity { chunk: 1 },
            ApplyError::ContentUnavailable { chunk: 1 },
            ApplyError::Sink(SinkError::new(
                super::super::sink::SinkOp::Write,
                std::io::ErrorKind::Other,
            )),
        ];
        let codes: Vec<_> = own.iter().map(ApplyError::reason_code).collect();
        assert_eq!(codes, ApplyError::REASON_CODES);
        for e in &own {
            assert!(!e.operator_message().is_empty());
        }
        // No overlap with the delegated code sets.
        for c in ApplyError::REASON_CODES {
            assert!(!WimError::REASON_CODES.contains(c), "{c}");
            assert!(!MetadataError::REASON_CODES.contains(c), "{c}");
            assert!(!ReparseError::REASON_CODES.contains(c), "{c}");
        }
    }
}
