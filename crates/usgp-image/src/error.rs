//! Why a WIM file was refused.
//!
//! Each [`WimError`] variant maps to exactly one stable reason code
//! ([`WimError::reason_code`]) that the API records as the content's
//! failure reason, and to fixed operator text
//! ([`WimError::operator_message`]). Neither ever contains bytes or text
//! from the file: only fixed words and numbers the check computed.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-11 (Error Handling) - fixed reason codes and operator
//   text; no file content is echoed.
// - SPEC: specs/os-images.md#REQ-IMG-022 (clear failure reasons)
// - SPEC: specs/os-images.md#REQ-IMG-037, #REQ-IMG-038
// - SPEC: specs/preinstall-env.md#REQ-PE-004

use std::fmt;
use std::io;

use crate::codec::CodecError;

/// Why a WIM file failed the check.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WimError {
    /// The file does not start with the WIM signature.
    NotWim,
    /// The file ends inside the header.
    TooShort,
    /// The header states a size other than the one this reader knows.
    HeaderSize {
        /// The `cbSize` value read.
        cb_size: u32,
    },
    /// A location or size the file declares lies outside the file.
    OutOfBounds {
        /// Which structure (fixed text).
        what: &'static str,
    },
    /// A structure is inconsistent with itself or with the header.
    Malformed {
        /// Which structure or rule (fixed text).
        what: &'static str,
    },
    /// A count or size exceeds a project limit ([`crate::WimLimits`]).
    LimitExceeded {
        /// Which limit (fixed text).
        what: &'static str,
    },
    /// The header declares no images.
    NoImages,
    /// The header, the XML and the lookup table disagree on the number of
    /// images.
    ImageCountMismatch {
        /// Images declared by the header.
        header: u32,
        /// `IMAGE` elements in the XML.
        xml: u32,
        /// Metadata entries in the lookup table.
        metadata: u32,
    },
    /// The XML data is not acceptable.
    XmlInvalid {
        /// Which rule failed (fixed text).
        reason: &'static str,
    },
    /// The XML data is larger than [`crate::WimLimits::max_xml_bytes`].
    XmlTooLarge,
    /// Two `IMAGE` elements carry the same `INDEX`.
    DuplicateIndex {
        /// The repeated index.
        index: u32,
    },
    /// The header's boot index names no image in the file.
    BadBootIndex {
        /// The boot index read.
        boot_index: u32,
    },
    /// An integrity table hash does not match the file.
    IntegrityMismatch {
        /// 0-based integrity chunk number.
        chunk: u64,
    },
    /// A metadata resource does not have the SHA-1 its lookup entry states.
    MetadataHashMismatch {
        /// Image index (1-based).
        index: u32,
    },
    /// The file is LZX-compressed (refused in M2, decision 0014).
    LzxNotSupported,
    /// The file uses a compression method no Microsoft source we read
    /// describes (LZMS, recovery `.esd`, or an undefined compression flag;
    /// decision 0014).
    CompressionNotSupported,
    /// The header carries flags this reader does not accept.
    HeaderFlagsNotSupported {
        /// The header flags.
        flags: u32,
    },
    /// A compressed resource holds a chunk whose stored size is not
    /// smaller than its expanded size; how such chunks are stored is
    /// OPEN-WIM-5, so they are refused.
    RawChunkNotSupported,
    /// The file is one part of a split (spanned) set.
    Spanned,
    /// The file holds only file resources.
    ResourceOnly,
    /// The file holds only metadata.
    MetadataOnly,
    /// Two resources (lookup entries, or a lookup entry and the lookup
    /// table, XML or integrity table) claim the same bytes of the file.
    ResourceOverlap,
    /// Two file (non-metadata) lookup entries carry the same hash. Two
    /// images with identical metadata are accepted (BOOT-011).
    DuplicateResource,
    /// The metadata entries, in lookup-table order, are not in increasing
    /// file-offset order, so which image each belongs to is not settled
    /// (OPEN-WIM-6). A serviced multi-image file may be written this way
    /// (BOOT-012); exporting each image to a new file is the remedy.
    MetadataOrderNotSupported,
    /// A compressed chunk could not be decoded.
    Decode(CodecError),
    /// Reading the file failed.
    Io(io::ErrorKind),
    /// The caller's progress hook asked the check to stop (watchdog or
    /// shutdown).
    Stalled,
    /// A PE file holds several images and names none as bootable
    /// (REQ-PE-004).
    PeNoUsableImage {
        /// Images in the file.
        image_count: u32,
    },
}

impl WimError {
    /// Every reason code, for tests and documentation.
    pub const REASON_CODES: &'static [&'static str] = &[
        "wim_not_wim",
        "wim_truncated",
        "wim_header_size",
        "wim_out_of_bounds",
        "wim_malformed",
        "wim_limit_exceeded",
        "wim_no_images",
        "wim_image_count_mismatch",
        "wim_xml_invalid",
        "wim_xml_too_large",
        "wim_duplicate_index",
        "wim_boot_index_invalid",
        "wim_integrity_mismatch",
        "wim_metadata_hash_mismatch",
        "wim_lzx_not_supported",
        "wim_compression_not_supported",
        "wim_header_flags_not_supported",
        "wim_raw_chunk_not_supported",
        "wim_split_not_supported",
        "wim_resource_only_not_supported",
        "wim_metadata_only_not_supported",
        "wim_resource_overlap",
        "wim_duplicate_resource",
        "wim_metadata_order_not_supported",
        "wim_decode_failed",
        "wim_read_error",
        "wim_check_stalled",
        "pe_no_usable_image",
    ];

    /// Stable machine-readable reason (REQ-IMG-022). One code per variant.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::NotWim => "wim_not_wim",
            Self::TooShort => "wim_truncated",
            Self::HeaderSize { .. } => "wim_header_size",
            Self::OutOfBounds { .. } => "wim_out_of_bounds",
            Self::Malformed { .. } => "wim_malformed",
            Self::LimitExceeded { .. } => "wim_limit_exceeded",
            Self::NoImages => "wim_no_images",
            Self::ImageCountMismatch { .. } => "wim_image_count_mismatch",
            Self::XmlInvalid { .. } => "wim_xml_invalid",
            Self::XmlTooLarge => "wim_xml_too_large",
            Self::DuplicateIndex { .. } => "wim_duplicate_index",
            Self::BadBootIndex { .. } => "wim_boot_index_invalid",
            Self::IntegrityMismatch { .. } => "wim_integrity_mismatch",
            Self::MetadataHashMismatch { .. } => "wim_metadata_hash_mismatch",
            Self::LzxNotSupported => "wim_lzx_not_supported",
            Self::CompressionNotSupported => "wim_compression_not_supported",
            Self::HeaderFlagsNotSupported { .. } => "wim_header_flags_not_supported",
            Self::RawChunkNotSupported => "wim_raw_chunk_not_supported",
            Self::Spanned => "wim_split_not_supported",
            Self::ResourceOnly => "wim_resource_only_not_supported",
            Self::MetadataOnly => "wim_metadata_only_not_supported",
            Self::ResourceOverlap => "wim_resource_overlap",
            Self::DuplicateResource => "wim_duplicate_resource",
            Self::MetadataOrderNotSupported => "wim_metadata_order_not_supported",
            Self::Decode(_) => "wim_decode_failed",
            Self::Io(_) => "wim_read_error",
            Self::Stalled => "wim_check_stalled",
            Self::PeNoUsableImage { .. } => "pe_no_usable_image",
        }
    }

    /// Operator-facing text: what failed, in terms the operator can act
    /// on. Fixed words and computed numbers only; never file content.
    #[must_use]
    pub fn operator_message(&self) -> String {
        match self {
            Self::NotWim => "not a WIM file (signature not found)".to_owned(),
            Self::TooShort => "file is damaged: it ends inside the WIM header".to_owned(),
            Self::HeaderSize { cb_size } => {
                format!("unsupported WIM header size {cb_size} (expected 208)")
            }
            Self::OutOfBounds { what } => {
                format!("file is damaged: the {what} lies outside the file")
            }
            Self::Malformed { what } => format!("file is damaged: invalid {what}"),
            Self::LimitExceeded { what } => format!("file exceeds the limit for {what}"),
            Self::NoImages => "file holds no images".to_owned(),
            Self::ImageCountMismatch {
                header,
                xml,
                metadata,
            } => format!(
                "file is damaged: image counts disagree (header {header}, \
                 XML {xml}, metadata {metadata})"
            ),
            Self::XmlInvalid { reason } => format!("image information is invalid: {reason}"),
            Self::XmlTooLarge => "image information is larger than the limit".to_owned(),
            Self::DuplicateIndex { index } => {
                format!("image information lists index {index} twice")
            }
            Self::BadBootIndex { boot_index } => {
                format!("boot index {boot_index} names no image in the file")
            }
            Self::IntegrityMismatch { chunk } => {
                format!("file is damaged: integrity check failed at chunk {chunk}")
            }
            Self::MetadataHashMismatch { index } => {
                format!("file is damaged: metadata of image {index} does not match its hash")
            }
            Self::LzxNotSupported => {
                "compression method not supported: LZX (use uncompressed or XPRESS)".to_owned()
            }
            Self::CompressionNotSupported => "compression method not supported: \
                 LZMS, recovery (.esd) or unknown (use uncompressed or XPRESS)"
                .to_owned(),
            Self::HeaderFlagsNotSupported { flags } => {
                format!("unsupported WIM header flags 0x{flags:08x}")
            }
            Self::RawChunkNotSupported => {
                "unsupported layout: a compressed resource holds an uncompressed chunk".to_owned()
            }
            Self::Spanned => "split WIM parts (.swm) are not supported".to_owned(),
            Self::ResourceOnly => "resource-only WIM files are not supported".to_owned(),
            Self::MetadataOnly => "metadata-only WIM files are not supported".to_owned(),
            Self::ResourceOverlap => {
                "file is damaged: two resources occupy the same bytes".to_owned()
            }
            Self::DuplicateResource => {
                "file is damaged: two file resources have the same hash".to_owned()
            }
            Self::MetadataOrderNotSupported => "unsupported layout: image metadata \
                 is not stored in lookup-table order (this can follow servicing \
                 a multi-image file); export each image to a new file and \
                 upload that file"
                .to_owned(),
            Self::Decode(e) => format!("file is damaged: compressed data invalid ({e})"),
            Self::Io(kind) => format!("file could not be read ({kind})"),
            Self::Stalled => "check stopped: no progress".to_owned(),
            Self::PeNoUsableImage { image_count } => format!(
                "preinstall environment holds {image_count} images and names none as bootable"
            ),
        }
    }
}

impl fmt::Display for WimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.operator_message())
    }
}

impl std::error::Error for WimError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(e) => Some(e),
            _ => None,
        }
    }
}

impl From<CodecError> for WimError {
    fn from(e: CodecError) -> Self {
        Self::Decode(e)
    }
}

impl From<io::Error> for WimError {
    fn from(e: io::Error) -> Self {
        Self::Io(e.kind())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_variant() -> Vec<WimError> {
        vec![
            WimError::NotWim,
            WimError::TooShort,
            WimError::HeaderSize { cb_size: 1 },
            WimError::OutOfBounds { what: "x" },
            WimError::Malformed { what: "x" },
            WimError::LimitExceeded { what: "x" },
            WimError::NoImages,
            WimError::ImageCountMismatch {
                header: 1,
                xml: 2,
                metadata: 3,
            },
            WimError::XmlInvalid { reason: "x" },
            WimError::XmlTooLarge,
            WimError::DuplicateIndex { index: 1 },
            WimError::BadBootIndex { boot_index: 2 },
            WimError::IntegrityMismatch { chunk: 0 },
            WimError::MetadataHashMismatch { index: 1 },
            WimError::LzxNotSupported,
            WimError::CompressionNotSupported,
            WimError::HeaderFlagsNotSupported { flags: 1 },
            WimError::RawChunkNotSupported,
            WimError::Spanned,
            WimError::ResourceOnly,
            WimError::MetadataOnly,
            WimError::ResourceOverlap,
            WimError::DuplicateResource,
            WimError::MetadataOrderNotSupported,
            WimError::Decode(CodecError::ShortOutput),
            WimError::Io(io::ErrorKind::UnexpectedEof),
            WimError::Stalled,
            WimError::PeNoUsableImage { image_count: 2 },
        ]
    }

    #[test]
    fn reason_codes_are_one_to_one() {
        let codes: Vec<_> = every_variant().iter().map(WimError::reason_code).collect();
        assert_eq!(codes, WimError::REASON_CODES);
        let mut seen = std::collections::HashSet::new();
        for c in &codes {
            assert!(seen.insert(*c), "duplicate {c}");
            assert!(
                c.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{c}"
            );
        }
    }

    #[test]
    fn metadata_order_message_states_the_remedy() {
        // BOOT-012: the operator is told what to do.
        let m = WimError::MetadataOrderNotSupported.operator_message();
        assert!(m.contains("export each image to a new file"), "{m}");
    }

    #[test]
    fn messages_are_non_empty() {
        for e in every_variant() {
            assert!(!e.operator_message().is_empty());
            assert_eq!(e.to_string(), e.operator_message());
        }
    }
}
