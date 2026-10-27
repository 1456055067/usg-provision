//! The WIM header (`wim.md` §2) and the header-flag decision: which files
//! M2 accepts and which it refuses before reading anything else
//! (decision 0014).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - fixed-size header,
//   every field checked before use.
// - SPEC: specs/os-images.md#REQ-IMG-037 (signature and header),
//   #REQ-IMG-038 (refused variants, named)
// - SPEC: specs/standards/wim.md §2, §10
// - DECISION: docs/decisions/0014-m2-wim-compression-scope.md

use super::reshdr::{RESHDR_LEN, ResourceHeader, le_u16, le_u32};
use crate::error::WimError;

/// Header size in bytes.
// FORMAT: OBS-001 - cbSize is 208 and data follows at offset 208 in every
// R1 file; wim.md §2 [derived] 208 confirmed.
pub const HEADER_LEN: usize = 208;

/// [`HEADER_LEN`] as a file offset.
pub const HEADER_LEN_U64: u64 = 208;

/// The signature: ASCII `MSWIM` and three zero bytes.
// FORMAT: OBS-001 - bytes 4d 53 57 49 4d 00 00 00 in all R1 files.
pub const MAGIC: [u8; 8] = *b"MSWIM\0\0\0";

/// `FLAG_HEADER_RESERVED`.
pub const FLAG_RESERVED: u32 = 0x0000_0001;
/// `FLAG_HEADER_COMPRESSION`.
pub const FLAG_COMPRESSION: u32 = 0x0000_0002;
/// `FLAG_HEADER_READONLY`.
pub const FLAG_READONLY: u32 = 0x0000_0004;
/// `FLAG_HEADER_SPANNED`.
pub const FLAG_SPANNED: u32 = 0x0000_0008;
/// `FLAG_HEADER_RESOURCE_ONLY`.
pub const FLAG_RESOURCE_ONLY: u32 = 0x0000_0010;
/// `FLAG_HEADER_METADATA_ONLY`.
pub const FLAG_METADATA_ONLY: u32 = 0x0000_0020;
/// `FLAG_HEADER_WRITE_IN_PROGRESS`.
pub const FLAG_WRITE_IN_PROGRESS: u32 = 0x0000_0040;
/// `FLAG_HEADER_RP_FIX`.
// FORMAT: OBS-005 - set in every R1 file; a reader must accept it.
pub const FLAG_RP_FIX: u32 = 0x0000_0080;
/// `FLAG_HEADER_COMPRESS_RESERVED`.
pub const FLAG_COMPRESS_RESERVED: u32 = 0x0001_0000;
/// `FLAG_HEADER_COMPRESS_XPRESS`.
// FORMAT: OBS-005 - `/Compress:fast` writes 0x00020082.
pub const FLAG_COMPRESS_XPRESS: u32 = 0x0002_0000;
/// `FLAG_HEADER_COMPRESS_LZX`.
// FORMAT: OBS-005 - `/Compress:max` writes 0x00040082.
pub const FLAG_COMPRESS_LZX: u32 = 0x0004_0000;

/// The compression-type bits (wim.md §2: valid only with 0x2 set).
const COMPRESS_TYPE_BITS: u32 = FLAG_COMPRESS_RESERVED | FLAG_COMPRESS_XPRESS | FLAG_COMPRESS_LZX;

/// Header flags this reader accepts on an otherwise acceptable file.
const ACCEPTED_FLAGS: u32 = FLAG_COMPRESSION | FLAG_READONLY | FLAG_RP_FIX | FLAG_COMPRESS_XPRESS;

/// Chunk size of compressed file resources (`wim.md` §4).
// FORMAT: wim.md §4 (32 KB chunks, formula uses 32768); OBS-011, OBS-012.
pub const CHUNK_SIZE: u32 = 32768;

/// The header field at offset 20 in an XPRESS file.
// FORMAT: OBS-004 - 32768 in every R1 XPRESS and LZX file, 0 when
// uncompressed; that it is the chunk size is a reading (OPEN-WIM-3).
pub const XPRESS_FIELD_20: u32 = CHUNK_SIZE;

/// Compression of a file M2 accepts (decision 0014).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Compression {
    /// No compressed resources.
    None,
    /// XPRESS ([MS-XCA] LZ77+Huffman) resources, chosen per resource by
    /// the resource's compressed flag.
    Xpress,
}

impl Compression {
    /// Stable text (`none`, `xpress`), equal to the wire values of
    /// `usgp_proto::WimCompression`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Xpress => "xpress",
        }
    }
}

/// The parsed header. Fields are as read; [`check_header`] decides
/// whether the file is acceptable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WimHeader {
    /// `cbSize`.
    pub cb_size: u32,
    /// `dwVersion` (recorded, never a reason to refuse on its own).
    pub version: u32,
    /// `dwFlags`.
    pub flags: u32,
    /// The field at offset 20 (OPEN-WIM-3, OBS-004).
    pub field_20: u32,
    /// `gWIMGuid`.
    pub guid: [u8; 16],
    /// `usPartNumber`.
    pub part_number: u16,
    /// `usTotalParts`.
    pub total_parts: u16,
    /// `dwImageCount`.
    pub image_count: u32,
    /// `rhOffsetTable`: the lookup table.
    pub lookup: ResourceHeader,
    /// `rhXmlData`.
    pub xml: ResourceHeader,
    /// `rhBootMetadata`.
    pub boot_metadata: ResourceHeader,
    /// `dwBootIndex` (0 = none).
    pub boot_index: u32,
    /// `rhIntegrity` (all zero when absent).
    pub integrity: ResourceHeader,
}

/// Offsets of the header fields (`wim.md` §2 [derived]; OBS-001, OBS-002,
/// OBS-007 confirm 8, 12, 16, 20, 40, 42, 44, 48, 72, 124).
mod off {
    pub const CB_SIZE: usize = 8;
    pub const VERSION: usize = 12;
    pub const FLAGS: usize = 16;
    pub const FIELD_20: usize = 20;
    pub const GUID: usize = 24;
    pub const PART: usize = 40;
    pub const TOTAL: usize = 42;
    pub const IMAGES: usize = 44;
    pub const LOOKUP: usize = 48;
    pub const XML: usize = 72;
    pub const BOOT_META: usize = 96;
    pub const BOOT_INDEX: usize = 120;
    pub const INTEGRITY: usize = 124;
}

fn reshdr_at(b: &[u8], at: usize) -> Result<ResourceHeader, WimError> {
    let end = at.checked_add(RESHDR_LEN).ok_or(WimError::TooShort)?;
    b.get(at..end)
        .and_then(ResourceHeader::parse)
        .ok_or(WimError::TooShort)
}

/// Parses the header from the first bytes of a file.
///
/// Checks only the signature and the header size; the flag and value
/// rules are in [`check_header`].
///
/// # Errors
///
/// - [`WimError::TooShort`] if fewer than 8 bytes, or fewer than
///   [`HEADER_LEN`] bytes after a valid signature;
/// - [`WimError::NotWim`] if the signature does not match;
/// - [`WimError::HeaderSize`] if `cbSize` is not 208.
pub fn parse_header(b: &[u8]) -> Result<WimHeader, WimError> {
    let magic = b.get(..MAGIC.len()).ok_or(WimError::TooShort)?;
    if magic != MAGIC {
        return Err(WimError::NotWim);
    }
    let b = b.get(..HEADER_LEN).ok_or(WimError::TooShort)?;
    let u32_at = |at| le_u32(b, at).ok_or(WimError::TooShort);
    let u16_at = |at| le_u16(b, at).ok_or(WimError::TooShort);
    let cb_size = u32_at(off::CB_SIZE)?;
    // Fail closed: a larger header would carry fields we do not know, and
    // the integrity range starts at the end of the header (OBS-015).
    // DECISION: 0017 (Accepted) - cbSize other than 208 is refused.
    if usize::try_from(cb_size).ok() != Some(HEADER_LEN) {
        return Err(WimError::HeaderSize { cb_size });
    }
    let guid_end = off::GUID.checked_add(16).ok_or(WimError::TooShort)?;
    let guid: [u8; 16] = b
        .get(off::GUID..guid_end)
        .and_then(|s| s.try_into().ok())
        .ok_or(WimError::TooShort)?;
    Ok(WimHeader {
        cb_size,
        version: u32_at(off::VERSION)?,
        flags: u32_at(off::FLAGS)?,
        field_20: u32_at(off::FIELD_20)?,
        guid,
        part_number: u16_at(off::PART)?,
        total_parts: u16_at(off::TOTAL)?,
        image_count: u32_at(off::IMAGES)?,
        lookup: reshdr_at(b, off::LOOKUP)?,
        xml: reshdr_at(b, off::XML)?,
        boot_metadata: reshdr_at(b, off::BOOT_META)?,
        boot_index: u32_at(off::BOOT_INDEX)?,
        integrity: reshdr_at(b, off::INTEGRITY)?,
    })
}

/// Decides from the header flags and part fields alone whether the file
/// is a variant M2 accepts, and with which compression. Runs before any
/// lookup entry is read.
///
/// Order: part fields, split, resource-only, metadata-only, compression,
/// other flags.
///
/// # Errors
///
/// [`WimError::Malformed`] for impossible part fields,
/// [`WimError::Spanned`], [`WimError::ResourceOnly`],
/// [`WimError::MetadataOnly`], [`WimError::LzxNotSupported`],
/// [`WimError::CompressionNotSupported`] or
/// [`WimError::HeaderFlagsNotSupported`].
pub fn classify_flags(h: &WimHeader) -> Result<Compression, WimError> {
    let flags = h.flags;
    // BOOT-010: no part 0, no total of 0, no part beyond the total. Such a
    // file is no part of any set, so it is damaged, not split.
    if h.total_parts == 0 || h.part_number == 0 || h.part_number > h.total_parts {
        return Err(WimError::Malformed {
            what: "part fields",
        });
    }
    // FORMAT: OBS-017 - a split part is marked by header flag 0x08 and a
    // total part count above 1 (resource flag 0x08 is never set); OBS-016
    // part number and total at 40 and 42. Fail closed: either sign alone,
    // or a valid part number other than 1, is also refused as split.
    if flags & FLAG_SPANNED != 0 || h.total_parts != 1 || h.part_number != 1 {
        return Err(WimError::Spanned);
    }
    if flags & FLAG_RESOURCE_ONLY != 0 {
        return Err(WimError::ResourceOnly);
    }
    if flags & FLAG_METADATA_ONLY != 0 {
        return Err(WimError::MetadataOnly);
    }
    let compression = if flags & FLAG_COMPRESSION != 0 {
        // wim.md §2: compressed but no defined compression flag, or an
        // undefined one, is a method the paper does not describe.
        // FORMAT: OBS-006 - the recovery (.esd) output sets 0x00080000
        // with no defined compression flag; refused here, before any
        // lookup entry is used.
        let compress_bits = flags & 0xffff_0000;
        if compress_bits == FLAG_COMPRESS_LZX {
            return Err(WimError::LzxNotSupported);
        }
        if compress_bits != FLAG_COMPRESS_XPRESS {
            return Err(WimError::CompressionNotSupported);
        }
        Compression::Xpress
    } else {
        // wim.md §2: the compression types are valid only with 0x2 set.
        if flags & COMPRESS_TYPE_BITS != 0 {
            return Err(WimError::HeaderFlagsNotSupported { flags });
        }
        Compression::None
    };
    // Anything left: reserved 0x01, write-in-progress 0x40 (another writer
    // may be changing the file), or undefined low bits. Fail closed.
    if flags & !ACCEPTED_FLAGS != 0 {
        return Err(WimError::HeaderFlagsNotSupported { flags });
    }
    Ok(compression)
}

/// Checks the header values that do not need the rest of the file:
/// flags ([`classify_flags`]), the offset-20 field for XPRESS, the image
/// count against `max_images`, and the boot index.
///
/// The version field is recorded but never a reason to refuse on its own
/// (OBS-003: OPEN-WIM-2 stays open).
///
/// # Errors
///
/// As [`classify_flags`], plus [`WimError::Malformed`] for the offset-20
/// field, [`WimError::NoImages`], [`WimError::LimitExceeded`] and
/// [`WimError::BadBootIndex`].
pub fn check_header(h: &WimHeader, max_images: u32) -> Result<Compression, WimError> {
    let compression = classify_flags(h)?;
    if compression == Compression::Xpress && h.field_20 != XPRESS_FIELD_20 {
        // Fail closed: every chunk computation assumes 32768-byte chunks.
        // DECISION: 0017 (Accepted) - an XPRESS file whose offset-20 value
        // is not 32768 is refused.
        return Err(WimError::Malformed {
            what: "chunk size field",
        });
    }
    if h.image_count == 0 {
        return Err(WimError::NoImages);
    }
    if h.image_count > max_images {
        return Err(WimError::LimitExceeded { what: "images" });
    }
    if h.boot_index > h.image_count {
        return Err(WimError::BadBootIndex {
            boot_index: h.boot_index,
        });
    }
    Ok(compression)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(flags: u32) -> WimHeader {
        WimHeader {
            cb_size: 208,
            version: 0x0001_0d00,
            flags,
            field_20: if flags & FLAG_COMPRESSION != 0 {
                32768
            } else {
                0
            },
            guid: [0; 16],
            part_number: 1,
            total_parts: 1,
            image_count: 1,
            lookup: ResourceHeader::default(),
            xml: ResourceHeader::default(),
            boot_metadata: ResourceHeader::default(),
            boot_index: 0,
            integrity: ResourceHeader::default(),
        }
    }

    #[test]
    fn dism_flag_values() {
        // OBS-005 / OBS-006 / OBS-017 values.
        assert_eq!(classify_flags(&header(0x80)), Ok(Compression::None));
        assert_eq!(
            classify_flags(&header(0x0002_0082)),
            Ok(Compression::Xpress)
        );
        assert_eq!(
            classify_flags(&header(0x0004_0082)),
            Err(WimError::LzxNotSupported)
        );
        assert_eq!(
            classify_flags(&header(0x0008_0082)),
            Err(WimError::CompressionNotSupported)
        );
        let mut split = header(0x0002_008a);
        split.total_parts = 7;
        assert_eq!(classify_flags(&split), Err(WimError::Spanned));
    }

    #[test]
    fn other_flags() {
        assert_eq!(classify_flags(&header(0)), Ok(Compression::None));
        assert_eq!(classify_flags(&header(0x04)), Ok(Compression::None));
        assert_eq!(classify_flags(&header(0x10)), Err(WimError::ResourceOnly));
        assert_eq!(classify_flags(&header(0x20)), Err(WimError::MetadataOnly));
        for f in [0x01, 0x40, 0x100, 0x0002_0000, 0x8000_0000] {
            assert_eq!(
                classify_flags(&header(f)),
                Err(WimError::HeaderFlagsNotSupported { flags: f }),
                "{f:#x}"
            );
        }
        // Compressed with no type, the reserved type, or two types.
        for f in [0x02, 0x0001_0002, 0x0006_0002, 0x0003_0002] {
            assert_eq!(
                classify_flags(&header(f)),
                Err(WimError::CompressionNotSupported),
                "{f:#x}"
            );
        }
        let bad_parts = WimError::Malformed {
            what: "part fields",
        };
        for (part, total) in [(2u16, 1u16), (0, 1), (1, 0), (0, 0), (8, 7)] {
            let mut h = header(0x80);
            h.part_number = part;
            h.total_parts = total;
            assert_eq!(classify_flags(&h), Err(bad_parts.clone()), "{part}/{total}");
        }
        // Valid n/N with N > 1, or 1/1 with the spanned flag: split.
        for (part, total, flags) in [(2u16, 7u16, 0x80), (1, 2, 0x80), (1, 1, 0x88)] {
            let mut h = header(flags);
            h.part_number = part;
            h.total_parts = total;
            assert_eq!(classify_flags(&h), Err(WimError::Spanned), "{part}/{total}");
        }
    }

    #[test]
    fn values() {
        let mut h = header(0x0002_0082);
        h.field_20 = 65536;
        assert!(matches!(
            check_header(&h, 10),
            Err(WimError::Malformed { .. })
        ));
        let mut h = header(0x80);
        h.image_count = 0;
        assert_eq!(check_header(&h, 10), Err(WimError::NoImages));
        h.image_count = 11;
        assert!(matches!(
            check_header(&h, 10),
            Err(WimError::LimitExceeded { .. })
        ));
        h.image_count = 2;
        h.boot_index = 3;
        assert_eq!(
            check_header(&h, 10),
            Err(WimError::BadBootIndex { boot_index: 3 })
        );
        h.boot_index = 2;
        h.version = 0x1234_5678;
        assert_eq!(check_header(&h, 10), Ok(Compression::None));
    }

    #[test]
    fn short_and_wrong() {
        assert_eq!(parse_header(b"MSWI"), Err(WimError::TooShort));
        assert_eq!(parse_header(b"MSWIM\0\0X"), Err(WimError::NotWim));
        let mut b = [0u8; 208];
        for (d, s) in b.iter_mut().zip(MAGIC) {
            *d = s;
        }
        assert_eq!(parse_header(&b[..207]).err(), Some(WimError::TooShort));
        assert_eq!(
            parse_header(&b).err(),
            Some(WimError::HeaderSize { cb_size: 0 })
        );
    }
}
