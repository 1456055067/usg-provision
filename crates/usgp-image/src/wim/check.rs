//! The whole-file check run before an uploaded WIM becomes ready.
//!
//! Order (plan §3.1): header → flags → resource bounds → lookup table
//! (streamed, then whole-table checks) → XML → counts → boot index →
//! metadata budget → integrity table → file chunk tables → metadata decode
//! and SHA-1. The first failure stops the check. Memory is bounded by
//! [`WimLimits`]: the XML is read whole (at most `max_xml_bytes`), the
//! lookup table's locations and hashes are held for the whole-table checks
//! (bounded by `max_lookup_bytes`), every other structure is streamed
//! through fixed buffers. Work is bounded too: no two resources may share
//! bytes, so each is read at most once, and decoded metadata is capped by
//! `max_metadata_total_bytes` and [`METADATA_EXPANSION_LIMIT`] times the
//! file length (SEC-003).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - every location and
//   size checked against the file length and limits before use.
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   integrity table and metadata hashes checked; damaged files refused.
// - NIST 800-53: SI-11 (Error Handling) - one named reason per refusal.
// - SPEC: specs/os-images.md#REQ-IMG-037, #REQ-IMG-038, #REQ-IMG-040,
//   #REQ-IMG-042, #REQ-IMG-051
// - SPEC: specs/preinstall-env.md#REQ-PE-004
// - SPEC: specs/standards/wim.md §2 to §8, §11, §12
// - DECISION: docs/decisions/0014-m2-wim-compression-scope.md

use std::io::{Read, Seek};

use usgp_crypto::CryptoProvider;

use super::header::{Compression, HEADER_LEN, HEADER_LEN_U64, check_header, parse_header};
use super::lookup::{self, ENTRY_LEN_U64};
use super::reshdr::{RESHDR_FLAG_METADATA, ResourceHeader};
use super::source::{Progress, Source};
use super::xml::{WimXmlImage, parse_xml};
use super::{integrity, resource};
use crate::codec::XpressDecoder;
use crate::error::WimError;
use crate::limits::{METADATA_EXPANSION_LIMIT, WimLimits};

/// One image of a checked file, as recorded in its XML (REQ-IMG-040).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditionInfo {
    /// Image index (1-based).
    pub index: u32,
    /// `NAME`.
    pub name: String,
    /// `DESCRIPTION` (empty if absent).
    pub description: String,
    /// `TOTALBYTES` of the image, if recorded.
    pub total_bytes: Option<u64>,
}

/// The result of a successful check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WimSummary {
    /// Number of images.
    pub image_count: u32,
    /// Compression of the file.
    pub compression: Compression,
    /// Boot index from the header (0 = none).
    pub boot_index: u32,
    /// True if the file carried an integrity table (and it matched).
    pub has_integrity_table: bool,
    /// Header version field, as recorded (OPEN-WIM-2; never a refusal
    /// reason on its own).
    pub version: u32,
    /// Images sorted by index, 1 to `image_count`.
    pub editions: Vec<EditionInfo>,
    /// The raw XML of each image, sorted by index, for documented fact
    /// cross-checks (decision 0013).
    pub xml_images: Vec<WimXmlImage>,
    /// Chunks of compressed file resources stored at or above their
    /// expanded size. How such chunks are stored is OPEN-WIM-5; M2 does
    /// not decode file resources, so they are recorded here, not refused
    /// (BOOT-007). Applying an image (M3) must settle them first.
    pub raw_sized_file_chunks: u64,
}

impl WimSummary {
    /// The raw XML of image `index`, if it exists.
    #[must_use]
    pub fn xml_image(&self, index: u32) -> Option<&WimXmlImage> {
        self.xml_images.iter().find(|i| i.index == index)
    }
}

/// Header resources (lookup, XML, integrity) may carry only these flags.
// FORMAT: OBS-007 - DISM sets 0x02 on the lookup and XML headers and 0x00
// on the integrity header; 0x02 there does not mark image metadata.
fn header_resource_flags_ok(rh: &ResourceHeader) -> bool {
    rh.flags & !RESHDR_FLAG_METADATA == 0
}

/// True if two resource headers name the same bytes with the same sizes;
/// the flag byte is not compared (BOOT-013).
fn same_location(a: &ResourceHeader, b: &ResourceHeader) -> bool {
    a.offset == b.offset && a.stored_size == b.stored_size && a.original_size == b.original_size
}

/// Checks a header resource that is stored uncompressed.
fn check_plain(rh: &ResourceHeader, what: &'static str) -> Result<(), WimError> {
    // FORMAT: OBS-007 - DISM never compresses the lookup table or XML
    // (stored == original in every R1 file).
    if !header_resource_flags_ok(rh) || rh.stored_size != rh.original_size {
        return Err(WimError::Malformed { what });
    }
    Ok(())
}

/// Checks an uploaded WIM file of `file_len` bytes.
///
/// `progress` is called after every read; returning `Break` stops the
/// check with [`WimError::Stalled`].
///
/// # Errors
///
/// The first [`WimError`] found; each names one reason (REQ-IMG-022).
pub fn check_wim<R: Read + Seek>(
    r: &mut R,
    file_len: u64,
    limits: &WimLimits,
    crypto: &dyn CryptoProvider,
    progress: &mut dyn Progress,
) -> Result<WimSummary, WimError> {
    let mut src = Source::new(r, progress);

    // 1. Header and flags.
    let head_len = usize::try_from(file_len.min(HEADER_LEN_U64)).map_err(|_| WimError::TooShort)?;
    let mut head = [0u8; HEADER_LEN];
    let head_buf = head.get_mut(..head_len).ok_or(WimError::TooShort)?;
    src.read_at(0, head_buf)?;
    let h = parse_header(head_buf)?;
    let compression = check_header(&h, limits.max_images)?;

    // 2. Resource bounds of the header's resources.
    check_plain(&h.lookup, "lookup table resource")?;
    if h.lookup.stored_size == 0 || h.lookup.stored_size % ENTRY_LEN_U64 != 0 {
        return Err(WimError::Malformed {
            what: "lookup table size",
        });
    }
    if h.lookup.stored_size > limits.max_lookup_bytes {
        return Err(WimError::LimitExceeded {
            what: "lookup table",
        });
    }
    h.lookup
        .check_within(HEADER_LEN_U64, file_len, "lookup table")?;
    check_plain(&h.xml, "XML data resource")?;
    if h.xml.stored_size > limits.max_xml_bytes {
        return Err(WimError::XmlTooLarge);
    }
    h.xml.check_within(HEADER_LEN_U64, file_len, "XML data")?;
    let has_integrity = !h.integrity.is_zero();
    if has_integrity {
        // FORMAT: OBS-007 - DISM writes flags 0x00 on the integrity header
        // (BOOT-009); anything else is refused.
        if h.integrity.flags != 0 {
            return Err(WimError::Malformed {
                what: "integrity table resource",
            });
        }
        h.integrity
            .check_within(HEADER_LEN_U64, file_len, "integrity table")?;
    }
    if !h.boot_metadata.is_zero() {
        h.boot_metadata
            .check_within(HEADER_LEN_U64, file_len, "boot metadata")?;
    }

    // 3. Lookup table, streamed, then checked as a whole against itself
    // and the header's own resources (no shared bytes, no repeated hash,
    // metadata in offset order).
    let mut header_resources = vec![h.lookup, h.xml];
    if has_integrity {
        header_resources.push(h.integrity);
    }
    let scan = lookup::scan(
        &mut src,
        &h.lookup,
        &header_resources,
        compression,
        file_len,
        limits.max_images,
    )?;

    // 4. XML (read whole; bounded above).
    let xml_len = usize::try_from(h.xml.stored_size).map_err(|_| WimError::XmlTooLarge)?;
    let mut xml_bytes = vec![0u8; xml_len];
    src.read_at(h.xml.offset, &mut xml_bytes)?;
    let xml = parse_xml(&xml_bytes, limits)?;
    drop(xml_bytes);

    // 5. Counts: header, XML and metadata entries agree; indexes 1..=n.
    let xml_count = u32::try_from(xml.images.len()).unwrap_or(u32::MAX);
    let meta_count = u32::try_from(scan.metadata.len()).unwrap_or(u32::MAX);
    if xml_count != h.image_count || meta_count != h.image_count {
        return Err(WimError::ImageCountMismatch {
            header: h.image_count,
            xml: xml_count,
            metadata: meta_count,
        });
    }
    // Sorted, unique and >= 1 (parse_xml), so 1..=n iff the last is n.
    if xml.images.last().map(|i| i.index) != Some(h.image_count) {
        return Err(WimError::XmlInvalid {
            reason: "INDEX out of range",
        });
    }

    // 5a. Boot index (BOOT-006, BOOT-013).
    // FORMAT: derived, unconfirmed - wim.md §2: the boot metadata header
    // locates the bootable image's metadata and boot index 0 means none.
    // OBS-001 saw both zero in every R1 file (no bootable sample,
    // OPEN-PE-LIC), so this cross-check rests on the paper's wording only.
    // Only the location is compared (offset, stored size, original size),
    // and the matched entry must be metadata. The header slot's flag byte
    // is not compared: OBS-007 shows DISM writing header-slot flags that
    // differ from the entry's, so a flag mismatch is not a refusal.
    if h.boot_index == 0 {
        if !h.boot_metadata.is_zero() {
            return Err(WimError::Malformed {
                what: "boot metadata",
            });
        }
    } else {
        let k = usize::try_from(h.boot_index.saturating_sub(1)).map_err(|_| {
            WimError::BadBootIndex {
                boot_index: h.boot_index,
            }
        })?;
        let located = scan
            .metadata
            .get(k)
            .is_some_and(|e| e.reshdr.is_metadata() && same_location(&e.reshdr, &h.boot_metadata));
        if !located {
            return Err(WimError::BadBootIndex {
                boot_index: h.boot_index,
            });
        }
    }

    // 5b. Metadata work budget, before anything is decoded (SEC-003).
    let mut metadata_total: u64 = 0;
    for entry in &scan.metadata {
        if entry.reshdr.original_size > limits.max_metadata_bytes {
            return Err(WimError::LimitExceeded { what: "metadata" });
        }
        metadata_total = metadata_total
            .checked_add(entry.reshdr.original_size)
            .ok_or(WimError::LimitExceeded {
                what: "total metadata",
            })?;
    }
    let relative_cap = file_len.saturating_mul(METADATA_EXPANSION_LIMIT);
    if metadata_total > limits.max_metadata_total_bytes || metadata_total > relative_cap {
        return Err(WimError::LimitExceeded {
            what: "total metadata",
        });
    }

    // 6. Integrity table.
    if has_integrity {
        integrity::verify(&mut src, &h.integrity, &h.lookup, limits, crypto)?;
    }

    // 6a. Chunk tables of compressed file resources, in offset order
    // (BOOT-007). Not decoded in M2.
    let mut raw_sized_file_chunks: u64 = 0;
    for rh in &scan.compressed_files {
        let raw = resource::check_chunk_table(&mut src, rh)?;
        raw_sized_file_chunks = raw_sized_file_chunks.saturating_add(raw);
    }

    // 7. Metadata resources: decode and SHA-1.
    // FORMAT: OBS-009 (partly settled) - the k-th lookup entry with the
    // metadata flag, in lookup-table order, is image index k. In S04
    // lookup, offset and index order coincide, so whether lookup order or
    // offset order rules is still open (OPEN-WIM-6); files where they
    // differ were refused by the lookup scan (BOOT-003).
    let mut decoder = match compression {
        Compression::Xpress => Some(XpressDecoder::new()),
        Compression::None => None,
    };
    for (index, entry) in (1u32..).zip(scan.metadata.iter()) {
        let mut hasher = crypto.legacy_sha1_hasher();
        let mut sink = |piece: &[u8]| {
            hasher.update(piece);
            Ok(())
        };
        resource::read_resource(&mut src, &entry.reshdr, decoder.as_mut(), &mut sink)?;
        if hasher.finish().0 != entry.sha1 {
            return Err(WimError::MetadataHashMismatch { index });
        }
    }

    let editions = xml
        .images
        .iter()
        .map(|i| EditionInfo {
            index: i.index,
            name: i.name.clone(),
            description: i.description.clone(),
            total_bytes: i.total_bytes,
        })
        .collect();
    Ok(WimSummary {
        image_count: h.image_count,
        compression,
        boot_index: h.boot_index,
        has_integrity_table: has_integrity,
        version: h.version,
        editions,
        xml_images: xml.images,
        raw_sized_file_chunks,
    })
}

/// Picks the image of a checked PE file to use (REQ-PE-004): the only
/// image of a one-image file, or the image the header's boot index names.
///
/// # Errors
///
/// [`WimError::PeNoUsableImage`] if the file holds several images and
/// names none as bootable.
pub fn check_pe(summary: &WimSummary) -> Result<u32, WimError> {
    // wim.md §11: only one image per file can be bootable; the header's
    // boot index records it, 0 meaning none. check_wim already refused a
    // boot index above the image count.
    if summary.boot_index != 0 && summary.boot_index <= summary.image_count {
        return Ok(summary.boot_index);
    }
    if summary.image_count == 1 {
        return Ok(1);
    }
    Err(WimError::PeNoUsableImage {
        image_count: summary.image_count,
    })
}
