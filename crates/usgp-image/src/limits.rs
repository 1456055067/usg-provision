//! Project limits for the WIM check (SI-10).
//!
//! These are our own bounds, chosen so a hostile file cannot make the check
//! use unbounded memory or time (REQ-IMG-037). They are not product limits
//! from any spec. A file over a limit is refused with
//! [`crate::WimError::LimitExceeded`] or [`crate::WimError::XmlTooLarge`],
//! never truncated.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SC-5 (Denial of
//   Service Protection) - bounded allocations and work per file.
// - SPEC: specs/os-images.md#REQ-IMG-037 (no unbounded memory or time)
// - SPEC: specs/standards/wim.md §12 (every size checked against the file
//   and the reader's own limits)

/// The sum of the original sizes of all metadata resources may be at most
/// this many times the file length (SEC-003, BOOT-001).
///
/// Our own bound, not a format fact. Metadata is decoded and hashed in
/// full, so this caps the check's decode work relative to what was
/// uploaded, whatever the configured byte limit. A decodable XPRESS chunk
/// needs at least 260 stored bytes (table and first units) for at most
/// 32768 output bytes, so a hostile file could otherwise reach about 126
/// times its length.
pub const METADATA_EXPANSION_LIMIT: u64 = 32;

/// Limits applied by [`crate::check_wim`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WimLimits {
    /// Largest XML data resource, in bytes (it is read whole).
    pub max_xml_bytes: u64,
    /// Most images per file.
    pub max_images: u32,
    /// Largest lookup table, in bytes. It is streamed, but the whole-table
    /// checks (overlapping ranges, repeated hashes; SEC-003) keep about 52
    /// bytes per 50-byte entry, so this also bounds that memory.
    pub max_lookup_bytes: u64,
    /// Largest original size of one metadata resource (it is streamed).
    pub max_metadata_bytes: u64,
    /// Largest sum of the original sizes of all metadata resources, which
    /// is the decode and hash work of the check. The sum is also bounded by
    /// [`METADATA_EXPANSION_LIMIT`] times the file length.
    pub max_metadata_total_bytes: u64,
    /// Longest text of one XML element (`NAME`, `DESCRIPTION` and every
    /// other recorded element), in Unicode scalar values.
    pub max_name_chars: usize,
    /// Deepest XML element nesting.
    pub max_xml_depth: usize,
    /// Most recorded leaf elements per `IMAGE`.
    pub max_xml_elements_per_image: usize,
    /// Largest integrity table, in bytes (it is streamed).
    pub max_integrity_bytes: u64,
}

impl WimLimits {
    /// The defaults of plan §3.1 plus our own bounds for the integrity
    /// table, the per-image element count and the total metadata work.
    ///
    /// `max_lookup_bytes` is 64 MiB (about 1.3 million resources), lowered
    /// from the plan's 512 MiB in fix round 1 so that the whole-table
    /// checks stay near 70 MiB of memory (SEC-003).
    pub const DEFAULT: Self = Self {
        max_xml_bytes: 16 * 1024 * 1024,
        max_images: 1024,
        max_lookup_bytes: 64 * 1024 * 1024,
        max_metadata_bytes: 1024 * 1024 * 1024,
        max_metadata_total_bytes: 4 * 1024 * 1024 * 1024,
        max_name_chars: 1024,
        max_xml_depth: 32,
        max_xml_elements_per_image: 1024,
        max_integrity_bytes: 16 * 1024 * 1024,
    };
}

impl Default for WimLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}
