//! Bounds applied to every driver archive (plan §1.5 default limits).
//!
//! The server's `[drivers]` configuration section (plan §3.6) fills an
//! [`ArchiveLimits`]; the defaults below are the plan's values.

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 (Configuration Settings), SI-10 (Information Input Validation)
// - SPEC: specs/drivers.md#REQ-DRV-009

/// One GiB.
const GIB: u64 = 1024 * 1024 * 1024;

/// Bounds for reading one archive. Exceeding any bound refuses the archive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveLimits {
    /// Largest archive file accepted, in bytes.
    pub max_archive_bytes: u64,
    /// Most entries (files and directories) in one archive.
    pub max_entries: u32,
    /// Largest total of all uncompressed entry sizes, in bytes.
    pub max_expanded_bytes: u64,
    /// Largest ratio of total uncompressed size to archive size.
    pub max_ratio_total: u64,
    /// Largest ratio of one entry's uncompressed size to its compressed size.
    pub max_ratio_entry: u64,
    /// Largest single entry, uncompressed, in bytes.
    pub max_entry_bytes: u64,
    /// Largest `.inf` file, in bytes.
    pub max_inf_bytes: u64,
    /// Longest entry name as stored, in bytes.
    pub max_name_bytes: usize,
    /// Most path segments in one name.
    pub max_depth: usize,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_archive_bytes: 8 * GIB,
            max_entries: 100_000,
            max_expanded_bytes: 32 * GIB,
            max_ratio_total: 200,
            max_ratio_entry: 1000,
            max_entry_bytes: 4 * GIB,
            max_inf_bytes: 16 * 1024 * 1024,
            max_name_bytes: 1024,
            max_depth: 32,
        }
    }
}
