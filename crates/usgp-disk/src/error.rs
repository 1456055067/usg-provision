//! Errors for GPT parsing, layout planning, the disk write path and UEFI
//! boot-option bytes.
//!
//! Variants carry LBAs, sizes, offsets and fixed reasons only, never disk
//! contents or variable data (REQ-DISK-016), so they can be logged and
//! reported as they are.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-11 (Error Handling) - no disk content in messages
// - SPEC: specs/disk.md#REQ-DISK-013, #REQ-DISK-016

use std::fmt;
use std::io;

use thiserror::Error;

/// Which copy of the GPT a problem was found in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GptCopy {
    /// The primary header at LBA 1 and its array.
    Primary,
    /// The backup header at the last LBA and its array.
    Backup,
}

impl fmt::Display for GptCopy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Primary => "primary",
            Self::Backup => "backup",
        })
    }
}

/// Why a GPT failed to parse or validate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GptError {
    /// Reading the device failed.
    #[error("device read failed: {}", .0.kind())]
    Io(#[from] io::Error),
    /// The device's logical sector size is not 512 or 4096.
    #[error("unsupported logical sector size {0}")]
    UnsupportedSectorSize(u32),
    /// The device is too small to hold a GPT.
    #[error("device too small for a GPT ({len} bytes)")]
    DeviceTooSmall {
        /// Device length in bytes.
        len: u64,
    },
    /// LBA 0 is not a protective MBR.
    #[error("no protective MBR: {0}")]
    NoProtectiveMbr(&'static str),
    /// A header failed one of the UEFI §5.3.2 checks.
    #[error("{copy} GPT header invalid: {reason}")]
    Header {
        /// Which header.
        copy: GptCopy,
        /// The check that failed.
        reason: &'static str,
    },
    /// A header's entry array failed its CRC or bounds.
    #[error("{copy} GPT entry array invalid: {reason}")]
    Array {
        /// Which array.
        copy: GptCopy,
        /// The check that failed.
        reason: &'static str,
    },
    /// A used entry is invalid (range, overlap, attributes, GUID).
    #[error("GPT entry {index} invalid: {reason}")]
    Entry {
        /// Entry index (0-based slot in the array).
        index: u32,
        /// The check that failed.
        reason: &'static str,
    },
    /// The backup header does not mirror the primary.
    #[error("backup GPT does not mirror primary: {0}")]
    BackupMismatch(&'static str),
    /// A size limit in [`crate::GptLimits`] was exceeded.
    #[error("GPT limit exceeded: {0}")]
    Limit(&'static str),
}

/// Why the Windows UEFI layout could not be planned.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum LayoutError {
    /// Logical/physical sector sizes are not 512n, 512e or 4Kn.
    #[error("unsupported sector sizes (logical {logical}, physical {physical})")]
    UnsupportedSectorSize {
        /// Logical sector size.
        logical: u32,
        /// Physical sector size.
        physical: u32,
    },
    /// The disk size is not a whole number of logical sectors.
    #[error("disk size {0} is not a whole number of sectors")]
    UnalignedSize(u64),
    /// The disk is smaller than the minimum (REQ-DISK-004).
    #[error("disk too small: {size} bytes, minimum {min} bytes")]
    TooSmall {
        /// Disk size in bytes.
        size: u64,
        /// Minimum in bytes.
        min: u64,
    },
    /// The recovery image size is out of range.
    #[error("recovery image size {0} out of range")]
    RecoveryTooLarge(u64),
    /// The random source produced a nil or repeated GUID.
    #[error("random source gave a nil or repeated GUID")]
    BadRandom,
}

/// Why the wipe-and-write step failed or was refused.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DiskError {
    /// The authorisation carries no durable wipe record; nothing was
    /// written (REQ-DISK-006).
    #[error("wipe not authorised: {0}")]
    NotAuthorised(&'static str),
    /// The opened device does not match the authorised disk or the plan
    /// (size or sector size); nothing was written.
    #[error("device does not match the authorised disk: {0}")]
    IdentityMismatch(&'static str),
    /// The wipe plan or layout is internally inconsistent; nothing was
    /// written.
    #[error("inconsistent disk plan: {0}")]
    BadPlan(&'static str),
    /// A write or flush failed; the disk may be partly written.
    #[error("disk write failed: {}", .0.kind())]
    Write(#[source] io::Error),
    /// The table read back after writing is invalid; the job must stop
    /// before formatting (REQ-DISK-009, 013).
    #[error("GPT read-back failed: {0}")]
    ReadBack(#[source] GptError),
    /// The table read back parses but does not match what was planned.
    #[error("GPT read-back differs from plan: {0}")]
    ReadBackMismatch(&'static str),
}

/// Why UEFI boot-option bytes could not be parsed or built.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum UefiError {
    /// The value ended before a field it must contain.
    #[error("truncated at offset {offset}: {what}")]
    Truncated {
        /// Byte offset where the field should start.
        offset: usize,
        /// The field.
        what: &'static str,
    },
    /// A field holds a value the standard does not allow.
    #[error("malformed at offset {offset}: {what}")]
    Malformed {
        /// Byte offset of the field.
        offset: usize,
        /// The rule broken.
        what: &'static str,
    },
    /// A design limit was exceeded.
    #[error("limit exceeded: {0}")]
    Limit(&'static str),
    /// A value we are asked to encode is not allowed.
    #[error("cannot encode: {0}")]
    Encode(&'static str),
}
