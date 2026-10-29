//! usgp-disk: target-disk eligibility, the Windows UEFI layout planner,
//! and a pure-Rust GPT writer and read-back checker.
//!
//! Everything here is OS-neutral and does no I/O of its own except through
//! the [`BlockDevice`] trait. The Windows platform backend implements that
//! trait for the chosen physical disk; tests use [`MemBlockDevice`] or
//! [`FileBlockDevice`] (regular files only, never a block device).
//!
//! - [`eligibility`]: pure rules over a [`DiskFacts`] description
//!   (REQ-DISK-004, REQ-DISK-005, OPEN-DISK-4/5 fail closed).
//! - [`layout`]: Microsoft's recommended UEFI layout (REQ-DISK-008, 010).
//! - [`gpt`], [`mbr`], [`crc32`], [`guid`]: GPT encode and strict parse
//!   (REQ-DISK-009).
//! - [`wipe`] and [`executor`]: the zero ranges and the single write path,
//!   which needs a [`WipeAuthorisation`] (REQ-DISK-006, 007, 015).
//! - [`uefi`]: `Boot####` and `BootOrder` bytes for the installed system's
//!   boot entry (REQ-BOOT-065); no Secure Boot variable can be named.
//!
//! Filled in: M3 (docs/ROADMAP.md section 3; plan WU-3).

// Parses untrusted input: indexing and slicing that can panic are denied
// (CLAUDE.md, Engineering Rules: parsers never panic on input).
#![deny(clippy::indexing_slicing)]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - GPT/MBR parsers
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   GPT read-back checked before formatting
// - NIST 800-53: AC-3 (Access Enforcement) - writes need a WipeAuthorisation
// - SPEC: specs/disk.md#REQ-DISK-004..010, #REQ-DISK-015, #REQ-DISK-016
// - SPEC: specs/boot-network.md#REQ-BOOT-065
// - UEFI 2.10 ch. 5 (summarised in specs/standards/gpt.md)

mod bytes;
pub mod crc32;
pub mod device;
pub mod eligibility;
pub mod error;
pub mod executor;
pub mod gpt;
pub mod guid;
pub mod layout;
pub mod mbr;
pub mod uefi;
pub mod wipe;

pub use device::{BlockDevice, FileBlockDevice, MemBlockDevice};
pub use eligibility::{
    Bus, DiskFacts, DiskIdentity, EligibilityPolicy, ExistingPartition, Ineligible, assess,
    assess_all,
};
pub use error::{DiskError, GptCopy, GptError, LayoutError, UefiError};
pub use executor::{WipeAuthorisation, WipeEvidence, wipe_and_write};
pub use gpt::{GptLimits, GptPlan, GptView, PartitionEntry, parse_gpt};
pub use guid::Guid;
pub use layout::{
    Part, PartRole, WindowsUefiLayout, fs_overhead_bytes, image_budget_bytes, minimum_disk_bytes,
    windows_bytes_needed,
};
pub use wipe::{ByteRange, WipePlan};
