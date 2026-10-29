//! What the engine needs from the operating system, as traits.
//!
//! The pre-boot agent (plan WU-12) implements these on `usgp-winapi`:
//!
//! - [`Platform::open_target`]: open the disk the plan names (by its
//!   `disk_token`, resolved to the device the technician chose) for
//!   writing, and report its facts as the platform sees them now. The
//!   returned device is a [`usgp_disk::BlockDevice`] with whole-sector I/O.
//!   Every other disk stays read-only.
//! - [`VolumeOps`]: format the new volumes (DiskPart, by a drive letter we
//!   assign after resolving each volume from the extents of the partition
//!   we wrote), and give an [`ApplySink`] rooted at the Windows volume.
//! - [`BootFiles`]: create the installed system's boot files on the ESP
//!   with BCDBoot from the applied image (REQ-BOOT-066).
//! - [`FirmwareVars`]: read and write `BootOrder` and `Boot####` only. The
//!   name type, [`BootVarName`], cannot name any other variable, so no
//!   Secure Boot variable can be changed (DEC-0018 item 5).
//!
//! Tests implement them with in-memory devices and loopback files; the
//! `sim` feature has a file-backed set (`crate::sim`).
//!
//! Errors carry fixed text and kinds only, never paths, disk content or
//! secrets (REQ-JOB-014, REQ-DISK-016).

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 (Access Enforcement) - only the planned disk is
//   opened for writing.
// - NIST 800-53: CM-7 (Least Functionality) - firmware access limited to
//   `BootOrder` and `Boot####` by type.
// - NIST 800-53: SI-11 (Error Handling) - fixed error text.
// - SPEC: specs/disk.md#REQ-DISK-007, #REQ-DISK-008, #REQ-DISK-015
// - SPEC: specs/boot-network.md#REQ-BOOT-065, #REQ-BOOT-066
// - DECISION: docs/decisions/0018 items 5, 7, 8, 9; 0019

use std::fmt;
use std::io;

use usgp_disk::layout::{PartRole, WindowsUefiLayout};
use usgp_disk::uefi::BootVarName;
use usgp_disk::{BlockDevice, DiskFacts};
use usgp_image::apply::{ApplyRoot, ApplySink};
use usgp_proto::disk::{FileSystem, PlanDiskV1};

/// What went wrong in a platform operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlatformErrorKind {
    /// The planned disk or a volume was not found.
    NotFound,
    /// What was found is not what the plan names (another disk, another
    /// volume).
    IdentityMismatch,
    /// The operating system refused (access, lock, privilege).
    Refused,
    /// An I/O error of this kind.
    Io(io::ErrorKind),
    /// A tool or call did not finish in its own time limit.
    Timeout,
    /// The platform cannot do this (for example, firmware variables on a
    /// legacy BIOS boot).
    Unsupported,
}

/// A platform failure: a kind and a fixed description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformError {
    /// The kind.
    pub kind: PlatformErrorKind,
    /// Fixed text naming the operation.
    pub what: &'static str,
}

impl PlatformError {
    /// A failure of `kind` in operation `what`.
    #[must_use]
    pub const fn new(kind: PlatformErrorKind, what: &'static str) -> Self {
        Self { kind, what }
    }
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            PlatformErrorKind::NotFound => write!(f, "{}: not found", self.what),
            PlatformErrorKind::IdentityMismatch => {
                write!(f, "{}: does not match the plan", self.what)
            }
            PlatformErrorKind::Refused => write!(f, "{}: refused", self.what),
            PlatformErrorKind::Io(k) => write!(f, "{}: I/O error ({k})", self.what),
            PlatformErrorKind::Timeout => write!(f, "{}: timed out", self.what),
            PlatformErrorKind::Unsupported => write!(f, "{}: not supported", self.what),
        }
    }
}

impl std::error::Error for PlatformError {}

/// The disk the plan names, opened for writing.
pub struct OpenedTarget {
    /// Its facts as the platform reads them now (identity, bus, removable,
    /// boot media, sector sizes, size, existing partitions; no content).
    pub facts: DiskFacts,
    /// The device. Owned, so the engine can close it before formatting.
    pub device: Box<dyn BlockDevice>,
}

impl fmt::Debug for OpenedTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedTarget")
            .field("facts", &self.facts)
            .finish_non_exhaustive()
    }
}

/// One volume to format (plan section 1.2(c)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeSpec {
    /// The partition's role in the layout.
    pub role: PartRole,
    /// GPT partition number.
    pub number: u32,
    /// Byte offset of the partition (for resolving its volume by extents).
    pub start_bytes: u64,
    /// Its size in bytes.
    pub size_bytes: u64,
    /// File system to create.
    pub fs: FileSystem,
    /// Volume label.
    pub label: &'static str,
}

// [project rule] (plan section 1.2(c); CR-002): the three volume labels
// are this project's choice. Microsoft's UEFI/GPT deployment sample uses
// the same labels, "System", "Windows" and "Recovery"
// (`specs/standards/winpe.md` §11, SRC-087); that is not a Microsoft
// requirement.

/// Volume label of the ESP (plan section 1.2(c); [project rule]).
pub const LABEL_SYSTEM: &str = "System";
/// Volume label of the Windows volume ([project rule]).
pub const LABEL_WINDOWS: &str = "Windows";
/// Volume label of the recovery volume ([project rule]).
pub const LABEL_RECOVERY: &str = "Recovery";

impl VolumeSpec {
    /// The three volumes of `layout` to format, in partition order: ESP
    /// (FAT32, "System"), Windows (NTFS, "Windows"), recovery (NTFS,
    /// "Recovery"). The MSR is never formatted (REQ-DISK-008 item 2).
    #[must_use]
    pub fn for_layout(layout: &WindowsUefiLayout) -> [Self; 3] {
        let block = u64::from(layout.block);
        let spec = |p: &usgp_disk::Part, fs, label| Self {
            role: p.role,
            number: p.number,
            start_bytes: p.first_lba.saturating_mul(block),
            size_bytes: p.len_lbas().saturating_mul(block),
            fs,
            label,
        };
        [
            spec(&layout.esp, FileSystem::Fat32, LABEL_SYSTEM),
            spec(&layout.windows, FileSystem::Ntfs, LABEL_WINDOWS),
            spec(&layout.recovery, FileSystem::Ntfs, LABEL_RECOVERY),
        ]
    }
}

/// A volume the platform formatted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormattedVolume {
    /// The spec it was formatted from.
    pub spec: VolumeSpec,
    /// The file system the platform read back after formatting.
    pub fs: FileSystem,
    /// The label the platform read back.
    pub label: String,
    /// The platform's handle on the volume (for example a volume GUID
    /// path). Opaque to the engine; never a user-supplied path.
    pub locator: String,
    /// The drive-letter root the platform read back for the volume
    /// (`L:\`), if it has one. For the Windows volume it must be the root
    /// [`VolumeOps::windows_root`] promised.
    pub root: Option<String>,
}

/// Formatting and the apply target.
pub trait VolumeOps {
    /// The drive-letter root (`L:\`) the Windows volume will have, chosen
    /// **before the wipe** so the verify pass and the apply use the same
    /// apply root (link re-basing depends on its text; decision 0022).
    ///
    /// Called once per job, in step 1. The platform must pick a letter
    /// that no volume uses, keep it free, and give exactly this letter to
    /// the Windows volume in [`VolumeOps::format`]. A bare drive letter
    /// only: never a mounted folder or a directory below a root (the
    /// engine refuses anything else).
    ///
    /// # Errors
    ///
    /// [`PlatformError`] if no letter is free.
    fn windows_root(&mut self) -> Result<String, PlatformError>;

    /// Formats exactly the volumes in `specs` on the disk just written,
    /// and reads each one back. `device` is the target, still open, for
    /// any refresh the platform needs (for example, updating the
    /// operating system's view of the new table). The Windows volume gets
    /// the drive letter of `windows_root` (as returned by
    /// [`VolumeOps::windows_root`], normalised `L:`), and its
    /// [`FormattedVolume::root`] reports it.
    ///
    /// # Errors
    ///
    /// [`PlatformError`].
    fn format(
        &mut self,
        device: &mut dyn BlockDevice,
        layout: &WindowsUefiLayout,
        specs: &[VolumeSpec],
        windows_root: &ApplyRoot,
    ) -> Result<Vec<FormattedVolume>, PlatformError>;

    /// The apply target, rooted at the formatted Windows volume.
    ///
    /// # Errors
    ///
    /// [`PlatformError`].
    fn windows_sink(
        &mut self,
        windows: &FormattedVolume,
    ) -> Result<Box<dyn ApplySink + '_>, PlatformError>;
}

/// Boot files on the ESP (REQ-BOOT-066).
pub trait BootFiles {
    /// Creates the installed system's boot files and boot configuration on
    /// `esp` from the Windows image applied to `windows` (BCDBoot from the
    /// applied image, naming the ESP; `uefi-boot-manager.md` §9.1). The
    /// firmware boot option is written by the engine afterwards.
    ///
    /// # Errors
    ///
    /// [`PlatformError`].
    fn create(
        &mut self,
        esp: &FormattedVolume,
        windows: &FormattedVolume,
    ) -> Result<(), PlatformError>;
}

/// Why a firmware variable could not be read or written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FwError {
    /// Firmware variables are not available (legacy BIOS boot).
    #[error("firmware variables are not available")]
    Unsupported,
    /// The platform refused (privilege, write protection).
    #[error("firmware refused the operation")]
    Denied,
    /// The value is larger than the platform's buffer.
    #[error("firmware variable too large")]
    TooLarge,
    /// Another failure.
    #[error("firmware variable I/O failed")]
    Io,
}

/// UEFI global variables `BootOrder` and `Boot####` (REQ-BOOT-065).
/// Implementations write with [`BootVarName::vendor`] and
/// [`BootVarName::attributes`] only.
pub trait FirmwareVars {
    /// The value of `name`, or `None` if it does not exist.
    ///
    /// # Errors
    ///
    /// [`FwError`].
    fn get(&mut self, name: &BootVarName) -> Result<Option<Vec<u8>>, FwError>;

    /// Writes `data` (non-empty) to `name`.
    ///
    /// # Errors
    ///
    /// [`FwError`].
    fn set(&mut self, name: &BootVarName, data: &[u8]) -> Result<(), FwError>;
}

/// Everything platform-specific the engine uses.
pub trait Platform {
    /// Opens the disk `want` names for writing and reads its facts. The
    /// implementation resolves `want.disk_token` to the device from its
    /// own enumeration and must not open any other disk for writing.
    ///
    /// # Errors
    ///
    /// [`PlatformError`]; `IdentityMismatch` if the token names no disk
    /// of this enumeration.
    fn open_target(&mut self, want: &PlanDiskV1) -> Result<OpenedTarget, PlatformError>;

    /// Volume formatting and the apply target.
    fn volumes(&mut self) -> &mut dyn VolumeOps;

    /// Boot-file creation.
    fn boot_files(&mut self) -> &mut dyn BootFiles;

    /// Firmware variables.
    fn firmware(&mut self) -> &mut dyn FirmwareVars;
}
