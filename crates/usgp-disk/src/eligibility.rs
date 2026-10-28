//! Which disks may be offered as the install target: pure functions over a
//! [`DiskFacts`] description gathered by the platform backend.
//!
//! Refused (each with a reason the device shows, REQ-DISK-001/003):
//!
//! - the disk carrying the boot environment (REQ-DISK-005; DEC-0018 item 8);
//! - removable media (REQ-DISK-005; DEC-0018 item 8);
//! - USB-attached disks, even when they report fixed media (OPEN-DISK-4,
//!   fail closed per the M3 brief);
//! - buses outside a fixed allowlist of internal disk buses, including SD,
//!   MMC and file-backed virtual disks (OPEN-DISK-5(c)/(d), fail closed);
//! - read-only disks (OPEN-DISK-5(a), fail closed);
//! - logical/physical sector sizes other than 512n, 512e or 4Kn
//!   (OPEN-DISK-5(b), fail closed; Windows supports no others,
//!   `windows-storage-firmware-api.md` §3.3);
//! - disks below the minimum size (REQ-DISK-004).
//!
//! A disk that already holds partitions is **eligible**: its partitions are
//! listed before the wipe (REQ-DISK-006) and destroyed by it (REQ-DISK-007).
//! A single eligible disk is still offered for explicit choice and
//! confirmation (REQ-DISK-002, DEC-0018 item 8); that is the agent's UI rule,
//! and nothing here selects a disk.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 (Access Enforcement) - destructive target restricted
// - NIST 800-53: SI-10 (Information Input Validation)
// - NIST 800-53: CM-7 (Least Functionality) - fail-closed bus allowlist
// - SPEC: specs/disk.md#REQ-DISK-001, #REQ-DISK-003, #REQ-DISK-004,
//   #REQ-DISK-005 (OPEN-DISK-4, OPEN-DISK-5 fail closed)
// - specs/standards/windows-storage-firmware-api.md §3, §11

use std::fmt;

/// The bus a disk is attached to (`windows-storage-firmware-api.md` §3.2,
/// by name; numeric values are the platform backend's concern,
/// OPEN-WAPI-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Bus {
    /// `BusTypeUnknown`.
    Unknown,
    /// `BusTypeScsi`.
    Scsi,
    /// `BusTypeAtapi`.
    Atapi,
    /// `BusTypeAta`.
    Ata,
    /// `BusType1394`.
    Ieee1394,
    /// `BusTypeSsa`.
    Ssa,
    /// `BusTypeFibre`.
    Fibre,
    /// `BusTypeUsb`.
    Usb,
    /// `BusTypeRAID`.
    Raid,
    /// `BusTypeiScsi`.
    Iscsi,
    /// `BusTypeSas`.
    Sas,
    /// `BusTypeSata`.
    Sata,
    /// `BusTypeSd`.
    Sd,
    /// `BusTypeMmc`.
    Mmc,
    /// `BusTypeVirtual`.
    Virtual,
    /// `BusTypeFileBackedVirtual`.
    FileBackedVirtual,
    /// `BusTypeSpaces`.
    Spaces,
    /// `BusTypeNvme`.
    Nvme,
    /// `BusTypeSCM`.
    Scm,
    /// `BusTypeUfs`.
    Ufs,
    /// `BusTypeNvmeof`.
    NvmeOf,
    /// A value outside the documented list.
    Other(u32),
}

impl fmt::Display for Bus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Unknown => "unknown",
            Self::Scsi => "SCSI",
            Self::Atapi => "ATAPI",
            Self::Ata => "ATA",
            Self::Ieee1394 => "IEEE 1394",
            Self::Ssa => "SSA",
            Self::Fibre => "Fibre Channel",
            Self::Usb => "USB",
            Self::Raid => "RAID",
            Self::Iscsi => "iSCSI",
            Self::Sas => "SAS",
            Self::Sata => "SATA",
            Self::Sd => "SD",
            Self::Mmc => "MMC",
            Self::Virtual => "virtual",
            Self::FileBackedVirtual => "file-backed virtual",
            Self::Spaces => "storage spaces",
            Self::Nvme => "NVMe",
            Self::Scm => "SCM",
            Self::Ufs => "UFS",
            Self::NvmeOf => "NVMe-oF",
            Self::Other(v) => return write!(f, "bus type {v}"),
        };
        f.write_str(s)
    }
}

/// Buses a target disk may be on. Design choice (plan §11 Q6, OPEN-DISK-5,
/// fail closed): the common internal disk buses only. Every other bus,
/// including those whose meaning the standards summary does not describe
/// (`windows-storage-firmware-api.md` §3.2), is refused until a spec says
/// otherwise.
const ALLOWED_BUSES: [Bus; 6] = [
    Bus::Ata,
    Bus::Sata,
    Bus::Scsi,
    Bus::Sas,
    Bus::Nvme,
    Bus::Raid,
];

/// FORMAT: windows-storage-firmware-api.md §3.3 - supported (logical,
/// physical) sector sizes: 512n, 512e and 4Kn. Anything else is refused
/// (OPEN-DISK-5(b), fail closed).
pub const SUPPORTED_SECTORS: [(u32, u32); 3] = [(512, 512), (512, 4096), (4096, 4096)];

/// How the person at the device recognises a disk (REQ-DISK-001). Strings
/// are as the disk reports them; the wire layer bounds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskIdentity {
    /// The platform's disk number (on Windows, the `PhysicalDriveN` number).
    pub device_number: u32,
    /// Model or product name.
    pub model: String,
    /// Serial number, if the disk reports one.
    pub serial: Option<String>,
}

/// A partition already on the disk, for the pre-wipe listing
/// (REQ-DISK-006) and for the wipe ranges. Structure only: no content
/// (REQ-DISK-016).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExistingPartition {
    /// Byte offset of the partition on the disk.
    pub start_bytes: u64,
    /// Length in bytes.
    pub size_bytes: u64,
    /// Volume label, if the platform could read one.
    pub label: Option<String>,
}

/// Everything eligibility depends on, gathered by the platform backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskFacts {
    /// Identity shown to the person.
    pub identity: DiskIdentity,
    /// Bus type.
    pub bus: Bus,
    /// The disk reports removable media.
    pub removable: bool,
    /// The disk reports itself not writable.
    pub read_only: bool,
    /// Logical sector size in bytes.
    pub logical_sector: u32,
    /// Physical sector size in bytes.
    pub physical_sector: u32,
    /// Size in bytes.
    pub size_bytes: u64,
    /// The boot environment (WinPE, or boot media) is on this disk.
    pub hosts_boot_environment: bool,
    /// Existing partitions.
    pub partitions: Vec<ExistingPartition>,
}

/// Why a disk cannot be offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Ineligible {
    /// It carries the boot environment (REQ-DISK-005).
    BootMedia,
    /// It reports removable media (REQ-DISK-005).
    Removable,
    /// USB-attached; refused until OPEN-DISK-4 is decided.
    UsbDisk,
    /// The bus is not one we install to (OPEN-DISK-5, fail closed).
    UnsupportedBus(Bus),
    /// The disk is not writable (OPEN-DISK-5(a), fail closed).
    ReadOnly,
    /// Sector sizes other than 512n, 512e or 4Kn.
    UnsupportedSectorSize {
        /// Logical sector size.
        logical: u32,
        /// Physical sector size.
        physical: u32,
    },
    /// Smaller than the minimum (REQ-DISK-004).
    TooSmall {
        /// Disk size in bytes.
        size: u64,
        /// Minimum in bytes.
        min: u64,
    },
}

impl fmt::Display for Ineligible {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BootMedia => f.write_str("holds the running boot environment"),
            Self::Removable => f.write_str("removable media"),
            Self::UsbDisk => f.write_str("USB-attached disk"),
            Self::UnsupportedBus(b) => write!(f, "unsupported bus ({b})"),
            Self::ReadOnly => f.write_str("read-only"),
            Self::UnsupportedSectorSize { logical, physical } => write!(
                f,
                "unsupported sector size (logical {logical}, physical {physical})"
            ),
            Self::TooSmall { size, min } => {
                write!(f, "too small: {size} bytes, minimum {min} bytes")
            }
        }
    }
}

/// Eligibility switches. [`EligibilityPolicy::default`] is the release
/// policy; there is no configuration key for it (plan §3.9: the refusals
/// are fixed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EligibilityPolicy {
    /// Accept file-backed virtual disks. `false` in release; `true` only in
    /// tests and the Windows CI job, which installs to attached VHDs (plan
    /// §10.2).
    pub allow_file_backed_virtual: bool,
}

/// `true` if `(logical, physical)` is 512n, 512e or 4Kn.
#[must_use]
pub fn sector_sizes_supported(logical: u32, physical: u32) -> bool {
    SUPPORTED_SECTORS.contains(&(logical, physical))
}

/// Every reason `f` is not eligible, in a fixed order (empty = eligible).
/// `min_bytes` is the minimum for the chosen package
/// ([`crate::minimum_disk_bytes`]); a value below 64 GB is raised to it.
#[must_use]
pub fn assess_all(f: &DiskFacts, p: &EligibilityPolicy, min_bytes: u64) -> Vec<Ineligible> {
    let mut out = Vec::new();
    if f.hosts_boot_environment {
        out.push(Ineligible::BootMedia);
    }
    if f.removable {
        out.push(Ineligible::Removable);
    }
    match f.bus {
        Bus::Usb => out.push(Ineligible::UsbDisk),
        Bus::FileBackedVirtual if p.allow_file_backed_virtual => {}
        b if !ALLOWED_BUSES.contains(&b) => out.push(Ineligible::UnsupportedBus(b)),
        _ => {}
    }
    if f.read_only {
        out.push(Ineligible::ReadOnly);
    }
    if !sector_sizes_supported(f.logical_sector, f.physical_sector) {
        out.push(Ineligible::UnsupportedSectorSize {
            logical: f.logical_sector,
            physical: f.physical_sector,
        });
    }
    // Never below Microsoft's 64 GB minimum, whatever the caller passes
    // (REQ-DISK-004; OPEN-DISK-1 keeps it fixed).
    let min = min_bytes.max(crate::layout::MIN_DISK_BYTES);
    if f.size_bytes < min {
        out.push(Ineligible::TooSmall {
            size: f.size_bytes,
            min,
        });
    }
    out
}

/// `Ok` if `f` may be offered; otherwise the first reason from
/// [`assess_all`].
///
/// # Errors
/// The first [`Ineligible`] reason.
pub fn assess(f: &DiskFacts, p: &EligibilityPolicy, min_bytes: u64) -> Result<(), Ineligible> {
    match assess_all(f, p, min_bytes).first() {
        Some(r) => Err(*r),
        None => Ok(()),
    }
}
