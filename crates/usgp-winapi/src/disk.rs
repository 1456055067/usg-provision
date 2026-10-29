//! Disks: enumeration, storage properties, geometry and length, the
//! current partition layout, and raw sector I/O for writing a layout.
//!
//! Two kinds of handle are used:
//!
//! - [`DiskQuery`] opens `\\.\PhysicalDriveN` with **no read or write
//!   access**. Every query here uses a control code whose required access
//!   (encoded in the `windows-sys` constant) is "any", so disk contents are
//!   never read while choosing a target (decision 0018 item 8).
//! - [`RawDisk`] opens one disk for reading and writing. It is meant to be
//!   opened only for the disk an authorised job names; it re-checks the
//!   device number and the size the job expects, and refuses unaligned or
//!   out-of-range I/O. Raw I/O itself goes through `std` (decision 0019
//!   item 3); only the control codes use FFI.
//!
//! Which disk is which (BOOT-002, SEC-003): disk numbers can change
//! (spec §7), but the SetupAPI device path of a disk's interface can be
//! reused across restarts (spec §2). [`interfaces`] keeps each disk's
//! path, and [`RawDisk::open_interface_for_write`] opens the write handle
//! **by that path**, so the handle is the device that was enumerated even
//! if numbers moved. The descriptor and the partition-table identity
//! ([`DriveLayout::table_id`]) can then be read on the write handle itself
//! and compared with what the person confirmed.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), AC-3 (Access
//   Enforcement) - zero-access query handles; writes only on a re-checked
//   disk; MP-6 boundary note: no sanitisation here
// - SPEC: specs/standards/windows-storage-firmware-api.md §1, §3, §4, §5,
//   §6, §7
// - SPEC: specs/disk.md (DISK-1) - facts used by eligibility
// - DECISION: docs/decisions/0019-windows-api-binding.md

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::{FileExt, OpenOptionsExt};

use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA,
    ERROR_NOT_SUPPORTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    BusType1394, BusTypeAta, BusTypeAtapi, BusTypeFibre, BusTypeFileBackedVirtual, BusTypeMmc,
    BusTypeNvme, BusTypeRAID, BusTypeSCM, BusTypeSas, BusTypeSata, BusTypeScsi, BusTypeSd,
    BusTypeSpaces, BusTypeSsa, BusTypeUfs, BusTypeUnknown, BusTypeUsb, BusTypeVirtual,
    BusTypeiScsi, FILE_DEVICE_DISK, FILE_FLAG_WRITE_THROUGH, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Ioctl::{
    FixedMedia, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
    IOCTL_DISK_GET_LENGTH_INFO, IOCTL_DISK_IS_WRITABLE, IOCTL_DISK_UPDATE_PROPERTIES,
    IOCTL_STORAGE_GET_DEVICE_NUMBER, IOCTL_STORAGE_QUERY_PROPERTY, PARTITION_ENTRY_UNUSED,
    PARTITION_STYLE_GPT, PARTITION_STYLE_MBR, PARTITION_STYLE_RAW, RemovableMedia,
    STORAGE_PROPERTY_ID, StorageAccessAlignmentProperty, StorageDeviceProperty, Unknown,
};

use crate::error::{Result, WinApiError};
use crate::ffi::{self, IoctlFailure, IoctlInput};
use crate::layout;
use crate::parse::{
    self, DeviceNumber, GptLayoutHeader, MAX_PARTITION_ENTRIES, RawPartition, RawPartitionKind,
    SectorSizes,
};

/// Most disk interfaces accepted from one enumeration.
pub const MAX_DISKS: usize = 256;

/// Largest storage descriptor accepted (bytes).
pub const MAX_DESCRIPTOR_BYTES: u32 = 64 * 1024;

/// The two logical sector sizes Windows supports (spec §3.3).
pub const SUPPORTED_LOGICAL_SECTORS: [u32; 2] = [512, 4096];

/// The device path of disk `n`.
#[must_use]
pub fn physical_drive_path(n: u32) -> String {
    format!("\\\\.\\PhysicalDrive{n}")
}

fn is_code(e: &io::Error, code: u32) -> bool {
    e.raw_os_error()
        .and_then(|c| u32::try_from(c).ok())
        .is_some_and(|c| c == code)
}

fn os(op: &'static str) -> impl FnOnce(IoctlFailure) -> WinApiError {
    move |f| WinApiError::os(op, f.error)
}

/// The bus a disk is attached to (`STORAGE_BUS_TYPE`, spec §3.2). Values
/// are mapped through the `windows-sys` constants; any other value is
/// [`Bus::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// Any other value, kept raw. This includes 20, which the spec's table
    /// lists as `BusTypeNvmeof` and the `windows-sys` declarations as
    /// `BusTypeMax`; callers must not treat it as a known bus.
    Other(i32),
}

/// `STORAGE_BUS_TYPE` values from `windows-sys` and their meaning. A table,
/// not a `match`, because the constants keep Microsoft's mixed-case names.
const BUS_TYPES: [(i32, Bus); 20] = [
    (BusTypeUnknown, Bus::Unknown),
    (BusTypeScsi, Bus::Scsi),
    (BusTypeAtapi, Bus::Atapi),
    (BusTypeAta, Bus::Ata),
    (BusType1394, Bus::Ieee1394),
    (BusTypeSsa, Bus::Ssa),
    (BusTypeFibre, Bus::Fibre),
    (BusTypeUsb, Bus::Usb),
    (BusTypeRAID, Bus::Raid),
    (BusTypeiScsi, Bus::Iscsi),
    (BusTypeSas, Bus::Sas),
    (BusTypeSata, Bus::Sata),
    (BusTypeSd, Bus::Sd),
    (BusTypeMmc, Bus::Mmc),
    (BusTypeVirtual, Bus::Virtual),
    (BusTypeFileBackedVirtual, Bus::FileBackedVirtual),
    (BusTypeSpaces, Bus::Spaces),
    (BusTypeNvme, Bus::Nvme),
    (BusTypeSCM, Bus::Scm),
    (BusTypeUfs, Bus::Ufs),
];

impl Bus {
    /// Maps a raw `STORAGE_BUS_TYPE`.
    #[must_use]
    pub fn from_raw(v: i32) -> Self {
        BUS_TYPES
            .iter()
            .find(|(raw, _)| *raw == v)
            .map_or(Self::Other(v), |&(_, b)| b)
    }
}

/// `MEDIA_TYPE` from the geometry (spec §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    /// `Unknown`.
    Unknown,
    /// `FixedMedia`.
    Fixed,
    /// `RemovableMedia`.
    Removable,
    /// Any other value (floppy formats), kept raw.
    Other(i32),
}

impl MediaType {
    /// Maps a raw `MEDIA_TYPE`.
    #[must_use]
    pub fn from_raw(v: i32) -> Self {
        if v == Unknown {
            Self::Unknown
        } else if v == FixedMedia {
            Self::Fixed
        } else if v == RemovableMedia {
            Self::Removable
        } else {
            Self::Other(v)
        }
    }
}

/// The device descriptor (spec §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceDescriptor {
    /// Bus.
    pub bus: Bus,
    /// `RemovableMedia`.
    pub removable_media: bool,
    /// SCSI peripheral device type.
    pub scsi_device_type: u8,
    /// Vendor id.
    pub vendor_id: Option<String>,
    /// Product id.
    pub product_id: Option<String>,
    /// Product revision.
    pub product_revision: Option<String>,
    /// Serial number.
    pub serial_number: Option<String>,
}

/// Size and geometry (spec §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    /// Media type.
    pub media: MediaType,
    /// `BytesPerSector`.
    pub bytes_per_sector: u32,
    /// Disk size in bytes.
    pub size_bytes: u64,
}

/// Answer of `IOCTL_DISK_IS_WRITABLE` (spec §6).
///
/// OPEN-WAPI-2: the page does not say which error means "write
/// protected", so any failure is "not writable" (fail closed) and the
/// code is kept for the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Writability {
    /// The call succeeded.
    Writable,
    /// The call failed.
    NotWritable {
        /// OS error code, if any.
        os_error: Option<i32>,
    },
}

/// Partition style (spec §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionStyle {
    /// `PARTITION_STYLE_MBR`.
    Mbr,
    /// `PARTITION_STYLE_GPT`.
    Gpt,
    /// `PARTITION_STYLE_RAW` (no partition table).
    Raw,
    /// Any other value, kept raw.
    Other(i32),
}

impl PartitionStyle {
    /// Maps a raw `PARTITION_STYLE`.
    #[must_use]
    pub fn from_raw(v: i32) -> Self {
        match v {
            PARTITION_STYLE_MBR => Self::Mbr,
            PARTITION_STYLE_GPT => Self::Gpt,
            PARTITION_STYLE_RAW => Self::Raw,
            other => Self::Other(other),
        }
    }
}

/// The identity a disk's current partition table carries (spec §5): the
/// GPT disk GUID or the MBR disk signature. Used with the device path and
/// descriptor to tell twin disks apart (BOOT-002).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableId {
    /// A GPT disk and its disk GUID.
    Gpt(parse::Guid),
    /// An MBR disk and its signature.
    Mbr(u32),
    /// No partition table, or a style without an identity.
    None,
}

/// The partition layout Windows reports for a disk (spec §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveLayout {
    /// Style.
    pub style: PartitionStyle,
    /// GPT header, for GPT disks.
    pub gpt: Option<GptLayoutHeader>,
    /// Disk signature, for MBR disks.
    pub mbr_signature: Option<u32>,
    /// Partitions in use. Unused MBR slots (type 0) are left out.
    pub partitions: Vec<RawPartition>,
}

impl DriveLayout {
    /// The table's identity: the GPT disk GUID or the MBR signature, as
    /// the style says; [`TableId::None`] otherwise.
    #[must_use]
    pub fn table_id(&self) -> TableId {
        match (self.style, &self.gpt, self.mbr_signature) {
            (PartitionStyle::Gpt, Some(g), _) => TableId::Gpt(g.disk_id),
            (PartitionStyle::Mbr, _, Some(sig)) => TableId::Mbr(sig),
            _ => TableId::None,
        }
    }

    fn from_raw(raw: parse::RawDriveLayout) -> Self {
        let unused = u8::try_from(PARTITION_ENTRY_UNUSED).unwrap_or(0);
        let partitions = raw
            .partitions
            .into_iter()
            .filter(|p| {
                !matches!(p.kind, RawPartitionKind::Mbr { partition_type, .. } if partition_type == unused)
            })
            .collect();
        Self {
            style: PartitionStyle::from_raw(raw.style),
            gpt: raw.gpt,
            mbr_signature: raw.mbr_signature,
            partitions,
        }
    }
}

/// Everything the queries report about one disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskInfo {
    /// Disk number (valid until removal or restart, spec §7).
    pub number: u32,
    /// The device path of the disk's interface (spec §2), when it was
    /// opened through the enumeration; `None` when opened by number.
    pub interface_path: Option<String>,
    /// Device descriptor.
    pub descriptor: DeviceDescriptor,
    /// Sector sizes, when the device supports the alignment query.
    pub sector_sizes: Option<SectorSizes>,
    /// Geometry and size.
    pub geometry: Geometry,
    /// Writable or not.
    pub writability: Writability,
    /// Current partition layout.
    pub layout: DriveLayout,
}

fn query_open_options() -> OpenOptions {
    let mut o = OpenOptions::new();
    // No read or write access: queries only (decision 0018 item 8).
    o.access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
    o
}

fn device_number_of(file: &File) -> Result<DeviceNumber> {
    let b = ffi::device_io_control(
        file,
        IOCTL_STORAGE_GET_DEVICE_NUMBER,
        IoctlInput::None,
        layout::DEVICE_NUMBER_LEN,
    )
    .map_err(os("get device number"))?;
    parse::device_number(&b, &layout::DEVICE_NUMBER)
        .map_err(|e| WinApiError::malformed("device number", e))
}

/// Checks that `file` is disk `number` (spec §7: numbers can change).
fn check_is_disk(file: &File, number: u32) -> Result<()> {
    let dn = device_number_of(file)?;
    if dn.device_type != FILE_DEVICE_DISK {
        return Err(WinApiError::DeviceMismatch {
            what: "device is not a disk",
        });
    }
    if dn.device_number != number {
        return Err(WinApiError::DeviceMismatch {
            what: "disk number changed",
        });
    }
    Ok(())
}

/// Two-step property query (spec §3): read the header's size, then the
/// whole descriptor.
fn storage_property(
    file: &File,
    id: STORAGE_PROPERTY_ID,
) -> core::result::Result<Vec<u8>, WinApiError> {
    let head = ffi::device_io_control(
        file,
        IOCTL_STORAGE_QUERY_PROPERTY,
        IoctlInput::StandardPropertyQuery(id),
        layout::HEADER.len,
    )
    .map_err(os("query storage property"))?;
    let size = parse::descriptor_size(&head, &layout::HEADER)
        .map_err(|e| WinApiError::malformed("storage descriptor header", e))?;
    if size > MAX_DESCRIPTOR_BYTES {
        return Err(WinApiError::LimitExceeded {
            what: "storage descriptor size",
            limit: u64::from(MAX_DESCRIPTOR_BYTES),
        });
    }
    let len = usize::try_from(size).map_err(|_| WinApiError::LimitExceeded {
        what: "storage descriptor size",
        limit: u64::from(MAX_DESCRIPTOR_BYTES),
    })?;
    ffi::device_io_control(
        file,
        IOCTL_STORAGE_QUERY_PROPERTY,
        IoctlInput::StandardPropertyQuery(id),
        len.max(layout::HEADER.len),
    )
    .map_err(os("query storage property"))
}

fn sector_sizes_of(file: &File) -> Result<Option<SectorSizes>> {
    match storage_property(file, StorageAccessAlignmentProperty) {
        Ok(b) => parse::access_alignment(&b, &layout::ALIGNMENT)
            .map(Some)
            .map_err(|e| WinApiError::malformed("access alignment descriptor", e)),
        // The device does not support the alignment query.
        Err(WinApiError::Os { source, .. })
            if [
                ERROR_INVALID_FUNCTION,
                ERROR_NOT_SUPPORTED,
                ERROR_INVALID_PARAMETER,
            ]
            .iter()
            .any(|&c| is_code(&source, c)) =>
        {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

fn geometry_of(file: &File) -> Result<Geometry> {
    let b = ffi::device_io_control(
        file,
        IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
        IoctlInput::None,
        layout::GEOMETRY_LEN,
    )
    .map_err(os("get drive geometry"))?;
    let g = parse::geometry(&b, &layout::GEOMETRY)
        .map_err(|e| WinApiError::malformed("drive geometry", e))?;
    Ok(Geometry {
        media: MediaType::from_raw(g.media_type),
        bytes_per_sector: g.bytes_per_sector,
        size_bytes: g.disk_size,
    })
}

/// A disk opened for queries only (no read or write access).
#[derive(Debug)]
pub struct DiskQuery {
    file: File,
    number: u32,
    path: Option<String>,
}

fn descriptor_of(file: &File) -> Result<DeviceDescriptor> {
    let b = storage_property(file, StorageDeviceProperty)?;
    let d = parse::device_descriptor(&b, &layout::DEVICE_DESCRIPTOR)
        .map_err(|e| WinApiError::malformed("device descriptor", e))?;
    Ok(DeviceDescriptor {
        bus: Bus::from_raw(d.bus_type),
        removable_media: d.removable_media,
        scsi_device_type: d.device_type,
        vendor_id: d.vendor_id,
        product_id: d.product_id,
        product_revision: d.product_revision,
        serial_number: d.serial_number,
    })
}

impl DiskQuery {
    /// Opens disk `number` for queries and checks that it is that disk.
    pub fn open(number: u32) -> Result<Self> {
        let file = query_open_options()
            .open(physical_drive_path(number))
            .map_err(|e| WinApiError::os("open disk for query", e))?;
        check_is_disk(&file, number)?;
        Ok(Self {
            file,
            number,
            path: None,
        })
    }

    /// Opens the disk at `iface`'s device path (as-is, never parsed;
    /// spec §2) for queries, and checks that it is a disk with
    /// `iface.number`.
    pub fn open_interface(iface: &DiskInterface) -> Result<Self> {
        let file = query_open_options()
            .open(&iface.path)
            .map_err(|e| WinApiError::os("open disk interface for query", e))?;
        check_is_disk(&file, iface.number)?;
        Ok(Self {
            file,
            number: iface.number,
            path: Some(iface.path.clone()),
        })
    }

    /// The disk number.
    #[must_use]
    pub fn number(&self) -> u32 {
        self.number
    }

    /// The device descriptor (spec §3.1).
    pub fn descriptor(&self) -> Result<DeviceDescriptor> {
        descriptor_of(&self.file)
    }

    /// Logical and physical sector sizes (spec §3.3), or `None` when the
    /// device does not support the query.
    pub fn sector_sizes(&self) -> Result<Option<SectorSizes>> {
        sector_sizes_of(&self.file)
    }

    /// Geometry and size (spec §4).
    pub fn geometry(&self) -> Result<Geometry> {
        geometry_of(&self.file)
    }

    /// Whether the disk is writable (spec §6; OPEN-WAPI-2).
    #[must_use]
    pub fn writability(&self) -> Writability {
        match ffi::device_io_control(&self.file, IOCTL_DISK_IS_WRITABLE, IoctlInput::None, 0) {
            Ok(_) => Writability::Writable,
            Err(f) => Writability::NotWritable {
                os_error: f.error.raw_os_error(),
            },
        }
    }

    /// The current partition layout (spec §5).
    pub fn layout(&self) -> Result<DriveLayout> {
        let max =
            layout::drive_layout_len(usize::try_from(MAX_PARTITION_ENTRIES).unwrap_or(usize::MAX));
        let mut len = layout::drive_layout_len(16);
        loop {
            match ffi::device_io_control(
                &self.file,
                IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
                IoctlInput::None,
                len,
            ) {
                Ok(b) => {
                    let raw = parse::drive_layout(&b, &layout::DRIVE_LAYOUT)
                        .map_err(|e| WinApiError::malformed("drive layout", e))?;
                    return Ok(DriveLayout::from_raw(raw));
                }
                Err(f)
                    if (is_code(&f.error, ERROR_INSUFFICIENT_BUFFER)
                        || is_code(&f.error, ERROR_MORE_DATA))
                        && len < max =>
                {
                    len = len.saturating_mul(4).min(max);
                }
                Err(f) => return Err(WinApiError::os("get drive layout", f.error)),
            }
        }
    }

    /// All of the above.
    pub fn inspect(&self) -> Result<DiskInfo> {
        Ok(DiskInfo {
            number: self.number,
            interface_path: self.path.clone(),
            descriptor: self.descriptor()?,
            sector_sizes: self.sector_sizes()?,
            geometry: self.geometry()?,
            writability: self.writability(),
            layout: self.layout()?,
        })
    }
}

/// One disk interface: its device path (spec §2) and the disk number read
/// through it (spec §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskInterface {
    /// Disk number now (not stable, spec §7).
    pub number: u32,
    /// The interface's device path, as SetupAPI returned it. Never parsed;
    /// can be reused across restarts (spec §2).
    pub path: String,
}

/// Lists the disk numbers present, in ascending order ([`interfaces`]).
pub fn enumerate() -> Result<Vec<u32>> {
    Ok(interfaces()?.into_iter().map(|i| i.number).collect())
}

/// Lists the disk interfaces present, by ascending disk number.
///
/// Uses the documented enumeration (spec §2): the present device
/// interfaces of class `GUID_DEVINTERFACE_DISK` through SetupAPI. Each
/// interface's device path is opened as-is (never parsed) with a
/// query-only handle, and its number is read with
/// `IOCTL_STORAGE_GET_DEVICE_NUMBER` (spec §7). Fails closed: an interface
/// that cannot be opened or queried, one that is not a disk, or two
/// interfaces with the same number, fail the whole enumeration rather than
/// being left out.
pub fn interfaces() -> Result<Vec<DiskInterface>> {
    let paths = ffi::disk_interface_paths(MAX_DISKS)
        .map_err(|e| WinApiError::os("enumerate disk interfaces", e))?;
    let mut found = Vec::with_capacity(paths.len());
    for units in paths {
        let path = String::from_utf16(&units).map_err(|_| WinApiError::Malformed {
            op: "disk interface path",
            source: parse::ParseError::InvalidUtf16,
        })?;
        let file = query_open_options()
            .open(&path)
            .map_err(|e| WinApiError::os("open disk interface for query", e))?;
        let dn = device_number_of(&file)?;
        if dn.device_type != FILE_DEVICE_DISK {
            return Err(WinApiError::DeviceMismatch {
                what: "disk interface is not a disk device",
            });
        }
        if found
            .iter()
            .any(|i: &DiskInterface| i.number == dn.device_number)
        {
            return Err(WinApiError::DeviceMismatch {
                what: "two disk interfaces report the same disk number",
            });
        }
        found.push(DiskInterface {
            number: dn.device_number,
            path,
        });
    }
    found.sort_unstable_by_key(|i| i.number);
    Ok(found)
}

/// Enumerates and inspects every disk, each through its interface path
/// (so [`DiskInfo::interface_path`] is set).
pub fn inspect_all() -> Result<Vec<DiskInfo>> {
    interfaces()?
        .iter()
        .map(|i| DiskQuery::open_interface(i)?.inspect())
        .collect()
}

/// One disk opened for raw reading and writing.
///
/// Open it only for the disk an authorised job names. Disk numbers are not
/// stable (spec §7), so the caller passes the size the job recorded, and
/// opening fails if the disk with that number is not a disk or has another
/// size. The caller (`usgp-disk::wipe_and_write`) re-checks identity before
/// any write. All I/O must be whole logical sectors inside the disk.
#[derive(Debug)]
pub struct RawDisk {
    file: File,
    number: u32,
    len: u64,
    logical_sector: u32,
}

impl RawDisk {
    /// Opens disk `number` for reading and writing (write-through), and
    /// checks its number, its size against `expected_size_bytes`, and that
    /// its logical sector size is 512 or 4096 (spec §3.3).
    ///
    /// Prefer [`Self::open_interface_for_write`]: a number names whichever
    /// disk has it now (spec §7).
    pub fn open_for_write(number: u32, expected_size_bytes: u64) -> Result<Self> {
        Self::open_path_for_write(&physical_drive_path(number), number, expected_size_bytes)
    }

    /// As [`Self::open_for_write`], but opens the disk by its interface's
    /// device path (spec §2), so the write handle is the enumerated device
    /// whatever its number is now; its number must still be
    /// `iface.number` (BOOT-002). Check [`Self::descriptor`] and
    /// [`Self::layout`] on the returned handle against what was confirmed.
    pub fn open_interface_for_write(
        iface: &DiskInterface,
        expected_size_bytes: u64,
    ) -> Result<Self> {
        Self::open_path_for_write(&iface.path, iface.number, expected_size_bytes)
    }

    fn open_path_for_write(path: &str, number: u32, expected_size_bytes: u64) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_WRITE_THROUGH)
            .open(path)
            .map_err(|e| WinApiError::os("open disk for write", e))?;
        check_is_disk(&file, number)?;
        let b = ffi::device_io_control(
            &file,
            IOCTL_DISK_GET_LENGTH_INFO,
            IoctlInput::None,
            layout::LENGTH_INFO_LEN,
        )
        .map_err(os("get disk length"))?;
        let len = parse::nonneg_i64_at(&b, layout::LENGTH_INFO_LENGTH)
            .map_err(|e| WinApiError::malformed("disk length", e))?;
        if len != expected_size_bytes {
            return Err(WinApiError::DeviceMismatch {
                what: "disk size differs from the job's record",
            });
        }
        let logical_sector = match sector_sizes_of(&file)? {
            Some(s) => s.logical,
            None => geometry_of(&file)?.bytes_per_sector,
        };
        if !SUPPORTED_LOGICAL_SECTORS.contains(&logical_sector) {
            return Err(WinApiError::Refused {
                reason: "unsupported logical sector size",
            });
        }
        if len == 0 || !len.is_multiple_of(u64::from(logical_sector)) {
            return Err(WinApiError::Refused {
                reason: "disk length is not a whole number of sectors",
            });
        }
        Ok(Self {
            file,
            number,
            len,
            logical_sector,
        })
    }

    /// The disk number.
    #[must_use]
    pub fn number(&self) -> u32 {
        self.number
    }

    /// Length in bytes (`IOCTL_DISK_GET_LENGTH_INFO`).
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Always false: a zero-length disk is refused at open.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Logical sector size in bytes.
    #[must_use]
    pub fn logical_sector(&self) -> u32 {
        self.logical_sector
    }

    fn check_range(&self, off: u64, len: usize) -> Result<()> {
        let sector = u64::from(self.logical_sector);
        let len = u64::try_from(len).map_err(|_| WinApiError::Refused {
            reason: "I/O length too large",
        })?;
        if !off.is_multiple_of(sector) || !len.is_multiple_of(sector) {
            return Err(WinApiError::Refused {
                reason: "I/O is not whole logical sectors",
            });
        }
        match off.checked_add(len) {
            Some(end) if end <= self.len => Ok(()),
            _ => Err(WinApiError::Refused {
                reason: "I/O past the end of the disk",
            }),
        }
    }

    /// Reads exactly `buf.len()` bytes at `off`.
    pub fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<()> {
        self.check_range(off, buf.len())?;
        let mut done = 0usize;
        while let Some(rest) = buf.get_mut(done..).filter(|r| !r.is_empty()) {
            let pos = off
                .checked_add(u64::try_from(done).unwrap_or(u64::MAX))
                .ok_or(WinApiError::Refused {
                    reason: "I/O past the end of the disk",
                })?;
            let n = self
                .file
                .seek_read(rest, pos)
                .map_err(|e| WinApiError::os("read disk", e))?;
            if n == 0 {
                return Err(WinApiError::os(
                    "read disk",
                    io::Error::from(io::ErrorKind::UnexpectedEof),
                ));
            }
            done = done.saturating_add(n);
        }
        Ok(())
    }

    /// Writes all of `data` at `off`.
    pub fn write_at(&mut self, off: u64, data: &[u8]) -> Result<()> {
        self.check_range(off, data.len())?;
        let mut done = 0usize;
        while let Some(rest) = data.get(done..).filter(|r| !r.is_empty()) {
            let pos = off
                .checked_add(u64::try_from(done).unwrap_or(u64::MAX))
                .ok_or(WinApiError::Refused {
                    reason: "I/O past the end of the disk",
                })?;
            let n = self
                .file
                .seek_write(rest, pos)
                .map_err(|e| WinApiError::os("write disk", e))?;
            if n == 0 {
                return Err(WinApiError::os(
                    "write disk",
                    io::Error::from(io::ErrorKind::WriteZero),
                ));
            }
            done = done.saturating_add(n);
        }
        Ok(())
    }

    /// Flushes buffered writes to the device.
    pub fn flush(&mut self) -> Result<()> {
        self.file
            .sync_all()
            .map_err(|e| WinApiError::os("flush disk", e))
    }

    /// `IOCTL_DISK_UPDATE_PROPERTIES`: makes Windows discard its cached
    /// partition table and re-read the disk, after the table was written
    /// directly (spec §5).
    pub fn update_properties(&mut self) -> Result<()> {
        ffi::device_io_control(
            &self.file,
            IOCTL_DISK_UPDATE_PROPERTIES,
            IoctlInput::None,
            0,
        )
        .map(|_| ())
        .map_err(os("update disk properties"))
    }

    /// The layout Windows now reports for this disk (spec §5), queried on
    /// this handle.
    pub fn layout(&self) -> Result<DriveLayout> {
        DiskQuery {
            file: self
                .file
                .try_clone()
                .map_err(|e| WinApiError::os("duplicate disk handle", e))?,
            number: self.number,
            path: None,
        }
        .layout()
    }

    /// The device descriptor (spec §3.1), queried on this handle, so the
    /// identity checked is that of the device being written (BOOT-002).
    pub fn descriptor(&self) -> Result<DeviceDescriptor> {
        descriptor_of(&self.file)
    }
}
