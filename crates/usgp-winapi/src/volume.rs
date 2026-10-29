//! Volumes: enumeration, the disks and offsets they occupy, drive letters,
//! and the file system on each.
//!
//! The plan resolves a new partition's volume by matching both the disk
//! number and the starting offset of its extent (plan §1.2(c) step 2);
//! [`disk_extents`] and [`volumes_with_extents`] supply that.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - names validated
//   before use; CM-7 (Least Functionality) - query-only volume handles
// - SPEC: specs/standards/windows-storage-firmware-api.md §7, §8, §15
// - DECISION: docs/decisions/0019-windows-api-binding.md

use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;

use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_SHARE_READ, FILE_SHARE_WRITE, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
};
use windows_sys::Win32::System::Ioctl::{FSCTL_DISMOUNT_VOLUME, FSCTL_LOCK_VOLUME};
use windows_sys::Win32::System::WindowsProgramming::{
    DRIVE_CDROM, DRIVE_FIXED, DRIVE_NO_ROOT_DIR, DRIVE_RAMDISK, DRIVE_REMOTE, DRIVE_REMOVABLE,
    DRIVE_UNKNOWN,
};

use crate::error::{Result, WinApiError};
use crate::ffi::{self, IoctlInput};
use crate::layout;
use crate::parse::{self, DiskExtent, MAX_VOLUME_EXTENTS, from_wide, split_multi_sz, to_wide_nul};
use crate::paths::{DriveLetter, VolumeGuidPath};

/// Most volumes listed.
pub const MAX_VOLUMES: usize = 4096;
/// Longest mount-point list accepted (UTF-16 units).
pub const MAX_MOUNT_POINT_UNITS: usize = 64 * 1024;

fn wide(s: &str) -> Result<Vec<u16>> {
    to_wide_nul(s).ok_or(WinApiError::Refused {
        reason: "name contains NUL",
    })
}

fn volume_from_units(op: &'static str, units: &[u16]) -> Result<VolumeGuidPath> {
    let s = from_wide(units).map_err(|e| WinApiError::malformed(op, e))?;
    VolumeGuidPath::parse(&s).ok_or(WinApiError::Malformed {
        op,
        source: parse::ParseError::InvalidUtf16,
    })
}

/// Lists every volume GUID path (spec §8). The order has no meaning.
pub fn volumes() -> Result<Vec<VolumeGuidPath>> {
    ffi::find_volumes(MAX_VOLUMES)
        .map_err(|e| WinApiError::os("enumerate volumes", e))?
        .iter()
        .map(|u| volume_from_units("volume name", u))
        .collect()
}

/// The disk extents of `volume` (spec §8). Opens the volume device with no
/// read or write access. Retries once with room for the reported count
/// when the volume spans several extents (`ERROR_MORE_DATA`).
pub fn disk_extents(volume: &VolumeGuidPath) -> Result<Vec<DiskExtent>> {
    let file = OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(volume.device_path())
        .map_err(|e| WinApiError::os("open volume for query", e))?;
    let first_len = parse::extents_len(&layout::EXTENTS, 1)
        .map_err(|e| WinApiError::malformed("volume extents", e))?;
    let bytes = match ffi::device_io_control(
        &file,
        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
        IoctlInput::None,
        first_len,
    ) {
        Ok(b) => b,
        Err(f)
            if f.error
                .raw_os_error()
                .and_then(|c| u32::try_from(c).ok())
                .is_some_and(|c| c == ERROR_MORE_DATA) =>
        {
            let count = parse::extent_count(&f.partial, &layout::EXTENTS).map_err(|_| {
                WinApiError::LimitExceeded {
                    what: "volume extent count",
                    limit: u64::from(MAX_VOLUME_EXTENTS),
                }
            })?;
            let len = parse::extents_len(&layout::EXTENTS, count)
                .map_err(|e| WinApiError::malformed("volume extents", e))?;
            ffi::device_io_control(
                &file,
                IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                IoctlInput::None,
                len,
            )
            .map_err(|f| WinApiError::os("get volume extents", f.error))?
        }
        Err(f) => return Err(WinApiError::os("get volume extents", f.error)),
    };
    parse::disk_extents(&bytes, &layout::EXTENTS)
        .map_err(|e| WinApiError::malformed("volume extents", e))
}

/// Every volume with its extents. A volume whose extents cannot be read
/// (for example a device with no media) is listed with the error, not left
/// out, so the caller decides; a caller checking whether a disk is in use
/// must treat an error as "may be on this disk".
pub fn volumes_with_extents() -> Result<Vec<(VolumeGuidPath, Result<Vec<DiskExtent>>)>> {
    Ok(volumes()?
        .into_iter()
        .map(|v| {
            let e = disk_extents(&v);
            (v, e)
        })
        .collect())
}

/// The mount points (drive letters and folders) of `volume`.
pub fn mount_points(volume: &VolumeGuidPath) -> Result<Vec<String>> {
    let units = ffi::volume_path_names(&wide(volume.as_str())?, MAX_MOUNT_POINT_UNITS)
        .map_err(|e| WinApiError::os("get volume mount points", e))?;
    split_multi_sz(&units).map_err(|e| WinApiError::malformed("volume mount points", e))
}

/// The drive letters of `volume`.
pub fn drive_letters(volume: &VolumeGuidPath) -> Result<Vec<DriveLetter>> {
    Ok(mount_points(volume)?
        .iter()
        .filter_map(|m| DriveLetter::from_root(m))
        .collect())
}

/// The volume mounted at `letter` (`GetVolumeNameForVolumeMountPoint`,
/// spec §8).
pub fn volume_at(letter: DriveLetter) -> Result<VolumeGuidPath> {
    let units = ffi::volume_name_for_mount_point(&wide(&letter.root())?)
        .map_err(|e| WinApiError::os("get volume at mount point", e))?;
    volume_from_units("volume name", &units)
}

/// `true` unless every check finds nothing at `letter` (fail closed):
///
/// - `GetVolumeNameForVolumeMountPoint` names a volume there (§8);
/// - `GetDriveType` on the letter's root does not report
///   `DRIVE_NO_ROOT_DIR`, "no volume mounted" (§25), or fails;
/// - it is the Windows PE system letter.
///
/// Two queries rather than one: on the CI runner a letter just given to a
/// new volume was not seen as taken by the first query alone, and the
/// next assignment of that letter failed (BOOT-004, CI run 40910029759;
/// the pages do not say how soon a new mount point is visible to each
/// query). Callers also exclude the letters they assigned themselves.
#[must_use]
pub fn letter_in_use(letter: DriveLetter) -> bool {
    if letter == DriveLetter::PE_SYSTEM || volume_at(letter).is_ok() {
        return true;
    }
    match wide(&letter.root()).ok().map(|w| ffi::drive_type(&w)) {
        Some(Ok(t)) => DriveType::from_raw(t) != DriveType::NoRootDir,
        _ => true,
    }
}

/// Every drive letter any volume reports (`GetVolumePathNamesForVolumeName`,
/// §15). Volumes whose list cannot be read are skipped; callers combine
/// this with [`letter_in_use`].
///
/// # Errors
///
/// The volume enumeration failed.
pub fn letters_in_use() -> Result<Vec<DriveLetter>> {
    let mut out = Vec::new();
    for v in volumes()? {
        if let Ok(ls) = drive_letters(&v) {
            out.extend(ls);
        }
    }
    Ok(out)
}

/// The first letter of `order` that is free: not in `taken` (letters the
/// caller has assigned or reserved), not reported by any volume
/// ([`letters_in_use`]), and not [`letter_in_use`]. Never `X:`.
///
/// # Errors
///
/// The volume enumeration failed.
pub fn free_letter(
    order: impl IntoIterator<Item = char>,
    taken: &[DriveLetter],
) -> Result<Option<DriveLetter>> {
    let reported = letters_in_use()?;
    Ok(order.into_iter().filter_map(DriveLetter::new).find(|l| {
        *l != DriveLetter::PE_SYSTEM
            && !taken.contains(l)
            && !reported.contains(l)
            && !letter_in_use(*l)
    }))
}

/// Gives `volume` the drive letter `letter` (`SetVolumeMountPoint`, spec
/// §8). The Windows PE system letter `X:` is refused (plan §1.2(c)).
pub fn assign_letter(letter: DriveLetter, volume: &VolumeGuidPath) -> Result<()> {
    if letter == DriveLetter::PE_SYSTEM {
        return Err(WinApiError::Refused {
            reason: "the Windows PE system letter is never assigned",
        });
    }
    ffi::set_volume_mount_point(&wide(&letter.root())?, &wide(volume.as_str())?)
        .map_err(|e| WinApiError::os("set volume mount point", e))
}

/// Removes the drive letter `letter`. The Windows PE system letter `X:` is
/// refused.
pub fn remove_letter(letter: DriveLetter) -> Result<()> {
    if letter == DriveLetter::PE_SYSTEM {
        return Err(WinApiError::Refused {
            reason: "the Windows PE system letter is never removed",
        });
    }
    ffi::delete_volume_mount_point(&wide(&letter.root())?)
        .map_err(|e| WinApiError::os("delete volume mount point", e))
}

/// The file-system name of `volume` (for example `NTFS` or `FAT32`), used
/// to check a format result (plan §1.2(c) step 5).
pub fn file_system_name(volume: &VolumeGuidPath) -> Result<String> {
    let units = ffi::volume_file_system_name(&wide(volume.as_str())?)
        .map_err(|e| WinApiError::os("get volume information", e))?;
    from_wide(&units).map_err(|e| WinApiError::malformed("file system name", e))
}

/// The label of `volume` (empty if it has none), used to check a format
/// result (plan §1.2(c) step 5; topic 23 §15 `GetVolumeInformation`).
pub fn label(volume: &VolumeGuidPath) -> Result<String> {
    let units = ffi::volume_label(&wide(volume.as_str())?)
        .map_err(|e| WinApiError::os("get volume label", e))?;
    from_wide(&units).map_err(|e| WinApiError::malformed("volume label", e))
}

/// A volume locked for exclusive use and dismounted. The lock lasts while
/// this value lives: dropping it closes the handle, which releases the
/// lock.
#[derive(Debug)]
pub struct LockedVolume {
    _file: File,
    volume: VolumeGuidPath,
}

impl LockedVolume {
    /// The locked volume.
    #[must_use]
    pub fn volume(&self) -> &VolumeGuidPath {
        &self.volume
    }
}

/// Locks `volume` (`FSCTL_LOCK_VOLUME`) and then dismounts it
/// (`FSCTL_DISMOUNT_VOLUME`), keeping the handle open.
///
/// Fails closed: if the lock is refused (for example because files are
/// open on the volume) nothing is dismounted and the error is returned; a
/// failed dismount is also an error. Nothing is ever forced.
///
/// Spec §14: the lock fails if any file on the volume is open, and lasts
/// until the handle is closed; dismount alone would not stop the volume
/// being mounted again, so the lock is taken first and held. The errors
/// for "in use" are not named (OPEN-WAPI-5); any failure is an error.
pub fn lock_and_dismount(volume: &VolumeGuidPath) -> Result<LockedVolume> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(volume.device_path())
        .map_err(|e| WinApiError::os("open volume for lock", e))?;
    ffi::device_io_control(&file, FSCTL_LOCK_VOLUME, IoctlInput::None, 0)
        .map_err(|f| WinApiError::os("lock volume", f.error))?;
    ffi::device_io_control(&file, FSCTL_DISMOUNT_VOLUME, IoctlInput::None, 0)
        .map_err(|f| WinApiError::os("dismount volume", f.error))?;
    Ok(LockedVolume {
        _file: file,
        volume: volume.clone(),
    })
}

/// What `GetDriveType` reports for a volume (spec §13; all values are
/// `windows-sys` constants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveType {
    /// `DRIVE_UNKNOWN`.
    Unknown,
    /// `DRIVE_NO_ROOT_DIR` (nothing mounted there).
    NoRootDir,
    /// `DRIVE_REMOVABLE`.
    Removable,
    /// `DRIVE_FIXED`.
    Fixed,
    /// `DRIVE_REMOTE` (network).
    Remote,
    /// `DRIVE_CDROM`.
    CdRom,
    /// `DRIVE_RAMDISK`.
    RamDisk,
    /// Any other value, raw.
    Other(u32),
}

impl DriveType {
    /// Maps a raw value.
    #[must_use]
    pub fn from_raw(v: u32) -> Self {
        match v {
            DRIVE_UNKNOWN => Self::Unknown,
            DRIVE_NO_ROOT_DIR => Self::NoRootDir,
            DRIVE_REMOVABLE => Self::Removable,
            DRIVE_FIXED => Self::Fixed,
            DRIVE_REMOTE => Self::Remote,
            DRIVE_CDROM => Self::CdRom,
            DRIVE_RAMDISK => Self::RamDisk,
            other => Self::Other(other),
        }
    }

    /// RAM disk, optical or network: documented as not a local disk
    /// volume (spec §13), so its extents are not asked for.
    #[must_use]
    pub fn is_not_disk_backed(self) -> bool {
        matches!(self, Self::RamDisk | Self::CdRom | Self::Remote)
    }
}

/// The drive type of `volume`, from its root path (the volume GUID path,
/// which ends in a backslash as spec §13 requires).
pub fn drive_type(volume: &VolumeGuidPath) -> Result<DriveType> {
    ffi::drive_type(&wide(volume.as_str())?)
        .map(DriveType::from_raw)
        .map_err(|e| WinApiError::os("get drive type", e))
}

/// Where a volume lives.
#[derive(Debug)]
pub enum VolumeBacking {
    /// RAM disk, optical or network (spec §13): on no local disk.
    NotDiskBacked(DriveType),
    /// A fixed or removable volume and its extents.
    OnDisks(Vec<DiskExtent>),
    /// It could not be established: a fixed or removable volume whose
    /// extents could not be read, or any other drive type. Callers must
    /// treat the volume as possibly on every disk (fail closed;
    /// REQ-DISK-005, DEC-0018 item 8).
    Undetermined {
        /// The drive type, if it could be read.
        drive_type: Option<DriveType>,
        /// Why.
        error: Option<WinApiError>,
    },
}

/// Classifies `volume`: drive type first, and extents only for fixed and
/// removable volumes (SR-3b, spec §13).
#[must_use]
pub fn backing(volume: &VolumeGuidPath) -> VolumeBacking {
    let dt = match drive_type(volume) {
        Ok(dt) => dt,
        Err(e) => {
            return VolumeBacking::Undetermined {
                drive_type: None,
                error: Some(e),
            };
        }
    };
    if dt.is_not_disk_backed() {
        return VolumeBacking::NotDiskBacked(dt);
    }
    if !matches!(dt, DriveType::Fixed | DriveType::Removable) {
        return VolumeBacking::Undetermined {
            drive_type: Some(dt),
            error: None,
        };
    }
    match disk_extents(volume) {
        Ok(e) => VolumeBacking::OnDisks(e),
        Err(e) => VolumeBacking::Undetermined {
            drive_type: Some(dt),
            error: Some(e),
        },
    }
}

/// Every volume with its backing.
pub fn volume_backings() -> Result<Vec<(VolumeGuidPath, VolumeBacking)>> {
    Ok(volumes()?
        .into_iter()
        .map(|v| {
            let b = backing(&v);
            (v, b)
        })
        .collect())
}

/// The volumes on disk `disk_number`.
///
/// Fails closed with [`WinApiError::Refused`] if any volume's backing is
/// undetermined: such a volume might lie on this disk (for example the
/// boot environment), so the disk must not be shown eligible or wiped
/// (REQ-DISK-005, DEC-0018 item 8).
pub fn volumes_on_disk(disk_number: u32) -> Result<Vec<VolumeGuidPath>> {
    let mut out = Vec::new();
    for (v, b) in volume_backings()? {
        match b {
            VolumeBacking::NotDiskBacked(_) => {}
            VolumeBacking::OnDisks(e) => {
                if e.iter().any(|x| x.disk_number == disk_number) {
                    out.push(v);
                }
            }
            VolumeBacking::Undetermined { .. } => {
                return Err(WinApiError::Refused {
                    reason: "a volume's disk could not be determined",
                });
            }
        }
    }
    Ok(out)
}

/// Locks and dismounts every volume on disk `disk_number` before it is
/// wiped ([`volumes_on_disk`], then [`lock_and_dismount`] each).
///
/// Fails closed, releasing any locks already taken, if any volume's
/// backing is undetermined or any lock or dismount fails. The returned
/// locks must be kept until the layout has been written and the disk's
/// properties updated.
pub fn lock_volumes_on_disk(disk_number: u32) -> Result<Vec<LockedVolume>> {
    volumes_on_disk(disk_number)?
        .iter()
        .map(lock_and_dismount)
        .collect()
}
