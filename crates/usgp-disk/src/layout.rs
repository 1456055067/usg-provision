//! Microsoft's recommended UEFI layout for Windows (REQ-DISK-008).
//!
//! In LBA order: ESP (FAT32), MSR (unformatted), Windows (NTFS, the rest
//! of the disk), recovery (NTFS, immediately after Windows). Every
//! partition starts on a 1 MiB boundary (REQ-DISK-010). Nothing else is
//! created.
//!
//! Sizes stated in MB/GB by Microsoft are taken here as binary MiB/GiB:
//! the minimums ("at least 200 MB", "at least 990 MB", "at least 20 GB")
//! are then met under either reading, and every size stays a whole number
//! of 1 MiB alignment units. The exact MSR size ("16 MB") becomes 16 MiB
//! (unspecified unit, noted in impl-notes-wu3.md). The disk minimum is
//! 64 × 10⁹ bytes as the plan states (§3.9).
//!
//! Space reserve (decision 0023 item 3, BOOT-003): an image fits only if
//! the Windows partition holds its expanded size, plus a file-system
//! overhead estimate, plus the 16 GB that must stay free after setup
//! (`gpt.md` §10). [`windows_bytes_needed`] is that one formula; the disk
//! minimum ([`minimum_disk_bytes`]) and the apply budget checked before the
//! wipe ([`image_budget_bytes`]) are both derived from it.

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 (Configuration Settings) - fixed, documented layout
// - SPEC: specs/disk.md#REQ-DISK-004, #REQ-DISK-008, #REQ-DISK-009,
//   #REQ-DISK-010; specs/progress.md#REQ-JOB-008
// - specs/standards/gpt.md §8, §9, §10, §13
// - DECISION: docs/decisions/0023 item 3 (space reserve)

use crate::eligibility::{DiskFacts, sector_sizes_supported};
use crate::error::{GptError, LayoutError};
use crate::gpt::{GptPlan, NAME_UNITS, PartitionEntry};
use crate::guid::{Guid, types};

/// FORMAT: gpt.md §8 - 1 MiB.
const MIB: u64 = 1 << 20;
/// FORMAT: gpt.md §8, REQ-DISK-010 - every partition starts on a 1 MiB
/// boundary.
pub const ALIGN_BYTES: u64 = MIB;
/// FORMAT: gpt.md §10, REQ-DISK-008 item 1 - ESP 200 MB on 512-byte
/// logical-sector disks (512n and 512e), as 200 MiB.
pub const ESP_BYTES_512: u64 = 200 * MIB;
/// FORMAT: gpt.md §10, REQ-DISK-008 item 1 - ESP 300 MB on 4K-native
/// disks, as 300 MiB.
pub const ESP_BYTES_4KN: u64 = 300 * MIB;
/// FORMAT: gpt.md §10, REQ-DISK-008 item 2 - MSR 16 MB, as 16 MiB.
pub const MSR_BYTES: u64 = 16 * MIB;
/// FORMAT: gpt.md §10, REQ-DISK-008 item 4 - at least 250 MB free in the
/// recovery partition beyond the recovery image, as 250 MiB.
pub const RECOVERY_FREE_BYTES: u64 = 250 * MIB;
/// FORMAT: gpt.md §10, REQ-DISK-008 item 4 - Microsoft recommends at
/// least 990 MB in total, as 990 MiB.
pub const RECOVERY_MIN_BYTES: u64 = 990 * MIB;
/// FORMAT: gpt.md §10 - Windows partition at least 20 GB for 64-bit, as
/// 20 GiB.
pub const WINDOWS_MIN_BYTES: u64 = 20 * 1024 * MIB;
/// FORMAT: gpt.md §13, REQ-DISK-004, plan §3.9 - Windows 11 needs 64 GB of
/// storage: 64 × 10⁹ bytes. Fixed (OPEN-DISK-1).
pub const MIN_DISK_BYTES: u64 = 64_000_000_000;
/// FORMAT: gpt.md §10 - the Windows partition must keep 16 GB free after
/// first-run setup and maintenance; as 16 GiB, like the other sizes here
/// (decision 0023 item 3).
pub const WINDOWS_FREE_BYTES: u64 = 16 * 1024 * MIB;
/// Design value (project design, decision 0023 item 3; not from a
/// standard or a measurement): the file-system overhead estimate is the
/// expanded image size divided by this, rounded up. That is 10 %, meant
/// to cover the file system's own structures and the space lost to
/// rounding each file up to whole clusters. No source we hold gives
/// NTFS's real overhead; the estimate is checked by the Windows CI disk
/// job and MT-2 (POAM, below).
pub const FS_OVERHEAD_DIVISOR: u64 = 10;
/// Design value (project design, decision 0023 item 3): the smallest file-
/// system overhead estimate, 1 GiB, so that a small image still leaves
/// room for the file system's fixed structures.
pub const FS_OVERHEAD_MIN_BYTES: u64 = 1024 * MIB;
/// Design limit (not from a standard): the recovery image size accepted,
/// 64 GiB. Real recovery images are far smaller; this only keeps the
/// arithmetic bounded.
pub const MAX_RECOVERY_IMAGE_BYTES: u64 = 64 * 1024 * MIB;
/// Room reserved at the end of the disk in [`minimum_disk_bytes`]: the
/// backup GPT (16 KiB array + one header block) plus up to 1 MiB lost to
/// aligning the recovery start down. 2 MiB covers both for 512 and 4096.
const TAIL_RESERVE_BYTES: u64 = 2 * MIB;

/// FORMAT: gpt.md §9, §5 - attribute bit 0, platform required.
pub const ATTR_PLATFORM_REQUIRED: u64 = 0x0000_0000_0000_0001;
/// FORMAT: gpt.md §9 - no drive letter by default.
pub const ATTR_NO_DRIVE_LETTER: u64 = 0x8000_0000_0000_0000;
/// FORMAT: gpt.md §10, REQ-DISK-008 item 4 - recovery attributes
/// `0x8000000000000001` (platform required + no drive letter).
pub const RECOVERY_ATTRIBUTES: u64 = ATTR_NO_DRIVE_LETTER | ATTR_PLATFORM_REQUIRED;

/// What a partition is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PartRole {
    /// EFI system partition, FAT32.
    Esp,
    /// Microsoft reserved, unformatted.
    Msr,
    /// Windows, NTFS.
    Windows,
    /// Recovery, NTFS.
    Recovery,
}

/// One planned partition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Part {
    /// Role.
    pub role: PartRole,
    /// GPT partition number (1-based; slot + 1).
    pub number: u32,
    /// PartitionTypeGUID (`gpt.md` §9).
    pub type_guid: Guid,
    /// New random UniquePartitionGUID.
    pub unique_guid: Guid,
    /// StartingLBA.
    pub first_lba: u64,
    /// EndingLBA, inclusive.
    pub last_lba: u64,
    /// Attributes.
    pub attributes: u64,
}

impl Part {
    /// Length in LBAs.
    #[must_use]
    pub fn len_lbas(&self) -> u64 {
        self.last_lba
            .saturating_sub(self.first_lba)
            .saturating_add(1)
    }

    fn entry(&self) -> PartitionEntry {
        PartitionEntry {
            type_guid: self.type_guid,
            unique_guid: self.unique_guid,
            first_lba: self.first_lba,
            last_lba: self.last_lba,
            attributes: self.attributes,
            // Names are not specified (gpt.md §5 allows an empty name);
            // left empty (impl-notes-wu3.md).
            name: [0; NAME_UNITS],
        }
    }
}

/// The planned layout for one disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsUefiLayout {
    /// Logical block size.
    pub block: u32,
    /// Disk size in logical blocks.
    pub total_lbas: u64,
    /// New random DiskGUID.
    pub disk_guid: Guid,
    /// Partition 1.
    pub esp: Part,
    /// Partition 2.
    pub msr: Part,
    /// Partition 3.
    pub windows: Part,
    /// Partition 4.
    pub recovery: Part,
}

/// Rounds up to a whole MiB; `None` on overflow.
fn round_up_mib(n: u64) -> Option<u64> {
    n.checked_next_multiple_of(MIB)
}

/// Recovery partition size for a recovery image of `recovery_bytes`:
/// the image plus 250 MiB free, at least 990 MiB, rounded up to 1 MiB
/// (REQ-DISK-008 item 4).
///
/// # Errors
/// [`LayoutError::RecoveryTooLarge`] above [`MAX_RECOVERY_IMAGE_BYTES`].
pub fn recovery_partition_bytes(recovery_bytes: u64) -> Result<u64, LayoutError> {
    if recovery_bytes > MAX_RECOVERY_IMAGE_BYTES {
        return Err(LayoutError::RecoveryTooLarge(recovery_bytes));
    }
    recovery_bytes
        .checked_add(RECOVERY_FREE_BYTES)
        .map(|n| n.max(RECOVERY_MIN_BYTES))
        .and_then(round_up_mib)
        .ok_or(LayoutError::RecoveryTooLarge(recovery_bytes))
}

/// ESP size for a logical sector size (REQ-DISK-008 item 1).
#[must_use]
pub fn esp_bytes(logical_sector: u32) -> u64 {
    if logical_sector == 4096 {
        ESP_BYTES_4KN
    } else {
        ESP_BYTES_512
    }
}

/// The file-system overhead estimate for an image that expands to
/// `image_bytes`: a tenth of it, rounded up, and at least 1 GiB
/// ([`FS_OVERHEAD_DIVISOR`], [`FS_OVERHEAD_MIN_BYTES`]; project design,
/// decision 0023 item 3).
// POAM: the file-system overhead estimate (10 %, at least 1 GiB) is a
// project design value, not a measured or published NTFS figure; confirm
// it against the free space left after a real apply (Windows CI disk job,
// MT-2) and adjust (BOOT-003).
#[must_use]
pub fn fs_overhead_bytes(image_bytes: u64) -> u64 {
    image_bytes
        .div_ceil(FS_OVERHEAD_DIVISOR)
        .max(FS_OVERHEAD_MIN_BYTES)
}

/// The Windows partition size an image that expands to `image_bytes`
/// needs: the image, plus [`fs_overhead_bytes`], plus [`WINDOWS_FREE_BYTES`]
/// free, rounded up to 1 MiB, and never less than [`WINDOWS_MIN_BYTES`]
/// (decision 0023 item 3, `gpt.md` §10).
///
/// This is the one space formula: [`minimum_disk_bytes`] and
/// [`image_budget_bytes`] both use it.
///
/// # Errors
/// [`LayoutError::TooSmall`] with `min = u64::MAX` if the sum overflows.
pub fn windows_bytes_needed(image_bytes: u64) -> Result<u64, LayoutError> {
    image_bytes
        .checked_add(fs_overhead_bytes(image_bytes))
        .and_then(|n| n.checked_add(WINDOWS_FREE_BYTES))
        .and_then(round_up_mib)
        .map(|n| n.max(WINDOWS_MIN_BYTES))
        .ok_or(LayoutError::TooSmall {
            size: 0,
            min: u64::MAX,
        })
}

/// The largest expanded image size that fits a Windows partition of
/// `windows_bytes` under [`windows_bytes_needed`]: the apply budget checked
/// before the wipe (decision 0023 item 3). `None` if not even an empty
/// image fits.
///
/// Found by a bisection over the same formula, so an image fits the budget
/// exactly when [`windows_bytes_needed`] for it is at most
/// `windows_bytes`.
#[must_use]
pub fn image_budget_bytes(windows_bytes: u64) -> Option<u64> {
    let fits = |i: u64| windows_bytes_needed(i).is_ok_and(|n| n <= windows_bytes);
    if !fits(0) {
        return None;
    }
    // Invariant: lo fits, and nothing above hi fits (an image larger than
    // the partition never does).
    let (mut lo, mut hi) = (0u64, windows_bytes);
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if fits(mid) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    Some(lo)
}

/// The smallest disk the layout fits on with the chosen image: the larger
/// of 64 × 10⁹ bytes and the whole layout with a Windows partition of
/// [`windows_bytes_needed`] for `image_bytes` expanded (REQ-DISK-004,
/// decision 0023 item 3).
///
/// # Errors
/// [`LayoutError::RecoveryTooLarge`] for an out-of-range recovery image;
/// [`LayoutError::TooSmall`] with `min = u64::MAX` if the sum overflows.
pub fn minimum_disk_bytes(
    logical_sector: u32,
    recovery_bytes: u64,
    image_bytes: u64,
) -> Result<u64, LayoutError> {
    let recovery = recovery_partition_bytes(recovery_bytes)?;
    let windows = windows_bytes_needed(image_bytes)?;
    let sum = [
        esp_bytes(logical_sector),
        MSR_BYTES,
        windows,
        recovery,
        TAIL_RESERVE_BYTES,
    ]
    .into_iter()
    .try_fold(ALIGN_BYTES, u64::checked_add)
    .ok_or(LayoutError::TooSmall {
        size: 0,
        min: u64::MAX,
    })?;
    Ok(sum.max(MIN_DISK_BYTES))
}

impl WindowsUefiLayout {
    /// Plans the layout for `f`, with a recovery partition sized for a
    /// recovery image of `recovery_bytes`. GUIDs come from `rng` (the FIPS
    /// DRBG through `usgp-crypto`; plan §5).
    ///
    /// The caller has already applied [`crate::assess`]; this re-checks the
    /// sector sizes and the 64 GB / 20 GiB minimums so that no layout can be
    /// produced for an unsupported disk.
    ///
    /// # Errors
    /// [`LayoutError`] for unsupported sectors, a size that is not whole
    /// sectors, a disk that is too small, or a bad random source.
    pub fn compute(
        f: &DiskFacts,
        recovery_bytes: u64,
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Result<Self, LayoutError> {
        let (logical, physical) = (f.logical_sector, f.physical_sector);
        if !sector_sizes_supported(logical, physical) {
            return Err(LayoutError::UnsupportedSectorSize { logical, physical });
        }
        let block = u64::from(logical);
        let size = f.size_bytes;
        if !size.is_multiple_of(block) {
            return Err(LayoutError::UnalignedSize(size));
        }
        let too_small = |min| LayoutError::TooSmall { size, min };
        if size < MIN_DISK_BYTES {
            return Err(too_small(MIN_DISK_BYTES));
        }
        let total_lbas = size / block;
        let rec_part_bytes = recovery_partition_bytes(recovery_bytes)?;

        // A probe plan gives the usable range for this geometry.
        let (first_usable, last_usable) = probe_usable(logical, total_lbas)?;

        let align = ALIGN_BYTES / block;
        let lbas = |bytes: u64| bytes / block;
        let esp_first = align;
        if esp_first < first_usable {
            return Err(too_small(MIN_DISK_BYTES));
        }
        let esp_last = esp_first + lbas(esp_bytes(logical)) - 1;
        let msr_first = esp_last + 1;
        let msr_last = msr_first + lbas(MSR_BYTES) - 1;
        let win_first = msr_last + 1;
        let rec_lbas = lbas(rec_part_bytes);
        // Recovery ends at or before LastUsableLBA and starts aligned.
        let rec_first = (last_usable + 1)
            .checked_sub(rec_lbas)
            .map(|s| s - s % align)
            .ok_or_else(|| too_small(MIN_DISK_BYTES))?;
        let rec_last = rec_first + rec_lbas - 1;
        let win_last = rec_first
            .checked_sub(1)
            .filter(|&l| l >= win_first)
            .ok_or_else(|| too_small(MIN_DISK_BYTES))?;
        let win_bytes = (win_last - win_first + 1) * block;
        if win_bytes < WINDOWS_MIN_BYTES {
            let min = minimum_disk_bytes(logical, recovery_bytes, 0).unwrap_or(u64::MAX);
            return Err(too_small(min));
        }

        // New random GUIDs: disk + 4 partitions, all distinct (REQ-DISK-009).
        let guids: Vec<Guid> = (0..5).map(|_| Guid::random(rng)).collect();
        let distinct = guids
            .iter()
            .enumerate()
            .all(|(i, g)| !g.is_nil() && guids.iter().skip(i + 1).all(|h| h != g));
        let [disk_guid, g1, g2, g3, g4] = guids.as_slice() else {
            return Err(LayoutError::BadRandom);
        };
        if !distinct {
            return Err(LayoutError::BadRandom);
        }

        let part = |role, number, type_guid, unique_guid, first_lba, last_lba, attributes| Part {
            role,
            number,
            type_guid,
            unique_guid,
            first_lba,
            last_lba,
            attributes,
        };
        let layout = Self {
            block: logical,
            total_lbas,
            disk_guid: *disk_guid,
            esp: part(PartRole::Esp, 1, types::ESP, *g1, esp_first, esp_last, 0),
            msr: part(PartRole::Msr, 2, types::MSR, *g2, msr_first, msr_last, 0),
            windows: part(
                PartRole::Windows,
                3,
                types::BASIC_DATA,
                *g3,
                win_first,
                win_last,
                0,
            ),
            recovery: part(
                PartRole::Recovery,
                4,
                types::RECOVERY,
                *g4,
                rec_first,
                rec_last,
                RECOVERY_ATTRIBUTES,
            ),
        };
        // Final cross-check through the GPT rules (range, overlap, GUIDs).
        layout.gpt_plan().map_err(|_| LayoutError::BadRandom)?;
        Ok(layout)
    }

    /// The four partitions in order.
    #[must_use]
    pub fn parts(&self) -> [&Part; 4] {
        [&self.esp, &self.msr, &self.windows, &self.recovery]
    }

    /// Disk size in bytes.
    #[must_use]
    pub fn disk_bytes(&self) -> u64 {
        self.total_lbas.saturating_mul(u64::from(self.block))
    }

    /// Windows partition size in bytes.
    #[must_use]
    pub fn windows_bytes(&self) -> u64 {
        self.windows
            .len_lbas()
            .saturating_mul(u64::from(self.block))
    }

    /// The largest expanded image this layout takes with the space reserve:
    /// the apply budget checked before the wipe (plan §3.7; decision 0023
    /// item 3, BOOT-003). `None` if not even an empty image fits.
    ///
    /// An image fits exactly when both hold:
    ///
    /// - [`windows_bytes_needed`] for it is at most [`Self::windows_bytes`];
    /// - [`minimum_disk_bytes`] for it, with this layout's sector size and
    ///   recovery partition, is at most [`Self::disk_bytes`].
    ///
    /// The second is the disk-size check the engine makes before the wipe,
    /// so an image within this budget never passes the content check and
    /// is then refused for the disk size. `minimum_disk_bytes` allows for
    /// the backup GPT and alignment with a fixed reserve, so the second
    /// bound is at most a few MiB below the first.
    #[must_use]
    pub fn image_budget_bytes(&self) -> Option<u64> {
        let block = u64::from(self.block);
        let part = |p: &Part| p.len_lbas().saturating_mul(block);
        let fixed = [
            part(&self.esp),
            part(&self.msr),
            part(&self.recovery),
            TAIL_RESERVE_BYTES,
        ]
        .into_iter()
        .try_fold(ALIGN_BYTES, u64::checked_add)?;
        let for_windows = self
            .disk_bytes()
            .checked_sub(fixed)?
            .min(self.windows_bytes());
        image_budget_bytes(for_windows)
    }

    /// The GPT to write for this layout.
    ///
    /// # Errors
    /// [`GptError`] if the layout breaks a GPT rule (not reachable for a
    /// layout from [`WindowsUefiLayout::compute`]).
    pub fn gpt_plan(&self) -> Result<GptPlan, GptError> {
        GptPlan::new(
            self.block,
            self.total_lbas,
            self.disk_guid,
            self.parts().iter().map(|p| p.entry()).collect(),
        )
    }
}

/// Usable range of our GPT geometry for this disk.
fn probe_usable(block: u32, total_lbas: u64) -> Result<(u64, u64), LayoutError> {
    // A non-nil placeholder GUID; the probe plan is discarded.
    let probe = Guid([1; 16]);
    GptPlan::new(block, total_lbas, probe, Vec::new())
        .map(|p| p.usable())
        .map_err(|_| LayoutError::TooSmall {
            size: total_lbas.saturating_mul(u64::from(block)),
            min: MIN_DISK_BYTES,
        })
}
