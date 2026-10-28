//! The byte ranges zeroed before the new GPT is written (REQ-DISK-007).
//!
//! The wipe destroys both copies of any earlier GPT and any earlier MBR,
//! and the start of every earlier and every new volume, so that no earlier
//! partition table or volume is recognised before the new volumes are
//! formatted:
//!
//! - the first 1 MiB of the disk (LBA 0, the primary GPT header and any
//!   primary entry array up to 1 MiB);
//! - the last 1 MiB of the disk (the backup GPT header at the last LBA and
//!   its array);
//! - the first 1 MiB of each existing partition;
//! - the first 1 MiB of each partition in the new layout.
//!
//! How much more of the old disk to overwrite is OPEN-DISK-2; 1 MiB per
//! region is a design choice (impl-notes-wu3.md). Nothing is read: the
//! ranges come from the partition list only (REQ-DISK-016).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - existing partition
//   extents are clamped to the disk and bounded in number
// - SPEC: specs/disk.md#REQ-DISK-007, #REQ-DISK-015, #REQ-DISK-016
// - specs/standards/gpt.md §2, §7

use crate::eligibility::ExistingPartition;
use crate::error::DiskError;
use crate::layout::{ALIGN_BYTES, WindowsUefiLayout};

/// Design value (OPEN-DISK-2): bytes zeroed at the head and tail of the
/// disk and at the head of each volume.
pub const WIPE_REGION_BYTES: u64 = ALIGN_BYTES;
/// Design limit: most existing partitions accepted in a wipe plan. Windows
/// allows 128 on GPT (`gpt.md` §10); 256 leaves room for MBR layouts.
pub const MAX_EXISTING_PARTITIONS: usize = 256;

/// A half-open byte range `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ByteRange {
    /// First byte.
    pub start: u64,
    /// One past the last byte.
    pub end: u64,
}

impl ByteRange {
    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// `true` if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }
}

/// Sorted, merged, sector-aligned ranges to zero on one disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WipePlan {
    disk_bytes: u64,
    block: u32,
    ranges: Vec<ByteRange>,
}

impl WipePlan {
    /// Builds the plan for the disk `layout` was computed for, given the
    /// partitions it holds now.
    ///
    /// # Errors
    /// [`DiskError::BadPlan`] if there are more than
    /// [`MAX_EXISTING_PARTITIONS`] existing partitions or the block size is
    /// not 512 or 4096.
    pub fn for_disk(
        layout: &WindowsUefiLayout,
        existing: &[ExistingPartition],
    ) -> Result<Self, DiskError> {
        if existing.len() > MAX_EXISTING_PARTITIONS {
            return Err(DiskError::BadPlan("too many existing partitions"));
        }
        if !crate::gpt::SUPPORTED_BLOCK_SIZES.contains(&layout.block) {
            return Err(DiskError::BadPlan("unsupported block size"));
        }
        let block = u64::from(layout.block);
        let disk_bytes = layout.disk_bytes();
        let mut raw: Vec<(u64, u64)> = Vec::with_capacity(existing.len() + 6);
        raw.push((0, WIPE_REGION_BYTES));
        raw.push((
            disk_bytes.saturating_sub(WIPE_REGION_BYTES),
            WIPE_REGION_BYTES,
        ));
        for p in existing {
            raw.push((p.start_bytes, p.size_bytes.min(WIPE_REGION_BYTES)));
        }
        for p in layout.parts() {
            let size = p.len_lbas().saturating_mul(block);
            raw.push((
                p.first_lba.saturating_mul(block),
                size.min(WIPE_REGION_BYTES),
            ));
        }

        // Align outwards to whole sectors and clamp to the disk.
        let mut ranges: Vec<ByteRange> = raw
            .into_iter()
            .filter_map(|(start, len)| {
                let s = start - start % block;
                let e = start
                    .saturating_add(len)
                    .checked_next_multiple_of(block)
                    .unwrap_or(disk_bytes)
                    .min(disk_bytes);
                (s < e).then_some(ByteRange { start: s, end: e })
            })
            .collect();
        ranges.sort_unstable();
        let mut merged: Vec<ByteRange> = Vec::with_capacity(ranges.len());
        for r in ranges {
            match merged.last_mut() {
                Some(last) if r.start <= last.end => last.end = last.end.max(r.end),
                _ => merged.push(r),
            }
        }
        Ok(Self {
            disk_bytes,
            block: layout.block,
            ranges: merged,
        })
    }

    /// The ranges, sorted and non-overlapping.
    #[must_use]
    pub fn ranges(&self) -> &[ByteRange] {
        &self.ranges
    }

    /// Disk size the plan was built for.
    #[must_use]
    pub fn disk_bytes(&self) -> u64 {
        self.disk_bytes
    }

    /// Logical block size the plan was built for.
    #[must_use]
    pub fn block(&self) -> u32 {
        self.block
    }
}
