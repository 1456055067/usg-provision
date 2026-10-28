//! The protective MBR at LBA 0, and a display-only reader for a legacy MBR.
//!
//! The legacy reader exists only so the device can list the partitions an
//! MBR disk already holds before the wipe (REQ-DISK-001, REQ-DISK-006). It
//! reads the four primary records of LBA 0 and nothing else: no extended
//! partition chain, no partition contents (REQ-DISK-016).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation)
// - SPEC: specs/disk.md#REQ-DISK-009 (protective MBR as UEFI defines it),
//   #REQ-DISK-016 (no content read out)
// - UEFI 2.10 §5.2.3, §5.2.2 (specs/standards/gpt.md §3)

use crate::bytes;

/// FORMAT: gpt.md §3 - offset of the first partition record.
pub const RECORDS_OFFSET: usize = 446;
/// FORMAT: gpt.md §3 - each partition record is 16 bytes; there are four.
pub const RECORD_LEN: usize = 16;
/// FORMAT: gpt.md §3 - number of partition records.
pub const RECORD_COUNT: usize = 4;
/// FORMAT: gpt.md §3 - offset of the boot signature.
pub const SIGNATURE_OFFSET: usize = 510;
/// FORMAT: gpt.md §3 - boot signature value `0xAA55` (bytes `55 AA`).
pub const SIGNATURE: u16 = 0xAA55;
/// FORMAT: gpt.md §3 - OSType of the GPT protective partition.
pub const OS_TYPE_GPT_PROTECTIVE: u8 = 0xEE;
/// FORMAT: gpt.md §3 - StartingCHS `0x000200`, stored little-endian.
const STARTING_CHS: [u8; 3] = [0x00, 0x02, 0x00];
/// FORMAT: gpt.md §3 - EndingCHS `0xFFFFFF` when the last block is not
/// representable in CHS. We always write it (see [`protective`]).
const ENDING_CHS_NOT_REPRESENTABLE: [u8; 3] = [0xFF, 0xFF, 0xFF];
/// FORMAT: gpt.md §3 - SizeInLBA when the size does not fit in 32 bits.
const SIZE_SATURATED: u32 = 0xFFFF_FFFF;
/// FORMAT: gpt.md §3 - the MBR occupies the first 512 bytes of LBA 0.
pub const MBR_LEN: usize = 512;

// Field offsets inside a 16-byte partition record (gpt.md §3, UEFI Table
// 5.4 order: BootIndicator, StartingCHS, OSType, EndingCHS, StartingLBA,
// SizeInLBA).
/// FORMAT: gpt.md §3 - BootIndicator at record offset 0.
const R_BOOT: usize = 0;
/// FORMAT: gpt.md §3 - StartingCHS at record offset 1 (3 bytes).
const R_START_CHS: usize = 1;
/// FORMAT: gpt.md §3 - OSType at record offset 4.
const R_OS_TYPE: usize = 4;
/// FORMAT: gpt.md §3 - EndingCHS at record offset 5 (3 bytes).
const R_END_CHS: usize = 5;
/// FORMAT: gpt.md §3 - StartingLBA at record offset 8 (4 bytes).
const R_START_LBA: usize = 8;
/// FORMAT: gpt.md §3 - SizeInLBA at record offset 12 (4 bytes).
const R_SIZE: usize = 12;

/// Builds the protective MBR block for a disk of `total_lbas` logical
/// blocks of `block_len` bytes.
///
/// Boot code, disk signature (offset 440) and the unknown field (444) are
/// zero; record 1 covers LBA 1 to the end of the disk (saturated at
/// `0xFFFFFFFF`); records 2 to 4 are zero; the rest of the block is zero.
///
/// EndingCHS is always `0xFFFFFF`. `gpt.md` §3 says to write the CHS of the
/// last block when representable, but gives no CHS geometry; our layouts
/// are only for disks of at least 64 GB (REQ-DISK-004), and we never
/// compute a CHS value (unspecified behaviour noted in impl-notes-wu3.md).
///
/// Returns `None` if `block_len` is under 512 bytes.
#[must_use]
pub fn protective(total_lbas: u64, block_len: usize) -> Option<Vec<u8>> {
    if block_len < MBR_LEN {
        return None;
    }
    let mut b = vec![0u8; block_len];
    let size = u32::try_from(total_lbas.saturating_sub(1)).unwrap_or(SIZE_SATURATED);
    let rec = RECORDS_OFFSET;
    let ok = bytes::put(&mut b, rec + R_BOOT, &[0x00])
        && bytes::put(&mut b, rec + R_START_CHS, &STARTING_CHS)
        && bytes::put(&mut b, rec + R_OS_TYPE, &[OS_TYPE_GPT_PROTECTIVE])
        && bytes::put(&mut b, rec + R_END_CHS, &ENDING_CHS_NOT_REPRESENTABLE)
        && bytes::put(&mut b, rec + R_START_LBA, &1u32.to_le_bytes())
        && bytes::put(&mut b, rec + R_SIZE, &size.to_le_bytes())
        && bytes::put(&mut b, SIGNATURE_OFFSET, &SIGNATURE.to_le_bytes());
    ok.then_some(b)
}

/// One primary record of a legacy MBR, for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MbrRecord {
    /// Record slot, 1 to 4.
    pub slot: u8,
    /// OSType byte.
    pub os_type: u8,
    /// StartingLBA.
    pub start_lba: u32,
    /// SizeInLBA.
    pub size_lbas: u32,
}

/// What LBA 0 holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lba0 {
    /// No `0xAA55` signature: no MBR.
    Empty,
    /// A protective MBR (record 1 OSType `0xEE`): look for a GPT.
    Protective,
    /// A legacy MBR with these non-empty primary records.
    Legacy(Vec<MbrRecord>),
}

/// Classifies LBA 0 (at least 512 bytes) for display. Records with OSType
/// zero or size zero are skipped.
#[must_use]
pub fn read_lba0(block: &[u8]) -> Lba0 {
    if bytes::le_u16(block, SIGNATURE_OFFSET) != Some(SIGNATURE) {
        return Lba0::Empty;
    }
    let mut out = Vec::new();
    for slot in 0..RECORD_COUNT {
        let base = RECORDS_OFFSET + slot * RECORD_LEN;
        let (Some(os_type), Some(start_lba), Some(size_lbas)) = (
            bytes::field(block, base + R_OS_TYPE, 1).and_then(|f| f.first().copied()),
            bytes::le_u32(block, base + R_START_LBA),
            bytes::le_u32(block, base + R_SIZE),
        ) else {
            return Lba0::Empty;
        };
        if os_type == OS_TYPE_GPT_PROTECTIVE {
            return Lba0::Protective;
        }
        if os_type != 0 && size_lbas != 0 {
            out.push(MbrRecord {
                slot: u8::try_from(slot + 1).unwrap_or(u8::MAX),
                os_type,
                start_lba,
                size_lbas,
            });
        }
    }
    Lba0::Legacy(out)
}

/// `true` if `block` is exactly the protective MBR [`protective`] would
/// write for `total_lbas` (used by the read-back check).
#[must_use]
pub fn is_our_protective(block: &[u8], total_lbas: u64) -> bool {
    protective(total_lbas, block.len()).is_some_and(|want| want == block)
}
