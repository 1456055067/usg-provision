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
/// representable in CHS. We always write it (see [`protective`]): this
/// relies on the 64 GB disk floor ([`crate::layout::MIN_DISK_BYTES`],
/// REQ-DISK-004; BOOT-007).
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
/// The constant relies on that floor: we take the last block of every disk
/// of 64 GB or more to be beyond what the 3-byte CHS field can name. A
/// layout for a smaller disk would first need a source for the CHS
/// geometry, which `gpt.md` does not give (BOOT-007).
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
    /// A protective MBR as `gpt.md` §3 defines it (record 1 OSType `0xEE`,
    /// records 2 to 4 all zero): look for a GPT.
    Protective,
    /// An MBR with OSType `0xEE` in some record that is not a protective
    /// MBR (`0xEE` in a slot other than 1, or records 2 to 4 not all
    /// zero): a hybrid MBR. Listed for display; never read as a GPT disk
    /// (BOOT-008). Holds every non-empty record, `0xEE` ones included.
    Hybrid(Vec<MbrRecord>),
    /// A legacy MBR with these non-empty primary records (none `0xEE`).
    Legacy(Vec<MbrRecord>),
}

/// Classifies LBA 0 (at least 512 bytes) for display. Records with OSType
/// zero or size zero are not listed.
///
/// Only record 1 with OSType `0xEE` and records 2 to 4 all zero (every
/// byte) is [`Lba0::Protective`] (`gpt.md` §3); any other MBR holding a
/// `0xEE` record is [`Lba0::Hybrid`] (BOOT-008).
#[must_use]
pub fn read_lba0(block: &[u8]) -> Lba0 {
    if bytes::le_u16(block, SIGNATURE_OFFSET) != Some(SIGNATURE) {
        return Lba0::Empty;
    }
    let mut out = Vec::new();
    let mut any_ee = false;
    let mut slot1_ee = false;
    let mut rest_zero = true;
    for slot in 0..RECORD_COUNT {
        let base = RECORDS_OFFSET + slot * RECORD_LEN;
        let (Some(record), Some(os_type), Some(start_lba), Some(size_lbas)) = (
            bytes::field(block, base, RECORD_LEN),
            bytes::field(block, base + R_OS_TYPE, 1).and_then(|f| f.first().copied()),
            bytes::le_u32(block, base + R_START_LBA),
            bytes::le_u32(block, base + R_SIZE),
        ) else {
            return Lba0::Empty;
        };
        if os_type == OS_TYPE_GPT_PROTECTIVE {
            any_ee = true;
            slot1_ee |= slot == 0;
        }
        if slot > 0 && record.iter().any(|&b| b != 0) {
            rest_zero = false;
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
    match (any_ee, slot1_ee && rest_zero) {
        (_, true) => Lba0::Protective,
        (true, false) => Lba0::Hybrid(out),
        (false, false) => Lba0::Legacy(out),
    }
}

/// `true` if `block` is exactly the protective MBR [`protective`] would
/// write for `total_lbas` (used by the read-back check).
#[must_use]
pub fn is_our_protective(block: &[u8], total_lbas: u64) -> bool {
    protective(total_lbas, block.len()).is_some_and(|want| want == block)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::GptError;

    fn record(b: &mut [u8], slot: usize, os_type: u8, start: u32, size: u32) {
        let base = RECORDS_OFFSET + slot * RECORD_LEN;
        assert!(bytes::put(b, base + R_OS_TYPE, &[os_type]));
        assert!(bytes::put(b, base + R_START_LBA, &start.to_le_bytes()));
        assert!(bytes::put(b, base + R_SIZE, &size.to_le_bytes()));
    }

    fn total_lbas_64gb(block: u64) -> u64 {
        crate::layout::MIN_DISK_BYTES / block
    }

    /// BOOT-007: EndingCHS is `0xFFFFFF` for every disk the layout accepts
    /// (64 GB and up), which is what the constant relies on.
    #[test]
    fn ending_chs_is_not_representable_from_the_floor_up() {
        for block in [512u64, 4096] {
            for total in [
                total_lbas_64gb(block),
                u64::from(u32::MAX),
                u64::MAX / block,
            ] {
                let b = protective(total, usize::try_from(block).unwrap_or(512));
                let end = b
                    .as_deref()
                    .and_then(|b| bytes::field(b, RECORDS_OFFSET + R_END_CHS, 3));
                assert_eq!(
                    end,
                    Some(&ENDING_CHS_NOT_REPRESENTABLE[..]),
                    "{block} {total}"
                );
            }
        }
    }

    /// BOOT-008: only slot 1 `0xEE` with slots 2 to 4 all zero is
    /// protective; `0xEE` anywhere else is a hybrid MBR, listed apart.
    #[test]
    fn protective_needs_slot_one_and_empty_rest() {
        let ours = protective(total_lbas_64gb(512), 512).unwrap_or_default();
        assert_eq!(read_lba0(&ours), Lba0::Protective);

        // Slot 1 0xEE plus a legacy record in slot 2: hybrid.
        let mut hybrid = ours.clone();
        record(&mut hybrid, 1, 0x07, 2048, 4096);
        match read_lba0(&hybrid) {
            Lba0::Hybrid(r) => {
                let slots: Vec<(u8, u8)> = r.iter().map(|r| (r.slot, r.os_type)).collect();
                assert_eq!(slots, vec![(1, OS_TYPE_GPT_PROTECTIVE), (2, 0x07)]);
            }
            other => panic!("{other:?}"),
        }

        // 0xEE only in slot 3: hybrid, not protective.
        let mut b = vec![0u8; 512];
        assert!(bytes::put(
            &mut b,
            SIGNATURE_OFFSET,
            &SIGNATURE.to_le_bytes()
        ));
        record(&mut b, 0, 0x0C, 2048, 4096);
        record(&mut b, 2, OS_TYPE_GPT_PROTECTIVE, 1, 100);
        assert!(matches!(read_lba0(&b), Lba0::Hybrid(r) if r.len() == 2));

        // A stray non-zero byte in an otherwise empty slot 4: hybrid.
        let mut stray = ours.clone();
        assert!(bytes::put(
            &mut stray,
            RECORDS_OFFSET + 3 * RECORD_LEN + R_BOOT,
            &[0x80]
        ));
        assert!(matches!(read_lba0(&stray), Lba0::Hybrid(_)));

        // No 0xEE anywhere: legacy.
        let mut legacy = vec![0u8; 512];
        assert!(bytes::put(
            &mut legacy,
            SIGNATURE_OFFSET,
            &SIGNATURE.to_le_bytes()
        ));
        record(&mut legacy, 0, 0x07, 2048, 4096);
        assert!(matches!(read_lba0(&legacy), Lba0::Legacy(r) if r.len() == 1));
    }

    /// A hybrid MBR is never read as a GPT disk.
    #[test]
    fn hybrid_is_not_parsed_as_gpt() {
        use crate::device::{BlockDevice, MemBlockDevice};
        use crate::guid::Guid;
        let total = 1 << 16;
        let mut dev = MemBlockDevice::new(total * 512, 512).unwrap_or_else(|_| unreachable!());
        let plan = crate::gpt::GptPlan::new(512, total, Guid([7; 16]), Vec::new())
            .unwrap_or_else(|_| unreachable!());
        for (off, block) in plan.writes().unwrap_or_default() {
            assert!(dev.write_at(off, &block).is_ok());
        }
        assert!(crate::parse_gpt(&mut dev, &crate::GptLimits::default()).is_ok());
        let mut lba0 = vec![0u8; 512];
        assert!(dev.read_at(0, &mut lba0).is_ok());
        record(&mut lba0, 1, 0x07, 2048, 4096);
        assert!(dev.write_at(0, &lba0).is_ok());
        let r = crate::parse_gpt(&mut dev, &crate::GptLimits::default());
        assert!(
            matches!(r, Err(GptError::NoProtectiveMbr("hybrid MBR"))),
            "{r:?}"
        );
    }
}
