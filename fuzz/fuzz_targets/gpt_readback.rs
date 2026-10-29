//! Fuzz target `gpt_readback`: arbitrary bytes at the start and end of an
//! in-memory disk, read back by `parse_gpt` (`usgp-disk`), and LBA 0
//! classified by `mbr::read_lba0`.
//!
//! Input (our design, WU-14):
//!
//! ```text
//! [0]      bit 0: 4096-byte sectors (else 512); bit 1: 1024-byte sectors
//!          (unsupported, must be refused); bits 2-3: limits (LIMITS)
//! [1..5]   total LBAs, u32 little-endian
//! [5..7]   h = head length, u16 little-endian
//! [7..7+h] head: written at offset 0, zero-padded to whole sectors
//! rest     tail: written so that it ends at the last byte of the disk,
//!          zero-padded at the front to whole sectors
//! ```
//!
//! The disk is a sparse `MemBlockDevice`, so a large LBA count costs only
//! the sectors written. Head and tail are cut to the disk.
//!
//! Invariants (plan WU-14; impl-notes-wu3 "WU-14"):
//!
//! - no panic; `parse_gpt` never writes to the device and gives the same
//!   answer twice;
//! - an accepted view has the device's block size and LBA count, the
//!   header layout rules (`gpt.md` §2, §4, §7) and the entry rules
//!   (REQ-DISK-009: inside the usable range, no overlap, non-nil distinct
//!   GUIDs, slots in order below `NumberOfPartitionEntries`), and LBA 0 is
//!   a protective MBR;
//! - limits: a table accepted under tighter limits is accepted, equal,
//!   under the defaults; an accepted table is accepted under limits that
//!   just fit it and refused with `Limit` one entry below;
//! - reference: a table in our fixed geometry (128 x 128-byte entries,
//!   primary array at LBA 2, slots used from 0) rebuilds as a `GptPlan`
//!   that `matches` the view, and the plan's writes on a fresh disk read
//!   back to the same view;
//! - `read_lba0`: legacy records are slots 1 to 4 in order, never empty
//!   and never protective.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SI-7 (Software,
//   Firmware, and Information Integrity), SA-11 (Developer Testing and
//   Evaluation)
// - SPEC: specs/disk.md#REQ-DISK-009, #REQ-DISK-010
// - specs/standards/gpt.md §2 to §7 (UEFI 2.10 §5.2, §5.3)

use libfuzzer_sys::fuzz_target;
use usgp_disk::gpt::{ENTRY_COUNT, ENTRY_SIZE, MIN_ARRAY_BYTES, PRIMARY_ARRAY_LBA};
use usgp_disk::mbr::{self, Lba0};
use usgp_disk::{BlockDevice, GptError, GptLimits, GptPlan, GptView, MemBlockDevice, parse_gpt};

/// Limits the input can select; the first is the default.
const LIMITS: [GptLimits; 4] = [
    GptLimits {
        max_entries: 1024,
        max_entry_size: 1024,
        max_array_bytes: 1024 * 1024,
    },
    GptLimits {
        max_entries: 128,
        max_entry_size: 128,
        max_array_bytes: 16_384,
    },
    GptLimits {
        max_entries: 4,
        max_entry_size: 128,
        max_array_bytes: 512,
    },
    GptLimits {
        max_entries: 1024,
        max_entry_size: 256,
        max_array_bytes: 65_536,
    },
];

fn round_up(n: usize, to: usize) -> usize {
    n.div_ceil(to).saturating_mul(to)
}

/// Writes `head` at 0 and `tail` ending at the device end, cut to the
/// device, in whole sectors.
fn place(dev: &mut MemBlockDevice, head: &[u8], tail: &[u8]) {
    let sector = usize::try_from(dev.logical_sector()).unwrap_or(512);
    let len = usize::try_from(dev.len()).unwrap_or(usize::MAX);
    let mut h = head.to_vec();
    h.resize(round_up(h.len(), sector).min(len), 0);
    if !h.is_empty() {
        assert!(dev.write_at(0, &h).is_ok(), "aligned head write refused");
    }
    let pad = round_up(tail.len(), sector) - tail.len();
    let mut t = vec![0u8; pad];
    t.extend_from_slice(tail);
    let keep = round_up(t.len(), sector).min(len - len % sector);
    let t = t.get(t.len() - keep.min(t.len())..).unwrap_or(&[]);
    if !t.is_empty() {
        let off = dev.len() - u64::try_from(t.len()).unwrap_or(0);
        assert!(dev.write_at(off, t).is_ok(), "aligned tail write refused");
    }
}

fn lba0(dev: &mut MemBlockDevice) -> Option<Lba0> {
    let n = usize::try_from(dev.logical_sector()).ok()?;
    if dev.len() < u64::try_from(n).ok()? {
        return None;
    }
    let mut b = vec![0u8; n];
    dev.read_at(0, &mut b).ok()?;
    let r = mbr::read_lba0(&b);
    if let Lba0::Legacy(recs) = &r {
        let mut last = 0u8;
        for rec in recs {
            assert!((1..=4).contains(&rec.slot), "record slot {}", rec.slot);
            assert!(rec.slot > last, "records out of order");
            last = rec.slot;
            assert!(
                rec.os_type != 0 && rec.size_lbas != 0,
                "empty record listed"
            );
            assert_ne!(
                rec.os_type,
                mbr::OS_TYPE_GPT_PROTECTIVE,
                "protective as legacy"
            );
        }
    }
    Some(r)
}

fn same(a: &Result<GptView, GptError>, b: &Result<GptView, GptError>) -> bool {
    match (a, b) {
        (Ok(x), Ok(y)) => x == y,
        (Err(x), Err(y)) => x.to_string() == y.to_string(),
        _ => false,
    }
}

fn check_view(v: &GptView, block: u32, total: u64, l: &GptLimits) {
    assert_eq!(v.block, block, "block size");
    assert_eq!(v.total_lbas, total, "LBA count");
    assert!(!v.disk_guid.is_nil(), "nil DiskGUID accepted");
    assert!(v.entry_count <= l.max_entries, "entry count over limit");
    assert!(v.entry_size <= l.max_entry_size, "entry size over limit");
    assert!(
        u64::from(v.entry_count) * u64::from(v.entry_size) <= u64::from(l.max_array_bytes),
        "array over limit"
    );
    assert!(
        v.entry_size >= 128
            && v.entry_size.is_multiple_of(128)
            && (v.entry_size / 128).is_power_of_two(),
        "SizeOfPartitionEntry {}",
        v.entry_size
    );
    let last_lba = total - 1;
    assert!(
        1 < v.first_usable && v.first_usable <= v.last_usable && v.last_usable < last_lba,
        "usable range"
    );
    let blk = u64::from(block);
    let arr = (u64::from(v.entry_count) * u64::from(v.entry_size)).div_ceil(blk);
    let reserved = MIN_ARRAY_BYTES.div_ceil(blk);
    assert!(
        v.primary_array_lba > 1
            && v.primary_array_lba + arr <= v.first_usable
            && v.first_usable - v.primary_array_lba >= reserved,
        "primary array location"
    );
    assert!(
        v.backup_array_lba > v.last_usable
            && v.backup_array_lba + arr <= last_lba
            && last_lba - v.backup_array_lba >= reserved,
        "backup array location"
    );
    let mut prev: Option<u32> = None;
    let mut spans: Vec<(u64, u64)> = Vec::new();
    for (i, (slot, e)) in v.entries.iter().enumerate() {
        assert!(*slot < v.entry_count, "slot past the array");
        assert!(prev.is_none_or(|p| p < *slot), "slots out of order");
        prev = Some(*slot);
        assert!(!e.type_guid.is_nil() && !e.unique_guid.is_nil(), "nil GUID");
        assert_ne!(e.unique_guid, v.disk_guid, "unique GUID equals DiskGUID");
        for (_, f) in v.entries.iter().skip(i + 1) {
            assert_ne!(e.unique_guid, f.unique_guid, "unique GUID repeated");
        }
        assert!(
            v.first_usable <= e.first_lba
                && e.first_lba <= e.last_lba
                && e.last_lba <= v.last_usable,
            "entry outside the usable range"
        );
        assert_eq!(
            e.attributes & usgp_disk::gpt::ATTR_UNDEFINED_MASK,
            0,
            "undefined attribute bits"
        );
        spans.push((e.first_lba, e.last_lba));
    }
    spans.sort_unstable();
    for w in spans.windows(2) {
        if let [(_, a_last), (b_first, _)] = w {
            assert!(b_first > a_last, "overlapping entries");
        }
    }
}

/// Our fixed geometry, computed independently of the crate.
fn standard_geometry(block: u32, total: u64) -> Option<(u64, u64, u64)> {
    let arr = (u64::from(ENTRY_COUNT) * u64::from(ENTRY_SIZE)).div_ceil(u64::from(block));
    let first = PRIMARY_ARRAY_LBA + arr;
    let backup = total.checked_sub(1)?.checked_sub(arr)?;
    let last = backup.checked_sub(1)?;
    Some((first, last, backup))
}

fn reference(v: &GptView, block: u32, total: u64) {
    if v.entry_count != ENTRY_COUNT
        || v.entry_size != ENTRY_SIZE
        || v.primary_array_lba != PRIMARY_ARRAY_LBA
        || !v
            .entries
            .iter()
            .enumerate()
            .all(|(i, (s, _))| usize::try_from(*s).ok() == Some(i))
    {
        return;
    }
    let Some((first, last, backup)) = standard_geometry(block, total) else {
        return;
    };
    if (v.first_usable, v.last_usable, v.backup_array_lba) != (first, last, backup) {
        return;
    }
    let entries = v.entries.iter().map(|(_, e)| *e).collect();
    let plan = match GptPlan::new(block, total, v.disk_guid, entries) {
        Ok(p) => p,
        Err(e) => panic!("read-back table in the fixed geometry not plannable: {e}"),
    };
    assert!(plan.matches(v), "plan does not match its own read-back");
    let writes = plan.writes().expect("plan encodes");
    let Ok(mut fresh) = MemBlockDevice::new(total * u64::from(block), block) else {
        panic!("device of the same size");
    };
    for (off, buf) in &writes {
        assert!(fresh.write_at(*off, buf).is_ok(), "plan write refused");
    }
    let again = parse_gpt(&mut fresh, &GptLimits::default());
    match again {
        Ok(w) => assert_eq!(&w, v, "rebuilt table reads back differently"),
        Err(e) => panic!("rebuilt table refused: {e}"),
    }
}

fuzz_target!(|input: &[u8]| {
    let [sel, l0, l1, l2, l3, h0, h1, rest @ ..] = input else {
        return;
    };
    let block: u32 = if sel & 2 != 0 {
        1024
    } else if sel & 1 != 0 {
        4096
    } else {
        512
    };
    let limits = LIMITS[usize::from((sel >> 2) & 3)];
    let total = u64::from(u32::from_le_bytes([*l0, *l1, *l2, *l3]));
    let h = usize::from(u16::from_le_bytes([*h0, *h1])).min(rest.len());
    let (head, tail) = rest.split_at(h);
    let Ok(mut dev) = MemBlockDevice::new(total * u64::from(block), block) else {
        return;
    };
    place(&mut dev, head, tail);
    let class = lba0(&mut dev);

    let writes = dev.write_count();
    let r = parse_gpt(&mut dev, &limits);
    let r2 = parse_gpt(&mut dev, &limits);
    assert_eq!(dev.write_count(), writes, "parse_gpt wrote to the device");
    assert!(same(&r, &r2), "parse_gpt not deterministic");

    if block == 1024 {
        assert!(
            matches!(r, Err(GptError::UnsupportedSectorSize(1024))),
            "1024-byte sectors accepted"
        );
        return;
    }
    let Ok(view) = r else { return };
    assert_eq!(
        class,
        Some(Lba0::Protective),
        "accepted without a protective MBR"
    );
    check_view(&view, block, total, &limits);

    // Limits are monotone.
    let default = parse_gpt(&mut dev, &GptLimits::default());
    assert!(
        matches!(&default, Ok(d) if *d == view),
        "accepted under tighter limits only"
    );
    let fit = GptLimits {
        max_entries: view.entry_count,
        max_entry_size: view.entry_size,
        max_array_bytes: view.entry_count.saturating_mul(view.entry_size),
    };
    let r_fit = parse_gpt(&mut dev, &fit);
    assert!(
        matches!(&r_fit, Ok(d) if *d == view),
        "refused under limits that fit"
    );
    if view.entry_count > 0 {
        let below = GptLimits {
            max_entries: view.entry_count - 1,
            ..fit
        };
        assert!(
            matches!(parse_gpt(&mut dev, &below), Err(GptError::Limit(_))),
            "accepted with one entry over the limit"
        );
    }
    reference(&view, block, total);
});
