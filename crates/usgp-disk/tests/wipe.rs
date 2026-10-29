//! Wipe ranges and the guarded write path (REQ-DISK-006, REQ-DISK-007,
//! REQ-DISK-009, REQ-DISK-013, REQ-DISK-015).

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 (Access Enforcement), SI-7, SA-11
// - SPEC: specs/disk.md#REQ-DISK-006, #REQ-DISK-007, #REQ-DISK-013,
//   #REQ-DISK-015, #REQ-DISK-016
// - specs/standards/gpt.md §7

pub mod common;

use std::io;

use common::{GB, GIB, MIB, auth_for, facts, layout, round_down, verified_plan};
use usgp_disk::mbr::{self, Lba0};
use usgp_disk::wipe::{MAX_EXISTING_PARTITIONS, WIPE_REGION_BYTES};
use usgp_disk::{
    BlockDevice, DiskError, ExistingPartition, GptError, GptLimits, MemBlockDevice,
    WipeAuthorisation, WipeEvidence, WipePlan, parse_gpt, wipe_and_write,
};

const SIZE: u64 = 128 * GB;

fn existing(start: u64, size: u64) -> ExistingPartition {
    ExistingPartition {
        start_bytes: start,
        size_bytes: size,
        label: Some("old".to_owned()),
    }
}

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Puts an earlier GPT disk (from a different layout) on `dev`, plus
/// recognisable bytes at the head of each of its volumes.
fn seed_old_disk(dev: &mut MemBlockDevice, lg: u32) -> TestResult<Vec<ExistingPartition>> {
    let old = layout(SIZE, lg, lg, 1000)?;
    let wipe = WipePlan::for_disk(&old, &[])?;
    wipe_and_write(dev, &auth_for(SIZE, lg)?, &wipe, &old)?;
    let block = vec![0x5A; lg as usize];
    let mut parts = Vec::new();
    for p in old.parts() {
        let off = p.first_lba * u64::from(lg);
        dev.write_at(off, &block)?;
        dev.write_at(off + 64 * 1024, &block)?;
        parts.push(existing(off, p.len_lbas() * u64::from(lg)));
    }
    // A volume at an offset the new layout does not start a partition at.
    let elsewhere = 60 * GIB;
    dev.write_at(elsewhere, &vec![0x77; lg as usize])?;
    parts.push(existing(elsewhere, 10 * GB));
    Ok(parts)
}

fn contains(dev: &mut MemBlockDevice, needle: &[u8]) -> TestResult<bool> {
    let lg = dev.logical_sector();
    for lba in dev.nonzero_lbas() {
        let mut b = vec![0u8; lg as usize];
        dev.read_at(lba * u64::from(lg), &mut b)?;
        if b.windows(needle.len()).any(|w| w == needle) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[test]
fn old_primary_and_backup_gpt_destroyed() {
    for lg in [512u32, 4096] {
        let mut dev = MemBlockDevice::new(SIZE, lg).unwrap();
        let old_parts = seed_old_disk(&mut dev, lg).unwrap();
        let old_guid = parse_gpt(&mut dev, &GptLimits::default())
            .unwrap()
            .disk_guid;
        let new = layout(SIZE, lg, lg, 2000).unwrap();
        let wipe = WipePlan::for_disk(&new, &old_parts).unwrap();
        let view = wipe_and_write(&mut dev, &auth_for(SIZE, lg).unwrap(), &wipe, &new).unwrap();
        assert_eq!(view.disk_guid, new.disk_guid);
        // No copy of the old disk GUID survives anywhere on the disk.
        assert!(!contains(&mut dev, &old_guid.0).unwrap(), "{lg}");
    }
}

#[test]
fn old_mbr_destroyed() {
    let mut dev = MemBlockDevice::new(SIZE, 512).unwrap();
    let mut legacy = vec![0xCC_u8; 512];
    legacy[446..510].fill(0);
    legacy[446 + 4] = 0x07;
    legacy[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
    legacy[446 + 12..446 + 16].copy_from_slice(&1_000_000u32.to_le_bytes());
    legacy[510] = 0x55;
    legacy[511] = 0xAA;
    dev.write_at(0, &legacy).unwrap();
    assert!(matches!(mbr::read_lba0(&legacy), Lba0::Legacy(_)));
    let new = layout(SIZE, 512, 512, 3).unwrap();
    let wipe = WipePlan::for_disk(&new, &[existing(2048 * 512, 1_000_000 * 512)]).unwrap();
    wipe_and_write(&mut dev, &auth_for(SIZE, 512).unwrap(), &wipe, &new).unwrap();
    let mut lba0 = vec![0u8; 512];
    dev.read_at(0, &mut lba0).unwrap();
    assert_eq!(mbr::read_lba0(&lba0), Lba0::Protective);
    assert!(mbr::is_our_protective(&lba0, new.total_lbas));
    assert!(lba0[..440].iter().all(|&b| b == 0), "old boot code gone");
}

#[test]
fn old_volume_heads_zeroed() {
    for lg in [512u32, 4096] {
        let mut dev = MemBlockDevice::new(SIZE, lg).unwrap();
        let old_parts = seed_old_disk(&mut dev, lg).unwrap();
        let new = layout(SIZE, lg, lg, 4000).unwrap();
        let wipe = WipePlan::for_disk(&new, &old_parts).unwrap();
        wipe_and_write(&mut dev, &auth_for(SIZE, lg).unwrap(), &wipe, &new).unwrap();
        assert!(!contains(&mut dev, &[0x5A; 64]).unwrap(), "{lg}");
        assert!(!contains(&mut dev, &[0x77; 64]).unwrap(), "{lg}");
        // Only GPT structures are left non-zero.
        let total = new.total_lbas;
        let arr = 16_384 / u64::from(lg);
        for lba in dev.nonzero_lbas() {
            let gpt = lba <= 1 + arr || lba >= total - 1 - arr;
            assert!(gpt, "unexpected data at LBA {lba}");
        }
    }
}

#[test]
fn wipe_plan_ranges_sorted_merged_aligned_clamped() {
    let new = layout(SIZE, 4096, 4096, 5).unwrap();
    let parts = vec![
        // Unaligned start, aligned outwards.
        existing(1_000_000 * 512 + 512, 10 * GB),
        // Duplicate and overlapping.
        existing(MIB, 100 * MIB),
        existing(MIB, 100 * MIB),
        // Smaller than the region.
        existing(300 * MIB, 4096),
        // Past the end of the disk: ignored.
        existing(SIZE + MIB, MIB),
        // Running off the end: clamped.
        existing(SIZE - 4096, 10 * MIB),
    ];
    let w = WipePlan::for_disk(&new, &parts).unwrap();
    let r = w.ranges();
    assert_eq!(r.first().unwrap().start, 0);
    assert_eq!(r.last().unwrap().end, SIZE);
    for x in r {
        assert_eq!(x.start % 4096, 0);
        assert_eq!(x.end % 4096, 0);
        assert!(!x.is_empty());
        assert!(x.end <= SIZE);
        assert!(x.len() <= 3 * WIPE_REGION_BYTES);
    }
    for pair in r.windows(2) {
        assert!(pair[0].end < pair[1].start, "sorted, merged");
    }
    // The unaligned partition's head is covered.
    let s = 1_000_000 * 512 + 512;
    assert!(
        r.iter()
            .any(|x| x.start <= s && s + WIPE_REGION_BYTES <= x.end)
    );
}

#[test]
fn too_many_existing_partitions_refused() {
    let new = layout(SIZE, 512, 512, 6).unwrap();
    let parts = vec![existing(MIB, MIB); MAX_EXISTING_PARTITIONS + 1];
    assert!(matches!(
        WipePlan::for_disk(&new, &parts),
        Err(DiskError::BadPlan(_))
    ));
}

/// NIST-007: the authorisation is built only from a verified plan, and
/// carries the plan's job, durable record and confirmed geometry.
#[test]
fn authorisation_comes_from_the_verified_plan() {
    let plan = verified_plan(SIZE, 4096, 77, [0x5c; 32]).unwrap();
    let opened = facts(SIZE, 4096, 4096).identity;
    let auth = WipeAuthorisation::from_verified_plan(&plan, opened.clone());
    assert_eq!(
        auth.evidence(),
        &WipeEvidence {
            job_id: common::JOB.to_owned(),
            audit_seq: 77,
            audit_record_hash: [0x5c; 32],
            disk: opened,
            size_bytes: SIZE,
            logical_sector: 4096,
        }
    );
}

#[test]
fn refused_without_durable_record_nothing_written() {
    // A plan naming no durable record (sequence 0) never verifies, so no
    // authorisation can be built for it.
    assert!(verified_plan(SIZE, 512, 0, [1; 32]).is_err());

    // A zero record hash verifies as a plan but is refused before any
    // write.
    let new = layout(SIZE, 512, 512, 7).unwrap();
    let wipe = WipePlan::for_disk(&new, &[]).unwrap();
    let plan = verified_plan(SIZE, 512, 7, [0; 32]).unwrap();
    let auth = WipeAuthorisation::from_verified_plan(&plan, facts(SIZE, 512, 512).identity);
    let mut dev = MemBlockDevice::new(SIZE, 512).unwrap();
    let r = wipe_and_write(&mut dev, &auth, &wipe, &new);
    assert!(matches!(r, Err(DiskError::NotAuthorised(_))), "{r:?}");
    assert_eq!(dev.write_count(), 0);
}

#[test]
fn identity_or_plan_mismatch_nothing_written() {
    let new = layout(SIZE, 512, 512, 8).unwrap();
    let wipe = WipePlan::for_disk(&new, &[]).unwrap();
    // Device of another size than the confirmed disk.
    let mut other = MemBlockDevice::new(SIZE + MIB, 512).unwrap();
    let r = wipe_and_write(&mut other, &auth_for(SIZE, 512).unwrap(), &wipe, &new);
    assert!(matches!(r, Err(DiskError::IdentityMismatch(_))), "{r:?}");
    assert_eq!(other.write_count(), 0);
    // Authorisation for another size than the device.
    let mut dev = MemBlockDevice::new(SIZE, 512).unwrap();
    let r = wipe_and_write(&mut dev, &auth_for(SIZE - MIB, 512).unwrap(), &wipe, &new);
    assert!(matches!(r, Err(DiskError::IdentityMismatch(_))), "{r:?}");
    // Sector size differs.
    let mut dev4k = MemBlockDevice::new(SIZE, 4096).unwrap();
    let r = wipe_and_write(&mut dev4k, &auth_for(SIZE, 512).unwrap(), &wipe, &new);
    assert!(matches!(r, Err(DiskError::IdentityMismatch(_))), "{r:?}");
    assert_eq!(dev4k.write_count(), 0);
    // Layout planned for another disk size.
    let other_layout = layout(SIZE - MIB, 512, 512, 9).unwrap();
    let r = wipe_and_write(
        &mut dev,
        &auth_for(SIZE, 512).unwrap(),
        &wipe,
        &other_layout,
    );
    assert!(matches!(r, Err(DiskError::IdentityMismatch(_))), "{r:?}");
    // Wipe plan built for another disk.
    let other_wipe = WipePlan::for_disk(&other_layout, &[]).unwrap();
    let r = wipe_and_write(&mut dev, &auth_for(SIZE, 512).unwrap(), &other_wipe, &new);
    assert!(matches!(r, Err(DiskError::BadPlan(_))), "{r:?}");
    assert_eq!(dev.write_count(), 0);
}

#[test]
fn only_target_written() {
    let new = layout(SIZE, 512, 512, 10).unwrap();
    let wipe = WipePlan::for_disk(&new, &[]).unwrap();
    let mut target = MemBlockDevice::new(SIZE, 512).unwrap();
    let mut other = MemBlockDevice::new(SIZE, 512).unwrap();
    other.write_at(0, &[0x42; 512]).unwrap();
    let before = other.clone();
    wipe_and_write(&mut target, &auth_for(SIZE, 512).unwrap(), &wipe, &new).unwrap();
    assert_eq!(other.write_count(), before.write_count());
    assert_eq!(other.nonzero_lbas(), before.nonzero_lbas());
    assert!(target.write_count() > 0);
}

/// A device that silently corrupts one byte of every write to `lba`.
struct Corrupting {
    inner: MemBlockDevice,
    lba: u64,
}

impl BlockDevice for Corrupting {
    fn len(&self) -> u64 {
        self.inner.len()
    }
    fn logical_sector(&self) -> u32 {
        self.inner.logical_sector()
    }
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        self.inner.read_at(off, buf)
    }
    fn write_at(&mut self, off: u64, buf: &[u8]) -> io::Result<()> {
        let mut b = buf.to_vec();
        let s = u64::from(self.logical_sector());
        if off / s == self.lba && b.iter().any(|&x| x != 0) {
            b[30] ^= 1;
        }
        self.inner.write_at(off, &b)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn readback_failure_reported() {
    let new = layout(SIZE, 512, 512, 11).unwrap();
    let wipe = WipePlan::for_disk(&new, &[]).unwrap();
    for lba in [0, 1, 2, new.total_lbas - 1] {
        let mut dev = Corrupting {
            inner: MemBlockDevice::new(SIZE, 512).unwrap(),
            lba,
        };
        let r = wipe_and_write(&mut dev, &auth_for(SIZE, 512).unwrap(), &wipe, &new);
        assert!(
            matches!(
                r,
                Err(DiskError::ReadBack(
                    GptError::Header { .. } | GptError::Array { .. } | GptError::NoProtectiveMbr(_)
                )) | Err(DiskError::ReadBackMismatch(_))
            ),
            "LBA {lba}: {r:?}"
        );
    }
}

#[test]
fn unaligned_4k_layout_sizes_use_round_down_helper() {
    // 4Kn disks whose byte size is not a 4096 multiple are not whole
    // sectors; the platform reports whole sectors, so tests round down.
    let size = round_down(70 * GB, 4096);
    let l = layout(size, 4096, 4096, 12).unwrap();
    assert_eq!(l.disk_bytes(), size);
}

/// NIST-015 and BOOT-003: the open design values carry their `// POAM:`
/// markers in the source, where the compliance scribe looks for them.
#[test]
fn poam_markers_present() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let read = |f: &str| std::fs::read_to_string(src.join(f)).unwrap();
    assert!(read("wipe.rs").contains("// POAM: OPEN-DISK-2"));
    assert!(read("layout.rs").contains("// POAM: the file-system overhead estimate"));
}
