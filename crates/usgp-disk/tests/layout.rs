//! The Windows UEFI layout planner (REQ-DISK-008, REQ-DISK-010,
//! REQ-DISK-004).

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation)
// - SPEC: specs/disk.md#REQ-DISK-004, #REQ-DISK-008, #REQ-DISK-009,
//   #REQ-DISK-010
// - specs/standards/gpt.md §8 to §10

pub mod common;

use common::{GB, GIB, MIB, TestRng, facts, layout, round_down};
use usgp_disk::guid::types;
use usgp_disk::layout::{
    MIN_DISK_BYTES, RECOVERY_ATTRIBUTES, WINDOWS_MIN_BYTES, recovery_partition_bytes,
};
use usgp_disk::{LayoutError, PartRole, WindowsUefiLayout, minimum_disk_bytes};

fn bytes(l: &WindowsUefiLayout, p: &usgp_disk::Part) -> u64 {
    p.len_lbas() * u64::from(l.block)
}

#[test]
fn order_types_attrs() {
    let l = layout(256 * GB, 512, 512, 1).unwrap();
    let roles: Vec<PartRole> = l.parts().iter().map(|p| p.role).collect();
    assert_eq!(
        roles,
        [
            PartRole::Esp,
            PartRole::Msr,
            PartRole::Windows,
            PartRole::Recovery
        ]
    );
    let numbers: Vec<u32> = l.parts().iter().map(|p| p.number).collect();
    assert_eq!(numbers, [1, 2, 3, 4]);
    assert_eq!(l.esp.type_guid, types::ESP);
    assert_eq!(l.msr.type_guid, types::MSR);
    assert_eq!(l.windows.type_guid, types::BASIC_DATA);
    assert_eq!(l.recovery.type_guid, types::RECOVERY);
    assert_eq!(
        types::ESP.to_string(),
        "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
    );
    assert_eq!(
        types::MSR.to_string(),
        "E3C9E316-0B5C-4DB8-817D-F92DF00215AE"
    );
    assert_eq!(
        types::BASIC_DATA.to_string(),
        "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
    );
    assert_eq!(
        types::RECOVERY.to_string(),
        "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC"
    );
    // UEFI byte order on disk (uefi-guid-text.md §1.2): first three fields
    // little-endian.
    assert_eq!(
        types::ESP.0,
        [
            0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E,
            0xC9, 0x3B
        ]
    );
    // In LBA order, contiguous, nothing else.
    let p = l.parts();
    for w in p.windows(2) {
        assert!(w[0].last_lba < w[1].first_lba);
    }
    assert_eq!(l.esp.attributes, 0);
    assert_eq!(l.msr.attributes, 0);
    assert_eq!(l.windows.attributes, 0);
}

#[test]
fn esp_200_512n_and_512e() {
    for physical in [512, 4096] {
        let l = layout(128 * GB, 512, physical, 2).unwrap();
        assert_eq!(bytes(&l, &l.esp), 200 * MIB, "512/{physical}");
    }
}

#[test]
fn esp_300_4kn() {
    let l = layout(128 * GB, 4096, 4096, 3).unwrap();
    assert_eq!(bytes(&l, &l.esp), 300 * MIB);
}

#[test]
fn msr_16() {
    for (lg, ph) in [(512, 512), (512, 4096), (4096, 4096)] {
        let l = layout(128 * GB, lg, ph, 4).unwrap();
        assert_eq!(bytes(&l, &l.msr), 16 * MIB);
        assert_eq!(l.msr.first_lba, l.esp.last_lba + 1);
        assert_eq!(l.windows.first_lba, l.msr.last_lba + 1);
    }
}

#[test]
fn recovery_after_windows_attrs() {
    let l = layout(500 * GB, 512, 512, 5).unwrap();
    assert_eq!(l.recovery.first_lba, l.windows.last_lba + 1);
    assert_eq!(l.recovery.attributes, 0x8000_0000_0000_0001);
    assert_eq!(l.recovery.attributes, RECOVERY_ATTRIBUTES);
    // Windows takes the rest: under 1 MiB is left after recovery before the
    // backup GPT.
    let plan = l.gpt_plan().unwrap();
    let (_, last_usable) = plan.usable();
    assert!(l.recovery.last_lba <= last_usable);
    assert!((last_usable - l.recovery.last_lba) * 512 < MIB);
    assert!(l.windows_bytes() >= WINDOWS_MIN_BYTES);
}

#[test]
fn recovery_size_from_winre() {
    // Small recovery image: the 990 MiB recommendation wins.
    assert_eq!(recovery_partition_bytes(0), Ok(990 * MIB));
    assert_eq!(recovery_partition_bytes(500 * MIB), Ok(990 * MIB));
    // Larger: image + 250 MiB, rounded up to 1 MiB.
    assert_eq!(recovery_partition_bytes(900 * MIB), Ok(1150 * MIB));
    assert_eq!(recovery_partition_bytes(900 * MIB + 1), Ok(1151 * MIB));
    // Out of range.
    assert!(matches!(
        recovery_partition_bytes(65 * GIB),
        Err(LayoutError::RecoveryTooLarge(_))
    ));
    let mut rng = TestRng::new(6);
    let l = WindowsUefiLayout::compute(&facts(128 * GB, 512, 512), 900 * MIB, &mut |b| rng.fill(b))
        .unwrap();
    assert_eq!(bytes(&l, &l.recovery), 1150 * MIB);
}

#[test]
fn all_starts_1mib_aligned() {
    let mut rng = TestRng::new(7);
    for (lg, ph) in [(512, 512), (512, 4096), (4096, 4096)] {
        for _ in 0..50 {
            let size = round_down(64 * GB + rng.next_u64() % (16_000 * GB), lg);
            let l = layout(size, lg, ph, rng.next_u64()).unwrap();
            for p in l.parts() {
                assert_eq!(
                    (p.first_lba * u64::from(lg)) % MIB,
                    0,
                    "{lg}/{ph} size {size} {:?}",
                    p.role
                );
            }
        }
    }
}

#[test]
fn first_partition_at_1mib() {
    assert_eq!(layout(128 * GB, 512, 512, 8).unwrap().esp.first_lba, 2048);
    assert_eq!(layout(128 * GB, 4096, 4096, 8).unwrap().esp.first_lba, 256);
}

#[test]
fn too_small_refused() {
    let r = layout(MIN_DISK_BYTES - 512, 512, 512, 9);
    assert_eq!(
        r,
        Err(LayoutError::TooSmall {
            size: MIN_DISK_BYTES - 512,
            min: MIN_DISK_BYTES
        })
    );
    assert!(layout(MIN_DISK_BYTES, 512, 512, 9).is_ok());
    assert!(layout(round_down(MIN_DISK_BYTES, 4096) + 4096, 4096, 4096, 9).is_ok());
}

#[test]
fn huge_recovery_leaving_windows_under_20gib_refused() {
    let mut rng = TestRng::new(10);
    let r = WindowsUefiLayout::compute(&facts(64 * GB, 512, 512), 50 * GIB, &mut |b| rng.fill(b));
    assert!(matches!(r, Err(LayoutError::TooSmall { .. })), "{r:?}");
}

#[test]
fn other_sector_sizes_refused() {
    for (lg, ph) in [(520, 520), (1024, 1024), (2048, 2048), (4096, 512), (0, 0)] {
        assert_eq!(
            layout(128 * GB, lg, ph, 11),
            Err(LayoutError::UnsupportedSectorSize {
                logical: lg,
                physical: ph
            })
        );
    }
}

#[test]
fn size_not_whole_sectors_refused() {
    assert_eq!(
        layout(128 * GB + 512, 4096, 4096, 12),
        Err(LayoutError::UnalignedSize(128 * GB + 512))
    );
}

#[test]
fn bad_random_source_refused() {
    // A constant source gives five identical GUIDs.
    let r = WindowsUefiLayout::compute(&facts(128 * GB, 512, 512), 0, &mut |b| b.fill(7));
    assert_eq!(r, Err(LayoutError::BadRandom));
}

#[test]
fn random_unique_guids_v4() {
    let a = layout(128 * GB, 512, 512, 13).unwrap();
    let b = layout(128 * GB, 512, 512, 14).unwrap();
    assert_ne!(a.disk_guid, b.disk_guid);
    let mut all = vec![a.disk_guid];
    all.extend(a.parts().iter().map(|p| p.unique_guid));
    for (i, g) in all.iter().enumerate() {
        assert!(!g.is_nil());
        assert!(all.iter().skip(i + 1).all(|h| h != g));
        // RFC 9562 version 4 and variant 10 (uefi-guid-text.md §1.1/§1.2).
        assert_eq!(g.0[7] >> 4, 4);
        assert_eq!(g.0[8] >> 6, 0b10);
        let text = g.to_string();
        assert_eq!(text.as_bytes()[14], b'4', "{text}");
    }
}

#[test]
fn layout_fits_on_its_minimum_disk() {
    for (lg, ph) in [(512, 512), (4096, 4096)] {
        for image in [0, 30 * GB, 70 * GB, 300 * GB] {
            let min = minimum_disk_bytes(lg, 2 * GIB, image).unwrap();
            let size = min.next_multiple_of(u64::from(lg));
            let mut rng = TestRng::new(image + 1);
            let l = WindowsUefiLayout::compute(&facts(size, lg, ph), 2 * GIB, &mut |b| rng.fill(b))
                .unwrap();
            assert!(l.windows_bytes() >= image, "{lg} {image}");
            assert!(l.windows_bytes() >= WINDOWS_MIN_BYTES);
        }
    }
}
