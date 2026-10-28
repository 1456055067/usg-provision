//! Disk eligibility rules (REQ-DISK-004, REQ-DISK-005; OPEN-DISK-4 and
//! OPEN-DISK-5 fail closed).

pub mod common;

use common::{GB, MIB, facts};
use usgp_disk::layout::MIN_DISK_BYTES;
use usgp_disk::{
    Bus, EligibilityPolicy, ExistingPartition, Ineligible, assess, assess_all, minimum_disk_bytes,
};

const DISK: u64 = 256 * GB;

fn release() -> EligibilityPolicy {
    EligibilityPolicy::default()
}

#[test]
fn internal_nvme_disk_is_eligible() {
    assert_eq!(
        assess(&facts(DISK, 512, 512), &release(), MIN_DISK_BYTES),
        Ok(())
    );
}

#[test]
fn too_small_refused_shows_min() {
    let f = facts(60 * GB, 512, 512);
    assert_eq!(
        assess(&f, &release(), MIN_DISK_BYTES),
        Err(Ineligible::TooSmall {
            size: 60 * GB,
            min: MIN_DISK_BYTES
        })
    );
    let shown = assess(&f, &release(), MIN_DISK_BYTES)
        .unwrap_err()
        .to_string();
    assert!(
        shown.contains("60000000000") && shown.contains("64000000000"),
        "{shown}"
    );
}

#[test]
fn minimum_never_below_64gb() {
    // A caller passing a lower minimum cannot lower the floor (OPEN-DISK-1).
    let f = facts(63 * GB, 512, 512);
    assert_eq!(
        assess(&f, &release(), 1),
        Err(Ineligible::TooSmall {
            size: 63 * GB,
            min: MIN_DISK_BYTES
        })
    );
    assert_eq!(
        assess(&facts(MIN_DISK_BYTES, 512, 512), &release(), 1),
        Ok(())
    );
}

#[test]
fn min_is_max_of_64gb_and_layout_plus_image() {
    // Small image: the 64 GB floor wins.
    assert_eq!(
        minimum_disk_bytes(512, 600 * MIB, 10 * GB),
        Ok(MIN_DISK_BYTES)
    );
    // Large image: layout plus image wins and exceeds the image itself.
    let image = 100 * GB;
    let min = minimum_disk_bytes(4096, 600 * MIB, image).unwrap();
    assert!(min > image + 300 * MIB + 16 * MIB + 990 * MIB, "{min}");
    let f = facts(min - 4096, 4096, 4096);
    assert!(matches!(
        assess(&f, &release(), min),
        Err(Ineligible::TooSmall { .. })
    ));
    assert_eq!(assess(&facts(min, 4096, 4096), &release(), min), Ok(()));
}

#[test]
fn removable_refused() {
    let mut f = facts(DISK, 512, 512);
    f.removable = true;
    assert_eq!(
        assess(&f, &release(), MIN_DISK_BYTES),
        Err(Ineligible::Removable)
    );
}

#[test]
fn usb_fixed_refused_open_disk_4() {
    let mut f = facts(DISK, 512, 512);
    f.bus = Bus::Usb;
    f.removable = false;
    assert_eq!(
        assess(&f, &release(), MIN_DISK_BYTES),
        Err(Ineligible::UsbDisk)
    );
}

#[test]
fn boot_media_refused() {
    let mut f = facts(DISK, 512, 512);
    f.hosts_boot_environment = true;
    assert_eq!(
        assess(&f, &release(), MIN_DISK_BYTES),
        Err(Ineligible::BootMedia)
    );
}

#[test]
fn read_only_refused_open_disk_5a() {
    let mut f = facts(DISK, 512, 512);
    f.read_only = true;
    assert_eq!(
        assess(&f, &release(), MIN_DISK_BYTES),
        Err(Ineligible::ReadOnly)
    );
}

#[test]
fn sector_sizes_512n_512e_4kn_accepted_others_refused() {
    for (l, p) in [(512, 512), (512, 4096), (4096, 4096)] {
        assert_eq!(
            assess(&facts(DISK, l, p), &release(), MIN_DISK_BYTES),
            Ok(()),
            "{l}/{p}"
        );
    }
    for (l, p) in [
        (520, 520),
        (1024, 1024),
        (2048, 2048),
        (4096, 512),
        (512, 8192),
        (0, 0),
    ] {
        assert_eq!(
            assess(&facts(DISK, l, p), &release(), MIN_DISK_BYTES),
            Err(Ineligible::UnsupportedSectorSize {
                logical: l,
                physical: p
            }),
            "{l}/{p}"
        );
    }
}

#[test]
fn sd_mmc_unknown_and_other_buses_refused_open_disk_5c() {
    for bus in [
        Bus::Sd,
        Bus::Mmc,
        Bus::Unknown,
        Bus::Atapi,
        Bus::Ieee1394,
        Bus::Virtual,
        Bus::Other(200),
    ] {
        let mut f = facts(DISK, 512, 512);
        f.bus = bus;
        assert_eq!(
            assess(&f, &release(), MIN_DISK_BYTES),
            Err(Ineligible::UnsupportedBus(bus)),
            "{bus}"
        );
    }
    for bus in [
        Bus::Ata,
        Bus::Sata,
        Bus::Scsi,
        Bus::Sas,
        Bus::Nvme,
        Bus::Raid,
    ] {
        let mut f = facts(DISK, 512, 512);
        f.bus = bus;
        assert_eq!(assess(&f, &release(), MIN_DISK_BYTES), Ok(()), "{bus}");
    }
}

#[test]
fn file_backed_virtual_refused_in_release_allowed_only_by_test_policy() {
    let mut f = facts(DISK, 512, 512);
    f.bus = Bus::FileBackedVirtual;
    assert_eq!(
        assess(&f, &release(), MIN_DISK_BYTES),
        Err(Ineligible::UnsupportedBus(Bus::FileBackedVirtual))
    );
    let test_policy = EligibilityPolicy {
        allow_file_backed_virtual: true,
    };
    assert_eq!(assess(&f, &test_policy, MIN_DISK_BYTES), Ok(()));
    // The test policy does not open the door to USB.
    f.bus = Bus::Usb;
    assert_eq!(
        assess(&f, &test_policy, MIN_DISK_BYTES),
        Err(Ineligible::UsbDisk)
    );
}

#[test]
fn disk_with_existing_partitions_is_eligible_and_lists_them() {
    let mut f = facts(DISK, 512, 512);
    f.partitions = vec![
        ExistingPartition {
            start_bytes: MIB,
            size_bytes: 100 * MIB,
            label: Some("SYSTEM".to_owned()),
        },
        ExistingPartition {
            start_bytes: 101 * MIB,
            size_bytes: 200 * GB,
            label: Some("Data".to_owned()),
        },
    ];
    assert_eq!(assess(&f, &release(), MIN_DISK_BYTES), Ok(()));
    assert_eq!(f.partitions.len(), 2);
}

#[test]
fn all_reasons_reported_in_fixed_order() {
    let mut f = facts(10 * GB, 520, 520);
    f.hosts_boot_environment = true;
    f.removable = true;
    f.bus = Bus::Usb;
    f.read_only = true;
    assert_eq!(
        assess_all(&f, &release(), MIN_DISK_BYTES),
        vec![
            Ineligible::BootMedia,
            Ineligible::Removable,
            Ineligible::UsbDisk,
            Ineligible::ReadOnly,
            Ineligible::UnsupportedSectorSize {
                logical: 520,
                physical: 520
            },
            Ineligible::TooSmall {
                size: 10 * GB,
                min: MIN_DISK_BYTES
            },
        ]
    );
    assert_eq!(
        assess(&f, &release(), MIN_DISK_BYTES),
        Err(Ineligible::BootMedia)
    );
}
