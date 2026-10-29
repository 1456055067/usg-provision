//! The device's screens (REQ-TGT-004, -006, -013; REQ-DISK-001..006;
//! REQ-JOB-002..005): exact content checks on the pure renderers.

#![cfg(test)]

use usgp_disk::{Bus, DiskFacts, DiskIdentity, EligibilityPolicy, ExistingPartition};
use usgp_preboot_agent::disks::{Discriminator, FoundDisk, Inventory};
use usgp_preboot_agent::ui::{self, JobScreen};
use usgp_proto::device::{DevicePackageV1, MacAddress};
use usgp_proto::disk::PartitionKind;
use usgp_proto::{DiskToken, DisplayCode};

fn package() -> DevicePackageV1 {
    serde_json::from_value(serde_json::json!({
        "package_id": "1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516", "revision": 1,
        "name": "Windows 11 Enterprise", "description": "Standard desktop",
        "os": {"release": "windows-11", "edition": "enterprise", "architecture": "x64", "source": "declared"},
        "image_bytes": 5_000_000_000u64, "required_disk_bytes": 64_000_000_000u64
    }))
    .unwrap()
}

fn disk(n: u32, size: u64, bus: Bus) -> FoundDisk {
    FoundDisk {
        facts: DiskFacts {
            identity: DiskIdentity {
                device_number: n,
                model: format!("Model {n}"),
                serial: Some(format!("SN-{n}")),
            },
            bus,
            removable: false,
            read_only: false,
            logical_sector: 512,
            physical_sector: 4096,
            size_bytes: size,
            hosts_boot_environment: false,
            partitions: vec![
                ExistingPartition {
                    start_bytes: 1 << 20,
                    size_bytes: 100 << 20,
                    label: Some("EFI".to_owned()),
                },
                ExistingPartition {
                    start_bytes: 101 << 20,
                    size_bytes: 50_000_000_000,
                    label: Some("Data".to_owned()),
                },
            ],
        },
        kinds: vec![PartitionKind::Esp, PartitionKind::Basic],
        volumes_known: true,
        discriminator: Discriminator::default(),
    }
}

fn inventory() -> Inventory {
    let mut n = 0u8;
    let mut usb = disk(2, 128_000_000_000, Bus::Usb);
    usb.facts.removable = true;
    let mut boot = disk(3, 256_000_000_000, Bus::Sata);
    boot.facts.hosts_boot_environment = true;
    Inventory::build(
        vec![
            disk(1, 512_000_000_000, Bus::Nvme),
            usb,
            boot,
            disk(4, 32_000_000_000, Bus::Sata),
        ],
        &EligibilityPolicy::default(),
        64_000_000_000,
        &mut || {
            n += 1;
            DiskToken::from_random_bytes([n; 16])
        },
    )
}

#[test]
fn package_list_shows_name_description_and_os() {
    let s = ui::packages_screen(&[package()], None);
    assert!(s.contains("  1) Windows 11 Enterprise"));
    assert!(s.contains("Standard desktop"));
    assert!(s.contains("windows-11 enterprise x64"));
    assert!(s.contains("64.0 GB"));
    assert!(s.contains("Type C to cancel"));
}

#[test]
fn disk_list_numbers_eligible_and_explains_refusals() {
    let s = ui::disks_screen("Windows 11 Enterprise", &inventory(), None);
    assert!(
        s.contains("  1) 512.0 GB - Model 1 - NVMe - 2 existing partitions"),
        "{s}"
    );
    assert!(!s.contains("  2)"), "only one disk is choosable: {s}");
    assert!(s.contains("because: removable media"));
    assert!(s.contains("because: USB-attached disk"));
    assert!(s.contains("because: holds the running boot environment"));
    assert!(s.contains("because: too small: 32.0 GB"));
    assert!(s.contains("Type B to go back, C to cancel"));
}

#[test]
fn wipe_screen_is_separate_and_lists_partitions() {
    let inv = inventory();
    let e = inv.eligible().next().unwrap();
    let macs = vec![
        MacAddress::new([0x02, 0, 0, 0, 0, 0x01]).unwrap(),
        MacAddress::new([0x02, 0, 0, 0, 0, 0x02]).unwrap(),
    ];
    let s = ui::wipe_screen(&package(), e, &macs);
    // Decision 0023 item 2: the claimed MACs are shown at confirmation.
    assert!(s.contains("network boot is stopped for these addresses"));
    assert!(s.contains("02:00:00:00:00:01") && s.contains("02:00:00:00:00:02"));
    assert!(!ui::wipe_screen(&package(), e, &[]).contains("Network adapters"));
    assert!(s.contains("EVERY PARTITION AND ALL DATA ON THIS DISK WILL BE DESTROYED"));
    assert!(s.contains("esp") && s.contains("\"EFI\""));
    assert!(s.contains("basic") && s.contains("\"Data\"") && s.contains("50.0 GB"));
    assert!(s.contains("Serial:   SN-1"));
    assert!(s.contains("Type WIPE"));
    assert!(s.contains("cannot be cancelled"));
}

#[test]
fn authorise_screen_shows_display_code_never_a_code() {
    let d = DisplayCode::parse("ABC-DEF").unwrap();
    let s = ui::authorise_screen(
        &d,
        4,
        Some("Relay One"),
        Some("That code was not accepted."),
    );
    assert!(s.contains("Display code:   ABC-DEF"));
    assert!(s.contains("is not shown"));
    assert!(s.contains("Code attempts left: 4"));
    assert!(s.contains("Relay One"));
}

#[test]
fn job_screen_never_shows_completion_without_success() {
    let j = JobScreen::default();
    let s = j.render();
    assert!(s.contains("Installing"));
    assert!(!s.contains("complete"));
    assert!(s.contains("[ ]       1. Download and verify the content"));
    assert!(s.contains("5. Report success and restart"));
}

#[test]
fn stop_screen_waits_for_the_person() {
    let s = ui::stop_screen("No disk can be used", &["x".to_owned()]);
    assert!(s.contains("Nothing more will happen until you act."));
    assert!(s.contains("Type R and Enter to restart, or S and Enter to shut down."));
}
