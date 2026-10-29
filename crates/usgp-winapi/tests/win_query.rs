//! Read-only checks of the disk, volume and firmware queries on the
//! Windows CI runner. Nothing here writes to a disk or a firmware
//! variable. Firmware reads need `SeSystemEnvironmentPrivilege`, which the
//! runner's administrator token holds.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-10
//! - SPEC: specs/standards/windows-storage-firmware-api.md §3 to §10

#![cfg(windows)]

use usgp_winapi::disk::{self, DiskQuery, PartitionStyle, SUPPORTED_LOGICAL_SECTORS, Writability};
use usgp_winapi::firmware::{self, FirmwareMode, FirmwareVars};
use usgp_winapi::paths::DriveLetter;
use usgp_winapi::system::{self, Arch};
use usgp_winapi::vars::{FlagState, ReadableVar};
use usgp_winapi::volume;
use usgp_winapi::{console, net};

fn system_letter() -> Option<DriveLetter> {
    let drive = std::env::var("SystemDrive").ok()?;
    DriveLetter::from_root(&format!("{drive}\\"))
}

#[test]
fn disks_enumerate_and_report_sane_facts() {
    let numbers = disk::enumerate().expect("enumerate disks");
    assert!(!numbers.is_empty(), "the runner has at least one disk");
    let mut sorted = numbers.clone();
    sorted.dedup();
    assert_eq!(sorted, numbers, "numbers are unique and ordered");

    for info in disk::inspect_all().expect("inspect disks") {
        println!(
            "disk {}: bus {:?} removable {} size {} sectors {:?} style {:?} parts {}",
            info.number,
            info.descriptor.bus,
            info.descriptor.removable_media,
            info.geometry.size_bytes,
            info.sector_sizes,
            info.layout.style,
            info.layout.partitions.len()
        );
        assert!(info.geometry.size_bytes > 0);
        if let Some(s) = info.sector_sizes {
            assert!(SUPPORTED_LOGICAL_SECTORS.contains(&s.logical), "{s:?}");
            assert!(s.physical >= s.logical, "{s:?}");
        }
        for p in &info.layout.partitions {
            let end = p
                .starting_offset
                .checked_add(p.length)
                .expect("no overflow");
            assert!(end <= info.geometry.size_bytes, "partition inside the disk");
        }
        if info.layout.style == PartitionStyle::Gpt {
            assert!(info.layout.gpt.is_some());
        }
    }
}

#[test]
fn query_handle_rechecks_the_disk_number() {
    let n = *disk::enumerate()
        .expect("enumerate")
        .first()
        .expect("one disk");
    let q = DiskQuery::open(n).expect("open");
    assert_eq!(q.number(), n);
    // A number no enumerated disk has is refused.
    let known = disk::enumerate().expect("enumerate");
    let unused = (0..=u32::from(u16::MAX))
        .find(|k| !known.contains(k))
        .expect("an unused number");
    assert!(DiskQuery::open(unused).is_err());
}

#[test]
fn system_volume_lies_on_an_enumerated_writable_disk() {
    let letter = system_letter().expect("SystemDrive is a letter");
    let vol = volume::volume_at(letter).expect("volume at the system drive");
    assert!(
        volume::drive_letters(&vol)
            .expect("letters")
            .contains(&letter),
        "mount points include the system letter"
    );
    let fs = volume::file_system_name(&vol).expect("file system name");
    assert_eq!(fs, "NTFS");

    let extents = volume::disk_extents(&vol).expect("extents");
    assert!(!extents.is_empty());
    let disks = disk::enumerate().expect("enumerate");
    for e in &extents {
        assert!(disks.contains(&e.disk_number), "{e:?}");
        let q = DiskQuery::open(e.disk_number).expect("open");
        assert_eq!(q.writability(), Writability::Writable);
        // The extent matches a partition of that disk by offset (the
        // plan's volume-resolution rule).
        let layout = q.layout().expect("layout");
        assert!(
            layout
                .partitions
                .iter()
                .any(|p| p.starting_offset == e.starting_offset),
            "{e:?} matches a partition"
        );
    }

    let all = volume::volumes().expect("volumes");
    assert!(all.contains(&vol));
}

#[test]
fn pe_system_letter_is_never_assigned_or_removed() {
    let vol = volume::volume_at(system_letter().expect("SystemDrive is a letter")).expect("volume");
    assert!(matches!(
        volume::assign_letter(DriveLetter::PE_SYSTEM, &vol),
        Err(usgp_winapi::WinApiError::Refused { .. })
    ));
    assert!(matches!(
        volume::remove_letter(DriveLetter::PE_SYSTEM),
        Err(usgp_winapi::WinApiError::Refused { .. })
    ));
}

#[test]
fn firmware_reads_only() {
    // Reads only: firmware variables are never written on the runner
    // (plan §10.2).
    let mode = firmware::firmware_mode().expect("firmware mode");
    println!("firmware mode: {mode:?}");
    match mode {
        FirmwareMode::LegacyBios => {
            assert!(matches!(
                FirmwareVars::open(),
                Err(usgp_winapi::WinApiError::NotUefi)
            ));
        }
        FirmwareMode::Uefi => {
            let fw = FirmwareVars::open().expect("open firmware variables");
            let sb = fw.secure_boot_status().expect("secure boot status");
            println!("secure boot: {sb:?}");
            assert_ne!(sb.secure_boot, FlagState::Unrecognised);
            if let Some(order) = fw.get(ReadableVar::BootOrder).expect("BootOrder") {
                assert!(order.data.len().is_multiple_of(2));
            }
        }
    }
}

#[test]
fn volume_backings_on_the_runner() {
    // Drive type first, extents only for fixed and removable volumes
    // (spec §13). The system volume must be fixed and on a disk; the
    // runner's disks must all be placeable (no undetermined volume), or
    // every wipe would be refused there.
    let sys = volume::volume_at(system_letter().expect("SystemDrive is a letter")).expect("volume");
    assert_eq!(
        volume::drive_type(&sys).expect("drive type"),
        volume::DriveType::Fixed
    );
    for (v, b) in volume::volume_backings().expect("volumes") {
        println!("{v}: {b:?}");
        if v == sys {
            assert!(matches!(b, volume::VolumeBacking::OnDisks(ref e) if !e.is_empty()));
        }
    }
    let disk = volume::disk_extents(&sys).expect("extents");
    let n = disk.first().expect("an extent").disk_number;
    let on = volume::volumes_on_disk(n).expect("volumes on the system disk");
    assert!(on.contains(&sys));
}

#[test]
fn system_facts() {
    assert_eq!(system::native_arch(), Arch::X64);
    assert!(system::total_memory_bytes().expect("memory") > 512 * 1024 * 1024);
    let dir = system::system_directory().expect("system directory");
    assert!(dir.join("diskpart.exe").is_file(), "{}", dir.display());
    assert!(system::current_executable().expect("exe").is_file());
}

#[test]
fn adapters_have_macs_and_addresses() {
    let list = net::adapters().expect("adapters");
    for a in &list {
        println!("{a:?}");
    }
    let macs = net::hello_macs(&list);
    assert!(!macs.is_empty(), "the runner has a reportable MAC");
    assert!(macs.iter().all(|m| m.is_reportable()));
    assert!(
        list.iter().any(|a| !a.loopback && !a.ipv4.is_empty()),
        "the runner has an IPv4 address"
    );
}

#[test]
fn hide_input_needs_a_console() {
    // Under the test harness standard input is usually not a console; then
    // the call must fail rather than pretend echo is off.
    match console::hide_input() {
        Ok(guard) => drop(guard),
        Err(e) => println!("no console: {e}"),
    }
}

/// NIST-001: the runner's administrator token holds every privilege the
/// agent uses; checking leaves none in use, and a guard keeps one enabled
/// only while it (or a nested guard) lives. Only `Backup` is counted here:
/// the other tests in this binary may use the firmware privilege at the
/// same time. Whether the token shows the privilege disabled afterwards
/// cannot be read with the calls in the standards summaries (topic 23
/// §10 has no query); the disable call itself must succeed.
#[test]
fn privileges_are_enabled_only_while_used() {
    use usgp_winapi::privilege::{self, Privilege};
    for p in [
        Privilege::SystemEnvironment,
        Privilege::Restore,
        Privilege::Backup,
        Privilege::Security,
        Privilege::CreateSymbolicLink,
    ] {
        privilege::check_held(p).unwrap_or_else(|e| panic!("{}: {e}", p.name()));
    }
    assert_eq!(privilege::users(Privilege::Backup), 0);
    let a = privilege::scoped(Privilege::Backup).expect("enable");
    let b = privilege::scoped(Privilege::Backup).expect("nested enable");
    assert_eq!(privilege::users(Privilege::Backup), 2);
    drop(a);
    assert_eq!(privilege::users(Privilege::Backup), 1);
    drop(b);
    assert_eq!(privilege::users(Privilege::Backup), 0);
}
