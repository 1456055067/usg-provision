//! The Windows boot option made first in `BootOrder` (REQ-BOOT-065,
//! DEC-0018 item 9), against an in-memory firmware store.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11, CM-7 (only boot-order variables), SI-7 (read-back)
// - SPEC: specs/boot-network.md#REQ-BOOT-065
// - SPEC: specs/standards/uefi-boot-manager.md §2, §10.2, §10.3

pub mod common;

use common::{MemFirmware, boot_order_of as order, test_esp as esp};
use usgp_deploy::{BootEntryError, FwError, make_windows_first};
use usgp_disk::uefi::{LoadOption, UefiLimits, encode_boot_order};

#[test]
fn empty_firmware_gets_boot0000_alone() {
    let mut fw = MemFirmware::default();
    let e = make_windows_first(&mut fw, &esp(1), &UefiLimits::default()).unwrap();
    assert_eq!((e.option, e.reused), (0, false));
    assert_eq!(order(&fw), vec![0]);
    assert_eq!(fw.written, vec!["Boot0000", "BootOrder"]);
}

#[test]
fn lowest_free_number_not_in_order_and_not_present() {
    let mut fw = MemFirmware::default();
    for n in [0u16, 2] {
        fw.vars.insert(format!("Boot{n:04X}"), vec![9]);
    }
    fw.vars
        .insert("BootOrder".to_owned(), encode_boot_order(&[3, 1, 0]));
    let e = make_windows_first(&mut fw, &esp(1), &UefiLimits::default()).unwrap();
    // 0 and 2 exist; 1 and 3 are in BootOrder (even without a variable).
    assert_eq!(e.option, 4);
    assert_eq!(order(&fw), vec![4, 3, 1, 0]);
    assert_eq!(fw.vars["Boot0000"], vec![9], "others untouched");
}

#[test]
fn existing_option_for_our_esp_is_reused_and_moved_first() {
    let part = esp(1);
    let mut fw = MemFirmware::default();
    let ours = LoadOption::windows_boot_manager(&part).encode().unwrap();
    fw.vars.insert("Boot0007".to_owned(), ours);
    fw.vars.insert("Boot0002".to_owned(), vec![1, 2, 3]); // does not parse
    fw.vars
        .insert("BootOrder".to_owned(), encode_boot_order(&[2, 7, 2]));
    let e = make_windows_first(&mut fw, &part, &UefiLimits::default()).unwrap();
    assert_eq!((e.option, e.reused), (7, true));
    assert_eq!(order(&fw), vec![7, 2], "repeats dropped, order kept");
    assert_eq!(fw.written, vec!["BootOrder"], "no option rewritten");
    assert_eq!(fw.vars["Boot0002"], vec![1, 2, 3]);
}

#[test]
fn option_for_another_esp_is_not_reused() {
    let mut fw = MemFirmware::default();
    let other = LoadOption::windows_boot_manager(&esp(9)).encode().unwrap();
    fw.vars.insert("Boot0000".to_owned(), other);
    fw.vars
        .insert("BootOrder".to_owned(), encode_boot_order(&[0]));
    let e = make_windows_first(&mut fw, &esp(1), &UefiLimits::default()).unwrap();
    assert_eq!((e.option, e.reused), (1, false));
    assert_eq!(order(&fw), vec![1, 0]);
}

#[test]
fn malformed_boot_order_is_refused_and_kept() {
    let mut fw = MemFirmware::default();
    fw.vars.insert("BootOrder".to_owned(), vec![0, 0, 1]);
    let e = make_windows_first(&mut fw, &esp(1), &UefiLimits::default()).unwrap_err();
    assert!(matches!(e, BootEntryError::BadBootOrder(_)));
    assert!(fw.written.is_empty());
}

#[test]
fn firmware_refusal_and_dropped_writes_are_errors() {
    let mut fw = MemFirmware {
        fail_set: Some(FwError::Unsupported),
        ..MemFirmware::default()
    };
    let e = make_windows_first(&mut fw, &esp(1), &UefiLimits::default()).unwrap_err();
    assert_eq!(e, BootEntryError::Firmware(FwError::Unsupported));

    let mut fw = MemFirmware {
        drop_writes: true,
        ..MemFirmware::default()
    };
    let e = make_windows_first(&mut fw, &esp(1), &UefiLimits::default()).unwrap_err();
    assert_eq!(e, BootEntryError::ReadBack("boot option"));
}

#[test]
fn no_free_number_within_the_probe_bound() {
    let mut fw = MemFirmware::default();
    for n in 0..usgp_deploy::bootentry::MAX_OPTION_PROBES {
        fw.vars.insert(format!("Boot{n:04X}"), vec![1]);
    }
    let e = make_windows_first(&mut fw, &esp(1), &UefiLimits::default()).unwrap_err();
    assert_eq!(e, BootEntryError::NoFreeNumber);
    assert!(fw.written.is_empty());
}
