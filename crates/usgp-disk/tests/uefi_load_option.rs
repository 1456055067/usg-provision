//! UEFI `Boot####` and `BootOrder` bytes (REQ-BOOT-065, DEC-0018 items 5
//! and 9; `uefi-boot-manager.md` §10).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), CM-7, SA-11
// - SPEC: specs/boot-network.md#REQ-BOOT-065
// - specs/standards/uefi-boot-manager.md §10.2 to §10.7

pub mod common;

use common::{GB, auth_for, layout};
use usgp_disk::uefi::{
    BootVarName, HardDrive, LoadOption, Node, UefiLimits, WINDOWS_BOOT_MANAGER_PATH,
    encode_boot_order, free_option_number, parse_boot_order, parse_load_option, put_first,
};
use usgp_disk::{GptLimits, MemBlockDevice, UefiError, WipePlan, parse_gpt, wipe_and_write};

fn lim() -> UefiLimits {
    UefiLimits::default()
}

macro_rules! esp_layout {
    () => {
        layout(128 * GB, 512, 512, 77).unwrap()
    };
}

/// A load option header + "A" description + `fpl` + `opt`.
fn option_with(fpl: &[u8], opt: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&u16::try_from(fpl.len()).unwrap_or(u16::MAX).to_le_bytes());
    v.extend_from_slice(&[b'A', 0, 0, 0]);
    v.extend_from_slice(fpl);
    v.extend_from_slice(opt);
    v
}

fn node(t: u8, st: u8, data: &[u8]) -> Vec<u8> {
    let mut v = vec![t, st];
    v.extend_from_slice(
        &u16::try_from(data.len() + 4)
            .unwrap_or(u16::MAX)
            .to_le_bytes(),
    );
    v.extend_from_slice(data);
    v
}

const END: [u8; 4] = [0x7F, 0xFF, 4, 0];

fn hd_data(format: u8, sig_type: u8, sig: [u8; 16]) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&1u32.to_le_bytes());
    d.extend_from_slice(&2048u64.to_le_bytes());
    d.extend_from_slice(&409_600u64.to_le_bytes());
    d.extend_from_slice(&sig);
    d.push(format);
    d.push(sig_type);
    d
}

fn utf16z(units: &[u16]) -> Vec<u8> {
    units.iter().flat_map(|u| u.to_le_bytes()).collect()
}

fn malformed(b: &[u8]) -> Option<UefiError> {
    parse_load_option(b, &lim()).err()
}

#[test]
fn windows_option_round_trip_and_layout() {
    let l = esp_layout!();
    let opt = LoadOption::windows_boot_manager(&l.esp);
    let bytes = opt.encode().unwrap();
    let back = parse_load_option(&bytes, &lim()).unwrap();
    assert_eq!(back, opt);
    assert!(back.points_to(&l.esp));
    assert!(!back.points_to(&l.recovery));
    assert_eq!(back.description_lossy(), "Windows Boot Manager");

    // Byte layout (§10.2): attributes ACTIVE, category boot.
    assert_eq!(&bytes[0..4], &1u32.to_le_bytes());
    let path_units = WINDOWS_BOOT_MANAGER_PATH.len() + 1;
    let fpl_len = 42 + (4 + 2 * path_units) + 4;
    assert_eq!(&bytes[4..6], &u16::try_from(fpl_len).unwrap().to_le_bytes());
    let desc_len = 2 * ("Windows Boot Manager".len() + 1);
    let fpl = &bytes[6 + desc_len..];
    assert_eq!(fpl.len(), fpl_len, "no optional data");
    // Hard Drive node (§10.5).
    assert_eq!(&fpl[0..4], &[0x04, 0x01, 42, 0]);
    assert_eq!(&fpl[4..8], &1u32.to_le_bytes());
    assert_eq!(&fpl[8..16], &l.esp.first_lba.to_le_bytes());
    assert_eq!(&fpl[16..24], &l.esp.len_lbas().to_le_bytes());
    assert_eq!(&fpl[24..40], &l.esp.unique_guid.0);
    assert_eq!(fpl[40], 0x02, "Partition Format GPT");
    assert_eq!(fpl[41], 0x02, "Signature Type GUID");
    // File Path node (§10.6), UTF-16 with a 16-bit null.
    assert_eq!(fpl[42], 0x04);
    assert_eq!(fpl[43], 0x04);
    let fp_len = u16::from_le_bytes([fpl[44], fpl[45]]) as usize;
    assert_eq!(fp_len, 4 + 2 * path_units);
    assert_eq!(&fpl[42 + fp_len - 2..42 + fp_len], &[0, 0]);
    // End node.
    assert_eq!(&fpl[fpl_len - 4..], &END);
}

#[test]
fn hard_drive_node_matches_written_gpt_partition() {
    for lg in [512u32, 4096] {
        let l = layout(128 * GB, lg, lg, 78).unwrap();
        let mut dev = MemBlockDevice::new(l.disk_bytes(), lg).unwrap();
        let wipe = WipePlan::for_disk(&l, &[]).unwrap();
        wipe_and_write(&mut dev, &auth_for(l.disk_bytes(), lg), &wipe, &l).unwrap();
        let view = parse_gpt(&mut dev, &GptLimits::default()).unwrap();
        let (slot, esp_entry) = view.entries[0];
        let bytes = LoadOption::windows_boot_manager(&l.esp).encode().unwrap();
        let opt = parse_load_option(&bytes, &lim()).unwrap();
        match opt.paths[0].as_slice() {
            [Node::HardDrive(hd), Node::FilePath(p), Node::EndEntire] => {
                assert_eq!(hd.partition_number, slot + 1);
                assert_eq!(hd.start_lba, esp_entry.first_lba);
                assert_eq!(hd.size_lbas, esp_entry.last_lba - esp_entry.first_lba + 1);
                assert_eq!(hd.signature, esp_entry.unique_guid.0);
                assert_eq!(p, "\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
            }
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn every_truncation_refused() {
    let l = esp_layout!();
    let bytes = LoadOption::windows_boot_manager(&l.esp).encode().unwrap();
    for n in 0..bytes.len() {
        assert!(
            parse_load_option(&bytes[..n], &lim()).is_err(),
            "prefix of {n} bytes accepted"
        );
    }
}

#[test]
fn optional_data_and_other_nodes_kept() {
    let mut fpl = node(0x01, 0x01, &[1, 2, 3, 4, 5, 6]); // a hardware node
    fpl.extend(node(0x04, 0x01, &hd_data(2, 2, [9; 16])));
    fpl.extend(node(
        0x04,
        0x04,
        &utf16z(&[u16::from(b'\\'), u16::from(b'x'), 0]),
    ));
    fpl.extend(END);
    // A second path in the list.
    fpl.extend(node(0x04, 0x04, &utf16z(&[u16::from(b'y'), 0])));
    fpl.extend(END);
    let b = option_with(&fpl, &[0xDE, 0xAD]);
    let o = parse_load_option(&b, &lim()).unwrap();
    assert_eq!(o.optional_data, vec![0xDE, 0xAD]);
    assert_eq!(o.paths.len(), 2);
    assert_eq!(
        o.paths[0][0],
        Node::Other {
            node_type: 1,
            sub_type: 1,
            data: vec![1, 2, 3, 4, 5, 6]
        }
    );
    assert_eq!(
        o.paths[1],
        vec![Node::FilePath("y".into()), Node::EndEntire]
    );
    // Not ours: the first node is not a Hard Drive node.
    assert!(!o.points_to(&esp_layout!().esp));
    // Re-encoding a parsed option gives the same bytes.
    assert_eq!(o.encode().unwrap(), b);
}

#[test]
fn multi_instance_end_accepted_inside_a_path() {
    let mut fpl = node(0x04, 0x04, &utf16z(&[u16::from(b'a'), 0]));
    fpl.extend([0x7F, 0x01, 4, 0]);
    fpl.extend(node(0x04, 0x04, &utf16z(&[u16::from(b'b'), 0])));
    fpl.extend(END);
    let o = parse_load_option(&option_with(&fpl, &[]), &lim()).unwrap();
    assert_eq!(o.paths.len(), 1);
    assert_eq!(o.paths[0][1], Node::EndInstance);
}

#[test]
fn malformed_device_paths_refused() {
    let fp = |units: &[u16]| node(0x04, 0x04, &utf16z(units));
    let with_end = |mut v: Vec<u8>| {
        v.extend(END);
        v
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty list", vec![]),
        ("no End", fp(&[0x41, 0])),
        ("node length 3", with_end(vec![0x04, 0x04, 3, 0])),
        (
            "node length past list",
            vec![0x04, 0x04, 200, 0, 0x7F, 0xFF, 4, 0],
        ),
        ("End length 5", vec![0x7F, 0xFF, 5, 0, 0]),
        ("End subtype unknown", vec![0x7F, 0x02, 4, 0]),
        (
            "Hard Drive length 41",
            with_end(node(0x04, 0x01, &hd_data(2, 2, [1; 16])[..37])),
        ),
        (
            "Hard Drive format 3",
            with_end(node(0x04, 0x01, &hd_data(3, 2, [1; 16]))),
        ),
        (
            "Hard Drive signature type 3",
            with_end(node(0x04, 0x01, &hd_data(2, 3, [1; 16]))),
        ),
        (
            "signature type 0 with bytes",
            with_end(node(0x04, 0x01, &hd_data(2, 0, [1; 16]))),
        ),
        (
            "MBR signature with tail",
            with_end(node(0x04, 0x01, &hd_data(1, 1, [1; 16]))),
        ),
        (
            "file path odd length",
            with_end(node(0x04, 0x04, &[0x41, 0, 0])),
        ),
        ("file path no null", with_end(fp(&[0x41, 0x42]))),
        ("file path interior null", with_end(fp(&[0x41, 0, 0x42, 0]))),
        (
            "file path unpaired surrogate",
            with_end(fp(&[0xD800, 0x41, 0])),
        ),
        ("bytes after the last End", {
            let mut v = with_end(fp(&[0x41, 0]));
            v.extend([0x04, 0x04]);
            v
        }),
    ];
    for (what, fpl) in cases {
        let r = parse_load_option(&option_with(&fpl, &[]), &lim());
        assert!(
            matches!(
                r,
                Err(UefiError::Malformed { .. } | UefiError::Truncated { .. })
            ),
            "{what}: {r:?}"
        );
    }
    // Valid MBR and no-signature Hard Drive nodes parse.
    for d in [
        hd_data(1, 1, [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        hd_data(2, 0, [0; 16]),
    ] {
        let r = parse_load_option(&option_with(&with_end(node(0x04, 0x01, &d)), &[]), &lim());
        assert!(r.is_ok(), "{r:?}");
    }
}

#[test]
fn malformed_option_headers_refused() {
    // FilePathListLength past the end.
    let mut b = option_with(&END, &[]);
    b[4] = 200;
    assert!(matches!(malformed(&b), Some(UefiError::Truncated { .. })));
    // Description never terminated.
    let mut b = vec![1, 0, 0, 0, 4, 0];
    b.extend([0x41, 0, 0x42, 0]);
    assert!(matches!(malformed(&b), Some(UefiError::Truncated { .. })));
    // Odd byte where the terminator should be.
    assert!(matches!(
        malformed(&[1, 0, 0, 0, 4, 0, 0x41]),
        Some(UefiError::Truncated { .. })
    ));
}

#[test]
fn oversized_values_hit_limits() {
    let l = esp_layout!();
    let bytes = LoadOption::windows_boot_manager(&l.esp).encode().unwrap();
    let tight = UefiLimits {
        max_option_bytes: bytes.len() - 1,
        ..lim()
    };
    assert_eq!(
        parse_load_option(&bytes, &tight),
        Err(UefiError::Limit("load option size"))
    );
    let tight = UefiLimits {
        max_description_units: 5,
        ..lim()
    };
    assert_eq!(
        parse_load_option(&bytes, &tight),
        Err(UefiError::Limit("description length"))
    );
    let tight = UefiLimits {
        max_path_units: 10,
        ..lim()
    };
    assert_eq!(
        parse_load_option(&bytes, &tight),
        Err(UefiError::Limit("file path length"))
    );
    // Too many nodes.
    let mut fpl = Vec::new();
    for _ in 0..65 {
        fpl.extend(node(0x01, 0x01, &[]));
    }
    fpl.extend(END);
    assert_eq!(
        parse_load_option(&option_with(&fpl, &[]), &lim()),
        Err(UefiError::Limit("device path nodes"))
    );
    // A 64 KiB + 1 value is refused before parsing.
    assert_eq!(
        parse_load_option(&vec![0u8; 64 * 1024 + 1], &lim()),
        Err(UefiError::Limit("load option size"))
    );
}

#[test]
fn encode_refuses_what_it_cannot_write_unambiguously() {
    let l = esp_layout!();
    let mut o = LoadOption::windows_boot_manager(&l.esp);
    o.description = "Windows \u{e9}".encode_utf16().collect();
    assert!(matches!(o.encode(), Err(UefiError::Encode(_))));
    let mut o = LoadOption::windows_boot_manager(&l.esp);
    o.paths[0][1] = Node::FilePath("\\EFI\\\u{e9}.efi".into());
    assert!(matches!(o.encode(), Err(UefiError::Encode(_))));
    let mut o = LoadOption::windows_boot_manager(&l.esp);
    o.paths[0].pop();
    assert!(matches!(o.encode(), Err(UefiError::Encode(_))));
    let mut o = LoadOption::windows_boot_manager(&l.esp);
    o.paths.clear();
    assert!(matches!(o.encode(), Err(UefiError::Encode(_))));
    let mut o = LoadOption::windows_boot_manager(&l.esp);
    o.paths[0].insert(0, Node::EndEntire);
    assert!(matches!(o.encode(), Err(UefiError::Encode(_))));
}

#[test]
fn points_to_requires_active_boot_category_and_exact_esp() {
    let l = esp_layout!();
    let mut o = LoadOption::windows_boot_manager(&l.esp);
    o.paths[0][1] = Node::FilePath("\\efi\\microsoft\\boot\\BOOTMGFW.EFI".into());
    assert!(o.points_to(&l.esp), "path matched case-insensitively");
    o.attributes = 0;
    assert!(!o.points_to(&l.esp), "inactive");
    o.attributes = 1 | 0x100;
    assert!(!o.points_to(&l.esp), "application category");
    let mut o = LoadOption::windows_boot_manager(&l.esp);
    if let Node::HardDrive(hd) = &mut o.paths[0][0] {
        hd.signature[0] ^= 1;
    }
    assert!(!o.points_to(&l.esp), "other partition GUID");
    let other = layout(128 * GB, 512, 512, 79).unwrap();
    assert!(!LoadOption::windows_boot_manager(&other.esp).points_to(&l.esp));
    assert_eq!(
        HardDrive::for_gpt_part(&l.esp).signature,
        l.esp.unique_guid.0
    );
}

#[test]
fn only_boot_order_and_boot_options_can_be_named() {
    assert_eq!(BootVarName::boot_order().to_string(), "BootOrder");
    assert_eq!(BootVarName::boot_option(1).to_string(), "Boot0001");
    assert_eq!(BootVarName::boot_option(0x0A02).to_string(), "Boot0A02");
    assert_eq!(BootVarName::boot_option(0xFFFF).to_string(), "BootFFFF");
    for n in [0u16, 1, 0x0A02, 0xBEEF, 0xFFFF] {
        let v = BootVarName::boot_option(n);
        assert_eq!(BootVarName::from_name(&v.to_string()), Some(v));
        assert_eq!(v.option_number(), Some(n));
    }
    assert_eq!(
        BootVarName::from_name("BootOrder"),
        Some(BootVarName::boot_order())
    );
    for bad in [
        "PK",
        "KEK",
        "db",
        "dbx",
        "dbt",
        "dbr",
        "SecureBoot",
        "SetupMode",
        "AuditMode",
        "DeployedMode",
        "BootNext",
        "BootCurrent",
        "BootOptionSupport",
        "Timeout",
        "boot0001",
        "Boot000a",
        "Boot001",
        "Boot00001",
        "Boot+001",
        "Boot 001",
        "BootOrderX",
        "Driver0001",
        "SysPrep0001",
        "PlatformRecovery0000",
        "",
    ] {
        assert_eq!(BootVarName::from_name(bad), None, "{bad}");
    }
    let v = BootVarName::boot_option(3);
    assert_eq!(
        v.vendor().to_string(),
        "8BE4DF61-93CA-11D2-AA0D-00E098032B8C"
    );
    assert_eq!(v.attributes(), 0x0000_0007);
    assert_eq!(BootVarName::boot_order().attributes(), 0x0000_0007);
}

#[test]
fn boot_order_round_trip_and_errors() {
    let order = vec![3u16, 0x0A02, 0, 0xFFFF];
    let b = encode_boot_order(&order);
    assert_eq!(b, vec![3, 0, 2, 0x0A, 0, 0, 0xFF, 0xFF]);
    assert_eq!(parse_boot_order(&b, &lim()), Ok(order));
    assert_eq!(parse_boot_order(&[], &lim()), Ok(vec![]));
    assert!(matches!(
        parse_boot_order(&[1, 0, 2], &lim()),
        Err(UefiError::Malformed { .. })
    ));
    assert_eq!(
        parse_boot_order(&vec![0u8; 2 * 1025], &lim()),
        Err(UefiError::Limit("BootOrder entries"))
    );
}

#[test]
fn put_first_keeps_rest_in_order_deduplicated() {
    assert_eq!(put_first(&[], 4), vec![4]);
    assert_eq!(put_first(&[3, 1, 2], 1), vec![1, 3, 2]);
    assert_eq!(put_first(&[1, 3, 2], 1), vec![1, 3, 2]);
    assert_eq!(put_first(&[2, 2, 5, 1, 5, 7, 2], 7), vec![7, 2, 5, 1]);
    assert_eq!(put_first(&[0x10, 0x11], 0x0A), vec![0x0A, 0x10, 0x11]);
    // Full edit through bytes, as the engine does it.
    let current = encode_boot_order(&[0x0004, 0x0001, 0x0004]);
    let next = put_first(&parse_boot_order(&current, &lim()).unwrap(), 0x0002);
    assert_eq!(
        parse_boot_order(&encode_boot_order(&next), &lim()).unwrap(),
        vec![2, 4, 1]
    );
}

#[test]
fn free_option_number_lowest_unused() {
    assert_eq!(free_option_number(&[]), Some(0));
    assert_eq!(free_option_number(&[0, 1, 3]), Some(2));
    let all: Vec<u16> = (0..=u16::MAX).collect();
    assert_eq!(free_option_number(&all), None);
}
