//! Fuzz target `efi_load_option`: UEFI `Boot####` and `BootOrder`
//! variable data and variable names (`usgp-disk` `uefi`).
//!
//! Octet 0 selects the path (modulo 4); the rest is the input:
//!
//! - 0: a `Boot####` value for `parse_load_option`, under the default
//!   limits and under limits taken from octets 1 to 5 (each a cap on one
//!   limit), then the value without those octets;
//! - 1: a `BootOrder` value for `parse_boot_order`, then `put_first` with
//!   the first two octets as the option number and `free_option_number`;
//! - 2: a variable name for `BootVarName::from_name`;
//! - 3: an ESP partition (number, start, size and GUID from the input)
//!   for `LoadOption::windows_boot_manager`, encoded and parsed back.
//!
//! Invariants (plan WU-14; impl-notes-wu3 `src/uefi.rs`):
//!
//! - no panic;
//! - an accepted load option has every device path ending in one End
//!   node, within the node, description and path limits; it re-encodes
//!   to exactly the input bytes whenever `encode` accepts it, and
//!   `encode` accepts it whenever its text is printable ASCII (the
//!   OPEN-UBM-2 rule); `parse(encode(o)) == o`;
//! - limits are monotone: what tighter limits accept, the defaults accept
//!   with the same result;
//! - `BootOrder`: odd lengths refused, at most the entry limit, encode
//!   round trip; `put_first` is `n` then the first occurrences of the
//!   rest in order (reference model); `free_option_number` is the lowest
//!   unused number (reference model);
//! - names: only `BootOrder` and `Boot` + four upper-case hex digits are
//!   accepted (reference model; never a Secure Boot variable), `Display`
//!   gives the input back, the vendor is `EFI_GLOBAL_VARIABLE` and the
//!   attributes NV|BS|RT;
//! - our own Windows Boot Manager option round-trips and `points_to` its
//!   ESP, and not to an ESP that differs in any field.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), CM-7 (Least
//   Functionality: only boot variables can be named), SA-11 (Developer
//   Testing and Evaluation)
// - SPEC: specs/boot-network.md#REQ-BOOT-065
// - specs/standards/uefi-boot-manager.md §10.2 to §10.7 (UEFI 2.10 §3.1.3,
//   §10.3)

use libfuzzer_sys::fuzz_target;
use usgp_disk::guid::types;
use usgp_disk::uefi::{
    BOOT_VARIABLE_ATTRIBUTES, BootVarName, EFI_GLOBAL_VARIABLE, LoadOption, Node, UefiLimits,
    encode_boot_order, free_option_number, parse_boot_order, parse_load_option, put_first,
};
use usgp_disk::{Guid, Part, PartRole, UefiError};

fn printable(u: u16) -> bool {
    (0x20..0x7F).contains(&u)
}

fn check_option(o: &LoadOption, l: &UefiLimits) {
    assert!(!o.paths.is_empty(), "no device path");
    let mut nodes = 0usize;
    for p in &o.paths {
        assert_eq!(p.last(), Some(&Node::EndEntire), "path not ended");
        assert_eq!(
            p.iter().filter(|n| **n == Node::EndEntire).count(),
            1,
            "End-entire inside a path"
        );
        nodes += p.len();
        for n in p {
            if let Node::FilePath(s) = n {
                assert!(s.encode_utf16().count() < l.max_path_units, "path units");
                assert!(!s.contains('\0'), "NUL inside a file path");
            }
            if let Node::Other { node_type, .. } = n {
                assert_ne!(*node_type, usgp_disk::uefi::TYPE_END, "End kept as Other");
            }
        }
    }
    assert!(nodes <= l.max_nodes, "node limit");
    assert!(
        o.description.len() < l.max_description_units,
        "description limit"
    );
    assert!(!o.description.contains(&0), "NUL inside the description");
}

fn ascii_text(o: &LoadOption) -> bool {
    o.description.iter().all(|&u| printable(u))
        && o.paths.iter().flatten().all(|n| match n {
            Node::FilePath(s) => !s.is_empty() && s.bytes().all(|b| printable(u16::from(b))),
            _ => true,
        })
}

fn load_option(b: &[u8]) {
    let def = UefiLimits::default();
    let full = parse_load_option(b, &def);
    if let [a, c, d, e, f, rest @ ..] = b {
        let tight = UefiLimits {
            max_option_bytes: usize::from(*a) * 64,
            max_description_units: usize::from(*c),
            max_nodes: usize::from(*d) % 65,
            max_path_units: usize::from(*e) * 4,
            max_boot_order_entries: usize::from(*f),
        };
        if let Ok(t) = parse_load_option(rest, &tight) {
            check_option(&t, &tight);
            assert_eq!(
                parse_load_option(rest, &def).as_ref(),
                Ok(&t),
                "tighter limits accepted more"
            );
        }
    }
    let o = match full {
        Ok(o) => o,
        Err(e) => {
            assert!(!e.to_string().is_empty());
            return;
        }
    };
    check_option(&o, &def);
    match o.encode() {
        Ok(enc) => {
            assert_eq!(enc, b, "accepted option does not re-encode to its bytes");
            assert_eq!(parse_load_option(&enc, &def).as_ref(), Ok(&o));
        }
        Err(UefiError::Encode(_)) => {
            assert!(!ascii_text(&o), "printable ASCII option not encodable");
        }
        Err(e) => panic!("encode failed with {e:?}"),
    }
    // Display only; never panics on any UTF-16.
    let _ = o.description_lossy();
}

fn boot_order(b: &[u8]) {
    let l = UefiLimits::default();
    let r = parse_boot_order(b, &l);
    if b.len() % 2 == 1 {
        assert!(matches!(r, Err(UefiError::Malformed { .. })), "odd length");
        return;
    }
    if b.len() / 2 > l.max_boot_order_entries {
        assert!(
            matches!(r, Err(UefiError::Limit(_))),
            "over the entry limit"
        );
        return;
    }
    let order = r.expect("even length within the limit");
    assert_eq!(encode_boot_order(&order), b, "BootOrder round trip");
    let n = order.first().copied().unwrap_or(0) ^ 0x5a5a;
    for n in [n, order.last().copied().unwrap_or(1)] {
        // Reference: n, then the first occurrence of each other number.
        let mut want = vec![n];
        for &x in &order {
            if !want.contains(&x) {
                want.push(x);
            }
        }
        assert_eq!(put_first(&order, n), want, "put_first");
    }
    let free = free_option_number(&order);
    let mut used = [false; 65536];
    for &x in &order {
        used[usize::from(x)] = true;
    }
    let want = (0..=u16::MAX).find(|&x| !used[usize::from(x)]);
    assert_eq!(free, want, "free_option_number");
}

fn name(b: &[u8]) {
    let Ok(s) = std::str::from_utf8(b) else {
        return;
    };
    let model = s == "BootOrder"
        || s.strip_prefix("Boot").is_some_and(|d| {
            d.len() == 4
                && d.bytes()
                    .all(|c| c.is_ascii_digit() || (b'A'..=b'F').contains(&c))
        });
    let got = BootVarName::from_name(s);
    assert_eq!(got.is_some(), model, "name accepted differs from the rule");
    if let Some(v) = got {
        assert_eq!(v.to_string(), s, "Display does not give the name back");
        assert_eq!(BootVarName::from_name(&v.to_string()), Some(v));
        assert_eq!(v.vendor(), EFI_GLOBAL_VARIABLE);
        assert_eq!(v.attributes(), BOOT_VARIABLE_ATTRIBUTES);
        assert_eq!(v.option_number().is_some(), s != "BootOrder");
    }
}

fn windows_option(b: &[u8]) {
    let mut buf = [0u8; 37];
    for (d, s) in buf.iter_mut().zip(b) {
        *d = *s;
    }
    let [n0, n1, n2, n3, s @ .., which] = buf;
    let (start, rest) = s.split_at(8);
    let (len, guid) = rest.split_at(8);
    let first = u64::from_le_bytes(start.try_into().unwrap_or([0; 8]));
    let size = u64::from_le_bytes(len.try_into().unwrap_or([0; 8]));
    let esp = Part {
        role: PartRole::Esp,
        number: u32::from_le_bytes([n0, n1, n2, n3]),
        type_guid: types::ESP,
        unique_guid: Guid(guid.try_into().unwrap_or([0; 16])),
        first_lba: first,
        last_lba: first.saturating_add(size),
        attributes: 0,
    };
    let o = LoadOption::windows_boot_manager(&esp);
    let enc = o.encode().expect("our option encodes");
    let back = parse_load_option(&enc, &UefiLimits::default()).expect("our option parses");
    assert_eq!(back, o, "our option does not round-trip");
    assert!(back.points_to(&esp), "our option does not point to its ESP");
    let mut other = esp;
    match which % 4 {
        0 => other.number ^= 1,
        1 => other.first_lba ^= 1,
        2 => other.last_lba = other.last_lba.wrapping_add(1),
        _ => other.unique_guid.0[15] ^= 1,
    }
    // Reference: the Hard Drive node names number, start, size and GUID.
    let same_node = other.number == esp.number
        && other.first_lba == esp.first_lba
        && other.len_lbas() == esp.len_lbas()
        && other.unique_guid == esp.unique_guid;
    assert_eq!(back.points_to(&other), same_node, "points_to another ESP");
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    match sel % 4 {
        0 => load_option(body),
        1 => boot_order(body),
        2 => name(body),
        _ => windows_option(body),
    }
});
