//! Fuzz target `tftp_name`: TFTP request-name normalisation and the
//! case-insensitive collision check (`usgp-tftp` `names`).
//!
//! Octet 0 selects (modulo 2): 0, the rest is one RRQ filename for
//! `normalize_request_name`; 1, the rest is a list of published names
//! separated by NUL octets for `case_insensitive_collision`.
//!
//! Invariants (impl-notes-wu6 "For WU-14"; M3 plan §1 "Request names"):
//!
//! - no panic;
//! - the result equals a reference model of the documented steps (every
//!   `\` becomes `/`, one leading `/` dropped, then the published-name
//!   allow-list: 1 to 127 bytes of `A-Z a-z 0-9 . _ - /`, no leading `/`,
//!   no empty, `.` or `..` component), refusal kinds included;
//! - an accepted name passes the allow-list, has no `..` component, is
//!   its own normal form, and matches published names exactly when they
//!   are equal ignoring ASCII case;
//! - a reported collision is a pair `i < j` of names equal ignoring ASCII
//!   case, and none is reported only when no such pair exists.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), AC-3 (Access
//   Enforcement: names compared with the published set only), SA-11
// - SPEC: specs/boot-network.md#REQ-BOOT-041, #REQ-BOOT-063
// - SPEC: specs/standards/winpe-network-boot.md §5 (backslash paths)
// - RFC 1123 §4.2.3.4 - control over the paths that can be accessed

use libfuzzer_sys::fuzz_target;
use usgp_tftp::{
    MAX_REQUEST_NAME_LEN, NameRefusal, case_insensitive_collision, normalize_request_name,
};

fn allowed(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/')
}

/// The documented steps, written independently of the crate.
fn model(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    if raw.len() > MAX_REQUEST_NAME_LEN + 1 {
        return Err("too_long");
    }
    let mut b: Vec<u8> = raw
        .iter()
        .map(|&c| if c == b'\\' { b'/' } else { c })
        .collect();
    if b.first() == Some(&b'/') {
        b.remove(0);
    }
    if b.is_empty() {
        return Err("empty");
    }
    if b.len() > MAX_REQUEST_NAME_LEN {
        return Err("too_long");
    }
    if !b.iter().all(|&c| allowed(c)) {
        return Err("invalid_byte");
    }
    if b.first() == Some(&b'/') {
        return Err("leading_slash");
    }
    for comp in b.split(|&c| c == b'/') {
        if comp.is_empty() {
            return Err("empty_component");
        }
        if comp == b"." || comp == b".." {
            return Err("dot_component");
        }
    }
    Ok(b)
}

fn normalize(raw: &[u8]) {
    let got = normalize_request_name(raw);
    match (&got, model(raw)) {
        (Ok(n), Ok(want)) => assert_eq!(n.as_bytes(), &want[..], "normal form"),
        (Err(e), Err(want)) => {
            assert_eq!(e.label(), want, "refusal kind");
            if let NameRefusal::InvalidByte { offset } = e {
                let skip = usize::from(matches!(raw.first(), Some(b'/' | b'\\')));
                let at = raw.get(offset + skip).copied().unwrap_or(0);
                assert!(
                    !allowed(at) && at != b'\\',
                    "offset does not name a refused byte"
                );
            }
        }
        (g, w) => panic!("crate {g:?}, model {w:?}"),
    }
    let Ok(n) = got else { return };
    let b = n.as_bytes();
    assert!((1..=MAX_REQUEST_NAME_LEN).contains(&b.len()), "length");
    assert!(b.iter().all(|&c| allowed(c)), "byte outside the allow-list");
    assert!(
        !b.split(|&c| c == b'/').any(|c| c == b".." || c == b"."),
        "dot component"
    );
    assert_eq!(n.as_str().as_bytes(), b);
    let again = normalize_request_name(b).expect("normal form is accepted");
    assert_eq!(again, n, "normal form is not a fixed point");
    assert!(n.matches(&b.to_ascii_uppercase()), "case-insensitive match");
    assert!(n.matches(&b.to_ascii_lowercase()), "case-insensitive match");
    let mut other = b.to_vec();
    other.push(b'x');
    assert!(!n.matches(&other), "matched a longer name");
}

fn collisions(list: &[u8]) {
    let names: Vec<&[u8]> = list.split(|&b| b == 0).take(256).collect();
    let r = case_insensitive_collision(names.iter().copied());
    let any = names
        .iter()
        .enumerate()
        .any(|(i, a)| names.iter().skip(i + 1).any(|b| a.eq_ignore_ascii_case(b)));
    match r {
        Some((i, j)) => {
            assert!(i < j && j < names.len(), "pair ({i}, {j})");
            assert!(
                names[i].eq_ignore_ascii_case(names[j]),
                "pair does not collide"
            );
        }
        None => assert!(!any, "collision missed"),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    if sel % 2 == 0 {
        normalize(rest);
    } else {
        collisions(rest);
    }
});
