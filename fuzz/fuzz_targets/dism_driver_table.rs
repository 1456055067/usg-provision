//! Fuzz target `dism_driver_table`: the list-format driver listing of the
//! offline image (`usgp-wincfg` `dism::parse_driver_table`).
//!
//! The input is read as UTF-8 (lossy, so every input reaches the parser).
//!
//! Invariants:
//!
//! - no panic; `TooLarge` exactly over `MAX_INPUT_BYTES`;
//! - an accepted listing has at most `MAX_ROWS` rows and no more rows
//!   than lines starting a `Published Name` field; every value is
//!   trimmed, has no line break, is at most `MAX_VALUE_BYTES`, and the
//!   published name, original file name and version are not empty;
//! - rows written back as `Label : value` blocks parse to the same rows;
//! - CRLF line ends give the same result as LF.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SA-11
// - SPEC: specs/drivers.md (driver staging check);
//   specs/standards/offline-drivers.md §7.3

use libfuzzer_sys::fuzz_target;
use usgp_wincfg::dism::{
    DismParseError, DriverRow, MAX_INPUT_BYTES, MAX_ROWS, MAX_VALUE_BYTES, parse_driver_table,
};

fn write_back(rows: &[DriverRow]) -> String {
    let mut s = String::new();
    for r in rows {
        let inbox = if r.inbox { "Yes" } else { "No" };
        for (k, v) in [
            ("Published Name", r.published_name.as_str()),
            ("Original File Name", &r.original_file_name),
            ("Inbox", inbox),
            ("Class Name", &r.class_name),
            ("Provider Name", &r.provider_name),
            ("Date", &r.date),
            ("Version", &r.version),
        ] {
            s.push_str(k);
            s.push_str(" : ");
            s.push_str(v);
            s.push('\n');
        }
        s.push('\n');
    }
    s
}

fn check_value(v: &str) {
    assert!(v.len() <= MAX_VALUE_BYTES, "value over the limit");
    assert_eq!(v, v.trim(), "value not trimmed");
    assert!(!v.contains('\n'), "value holds a line break");
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let res = parse_driver_table(&text);
    if text.len() > MAX_INPUT_BYTES {
        assert_eq!(res, Err(DismParseError::TooLarge));
        return;
    }
    assert_ne!(
        res,
        Err(DismParseError::TooLarge),
        "too large under the cap"
    );
    if let Ok(rows) = &res {
        assert!(rows.len() <= MAX_ROWS);
        let starts = text
            .lines()
            .filter(|l| {
                l.split_once(':')
                    .is_some_and(|(k, _)| k.trim() == "Published Name")
            })
            .count();
        assert!(rows.len() <= starts, "more rows than published names");
        for r in rows {
            for v in [
                &r.published_name,
                &r.original_file_name,
                &r.class_name,
                &r.provider_name,
                &r.date,
                &r.version,
            ] {
                check_value(v);
            }
            assert!(!r.published_name.is_empty() && !r.original_file_name.is_empty());
            assert!(!r.version.is_empty());
        }
        let again = parse_driver_table(&write_back(rows)).expect("written rows re-parse");
        assert_eq!(&again, rows, "rows do not round-trip");
    }
    let crlf = text.replace('\n', "\r\n");
    if crlf.len() <= MAX_INPUT_BYTES && !text.contains('\r') {
        assert_eq!(parse_driver_table(&crlf), res, "CRLF differs from LF");
    }
});
