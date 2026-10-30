//! Fuzz target `inf_version`: one INF file's text, scanned for its
//! `[Version]` section (`usgp-wincfg` archive INF scan).
//!
//! The scan is internal to the archive reader, so the input is placed as
//! `pkg/x.inf` in a stored ZIP built with our own test writer, next to
//! `pkg/x.cat` and `pkg/y.cat`, and the archive is read in plain mode;
//! the report lists the INF exactly when the scan finds a driver package
//! whose catalogs are present.
//!
//! Invariants:
//!
//! - no panic; plain mode always accepts the archive (the names and sizes
//!   are fixed and valid), and lists at most `pkg/x.inf`;
//! - driver mode accepts exactly when plain mode lists the INF, and
//!   otherwise refuses with `no_inf_packages`;
//! - a listed INF decodes as UTF-8 (optional BOM) or BOM-led UTF-16LE and
//!   holds, ignoring ASCII case, `version`, `signature`, `catalogfile`
//!   and `$windows nt$` or `$chicago$` (a necessary-condition model of
//!   the rule in plan section 1.5);
//! - removing the catalogs never lists more;
//! - the same text as BOM-led UTF-16LE gives the same decision.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), CM-7, SA-11
// - SPEC: specs/drivers.md#REQ-DRV-006 (INF driver packages only)

use libfuzzer_sys::fuzz_target;
use usgp_wincfg::archive::testkit::{ZipBuilder, ZipEntrySpec};
use usgp_wincfg::{ArchiveError, ArchiveLimits, ArchiveMode, validate_archive_mode};

fn listed(inf: &[u8], cats: bool, mode: ArchiveMode) -> Result<bool, ArchiveError> {
    let mut b = ZipBuilder::default().entry(ZipEntrySpec::stored("pkg/x.inf", inf));
    if cats {
        b = b
            .entry(ZipEntrySpec::stored("pkg/x.cat", b"c"))
            .entry(ZipEntrySpec::stored("pkg/y.cat", b"c"));
    }
    let zip = b.build();
    let r = validate_archive_mode(
        &zip.as_slice(),
        zip.len() as u64,
        &ArchiveLimits::default(),
        mode,
    )?;
    assert!(r.infs.len() <= 1, "more than one INF listed");
    if let Some(p) = r.infs.first() {
        assert_eq!(p.as_str(), "pkg/x.inf", "listed a non-INF");
    }
    Ok(!r.infs.is_empty())
}

fn decode(b: &[u8]) -> Option<String> {
    if let Some(rest) = b.strip_prefix(&[0xFF, 0xFE]) {
        let (units, tail) = rest.as_chunks::<2>();
        if !tail.is_empty() {
            return None;
        }
        return char::decode_utf16(units.iter().map(|c| u16::from_le_bytes(*c)))
            .collect::<Result<String, _>>()
            .ok();
    }
    let b = b.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(b);
    std::str::from_utf8(b).ok().map(str::to_owned)
}

fuzz_target!(|data: &[u8]| {
    // Over the INF size limit is an archive refusal, not a scan result.
    if data.len() > 1 << 20 {
        return;
    }
    let plain = listed(data, true, ArchiveMode::Plain).expect("plain mode accepts");
    match listed(data, true, ArchiveMode::DriverPackages) {
        Ok(d) => assert!(d && plain, "driver mode accepts without a listed INF"),
        Err(ArchiveError::NoInfPackages) => assert!(!plain, "listed INF refused"),
        Err(e) => panic!("unexpected refusal {}", e.reason()),
    }
    if plain {
        let text = decode(data)
            .expect("listed INF does not decode")
            .to_ascii_lowercase();
        for k in ["version", "signature", "catalogfile"] {
            assert!(text.contains(k), "listed INF lacks {k}");
        }
        assert!(
            text.contains("$windows nt$") || text.contains("$chicago$"),
            "listed INF lacks a known signature"
        );
    }
    let bare = listed(data, false, ArchiveMode::Plain).expect("plain mode accepts");
    assert!(!bare || plain, "fewer catalogs list more");
    if !data.starts_with(&[0xFF, 0xFE])
        && let Ok(s) = std::str::from_utf8(data)
    {
        let s = s.strip_prefix('\u{feff}').unwrap_or(s);
        let mut wide = vec![0xFF, 0xFE];
        wide.extend(s.encode_utf16().flat_map(u16::to_le_bytes));
        if wide.len() <= 1 << 20 {
            let w = listed(&wide, true, ArchiveMode::Plain).expect("plain mode accepts");
            assert_eq!(w, plain, "UTF-16LE form decides differently");
        }
    }
});
