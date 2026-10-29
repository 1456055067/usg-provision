//! Fuzz target `boot_manifest`: arbitrary text as the relay's boot
//! manifest, `[pe_kit]` section included (`usgp-proto`
//! `BootManifest::from_toml`, `PeKitV1`).
//!
//! The whole input, if UTF-8, is the manifest text.
//!
//! Invariants (impl-notes-integration item 7; impl-notes-wu11 "WU-14"):
//!
//! - no panic; every refusal has operator text;
//! - an accepted manifest validates: schema 1, 1 to 256 files, names
//!   unique, sizes within the limit; `get` finds every file by name and
//!   nothing else; `to_toml` parses back to the same manifest;
//! - `[pe_kit]`: at most 32 fonts and no file named for two roles;
//!   `assess` equals a reference model (each role whose file is not
//!   published, in role order; then a boot program mismatch when the
//!   caller names another program; then a digest mismatch when the WIM is
//!   published with another SHA-256), and naming the kit's own boot
//!   program adds nothing.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity),
//   SI-10 (Information Input Validation), CM-7, SA-11
// - SPEC: specs/boot-network.md#REQ-BOOT-052, #REQ-BOOT-063
// - SPEC: specs/preinstall-env.md#REQ-PE-011, #REQ-PE-012
// - DECISION: docs/decisions/0018 item 3

use std::collections::HashSet;

use libfuzzer_sys::fuzz_target;
use usgp_proto::boot_manifest::{MAX_FILE_SIZE, MAX_FILES, MAX_MANIFEST_BYTES, SCHEMA_VERSION};
use usgp_proto::pe_kit::{KitProblem, MAX_FONTS, PeKitV1};
use usgp_proto::{BootFileName, BootManifest, DigestName, ManifestError};

fn model(kit: &PeKitV1, m: &BootManifest, program: Option<&BootFileName>) -> Vec<KitProblem> {
    let published = |n: &BootFileName| m.files.iter().any(|f| f.name.as_bytes() == n.as_bytes());
    let mut out: Vec<KitProblem> = kit
        .files()
        .into_iter()
        .filter(|(_, n)| !published(n))
        .map(|(r, n)| KitProblem::NotPublished(r, n.clone()))
        .collect();
    if program.is_some_and(|p| p.as_bytes() != kit.boot_program.as_bytes()) {
        out.push(KitProblem::ProgramMismatch);
    }
    if m.files
        .iter()
        .any(|f| f.name.as_bytes() == kit.wim.as_bytes() && f.sha256 != kit.pe_content_sha256)
    {
        out.push(KitProblem::PeDigestMismatch);
    }
    out
}

fn check_kit(kit: &PeKitV1, m: &BootManifest) {
    assert!(kit.fonts.len() <= MAX_FONTS, "font limit");
    let files = kit.files();
    assert_eq!(files.len(), 4 + kit.fonts.len(), "roles");
    let mut seen = HashSet::new();
    assert!(
        files.iter().all(|(_, n)| seen.insert(n.as_bytes())),
        "file in two roles"
    );
    let none = kit.assess(m, None);
    assert_eq!(none, model(kit, m, None), "assess without a program");
    assert_eq!(
        kit.assess(m, Some(&kit.boot_program)),
        none,
        "own program mismatched"
    );
    if let Some(other) = m
        .files
        .iter()
        .map(|f| &f.name)
        .find(|n| n.as_bytes() != kit.boot_program.as_bytes())
    {
        assert_eq!(
            kit.assess(m, Some(other)),
            model(kit, m, Some(other)),
            "assess with another program"
        );
    }
    for p in &none {
        assert!(!p.describe().is_empty() && !p.to_string().is_empty());
        assert!(!p.label().is_empty());
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let m = match BootManifest::from_toml(text) {
        Ok(m) => m,
        Err(e) => {
            assert!(!e.to_string().is_empty(), "empty refusal text");
            if text.len() > MAX_MANIFEST_BYTES {
                assert!(matches!(e, ManifestError::TooLarge), "size checked first");
            }
            return;
        }
    };
    assert!(text.len() <= MAX_MANIFEST_BYTES, "over the size limit");
    assert!(m.validate().is_ok(), "accepted manifest does not validate");
    assert_eq!(m.schema_version, SCHEMA_VERSION);
    assert_eq!(m.algorithm, DigestName::Sha256);
    assert!((1..=MAX_FILES).contains(&m.files.len()), "file count");
    let mut names = HashSet::new();
    for f in &m.files {
        assert!(names.insert(f.name.as_bytes()), "duplicate name accepted");
        assert!(f.size <= MAX_FILE_SIZE, "size limit");
        assert_eq!(m.get(f.name.as_bytes()), Some(f), "get by name");
    }
    let mut absent = m
        .files
        .first()
        .map(|f| f.name.as_bytes().to_vec())
        .unwrap_or_default();
    absent.push(b'~');
    assert!(m.get(&absent).is_none(), "get found an unlisted name");
    let out = m.to_toml();
    match BootManifest::from_toml(&out) {
        Ok(again) => assert_eq!(again, m, "to_toml does not round-trip"),
        Err(e) => panic!("own TOML refused: {e}"),
    }
    if let Some(kit) = &m.pe_kit {
        check_kit(kit, &m);
    }
});
