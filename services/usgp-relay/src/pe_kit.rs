//! The boot manifest's optional `pe_kit` section, as the relay uses it
//! (plan WU-11, sections 1.2(e) and 5; decision 0018 item 3).
//!
//! The section's type, its parser and its checks are shared with
//! `usgp-cli`, which writes it: [`usgp_proto::pe_kit`] (the format is
//! documented there). The manifest is parsed by
//! [`usgp_proto::BootManifest::from_toml`], which accepts the optional
//! section and refuses unknown keys, bad names, a file named for two roles
//! and too many fonts; such a manifest refuses start-up (exit 78), as for
//! any malformed M1 manifest. A manifest without `[pe_kit]` is exactly the
//! M1 format and is handled as in M1. A manifest with `[pe_kit]` requires
//! `[server_feed]` with `enabled = true` in the relay configuration, or
//! start-up is refused (exit 78; [`crate::check_kit_has_feed`],
//! REQ-BOOT-067). The relay never generates or edits a
//! boot configuration; the BCD is an opaque operator file, checked like
//! every other published file (`winpe-network-boot.md` §6, REQ-PE-012).
//!
//! Completeness and binding ([`PeKitV1::assess`] with the configured
//! `boot.uefi_x64_program`): every role must name a published `[[file]]`;
//! `boot_program` must be the configured program; the WIM's manifest
//! digest must equal `pe_content_sha256`. A failure is **missing content**
//! (REQ-PE-012, REQ-BOOT-052): the relay runs, offers no boot program, and
//! reports `boot.kit.incomplete`. Each kit file's bytes are then verified
//! like any published file, at start-up, periodically, and on every read
//! (SI-7), so a kit file that is absent or altered on disk is missing
//! content too.
//!
//! The check that `pe_content_sha256` names a Ready x64 PE on the server
//! is done by `usgp-cli` when it writes the manifest (plan WU-13); the
//! relay has no server lookup for it.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   the kit is complete and bound to the imported PE's digest before any
//   boot program is offered; each file verified before serving.
// - NIST 800-53: CM-7 (Least Functionality) - only the named kit files
//   are served, as published files.
// - SPEC: specs/preinstall-env.md#REQ-PE-011, #REQ-PE-012
// - SPEC: specs/boot-network.md#REQ-BOOT-052, #REQ-BOOT-063
// - DECISION: docs/decisions/0018 item 3

pub use usgp_proto::pe_kit::{KitProblem, KitRole, MAX_FONTS, PeKitError, PeKitV1};

use crate::state::FileStatus;

/// The name under which the kit's own status is tracked in the service
/// state. Brackets cannot appear in a published name, so it never
/// collides with a file.
pub const KIT_STATUS_NAME: &str = "[pe_kit]";

/// The status recorded for the kit for one problem: an absent file is
/// missing, a mismatch is an integrity failure.
#[must_use]
pub fn problem_status(p: &KitProblem) -> FileStatus {
    match p {
        KitProblem::NotPublished(..) => FileStatus::Missing,
        // ProgramMismatch, PeDigestMismatch, and any later reason: fail
        // closed as an integrity failure.
        _ => FileStatus::IntegrityFailed,
    }
}

#[cfg(test)]
mod tests {
    use usgp_proto::{BootFileName, BootManifest, ManifestError};

    use super::*;

    const D1: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const D2: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn files() -> String {
        ["bootmgfw.efi", "Boot/BCD", "Boot/boot.sdi", "Boot/boot.wim"]
            .iter()
            .map(|n| format!("[[file]]\nname = \"{n}\"\nsize = 3\nsha256 = \"{D1}\"\n\n"))
            .collect()
    }

    fn kit(extra: &str) -> String {
        format!(
            "schema_version = 1\nalgorithm = \"sha256\"\n\n{}[pe_kit]\nboot_program = \"bootmgfw.efi\"\n\
             bcd = \"Boot/BCD\"\nsdi = \"Boot/boot.sdi\"\nwim = \"Boot/boot.wim\"\n\
             pe_content_sha256 = \"{D1}\"\n{extra}",
            files()
        )
    }

    fn prog() -> BootFileName {
        BootFileName::try_from("bootmgfw.efi").unwrap()
    }

    #[test]
    fn complete_kit() {
        let m = BootManifest::from_toml(&kit("")).unwrap();
        let k = m.pe_kit.as_ref().unwrap();
        assert!(k.assess(&m, Some(&prog())).is_empty());
        assert_eq!(k.files().len(), 4);
    }

    #[test]
    fn shape_errors_refuse_the_manifest() {
        assert!(matches!(
            BootManifest::from_toml(&kit("fonts = [\"Boot/BCD\"]\n")),
            Err(ManifestError::PeKit(PeKitError::DuplicateRole))
        ));
        assert!(matches!(
            BootManifest::from_toml(&kit("extra = 1\n")),
            Err(ManifestError::Parse(_))
        ));
    }

    #[test]
    fn incomplete_and_mismatched_kits() {
        // A font that is not published.
        let m = BootManifest::from_toml(&kit("fonts = [\"Boot/Fonts/a.ttf\"]\n")).unwrap();
        let p = m.pe_kit.as_ref().unwrap().assess(&m, Some(&prog()));
        assert_eq!(p.len(), 1);
        let first = p.first().unwrap();
        assert_eq!(problem_status(first), FileStatus::Missing);
        assert_eq!(first.describe(), "not_published:font:Boot/Fonts/a.ttf");
        // Another configured boot program.
        let m = BootManifest::from_toml(&kit("")).unwrap();
        let other = BootFileName::try_from("Boot/BCD").unwrap();
        let p = m.pe_kit.as_ref().unwrap().assess(&m, Some(&other));
        assert_eq!(p, vec![KitProblem::ProgramMismatch]);
        assert_eq!(p.first().unwrap().describe(), "boot_program_mismatch");
        // The WIM is not the imported PE.
        let text = kit("").replace(
            &format!("pe_content_sha256 = \"{D1}\""),
            &format!("pe_content_sha256 = \"{D2}\""),
        );
        let m = BootManifest::from_toml(&text).unwrap();
        let p = m.pe_kit.as_ref().unwrap().assess(&m, Some(&prog()));
        assert_eq!(p, vec![KitProblem::PeDigestMismatch]);
        assert_eq!(
            problem_status(p.first().unwrap()),
            FileStatus::IntegrityFailed
        );
    }
}
