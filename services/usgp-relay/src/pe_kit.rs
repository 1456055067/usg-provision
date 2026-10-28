//! The boot manifest's optional `pe_kit` section: the operator's Windows PE
//! network-boot files (plan WU-11, sections 1.2(e) and 5; decision 0018
//! item 3).
//!
//! ```toml
//! schema_version = 1
//! algorithm = "sha256"
//!
//! [[file]]          # every kit file is also an ordinary published file
//! name = "bootmgfw.efi"
//! size = ...
//! sha256 = "..."
//! # ... Boot/BCD, Boot/boot.sdi, Boot/boot.wim, Boot/Fonts/*.ttf
//!
//! [pe_kit]
//! boot_program = "bootmgfw.efi"      # the UEFI x64 boot manager
//! bcd = "Boot/BCD"                   # operator-built boot configuration
//! sdi = "Boot/boot.sdi"              # RAM-disk support file
//! wim = "Boot/boot.wim"              # the Windows PE image
//! fonts = ["Boot/Fonts/wgl4_boot.ttf"]  # optional
//! pe_content_sha256 = "..."          # SHA-256 of the imported, Ready PE
//! ```
//!
//! A manifest without `[pe_kit]` is exactly the M1 format and is handled
//! as in M1. The relay never generates or edits a boot configuration; the
//! BCD is an opaque operator file, checked like every other published file
//! (`winpe-network-boot.md` §6, REQ-PE-012).
//!
//! Two levels of checks:
//!
//! - **Shape** ([`parse_manifest`]): unknown keys, bad names, a file named
//!   for two roles, or too many fonts make the manifest invalid, which
//!   refuses start-up (exit 78), as for any malformed M1 manifest.
//! - **Completeness and integrity** ([`assess`]): every role must name a
//!   published `[[file]]`; `boot_program` must be the configured
//!   `boot.uefi_x64_program`; the WIM's manifest digest must equal
//!   `pe_content_sha256`. A failure is **missing content** (REQ-PE-012,
//!   REQ-BOOT-052): the relay runs, offers no boot program, and reports
//!   `boot.kit.incomplete`. Each kit file's bytes are then verified like
//!   any published file, at start-up, periodically, and on every read
//!   (SI-7), so a kit file that is absent or altered on disk is missing
//!   content too.
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
// - NIST 800-53: SI-10 (Information Input Validation) - strict shape,
//   validated names, bounded list.
// - SPEC: specs/preinstall-env.md#REQ-PE-011, #REQ-PE-012
// - SPEC: specs/boot-network.md#REQ-BOOT-052, #REQ-BOOT-063
// - SPEC: specs/standards/winpe-network-boot.md §2, §5, §6
// - DECISION: docs/decisions/0018 item 3

use std::collections::HashSet;

use usgp_common::Sha256Digest;
use usgp_proto::boot_manifest::{DigestName, MAX_MANIFEST_BYTES};
use usgp_proto::{BootFileName, BootManifest, ManifestEntry, ManifestError};

use crate::state::FileStatus;

/// Most font files in one kit (project design).
pub const MAX_FONTS: usize = 32;

/// The name under which the kit's own status is tracked in the service
/// state. Brackets cannot appear in a published name, so it never
/// collides with a file.
pub const KIT_STATUS_NAME: &str = "[pe_kit]";

/// The `[pe_kit]` section as written.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeKitDocument {
    /// Microsoft's UEFI boot manager from the kit.
    pub boot_program: BootFileName,
    /// The operator-built boot configuration store.
    pub bcd: BootFileName,
    /// The RAM-disk support file.
    pub sdi: BootFileName,
    /// The Windows PE image.
    pub wim: BootFileName,
    /// Font files (optional).
    #[serde(default)]
    pub fonts: Vec<BootFileName>,
    /// SHA-256 of the imported, Ready PE content (the WIM).
    pub pe_content_sha256: Sha256Digest,
}

/// The whole manifest as written: the M1 fields plus `[pe_kit]`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestDocument {
    schema_version: u32,
    algorithm: DigestName,
    #[serde(rename = "file", default)]
    files: Vec<ManifestEntry>,
    pe_kit: Option<PeKitDocument>,
}

/// A kit whose shape is valid (roles distinct, fonts bounded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeKit {
    doc: PeKitDocument,
}

/// The role a kit file plays, for events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KitRole {
    /// `boot_program`.
    BootProgram,
    /// `bcd`.
    Bcd,
    /// `sdi`.
    Sdi,
    /// `wim`.
    Wim,
    /// One of `fonts`.
    Font,
}

impl KitRole {
    /// Stable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::BootProgram => "boot_program",
            Self::Bcd => "bcd",
            Self::Sdi => "sdi",
            Self::Wim => "wim",
            Self::Font => "font",
        }
    }
}

impl PeKit {
    /// Every kit file with its role, boot program first.
    #[must_use]
    pub fn files(&self) -> Vec<(KitRole, &BootFileName)> {
        let d = &self.doc;
        let mut v = vec![
            (KitRole::BootProgram, &d.boot_program),
            (KitRole::Bcd, &d.bcd),
            (KitRole::Sdi, &d.sdi),
            (KitRole::Wim, &d.wim),
        ];
        v.extend(d.fonts.iter().map(|f| (KitRole::Font, f)));
        v
    }

    /// The boot program the kit names.
    #[must_use]
    pub fn boot_program(&self) -> &BootFileName {
        &self.doc.boot_program
    }

    /// The imported PE's digest.
    #[must_use]
    pub fn pe_content_sha256(&self) -> Sha256Digest {
        self.doc.pe_content_sha256
    }
}

/// Why the `[pe_kit]` section has an invalid shape (start-up refused).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PeKitShapeError {
    /// One file is named for two roles (or twice in `fonts`).
    #[error("boot manifest pe_kit names one file for two roles")]
    DuplicateRole,
    /// More than [`MAX_FONTS`] fonts.
    #[error("boot manifest pe_kit lists more than 32 fonts")]
    TooManyFonts,
}

/// Why the manifest text could not be used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The M1 manifest rules.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// The `[pe_kit]` shape rules.
    #[error(transparent)]
    Shape(#[from] PeKitShapeError),
}

/// Parses manifest text: the M1 [`BootManifest`] (validated by its own
/// rules) and the optional kit (shape rules).
///
/// # Errors
///
/// [`ParseError`]; a manifest without `[pe_kit]` fails exactly where
/// [`BootManifest::from_toml`] fails.
pub fn parse_manifest(text: &str) -> Result<(BootManifest, Option<PeKit>), ParseError> {
    if text.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::TooLarge.into());
    }
    let doc: ManifestDocument =
        usgp_common::config::parse_toml(text).map_err(ManifestError::Parse)?;
    let manifest = BootManifest {
        schema_version: doc.schema_version,
        algorithm: doc.algorithm,
        files: doc.files,
    };
    manifest.validate()?;
    let kit = match doc.pe_kit {
        None => None,
        Some(k) => {
            if k.fonts.len() > MAX_FONTS {
                return Err(PeKitShapeError::TooManyFonts.into());
            }
            let kit = PeKit { doc: k };
            let mut seen = HashSet::new();
            if !kit.files().iter().all(|(_, n)| seen.insert(n.as_bytes())) {
                return Err(PeKitShapeError::DuplicateRole.into());
            }
            Some(kit)
        }
    };
    Ok((manifest, kit))
}

/// One reason a kit is incomplete or does not match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KitProblem {
    /// A role names a file that is not a published `[[file]]`.
    NotPublished(KitRole, BootFileName),
    /// `boot_program` is not the configured `boot.uefi_x64_program`.
    ProgramMismatch,
    /// The WIM's manifest digest is not `pe_content_sha256`.
    PeDigestMismatch,
}

impl KitProblem {
    /// Stable label.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::NotPublished(..) => "not_published",
            Self::ProgramMismatch => "boot_program_mismatch",
            Self::PeDigestMismatch => "pe_digest_mismatch",
        }
    }

    /// The status recorded for the kit: an absent file is missing, a
    /// mismatch is an integrity failure.
    #[must_use]
    pub fn status(&self) -> FileStatus {
        match self {
            Self::NotPublished(..) => FileStatus::Missing,
            Self::ProgramMismatch | Self::PeDigestMismatch => FileStatus::IntegrityFailed,
        }
    }

    /// `label` plus the role and file, for events.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::NotPublished(role, name) => {
                format!("{}:{}:{}", self.label(), role.label(), name.as_str())
            }
            _ => self.label().to_owned(),
        }
    }
}

/// Checks the kit against the manifest and the configured boot program
/// (module docs). Empty means complete.
#[must_use]
pub fn assess(kit: &PeKit, manifest: &BootManifest, program: &BootFileName) -> Vec<KitProblem> {
    let mut problems: Vec<KitProblem> = kit
        .files()
        .into_iter()
        .filter(|(_, name)| manifest.get(name.as_bytes()).is_none())
        .map(|(role, name)| KitProblem::NotPublished(role, name.clone()))
        .collect();
    if kit.boot_program().as_bytes() != program.as_bytes() {
        problems.push(KitProblem::ProgramMismatch);
    }
    if let Some(wim) = manifest.get(kit.doc.wim.as_bytes())
        && wim.sha256 != kit.pe_content_sha256()
    {
        problems.push(KitProblem::PeDigestMismatch);
    }
    problems
}

#[cfg(test)]
mod tests {
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

    #[test]
    fn m1_manifest_parses_without_kit() {
        let text = format!("schema_version = 1\nalgorithm = \"sha256\"\n\n{}", files());
        let (m, k) = parse_manifest(&text).unwrap();
        assert_eq!(m, BootManifest::from_toml(&text).unwrap());
        assert!(k.is_none());
    }

    #[test]
    fn complete_kit() {
        let (m, k) = parse_manifest(&kit("")).unwrap();
        let k = k.unwrap();
        let prog = BootFileName::try_from("bootmgfw.efi").unwrap();
        assert!(assess(&k, &m, &prog).is_empty());
        assert_eq!(k.files().len(), 4);
    }

    #[test]
    fn shape_errors_refused() {
        assert!(matches!(
            parse_manifest(&kit("fonts = [\"Boot/BCD\"]\n")),
            Err(ParseError::Shape(PeKitShapeError::DuplicateRole))
        ));
        let many: Vec<String> = (0..=MAX_FONTS).map(|i| format!("\"f{i}.ttf\"")).collect();
        assert!(matches!(
            parse_manifest(&kit(&format!("fonts = [{}]\n", many.join(",")))),
            Err(ParseError::Shape(PeKitShapeError::TooManyFonts))
        ));
        for bad in [
            "extra = 1\n",
            "fonts = [\"../x.ttf\"]\n",
            "fonts = \"x.ttf\"\n",
        ] {
            assert!(
                matches!(parse_manifest(&kit(bad)), Err(ParseError::Manifest(_))),
                "{bad}"
            );
        }
        // A missing role key.
        let text = kit("").replace("sdi = \"Boot/boot.sdi\"\n", "");
        assert!(matches!(
            parse_manifest(&text),
            Err(ParseError::Manifest(_))
        ));
    }

    #[test]
    fn incomplete_and_mismatched_kits() {
        let prog = BootFileName::try_from("bootmgfw.efi").unwrap();
        // A font that is not published.
        let (m, k) = parse_manifest(&kit("fonts = [\"Boot/Fonts/a.ttf\"]\n")).unwrap();
        let p = assess(&k.unwrap(), &m, &prog);
        assert_eq!(p.len(), 1);
        let first = p.first().unwrap();
        assert_eq!(first.status(), FileStatus::Missing);
        assert_eq!(first.describe(), "not_published:font:Boot/Fonts/a.ttf");
        // Another configured boot program.
        let (m, k) = parse_manifest(&kit("")).unwrap();
        let other = BootFileName::try_from("Boot/BCD").unwrap();
        assert_eq!(
            assess(k.as_ref().unwrap(), &m, &other),
            vec![KitProblem::ProgramMismatch]
        );
        // The WIM is not the imported PE.
        let text = kit("").replace(
            &format!("pe_content_sha256 = \"{D1}\""),
            &format!("pe_content_sha256 = \"{D2}\""),
        );
        let (m, k) = parse_manifest(&text).unwrap();
        let p = assess(&k.unwrap(), &m, &prog);
        assert_eq!(p, vec![KitProblem::PeDigestMismatch]);
        assert_eq!(p.first().unwrap().status(), FileStatus::IntegrityFailed);
    }
}
