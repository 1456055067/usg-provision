//! The boot manifest's optional `[pe_kit]` section: the operator's Windows
//! PE network-boot files (M3 plan WU-11/WU-13, sections 1.2(e) and 5;
//! decision 0018 item 3). One type and one parser shared by the relay,
//! which reads it, and `usgp-cli`, which writes it.
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
//! fonts = ["Boot/Fonts/a.ttf"]       # optional
//! pe_content_sha256 = "..."          # SHA-256 of the imported, Ready PE
//! ```
//!
//! The section is the `pe_kit` field of [`crate::BootManifest`]; a manifest
//! without it is exactly the M1 format. Two levels of checks:
//!
//! - **Shape** ([`PeKitV1::validate`], run by
//!   [`crate::BootManifest::validate`] on every parse): unknown keys
//!   (serde), bad names (the name type), at most [`MAX_FONTS`] fonts, and
//!   no file named for two roles.
//! - **Completeness and binding** ([`PeKitV1::assess`]): every role names a
//!   published `[[file]]`, the WIM's manifest digest equals
//!   `pe_content_sha256`, and (when the caller knows it) the boot program
//!   is the one the relay offers. A failure is missing content
//!   (REQ-PE-012, REQ-BOOT-052), not a malformed manifest.
//!
//! The BCD is an opaque operator file; nothing here generates or edits one
//! (`winpe-network-boot.md` §6).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   the kit is bound to the imported PE's digest; every kit file is a
//   published file with its own SHA-256.
// - NIST 800-53: SI-10 (Information Input Validation) - strict shape,
//   validated names, bounded font list, unknown keys refused.
// - NIST 800-53: CM-7 (Least Functionality) - only the named kit files.
// - SPEC: specs/preinstall-env.md#REQ-PE-011, #REQ-PE-012
// - SPEC: specs/boot-network.md#REQ-BOOT-052, #REQ-BOOT-063
// - SPEC: specs/standards/winpe-network-boot.md §2, §5, §6
// - DECISION: docs/decisions/0018 item 3

use std::collections::HashSet;
use std::fmt::{self, Write as _};

use usgp_common::Sha256Digest;

use crate::boot_file_name::BootFileName;
use crate::boot_manifest::BootManifest;

/// Most font files in one kit (project design).
pub const MAX_FONTS: usize = 32;

/// The `[pe_kit]` section.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeKitV1 {
    /// Microsoft's UEFI boot manager from the kit.
    pub boot_program: BootFileName,
    /// The operator-built boot configuration store.
    pub bcd: BootFileName,
    /// The RAM-disk support file.
    pub sdi: BootFileName,
    /// The Windows PE image.
    pub wim: BootFileName,
    /// Font files (optional; absent means none).
    #[serde(default)]
    pub fonts: Vec<BootFileName>,
    /// SHA-256 of the imported, Ready PE content (the WIM).
    pub pe_content_sha256: Sha256Digest,
}

/// The role a kit file plays.
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
    /// Stable label (the manifest key; `font` for one of `fonts`).
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

/// Why a `[pe_kit]` section has an invalid shape (the manifest is
/// invalid).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PeKitError {
    /// One file is named for two roles (or twice in `fonts`).
    #[error("boot manifest pe_kit names one file for two roles")]
    DuplicateRole,
    /// More than [`MAX_FONTS`] fonts.
    #[error("boot manifest pe_kit lists more than {MAX_FONTS} fonts")]
    TooManyFonts,
}

/// One reason a kit is incomplete or does not match its manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KitProblem {
    /// A role names a file that is not a published `[[file]]`.
    NotPublished(KitRole, BootFileName),
    /// `boot_program` is not the boot program the relay offers.
    ProgramMismatch,
    /// The WIM's manifest digest is not `pe_content_sha256`.
    PeDigestMismatch,
}

impl KitProblem {
    /// Stable label.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::NotPublished(..) => "not_published",
            Self::ProgramMismatch => "boot_program_mismatch",
            Self::PeDigestMismatch => "pe_digest_mismatch",
        }
    }

    /// `label` plus the role and file, for events
    /// (`not_published:font:Boot/Fonts/a.ttf`).
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

impl fmt::Display for KitProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPublished(role, name) => {
                write!(f, "pe_kit {} {name} is not a published file", role.label())
            }
            Self::ProgramMismatch => {
                f.write_str("pe_kit boot_program is not the boot program the relay offers")
            }
            Self::PeDigestMismatch => f.write_str(
                "pe_kit wim's manifest sha256 is not pe_content_sha256 (the imported PE)",
            ),
        }
    }
}

impl PeKitV1 {
    /// Every kit file with its role, boot program first.
    #[must_use]
    pub fn files(&self) -> Vec<(KitRole, &BootFileName)> {
        let mut v = vec![
            (KitRole::BootProgram, &self.boot_program),
            (KitRole::Bcd, &self.bcd),
            (KitRole::Sdi, &self.sdi),
            (KitRole::Wim, &self.wim),
        ];
        v.extend(self.fonts.iter().map(|f| (KitRole::Font, f)));
        v
    }

    /// Checks the shape rules: at most [`MAX_FONTS`] fonts, and no file in
    /// two roles (or twice in `fonts`). Key and value rules are enforced
    /// by the types when parsing.
    ///
    /// # Errors
    ///
    /// [`PeKitError`], fonts first.
    pub fn validate(&self) -> Result<(), PeKitError> {
        if self.fonts.len() > MAX_FONTS {
            return Err(PeKitError::TooManyFonts);
        }
        let mut seen = HashSet::new();
        if !self.files().iter().all(|(_, n)| seen.insert(n.as_bytes())) {
            return Err(PeKitError::DuplicateRole);
        }
        Ok(())
    }

    /// Checks the kit against `manifest` (module docs). `program` is the
    /// boot program the caller offers, if it knows it (the relay does; the
    /// CLI does not). Empty means complete.
    #[must_use]
    pub fn assess(
        &self,
        manifest: &BootManifest,
        program: Option<&BootFileName>,
    ) -> Vec<KitProblem> {
        let mut problems: Vec<KitProblem> = self
            .files()
            .into_iter()
            .filter(|(_, name)| manifest.get(name.as_bytes()).is_none())
            .map(|(role, name)| KitProblem::NotPublished(role, name.clone()))
            .collect();
        if let Some(p) = program
            && p.as_bytes() != self.boot_program.as_bytes()
        {
            problems.push(KitProblem::ProgramMismatch);
        }
        if let Some(wim) = manifest.get(self.wim.as_bytes())
            && wim.sha256 != self.pe_content_sha256
        {
            problems.push(KitProblem::PeDigestMismatch);
        }
        problems
    }

    /// Appends the canonical `[pe_kit]` section (preceded by a blank line).
    /// Names need no TOML escaping (`BootFileName` allows only
    /// `A-Z a-z 0-9 . _ - /`) and the digest is hex. `fonts` is always
    /// written, as an empty list when there are none.
    pub(crate) fn write_toml(&self, out: &mut String) {
        let fonts: Vec<String> = self
            .fonts
            .iter()
            .map(|f| format!("\"{}\"", f.as_str()))
            .collect();
        let _ = write!(
            out,
            "\n[pe_kit]\nboot_program = \"{}\"\nbcd = \"{}\"\nsdi = \"{}\"\nwim = \"{}\"\n\
             fonts = [{}]\npe_content_sha256 = \"{}\"\n",
            self.boot_program.as_str(),
            self.bcd.as_str(),
            self.sdi.as_str(),
            self.wim.as_str(),
            fonts.join(", "),
            self.pe_content_sha256.to_hex()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot_manifest::{ManifestEntry, ManifestError};

    const D1: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const D2: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn n(s: &str) -> BootFileName {
        BootFileName::try_from(s).unwrap()
    }

    fn d(s: &str) -> Sha256Digest {
        Sha256Digest::from_hex(s).unwrap()
    }

    fn files_text() -> String {
        ["bootmgfw.efi", "Boot/BCD", "Boot/boot.sdi", "Boot/boot.wim"]
            .iter()
            .map(|n| format!("[[file]]\nname = \"{n}\"\nsize = 3\nsha256 = \"{D1}\"\n\n"))
            .collect()
    }

    /// The relay's WU-11 unit-test text: no `fonts` key, relay key order.
    fn relay_text(extra: &str) -> String {
        format!(
            "schema_version = 1\nalgorithm = \"sha256\"\n\n{}[pe_kit]\nboot_program = \"bootmgfw.efi\"\n\
             bcd = \"Boot/BCD\"\nsdi = \"Boot/boot.sdi\"\nwim = \"Boot/boot.wim\"\n\
             pe_content_sha256 = \"{D1}\"\n{extra}",
            files_text()
        )
    }

    fn kit() -> PeKitV1 {
        PeKitV1 {
            boot_program: n("bootmgfw.efi"),
            bcd: n("Boot/BCD"),
            sdi: n("Boot/boot.sdi"),
            wim: n("Boot/boot.wim"),
            fonts: vec![n("Boot/Fonts/a.ttf")],
            pe_content_sha256: d(D1),
        }
    }

    const ALL: [&str; 5] = [
        "bootmgfw.efi",
        "Boot/BCD",
        "Boot/boot.sdi",
        "Boot/boot.wim",
        "Boot/Fonts/a.ttf",
    ];

    fn manifest(names: &[&str]) -> BootManifest {
        BootManifest::new(
            names
                .iter()
                .map(|x| ManifestEntry {
                    name: n(x),
                    size: 3,
                    sha256: d(D1),
                })
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn m1_manifest_parses_without_kit() {
        let text = format!(
            "schema_version = 1\nalgorithm = \"sha256\"\n\n{}",
            files_text()
        );
        let m = BootManifest::from_toml(&text).unwrap();
        assert!(m.pe_kit.is_none());
        assert!(!m.to_toml().contains("pe_kit"));
    }

    #[test]
    fn relay_format_parses() {
        let m = BootManifest::from_toml(&relay_text("")).unwrap();
        let k = m.pe_kit.as_ref().unwrap();
        assert!(k.fonts.is_empty());
        assert_eq!(k.files().len(), 4);
        assert!(k.assess(&m, Some(&n("bootmgfw.efi"))).is_empty());
        assert!(k.assess(&m, None).is_empty());
    }

    #[test]
    fn written_text_reads_back_unchanged() {
        let m = manifest(&ALL).with_pe_kit(kit()).unwrap();
        let text = m.to_toml();
        assert_eq!(BootManifest::from_toml(&text).unwrap(), m);
        // No fonts: an empty list, still read back.
        let mut k = kit();
        k.fonts.clear();
        let m = manifest(&ALL).with_pe_kit(k).unwrap();
        assert_eq!(BootManifest::from_toml(&m.to_toml()).unwrap(), m);
    }

    #[test]
    fn shape_errors_refused() {
        assert!(matches!(
            BootManifest::from_toml(&relay_text("fonts = [\"Boot/BCD\"]\n")),
            Err(ManifestError::PeKit(PeKitError::DuplicateRole))
        ));
        let many: Vec<String> = (0..=MAX_FONTS).map(|i| format!("\"f{i}.ttf\"")).collect();
        assert!(matches!(
            BootManifest::from_toml(&relay_text(&format!("fonts = [{}]\n", many.join(",")))),
            Err(ManifestError::PeKit(PeKitError::TooManyFonts))
        ));
        for bad in [
            "extra = 1\n",
            "fonts = [\"../x.ttf\"]\n",
            "fonts = \"x.ttf\"\n",
        ] {
            assert!(
                matches!(
                    BootManifest::from_toml(&relay_text(bad)),
                    Err(ManifestError::Parse(_))
                ),
                "{bad}"
            );
        }
        let base = relay_text("");
        for text in [
            base.replace("sdi = \"Boot/boot.sdi\"\n", ""),
            base.replace(
                &format!("pe_content_sha256 = \"{D1}\""),
                "pe_content_sha256 = \"x\"",
            ),
            base.replace(
                "algorithm = \"sha256\"\n",
                "algorithm = \"sha256\"\nsurprise = 1\n",
            ),
            base.replace("[pe_kit]\n", "pe_kit = 1\n[other]\n"),
        ] {
            assert!(
                matches!(BootManifest::from_toml(&text), Err(ManifestError::Parse(_))),
                "{text}"
            );
        }
        // A hand-built bad kit is refused by `with_pe_kit` too.
        let mut k = kit();
        k.sdi = n("Boot/BCD");
        assert!(matches!(
            manifest(&ALL).with_pe_kit(k),
            Err(ManifestError::PeKit(PeKitError::DuplicateRole))
        ));
    }

    #[test]
    fn incomplete_and_mismatched_kits() {
        let m = manifest(&ALL[..4]);
        let p = kit().assess(&m, None);
        assert_eq!(
            p,
            vec![KitProblem::NotPublished(
                KitRole::Font,
                n("Boot/Fonts/a.ttf")
            )]
        );
        assert_eq!(
            p.first().unwrap().describe(),
            "not_published:font:Boot/Fonts/a.ttf"
        );
        assert_eq!(
            kit().assess(&manifest(&ALL), Some(&n("Boot/BCD"))),
            vec![KitProblem::ProgramMismatch]
        );
        let mut k = kit();
        k.pe_content_sha256 = d(D2);
        let p = k.assess(&manifest(&ALL), None);
        assert_eq!(p, vec![KitProblem::PeDigestMismatch]);
        assert_eq!(p.first().unwrap().label(), "pe_digest_mismatch");
    }
}
