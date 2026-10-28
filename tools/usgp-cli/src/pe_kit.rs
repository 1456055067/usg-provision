//! The relay boot manifest's optional `[pe_kit]` section, as the CLI
//! writes and checks it (M3 plan WU-13; relay format from WU-11).
//!
//! ```toml
//! schema_version = 1
//! algorithm = "sha256"
//!
//! [[file]]          # every kit file is also an ordinary published file
//! name = "bootmgfw.efi"
//! size = ...
//! sha256 = "..."
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
//! The relay parses this section with its own type
//! (`services/usgp-relay/src/pe_kit.rs`, `PeKitDocument`). Services and
//! tools do not depend on each other, and the shared type has not yet
//! moved to `usgp-proto`, so this module keeps a local copy of the same
//! shape: the same keys, the same name and digest types, the same
//! limits (at most [`MAX_FONTS`] fonts, no file in two roles, every other
//! key refused). [`to_toml`] writes text that [`parse_manifest`] (and the
//! relay) reads back unchanged.
//!
//! The boot configuration (BCD) is an opaque operator file. This module
//! never generates or edits one; it is hashed and listed like any other
//! published file (decision 0018 item 3, REQ-PE-012).
//!
//! The boot program's PE/COFF header is checked ([`check_boot_program`]):
//! `PE\0\0` signature, `Machine` x64 (`0x8664`), optional header `Magic`
//! PE32+ (`0x20B`) and `Subsystem` UEFI application (`10`), all read
//! little-endian with bounds checks (`specs/standards/winpe.md` §10).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   the kit is bound to the digest of the imported PE; every kit file is
//   listed with its SHA-256 for the relay to verify before serving.
// - NIST 800-53: SI-10 (Information Input Validation) - strict shape,
//   validated names, bounded font list; PE/COFF header read with checked
//   offsets only, never trusting a length or offset from the file.
// - NIST 800-53: CM-7 (Least Functionality) - only the named kit files.
// - SPEC: specs/preinstall-env.md#REQ-PE-012 (complete set, matching
//   architecture, never generated), #REQ-PE-018 (memory requirement)
// - SPEC: specs/standards/winpe.md §6, §9 (512 MB base plus the WIM),
//   §10 (PE/COFF Machine field, SR-2)
// - SPEC: specs/standards/winpe-network-boot.md §2 (kit files), §6 (BCD
//   is opaque)
// - DECISION: docs/decisions/0018 item 3

use std::collections::HashSet;
use std::fmt::Write as _;

use usgp_common::Sha256Digest;
use usgp_proto::boot_manifest::MAX_MANIFEST_BYTES;
use usgp_proto::{BootFileName, BootManifest, ManifestError};

/// Most font files in one kit (the relay's limit).
pub const MAX_FONTS: usize = 32;

/// Base memory Windows PE needs before its image is loaded: 512 MiB
/// (`winpe.md` §6 "512 MB"; plan section 3.5 reads it as MiB, the larger
/// value).
pub const PE_BASE_MEMORY_BYTES: u64 = 512 * 1024 * 1024;

/// `IMAGE_FILE_MACHINE_AMD64` (`winpe.md` §10).
pub const MACHINE_X64: u16 = 0x8664;

/// Optional header `Magic` of a PE32+ image (`winpe.md` §10).
pub const MAGIC_PE32_PLUS: u16 = 0x20B;

/// `IMAGE_SUBSYSTEM_EFI_APPLICATION` (`winpe.md` §10).
pub const SUBSYSTEM_EFI_APPLICATION: u16 = 10;

/// File offset of the stub's pointer to the PE signature.
const PE_POINTER_OFFSET: usize = 0x3C;
/// Size of the COFF file header.
const COFF_HEADER_LEN: usize = 20;
/// Offset of `SizeOfOptionalHeader` in the COFF file header.
const COFF_SIZE_OF_OPTIONAL_HEADER: usize = 16;
/// Offset of `Subsystem` in the optional header (PE32 and PE32+).
const OPTIONAL_SUBSYSTEM: usize = 68;

/// The `[pe_kit]` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeKit {
    /// Microsoft's UEFI boot manager from the kit.
    pub boot_program: BootFileName,
    /// The operator-built boot configuration store.
    pub bcd: BootFileName,
    /// The RAM-disk support file.
    pub sdi: BootFileName,
    /// The Windows PE image.
    pub wim: BootFileName,
    /// Font files (optional).
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
    /// The manifest key.
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
        let mut v = vec![
            (KitRole::BootProgram, &self.boot_program),
            (KitRole::Bcd, &self.bcd),
            (KitRole::Sdi, &self.sdi),
            (KitRole::Wim, &self.wim),
        ];
        v.extend(self.fonts.iter().map(|f| (KitRole::Font, f)));
        v
    }

    /// Checks the shape rules: at most [`MAX_FONTS`] fonts, and no file
    /// in two roles (or twice in `fonts`).
    ///
    /// # Errors
    ///
    /// [`KitShapeError`].
    pub fn check_shape(&self) -> Result<(), KitShapeError> {
        if self.fonts.len() > MAX_FONTS {
            return Err(KitShapeError::TooManyFonts);
        }
        let mut seen = HashSet::new();
        if !self.files().iter().all(|(_, n)| seen.insert(n.as_bytes())) {
            return Err(KitShapeError::DuplicateRole);
        }
        Ok(())
    }
}

/// Why a `[pe_kit]` section has an invalid shape.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KitShapeError {
    /// One file is named for two roles (or twice in `fonts`).
    #[error("pe_kit names one file for two roles")]
    DuplicateRole,
    /// More than [`MAX_FONTS`] fonts.
    #[error("pe_kit lists more than {MAX_FONTS} fonts")]
    TooManyFonts,
    /// `[pe_kit]` is not a table.
    #[error("pe_kit must be a table")]
    NotTable,
    /// A key other than the six the relay reads.
    #[error("pe_kit has an unknown key {0:?}")]
    UnknownKey(String),
    /// A required key is absent.
    #[error("pe_kit has no {0}")]
    Missing(&'static str),
    /// A value has the wrong type or breaks its rule.
    #[error("pe_kit {0} is not valid")]
    BadValue(&'static str),
}

/// Why manifest text could not be used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KitManifestError {
    /// The M1 manifest rules.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// The `[pe_kit]` shape rules.
    #[error("boot manifest is invalid: {0}")]
    Shape(#[from] KitShapeError),
}

/// Longest key name echoed in an error.
const MAX_SHOWN_KEY: usize = 64;

fn file_name(v: serde_json::Value, key: &'static str) -> Result<BootFileName, KitShapeError> {
    serde_json::from_value(v).map_err(|_| KitShapeError::BadValue(key))
}

/// Builds a [`PeKit`] from the parsed `[pe_kit]` table, refusing every key
/// the relay would refuse.
fn kit_from_value(v: serde_json::Value) -> Result<PeKit, KitShapeError> {
    let serde_json::Value::Object(mut map) = v else {
        return Err(KitShapeError::NotTable);
    };
    if let Some(k) = map.keys().find(|k| {
        !matches!(
            k.as_str(),
            "boot_program" | "bcd" | "sdi" | "wim" | "fonts" | "pe_content_sha256"
        )
    }) {
        return Err(KitShapeError::UnknownKey(
            k.chars().take(MAX_SHOWN_KEY).collect(),
        ));
    }
    let mut take = |key: &'static str| map.remove(key).ok_or(KitShapeError::Missing(key));
    let boot_program = file_name(take("boot_program")?, "boot_program")?;
    let bcd = file_name(take("bcd")?, "bcd")?;
    let sdi = file_name(take("sdi")?, "sdi")?;
    let wim = file_name(take("wim")?, "wim")?;
    let pe_content_sha256 = serde_json::from_value(take("pe_content_sha256")?)
        .map_err(|_| KitShapeError::BadValue("pe_content_sha256"))?;
    let fonts = match map.remove("fonts") {
        None => Vec::new(),
        Some(serde_json::Value::Array(items)) => {
            if items.len() > MAX_FONTS {
                return Err(KitShapeError::TooManyFonts);
            }
            items
                .into_iter()
                .map(|i| file_name(i, "fonts"))
                .collect::<Result<_, _>>()?
        }
        Some(_) => return Err(KitShapeError::BadValue("fonts")),
    };
    let kit = PeKit {
        boot_program,
        bcd,
        sdi,
        wim,
        fonts,
        pe_content_sha256,
    };
    kit.check_shape()?;
    Ok(kit)
}

/// Parses manifest text: the M1 [`BootManifest`] (its own rules) and the
/// optional `[pe_kit]` (shape rules). Text without `[pe_kit]` is parsed
/// exactly as [`BootManifest::from_toml`] parses it.
///
/// # Errors
///
/// [`KitManifestError`].
pub fn parse_manifest(text: &str) -> Result<(BootManifest, Option<PeKit>), KitManifestError> {
    if text.len() > MAX_MANIFEST_BYTES {
        return Err(ManifestError::TooLarge.into());
    }
    let value: serde_json::Value =
        usgp_common::config::parse_toml(text).map_err(ManifestError::Parse)?;
    let serde_json::Value::Object(mut map) = value else {
        // Not reachable for TOML text; refused the M1 way.
        return Ok((BootManifest::from_toml(text)?, None));
    };
    let Some(kit) = map.remove("pe_kit") else {
        return Ok((BootManifest::from_toml(text)?, None));
    };
    let kit = kit_from_value(kit)?;
    // The M1 part, through the M1 type and its rules (unknown keys
    // refused by its `deny_unknown_fields`).
    let manifest: BootManifest = serde_json::from_value(serde_json::Value::Object(map))
        .map_err(|_| KitShapeError::BadValue("manifest (outside pe_kit)"))?;
    manifest.validate()?;
    Ok((manifest, Some(kit)))
}

/// Canonical manifest text: [`BootManifest::to_toml`] followed by the
/// `[pe_kit]` section. Names need no TOML escaping (`BootFileName` allows
/// only `A-Z a-z 0-9 . _ - /`) and the digest is hex.
#[must_use]
pub fn to_toml(manifest: &BootManifest, kit: &PeKit) -> String {
    let mut out = manifest.to_toml();
    let fonts: Vec<String> = kit
        .fonts
        .iter()
        .map(|f| format!("\"{}\"", f.as_str()))
        .collect();
    let _ = write!(
        out,
        "\n[pe_kit]\nboot_program = \"{}\"\nbcd = \"{}\"\nsdi = \"{}\"\nwim = \"{}\"\n\
         fonts = [{}]\npe_content_sha256 = \"{}\"\n",
        kit.boot_program.as_str(),
        kit.bcd.as_str(),
        kit.sdi.as_str(),
        kit.wim.as_str(),
        fonts.join(", "),
        kit.pe_content_sha256.to_hex()
    );
    out
}

/// One reason a kit is incomplete or does not match its manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KitProblem {
    /// A role names a file that is not a published `[[file]]`.
    NotPublished(KitRole, BootFileName),
    /// The WIM's manifest digest is not `pe_content_sha256`.
    PeDigestMismatch,
}

impl std::fmt::Display for KitProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPublished(role, name) => {
                write!(f, "pe_kit {} {name} is not a published file", role.label())
            }
            Self::PeDigestMismatch => f.write_str(
                "pe_kit wim's manifest sha256 is not pe_content_sha256 (the imported PE)",
            ),
        }
    }
}

/// Checks the kit against the manifest. Empty means complete. (The relay
/// also checks `boot_program` against its configured
/// `boot.uefi_x64_program`, which this tool cannot see.)
#[must_use]
pub fn assess(kit: &PeKit, manifest: &BootManifest) -> Vec<KitProblem> {
    let mut problems: Vec<KitProblem> = kit
        .files()
        .into_iter()
        .filter(|(_, name)| manifest.get(name.as_bytes()).is_none())
        .map(|(role, name)| KitProblem::NotPublished(role, name.clone()))
        .collect();
    if let Some(wim) = manifest.get(kit.wim.as_bytes())
        && wim.sha256 != kit.pe_content_sha256
    {
        problems.push(KitProblem::PeDigestMismatch);
    }
    problems
}

/// Memory a device needs to start the PE: the base plus the WIM, which is
/// held in memory (REQ-PE-018). Saturates rather than wrapping.
#[must_use]
pub const fn memory_required(wim_size: u64) -> u64 {
    PE_BASE_MEMORY_BYTES.saturating_add(wim_size)
}

/// Why a boot program is not a UEFI x64 application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PeCoffError {
    /// The file ends before a header field it must hold.
    #[error("is too short to hold a PE/COFF header")]
    Truncated,
    /// No `PE\0\0` signature at the offset the stub names.
    #[error("has no PE signature at the offset its MS-DOS stub names")]
    NoSignature,
    /// `Machine` is not x64.
    #[error("is built for machine type 0x{0:04x}, not x64 (0x8664)")]
    WrongMachine(u16),
    /// Optional header `Magic` is not PE32+.
    #[error("optional header magic is 0x{0:04x}, not PE32+ (0x020b)")]
    NotPe32Plus(u16),
    /// `Subsystem` is not a UEFI application.
    #[error("subsystem is {0}, not a UEFI application (10)")]
    NotUefiApplication(u16),
}

fn u16_at(b: &[u8], off: usize) -> Result<u16, PeCoffError> {
    let end = off.checked_add(2).ok_or(PeCoffError::Truncated)?;
    let s = b.get(off..end).ok_or(PeCoffError::Truncated)?;
    let mut a = [0u8; 2];
    a.copy_from_slice(s);
    Ok(u16::from_le_bytes(a))
}

fn u32_at(b: &[u8], off: usize) -> Result<u32, PeCoffError> {
    let end = off.checked_add(4).ok_or(PeCoffError::Truncated)?;
    let s = b.get(off..end).ok_or(PeCoffError::Truncated)?;
    let mut a = [0u8; 4];
    a.copy_from_slice(s);
    Ok(u32::from_le_bytes(a))
}

/// Checks that `bytes` is a UEFI x64 application (`winpe.md` §10): the
/// stub's pointer at `0x3C` leads to `PE\0\0`; the COFF `Machine` is
/// `0x8664`; the optional header is PE32+ and its `Subsystem` is 10. All
/// fields little-endian (UEFI §1.9.1). Every offset is checked; nothing in
/// the file can make this read out of bounds or overflow.
///
/// # Errors
///
/// [`PeCoffError`] for the first rule that fails, in that order.
pub fn check_boot_program(bytes: &[u8]) -> Result<(), PeCoffError> {
    let sig =
        usize::try_from(u32_at(bytes, PE_POINTER_OFFSET)?).map_err(|_| PeCoffError::Truncated)?;
    let sig_end = sig.checked_add(4).ok_or(PeCoffError::Truncated)?;
    match bytes.get(sig..sig_end) {
        Some(b"PE\0\0") => {}
        Some(_) => return Err(PeCoffError::NoSignature),
        None => return Err(PeCoffError::Truncated),
    }
    let coff = sig_end;
    let machine = u16_at(bytes, coff)?;
    if machine != MACHINE_X64 {
        return Err(PeCoffError::WrongMachine(machine));
    }
    let opt_len = usize::from(u16_at(
        bytes,
        coff.checked_add(COFF_SIZE_OF_OPTIONAL_HEADER)
            .ok_or(PeCoffError::Truncated)?,
    )?);
    let opt = coff
        .checked_add(COFF_HEADER_LEN)
        .ok_or(PeCoffError::Truncated)?;
    let magic = u16_at(bytes, opt)?;
    if magic != MAGIC_PE32_PLUS {
        return Err(PeCoffError::NotPe32Plus(magic));
    }
    // The subsystem field must lie inside the declared optional header.
    if opt_len < OPTIONAL_SUBSYSTEM.saturating_add(2) {
        return Err(PeCoffError::Truncated);
    }
    let subsystem = u16_at(
        bytes,
        opt.checked_add(OPTIONAL_SUBSYSTEM)
            .ok_or(PeCoffError::Truncated)?,
    )?;
    if subsystem != SUBSYSTEM_EFI_APPLICATION {
        return Err(PeCoffError::NotUefiApplication(subsystem));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use usgp_proto::ManifestEntry;

    const D1: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const D2: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// A minimal image header: stub pointer, signature, COFF header and
    /// the first 70 bytes of an optional header. Not a runnable program;
    /// only the fields `check_boot_program` reads are set.
    pub(crate) fn pe_header(machine: u16, magic: u16, subsystem: u16) -> Vec<u8> {
        let sig = 0x80usize;
        let mut b = vec![0u8; sig + 4 + COFF_HEADER_LEN + 0xF0];
        b.get_mut(0..2).unwrap().copy_from_slice(b"MZ");
        b.get_mut(0x3C..0x40)
            .unwrap()
            .copy_from_slice(&u32::try_from(sig).unwrap().to_le_bytes());
        b.get_mut(sig..sig + 4).unwrap().copy_from_slice(b"PE\0\0");
        let coff = sig + 4;
        b.get_mut(coff..coff + 2)
            .unwrap()
            .copy_from_slice(&machine.to_le_bytes());
        b.get_mut(coff + 16..coff + 18)
            .unwrap()
            .copy_from_slice(&0xF0u16.to_le_bytes());
        let opt = coff + COFF_HEADER_LEN;
        b.get_mut(opt..opt + 2)
            .unwrap()
            .copy_from_slice(&magic.to_le_bytes());
        b.get_mut(opt + 68..opt + 70)
            .unwrap()
            .copy_from_slice(&subsystem.to_le_bytes());
        b
    }

    pub(crate) fn x64_efi() -> Vec<u8> {
        pe_header(MACHINE_X64, MAGIC_PE32_PLUS, SUBSYSTEM_EFI_APPLICATION)
    }

    #[test]
    fn x64_uefi_application_accepted() {
        assert_eq!(check_boot_program(&x64_efi()), Ok(()));
    }

    #[test]
    fn wrong_machine_magic_subsystem_refused() {
        for (m, want) in [
            (0x014C, PeCoffError::WrongMachine(0x014C)),
            (0xAA64, PeCoffError::WrongMachine(0xAA64)),
            (0x0000, PeCoffError::WrongMachine(0)),
            // Big-endian x64 bytes (86 64) read as 0x6486.
            (0x6486, PeCoffError::WrongMachine(0x6486)),
        ] {
            assert_eq!(
                check_boot_program(&pe_header(m, MAGIC_PE32_PLUS, 10)),
                Err(want)
            );
        }
        assert_eq!(
            check_boot_program(&pe_header(MACHINE_X64, 0x10B, 10)),
            Err(PeCoffError::NotPe32Plus(0x10B))
        );
        assert_eq!(
            check_boot_program(&pe_header(MACHINE_X64, MAGIC_PE32_PLUS, 11)),
            Err(PeCoffError::NotUefiApplication(11))
        );
    }

    #[test]
    fn malformed_headers_never_panic() {
        assert_eq!(check_boot_program(b""), Err(PeCoffError::Truncated));
        assert_eq!(
            check_boot_program(&[0u8; 0x3F]),
            Err(PeCoffError::Truncated)
        );
        // Pointer far past the end, and the largest pointer.
        for ptr in [0x1000u32, u32::MAX, u32::MAX - 3] {
            let mut b = x64_efi();
            b.get_mut(0x3C..0x40)
                .unwrap()
                .copy_from_slice(&ptr.to_le_bytes());
            assert_eq!(check_boot_program(&b), Err(PeCoffError::Truncated));
        }
        // Wrong signature.
        let mut b = x64_efi();
        b.get_mut(0x80..0x84).unwrap().copy_from_slice(b"PE\0\x01");
        assert_eq!(check_boot_program(&b), Err(PeCoffError::NoSignature));
        // Optional header declared too short for Subsystem.
        let mut b = x64_efi();
        b.get_mut(0x84 + 16..0x84 + 18)
            .unwrap()
            .copy_from_slice(&69u16.to_le_bytes());
        assert_eq!(check_boot_program(&b), Err(PeCoffError::Truncated));
        // File cut inside the optional header.
        let b = x64_efi();
        let cut = b.get(..0x84 + COFF_HEADER_LEN + 40).unwrap();
        assert_eq!(check_boot_program(cut), Err(PeCoffError::Truncated));
        // Every prefix that ends before the last field read (Subsystem)
        // is refused without a panic; the first long enough one passes.
        let good = x64_efi();
        let last = 0x84 + COFF_HEADER_LEN + OPTIONAL_SUBSYSTEM + 2;
        for n in 0..last {
            assert!(check_boot_program(good.get(..n).unwrap()).is_err(), "{n}");
        }
        assert_eq!(check_boot_program(good.get(..last).unwrap()), Ok(()));
    }

    fn n(s: &str) -> BootFileName {
        BootFileName::try_from(s).unwrap()
    }

    fn d(s: &str) -> Sha256Digest {
        Sha256Digest::from_hex(s).unwrap()
    }

    fn kit() -> PeKit {
        PeKit {
            boot_program: n("bootmgfw.efi"),
            bcd: n("Boot/BCD"),
            sdi: n("Boot/boot.sdi"),
            wim: n("Boot/boot.wim"),
            fonts: vec![n("Boot/Fonts/a.ttf")],
            pe_content_sha256: d(D1),
        }
    }

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

    const ALL: [&str; 5] = [
        "bootmgfw.efi",
        "Boot/BCD",
        "Boot/boot.sdi",
        "Boot/boot.wim",
        "Boot/Fonts/a.ttf",
    ];

    #[test]
    fn written_text_reads_back_unchanged() {
        let m = manifest(&ALL);
        let text = to_toml(&m, &kit());
        let (m2, k2) = parse_manifest(&text).unwrap();
        assert_eq!(m2, m);
        assert_eq!(k2.unwrap(), kit());
        assert!(assess(&kit(), &m).is_empty());
        // No fonts: an empty list, still read back.
        let mut k = kit();
        k.fonts.clear();
        let (_, k3) = parse_manifest(&to_toml(&manifest(&ALL), &k)).unwrap();
        assert_eq!(k3.unwrap(), k);
    }

    /// The relay's own unit-test manifest text (WU-11
    /// `services/usgp-relay/src/pe_kit.rs`), copied, parses here too:
    /// no `fonts` key, keys in the relay's order.
    #[test]
    fn relay_format_parses() {
        let files: String = ["bootmgfw.efi", "Boot/BCD", "Boot/boot.sdi", "Boot/boot.wim"]
            .iter()
            .map(|n| format!("[[file]]\nname = \"{n}\"\nsize = 3\nsha256 = \"{D1}\"\n\n"))
            .collect();
        let text = format!(
            "schema_version = 1\nalgorithm = \"sha256\"\n\n{files}[pe_kit]\nboot_program = \"bootmgfw.efi\"\n\
             bcd = \"Boot/BCD\"\nsdi = \"Boot/boot.sdi\"\nwim = \"Boot/boot.wim\"\n\
             pe_content_sha256 = \"{D1}\"\n"
        );
        let (m, k) = parse_manifest(&text).unwrap();
        let k = k.unwrap();
        assert!(k.fonts.is_empty());
        assert!(assess(&k, &m).is_empty());
        // Without the section it is exactly the M1 format.
        let m1 = format!("schema_version = 1\nalgorithm = \"sha256\"\n\n{files}");
        let (m, k) = parse_manifest(&m1).unwrap();
        assert_eq!(m, BootManifest::from_toml(&m1).unwrap());
        assert!(k.is_none());
    }

    #[test]
    fn shape_errors_refused() {
        let base = to_toml(&manifest(&ALL), &kit());
        let with = |from: &str, to: &str| base.replace(from, to);
        let cases = [
            with("fonts = [", "extra = 1\nfonts = ["),
            with("\"Boot/Fonts/a.ttf\"]", "\"Boot/BCD\"]"),
            with("\"Boot/Fonts/a.ttf\"]", "\"../x.ttf\"]"),
            with("fonts = [\"Boot/Fonts/a.ttf\"]", "fonts = \"a.ttf\""),
            with("sdi = \"Boot/boot.sdi\"\n", ""),
            with(
                &format!("pe_content_sha256 = \"{D1}\""),
                "pe_content_sha256 = \"x\"",
            ),
            with(
                "algorithm = \"sha256\"\n",
                "algorithm = \"sha256\"\nsurprise = 1\n",
            ),
            with("[pe_kit]\n", "pe_kit = 1\n[other]\n"),
        ];
        for text in &cases {
            assert!(parse_manifest(text).is_err(), "{text}");
        }
        let many: Vec<String> = (0..=MAX_FONTS).map(|i| format!("\"f{i}.ttf\"")).collect();
        let text = with(
            "fonts = [\"Boot/Fonts/a.ttf\"]",
            &format!("fonts = [{}]", many.join(",")),
        );
        assert!(matches!(
            parse_manifest(&text),
            Err(KitManifestError::Shape(KitShapeError::TooManyFonts))
        ));
    }

    #[test]
    fn incomplete_and_mismatched_kits() {
        let m = manifest(&ALL[..4]);
        assert_eq!(
            assess(&kit(), &m),
            vec![KitProblem::NotPublished(
                KitRole::Font,
                n("Boot/Fonts/a.ttf")
            )]
        );
        let mut k = kit();
        k.pe_content_sha256 = d(D2);
        assert_eq!(
            assess(&k, &manifest(&ALL)),
            vec![KitProblem::PeDigestMismatch]
        );
    }

    #[test]
    fn memory_requirement() {
        assert_eq!(memory_required(0), 536_870_912);
        assert_eq!(memory_required(300_000_000), 836_870_912);
        assert_eq!(memory_required(u64::MAX), u64::MAX);
    }
}
