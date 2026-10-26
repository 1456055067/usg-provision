//! Boot manifest: the operator-approved list of boot files the relay may
//! serve, with each file's size and SHA-256 digest.
//!
//! Format (plan section 3.3, our design), at most [`MAX_MANIFEST_BYTES`]:
//!
//! ```toml
//! schema_version = 1
//! algorithm = "sha256"
//!
//! [[file]]
//! name = "usgp-test-payload.efi"
//! size = 5632
//! sha256 = "<64 lowercase hex>"
//! ```
//!
//! Parsing is strict: unknown keys are rejected at every level, and
//! [`BootManifest::validate`] runs on every parse.
//!
//! This type only describes content. Digests are computed by `usgp-crypto`,
//! and verifying file bytes against an entry is the consumer's job.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   reference digests for verify-before-serve.
// - NIST 800-53: SI-10 (Information Input Validation) - bounded, strict
//   parse; unknown keys, bad names, duplicates and oversize entries refused.
// - NIST 800-53: CM-6 (Configuration Settings) - schema version checked.
// - SPEC: specs/boot-network.md#REQ-BOOT-041, #REQ-BOOT-052, #REQ-BOOT-053

// POAM: SI-7 - the M1 manifest is not signed. The relay accepts it only
// if it is owned by root or the configured administrator uid, is not
// group- or world-writable, and every directory above it is owned by root
// or that uid and not group- or world-writable unless sticky; checked on
// the opened file (usgp_common::config::read_trusted). ACLs are not
// inspected. Anyone who can act as root or the administrator uid can
// still replace manifest and payload together. M2 adds a server-signed
// manifest.

use std::collections::HashSet;
use std::fmt::Write as _;

use usgp_common::Sha256Digest;
use usgp_common::config::{ConfigError, parse_toml};

use crate::boot_file_name::BootFileName;

/// The only supported `schema_version`.
pub const SCHEMA_VERSION: u32 = 1;

/// Largest manifest text accepted (1 MiB).
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

/// Most entries in one manifest.
pub const MAX_FILES: usize = 256;

/// Largest file size an entry may declare (4 GiB, inclusive).
pub const MAX_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Digest algorithm named in the manifest. Only `"sha256"` exists; any
/// other text fails to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum DigestName {
    /// SHA-256 (FIPS 180-4).
    #[serde(rename = "sha256")]
    Sha256,
}

impl DigestName {
    /// The manifest text for this algorithm.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
        }
    }
}

/// One published boot file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestEntry {
    /// Name matched byte for byte against TFTP requests, and the path
    /// relative to the boot root.
    pub name: BootFileName,
    /// Exact size in bytes.
    pub size: u64,
    /// SHA-256 of the file's bytes.
    pub sha256: Sha256Digest,
}

/// The boot manifest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootManifest {
    /// Format version; must be [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Digest algorithm of every entry.
    pub algorithm: DigestName,
    /// Published files (TOML `[[file]]` tables), in manifest order.
    #[serde(rename = "file", default)]
    pub files: Vec<ManifestEntry>,
}

/// Manifest parse or validation errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ManifestError {
    /// The text is larger than [`MAX_MANIFEST_BYTES`].
    #[error("boot manifest is larger than the {MAX_MANIFEST_BYTES}-byte limit")]
    TooLarge,
    /// The TOML did not parse into the manifest shape (includes unknown
    /// keys, a bad algorithm, a bad name or a bad digest).
    #[error("boot manifest is invalid: {0}")]
    Parse(#[source] ConfigError),
    /// `schema_version` is not supported.
    #[error("boot manifest schema_version {0} is not supported (expected 1)")]
    UnsupportedSchema(u32),
    /// No `[[file]]` entries.
    #[error("boot manifest lists no files")]
    NoFiles,
    /// More than [`MAX_FILES`] entries.
    #[error("boot manifest lists {0} files; the limit is {MAX_FILES}")]
    TooManyFiles(usize),
    /// Two entries have the same name.
    #[error("boot manifest lists {0} more than once")]
    DuplicateName(BootFileName),
    /// An entry declares a size above [`MAX_FILE_SIZE`].
    #[error("boot manifest entry {name} declares {size} bytes; the limit is {MAX_FILE_SIZE}")]
    FileTooLarge {
        /// The entry.
        name: BootFileName,
        /// Declared size.
        size: u64,
    },
}

impl BootManifest {
    /// A validated version-1 SHA-256 manifest of `files`.
    ///
    /// # Errors
    ///
    /// As [`BootManifest::validate`].
    pub fn new(files: Vec<ManifestEntry>) -> Result<Self, ManifestError> {
        let m = Self {
            schema_version: SCHEMA_VERSION,
            algorithm: DigestName::Sha256,
            files,
        };
        m.validate()?;
        Ok(m)
    }

    /// Parses and validates manifest text.
    ///
    /// # Errors
    ///
    /// [`ManifestError::TooLarge`] before any parsing if `text` exceeds
    /// [`MAX_MANIFEST_BYTES`]; [`ManifestError::Parse`] for TOML or shape
    /// errors; otherwise as [`BootManifest::validate`].
    pub fn from_toml(text: &str) -> Result<Self, ManifestError> {
        if text.len() > MAX_MANIFEST_BYTES {
            return Err(ManifestError::TooLarge);
        }
        let m: Self = parse_toml(text).map_err(ManifestError::Parse)?;
        m.validate()?;
        Ok(m)
    }

    /// Checks the manifest rules: schema version 1, 1 to 256 entries,
    /// unique names, and each size at most 4 GiB. (The algorithm and name
    /// rules are enforced by the types.)
    ///
    /// # Errors
    ///
    /// The first rule that fails, in that order.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ManifestError::UnsupportedSchema(self.schema_version));
        }
        if self.files.is_empty() {
            return Err(ManifestError::NoFiles);
        }
        if self.files.len() > MAX_FILES {
            return Err(ManifestError::TooManyFiles(self.files.len()));
        }
        let mut seen = HashSet::with_capacity(self.files.len());
        for entry in &self.files {
            if !seen.insert(entry.name.as_bytes()) {
                return Err(ManifestError::DuplicateName(entry.name.clone()));
            }
            if entry.size > MAX_FILE_SIZE {
                return Err(ManifestError::FileTooLarge {
                    name: entry.name.clone(),
                    size: entry.size,
                });
            }
        }
        Ok(())
    }

    /// Canonical TOML text (the format in the module docs, entries in
    /// order). [`BootManifest::from_toml`] reads it back unchanged.
    ///
    /// Written by hand rather than through a serializer so the output is
    /// stable and has no failure path: names are restricted to characters
    /// that need no TOML escaping, and digests are hex.
    #[must_use]
    pub fn to_toml(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "schema_version = {}", self.schema_version);
        let _ = writeln!(out, "algorithm = \"{}\"", self.algorithm.as_str());
        for entry in &self.files {
            let _ = write!(
                out,
                "\n[[file]]\nname = \"{}\"\nsize = {}\nsha256 = \"{}\"\n",
                entry.name.as_str(),
                entry.size,
                entry.sha256.to_hex()
            );
        }
        out
    }

    /// The entry whose name equals `name` byte for byte.
    #[must_use]
    pub fn get(&self, name: &[u8]) -> Option<&ManifestEntry> {
        self.files.iter().find(|e| e.name.as_bytes() == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D1: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const D2: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// Golden v1 manifest in canonical form. Changing this text is a
    /// format change (REQ-BOOT-053).
    const GOLDEN_V1: &str = "schema_version = 1
algorithm = \"sha256\"

[[file]]
name = \"usgp-test-payload.efi\"
size = 5632
sha256 = \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"

[[file]]
name = \"x64/empty.bin\"
size = 0
sha256 = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"
";

    fn entry(name: &str, size: u64, hex: &str) -> ManifestEntry {
        ManifestEntry {
            name: BootFileName::try_from(name).unwrap(),
            size,
            sha256: Sha256Digest::from_hex(hex).unwrap(),
        }
    }

    fn one_file(extra_top: &str, extra_entry: &str) -> String {
        format!(
            "schema_version = 1\nalgorithm = \"sha256\"\n{extra_top}\n[[file]]\nname = \"a.efi\"\nsize = 1\nsha256 = \"{D1}\"\n{extra_entry}"
        )
    }

    #[test]
    fn golden_v1_parses() {
        let m = BootManifest::from_toml(GOLDEN_V1).unwrap();
        assert_eq!(m.schema_version, 1);
        assert_eq!(m.algorithm, DigestName::Sha256);
        assert_eq!(
            m.files,
            vec![
                entry("usgp-test-payload.efi", 5632, D1),
                entry("x64/empty.bin", 0, D2)
            ]
        );
    }

    #[test]
    fn golden_v1_is_canonical_output() {
        let m = BootManifest::new(vec![
            entry("usgp-test-payload.efi", 5632, D1),
            entry("x64/empty.bin", 0, D2),
        ])
        .unwrap();
        assert_eq!(m.to_toml(), GOLDEN_V1);
        assert_eq!(BootManifest::from_toml(&m.to_toml()).unwrap(), m);
    }

    #[test]
    fn uppercase_digest_accepted_written_lowercase() {
        let text = one_file("", "").replace(D1, &D1.to_ascii_uppercase());
        let m = BootManifest::from_toml(&text).unwrap();
        assert!(m.to_toml().contains(D1));
    }

    #[test]
    fn get_is_byte_exact() {
        let m = BootManifest::from_toml(GOLDEN_V1).unwrap();
        assert_eq!(m.get(b"usgp-test-payload.efi").map(|e| e.size), Some(5632));
        assert!(m.get(b"USGP-TEST-PAYLOAD.EFI").is_none());
        assert!(m.get(b"usgp-test-payload.efi\0").is_none());
        assert!(m.get(b"/usgp-test-payload.efi").is_none());
        assert!(m.get(b"x64/../usgp-test-payload.efi").is_none());
        assert!(m.get(b"").is_none());
    }

    #[test]
    fn unknown_keys_rejected_at_both_levels() {
        let top = one_file("signed = true", "");
        assert!(matches!(
            BootManifest::from_toml(&top),
            Err(ManifestError::Parse(_))
        ));
        let inner = one_file("", "mode = \"0644\"\n");
        assert!(matches!(
            BootManifest::from_toml(&inner),
            Err(ManifestError::Parse(_))
        ));
    }

    #[test]
    fn schema_version_must_be_1() {
        for v in ["0", "2", "4294967295"] {
            let text =
                one_file("", "").replace("schema_version = 1", &format!("schema_version = {v}"));
            let want: u32 = v.parse().unwrap();
            assert!(
                matches!(BootManifest::from_toml(&text), Err(ManifestError::UnsupportedSchema(got)) if got == want),
                "{v}"
            );
        }
        for v in ["-1", "4294967296", "\"1\"", "1.0"] {
            let text =
                one_file("", "").replace("schema_version = 1", &format!("schema_version = {v}"));
            assert!(
                matches!(BootManifest::from_toml(&text), Err(ManifestError::Parse(_))),
                "{v}"
            );
        }
        let missing = one_file("", "").replace("schema_version = 1\n", "");
        assert!(matches!(
            BootManifest::from_toml(&missing),
            Err(ManifestError::Parse(_))
        ));
    }

    #[test]
    fn algorithm_must_be_sha256() {
        for alg in ["sha1", "SHA256", "sha-256", "sha384", ""] {
            let text = one_file("", "").replace("\"sha256\"", &format!("\"{alg}\""));
            assert!(
                matches!(BootManifest::from_toml(&text), Err(ManifestError::Parse(_))),
                "{alg}"
            );
        }
        let missing = one_file("", "").replace("algorithm = \"sha256\"\n", "");
        assert!(matches!(
            BootManifest::from_toml(&missing),
            Err(ManifestError::Parse(_))
        ));
    }

    #[test]
    fn no_files_rejected() {
        let text = "schema_version = 1\nalgorithm = \"sha256\"\n";
        assert!(matches!(
            BootManifest::from_toml(text),
            Err(ManifestError::NoFiles)
        ));
        assert!(matches!(
            BootManifest::new(vec![]),
            Err(ManifestError::NoFiles)
        ));
    }

    #[test]
    fn file_count_limit() {
        let files: Vec<_> = (0..MAX_FILES)
            .map(|i| entry(&format!("f{i}"), 1, D1))
            .collect();
        let m = BootManifest::new(files.clone()).unwrap();
        assert_eq!(BootManifest::from_toml(&m.to_toml()).unwrap(), m);

        let mut over = files;
        over.push(entry("one-more", 1, D1));
        assert!(matches!(
            BootManifest::new(over.clone()),
            Err(ManifestError::TooManyFiles(257))
        ));
        let text = BootManifest {
            schema_version: 1,
            algorithm: DigestName::Sha256,
            files: over,
        }
        .to_toml();
        assert!(matches!(
            BootManifest::from_toml(&text),
            Err(ManifestError::TooManyFiles(257))
        ));
    }

    #[test]
    fn duplicate_names_rejected() {
        let e = BootManifest::new(vec![
            entry("a.efi", 1, D1),
            entry("b.efi", 2, D2),
            entry("a.efi", 3, D2),
        ])
        .unwrap_err();
        assert!(
            matches!(&e, ManifestError::DuplicateName(n) if n.as_str() == "a.efi"),
            "{e:?}"
        );
        // Names differing only in case are distinct (byte-for-byte matching).
        BootManifest::new(vec![entry("a.efi", 1, D1), entry("A.efi", 1, D1)]).unwrap();
    }

    #[test]
    fn size_limit_inclusive_4_gib() {
        BootManifest::new(vec![entry("a", MAX_FILE_SIZE, D1)]).unwrap();
        assert!(matches!(
            BootManifest::new(vec![entry("a", MAX_FILE_SIZE + 1, D1)]),
            Err(ManifestError::FileTooLarge { size, .. }) if size == MAX_FILE_SIZE + 1
        ));
        let neg = one_file("", "").replace("size = 1", "size = -1");
        assert!(matches!(
            BootManifest::from_toml(&neg),
            Err(ManifestError::Parse(_))
        ));
    }

    #[test]
    fn bad_names_rejected_in_manifest() {
        for name in [
            "../x",
            "/etc/passwd",
            "a/../b",
            "a\\\\b",
            "%2e%2e",
            "",
            "a//b",
        ] {
            let text = one_file("", "").replace("a.efi", name);
            assert!(
                matches!(BootManifest::from_toml(&text), Err(ManifestError::Parse(_))),
                "{name}"
            );
        }
        let long = one_file("", "").replace("a.efi", &"a".repeat(128));
        assert!(matches!(
            BootManifest::from_toml(&long),
            Err(ManifestError::Parse(_))
        ));
        let nul = one_file("", "").replace("a.efi", "a\\u0000b");
        assert!(matches!(
            BootManifest::from_toml(&nul),
            Err(ManifestError::Parse(_))
        ));
    }

    #[test]
    fn bad_digests_rejected() {
        for d in ["", "abc", "zz"] {
            let text = one_file("", "").replace(D1, d);
            assert!(
                matches!(BootManifest::from_toml(&text), Err(ManifestError::Parse(_))),
                "{d}"
            );
        }
        let short = one_file("", "").replace(D1, D1.get(1..).unwrap());
        assert!(matches!(
            BootManifest::from_toml(&short),
            Err(ManifestError::Parse(_))
        ));
        let missing = one_file("", "").replace(&format!("sha256 = \"{D1}\"\n"), "");
        assert!(matches!(
            BootManifest::from_toml(&missing),
            Err(ManifestError::Parse(_))
        ));
    }

    #[test]
    fn oversize_text_rejected_before_parse() {
        let mut text = one_file("", "");
        text.push_str(&"#".repeat(MAX_MANIFEST_BYTES));
        assert!(matches!(
            BootManifest::from_toml(&text),
            Err(ManifestError::TooLarge)
        ));
    }

    #[test]
    fn not_toml_rejected() {
        for t in [
            "",
            "\0",
            "[[file]",
            "schema_version = 1\nschema_version = 1\n",
        ] {
            assert!(BootManifest::from_toml(t).is_err(), "{t:?}");
        }
    }

    #[test]
    fn validate_catches_hand_built_bad_schema() {
        let m = BootManifest {
            schema_version: 2,
            algorithm: DigestName::Sha256,
            files: vec![entry("a", 1, D1)],
        };
        assert!(matches!(
            m.validate(),
            Err(ManifestError::UnsupportedSchema(2))
        ));
    }
}
