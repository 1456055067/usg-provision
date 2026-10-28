//! Validated volume names and drive letters.
//!
//! Strings passed to the volume and mount-point functions are checked
//! here first, so that a malformed or unexpected name never reaches the
//! API (`windows-storage-firmware-api.md` §8: volume GUID paths have the
//! form `\\?\Volume{GUID}\` and mount points end in a backslash).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation)
// - SPEC: specs/standards/windows-storage-firmware-api.md §8

use core::fmt;

const VOLUME_PREFIX: &str = "\\\\?\\Volume{";
const VOLUME_SUFFIX: &str = "}\\";
/// `\\?\Volume{` + 36 GUID characters + `}\`.
const VOLUME_PATH_LEN: usize = VOLUME_PREFIX.len() + 36 + VOLUME_SUFFIX.len();

/// A volume GUID path, `\\?\Volume{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\`,
/// with its trailing backslash (spec §8).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VolumeGuidPath(String);

impl VolumeGuidPath {
    /// Accepts exactly the volume GUID path form; anything else is `None`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        if s.len() != VOLUME_PATH_LEN {
            return None;
        }
        let guid = s.strip_prefix(VOLUME_PREFIX)?.strip_suffix(VOLUME_SUFFIX)?;
        let ok = guid.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        });
        (ok && guid.len() == 36).then(|| Self(s.to_owned()))
    }

    /// The path with its trailing backslash, as the volume and mount-point
    /// functions take it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The path without its trailing backslash: opening this names the
    /// volume device rather than its root directory (spec §8).
    #[must_use]
    pub fn device_path(&self) -> &str {
        self.0.strip_suffix('\\').unwrap_or(&self.0)
    }
}

impl fmt::Display for VolumeGuidPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A drive letter `A` to `Z`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DriveLetter(char);

impl DriveLetter {
    /// The Windows PE system drive letter. The plan never assigns or
    /// removes it (plan §1.2(c) step 3).
    pub const PE_SYSTEM: DriveLetter = DriveLetter('X');

    /// Accepts `A`-`Z` (either case); stores upper case.
    #[must_use]
    pub fn new(c: char) -> Option<Self> {
        let u = c.to_ascii_uppercase();
        u.is_ascii_uppercase().then_some(Self(u))
    }

    /// The letter, upper case.
    #[must_use]
    pub fn letter(self) -> char {
        self.0
    }

    /// The mount-point form `L:\` (spec §8: mount points end in a backslash).
    #[must_use]
    pub fn root(self) -> String {
        format!("{}:\\", self.0)
    }

    /// Parses a mount point returned by Windows (`L:\`) back into a letter.
    #[must_use]
    pub fn from_root(s: &str) -> Option<Self> {
        let mut it = s.chars();
        match (it.next(), it.next(), it.next(), it.next()) {
            (Some(c), Some(':'), Some('\\'), None) => Self::new(c),
            _ => None,
        }
    }
}

impl fmt::Display for DriveLetter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "\\\\?\\Volume{3f2a9c1e-0b7d-11ef-9a01-806e6f6e6963}\\";

    #[test]
    fn volume_path_accepts_only_the_guid_form() {
        let v = VolumeGuidPath::parse(GOOD);
        assert_eq!(v.as_ref().map(VolumeGuidPath::as_str), Some(GOOD));
        assert_eq!(
            v.as_ref().map(VolumeGuidPath::device_path),
            Some("\\\\?\\Volume{3f2a9c1e-0b7d-11ef-9a01-806e6f6e6963}")
        );
        for bad in [
            "",
            "\\\\?\\Volume{3f2a9c1e-0b7d-11ef-9a01-806e6f6e6963}",
            "\\\\.\\Volume{3f2a9c1e-0b7d-11ef-9a01-806e6f6e6963}\\",
            "\\\\?\\Volume{3f2a9c1e-0b7d-11ef-9a01-806e6f6e696}\\x",
            "\\\\?\\Volume{3f2a9c1e00b7d-11ef-9a01-806e6f6e6963}\\",
            "\\\\?\\Volume{3f2a9c1g-0b7d-11ef-9a01-806e6f6e6963}\\",
            "\\\\?\\Volume{3f2a9c1e-0b7d-11ef-9a01-806e6f6e696\u{e9}}\\",
            "C:\\",
        ] {
            assert_eq!(VolumeGuidPath::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn drive_letters() {
        assert_eq!(
            DriveLetter::new('c').map(DriveLetter::root),
            Some("C:\\".into())
        );
        assert_eq!(DriveLetter::new('1'), None);
        assert_eq!(DriveLetter::new('\u{c4}'), None);
        assert_eq!(DriveLetter::from_root("d:\\"), DriveLetter::new('D'));
        assert_eq!(DriveLetter::from_root("D:"), None);
        assert_eq!(DriveLetter::from_root("D:\\x\\"), None);
        assert_eq!(DriveLetter::new('x'), Some(DriveLetter::PE_SYSTEM));
    }
}

/// One entry of a file's data-stream list, as the stream enumeration
/// returns its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEntry {
    /// The unnamed (main) data stream, `::$DATA`.
    Unnamed,
    /// A named data stream, `:name:$DATA`, with its name.
    Named(String),
}

impl StreamEntry {
    /// Parses `:name:$DATA` or `::$DATA`. Any other form (another stream
    /// type, an empty or colon-containing name) is `None`, and callers
    /// treat it as an error rather than skipping it.
    ///
    /// SR-3: the name form is not summarised in topic 23; it is the form
    /// the stream enumeration returns, to be confirmed by the spec request.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let inner = raw.strip_prefix(':')?.strip_suffix(":$DATA")?;
        if inner.is_empty() {
            return Some(Self::Unnamed);
        }
        (!inner.contains(':') && !inner.contains('\0')).then(|| Self::Named(inner.to_owned()))
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;

    #[test]
    fn stream_names() {
        assert_eq!(StreamEntry::parse("::$DATA"), Some(StreamEntry::Unnamed));
        assert_eq!(
            StreamEntry::parse(":Zone.Identifier:$DATA"),
            Some(StreamEntry::Named("Zone.Identifier".into()))
        );
        for bad in [
            "",
            ":",
            "::$INDEX_ALLOCATION",
            "x:$DATA",
            ":a:b:$DATA",
            ":a:$data",
        ] {
            assert_eq!(StreamEntry::parse(bad), None, "{bad:?}");
        }
    }
}
