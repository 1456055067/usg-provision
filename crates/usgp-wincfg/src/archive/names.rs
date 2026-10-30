//! Entry-name rules shared by the ZIP and CAB readers (plan §1.5 "Names").
//!
//! Stored names are untrusted. A name is accepted only if every segment can
//! be created as an ordinary file or folder below the extraction folder on
//! Windows, without escaping it. Anything else refuses the whole archive.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation)
// - SPEC: specs/drivers.md#REQ-DRV-009
// - PKWARE APPNOTE §4.4.17.1 - relative paths, forward slashes
//   (specs/standards/zip-cab.md §A.5, §A.6, §B.8)

use std::collections::HashMap;
use std::fmt;

use super::{ArchiveError, ArchiveLimits};

/// A validated relative path: one or more segments joined by `/`.
///
/// Every segment has passed the name rules, so joining it below a fixed
/// staging folder cannot leave that folder.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RelPath(String);

impl RelPath {
    /// The path with `/` separators.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The path segments, outermost first.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0.split('/')
    }

    /// The last segment.
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or(&self.0)
    }

    /// The parent folder, or `None` at the top level.
    #[must_use]
    pub fn parent(&self) -> Option<RelPath> {
        self.0.rsplit_once('/').map(|(p, _)| RelPath(p.to_owned()))
    }

    /// The case-folded form used for duplicate detection (Windows file
    /// names are case-insensitive).
    #[must_use]
    pub(crate) fn folded(&self) -> String {
        fold(&self.0)
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Case folding for name comparison.
pub(crate) fn fold(s: &str) -> String {
    s.chars().flat_map(char::to_uppercase).collect()
}

/// Which separator rules apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flavor {
    /// ZIP: `/` only; `\` is refused (APPNOTE §4.4.17.1).
    Zip,
    /// CAB: `\` is also a separator (plan §1.5, CAB names only).
    Cab,
}

/// Validates a decoded entry name. Returns the path and whether the entry
/// is a directory (ZIP only: a trailing `/`).
pub(crate) fn validate(
    raw: &str,
    flavor: Flavor,
    lim: &ArchiveLimits,
) -> Result<(RelPath, bool), ArchiveError> {
    let bad = |reason: &'static str| ArchiveError::BadName { reason };
    if raw.len() > lim.max_name_bytes {
        return Err(bad("name_too_long"));
    }
    let owned;
    let mut name = match flavor {
        Flavor::Zip => {
            if raw.contains('\\') {
                return Err(bad("backslash"));
            }
            raw
        }
        Flavor::Cab => {
            owned = raw.replace('\\', "/");
            owned.as_str()
        }
    };
    if name.is_empty() {
        return Err(bad("empty"));
    }
    if name.starts_with('/') {
        return Err(bad("absolute"));
    }
    let mut is_dir = false;
    if let Some(stripped) = name.strip_suffix('/') {
        if flavor == Flavor::Cab {
            return Err(bad("empty_segment"));
        }
        is_dir = true;
        name = stripped;
    }
    let mut depth = 0usize;
    for seg in name.split('/') {
        depth = depth.saturating_add(1);
        check_segment(seg)?;
    }
    if depth > lim.max_depth {
        return Err(bad("too_deep"));
    }
    Ok((RelPath(name.to_owned()), is_dir))
}

/// Windows device names, refused with or without an extension.
const DEVICES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM0", "COM1", "COM2", "COM3", "COM4",
    "COM5", "COM6", "COM7", "COM8", "COM9", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6",
    "LPT7", "LPT8", "LPT9",
];

/// One path segment (also used for a catalog name inside an INF).
pub(crate) fn check_segment(seg: &str) -> Result<(), ArchiveError> {
    let bad = |reason: &'static str| ArchiveError::BadName { reason };
    if seg.is_empty() {
        return Err(bad("empty_segment"));
    }
    if seg == "." || seg == ".." {
        return Err(bad("dot_segment"));
    }
    for c in seg.chars() {
        if c.is_control() {
            return Err(bad("control_char"));
        }
        // `:` is in the plan's list; the others cannot be created on
        // Windows either, so they are refused as well (fail closed).
        if matches!(c, ':' | '\\' | '<' | '>' | '"' | '|' | '?' | '*') {
            return Err(bad("reserved_char"));
        }
    }
    if seg.ends_with('.') || seg.ends_with(' ') {
        return Err(bad("trailing_dot_or_space"));
    }
    if seg.encode_utf16().count() > 255 {
        return Err(bad("segment_too_long"));
    }
    let stem = seg.split('.').next().unwrap_or(seg).trim_end_matches(' ');
    let stem = fold(stem);
    if DEVICES.iter().any(|d| *d == stem) {
        return Err(bad("device_name"));
    }
    Ok(())
}

/// Kind of a recorded name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
}

/// All names of one archive, case-folded, for duplicate and conflict checks.
#[derive(Debug, Default)]
pub(crate) struct NameSet {
    names: HashMap<String, Kind>,
}

impl NameSet {
    /// Records an explicit entry. The same name twice (after case folding)
    /// is refused, except a directory repeated as a directory.
    pub(crate) fn insert(&mut self, path: &RelPath, is_dir: bool) -> Result<(), ArchiveError> {
        let kind = if is_dir { Kind::Dir } else { Kind::File };
        match self.names.insert(path.folded(), kind) {
            None => Ok(()),
            Some(_) => Err(ArchiveError::DuplicateName),
        }
    }

    /// After all entries are inserted: no file may also be used as a folder
    /// by another entry's path.
    pub(crate) fn check_conflicts(&self) -> Result<(), ArchiveError> {
        for key in self.names.keys() {
            let mut prefix = key.as_str();
            while let Some((p, _)) = prefix.rsplit_once('/') {
                if self.names.get(p) == Some(&Kind::File) {
                    return Err(ArchiveError::PathConflict);
                }
                prefix = p;
            }
        }
        Ok(())
    }

    /// Whether a file with this exact (folded) path exists.
    pub(crate) fn has_file(&self, folded: &str) -> bool {
        self.names.get(folded) == Some(&Kind::File)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> (String, bool) {
        let (p, d) = validate(s, Flavor::Zip, &ArchiveLimits::default()).unwrap();
        (p.as_str().to_owned(), d)
    }

    #[test]
    fn accepts_plain_names() {
        assert_eq!(ok("a/b.inf"), ("a/b.inf".into(), false));
        assert_eq!(ok("dir/"), ("dir".into(), true));
        assert_eq!(ok("x86/net.sys"), ("x86/net.sys".into(), false));
        let (p, _) = validate("a\\b.cat", Flavor::Cab, &ArchiveLimits::default()).unwrap();
        assert_eq!(p.as_str(), "a/b.cat");
    }

    #[test]
    fn traversal_set_refused() {
        let lim = ArchiveLimits::default();
        for bad in [
            "",
            "/etc/x",
            "../x",
            "a/../x",
            "a/./x",
            "a//x",
            "a\\x",
            "C:/x",
            "C:x",
            "a/x\0",
            "a/\u{1}x",
            "con",
            "CON.txt",
            "a/lpt1.inf",
            "Nul .x",
            "a.",
            "a ",
            "a/b./c",
            "a?b",
            "/",
        ] {
            assert!(validate(bad, Flavor::Zip, &lim).is_err(), "{bad:?}");
        }
        for bad in ["..\\x", "\\x", "a\\\\b", "x\\"] {
            assert!(validate(bad, Flavor::Cab, &lim).is_err(), "{bad:?}");
        }
        let long = "a".repeat(256);
        assert!(validate(&long, Flavor::Zip, &lim).is_err());
        let deep = vec!["d"; 33].join("/");
        assert!(validate(&deep, Flavor::Zip, &lim).is_err());
        let ok_deep = vec!["d"; 32].join("/");
        assert!(validate(&ok_deep, Flavor::Zip, &lim).is_ok());
        let huge = "a/".repeat(600);
        assert!(validate(&huge, Flavor::Zip, &lim).is_err());
    }

    #[test]
    fn duplicates_and_conflicts() {
        let lim = ArchiveLimits::default();
        let p = |s| validate(s, Flavor::Zip, &lim).unwrap().0;
        let mut set = NameSet::default();
        set.insert(&p("A/b.inf"), false).unwrap();
        assert!(matches!(
            set.insert(&p("a/B.INF"), false),
            Err(ArchiveError::DuplicateName)
        ));
        let mut set = NameSet::default();
        set.insert(&p("a"), false).unwrap();
        set.insert(&p("a/b"), false).unwrap();
        assert!(matches!(
            set.check_conflicts(),
            Err(ArchiveError::PathConflict)
        ));
    }
}
