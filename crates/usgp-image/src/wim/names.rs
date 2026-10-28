//! Names, short names and stream names of metadata entries, and the
//! validated path types the apply sink receives.
//!
//! Every name is one path component (OBS-041): it is decoded strictly from
//! UTF-16LE and checked so that joining components under a sink root can
//! never leave that root. The types here can only be built through these
//! checks, so a sink never sees an unchecked component.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - strict decoding;
//   separators, NUL, `.` and `..` refused (path traversal).
// - SPEC: specs/standards/wim.md §6, §6.1 "Names and short names"
// - SPEC: specs/preinstall-env.md#REQ-PE-017 (apply of the chosen image)

use std::fmt;

use super::metadata::MetadataError;

/// Most UTF-16 units of a short name.
// FORMAT: OBS-028 - short names seen were at most 12 characters
// (`EXPLICIT.TXT`, `LONGFI~1.TXT`); M-05: longer ones are refused.
pub const MAX_SHORT_NAME_UNITS: usize = 12;

/// Which kind of name is being checked (for the refusal text only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NameKind {
    /// An entry's long name.
    Long,
    /// An entry's short name.
    Short,
    /// A named stream's name.
    Stream,
}

impl NameKind {
    fn error(self, what: &'static str) -> MetadataError {
        match self {
            Self::Long => MetadataError::Name { what },
            Self::Short => MetadataError::ShortName { what },
            Self::Stream => MetadataError::StreamName { what },
        }
    }
}

/// Decodes `bytes` (UTF-16LE, no terminator) strictly.
///
/// # Errors
///
/// An odd length, or an unpaired surrogate (M-04).
// FORMAT: OBS-027 - names are UTF-16LE; characters outside the BMP are
// surrogate pairs.
pub(crate) fn decode_utf16le(bytes: &[u8], kind: NameKind) -> Result<String, MetadataError> {
    let (units, rest) = bytes.as_chunks::<2>();
    if !rest.is_empty() {
        return Err(kind.error("odd length"));
    }
    char::decode_utf16(units.iter().map(|u| u16::from_le_bytes(*u)))
        .collect::<Result<String, _>>()
        .map_err(|_| kind.error("unpaired surrogate"))
}

/// Checks one decoded component: not empty, not `.` or `..`, and free of
/// `\`, `/`, `:` and NUL (M-04).
pub(crate) fn check_component(s: &str, kind: NameKind) -> Result<(), MetadataError> {
    if s.is_empty() {
        return Err(kind.error("empty"));
    }
    if s == "." || s == ".." {
        return Err(kind.error("dot component"));
    }
    if s.chars().any(|c| matches!(c, '\\' | '/' | ':' | '\0')) {
        return Err(kind.error("reserved character"));
    }
    Ok(())
}

/// The key two sibling names (or two stream names of one entry) must not
/// share: Windows file systems compare names without case, so names equal
/// after lower-casing would collide on the target.
// FORMAT: derived, unconfirmed - the target file system's exact
// case-folding table is not in our sources; Unicode lower-casing is used
// as an approximation, which refuses at least every pair that folds equal
// under it (fail closed for those; OBS-042 compared folding only on the
// names in our samples).
pub(crate) fn fold_key(s: &str) -> String {
    s.to_lowercase()
}

/// One validated path component (an entry's long name).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Component(String);

impl Component {
    /// Checks `s` as an entry name (M-04).
    ///
    /// # Errors
    ///
    /// [`MetadataError::Name`] if `s` is empty, `.`, `..`, or contains
    /// `\`, `/`, `:` or NUL.
    pub fn new(s: &str) -> Result<Self, MetadataError> {
        check_component(s, NameKind::Long)?;
        Ok(Self(s.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Component {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

/// A path below the apply root, as validated components. The empty path
/// is the root itself.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ImagePath(Vec<Component>);

impl ImagePath {
    /// The root.
    #[must_use]
    pub fn root() -> Self {
        Self(Vec::new())
    }

    /// This path with `c` appended.
    #[must_use]
    pub fn join(&self, c: Component) -> Self {
        let mut v = Vec::with_capacity(self.0.len().saturating_add(1));
        v.extend(self.0.iter().cloned());
        v.push(c);
        Self(v)
    }

    /// Builds a path from `\`-separated text (tests and tools). Each
    /// component is checked as a name.
    ///
    /// # Errors
    ///
    /// As [`Component::new`] for any component.
    pub fn parse(text: &str) -> Result<Self, MetadataError> {
        if text.is_empty() {
            return Ok(Self::root());
        }
        text.split('\\')
            .map(Component::new)
            .collect::<Result<Vec<_>, _>>()
            .map(Self)
    }

    /// The components, root first.
    #[must_use]
    pub fn components(&self) -> &[Component] {
        &self.0
    }

    /// True for the root.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// The components joined by `\` (empty for the root).
    #[must_use]
    pub fn to_text(&self) -> String {
        let parts: Vec<&str> = self.0.iter().map(Component::as_str).collect();
        parts.join("\\")
    }
}

impl fmt::Debug for ImagePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ImagePath({:?})", self.to_text())
    }
}

/// A validated named-stream name (never empty: the unnamed stream is
/// `None` wherever a stream is optional).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamName(String);

impl StreamName {
    /// Checks `s` as a stream name (M-04 rules, applied to stream names).
    ///
    /// # Errors
    ///
    /// [`MetadataError::StreamName`] on the same rules as entry names.
    pub fn new(s: &str) -> Result<Self, MetadataError> {
        check_component(s, NameKind::Stream)?;
        Ok(Self(s.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for StreamName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

/// A validated short name (M-05).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShortName(String);

impl ShortName {
    /// Checks `s` as a short name: a valid component of at most
    /// [`MAX_SHORT_NAME_UNITS`] UTF-16 units.
    ///
    /// # Errors
    ///
    /// [`MetadataError::ShortName`].
    pub fn new(s: &str) -> Result<Self, MetadataError> {
        check_component(s, NameKind::Short)?;
        if s.encode_utf16().count() > MAX_SHORT_NAME_UNITS {
            return Err(MetadataError::ShortName {
                what: "longer than 12 characters",
            });
        }
        Ok(Self(s.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ShortName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn decodes_supplementary_and_refuses_unpaired() {
        // OBS-027: U+10400 as a surrogate pair.
        let b = [0x01, 0xd8, 0x00, 0xdc, b'-', 0];
        assert_eq!(
            decode_utf16le(&b, NameKind::Long).ok().as_deref(),
            Some("\u{10400}-")
        );
        assert!(decode_utf16le(&[0x01, 0xd8], NameKind::Long).is_err());
        assert!(decode_utf16le(&[0x00, 0xdc, b'a', 0], NameKind::Long).is_err());
        assert!(decode_utf16le(b"a", NameKind::Long).is_err());
        assert_eq!(
            decode_utf16le(&utf16("é日本"), NameKind::Long)
                .ok()
                .as_deref(),
            Some("é日本")
        );
    }

    #[test]
    fn component_rules() {
        for bad in ["", ".", "..", "a\\b", "a/b", "a:b", "a\0b"] {
            assert!(Component::new(bad).is_err(), "{bad:?}");
            assert!(StreamName::new(bad).is_err(), "{bad:?}");
        }
        for good in ["a", "...", ".x", "x.", " sp ace", "\u{10400}"] {
            assert!(Component::new(good).is_ok(), "{good:?}");
        }
    }

    #[test]
    fn short_name_length() {
        assert!(ShortName::new("EXPLICIT.TXT").is_ok());
        assert!(ShortName::new("EXPLICIT.TXTX").is_err());
        assert!(ShortName::new("A:B").is_err());
    }

    #[test]
    fn paths() {
        let p = ImagePath::parse("a\\b").unwrap_or_default();
        assert_eq!(p.components().len(), 2);
        assert_eq!(p.to_text(), "a\\b");
        assert!(ImagePath::parse("a\\..").is_err());
        assert!(ImagePath::parse("").is_ok_and(|p| p.is_root()));
    }
}
