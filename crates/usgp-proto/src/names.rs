//! Validated operator-supplied text: display names, descriptions, file
//! names, and edition indexes.
//!
//! Rules (plan WU-4; project SI-10 limits, see [`crate::limits`]):
//!
//! - [`DisplayName`]: 1 to 128 Unicode scalar values, no control
//!   characters.
//! - [`Description`]: 0 to 1024 Unicode scalar values, no control
//!   characters.
//! - [`FileName`]: 1 to 255 bytes of UTF-8; no `/`, `\`, NUL or control
//!   characters; spaces allowed (REQ-IMG-033); not `.` or `..`.
//! - [`EditionIndex`]: 1 to the image count of the file.
//! - [`WimText`]: an edition name or description read from a WIM file;
//!   0 to 1024 Unicode scalar values, any characters. It is file content,
//!   not operator input, so only its length is bounded; anything that
//!   displays it must escape control characters.
//!
//! "Control character" means a character in the Unicode general category
//! Cc (`char::is_control`): U+0000 to U+001F and U+007F to U+009F.
//!
//! Errors carry lengths and positions, never the text itself.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - length and
//   character rules on every operator-supplied name.
// - SPEC: specs/os-images.md#REQ-IMG-002 (lengths enforced, operator told;
//   limits are project values, the product limits are OPEN)
// - SPEC: specs/os-images.md#REQ-IMG-022 (refusal reason names the problem)
// - SPEC: specs/os-images.md#REQ-IMG-033 (file names with spaces)
// - SPEC: specs/os-images.md#REQ-IMG-041 (edition chosen by index)

use std::fmt;

use crate::limits::{
    MAX_DESCRIPTION_CHARS, MAX_DISPLAY_NAME_CHARS, MAX_FILE_NAME_BYTES, MAX_WIM_TEXT_CHARS,
};

/// Why a name was rejected. The text is never echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NameError {
    /// The value is empty.
    #[error("must not be empty")]
    Empty,
    /// The value is longer than the limit.
    #[error("is {len} {unit} long; the limit is {max}")]
    TooLong {
        /// Length of the input.
        len: usize,
        /// The limit.
        max: usize,
        /// `"characters"` or `"bytes"`.
        unit: &'static str,
    },
    /// A disallowed character at a character position (0-based).
    #[error("has a disallowed character at position {position}")]
    InvalidCharacter {
        /// Position in Unicode scalar values.
        position: usize,
    },
    /// `.` or `..`, which are not file names.
    #[error("must not be '.' or '..'")]
    Reserved,
}

fn check_chars(s: &str, min: usize, max: usize) -> Result<(), NameError> {
    if min > 0 && s.is_empty() {
        return Err(NameError::Empty);
    }
    let len = s.chars().count();
    if len > max {
        return Err(NameError::TooLong {
            len,
            max,
            unit: "characters",
        });
    }
    if let Some(position) = s.chars().position(char::is_control) {
        return Err(NameError::InvalidCharacter { position });
    }
    Ok(())
}

fn check_len(s: &str, max: usize) -> Result<(), NameError> {
    let len = s.chars().count();
    if len > max {
        return Err(NameError::TooLong {
            len,
            max,
            unit: "characters",
        });
    }
    Ok(())
}

fn check_file_name(s: &str) -> Result<(), NameError> {
    if s.is_empty() {
        return Err(NameError::Empty);
    }
    if s.len() > MAX_FILE_NAME_BYTES {
        return Err(NameError::TooLong {
            len: s.len(),
            max: MAX_FILE_NAME_BYTES,
            unit: "bytes",
        });
    }
    if let Some(position) = s
        .chars()
        .position(|c| c == '/' || c == '\\' || c.is_control())
    {
        return Err(NameError::InvalidCharacter { position });
    }
    if s == "." || s == ".." {
        return Err(NameError::Reserved);
    }
    Ok(())
}

macro_rules! text_type {
    ($(#[$doc:meta])* $name:ident, $check:expr, $expecting:literal) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// Validates and wraps `s`.
            ///
            /// # Errors
            ///
            /// [`NameError`] naming the rule that failed.
            pub fn new(s: impl Into<String>) -> Result<Self, NameError> {
                let s = s.into();
                let check: fn(&str) -> Result<(), NameError> = $check;
                check(&s)?;
                Ok(Self(s))
            }

            /// The value as text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// The value as an owned string.
            #[must_use]
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = NameError;

            fn try_from(s: String) -> Result<Self, Self::Error> {
                Self::new(s)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = NameError;

            fn try_from(s: &str) -> Result<Self, Self::Error> {
                Self::new(s)
            }
        }

        impl std::str::FromStr for $name {
            type Err = NameError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({:?})"), self.0)
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;

                impl serde::de::Visitor<'_> for V {
                    type Value = $name;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str($expecting)
                    }

                    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<$name, E> {
                        $name::new(v).map_err(E::custom)
                    }
                }

                d.deserialize_str(V)
            }
        }
    };
}

text_type!(
    /// A display name for an image file, PE kit or package: 1 to 128
    /// Unicode scalar values, no control characters.
    DisplayName,
    |s| check_chars(s, 1, MAX_DISPLAY_NAME_CHARS),
    "a display name (1-128 characters, no control characters)"
);

text_type!(
    /// A package description: 0 to 1024 Unicode scalar values, no control
    /// characters.
    Description,
    |s| check_chars(s, 0, MAX_DESCRIPTION_CHARS),
    "a description (up to 1024 characters, no control characters)"
);

text_type!(
    /// The name of an uploaded file, kept for display and download. It is
    /// never used to build a storage path (content is stored by digest,
    /// plan section 1.1). 1 to 255 bytes of UTF-8; no `/`, `\`, NUL or
    /// control characters; spaces allowed (REQ-IMG-033); not `.` or `..`.
    FileName,
    check_file_name,
    "a file name (1-255 bytes, no '/', '\\\\', NUL or control characters)"
);

text_type!(
    /// An edition name or description as recorded in a WIM file's XML
    /// (`specs/standards/wim.md` §7; REQ-IMG-040): up to 1024 Unicode
    /// scalar values (`WimLimits::max_name_chars`). Not validated beyond
    /// length; displays must escape it.
    WimText,
    |s| check_len(s, MAX_WIM_TEXT_CHARS),
    "WIM edition text (up to 1024 characters)"
);

/// A 1-based edition (image) index within a WIM file
/// (`specs/standards/wim.md` §7; REQ-IMG-041). Zero is never an edition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(transparent)]
pub struct EditionIndex(u32);

/// An edition index outside `1..=image_count`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("edition index {index} is out of range; the file has {image_count} editions")]
pub struct EditionIndexError {
    /// The requested index.
    pub index: u64,
    /// Number of editions in the file (0 when the count is not known yet).
    pub image_count: u32,
}

impl EditionIndex {
    /// An index of at least 1, not yet checked against a file.
    ///
    /// # Errors
    ///
    /// [`EditionIndexError`] for 0 or a value above `u32::MAX`.
    pub fn new(index: u64) -> Result<Self, EditionIndexError> {
        match u32::try_from(index) {
            Ok(i) if i >= 1 => Ok(Self(i)),
            _ => Err(EditionIndexError {
                index,
                image_count: 0,
            }),
        }
    }

    /// Checks the index against the number of editions in a file.
    ///
    /// # Errors
    ///
    /// [`EditionIndexError`] if the index is above `image_count`.
    pub fn check(self, image_count: u32) -> Result<Self, EditionIndexError> {
        if self.0 <= image_count {
            Ok(self)
        } else {
            Err(EditionIndexError {
                index: u64::from(self.0),
                image_count,
            })
        }
    }

    /// The index value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl<'de> serde::Deserialize<'de> for EditionIndex {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = u64::deserialize(d)?;
        Self::new(v).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_name_limits() {
        assert_eq!(DisplayName::new(""), Err(NameError::Empty));
        assert!(DisplayName::new("a").is_ok());
        assert!(DisplayName::new("Windows 11 Enterprise x64 (24H2)").is_ok());
        assert!(DisplayName::new("é".repeat(128)).is_ok());
        assert_eq!(
            DisplayName::new("é".repeat(129)),
            Err(NameError::TooLong {
                len: 129,
                max: 128,
                unit: "characters"
            })
        );
        // Multi-byte characters count once each.
        assert!(DisplayName::new("\u{1F600}".repeat(128)).is_ok());
        for (s, position) in [("a\nb", 1), ("\u{7f}", 0), ("ab\u{85}", 2), ("\0", 0)] {
            assert_eq!(
                DisplayName::new(s),
                Err(NameError::InvalidCharacter { position }),
                "{s:?}"
            );
        }
    }

    #[test]
    fn description_limits() {
        assert!(Description::new("").is_ok());
        assert!(Description::new("x".repeat(1024)).is_ok());
        assert!(matches!(
            Description::new("x".repeat(1025)),
            Err(NameError::TooLong { len: 1025, .. })
        ));
        assert_eq!(
            Description::new("a\tb"),
            Err(NameError::InvalidCharacter { position: 1 })
        );
    }

    #[test]
    fn file_name_rules() {
        // REQ-IMG-033: spaces are allowed and kept exactly.
        let n = FileName::new("Windows 11 install.wim").unwrap();
        assert_eq!(n.as_str(), "Windows 11 install.wim");
        assert!(FileName::new(" leading and trailing ").is_ok());
        assert!(FileName::new("ünïcode.wim").is_ok());
        assert!(FileName::new("a".repeat(255)).is_ok());
        assert!(FileName::new("..wim").is_ok());
        assert_eq!(
            FileName::new("a".repeat(256)),
            Err(NameError::TooLong {
                len: 256,
                max: 255,
                unit: "bytes"
            })
        );
        // 128 two-byte characters = 256 bytes.
        assert!(matches!(
            FileName::new("é".repeat(128)),
            Err(NameError::TooLong { len: 256, .. })
        ));
        assert_eq!(FileName::new(""), Err(NameError::Empty));
        for (s, position) in [
            ("a/b", 1),
            ("a\\b", 1),
            ("a\0b", 1),
            ("\u{1b}[31m", 0),
            ("x\u{9f}", 1),
        ] {
            assert_eq!(
                FileName::new(s),
                Err(NameError::InvalidCharacter { position }),
                "{s:?}"
            );
        }
        assert_eq!(FileName::new("."), Err(NameError::Reserved));
        assert_eq!(FileName::new(".."), Err(NameError::Reserved));
    }

    #[test]
    fn serde_validates() {
        let n: FileName = serde_json::from_str("\"my image.wim\"").unwrap();
        assert_eq!(serde_json::to_string(&n).unwrap(), "\"my image.wim\"");
        assert!(serde_json::from_str::<FileName>("\"a/b\"").is_err());
        assert!(serde_json::from_str::<DisplayName>("\"\"").is_err());
        assert!(serde_json::from_str::<DisplayName>("5").is_err());
    }

    #[test]
    fn errors_never_echo_text() {
        let e = DisplayName::new(format!("secret{}", "x".repeat(200))).unwrap_err();
        assert!(!e.to_string().contains("secret"));
        let e = FileName::new("secret/name").unwrap_err();
        assert!(!e.to_string().contains("secret"));
    }

    #[test]
    fn wim_text_bounds_length_only() {
        assert!(WimText::new("").is_ok());
        assert!(WimText::new("Windows 11 Enterprise\n\t").is_ok());
        assert!(WimText::new("x".repeat(1024)).is_ok());
        assert!(matches!(
            WimText::new("x".repeat(1025)),
            Err(NameError::TooLong { len: 1025, .. })
        ));
    }

    #[test]
    fn edition_index() {
        assert!(EditionIndex::new(0).is_err());
        assert!(EditionIndex::new(u64::from(u32::MAX) + 1).is_err());
        let i = EditionIndex::new(12).unwrap();
        assert_eq!(i.get(), 12);
        assert!(i.check(12).is_ok());
        assert_eq!(
            i.check(11),
            Err(EditionIndexError {
                index: 12,
                image_count: 11
            })
        );
        assert!(serde_json::from_str::<EditionIndex>("0").is_err());
        assert!(serde_json::from_str::<EditionIndex>("-1").is_err());
        assert_eq!(serde_json::from_str::<EditionIndex>("3").unwrap().get(), 3);
    }
}
