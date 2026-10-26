//! Published boot file names.
//!
//! A [`BootFileName`] is the only form in which a boot file is named: in
//! the manifest, in the DHCP `file` field, and when matching a TFTP read
//! request. Matching is byte for byte; a request is never used to build a
//! path (plan section 1.1, Names).
//!
//! Rules (plan section 3.3, our design):
//!
//! - 1 to 127 bytes, so the name fits the 128-octet BOOTP `file` field with
//!   its terminating NUL (RFC 2131 §2, `file` field).
//! - Only ASCII `A-Z a-z 0-9 . _ -` and `/`.
//! - No leading `/`, no empty component (so no `//` and no trailing `/`),
//!   and no `.` or `..` component.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - allow-list of bytes
//   and components; everything else rejected.
// - NIST 800-53: AC-3 (Access Enforcement) - only manifest names can be
//   served; traversal names cannot be represented.
// - SPEC: specs/boot-network.md#REQ-BOOT-041
// - RFC 2131 §2 - `file` field is 128 octets, null terminated.

use std::fmt;

/// Longest allowed name in bytes (128-octet `file` field minus its NUL).
pub const MAX_BOOT_FILE_NAME_LEN: usize = 127;

/// A validated boot file name.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BootFileName(String);

/// Why a name was rejected. Variants carry positions, never the name, so
/// an untrusted request name cannot reach a log through this error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BootFileNameError {
    /// The name is empty.
    #[error("boot file name is empty")]
    Empty,
    /// The name is longer than [`MAX_BOOT_FILE_NAME_LEN`] bytes.
    #[error("boot file name is {len} bytes; the limit is 127")]
    TooLong {
        /// Length in bytes.
        len: usize,
    },
    /// A byte outside the allowed set.
    #[error("boot file name has a disallowed byte at offset {offset}")]
    InvalidByte {
        /// Offset of the first disallowed byte.
        offset: usize,
    },
    /// The name starts with `/`.
    #[error("boot file name must not start with '/'")]
    LeadingSlash,
    /// An empty path component (`//` or a trailing `/`).
    #[error("boot file name has an empty path component")]
    EmptyComponent,
    /// A `.` or `..` component.
    #[error("boot file name has a '.' or '..' component")]
    DotComponent,
}

fn allowed(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/')
}

fn validate(bytes: &[u8]) -> Result<(), BootFileNameError> {
    if bytes.is_empty() {
        return Err(BootFileNameError::Empty);
    }
    if bytes.len() > MAX_BOOT_FILE_NAME_LEN {
        return Err(BootFileNameError::TooLong { len: bytes.len() });
    }
    if let Some(offset) = bytes.iter().position(|&b| !allowed(b)) {
        return Err(BootFileNameError::InvalidByte { offset });
    }
    if bytes.first() == Some(&b'/') {
        return Err(BootFileNameError::LeadingSlash);
    }
    for component in bytes.split(|&b| b == b'/') {
        match component {
            [] => return Err(BootFileNameError::EmptyComponent),
            b"." | b".." => return Err(BootFileNameError::DotComponent),
            _ => {}
        }
    }
    Ok(())
}

impl BootFileName {
    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The name as bytes (for byte-for-byte request matching).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl TryFrom<&[u8]> for BootFileName {
    type Error = BootFileNameError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        validate(bytes)?;
        // All bytes are ASCII after validation, so this cannot fail.
        std::str::from_utf8(bytes)
            .map(|s| Self(s.to_owned()))
            .map_err(|e| BootFileNameError::InvalidByte {
                offset: e.valid_up_to(),
            })
    }
}

impl TryFrom<&str> for BootFileName {
    type Error = BootFileNameError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        validate(s.as_bytes())?;
        Ok(Self(s.to_owned()))
    }
}

impl TryFrom<String> for BootFileName {
    type Error = BootFileNameError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        validate(s.as_bytes())?;
        Ok(Self(s))
    }
}

impl std::str::FromStr for BootFileName {
    type Err = BootFileNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl AsRef<str> for BootFileName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BootFileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for BootFileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BootFileName({:?})", self.0)
    }
}

impl serde::Serialize for BootFileName {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for BootFileName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NameVisitor;

        impl serde::de::Visitor<'_> for NameVisitor {
            type Value = BootFileName;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a boot file name (1-127 bytes of A-Z a-z 0-9 . _ - /)")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                BootFileName::try_from(v).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(NameVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) {
        let n = BootFileName::try_from(s).unwrap_or_else(|e| panic!("{s:?} rejected: {e}"));
        assert_eq!(n.as_str(), s);
        assert_eq!(n.as_bytes(), s.as_bytes());
        assert_eq!(BootFileName::try_from(s.as_bytes()).unwrap(), n);
    }

    fn bad(s: &[u8], want: BootFileNameError) {
        assert_eq!(BootFileName::try_from(s), Err(want), "{s:?}");
        if let Ok(text) = std::str::from_utf8(s) {
            assert_eq!(BootFileName::try_from(text), Err(want), "{text:?}");
        }
    }

    #[test]
    fn accepts_allowed_names() {
        ok("usgp-test-payload.efi");
        ok("a");
        ok("x64/boot_x64.efi");
        ok("A/b/C/d-1.2_3");
        ok(".hidden"); // a component that merely starts with '.'
        ok("...");
        ok("a..b");
        ok("dir/..x");
        ok(&"a".repeat(127));
    }

    #[test]
    fn length_limits() {
        bad(b"", BootFileNameError::Empty);
        bad(
            "a".repeat(128).as_bytes(),
            BootFileNameError::TooLong { len: 128 },
        );
        bad(
            "a".repeat(4096).as_bytes(),
            BootFileNameError::TooLong { len: 4096 },
        );
    }

    #[test]
    fn rejects_disallowed_bytes() {
        for (name, offset) in [
            (b"a\\b".as_slice(), 1usize),
            (b"\\x", 0),
            (b"a\0b", 1),
            (b"%2e%2e", 0),
            (b"a b", 1),
            (b"a:b", 1),
            (b"a~", 1),
            (b"a*", 1),
            (b"a\n", 1),
            (b"\x7f", 0),
            (b"a\x80", 1),
            (b"\xff", 0),
            ("caf\u{e9}".as_bytes(), 3),
            (b"C:\\boot", 1),
        ] {
            bad(name, BootFileNameError::InvalidByte { offset });
        }
    }

    #[test]
    fn rejects_traversal_and_bad_components() {
        bad(b"/etc/passwd", BootFileNameError::LeadingSlash);
        bad(b"/", BootFileNameError::LeadingSlash);
        bad(b"../x", BootFileNameError::DotComponent);
        bad(b"a/../b", BootFileNameError::DotComponent);
        bad(b"a/..", BootFileNameError::DotComponent);
        bad(b"..", BootFileNameError::DotComponent);
        bad(b".", BootFileNameError::DotComponent);
        bad(b"./a", BootFileNameError::DotComponent);
        bad(b"a/./b", BootFileNameError::DotComponent);
        bad(b"a//b", BootFileNameError::EmptyComponent);
        bad(b"a/", BootFileNameError::EmptyComponent);
    }

    #[test]
    fn error_text_never_contains_name() {
        let e = BootFileName::try_from("secret name").unwrap_err();
        assert!(!e.to_string().contains("secret"));
    }

    #[test]
    fn byte_matching_is_exact() {
        let n = BootFileName::try_from("Boot.efi").unwrap();
        assert_ne!(n.as_bytes(), b"boot.efi");
        assert_eq!(n.as_bytes(), b"Boot.efi");
    }
}
