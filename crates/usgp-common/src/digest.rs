//! SHA-256 digest value type.
//!
//! This is a plain value: 32 bytes with a hex text form. It computes
//! nothing. Every digest is produced by `usgp-crypto` (decision 0001), and
//! this type only carries and compares results.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   carrier for the manifest digests checked before serving.
// - NIST 800-53: SI-10 (Information Input Validation) - strict hex parsing
//   (exactly 64 hex digits).
// - FIPS 180-4 §6.2 - SHA-256 output is 256 bits.

use std::fmt;

/// Length of a SHA-256 digest in bytes (FIPS 180-4).
pub const SHA256_LEN: usize = 32;

/// Length of the hex text form of a SHA-256 digest.
pub const SHA256_HEX_LEN: usize = SHA256_LEN * 2;

/// A SHA-256 digest.
///
/// Text form: 64 hex digits. [`Sha256Digest::from_hex`] accepts either
/// case; [`Sha256Digest::to_hex`], `Display` and serde output lowercase.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Digest(pub [u8; SHA256_LEN]);

/// Why a hex digest string was rejected.
///
/// The error never echoes the input text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DigestParseError {
    /// The text is not exactly 64 characters (bytes).
    #[error("SHA-256 hex digest must be exactly 64 characters, got {len}")]
    BadLength {
        /// Length of the input in bytes.
        len: usize,
    },
    /// A byte is not an ASCII hex digit.
    #[error("SHA-256 hex digest has a non-hex character at offset {offset}")]
    BadCharacter {
        /// Byte offset of the first bad character.
        offset: usize,
    },
}

impl Sha256Digest {
    /// Parses exactly 64 hex digits (upper or lower case).
    ///
    /// # Errors
    ///
    /// [`DigestParseError::BadLength`] if the input is not 64 bytes, and
    /// [`DigestParseError::BadCharacter`] for any non-hex byte (including a
    /// sign, whitespace, or a `0x` prefix).
    pub fn from_hex(text: &str) -> Result<Self, DigestParseError> {
        let bytes = text.as_bytes();
        if bytes.len() != SHA256_HEX_LEN {
            return Err(DigestParseError::BadLength { len: bytes.len() });
        }
        let mut out = [0u8; SHA256_LEN];
        let (pairs, _) = bytes.as_chunks::<2>();
        for (i, (slot, &[hi, lo])) in out.iter_mut().zip(pairs).enumerate() {
            let hi = hex_value(hi).ok_or(DigestParseError::BadCharacter { offset: i * 2 })?;
            let lo = hex_value(lo).ok_or(DigestParseError::BadCharacter { offset: i * 2 + 1 })?;
            *slot = (hi << 4) | lo;
        }
        Ok(Self(out))
    }

    /// Lowercase hex text form (64 characters).
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(SHA256_HEX_LEN);
        for b in self.0 {
            s.push(hex_digit(b >> 4));
            s.push(hex_digit(b & 0x0f));
        }
        s
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SHA256_LEN] {
        &self.0
    }
}

/// Lowercase hex digit for a nibble (`n` is always below 16 here).
fn hex_digit(n: u8) -> char {
    char::from_digit(u32::from(n), 16).unwrap_or('0')
}

fn hex_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A digest of public boot content is not a secret.
        write!(f, "Sha256Digest({})", self.to_hex())
    }
}

impl std::str::FromStr for Sha256Digest {
    type Err = DigestParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl serde::Serialize for Sha256Digest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> serde::Deserialize<'de> for Sha256Digest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct HexVisitor;

        impl serde::de::Visitor<'_> for HexVisitor {
            type Value = Sha256Digest;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string of exactly 64 hex digits")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Sha256Digest::from_hex(v).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(HexVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn hex_round_trip_lowercase() {
        let d = Sha256Digest::from_hex(ABC).unwrap();
        assert_eq!(d.0[0], 0xba);
        assert_eq!(d.0[31], 0xad);
        assert_eq!(d.to_hex(), ABC);
        assert_eq!(d.to_string(), ABC);
    }

    #[test]
    fn uppercase_accepted_output_lowercase() {
        let d = Sha256Digest::from_hex(&ABC.to_ascii_uppercase()).unwrap();
        assert_eq!(d.to_hex(), ABC);
    }

    #[test]
    fn mixed_case_accepted() {
        let mixed = "BA7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015AD";
        assert_eq!(Sha256Digest::from_hex(mixed).unwrap().to_hex(), ABC);
    }

    #[test]
    fn bad_lengths_rejected() {
        for len in [0usize, 1, 62, 63, 65, 66, 128] {
            let s = "a".repeat(len);
            assert_eq!(
                Sha256Digest::from_hex(&s),
                Err(DigestParseError::BadLength { len }),
                "len {len}"
            );
        }
    }

    #[test]
    fn multibyte_utf8_counted_in_bytes() {
        // 62 ASCII + one 2-byte character = 64 bytes but not hex.
        let s = format!("{}é", "a".repeat(62));
        assert_eq!(s.len(), 64);
        assert_eq!(
            Sha256Digest::from_hex(&s),
            Err(DigestParseError::BadCharacter { offset: 62 })
        );
        // 63 ASCII + 2-byte character = 65 bytes.
        let s = format!("{}é", "a".repeat(63));
        assert_eq!(
            Sha256Digest::from_hex(&s),
            Err(DigestParseError::BadLength { len: 65 })
        );
    }

    #[test]
    fn bad_characters_rejected_with_offset() {
        for (offset, bad) in [(0usize, 'g'), (10, ' '), (33, '-'), (63, 'z'), (5, '+')] {
            let mut s: Vec<char> = ABC.chars().collect();
            if let Some(c) = s.get_mut(offset) {
                *c = bad;
            }
            let s: String = s.into_iter().collect();
            assert_eq!(
                Sha256Digest::from_hex(&s),
                Err(DigestParseError::BadCharacter { offset }),
                "{bad:?} at {offset}"
            );
        }
    }

    #[test]
    fn prefix_and_whitespace_rejected() {
        let prefixed = format!("0x{}", ABC.get(2..).unwrap());
        assert!(Sha256Digest::from_hex(&prefixed).is_err());
        let padded = format!(" {}", ABC.get(1..).unwrap());
        assert!(Sha256Digest::from_hex(&padded).is_err());
    }

    #[test]
    fn error_does_not_echo_input() {
        let secretish = "s".repeat(64);
        let msg = Sha256Digest::from_hex(&secretish).unwrap_err().to_string();
        assert!(!msg.contains("ssss"), "{msg}");
    }

    #[test]
    fn serde_round_trip_through_toml() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Wrap {
            sha256: Sha256Digest,
        }
        let w: Wrap =
            toml::from_str(&format!("sha256 = \"{}\"", ABC.to_ascii_uppercase())).unwrap();
        assert_eq!(w.sha256.to_hex(), ABC);
        let text = toml::to_string(&w).unwrap();
        assert_eq!(text.trim(), format!("sha256 = \"{ABC}\""));
        assert!(toml::from_str::<Wrap>("sha256 = \"abc\"").is_err());
        assert!(toml::from_str::<Wrap>("sha256 = 5").is_err());
    }

    #[test]
    fn debug_shows_hex() {
        let d = Sha256Digest([0u8; 32]);
        assert_eq!(
            format!("{d:?}"),
            format!("Sha256Digest({})", "0".repeat(64))
        );
    }
}
