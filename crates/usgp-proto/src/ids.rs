//! Identifiers and timestamps used on the M2 API and in signed manifests.
//!
//! Identifiers are UUIDs (RFC 9562) in their 36-character hyphenated text
//! form. They are built from random bytes that the caller draws from the
//! `usgp-crypto` DRBG ([`ContentId::from_random_bytes`]); this crate never
//! generates randomness itself (plan section 4, `uuid` row).
//!
//! Timestamps are [`UnixMicros`]: microseconds since the Unix epoch, UTC,
//! as a JSON integer (the audit chain uses the same unit, plan section 5.6).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - only the canonical
//   36-character form is accepted; the nil UUID is refused; error text
//   never echoes the input.
// - NIST 800-53: AU-8 (Time Stamps) - UTC microseconds.
// - RFC 9562 §4, §5.4 - UUID text form and version 4 layout.

use std::fmt;

/// Length of the hyphenated UUID text form.
pub const UUID_TEXT_LEN: usize = 36;

/// Why an identifier was rejected. The input is never echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IdError {
    /// The text is not exactly 36 bytes.
    #[error("identifier must be 36 characters (hyphenated UUID), got {len}")]
    BadLength {
        /// Length of the input in bytes.
        len: usize,
    },
    /// The text is not a hyphenated UUID.
    #[error("identifier is not a hyphenated UUID")]
    BadFormat,
    /// The nil UUID is never issued.
    #[error("identifier must not be the nil UUID")]
    Nil,
}

fn parse_uuid(text: &str) -> Result<uuid::Uuid, IdError> {
    if text.len() != UUID_TEXT_LEN {
        return Err(IdError::BadLength { len: text.len() });
    }
    // With exactly 36 bytes, `try_parse` accepts only the hyphenated form.
    let u = uuid::Uuid::try_parse(text).map_err(|_| IdError::BadFormat)?;
    if u.is_nil() {
        return Err(IdError::Nil);
    }
    Ok(u)
}

macro_rules! uuid_id {
    ($(#[$doc:meta])* $name:ident, $label:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(uuid::Uuid);

        impl $name {
            /// A version-4 layout identifier from 16 bytes the caller drew
            /// from the `usgp-crypto` DRBG (RFC 9562 §5.4: the version and
            /// variant bits are set; the other 122 bits are the input).
            #[must_use]
            pub const fn from_random_bytes(bytes: [u8; 16]) -> Self {
                Self(uuid::Builder::from_random_bytes(bytes).into_uuid())
            }

            /// Parses the 36-character hyphenated form (either case).
            ///
            /// # Errors
            ///
            /// [`IdError`] for a wrong length, a bad format or the nil UUID.
            pub fn parse(text: &str) -> Result<Self, IdError> {
                parse_uuid(text).map(Self)
            }

            /// The 16 bytes (for database columns).
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }

            /// Rebuilds an identifier from stored bytes.
            ///
            /// # Errors
            ///
            /// [`IdError::Nil`] for 16 zero bytes.
            pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, IdError> {
                let u = uuid::Uuid::from_bytes(bytes);
                if u.is_nil() {
                    return Err(IdError::Nil);
                }
                Ok(Self(u))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0.hyphenated(), f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($label, "({})"), self.0.hyphenated())
            }
        }

        impl std::str::FromStr for $name {
            type Err = IdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(&self.0.hyphenated())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                struct V;

                impl serde::de::Visitor<'_> for V {
                    type Value = $name;

                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str("a hyphenated UUID")
                    }

                    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<$name, E> {
                        $name::parse(v).map_err(E::custom)
                    }
                }

                d.deserialize_str(V)
            }
        }
    };
}

uuid_id!(
    /// An uploaded content item (image file or PE kit).
    ContentId,
    "ContentId"
);
uuid_id!(
    /// An upload session.
    UploadId,
    "UploadId"
);
uuid_id!(
    /// A deployment package.
    PackageId,
    "PackageId"
);
uuid_id!(
    /// An enrolled operator.
    OperatorId,
    "OperatorId"
);

/// A UTC timestamp in microseconds since the Unix epoch (JSON integer).
/// Negative values are refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(transparent)]
pub struct UnixMicros(i64);

/// A negative timestamp was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("timestamp must not be before the Unix epoch")]
pub struct NegativeTimestamp;

impl UnixMicros {
    /// A timestamp from microseconds since the epoch.
    ///
    /// # Errors
    ///
    /// [`NegativeTimestamp`] if `us < 0`.
    pub const fn new(us: i64) -> Result<Self, NegativeTimestamp> {
        if us < 0 {
            return Err(NegativeTimestamp);
        }
        Ok(Self(us))
    }

    /// Microseconds since the epoch.
    #[must_use]
    pub const fn as_micros(self) -> i64 {
        self.0
    }
}

impl<'de> serde::Deserialize<'de> for UnixMicros {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = i64::deserialize(d)?;
        Self::new(v).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f";

    #[test]
    fn parses_hyphenated_and_round_trips() {
        let id = ContentId::parse(GOOD).unwrap();
        assert_eq!(id.to_string(), GOOD);
        let upper = ContentId::parse(&GOOD.to_ascii_uppercase()).unwrap();
        assert_eq!(upper, id);
        assert_eq!(ContentId::from_bytes(*id.as_bytes()).unwrap(), id);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{GOOD}\""));
        assert_eq!(serde_json::from_str::<ContentId>(&json).unwrap(), id);
    }

    #[test]
    fn refuses_other_forms() {
        let simple = GOOD.replace('-', "");
        assert_eq!(
            PackageId::parse(&simple),
            Err(IdError::BadLength { len: 32 })
        );
        let braced = format!("{{{GOOD}}}");
        assert_eq!(
            PackageId::parse(&braced),
            Err(IdError::BadLength { len: 38 })
        );
        let urn = format!("urn:uuid:{GOOD}");
        assert!(PackageId::parse(&urn).is_err());
        assert_eq!(
            PackageId::parse("0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6g"),
            Err(IdError::BadFormat)
        );
        assert_eq!(
            PackageId::parse("0b7c2f4e+9a1d-4c3b-8e6f-1a2b3c4d5e6f"),
            Err(IdError::BadFormat)
        );
        assert_eq!(
            PackageId::parse("00000000-0000-0000-0000-000000000000"),
            Err(IdError::Nil)
        );
        assert_eq!(OperatorId::from_bytes([0; 16]), Err(IdError::Nil));
        assert!(serde_json::from_str::<UploadId>("5").is_err());
    }

    #[test]
    fn from_random_bytes_sets_v4_layout() {
        let id = UploadId::from_random_bytes([0xff; 16]);
        let text = id.to_string();
        // Version nibble 4, variant 10xx.
        assert_eq!(text.as_bytes().get(14), Some(&b'4'));
        assert_eq!(text.as_bytes().get(19), Some(&b'b'));
        let zero = UploadId::from_random_bytes([0; 16]);
        assert_eq!(zero.to_string(), "00000000-0000-4000-8000-000000000000");
    }

    #[test]
    fn error_never_echoes_input() {
        let e = ContentId::parse("secret-secret-secret-secret-secret-x").unwrap_err();
        assert!(!e.to_string().contains("secret"));
    }

    #[test]
    fn timestamps() {
        assert_eq!(UnixMicros::new(-1), Err(NegativeTimestamp));
        let t = UnixMicros::new(1_793_000_000_000_000).unwrap();
        assert_eq!(serde_json::to_string(&t).unwrap(), "1793000000000000");
        assert!(serde_json::from_str::<UnixMicros>("-5").is_err());
        assert!(serde_json::from_str::<UnixMicros>("1.5").is_err());
        assert_eq!(
            serde_json::from_str::<UnixMicros>("0").unwrap().as_micros(),
            0
        );
    }
}
