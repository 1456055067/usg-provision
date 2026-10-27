//! Declared and verified facts about image editions and PE kits
//! (decision 0013).
//!
//! The operator declares an edition's Windows release, edition and
//! architecture, and a PE kit's architecture and kit version. Each fact is
//! carried with its [`FactSource`]: `declared` when only the operator
//! stated it, `verified` when the file also states it, as Microsoft
//! documents, and the two agree. The source travels with the value
//! everywhere a fact is shown, stored or signed ([`Fact`]).
//!
//! The value sets are closed. Unknown text is refused, never mapped to a
//! nearby value, and nothing is inferred from edition names. There is no
//! feature-update field (REQ-OS-008).
//!
//! Which values are in scope is decided by `usgp-image::os_support`, not
//! here; these types only carry the facts.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - closed value sets;
//   strict kit version syntax.
// - NIST 800-53: AU-10 (Non-repudiation, basis) - the declared/verified
//   source is part of every stored and signed fact.
// - SPEC: specs/os-images.md#REQ-IMG-043 (items 1 to 3: declared,
//   cross-checked, marked)
// - SPEC: specs/os-support.md#REQ-OS-001, #REQ-OS-002, #REQ-OS-004,
//   #REQ-OS-007 (values that scope decisions are made on)
// - SPEC: specs/os-support.md#REQ-OS-008 (no feature-update input)
// - SPEC: specs/preinstall-env.md#REQ-PE-005 (PE architecture and kit
//   version, declared)
// - Decision 0013 (operator-declared facts, cross-checked)

use std::fmt;

closed_enum!(
    /// Windows release family of an edition.
    Release, "release" {
        /// Windows 11 (in scope for M2, REQ-OS-001).
        Windows11 => "windows-11",
        /// Windows 10 (refused in M2, REQ-OS-007).
        Windows10 => "windows-10",
        /// Any other release (refused in M2, REQ-OS-001).
        Other => "other",
    }
);

closed_enum!(
    /// Windows edition of an image.
    Edition, "edition" {
        /// Plain Enterprise (in scope for M2, REQ-OS-004).
        Enterprise => "enterprise",
        /// Enterprise LTSC (refused in M2, decision 0013 item 3).
        EnterpriseLtsc => "enterprise-ltsc",
        /// IoT Enterprise (refused in M2, decision 0013 item 3).
        IotEnterprise => "iot-enterprise",
        /// Education.
        Education => "education",
        /// Pro.
        Pro => "pro",
        /// Home.
        Home => "home",
        /// Any other edition.
        Other => "other",
    }
);

closed_enum!(
    /// Processor architecture of an edition or PE kit.
    Architecture, "architecture" {
        /// x64 (amd64; in scope for M2, REQ-OS-002, REQ-PE-005).
        X64 => "x64",
        /// 32-bit x86.
        X86 => "x86",
        /// Arm64.
        Arm64 => "arm64",
        /// 32-bit Arm.
        Arm => "arm",
    }
);

closed_enum!(
    /// Where a fact came from (decision 0013 item 2; REQ-IMG-043 item 3).
    FactSource, "fact source" {
        /// Stated only by the operator.
        Declared => "declared",
        /// Stated by the operator and by the file (as documented), and the
        /// two agree.
        Verified => "verified",
    }
);

closed_enum!(
    /// Support status of an edition or PE kit against the M2 scope
    /// (decision 0009). Computed by `usgp-image::os_support`.
    SupportState, "support status" {
        /// Within scope.
        Supported => "supported",
        /// Outside scope; a reason names the failing fact.
        NotSupported => "not_supported",
        /// Not known (no declaration); blocks readiness (REQ-OS-009).
        Unknown => "unknown",
    }
);

/// A fact value with its source. Serialized as
/// `{"value": ..., "source": "declared" | "verified"}`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fact<T> {
    /// The value.
    pub value: T,
    /// Where it came from.
    pub source: FactSource,
}

impl<T> Fact<T> {
    /// A fact stated only by the operator.
    pub const fn declared(value: T) -> Self {
        Self {
            value,
            source: FactSource::Declared,
        }
    }

    /// A fact stated by the operator and confirmed by the file.
    pub const fn verified(value: T) -> Self {
        Self {
            value,
            source: FactSource::Verified,
        }
    }
}

/// The three facts of an image edition, each with its source.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EditionFacts {
    /// Windows release.
    pub release: Fact<Release>,
    /// Windows edition.
    pub edition: Fact<Edition>,
    /// Processor architecture.
    pub architecture: Fact<Architecture>,
}

/// Highest number of dot-separated parts in a [`KitVersion`].
pub const KIT_VERSION_MAX_PARTS: usize = 4;

/// Lowest number of dot-separated parts in a [`KitVersion`].
pub const KIT_VERSION_MIN_PARTS: usize = 2;

/// Longest kit version text: four parts of five digits and three dots.
pub const KIT_VERSION_MAX_LEN: usize = 23;

/// A Windows PE kit version as declared, for example `10.1.26100.9457`.
///
/// Syntax (plan WU-4): 2 to 4 parts separated by `.`, each part 1 to 5
/// ASCII decimal digits with a value of at most 65535, and no sign or
/// spaces. A part has no leading zero unless it is `0`, so each version
/// has exactly one text form and comparisons (REQ-PE-009) are exact.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KitVersion {
    parts: [u16; KIT_VERSION_MAX_PARTS],
    len: u8,
}

/// Why a kit version was rejected. The text is never echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KitVersionError {
    /// Longer than [`KIT_VERSION_MAX_LEN`] bytes.
    #[error("kit version is {len} bytes; the limit is 23")]
    TooLong {
        /// Length in bytes.
        len: usize,
    },
    /// Not 2 to 4 parts.
    #[error("kit version must have 2 to 4 dot-separated parts")]
    PartCount,
    /// A part is empty, has a non-digit, or has a leading zero.
    #[error("kit version part {part} is not a decimal number without leading zeros")]
    BadPart {
        /// 1-based part number.
        part: usize,
    },
    /// A part is above 65535.
    #[error("kit version part {part} is above 65535")]
    PartTooLarge {
        /// 1-based part number.
        part: usize,
    },
}

impl KitVersion {
    /// Parses the text form.
    ///
    /// # Errors
    ///
    /// [`KitVersionError`] naming the first rule that failed.
    pub fn parse(text: &str) -> Result<Self, KitVersionError> {
        if text.len() > KIT_VERSION_MAX_LEN {
            return Err(KitVersionError::TooLong { len: text.len() });
        }
        let mut parts = [0u16; KIT_VERSION_MAX_PARTS];
        let mut count = 0usize;
        for (i, piece) in text.split('.').enumerate() {
            let part = i + 1;
            let slot = parts.get_mut(i).ok_or(KitVersionError::PartCount)?;
            let bytes = piece.as_bytes();
            let digits_ok = !bytes.is_empty()
                && bytes.len() <= 5
                && bytes.iter().all(u8::is_ascii_digit)
                && !(bytes.len() > 1 && bytes.first() == Some(&b'0'));
            if !digits_ok {
                return Err(KitVersionError::BadPart { part });
            }
            let value: u32 = piece
                .parse()
                .map_err(|_| KitVersionError::BadPart { part })?;
            *slot = u16::try_from(value).map_err(|_| KitVersionError::PartTooLarge { part })?;
            count = part;
        }
        if count < KIT_VERSION_MIN_PARTS {
            return Err(KitVersionError::PartCount);
        }
        let len = u8::try_from(count).map_err(|_| KitVersionError::PartCount)?;
        Ok(Self { parts, len })
    }

    /// The parts, most significant first.
    #[must_use]
    pub fn parts(&self) -> &[u16] {
        self.parts
            .get(..usize::from(self.len))
            .unwrap_or(&self.parts)
    }
}

impl fmt::Display for KitVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, p) in self.parts().iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            write!(f, "{p}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for KitVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KitVersion({self})")
    }
}

impl std::str::FromStr for KitVersion {
    type Err = KitVersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl serde::Serialize for KitVersion {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for KitVersion {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;

        impl serde::de::Visitor<'_> for V {
            type Value = KitVersion;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a kit version such as 10.1.26100.1")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<KitVersion, E> {
                KitVersion::parse(v).map_err(E::custom)
            }
        }

        d.deserialize_str(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_sets_round_trip() {
        for r in Release::ALL {
            assert_eq!(Release::parse(r.as_str()), Some(*r));
            let j = serde_json::to_string(r).unwrap();
            assert_eq!(serde_json::from_str::<Release>(&j).unwrap(), *r);
        }
        for e in Edition::ALL {
            assert_eq!(Edition::parse(e.as_str()), Some(*e));
        }
        for a in Architecture::ALL {
            assert_eq!(Architecture::parse(a.as_str()), Some(*a));
        }
        assert_eq!(Release::ALL.len(), 3);
        assert_eq!(Edition::ALL.len(), 7);
        assert_eq!(Architecture::ALL.len(), 4);
        assert_eq!(FactSource::ALL.len(), 2);
        assert_eq!(SupportState::ALL.len(), 3);
    }

    #[test]
    fn unknown_text_refused_not_mapped() {
        for bad in [
            "Windows-11",
            "windows11",
            "win11",
            " windows-11",
            "windows-11 ",
            "",
        ] {
            assert_eq!(Release::parse(bad), None, "{bad:?}");
        }
        for bad in ["Enterprise", "enterprise ltsc", "enterprisen", "ltsc"] {
            assert_eq!(Edition::parse(bad), None, "{bad:?}");
        }
        for bad in ["amd64", "X64", "x86_64", "aarch64"] {
            assert_eq!(Architecture::parse(bad), None, "{bad:?}");
        }
        assert!(serde_json::from_str::<Architecture>("\"amd64\"").is_err());
        let e = serde_json::from_str::<Edition>("\"secret\"").unwrap_err();
        assert!(!e.to_string().contains("secret"));
    }

    #[test]
    fn fact_wire_shape() {
        let f = Fact::declared(Architecture::X64);
        assert_eq!(
            serde_json::to_string(&f).unwrap(),
            r#"{"value":"x64","source":"declared"}"#
        );
        assert!(
            serde_json::from_str::<Fact<Architecture>>(
                r#"{"value":"x64","source":"declared","x":1}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<Fact<Architecture>>(r#"{"value":"x64","source":"assumed"}"#)
                .is_err()
        );
    }

    #[test]
    fn kit_version_accepts() {
        for ok in [
            "10.1.26100.9457",
            "10.0",
            "0.0",
            "65535.65535.65535.65535",
            "10.1.22621",
        ] {
            let v = KitVersion::parse(ok).unwrap();
            assert_eq!(v.to_string(), ok);
        }
        assert_eq!(
            KitVersion::parse("10.1.26100.9457").unwrap().parts(),
            &[10, 1, 26100, 9457]
        );
    }

    #[test]
    fn kit_version_refuses() {
        use KitVersionError as E;
        let cases: &[(&str, KitVersionError)] = &[
            ("10", E::PartCount),
            ("1.2.3.4.5", E::PartCount),
            ("", E::BadPart { part: 1 }),
            ("10.", E::BadPart { part: 2 }),
            (".10", E::BadPart { part: 1 }),
            ("+10.1", E::BadPart { part: 1 }),
            ("-10.1", E::BadPart { part: 1 }),
            (" 10.1", E::BadPart { part: 1 }),
            ("10.1 ", E::BadPart { part: 2 }),
            ("10.01", E::BadPart { part: 2 }),
            ("10.65536", E::PartTooLarge { part: 2 }),
            ("10.123456", E::BadPart { part: 2 }),
            ("10.1a", E::BadPart { part: 2 }),
            ("1٠.1", E::BadPart { part: 1 }),
            ("10..1", E::BadPart { part: 2 }),
            ("123456789012345678901234", E::TooLong { len: 24 }),
        ];
        for (text, want) in cases {
            assert_eq!(KitVersion::parse(text), Err(*want), "{text:?}");
        }
    }

    #[test]
    fn kit_version_order_and_serde() {
        let a = KitVersion::parse("10.1.22621.1").unwrap();
        let b = KitVersion::parse("10.1.26100.1").unwrap();
        assert!(a < b);
        assert_eq!(serde_json::to_string(&b).unwrap(), "\"10.1.26100.1\"");
        assert!(serde_json::from_str::<KitVersion>("\"10\"").is_err());
        assert!(serde_json::from_str::<KitVersion>("10.1").is_err());
    }
}
