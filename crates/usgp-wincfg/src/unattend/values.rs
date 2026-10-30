//! Package and device value checks (plan section 1.6, "Value validation").

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), CM-6
//   (Configuration Settings)
// - SPEC: specs/configuration.md#REQ-CFG-005 (computer name),
//   #REQ-CFG-006 (domain and OU carried unchanged), #REQ-CFG-007 (time
//   zone, free text), #REQ-CFG-009 (tags)
// - SPEC: specs/standards/unattend.md §3.1, §3.2
// - RFC 1123 §2.1 - host name labels (letters, digits, hyphen)

use thiserror::Error;

use super::parse::is_xml_char;

/// Longest computer name, in bytes (`unattend.md` §3.1).
pub const MAX_COMPUTER_NAME_BYTES: usize = 15;
/// Longest time zone, in characters (`unattend.md` §3.2).
pub const MAX_TIME_ZONE_CHARS: usize = 256;
/// Longest domain or OU, in characters (plan section 1.6).
pub const MAX_CARRIED_CHARS: usize = 2048;
/// Most tags (plan section 1.6).
pub const MAX_TAGS: usize = 64;
/// Longest tag, in characters (plan section 1.6).
pub const MAX_TAG_CHARS: usize = 128;

/// Why a value was refused. Carries no part of the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ValueError {
    /// Empty.
    #[error("value is empty")]
    Empty,
    /// Over the length limit.
    #[error("value is too long")]
    TooLong,
    /// `*` (a random name): refused, the name must be deterministic.
    #[error("a random computer name is not allowed")]
    Random,
    /// A character not allowed in this value.
    #[error("value contains a character that is not allowed")]
    ForbiddenCharacter,
    /// A computer name made only of digits.
    #[error("computer name is all digits")]
    AllDigits,
    /// A computer name starting or ending with a hyphen.
    #[error("computer name starts or ends with a hyphen")]
    HyphenAtEnd,
    /// More tags than [`MAX_TAGS`].
    #[error("too many tags")]
    TooManyTags,
}

/// Checks a computer name (`unattend.md` §3.1).
///
/// 1 to 15 bytes; a DNS label (RFC 1123 letters, digits and hyphen, no
/// hyphen at either end), which excludes every character §3.1 lists as
/// forbidden; not all digits; `*` refused.
///
/// # Errors
///
/// The first failed rule.
pub fn check_computer_name(name: &str) -> Result<(), ValueError> {
    if name.is_empty() {
        return Err(ValueError::Empty);
    }
    if name == "*" {
        return Err(ValueError::Random);
    }
    if name.len() > MAX_COMPUTER_NAME_BYTES {
        return Err(ValueError::TooLong);
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(ValueError::ForbiddenCharacter);
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(ValueError::HyphenAtEnd);
    }
    if name.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ValueError::AllDigits);
    }
    Ok(())
}

fn printable(s: &str) -> bool {
    s.chars().all(|c| !c.is_control() && is_xml_char(c))
}

/// Checks a time zone: 1 to 256 printable characters, free text
/// (REQ-CFG-007; no list check, OPEN-CFG-3).
///
/// # Errors
///
/// The first failed rule.
pub fn check_time_zone(tz: &str) -> Result<(), ValueError> {
    if tz.is_empty() {
        return Err(ValueError::Empty);
    }
    if tz.chars().count() > MAX_TIME_ZONE_CHARS {
        return Err(ValueError::TooLong);
    }
    if !printable(tz) {
        return Err(ValueError::ForbiddenCharacter);
    }
    Ok(())
}

/// Checks a value carried unchanged (domain, OU, other device values):
/// non-empty, at most 2,048 characters, only characters XML can carry.
///
/// # Errors
///
/// The first failed rule.
pub fn check_carried(v: &str) -> Result<(), ValueError> {
    if v.is_empty() {
        return Err(ValueError::Empty);
    }
    if v.chars().count() > MAX_CARRIED_CHARS {
        return Err(ValueError::TooLong);
    }
    if !v.chars().all(is_xml_char) {
        return Err(ValueError::ForbiddenCharacter);
    }
    Ok(())
}

/// Checks tags: at most 64, each 1 to 128 printable characters
/// (REQ-CFG-009).
///
/// # Errors
///
/// The first failed rule.
pub fn check_tags<S: AsRef<str>>(tags: &[S]) -> Result<(), ValueError> {
    if tags.len() > MAX_TAGS {
        return Err(ValueError::TooManyTags);
    }
    for t in tags {
        let t = t.as_ref();
        if t.is_empty() {
            return Err(ValueError::Empty);
        }
        if t.chars().count() > MAX_TAG_CHARS {
            return Err(ValueError::TooLong);
        }
        if !printable(t) {
            return Err(ValueError::ForbiddenCharacter);
        }
    }
    Ok(())
}

/// The check for a reference name's value at render.
pub(crate) fn check_for(name: &str, v: &str) -> Result<(), ValueError> {
    match name {
        "computer_name" | "device.computer_name" => check_computer_name(v),
        "time_zone" => check_time_zone(v),
        _ => check_carried(v),
    }
}
