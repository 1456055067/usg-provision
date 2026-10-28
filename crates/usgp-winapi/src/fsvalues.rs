//! Pure value rules for the file-system writer ([`crate::fs`]): which
//! attribute bits are set, FILETIME conversion, and the component check.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation)
// - SPEC: specs/preinstall-env.md REQ-PE-017

use std::time::{Duration, SystemTime};

/// 100-ns intervals from 1601-01-01 to 1970-01-01 (11644473600 s).
const FILETIME_UNIX_OFFSET: u64 = 11_644_473_600 * 10_000_000;

/// A FILETIME (100-ns intervals since 1601-01-01 UTC) as a
/// [`SystemTime`], exactly (whole 100-ns steps), if representable.
#[must_use]
pub fn filetime_to_system_time(ft: u64) -> Option<SystemTime> {
    let nanos = |d: u64| d.checked_mul(100).map(Duration::from_nanos);
    if ft >= FILETIME_UNIX_OFFSET {
        SystemTime::UNIX_EPOCH.checked_add(nanos(ft - FILETIME_UNIX_OFFSET)?)
    } else {
        SystemTime::UNIX_EPOCH.checked_sub(nanos(FILETIME_UNIX_OFFSET - ft)?)
    }
}

/// What to send in a basic-information set for the stored attribute
/// value (topic 23 §22): only the `settable` bits; never 0 to mean "clear
/// all", because 0 means "unchanged".
///
/// - Some settable bits wanted: send exactly them.
/// - None wanted, a file: send `normal` (valid alone, clears the others).
/// - None wanted, a directory that has none set: nothing to send.
/// - None wanted, a directory that has some set: `Err`, because a
///   directory never gets `normal` and 0 would leave them (fail closed).
pub fn attributes_to_send(
    current: u32,
    stored: u32,
    is_dir: bool,
    settable: u32,
    normal: u32,
) -> Result<Option<u32>, &'static str> {
    let want = stored & settable;
    if want != 0 {
        return Ok(Some(want));
    }
    if !is_dir {
        return Ok(Some(normal));
    }
    if current & settable == 0 {
        Ok(None)
    } else {
        Err("directory attributes cannot be cleared to none")
    }
}

/// A path component or stream name safe to join under the writer's root:
/// non-empty, not `.` or `..`, and free of separators, colons and NUL.
/// `usgp-image` already validates names; this is a second, local check.
#[must_use]
pub fn is_safe_component(c: &str) -> bool {
    !c.is_empty() && c != "." && c != ".." && !c.contains(['\\', '/', ':', '\0'])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_round_trip_is_exact() {
        for ft in [1u64, 3, FILETIME_UNIX_OFFSET, 133_170_048_001_234_567] {
            let t = filetime_to_system_time(ft).expect("representable");
            let back = match t.duration_since(SystemTime::UNIX_EPOCH) {
                Ok(d) => FILETIME_UNIX_OFFSET + u64::try_from(d.as_nanos() / 100).unwrap_or(0),
                Err(e) => {
                    FILETIME_UNIX_OFFSET - u64::try_from(e.duration().as_nanos() / 100).unwrap_or(0)
                }
            };
            assert_eq!(back, ft);
        }
    }

    #[test]
    fn attribute_rules() {
        let settable = 0x0001 | 0x0002 | 0x0004 | 0x0020 | 0x2000;
        // Sparse/compressed/directory bits in the stored value are not sent.
        assert_eq!(
            attributes_to_send(0x20, 0x01 | 0x200, false, settable, 0x80),
            Ok(Some(0x01))
        );
        assert_eq!(
            attributes_to_send(0x10, 0x16, true, settable, 0x80),
            Ok(Some(0x06))
        );
        // Files with nothing settable get NORMAL, never 0.
        assert_eq!(
            attributes_to_send(0x20, 0x800, false, settable, 0x80),
            Ok(Some(0x80))
        );
        // Directories never get NORMAL.
        assert_eq!(
            attributes_to_send(0x10, 0x10, true, settable, 0x80),
            Ok(None)
        );
        assert!(attributes_to_send(0x12, 0x10, true, settable, 0x80).is_err());
        for (c, st, d) in [(0x20, 0, false), (0x10, 0x10, true), (0x16, 0x2, true)] {
            assert_ne!(attributes_to_send(c, st, d, settable, 0x80), Ok(Some(0)));
        }
    }

    #[test]
    fn components() {
        for ok in ["a", "a b", "\u{10400}.txt", "x.y.z"] {
            assert!(is_safe_component(ok));
        }
        for bad in ["", ".", "..", "a\\b", "a/b", "a:b", "a\0"] {
            assert!(!is_safe_component(bad), "{bad:?}");
        }
    }
}
