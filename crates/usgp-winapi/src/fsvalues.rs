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

// Attribute values from topic 23 §22 (the "File Attribute Constants" and
// `SetFileAttributes` pages). Plain numbers so the rules below are pure
// and tested on every target.
/// `FILE_ATTRIBUTE_READONLY`.
pub const ATTR_READONLY: u32 = 0x0001;
/// `FILE_ATTRIBUTE_HIDDEN`.
pub const ATTR_HIDDEN: u32 = 0x0002;
/// `FILE_ATTRIBUTE_SYSTEM`.
pub const ATTR_SYSTEM: u32 = 0x0004;
/// `FILE_ATTRIBUTE_DIRECTORY` (structural; never set).
pub const ATTR_DIRECTORY: u32 = 0x0010;
/// `FILE_ATTRIBUTE_ARCHIVE`.
pub const ATTR_ARCHIVE: u32 = 0x0020;
/// `FILE_ATTRIBUTE_DEVICE` (reserved for the system).
pub const ATTR_DEVICE: u32 = 0x0040;
/// `FILE_ATTRIBUTE_NORMAL` (valid only alone).
pub const ATTR_NORMAL: u32 = 0x0080;
/// `FILE_ATTRIBUTE_TEMPORARY`.
pub const ATTR_TEMPORARY: u32 = 0x0100;
/// `FILE_ATTRIBUTE_SPARSE_FILE` (set by `FSCTL_SET_SPARSE`).
pub const ATTR_SPARSE: u32 = 0x0200;
/// `FILE_ATTRIBUTE_REPARSE_POINT` (structural; `FSCTL_SET_REPARSE_POINT`).
pub const ATTR_REPARSE_POINT: u32 = 0x0400;
/// `FILE_ATTRIBUTE_COMPRESSED` (set by `FSCTL_SET_COMPRESSION`).
pub const ATTR_COMPRESSED: u32 = 0x0800;
/// `FILE_ATTRIBUTE_OFFLINE`.
pub const ATTR_OFFLINE: u32 = 0x1000;
/// `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED`.
pub const ATTR_NOT_CONTENT_INDEXED: u32 = 0x2000;
/// `FILE_ATTRIBUTE_ENCRYPTED` (created encrypted or `EncryptFile`).
pub const ATTR_ENCRYPTED: u32 = 0x4000;
/// `FILE_ATTRIBUTE_VIRTUAL` (reserved for the system).
pub const ATTR_VIRTUAL: u32 = 0x0001_0000;

/// The bits written through a basic-information set: the `SetFileAttributes`
/// settable list of topic 23 §22 without `NORMAL`, which is valid only
/// alone and is handled by [`attributes_to_send`].
pub const SETTABLE: u32 = ATTR_READONLY
    | ATTR_HIDDEN
    | ATTR_SYSTEM
    | ATTR_ARCHIVE
    | ATTR_TEMPORARY
    | ATTR_OFFLINE
    | ATTR_NOT_CONTENT_INDEXED;

/// Bits already realised by how the item was created (a directory) or by
/// the reparse set (§24); dropped silently from the attribute write.
pub const STRUCTURAL: u32 = ATTR_DIRECTORY | ATTR_REPARSE_POINT;

/// Bits set by other means this writer does not implement, dropped from
/// the write. The content itself is hash-verified and written in full;
/// only the on-disk storage form differs.
// POAM: sparse and NTFS-compressed storage (FSCTL_SET_SPARSE,
// FSCTL_SET_COMPRESSION, topic 23 §22) are not reproduced; such files are
// written as ordinary files with verified content.
pub const DROPPED_OTHER_MEANS: u32 = ATTR_SPARSE | ATTR_COMPRESSED;

/// What to send in a basic-information set for the stored attribute
/// value (topic 23 §22). Pure, so the rules are tested on every target.
///
/// - `DEVICE`, `VIRTUAL` (system-reserved), `ENCRYPTED` (not implemented;
///   the apply engine refuses it first, decision 0006) and any bit §22
///   does not name: `Err` (fail closed).
/// - `DIRECTORY`, `REPARSE_POINT`: never sent (structural).
/// - `SPARSE`, `COMPRESSED`: never sent ([`DROPPED_OTHER_MEANS`]).
/// - Some [`SETTABLE`] bits wanted: send exactly them.
/// - None wanted, a file: send `NORMAL` (valid alone, clears the others).
/// - None wanted, a directory that has none set: nothing to send (0 means
///   "unchanged"; `NORMAL` is never sent to a directory, OPEN-WAPI-12).
/// - None wanted, a directory whose only extra settable bit is
///   `ARCHIVE` (a named-stream write sets it): nothing to send, the bit is
///   tolerated ([`tolerated_dir_extra`]).
/// - None wanted, a directory with any other settable bit set: `Err`,
///   because a directory never gets `NORMAL` and 0 would leave them (fail
///   closed).
///
/// Never returns `Some(0)` and never a value with a non-settable bit.
// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity),
//   SI-10 (Information Input Validation)
// - SPEC: specs/standards/windows-storage-firmware-api.md §22
//   (OPEN-WAPI-11: only the settable set is ever sent, so whether the
//   call accepts other bits is never relied on; OPEN-WAPI-12)
pub fn attributes_to_send(
    current: u32,
    stored: u32,
    is_dir: bool,
) -> Result<Option<u32>, &'static str> {
    if stored & (ATTR_DEVICE | ATTR_VIRTUAL) != 0 {
        return Err("system-reserved attribute bit");
    }
    if stored & ATTR_ENCRYPTED != 0 {
        return Err("encrypted attribute not supported");
    }
    let named = SETTABLE | ATTR_NORMAL | STRUCTURAL | DROPPED_OTHER_MEANS;
    if stored & !named != 0 {
        return Err("unknown attribute bit");
    }
    let want = stored & SETTABLE;
    if want != 0 {
        return Ok(Some(want));
    }
    if !is_dir {
        return Ok(Some(ATTR_NORMAL));
    }
    if tolerated_dir_extra(current, stored, is_dir) == current & SETTABLE {
        Ok(None)
    } else {
        Err("directory attributes cannot be cleared to none")
    }
}

/// The settable bits a read-back may find on an applied item beyond the
/// stored ones: `ARCHIVE` on a directory whose stored settable bits are
/// empty, when `current` has it set; zero in every other case. The only
/// tolerated attribute difference (round 6, owner decision).
// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7, SI-10
// - SPEC: specs/standards/windows-storage-firmware-api.md §22 (topic 23;
//   OPEN-WAPI-11: CI run 40962201434 showed a named-stream write set
//   ARCHIVE on a directory stored with no settable bit; OPEN-WAPI-12:
//   `NORMAL` on a directory is undocumented and not relied on, although
//   CI run 40974183608's probe saw it clear ARCHIVE; POAM-61)
// POAM: directory ARCHIVE left set when the image stores no settable bits
// and a named-stream write set it; OPEN-WAPI-12; harmless metadata
// difference, content hash-verified
#[must_use]
pub fn tolerated_dir_extra(current: u32, stored: u32, is_dir: bool) -> u32 {
    if is_dir && stored & SETTABLE == 0 {
        current & ATTR_ARCHIVE
    } else {
        0
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
        // Sparse/compressed/directory/reparse bits are not sent.
        assert_eq!(
            attributes_to_send(0x20, 0x01 | 0x200, false),
            Ok(Some(0x01))
        );
        assert_eq!(attributes_to_send(0x10, 0x16, true), Ok(Some(0x06)));
        assert_eq!(attributes_to_send(0x410, 0x412, true), Ok(Some(0x02)));
        // The CI tree's hidden directory sends HIDDEN only.
        assert_eq!(
            attributes_to_send(ATTR_DIRECTORY, ATTR_DIRECTORY | ATTR_HIDDEN, true),
            Ok(Some(ATTR_HIDDEN))
        );
        // Temporary and offline are settable.
        assert_eq!(attributes_to_send(0, 0x1100, false), Ok(Some(0x1100)));
        // Files with nothing settable get NORMAL, never 0.
        assert_eq!(attributes_to_send(0x20, 0x800, false), Ok(Some(0x80)));
        assert_eq!(attributes_to_send(0x20, 0x80, false), Ok(Some(0x80)));
        // Directories never get NORMAL; masked 0 stays "unchanged".
        assert_eq!(attributes_to_send(0x10, 0x10, true), Ok(None));
        assert_eq!(attributes_to_send(0x10, 0x90, true), Ok(None));
        assert!(attributes_to_send(0x12, 0x10, true).is_err());
        // OPEN-WAPI-11 (CI run 40962201434): ARCHIVE alone set on a
        // directory stored with no settable bit is tolerated, no call.
        assert_eq!(attributes_to_send(0x30, 0x10, true), Ok(None));
        assert_eq!(attributes_to_send(0x30, 0x90, true), Ok(None));
        assert_eq!(attributes_to_send(0x30, 0x810, true), Ok(None));
        // Any other extra bit, alone or with ARCHIVE, stays refused.
        assert!(attributes_to_send(0x32, 0x10, true).is_err());
        assert!(attributes_to_send(0x11, 0x10, true).is_err());
        assert!(attributes_to_send(0x2010, 0x10, true).is_err());
        // Files are unchanged: NORMAL whatever is set.
        assert_eq!(attributes_to_send(0x20, 0, false), Ok(Some(0x80)));
        // The tolerance applies only to that case.
        assert_eq!(tolerated_dir_extra(0x30, 0x10, true), ATTR_ARCHIVE);
        assert_eq!(tolerated_dir_extra(0x32, 0x10, true), ATTR_ARCHIVE);
        assert_eq!(tolerated_dir_extra(0x10, 0x10, true), 0);
        assert_eq!(tolerated_dir_extra(0x32, 0x12, true), 0);
        assert_eq!(tolerated_dir_extra(0x20, 0, false), 0);
        // Refused: reserved, encrypted, unnamed bits.
        for bad in [
            ATTR_DEVICE,
            ATTR_VIRTUAL,
            ATTR_ENCRYPTED,
            0x0002_0000,
            0x8000,
        ] {
            assert!(
                attributes_to_send(0, bad | ATTR_ARCHIVE, false).is_err(),
                "{bad:#x}"
            );
            assert!(
                attributes_to_send(0x10, bad | 0x10, true).is_err(),
                "{bad:#x}"
            );
        }
    }

    #[test]
    fn attribute_output_is_settable_and_never_zero() {
        let normal_ok = |v: u32, d: bool| !d && v == ATTR_NORMAL;
        for stored in 0u32..0x0004_0000 {
            for (current, d) in [
                (0, false),
                (0x10, true),
                (0x12, true),
                (0x30, true),
                (0x32, true),
                (0x20, false),
            ] {
                if let Ok(Some(v)) = attributes_to_send(current, stored, d) {
                    assert_ne!(v, 0);
                    assert!(
                        v & !SETTABLE == 0 || normal_ok(v, d),
                        "{stored:#x} -> {v:#x}"
                    );
                }
            }
        }
    }

    /// Every directory `current` (settable bits and the directory bit)
    /// against stored values with and without settable bits: no call only
    /// when the stored settable bits are empty and the extra bits are none
    /// or exactly `ARCHIVE`; files never get `None`.
    #[test]
    fn directory_tolerance_is_exactly_archive() {
        let mut currents = Vec::new();
        let mut c = 0u32;
        loop {
            currents.push(c | ATTR_DIRECTORY);
            // Next subset of SETTABLE.
            c = (c.wrapping_sub(SETTABLE)) & SETTABLE;
            if c == 0 {
                break;
            }
        }
        for current in currents {
            for stored in [
                ATTR_DIRECTORY,
                ATTR_DIRECTORY | ATTR_NORMAL,
                0x810,
                0x12,
                0x30,
            ] {
                let r = attributes_to_send(current, stored, true);
                let extra = current & SETTABLE & !stored;
                if stored & SETTABLE != 0 {
                    assert_eq!(r, Ok(Some(stored & SETTABLE)), "{current:#x} {stored:#x}");
                } else if extra == 0 || extra == ATTR_ARCHIVE {
                    assert_eq!(r, Ok(None), "{current:#x} {stored:#x}");
                } else {
                    assert!(r.is_err(), "{current:#x} {stored:#x}");
                }
                let file =
                    attributes_to_send(current & !ATTR_DIRECTORY, stored & !ATTR_DIRECTORY, false);
                assert_ne!(file, Ok(None), "{current:#x} {stored:#x}");
            }
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
