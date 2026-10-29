//! Fuzz target `winapi_reparse`: `usgp_winapi::parse::check_reparse_buffer`
//! on arbitrary bytes, with the synthetic `REPARSE_DATA_BUFFER` layout of
//! `parse::testkit::REPARSE` (feature `parse-testkit`; on Windows
//! `layout.rs` asserts it equals the windows-sys layout). The bytes stand
//! for reparse data from a WIM before it is handed to Windows (SEC-004).
//!
//! Invariants:
//!
//! - no panic; the same input gives the same answer twice;
//! - `Ok(kind)` implies, by a check written here (not the parser's code):
//!   the 8-octet header is inside the input; `ReparseDataLength` equals
//!   the octets after it; `Reserved` is 0; the tag is the one of `kind`;
//!   the member's fixed fields lie inside the data; a symbolic link's
//!   `Flags` is 0 or relative; both names have an even offset and length,
//!   at most 32 760 characters, and lie inside the path buffer.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SI-16 (Memory
//   Protection), SA-11
// - SPEC: specs/standards/reparse-and-security-descriptors.md (topic 24
//   §2 to §5)

use libfuzzer_sys::fuzz_target;
use usgp_winapi::parse::testkit::REPARSE as L;
use usgp_winapi::parse::{MAX_PATHNAME_CHARS, ReparseKind, check_reparse_buffer};

fn field<'a>(b: &'a [u8], off: usize, len: usize, what: &str) -> &'a [u8] {
    off.checked_add(len)
        .and_then(|end| b.get(off..end))
        .unwrap_or_else(|| panic!("Ok, but {what} ({off}+{len}) is outside {} octets", b.len()))
}

fn u16_le(b: &[u8], off: usize, what: &str) -> usize {
    let v = field(b, off, 2, what);
    usize::from(u16::from_le_bytes([v[0], v[1]]))
}

fn u32_le(b: &[u8], off: usize, what: &str) -> u32 {
    let v = field(b, off, 4, what);
    u32::from_le_bytes([v[0], v[1], v[2], v[3]])
}

fuzz_target!(|buf: &[u8]| {
    let r = check_reparse_buffer(buf, &L);
    assert_eq!(r, check_reparse_buffer(buf, &L), "not deterministic");
    let Ok(kind) = r else {
        return;
    };
    let data = buf.get(L.data..).expect("Ok, but no data part");
    assert_eq!(u16_le(buf, L.data_length, "data length"), data.len());
    assert_eq!(u16_le(buf, L.reserved, "reserved"), 0);
    let tag = u32_le(buf, L.tag, "tag");
    let fields = match kind {
        ReparseKind::Symlink => {
            assert_eq!(tag, L.symlink_tag);
            let flags = u32_le(data, L.symlink_flags, "symlink flags");
            assert!(flags == 0 || flags == L.relative_flag, "flags {flags:#x}");
            &L.symlink
        }
        ReparseKind::MountPoint => {
            assert_eq!(tag, L.mount_point_tag);
            &L.mount_point
        }
    };
    let path = data
        .get(fields.path_buffer..)
        .unwrap_or_else(|| panic!("Ok, but the path buffer starts past the data"));
    for (o, n, what) in [
        (fields.sub_offset, fields.sub_length, "substitute name"),
        (fields.print_offset, fields.print_length, "print name"),
    ] {
        let off = u16_le(data, o, what);
        let len = u16_le(data, n, what);
        assert!(off % 2 == 0 && len % 2 == 0, "{what} odd offset or length");
        assert!(len / 2 <= MAX_PATHNAME_CHARS, "{what} too long");
        field(path, off, len, what);
    }
});
