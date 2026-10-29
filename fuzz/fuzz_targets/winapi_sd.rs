//! Fuzz target `winapi_sd`: `usgp_winapi::parse::check_security_descriptor`
//! on arbitrary bytes, with the synthetic self-relative layout of
//! `parse::testkit::SECURITY_DESCRIPTOR` (feature `parse-testkit`; on
//! Windows `layout.rs` asserts it equals the windows-sys layout). The
//! bytes stand for a descriptor taken from a WIM before it is handed to
//! Windows (SEC-004).
//!
//! Invariants:
//!
//! - no panic; the same input gives the same answer twice;
//! - `Ok` implies every offset and length lies inside the input, checked
//!   by a walk written here (not the parser's code): the fixed header;
//!   each non-zero owner or group offset at or past the header, with the
//!   SID's revision, sub-authority count (at most 15) and sub-authorities
//!   inside the input; each non-zero SACL or DACL offset with its present
//!   flag, past the header, the ACL header and `AclSize` inside the input,
//!   and its `AceCount` ACE headers, each at least a header and a multiple
//!   of 4, inside `AclSize`;
//! - `Ok` reports the stored control word and presence flags, and a null
//!   DACL exactly when the DACL flag is set with offset 0.
//!
//! ACE bodies are not bounded by the parser (`// POAM: SEC-004 residual`,
//! `usgp-winapi/src/ffi.rs`), so they are not checked here.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SI-16 (Memory
//   Protection), SA-11
// - SPEC: specs/standards/reparse-and-security-descriptors.md (topic 24
//   §7 to §9)

use libfuzzer_sys::fuzz_target;
use usgp_winapi::parse::testkit::SECURITY_DESCRIPTOR as L;
use usgp_winapi::parse::{MAX_SECURITY_DESCRIPTOR_BYTES, check_security_descriptor};

/// `len` octets at `off`, or a panic naming the field: after `Ok`, every
/// read must be inside the input.
fn field<'a>(sd: &'a [u8], off: usize, len: usize, what: &str) -> &'a [u8] {
    off.checked_add(len)
        .and_then(|end| sd.get(off..end))
        .unwrap_or_else(|| {
            panic!(
                "Ok, but {what} ({off}+{len}) is outside {} octets",
                sd.len()
            )
        })
}

fn u16_le(sd: &[u8], off: usize, what: &str) -> usize {
    let b = field(sd, off, 2, what);
    usize::from(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_le(sd: &[u8], off: usize, what: &str) -> usize {
    let b = field(sd, off, 4, what);
    usize::try_from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])).expect("u32 fits usize")
}

fn sid(sd: &[u8], off: usize, what: &str) {
    assert!(off >= L.fixed_len, "{what} offset inside the header");
    assert_eq!(
        field(sd, off + L.sid_revision_field, 1, what)[0],
        L.sid_revision
    );
    let count = field(sd, off + L.sid_count, 1, what)[0];
    assert!(count <= L.sid_max_sub_authorities, "{what} count {count}");
    field(sd, off, L.sid_sub_authority + 4 * usize::from(count), what);
}

fn acl(sd: &[u8], off: usize, what: &str) {
    assert!(off >= L.fixed_len, "{what} offset inside the header");
    field(sd, off, L.acl_fixed_len, what);
    let size = u16_le(sd, off + L.acl_size, what);
    assert!(
        size >= L.acl_fixed_len && size % 4 == 0,
        "{what} size {size}"
    );
    field(sd, off, size, what);
    let count = u16_le(sd, off + L.acl_ace_count, what);
    let mut pos = L.acl_fixed_len;
    for i in 0..count {
        assert!(
            pos + L.ace_header_len <= size,
            "{what} ACE {i} header past AclSize"
        );
        let ace = u16_le(sd, off + pos + L.ace_size, what);
        assert!(
            ace >= L.ace_header_len && ace % 4 == 0,
            "{what} ACE {i} size {ace}"
        );
        pos += ace;
        assert!(pos <= size, "{what} ACE {i} past AclSize");
        field(sd, off, pos, what);
    }
}

fuzz_target!(|sd: &[u8]| {
    let r = check_security_descriptor(sd, &L);
    assert_eq!(r, check_security_descriptor(sd, &L), "not deterministic");
    let Ok(parts) = r else {
        return;
    };
    assert!(sd.len() <= MAX_SECURITY_DESCRIPTOR_BYTES);
    field(sd, 0, L.fixed_len, "header");
    assert_eq!(sd[L.revision], L.sd_revision);
    let control = u16::try_from(u16_le(sd, L.control, "control")).expect("u16");
    assert_eq!(parts.control, control);
    assert!(control & L.self_relative != 0);
    let owner = u32_le(sd, L.owner, "owner offset");
    let group = u32_le(sd, L.group, "group offset");
    let sacl = u32_le(sd, L.sacl, "SACL offset");
    let dacl = u32_le(sd, L.dacl, "DACL offset");
    assert_eq!(parts.owner, owner != 0);
    assert_eq!(parts.group, group != 0);
    if owner != 0 {
        sid(sd, owner, "owner SID");
    }
    if group != 0 {
        sid(sd, group, "group SID");
    }
    let sacl_flag = control & L.sacl_present != 0;
    let dacl_flag = control & L.dacl_present != 0;
    assert_eq!(parts.sacl, sacl_flag);
    assert_eq!(parts.dacl, dacl_flag);
    assert_eq!(parts.null_dacl, dacl_flag && dacl == 0);
    if sacl != 0 {
        assert!(sacl_flag, "SACL offset without its flag");
        acl(sd, sacl, "SACL");
    }
    if dacl != 0 {
        assert!(dacl_flag, "DACL offset without its flag");
        acl(sd, dacl, "DACL");
    }
});
