//! A protected DACL that grants SYSTEM full control and nothing else, for
//! the agent's private files (the job key, plan section 1.2).
//!
//! The descriptor is built here as self-relative bytes with the offsets
//! and constants of `windows-sys` (no hand-written layout, OPEN-WAPI-1),
//! checked by [`crate::parse::check_security_descriptor`] and Windows'
//! own validity check, and applied with the existing
//! `ffi::set_file_security` (`SetSecurityInfo` on the open handle). The
//! descriptor's "protected" control bit makes that call pass
//! `PROTECTED_DACL_SECURITY_INFORMATION`, so no entry is inherited from
//! the parent (topic 23 §20).

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 (Access Enforcement), AC-6 (Least Privilege),
//   SC-28 (Protection of Information at Rest) - SYSTEM-only protected DACL
// - SPEC: specs/standards/windows-storage-firmware-api.md §20;
//   specs/standards/reparse-and-security-descriptors.md §7 to §9

use crate::parse::SecurityDescriptorLayout;

/// The parts of one access-allowed entry and the descriptor flags that
/// are not in [`SecurityDescriptorLayout`]. On Windows every value comes
/// from `windows-sys` ([`windows_ace`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AceSpec {
    /// `ACL_REVISION`.
    pub acl_revision: u8,
    /// `ACCESS_ALLOWED_ACE_TYPE`.
    pub ace_type: u8,
    /// Offset of `ACCESS_ALLOWED_ACE.Mask`.
    pub mask_offset: usize,
    /// Offset of `ACCESS_ALLOWED_ACE.SidStart`.
    pub sid_offset: usize,
    /// The access mask granted.
    pub mask: u32,
    /// `SE_DACL_PROTECTED`.
    pub dacl_protected: u16,
}

/// Largest SID accepted for the entry (bytes): eight fixed bytes and at
/// most 15 sub-authorities (topic 24 §7).
const MAX_SID_BYTES: usize = 8 + 4 * 15;

fn put(buf: &mut [u8], at: usize, bytes: &[u8]) -> Option<()> {
    buf.get_mut(at..at.checked_add(bytes.len())?)?
        .copy_from_slice(bytes);
    Some(())
}

/// A self-relative descriptor with only a protected DACL holding one
/// access-allowed entry (no inheritance flags) for `sid` with `a.mask`.
/// No owner, group or SACL. `None` if `sid` is empty, too long, or a size
/// overflows the 16-bit fields.
pub(crate) fn protected_single_ace(
    l: &SecurityDescriptorLayout,
    a: &AceSpec,
    sid: &[u8],
) -> Option<Vec<u8>> {
    if sid.is_empty() || sid.len() > MAX_SID_BYTES {
        return None;
    }
    // ACE: header and mask, then the SID, padded to a multiple of 4.
    let ace_len = a
        .sid_offset
        .checked_add(sid.len())?
        .checked_next_multiple_of(4)?;
    let acl_len = l.acl_fixed_len.checked_add(ace_len)?;
    let total = l.fixed_len.checked_add(acl_len)?;
    let acl_size = u16::try_from(acl_len).ok()?;
    let ace_size = u16::try_from(ace_len).ok()?;
    let dacl_at = u32::try_from(l.fixed_len).ok()?;
    let control = l.self_relative | l.dacl_present | a.dacl_protected;

    let mut sd = vec![0u8; total];
    // Header: revision, control, DACL offset. Owner, group and SACL
    // offsets stay zero (absent).
    put(&mut sd, l.revision, &[l.sd_revision])?;
    put(&mut sd, l.control, &control.to_le_bytes())?;
    put(&mut sd, l.dacl, &dacl_at.to_le_bytes())?;
    // ACL header: revision at offset 0 (topic 24 §8), size and count.
    let acl = l.fixed_len;
    put(&mut sd, acl, &[a.acl_revision])?;
    put(
        &mut sd,
        acl.checked_add(l.acl_size)?,
        &acl_size.to_le_bytes(),
    )?;
    put(
        &mut sd,
        acl.checked_add(l.acl_ace_count)?,
        &1u16.to_le_bytes(),
    )?;
    // ACE header: type at offset 0, flags 0 (no inheritance), size.
    let ace = acl.checked_add(l.acl_fixed_len)?;
    put(&mut sd, ace, &[a.ace_type])?;
    put(
        &mut sd,
        ace.checked_add(l.ace_size)?,
        &ace_size.to_le_bytes(),
    )?;
    put(
        &mut sd,
        ace.checked_add(a.mask_offset)?,
        &a.mask.to_le_bytes(),
    )?;
    put(&mut sd, ace.checked_add(a.sid_offset)?, sid)?;
    Some(sd)
}

#[cfg(windows)]
pub use self::windows::protect_file_system_only;

#[cfg(all(windows, test))]
use self::windows::windows_ace;

#[cfg(windows)]
mod windows {
    use core::mem::offset_of;
    use std::fs::File;

    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL_REVISION, DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

    use super::{AceSpec, protected_single_ace};
    use crate::error::{Result, WinApiError};
    use crate::ffi;
    use crate::layout::SECURITY_DESCRIPTOR;

    /// The `windows-sys` values for one full-control file entry.
    /// `ACL_REVISION` and `ACCESS_ALLOWED_ACE_TYPE` are `u32` there and
    /// fit in a byte (checked at compile time below).
    pub(crate) const fn windows_ace() -> AceSpec {
        AceSpec {
            acl_revision: ACL_REVISION as u8,
            ace_type: ACCESS_ALLOWED_ACE_TYPE as u8,
            mask_offset: offset_of!(ACCESS_ALLOWED_ACE, Mask),
            sid_offset: offset_of!(ACCESS_ALLOWED_ACE, SidStart),
            mask: FILE_ALL_ACCESS,
            dacl_protected: SE_DACL_PROTECTED,
        }
    }

    const _: () = assert!(ACL_REVISION >> 8 == 0 && ACCESS_ALLOWED_ACE_TYPE >> 8 == 0);

    /// Replaces the DACL of `file` with a protected DACL granting SYSTEM
    /// (`WinLocalSystemSid`) full control and nothing else. Entries
    /// inherited from the parent are removed and none are inherited later
    /// (topic 23 §20, "protected"). `file` must be open with `WRITE_DAC`
    /// (topic 23 §20). Owner, group and SACL are left as they are.
    ///
    /// After this, only SYSTEM (and holders of privileges such as backup
    /// and restore) can open the file; the agent runs as SYSTEM.
    pub fn protect_file_system_only(file: &File) -> Result<()> {
        let sid = ffi::local_system_sid().map_err(|e| WinApiError::os("create SYSTEM SID", e))?;
        let sd = protected_single_ace(&SECURITY_DESCRIPTOR, &windows_ace(), &sid).ok_or(
            WinApiError::Refused {
                reason: "SYSTEM SID does not fit a descriptor",
            },
        )?;
        ffi::set_file_security(file, &sd, DACL_SECURITY_INFORMATION)
            .map_err(|e| WinApiError::os("set protected DACL", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::check_security_descriptor;
    use crate::parse::testkit::SECURITY_DESCRIPTOR as SDL;

    /// The windows-sys 0.61.2 values (read from its declarations:
    /// `ACL_REVISION` 2, `ACCESS_ALLOWED_ACE_TYPE` 0, `Mask` at 4,
    /// `SidStart` at 8, `FILE_ALL_ACCESS` 0x1F01FF, `SE_DACL_PROTECTED`
    /// 0x1000). On Windows a test asserts they equal [`windows_ace`].
    const ACE: AceSpec = AceSpec {
        acl_revision: 2,
        ace_type: 0,
        mask_offset: 4,
        sid_offset: 8,
        mask: 0x001F_01FF,
        dacl_protected: 0x1000,
    };

    /// S-1-5-18 in its binary form (topic 24 §7).
    const SYSTEM_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

    #[test]
    fn builds_a_well_formed_protected_dacl_only_descriptor() {
        let sd = protected_single_ace(&SDL, &ACE, &SYSTEM_SID).expect("builds");
        // 20 header + 8 ACL header + (8 + 12) ACE.
        assert_eq!(sd.len(), 48);
        let parts = check_security_descriptor(&sd, &SDL).expect("well formed");
        assert!(parts.dacl && !parts.null_dacl);
        assert!(!parts.owner && !parts.group && !parts.sacl);
        assert_ne!(parts.control & ACE.dacl_protected, 0);
        assert_eq!(sd.get(28), Some(&0), "access-allowed type");
        assert_eq!(sd.get(29), Some(&0), "no inheritance flags");
        assert_eq!(sd.get(32..36), Some(&0x001F_01FFu32.to_le_bytes()[..]));
        assert_eq!(sd.get(36..48), Some(&SYSTEM_SID[..]));
    }

    #[test]
    fn pads_the_entry_to_four_bytes() {
        let sid = [1u8, 0, 0, 0, 0, 0, 0, 5, 0xAA];
        let sd = protected_single_ace(&SDL, &ACE, &sid).expect("builds");
        assert_eq!(sd.len(), 20 + 8 + 20);
        check_security_descriptor(&sd, &SDL).expect("sizes are multiples of 4");
    }

    #[test]
    fn refuses_empty_or_oversized_sids() {
        assert!(protected_single_ace(&SDL, &ACE, &[]).is_none());
        assert!(protected_single_ace(&SDL, &ACE, &[0u8; MAX_SID_BYTES + 1]).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn test_values_match_windows_sys() {
        assert_eq!(ACE, windows_ace());
    }
}
