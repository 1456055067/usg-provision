//! Local accounts: finding the built-in Administrator by SID, setting its
//! password, and enabling or disabling it (topic 23 §30).
//!
//! The built-in Administrator can be renamed, so it is found by SID: the
//! machine's account-domain SID with RID 500 (§30.2), turned into a name
//! with `LookupAccountSidW`. Its password is set with `NetUserSetInfo`
//! level 1003 and its "disabled" flag with level 1008 (§30.1).
//!
//! Level 1008 is written as a read-modify-write: whether it replaces or
//! merges the flag set is not documented (OPEN-WAPI-21), `UF_SCRIPT` must
//! be set, and the account-type bits cannot change, so the current flags
//! are read, only `UF_ACCOUNTDISABLE` is changed, `UF_SCRIPT` is forced on,
//! and the result is read back. Flag values come from `windows-sys`, not
//! from the documentation pages, which give none (OPEN-WAPI-20).
//!
//! These calls act on the account database of the **running** system
//! (OPEN-WAPI-23): the agent calls them from the installed OS, not from
//! Windows PE against an offline image.

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-5 (Authenticator Management) - unique random password
//   set on the built-in account; AC-2 (Account Management) - account
//   enabled or disabled explicitly; SC-28 - password held only in locked,
//   wiped memory (`crate::memlock`)
// - SPEC: specs/standards/windows-storage-firmware-api.md §30
//   (OPEN-WAPI-20, -21, -22, -23)

/// `DOMAIN_USER_RID_ADMIN` (500, given on the "Well-known SIDs" page,
/// §30.2).
pub const RID_ADMIN: u32 = 500;

/// Longest account name (characters, §30.1).
pub const MAX_ACCOUNT_NAME_CHARS: usize = 20;

/// Whether `name` is an account name §30.1 allows: 1 to 20 characters,
/// not ending in a period, none of `" / \ [ ] : | < > + = ; ? * ,` and no
/// character 1 to 31 (or NUL).
#[must_use]
pub fn valid_account_name(name: &str) -> bool {
    let n = name.chars().count();
    (1..=MAX_ACCOUNT_NAME_CHARS).contains(&n)
        && !name.ends_with('.')
        && !name
            .chars()
            .any(|c| u32::from(c) < 32 || "\"/\\[]:|<>+=;?*,".contains(c))
}

/// The level-1008 value to write: `current` with only `disable_bit`
/// changed (set to disable, cleared to enable) and `script_bit` forced on
/// (§30.1, OPEN-WAPI-21).
#[must_use]
pub(crate) fn updated_flags(current: u32, enable: bool, script_bit: u32, disable_bit: u32) -> u32 {
    let f = if enable {
        current & !disable_bit
    } else {
        current | disable_bit
    };
    f | script_bit
}

/// Offsets of the `SID` fields used by [`is_admin_sid`]. On Windows they
/// come from `windows-sys`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SidLayout {
    /// Offset of `Revision`.
    pub revision: usize,
    /// Offset of `SubAuthorityCount`.
    pub count: usize,
    /// Offset of `IdentifierAuthority` (six bytes).
    pub authority: usize,
    /// Offset of the first `SubAuthority`.
    pub sub: usize,
}

/// Whether `sid` has the shape §30.2 describes for the built-in
/// Administrator of a machine account domain: revision 1, authority 5
/// (`SECURITY_NT_AUTHORITY`), first sub-authority 21
/// (`SECURITY_NT_NON_UNIQUE`), last sub-authority [`RID_ADMIN`], and a
/// length that matches its count exactly.
pub(crate) fn is_admin_sid(sid: &[u8], l: &SidLayout) -> bool {
    let Some(&count) = sid.get(l.count) else {
        return false;
    };
    let count = usize::from(count);
    let sub = |i: usize| -> Option<u32> {
        let at = l.sub.checked_add(i.checked_mul(4)?)?;
        let b: [u8; 4] = sid.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(u32::from_le_bytes(b))
    };
    sid.get(l.revision) == Some(&1)
        && (2..=15).contains(&count)
        && l.sub.checked_add(count * 4) == Some(sid.len())
        && sid.get(l.authority..l.authority + 6) == Some(&[0, 0, 0, 0, 0, 5][..])
        && sub(0) == Some(21)
        && sub(count - 1) == Some(RID_ADMIN)
}

#[cfg(windows)]
pub use self::windows::{LocalAccount, builtin_administrator};

#[cfg(windows)]
mod windows {
    use core::mem::offset_of;

    use windows_sys::Win32::NetworkManagement::NetManagement::{UF_ACCOUNTDISABLE, UF_SCRIPT};
    use windows_sys::Win32::Security::{SID, SidTypeUser};

    use super::{SidLayout, is_admin_sid, updated_flags, valid_account_name};
    use crate::error::{Result, WinApiError};
    use crate::ffi::{self, NetStatus};
    use crate::memlock::LockedWide;
    use crate::parse::{from_wide, to_wide_nul};

    const SID_LAYOUT: SidLayout = SidLayout {
        revision: offset_of!(SID, Revision),
        count: offset_of!(SID, SubAuthorityCount),
        authority: offset_of!(SID, IdentifierAuthority),
        sub: offset_of!(SID, SubAuthority),
    };

    fn net(op: &'static str) -> impl FnOnce(NetStatus) -> WinApiError {
        move |s| WinApiError::NetApi { op, code: s.0 }
    }

    /// A local account, named as `NetUserSetInfo` expects.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct LocalAccount {
        name: String,
        wide: Vec<u16>,
    }

    impl LocalAccount {
        /// An account given by name, for the Windows-runner tests on a
        /// throwaway account. The agent uses [`builtin_administrator`].
        pub fn by_name(name: &str) -> Result<Self> {
            if !valid_account_name(name) {
                return Err(WinApiError::Refused {
                    reason: "account name not allowed (topic 23 §30.1)",
                });
            }
            let wide = to_wide_nul(name).ok_or(WinApiError::Refused {
                reason: "account name holds a NUL",
            })?;
            Ok(Self {
                name: name.to_owned(),
                wide,
            })
        }

        /// The account name.
        #[must_use]
        pub fn name(&self) -> &str {
            &self.name
        }

        /// Sets the password (`NetUserSetInfo` level 1003, local computer).
        /// An administrator needs no old password (§30.1).
        /// `NERR_PasswordTooShort` in the error means the policy rejected
        /// it, not only its length (§30.1 [reading]).
        pub fn set_password(&self, password: &LockedWide) -> Result<()> {
            ffi::net_user_set_password(&self.wide, password.as_wide_nul())
                .map_err(net("set account password"))
        }

        /// Whether the account is enabled (`UF_ACCOUNTDISABLE` clear).
        pub fn is_enabled(&self) -> Result<bool> {
            let f = ffi::net_user_flags(&self.wide).map_err(net("read account flags"))?;
            Ok(f & UF_ACCOUNTDISABLE == 0)
        }

        /// Enables or disables the account: reads the flags, changes only
        /// `UF_ACCOUNTDISABLE`, keeps `UF_SCRIPT` set, writes them with
        /// level 1008 and reads them back (OPEN-WAPI-21). A read-back that
        /// does not show the change is an error.
        pub fn set_enabled(&self, enable: bool) -> Result<()> {
            let current = ffi::net_user_flags(&self.wide).map_err(net("read account flags"))?;
            let want = updated_flags(current, enable, UF_SCRIPT, UF_ACCOUNTDISABLE);
            if want != current {
                ffi::net_user_set_flags(&self.wide, want).map_err(net("set account flags"))?;
            }
            if self.is_enabled()? != enable {
                return Err(WinApiError::Refused {
                    reason: "account flag did not change",
                });
            }
            Ok(())
        }
    }

    /// The built-in Administrator (RID 500 in the machine's account
    /// domain), whatever it is named (§30.2). Needs an administrator
    /// token (`LsaOpenPolicy`). Fails if the SID does not have the
    /// expected shape or does not name a user account.
    pub fn builtin_administrator() -> Result<LocalAccount> {
        let sid = ffi::administrator_sid().map_err(|e| WinApiError::os("form RID 500 SID", e))?;
        if !is_admin_sid(&sid, &SID_LAYOUT) {
            return Err(WinApiError::Refused {
                reason: "administrator SID has an unexpected shape",
            });
        }
        let (units, use_) =
            ffi::lookup_account_sid(&sid).map_err(|e| WinApiError::os("look up RID 500", e))?;
        // `SidTypeUser` value from windows-sys (OPEN-WAPI-22).
        if use_ != SidTypeUser {
            return Err(WinApiError::Refused {
                reason: "RID 500 does not name a user account",
            });
        }
        let name = from_wide(&units).map_err(|e| WinApiError::malformed("account name", e))?;
        LocalAccount::by_name(&name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// windows-sys 0.61.2 values: `UF_SCRIPT` 1, `UF_ACCOUNTDISABLE` 2
    /// (OPEN-WAPI-20; asserted against windows-sys on Windows below).
    const SCRIPT: u32 = 1;
    const DISABLE: u32 = 2;
    const L: SidLayout = SidLayout {
        revision: 0,
        count: 1,
        authority: 2,
        sub: 8,
    };

    fn sid(subs: &[u32]) -> Vec<u8> {
        let mut v = vec![1u8, u8::try_from(subs.len()).unwrap_or(0), 0, 0, 0, 0, 0, 5];
        for s in subs {
            v.extend_from_slice(&s.to_le_bytes());
        }
        v
    }

    #[test]
    fn flags_change_only_the_disable_bit_and_keep_script() {
        // Normal account (0x200) plus "password never expires" (0x10000).
        let other = 0x0001_0200;
        assert_eq!(
            updated_flags(other | DISABLE | SCRIPT, true, SCRIPT, DISABLE),
            other | SCRIPT
        );
        assert_eq!(
            updated_flags(other, false, SCRIPT, DISABLE),
            other | DISABLE | SCRIPT
        );
        assert_eq!(updated_flags(other, true, SCRIPT, DISABLE), other | SCRIPT);
    }

    #[test]
    fn account_names_follow_the_documented_rules() {
        assert!(valid_account_name("Administrator"));
        assert!(valid_account_name("usgp-test1"));
        assert!(!valid_account_name(""));
        assert!(!valid_account_name("a.b."));
        assert!(!valid_account_name("abcdefghijklmnopqrstu"));
        for bad in [
            "a\"b", "a/b", "a\\b", "a[b", "a:b", "a|b", "a<b", "a+b", "a=b", "a;b",
        ] {
            assert!(!valid_account_name(bad), "{bad}");
        }
        assert!(!valid_account_name("a,b"));
        assert!(!valid_account_name("a\u{1}b"));
    }

    #[test]
    fn only_a_machine_domain_rid_500_sid_is_accepted() {
        assert!(is_admin_sid(&sid(&[21, 1, 2, 3, 500]), &L));
        assert!(!is_admin_sid(&sid(&[21, 1, 2, 3, 501]), &L), "guest");
        assert!(!is_admin_sid(&sid(&[32, 544]), &L), "Administrators group");
        let mut s = sid(&[21, 1, 2, 3, 500]);
        s.push(0);
        assert!(!is_admin_sid(&s, &L), "trailing bytes");
        let s = sid(&[21, 1, 2, 3, 500]);
        assert!(
            !is_admin_sid(s.get(..s.len() - 1).unwrap_or(&[]), &L),
            "short"
        );
        let mut s = sid(&[21, 1, 2, 3, 500]);
        if let Some(b) = s.get_mut(7) {
            *b = 1;
        }
        assert!(!is_admin_sid(&s, &L), "authority");
        assert!(!is_admin_sid(&[], &L));
    }

    #[cfg(windows)]
    #[test]
    fn test_values_match_windows_sys() {
        use windows_sys::Win32::NetworkManagement::NetManagement::{UF_ACCOUNTDISABLE, UF_SCRIPT};
        use windows_sys::Win32::System::SystemServices::DOMAIN_USER_RID_ADMIN;
        assert_eq!((SCRIPT, DISABLE), (UF_SCRIPT, UF_ACCOUNTDISABLE));
        assert_eq!(u32::try_from(DOMAIN_USER_RID_ADMIN).ok(), Some(RID_ADMIN));
    }
}
