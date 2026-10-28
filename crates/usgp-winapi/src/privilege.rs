//! Enabling token privileges.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-6 (Least Privilege) - only the one privilege the
//   firmware-variable functions need is enabled, and only when used
// - SPEC: specs/standards/windows-storage-firmware-api.md §10

use crate::error::{Result, WinApiError};
use crate::ffi::{self, PrivilegeOutcome};

/// A privilege this crate may enable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Privilege {
    /// `SeSystemEnvironmentPrivilege`: read and write firmware variables
    /// (spec §9, §10).
    SystemEnvironment,
    /// `SeRestorePrivilege`: lets the apply sink set any owner, set short
    /// names, and open files it already secured (backup semantics).
    /// Topic 23 §23.
    Restore,
    /// `SeSecurityPrivilege`: lets the apply sink set a SACL (topic 23
    /// §23).
    Security,
    /// `SeBackupPrivilege`: with backup semantics, read access whatever
    /// the ACL (topic 23 §23).
    Backup,
    /// `SeCreateSymbolicLinkPrivilege`: needed to set a symbolic-link
    /// reparse point (topic 24 §6).
    CreateSymbolicLink,
}

impl Privilege {
    /// The privilege's name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::SystemEnvironment => "SeSystemEnvironmentPrivilege",
            Self::Restore => "SeRestorePrivilege",
            Self::Security => "SeSecurityPrivilege",
            Self::Backup => "SeBackupPrivilege",
            Self::CreateSymbolicLink => "SeCreateSymbolicLinkPrivilege",
        }
    }
}

/// Enables `p` in the process token.
///
/// Fails with [`WinApiError::PrivilegeNotHeld`] when the token lacks it:
/// the adjust call can only enable a privilege the token already holds,
/// and reports that case through `ERROR_NOT_ALL_ASSIGNED` on success
/// (spec §10).
pub fn enable(p: Privilege) -> Result<()> {
    let outcome = match p {
        Privilege::SystemEnvironment => {
            ffi::enable_privilege(ffi::PrivilegeName::SystemEnvironment)
        }
        Privilege::Restore => ffi::enable_privilege(ffi::PrivilegeName::Restore),
        Privilege::Security => ffi::enable_privilege(ffi::PrivilegeName::Security),
        Privilege::Backup => ffi::enable_privilege(ffi::PrivilegeName::Backup),
        Privilege::CreateSymbolicLink => {
            ffi::enable_privilege(ffi::PrivilegeName::CreateSymbolicLink)
        }
    }
    .map_err(|e| WinApiError::os("enable privilege", e))?;
    match outcome {
        PrivilegeOutcome::Enabled => Ok(()),
        PrivilegeOutcome::NotHeld => Err(WinApiError::PrivilegeNotHeld {
            privilege: p.name(),
        }),
    }
}
