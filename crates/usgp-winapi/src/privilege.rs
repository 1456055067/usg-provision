//! Token privileges, enabled only while an operation that needs them runs.
//!
//! [`scoped`] enables a privilege and returns an [`EnabledPrivilege`]; the
//! privilege is disabled again when the last such guard for it is dropped
//! (`privscope.rs` counts nested users). [`check_held`] tells at start-up
//! whether the token holds a privilege, leaving it disabled. Nothing in
//! this crate leaves a privilege enabled once its operation has ended
//! (NIST-001):
//!
//! - `SystemEnvironment`: for the duration of each firmware-variable call
//!   (`firmware.rs`);
//! - `Restore` and `Backup`: for the life of one `fs::TreeWriter`, that is
//!   the apply step only;
//! - `Security`: for one descriptor set that carries a SACL;
//! - `CreateSymbolicLink`: for one reparse-point set.
//!
//! The token is the process token, so the state is process-wide: the
//! counts are kept behind one lock, and any thread's guard keeps the
//! privilege enabled for all threads until it is dropped.
//!
//! Microsoft's own steps for the security privilege are "enable, use,
//! disable" (topic 23 §23); the same pattern is applied to the others.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-6 (Least Privilege) - each privilege is enabled only
//   for the operation that needs it and disabled when it ends; the agent
//   enables none at start-up (it only checks they are held).
// - SPEC: specs/standards/windows-storage-firmware-api.md §10, §23, §26

use std::sync::Mutex;

use crate::error::{Result, WinApiError};
use crate::ffi::{self, PrivilegeName, PrivilegeOutcome};
use crate::privscope::ScopeCounts;

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
    /// the ACL (topic 23 §23). The apply sink needs it: a descriptor set
    /// opens the file for `READ_CONTROL` and an attribute set reads the
    /// attributes, and both can follow a just-applied DACL that grants
    /// neither; topic 23 §23 lists those rights among the ones backup
    /// grants, and restore does not grant them.
    Backup,
    /// `SeCreateSymbolicLinkPrivilege`: needed to set a symbolic-link
    /// reparse point (topic 24 §6).
    CreateSymbolicLink,
}

/// Number of [`Privilege`] values.
const COUNT: usize = 5;

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

    fn index(self) -> usize {
        match self {
            Self::SystemEnvironment => 0,
            Self::Restore => 1,
            Self::Security => 2,
            Self::Backup => 3,
            Self::CreateSymbolicLink => 4,
        }
    }

    fn ffi_name(self) -> PrivilegeName {
        match self {
            Self::SystemEnvironment => PrivilegeName::SystemEnvironment,
            Self::Restore => PrivilegeName::Restore,
            Self::Security => PrivilegeName::Security,
            Self::Backup => PrivilegeName::Backup,
            Self::CreateSymbolicLink => PrivilegeName::CreateSymbolicLink,
        }
    }
}

/// Users of each privilege in this process.
static COUNTS: Mutex<ScopeCounts<COUNT>> = Mutex::new(ScopeCounts::new());

fn with_counts<T>(f: impl FnOnce(&mut ScopeCounts<COUNT>) -> T) -> T {
    // A poisoned lock still holds valid counts (every update is a single
    // step), so it is used as is.
    let mut g = COUNTS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    f(&mut g)
}

/// Enables or disables `p`. Enabling a privilege the token lacks is
/// [`WinApiError::PrivilegeNotHeld`] (spec §10: the call can only adjust
/// a privilege the token already holds, and reports that case through
/// `ERROR_NOT_ALL_ASSIGNED` on success). Disabling one the token lacks is
/// not an error: it is not enabled.
fn adjust(p: Privilege, enable: bool) -> Result<()> {
    let op = if enable {
        "enable privilege"
    } else {
        "disable privilege"
    };
    match ffi::adjust_privilege(p.ffi_name(), enable).map_err(|e| WinApiError::os(op, e))? {
        PrivilegeOutcome::Adjusted => Ok(()),
        PrivilegeOutcome::NotHeld if enable => Err(WinApiError::PrivilegeNotHeld {
            privilege: p.name(),
        }),
        PrivilegeOutcome::NotHeld => Ok(()),
    }
}

/// `p`, enabled until this guard (and every other guard for `p`) is
/// dropped.
#[derive(Debug)]
#[must_use = "the privilege is disabled again when the guard is dropped"]
pub struct EnabledPrivilege {
    p: Privilege,
}

impl EnabledPrivilege {
    /// The privilege held enabled.
    #[must_use]
    pub fn privilege(&self) -> Privilege {
        self.p
    }
}

impl Drop for EnabledPrivilege {
    fn drop(&mut self) {
        let p = self.p;
        // Best effort: a drop cannot report an error. The disable call
        // fails only if the process token cannot be opened, in which case
        // nothing else in the process can adjust it either.
        let _ = with_counts(|c| c.release(p.index(), |on| adjust(p, on)));
    }
}

/// Enables `p` in the process token for as long as the returned guard
/// lives.
///
/// # Errors
///
/// [`WinApiError::PrivilegeNotHeld`] if the token lacks it, or the OS
/// error of the adjust call.
pub fn scoped(p: Privilege) -> Result<EnabledPrivilege> {
    with_counts(|c| c.acquire(p.index(), |on| adjust(p, on)))?;
    Ok(EnabledPrivilege { p })
}

/// Checks that the token holds `p` by enabling and at once disabling it
/// (when no guard for it is alive; otherwise it is held and enabled
/// already). Used at start-up so a missing privilege stops the agent
/// before any disk is touched, without leaving it enabled.
///
/// # Errors
///
/// As [`scoped`].
pub fn check_held(p: Privilege) -> Result<()> {
    with_counts(|c| c.probe(p.index(), |on| adjust(p, on)))
}

/// The number of live guards for `p` (for tests and diagnostics).
#[must_use]
pub fn users(p: Privilege) -> u32 {
    with_counts(|c| c.count(p.index()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexes_are_distinct_and_in_range() {
        let all = [
            Privilege::SystemEnvironment,
            Privilege::Restore,
            Privilege::Security,
            Privilege::Backup,
            Privilege::CreateSymbolicLink,
        ];
        let mut seen = [false; COUNT];
        for p in all {
            let slot = seen.get_mut(p.index()).expect("index in range");
            assert!(!*slot, "{p:?}");
            *slot = true;
        }
    }
}
