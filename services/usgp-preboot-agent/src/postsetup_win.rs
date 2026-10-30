//! The installed-Windows side of the post-setup runner (M4 plan WU-10;
//! §1.2, §1.3): the folders, the SYSTEM-only DACL and the account and
//! memory-lock operations, all on `usgp-winapi` (decision 0019; this crate
//! has no `unsafe`).
//!
//! - **Folders**: the post-setup folder is the folder of the running
//!   program, which must be `…\usgp\postsetup\` (as our
//!   `SetupComplete.cmd` starts it); the Windows folder is the parent of
//!   the system directory. Nothing is taken from the environment.
//! - **Password** (M4 plan §1.3, decision 0024): copied into one locked,
//!   page-aligned block (`usgp_winapi::memlock::LockedWide`), set on the
//!   built-in Administrator (RID 500, whatever its name) with
//!   `NetUserSetInfo` level 1003, then the account enabled (level 1008,
//!   read back); the block is wiped after the call and wiped and unlocked
//!   when the runner is done.

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-5(1) - the escrowed password set on RID 500 only
//   after the server's acknowledgement (the runner's order).
// - NIST 800-53: SI-16, SC-28 - the copy passed to the account call is in
//   locked memory, wiped after use; a lock failure fails closed.
// - NIST 800-53: AC-3, AC-6 - protected SYSTEM-only DACLs.
// - SPEC: specs/configuration.md#REQ-CFG-008 (as modified by decision
//   0024)
// - SPEC: specs/standards/windows-storage-firmware-api.md §20, §30, §31
// - DECISION: docs/decisions/0019, 0024

use std::fs::File;
use std::io;

use usgp_deploy::postsetup::AccountError;
use usgp_deploy::{PlatformError, PlatformErrorKind};
use usgp_winapi::WinApiError;
use usgp_winapi::account::builtin_administrator;
use usgp_winapi::memlock::LockedWide;
use zeroize::Zeroizing;

use crate::installed::{AccountOps, InstalledPaths, InstalledPlatform};
use crate::wintools;

/// `ERROR_NOT_LOCKED` (158): the password was offered before the memory
/// was locked. A documented Win32 code, reported as the account status.
const ERROR_NOT_LOCKED: u32 = 158;
/// `ERROR_INVALID_PARAMETER` (87): the password did not fit the locked
/// block.
const ERROR_INVALID_PARAMETER: u32 = 87;

/// Applies a protected DACL granting SYSTEM full control and nothing else
/// (`usgp_winapi::acl`; the file is open with `WRITE_DAC`).
///
/// # Errors
///
/// The failure as an I/O error.
pub fn protect_system_only(f: &File) -> io::Result<()> {
    usgp_winapi::acl::protect_file_system_only(f)
        .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))
}

/// The status code of a failed account call.
fn account_error(e: &WinApiError) -> AccountError {
    let win32 = match e {
        WinApiError::NetApi { code, .. } => *code,
        other => other.os_code().map_or(u32::MAX, wintools::exit_code_u32),
    };
    AccountError { win32 }
}

/// [`AccountOps`] on `usgp-winapi`.
#[derive(Debug, Default)]
pub struct WinAccount {
    locked: Option<LockedWide>,
}

impl AccountOps for WinAccount {
    fn lock(&mut self) -> Result<(), PlatformError> {
        if self.locked.is_none() {
            let block = LockedWide::new().map_err(|_| {
                PlatformError::new(PlatformErrorKind::Refused, "lock memory for the password")
            })?;
            self.locked = Some(block);
        }
        Ok(())
    }

    fn unlock(&mut self) {
        if let Some(block) = self.locked.take()
            && let Err(e) = block.close()
        {
            // Wiped either way; a lost lock is recorded for the operator.
            eprintln!("usgp-agent postsetup: memory unlock: {e}");
        }
    }

    fn set_admin_password(&mut self, password: &Zeroizing<String>) -> Result<(), AccountError> {
        let block = self.locked.as_mut().ok_or(AccountError {
            win32: ERROR_NOT_LOCKED,
        })?;
        block.set(password.as_str()).map_err(|_| AccountError {
            win32: ERROR_INVALID_PARAMETER,
        })?;
        let result = {
            let pw: &LockedWide = block;
            builtin_administrator().and_then(|a| {
                a.set_password(pw)?;
                a.set_enabled(true)
            })
        };
        // Wipe the copy at once; the block itself is released by `unlock`.
        let _ = block.set("");
        result.map_err(|e| account_error(&e))
    }
}

/// The post-setup platform for the running program, or why not.
///
/// # Errors
///
/// A fixed description: the program is not in a post-setup folder, or
/// the system directory cannot be read.
pub fn open() -> Result<InstalledPlatform<WinAccount>, String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("the program's own path cannot be read ({})", e.kind()))?;
    let system = usgp_winapi::system::system_directory()
        .map_err(|e| format!("the system directory cannot be read: {e}"))?;
    let windows = system
        .parent()
        .ok_or("the system directory has no parent")?
        .to_path_buf();
    let paths = InstalledPaths::for_runner(&exe, &windows, &system)
        .ok_or("the program is not in a usgp\\postsetup folder")?;
    Ok(InstalledPlatform::new(
        paths,
        protect_system_only,
        WinAccount::default(),
    ))
}
