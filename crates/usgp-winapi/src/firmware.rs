//! UEFI firmware variables: boot-option reads and writes, and the
//! read-only Secure Boot state.
//!
//! Writes are possible only through [`FirmwareVars::set_boot_var`], which
//! takes a [`WritableBootVar`] (`BootOrder` or `Boot####`). Nothing in
//! this crate can write a Secure Boot variable (decision 0018 item 5).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   Secure Boot state is read, never written; CM-5 (Access Restrictions
//   for Change); AC-6 (Least Privilege) - the firmware privilege is
//   enabled per call and disabled after it
// - SPEC: specs/standards/windows-storage-firmware-api.md §9, §10
// - SPEC: specs/standards/uefi-boot-manager.md §4, §10.3
// - UEFI 2.10 §3.3 - SecureBoot and SetupMode global variables

use windows_sys::Win32::Foundation::{
    ERROR_ENVVAR_NOT_FOUND, ERROR_INVALID_FUNCTION, ERROR_PRIVILEGE_NOT_HELD,
};

use crate::error::{Result, WinApiError};
use crate::ffi;
use crate::parse::{Guid, to_wide_nul};
use crate::privilege::{self, Privilege};
use crate::vars::{EFI_GLOBAL_VARIABLE, FlagState, ReadableVar, SecureBootStatus, WritableBootVar};

/// Largest variable value read.
pub const MAX_VAR_READ: usize = 64 * 1024;

/// How the running system was started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirmwareMode {
    /// UEFI.
    Uefi,
    /// Legacy BIOS (or a dual-mode machine started in legacy mode).
    LegacyBios,
}

fn code_of(e: &std::io::Error) -> Option<u32> {
    e.raw_os_error().and_then(|c| u32::try_from(c).ok())
}

fn wide(s: &str) -> Result<Vec<u16>> {
    to_wide_nul(s).ok_or(WinApiError::Refused {
        reason: "name contains NUL",
    })
}

/// Tells UEFI from legacy BIOS with Microsoft's documented test (spec §9):
/// read a variable with an empty name in the all-zero namespace. It fails
/// with `ERROR_INVALID_FUNCTION` on legacy BIOS and with a
/// firmware-specific error on UEFI.
///
/// Enables `SeSystemEnvironmentPrivilege` for the read only, because the
/// read needs it (spec §9); it is disabled again on return. A missing
/// privilege is an error, not a mode.
pub fn firmware_mode() -> Result<FirmwareMode> {
    let _p = privilege::scoped(Privilege::SystemEnvironment)?;
    let name = wide("")?;
    let guid = wide(&Guid::default().to_braced_upper())?;
    match ffi::get_firmware_variable(&name, &guid, 16) {
        Ok(_) => Ok(FirmwareMode::Uefi),
        Err(e) => match code_of(&e) {
            Some(ERROR_INVALID_FUNCTION) => Ok(FirmwareMode::LegacyBios),
            Some(ERROR_PRIVILEGE_NOT_HELD) => Err(WinApiError::PrivilegeNotHeld {
                privilege: Privilege::SystemEnvironment.name(),
            }),
            _ => Ok(FirmwareMode::Uefi),
        },
    }
}

/// A firmware variable's value and attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareValue {
    /// The value bytes.
    pub data: Vec<u8>,
    /// The attributes the firmware reported.
    pub attributes: u32,
}

/// Access to the EFI global variables on a UEFI system.
///
/// `SeSystemEnvironmentPrivilege` is enabled only for the duration of each
/// read or write and disabled again afterwards (AC-6; NIST-001), so
/// holding a `FirmwareVars` leaves no privilege enabled.
#[derive(Debug)]
pub struct FirmwareVars {
    _private: (),
}

impl FirmwareVars {
    /// Checks that the firmware is UEFI (and that the token holds the
    /// privilege, which the check uses).
    pub fn open() -> Result<Self> {
        match firmware_mode()? {
            FirmwareMode::Uefi => Ok(Self { _private: () }),
            FirmwareMode::LegacyBios => Err(WinApiError::NotUefi),
        }
    }

    /// Reads `var`. A variable that does not exist is `Ok(None)`.
    pub fn get(&self, var: ReadableVar) -> Result<Option<FirmwareValue>> {
        let name = wide(&var.name())?;
        let guid = wide(&EFI_GLOBAL_VARIABLE.to_braced_upper())?;
        let _p = privilege::scoped(Privilege::SystemEnvironment)?;
        match ffi::get_firmware_variable(&name, &guid, MAX_VAR_READ) {
            Ok((data, attributes)) => Ok(Some(FirmwareValue { data, attributes })),
            Err(e) if code_of(&e) == Some(ERROR_ENVVAR_NOT_FOUND) => Ok(None),
            Err(e) => Err(WinApiError::os("read firmware variable", e)),
        }
    }

    /// Writes `BootOrder` or `Boot####` with NV + BS + RT. Empty values
    /// (which would delete the variable) and values over
    /// [`crate::vars::MAX_BOOT_VAR_WRITE`] bytes are refused before the
    /// call. `BootOrder` must be a whole number of UINT16 entries
    /// (`uefi-boot-manager.md` §10.3).
    pub fn set_boot_var(&mut self, var: WritableBootVar, data: &[u8]) -> Result<()> {
        if var == WritableBootVar::BootOrder && !data.len().is_multiple_of(2) {
            return Err(WinApiError::Refused {
                reason: "BootOrder length is not a multiple of 2",
            });
        }
        let _p = privilege::scoped(Privilege::SystemEnvironment)?;
        ffi::set_boot_variable(var, data).map_err(|e| WinApiError::os("write boot variable", e))
    }

    /// Reads `SecureBoot` and `SetupMode` (UEFI §3.3). Values that are not
    /// one byte of 0 or 1 are reported as [`FlagState::Unrecognised`].
    pub fn secure_boot_status(&self) -> Result<SecureBootStatus> {
        let read = |v| {
            self.get(v)
                .map(|o| FlagState::from_value(o.as_ref().map(|x| x.data.as_slice())))
        };
        Ok(SecureBootStatus {
            secure_boot: read(ReadableVar::SecureBoot)?,
            setup_mode: read(ReadableVar::SetupMode)?,
        })
    }
}
