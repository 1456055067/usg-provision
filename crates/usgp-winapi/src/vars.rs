//! Names of the UEFI variables this crate may read or write.
//!
//! Writes are limited by type: [`WritableBootVar`] can name only
//! `BootOrder` and `Boot####` in the EFI global namespace, and it is the
//! only name the write path in `ffi.rs` accepts. No value of any type here
//! names `PK`, `KEK`, `db`, `dbx`, `SecureBoot` or `SetupMode` for writing,
//! so no code path can change Secure Boot state (decision 0018 item 5;
//! plan §1.2(a)).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   Secure Boot variables are never written; CM-5 (Access Restrictions for
//   Change) - the write path names only boot-option variables
// - SPEC: specs/standards/uefi-boot-manager.md §4, §10.3
// - SPEC: specs/standards/windows-storage-firmware-api.md §9
// - UEFI 2.10 §3.3 - globally defined variables (SecureBoot, SetupMode)

use crate::parse::Guid;

/// `EFI_GLOBAL_VARIABLE`, `{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}`
/// (`uefi-boot-manager.md` §10.3).
pub const EFI_GLOBAL_VARIABLE: Guid = Guid {
    data1: 0x8BE4_DF61,
    data2: 0x93CA,
    data3: 0x11D2,
    data4: [0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C],
};

/// `EFI_VARIABLE_NON_VOLATILE` (`uefi-boot-manager.md` §10.3;
/// `windows-storage-firmware-api.md` §9).
pub const ATTR_NON_VOLATILE: u32 = 0x01;
/// `EFI_VARIABLE_BOOTSERVICE_ACCESS`.
pub const ATTR_BOOTSERVICE_ACCESS: u32 = 0x02;
/// `EFI_VARIABLE_RUNTIME_ACCESS`.
pub const ATTR_RUNTIME_ACCESS: u32 = 0x04;
/// NV + BS + RT, the attributes of `Boot####` and `BootOrder`
/// (`uefi-boot-manager.md` §10.3).
pub const BOOT_VAR_ATTRIBUTES: u32 =
    ATTR_NON_VOLATILE | ATTR_BOOTSERVICE_ACCESS | ATTR_RUNTIME_ACCESS;

/// Largest value accepted for a boot-variable write. A `Boot####` load
/// option or a `BootOrder` list larger than this is refused before the
/// call. (No standard limit is given; this bounds what the agent writes.)
pub const MAX_BOOT_VAR_WRITE: usize = 64 * 1024;

/// A global-namespace variable that may be written: only these two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WritableBootVar {
    /// `BootOrder`.
    BootOrder,
    /// `Boot####`, with the option number.
    Boot(u16),
}

impl WritableBootVar {
    /// The variable name (`uefi-boot-manager.md` §10.3: `Boot####` is four
    /// upper-case hexadecimal digits with leading zeros).
    #[must_use]
    pub fn name(self) -> String {
        match self {
            Self::BootOrder => "BootOrder".to_owned(),
            Self::Boot(n) => format!("Boot{n:04X}"),
        }
    }
}

/// A global-namespace variable that may be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadableVar {
    /// `BootOrder`.
    BootOrder,
    /// `Boot####`.
    Boot(u16),
    /// `BootCurrent` (read-only to the OS).
    BootCurrent,
    /// `SecureBoot` (UEFI §3.3; read-only).
    SecureBoot,
    /// `SetupMode` (UEFI §3.3; read-only).
    SetupMode,
}

impl ReadableVar {
    /// The variable name.
    #[must_use]
    pub fn name(self) -> String {
        match self {
            Self::BootOrder => WritableBootVar::BootOrder.name(),
            Self::Boot(n) => WritableBootVar::Boot(n).name(),
            Self::BootCurrent => "BootCurrent".to_owned(),
            Self::SecureBoot => "SecureBoot".to_owned(),
            Self::SetupMode => "SetupMode".to_owned(),
        }
    }
}

impl From<WritableBootVar> for ReadableVar {
    fn from(v: WritableBootVar) -> Self {
        match v {
            WritableBootVar::BootOrder => Self::BootOrder,
            WritableBootVar::Boot(n) => Self::Boot(n),
        }
    }
}

/// The value of a one-byte Secure Boot state flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagState {
    /// The byte is 1.
    On,
    /// The byte is 0.
    Off,
    /// The variable does not exist.
    Absent,
    /// The variable exists but is not exactly one byte of 0 or 1. Callers
    /// must treat this as unknown, never as off.
    Unrecognised,
}

impl FlagState {
    /// Interprets a `SecureBoot` or `SetupMode` value (UEFI §3.3: one byte,
    /// 1 = on, 0 = off). Anything else is [`FlagState::Unrecognised`].
    #[must_use]
    pub fn from_value(value: Option<&[u8]>) -> Self {
        match value {
            None => Self::Absent,
            Some([1]) => Self::On,
            Some([0]) => Self::Off,
            Some(_) => Self::Unrecognised,
        }
    }
}

/// The platform's Secure Boot state, read only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecureBootStatus {
    /// `SecureBoot`.
    pub secure_boot: FlagState,
    /// `SetupMode`.
    pub setup_mode: FlagState,
}

impl SecureBootStatus {
    /// True only when Secure Boot reports on and setup mode reports off,
    /// the state Microsoft's guidance gives for a platform ready for
    /// Windows (`uefi-secure-boot.md` §3). Every other combination,
    /// including unknown values, is false.
    #[must_use]
    pub fn enforcing(&self) -> bool {
        self.secure_boot == FlagState::On && self.setup_mode == FlagState::Off
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_var_names() {
        assert_eq!(WritableBootVar::BootOrder.name(), "BootOrder");
        assert_eq!(WritableBootVar::Boot(1).name(), "Boot0001");
        assert_eq!(WritableBootVar::Boot(0x0A02).name(), "Boot0A02");
        assert_eq!(WritableBootVar::Boot(0xFFFF).name(), "BootFFFF");
    }

    #[test]
    fn no_writable_name_is_a_secure_boot_variable() {
        // Exhaustive over every value the write type can hold.
        let protected = [
            "PK",
            "KEK",
            "db",
            "dbx",
            "dbt",
            "dbr",
            "SecureBoot",
            "SetupMode",
        ];
        let all = core::iter::once(WritableBootVar::BootOrder)
            .chain((0..=u16::MAX).map(WritableBootVar::Boot));
        for v in all {
            let n = v.name();
            assert!(
                n == "BootOrder" || (n.len() == 8 && n.starts_with("Boot")),
                "{n}"
            );
            assert!(!protected.iter().any(|p| p.eq_ignore_ascii_case(&n)), "{n}");
        }
    }

    #[test]
    fn the_only_firmware_write_takes_a_writable_boot_var() {
        // Source check, run on every host: ffi.rs makes exactly one
        // firmware-variable write call, inside `set_boot_variable`, whose
        // only name input is a `WritableBootVar`.
        let ffi = include_str!("ffi.rs");
        assert_eq!(ffi.matches("SetFirmwareEnvironmentVariableExW(").count(), 1);
        assert_eq!(ffi.matches("SetFirmwareEnvironmentVariable").count(), 2);
        let start = ffi.find("pub(crate) fn set_boot_variable(var: WritableBootVar, data: &[u8])");
        let call = ffi.find("SetFirmwareEnvironmentVariableExW(");
        let end = start
            .and_then(|s| ffi.get(s..))
            .and_then(|t| t.find("\n}\n"));
        assert!(matches!((start, call, end), (Some(s), Some(c), Some(e)) if s < c && c < s + e));
        // No other crate source names the write function.
        for other in [
            include_str!("disk.rs"),
            include_str!("volume.rs"),
            include_str!("firmware.rs"),
            include_str!("privilege.rs"),
        ] {
            assert!(!other.contains("SetFirmwareEnvironmentVariable"));
        }
    }

    #[test]
    fn global_guid_text() {
        assert_eq!(
            EFI_GLOBAL_VARIABLE.to_braced_upper(),
            "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"
        );
        assert_eq!(BOOT_VAR_ATTRIBUTES, 0x7);
    }

    #[test]
    fn secure_boot_flags_fail_closed() {
        assert_eq!(FlagState::from_value(Some(&[1])), FlagState::On);
        assert_eq!(FlagState::from_value(Some(&[0])), FlagState::Off);
        assert_eq!(FlagState::from_value(None), FlagState::Absent);
        assert_eq!(FlagState::from_value(Some(&[2])), FlagState::Unrecognised);
        assert_eq!(
            FlagState::from_value(Some(&[1, 0])),
            FlagState::Unrecognised
        );
        assert_eq!(FlagState::from_value(Some(&[])), FlagState::Unrecognised);
        let on = SecureBootStatus {
            secure_boot: FlagState::On,
            setup_mode: FlagState::Off,
        };
        assert!(on.enforcing());
        for (sb, sm) in [
            (FlagState::On, FlagState::On),
            (FlagState::On, FlagState::Absent),
            (FlagState::Unrecognised, FlagState::Off),
            (FlagState::Off, FlagState::Off),
        ] {
            assert!(
                !SecureBootStatus {
                    secure_boot: sb,
                    setup_mode: sm
                }
                .enforcing()
            );
        }
    }
}
