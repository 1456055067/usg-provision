//! The crate's error type.
//!
//! Errors carry the operation name and the OS error code. They never carry
//! buffer contents or firmware-variable values.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-11 (Error Handling) - operation and OS code only, no
//   data

use core::fmt;
use std::io;

use crate::parse::{ParseError, ReparseRefusal};

/// Why a Windows call failed or was refused.
#[derive(Debug)]
#[non_exhaustive]
pub enum WinApiError {
    /// The OS reported an error.
    Os {
        /// What was being done.
        op: &'static str,
        /// The OS error.
        source: io::Error,
    },
    /// The OS returned a structure that failed the bounds checks.
    Malformed {
        /// What was being parsed.
        op: &'static str,
        /// The parse failure.
        source: ParseError,
    },
    /// A size or count reported by the OS is above this crate's limit.
    LimitExceeded {
        /// What exceeded the limit.
        what: &'static str,
        /// The limit.
        limit: u64,
    },
    /// The process token does not hold a privilege it needs (spec §10).
    PrivilegeNotHeld {
        /// The privilege.
        privilege: &'static str,
    },
    /// The firmware is not UEFI, so firmware variables are unavailable
    /// (spec §9).
    NotUefi,
    /// A device opened by number is not the device asked for (disk numbers
    /// are not stable, spec §7).
    DeviceMismatch {
        /// What did not match.
        what: &'static str,
    },
    /// Stored reparse data was refused (topic 24; only relative symbolic
    /// links are applied, OPEN-WIM-12).
    Reparse(ReparseRefusal),
    /// A short name could not be set; the OS code is kept. Disabled 8.3
    /// generation is not by itself a cause: CI run 40958577980 saw an
    /// explicit set succeed on such a volume (OPEN-WAPI-9, topic 23 §21).
    /// Persistent: the apply stops and does not continue without the name.
    ShortNameNotSet {
        /// OS error code, if any.
        os_code: Option<i32>,
    },
    /// A request this crate refuses by policy (for example, an unaligned or
    /// out-of-range write, or the Windows PE system letter).
    Refused {
        /// Why.
        reason: &'static str,
    },
    /// A local-account call (`NetUserGetInfo`, `NetUserSetInfo`) failed
    /// with this `NET_API_STATUS` (topic 23 §30.1: the return value is the
    /// error). `NERR_PasswordTooShort` means "policy rejected" (§30.1).
    NetApi {
        /// What was being done.
        op: &'static str,
        /// The status value.
        code: u32,
    },
    /// Memory could not be locked, even after raising the working-set
    /// minimum as topic 23 §31 describes (OPEN-WAPI-24). The secret is not
    /// placed in unlocked memory: the caller fails closed.
    MemoryNotLocked {
        /// OS error code of the last attempt, if any.
        os_code: Option<i32>,
    },
    /// An unlock found pages no longer locked (`ERROR_NOT_LOCKED`): the
    /// lock silently failed or was undone (topic 23 §31 [reading]).
    LockLost,
}

impl WinApiError {
    pub(crate) fn os(op: &'static str, source: io::Error) -> Self {
        Self::Os { op, source }
    }

    pub(crate) fn malformed(op: &'static str, source: ParseError) -> Self {
        Self::Malformed { op, source }
    }

    /// The raw OS error code, when the error came from the OS.
    #[must_use]
    pub fn os_code(&self) -> Option<i32> {
        match self {
            Self::Os { source, .. } => source.raw_os_error(),
            _ => None,
        }
    }
}

impl fmt::Display for WinApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Os { op, source } => write!(f, "{op} failed: {source}"),
            Self::Malformed { op, source } => write!(f, "{op}: malformed result: {source}"),
            Self::LimitExceeded { what, limit } => write!(f, "{what} exceeds the limit {limit}"),
            Self::PrivilegeNotHeld { privilege } => {
                write!(f, "the process token does not hold {privilege}")
            }
            Self::NotUefi => f.write_str("firmware is not UEFI"),
            Self::DeviceMismatch { what } => write!(f, "device mismatch: {what}"),
            Self::Reparse(r) => write!(f, "reparse data refused: {r}"),
            Self::ShortNameNotSet { os_code } => write!(
                f,
                "short name could not be set on the target volume (OS code {os_code:?})"
            ),
            Self::Refused { reason } => write!(f, "refused: {reason}"),
            Self::NetApi { op, code } => write!(f, "{op} failed: status {code}"),
            Self::MemoryNotLocked { os_code } => {
                write!(f, "memory could not be locked (OS code {os_code:?})")
            }
            Self::LockLost => f.write_str("locked memory was found unlocked"),
        }
    }
}

impl std::error::Error for WinApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Os { source, .. } => Some(source),
            Self::Malformed { source, .. } => Some(source),
            Self::Reparse(r) => Some(r),
            _ => None,
        }
    }
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, WinApiError>;
