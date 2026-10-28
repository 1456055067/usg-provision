//! System facts the agent checks at start and reports in its hello:
//! processor architecture, physical memory and the system directory.
//!
//! The executable's own path comes from `std::env::current_exe` (decision
//! 0019 item 3: `std` first); no FFI is used for it.
//!
//! SR-3: `GetNativeSystemInfo`, `GlobalMemoryStatusEx` and
//! `GetSystemDirectoryW` are not summarised in topic 23. Only plain value
//! reads are relied on (spec request in the WU-5 notes).

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-8 (System Component Inventory) - architecture and
//   memory reported with the device
// - SPEC: specs/preinstall-env.md REQ-PE-020 (x64), REQ-PE-018 (memory)
// - DECISION: docs/decisions/0019-windows-api-binding.md

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows_sys::Win32::System::SystemInformation::{
    PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_ARM64, PROCESSOR_ARCHITECTURE_INTEL,
};

use crate::error::{Result, WinApiError};
use crate::ffi;

/// Native processor architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    /// x64 (`PROCESSOR_ARCHITECTURE_AMD64`).
    X64,
    /// x86 (`PROCESSOR_ARCHITECTURE_INTEL`).
    X86,
    /// Arm64 (`PROCESSOR_ARCHITECTURE_ARM64`).
    Arm64,
    /// Anything else, raw. Treated as unsupported.
    Other(u16),
}

impl Arch {
    /// Maps a raw `wProcessorArchitecture`.
    #[must_use]
    pub fn from_raw(v: u16) -> Self {
        if v == PROCESSOR_ARCHITECTURE_AMD64 {
            Self::X64
        } else if v == PROCESSOR_ARCHITECTURE_INTEL {
            Self::X86
        } else if v == PROCESSOR_ARCHITECTURE_ARM64 {
            Self::Arm64
        } else {
            Self::Other(v)
        }
    }
}

/// The machine's native architecture (not the process's, should they
/// differ).
#[must_use]
pub fn native_arch() -> Arch {
    Arch::from_raw(ffi::native_processor_architecture())
}

/// Total physical memory in bytes.
pub fn total_memory_bytes() -> Result<u64> {
    ffi::total_physical_memory().map_err(|e| WinApiError::os("query memory status", e))
}

/// The system directory (for example `X:\Windows\System32` in Windows
/// PE), used to locate the system's own tools by full path.
pub fn system_directory() -> Result<PathBuf> {
    let units = ffi::system_directory().map_err(|e| WinApiError::os("get system directory", e))?;
    Ok(PathBuf::from(OsString::from_wide(&units)))
}

/// This executable's path (`std::env::current_exe`).
pub fn current_executable() -> Result<PathBuf> {
    std::env::current_exe().map_err(|e| WinApiError::os("get executable path", e))
}
