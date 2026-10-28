//! Console input without echo, so that a session code typed at the device
//! is not shown on screen (plan §1.2(a)).
//!
//! SR-3: `GetStdHandle`, `GetConsoleMode` and `SetConsoleMode` are not
//! summarised in topic 23. Only the echo flag is changed, and the previous
//! mode is restored when the guard is dropped.

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-6 (Authentication Feedback) - typed codes not echoed
// - DECISION: docs/decisions/0019-windows-api-binding.md

use windows_sys::Win32::System::Console::ENABLE_ECHO_INPUT;

use crate::error::{Result, WinApiError};
use crate::ffi;

/// Echo is off while this lives; dropping it restores the previous mode.
#[derive(Debug)]
pub struct EchoOff {
    previous: u32,
}

/// Turns off echo of standard-input characters. Fails if standard input
/// is not a console, so the caller never prompts for a code without the
/// echo turned off.
pub fn hide_input() -> Result<EchoOff> {
    let previous = ffi::stdin_console_mode().map_err(|e| WinApiError::os("get console mode", e))?;
    ffi::set_stdin_console_mode(previous & !ENABLE_ECHO_INPUT)
        .map_err(|e| WinApiError::os("set console mode", e))?;
    Ok(EchoOff { previous })
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // Best effort: nothing can be reported from `drop`.
        let _ = ffi::set_stdin_console_mode(self.previous);
    }
}
