//! The only module in the workspace allowed to hold `unsafe` code
//! (decision 0019 item 2).
//!
//! Every `unsafe` block here carries a `// SAFETY:` comment
//! (`clippy::undocumented_unsafe_blocks` is denied). Calls go through
//! `windows-sys` declarations only. Safe wrappers in the other modules
//! never use `unsafe` themselves.
//!
//! Status: skeleton (M3 WU-0). The FFI calls are added by M3 WU-5. The
//! test below is the WU-0 link probe: it shows that `windows-sys` links
//! through `windows-link` (raw-dylib) in a static-CRT build.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-16 (Memory Protection), SA-15 (Development Process,
//   Standards, and Tools)
// - DECISION: docs/decisions/0019-windows-api-binding.md

#![allow(unsafe_code)]

#[cfg(test)]
mod tests {
    #[test]
    fn windows_sys_links_and_agrees_with_std() {
        // SAFETY: `GetCurrentProcessId` takes no arguments, has no
        // preconditions, cannot fail, and only returns the caller's
        // process id.
        let id = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() };
        assert_eq!(id, std::process::id());
    }
}
