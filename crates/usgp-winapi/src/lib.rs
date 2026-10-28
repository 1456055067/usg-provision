//! usgp-winapi: Windows API wrappers for the pre-boot agent.
//!
//! Status: skeleton (M3 WU-0). The safe wrappers (disk, volume, file
//! system, firmware, system, network, console, privilege) are filled in by
//! M3 WU-5. See docs/decisions/0019-windows-api-binding.md.
//!
//! Rules (decision 0019):
//!
//! - This is the only crate that may depend on `windows-sys`.
//! - Every `unsafe` block lives in `src/ffi.rs`, and each carries a
//!   `// SAFETY:` comment. The rest of the crate denies `unsafe_code`.
//! - Where `std` covers an operation, `std` is used instead of FFI.
//! - Variable-length structures returned by Windows are copied into owned
//!   buffers and parsed by bounds-checked safe code.
//!
//! On targets other than Windows the crate is empty.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-15 (Development Process, Standards, and Tools),
//   SI-16 (Memory Protection) - unsafe confined to one reviewed module
// - DECISION: docs/decisions/0019-windows-api-binding.md

// Windows returns variable-length structures that are parsed here: indexing
// and slicing that can panic are denied (CLAUDE.md, Engineering Rules).
#![deny(clippy::indexing_slicing)]

#[cfg(windows)]
mod ffi;
