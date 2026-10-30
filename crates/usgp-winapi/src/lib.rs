//! usgp-winapi: Windows API wrappers for the pre-boot agent.
//!
//! See docs/decisions/0019-windows-api-binding.md. Semantics follow
//! `specs/standards/windows-storage-firmware-api.md`; structure layouts and
//! numeric constants come only from `windows-sys` (OPEN-WAPI-1).
//!
//! Rules (decision 0019):
//!
//! - This is the only crate that may depend on `windows-sys`.
//! - Every `unsafe` block lives in `src/ffi.rs`, and each carries a
//!   `// SAFETY:` comment. The rest of the crate denies `unsafe_code`.
//! - Where `std` covers an operation, `std` is used instead of FFI (raw
//!   disk I/O, opening devices).
//! - Variable-length structures returned by Windows are copied into owned
//!   buffers and parsed by bounds-checked safe code ([`parse`]).
//! - No code path writes a Secure Boot variable: the only firmware write
//!   takes a [`vars::WritableBootVar`] (`BootOrder` or `Boot####`).
//!
//! Modules on Windows:
//!
//! - [`disk`]: SetupAPI enumeration, storage properties, geometry, length,
//!   layout, raw I/O and property update;
//! - [`volume`]: volumes, extents, drive letters, file-system name, and
//!   lock and dismount before a wipe;
//! - [`firmware`]: firmware mode, boot variables, read-only Secure Boot
//!   state; [`privilege`];
//! - [`system`], [`net`], [`console`]: architecture and memory, adapters
//!   and addresses, input without echo;
//! - [`fsquery`] and [`manifest`]: read-only file metadata and the
//!   canonical tree manifest (`examples/tree_manifest.rs`).
//!
//! - [`acl`], [`account`] and [`memlock`] (M4): a SYSTEM-only protected
//!   DACL, the built-in Administrator (RID 500) and a locked page for its
//!   password (topic 23 §20, §30, §31);
//! - [`format`] (with the OS-neutral [`diskpart`]): formatting one new
//!   volume with DiskPart, shared by the agent and the VHD tests;
//! - [`fs`]: the tree writer behind `winsink::WinSink` (feature `sink`,
//!   which brings `usgp-image`'s `ApplySink`).
//!
//! On targets other than Windows the crate holds only its pure, OS-neutral
//! parts: [`parse`] (built for every target so its checks can be fuzzed,
//! SEC-004) and, in tests, the other pure helpers.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-15 (Development Process, Standards, and Tools),
//   SI-16 (Memory Protection) - unsafe confined to one reviewed module
// - DECISION: docs/decisions/0019-windows-api-binding.md

// Windows returns variable-length structures that are parsed here: indexing
// and slicing that can panic are denied (CLAUDE.md, Engineering Rules).
#![deny(clippy::indexing_slicing)]

#[cfg(windows)]
mod ffi;
#[cfg(windows)]
mod layout;
#[cfg(any(windows, test))]
mod privscope;

// Every target: the bounds checks that guard the FFI (descriptor and
// reparse-buffer checks) are fuzzed off Windows too (SEC-004).
pub mod parse;

#[cfg(any(windows, test))]
pub mod account;
#[cfg(any(windows, test))]
pub mod acl;
#[cfg(any(windows, test))]
pub mod diskpart;
#[cfg(any(windows, test))]
pub mod fsvalues;
#[cfg(any(windows, test))]
pub mod manifest_text;
#[cfg(any(windows, test))]
pub mod netaddr;
#[cfg(any(windows, test))]
pub mod paths;
#[cfg(any(windows, test))]
pub mod vars;

#[cfg(windows)]
pub mod console;
#[cfg(windows)]
pub mod disk;
#[cfg(windows)]
pub mod error;
#[cfg(windows)]
pub mod firmware;
#[cfg(windows)]
pub mod format;
#[cfg(windows)]
pub mod fs;
#[cfg(windows)]
pub mod fsquery;
#[cfg(windows)]
pub mod manifest;
#[cfg(windows)]
pub mod memlock;
#[cfg(windows)]
pub mod net;
#[cfg(windows)]
pub mod privilege;
#[cfg(windows)]
pub mod system;
#[cfg(windows)]
pub mod volume;

#[cfg(all(windows, feature = "sink"))]
pub mod winsink;

#[cfg(windows)]
pub use error::{Result, WinApiError};
