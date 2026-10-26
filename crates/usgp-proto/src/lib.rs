//! usgp-proto: wire types shared by server, relay, agent, and cli.
//!
//! M1 contents: the boot manifest ([`BootManifest`]) and the published boot
//! file name type ([`BootFileName`]). Session and plan types arrive in
//! M2/M3 (docs/ROADMAP.md section 3). See docs/ARCHITECTURE.md.

// Parses untrusted input: indexing and slicing that can panic are denied
// (CLAUDE.md, Engineering Rules: parsers never panic on input).
#![deny(clippy::indexing_slicing)]

pub mod boot_file_name;
pub mod boot_manifest;

pub use boot_file_name::{BootFileName, BootFileNameError};
pub use boot_manifest::{BootManifest, DigestName, ManifestEntry, ManifestError};
