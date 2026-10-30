//! usgp-common: config loading and validation, error base, ids, time, tracing init.
//!
//! M1 contents:
//!
//! - [`digest`]: the [`Sha256Digest`] value type (hex form, serde). It holds
//!   no cryptography; digests are computed only by `usgp-crypto`.
//! - [`crc32`]: CRC-32 (GPT and ZIP), moved from `usgp-disk` in M4.
//! - [`config`]: bounded, strict reading of operator-owned files.
//! - [`event`]: fixed-shape audit events on the `audit` tracing target.
//! - [`process`]: effective/real uid and host name for audit records and
//!   trust checks.
//! - [`telemetry`]: JSON-lines tracing subscriber.
//!
//! See docs/ARCHITECTURE.md.

// Reads operator files and parses hex from them: indexing and slicing that
// can panic are denied (CLAUDE.md, Engineering Rules).
#![deny(clippy::indexing_slicing)]

pub mod config;
pub mod crc32;
pub mod digest;
pub mod event;
pub mod process;
pub mod telemetry;

pub use digest::Sha256Digest;
