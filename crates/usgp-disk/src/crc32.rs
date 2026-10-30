//! CRC-32 for GPT headers and partition entry arrays.
//!
//! The implementation moved to [`usgp_common::crc32`] in M4 (plan WU-2) so
//! that the ZIP reader in `usgp-wincfg` shares it; this module re-exports it
//! unchanged for existing callers.

pub use usgp_common::crc32::{Crc32, crc32};
