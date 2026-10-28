//! usgp-image: WIM check, XPRESS decoding and content digests.
//!
//! Status: M2. [`check_wim`] checks an uploaded WIM file before it becomes
//! ready (REQ-IMG-037/038): header, flags, resource bounds, lookup table,
//! XML image information, integrity table and metadata hashes, with every
//! refusal named by a [`WimError`] reason code (REQ-IMG-022).
//! [`check_pe`] picks the usable image of a preinstall environment
//! (REQ-PE-004). [`chunks::ContentHasher`] computes the content store's
//! total and per-chunk SHA-256 in one pass (REQ-IMG-050).
//!
//! M2 accepts uncompressed and XPRESS files only (decision 0014).
//!
//! M3 adds applying one image: [`wim::metadata`] parses an image's
//! metadata into a validated tree, and [`apply`] verifies and applies it
//! through an [`apply::ApplySink`], reading the file only through
//! verified content chunks ([`wim::remote::ChunkSource`]). See
//! docs/ARCHITECTURE.md.

// Parses untrusted input: indexing and slicing that can panic are denied
// (CLAUDE.md, Engineering Rules: parsers never panic on input).
#![deny(clippy::indexing_slicing)]

pub mod apply;
pub mod chunks;
pub mod codec;
pub mod error;
pub mod limits;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;
pub mod wim;

pub use error::WimError;
pub use limits::WimLimits;
pub use wim::{
    Compression, EditionInfo, NoProgress, Progress, WimSummary, WimXmlImage, XmlLeaf, check_pe,
    check_wim,
};
pub mod facts;
pub mod os_support;
