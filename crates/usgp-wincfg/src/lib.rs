//! usgp-wincfg: unattend template model/render, driver package ingest (ZIP/CAB).
//!
//! Status: stub (M0). See docs/ARCHITECTURE.md.
//! Filled in: M4 (docs/ROADMAP.md section 3).

// Parses untrusted input: indexing and slicing that can panic are denied
// (CLAUDE.md, Engineering Rules: parsers never panic on input).
#![deny(clippy::indexing_slicing)]

pub mod archive;
pub mod dism;
pub mod unattend;

pub use archive::{
    ArchiveError, ArchiveKind, ArchiveLimits, ArchiveMode, ArchiveReport, ExtractSink, ReadAt,
    RelPath, extract_archive, extract_archive_mode, validate_archive, validate_archive_mode,
};
