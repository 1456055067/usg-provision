//! usgp-wincfg: unattend template model/render, driver package ingest (ZIP/CAB).
//!
//! Status: stub (M0). See docs/ARCHITECTURE.md.
//! Filled in: M4 (docs/ROADMAP.md section 3).

// Parses untrusted input: indexing and slicing that can panic are denied
// (CLAUDE.md, Engineering Rules: parsers never panic on input).
#![deny(clippy::indexing_slicing)]
