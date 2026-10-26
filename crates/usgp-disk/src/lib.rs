//! usgp-disk: disk inventory model, GPT/MBR layout plans, layout executor trait.
//!
//! Status: stub (M0). See docs/ARCHITECTURE.md.
//! Filled in: M3 (docs/ROADMAP.md section 3).

// Parses untrusted input: indexing and slicing that can panic are denied
// (CLAUDE.md, Engineering Rules: parsers never panic on input).
#![deny(clippy::indexing_slicing)]
