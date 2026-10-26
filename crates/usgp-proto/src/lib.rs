//! usgp-proto: wire types shared by server, relay, agent, and cli.
//!
//! Status: stub (M0). See docs/ARCHITECTURE.md.
//! Filled in: M2 (session and plan types in M3) (docs/ROADMAP.md section 3).

// Parses untrusted input: indexing and slicing that can panic are denied
// (CLAUDE.md, Engineering Rules: parsers never panic on input).
#![deny(clippy::indexing_slicing)]
