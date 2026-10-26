//! usgp-dhcp: sans-IO DHCP/PXE parser and ProxyDHCP responder logic.
//!
//! ProxyDHCP only: this crate never leases addresses. Any reply that would
//! assign one (`yiaddr` != 0 in an OFFER/ACK) is a defect
//! (docs/decisions/0003-proxy-dhcp-only.md).
//!
//! Status: stub (M0). See docs/ARCHITECTURE.md.
//! Filled in: M1 (docs/ROADMAP.md section 3).

// Parses untrusted input: indexing and slicing that can panic are denied
// (CLAUDE.md, Engineering Rules: parsers never panic on input).
#![deny(clippy::indexing_slicing)]
