//! usgp-dhcp: sans-IO DHCP/PXE parser and ProxyDHCP responder logic.
//!
//! ProxyDHCP only: this crate never leases addresses
//! (docs/decisions/0003-proxy-dhcp-only.md). The invariant holds by
//! construction: the reply builder ([`reply::ProxyReply`]) has no `yiaddr`
//! input and no API for lease, router or subnet options, and its encoder
//! writes `yiaddr` = 0.0.0.0 from a constant.
//!
//! Flow: [`parse_request`] turns bytes into a [`Request`] (or a
//! [`ParseError`]; the caller drops silently). [`respond`] classifies the
//! request against a [`BootPolicy`] and returns a [`Decision`]: a
//! [`Reply`] with its [`Destination`], or a [`DropReason`]. [`handle`] does
//! both. Nothing here performs I/O or reads the clock.
//!
//! Filled in: M1 (docs/ROADMAP.md section 3; plan WU-4).

// Parses untrusted input: indexing and slicing that can panic are denied
// (CLAUDE.md, Engineering Rules: parsers never panic on input).
#![deny(clippy::indexing_slicing)]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation)
// - NIST 800-53: CM-7 (Least Functionality)
// - SPEC: specs/boot-network.md#REQ-BOOT-001..007, #REQ-BOOT-010..012,
//   #REQ-BOOT-020..022, #REQ-BOOT-051, #REQ-BOOT-052
// - DECISION: docs/decisions/0003-proxy-dhcp-only.md

pub mod craft;
pub mod error;
pub mod ident;
pub mod options;
pub mod packet;
pub mod reply;
pub mod responder;

pub use error::ParseError;
pub use ident::{ArchList, ClientArch, Guid, IdentError, MacAddr};
pub use packet::{BootItem, MessageType, Request, parse_request};
pub use reply::{BuildError, ReplyKind, inspect_reply};
pub use responder::{
    BootPolicy, Decision, Destination, DropReason, ListenPort, Reply, ResponderContext, handle,
    respond,
};
