//! usgp-preboot-agent: the agent that runs in the operator's Windows PE on
//! the target device (M3 plan WU-12, sections 1.1, 3.1 to 3.4).
//!
//! Flow ([`app::run`]):
//!
//! 1. Start-up: the FIPS self-test, the public `agent.toml`
//!    ([`config`]), the firmware and architecture check (REQ-PE-020), a
//!    bounded wait for a DHCP address (REQ-PE-014) and the TLS connection to
//!    the server with the configured trust anchor (REQ-PE-015).
//! 2. The device session ([`session`]): open, display code, operator code
//!    (echo off) or console approval, package choice, disk choice (refused
//!    disks shown with their reason), and the separate wipe confirmation.
//!    Cancel is offered only before the wipe confirmation.
//! 3. The job: the `usgp-deploy` engine on the platform ([`host`]), with
//!    progress and a persistent error screen ([`ui`]).
//! 4. Restart after success.
//!
//! The device holds no secret (decision 0020): the session token and the
//! typed code live only in memory, in zeroizing buffers, and travel only
//! inside TLS. All Windows calls are in `usgp-winapi` (decision 0019); this
//! crate forbids `unsafe`. Off Windows the binary uses the engine's
//! simulated platform, for CI end-to-end tests ([`sim`]).

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 (Access Enforcement) - nothing is listed or written
//   before the session is authorised and the wipe confirmed.
// - NIST 800-53: IA-3 (Device Identification and Authentication),
//   SC-8 (Transmission Confidentiality and Integrity), SC-23 (Session
//   Authenticity) - server-authenticated TLS with pinned anchors; bearer
//   session token only inside TLS.
// - NIST 800-53: SC-13 (Cryptographic Protection) - FIPS self-test first.
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   the signed plan and every chunk verified by the engine before use.
// - NIST 800-53: SI-10 (Information Input Validation) - bounded HTTP and
//   JSON parsing; bounded console input.
// - NIST 800-53: SI-11 (Error Handling) - persistent named errors; no
//   secrets on screen or in reports.
// - SPEC: specs/preinstall-env.md#REQ-PE-013..020
// - SPEC: specs/targeting.md#REQ-TGT-004..006, #REQ-TGT-008..015
// - SPEC: specs/disk.md#REQ-DISK-001..006, #REQ-DISK-011, #REQ-DISK-015,
//   #REQ-DISK-016
// - SPEC: specs/progress.md#REQ-JOB-002..005, #REQ-JOB-014
// - DECISION: docs/decisions/0001, 0018, 0019, 0020, 0021

// Parses network input and console input: indexing and slicing that can
// panic are denied (CLAUDE.md, Engineering Rules).
#![deny(clippy::indexing_slicing)]

pub mod app;
pub mod client;
pub mod config;
pub mod disks;
pub mod host;
pub mod http;
pub mod link;
pub mod selftest;
pub mod session;
pub mod ui;

#[cfg(windows)]
pub mod platform_win;
#[cfg(any(not(windows), feature = "sim"))]
pub mod sim;
#[cfg(any(windows, test))]
pub mod wintools;

/// The agent's version, sent in the session hello.
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
