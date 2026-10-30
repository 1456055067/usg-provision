//! The engine's view of the server: chunk fetch (plan section 3.3) and
//! progress reports (plan section 3.4).
//!
//! The pre-boot agent implements [`ServerLink`] over its HTTPS session
//! (server-authenticated TLS through `usgp-crypto`, bearer token). The
//! implementation owns the transport limits: connect, read and idle
//! timeouts, and a body of at most one content chunk (8 MiB) for chunk
//! responses. The engine owns retry (REQ-JOB-007) and verification: chunk
//! bytes from the link are untrusted until their SHA-256 matches the
//! signed content manifest.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-8 (Transmission Confidentiality and Integrity) - the
//   implementation uses the TLS session; the token never reaches here.
// - NIST 800-53: SI-10 (Information Input Validation) - chunk bytes are
//   untrusted until verified (content.rs).
// - SPEC: specs/progress.md#REQ-JOB-007 (which failures are transient)
// - SPEC: specs/preinstall-env.md#REQ-PE-015, #REQ-PE-016

use usgp_common::Sha256Digest;
use usgp_proto::JobId;
use usgp_proto::progress::{ProgressAckV1, ProgressV1, ProgressV2};

/// Why a server request failed, as the engine needs to know it.
///
/// Only [`LinkError::Transient`] is retried (REQ-JOB-007: integrity
/// failures, refusals and "not found" are not).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LinkError {
    /// Connection failure, timeout, or 503: may succeed if repeated.
    #[error("server not reachable")]
    Transient,
    /// 404: the content or chunk is unknown.
    #[error("not found on the server")]
    NotFound,
    /// 409 or another refusal (for example, the job is not running).
    #[error("refused by the server")]
    Refused,
    /// 500 `integrity_failed`: the server's own copy failed its check.
    #[error("server reported an integrity failure")]
    ServerIntegrity,
    /// The response broke the protocol (bad status, oversized body, bad
    /// JSON).
    #[error("bad response from the server")]
    Protocol,
}

impl LinkError {
    /// `true` only for [`LinkError::Transient`].
    #[must_use]
    pub const fn is_transient(self) -> bool {
        matches!(self, Self::Transient)
    }
}

// POAM: step timeouts and stall detection are checked between calls; a
// call that blocks is not interrupted by the engine. Every ServerLink and
// Platform implementation (WU-12) must bound its own waits (socket
// timeouts, subprocess time limits) below the plan's stall limit.

/// The server, as the engine uses it. Calls block; implementations bound
/// every wait with their own I/O timeouts.
pub trait ServerLink {
    /// `GET /v1/device/jobs/{job}/content/{content}/chunks/{n}`: the bytes
    /// of chunk `n` (0-based) as received. Untrusted.
    ///
    /// # Errors
    ///
    /// [`LinkError`].
    fn fetch_chunk(
        &mut self,
        job: JobId,
        content: &Sha256Digest,
        n: u64,
    ) -> Result<Vec<u8>, LinkError>;

    /// `POST /v1/device/jobs/{job}/progress`.
    ///
    /// # Errors
    ///
    /// [`LinkError`].
    fn report(&mut self, job: JobId, report: &ProgressV1) -> Result<ProgressAckV1, LinkError>;
}

/// Progress schema 2 (M4 plan section 3.1): the WinPE agent sends steps 1
/// to 6 with its session token, the post-setup runner steps 7 to 9 with
/// its resume token. The implementation holds the token; it never reaches
/// the engine.
pub trait ProgressLinkV2 {
    /// `POST /v1/device/jobs/{job}/progress` with a [`ProgressV2`] body.
    ///
    /// # Errors
    ///
    /// [`LinkError`].
    fn report_v2(&mut self, job: JobId, report: &ProgressV2) -> Result<ProgressAckV1, LinkError>;
}

/// The WinPE link of a v2 job: chunk fetch and v2 progress.
pub trait ServerLinkV2: ServerLink + ProgressLinkV2 {}

impl<T: ServerLink + ProgressLinkV2 + ?Sized> ServerLinkV2 for T {}
