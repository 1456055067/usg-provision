//! The engine's [`ServerLink`] over the device session ([`DeviceApi`]).
//!
//! Maps transport failures and server answers onto the engine's retry
//! classes (plan section 3.3; WU-8 notes): connection failures, timeouts,
//! 429 and 5xx other than `integrity_failed` are transient; 404 is
//! "not found"; 401, 403 and 409 are refusals; 500 `integrity_failed` is
//! the server's own integrity failure (never retried); anything else
//! breaks the protocol. The bytes returned are untrusted: the engine
//! verifies each chunk against the signed content manifest before use.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   chunk bytes passed on unverified only to the engine's check.
// - NIST 800-53: SC-8 - over the session's TLS connection.
// - SPEC: specs/progress.md#REQ-JOB-007 (transient failures retried, others
//   not)

use usgp_common::Sha256Digest;
use usgp_deploy::{LinkError, ServerLink};
use usgp_proto::JobId;
use usgp_proto::codes;
use usgp_proto::progress::{ProgressAckV1, ProgressV1};

use crate::client::{ApiFailure, DeviceApi};

/// [`ServerLink`] over a [`DeviceApi`].
pub struct ApiLink<'a> {
    api: &'a mut dyn DeviceApi,
}

impl std::fmt::Debug for ApiLink<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiLink").finish_non_exhaustive()
    }
}

impl<'a> ApiLink<'a> {
    /// A link over `api`, which already holds the session.
    pub fn new(api: &'a mut dyn DeviceApi) -> Self {
        Self { api }
    }
}

/// The engine's class for a failed call.
#[must_use]
pub fn classify(f: &ApiFailure) -> LinkError {
    match f {
        ApiFailure::Transport { transient, .. } => {
            if *transient {
                LinkError::Transient
            } else {
                // A TLS refusal will not change by retrying.
                LinkError::Refused
            }
        }
        ApiFailure::BadResponse(_) => LinkError::Protocol,
        ApiFailure::Status { status, code, .. } => match *status {
            404 => LinkError::NotFound,
            401 | 403 | 409 => LinkError::Refused,
            429 | 503 => LinkError::Transient,
            500 if code.as_ref() == Some(&codes::INTEGRITY_FAILED) => LinkError::ServerIntegrity,
            500..=599 => LinkError::Transient,
            _ => LinkError::Protocol,
        },
    }
}

impl ServerLink for ApiLink<'_> {
    fn fetch_chunk(
        &mut self,
        job: JobId,
        content: &Sha256Digest,
        n: u64,
    ) -> Result<Vec<u8>, LinkError> {
        self.api
            .fetch_chunk(job, content, n)
            .map_err(|e| classify(&e))
    }

    fn report(&mut self, job: JobId, report: &ProgressV1) -> Result<ProgressAckV1, LinkError> {
        self.api.report(job, report).map_err(|e| classify(&e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(s: u16, code: Option<usgp_proto::ErrorCode>) -> ApiFailure {
        ApiFailure::Status {
            status: s,
            code,
            message: None,
            attempts_left: None,
        }
    }

    #[test]
    fn classes() {
        let t = |transient| ApiFailure::Transport {
            what: String::new(),
            time_related: false,
            transient,
        };
        assert_eq!(classify(&t(true)), LinkError::Transient);
        assert_eq!(classify(&t(false)), LinkError::Refused);
        assert_eq!(classify(&status(404, None)), LinkError::NotFound);
        assert_eq!(classify(&status(409, None)), LinkError::Refused);
        assert_eq!(classify(&status(403, None)), LinkError::Refused);
        assert_eq!(classify(&status(429, None)), LinkError::Transient);
        assert_eq!(classify(&status(503, None)), LinkError::Transient);
        assert_eq!(
            classify(&status(500, Some(codes::INTEGRITY_FAILED))),
            LinkError::ServerIntegrity
        );
        assert_eq!(classify(&status(500, None)), LinkError::Transient);
        assert_eq!(classify(&status(400, None)), LinkError::Protocol);
        assert_eq!(classify(&ApiFailure::BadResponse("x")), LinkError::Protocol);
    }
}
