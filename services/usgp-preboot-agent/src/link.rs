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
    unauthorised: bool,
}

impl std::fmt::Debug for ApiLink<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiLink").finish_non_exhaustive()
    }
}

impl<'a> ApiLink<'a> {
    /// A link over `api`, which already holds the session.
    pub fn new(api: &'a mut dyn DeviceApi) -> Self {
        Self {
            api,
            unauthorised: false,
        }
    }

    /// `true` once any call was answered 401: the server no longer
    /// accepts the session token. With decision 0023 item 1 that happens
    /// when the device's source network changed (for example a new IPv4
    /// address after the wipe) or the confirmed session lapsed (SEC-013.2).
    #[must_use]
    pub fn saw_unauthorised(&self) -> bool {
        self.unauthorised
    }

    fn note<T>(&mut self, r: Result<T, ApiFailure>) -> Result<T, LinkError> {
        r.map_err(|e| {
            if e.status() == Some(401) {
                self.unauthorised = true;
            }
            classify(&e)
        })
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
        let r = self.api.fetch_chunk(job, content, n);
        self.note(r)
    }

    fn report(&mut self, job: JobId, report: &ProgressV1) -> Result<ProgressAckV1, LinkError> {
        let r = self.api.report(job, report);
        self.note(r)
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

    /// A device API whose every call fails with `fail`.
    struct Failing(ApiFailure);

    impl DeviceApi for Failing {
        fn open(
            &mut self,
            _: &usgp_proto::device::DeviceHelloV1,
        ) -> Result<usgp_proto::device::SessionOpenedV1, ApiFailure> {
            Err(self.0.clone())
        }
        fn status(&mut self) -> Result<usgp_proto::device::SessionStatusV1, ApiFailure> {
            Err(self.0.clone())
        }
        fn submit_code(
            &mut self,
            _: &usgp_proto::AuthCode,
        ) -> Result<usgp_proto::device::SessionStatusV1, ApiFailure> {
            Err(self.0.clone())
        }
        fn packages(&mut self) -> Result<usgp_proto::device::DevicePackageListV1, ApiFailure> {
            Err(self.0.clone())
        }
        fn choose_package(
            &mut self,
            _: &usgp_proto::device::ChoosePackageV1,
        ) -> Result<(), ApiFailure> {
            Err(self.0.clone())
        }
        fn choose_disk(&mut self, _: &usgp_proto::DiskDescriptorV1) -> Result<(), ApiFailure> {
            Err(self.0.clone())
        }
        fn confirm(
            &mut self,
            _: &usgp_proto::device::ConfirmV1,
        ) -> Result<usgp_proto::device::ConfirmedV1, ApiFailure> {
            Err(self.0.clone())
        }
        fn cancel(&mut self) -> Result<(), ApiFailure> {
            Err(self.0.clone())
        }
        fn end(&mut self, _: &usgp_proto::device::EndSessionV1) -> Result<(), ApiFailure> {
            Err(self.0.clone())
        }
        fn fetch_chunk(
            &mut self,
            _: JobId,
            _: &Sha256Digest,
            _: u64,
        ) -> Result<Vec<u8>, ApiFailure> {
            Err(self.0.clone())
        }
        fn report(&mut self, _: JobId, _: &ProgressV1) -> Result<ProgressAckV1, ApiFailure> {
            Err(self.0.clone())
        }
        fn bound_waits(&mut self, _: std::time::Duration, _: std::time::Duration) {}
    }

    /// SEC-013.2: a 401 during the job is remembered, so the agent can
    /// show its own screen rather than a generic refusal.
    #[test]
    fn a_401_is_remembered() {
        let job = JobId::parse("0b6f2c1e-8a4d-4f3b-9c2e-7d5a1b3c4e6f").unwrap();
        let digest = usgp_crypto::sha256(b"chunk");
        let mut api = Failing(status(401, Some(codes::INVALID_TOKEN)));
        let mut link = ApiLink::new(&mut api);
        assert!(!link.saw_unauthorised());
        assert_eq!(link.fetch_chunk(job, &digest, 0), Err(LinkError::Refused));
        assert!(link.saw_unauthorised());

        let mut api = Failing(status(403, Some(codes::FORBIDDEN)));
        let mut link = ApiLink::new(&mut api);
        let _ = link.fetch_chunk(job, &digest, 0);
        assert!(!link.saw_unauthorised(), "403 is not a token refusal");
        let mut api = Failing(status(503, None));
        let mut link = ApiLink::new(&mut api);
        let _ = link.fetch_chunk(job, &digest, 0);
        assert!(!link.saw_unauthorised());
    }
}
