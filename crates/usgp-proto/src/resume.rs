//! Post-setup re-contact (M4 plan sections 1.2 and 3.1; decision 0025
//! item 1).
//!
//! | Route | Body | Response |
//! |---|---|---|
//! | `POST /v1/device/jobs/{id}/resume/challenge` | `{}` | [`ResumeChallengeV1`] |
//! | `POST /v1/device/jobs/{id}/resume` | [`ResumeRequestV1`] | [`ResumedV1`] |
//!
//! The runner signs [`resume_payload`] (`job_id || nonce`) with the job
//! key under the domain `USGP-SIG-V1` and payload type
//! [`PayloadType::ResumeV1`] ([`resume_signing_input`]). The server checks
//! the signature with the job key whose SPKI it stored at confirm, uses the
//! nonce once, and issues a job-scoped bearer token. The token is a secret:
//! it reuses [`SessionToken`] (zeroized, `Debug` redacted, stored only as
//! its SHA-256 on the server).

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-3 (Device Identification and Authentication) - the
//   device proves possession of the job key it generated in Windows PE.
// - NIST 800-53: SC-23 (Session Authenticity) - single-use server nonce,
//   bound to the job id; token scoped to one job.
// - NIST 800-53: SI-10 - exact nonce length, bounded signature, strict
//   parse.
// - SPEC: specs/workflow.md (re-contact after the first restart)
// - DECISION: docs/decisions/0025 item 1
// - FIPS 186-5 (ECDSA P-384)

use crate::b64::B64Bytes;
use crate::device::SessionToken;
use crate::envelope::{PayloadType, signing_input};
use crate::ids::{JobId, UnixMicros};
use crate::limits::MAX_SIGNATURE_BYTES;

/// Length of a resume nonce.
pub const RESUME_NONCE_LEN: usize = 32;

/// A server resume nonce (32 bytes, padded base64).
pub type ResumeNonce = B64Bytes<RESUME_NONCE_LEN, RESUME_NONCE_LEN>;

/// A signature over [`resume_signing_input`] (ASN.1 DER ECDSA; 1 to
/// [`MAX_SIGNATURE_BYTES`] bytes, padded base64).
pub type ResumeSignature = B64Bytes<1, MAX_SIGNATURE_BYTES>;

/// `200` response to the challenge route: a fresh nonce, valid for 60 s.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeChallengeV1 {
    /// The nonce to sign.
    pub nonce: ResumeNonce,
    /// When it expires.
    pub expires_at: UnixMicros,
}

/// `POST …/resume` body: the nonce and the job key's signature.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeRequestV1 {
    /// The nonce from [`ResumeChallengeV1`].
    pub nonce: ResumeNonce,
    /// The signature.
    pub sig: ResumeSignature,
}

/// `200` response to a resume request: the job-scoped bearer token.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumedV1 {
    /// Bearer token for progress and escrow on this job only.
    pub token: SessionToken,
    /// When it expires (at most 24 h, or when the job ends).
    pub expires_at: UnixMicros,
}

/// The resume payload: the 16 job id bytes, then the 32 nonce bytes.
#[must_use]
pub fn resume_payload(job_id: &JobId, nonce: &ResumeNonce) -> Vec<u8> {
    let mut v = Vec::with_capacity(16 + RESUME_NONCE_LEN);
    v.extend_from_slice(job_id.as_bytes());
    v.extend_from_slice(nonce.as_bytes());
    v
}

/// The exact bytes the job key signs: [`signing_input`] of
/// [`PayloadType::ResumeV1`] over [`resume_payload`].
#[must_use]
pub fn resume_signing_input(job_id: &JobId, nonce: &ResumeNonce) -> Vec<u8> {
    signing_input(PayloadType::ResumeV1, &resume_payload(job_id, nonce))
}

#[cfg(test)]
mod tests {
    use super::*;

    const JOB: &str = "6b2c3d4e-5f60-4b7c-9d8e-0f1a2b3c4d5e";

    #[test]
    fn payload_and_signing_input() {
        let job = JobId::parse(JOB).unwrap();
        let nonce = ResumeNonce::new(vec![7; 32]).unwrap();
        let p = resume_payload(&job, &nonce);
        assert_eq!(p.len(), 48);
        assert_eq!(p.get(..16), Some(&job.as_bytes()[..]));
        assert_eq!(p.get(16..), Some(&[7u8; 32][..]));
        let si = resume_signing_input(&job, &nonce);
        assert_eq!(si, signing_input(PayloadType::ResumeV1, &p));
        assert_ne!(si, signing_input(PayloadType::JobPlanV2, &p));
    }

    #[test]
    fn strict_bodies() {
        let n = "A".repeat(43) + "=";
        let ok = format!(r#"{{"nonce":"{n}","sig":"AQID"}}"#);
        assert!(serde_json::from_str::<ResumeRequestV1>(&ok).is_ok());
        assert!(
            serde_json::from_str::<ResumeRequestV1>(r#"{"nonce":"AQID","sig":"AQID"}"#).is_err()
        );
        let extra = format!(r#"{{"nonce":"{n}","sig":"AQID","x":1}}"#);
        assert!(serde_json::from_str::<ResumeRequestV1>(&extra).is_err());
        let ch = format!(r#"{{"nonce":"{n}","expires_at":1793000000000000}}"#);
        assert!(serde_json::from_str::<ResumeChallengeV1>(&ch).is_ok());
    }

    #[test]
    fn token_is_redacted() {
        let r = ResumedV1 {
            token: SessionToken::from_random_bytes(&[9; 32]),
            expires_at: UnixMicros::new(1).unwrap(),
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("redacted") && !dbg.contains(r.token.expose()));
    }
}
