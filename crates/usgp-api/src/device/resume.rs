//! Re-contact after the first restart (M4 plan sections 1.2 and 3.1;
//! decision 0025 item 1).
//!
//! The Windows PE session token is revoked at step 6. After Windows setup
//! the post-setup runner proves it holds the job key the agent generated
//! in Windows PE (whose public half the server stored at confirmation):
//!
//! 1. `POST /v1/device/jobs/{id}/resume/challenge` `{}` returns a fresh
//!    32-byte nonce valid for 60 s. Only for a v2 job that is running (or
//!    lost) with step 6 completed; otherwise 404, the same as for an
//!    unknown job (no oracle beyond existence). Not audited when issued (no
//!    state change). Rate limited per source address; at most 16 live
//!    nonces per job (above that 429 and `job.resume.refused`, under the
//!    per-source record cap).
//! 2. `POST /v1/device/jobs/{id}/resume` `{nonce, sig}`: the nonce is used
//!    once, whatever the outcome; the signature (ECDSA P-384 over
//!    `USGP-SIG-V1`, payload type `resume.v1`, payload `job_id‖nonce`) is
//!    verified with the stored job key; at most `resume.max_per_job`
//!    tokens per job. The answer is a 32-byte bearer token scoped to the
//!    job (only its SHA-256 is stored), valid until the job ends or for
//!    `resume.token_ttl_s`, with `ack_seq`, the last progress sequence
//!    number the server accepted. `job.resumed` or `job.resume.refused`
//!    in the same transaction as the nonce use.
//!
//! No secret goes from the server to the device beyond the token, which
//! is good only for this job's progress and escrow routes.

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-3, IA-5 - the device re-authenticates by proving the
//   job key (challenge-response, single-use nonce); the token is stored
//   only as its SHA-256 and expires with the job.
// - NIST 800-53: AC-3, SC-23 - the token is scoped to one job; resume only
//   in the state the plan allows.
// - NIST 800-53: AC-7, SC-5 - challenges rate limited per source and
//   capped per job; resumes capped per job.
// - NIST 800-53: AU-2, AU-3, AU-12 - `job.resumed` / `job.resume.refused`.
// - NIST 800-53: SC-13 - ECDSA P-384 verification in the FIPS module.
// - SPEC: specs/workflow.md#REQ-SEQ-002, #REQ-SEQ-006
// - Decision 0025 item 1

use std::time::Instant;

use hyper::body::{Bytes, Incoming};
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use usgp_audit::{Detail, Outcome};
use usgp_db::{NewResumeNonce, NewResumeToken, NonceIssue, RepoTx, Store};
use usgp_proto::resume::{
    RESUME_NONCE_LEN, ResumeChallengeV1, ResumeNonce, ResumeRequestV1, ResumedV1,
    resume_signing_input,
};
use usgp_proto::{JobId, JobState, SessionToken, StepState, StepV2, codes};
use zeroize::Zeroizing;

use super::auth::{DeviceCtx, resume_actor};
use super::handlers::rate_limited;
use crate::body::ApiBody;
use crate::context::Api;
use crate::error::ApiError;
use crate::handlers::auth_codes::{plus_secs, random};
use crate::handlers::{json_response, parse_device_json, read_body};

/// Lifetime of a resume nonce (M4 plan section 3.1).
pub const RESUME_NONCE_TTL_S: u64 = 60;

/// The `{}` body of the challenge.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

fn job_param(ctx: &DeviceCtx) -> Result<JobId, ApiError> {
    JobId::parse(ctx.params.get(0)).map_err(|_| ApiError::not_found("job"))
}

/// 403 `resume_refused`.
fn refused(message: &str) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, codes::RESUME_REFUSED, message)
}

/// `POST /v1/device/jobs/{id}/resume/challenge`.
pub(crate) async fn challenge<S: Store + 'static>(
    api: &Api<S>,
    ctx: &DeviceCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let job_id = job_param(ctx)?;
    let c = &api.config().device;
    let body = read_body(req, c.max_json_bytes).await?;
    parse_device_json!(Empty, &body, c.max_json_bytes)?;
    if !api
        .inner
        .device
        .resume_challenges
        .admit(ctx.ip, Instant::now())
    {
        return Err(
            rate_limited("too many resume challenges from this address; try again later")
                .target("job", job_id),
        );
    }
    let nonce = Zeroizing::new(random::<RESUME_NONCE_LEN>()?);
    let at = api.now()?;
    let expires_at = plus_secs(at, RESUME_NONCE_TTL_S)?;
    let n = NewResumeNonce {
        nonce_hash: usgp_crypto::sha256(&*nonce),
        job_id,
        issued_at: at,
        expires_at,
    };
    let mut tx = api.store().begin().await?;
    match tx.insert_resume_nonce(&n).await? {
        NonceIssue::Issued => {
            api.commit(tx, &[]).await?;
        }
        NonceIssue::NotEligible => {
            tx.rollback().await;
            return Err(ApiError::not_found("job"));
        }
        NonceIssue::OverCap => {
            tx.rollback().await;
            return Err(rate_limited(
                "too many resume challenges are open for this job; wait a minute",
            )
            .target("job", job_id)
            .detail(Detail::new().with("limit", "live_nonces_per_job")));
        }
    }
    let out = ResumeChallengeV1 {
        nonce: ResumeNonce::new(nonce.to_vec()).map_err(ApiError::internal_error)?,
        expires_at,
    };
    json_response!(StatusCode::OK, &out)
}

/// `POST /v1/device/jobs/{id}/resume`.
pub(crate) async fn resume<S: Store + 'static>(
    api: &Api<S>,
    ctx: &DeviceCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let job_id = job_param(ctx)?;
    let c = &api.config().device;
    let body = read_body(req, c.max_json_bytes).await?;
    let r = parse_device_json!(ResumeRequestV1, &body, c.max_json_bytes)?;
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    // The same 404 for an unknown job and one not in the resumable state.
    let job = tx
        .lock_job_v2(job_id)
        .await?
        .ok_or_else(|| ApiError::not_found("job"))?;
    let steps = tx.job_steps_v2(job_id).await?;
    let step6_done = steps
        .iter()
        .any(|s| s.step == StepV2::MAKE_BOOTABLE_RESTART && s.state == StepState::Done);
    if !matches!(job.state, JobState::Running | JobState::Lost) || !step6_done {
        return Err(ApiError::not_found("job"));
    }
    let actor = resume_actor(job.session_id, job_id, ctx.ip);
    let target = job_id.to_string();
    let refuse_in_tx = |reason: &'static str| {
        ctx.draft_as(actor.clone(), "job.resume.refused", Outcome::Refused)
            .target("job", &target)
            .reason(reason)
            .detail(Detail::new().with("state", job.state.as_str()))
    };
    // The nonce is used once whatever happens next: a failed signature
    // cannot be retried against the same nonce.
    let nonce_hash = usgp_crypto::sha256(r.nonce.as_bytes());
    if !tx.consume_resume_nonce(job_id, &nonce_hash, at).await? {
        tx.rollback().await;
        return Err(refused("the nonce is not valid; ask for a new challenge")
            .event("job.resume.refused")
            .target("job", job_id)
            .detail(Detail::new().with("cause", "nonce_not_accepted")));
    }
    let key = usgp_crypto::VerifyingKey::from_spki_der(job.job_key_spki.as_der());
    let verified = key.is_ok_and(|k| {
        usgp_crypto::verify_signing_input(
            &k,
            &resume_signing_input(&job_id, &r.nonce),
            r.sig.as_bytes(),
        )
        .is_ok()
    });
    if !verified {
        let rec = api
            .append(&mut tx, &refuse_in_tx("signature_invalid"))
            .await?;
        api.commit(tx, &[rec]).await?;
        return Err(refused("the job key's signature did not verify").audited());
    }
    let issued = tx.count_resume_tokens(job_id).await?;
    let max = c.m4.resume_max_per_job;
    if issued >= max {
        let rec = api.append(&mut tx, &refuse_in_tx("max_resumes")).await?;
        api.commit(tx, &[rec]).await?;
        return Err(refused("the job has been resumed too many times").audited());
    }
    let raw = Zeroizing::new(random::<32>()?);
    let token = SessionToken::from_random_bytes(&raw);
    drop(raw);
    let expires_at = plus_secs(at, c.m4.resume_token_ttl.as_secs())?;
    let t = NewResumeToken {
        token_hash: usgp_crypto::sha256(token.expose().as_bytes()),
        job_id,
        issued_at: at,
        expires_at,
    };
    tx.insert_resume_token(&t).await?;
    let d = ctx
        .draft_as(actor.clone(), "job.resumed", Outcome::Success)
        .target("job", &target)
        .detail(
            Detail::new()
                .with("via", "job_key")
                .with("state", job.state.as_str())
                .with("resumes", &issued.saturating_add(1))
                .with("ack_seq", &job.last_seq)
                .with("token_expires_at_us", &expires_at.as_micros()),
        );
    let rec = api.append(&mut tx, &d).await?;
    api.commit(tx, &[rec]).await?;
    let out = ResumedV1 {
        token,
        expires_at,
        ack_seq: job.last_seq,
    };
    // Sized up front so the writer does not reallocate the token's copy.
    let mut json = Zeroizing::new(Vec::with_capacity(256));
    serde_json::to_writer(&mut *json, &out).map_err(ApiError::internal_error)?;
    drop(out);
    // POAM: SC-28/IA-5 - as for the session token, the response passes
    // through hyper's `Bytes`, which is not zeroized when freed.
    let mut resp = Response::new(ApiBody::full(Bytes::copy_from_slice(&json)));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(usgp_proto::api::JSON_MEDIA_TYPE),
    );
    Ok(resp)
}
