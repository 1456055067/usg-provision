//! Administrator-password escrow, device side (M4 plan sections 1.3 and
//! 3.1; decision 0024 item 1). Both routes take the job's resume token.
//!
//! - `POST /v1/device/jobs/{id}/escrow` `EscrowSubmitV1`: the password the
//!   runner generated, sealed (ECDH P-384 + HKDF-SHA-384 + AES-256-GCM) to
//!   the server's escrow key. Accepted only while step 7 is running, once
//!   per job (409 after: a second submission never overwrites the first),
//!   and only for an escrow key this server holds. The row and
//!   `escrow.received` are written in one transaction, then 201.
//! - `POST /v1/device/jobs/{id}/escrow/confirm` `{set, code?}`: whether
//!   the password was set on the account; `escrow.applied` or
//!   `escrow.not_applied` (with the code) in the same transaction.
//!
//! Only the sealed form is stored. The server never opens it here, and no
//! record carries the ciphertext.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-28, SC-28(1) - stored sealed to the server's key; the
//   database holds no plaintext.
// - NIST 800-53: SC-8 - device to server directly over TLS; relays never
//   see it.
// - NIST 800-53: AC-3 - resume token scoped to the job; step 7 only; once.
// - NIST 800-53: AU-2, AU-3, AU-12 - received, applied and not applied
//   recorded in the same transaction as the change.
// - NIST 800-53: SI-10 - strict parsing; point form and lengths checked.
// - SPEC: specs/configuration.md#REQ-CFG-010
// - Decisions 0024 item 1, 0025 item 2

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use usgp_audit::{Detail, Outcome};
use usgp_crypto::KeyId;
use usgp_db::{DbError, NewEscrow, RepoTx, SealedPassword, Store};
use usgp_proto::escrow::{EscrowConfirmV1, EscrowSubmitV1, GCM_NONCE_LEN, P384_POINT_LEN};
use usgp_proto::{JobId, JobState, StepState, StepV2, codes};

use super::auth::DeviceCtx;
use crate::body::ApiBody;
use crate::context::Api;
use crate::error::ApiError;
use crate::handlers::{json_response, parse_device_json, read_body};

/// 409 `escrow_refused`.
fn escrow_refused(message: &str) -> ApiError {
    ApiError::conflict(codes::ESCROW_REFUSED, message.to_owned())
}

fn own_job(ctx: &DeviceCtx) -> Result<JobId, ApiError> {
    let r = ctx
        .resume
        .ok_or_else(|| ApiError::internal_error("resume route without a resume token"))?;
    let path = JobId::parse(ctx.params.get(0)).map_err(|_| ApiError::not_found("job"))?;
    if path != r.job_id {
        return Err(ApiError::not_found("job"));
    }
    Ok(r.job_id)
}

#[derive(serde::Serialize)]
struct Empty {}

/// `POST /v1/device/jobs/{id}/escrow`.
pub(crate) async fn submit<S: Store + 'static>(
    api: &Api<S>,
    ctx: &DeviceCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let job_id = own_job(ctx)?;
    let c = &api.config().device;
    let body = read_body(req, c.max_json_bytes).await?;
    let e = parse_device_json!(EscrowSubmitV1, &body, c.max_json_bytes)?;
    drop(body);
    let Some(keys) = api.escrow_keys() else {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            codes::UNAVAILABLE,
            "the escrow key is not configured on this server",
        ));
    };
    // The plan names the server's escrow key at confirmation; the plan is
    // not stored, so the key must be one this server holds (current or
    // retired), and it must open later.
    if keys.by_id(&KeyId(e.key_id)).is_none() {
        return Err(
            escrow_refused("the password is sealed to a key this server does not hold")
                .detail(Detail::new().with("key_id", &e.key_id)),
        );
    }
    let eph_pub: [u8; P384_POINT_LEN] = e
        .eph_pub_b64
        .as_bytes()
        .try_into()
        .map_err(|_| ApiError::bad_request("eph_pub_b64 has the wrong length"))?;
    let nonce: [u8; GCM_NONCE_LEN] = e
        .nonce_b64
        .as_bytes()
        .try_into()
        .map_err(|_| ApiError::bad_request("nonce_b64 has the wrong length"))?;
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    let job = tx
        .lock_job_v2(job_id)
        .await?
        .ok_or_else(|| ApiError::not_found("job"))?;
    let step7_running = tx
        .job_steps_v2(job_id)
        .await?
        .iter()
        .any(|s| s.step == StepV2::WINDOWS_SETUP && s.state == StepState::Running);
    if job.state != JobState::Running || !step7_running {
        return Err(escrow_refused(
            "the password is accepted only while step 7 is running",
        ));
    }
    let new = NewEscrow {
        job_id,
        account: e.account,
        key_id: e.key_id,
        sealed: SealedPassword {
            eph_pub,
            nonce,
            ciphertext: e.ct_b64.as_bytes().to_vec(),
        },
        received_at: at,
    };
    match tx.insert_escrow(&new).await {
        Ok(()) => {}
        Err(DbError::Conflict { .. }) => {
            return Err(escrow_refused(
                "a password is already escrowed for this job; it is never replaced",
            ));
        }
        Err(DbError::InvalidArgument { .. }) => {
            return Err(ApiError::bad_request("the sealed password is malformed"));
        }
        Err(e) => return Err(e.into()),
    }
    // Never the sealed bytes: the account, key and sizes only.
    let d = ctx
        .ok("escrow.received")
        .target("job", &job_id.to_string())
        .detail(
            Detail::new()
                .with("account", new.account.as_str())
                .with("key_id", &new.key_id)
                .with("ciphertext_bytes", &new.sealed.ciphertext.len()),
        );
    let r = api.append(&mut tx, &d).await?;
    api.commit(tx, &[r]).await?;
    json_response!(StatusCode::CREATED, &Empty {})
}

/// `POST /v1/device/jobs/{id}/escrow/confirm`.
pub(crate) async fn confirm<S: Store + 'static>(
    api: &Api<S>,
    ctx: &DeviceCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let job_id = own_job(ctx)?;
    let c = &api.config().device;
    let body = read_body(req, c.max_json_bytes).await?;
    let conf = parse_device_json!(EscrowConfirmV1, &body, c.max_json_bytes)?;
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    let e = tx
        .lock_escrow(job_id)
        .await?
        .ok_or_else(|| ApiError::not_found("escrow"))?;
    match tx.set_escrow_outcome(job_id, conf.set, at).await {
        Ok(()) => {}
        Err(DbError::Conflict { .. }) => {
            return Err(ApiError::conflict(
                codes::WRONG_STATE,
                format!(
                    "the escrow outcome is already recorded ({})",
                    e.state.as_str()
                ),
            ));
        }
        Err(e) => return Err(e.into()),
    }
    let mut d = if conf.set {
        ctx.ok("escrow.applied")
    } else {
        ctx.draft("escrow.not_applied", Outcome::Failure)
    }
    .target("job", &job_id.to_string())
    .detail(
        Detail::new()
            .with("account", e.account.as_str())
            .with("key_id", &e.key_id),
    );
    if let Some(code) = &conf.code {
        d = d.reason(code.as_str());
    }
    let r = api.append(&mut tx, &d).await?;
    api.commit(tx, &[r]).await?;
    json_response!(StatusCode::OK, &Empty {})
}
