//! Escrowed administrator passwords, operator side (M4 plan section 1.3;
//! decision 0024 item 1).
//!
//! - `GET /v1/jobs/{id}/admin-password` (`job.view`): metadata only
//!   (state, key id, received and applied times, reveal count).
//! - `POST /v1/jobs/{id}/admin-password/reveal` (`escrow.reveal`, held by
//!   `escrow_officer` only) with `{reason}`:
//!   1. the self-grant guard and the per-operator rate limit;
//!   2. the reveal count and the `escrow.revealed` record (who, job, MACs,
//!      reason) are **committed before** anything is decrypted; if that
//!      fails the answer is 503 and nothing is revealed (fail closed);
//!   3. the sealed bytes are read and opened with the escrow key;
//!   4. the password is returned with `Cache-Control: no-store`, from a
//!      buffer that is wiped when dropped.
//!
//! The password is never logged, never in an audit record, never in an
//! error.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3, AC-5, AC-6 - `escrow.reveal` held by the escrow
//   officer only; an administrator's second certificate is refused.
// - NIST 800-53: AU-2, AU-3, AU-12 - every reveal recorded with who, job,
//   MACs and reason; metadata reads recorded.
// - NIST 800-53: AU-5 - the reveal record is durable before decryption;
//   if it cannot be written, nothing is revealed (503).
// - NIST 800-53: AC-7 (style) - reveals per operator per hour capped.
// - NIST 800-53: SC-28, SC-12, SC-13 - stored sealed; opened only here,
//   with the server's escrow key in the FIPS module.
// - NIST 800-53: IA-5(1) - the plaintext lives only in a zeroizing
//   buffer for the response.
// - SPEC: specs/configuration.md#REQ-CFG-010
// - Decisions 0024 item 1, 0025 item 2

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use hyper::body::{Bytes, Incoming};
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use usgp_audit::{Detail, Outcome};
use usgp_common::Sha256Digest;
use usgp_crypto::{EscrowContext, KeyId, SealedV1};
use usgp_db::{EscrowRecord, RepoTx, Store};
use usgp_proto::{JobId, OperatorId, UnixMicros, codes};
use zeroize::Zeroizing;

use super::{json_response, parse_json, read_body};
use crate::body::ApiBody;
use crate::context::{Api, RequestCtx};
use crate::error::ApiError;
use crate::rbac::self_granted;

/// Longest reveal reason, characters.
pub const MAX_REVEAL_REASON_CHARS: usize = 256;

/// Operators tracked by the reveal limiter; beyond it the oldest windows
/// are dropped.
const MAX_TRACKED_OPERATORS: usize = 4096;

/// The rate window of the reveal limiter.
const REVEAL_WINDOW: Duration = Duration::from_secs(3600);

/// Reveals per operator per hour (`escrow.reveal_rate_per_hour`).
#[derive(Debug)]
pub(crate) struct RevealLimiter {
    per_hour: u32,
    windows: Mutex<HashMap<OperatorId, (Instant, u32)>>,
}

impl RevealLimiter {
    pub(crate) fn new(per_hour: u32) -> Self {
        Self {
            per_hour,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Counts one reveal by `op` at `now`; false if over the limit.
    pub(crate) fn admit(&self, op: OperatorId, now: Instant) -> bool {
        let mut m = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        if m.len() >= MAX_TRACKED_OPERATORS && !m.contains_key(&op) {
            m.retain(|_, (start, _)| now.saturating_duration_since(*start) < REVEAL_WINDOW);
        }
        let w = m.entry(op).or_insert((now, 0));
        if now.saturating_duration_since(w.0) >= REVEAL_WINDOW {
            *w = (now, 0);
        }
        if w.1 >= self.per_hour {
            return false;
        }
        w.1 = w.1.saturating_add(1);
        true
    }
}

/// Metadata of an escrow (never the sealed bytes).
#[derive(Debug, serde::Serialize)]
struct MetadataView {
    job_id: JobId,
    account: &'static str,
    key_id: Sha256Digest,
    state: &'static str,
    received_at: UnixMicros,
    #[serde(skip_serializing_if = "Option::is_none")]
    applied_at: Option<UnixMicros>,
    reveal_count: u32,
}

fn metadata_view(e: &EscrowRecord) -> MetadataView {
    MetadataView {
        job_id: e.job_id,
        account: e.account.as_str(),
        key_id: e.key_id,
        state: e.state.as_str(),
        received_at: e.received_at,
        applied_at: e.applied_at,
        reveal_count: e.reveal_count,
    }
}

fn job_id(ctx: &RequestCtx) -> Result<JobId, ApiError> {
    JobId::parse(ctx.params.get(0)).map_err(|_| ApiError::not_found("job"))
}

/// `GET /v1/jobs/{id}/admin-password`.
pub(crate) async fn metadata<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let id = job_id(ctx)?;
    let mut tx = api.store().begin().await?;
    let e = tx
        .escrow(id)
        .await?
        .ok_or_else(|| ApiError::not_found("escrow"))?;
    let d = ctx
        .ok("escrow.metadata.read")
        .target("job", &id.to_string())
        .detail(
            Detail::new()
                .with("state", e.state.as_str())
                .with("reveal_count", &e.reveal_count),
        );
    let r = api.append(&mut tx, &d).await?;
    api.commit(tx, &[r]).await?;
    json_response!(StatusCode::OK, &metadata_view(&e))
}

/// `POST …/reveal` body.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RevealRequest {
    reason: String,
}

fn reveal_reason(body: &[u8], max: usize) -> Result<String, ApiError> {
    let r = parse_json!(RevealRequest, body, max)?;
    let n = r.reason.chars().count();
    if n == 0
        || n > MAX_REVEAL_REASON_CHARS
        || r.reason.chars().any(char::is_control)
        || r.reason.trim().is_empty()
    {
        return Err(ApiError::unprocessable(
            codes::INVALID_VALUE
                .with_param("reason")
                .unwrap_or(codes::INVALID_VALUE),
            format!("reason must be 1 to {MAX_REVEAL_REASON_CHARS} printable characters"),
        ));
    }
    Ok(r.reason)
}

/// A failure before or while writing the reveal record: 503, nothing
/// revealed (M4 plan section 1.3).
fn unavailable(mut e: ApiError) -> ApiError {
    if e.code() == &codes::AUDIT_UNAVAILABLE || e.status.is_server_error() {
        e.status = StatusCode::SERVICE_UNAVAILABLE;
    }
    e
}

/// The response body `{"job_id", "account", "password"}`, built in a
/// buffer that is wiped when dropped.
fn secret_body(job: JobId, account: &str, password: &str) -> Result<Zeroizing<Vec<u8>>, ApiError> {
    #[derive(serde::Serialize)]
    struct Revealed<'a> {
        job_id: JobId,
        account: &'a str,
        password: &'a str,
    }
    // Sized up front so the writer does not reallocate (a reallocation
    // would leave a copy in freed memory).
    let mut out = Zeroizing::new(Vec::with_capacity(
        password.len().saturating_mul(6).saturating_add(256),
    ));
    serde_json::to_writer(
        &mut *out,
        &Revealed {
            job_id: job,
            account,
            password,
        },
    )
    .map_err(|_| ApiError::internal_error("the response could not be built"))?;
    Ok(out)
}

/// `POST /v1/jobs/{id}/admin-password/reveal`.
pub(crate) async fn reveal<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let id = job_id(ctx)?;
    let max = api.config().limits.max_json_bytes;
    let body = read_body(req, max).await?;
    let reason = reveal_reason(&body, max)?;
    let Some(keys) = api.escrow_keys() else {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            codes::UNAVAILABLE,
            "the escrow key is not configured on this server",
        ));
    };
    let me = &ctx.principal.operator;

    // 1. Self-grant guard (AC-5) and rate limit.
    let mut tx = api.store().begin().await?;
    let operators = tx.list_operators().await;
    tx.rollback().await;
    if self_granted(me, &operators?) {
        return Err(ApiError::forbidden().detail(Detail::new().with("guard", "self_granted")));
    }
    if !api.inner.reveals.admit(me.id, Instant::now()) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            codes::RATE_LIMITED,
            "too many reveals in the last hour; try again later",
        ));
    }

    // 2. The reveal record is durable before anything is decrypted.
    let mut tx = api.store().begin().await?;
    let e = tx
        .lock_escrow(id)
        .await?
        .ok_or_else(|| ApiError::not_found("escrow"))?;
    let macs = match tx.job_v2(id).await? {
        Some(j) => j
            .macs
            .as_slice()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        None => String::new(),
    };
    let count = tx.record_escrow_reveal(id).await?;
    let d = ctx
        .ok("escrow.revealed")
        .target("job", &id.to_string())
        .detail(
            Detail::new()
                .with("account", e.account.as_str())
                .with("key_id", &e.key_id)
                .with("state", e.state.as_str())
                .with("macs", &macs)
                .with("claimed", "macs")
                .with("reason_text", reason.as_str())
                .with("reveal_count", &count),
        );
    let r = api.append(&mut tx, &d).await.map_err(unavailable)?;
    let seq = r.seq;
    api.commit(tx, &[r]).await.map_err(unavailable)?;

    // 3. Read and open.
    let fail = |what: &'static str| async move {
        let d = ctx
            .draft("escrow.reveal_refused", Outcome::Failure)
            .target("job", &id.to_string())
            .reason(codes::INTERNAL.as_str())
            .initiated_by(seq)
            .detail(Detail::new().with("internal_cause", what));
        api.record_refusal(&d).await;
        ApiError::internal_error(what).audited()
    };
    let mut tx = api.store().begin().await?;
    let sealed = tx.escrow_sealed(id).await;
    tx.rollback().await;
    let Some(sealed) = sealed? else {
        return Err(fail("the sealed password is missing").await);
    };
    let Some(sk) = keys.by_id(&KeyId(e.key_id)) else {
        return Err(fail("the escrow key this password was sealed to is not configured").await);
    };
    let s = SealedV1 {
        key_id: KeyId(e.key_id),
        eph_pub: sealed.eph_pub.to_vec(),
        nonce: sealed.nonce,
        ct: sealed.ciphertext.clone(),
    };
    let ectx = EscrowContext {
        job_id: *id.as_bytes(),
        account: e.account.as_str(),
    };
    let Ok(plain) = usgp_crypto::escrow_open(sk, &ectx, &s) else {
        return Err(fail("the sealed password did not open").await);
    };
    let Ok(password) = std::str::from_utf8(&plain) else {
        return Err(fail("the opened password is not UTF-8").await);
    };

    // 4. The response, not cached.
    let json = secret_body(id, e.account.as_str(), password)?;
    drop(plain);
    // POAM: SC-28/IA-5 - the response passes through hyper's `Bytes`
    // buffer, which is not zeroized when freed (as for the session token,
    // `device::handlers::secret_json`).
    let mut resp = Response::new(ApiBody::full(Bytes::copy_from_slice(&json)));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(usgp_proto::api::JSON_MEDIA_TYPE),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_counts_per_operator_per_hour() {
        let l = RevealLimiter::new(2);
        let a = OperatorId::from_random_bytes([1; 16]);
        let b = OperatorId::from_random_bytes([2; 16]);
        let t = Instant::now();
        assert!(l.admit(a, t));
        assert!(l.admit(a, t));
        assert!(!l.admit(a, t));
        assert!(l.admit(b, t));
        assert!(l.admit(a, t + REVEAL_WINDOW));
    }

    #[test]
    fn reason_bounds() {
        assert!(reveal_reason(br#"{"reason":"ticket 42"}"#, 1024).is_ok());
        assert!(reveal_reason(br#"{"reason":""}"#, 1024).is_err());
        assert!(reveal_reason(br#"{"reason":"  "}"#, 1024).is_err());
        assert!(reveal_reason(br#"{"reason":"a\nb"}"#, 1024).is_err());
        let long = format!(r#"{{"reason":"{}"}}"#, "x".repeat(257));
        assert!(reveal_reason(long.as_bytes(), 4096).is_err());
        assert!(reveal_reason(br#"{"reason":"x","more":1}"#, 1024).is_err());
    }
}
