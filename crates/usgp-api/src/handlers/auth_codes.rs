//! Operator-issued device codes: issue, list, revoke (plan M3 section 3.5,
//! REQ-TGT-013).
//!
//! A code is 50 bits from the DRBG, shown once in the issue response
//! (`Cache-Control: no-store`) and stored only as its HMAC under the
//! server's code key. Its value never reaches a log, an audit record or a
//! later response.

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-5, IA-5(1) (Authenticator Management) - DRBG codes,
//   single use, bounded lifetime, stored as an HMAC only, revocable.
// - NIST 800-53: AU-2, AU-3, AU-12 - issue, list and revoke audited
//   without the value (decision 0010).
// - NIST 800-53: SC-28 - no code value at rest.
// - SPEC: specs/targeting.md#REQ-TGT-013
// - Decision 0018 item 1

use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use usgp_audit::Detail;
use usgp_db::{DbError, NewAuthCode, RepoTx, Store};
use usgp_proto::ops::{AuthCodeIssuedV1, AuthCodeList, IssueAuthCodeRequest};
use usgp_proto::{AuthCode, AuthCodeId, codes};
use zeroize::Zeroizing;

use super::{field_error, json_response, parse_json, read_body};
use crate::body::ApiBody;
use crate::context::{Api, RequestCtx};
use crate::error::ApiError;

/// Draws at most this many codes when one collides with a stored HMAC.
const DRAWS: usize = 4;

/// 503 `unavailable`: the M3 keys are not configured (fail closed).
pub(crate) fn keys_unavailable() -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        codes::UNAVAILABLE,
        "device provisioning keys are not configured on this server",
    )
}

/// `t` plus `secs` seconds.
pub(crate) fn plus_secs(
    t: usgp_proto::UnixMicros,
    secs: u64,
) -> Result<usgp_proto::UnixMicros, ApiError> {
    i64::try_from(secs)
        .ok()
        .and_then(|s| s.checked_mul(1_000_000))
        .and_then(|d| t.as_micros().checked_add(d))
        .and_then(|us| usgp_proto::UnixMicros::new(us).ok())
        .ok_or_else(|| ApiError::internal_error("time out of range"))
}

/// Random bytes from the FIPS DRBG.
pub(crate) fn random<const N: usize>() -> Result<[u8; N], ApiError> {
    let mut b = [0u8; N];
    usgp_crypto::fill_random(&mut b).map_err(ApiError::internal_error)?;
    Ok(b)
}

pub(crate) fn code_id(ctx: &RequestCtx) -> Result<AuthCodeId, ApiError> {
    AuthCodeId::parse(ctx.params.get(0)).map_err(|_| ApiError::not_found("code"))
}

/// `POST /v1/auth-codes`.
pub(crate) async fn issue<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let max = api.config().limits.max_json_bytes;
    let body = read_body(req, max).await?;
    let wire = parse_json!(IssueAuthCodeRequest, &body, max)?;
    let v = wire.validate().map_err(|e| field_error(&e))?;
    let keys = api.provisioning_keys().ok_or_else(keys_unavailable)?;
    let c = &api.config().device;
    let ttl = v.ttl_s.map_or(c.code_default_ttl.as_secs(), u64::from);
    if ttl > c.code_max_ttl.as_secs() {
        return Err(ApiError::unprocessable(
            codes::OUT_OF_RANGE
                .with_param("ttl_s")
                .unwrap_or(codes::OUT_OF_RANGE),
            format!(
                "ttl_s must be 1 to {} seconds on this server",
                c.code_max_ttl.as_secs()
            ),
        ));
    }
    for _ in 0..DRAWS {
        let at = api.now()?;
        let expires_at = plus_secs(at, ttl)?;
        let raw = Zeroizing::new(random::<8>()?);
        let code = AuthCode::from_random_bytes(&raw);
        drop(raw);
        let id = AuthCodeId::from_random_bytes(random::<16>()?);
        let rec = NewAuthCode {
            id,
            code_hmac: keys.code_tag(&code),
            issued_by: ctx.principal.operator.id,
            issued_at: at,
            expires_at,
            note: v.note.clone(),
        };
        let mut tx = api.store().begin().await?;
        match tx.insert_auth_code(&rec).await {
            Ok(()) => {}
            // The HMAC exists already: draw another code.
            Err(DbError::Conflict { .. }) => continue,
            Err(e) => return Err(e.into()),
        }
        let d = ctx
            .ok("auth_code.issued")
            .target("auth_code", &id.to_string())
            .detail(
                Detail::new()
                    .with("expires_at_us", &expires_at.as_micros())
                    .with("ttl_s", &ttl)
                    .with("has_note", &v.note.is_some()),
            );
        let r = api.append(&mut tx, &d).await?;
        api.commit(tx, &[r]).await?;
        let out = AuthCodeIssuedV1 {
            id,
            code,
            expires_at,
        };
        let json = out.to_json_zeroizing().map_err(ApiError::internal_error)?;
        let mut resp = Response::new(ApiBody::full(Bytes::copy_from_slice(&json)));
        *resp.status_mut() = StatusCode::CREATED;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static(usgp_proto::api::JSON_MEDIA_TYPE),
        );
        return Ok(resp);
    }
    Err(ApiError::internal_error(
        "code space collision on every draw",
    ))
}

/// `GET /v1/auth-codes`.
pub(crate) async fn list<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    let list = AuthCodeList {
        codes: tx
            .list_auth_codes()
            .await?
            .iter()
            .map(|c| c.view(at))
            .collect(),
    };
    let d = ctx
        .ok("auth_code.list.read")
        .detail(Detail::new().with("count", &list.codes.len()));
    let r = api.append(&mut tx, &d).await?;
    api.commit(tx, &[r]).await?;
    json_response!(StatusCode::OK, &list)
}

/// `DELETE /v1/auth-codes/{id}`.
pub(crate) async fn revoke<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let id = code_id(ctx)?;
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    if tx.auth_code(id).await?.is_none() {
        return Err(ApiError::not_found("code"));
    }
    match tx.revoke_auth_code(id, ctx.principal.operator.id, at).await {
        Ok(()) => {}
        Err(DbError::Conflict { .. }) => {
            return Err(ApiError::conflict(
                codes::WRONG_STATE,
                "the code is already used or revoked",
            ));
        }
        Err(e) => return Err(e.into()),
    }
    let view = tx
        .auth_code(id)
        .await?
        .ok_or_else(|| ApiError::internal_error("revoked code vanished"))?
        .view(at);
    let d = ctx
        .ok("auth_code.revoked")
        .target("auth_code", &id.to_string());
    let r = api.append(&mut tx, &d).await?;
    api.commit(tx, &[r]).await?;
    json_response!(StatusCode::OK, &view)
}
