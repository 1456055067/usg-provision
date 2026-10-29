//! Device sessions as the operator sees them: list, approve, refuse
//! (plan M3 section 3.5, REQ-TGT-014, REQ-TGT-016).
//!
//! Approval names the display code shown on the device's screen; it must
//! equal the session's, which binds the approval to the device in front of
//! the operator (plan section 6, "approval confusion").

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3, IA-11 - a session is authorised only by an
//   operator approval bound to its display code, or by a code (device
//   routes). IA-3 is partial: the device itself is identified only by
//   claimed values (POAM IA-3 (TB-2) in `device::auth`).
// - NIST 800-53: AU-2, AU-3, AU-12 - list, approval, refused approval and
//   refusal audited (decision 0018 item 10).
// - SPEC: specs/targeting.md#REQ-TGT-014, #REQ-TGT-016
// - Decisions 0018 item 1, 0020 item 3

use std::collections::HashMap;

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use usgp_audit::Detail;
use usgp_db::{DbError, DeviceSession, RepoTx, SessionAuth, Store};
use usgp_proto::device::SessionState;
use usgp_proto::ops::{ApproveSessionRequest, DeviceSessionList, RefuseSessionRequest};
use usgp_proto::{BootServiceId, DisplayName, SessionId, codes};

use super::{code_of, field_error, json_response, parse_json, read_body};
use crate::body::ApiBody;
use crate::context::{Api, RequestCtx};
use crate::error::ApiError;

/// States in which a session is still pending (before its confirmation).
pub(crate) const PENDING: [SessionState; 2] = [
    SessionState::AwaitingAuthorisation,
    SessionState::Authorised,
];

/// End reason of a session an operator refused.
pub(crate) const OPERATOR_REFUSED: &str = "operator_refused";

fn session_id(ctx: &RequestCtx) -> Result<SessionId, ApiError> {
    SessionId::parse(ctx.params.get(0)).map_err(|_| ApiError::not_found("device session"))
}

/// The value of query parameter `name`, if the query is exactly
/// `name=<value>` (or absent).
pub(crate) fn single_query<'a, B>(
    req: &'a Request<B>,
    name: &str,
) -> Result<Option<&'a str>, ApiError> {
    let Some(q) = req.uri().query() else {
        return Ok(None);
    };
    match q.split_once('=') {
        Some((k, v)) if k == name && !v.is_empty() && !v.contains('&') => Ok(Some(v)),
        _ => Err(ApiError::bad_request(format!(
            "the only query parameter allowed is {name}"
        ))),
    }
}

/// Boot-service names, looked up once each.
pub(crate) async fn bs_name<T: RepoTx>(
    tx: &mut T,
    cache: &mut HashMap<BootServiceId, Option<DisplayName>>,
    id: Option<BootServiceId>,
) -> Result<Option<DisplayName>, ApiError> {
    let Some(id) = id else {
        return Ok(None);
    };
    if let Some(n) = cache.get(&id) {
        return Ok(n.clone());
    }
    let n = tx.boot_service(id).await?.map(|b| b.name);
    cache.insert(id, n.clone());
    Ok(n)
}

/// `GET /v1/device-sessions[?state=]`.
pub(crate) async fn list<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: &Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let states: Vec<SessionState> = match single_query(req, "state")? {
        None => Vec::new(),
        Some(v) => vec![
            SessionState::parse(v).ok_or_else(|| ApiError::bad_request("unknown session state"))?,
        ],
    };
    let mut tx = api.store().begin().await?;
    let mut names = HashMap::new();
    let mut sessions = Vec::new();
    for s in tx.list_device_sessions(&states).await? {
        let name = bs_name(&mut tx, &mut names, s.boot_service_id).await?;
        sessions.push(s.view(name));
    }
    let list = DeviceSessionList { sessions };
    let d = ctx
        .ok("device_session.list.read")
        .detail(Detail::new().with("count", &list.sessions.len()));
    let r = api.append(&mut tx, &d).await?;
    api.commit(tx, &[r]).await?;
    json_response!(StatusCode::OK, &list)
}

/// Identity of a session for audit detail (claimed values marked so).
pub(crate) fn identity(s: &DeviceSession) -> Detail {
    Detail::new()
        .with("macs", &macs_text(s))
        .with("source_ip", &s.source_ip.to_string())
        .with("display_code", s.display_code.as_str())
        .with("claimed", "macs,firmware,arch,secure_boot,memory_bytes")
}

/// The MACs, comma separated.
pub(crate) fn macs_text(s: &DeviceSession) -> String {
    s.macs
        .as_slice()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// `POST /v1/device-sessions/{id}/approve`.
pub(crate) async fn approve<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let id = session_id(ctx)?;
    let max = api.config().limits.max_json_bytes;
    let body = read_body(req, max).await?;
    let wire = parse_json!(ApproveSessionRequest, &body, max)?;
    let code = wire.validate().map_err(|e| field_error(&e))?;
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    let s = tx
        .lock_device_session(id)
        .await?
        .ok_or_else(|| ApiError::not_found("device session"))?;
    if s.state != SessionState::AwaitingAuthorisation {
        return Err(ApiError::conflict(
            codes::WRONG_STATE,
            format!("the session is {}, not awaiting authorisation", s.state),
        ));
    }
    if at >= s.expires_at {
        return Err(ApiError::conflict(
            codes::SESSION_ENDED,
            "the session has expired",
        ));
    }
    // Display codes are not secrets; the comparison binds the approval to
    // the screen the operator reads.
    if code != s.display_code {
        return Err(ApiError::unprocessable(
            codes::DISPLAY_CODE_MISMATCH,
            "the display code does not match this session; read it again from the device",
        )
        .detail(identity(&s)));
    }
    match tx
        .authorise_device_session(id, SessionAuth::Approval(ctx.principal.operator.id), at)
        .await
    {
        Ok(()) => {}
        Err(DbError::Conflict { .. }) => {
            return Err(ApiError::conflict(
                codes::WRONG_STATE,
                "the session can no longer be approved",
            ));
        }
        Err(e) => return Err(e.into()),
    }
    let d = ctx
        .ok("device.session.approved")
        .target("device_session", &id.to_string())
        .detail(identity(&s).with("method", "approval"));
    let r = api.append(&mut tx, &d).await?;
    let mut names = HashMap::new();
    let after = tx
        .device_session(id)
        .await?
        .ok_or_else(|| ApiError::internal_error("approved session vanished"))?;
    let view = after.view(bs_name(&mut tx, &mut names, after.boot_service_id).await?);
    api.commit(tx, &[r]).await?;
    json_response!(StatusCode::OK, &view)
}

/// `POST /v1/device-sessions/{id}/refuse`.
pub(crate) async fn refuse<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let id = session_id(ctx)?;
    let max = api.config().limits.max_json_bytes;
    let body = read_body(req, max).await?;
    let wire = parse_json!(RefuseSessionRequest, &body, max)?;
    let note = wire.validate().map_err(|e| field_error(&e))?;
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    let s = tx
        .lock_device_session(id)
        .await?
        .ok_or_else(|| ApiError::not_found("device session"))?;
    if !PENDING.contains(&s.state) {
        return Err(ApiError::conflict(
            codes::WRONG_STATE,
            format!(
                "the session is {}; only a pending session can be refused",
                s.state
            ),
        ));
    }
    match tx
        .set_device_session_state(
            id,
            &PENDING,
            SessionState::Refused,
            Some(&code_of(OPERATOR_REFUSED)),
            at,
        )
        .await
    {
        Ok(()) => {}
        Err(DbError::Conflict { .. }) => {
            return Err(ApiError::conflict(
                codes::WRONG_STATE,
                "the session can no longer be refused",
            ));
        }
        Err(e) => return Err(e.into()),
    }
    let d = ctx
        .ok("device.session.refused")
        .target("device_session", &id.to_string())
        .reason(OPERATOR_REFUSED)
        .detail(identity(&s).with("has_note", &note.is_some()));
    let r = api.append(&mut tx, &d).await?;
    let mut names = HashMap::new();
    let after = tx
        .device_session(id)
        .await?
        .ok_or_else(|| ApiError::internal_error("refused session vanished"))?;
    let view = after.view(bs_name(&mut tx, &mut names, after.boot_service_id).await?);
    api.commit(tx, &[r]).await?;
    json_response!(StatusCode::OK, &view)
}
