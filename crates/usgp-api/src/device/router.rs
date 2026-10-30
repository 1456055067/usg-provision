//! Per-request pipeline of the device listener.
//!
//! 1. **Route match** against [`super::routes::DEVICE_ROUTES`]: 404 / 405,
//!    audited under the per-source cap.
//! 2. **Credentials** ([`super::auth`]): none on open, the resume
//!    challenge and resume (which proves the job key itself); a job-scoped
//!    resume token on the M4 escrow routes, and on progress once the
//!    session token is unknown; the session's bearer token elsewhere: 401
//!    `invalid_token` with `WWW-Authenticate: Bearer` and
//!    `Connection: close`, audited under the per-source cap, for a
//!    missing, malformed or unknown token and for a token sent from
//!    another source network than its session's (decision 0023 item 1).
//!    A pending session past its expiry (or idle while unauthorised) is
//!    expired (audited) and refused; a confirmed session whose token has
//!    lapsed with its job is refused 403 `session_ended` (audited).
//! 3. **Media type** of JSON routes (415).
//! 4. The **handler**. Its success records are written in its own
//!    transaction; an error it returns is audited here unless it already
//!    wrote one (high-volume routes under the per-source cap).
//!
//! A refusal because the audit record could not be written is answered
//! 503 `audit_unavailable` on this listener (plan section 3.1: the agent
//! retries 503), never 2xx.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3, SC-23, AC-12 - no handler but open runs without a
//   live session from its own source network; the session state is
//   checked by each handler (decision 0023 item 1).
// - NIST 800-53: AU-2, AU-3, AU-12 - refusals audited with the session
//   (or the source) as actor; AU-4/SC-5 - high-volume refusals capped.
// - NIST 800-53: AU-5 - audit failure refuses the request (503).
// - NIST 800-53: SI-11 - error bodies carry a code and text only; never a
//   token or code value.
// - SPEC: specs/targeting.md#REQ-TGT-012, #REQ-TGT-015
// - RFC 6750 §3 (WWW-Authenticate: Bearer), RFC 9110 §15.5.6 (405 + Allow)

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use usgp_audit::{Actor, AuditDraft, Detail, Interface, Outcome};
use usgp_db::Store;
use usgp_proto::api::JSON_MEDIA_TYPE;
use usgp_proto::codes;

use super::auth::{
    BearerFailure, DEVICE_WWW_AUTHENTICATE, DeviceCtx, bearer_session, invalid_token, lapsed_error,
    resume_bearer, same_source_network,
};
use super::routes::{
    DeviceAuth, DeviceMatch, DeviceRouteId, device_allowed_methods, match_device_route,
};
use super::{confirm, escrow, handlers, job, resume};
use crate::body::ApiBody;
use crate::context::{Api, COMPONENT};
use crate::error::ApiError;
use crate::router::error_response;

/// Audit reason for a token sent from another source network.
pub const TOKEN_SOURCE_MISMATCH: &str = "token_source_mismatch";

/// What the TLS layer established for a device connection (no identity:
/// devices hold no certificate).
#[derive(Debug, Clone, Copy)]
pub struct DeviceConn {
    /// The peer address.
    pub remote: SocketAddr,
}

/// The address a request came from, IPv4-mapped IPv6 as IPv4 (so subnet
/// matching and per-source counts see one form).
#[must_use]
pub fn device_ip(remote: SocketAddr) -> IpAddr {
    match remote.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    }
}

/// The response for `e` on the device listener.
fn device_error(e: &ApiError) -> Response<ApiBody> {
    let mut e = e.clone();
    if e.code() == &codes::AUDIT_UNAVAILABLE {
        e.status = StatusCode::SERVICE_UNAVAILABLE;
    }
    let mut r = error_response(&e);
    if e.status == StatusCode::UNAUTHORIZED {
        r.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(DEVICE_WWW_AUTHENTICATE),
        );
        r.headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    r
}

fn is_json<B>(req: &Request<B>) -> bool {
    req.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case(JSON_MEDIA_TYPE))
}

/// Handles one request on a device connection.
///
/// # Errors
///
/// Never: every failure becomes an error response.
pub async fn handle_device<S: Store + 'static>(
    api: Api<S>,
    conn: Arc<DeviceConn>,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, Infallible> {
    let ip = device_ip(conn.remote);
    let source = conn.remote.to_string();
    let method = req.method().as_str().to_owned();
    let path = req.uri().path().to_owned();
    let request_detail = || {
        Detail::new()
            .with("method", method.as_str())
            .with("path", path.as_str())
            .with("listener", "device_api")
    };
    let anonymous = |event: &str, reason: &str| {
        AuditDraft::new(
            event,
            Outcome::Refused,
            Actor::unauthenticated(Some("device")),
            Interface::DeviceApi,
        )
        .source(&source)
        .reason(reason)
        .detail(request_detail())
    };

    // 1. Route.
    let (route, params) = match match_device_route(&method, &path) {
        DeviceMatch::Found(r, p) => (r, p),
        other => {
            let (e, allow) = if other == DeviceMatch::MethodNotAllowed {
                (
                    ApiError::new(
                        StatusCode::METHOD_NOT_ALLOWED,
                        codes::METHOD_NOT_ALLOWED,
                        "this method is not allowed on this path",
                    ),
                    Some(device_allowed_methods(&path).join(", ")),
                )
            } else {
                (ApiError::not_found("route"), None)
            };
            let d = anonymous("api.request.refused", e.code().as_str());
            let e = api.capped_refusal(ip, "not_routed", d, e).await;
            let mut r = device_error(&e);
            if let Some(a) = allow.and_then(|a| HeaderValue::from_str(&a).ok()) {
                r.headers_mut().insert(header::ALLOW, a);
            }
            return Ok(r);
        }
    };

    // 2. Credentials: the session's bearer token, or (M4) a job-scoped
    // resume token, as the route requires.
    let path_job = usgp_proto::JobId::parse(params.get(0)).ok();
    let try_session = matches!(
        route.auth,
        DeviceAuth::Session | DeviceAuth::SessionOrResume
    );
    let mut session = None;
    let mut resume = None;
    let mut need_resume = route.auth == DeviceAuth::Resume;
    if try_session {
        match bearer_session(&api, req.headers()).await {
            // Decision 0023 item 1: the token is good only from the
            // session's source network.
            Ok(Ok(s)) if !same_source_network(&s, ip) => {
                let d = anonymous("auth.unauthenticated", TOKEN_SOURCE_MISMATCH)
                    .target("device_session", &s.id.to_string())
                    .detail(
                        request_detail()
                            .with("session_source_ip", &s.source_ip.to_string())
                            .with("request_source_ip", &ip.to_string()),
                    );
                let e = api
                    .capped_refusal(ip, TOKEN_SOURCE_MISMATCH, d, invalid_token())
                    .await;
                return Ok(device_error(&e));
            }
            Ok(Ok(s)) => match api.expire_if_due(s).await {
                Ok(s) => session = Some(s),
                Err(e) => return Ok(device_error(&e)),
            },
            // Not a session token: on progress, it may be a resume token.
            Ok(Err(BearerFailure::Unknown)) if route.auth == DeviceAuth::SessionOrResume => {
                need_resume = true;
            }
            Ok(Err(f)) => {
                let d = anonymous("auth.unauthenticated", f.reason());
                let e = api.capped_refusal(ip, f.reason(), d, invalid_token()).await;
                return Ok(device_error(&e));
            }
            Err(e) => {
                let d = anonymous("api.request.failed", codes::INTERNAL.as_str());
                usgp_audit::mirror::emit_unpersisted(COMPONENT, api.chain(), &d);
                return Ok(device_error(&e));
            }
        }
    }
    if need_resume {
        match resume_bearer(&api, req.headers(), path_job).await {
            Ok(Ok(r)) => resume = Some(r),
            Ok(Err(f)) => {
                let mut d = anonymous("auth.unauthenticated", f.reason());
                if let Some(j) = path_job {
                    d = d.target("job", &j.to_string());
                }
                let e = api.capped_refusal(ip, f.reason(), d, invalid_token()).await;
                return Ok(device_error(&e));
            }
            Err(e) => {
                let d = anonymous("api.request.failed", codes::INTERNAL.as_str());
                usgp_audit::mirror::emit_unpersisted(COMPONENT, api.chain(), &d);
                return Ok(device_error(&e));
            }
        }
    }
    let ctx = DeviceCtx {
        source,
        ip,
        route,
        params,
        session,
        resume,
    };

    // A confirmed session whose token lapsed with its job (decision 0023
    // item 1): refused on every route, audited below.
    let lapsed = match &ctx.session {
        Some(s) => match api.confirmed_lapsed(s).await {
            Ok(l) => l,
            Err(e) => return Ok(device_error(&e)),
        },
        None => None,
    };

    // 3. Media type.
    let result = if let Some(lapse) = lapsed {
        Err(lapsed_error(lapse))
    } else if route.json_body && !is_json(&req) {
        Err(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            codes::UNSUPPORTED_MEDIA_TYPE,
            "the request body must be application/json",
        ))
    } else {
        // 4. Handler.
        dispatch(&api, &ctx, req).await
    };
    match result {
        Ok(mut r) => {
            r.headers_mut()
                .entry(header::CACHE_CONTROL)
                .or_insert(HeaderValue::from_static("no-store"));
            Ok(r)
        }
        Err(e) => {
            let e = if e.audited {
                e
            } else {
                audit_device_error(&api, &ctx, e, &method, &path).await
            };
            Ok(device_error(&e))
        }
    }
}

async fn dispatch<S: Store + 'static>(
    api: &Api<S>,
    ctx: &DeviceCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    match ctx.route.id {
        DeviceRouteId::Open => handlers::open(api, ctx, req).await,
        DeviceRouteId::Status => handlers::status(api, ctx).await,
        DeviceRouteId::Code => handlers::code(api, ctx, req).await,
        DeviceRouteId::Packages => handlers::packages(api, ctx).await,
        DeviceRouteId::ChoosePackage => handlers::choose_package(api, ctx, req).await,
        DeviceRouteId::ChooseDisk => handlers::choose_disk(api, ctx, req).await,
        DeviceRouteId::Confirm => confirm::confirm(api, ctx, req).await,
        DeviceRouteId::Cancel => handlers::cancel(api, ctx, req).await,
        DeviceRouteId::End => handlers::end(api, ctx, req).await,
        DeviceRouteId::Chunk => job::chunk(api, ctx).await,
        DeviceRouteId::Progress => job::progress(api, ctx, req).await,
        DeviceRouteId::ResumeChallenge => resume::challenge(api, ctx, req).await,
        DeviceRouteId::Resume => resume::resume(api, ctx, req).await,
        DeviceRouteId::Escrow => escrow::submit(api, ctx, req).await,
        DeviceRouteId::EscrowConfirm => escrow::confirm(api, ctx, req).await,
    }
}

/// Audits a refusal or failure of a device request (capped on the
/// high-volume routes) and returns the error marked audited.
async fn audit_device_error<S: Store + 'static>(
    api: &Api<S>,
    ctx: &DeviceCtx,
    e: ApiError,
    method: &str,
    path: &str,
) -> ApiError {
    let outcome = if e.status.is_server_error() {
        Outcome::Failure
    } else {
        Outcome::Refused
    };
    let event = e.event.unwrap_or(ctx.route.refused_event);
    let mut d = ctx.draft(event, outcome).reason(e.code().as_str());
    if let Some((k, id)) = &e.target {
        d = d.target(k, id);
    }
    let mut detail = e
        .detail
        .clone()
        .unwrap_or_default()
        .with("http_status", &e.status.as_u16())
        .with("http_route", ctx.route.pattern)
        .with("method", method)
        .with("path", path);
    if let Some(cause) = &e.internal {
        detail = detail.with("internal_cause", cause.as_str());
    }
    let d = d.detail(detail);
    if ctx.route.capped_refusals && !e.status.is_server_error() {
        api.capped_refusal(ctx.ip, "device_refusal", d, e).await
    } else {
        api.record_refusal(&d).await;
        e.audited()
    }
}
