//! Per-request pipeline: authenticate, match the route, authorise, run
//! the handler, audit the outcome (plan M2 sections 3.2 and 7).
//!
//! Order matters and is fixed here, not in the handlers:
//!
//! 1. **Authentication** before anything else, so an unauthenticated
//!    request learns nothing (not even whether a route exists): 401 with
//!    `WWW-Authenticate` and an audit record (rate-capped per source),
//!    and `Connection: close`, so the connection is not kept.
//! 2. **Route match**: 404 / 405, audited.
//! 3. **Authorisation** against the route's permission before any path
//!    parameter is parsed or any item is looked up: 403 never reveals
//!    whether an item exists (REQ-RBAC-003). Audited `authz.denied`.
//! 4. The **handler**. Its success records are written in its own
//!    transaction; any error it returns is audited here unless it already
//!    wrote one.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 (Access Enforcement) - permission checked on every
//   route before the handler.
// - NIST 800-53: IA-2 - no request reaches a handler without an
//   authenticated operator.
// - NIST 800-53: AU-2, AU-3, AU-12 - authn failures, denials, refusals and
//   failures audited with who/what/when/where/source/outcome.
// - NIST 800-53: SI-11 - error bodies carry a code and operator text only.
// - NIST 800-53: SC-5 - a 401 closes the connection.
// - SPEC: specs/operator-access.md#REQ-RBAC-001, #REQ-RBAC-003,
//   #REQ-RBAC-005, #REQ-AUD-001
// - RFC 9110 §15.5.2 (401 + WWW-Authenticate), §15.5.4 (403), §15.5.6
//   (405 + Allow), §15.5.16 (415)

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use usgp_audit::{AuditDraft, Detail, Interface, Outcome};
use usgp_crypto::PeerCertificate;
use usgp_db::Store;
use usgp_proto::api::{JSON_MEDIA_TYPE, WWW_AUTHENTICATE};
use usgp_proto::codes;

use crate::authn::{AuthClass, authenticate};
use crate::body::ApiBody;
use crate::context::{Api, COMPONENT, RequestCtx};
use crate::error::ApiError;
use crate::handlers;
use crate::rbac::allows;
use crate::routes::{Match, allowed_methods, match_route};

/// What the TLS layer established for a connection.
#[derive(Debug, Clone)]
pub struct ConnInfo {
    /// The validated client certificate, if one was presented.
    pub peer: Option<PeerCertificate>,
    /// The peer address.
    pub remote: SocketAddr,
}

/// The error response for `e`.
#[must_use]
pub fn error_response(e: &ApiError) -> Response<ApiBody> {
    let body = serde_json::to_vec(&e.body).unwrap_or_else(|_| b"{}".to_vec());
    let mut r = Response::new(ApiBody::full(body));
    *r.status_mut() = e.status;
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(JSON_MEDIA_TYPE),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if e.www_authenticate {
        h.insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static(WWW_AUTHENTICATE),
        );
        // An unauthenticated peer does not keep its connection slot
        // through keep-alive (finding SEC-001).
        h.insert(header::CONNECTION, HeaderValue::from_static("close"));
    }
    r
}

fn unauthenticated_draft(event: &str, actor: usgp_audit::Actor, source: &str) -> AuditDraft {
    AuditDraft::new(event, Outcome::Refused, actor, Interface::Api).source(source)
}

/// Handles one request on an established connection.
///
/// # Errors
///
/// Never: every failure becomes an error response.
pub async fn handle<S: Store + 'static>(
    api: Api<S>,
    conn: Arc<ConnInfo>,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, Infallible> {
    let source = conn.remote.to_string();
    let method = req.method().as_str().to_owned();
    let path = req.uri().path().to_owned();
    let request_detail = || {
        Detail::new()
            .with("method", method.as_str())
            .with("path", path.as_str())
    };

    // 1. Authentication.
    let principal = match authenticate(api.store(), conn.peer.as_ref()).await {
        Ok(Ok(p)) => p,
        Ok(Err(f)) => {
            if api.inner.unauth.admit(
                conn.remote.ip(),
                f.reason(),
                AuthClass::of_http(&f),
                Instant::now(),
            ) {
                let d = unauthenticated_draft(f.event(), f.actor(), &source)
                    .reason(f.reason())
                    .detail(request_detail());
                api.record_refusal(&d).await;
            }
            return Ok(error_response(&ApiError::unauthenticated()));
        }
        Err(e) => {
            let d = unauthenticated_draft(
                "api.request.failed",
                usgp_audit::Actor::unauthenticated(None),
                &source,
            )
            .reason(codes::INTERNAL.as_str())
            .detail(request_detail().with("cause", &e.to_string()));
            usgp_audit::mirror::emit_unpersisted(COMPONENT, api.chain(), &d);
            return Ok(error_response(&ApiError::internal_error(e)));
        }
    };

    // 2. Route.
    let (route, params) = match match_route(&method, &path) {
        Match::Found(r, p) => (r, p),
        other => {
            let (e, allow) = if other == Match::MethodNotAllowed {
                let allow = allowed_methods(&path);
                (
                    ApiError::new(
                        StatusCode::METHOD_NOT_ALLOWED,
                        codes::METHOD_NOT_ALLOWED,
                        "this method is not allowed on this path",
                    ),
                    Some(allow.join(", ")),
                )
            } else {
                (ApiError::not_found("route"), None)
            };
            let d = AuditDraft::new(
                "api.request.refused",
                Outcome::Refused,
                principal.actor(),
                Interface::Api,
            )
            .source(&source)
            .reason(e.code().as_str())
            .detail(request_detail());
            api.record_refusal(&d).await;
            let mut r = error_response(&e);
            if let Some(a) = allow.and_then(|a| HeaderValue::from_str(&a).ok()) {
                r.headers_mut().insert(header::ALLOW, a);
            }
            return Ok(r);
        }
    };

    let ctx = RequestCtx {
        principal,
        source,
        route,
        params,
    };

    // 3. Authorisation (before any lookup: no existence leak).
    let role = ctx.principal.operator.role;
    if !route.access.permissions().iter().any(|&p| allows(role, p)) {
        let d = ctx
            .draft("authz.denied", Outcome::Refused)
            .reason(codes::FORBIDDEN.as_str())
            .detail(
                request_detail()
                    .with("route", route.pattern)
                    .with("permission", route.access.as_str()),
            );
        api.record_refusal(&d).await;
        return Ok(error_response(&ApiError::forbidden()));
    }

    // JSON routes need a JSON body (415 otherwise).
    if route.json_body && !is_json(&req) {
        let e = ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            codes::UNSUPPORTED_MEDIA_TYPE,
            "the request body must be application/json",
        );
        audit_error(&api, &ctx, &e).await;
        return Ok(error_response(&e));
    }

    // 4. Handler.
    match handlers::dispatch(&api, &ctx, req).await {
        Ok(mut r) => {
            r.headers_mut()
                .entry(header::CACHE_CONTROL)
                .or_insert(HeaderValue::from_static("no-store"));
            Ok(r)
        }
        Err(e) => {
            if !e.audited {
                audit_error(&api, &ctx, &e).await;
            }
            Ok(error_response(&e))
        }
    }
}

fn is_json<B>(req: &Request<B>) -> bool {
    req.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case(JSON_MEDIA_TYPE))
}

/// Audits a refusal or failure of an authenticated request.
pub(crate) async fn audit_error<S: Store + 'static>(api: &Api<S>, ctx: &RequestCtx, e: &ApiError) {
    let outcome = if e.status.is_server_error() {
        Outcome::Failure
    } else {
        Outcome::Refused
    };
    let event = e.event.unwrap_or(ctx.route.refused_event);
    let mut d = ctx.draft(event, outcome).reason(e.code().as_str());
    match &e.target {
        Some((k, id)) => d = d.target(k, id),
        None if !ctx.params.get(0).is_empty() => {
            d = d.target(ctx.route.target_kind, ctx.params.get(0));
        }
        None => {}
    }
    let mut detail = e
        .detail
        .clone()
        .unwrap_or_default()
        .with("http_status", &e.status.as_u16())
        .with("http_route", ctx.route.pattern);
    if let Some(cause) = &e.internal {
        detail = detail.with("internal_cause", cause.as_str());
    }
    api.record_refusal(&d.detail(detail)).await;
}
