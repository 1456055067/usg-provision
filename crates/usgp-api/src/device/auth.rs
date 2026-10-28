//! Bearer sessions on the device listener (plan M3 section 3.1).
//!
//! Every route except open carries `Authorization: Bearer <token>`. The
//! token is 32 DRBG bytes (base64url), sent once in the open response;
//! the server keeps only its SHA-256 and finds the session by it. The
//! token is bound to that one session:
//!
//! - before the wipe confirmation, the session expires at `expires_at`
//!   (pending TTL, OPEN-TGT-1); an expired session is moved to `expired`
//!   (audited) on its next request and answers 403 `session_ended`;
//! - after the confirmation, it reaches only its own job (chunk fetch and
//!   progress while the job is unfinished) and its own status;
//! - a refused, cancelled, expired or ended session reads its status only.
//!
//! A missing, malformed or unknown token is 401 `invalid_token` with
//! `WWW-Authenticate: Bearer` and `Connection: close`, audited under the
//! per-source cap.

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-2, IA-3 - every device request names its session by a
//   DRBG token; the token is the session's only handle.
// - NIST 800-53: IA-5(1) / SC-28 - only the token's SHA-256 is stored; the
//   token is zeroized after hashing and never logged.
// - NIST 800-53: AC-12 (Session Termination) - pending sessions expire;
//   final sessions only read their status.
// - NIST 800-53: SC-23 (Session Authenticity) - token bound to one session.
// - SPEC: specs/targeting.md#REQ-TGT-012, #REQ-TGT-015
// - Decision 0020 (consequences: authorised token, bound and expiring)
// - RFC 6750 §2.1, §3 (Bearer, WWW-Authenticate)

use std::net::IpAddr;

use hyper::StatusCode;
use hyper::header::{self, HeaderMap};
use usgp_audit::{Actor, AuditDraft, Detail, Interface, Outcome};
use usgp_db::{DbError, DeviceSession, RepoTx, Store};
use usgp_proto::device::SessionState;
use usgp_proto::{SessionId, SessionToken, codes};

use super::routes::DeviceRoute;
use crate::context::{Api, system_draft};
use crate::error::ApiError;
use crate::handlers::code_of;
use crate::handlers::sessions::{PENDING, macs_text};
use crate::routes::Params;

/// `WWW-Authenticate` on a device 401 (RFC 6750 §3).
pub const DEVICE_WWW_AUTHENTICATE: &str = "Bearer realm=\"usg-provision-device\"";

/// End reason of an expired session.
pub(crate) const SESSION_EXPIRED: &str = "session_expired";

/// One device request: where from, which route, which session.
#[derive(Debug, Clone)]
pub struct DeviceCtx {
    /// Peer `ip:port`.
    pub source: String,
    /// Peer address.
    pub ip: IpAddr,
    /// The matched route.
    pub route: &'static DeviceRoute,
    /// Path parameters.
    pub params: Params,
    /// The session (every route but open).
    pub session: Option<DeviceSession>,
}

/// The audit actor of a device session (plan M3 section 7: kind
/// `device_session`, id, MACs and source address, claimed values marked).
#[must_use]
pub fn session_actor(s: &DeviceSession) -> Actor {
    opened_actor(s.id, &macs_text(s), s.source_ip)
}

/// The actor of a session just opened (its `device.session.opened`
/// record names the new session, not an anonymous device).
pub(crate) fn opened_actor(id: SessionId, macs: &str, source_ip: IpAddr) -> Actor {
    Actor::device_session(
        &id.to_string(),
        &format!("macs {macs} (claimed); source {source_ip}"),
    )
}

impl DeviceCtx {
    /// A draft by `actor` (the session being opened) through the device
    /// listener, from this request's source.
    pub(crate) fn draft_as(&self, actor: Actor, event: &str, outcome: Outcome) -> AuditDraft {
        AuditDraft::new(event, outcome, actor, Interface::DeviceApi).source(&self.source)
    }
}

impl DeviceCtx {
    /// The audit actor: the session, or an unidentified device on open.
    #[must_use]
    pub fn actor(&self) -> Actor {
        self.session.as_ref().map_or_else(
            || Actor::unauthenticated(Some("device (no session)")),
            session_actor,
        )
    }

    /// A draft for this request: the session's actor, interface
    /// `device_api`,
    /// source address, and the session as default target.
    #[must_use]
    pub fn draft(&self, event: &str, outcome: Outcome) -> AuditDraft {
        let d = AuditDraft::new(event, outcome, self.actor(), Interface::DeviceApi)
            .source(&self.source);
        match &self.session {
            Some(s) => d.target("device_session", &s.id.to_string()),
            None => d,
        }
    }

    /// A success draft.
    #[must_use]
    pub fn ok(&self, event: &str) -> AuditDraft {
        self.draft(event, Outcome::Success)
    }

    /// The session (present on every bearer route).
    pub(crate) fn session(&self) -> Result<&DeviceSession, ApiError> {
        self.session
            .as_ref()
            .ok_or_else(|| ApiError::internal_error("bearer route without a session"))
    }
}

/// Why a bearer token was not accepted (all 401 `invalid_token`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerFailure {
    /// No `Authorization` header.
    Missing,
    /// Not `Bearer <43 base64url characters>`.
    Malformed,
    /// No session has this token.
    Unknown,
}

impl BearerFailure {
    /// The audit reason.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Missing => "no_token",
            Self::Malformed => "malformed_token",
            Self::Unknown => "unknown_token",
        }
    }
}

/// The session named by the request's bearer token.
///
/// # Errors
///
/// `Ok(Err(BearerFailure))` for a 401; `Err` if the lookup failed.
pub(crate) async fn bearer_session<S: Store + 'static>(
    api: &Api<S>,
    headers: &HeaderMap,
) -> Result<Result<DeviceSession, BearerFailure>, ApiError> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(Err(BearerFailure::Missing));
    };
    let Some(token) = SessionToken::from_authorization(value.as_bytes()) else {
        return Ok(Err(BearerFailure::Malformed));
    };
    let digest = usgp_crypto::sha256(token.expose().as_bytes());
    drop(token);
    let mut tx = api.store().begin().await?;
    let s = tx.device_session_by_token(&digest).await;
    tx.rollback().await;
    Ok(s?.ok_or(BearerFailure::Unknown))
}

/// The 401 for a device request.
#[must_use]
pub fn invalid_token() -> ApiError {
    ApiError::new(
        StatusCode::UNAUTHORIZED,
        codes::INVALID_TOKEN,
        "a valid session token is required",
    )
}

/// The refusal for a session in state `st` on a route that needs another
/// state.
pub(crate) fn state_error(st: SessionState) -> ApiError {
    match st {
        SessionState::AwaitingAuthorisation => ApiError::new(
            StatusCode::FORBIDDEN,
            codes::NOT_AUTHORISED,
            "the session is not authorised yet; enter the code or wait for approval",
        ),
        SessionState::Authorised => ApiError::conflict(
            codes::WRONG_STATE,
            "the request does not fit the session's state",
        ),
        SessionState::Confirmed => ApiError::conflict(
            codes::JOB_STARTED,
            "the wipe was confirmed and the job has started; it cannot be changed or cancelled",
        ),
        SessionState::Refused => ApiError::new(
            StatusCode::FORBIDDEN,
            codes::SESSION_REFUSED,
            "the session was refused",
        ),
        SessionState::Cancelled | SessionState::Expired | SessionState::Ended => ApiError::new(
            StatusCode::FORBIDDEN,
            codes::SESSION_ENDED,
            "the session has ended",
        ),
    }
}

/// Refuses unless the session is in one of `allowed`.
pub(crate) fn require(s: &DeviceSession, allowed: &[SessionState]) -> Result<(), ApiError> {
    if allowed.contains(&s.state) {
        Ok(())
    } else {
        Err(state_error(s.state))
    }
}

impl<S: Store + 'static> Api<S> {
    /// Moves a pending session past its expiry to `expired` (audited
    /// `device.session.expired`), and returns the session as it now is.
    pub(crate) async fn expire_if_due(&self, s: DeviceSession) -> Result<DeviceSession, ApiError> {
        let at = self.now()?;
        if !PENDING.contains(&s.state) || at < s.expires_at {
            return Ok(s);
        }
        let mut tx = self.store().begin().await?;
        match tx
            .set_device_session_state(
                s.id,
                &PENDING,
                SessionState::Expired,
                Some(&code_of(SESSION_EXPIRED)),
                at,
            )
            .await
        {
            Ok(()) => {
                let d = expired_draft(&s);
                let r = self.append(&mut tx, &d).await?;
                self.commit(tx, &[r]).await?;
            }
            // Another request moved it first.
            Err(DbError::Conflict { .. }) => tx.rollback().await,
            Err(e) => return Err(e.into()),
        }
        let mut tx = self.store().begin().await?;
        let now = tx.device_session(s.id).await;
        tx.rollback().await;
        now?.ok_or_else(|| ApiError::internal_error("session vanished"))
    }

    /// The expiry sweep (maintenance): every pending session past its
    /// expiry becomes `expired`, one `device.session.expired` record each,
    /// in one transaction. Returns how many expired.
    ///
    /// # Errors
    ///
    /// [`ApiError`] if the store or the audit write failed (nothing
    /// changed then).
    pub async fn expire_device_sessions(&self) -> Result<usize, ApiError> {
        let at = self.now()?;
        let mut tx = self.store().begin().await?;
        let ids = tx.expire_device_sessions(at).await?;
        if ids.is_empty() {
            tx.rollback().await;
            return Ok(0);
        }
        let mut recs = Vec::with_capacity(ids.len());
        for id in &ids {
            let d = system_draft("device.session.expired", Outcome::Success)
                .target("device_session", &id.to_string())
                .reason(SESSION_EXPIRED);
            recs.push(self.append(&mut tx, &d).await?);
        }
        self.commit(tx, &recs).await?;
        Ok(ids.len())
    }
}

fn expired_draft(s: &DeviceSession) -> AuditDraft {
    system_draft("device.session.expired", Outcome::Success)
        .target("device_session", &s.id.to_string())
        .reason(SESSION_EXPIRED)
        .detail(
            Detail::new()
                .with("macs", &macs_text(s))
                .with("source_ip", &s.source_ip.to_string()),
        )
}
