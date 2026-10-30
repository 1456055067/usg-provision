//! Bearer sessions on the device listener (plan M3 section 3.1).
//!
//! Every route except open carries `Authorization: Bearer <token>`. The
//! token is 32 DRBG bytes (base64url), sent once in the open response;
//! the server keeps only its SHA-256 and finds the session by it. The
//! token is bound to that one session and to the session's source
//! network, with an expiry (decision 0023 item 1, amending decision
//! 0020):
//!
//! - a request from another source network (another IPv4 address, or an
//!   address outside the IPv6 /64 the session was opened from) is refused
//!   401 `invalid_token` and audited, as an unknown token is;
//! - before the wipe confirmation, the session expires at `expires_at`
//!   (pending TTL, OPEN-TGT-1), and a session never authorised expires
//!   sooner when not heard from for `unauthorised_idle_timeout` (finding
//!   SEC-001); an expired session is moved to `expired` (audited) on its
//!   next request and answers 403 `session_ended`;
//! - after the confirmation, it reaches only its own job (chunk fetch and
//!   progress while the job is unfinished) and its own status, and it
//!   lapses with the job's lost-job timeout ([`confirmed_lapse_at`]): 403
//!   `session_ended` on every route, audited;
//! - a refused, cancelled, expired or ended session reads its status only.
//!
//! A missing, malformed or unknown token is 401 `invalid_token` with
//! `WWW-Authenticate: Bearer` and `Connection: close`, audited under the
//! per-source cap.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-23 (Session Authenticity) - every device request names
//   its session by a DRBG token, the session's only handle, bound to that
//   session and to its source network (decision 0023 item 1).
// - NIST 800-53: AC-12 (Session Termination) - pending sessions expire,
//   idle unauthorised ones sooner; a confirmed session lapses with its
//   job's lost-job timeout; final sessions only read their status.
// - NIST 800-53: IA-11 (Re-authentication) - the token carries an
//   authorisation (operator code or approval) that ends with the session;
//   nothing outlives it.
// - NIST 800-53: IA-3 (Device Identification and Authentication) -
//   PARTIAL: the device is identified only by claimed values (MACs) and
//   its source network; it holds no credential of its own.
// - NIST 800-53: IA-5(1) / SC-28 - only the token's SHA-256 is stored; the
//   token is zeroized after hashing and never logged.
// - SPEC: specs/targeting.md#REQ-TGT-012, #REQ-TGT-015
// - Decision 0020 (consequences: authorised token, bound and expiring), as
//   amended by decision 0023 item 1
// - RFC 6750 §2.1, §3 (Bearer, WWW-Authenticate)

// POAM: IA-3 (TB-2) - the pre-boot device has no credential of its own
// (decision 0020); a token is bound only to its source network, so a host
// on the same network (the same IPv4 address, or the same IPv6 /64) that
// learns a token can use it until the session ends or lapses (decision
// 0023 item 1 residual). Device attestation is not in M3.

// POAM: SC-23/AC-12 (decision 0023 item 1 residual) - the token is bound to
// the source network, not to the TLS channel (no channel binding over
// HTTP/1.1 bearer tokens here); a confirmed session stays usable for up to
// twice `jobs.lost_after_s` after its job was last heard from, so a lost
// job can be resumed (REQ-JOB-012). The binding has a cost: if a device's
// IPv4 address (or IPv6 /64) changes after the wipe, every later request
// gets 401 `invalid_token` and the job becomes `lost` (finding SEC-013.2;
// the agent is to report this 401 distinctly).

use std::net::IpAddr;

use hyper::StatusCode;
use hyper::header::{self, HeaderMap};
use usgp_audit::{Actor, AuditDraft, Detail, Interface, Outcome};
use usgp_db::{DbError, DeviceSession, Job, JobV2, RepoTx, Store, source_network};
use usgp_proto::device::SessionState;
use usgp_proto::{JobId, SessionId, SessionToken, UnixMicros, codes};

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

/// Audit reason when a confirmed session's token has lapsed.
pub(crate) const SESSION_LAPSED: &str = "session_lapsed";

/// `t` plus `d` (saturating).
fn plus(t: UnixMicros, d: std::time::Duration) -> UnixMicros {
    let us = i64::try_from(d.as_micros()).unwrap_or(i64::MAX);
    UnixMicros::new(t.as_micros().saturating_add(us)).unwrap_or(t)
}

/// `t` minus `d` (saturating at 0).
fn minus(t: UnixMicros, d: std::time::Duration) -> UnixMicros {
    let us = i64::try_from(d.as_micros()).unwrap_or(i64::MAX);
    UnixMicros::new(t.as_micros().saturating_sub(us).max(0)).unwrap_or(t)
}

/// True if a pending session is due to expire at `at`: past its TTL, or
/// never authorised and not heard from since `idle` before `at` (finding
/// SEC-001).
pub(crate) fn pending_due(s: &DeviceSession, at: UnixMicros, idle: std::time::Duration) -> bool {
    PENDING.contains(&s.state)
        && (at >= s.expires_at
            || (s.state == SessionState::AwaitingAuthorisation
                && s.last_seen_at <= minus(at, idle)))
}

/// When a confirmed session's token lapses (decision 0023 item 1: "a
/// confirmed session expires with its job's lost-job timeout").
///
/// - Unfinished job: one `lost_after` after the job was declared lost,
///   that is, `2 × lost_after` after it was last heard from (its last
///   report, or its start). Until then a lost job can still be resumed
///   (REQ-JOB-012: Lost → Running when the device reports again).
/// - Finished job: `lost_after` after it finished (the agent can still
///   read its status, then nothing).
#[must_use]
pub fn confirmed_lapse_at(job: &Job, lost_after: std::time::Duration) -> UnixMicros {
    lapse_at(
        job.state,
        job.finished_at,
        job.last_report_at,
        job.started_at,
        lost_after,
    )
}

/// As [`confirmed_lapse_at`] for a v2 (nine-step) job (M4).
#[must_use]
pub fn confirmed_lapse_at_v2(job: &JobV2, lost_after: std::time::Duration) -> UnixMicros {
    lapse_at(
        job.state,
        job.finished_at,
        job.last_report_at,
        job.started_at,
        lost_after,
    )
}

fn lapse_at(
    state: usgp_proto::JobState,
    finished_at: Option<UnixMicros>,
    last_report_at: Option<UnixMicros>,
    started_at: UnixMicros,
    lost_after: std::time::Duration,
) -> UnixMicros {
    match finished_at {
        Some(f) if state.is_final() => plus(f, lost_after),
        _ => {
            let heard = last_report_at.unwrap_or(started_at).max(started_at);
            plus(plus(heard, lost_after), lost_after)
        }
    }
}

/// True if the request comes from the session's source network (decision
/// 0023 item 1: an IPv4 address, or an IPv6 /64).
#[must_use]
pub fn same_source_network(s: &DeviceSession, ip: IpAddr) -> bool {
    source_network(s.source_ip) == source_network(ip)
}

/// A request authenticated by a job-scoped resume token (M4 plan section
/// 3.1): the job it is good for and the session that confirmed the job
/// (the audit actor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumeAuth {
    /// The job the token is scoped to (equal to the path's job).
    pub job_id: JobId,
    /// The session that confirmed the job.
    pub session_id: SessionId,
}

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
    /// The session (session-token routes).
    pub session: Option<DeviceSession>,
    /// The resume token's job (resume-token routes, M4).
    pub resume: Option<ResumeAuth>,
}

/// The audit actor of a device session (plan M3 section 7: kind
/// `device_session`, id, MACs and source address, claimed values marked).
#[must_use]
pub fn session_actor(s: &DeviceSession) -> Actor {
    opened_actor(s.id, &macs_text(s), s.source_ip)
}

/// The actor of a request carrying a job's resume token, or proving its
/// job key (M4): the job's session, marked as the job-key holder.
pub(crate) fn resume_actor(session: SessionId, job: JobId, source_ip: IpAddr) -> Actor {
    Actor::device_session(
        &session.to_string(),
        &format!("job {job} key holder (after restart); source {source_ip}"),
    )
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
    /// The audit actor: the session; the holder of a job's resume token
    /// (named by the job's session, M4); or an unidentified device on open.
    #[must_use]
    pub fn actor(&self) -> Actor {
        match (&self.session, &self.resume) {
            (Some(s), _) => session_actor(s),
            (None, Some(r)) => resume_actor(r.session_id, r.job_id, self.ip),
            (None, None) => Actor::unauthenticated(Some("device (no session)")),
        }
    }

    /// A draft for this request: the session's actor, interface
    /// `device_api`,
    /// source address, and the session as default target.
    #[must_use]
    pub fn draft(&self, event: &str, outcome: Outcome) -> AuditDraft {
        let d = AuditDraft::new(event, outcome, self.actor(), Interface::DeviceApi)
            .source(&self.source);
        match (&self.session, &self.resume) {
            (Some(s), _) => d.target("device_session", &s.id.to_string()),
            (None, Some(r)) => d.target("job", &r.job_id.to_string()),
            (None, None) => d,
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

/// Why a resume token was not accepted (all 401 `invalid_token`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeFailure {
    /// As [`BearerFailure`].
    Bearer(BearerFailure),
    /// Past its expiry or revoked.
    Lapsed,
    /// Scoped to another job than the path's.
    OtherJob,
    /// Its job has ended or is not a v2 job.
    JobEnded,
}

impl ResumeFailure {
    /// The audit reason.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Bearer(b) => b.reason(),
            Self::Lapsed => "resume_token_lapsed",
            Self::OtherJob => "resume_token_other_job",
            Self::JobEnded => "resume_token_job_ended",
        }
    }
}

/// The SHA-256 of the request's bearer token.
fn bearer_digest(headers: &HeaderMap) -> Result<usgp_common::Sha256Digest, BearerFailure> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or(BearerFailure::Missing)?;
    let token =
        SessionToken::from_authorization(value.as_bytes()).ok_or(BearerFailure::Malformed)?;
    Ok(usgp_crypto::sha256(token.expose().as_bytes()))
}

/// The job a request's resume token is good for (M4 plan section 3.1): a
/// live token (unrevoked, unexpired), scoped to `path_job`, whose v2 job
/// has not ended.
///
/// # Errors
///
/// `Ok(Err(ResumeFailure))` for a 401; `Err` if the lookup failed.
pub(crate) async fn resume_bearer<S: Store + 'static>(
    api: &Api<S>,
    headers: &HeaderMap,
    path_job: Option<JobId>,
) -> Result<Result<ResumeAuth, ResumeFailure>, ApiError> {
    let digest = match bearer_digest(headers) {
        Ok(d) => d,
        Err(f) => return Ok(Err(ResumeFailure::Bearer(f))),
    };
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    let t = tx.resume_token(&digest).await;
    let t = match t {
        Ok(Some(t)) => t,
        Ok(None) => {
            tx.rollback().await;
            return Ok(Err(ResumeFailure::Bearer(BearerFailure::Unknown)));
        }
        Err(e) => {
            tx.rollback().await;
            return Err(e.into());
        }
    };
    if !t.live(at) {
        tx.rollback().await;
        return Ok(Err(ResumeFailure::Lapsed));
    }
    if path_job != Some(t.job_id) {
        tx.rollback().await;
        return Ok(Err(ResumeFailure::OtherJob));
    }
    let job = tx.job_v2(t.job_id).await;
    tx.rollback().await;
    match job? {
        Some(j) if !j.state.is_final() => Ok(Ok(ResumeAuth {
            job_id: j.id,
            session_id: j.session_id,
        })),
        _ => Ok(Err(ResumeFailure::JobEnded)),
    }
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
    /// Moves a pending session past its expiry, or idle while never
    /// authorised, to `expired` (audited `device.session.expired`), and
    /// returns the session as it now is.
    pub(crate) async fn expire_if_due(&self, s: DeviceSession) -> Result<DeviceSession, ApiError> {
        let at = self.now()?;
        if !pending_due(&s, at, self.config().device.unauthorised_idle_timeout) {
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
                let d = expired_draft(&s, at >= s.expires_at);
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
    /// expiry, and every never-authorised session idle for
    /// `device_api.unauthorised_idle_timeout_s`, becomes `expired`, one
    /// `device.session.expired` record each, in one transaction. Returns
    /// how many expired.
    ///
    /// # Errors
    ///
    /// [`ApiError`] if the store or the audit write failed (nothing
    /// changed then).
    pub async fn expire_device_sessions(&self) -> Result<usize, ApiError> {
        let at = self.now()?;
        let idle = self.config().device.unauthorised_idle_timeout;
        let mut tx = self.store().begin().await?;
        let ids = tx.expire_device_sessions(at, minus(at, idle)).await?;
        if ids.is_empty() {
            tx.rollback().await;
            return Ok(0);
        }
        let mut recs = Vec::with_capacity(ids.len());
        for id in &ids {
            let d = system_draft("device.session.expired", Outcome::Success)
                .target("device_session", &id.to_string())
                .reason(SESSION_EXPIRED)
                .detail(Detail::new().with("unauthorised_idle_timeout_s", &idle.as_secs()));
            recs.push(self.append(&mut tx, &d).await?);
        }
        self.commit(tx, &recs).await?;
        Ok(ids.len())
    }
}

fn expired_draft(s: &DeviceSession, ttl: bool) -> AuditDraft {
    system_draft("device.session.expired", Outcome::Success)
        .target("device_session", &s.id.to_string())
        .reason(SESSION_EXPIRED)
        .detail(
            Detail::new()
                .with("macs", &macs_text(s))
                .with("source_ip", &s.source_ip.to_string())
                .with("cause", if ttl { "ttl" } else { "idle_unauthorised" }),
        )
}

impl<S: Store + 'static> Api<S> {
    /// For a confirmed session: `Some(lapse time)` if its token has lapsed
    /// at `at` ([`confirmed_lapse_at`]); `None` otherwise (any other state,
    /// or not yet lapsed).
    pub(crate) async fn confirmed_lapsed(
        &self,
        s: &DeviceSession,
    ) -> Result<Option<UnixMicros>, ApiError> {
        if s.state != SessionState::Confirmed {
            return Ok(None);
        }
        let at = self.now()?;
        let mut tx = self.store().begin().await?;
        let job = tx.job_by_session(s.id).await;
        let job_v2 = match &job {
            Ok(None) => tx.job_v2_by_session(s.id).await,
            _ => Ok(None),
        };
        tx.rollback().await;
        let lost_after = self.config().device.jobs.lost_after;
        let lapse = match (job?, job_v2?) {
            (Some(j), _) => confirmed_lapse_at(&j, lost_after),
            (None, Some(j)) => confirmed_lapse_at_v2(&j, lost_after),
            (None, None) => return Ok(None),
        };
        Ok((at >= lapse).then_some(lapse))
    }
}

/// The refusal for a confirmed session whose token has lapsed.
pub(crate) fn lapsed_error(lapse: UnixMicros) -> ApiError {
    state_error(SessionState::Expired).detail(
        Detail::new()
            .with("lapse_reason", SESSION_LAPSED)
            .with("lapsed_at_us", &lapse.as_micros()),
    )
}
