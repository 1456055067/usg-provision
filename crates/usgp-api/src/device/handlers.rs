//! Device session routes before the wipe confirmation (plan M3 section
//! 3.1): open, poll, code, package list, package and disk choice, cancel,
//! end.
//!
//! Each state-changing route locks the session, re-checks its state and
//! expiry, makes the change and writes its audit record in one
//! transaction (decision 0015 item 1). A route whose record cannot be
//! written is refused with 503 `audit_unavailable` and changes nothing.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 - nothing listed or chosen before authorisation
//   (REQ-TGT-013 to 015); choices only from the offered list.
// - NIST 800-53: AC-7 (Unsuccessful Logon Attempts) - failed codes counted;
//   the session is refused after the configured number; per-source rate.
// - NIST 800-53: IA-5 - code compared by its HMAC; wrong, expired, used and
//   revoked codes get the same answer (no oracle).
// - NIST 800-53: AU-2, AU-3, AU-12 - every device choice and session state
//   change audited (decision 0018 item 10, REQ-TGT-016); never the code or
//   the token.
// - NIST 800-53: SC-5 - session caps per source and in total, opens per
//   source per minute.
// - SPEC: specs/targeting.md#REQ-TGT-004, #REQ-TGT-005, #REQ-TGT-008,
//   #REQ-TGT-009, #REQ-TGT-010, #REQ-TGT-011, #REQ-TGT-013, #REQ-TGT-014,
//   #REQ-TGT-016; specs/disk.md#REQ-DISK-003, #REQ-DISK-004,
//   #REQ-DISK-005, #REQ-DISK-016
// - Decisions 0018 items 1, 8 and 10; 0020

use std::net::IpAddr;
use std::time::Instant;

use hyper::body::{Bytes, Incoming};
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use usgp_audit::{Detail, Outcome};
use usgp_db::{
    BootService, ChosenPackage, DbError, DeviceSession, NewDeviceSession, RepoTx, SessionAuth,
    Store,
};
use usgp_proto::device::{
    CancelV1, ChooseDiskV1, ChoosePackageV1, CodeSubmitV1, DeviceHelloV1, DevicePackageListV1,
    EndSessionV1, SessionOpenedV1, SessionState, SessionStatusV1,
};
use usgp_proto::disk::Bus;
use usgp_proto::ops::BootServiceStatus;
use usgp_proto::{DisplayCode, SessionId, SessionToken, codes};
use zeroize::Zeroizing;

use super::auth::{DeviceCtx, opened_actor, require, state_error};
use super::offer::{NoOffer, offered};
use crate::authn::AuthClass;
use crate::body::ApiBody;
use crate::context::Api;
use crate::error::ApiError;
use crate::handlers::auth_codes::{keys_unavailable, plus_secs, random};
use crate::handlers::sessions::{PENDING, macs_text};
use crate::handlers::{code_of, json_response, parse_json, read_body};

/// Draws at most this many ids, tokens and display codes on a collision.
const DRAWS: usize = 4;

/// Reason when the boot service has no usable package (REQ-TGT-008).
const NO_USABLE_PACKAGE: &str = "no_usable_package";

/// End reason when the code attempts are used up.
pub(crate) const CODE_ATTEMPTS_EXHAUSTED: &str = "code_attempts_exhausted";

/// 429 `rate_limited`.
pub(crate) fn rate_limited(message: &str) -> ApiError {
    ApiError::new(StatusCode::TOO_MANY_REQUESTS, codes::RATE_LIMITED, message)
}

impl<S: Store + 'static> Api<S> {
    /// Audits a refusal of a high-volume device request under the
    /// per-source cap (anonymous budget); refusals over the cap are
    /// counted for `auth.unauthenticated.summary`. Returns `e` marked as
    /// audited.
    pub(crate) async fn capped_refusal(
        &self,
        ip: IpAddr,
        reason: &'static str,
        d: usgp_audit::AuditDraft,
        e: ApiError,
    ) -> ApiError {
        if self
            .inner
            .unauth
            .admit(ip, reason, AuthClass::Anonymous, Instant::now())
        {
            self.record_refusal(&d).await;
        }
        e.audited()
    }
}

/// A JSON response from bytes that may hold a secret (the buffer is
/// wiped; hyper's copy is the POAM of `usgp_proto::device`).
// POAM: SC-28/IA-5 - the session token (open response) and the code (issue
// response, code request body) pass through hyper's `Bytes` buffers, which are not
// zeroized when freed. The values live in `Zeroizing` buffers everywhere
// this crate holds them; closing this needs a zeroizing body type in the
// HTTP stack.
fn secret_json(status: StatusCode, json: &Zeroizing<Vec<u8>>) -> Response<ApiBody> {
    let mut r = Response::new(ApiBody::full(Bytes::copy_from_slice(json)));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(usgp_proto::api::JSON_MEDIA_TYPE),
    );
    r
}

/// The boot service whose served subnets contain `ip`: exactly one active
/// service, or none ("ambiguous" when several match; fail closed).
async fn resolve_boot_service<T: RepoTx>(
    tx: &mut T,
    ip: IpAddr,
) -> Result<(Option<BootService>, &'static str), ApiError> {
    let mut found: Vec<BootService> = tx
        .list_boot_services()
        .await?
        .into_iter()
        .filter(|b| b.status == BootServiceStatus::Active && b.served_subnets.contains(ip))
        .collect();
    Ok(match found.len() {
        0 => (None, "none"),
        1 => (found.pop(), "matched"),
        _ => (None, "ambiguous"),
    })
}

/// The device's status view of `s`.
pub(crate) async fn status_view<S: Store + 'static, T: RepoTx>(
    api: &Api<S>,
    tx: &mut T,
    s: &DeviceSession,
) -> Result<SessionStatusV1, ApiError> {
    let name = match s.boot_service_id {
        Some(id) => tx.boot_service(id).await?.map(|b| b.name),
        None => None,
    };
    Ok(SessionStatusV1 {
        state: s.state,
        display_code: s.display_code,
        code_attempts_left: api
            .config()
            .device
            .code_attempts_per_session
            .saturating_sub(s.failed_code_attempts),
        expires_at: s.expires_at,
        boot_service_name: name,
        reason_code: s.end_reason.clone(),
    })
}

/// Locks the session in `tx` and checks it is in one of `allowed` and
/// not past its expiry.
pub(crate) async fn lock_live<S: Store + 'static>(
    api: &Api<S>,
    tx: &mut S::Tx,
    id: SessionId,
    allowed: &[SessionState],
) -> Result<DeviceSession, ApiError> {
    let s = tx
        .lock_device_session(id)
        .await?
        .ok_or_else(|| ApiError::internal_error("session vanished"))?;
    require(&s, allowed)?;
    if PENDING.contains(&s.state) && api.now()? >= s.expires_at {
        // The next request moves it to `expired` (audited); this one is
        // refused now.
        return Err(state_error(SessionState::Expired));
    }
    Ok(s)
}

/// Commits `tx` with `recs` and answers with the session's status.
async fn respond_status<S: Store + 'static>(
    api: &Api<S>,
    mut tx: S::Tx,
    id: SessionId,
    recs: &[usgp_audit::AuditRecord],
) -> Result<Response<ApiBody>, ApiError> {
    let after = tx
        .device_session(id)
        .await?
        .ok_or_else(|| ApiError::internal_error("session vanished"))?;
    let view = status_view(api, &mut tx, &after).await?;
    api.commit(tx, recs).await?;
    json_response!(StatusCode::OK, &view)
}

/// `POST /v1/device/sessions`.
pub(crate) async fn open<S: Store + 'static>(
    api: &Api<S>,
    ctx: &DeviceCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let c = &api.config().device;
    let body = read_body(req, c.max_json_bytes).await?;
    let hello = parse_json!(DeviceHelloV1, &body, c.max_json_bytes)?;
    let claims = || {
        Detail::new()
            .with(
                "macs",
                &hello
                    .macs
                    .as_slice()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .with("firmware", hello.firmware.as_str())
            .with("arch", hello.arch.as_str())
            .with("secure_boot", hello.secure_boot.as_str())
            .with("memory_bytes", &hello.memory_bytes)
            .with("agent_version", hello.agent_version.as_str())
            .with(
                "claimed",
                "macs,firmware,arch,secure_boot,memory_bytes,agent_version",
            )
    };
    if !api.inner.device.opens.admit(ctx.ip, Instant::now()) {
        let d = ctx
            .draft("device.session.open_refused", Outcome::Refused)
            .reason(codes::RATE_LIMITED.as_str())
            .detail(claims());
        let e = rate_limited("too many sessions were opened from this address; try again later");
        return Err(api.capped_refusal(ctx.ip, "rate_limited", d, e).await);
    }
    let at = api.now()?;
    let expires_at = plus_secs(at, c.pending_session_ttl.as_secs())?;
    for _ in 0..DRAWS {
        let id = SessionId::from_random_bytes(random::<16>()?);
        let raw = Zeroizing::new(random::<32>()?);
        let token = SessionToken::from_random_bytes(&raw);
        drop(raw);
        let display_code = DisplayCode::from_random_bytes(random::<4>()?);
        let mut tx = api.store().begin().await?;
        tx.lock_device_session_quota().await?;
        let total = tx.count_device_sessions(&PENDING, None).await?;
        let mine = tx.count_device_sessions(&PENDING, Some(ctx.ip)).await?;
        if total >= c.max_pending_sessions || mine >= c.max_pending_sessions_per_ip {
            tx.rollback().await;
            let d = ctx
                .draft("device.session.open_refused", Outcome::Refused)
                .reason("capacity")
                .detail(
                    claims()
                        .with("pending_total", &total)
                        .with("pending_from_source", &mine),
                );
            let e = rate_limited("too many devices are waiting; try again later");
            return Err(api.capped_refusal(ctx.ip, "capacity", d, e).await);
        }
        let (bs, resolution) = resolve_boot_service(&mut tx, ctx.ip).await?;
        let new = NewDeviceSession {
            id,
            token_sha256: usgp_crypto::sha256(token.expose().as_bytes()),
            boot_service_id: bs.as_ref().map(|b| b.id),
            source_ip: ctx.ip,
            macs: hello.macs.clone(),
            firmware: hello.firmware,
            arch: hello.arch,
            secure_boot: hello.secure_boot,
            memory_bytes: hello.memory_bytes,
            agent_version: hello.agent_version.clone(),
            display_code,
            created_at: at,
            expires_at,
        };
        match tx.insert_device_session(&new).await {
            Ok(()) => {}
            // Token, id or live display code collision: draw again.
            Err(DbError::Conflict { .. }) => continue,
            Err(e) => return Err(e.into()),
        }
        let macs = new
            .macs
            .as_slice()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let d = ctx
            .draft_as(
                opened_actor(id, &macs, ctx.ip),
                "device.session.opened",
                Outcome::Success,
            )
            .target("device_session", &id.to_string())
            .detail(
                claims()
                    .with("display_code", display_code.as_str())
                    .with(
                        "boot_service_id",
                        &bs.as_ref()
                            .map_or_else(|| "none".to_owned(), |b| b.id.to_string()),
                    )
                    .with("boot_service_resolution", resolution)
                    .with("expires_at_us", &expires_at.as_micros()),
            );
        let r = api.append(&mut tx, &d).await?;
        api.commit(tx, &[r]).await?;
        let out = SessionOpenedV1 {
            session_id: id,
            token,
            display_code,
            state: SessionState::AwaitingAuthorisation,
            poll_ms: c.poll_ms,
            expires_at,
        };
        let json = out.to_json_zeroizing().map_err(ApiError::internal_error)?;
        return Ok(secret_json(StatusCode::CREATED, &json));
    }
    Err(ApiError::internal_error(
        "session id, token or display code collided on every draw",
    ))
}

/// `GET /v1/device/session`: the poll. Updates `last_seen_at` only (not
/// audited, plan section 3.1).
pub(crate) async fn status<S: Store + 'static>(
    api: &Api<S>,
    ctx: &DeviceCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let s = ctx.session()?;
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    tx.touch_device_session(s.id, at).await?;
    respond_status(api, tx, s.id, &[]).await
}

/// `POST /v1/device/session/code`.
pub(crate) async fn code<S: Store + 'static>(
    api: &Api<S>,
    ctx: &DeviceCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let s = ctx.session()?;
    require(s, &[SessionState::AwaitingAuthorisation])?;
    let keys = api.provisioning_keys().ok_or_else(keys_unavailable)?;
    let c = &api.config().device;
    let body = read_body(req, c.max_json_bytes).await?;
    if !api.inner.device.code_attempts.admit(ctx.ip, Instant::now()) {
        let d = ctx
            .draft("device.session.code_refused", Outcome::Refused)
            .reason(codes::RATE_LIMITED.as_str());
        let e = rate_limited("too many codes were tried from this address; wait a minute");
        return Err(api.capped_refusal(ctx.ip, "rate_limited", d, e).await);
    }
    let submit = parse_json!(CodeSubmitV1, &body, c.max_json_bytes)?;
    let tag = keys.code_tag(&submit.code);
    drop(submit);
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    let cur = lock_live(api, &mut tx, s.id, &[SessionState::AwaitingAuthorisation]).await?;
    if let Some(code_id) = tx.consume_auth_code(&tag, s.id, at).await? {
        match tx
            .authorise_device_session(s.id, SessionAuth::Code(code_id), at)
            .await
        {
            Ok(()) => {}
            Err(DbError::Conflict { .. }) => {
                return Err(state_error(SessionState::Expired));
            }
            Err(e) => return Err(e.into()),
        }
        let used = ctx
            .ok("auth_code.used")
            .target("auth_code", &code_id.to_string())
            .detail(Detail::new().with("session_id", &s.id.to_string()));
        let r1 = api.append(&mut tx, &used).await?;
        let auth = ctx
            .ok("device.session.authorised")
            .initiated_by(r1.seq)
            .detail(
                Detail::new()
                    .with("method", "code")
                    .with("auth_code_id", &code_id.to_string())
                    .with("macs", &macs_text(&cur)),
            );
        let r2 = api.append(&mut tx, &auth).await?;
        return respond_status(api, tx, s.id, &[r1, r2]).await;
    }
    // Wrong, expired, used or revoked: one answer (no oracle).
    let n = tx.record_failed_code_attempt(s.id).await?;
    let left = c.code_attempts_per_session.saturating_sub(n);
    let d = ctx
        .draft("device.session.code_refused", Outcome::Refused)
        .reason(codes::CODE_NOT_ACCEPTED.as_str())
        .detail(
            Detail::new()
                .with("failed_attempts", &n)
                .with("attempts_left", &left),
        );
    let r1 = api.append(&mut tx, &d).await?;
    if left == 0 {
        match tx
            .set_device_session_state(
                s.id,
                &[SessionState::AwaitingAuthorisation],
                SessionState::Refused,
                Some(&code_of(CODE_ATTEMPTS_EXHAUSTED)),
                at,
            )
            .await
        {
            Ok(()) => {}
            Err(DbError::Conflict { .. }) => return Err(state_error(SessionState::Expired)),
            Err(e) => return Err(e.into()),
        }
        let d = ctx
            .ok("device.session.refused")
            .reason(CODE_ATTEMPTS_EXHAUSTED)
            .initiated_by(r1.seq)
            .detail(Detail::new().with("failed_attempts", &n));
        let r2 = api.append(&mut tx, &d).await?;
        api.commit(tx, &[r1, r2]).await?;
        return Err(state_error(SessionState::Refused).audited());
    }
    api.commit(tx, &[r1]).await?;
    let mut e = ApiError::unprocessable(
        codes::CODE_NOT_ACCEPTED,
        "the code was not accepted; check it and try again",
    )
    .audited();
    e.body.error.attempts_left = Some(left);
    Err(e)
}

/// `GET /v1/device/session/packages`.
pub(crate) async fn packages<S: Store + 'static>(
    api: &Api<S>,
    ctx: &DeviceCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let s = ctx.session()?;
    require(s, &[SessionState::Authorised])?;
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    let cur = lock_live(api, &mut tx, s.id, &[SessionState::Authorised]).await?;
    tx.touch_device_session(s.id, at).await?;
    let mut recs = Vec::new();
    // Why nothing is offered decides which record is written (QA-004):
    // `boot_service.no_usable_package` only when the boot service itself
    // has nothing usable; a device mismatch is the device's, not the boot
    // service's.
    let (offers, nothing_reason) = match offered(api, &mut tx, &cur).await? {
        Ok(o) if o.is_empty() => {
            if let Some(bs) = cur.boot_service_id {
                let d = ctx
                    .ok("boot_service.no_usable_package")
                    .target("boot_service", &bs.to_string())
                    .reason(NO_USABLE_PACKAGE)
                    .detail(Detail::new().with("session_id", &cur.id.to_string()));
                recs.push(api.append(&mut tx, &d).await?);
            }
            (o, Some(NO_USABLE_PACKAGE))
        }
        Ok(o) => (o, None),
        Err(no @ NoOffer::NoBootService) => {
            let d = ctx
                .ok("device.session.no_boot_service")
                .reason(no.reason())
                .detail(Detail::new().with("source_ip", &cur.source_ip.to_string()));
            recs.push(api.append(&mut tx, &d).await?);
            (Vec::new(), Some(no.reason()))
        }
        Err(no @ NoOffer::DeviceUnsupported) => (Vec::new(), Some(no.reason())),
    };
    let device_mismatch = nothing_reason == Some(NoOffer::DeviceUnsupported.reason());
    let ids = offers
        .iter()
        .map(|o| format!("{}@r{}", o.view.package_id, o.view.revision))
        .collect::<Vec<_>>()
        .join(",");
    let detail = Detail::new()
        .with("count", &offers.len())
        .with("packages", &ids);
    let d = match nothing_reason {
        // REQ-TGT-003: the device's claimed firmware or architecture is not
        // UEFI on x64; the list is refused for that reason.
        Some(r) if device_mismatch => ctx
            .draft("device.session.packages.read", Outcome::Refused)
            .reason(r)
            .detail(
                detail
                    .with("firmware", cur.firmware.as_str())
                    .with("arch", cur.arch.as_str())
                    .with("claimed", "firmware,arch"),
            ),
        Some(r) => ctx
            .ok("device.session.packages.read")
            .reason(r)
            .detail(detail),
        None => ctx.ok("device.session.packages.read").detail(detail),
    };
    recs.push(api.append(&mut tx, &d).await?);
    let list = DevicePackageListV1::new(offers.into_iter().map(|o| o.view).collect())
        .map_err(ApiError::internal_error)?;
    api.commit(tx, &recs).await?;
    json_response!(StatusCode::OK, &list)
}

fn not_offered() -> ApiError {
    ApiError::unprocessable(
        codes::PACKAGE_NOT_OFFERED,
        "that package is not offered to this device; list the packages again",
    )
}

/// `POST /v1/device/session/package`.
pub(crate) async fn choose_package<S: Store + 'static>(
    api: &Api<S>,
    ctx: &DeviceCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let s = ctx.session()?;
    require(s, &[SessionState::Authorised])?;
    let max = api.config().device.max_json_bytes;
    let body = read_body(req, max).await?;
    let choice = parse_json!(ChoosePackageV1, &body, max)?;
    let mut tx = api.store().begin().await?;
    let cur = lock_live(api, &mut tx, s.id, &[SessionState::Authorised]).await?;
    let offers = offered(api, &mut tx, &cur).await?.unwrap_or_default();
    let Some(o) = offers
        .iter()
        .find(|o| o.view.package_id == choice.package_id && o.view.revision == choice.revision)
    else {
        return Err(not_offered().detail(
            Detail::new()
                .with("package_id", &choice.package_id.to_string())
                .with("revision", &choice.revision),
        ));
    };
    tx.choose_session_package(
        s.id,
        ChosenPackage {
            id: choice.package_id,
            revision: choice.revision,
        },
    )
    .await?;
    let d = ctx.ok("device.session.package_chosen").detail(
        Detail::new()
            .with("package_id", &choice.package_id.to_string())
            .with("revision", &choice.revision)
            .with("name", o.view.name.as_str()),
    );
    let r = api.append(&mut tx, &d).await?;
    respond_status(api, tx, s.id, &[r]).await
}

/// `POST /v1/device/session/disk`.
pub(crate) async fn choose_disk<S: Store + 'static>(
    api: &Api<S>,
    ctx: &DeviceCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let s = ctx.session()?;
    require(s, &[SessionState::Authorised])?;
    let max = api.config().device.max_json_bytes;
    let body = read_body(req, max).await?;
    let ChooseDiskV1 { disk } = parse_json!(ChooseDiskV1, &body, max)?;
    let mut tx = api.store().begin().await?;
    let cur = lock_live(api, &mut tx, s.id, &[SessionState::Authorised]).await?;
    let Some(chosen) = cur.chosen_package else {
        return Err(ApiError::conflict(
            codes::WRONG_STATE,
            "choose a package before a disk",
        ));
    };
    let offers = offered(api, &mut tx, &cur).await?.unwrap_or_default();
    let Some(o) = offers
        .iter()
        .find(|o| o.view.package_id == chosen.id && o.view.revision == chosen.revision)
    else {
        return Err(not_offered());
    };
    let disk_detail = Detail::new()
        .with("disk_token", &disk.disk_token().to_string())
        .with("bus", disk.bus().as_str())
        .with("model", disk.model().as_str())
        .with("serial", disk.serial().as_str())
        .with("size_bytes", &disk.size_bytes())
        .with("logical_sector", &disk.logical_sector())
        .with("physical_sector", &disk.physical_sector())
        .with("removable", &disk.removable())
        .with("existing_partitions", &disk.partitions().len());
    // Defence in depth for what the agent already refuses (REQ-DISK-005;
    // OPEN-DISK-4: a USB disk is refused even if it reports itself fixed).
    if disk.removable() || disk.bus() == Bus::Usb {
        return Err(ApiError::unprocessable(
            codes::INVALID_VALUE
                .with_param("disk")
                .unwrap_or(codes::INVALID_VALUE),
            "removable and USB disks are not eligible",
        )
        .detail(disk_detail));
    }
    if disk.size_bytes() < o.view.required_disk_bytes {
        return Err(ApiError::unprocessable(
            codes::DISK_TOO_SMALL,
            format!(
                "the disk is {} bytes; this package needs at least {} bytes",
                disk.size_bytes(),
                o.view.required_disk_bytes
            ),
        )
        .detail(disk_detail.with("required_bytes", &o.view.required_disk_bytes)));
    }
    match tx.choose_session_disk(s.id, &disk).await {
        Ok(()) => {}
        Err(DbError::Conflict { .. }) => {
            return Err(ApiError::conflict(
                codes::WRONG_STATE,
                "choose a package before a disk",
            ));
        }
        Err(e) => return Err(e.into()),
    }
    let d = ctx
        .ok("device.session.disk_chosen")
        .detail(disk_detail.with("package_id", &chosen.id.to_string()));
    let r = api.append(&mut tx, &d).await?;
    respond_status(api, tx, s.id, &[r]).await
}

/// `POST /v1/device/session/cancel`: only before the wipe confirmation
/// (REQ-TGT-010, REQ-TGT-011).
pub(crate) async fn cancel<S: Store + 'static>(
    api: &Api<S>,
    ctx: &DeviceCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let s = ctx.session()?;
    require(s, &PENDING)?;
    let max = api.config().device.max_json_bytes;
    let body = read_body(req, max).await?;
    let CancelV1 {} = parse_json!(CancelV1, &body, max)?;
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    let cur = lock_live(api, &mut tx, s.id, &PENDING).await?;
    match tx
        .set_device_session_state(
            s.id,
            &PENDING,
            SessionState::Cancelled,
            Some(&codes::CANCELLED),
            at,
        )
        .await
    {
        Ok(()) => {}
        Err(DbError::Conflict { .. }) => return Err(state_error(SessionState::Confirmed)),
        Err(e) => return Err(e.into()),
    }
    let d = ctx
        .ok("device.session.cancelled")
        .reason(codes::CANCELLED.as_str())
        .detail(Detail::new().with("from_state", cur.state.as_str()));
    let r = api.append(&mut tx, &d).await?;
    respond_status(api, tx, s.id, &[r]).await
}

/// `POST /v1/device/session/end`: the device stops before confirmation
/// (nothing to offer, no disk, firmware unsupported, agent error).
pub(crate) async fn end<S: Store + 'static>(
    api: &Api<S>,
    ctx: &DeviceCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let s = ctx.session()?;
    require(s, &PENDING)?;
    let max = api.config().device.max_json_bytes;
    let body = read_body(req, max).await?;
    let end = parse_json!(EndSessionV1, &body, max)?;
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    let cur = lock_live(api, &mut tx, s.id, &PENDING).await?;
    let reason = code_of(end.reason.as_str());
    match tx
        .set_device_session_state(s.id, &PENDING, SessionState::Ended, Some(&reason), at)
        .await
    {
        Ok(()) => {}
        Err(DbError::Conflict { .. }) => return Err(state_error(SessionState::Confirmed)),
        Err(e) => return Err(e.into()),
    }
    // Refused disks: bus, size and reason only (REQ-DISK-003, -016).
    let refused = end
        .refused_disks
        .iter()
        .map(|d| format!("{}:{}:{}", d.bus, d.size_bytes, d.reason))
        .collect::<Vec<_>>()
        .join(",");
    let d = ctx
        .ok("device.session.ended")
        .reason(reason.as_str())
        .detail(
            Detail::new()
                .with("from_state", cur.state.as_str())
                .with("refused_disks", &end.refused_disks.len())
                .with("refused_disk_summary", &refused),
        );
    let r = api.append(&mut tx, &d).await?;
    respond_status(api, tx, s.id, &[r]).await
}
