//! Job routes of a confirmed session: chunk fetch (plan M3 section 3.3)
//! and progress reports (section 3.4).
//!
//! **Chunk fetch.** Only the session's own job, while it is `running`
//! (a `lost` job becomes `running` again, audited), and only the image the
//! job's plan names. Each chunk is read and its SHA-256 compared with the
//! signed content manifest before any byte is sent (server-side
//! verify-on-use, M2 section 5.7); a mismatch marks the content failed
//! (500 `integrity_failed`, not retried). One `job.content.read` record
//! per job and step (the verify pass of step 1 and the apply pass of step
//! 3), written before the first chunk of that pass is served. At most
//! `device_api.max_chunk_requests_per_job` requests run at once per job.
//!
//! **Progress.** `seq` must exceed the last accepted one (otherwise the
//! report is ignored: 200 with the current `ack_seq`); steps advance only
//! in order; `succeeded` only after step 4 completed (REQ-JOB-013);
//! `failed` is final; `progress` reports update byte counts at most every
//! `device_api.progress_min_interval` and are not audited. Every state
//! change is an audit record in the same transaction (REQ-JOB-012).
//! `succeeded` also completes step 5 (with its `job.step.*` records),
//! adds a boot stop for each of the job's MACs on every active boot
//! service whose subnets contain the device's source address, and bumps
//! each such service's policy generation (REQ-BOOT-067, decision 0023 item
//! 2), in the same transaction. The final record (`job.succeeded` or
//! `job.failed`) carries the job's step history (finding NIST-009).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7, SI-7(1) - chunks verified against the signed
//   manifest before they are sent; mismatch fails the content.
// - NIST 800-53: AC-3, SC-23 - bearer bound to the session and its job;
//   report order enforced (a forged success cannot skip steps).
// - NIST 800-53: AU-2, AU-3, AU-12 - content reads per pass, every job
//   and step state change (step 5 included), boot stops marked as based
//   on claimed MACs (REQ-JOB-012, decision 0018 item 10, decision 0023
//   item 2); the final record carries the step history.
// - NIST 800-53: AU-5 (partial) - see the POAM below.
// - NIST 800-53: SC-5 - chunk concurrency per job; progress records
//   rate-limited.
// - SPEC: specs/progress.md#REQ-JOB-002, #REQ-JOB-005, #REQ-JOB-012,
//   #REQ-JOB-013; specs/preinstall-env.md#REQ-PE-016;
//   specs/boot-network.md#REQ-BOOT-067
// - Decisions 0011, 0018 items 9 and 10, 0021 items 2 and 4

// POAM: AU-5 (post-wipe scope) - after the wipe the device carries on
// with its steps even while the server answers 503 `audit_unavailable`
// (it cannot undo the wipe); a step whose report was refused has no
// `job.step.*` record until a later report succeeds. The final record
// carries the server's step history, but steps the device ran while the
// audit trail was down are not recorded as they happened (finding
// NIST-009).

// POAM: SC-23/IA-3 (boot stops, M5) - stops are recorded for the MACs the
// agent claims (guarded at confirmation, decision 0023 item 2), not for
// the client hardware address the relay observed in the device's DHCP
// requests, and not by the SMBIOS system UUID / DHCP option 97 client
// GUID. A holder of a code can still claim MACs of devices that have no
// stop and no running job. Target: M5.

// POAM: AU-3/IA-3 (SMBIOS identifier, finding NIST-015) - the session and the
// job identify the device only by claimed MACs; the SMBIOS machine
// identifier is not collected or recorded. Target: M5, with the stop
// keying above.

use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use usgp_audit::{Detail, Outcome};
use usgp_common::Sha256Digest;
use usgp_db::{DbError, Job, JobStep, NewBootStop, RepoTx, Store};
use usgp_proto::content_manifest::chunk_count;
use usgp_proto::device::SessionState;
use usgp_proto::ops::BootServiceStatus;
use usgp_proto::progress::FailureCategory;
use usgp_proto::{
    BootStopId, ContentState, ErrorCode, FailureV1, JobId, JobState, ProgressAckV1, ProgressEvent,
    ProgressV1, Step, StepState, UnixMicros, codes,
};

use super::auth::{DeviceCtx, require};
use crate::body::ApiBody;
use crate::context::Api;
use crate::error::ApiError;
use crate::handlers::auth_codes::random;
use crate::handlers::content::verified_manifest;
use crate::handlers::{json_response, parse_device_json, read_body};

/// Longest chunk index text (u64).
const MAX_INDEX_DIGITS: usize = 20;

fn job_param(ctx: &DeviceCtx) -> Result<JobId, ApiError> {
    JobId::parse(ctx.params.get(0)).map_err(|_| ApiError::not_found("job"))
}

/// 500 `integrity_failed` (already audited).
fn integrity_error(what: &str) -> ApiError {
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        codes::INTEGRITY_FAILED,
        "the content failed its integrity check on the server and was not sent",
    )
    .internal(what)
    .event("content.integrity.failed")
    .audited()
}

fn not_running(state: JobState) -> ApiError {
    ApiError::conflict(
        codes::JOB_NOT_RUNNING,
        format!("the job is {state}; it no longer takes requests"),
    )
}

fn out_of_order(why: &str) -> ApiError {
    ApiError::conflict(codes::PROGRESS_OUT_OF_ORDER, why.to_owned())
}

/// The session's own job (404 for any other: no existence leak).
async fn own_job<T: RepoTx>(
    tx: &mut T,
    ctx: &DeviceCtx,
    id: JobId,
    lock: bool,
) -> Result<Job, ApiError> {
    let s = ctx.session()?;
    let j = if lock {
        tx.lock_job(id).await?
    } else {
        tx.job(id).await?
    };
    j.filter(|j| j.session_id == s.id)
        .ok_or_else(|| ApiError::not_found("job"))
}

/// Moves a lost job back to running with `job.resumed` in `tx`.
async fn resume<S: Store + 'static>(
    api: &Api<S>,
    tx: &mut S::Tx,
    ctx: &DeviceCtx,
    job: &Job,
) -> Result<usgp_audit::AuditRecord, ApiError> {
    let at = api.now()?;
    match tx
        .set_job_state(job.id, &[JobState::Lost], JobState::Running, at)
        .await
    {
        Ok(()) => {}
        Err(DbError::Conflict { .. }) => return Err(not_running(job.state)),
        Err(e) => return Err(e.into()),
    }
    let d = ctx
        .ok("job.resumed")
        .target("job", &job.id.to_string())
        .detail(Detail::new().with("step", &job.current_step.get()));
    api.append(tx, &d).await
}

/// `GET /v1/device/jobs/{job}/content/{sha256}/chunks/{n}`.
pub(crate) async fn chunk<S: Store + 'static>(
    api: &Api<S>,
    ctx: &DeviceCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let s = ctx.session()?;
    require(s, &[SessionState::Confirmed])?;
    let job_id = job_param(ctx)?;
    let sha =
        Sha256Digest::from_hex(ctx.params.get(1)).map_err(|_| ApiError::not_found("content"))?;
    let n_text = ctx.params.get(2);
    if n_text.is_empty()
        || n_text.len() > MAX_INDEX_DIGITS
        || !n_text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(ApiError::not_found("chunk"));
    }
    let n: u64 = n_text.parse().map_err(|_| ApiError::not_found("chunk"))?;

    let mut tx = api.store().begin().await?;
    let mut job = own_job(&mut tx, ctx, job_id, true).await?;
    match job.state {
        JobState::Running => tx.rollback().await,
        JobState::Lost => {
            let r = resume(api, &mut tx, ctx, &job).await?;
            api.commit(tx, &[r]).await?;
            job.state = JobState::Running;
        }
        other => return Err(not_running(other)),
    }
    let mut tx = api.store().begin().await?;
    let content = tx.content(job.image_content_id).await;
    tx.rollback().await;
    let content = content?
        .filter(|c| c.sha256 == sha)
        .ok_or_else(|| ApiError::not_found("content"))?;
    let device_draft = |e: &str, o: Outcome| ctx.draft(e, o);
    if content.state != ContentState::Ready {
        return Err(integrity_error("content is not ready (failed or deleted)"));
    }
    let m = match verified_manifest(api, &content) {
        Ok(m) => m,
        Err(what) => {
            let _ = api.integrity_failed_by(&device_draft, &content, what).await;
            return Err(integrity_error(what));
        }
    };
    if n >= chunk_count(m.size) {
        return Err(ApiError::not_found("chunk"));
    }
    let max = api.config().device.max_chunk_requests_per_job;
    let Some(_slot) = api.inner.device.chunk_slot(job_id, max) else {
        return Err(super::handlers::rate_limited(
            "too many chunk requests for this job at once",
        ));
    };
    let step = job.current_step.get();
    if api.inner.device.first_content_read(job_id, step) {
        let d = ctx
            .ok("job.content.read")
            .target("job", &job_id.to_string())
            .detail(
                Detail::new()
                    .with("content_id", &content.id.to_string())
                    .with("sha256", &content.sha256)
                    .with("step", &step)
                    .with("chunks", &chunk_count(m.size)),
            );
        if let Err(e) = api.record(&d).await {
            api.inner.device.forget_content_read(job_id, step);
            return Err(e);
        }
    }
    let files = api.files().clone();
    let m2 = m.clone();
    let read = tokio::task::spawn_blocking(move || files.read_chunk(&m2, n))
        .await
        .map_err(ApiError::internal_error)?;
    match read {
        Ok(bytes) => {
            let mut r = Response::new(ApiBody::full(bytes));
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            Ok(r)
        }
        // A read error is not evidence about the bytes: 503, content stays
        // Ready (M2 finding SEC-008).
        Err(e) if !e.is_integrity() => {
            let d = ctx
                .draft("job.content.read", Outcome::Failure)
                .target("job", &job_id.to_string())
                .reason(codes::STORAGE_ERROR.as_str())
                .detail(Detail::new().with("chunk", &n));
            api.record_refusal(&d).await;
            Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                codes::STORAGE_ERROR,
                "the content could not be read from storage; try again later",
            )
            .audited())
        }
        Err(e) => {
            let what = e.to_string();
            let _ = api
                .integrity_failed_by(&device_draft, &content, &what)
                .await;
            Err(integrity_error(&what))
        }
    }
}

/// The state of `step` among `steps`.
fn state_of(steps: &[usgp_db::JobStep], step: Step) -> Option<StepState> {
    steps.iter().find(|s| s.step == step).map(|s| s.state)
}

/// The step history for a job's final record (finding NIST-009):
/// `step:state:started_us:finished_us` per step, `-` for no time.
fn step_history(steps: &[usgp_db::JobStep]) -> String {
    let t = |u: Option<usgp_proto::UnixMicros>| {
        u.map_or_else(|| "-".to_owned(), |u| u.as_micros().to_string())
    };
    steps
        .iter()
        .map(|s| {
            format!(
                "{}:{}:{}:{}",
                s.step.get(),
                s.state.as_str(),
                t(s.started_at),
                t(s.finished_at)
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Why a running job is past its signed plan's timeouts (finding
/// SEC-012; REQ-JOB-011).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Overdue {
    /// The step it fails at (the current step).
    pub step: Step,
    /// `step_timeout` or `stall_timeout`.
    pub reason: &'static str,
    /// The timeout exceeded, seconds.
    pub timeout_s: u32,
}

/// `t` plus `secs` seconds (saturating).
fn plus_s(t: UnixMicros, secs: u32) -> UnixMicros {
    UnixMicros::new(
        t.as_micros()
            .saturating_add(i64::from(secs).saturating_mul(1_000_000)),
    )
    .unwrap_or(t)
}

/// `Some` if `job` is running and past its plan's step timeout (the
/// current step has run for longer than its timeout) or stall timeout (no
/// accepted report for that long) at `at`.
pub(crate) fn overdue(job: &Job, steps: &[JobStep], at: UnixMicros) -> Option<Overdue> {
    if job.state != JobState::Running {
        return None;
    }
    let step = job.current_step;
    let t = job.timeouts.step_s(step);
    let started = steps
        .iter()
        .find(|s| s.step == step && s.state == StepState::Running)
        .and_then(|s| s.started_at);
    if let Some(started) = started
        && at >= plus_s(started, t)
    {
        return Some(Overdue {
            step,
            reason: STEP_TIMEOUT,
            timeout_s: t,
        });
    }
    let heard = job
        .last_report_at
        .unwrap_or(job.started_at)
        .max(job.started_at);
    (at >= plus_s(heard, job.timeouts.stall_s)).then_some(Overdue {
        step,
        reason: STALL_TIMEOUT,
        timeout_s: job.timeouts.stall_s,
    })
}

/// Reason of a server-side step-timeout failure.
pub(crate) const STEP_TIMEOUT: &str = "step_timeout";
/// Reason of a server-side stall-timeout failure.
pub(crate) const STALL_TIMEOUT: &str = "stall_timeout";

/// A failure the server records itself (no files, one attempt).
pub(crate) fn server_failure(
    step: Step,
    category: FailureCategory,
    code: &'static str,
) -> Result<FailureV1, ApiError> {
    Ok(FailureV1 {
        step,
        category,
        code: ErrorCode::new(code).map_err(ApiError::internal_error)?,
        files: Vec::new(),
        count: 0,
        attempts: 1,
    })
}

/// Fails `job` from one of `from` in `tx`: its current step (if running)
/// becomes failed, then the job, with `failure`. Returns the step history
/// after the change. [`DbError::Conflict`] becomes 409 `wrong_state`.
pub(crate) async fn fail_in_tx<T: RepoTx>(
    tx: &mut T,
    job: &Job,
    from: &[JobState],
    failure: &FailureV1,
    at: UnixMicros,
) -> Result<String, ApiError> {
    let steps = tx.job_steps(job.id).await?;
    if state_of(&steps, job.current_step) == Some(StepState::Running) {
        tx.set_job_step(job.id, job.current_step, StepState::Failed, at)
            .await?;
    }
    match tx.fail_job(job.id, from, failure, at).await {
        Ok(()) => {}
        Err(DbError::Conflict { .. }) => {
            return Err(ApiError::conflict(
                codes::WRONG_STATE,
                format!("the job is {}; it can no longer be failed", job.state),
            ));
        }
        Err(e) => return Err(e.into()),
    }
    Ok(step_history(&tx.job_steps(job.id).await?))
}

/// The boot services a succeeded job's stops go on: its own, then every
/// other active boot service whose served subnets contain the device's
/// source address (decision 0023 item 2), each once.
async fn stop_services<T: RepoTx>(
    tx: &mut T,
    job: &Job,
    source_ip: std::net::IpAddr,
) -> Result<Vec<usgp_proto::BootServiceId>, ApiError> {
    let mut v = vec![job.boot_service_id];
    for b in tx.list_boot_services().await? {
        if b.status == BootServiceStatus::Active
            && b.served_subnets.contains(source_ip)
            && !v.contains(&b.id)
        {
            v.push(b.id);
        }
    }
    Ok(v)
}

/// `POST /v1/device/jobs/{job}/progress`.
pub(crate) async fn progress<S: Store + 'static>(
    api: &Api<S>,
    ctx: &DeviceCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let s = ctx.session()?;
    require(s, &[SessionState::Confirmed])?;
    let job_id = job_param(ctx)?;
    let max = api.config().device.max_json_bytes;
    let body = read_body(req, max).await?;
    let p = parse_device_json!(ProgressV1, &body, max)?;
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    let job = own_job(&mut tx, ctx, job_id, true).await?;
    if job.state.is_final() {
        return Err(not_running(job.state));
    }
    // Finding SEC-014: a job past its plan's step or stall timeout has
    // released its MACs; it is failed here, as the sweep would, before
    // any report (a success above all) is applied. A lost job reporting
    // again is judged as running (REQ-JOB-012: Lost -> Failed).
    let as_running = Job {
        state: JobState::Running,
        ..job.clone()
    };
    if let Some(o) = overdue(&as_running, &tx.job_steps(job_id).await?, at) {
        let r = api
            .fail_overdue_in_tx(&mut tx, &job, o, &[JobState::Running, JobState::Lost], at)
            .await?;
        api.commit(tx, &[r]).await?;
        return Err(not_running(JobState::Failed).detail(
            Detail::new()
                .with("job_id", &job_id.to_string())
                .with("seq", &p.seq)
                .with("event", p.event.as_str())
                .with("overdue", o.reason),
        ));
    }
    let ack = |seq: u64, state: JobState| ProgressAckV1 {
        ack_seq: seq,
        job_state: state,
    };
    if p.seq <= job.last_seq {
        tx.rollback().await;
        return json_response!(StatusCode::OK, &ack(job.last_seq, job.state));
    }
    let refused = |e: ApiError| {
        e.detail(
            Detail::new()
                .with("job_id", &job_id.to_string())
                .with("seq", &p.seq)
                .with("step", &p.step.get())
                .with("event", p.event.as_str()),
        )
    };
    if p.layout.is_some() && p.step != Step::PARTITION_FORMAT {
        return Err(refused(ApiError::unprocessable(
            codes::INVALID_VALUE
                .with_param("layout")
                .unwrap_or(codes::INVALID_VALUE),
            "a layout is reported only with step 2",
        )));
    }
    let mut recs = Vec::new();
    if job.state == JobState::Lost {
        recs.push(resume(api, &mut tx, ctx, &job).await?);
    }
    let steps = tx.job_steps(job_id).await?;
    if p.event == ProgressEvent::Progress {
        if p.step != job.current_step || state_of(&steps, p.step) != Some(StepState::Running) {
            return Err(refused(out_of_order(
                "progress is reported only for the running step",
            )));
        }
        let min = i64::try_from(api.config().device.progress_min_interval.as_micros())
            .unwrap_or(i64::MAX);
        if recs.is_empty()
            && job
                .last_report_at
                .is_some_and(|t| at.as_micros().saturating_sub(t.as_micros()) < min)
        {
            // Too soon after the last report: dropped (plan section 3.4).
            tx.rollback().await;
            return json_response!(StatusCode::OK, &ack(job.last_seq, job.state));
        }
    }
    match tx
        .record_job_progress(job_id, p.seq, p.bytes_done, p.bytes_total, at)
        .await
    {
        Ok(()) => {}
        Err(DbError::Conflict { .. } | DbError::InvalidArgument { .. }) => {
            return Err(refused(out_of_order(
                "the report's sequence number or byte counts do not follow the last report",
            )));
        }
        Err(e) => return Err(e.into()),
    }
    if let Some(layout) = &p.layout {
        tx.set_job_layout(job_id, layout).await?;
    }
    let step_detail = |step: Step| {
        Detail::new()
            .with("step", &step.get())
            .with("kind", step.kind().as_str())
            .with("seq", &p.seq)
    };
    let job_target = job_id.to_string();
    let mut state = JobState::Running;
    match p.event {
        ProgressEvent::Progress => {}
        ProgressEvent::StepStarted => match state_of(&steps, p.step) {
            Some(StepState::Running) => {}
            Some(StepState::Pending) => {
                if tx
                    .set_job_step(job_id, p.step, StepState::Running, at)
                    .await
                    .is_err()
                {
                    return Err(refused(out_of_order("an earlier step is not completed")));
                }
                let d = ctx
                    .ok("job.step.started")
                    .target("job", &job_target)
                    .detail(step_detail(p.step));
                recs.push(api.append(&mut tx, &d).await?);
            }
            _ => return Err(refused(out_of_order("that step cannot start now"))),
        },
        ProgressEvent::StepCompleted => {
            if state_of(&steps, p.step) != Some(StepState::Running)
                || tx
                    .set_job_step(job_id, p.step, StepState::Done, at)
                    .await
                    .is_err()
            {
                return Err(refused(out_of_order("that step is not running")));
            }
            let mut detail = step_detail(p.step);
            if let Some(l) = &p.layout {
                detail = detail
                    .with("disk_guid", &l.disk_guid().to_string())
                    .with("partitions", &l.partitions().len());
            }
            let d = ctx
                .ok("job.step.completed")
                .target("job", &job_target)
                .detail(detail);
            recs.push(api.append(&mut tx, &d).await?);
        }
        ProgressEvent::Failed => {
            let f = p
                .failure
                .as_ref()
                .ok_or_else(|| ApiError::internal_error("failed event without failure"))?;
            if state_of(&steps, p.step) == Some(StepState::Running) {
                tx.set_job_step(job_id, p.step, StepState::Failed, at)
                    .await?;
            }
            match tx.fail_job(job_id, &[JobState::Running], f, at).await {
                Ok(()) => {}
                Err(DbError::Conflict { .. }) => return Err(not_running(job.state)),
                Err(e) => return Err(e.into()),
            }
            let history = step_history(&tx.job_steps(job_id).await?);
            let files = f
                .files
                .iter()
                .map(|i| format!("{}:{}", i.role, i.name.as_str()))
                .collect::<Vec<_>>()
                .join(",");
            let d = ctx
                .draft("job.failed", Outcome::Failure)
                .target("job", &job_target)
                .reason(f.code.as_str())
                .detail(
                    step_detail(f.step)
                        .with("category", f.category.as_str())
                        .with("count", &f.count)
                        .with("attempts", &f.attempts)
                        .with("files", &files)
                        .with("steps", &history),
                );
            recs.push(api.append(&mut tx, &d).await?);
            state = JobState::Failed;
        }
        ProgressEvent::Succeeded => {
            if state_of(&steps, Step::MAKE_BOOTABLE) != Some(StepState::Done) {
                return Err(refused(out_of_order(
                    "success is reported only after step 4 completed",
                )));
            }
            // Finding SEC-013.1: the job stops holding its MACs and its
            // stops appear in one step for any concurrent confirmation.
            tx.lock_mac_claims().await?;
            // Finding SEC-014: second guard. Its MACs must still be its
            // own: no other session's running job and no stop, under the
            // claim lock.
            super::confirm::claims_free(&mut tx, &job.macs, s.id, at).await?;
            // Step 5 changes state with its own records (finding NIST-009).
            let last = Step::REPORT_RESTART;
            if state_of(&steps, last) == Some(StepState::Pending) {
                tx.set_job_step(job_id, last, StepState::Running, at)
                    .await?;
                let d = ctx
                    .ok("job.step.started")
                    .target("job", &job_target)
                    .detail(step_detail(last).with("implied_by", "succeeded"));
                recs.push(api.append(&mut tx, &d).await?);
            }
            if state_of(&steps, last) != Some(StepState::Done) {
                tx.set_job_step(job_id, last, StepState::Done, at).await?;
                let d = ctx
                    .ok("job.step.completed")
                    .target("job", &job_target)
                    .detail(step_detail(last).with("implied_by", "succeeded"));
                recs.push(api.append(&mut tx, &d).await?);
            }
            match tx
                .set_job_state(job_id, &[JobState::Running], JobState::Succeeded, at)
                .await
            {
                Ok(()) => {}
                Err(DbError::Conflict { .. }) => {
                    return Err(refused(out_of_order("the job cannot succeed now")));
                }
                Err(e) => return Err(e.into()),
            }
            // REQ-BOOT-067: stop offering a boot program to this device,
            // on every active boot service that serves its source address
            // and on the job's own (decision 0023 item 2). The MACs are
            // the agent's claim, checked at confirmation.
            let services = stop_services(&mut tx, &job, s.source_ip).await?;
            let mut added = 0usize;
            let mut generations = Vec::with_capacity(services.len());
            for bs in &services {
                let mut added_here = 0usize;
                for mac in job.macs.as_slice() {
                    let stop = NewBootStop {
                        id: BootStopId::from_random_bytes(random::<16>()?),
                        boot_service_id: *bs,
                        mac: *mac,
                        job_id,
                        created_at: at,
                    };
                    if tx.add_boot_stop(&stop).await? {
                        added_here = added_here.saturating_add(1);
                        let d = ctx
                            .ok("boot_stop.added")
                            .target("boot_stop", &stop.id.to_string())
                            .detail(
                                Detail::new()
                                    .with("mac", &mac.to_string())
                                    .with("claimed", "mac")
                                    .with("mac_basis", "agent_claim")
                                    .with("job_id", &job_target)
                                    .with("boot_service_id", &bs.to_string())
                                    .with("job_boot_service", &(*bs == job.boot_service_id)),
                            );
                        recs.push(api.append(&mut tx, &d).await?);
                    }
                }
                let generation = if added_here > 0 {
                    tx.bump_boot_policy_generation(*bs).await?
                } else {
                    tx.boot_policy_generation(*bs).await?
                };
                generations.push(format!("{bs}:{generation}"));
                added = added.saturating_add(added_here);
            }
            let history = step_history(&tx.job_steps(job_id).await?);
            let d = ctx.ok("job.succeeded").target("job", &job_target).detail(
                Detail::new()
                    .with("seq", &p.seq)
                    .with(
                        "macs",
                        &job.macs
                            .as_slice()
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(","),
                    )
                    .with("claimed", "macs")
                    .with("boot_stops_added", &added)
                    .with("boot_policy_generations", &generations.join(","))
                    .with("steps", &history),
            );
            recs.push(api.append(&mut tx, &d).await?);
            state = JobState::Succeeded;
        }
    }
    api.commit(tx, &recs).await?;
    json_response!(StatusCode::OK, &ack(p.seq, state))
}

impl<S: Store + 'static> Api<S> {
    /// Fails an overdue job in `tx` (from one of `from`) and appends its
    /// `job.failed` record by the server (findings SEC-012, SEC-014).
    pub(crate) async fn fail_overdue_in_tx(
        &self,
        tx: &mut S::Tx,
        job: &Job,
        o: Overdue,
        from: &[JobState],
        at: UnixMicros,
    ) -> Result<usgp_audit::AuditRecord, ApiError> {
        let f = server_failure(o.step, FailureCategory::Timeout, o.reason)?;
        let history = fail_in_tx(tx, job, from, &f, at).await?;
        let d = crate::context::system_draft("job.failed", Outcome::Failure)
            .target("job", &job.id.to_string())
            .reason(o.reason)
            .detail(
                Detail::new()
                    .with("step", &o.step.get())
                    .with("kind", o.step.kind().as_str())
                    .with("category", FailureCategory::Timeout.as_str())
                    .with("timeout_s", &o.timeout_s)
                    .with("failed_by", "server")
                    .with("from_state", job.state.as_str())
                    .with("steps", &history),
            );
        self.append(tx, &d).await
    }

    /// The timeout sweep (maintenance; finding SEC-012, REQ-JOB-011):
    /// every running job past its signed plan's step timeout or stall
    /// timeout is failed (category `timeout`, reason `step_timeout` or
    /// `stall_timeout`), with one `job.failed` record by the server, each
    /// job in its own transaction. Returns how many were failed.
    ///
    /// # Errors
    ///
    /// [`ApiError`] for the first job that could not be failed (the others
    /// before it stay failed; it and the rest are retried next pass).
    // COMPLIANCE MAPPING:
    // - NIST 800-53: SC-5, AC-12 - a job cannot hold its claimed MACs past
    //   its timeouts; AU-2, AU-3, AU-12 - each failure audited with the
    //   server as actor.
    // - SPEC: specs/progress.md#REQ-JOB-011, #REQ-JOB-012
    pub async fn fail_overdue_jobs(&self) -> Result<usize, ApiError> {
        let at = self.now()?;
        let mut tx = self.store().begin().await?;
        let running = tx.list_jobs(&[JobState::Running]).await;
        tx.rollback().await;
        let mut failed = 0usize;
        for j in running? {
            let mut tx = self.store().begin().await?;
            let Some(job) = tx.lock_job(j.id).await? else {
                tx.rollback().await;
                continue;
            };
            let steps = tx.job_steps(job.id).await?;
            let Some(o) = overdue(&job, &steps, at) else {
                tx.rollback().await;
                continue;
            };
            let r = self
                .fail_overdue_in_tx(&mut tx, &job, o, &[JobState::Running], at)
                .await?;
            self.commit(tx, &[r]).await?;
            failed = failed.saturating_add(1);
        }
        Ok(failed)
    }

    /// The lost-job sweep (maintenance): every running job not heard from
    /// for `jobs.lost_after_s` becomes `lost`, one `job.lost` record each,
    /// in one transaction (REQ-JOB-012). Returns how many.
    ///
    /// # Errors
    ///
    /// [`ApiError`] if the store or the audit write failed (nothing
    /// changed then).
    pub async fn mark_lost_jobs(&self) -> Result<usize, ApiError> {
        let at = self.now()?;
        let after =
            i64::try_from(self.config().device.jobs.lost_after.as_micros()).unwrap_or(i64::MAX);
        let before = usgp_proto::UnixMicros::new(at.as_micros().saturating_sub(after).max(0))
            .map_err(|_| ApiError::internal_error("time out of range"))?;
        let mut tx = self.store().begin().await?;
        let ids = tx.mark_lost_jobs(before).await?;
        if ids.is_empty() {
            tx.rollback().await;
            return Ok(0);
        }
        let mut recs = Vec::with_capacity(ids.len());
        for id in &ids {
            let d = crate::context::system_draft("job.lost", Outcome::Failure)
                .target("job", &id.to_string())
                .reason("not_heard_from")
                .detail(Detail::new().with(
                    "lost_after_s",
                    &self.config().device.jobs.lost_after.as_secs(),
                ));
            recs.push(self.append(&mut tx, &d).await?);
        }
        self.commit(tx, &recs).await?;
        Ok(ids.len())
    }
}
