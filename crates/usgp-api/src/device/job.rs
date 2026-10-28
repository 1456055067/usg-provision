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
//! `succeeded` also adds a boot stop for each of the job's MACs and bumps
//! the boot service's policy generation (REQ-BOOT-067), in the same
//! transaction.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7, SI-7(1) - chunks verified against the signed
//   manifest before they are sent; mismatch fails the content.
// - NIST 800-53: AC-3, SC-23 - bearer bound to the session and its job;
//   report order enforced (a forged success cannot skip steps).
// - NIST 800-53: AU-2, AU-3, AU-12 - content reads per pass, every job
//   state change, boot stops (REQ-JOB-012, decision 0018 item 10).
// - NIST 800-53: SC-5 - chunk concurrency per job; progress records
//   rate-limited.
// - SPEC: specs/progress.md#REQ-JOB-002, #REQ-JOB-005, #REQ-JOB-012,
//   #REQ-JOB-013; specs/preinstall-env.md#REQ-PE-016;
//   specs/boot-network.md#REQ-BOOT-067
// - Decisions 0011, 0018 items 9 and 10, 0021 items 2 and 4

use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use usgp_audit::{Detail, Outcome};
use usgp_common::Sha256Digest;
use usgp_db::{DbError, Job, NewBootStop, RepoTx, Store};
use usgp_proto::content_manifest::chunk_count;
use usgp_proto::device::SessionState;
use usgp_proto::{
    BootStopId, ContentState, JobId, JobState, ProgressAckV1, ProgressEvent, ProgressV1, Step,
    StepState, codes,
};

use super::auth::{DeviceCtx, require};
use crate::body::ApiBody;
use crate::context::Api;
use crate::error::ApiError;
use crate::handlers::auth_codes::random;
use crate::handlers::content::verified_manifest;
use crate::handlers::{json_response, parse_json, read_body};

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
    let p = parse_json!(ProgressV1, &body, max)?;
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    let job = own_job(&mut tx, ctx, job_id, true).await?;
    if job.state.is_final() {
        return Err(not_running(job.state));
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
                        .with("files", &files),
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
            let last = Step::REPORT_RESTART;
            if state_of(&steps, last) == Some(StepState::Pending) {
                tx.set_job_step(job_id, last, StepState::Running, at)
                    .await?;
            }
            if state_of(&steps, last) != Some(StepState::Done) {
                tx.set_job_step(job_id, last, StepState::Done, at).await?;
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
            // REQ-BOOT-067: stop offering a boot program to this device.
            let mut added = 0usize;
            for mac in job.macs.as_slice() {
                let stop = NewBootStop {
                    id: BootStopId::from_random_bytes(random::<16>()?),
                    boot_service_id: job.boot_service_id,
                    mac: *mac,
                    job_id,
                    created_at: at,
                };
                if tx.add_boot_stop(&stop).await? {
                    added = added.saturating_add(1);
                    let d = ctx
                        .ok("boot_stop.added")
                        .target("boot_stop", &stop.id.to_string())
                        .detail(
                            Detail::new()
                                .with("mac", &mac.to_string())
                                .with("job_id", &job_target)
                                .with("boot_service_id", &job.boot_service_id.to_string()),
                        );
                    recs.push(api.append(&mut tx, &d).await?);
                }
            }
            let generation = if added > 0 {
                tx.bump_boot_policy_generation(job.boot_service_id).await?
            } else {
                tx.boot_policy_generation(job.boot_service_id).await?
            };
            let d = ctx.ok("job.succeeded").target("job", &job_target).detail(
                Detail::new()
                    .with("seq", &p.seq)
                    .with("boot_stops_added", &added)
                    .with("boot_policy_generation", &generation),
            );
            recs.push(api.append(&mut tx, &d).await?);
            state = JobState::Succeeded;
        }
    }
    api.commit(tx, &recs).await?;
    json_response!(StatusCode::OK, &ack(p.seq, state))
}

impl<S: Store + 'static> Api<S> {
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
