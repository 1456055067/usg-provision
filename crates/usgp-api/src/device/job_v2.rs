//! Job routes of a v2 (nine-step) job (M4 plan sections 1.1, 1.2 and
//! 3.1): progress reports and chunk fetch.
//!
//! **Who may report which step.** Steps 1 to 6 run in Windows PE and are
//! reported with the session's bearer token; steps 7 to 9 run after the
//! restart and are reported with the job's resume token. A report for a
//! step the credential does not cover is refused (403).
//!
//! **Step 6.** When step 6 (make bootable, restart) completes, in the
//! same transaction:
//!
//! 1. a boot stop is added for each of the job's MACs, on every active
//!    boot service that serves the device's source address and on the
//!    job's own (REQ-BOOT-067, decision 0023 item 2; the M3 rule, now at
//!    step 6 so the restarted machine boots from its disk);
//! 2. the session moves from `confirmed` to `ended` with reason
//!    `restarting` (`device.session.closed`), so its token is refused from
//!    then on (WU-6 deviation 2).
//!
//! **Success** is accepted only for step 9 with steps 1 to 8 done; step 9
//! is completed by it (its own records). Success or failure revokes the
//! job's resume tokens. `restart_pending` on step 8's completion is kept
//! on the job (the runner never restarts the machine).
//!
//! Ordering, sequence numbers, the progress rate and the lost-to-running
//! move follow the M3 rules (`job.rs`).
//!
//! **Chunks.** As M3, for the session's own v2 job while it runs: the
//! image, and (M4) driver archives and the agent package, each verified
//! against its signed content manifest chunk by chunk before it is sent.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3, SC-23 - steps 1 to 6 only with the session token,
//   7 to 9 only with the job's resume token; the session token is
//   revoked at step 6 (AC-12).
// - NIST 800-53: AU-2, AU-3, AU-12 - every step and job state change,
//   the boot stops and the session close in the same transaction as the
//   change (REQ-SEQ-007).
// - NIST 800-53: SI-7, SI-7(1) - chunks verified against the signed
//   manifests before they are sent.
// - NIST 800-53: SC-5 - chunk concurrency per job; progress rate-limited.
// - SPEC: specs/workflow.md#REQ-SEQ-001, #REQ-SEQ-002, #REQ-SEQ-005,
//   #REQ-SEQ-006, #REQ-SEQ-007; specs/progress.md#REQ-JOB-012,
//   #REQ-JOB-013; specs/boot-network.md#REQ-BOOT-067
// - Decisions 0023 item 2, 0025 item 1

// POAM: SI-7/AC-6 (M4, job-to-content binding) - the job row does not
// record which driver archives and agent package its signed plan names
// (no column in migration 0005), so a v2 job may fetch the chunks of any
// Ready driver archive or agent package, not only its own. The content is
// non-secret by decision 0024 and every chunk is verified before it is
// sent. Planned fix: store the plan's content digests on the job.

use hyper::body::Bytes;
use hyper::header::{self, HeaderValue};
use hyper::{Response, StatusCode};
use usgp_audit::{AuditRecord, Detail, Outcome};
use usgp_common::Sha256Digest;
use usgp_db::{DbError, JobStepV2, JobV2, NewBootStop, RepoTx, Store};
use usgp_proto::content_manifest::chunk_count;
use usgp_proto::device::SessionState;
use usgp_proto::progress::FailureCategory;
use usgp_proto::{
    BootStopId, ContentKindV2, ContentState, ErrorCode, FailureV2, JobId, JobState, ProgressAckV1,
    ProgressEvent, ProgressV2, StepState, StepV2, UnixMicros, codes,
};

use super::auth::{DeviceCtx, require};
use crate::body::ApiBody;
use crate::context::Api;
use crate::error::ApiError;
use crate::handlers::auth_codes::random;
use crate::handlers::content::verified_manifest;
use crate::handlers::{json_response, parse_device_json};

/// Session end reason at step 6 (M4 plan section 3.1).
pub const RESTARTING: &str = "restarting";

fn not_running(state: JobState) -> ApiError {
    ApiError::conflict(
        codes::JOB_NOT_RUNNING,
        format!("the job is {state}; it no longer takes requests"),
    )
}

fn out_of_order(why: &str) -> ApiError {
    ApiError::conflict(codes::PROGRESS_OUT_OF_ORDER, why.to_owned())
}

fn state_of(steps: &[JobStepV2], step: StepV2) -> Option<StepState> {
    steps.iter().find(|s| s.step == step).map(|s| s.state)
}

/// `step:state:started_us:finished_us` per step (finding NIST-009).
fn step_history(steps: &[JobStepV2]) -> String {
    let t = |u: Option<UnixMicros>| u.map_or_else(|| "-".to_owned(), |u| u.as_micros().to_string());
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

fn plus_s(t: UnixMicros, secs: u32) -> UnixMicros {
    UnixMicros::new(
        t.as_micros()
            .saturating_add(i64::from(secs).saturating_mul(1_000_000)),
    )
    .unwrap_or(t)
}

/// Why a running v2 job is past its plan's timeouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OverdueV2 {
    /// The step it fails at.
    pub step: StepV2,
    /// `step_timeout` or `stall_timeout`.
    pub reason: &'static str,
    /// The timeout exceeded, seconds.
    pub timeout_s: u32,
}

/// `Some` if a running v2 job is past a timeout at `at`.
///
/// - A running step past its own timeout.
/// - Between step 6 and the first report after the restart (Windows
///   setup, when the device cannot report), the step 7 timeout counted
///   from step 6's end; the stall timeout does not apply there.
/// - Otherwise no accepted report for the stall timeout.
pub(crate) fn overdue_v2(job: &JobV2, steps: &[JobStepV2], at: UnixMicros) -> Option<OverdueV2> {
    if job.state != JobState::Running {
        return None;
    }
    let step = job.current_step;
    let running = steps
        .iter()
        .find(|s| s.step == step && s.state == StepState::Running);
    if let Some(started) = running.and_then(|s| s.started_at) {
        let t = job.timeouts.step_s(step);
        if at >= plus_s(started, t) {
            return Some(OverdueV2 {
                step,
                reason: super::job::STEP_TIMEOUT,
                timeout_s: t,
            });
        }
    }
    let six = steps
        .iter()
        .find(|s| s.step == StepV2::MAKE_BOOTABLE_RESTART);
    let seven = state_of(steps, StepV2::WINDOWS_SETUP);
    if let (Some(six), Some(StepState::Pending)) = (six, seven)
        && six.state == StepState::Done
    {
        let t = job.timeouts.step_s(StepV2::WINDOWS_SETUP);
        let since = six.finished_at.unwrap_or(job.started_at);
        return (at >= plus_s(since, t)).then_some(OverdueV2 {
            step: StepV2::WINDOWS_SETUP,
            reason: super::job::STEP_TIMEOUT,
            timeout_s: t,
        });
    }
    let heard = job
        .last_report_at
        .unwrap_or(job.started_at)
        .max(job.started_at);
    (at >= plus_s(heard, job.timeouts.stall_s)).then_some(OverdueV2 {
        step,
        reason: super::job::STALL_TIMEOUT,
        timeout_s: job.timeouts.stall_s,
    })
}

/// Fails a v2 job in `tx` from one of `from`: its running step, then the
/// job; revokes its resume tokens. Returns the step history.
async fn fail_v2_in_tx<T: RepoTx>(
    tx: &mut T,
    job: &JobV2,
    from: &[JobState],
    failure: &FailureV2,
    at: UnixMicros,
) -> Result<String, ApiError> {
    let steps = tx.job_steps_v2(job.id).await?;
    if state_of(&steps, failure.step) == Some(StepState::Running) {
        tx.set_job_step_v2(job.id, failure.step, StepState::Failed, at)
            .await?;
    }
    match tx.fail_job_v2(job.id, from, failure, at).await {
        Ok(()) => {}
        Err(DbError::Conflict { .. }) => return Err(not_running(job.state)),
        Err(e) => return Err(e.into()),
    }
    tx.revoke_resume_tokens(job.id, at).await?;
    Ok(step_history(&tx.job_steps_v2(job.id).await?))
}

impl<S: Store + 'static> Api<S> {
    /// Fails an overdue v2 job in `tx` with a `job.failed` record by the
    /// server.
    pub(crate) async fn fail_overdue_v2_in_tx(
        &self,
        tx: &mut S::Tx,
        job: &JobV2,
        o: OverdueV2,
        from: &[JobState],
        at: UnixMicros,
    ) -> Result<AuditRecord, ApiError> {
        let f = FailureV2 {
            step: o.step,
            category: FailureCategory::Timeout,
            code: ErrorCode::new(o.reason).map_err(ApiError::internal_error)?,
            files: Vec::new(),
            count: 0,
            attempts: 1,
        };
        let history = fail_v2_in_tx(tx, job, from, &f, at).await?;
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
                    .with("plan_schema", &2u8)
                    .with("steps", &history),
            );
        self.append(tx, &d).await
    }

    /// The timeout sweep for v2 jobs (as [`Api::fail_overdue_jobs`]).
    ///
    /// # Errors
    ///
    /// [`ApiError`] for the first job that could not be failed.
    pub async fn fail_overdue_jobs_v2(&self) -> Result<usize, ApiError> {
        let at = self.now()?;
        let mut tx = self.store().begin().await?;
        let running = tx.list_jobs_v2(&[JobState::Running]).await;
        tx.rollback().await;
        let mut failed = 0usize;
        for j in running? {
            let mut tx = self.store().begin().await?;
            let Some(job) = tx.lock_job_v2(j.id).await? else {
                tx.rollback().await;
                continue;
            };
            let steps = tx.job_steps_v2(job.id).await?;
            let Some(o) = overdue_v2(&job, &steps, at) else {
                tx.rollback().await;
                continue;
            };
            let r = self
                .fail_overdue_v2_in_tx(&mut tx, &job, o, &[JobState::Running], at)
                .await?;
            self.commit(tx, &[r]).await?;
            failed = failed.saturating_add(1);
        }
        Ok(failed)
    }
}

/// Moves a lost v2 job back to running with `job.resumed` in `tx`.
async fn back_to_running<S: Store + 'static>(
    api: &Api<S>,
    tx: &mut S::Tx,
    ctx: &DeviceCtx,
    job: &JobV2,
    at: UnixMicros,
) -> Result<AuditRecord, ApiError> {
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

/// The boot stops at step 6 (REQ-BOOT-067; the M3 success rule).
async fn add_stops<S: Store + 'static>(
    api: &Api<S>,
    tx: &mut S::Tx,
    ctx: &DeviceCtx,
    job: &JobV2,
    source_ip: std::net::IpAddr,
    at: UnixMicros,
    recs: &mut Vec<AuditRecord>,
) -> Result<(usize, Vec<String>), ApiError> {
    let mut services = vec![job.boot_service_id];
    for b in tx.list_boot_services().await? {
        if b.status == usgp_proto::ops::BootServiceStatus::Active
            && b.served_subnets.contains(source_ip)
            && !services.contains(&b.id)
        {
            services.push(b.id);
        }
    }
    let job_target = job.id.to_string();
    let mut added = 0usize;
    let mut generations = Vec::with_capacity(services.len());
    for bs in &services {
        let mut here = 0usize;
        for mac in job.macs.as_slice() {
            let stop = NewBootStop {
                id: BootStopId::from_random_bytes(random::<16>()?),
                boot_service_id: *bs,
                mac: *mac,
                job_id: job.id,
                created_at: at,
            };
            if tx.add_boot_stop(&stop).await? {
                here = here.saturating_add(1);
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
                            .with("job_boot_service", &(*bs == job.boot_service_id))
                            .with("at_step", &StepV2::MAKE_BOOTABLE_RESTART.get()),
                    );
                recs.push(api.append(tx, &d).await?);
            }
        }
        let generation = if here > 0 {
            tx.bump_boot_policy_generation(*bs).await?
        } else {
            tx.boot_policy_generation(*bs).await?
        };
        generations.push(format!("{bs}:{generation}"));
        added = added.saturating_add(here);
    }
    Ok((added, generations))
}

/// `POST /v1/device/jobs/{job}/progress` for a v2 job (body already read).
pub(crate) async fn progress<S: Store + 'static>(
    api: &Api<S>,
    ctx: &DeviceCtx,
    job_id: JobId,
    body: &[u8],
) -> Result<Response<ApiBody>, ApiError> {
    let max = api.config().device.max_json_bytes;
    let p = parse_device_json!(ProgressV2, body, max)?;
    let at = api.now()?;
    let by_session = ctx.session.is_some();
    let mut tx = api.store().begin().await?;
    let job = tx
        .lock_job_v2(job_id)
        .await?
        .ok_or_else(|| ApiError::not_found("job"))?;
    match (&ctx.session, &ctx.resume) {
        (Some(s), _) if s.id == job.session_id => {
            require(s, &[SessionState::Confirmed])?;
        }
        (None, Some(r)) if r.job_id == job.id => {}
        _ => return Err(ApiError::not_found("job")),
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
    // Steps 1 to 6 with the session token, 7 to 9 with the resume token.
    if p.step.runs_after_restart() == by_session {
        return Err(refused(ApiError::new(
            StatusCode::FORBIDDEN,
            codes::FORBIDDEN,
            if by_session {
                "steps 7 to 9 are reported with the job's resume token"
            } else {
                "steps 1 to 6 are reported with the session token"
            },
        )));
    }
    if job.state.is_final() {
        return Err(not_running(job.state));
    }
    let as_running = JobV2 {
        state: JobState::Running,
        ..job.clone()
    };
    if let Some(o) = overdue_v2(&as_running, &tx.job_steps_v2(job_id).await?, at) {
        let r = api
            .fail_overdue_v2_in_tx(&mut tx, &job, o, &[JobState::Running, JobState::Lost], at)
            .await?;
        api.commit(tx, &[r]).await?;
        return Err(refused(not_running(JobState::Failed)));
    }
    let ack = |seq: u64, state: JobState| ProgressAckV1 {
        ack_seq: seq,
        job_state: state,
    };
    if p.seq <= job.last_seq {
        tx.rollback().await;
        return json_response!(StatusCode::OK, &ack(job.last_seq, job.state));
    }
    if p.layout.is_some() && p.step != StepV2::PARTITION_FORMAT {
        return Err(refused(ApiError::unprocessable(
            codes::INVALID_VALUE
                .with_param("layout")
                .unwrap_or(codes::INVALID_VALUE),
            "a layout is reported only with step 2",
        )));
    }
    let mut recs = Vec::new();
    if job.state == JobState::Lost {
        recs.push(back_to_running(api, &mut tx, ctx, &job, at).await?);
    }
    let steps = tx.job_steps_v2(job_id).await?;
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
    let step_detail = |step: StepV2| {
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
                    .set_job_step_v2(job_id, p.step, StepState::Running, at)
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
                    .set_job_step_v2(job_id, p.step, StepState::Done, at)
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
            if p.restart_pending == Some(true) {
                tx.set_job_restart_pending(job_id).await?;
                detail = detail.with("restart_pending", &true);
            }
            let d = ctx
                .ok("job.step.completed")
                .target("job", &job_target)
                .detail(detail);
            let done = api.append(&mut tx, &d).await?;
            let seq = done.seq;
            recs.push(done);
            if p.step == StepV2::MAKE_BOOTABLE_RESTART {
                let s = ctx.session()?;
                // Its MACs must still be its own (finding SEC-014), under
                // the claim lock (finding SEC-013.1).
                tx.lock_mac_claims().await?;
                super::confirm::claims_free(&mut tx, &job.macs, s.id, at).await?;
                let (added, generations) =
                    add_stops(api, &mut tx, ctx, &job, s.source_ip, at, &mut recs).await?;
                let reason = ErrorCode::new(RESTARTING).map_err(ApiError::internal_error)?;
                match tx.close_confirmed_session(s.id, &reason, at).await {
                    Ok(()) => {}
                    Err(DbError::Conflict { .. }) => {
                        return Err(refused(out_of_order("the session is no longer confirmed")));
                    }
                    Err(e) => return Err(e.into()),
                }
                let d = ctx
                    .ok("device.session.closed")
                    .reason(RESTARTING)
                    .initiated_by(seq)
                    .detail(
                        Detail::new()
                            .with("job_id", &job_target)
                            .with("boot_stops_added", &added)
                            .with("boot_policy_generations", &generations.join(",")),
                    );
                recs.push(api.append(&mut tx, &d).await?);
            }
        }
        ProgressEvent::Failed => {
            let f = p
                .failure
                .as_ref()
                .ok_or_else(|| ApiError::internal_error("failed event without failure"))?;
            let history = fail_v2_in_tx(&mut tx, &job, &[JobState::Running], f, at).await?;
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
            let earlier_done = StepV2::ALL
                .iter()
                .filter(|s| **s != StepV2::LAST)
                .all(|s| state_of(&steps, *s) == Some(StepState::Done));
            if !earlier_done {
                return Err(refused(out_of_order(
                    "success is reported only after steps 1 to 8 completed",
                )));
            }
            let last = StepV2::LAST;
            if state_of(&steps, last) == Some(StepState::Pending) {
                tx.set_job_step_v2(job_id, last, StepState::Running, at)
                    .await?;
                let d = ctx
                    .ok("job.step.started")
                    .target("job", &job_target)
                    .detail(step_detail(last).with("implied_by", "succeeded"));
                recs.push(api.append(&mut tx, &d).await?);
            }
            if state_of(&steps, last) != Some(StepState::Done) {
                tx.set_job_step_v2(job_id, last, StepState::Done, at)
                    .await?;
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
            let revoked = tx.revoke_resume_tokens(job_id, at).await?;
            let history = step_history(&tx.job_steps_v2(job_id).await?);
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
                    .with("restart_pending", &job.restart_pending)
                    .with("resume_tokens_revoked", &revoked)
                    .with("steps", &history),
            );
            recs.push(api.append(&mut tx, &d).await?);
            state = JobState::Succeeded;
        }
    }
    api.commit(tx, &recs).await?;
    json_response!(StatusCode::OK, &ack(p.seq, state))
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

/// The verified chunk source of a v2 job's content.
enum Source {
    Image(usgp_proto::ContentManifestV1),
    Archive(usgp_proto::ContentManifestV2),
}

/// `GET /v1/device/jobs/{job}/content/{sha256}/chunks/{n}` for a v2 job
/// (session token; path already parsed).
pub(crate) async fn chunk<S: Store + 'static>(
    api: &Api<S>,
    ctx: &DeviceCtx,
    job_id: JobId,
    sha: Sha256Digest,
    n: u64,
) -> Result<Response<ApiBody>, ApiError> {
    let s = ctx.session()?;
    require(s, &[SessionState::Confirmed])?;
    let mut tx = api.store().begin().await?;
    let mut job = tx
        .lock_job_v2(job_id)
        .await?
        .filter(|j| j.session_id == s.id)
        .ok_or_else(|| ApiError::not_found("job"))?;
    match job.state {
        JobState::Running => tx.rollback().await,
        JobState::Lost => {
            let at = api.now()?;
            let r = back_to_running(api, &mut tx, ctx, &job, at).await?;
            api.commit(tx, &[r]).await?;
            job.state = JobState::Running;
        }
        other => return Err(not_running(other)),
    }
    let mut tx = api.store().begin().await?;
    let image = tx.content(job.image_content_id).await;
    let archive = match &image {
        Ok(Some(c)) if c.sha256 == sha => Ok(None),
        _ => tx.archive_content_by_sha256(&sha).await,
    };
    tx.rollback().await;
    let device_draft = |e: &str, o: Outcome| ctx.draft(e, o);
    let (src, size, content_id) = if let Some(c) = image?.filter(|c| c.sha256 == sha) {
        if c.state != ContentState::Ready {
            return Err(integrity_error("content is not ready (failed or deleted)"));
        }
        match verified_manifest(api, &c) {
            Ok(m) => (Source::Image(m), c.size, c.id),
            Err(what) => {
                let _ = api.integrity_failed_by(&device_draft, &c, what).await;
                return Err(integrity_error(what));
            }
        }
    } else {
        let c = archive?
            .filter(|c| {
                matches!(
                    c.kind,
                    ContentKindV2::DriverArchive | ContentKindV2::AgentPackage
                )
            })
            .ok_or_else(|| ApiError::not_found("content"))?;
        if c.state != ContentState::Ready {
            return Err(ApiError::not_found("content"));
        }
        let m = c
            .manifest
            .as_ref()
            .ok_or("content manifest missing")
            .and_then(|m| {
                crate::manifest::open_content_v2(api.keys(), m)
                    .map_err(|_| "content manifest signature or payload invalid")
            })
            .and_then(|m| {
                (m.content_id == c.id
                    && m.kind == c.kind
                    && m.size == c.size
                    && m.sha256 == c.sha256)
                    .then_some(m)
                    .ok_or("content manifest does not match the content record")
            });
        match m {
            Ok(m) => (Source::Archive(m), c.size, c.id),
            Err(what) => {
                let d = ctx
                    .draft("content.integrity.failed", Outcome::Failure)
                    .target("content", &c.id.to_string())
                    .reason(codes::INTEGRITY_FAILED.as_str())
                    .detail(Detail::new().with("internal_cause", what));
                api.record_refusal(&d).await;
                return Err(integrity_error(what));
            }
        }
    };
    if n >= chunk_count(size) {
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
                    .with("content_id", &content_id.to_string())
                    .with("sha256", &sha)
                    .with("step", &step)
                    .with("chunks", &chunk_count(size)),
            );
        if let Err(e) = api.record(&d).await {
            api.inner.device.forget_content_read(job_id, step);
            return Err(e);
        }
    }
    let files = api.files().clone();
    let read = tokio::task::spawn_blocking(move || match &src {
        Source::Image(m) => files.read_chunk(m, n),
        Source::Archive(m) => files.read_chunk_v2(m, n),
    })
    .await
    .map_err(ApiError::internal_error)?;
    match read {
        Ok(bytes) => {
            let mut r = Response::new(ApiBody::full(Bytes::from(bytes)));
            r.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            Ok(r)
        }
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
            let d = ctx
                .draft("content.integrity.failed", Outcome::Failure)
                .target("content", &content_id.to_string())
                .reason(codes::INTEGRITY_FAILED.as_str())
                .detail(Detail::new().with("internal_cause", what.as_str()));
            api.record_refusal(&d).await;
            Err(integrity_error(&what))
        }
    }
}
