//! Job status for the operator: list, view, acknowledge a failure (plan
//! M3 section 3.5, REQ-JOB-001).

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-2, AU-3, AU-12 - job reads, acknowledgements and
//   operator failures audited (who, which job, why).
// - NIST 800-53: AC-3 - `job.fail` is its own permission (finding
//   SEC-012).
// - NIST 800-53: SI-11 - failure detail as the device reported it, through
//   the validated `FailureV1` type.
// - SPEC: specs/progress.md#REQ-JOB-001 (status items), #REQ-JOB-005
//   (persistent failure shown), #REQ-JOB-009 (previous job), #REQ-JOB-012

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use usgp_audit::Detail;
use usgp_db::{DbError, RepoTx, Store};
use usgp_proto::ops::JobList;
use usgp_proto::progress::FailureCategory;
use usgp_proto::{JobId, JobState, codes};

use super::sessions::single_query;
use super::{json_response, read_body};
use crate::body::ApiBody;
use crate::context::{Api, RequestCtx};
use crate::error::ApiError;

fn job_id(ctx: &RequestCtx) -> Result<JobId, ApiError> {
    JobId::parse(ctx.params.get(0)).map_err(|_| ApiError::not_found("job"))
}

/// `GET /v1/jobs[?state=]`.
pub(crate) async fn list<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: &Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let states: Vec<JobState> = match single_query(req, "state")? {
        None => Vec::new(),
        Some(v) => {
            vec![JobState::parse(v).ok_or_else(|| ApiError::bad_request("unknown job state"))?]
        }
    };
    let mut tx = api.store().begin().await?;
    let mut jobs = Vec::new();
    for j in tx.list_jobs(&states).await? {
        let steps = tx.job_steps(j.id).await?;
        jobs.push(j.view(&steps));
    }
    let list = JobList { jobs };
    let d = ctx
        .ok("job.list.read")
        .detail(Detail::new().with("count", &list.jobs.len()));
    let r = api.append(&mut tx, &d).await?;
    api.commit(tx, &[r]).await?;
    json_response!(StatusCode::OK, &list)
}

/// `GET /v1/jobs/{id}`.
pub(crate) async fn get<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let id = job_id(ctx)?;
    let mut tx = api.store().begin().await?;
    let j = tx
        .job(id)
        .await?
        .ok_or_else(|| ApiError::not_found("job"))?;
    let view = j.view(&tx.job_steps(id).await?);
    let d = ctx.ok("job.read").target("job", &id.to_string());
    let r = api.append(&mut tx, &d).await?;
    api.commit(tx, &[r]).await?;
    json_response!(StatusCode::OK, &view)
}

/// `POST /v1/jobs/{id}/acknowledge`: failed jobs only; clears the
/// attention flag, the state stays `failed`.
pub(crate) async fn acknowledge<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let id = job_id(ctx)?;
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    let j = tx
        .lock_job(id)
        .await?
        .ok_or_else(|| ApiError::not_found("job"))?;
    match tx
        .acknowledge_job_failure(id, ctx.principal.operator.id, at)
        .await
    {
        Ok(()) => {}
        Err(DbError::Conflict { .. }) => {
            return Err(ApiError::conflict(
                codes::WRONG_STATE,
                format!(
                    "the job is {}; only an unacknowledged failed job can be acknowledged",
                    j.state
                ),
            ));
        }
        Err(e) => return Err(e.into()),
    }
    let d = ctx
        .ok("job.failure.acknowledged")
        .target("job", &id.to_string());
    let r = api.append(&mut tx, &d).await?;
    let after = tx
        .job(id)
        .await?
        .ok_or_else(|| ApiError::internal_error("job vanished"))?;
    let view = after.view(&tx.job_steps(id).await?);
    api.commit(tx, &[r]).await?;
    json_response!(StatusCode::OK, &view)
}

/// Longest operator reason for failing a job, characters.
pub const MAX_FAIL_REASON_CHARS: usize = 200;

/// Reason code of an operator-failed job.
pub const OPERATOR_FAILED: &str = "operator_failed";

/// The `reason` of a fail request: exactly `{"reason": "<1 to 200
/// printable characters>"}`.
fn fail_reason(body: &[u8], max: usize) -> Result<String, ApiError> {
    let bad = || {
        ApiError::unprocessable(
            codes::INVALID_VALUE
                .with_param("reason")
                .unwrap_or(codes::INVALID_VALUE),
            format!(
                "the body must be {{\"reason\": \"...\"}} with 1 to {MAX_FAIL_REASON_CHARS} printable characters"
            ),
        )
    };
    let v = super::parse_json!(serde_json::Value, body, max)?;
    let obj = v.as_object().filter(|o| o.len() == 1).ok_or_else(bad)?;
    let text = obj.get("reason").and_then(|r| r.as_str()).ok_or_else(bad)?;
    let n = text.chars().count();
    if n == 0
        || n > MAX_FAIL_REASON_CHARS
        || text.chars().any(char::is_control)
        || text.trim().is_empty()
    {
        return Err(bad());
    }
    Ok(text.to_owned())
}

/// `POST /v1/jobs/{id}/fail`: an operator fails a running or lost job
/// (finding SEC-012), so it stops holding the MACs it claimed. The job's
/// current step and the job become failed (category `refused`, reason
/// `operator_failed`), with `job.failed` by the operator, in one
/// transaction. A finished job is refused 409.
pub(crate) async fn fail<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let id = job_id(ctx)?;
    let max = api.config().limits.max_json_bytes;
    let body = read_body(req, max).await?;
    let reason = fail_reason(&body, max)?;
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    let j = tx
        .lock_job(id)
        .await?
        .ok_or_else(|| ApiError::not_found("job"))?;
    let failure = crate::device::job::server_failure(
        j.current_step,
        FailureCategory::Refused,
        OPERATOR_FAILED,
    )?;
    let history = crate::device::job::fail_in_tx(
        &mut tx,
        &j,
        &[JobState::Running, JobState::Lost],
        &failure,
        at,
    )
    .await?;
    let d = ctx
        .draft("job.failed", usgp_audit::Outcome::Failure)
        .target("job", &id.to_string())
        .reason(OPERATOR_FAILED)
        .detail(
            Detail::new()
                .with("step", &j.current_step.get())
                .with("from_state", j.state.as_str())
                .with("category", FailureCategory::Refused.as_str())
                .with("failed_by", "operator")
                .with("note", reason.as_str())
                .with("steps", &history),
        );
    let r = api.append(&mut tx, &d).await?;
    let after = tx
        .job(id)
        .await?
        .ok_or_else(|| ApiError::internal_error("job vanished"))?;
    let view = after.view(&tx.job_steps(id).await?);
    api.commit(tx, &[r]).await?;
    json_response!(StatusCode::OK, &view)
}
