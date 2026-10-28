//! Job status for the operator: list, view, acknowledge a failure (plan
//! M3 section 3.5, REQ-JOB-001).

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-2, AU-12 - job reads and acknowledgements audited.
// - NIST 800-53: SI-11 - failure detail as the device reported it, through
//   the validated `FailureV1` type.
// - SPEC: specs/progress.md#REQ-JOB-001 (status items), #REQ-JOB-005
//   (persistent failure shown), #REQ-JOB-009 (previous job), #REQ-JOB-012

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use usgp_audit::Detail;
use usgp_db::{DbError, RepoTx, Store};
use usgp_proto::ops::JobList;
use usgp_proto::{JobId, JobState, codes};

use super::json_response;
use super::sessions::single_query;
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
