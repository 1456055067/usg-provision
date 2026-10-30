//! Jobs and job steps (PostgreSQL): v1 (M3, five steps) and v2 (M4, nine
//! steps, migration 0005).
//!
//! A job is inserted in the confirming transaction together with its
//! `job.created` and `disk.wipe.authorised` audit records; the job names
//! the latter by sequence number and record hash, and migration 0004
//! refuses the transaction at its end unless that record exists, is a
//! successful `disk.wipe.authorised` and targets this job (the wipe
//! guard, REQ-DISK-006).

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-12, AU-5 - the wipe authorisation is a durable audit
//   record before any plan exists; no record, no job.
// - NIST 800-53: SI-10 - steps advance only in order; success only after
//   step 4; a finished job never changes (guard in migration 0004).
// - NIST 800-53: SI-7 - plan digest and signing key recorded.
// - SPEC: specs/workflow.md#REQ-SEQ-002, #REQ-SEQ-006 (v2: nine steps;
//   success only after step 9)
// - SPEC: specs/disk.md#REQ-DISK-006; specs/progress.md#REQ-JOB-001,
//   #REQ-JOB-002, #REQ-JOB-005, #REQ-JOB-006, #REQ-JOB-009, #REQ-JOB-012,
//   #REQ-JOB-013
// - Decision 0018 items 7 and 10

use tokio_postgres::Row;
use usgp_crypto::KeyId;
use usgp_proto::{
    BootServiceId, ContentId, EditionIndex, FailureV1, FailureV2, JobId, JobState, LayoutReportV1,
    MacList, OperatorId, P384Spki, PackageId, SessionId, Step, StepState, StepV2, UnixMicros,
};

use super::content::cas_miss;
use super::conv::{
    bytes32, col, col_digest, col_enum, col_id, col_json, col_macs, col_micros, col_opt_id,
    col_opt_json, col_opt_micros, col_opt_u64, col_step, col_u32, col_u64, mac_params, step_param,
    texts, to_i32, to_i64, to_json, to_uuid,
};
use super::package_config::{tag_params, tags_from};
use crate::error::DbError;
use crate::model::{
    ChosenPackage, Job, JobStep, JobStepV2, JobTimeouts, JobTimeoutsV2, JobV2, NewJob, NewJobV2,
};
use crate::pool::{Bookkeeping, PgTx};

const COLUMNS: &str = "id, session_id, boot_service_id, package_id, package_revision, \
     image_content_id, edition_index, disk, layout, macs, state, current_step, failure_step, \
     failure_category, failure_detail, attempts, bytes_done, bytes_total, last_seq, \
     started_at_us, last_report_at_us, finished_at_us, previous_job_id, wipe_audit_seq, \
     wipe_record_hash, plan_sha256, plan_key_id, step_timeouts_s, stall_timeout_s, \
     acknowledged_by, acknowledged_at_us";

const STEP_COLUMNS: &str = "job_id, step, state, started_at_us, finished_at_us";

fn from_row(r: &Row) -> Result<Job, DbError> {
    let failure: Option<FailureV1> = col_opt_json(r, "failure_detail")?;
    let failure_step: Option<i16> = col(r, "failure_step")?;
    let failure_category: Option<&str> = col(r, "failure_category")?;
    // The indexed columns must agree with the stored failure.
    match (&failure, failure_step, failure_category) {
        (None, None, None) => {}
        (Some(f), Some(s), Some(c)) if step_param(f.step) == s && f.category.as_str() == c => {}
        _ => {
            return Err(DbError::Corrupt {
                what: "failure_detail",
            });
        }
    }
    let ack_by = col_opt_id(r, "acknowledged_by", OperatorId::from_bytes)?;
    let ack_at = col_opt_micros(r, "acknowledged_at_us")?;
    let acknowledged = match (ack_by, ack_at) {
        (None, None) => None,
        (Some(by), Some(at)) => Some((by, at)),
        _ => {
            return Err(DbError::Corrupt {
                what: "acknowledged",
            });
        }
    };
    let key: &[u8] = col(r, "plan_key_id")?;
    let steps: Vec<i32> = col(r, "step_timeouts_s")?;
    let positive = |v: i32| u32::try_from(v).ok().filter(|v| *v >= 1);
    let steps_s: [u32; 5] = steps
        .into_iter()
        .map(positive)
        .collect::<Option<Vec<u32>>>()
        .and_then(|v| v.try_into().ok())
        .ok_or(DbError::Corrupt {
            what: "step_timeouts_s",
        })?;
    let stall: i32 = col(r, "stall_timeout_s")?;
    let timeouts = JobTimeouts {
        steps_s,
        stall_s: positive(stall).ok_or(DbError::Corrupt {
            what: "stall_timeout_s",
        })?,
    };
    Ok(Job {
        id: col_id(r, "id", JobId::from_bytes)?,
        session_id: col_id(r, "session_id", SessionId::from_bytes)?,
        boot_service_id: col_id(r, "boot_service_id", BootServiceId::from_bytes)?,
        package: ChosenPackage {
            id: col_id(r, "package_id", PackageId::from_bytes)?,
            revision: col_u64(r, "package_revision")?,
        },
        image_content_id: col_id(r, "image_content_id", ContentId::from_bytes)?,
        edition_index: EditionIndex::new(u64::from(col_u32(r, "edition_index")?)).map_err(
            |_| DbError::Corrupt {
                what: "edition_index",
            },
        )?,
        disk: col_json(r, "disk")?,
        layout: col_opt_json(r, "layout")?,
        macs: col_macs(r, "macs")?,
        state: col_enum(r, "state", JobState::parse)?,
        current_step: col_step(r, "current_step")?,
        failure,
        attempts: col_u32(r, "attempts")?,
        bytes_done: col_opt_u64(r, "bytes_done")?,
        bytes_total: col_opt_u64(r, "bytes_total")?,
        last_seq: col_u64(r, "last_seq")?,
        started_at: col_micros(r, "started_at_us")?,
        last_report_at: col_opt_micros(r, "last_report_at_us")?,
        finished_at: col_opt_micros(r, "finished_at_us")?,
        previous_job_id: col_opt_id(r, "previous_job_id", JobId::from_bytes)?,
        wipe_audit_seq: col_u64(r, "wipe_audit_seq")?,
        wipe_record_hash: col_digest(r, "wipe_record_hash")?,
        plan_sha256: col_digest(r, "plan_sha256")?,
        plan_key_id: KeyId(usgp_common::Sha256Digest(bytes32(key, "plan_key_id")?)),
        timeouts,
        acknowledged,
    })
}

fn step_from_row(r: &Row) -> Result<JobStep, DbError> {
    Ok(JobStep {
        job_id: col_id(r, "job_id", JobId::from_bytes)?,
        step: col_step(r, "step")?,
        state: col_enum(r, "state", StepState::parse)?,
        started_at: col_opt_micros(r, "started_at_us")?,
        finished_at: col_opt_micros(r, "finished_at_us")?,
    })
}

pub(crate) async fn insert(tx: &mut PgTx, j: &NewJob) -> Result<(), DbError> {
    if j.previous_job_id == Some(j.id) {
        return Err(DbError::InvalidArgument {
            what: "previous job is the job itself",
        });
    }
    if !j.timeouts.valid() {
        return Err(DbError::InvalidArgument {
            what: "job timeouts",
        });
    }
    let disk = to_json(&j.disk, "disk descriptor")?;
    let id = to_uuid(j.id.as_bytes());
    let step_timeouts: Vec<i32> = j
        .timeouts
        .steps_s
        .iter()
        .map(|v| to_i32(*v, "step timeout"))
        .collect::<Result<_, _>>()?;
    tx.execute(
        "insert job",
        "INSERT INTO job (id, session_id, boot_service_id, package_id, package_revision, \
         image_content_id, edition_index, disk, macs, state, current_step, bytes_total, \
         started_at_us, previous_job_id, wipe_audit_seq, wipe_record_hash, plan_sha256, \
         plan_key_id, step_timeouts_s, stall_timeout_s) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'running', 1, $10, $11, $12, $13, $14, \
         $15, $16, $17, $18)",
        &[
            &id,
            &to_uuid(j.session_id.as_bytes()),
            &to_uuid(j.boot_service_id.as_bytes()),
            &to_uuid(j.package.id.as_bytes()),
            &to_i64(j.package.revision, "package revision")?,
            &to_uuid(j.image_content_id.as_bytes()),
            &to_i32(j.edition_index.get(), "edition index")?,
            &disk,
            &mac_params(&j.macs),
            &j.bytes_total
                .map(|b| to_i64(b, "bytes_total"))
                .transpose()?,
            &j.started_at.as_micros(),
            &j.previous_job_id.map(|p| to_uuid(p.as_bytes())),
            &to_i64(j.wipe_audit_seq, "wipe audit seq")?,
            &j.wipe_record_hash.0.as_slice(),
            &j.plan_sha256.0.as_slice(),
            &j.plan_key_id.0.0.as_slice(),
            &step_timeouts,
            &to_i32(j.timeouts.stall_s, "stall timeout")?,
        ],
    )
    .await?;
    for step in Step::ALL {
        let first = step == Step::VERIFY_CONTENT;
        let state = if first {
            StepState::Running
        } else {
            StepState::Pending
        };
        tx.execute(
            "insert job_step",
            "INSERT INTO job_step (job_id, step, state, started_at_us) VALUES ($1, $2, $3, $4)",
            &[
                &id,
                &step_param(step),
                &state.as_str(),
                &first.then(|| j.started_at.as_micros()),
            ],
        )
        .await?;
    }
    Ok(())
}

pub(crate) async fn get(tx: &mut PgTx, id: JobId, lock: bool) -> Result<Option<Job>, DbError> {
    let sql = format!(
        "SELECT {COLUMNS} FROM job WHERE id = $1 AND plan_schema = 1{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = tx
        .query_opt("read job", &sql, &[&to_uuid(id.as_bytes())])
        .await?;
    row.map(|r| from_row(&r)).transpose()
}

pub(crate) async fn by_session(tx: &mut PgTx, id: SessionId) -> Result<Option<Job>, DbError> {
    let sql = format!("SELECT {COLUMNS} FROM job WHERE session_id = $1 AND plan_schema = 1");
    let row = tx
        .query_opt("read job", &sql, &[&to_uuid(id.as_bytes())])
        .await?;
    row.map(|r| from_row(&r)).transpose()
}

pub(crate) async fn list(tx: &mut PgTx, states: &[JobState]) -> Result<Vec<Job>, DbError> {
    let st = texts(states, JobState::as_str);
    let sql = format!(
        "SELECT {COLUMNS} FROM job WHERE (cardinality($1::text[]) = 0 OR state = ANY($1)) \
         AND plan_schema = 1 ORDER BY started_at_us, id"
    );
    let rows = tx.query("list job", &sql, &[&st]).await?;
    rows.iter().map(from_row).collect()
}

pub(crate) async fn steps(tx: &mut PgTx, id: JobId) -> Result<Vec<JobStep>, DbError> {
    let sql = format!(
        "SELECT {STEP_COLUMNS} FROM job_step WHERE job_id = $1 \
         AND EXISTS (SELECT 1 FROM job j WHERE j.id = $1 AND j.plan_schema = 1) ORDER BY step"
    );
    let rows = tx
        .query("list job_step", &sql, &[&to_uuid(id.as_bytes())])
        .await?;
    rows.iter().map(step_from_row).collect()
}

/// Advisory-lock key serialising MAC-claim decisions ("usgpmacs").
pub(crate) const MAC_CLAIM_LOCK_KEY: i64 = 0x7573_6770_6d61_6373;

pub(crate) async fn lock_claims(tx: &mut PgTx) -> Result<(), DbError> {
    // Transaction-scoped; changes no row (a query, as the session quota
    // lock). Under READ COMMITTED every later statement sees what the
    // previous holder committed.
    tx.query_opt(
        "lock mac claims",
        "SELECT pg_advisory_xact_lock($1)",
        &[&MAC_CLAIM_LOCK_KEY],
    )
    .await?;
    Ok(())
}

pub(crate) async fn running_for_macs(tx: &mut PgTx, macs: &MacList) -> Result<Vec<JobId>, DbError> {
    let rows = tx
        .query(
            "list job by mac",
            "SELECT id FROM job WHERE state = 'running' AND macs && $1::bytea[] \
             ORDER BY started_at_us, id",
            &[&mac_params(macs)],
        )
        .await?;
    rows.iter()
        .map(|r| col_id(r, "id", JobId::from_bytes))
        .collect()
}

pub(crate) async fn previous_failed(
    tx: &mut PgTx,
    macs: &MacList,
) -> Result<Option<JobId>, DbError> {
    let row = tx
        .query_opt(
            "read job by mac",
            "SELECT id FROM job WHERE state IN ('failed', 'lost') AND macs && $1::bytea[] \
             ORDER BY started_at_us DESC, id DESC LIMIT 1",
            &[&mac_params(macs)],
        )
        .await?;
    row.map(|r| col_id(&r, "id", JobId::from_bytes)).transpose()
}

/// The row-locked state and plan schema of a job, or `NotFound`.
async fn locked_state(tx: &mut PgTx, id: &uuid::Uuid) -> Result<(JobState, i16), DbError> {
    let row = tx
        .query_opt(
            "lock job",
            "SELECT state, plan_schema FROM job WHERE id = $1 FOR UPDATE",
            &[id],
        )
        .await?;
    match row {
        Some(r) => Ok((
            col_enum(&r, "state", JobState::parse)?,
            col(&r, "plan_schema")?,
        )),
        None => Err(DbError::NotFound { what: "job" }),
    }
}

/// The source state a step must be in to move to `to`.
pub(crate) fn step_from_state(to: StepState) -> Result<StepState, DbError> {
    match to {
        StepState::Running => Ok(StepState::Pending),
        StepState::Done | StepState::Failed => Ok(StepState::Running),
        StepState::Pending => Err(DbError::InvalidArgument {
            what: "a step cannot return to pending",
        }),
    }
}

pub(crate) async fn set_step(
    tx: &mut PgTx,
    id: JobId,
    step: Step,
    to: StepState,
    at: UnixMicros,
) -> Result<(), DbError> {
    set_step_n(tx, id, 1, step_param(step), to, at).await
}

/// Moves step `n` of a job whose plan schema is `schema` (a job of the
/// other schema is `NotFound`).
async fn set_step_n(
    tx: &mut PgTx,
    id: JobId,
    schema: i16,
    n: i16,
    to: StepState,
    at: UnixMicros,
) -> Result<(), DbError> {
    let from = step_from_state(to)?;
    let uid = to_uuid(id.as_bytes());
    let (state, stored) = locked_state(tx, &uid).await?;
    if stored != schema {
        return Err(DbError::NotFound { what: "job" });
    }
    if state.is_final() {
        return Err(DbError::Conflict { what: "job" });
    }
    if to == StepState::Running {
        // Steps advance only in order (plan section 3.4).
        let row = tx
            .query_opt(
                "read job_step",
                "SELECT count(*) AS n FROM job_step \
                 WHERE job_id = $1 AND step < $2 AND state <> 'done'",
                &[&uid, &n],
            )
            .await?;
        let open = match row {
            Some(r) => col_u64(&r, "n")?,
            None => return Err(DbError::Corrupt { what: "count" }),
        };
        if open != 0 {
            return Err(DbError::Conflict { what: "job step" });
        }
    }
    let at = at.as_micros();
    let started = (to == StepState::Running).then_some(at);
    let finished = (to != StepState::Running).then_some(at);
    let changed = tx
        .execute(
            "update job_step",
            "UPDATE job_step SET state = $3, started_at_us = COALESCE($4, started_at_us), \
             finished_at_us = COALESCE($5, finished_at_us) \
             WHERE job_id = $1 AND step = $2 AND state = $6",
            &[&uid, &n, &to.as_str(), &started, &finished, &from.as_str()],
        )
        .await?;
    if changed == 0 {
        return Err(DbError::Conflict { what: "job step" });
    }
    if to == StepState::Running {
        tx.execute(
            "update job step",
            "UPDATE job SET current_step = GREATEST(current_step, $2) WHERE id = $1",
            &[&uid, &n],
        )
        .await?;
    }
    Ok(())
}

pub(crate) async fn set_state(
    tx: &mut PgTx,
    id: JobId,
    from: &[JobState],
    to: JobState,
    at: UnixMicros,
) -> Result<(), DbError> {
    if to == JobState::Failed {
        return Err(DbError::InvalidArgument {
            what: "use fail_job",
        });
    }
    let uid = to_uuid(id.as_bytes());
    let st = texts(from, JobState::as_str);
    let finished = (to == JobState::Succeeded).then(|| at.as_micros());
    // Success only after the last step that completes the job: step 4 of
    // a v1 job (REQ-JOB-013), step 9 of a v2 job (REQ-SEQ-006).
    let n = tx
        .execute(
            "update job state",
            "UPDATE job SET state = $2, finished_at_us = $3 \
             WHERE id = $1 AND state = ANY($4) AND ($2 <> 'succeeded' OR EXISTS ( \
                 SELECT 1 FROM job_step s WHERE s.job_id = $1 \
                 AND s.step = CASE plan_schema WHEN 1 THEN 4 ELSE 9 END AND s.state = 'done'))",
            &[&uid, &to.as_str(), &finished, &st],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "job", &uid).await);
    }
    Ok(())
}

pub(crate) async fn fail(
    tx: &mut PgTx,
    id: JobId,
    from: &[JobState],
    failure: &FailureV1,
    at: UnixMicros,
) -> Result<(), DbError> {
    failure
        .validate()
        .map_err(|_| DbError::InvalidArgument { what: "failure" })?;
    let uid = to_uuid(id.as_bytes());
    let st = texts(from, JobState::as_str);
    let detail = to_json(failure, "failure")?;
    let n = tx
        .execute(
            "update job failed",
            "UPDATE job SET state = 'failed', failure_step = $2, failure_category = $3, \
             failure_detail = $4, attempts = $5, finished_at_us = $6 \
             WHERE id = $1 AND state = ANY($7) AND plan_schema = 1",
            &[
                &uid,
                &step_param(failure.step),
                &failure.category.as_str(),
                &detail,
                &to_i32(failure.attempts, "attempts")?,
                &at.as_micros(),
                &st,
            ],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "job", &uid).await);
    }
    Ok(())
}

pub(crate) async fn set_layout(
    tx: &mut PgTx,
    id: JobId,
    layout: &LayoutReportV1,
) -> Result<(), DbError> {
    let uid = to_uuid(id.as_bytes());
    let json = to_json(layout, "layout")?;
    let n = tx
        .execute(
            "update job layout",
            "UPDATE job SET layout = $2 WHERE id = $1 AND state IN ('running', 'lost')",
            &[&uid, &json],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "job", &uid).await);
    }
    Ok(())
}

pub(crate) async fn record_progress(
    tx: &mut PgTx,
    id: JobId,
    seq: u64,
    bytes_done: Option<u64>,
    bytes_total: Option<u64>,
    at: UnixMicros,
) -> Result<(), DbError> {
    if let (Some(d), Some(t)) = (bytes_done, bytes_total)
        && d > t
    {
        return Err(DbError::InvalidArgument {
            what: "bytes_done above bytes_total",
        });
    }
    let uid = to_uuid(id.as_bytes());
    let n = tx
        .execute_bookkeeping(
            Bookkeeping::JobProgress,
            &[
                &uid,
                &to_i64(seq, "seq")?,
                &at.as_micros(),
                &bytes_done.map(|b| to_i64(b, "bytes_done")).transpose()?,
                &bytes_total.map(|b| to_i64(b, "bytes_total")).transpose()?,
            ],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "job", &uid).await);
    }
    Ok(())
}

pub(crate) async fn acknowledge(
    tx: &mut PgTx,
    id: JobId,
    by: OperatorId,
    at: UnixMicros,
) -> Result<(), DbError> {
    let uid = to_uuid(id.as_bytes());
    let n = tx
        .execute(
            "update job acknowledged",
            "UPDATE job SET acknowledged_by = $2, acknowledged_at_us = $3 \
             WHERE id = $1 AND state = 'failed' AND acknowledged_by IS NULL",
            &[&uid, &to_uuid(by.as_bytes()), &at.as_micros()],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "job", &uid).await);
    }
    Ok(())
}

pub(crate) async fn mark_lost(
    tx: &mut PgTx,
    silent_before: UnixMicros,
) -> Result<Vec<JobId>, DbError> {
    let rows = tx
        .query_write(
            "update job lost",
            "UPDATE job SET state = 'lost' WHERE state = 'running' \
             AND COALESCE(last_report_at_us, started_at_us) < $1 RETURNING id",
            &[&silent_before.as_micros()],
        )
        .await?;
    let mut ids = rows
        .iter()
        .map(|r| col_id(r, "id", JobId::from_bytes))
        .collect::<Result<Vec<_>, _>>()?;
    ids.sort();
    Ok(ids)
}

// ------------------------------------------------------------ v2 jobs --
//
// M4 (migration 0005): a v2 job has nine steps (REQ-SEQ-002), a v2
// failure, the device's job key, the rendered answer-file digest and its
// tags. The v1 readers above see only v1 jobs and these only v2 jobs; the
// state functions (`set_state`, `set_layout`, `record_progress`,
// `acknowledge`, `mark_lost`) serve both.

const COLUMNS_V2: &str = "id, session_id, boot_service_id, package_id, package_revision, \
     image_content_id, edition_index, disk, layout, macs, state, current_step, failure_step, \
     failure_category, failure_detail, attempts, bytes_done, bytes_total, last_seq, \
     started_at_us, last_report_at_us, finished_at_us, previous_job_id, wipe_audit_seq, \
     wipe_record_hash, plan_sha256, plan_key_id, step_timeouts_s, stall_timeout_s, \
     acknowledged_by, acknowledged_at_us, job_key_spki, job_key_id, rendered_answer_sha256, \
     tags, restart_pending";

/// A `smallint` v2 step column.
fn col_step_v2(r: &Row, name: &'static str) -> Result<StepV2, DbError> {
    let v: i16 = col(r, name)?;
    u8::try_from(v)
        .ok()
        .and_then(|n| StepV2::new(n).ok())
        .ok_or(DbError::Corrupt { what: name })
}

/// A v2 step as a `smallint` parameter.
fn step_v2_param(s: StepV2) -> i16 {
    i16::from(s.get())
}

fn from_row_v2(r: &Row) -> Result<JobV2, DbError> {
    let schema: i16 = col(r, "plan_schema_check")?;
    if schema != 2 {
        return Err(DbError::Corrupt {
            what: "plan_schema",
        });
    }
    let failure: Option<FailureV2> = col_opt_json(r, "failure_detail")?;
    let failure_step: Option<i16> = col(r, "failure_step")?;
    let failure_category: Option<&str> = col(r, "failure_category")?;
    match (&failure, failure_step, failure_category) {
        (None, None, None) => {}
        (Some(f), Some(s), Some(c)) if step_v2_param(f.step) == s && f.category.as_str() == c => {}
        _ => {
            return Err(DbError::Corrupt {
                what: "failure_detail",
            });
        }
    }
    let ack_by = col_opt_id(r, "acknowledged_by", OperatorId::from_bytes)?;
    let ack_at = col_opt_micros(r, "acknowledged_at_us")?;
    let acknowledged = match (ack_by, ack_at) {
        (None, None) => None,
        (Some(by), Some(at)) => Some((by, at)),
        _ => {
            return Err(DbError::Corrupt {
                what: "acknowledged",
            });
        }
    };
    let key: &[u8] = col(r, "plan_key_id")?;
    let steps: Vec<i32> = col(r, "step_timeouts_s")?;
    let positive = |v: i32| u32::try_from(v).ok().filter(|v| *v >= 1);
    let steps_s: [u32; 9] = steps
        .into_iter()
        .map(positive)
        .collect::<Option<Vec<u32>>>()
        .and_then(|v| v.try_into().ok())
        .ok_or(DbError::Corrupt {
            what: "step_timeouts_s",
        })?;
    let stall: i32 = col(r, "stall_timeout_s")?;
    let timeouts = JobTimeoutsV2 {
        steps_s,
        stall_s: positive(stall).ok_or(DbError::Corrupt {
            what: "stall_timeout_s",
        })?,
    };
    let spki: &[u8] = col(r, "job_key_spki")?;
    let job_key_spki = P384Spki::from_der(spki).map_err(|_| DbError::Corrupt {
        what: "job_key_spki",
    })?;
    let job_key_id = col_digest(r, "job_key_id")?;
    if usgp_crypto::sha256(job_key_spki.as_der()) != job_key_id {
        return Err(DbError::Corrupt { what: "job_key_id" });
    }
    Ok(JobV2 {
        id: col_id(r, "id", JobId::from_bytes)?,
        session_id: col_id(r, "session_id", SessionId::from_bytes)?,
        boot_service_id: col_id(r, "boot_service_id", BootServiceId::from_bytes)?,
        package: ChosenPackage {
            id: col_id(r, "package_id", PackageId::from_bytes)?,
            revision: col_u64(r, "package_revision")?,
        },
        image_content_id: col_id(r, "image_content_id", ContentId::from_bytes)?,
        edition_index: EditionIndex::new(u64::from(col_u32(r, "edition_index")?)).map_err(
            |_| DbError::Corrupt {
                what: "edition_index",
            },
        )?,
        disk: col_json(r, "disk")?,
        layout: col_opt_json(r, "layout")?,
        macs: col_macs(r, "macs")?,
        state: col_enum(r, "state", JobState::parse)?,
        current_step: col_step_v2(r, "current_step")?,
        failure,
        attempts: col_u32(r, "attempts")?,
        bytes_done: col_opt_u64(r, "bytes_done")?,
        bytes_total: col_opt_u64(r, "bytes_total")?,
        last_seq: col_u64(r, "last_seq")?,
        started_at: col_micros(r, "started_at_us")?,
        last_report_at: col_opt_micros(r, "last_report_at_us")?,
        finished_at: col_opt_micros(r, "finished_at_us")?,
        previous_job_id: col_opt_id(r, "previous_job_id", JobId::from_bytes)?,
        wipe_audit_seq: col_u64(r, "wipe_audit_seq")?,
        wipe_record_hash: col_digest(r, "wipe_record_hash")?,
        plan_sha256: col_digest(r, "plan_sha256")?,
        plan_key_id: KeyId(usgp_common::Sha256Digest(bytes32(key, "plan_key_id")?)),
        timeouts,
        acknowledged,
        job_key_spki,
        job_key_id,
        rendered_answer_sha256: col_digest(r, "rendered_answer_sha256")?,
        tags: tags_from(col(r, "tags")?, true)?,
        restart_pending: col(r, "restart_pending")?,
    })
}

fn step_v2_from_row(r: &Row) -> Result<JobStepV2, DbError> {
    Ok(JobStepV2 {
        job_id: col_id(r, "job_id", JobId::from_bytes)?,
        step: col_step_v2(r, "step")?,
        state: col_enum(r, "state", StepState::parse)?,
        started_at: col_opt_micros(r, "started_at_us")?,
        finished_at: col_opt_micros(r, "finished_at_us")?,
    })
}

/// The select list of a v2 read (the schema is selected again under a
/// distinct name so the row parser can re-check it).
fn select_v2(filter: &str) -> String {
    format!(
        "SELECT {COLUMNS_V2}, plan_schema AS plan_schema_check FROM job \
         WHERE plan_schema = 2 AND {filter}"
    )
}

pub(crate) async fn insert_v2(tx: &mut PgTx, j: &NewJobV2) -> Result<(), DbError> {
    if j.previous_job_id == Some(j.id) {
        return Err(DbError::InvalidArgument {
            what: "previous job is the job itself",
        });
    }
    if !j.timeouts.valid() {
        return Err(DbError::InvalidArgument {
            what: "job timeouts",
        });
    }
    if usgp_crypto::sha256(j.job_key_spki.as_der()) != j.job_key_id {
        return Err(DbError::InvalidArgument { what: "job key id" });
    }
    let disk = to_json(&j.disk, "disk descriptor")?;
    let id = to_uuid(j.id.as_bytes());
    let step_timeouts: Vec<i32> = j
        .timeouts
        .steps_s
        .iter()
        .map(|v| to_i32(*v, "step timeout"))
        .collect::<Result<_, _>>()?;
    tx.execute(
        "insert job",
        "INSERT INTO job (id, session_id, boot_service_id, package_id, package_revision, \
         image_content_id, edition_index, disk, macs, state, current_step, bytes_total, \
         started_at_us, previous_job_id, wipe_audit_seq, wipe_record_hash, plan_sha256, \
         plan_key_id, step_timeouts_s, stall_timeout_s, plan_schema, job_key_spki, job_key_id, \
         rendered_answer_sha256, tags) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'running', 1, $10, $11, $12, $13, $14, \
         $15, $16, $17, $18, 2, $19, $20, $21, $22)",
        &[
            &id,
            &to_uuid(j.session_id.as_bytes()),
            &to_uuid(j.boot_service_id.as_bytes()),
            &to_uuid(j.package.id.as_bytes()),
            &to_i64(j.package.revision, "package revision")?,
            &to_uuid(j.image_content_id.as_bytes()),
            &to_i32(j.edition_index.get(), "edition index")?,
            &disk,
            &mac_params(&j.macs),
            &j.bytes_total
                .map(|b| to_i64(b, "bytes_total"))
                .transpose()?,
            &j.started_at.as_micros(),
            &j.previous_job_id.map(|p| to_uuid(p.as_bytes())),
            &to_i64(j.wipe_audit_seq, "wipe audit seq")?,
            &j.wipe_record_hash.0.as_slice(),
            &j.plan_sha256.0.as_slice(),
            &j.plan_key_id.0.0.as_slice(),
            &step_timeouts,
            &to_i32(j.timeouts.stall_s, "stall timeout")?,
            &j.job_key_spki.as_der().as_slice(),
            &j.job_key_id.0.as_slice(),
            &j.rendered_answer_sha256.0.as_slice(),
            &tag_params(&j.tags)?,
        ],
    )
    .await?;
    for step in StepV2::ALL {
        let first = step == StepV2::VERIFY_CONTENT;
        let state = if first {
            StepState::Running
        } else {
            StepState::Pending
        };
        tx.execute(
            "insert job_step",
            "INSERT INTO job_step (job_id, step, state, started_at_us) VALUES ($1, $2, $3, $4)",
            &[
                &id,
                &step_v2_param(step),
                &state.as_str(),
                &first.then(|| j.started_at.as_micros()),
            ],
        )
        .await?;
    }
    Ok(())
}

pub(crate) async fn get_v2(tx: &mut PgTx, id: JobId, lock: bool) -> Result<Option<JobV2>, DbError> {
    let sql = format!(
        "{}{}",
        select_v2("id = $1"),
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = tx
        .query_opt("read job", &sql, &[&to_uuid(id.as_bytes())])
        .await?;
    row.map(|r| from_row_v2(&r)).transpose()
}

pub(crate) async fn by_session_v2(tx: &mut PgTx, id: SessionId) -> Result<Option<JobV2>, DbError> {
    let row = tx
        .query_opt(
            "read job",
            &select_v2("session_id = $1"),
            &[&to_uuid(id.as_bytes())],
        )
        .await?;
    row.map(|r| from_row_v2(&r)).transpose()
}

pub(crate) async fn list_v2(tx: &mut PgTx, states: &[JobState]) -> Result<Vec<JobV2>, DbError> {
    let st = texts(states, JobState::as_str);
    let sql = format!(
        "{} ORDER BY started_at_us, id",
        select_v2("(cardinality($1::text[]) = 0 OR state = ANY($1))")
    );
    let rows = tx.query("list job", &sql, &[&st]).await?;
    rows.iter().map(from_row_v2).collect()
}

pub(crate) async fn plan_schema(tx: &mut PgTx, id: JobId) -> Result<Option<u8>, DbError> {
    let row = tx
        .query_opt(
            "read job schema",
            "SELECT plan_schema FROM job WHERE id = $1",
            &[&to_uuid(id.as_bytes())],
        )
        .await?;
    row.map(|r| {
        let v: i16 = col(&r, "plan_schema")?;
        u8::try_from(v)
            .ok()
            .filter(|v| matches!(v, 1 | 2))
            .ok_or(DbError::Corrupt {
                what: "plan_schema",
            })
    })
    .transpose()
}

pub(crate) async fn steps_v2(tx: &mut PgTx, id: JobId) -> Result<Vec<JobStepV2>, DbError> {
    let sql = format!(
        "SELECT {STEP_COLUMNS} FROM job_step WHERE job_id = $1 \
         AND EXISTS (SELECT 1 FROM job j WHERE j.id = $1 AND j.plan_schema = 2) ORDER BY step"
    );
    let rows = tx
        .query("list job_step", &sql, &[&to_uuid(id.as_bytes())])
        .await?;
    rows.iter().map(step_v2_from_row).collect()
}

pub(crate) async fn set_step_v2(
    tx: &mut PgTx,
    id: JobId,
    step: StepV2,
    to: StepState,
    at: UnixMicros,
) -> Result<(), DbError> {
    set_step_n(tx, id, 2, step_v2_param(step), to, at).await
}

pub(crate) async fn fail_v2(
    tx: &mut PgTx,
    id: JobId,
    from: &[JobState],
    failure: &FailureV2,
    at: UnixMicros,
) -> Result<(), DbError> {
    failure
        .validate()
        .map_err(|_| DbError::InvalidArgument { what: "failure" })?;
    let uid = to_uuid(id.as_bytes());
    let st = texts(from, JobState::as_str);
    let detail = to_json(failure, "failure")?;
    let n = tx
        .execute(
            "update job failed",
            "UPDATE job SET state = 'failed', failure_step = $2, failure_category = $3, \
             failure_detail = $4, attempts = $5, finished_at_us = $6 \
             WHERE id = $1 AND state = ANY($7) AND plan_schema = 2",
            &[
                &uid,
                &step_v2_param(failure.step),
                &failure.category.as_str(),
                &detail,
                &to_i32(failure.attempts, "attempts")?,
                &at.as_micros(),
                &st,
            ],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "job", &uid).await);
    }
    Ok(())
}

pub(crate) async fn set_restart_pending(tx: &mut PgTx, id: JobId) -> Result<(), DbError> {
    let uid = to_uuid(id.as_bytes());
    let n = tx
        .execute(
            "update job restart pending",
            "UPDATE job SET restart_pending = true \
             WHERE id = $1 AND plan_schema = 2 AND state IN ('running', 'lost')",
            &[&uid],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "job", &uid).await);
    }
    Ok(())
}
