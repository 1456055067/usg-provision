//! `POST /v1/device/session/confirm`: the separate wipe confirmation and
//! the signed job plan (plan M3 sections 1.1 step 7, 3.1 and 3.2).
//!
//! In **one transaction** the server:
//!
//! 1. re-checks the session (authorised, not expired), that the request
//!    repeats the chosen package and disk, and that the package is still
//!    offered and the disk still large enough;
//! 2. writes `job.created` and `disk.wipe.authorised` (target `job`, the
//!    new job id, outcome success: the WU-7 wipe-guard contract);
//! 3. builds the plan payload, which carries that record's sequence
//!    number and hash, and stores the job with the payload's SHA-256;
//! 4. moves the session to `confirmed`.
//!
//! Only after the commit is the payload signed and returned, with
//! `job.plan.issued`. If any audit write fails, the transaction is dropped:
//! no job, no plan, the session stays authorised, and the answer is 503
//! `audit_unavailable` (acceptance criterion 3). A wipe never starts
//! without a durable `disk.wipe.authorised`, since the agent builds its
//! wipe authorisation only from a verified plan that names the record.
//!
//! The plan carries no secret (REQ-TGT-015).

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-2, AU-3, AU-12 - the wipe authorisation is recorded
//   before the plan exists; the plan names the record, and the record
//   names how the session was authorised (`auth_method`, with
//   `auth_code_id` or `approved_by_operator`; finding NIST-006).
// - NIST 800-53: AU-10 (basis only) - the person who confirms the wipe at
//   the device is not identified; the record binds the confirmation to the
//   session and its authorisation, not to a person.
// - NIST 800-53: SI-10, CM-3 - claimed MACs already stopped from network
//   boot, or held by another running job, are refused (decision 0023
//   item 2).
// - NIST 800-53: AU-5 - an audit failure refuses the confirmation.
// - NIST 800-53: SI-7(6), SC-13 - plan signed with the plan key (ECDSA
//   P-384, FIPS module), bound to the agent's nonce.
// - NIST 800-53: SC-23 - plan bound to session, job, nonce, MACs and disk.
// - NIST 800-53: CM-3 - the destructive change is authorised explicitly,
//   separately from the disk choice.
// - SPEC: specs/targeting.md#REQ-TGT-006, #REQ-TGT-011, #REQ-TGT-015;
//   specs/disk.md#REQ-DISK-006, #REQ-DISK-015; specs/progress.md
//   #REQ-JOB-009 (previous job), #REQ-JOB-012
// - Decision 0018 items 7 and 10

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use usgp_audit::Detail;
use usgp_db::{ChosenPackage, DbError, JobTimeouts, NewJob, RepoTx, SessionAuth, Store};
use usgp_proto::device::{ConfirmV1, ConfirmedV1, SessionState};
use usgp_proto::job_plan::{
    LayoutPolicyV1, PlanDeviceV1, PlanImageV1, PlanPackageV1, PlanStepV1, PlanWipeV1,
    RetryPolicyV1, SCHEMA_V1, WipeScope,
};
use usgp_proto::{
    JobId, JobPlanV1, MacList, PayloadType, PlanDiskV1, SessionId, Step, UnixMicros, codes,
};

use super::auth::{DeviceCtx, require};
use super::handlers::lock_live;
use super::job::overdue;
use super::offer::offered;
use crate::body::ApiBody;
use crate::context::Api;
use crate::error::ApiError;
use crate::handlers::auth_codes::{keys_unavailable, random};
use crate::handlers::sessions::macs_text;
use crate::handlers::{json_response, parse_device_json, read_body};
use crate::manifest::envelope;

/// The event the wipe guard requires (WU-7 contract).
pub const WIPE_AUTHORISED: &str = "disk.wipe.authorised";

/// Refuses (409 `in_use`) if one of `macs` has an uncleared boot stop on
/// any boot service, or belongs to a running job of a session other than
/// `own` (decision 0023 item 2). A running job already past its plan's
/// step or stall timeout does not hold its MACs (finding SEC-012; the
/// sweep fails it). The caller holds the claim lock (finding SEC-013.1).
/// Used at confirmation and again when a job succeeds (finding SEC-014).
pub(crate) async fn claims_free<T: RepoTx>(
    tx: &mut T,
    macs: &MacList,
    own: SessionId,
    at: UnixMicros,
) -> Result<(), ApiError> {
    let stops = tx.active_boot_stops_for_macs(macs).await?;
    let running: Vec<JobId> = tx.running_jobs_for_macs(macs).await?;
    let mut others = Vec::with_capacity(running.len());
    for id in running {
        if let Some(j) = tx.job(id).await? {
            if j.session_id == own {
                continue;
            }
            let steps = tx.job_steps(id).await?;
            if overdue(&j, &steps, at).is_none() {
                others.push(id);
            }
        } else if let Some(j) = tx.job_v2(id).await? {
            // M4: a nine-step job holds its MACs the same way.
            if j.session_id == own {
                continue;
            }
            let steps = tx.job_steps_v2(id).await?;
            if super::job_v2::overdue_v2(&j, &steps, at).is_none() {
                others.push(id);
            }
        }
    }
    if stops.is_empty() && others.is_empty() {
        return Ok(());
    }
    let list = |v: Vec<String>| v.join(",");
    Err(ApiError::conflict(
        codes::IN_USE,
        "a network address this device reports is already stopped from network boot or in \
         use by another running job; an operator must clear the stop or the job must finish",
    )
    .detail(
        Detail::new()
            .with(
                "macs",
                &macs
                    .as_slice()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
            )
            .with("claimed", "macs")
            .with(
                "stopped_macs",
                &list(stops.iter().map(|b| b.mac.to_string()).collect()),
            )
            .with(
                "boot_stop_ids",
                &list(stops.iter().map(|b| b.id.to_string()).collect()),
            )
            .with(
                "running_job_ids",
                &list(others.iter().map(ToString::to_string).collect()),
            ),
    ))
}

pub(crate) fn mismatch(what: &str) -> ApiError {
    ApiError::conflict(
        codes::WRONG_STATE,
        format!("the confirmation does not match the chosen {what}; choose again"),
    )
}

/// The step list with the configured timeouts.
fn steps(j: &crate::device::JobSettings) -> Vec<PlanStepV1> {
    let t = [
        j.timeout_verify_s,
        j.timeout_disk_s,
        j.timeout_apply_s,
        j.timeout_boot_s,
        j.timeout_report_s,
    ];
    Step::ALL
        .iter()
        .zip(t)
        .map(|(s, timeout_s)| PlanStepV1 {
            step: *s,
            kind: s.kind(),
            timeout_s,
        })
        .collect()
}

/// `POST /v1/device/session/confirm`.
pub(crate) async fn confirm<S: Store + 'static>(
    api: &Api<S>,
    ctx: &DeviceCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let s = ctx.session()?;
    require(s, &[SessionState::Authorised])?;
    let keys = api.provisioning_keys().ok_or_else(keys_unavailable)?;
    let c = &api.config().device;
    let body = read_body(req, c.max_json_bytes).await?;
    // M4: an agent that sends a job key gets a v2 (nine-step) plan.
    if super::confirm_v2::is_v2(&body) {
        return super::confirm_v2::confirm(api, ctx, &body).await;
    }
    let confirm = parse_device_json!(ConfirmV1, &body, c.max_json_bytes)?;
    let at = api.now()?;
    let job_id = JobId::from_random_bytes(random::<16>()?);

    let mut tx = api.store().begin().await?;
    let cur = lock_live(api, &mut tx, s.id, &[SessionState::Authorised]).await?;
    let (Some(chosen), Some(disk)) = (cur.chosen_package, cur.chosen_disk.clone()) else {
        return Err(ApiError::conflict(
            codes::WRONG_STATE,
            "choose a package and a disk before confirming the wipe",
        ));
    };
    if (confirm.package_id, confirm.revision) != (chosen.id, chosen.revision) {
        return Err(mismatch("package"));
    }
    if confirm.disk_token != disk.disk_token() {
        return Err(mismatch("disk"));
    }
    let Some(bs) = cur.boot_service_id else {
        return Err(ApiError::conflict(
            codes::WRONG_STATE,
            "the device has no boot service",
        ));
    };
    let offers = offered(api, &mut tx, &cur).await?.unwrap_or_default();
    let Some(o) = offers
        .into_iter()
        .find(|o| o.view.package_id == chosen.id && o.view.revision == chosen.revision)
    else {
        return Err(ApiError::unprocessable(
            codes::PACKAGE_NOT_OFFERED,
            "the chosen package is no longer offered to this device",
        ));
    };
    if disk.size_bytes() < o.view.required_disk_bytes {
        return Err(ApiError::unprocessable(
            codes::DISK_TOO_SMALL,
            "the chosen disk is smaller than the package needs",
        ));
    }
    // Decision 0023 item 2 (findings SEC-002, BOOT-005): the MACs this
    // session claims become boot stops when its job succeeds, so a MAC
    // that is already stopped, or held by a running job of another
    // session, is refused here.
    // Finding SEC-013.1: held until the job row commits, so a second
    // confirmation claiming one of these MACs sees this job running.
    tx.lock_mac_claims().await?;
    claims_free(&mut tx, &cur.macs, cur.id, at).await?;
    let previous = tx.previous_failed_job(&cur.macs).await?;
    let disk_detail = || {
        Detail::new()
            .with("session_id", &cur.id.to_string())
            .with("disk_token", &disk.disk_token().to_string())
            .with("bus", disk.bus().as_str())
            .with("model", disk.model().as_str())
            .with("serial", disk.serial().as_str())
            .with("size_bytes", &disk.size_bytes())
            .with("existing_partitions", &disk.partitions().len())
            .with("package_id", &chosen.id.to_string())
            .with("revision", &chosen.revision)
            .with("macs", &macs_text(&cur))
            .with("claimed", "macs")
    };
    // NIST-006 (AU-3): how the session was authorised, and by what.
    let auth_detail = |d: Detail| match cur.auth {
        Some(SessionAuth::Code(id)) => d
            .with("auth_method", "code")
            .with("auth_code_id", &id.to_string()),
        Some(SessionAuth::Approval(op)) => d
            .with("auth_method", "approval")
            .with("approved_by_operator", &op.to_string()),
        None => d.with("auth_method", "none"),
    };

    // 1. job.created, 2. disk.wipe.authorised: both before the job row.
    let created = ctx
        .ok("job.created")
        .target("job", &job_id.to_string())
        .detail(disk_detail().with(
            "previous_job_id",
            &previous.map_or_else(|| "none".to_owned(), |p| p.to_string()),
        ));
    let r_created = api.append(&mut tx, &created).await?;
    let wipe = ctx
        .ok(WIPE_AUTHORISED)
        .target("job", &job_id.to_string())
        .initiated_by(r_created.seq)
        .detail(auth_detail(
            disk_detail().with("scope", WipeScope::TablesAndVolumeHeads1Mib.as_str()),
        ));
    let r_wipe = api.append(&mut tx, &wipe).await?;

    // 3. The plan payload names the wipe record.
    let plan_key_id = keys.plan_key_id();
    let j = &c.jobs;
    let plan = JobPlanV1 {
        schema: SCHEMA_V1,
        job_id,
        session_id: cur.id,
        boot_service_id: bs,
        issued_at_us: at,
        key_id: plan_key_id.0,
        agent_nonce: confirm.agent_nonce,
        device: PlanDeviceV1 {
            macs: cur.macs.clone(),
        },
        package: PlanPackageV1 {
            id: chosen.id,
            revision: chosen.revision,
            manifest_sha256: o.package_manifest_sha256,
        },
        image: PlanImageV1 {
            content_sha256: o.image.sha256,
            size: o.image.size,
            content_manifest_sha256: usgp_crypto::sha256(&o.stored_content_manifest.payload),
            edition_index: o.edition_index,
            edition_name: o.edition_name.clone(),
            total_bytes: o.total_bytes,
        },
        disk: PlanDiskV1::from(&disk),
        layout_policy: LayoutPolicyV1::STANDARD,
        wipe: PlanWipeV1 {
            audit_seq: r_wipe.seq,
            record_hash: r_wipe.record_hash,
            scope: WipeScope::TablesAndVolumeHeads1Mib,
        },
        steps: steps(j),
        retry: RetryPolicyV1 {
            attempts: j.retry_attempts,
            base_ms: j.retry_base_ms,
            max_ms: j.retry_max_ms,
        },
        stall_timeout_s: j.stall_timeout_s,
        report_interval_s: j.report_interval_s,
    };
    let payload = plan.to_payload().map_err(ApiError::internal_error)?;
    let plan_sha256 = usgp_crypto::sha256(&payload);
    let new = NewJob {
        id: job_id,
        session_id: cur.id,
        boot_service_id: bs,
        package: ChosenPackage {
            id: chosen.id,
            revision: chosen.revision,
        },
        image_content_id: o.image.id,
        edition_index: o.edition_index,
        disk: disk.clone(),
        macs: cur.macs.clone(),
        previous_job_id: previous,
        wipe_audit_seq: r_wipe.seq,
        wipe_record_hash: r_wipe.record_hash,
        plan_sha256,
        plan_key_id,
        timeouts: JobTimeouts {
            steps_s: [
                j.timeout_verify_s,
                j.timeout_disk_s,
                j.timeout_apply_s,
                j.timeout_boot_s,
                j.timeout_report_s,
            ],
            stall_s: j.stall_timeout_s,
        },
        bytes_total: None,
        started_at: at,
    };
    match tx.insert_job(&new).await {
        Ok(()) => {}
        Err(DbError::Conflict { .. }) => {
            return Err(ApiError::conflict(
                codes::JOB_STARTED,
                "a job already exists for this session",
            ));
        }
        Err(e) => return Err(e.into()),
    }
    // 4. The session is confirmed: no cancel from here (REQ-TGT-011).
    match tx
        .set_device_session_state(
            cur.id,
            &[SessionState::Authorised],
            SessionState::Confirmed,
            None,
            at,
        )
        .await
    {
        Ok(()) => {}
        Err(DbError::Conflict { .. }) => {
            return Err(ApiError::conflict(
                codes::WRONG_STATE,
                "the session can no longer be confirmed",
            ));
        }
        Err(e) => return Err(e.into()),
    }
    // The wipe guard checks the record at commit: a job without its
    // durable `disk.wipe.authorised` cannot commit.
    api.commit(tx, &[r_created, r_wipe.clone()]).await?;

    // After the commit: sign and return the plan.
    let signed = keys.sign_plan(payload).map_err(ApiError::internal_error)?;
    let plan_env = envelope(PayloadType::JobPlanV1, &signed).map_err(ApiError::internal_error)?;
    let content_env = envelope(PayloadType::ContentManifestV1, &o.stored_content_manifest)
        .map_err(ApiError::internal_error)?;
    let issued = ctx
        .ok("job.plan.issued")
        .target("job", &job_id.to_string())
        .initiated_by(r_wipe.seq)
        .detail(
            Detail::new()
                .with("plan_sha256", &plan_sha256)
                .with("key_id", &plan_key_id)
                .with("wipe_audit_seq", &r_wipe.seq),
        );
    // If the issue cannot be recorded the plan is withheld (fail closed):
    // the job is reported lost later and nothing is written to the disk.
    api.record(&issued).await?;
    let out = ConfirmedV1 {
        job_id,
        plan: plan_env,
        content_manifest: content_env,
    };
    json_response!(StatusCode::CREATED, &out)
}
