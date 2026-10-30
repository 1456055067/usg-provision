//! `POST /v1/device/session/confirm` from an M4 agent (`ConfirmV2`, with
//! the public half of the job key): the signed v2 (nine-step) plan (M4
//! plan sections 1.1, 1.6, 1.7, 3.1; decisions 0024 and 0025).
//!
//! As the M3 confirmation (`confirm.rs`), in **one transaction**, plus:
//!
//! 1. the package's configuration, its agent package (Ready, signer not
//!    revoked) and its driver archives (Ready) are read, and each one's
//!    signed content manifest is verified; anything missing is 409
//!    `package_not_ready:<what>`;
//! 2. the answer-file template is parsed and linted again and **rendered
//!    before the job row**, with the package values and the values set for
//!    the device's MAC (`device.<key>`). An unresolved or invalid value
//!    ends the session (`config_unresolved`), writes
//!    `job.config.unresolved` (names only) and answers 409
//!    `unresolved_value:<name>`: no job, no wipe;
//! 3. on success `job.config.resolved` (reference names and the rendered
//!    file's SHA-256) joins `job.created` and `disk.wipe.authorised`, and
//!    the job row stores the job key, its id, the rendered SHA-256 and the
//!    tags;
//! 4. when the package's `admin_password` is `generate_and_escrow`, the
//!    plan carries the server's escrow public key (503 if none is
//!    configured: fail closed).
//!
//! The plan carries no secret (decision 0024): the answer file holds none
//! by construction (the lint refuses secret-bearing settings), and the
//! escrow key is a public key.

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-2, AU-3, AU-12 - configuration resolved or unresolved,
//   job, wipe and plan records before the plan exists; AU-5 - an audit
//   failure refuses the confirmation.
// - NIST 800-53: SI-7, SI-7(6) - every content manifest verified before
//   it is named; the plan signed with the plan key (FIPS module).
// - NIST 800-53: SI-10, CM-6 - the template parsed (no DTD, bounded) and
//   linted; values checked at render; output parsed again.
// - NIST 800-53: IA-5, SC-28 - no secret in the plan or the answer file
//   (REQ-CFG-010, decision 0024 item 1).
// - NIST 800-53: SC-23 - plan bound to session, job, nonce, MACs, disk
//   and the device's job key.
// - SPEC: specs/configuration.md#REQ-CFG-003, #REQ-CFG-004,
//   #REQ-CFG-005, #REQ-CFG-008, #REQ-CFG-009, #REQ-CFG-010;
//   specs/drivers.md#REQ-DRV-004, #REQ-DRV-006;
//   specs/agent-handoff.md#REQ-AGT-001; specs/workflow.md#REQ-SEQ-001;
//   specs/targeting.md#REQ-TGT-006, #REQ-TGT-011, #REQ-TGT-015
// - Decisions 0024, 0025 item 1

use std::collections::BTreeMap;

use hyper::{Response, StatusCode};
use usgp_audit::{Detail, Outcome};
use usgp_db::{
    AdminPasswordMode, AgentPackageStatus, ChosenPackage, DbError, DeviceSession,
    DriverArchiveStatus, JobTimeoutsV2, NewJobV2, PackageConfig, RepoTx, SessionAuth, Store,
    StoredManifest,
};
use usgp_proto::device::{ConfirmV2, ConfirmedV2, SessionState};
use usgp_proto::job_plan::{
    LayoutPolicyV1, PlanAgentV2, PlanAnswerFileV2, PlanDeviceV1, PlanDriverV2, PlanEscrowV2,
    PlanImageV1, PlanPackageV1, PlanPostSetupV2, PlanStepV2, PlanWipeV1, RetryPolicyV1, SCHEMA_V2,
    WipeScope, resume_path,
};
use usgp_proto::{
    ContentKindV2, ContentState, EscrowAccount, JobId, JobPlanV2, P384Spki, PackageId, PayloadType,
    PlanDiskV1, StepV2, UrlPath, codes,
};
use usgp_wincfg::unattend::{MapResolver, RenderError};

use super::auth::{DeviceCtx, require};
use super::confirm::{WIPE_AUTHORISED, claims_free, mismatch};
use super::handlers::lock_live;
use super::offer::offered;
use crate::body::ApiBody;
use crate::context::Api;
use crate::error::ApiError;
use crate::handlers::auth_codes::{keys_unavailable, random};
use crate::handlers::package_config::check_template;
use crate::handlers::sessions::macs_text;
use crate::handlers::{code_of, json_response, parse_device_json};
use crate::manifest::{envelope, open_content_v2};

/// Session end reason when a value is unresolved (M4 plan section 1.6).
pub const CONFIG_UNRESOLVED: &str = "config_unresolved";

/// True if a confirm body is a v2 one (it carries `job_key_spki_b64`).
pub(crate) fn is_v2(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(body)
        .is_ok_and(|m| m.contains_key("job_key_spki_b64"))
}

/// 409 `package_not_ready:<what>`.
fn not_ready(what: &str, message: &str) -> ApiError {
    ApiError::conflict(
        codes::PACKAGE_NOT_READY
            .with_param(what)
            .unwrap_or(codes::PACKAGE_NOT_READY),
        message.to_owned(),
    )
}

/// The verified content the plan names.
struct Gathered {
    config: PackageConfig,
    drivers: Vec<(PlanDriverV2, StoredManifest)>,
    agent: (PlanAgentV2, StoredManifest),
}

/// Verifies a Ready archive item's stored manifest against the row.
async fn verified_archive<S: Store + 'static, T: RepoTx>(
    api: &Api<S>,
    tx: &mut T,
    id: usgp_proto::ContentId,
    kind: ContentKindV2,
    what: &str,
) -> Result<(usgp_proto::ContentManifestV2, StoredManifest), ApiError> {
    let c = tx
        .archive_content(id)
        .await?
        .filter(|c| c.kind == kind && c.state == ContentState::Ready)
        .ok_or_else(|| not_ready(what, "a content item the package names is not ready"))?;
    let stored = c
        .manifest
        .clone()
        .ok_or_else(|| not_ready(what, "a content item the package names has no manifest"))?;
    let m = open_content_v2(api.keys(), &stored)
        .ok()
        .filter(|m| {
            m.content_id == c.id && m.kind == c.kind && m.size == c.size && m.sha256 == c.sha256
        })
        .ok_or_else(|| {
            not_ready(what, "a content item's manifest did not verify")
                .internal("content manifest v2 signature, payload or binding invalid")
        })?;
    Ok((m, stored))
}

/// The package's configuration, agent package and driver archives, all
/// verified.
async fn gather<S: Store + 'static, T: RepoTx>(
    api: &Api<S>,
    tx: &mut T,
    package: PackageId,
) -> Result<Gathered, ApiError> {
    let config = tx.package_config(package).await?.ok_or_else(|| {
        not_ready(
            "config",
            "the package has no answer file, agent package or password setting",
        )
    })?;
    let ap = tx
        .agent_package(config.agent_package_id)
        .await?
        .filter(|a| a.status == AgentPackageStatus::Ready)
        .ok_or_else(|| not_ready("agent_package", "the package's agent package is not ready"))?;
    let (am, astored) = verified_archive(
        api,
        tx,
        ap.content_id,
        ContentKindV2::AgentPackage,
        "agent_package",
    )
    .await?;
    let agent = (
        PlanAgentV2 {
            agent_package_id: ap.id,
            content_sha256: am.sha256,
            content_manifest_sha256: usgp_crypto::sha256(&astored.payload),
        },
        astored,
    );
    let mut drivers = Vec::new();
    for id in tx.package_drivers(package).await? {
        let d = tx
            .driver_archive(id)
            .await?
            .filter(|d| d.status == DriverArchiveStatus::Ready)
            .ok_or_else(|| not_ready("driver_archive", "a driver archive is not ready"))?;
        let (m, stored) = verified_archive(
            api,
            tx,
            d.content_id,
            ContentKindV2::DriverArchive,
            "driver_archive",
        )
        .await?;
        drivers.push((
            PlanDriverV2 {
                archive_id: d.id,
                content_sha256: m.sha256,
                content_manifest_sha256: usgp_crypto::sha256(&stored.payload),
                infs: m.archive.infs.clone(),
            },
            stored,
        ));
    }
    Ok(Gathered {
        config,
        drivers,
        agent,
    })
}

/// The render outcome.
enum Render {
    Done { bytes: Vec<u8>, names: Vec<String> },
    Unresolved { name: String, why: &'static str },
}

/// Renders the template with the package values and the device's values.
async fn render<T: RepoTx>(
    tx: &mut T,
    cfg: &PackageConfig,
    s: &DeviceSession,
) -> Result<Render, ApiError> {
    let template = check_template(&cfg.answer_template, &cfg.values).map_err(|_| {
        not_ready(
            "answer_file",
            "the package's answer file no longer passes its checks",
        )
    })?;
    let mut map = BTreeMap::new();
    let v = &cfg.values;
    for (k, val) in [
        ("computer_name", &v.computer_name),
        ("time_zone", &v.time_zone),
        ("domain", &v.domain),
        ("machine_ou", &v.machine_ou),
    ] {
        if let Some(val) = val {
            map.insert(k.to_owned(), val.clone());
        }
    }
    // The device's values, by any of its MACs. Values set for two of its
    // MACs are ambiguous: refused, not guessed (fail closed).
    let mut rows = Vec::new();
    for mac in s.macs.as_slice() {
        if let Some(r) = tx.device_values(*mac).await? {
            rows.push(r);
        }
    }
    if rows.len() > 1 {
        return Ok(Render::Unresolved {
            name: "device".to_owned(),
            why: "values are set for more than one of the device's addresses",
        });
    }
    if let Some(r) = rows.pop() {
        for (k, val) in r.values {
            map.insert(format!("device.{k}"), val);
        }
    }
    let names = template.references();
    match template.render(&MapResolver(map)) {
        Ok(r) => Ok(Render::Done {
            bytes: r.bytes,
            names,
        }),
        Err(RenderError::Unresolved { name }) => Ok(Render::Unresolved {
            name,
            why: "no value is set",
        }),
        Err(RenderError::InvalidValue { name, .. }) => Ok(Render::Unresolved {
            name,
            why: "the value breaks its rules",
        }),
        Err(RenderError::TooLarge | RenderError::SelfCheck(_)) => Err(not_ready(
            "answer_file",
            "the rendered answer file failed its checks",
        )),
    }
}

/// `POST /v1/device/session/confirm` with a `ConfirmV2` body.
pub(crate) async fn confirm<S: Store + 'static>(
    api: &Api<S>,
    ctx: &DeviceCtx,
    body: &[u8],
) -> Result<Response<ApiBody>, ApiError> {
    let s = ctx.session()?;
    require(s, &[SessionState::Authorised])?;
    let keys = api.provisioning_keys().ok_or_else(keys_unavailable)?;
    let c = &api.config().device;
    let confirm = parse_device_json!(ConfirmV2, body, c.max_json_bytes)?;
    // The job key must be a P-384 key the FIPS module accepts: the
    // post-setup runner proves it later.
    usgp_crypto::VerifyingKey::from_spki_der(confirm.job_key_spki_b64.as_der()).map_err(|_| {
        ApiError::unprocessable(
            codes::INVALID_VALUE
                .with_param("job_key_spki_b64")
                .unwrap_or(codes::INVALID_VALUE),
            "job_key_spki_b64 is not a P-384 public key",
        )
    })?;
    let job_key_id = usgp_crypto::sha256(confirm.job_key_spki_b64.as_der());
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
    let g = gather(api, &mut tx, chosen.id).await?;
    let escrow = match g.config.admin_password {
        AdminPasswordMode::None => None,
        AdminPasswordMode::GenerateAndEscrow => {
            let ek = api.escrow_keys().ok_or_else(|| {
                ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    codes::UNAVAILABLE,
                    "the escrow key is not configured on this server",
                )
            })?;
            let public = ek.current().public();
            Some(PlanEscrowV2 {
                key_id: public.key_id().0,
                spki_b64: P384Spki::from_der(public.spki_der())
                    .map_err(ApiError::internal_error)?,
                account: EscrowAccount::Administrator,
            })
        }
    };

    // Render before any job record (REQ-CFG-004).
    let (rendered, names) = match render(&mut tx, &g.config, &cur).await? {
        Render::Done { bytes, names } => (bytes, names),
        Render::Unresolved { name, why } => {
            match tx
                .set_device_session_state(
                    cur.id,
                    &[SessionState::Authorised],
                    SessionState::Ended,
                    Some(&code_of(CONFIG_UNRESOLVED)),
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
            let d = ctx
                .draft("job.config.unresolved", Outcome::Refused)
                .reason(codes::UNRESOLVED_VALUE.as_str())
                .detail(
                    Detail::new()
                        .with("name", name.as_str())
                        .with("cause", why)
                        .with("package_id", &chosen.id.to_string())
                        .with("revision", &chosen.revision)
                        .with("macs", &macs_text(&cur))
                        .with("claimed", "macs")
                        .with("session_end_reason", CONFIG_UNRESOLVED),
                );
            let r = api.append(&mut tx, &d).await?;
            api.commit(tx, &[r]).await?;
            let code = codes::UNRESOLVED_VALUE
                .with_param(&name)
                .unwrap_or(codes::UNRESOLVED_VALUE);
            return Err(ApiError::conflict(
                code,
                format!("the answer file needs the value {name}, but {why}; ask an operator"),
            )
            .audited());
        }
    };
    let rendered_sha256 = usgp_crypto::sha256(&rendered);

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
            .with("plan_schema", &2u8)
    };
    let auth_detail = |d: Detail| match cur.auth {
        Some(SessionAuth::Code(id)) => d
            .with("auth_method", "code")
            .with("auth_code_id", &id.to_string()),
        Some(SessionAuth::Approval(op)) => d
            .with("auth_method", "approval")
            .with("approved_by_operator", &op.to_string()),
        None => d.with("auth_method", "none"),
    };
    let created = ctx
        .ok("job.created")
        .target("job", &job_id.to_string())
        .detail(disk_detail().with(
            "previous_job_id",
            &previous.map_or_else(|| "none".to_owned(), |p| p.to_string()),
        ));
    let r_created = api.append(&mut tx, &created).await?;
    let resolved = ctx
        .ok("job.config.resolved")
        .target("job", &job_id.to_string())
        .initiated_by(r_created.seq)
        .detail(
            Detail::new()
                .with("names", &names.join(","))
                .with("rendered_sha256", &rendered_sha256)
                .with("answer_template_sha256", &g.config.answer_sha256)
                .with("drivers", &g.drivers.len())
                .with("agent_package_id", &g.agent.0.agent_package_id.to_string())
                .with("admin_password", g.config.admin_password.as_str())
                .with("tags", &g.config.tags.len())
                .with("job_key_id", &job_key_id),
        );
    let r_resolved = api.append(&mut tx, &resolved).await?;
    let wipe = ctx
        .ok(WIPE_AUTHORISED)
        .target("job", &job_id.to_string())
        .initiated_by(r_created.seq)
        .detail(auth_detail(
            disk_detail().with("scope", WipeScope::TablesAndVolumeHeads1Mib.as_str()),
        ));
    let r_wipe = api.append(&mut tx, &wipe).await?;

    let plan_key_id = keys.plan_key_id();
    let j = &c.jobs;
    let timeouts = c.m4.step_timeouts_s;
    let plan = JobPlanV2 {
        schema: SCHEMA_V2,
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
        steps: StepV2::ALL
            .iter()
            .zip(timeouts)
            .map(|(s, timeout_s)| PlanStepV2 {
                step: *s,
                kind: s.kind(),
                timeout_s,
            })
            .collect(),
        retry: RetryPolicyV1 {
            attempts: j.retry_attempts,
            base_ms: j.retry_base_ms,
            max_ms: j.retry_max_ms,
        },
        stall_timeout_s: j.stall_timeout_s,
        report_interval_s: j.report_interval_s,
        answer_file: PlanAnswerFileV2 {
            sha256: rendered_sha256,
            b64: usgp_proto::B64Bytes::new(rendered).map_err(ApiError::internal_error)?,
        },
        drivers: g.drivers.iter().map(|(d, _)| d.clone()).collect(),
        agent: g.agent.0.clone(),
        tags: g.config.tags.clone(),
        escrow,
        job_key_id,
        postsetup: PlanPostSetupV2 {
            resume_url_path: UrlPath::new(resume_path(job_id)).map_err(ApiError::internal_error)?,
        },
    };
    let payload = plan.to_payload().map_err(ApiError::internal_error)?;
    let plan_sha256 = usgp_crypto::sha256(&payload);
    let new = NewJobV2 {
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
        timeouts: JobTimeoutsV2 {
            steps_s: timeouts,
            stall_s: j.stall_timeout_s,
        },
        bytes_total: None,
        started_at: at,
        job_key_spki: confirm.job_key_spki_b64.clone(),
        job_key_id,
        rendered_answer_sha256: rendered_sha256,
        tags: g.config.tags.clone(),
    };
    match tx.insert_job_v2(&new).await {
        Ok(()) => {}
        Err(DbError::Conflict { .. }) => {
            return Err(ApiError::conflict(
                codes::JOB_STARTED,
                "a job already exists for this session",
            ));
        }
        Err(e) => return Err(e.into()),
    }
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
    api.commit(tx, &[r_created, r_resolved, r_wipe.clone()])
        .await?;

    // After the commit: sign and return the plan with its manifests.
    let signed = keys
        .sign_plan_v2(payload)
        .map_err(ApiError::internal_error)?;
    let env = |ty, m: &StoredManifest| envelope(ty, m).map_err(ApiError::internal_error);
    let out = ConfirmedV2 {
        job_id,
        plan: env(PayloadType::JobPlanV2, &signed)?,
        content_manifest: env(PayloadType::ContentManifestV1, &o.stored_content_manifest)?,
        driver_manifests: g
            .drivers
            .iter()
            .map(|(_, m)| env(PayloadType::ContentManifestV2, m))
            .collect::<Result<_, _>>()?,
        agent_manifest: env(PayloadType::ContentManifestV2, &g.agent.1)?,
    };
    let issued = ctx
        .ok("job.plan.issued")
        .target("job", &job_id.to_string())
        .initiated_by(r_wipe.seq)
        .detail(
            Detail::new()
                .with("plan_sha256", &plan_sha256)
                .with("key_id", &plan_key_id)
                .with("wipe_audit_seq", &r_wipe.seq)
                .with("plan_schema", &2u8),
        );
    // Withheld if the issue cannot be recorded (fail closed).
    api.record(&issued).await?;
    json_response!(StatusCode::CREATED, &out)
}
