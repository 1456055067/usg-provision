//! QA M3 (qa-engineer): gaps found while tracing the AUDITED M3
//! requirements to tests. Offer filtering by firmware and integrity
//! (REQ-TGT-002, REQ-TGT-003), operator refusal (REQ-TGT-014), the link
//! to the previous failed job (REQ-JOB-009), failure persistence
//! (REQ-JOB-006), Lost to a final state (REQ-JOB-012), AU-3 fields on
//! every job state change and device choice (REQ-TGT-016, REQ-JOB-012,
//! decision 0018 item 10) and no secret in any operator view
//! (REQ-JOB-014, REQ-TGT-015).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: AU-3, AU-12, AC-3, SI-7, SI-11, SA-11
//! - SPEC: specs/targeting.md, specs/progress.md

use std::time::Duration;

use usgp_audit::AuditRecord;
use usgp_db::{RepoTx, Store};
use usgp_proto::{JobId, JobState};

use crate::common::{Harness, Opened, Who, hello, nonce};

fn ev(seq: u64, step: u8, event: &str) -> serde_json::Value {
    serde_json::json!({ "seq": seq, "step": step, "event": event })
}

fn failed(seq: u64) -> serde_json::Value {
    let mut f = ev(seq, 1, "failed");
    f["failure"] = serde_json::json!({
        "step": 1, "category": "integrity", "code": "chunk_digest_mismatch",
        "files": [{"role": "image", "name": "install.wim"}], "count": 1, "attempts": 1
    });
    f
}

async fn confirm_job(
    h: &Harness,
    token: &str,
    pkg: &str,
    d: &usgp_proto::DiskDescriptorV1,
) -> String {
    let r = h.confirm(token, pkg, d, &nonce()).await;
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    r.json()["job_id"].as_str().unwrap().to_owned()
}

/// Opens a session with a custom hello and authorises it by code.
async fn authorised_with(h: &Harness, hello: serde_json::Value) -> Opened {
    let r = h
        .dev("POST", "/v1/device/sessions", None, Some(hello))
        .await;
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    let j = r.json();
    let s = Opened {
        id: j["session_id"].as_str().unwrap().to_owned(),
        token: j["token"].as_str().unwrap().to_owned(),
        display_code: j["display_code"].as_str().unwrap().to_owned(),
    };
    let (_, code) = h.issue_code().await;
    assert_eq!(h.submit_code(&s.token, &code).await.status, 200);
    s
}

async fn job_state(h: &Harness, job: &str) -> JobState {
    let mut tx = h.store.begin().await.unwrap();
    let st = tx
        .job(JobId::parse(job).unwrap())
        .await
        .unwrap()
        .unwrap()
        .state;
    tx.rollback().await;
    st
}

/// AU-3: what (event, outcome), when (time), who (the device session,
/// claimed identity), where (device listener, source address), on what
/// (target).
fn assert_device_au3(r: &AuditRecord, session: &str, target_kind: &str, target_id: &str) {
    assert!(r.ts_us > 0, "{r:?}");
    assert_eq!(r.outcome, "success", "{r:?}");
    assert_eq!(r.actor_kind, "device_session", "{r:?}");
    assert_eq!(r.actor_id.as_deref(), Some(session), "{r:?}");
    assert!(
        r.actor_label
            .as_deref()
            .is_some_and(|l| l.contains("(claimed)")),
        "{r:?}"
    );
    assert_eq!(r.interface, "device_api", "{r:?}");
    assert!(
        r.source
            .as_deref()
            .is_some_and(|s| s.starts_with("127.0.0.1:")),
        "{r:?}"
    );
    assert_eq!(r.target_kind.as_deref(), Some(target_kind), "{r:?}");
    assert_eq!(r.target_id.as_deref(), Some(target_id), "{r:?}");
}

/// REQ-TGT-003: a BIOS or non-x64 device is offered nothing, and cannot
/// choose an assigned, Ready package by naming it directly.
#[tokio::test]
async fn firmware_or_arch_mismatch_offers_nothing_and_package_cannot_be_named() {
    let h = Harness::m3().await;
    let rd = h.ready_device("fwmismatch", &["02:00:00:00:0a:01"]).await;
    for (i, (fw, arch)) in [
        ("bios", "x64"),
        ("uefi", "arm64"),
        ("uefi", "x86"),
        ("unknown", "x64"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut hl = hello(&[&format!("02:00:00:00:0a:1{i}")]);
        hl["firmware"] = fw.into();
        hl["arch"] = arch.into();
        let s = authorised_with(&h, hl).await;
        let r = h
            .dev("GET", "/v1/device/session/packages", Some(&s.token), None)
            .await;
        assert_eq!(r.status, 200, "{fw}/{arch}");
        assert_eq!(r.json()["packages"], serde_json::json!([]), "{fw}/{arch}");
        let r = h
            .dev(
                "POST",
                "/v1/device/session/package",
                Some(&s.token),
                Some(serde_json::json!({ "package_id": rd.pkg, "revision": 1 })),
            )
            .await;
        assert_eq!(
            r.status,
            422,
            "{fw}/{arch}: {}",
            String::from_utf8_lossy(&r.body)
        );
        assert_eq!(r.code(), "package_not_offered", "{fw}/{arch}");
    }
    // The UEFI x64 session of the same boot service still sees it.
    let r = h
        .dev(
            "GET",
            "/v1/device/session/packages",
            Some(&rd.session.token),
            None,
        )
        .await;
    assert_eq!(r.json()["packages"].as_array().unwrap().len(), 1);
}

/// REQ-TGT-002 (fail closed): once the package's image fails its
/// integrity check, no session is offered it, and a session that chose
/// it before the failure cannot confirm (no job, no wipe record).
#[tokio::test]
async fn integrity_failed_package_is_withdrawn_even_after_it_was_chosen() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::m3().await;
    let rd = h.ready_device("withdrawn", &["02:00:00:00:0b:01"]).await;
    // A second device chose the same package and disk before the damage.
    let (late, late_disk) = h.chosen_session(&rd.pkg, &["02:00:00:00:0b:02"]).await;
    let job = confirm_job(&h, &rd.session.token, &rd.pkg, &rd.disk).await;
    let sha = {
        let mut tx = h.store.begin().await.unwrap();
        let j = tx.job(JobId::parse(&job).unwrap()).await.unwrap().unwrap();
        let c = tx.content(j.image_content_id).await.unwrap().unwrap();
        tx.rollback().await;
        c.sha256
    };
    let path = h.api.files().object_path(&sha);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[0] ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    let r = h
        .dev(
            "GET",
            &format!("/v1/device/jobs/{job}/content/{}/chunks/0", sha.to_hex()),
            Some(&rd.session.token),
            None,
        )
        .await;
    assert_eq!(r.status, 500);
    assert_eq!(r.code(), "integrity_failed");
    let wipes_before = h.events("disk.wipe.authorised").len();
    // The late session cannot start a job on the damaged package.
    let r = h.confirm(&late.token, &rd.pkg, &late_disk, &nonce()).await;
    assert_ne!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    assert!(r.json().get("plan").is_none());
    assert_eq!(h.events("disk.wipe.authorised").len(), wipes_before);
    let mut tx = h.store.begin().await.unwrap();
    assert!(
        tx.job_by_session(usgp_proto::SessionId::parse(&late.id).unwrap())
            .await
            .unwrap()
            .is_none()
    );
    tx.rollback().await;
    // A new session is offered nothing.
    let fresh = authorised_with(&h, hello(&["02:00:00:00:0b:03"])).await;
    let r = h
        .dev(
            "GET",
            "/v1/device/session/packages",
            Some(&fresh.token),
            None,
        )
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["packages"], serde_json::json!([]));
    assert!(!h.events("boot_service.no_usable_package").is_empty());
}

/// REQ-TGT-014: an operator refuses a waiting device; it gets nothing
/// afterwards, even with a valid code; the refusal is audited with the
/// operator as actor and no display-code check is skipped elsewhere.
#[tokio::test]
async fn operator_refusal_of_a_waiting_device() {
    let h = Harness::m3().await;
    let _rd = h.ready_device("refuse", &["02:00:00:00:0c:01"]).await;
    let s = h.open_session(&["02:00:00:00:0c:02"]).await;
    let r = h
        .post_json(
            Who::Admin,
            &format!("/v1/device-sessions/{}/refuse", s.id),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let r = h
        .dev("GET", "/v1/device/session", Some(&s.token), None)
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["state"], "refused");
    assert_eq!(r.json()["reason_code"], "operator_refused");
    let r = h
        .dev("GET", "/v1/device/session/packages", Some(&s.token), None)
        .await;
    assert_eq!(r.status, 403);
    let (_, code) = h.issue_code().await;
    assert_eq!(h.submit_code(&s.token, &code).await.status, 403);
    // Approval after refusal is refused; a second refusal is refused.
    let r = h
        .post_json(
            Who::Admin,
            &format!("/v1/device-sessions/{}/approve", s.id),
            serde_json::json!({ "display_code": s.display_code }),
        )
        .await;
    assert_eq!(r.status, 409);
    let r = h
        .post_json(
            Who::Admin,
            &format!("/v1/device-sessions/{}/refuse", s.id),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(r.status, 409);
    let recs: Vec<_> = h
        .events("device.session.refused")
        .into_iter()
        .filter(|r| r.target_id.as_deref() == Some(s.id.as_str()))
        .collect();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].reason.as_deref(), Some("operator_refused"));
    assert_eq!(recs[0].actor_kind, "operator");
    assert_eq!(recs[0].outcome, "success");
    // A refused session never became a job.
    let mut tx = h.store.begin().await.unwrap();
    assert!(
        tx.job_by_session(usgp_proto::SessionId::parse(&s.id).unwrap())
            .await
            .unwrap()
            .is_none()
    );
    tx.rollback().await;
}

/// REQ-JOB-009: a new job for the same device links the failed one, in
/// the operator view and in its `job.created` record.
#[tokio::test]
async fn new_job_links_the_previous_failed_job() {
    let h = Harness::m3().await;
    let macs = ["02:00:00:00:0d:01"];
    let rd = h.ready_device("relink", &macs).await;
    let first = confirm_job(&h, &rd.session.token, &rd.pkg, &rd.disk).await;
    let r = h.report(&rd.session.token, &first, failed(1)).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let (s2, d2) = h.chosen_session(&rd.pkg, &macs).await;
    let second = confirm_job(&h, &s2.token, &rd.pkg, &d2).await;
    assert_ne!(first, second);
    let r = h.get(Who::Admin, &format!("/v1/jobs/{second}")).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["previous_job_id"], first.as_str());
    let created: Vec<_> = h
        .events("job.created")
        .into_iter()
        .filter(|r| r.target_id.as_deref() == Some(second.as_str()))
        .collect();
    assert_eq!(created.len(), 1);
    assert!(created[0].detail.contains(&first), "{}", created[0].detail);
    // A different device does not inherit the link.
    let (s3, d3) = h.chosen_session(&rd.pkg, &["02:00:00:00:0d:02"]).await;
    let third = confirm_job(&h, &s3.token, &rd.pkg, &d3).await;
    let r = h.get(Who::Admin, &format!("/v1/jobs/{third}")).await;
    assert!(r.json().get("previous_job_id").is_none(), "{}", r.json());
}

/// REQ-JOB-006: the failed state, its detail and the time of failure stay
/// in the operator view; the lost and expiry sweeps do not clear them.
#[tokio::test]
async fn failure_is_not_cleared_by_the_passage_of_time() {
    let h = Harness::m3().await;
    let rd = h.ready_device("persist", &["02:00:00:00:0e:01"]).await;
    let job = confirm_job(&h, &rd.session.token, &rd.pkg, &rd.disk).await;
    assert_eq!(
        h.report(&rd.session.token, &job, failed(1)).await.status,
        200
    );
    let before = h.get(Who::Admin, &format!("/v1/jobs/{job}")).await.json();
    for _ in 0..7 {
        h.clock.advance(Duration::from_secs(86_400));
        assert_eq!(h.api.mark_lost_jobs().await.unwrap(), 0);
        let _ = h.api.expire_device_sessions().await.unwrap();
    }
    let after = h.get(Who::Admin, &format!("/v1/jobs/{job}")).await.json();
    assert_eq!(after["state"], "failed");
    assert_eq!(after["acknowledged"], false);
    assert_eq!(after["failure"], before["failure"]);
    assert_eq!(after["failed_at"], before["failed_at"]);
    assert_eq!(after["failure"]["step"], 1);
    assert_eq!(after["failure"]["category"], "integrity");
    assert_eq!(after["failure"]["count"], 1);
    assert_eq!(after["failure"]["files"][0]["role"], "image");
    assert!(after["attempts"].as_u64().unwrap() >= 1);
    assert!(h.events("job.lost").is_empty());
}

/// REQ-JOB-012: Lost goes back to Failed or to Succeeded when the device
/// reports again; each change is one audit record naming the job.
#[tokio::test]
async fn lost_job_reaches_failed_and_succeeded() {
    let h = Harness::m3().await;
    let rd = h.ready_device("lostfinal", &["02:00:00:00:0f:01"]).await;
    let a = confirm_job(&h, &rd.session.token, &rd.pkg, &rd.disk).await;
    let (s2, d2) = h.chosen_session(&rd.pkg, &["02:00:00:00:0f:02"]).await;
    let b = confirm_job(&h, &s2.token, &rd.pkg, &d2).await;
    h.clock.advance(Duration::from_secs(901));
    assert_eq!(h.api.mark_lost_jobs().await.unwrap(), 2);
    assert_eq!(job_state(&h, &a).await, JobState::Lost);
    // Lost -> Failed.
    let r = h.report(&rd.session.token, &a, failed(1)).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(job_state(&h, &a).await, JobState::Failed);
    // Lost -> Running -> Succeeded.
    let mut seq = 1;
    for step in 1..=4u8 {
        if step > 1 {
            assert_eq!(
                h.report(&s2.token, &b, ev(seq, step, "step_started"))
                    .await
                    .status,
                200
            );
            seq += 1;
        }
        assert_eq!(
            h.report(&s2.token, &b, ev(seq, step, "step_completed"))
                .await
                .status,
            200
        );
        seq += 1;
    }
    let r = h.report(&s2.token, &b, ev(seq, 5, "succeeded")).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(job_state(&h, &b).await, JobState::Succeeded);
    for (event, job) in [
        ("job.lost", &a),
        ("job.lost", &b),
        ("job.failed", &a),
        ("job.resumed", &b),
        ("job.succeeded", &b),
    ] {
        let n = h
            .events(event)
            .iter()
            .filter(|r| r.target_id.as_deref() == Some(job.as_str()))
            .count();
        assert_eq!(n, 1, "{event} for {job}");
    }
}

/// Decision 0018 item 10, REQ-TGT-016, REQ-JOB-012: every device choice
/// and every job state change of one session is an audit record with the
/// AU-3 fields, in order, one per change.
#[tokio::test]
async fn every_choice_and_state_change_has_au3_fields() {
    let h = Harness::m3().await;
    let rd = h.ready_device("au3", &["02:00:00:00:10:01"]).await;
    let sid = rd.session.id.clone();
    let job = confirm_job(&h, &rd.session.token, &rd.pkg, &rd.disk).await;
    let tok = rd.session.token.as_str();
    let mut seq = 1;
    for step in 1..=4u8 {
        if step > 1 {
            assert_eq!(
                h.report(tok, &job, ev(seq, step, "step_started"))
                    .await
                    .status,
                200
            );
            seq += 1;
        }
        assert_eq!(
            h.report(tok, &job, ev(seq, step, "step_completed"))
                .await
                .status,
            200
        );
        seq += 1;
    }
    assert_eq!(
        h.report(tok, &job, ev(seq, 5, "succeeded")).await.status,
        200
    );

    let mine = |event: &str| -> Vec<AuditRecord> {
        h.events(event)
            .into_iter()
            .filter(|r| r.actor_id.as_deref() == Some(sid.as_str()))
            .collect()
    };
    for (event, kind, id) in [
        ("device.session.opened", "device_session", sid.as_str()),
        ("device.session.authorised", "device_session", sid.as_str()),
        (
            "device.session.package_chosen",
            "device_session",
            sid.as_str(),
        ),
        ("device.session.disk_chosen", "device_session", sid.as_str()),
        ("disk.wipe.authorised", "job", job.as_str()),
        ("job.created", "job", job.as_str()),
        ("job.plan.issued", "job", job.as_str()),
        ("job.succeeded", "job", job.as_str()),
    ] {
        let recs = mine(event);
        assert_eq!(recs.len(), 1, "{event}: {recs:?}");
        assert_device_au3(&recs[0], &sid, kind, id);
    }
    // One record per step change: steps 2..4 started by report, 1..4
    // completed by report, and step 5 started and completed by the
    // success report (finding NIST-009).
    let started = mine("job.step.started");
    let completed = mine("job.step.completed");
    assert_eq!(started.len(), 4, "{started:?}");
    assert_eq!(completed.len(), 5, "{completed:?}");
    for r in [started.last().unwrap(), completed.last().unwrap()] {
        assert!(r.detail.contains("\"step\":\"5\""), "{}", r.detail);
        assert!(r.detail.contains("\"implied_by\":\"succeeded\""));
    }
    // The final record carries the step history and the claimed MACs.
    let done = &mine("job.succeeded")[0];
    for want in [
        "\"steps\":\"1:done:",
        ",5:done:",
        "\"macs\":\"02:00:00:00:10:01\"",
        "\"claimed\":\"macs\"",
    ] {
        assert!(done.detail.contains(want), "{want} in {}", done.detail);
    }
    for r in started.iter().chain(&completed) {
        assert_device_au3(r, &sid, "job", &job);
    }
    // The choices name what was chosen.
    assert!(
        mine("device.session.package_chosen")[0]
            .detail
            .contains(&rd.pkg)
    );
    let disk_rec = &mine("device.session.disk_chosen")[0];
    assert!(
        disk_rec.detail.contains("1000204886016"),
        "{}",
        disk_rec.detail
    );
    // Order: opened < authorised < package < disk < wipe < plan issued <
    // succeeded. `job.created` is written in the confirm transaction with
    // the wipe record (either order), so it is checked only against the
    // plan.
    let order: Vec<u64> = [
        "device.session.opened",
        "device.session.authorised",
        "device.session.package_chosen",
        "device.session.disk_chosen",
        "disk.wipe.authorised",
        "job.plan.issued",
        "job.succeeded",
    ]
    .iter()
    .map(|e| mine(e)[0].seq)
    .collect();
    assert!(order.windows(2).all(|w| w[0] < w[1]), "{order:?}");
    assert!(mine("job.created")[0].seq < mine("job.plan.issued")[0].seq);
    // The wipe record precedes every step record (decision 0018 item 7).
    let wipe = mine("disk.wipe.authorised")[0].seq;
    assert!(started.iter().chain(&completed).all(|r| r.seq > wipe));
    // A boot stop was added for the device's MAC, naming the job.
    let stops = mine("boot_stop.added");
    assert_eq!(stops.len(), 1, "{stops:?}");
    assert_eq!(stops[0].target_kind.as_deref(), Some("boot_stop"));
    assert!(stops[0].detail.contains(&job), "{}", stops[0].detail);
    assert!(
        stops[0].detail.contains("02:00:00:00:10:01"),
        "{}",
        stops[0].detail
    );
    // Decision 0023 item 2: the stop is marked as based on a claim.
    assert!(stops[0].detail.contains("\"claimed\":\"mac\""));
    assert!(stops[0].detail.contains("\"mac_basis\":\"agent_claim\""));
}

/// REQ-JOB-014, REQ-TGT-015: no session token or code value appears in
/// any operator view of sessions, codes or jobs, or in any record.
#[tokio::test]
async fn no_token_or_code_in_operator_views_or_records() {
    let h = Harness::m3().await;
    let rd = h.ready_device("views", &["02:00:00:00:11:01"]).await;
    let waiting = h.open_session(&["02:00:00:00:11:02"]).await;
    let (_, unused_code) = h.issue_code().await;
    let job = confirm_job(&h, &rd.session.token, &rd.pkg, &rd.disk).await;
    assert_eq!(
        h.report(&rd.session.token, &job, failed(1)).await.status,
        200
    );
    let secrets = [
        rd.session.token.as_str(),
        waiting.token.as_str(),
        unused_code.as_str(),
    ];
    let mut bodies = Vec::new();
    for path in [
        "/v1/device-sessions".to_owned(),
        "/v1/device-sessions?state=awaiting_authorisation".to_owned(),
        "/v1/auth-codes".to_owned(),
        "/v1/jobs".to_owned(),
        format!("/v1/jobs/{job}"),
    ] {
        let r = h.get(Who::Admin, &path).await;
        assert_eq!(r.status, 200, "{path}");
        bodies.push(String::from_utf8(r.body).unwrap());
    }
    bodies.push(h.all_record_text());
    for b in &bodies {
        for s in secrets {
            let plain: String = s.chars().filter(|c| *c != '-').collect();
            assert!(!b.contains(s), "secret in an operator view or record");
            assert!(!b.contains(&plain), "secret in an operator view or record");
        }
    }
}

/// REQ-JOB-003 (operator SHOULD), REQ-JOB-001: the operator view shows
/// the overall percentage of the download step and the job record fields.
#[tokio::test]
async fn job_view_shows_percentage_and_record_fields() {
    let h = Harness::m3().await;
    let rd = h.ready_device("percent", &["02:00:00:00:12:01"]).await;
    let job = confirm_job(&h, &rd.session.token, &rd.pkg, &rd.disk).await;
    let mut p = ev(1, 1, "progress");
    p["bytes_done"] = 10.into();
    p["bytes_total"] = 40.into();
    assert_eq!(h.report(&rd.session.token, &job, p).await.status, 200);
    let v = h.get(Who::Admin, &format!("/v1/jobs/{job}")).await.json();
    assert_eq!(v["percent"], 25, "{v}");
    assert_eq!(v["bytes_done"], 10, "{v}");
    assert_eq!(v["bytes_total"], 40, "{v}");
    assert_eq!(v["state"], "running");
    assert_eq!(v["current_step"], 1);
    assert_eq!(v["session_id"], rd.session.id.as_str());
    assert_eq!(v["boot_service_id"], rd.bs.to_string().as_str());
    assert_eq!(v["package_id"], rd.pkg.as_str());
    assert_eq!(v["macs"][0], "02:00:00:00:12:01");
    assert_eq!(v["disk"]["size_bytes"], 1_000_204_886_016u64);
    assert!(
        v["started_at"]
            .as_i64()
            .expect("started_at in microseconds")
            > 0,
        "{v}"
    );
    assert!(v.get("last_report_at").is_some(), "{v}");
}
