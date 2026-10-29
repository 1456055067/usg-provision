//! M3 review fix round 2, group A: findings SEC-001 (connection
//! admission), SEC-011 (open order and per-boot-service ceiling), SEC-012
//! (server-side timeouts, operator fail route, overdue jobs release their
//! MACs) and SEC-013.1 (race-free MAC claims). Each fails without its fix.

use std::time::Duration;

use usgp_db::{RepoTx, Store};
use usgp_proto::ops::BootServiceStatus;
use usgp_proto::{BootServiceId, JobId, JobState};

use crate::common::{Harness, Opts, ReadyDevice, Who, hello, nonce};

fn ev(seq: u64, step: u8, event: &str) -> serde_json::Value {
    serde_json::json!({ "seq": seq, "step": step, "event": event })
}

fn opts(f: impl FnOnce(&mut usgp_api::ApiConfig) + Send + 'static) -> Opts {
    Opts {
        config: Box::new(move |c| {
            c.unauth_records_per_source_per_min = 10_000;
            c.unauth_records_global_per_min = 100_000;
            c.device.max_pending_sessions_per_ip = 64;
            c.device.session_opens_per_ip_per_min = 1000;
            c.device.code_attempts_per_ip_per_min = 1000;
            f(c);
        }),
        ..Opts::default()
    }
}

async fn start(h: &Harness, rd: &ReadyDevice) -> String {
    let r = h
        .confirm(&rd.session.token, &rd.pkg, &rd.disk, &nonce())
        .await;
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    r.json()["job_id"].as_str().unwrap().to_owned()
}

async fn job_state(h: &Harness, job: &str) -> usgp_db::Job {
    let mut tx = h.store.begin().await.unwrap();
    let j = tx.job(JobId::parse(job).unwrap()).await.unwrap().unwrap();
    tx.rollback().await;
    j
}

/// Sets a boot service's status in the store only (the device listener's
/// cached table is not reloaded).
async fn set_status(h: &Harness, bs: BootServiceId, st: BootServiceStatus) {
    let mut tx = h.store.begin().await.unwrap();
    tx.set_boot_service_status(bs, st).await.unwrap();
    let d = usgp_audit::AuditDraft::new(
        "boot_service.disabled",
        usgp_audit::Outcome::Success,
        usgp_audit::Actor::local_user(0, None),
        usgp_audit::Interface::ServerCli,
    );
    h.api.chain().append(&mut tx, &d).await.unwrap();
    tx.commit().await.unwrap();
}

/// SEC-001: connections are capped per boot service; a closed one frees
/// its slot.
#[tokio::test]
async fn sec001_connections_capped_per_boot_service() {
    let h = Harness::with(opts(|c| c.device.max_connections_per_boot_service = 2)).await;
    h.loopback_service("conncap").await;
    let a = h.connect_to(h.device_addr, None).await.expect("first");
    let b = h.connect_to(h.device_addr, None).await.expect("second");
    assert!(h.connect_to(h.device_addr, None).await.is_err(), "third");
    drop(a);
    let mut ok = false;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        if h.connect_to(h.device_addr, None).await.is_ok() {
            ok = true;
            break;
        }
    }
    assert!(ok, "a closed connection frees its slot");
    drop(b);
}

/// SEC-001: a boot service enrolled after start is picked up (the
/// harness reloads the table as the server's refresh does); a disabled
/// one stops admitting once the table is reloaded.
#[tokio::test]
async fn sec001_table_follows_enrolment_and_disabling() {
    let h = Harness::m3().await;
    assert!(h.connect_to(h.device_addr, None).await.is_err());
    let bs = h.loopback_service("follows").await;
    assert!(h.connect_to(h.device_addr, None).await.is_ok());
    set_status(&h, bs, BootServiceStatus::Disabled).await;
    h.api.refresh_device_boot_services().await.unwrap();
    assert!(h.connect_to(h.device_addr, None).await.is_err());
}

/// SEC-011: a source no boot service serves is refused before any
/// limiter counts it (here: the cached table still admits the connection
/// while the store says the service is disabled), and opens are capped
/// per boot service.
#[tokio::test]
async fn sec011_refused_before_limiters_and_capped_per_service() {
    let h = Harness::with(opts(|c| {
        c.device.session_opens_per_ip_per_min = 2;
        c.device.session_opens_per_boot_service_per_min = 2;
        c.device.session_opens_per_min = 2;
    }))
    .await;
    let bs = h.loopback_service("order").await;
    // The listener has loaded its table (it accepts only after that).
    assert!(h.connect_to(h.device_addr, None).await.is_ok());
    set_status(&h, bs, BootServiceStatus::Disabled).await;
    for i in 0..5u8 {
        let r = h
            .dev(
                "POST",
                "/v1/device/sessions",
                None,
                Some(hello(&[&format!("02:00:00:00:b1:0{i}")])),
            )
            .await;
        assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
    }
    set_status(&h, bs, BootServiceStatus::Active).await;
    // Nothing was counted: two opens fit, the third is over the ceilings.
    h.open_session(&["02:00:00:00:b1:10"]).await;
    h.open_session(&["02:00:00:00:b1:11"]).await;
    let r = h
        .dev(
            "POST",
            "/v1/device/sessions",
            None,
            Some(hello(&["02:00:00:00:b1:12"])),
        )
        .await;
    assert_eq!(r.status, 429);
}

/// SEC-011: the per-boot-service opens ceiling is its own limit.
#[tokio::test]
async fn sec011_opens_ceiling_per_boot_service() {
    let h = Harness::with(opts(|c| {
        c.device.session_opens_per_boot_service_per_min = 1;
    }))
    .await;
    let bs = h.loopback_service("perservice").await;
    h.open_session(&["02:00:00:00:b2:01"]).await;
    let r = h
        .dev(
            "POST",
            "/v1/device/sessions",
            None,
            Some(hello(&["02:00:00:00:b2:02"])),
        )
        .await;
    assert_eq!(r.status, 429);
    let rec = h.events("device.session.open_refused").pop().unwrap();
    assert!(
        rec.detail
            .contains("\"limit\":\"session_opens_per_boot_service_per_min\""),
        "{}",
        rec.detail
    );
    assert!(rec.detail.contains(&bs.to_string()));
}

/// SEC-012: a running job past its stall timeout is failed by the server
/// (category `timeout`, audited with the server as actor); until then,
/// and while overdue, another device may claim its MACs.
#[tokio::test]
async fn sec012_stall_timeout_fails_job_and_frees_macs() {
    let h = Harness::m3().await;
    let mac = "02:00:00:00:b3:01";
    let rd = h.ready_device("stall", &[mac]).await;
    let job = start(&h, &rd).await;
    assert_eq!(h.api.fail_overdue_jobs().await.unwrap(), 0);
    // Stall timeout 1800 s (no report since the start); the lost sweep is
    // not run here, so the job is still running.
    h.clock.advance(Duration::from_secs(1801));
    // Overdue but not yet swept: it no longer holds its MAC.
    let (s2, d2) = h.chosen_session(&rd.pkg, &[mac]).await;
    let r = h.confirm(&s2.token, &rd.pkg, &d2, &nonce()).await;
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(h.api.fail_overdue_jobs().await.unwrap(), 1);
    let j = job_state(&h, &job).await;
    assert_eq!(j.state, JobState::Failed);
    let f = j.failure.unwrap();
    assert_eq!(f.category.as_str(), "timeout");
    assert_eq!(f.code.as_str(), "stall_timeout");
    let rec = h
        .events("job.failed")
        .into_iter()
        .find(|r| r.target_id.as_deref() == Some(job.as_str()))
        .unwrap();
    assert_eq!(rec.actor_kind, "system");
    assert_eq!(rec.reason.as_deref(), Some("stall_timeout"));
    assert!(rec.detail.contains("\"failed_by\":\"server\""));
    assert!(rec.detail.contains("\"timeout_s\":\"1800\""));
    // The device's next report is refused: the job is final.
    let r = h
        .report(&rd.session.token, &job, ev(1, 1, "step_completed"))
        .await;
    assert_eq!(r.status, 409);
}

/// SEC-012: the step timeout from the signed plan, measured from the
/// step's start, while the device keeps reporting.
#[tokio::test]
async fn sec012_step_timeout_from_the_plan() {
    let h = Harness::with(opts(|c| c.device.jobs.timeout_verify_s = 600)).await;
    let rd = h.ready_device("steptimeout", &["02:00:00:00:b4:01"]).await;
    let job = start(&h, &rd).await;
    for seq in 1..=2u64 {
        h.clock.advance(Duration::from_secs(250));
        let r = h
            .report(
                &rd.session.token,
                &job,
                serde_json::json!({"seq": seq, "step": 1, "event": "progress",
                    "bytes_done": seq, "bytes_total": 100}),
            )
            .await;
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    }
    assert_eq!(h.api.fail_overdue_jobs().await.unwrap(), 0);
    h.clock.advance(Duration::from_secs(101));
    assert_eq!(h.api.fail_overdue_jobs().await.unwrap(), 1);
    let j = job_state(&h, &job).await;
    assert_eq!(j.failure.unwrap().code.as_str(), "step_timeout");
    // The maintenance pass runs the sweep too (nothing left to fail).
    assert!(h.api.maintenance().await.failed.is_empty());
}

/// SEC-012: an operator with `job.fail` fails a running job; it is
/// audited with the operator and the reason, frees the job's MACs, and
/// cannot be repeated.
#[tokio::test]
async fn sec012_operator_fails_a_running_job() {
    let h = Harness::m3().await;
    let mac = "02:00:00:00:b5:01";
    let rd = h.ready_device("opfail", &[mac]).await;
    let job = start(&h, &rd).await;
    let path = format!("/v1/jobs/{job}/fail");
    for bad in [
        serde_json::json!({}),
        serde_json::json!({ "reason": "" }),
        serde_json::json!({ "reason": "x".repeat(201) }),
        serde_json::json!({ "reason": "ok", "force": true }),
    ] {
        let r = h.post_json(Who::Admin, &path, bad).await;
        assert_eq!(r.status, 422, "{}", String::from_utf8_lossy(&r.body));
    }
    assert_eq!(job_state(&h, &job).await.state, JobState::Running);
    let r = h
        .post_json(
            Who::Admin,
            &path,
            serde_json::json!({ "reason": "device replaced on the bench" }),
        )
        .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["state"], "failed");
    let j = job_state(&h, &job).await;
    assert_eq!(j.failure.unwrap().code.as_str(), "operator_failed");
    let rec = h.events("job.failed").pop().unwrap();
    assert_eq!(rec.actor_kind, "operator");
    assert_eq!(rec.reason.as_deref(), Some("operator_failed"));
    assert!(rec.detail.contains("device replaced on the bench"));
    // Final: a second fail is refused (audited).
    let r = h
        .post_json(Who::Admin, &path, serde_json::json!({ "reason": "again" }))
        .await;
    assert_eq!(r.status, 409);
    assert_eq!(h.events("job.fail_refused").len(), 5);
    // The MAC is free for another device.
    let (s2, d2) = h.chosen_session(&rd.pkg, &[mac]).await;
    let r = h.confirm(&s2.token, &rd.pkg, &d2, &nonce()).await;
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
}

/// SEC-013.1: two confirmations claiming one MAC at the same time: one
/// job, one 409 `in_use`. (The memory store serialises transactions; the
/// PostgreSQL claim lock is tested in usgp-db `m3_claim_lock_serialises`.)
#[tokio::test]
async fn sec013_concurrent_confirms_one_job() {
    let h = Harness::m3().await;
    let mac = "02:00:00:00:b6:01";
    let rd = h.ready_device("race", &[mac]).await;
    let (s2, d2) = h.chosen_session(&rd.pkg, &[mac]).await;
    let (n1, n2) = (nonce(), nonce());
    let (a, b) = tokio::join!(
        h.confirm(&rd.session.token, &rd.pkg, &rd.disk, &n1),
        h.confirm(&s2.token, &rd.pkg, &d2, &n2),
    );
    let mut st = [a.status, b.status];
    st.sort_unstable();
    assert_eq!(st, [201, 409]);
    let mut tx = h.store.begin().await.unwrap();
    assert_eq!(tx.list_jobs(&[JobState::Running]).await.unwrap().len(), 1);
    tx.rollback().await;
}

/// Boot-smoke S9 (CI run 40876728637): the boot-service read sends an
/// `ETag` a client can echo (at most `MAX_IF_MATCH_BYTES` of visible
/// ASCII, the rule `usgp-cli` applies), and `If-Match` with it sets the
/// packages; the response carries the new tag, usable again.
#[tokio::test]
async fn s9_boot_service_etag_round_trips() {
    let h = Harness::m3().await;
    let bs = h.loopback_service("s9").await;
    let (pkg, _, _) = h.ready_package("s9").await;
    let r = h.get(Who::Admin, &format!("/v1/boot-services/{bs}")).await;
    assert_eq!(r.status, 200);
    let tag = r.header("etag").expect("ETag on the boot-service read");
    let fits = |t: &str| {
        !t.is_empty()
            && t.len() <= usgp_proto::api::MAX_IF_MATCH_BYTES
            && t.bytes().all(|b| b.is_ascii_graphic())
    };
    assert!(fits(&tag), "{tag} ({} bytes)", tag.len());
    let put = |tag: String, ids: Vec<String>| {
        let h = &h;
        async move {
            h.req(
                Who::Admin,
                "PUT",
                &format!("/v1/boot-services/{bs}/packages"),
                &[("if-match", &tag)],
                Some(serde_json::to_vec(&serde_json::json!({ "package_ids": ids })).unwrap()),
            )
            .await
        }
    };
    let r = put(tag.clone(), vec![pkg.clone()]).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let next = r.header("etag").expect("ETag on the set-packages answer");
    assert!(fits(&next));
    assert_ne!(next, tag);
    // The old tag is now stale (412); the new one works.
    assert_eq!(put(tag, vec![]).await.status, 412);
    assert_eq!(put(next, vec![]).await.status, 200);
}

/// M3 review (content ETag): the image read sends the content tag naming
/// the full signed digest, which fits `MAX_IF_MATCH_BYTES`; `If-Match`
/// with it deletes the image; a stale or over-long tag gets 412.
#[tokio::test]
async fn content_etag_fits_and_deletes() {
    let h = Harness::m3().await;
    let image = h.ready_image(1, "etag").await;
    let r = h.get(Who::Admin, &format!("/v1/images/{image}")).await;
    assert_eq!(r.status, 200);
    let tag = r.header("etag").expect("ETag on the image read");
    let sha = r.json()["sha256"].as_str().unwrap().to_owned();
    assert_eq!(tag, format!("\"sha256:{sha}\""), "names the full digest");
    assert_eq!(tag.len(), 73);
    assert!(tag.len() <= usgp_proto::api::MAX_IF_MATCH_BYTES);
    assert!(tag.bytes().all(|b| b.is_ascii_graphic()));
    let path = format!("/v1/images/{image}");
    let long = format!("\"{}\"", "a".repeat(usgp_proto::api::MAX_IF_MATCH_BYTES));
    for bad in [format!("\"sha256:{}\"", "0".repeat(64)), long] {
        let r = h
            .req(Who::Admin, "DELETE", &path, &[("if-match", &bad)], None)
            .await;
        assert_eq!(r.status, 412, "{bad}");
    }
    let r = h
        .req(Who::Admin, "DELETE", &path, &[("if-match", &tag)], None)
        .await;
    assert!(
        (200..300).contains(&r.status),
        "{}",
        String::from_utf8_lossy(&r.body)
    );
}
