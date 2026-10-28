//! Job routes (M3 plan sections 3.3 and 3.4) and the operator's job view
//! (section 3.5): chunk fetch bound to the session's job and verified on
//! the server, progress order, success adding boot stops, failure final,
//! lost and resumed, acknowledgement.

use std::time::Duration;

use usgp_db::{RepoTx, Store};
use usgp_proto::{JobId, JobState};

use crate::common::{Harness, ReadyDevice, Who, nonce};

/// Confirms and returns the job id.
async fn start(h: &Harness, rd: &ReadyDevice) -> String {
    let r = h
        .confirm(&rd.session.token, &rd.pkg, &rd.disk, &nonce())
        .await;
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    r.json()["job_id"].as_str().unwrap().to_owned()
}

/// A second device on the same boot service and package (two boot
/// services serving the same subnet would be ambiguous: nothing offered).
async fn second(h: &Harness, rd: &ReadyDevice, macs: &[&str]) -> ReadyDevice {
    let (session, disk) = h.chosen_session(&rd.pkg, macs).await;
    ReadyDevice {
        relay: h.relay_cert("unused"),
        bs: rd.bs,
        pkg: rd.pkg.clone(),
        session,
        disk,
    }
}

fn ev(seq: u64, step: u8, event: &str) -> serde_json::Value {
    serde_json::json!({ "seq": seq, "step": step, "event": event })
}

/// Runs steps 1 to 4 to completion from `seq`; returns the next seq.
async fn run_to_step4(h: &Harness, token: &str, job: &str, from: u64) -> u64 {
    let mut seq = from;
    for step in 1..=4u8 {
        if step > 1 {
            let r = h.report(token, job, ev(seq, step, "step_started")).await;
            assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
            seq += 1;
        }
        let r = h.report(token, job, ev(seq, step, "step_completed")).await;
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        seq += 1;
    }
    seq
}

fn chunk_path(job: &str, sha: &str, n: u64) -> String {
    format!("/v1/device/jobs/{job}/content/{sha}/chunks/{n}")
}

/// The image's SHA-256 (from the plan's content manifest).
async fn image_sha(h: &Harness, job: &str) -> String {
    let mut tx = h.store.begin().await.unwrap();
    let j = tx.job(JobId::parse(job).unwrap()).await.unwrap().unwrap();
    let c = tx.content(j.image_content_id).await.unwrap().unwrap();
    tx.rollback().await;
    c.sha256.to_hex()
}

/// Chunk 0 is the verified content; beyond the end, another content or
/// another session's token get 404; one read record per pass.
#[tokio::test]
async fn chunk_fetch_bound_and_verified() {
    let h = Harness::m3().await;
    let rd = h.ready_device("chunks", &["02:00:00:00:01:01"]).await;
    let job = start(&h, &rd).await;
    let sha = image_sha(&h, &job).await;
    let tok = rd.session.token.as_str();
    let r = h
        .dev("GET", &chunk_path(&job, &sha, 0), Some(tok), None)
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.body, b"FAKEWIM:3:image chunks");
    assert_eq!(
        r.header("content-type").as_deref(),
        Some("application/octet-stream")
    );
    let r = h
        .dev("GET", &chunk_path(&job, &sha, 0), Some(tok), None)
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(h.events("job.content.read").len(), 1, "one record per pass");
    assert_eq!(
        h.dev("GET", &chunk_path(&job, &sha, 1), Some(tok), None)
            .await
            .status,
        404
    );
    let other = "ab".repeat(32);
    assert_eq!(
        h.dev("GET", &chunk_path(&job, &other, 0), Some(tok), None)
            .await
            .status,
        404
    );
    // Another confirmed session cannot read this job.
    let rd2 = second(&h, &rd, &["02:00:00:00:01:02"]).await;
    let _job2 = start(&h, &rd2).await;
    let r = h
        .dev(
            "GET",
            &chunk_path(&job, &sha, 0),
            Some(&rd2.session.token),
            None,
        )
        .await;
    assert_eq!(r.status, 404);
    // An authorised but unconfirmed session cannot read content at all.
    let s = h.open_session(&["02:00:00:00:01:03"]).await;
    let r = h
        .dev("GET", &chunk_path(&job, &sha, 0), Some(&s.token), None)
        .await;
    assert_eq!(r.status, 403);
    // The apply pass (step 3) gets its own record.
    for (seq, (step, event)) in (1u64..).zip([
        (1, "step_completed"),
        (2, "step_started"),
        (2, "step_completed"),
        (3, "step_started"),
    ]) {
        assert_eq!(h.report(tok, &job, ev(seq, step, event)).await.status, 200);
    }
    assert_eq!(
        h.dev("GET", &chunk_path(&job, &sha, 0), Some(tok), None)
            .await
            .status,
        200
    );
    assert_eq!(h.events("job.content.read").len(), 2);
}

/// A chunk changed on the server's disk is not sent: 500
/// `integrity_failed`, the content becomes Failed.
#[tokio::test]
async fn tampered_chunk_not_served() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::m3().await;
    let rd = h.ready_device("tamper", &["02:00:00:00:01:04"]).await;
    let job = start(&h, &rd).await;
    let sha = image_sha(&h, &job).await;
    let path = h
        .api
        .files()
        .object_path(&usgp_common::Sha256Digest::from_hex(&sha).unwrap());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[0] ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    let r = h
        .dev(
            "GET",
            &chunk_path(&job, &sha, 0),
            Some(&rd.session.token),
            None,
        )
        .await;
    assert_eq!(r.status, 500);
    assert_eq!(r.code(), "integrity_failed");
    assert_ne!(r.body, bytes);
    assert_eq!(h.events("content.integrity.failed").len(), 1);
    let rec = &h.events("content.integrity.failed")[0];
    assert_eq!(rec.actor_kind, "device_session");
    assert_eq!(rec.actor_id.as_deref(), Some(rd.session.id.as_str()));
}

/// Steps advance only in order; success needs step 4; a stale seq is
/// ignored; success adds the boot stops and bumps the generation.
#[tokio::test]
async fn progress_order_and_success() {
    let h = Harness::m3().await;
    let macs = ["02:00:00:00:01:05", "02:00:00:00:01:06"];
    let rd = h.ready_device("progress", &macs).await;
    let job = start(&h, &rd).await;
    let tok = rd.session.token.as_str();
    // Out of order: step 3 before step 2.
    let r = h.report(tok, &job, ev(1, 3, "step_started")).await;
    assert_eq!(r.status, 409);
    assert_eq!(r.code(), "progress_out_of_order");
    // Success before step 4.
    let r = h.report(tok, &job, ev(1, 1, "succeeded")).await;
    assert_eq!(r.status, 409);
    assert_eq!(h.events("job.progress.refused").len(), 2);
    // Byte progress on the running step.
    let mut p = ev(1, 1, "progress");
    p["bytes_done"] = 10.into();
    p["bytes_total"] = 22.into();
    let r = h.report(tok, &job, p).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["ack_seq"], 1);
    // Too soon: dropped, the ack stays.
    let r = h.report(tok, &job, ev(2, 1, "progress")).await;
    assert_eq!(r.json()["ack_seq"], 1);
    let seq = run_to_step4(&h, tok, &job, 2).await;
    // Stale seq: ignored, current ack.
    let r = h.report(tok, &job, ev(1, 4, "succeeded")).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["job_state"], "running");
    let r = h.report(tok, &job, ev(seq, 5, "succeeded")).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["job_state"], "succeeded");
    for e in ["job.step.started", "job.step.completed", "job.succeeded"] {
        assert!(!h.events(e).is_empty(), "{e}");
    }
    assert_eq!(h.events("boot_stop.added").len(), 2);
    let mut tx = h.store.begin().await.unwrap();
    let stops = tx.list_boot_stops(Some(rd.bs), true).await.unwrap();
    let generation = tx.boot_policy_generation(rd.bs).await.unwrap();
    tx.rollback().await;
    assert_eq!(stops.len(), 2);
    assert!(generation >= 1);
    // The operator sees it; reports after the end are refused; chunks too.
    let r = h.get(Who::Admin, &format!("/v1/jobs/{job}")).await;
    assert_eq!(r.status, 200);
    let v = r.json();
    assert_eq!(v["state"], "succeeded");
    assert_eq!(v["steps"].as_array().unwrap().len(), 5);
    assert!(
        v["steps"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["state"] == "done")
    );
    let r = h.report(tok, &job, ev(seq + 1, 5, "progress")).await;
    assert_eq!(r.status, 409);
    assert_eq!(r.code(), "job_not_running");
    let r = h.get(Who::Admin, "/v1/jobs?state=succeeded").await;
    assert_eq!(r.json()["jobs"].as_array().unwrap().len(), 1);
    assert_eq!(h.get(Who::Admin, "/v1/jobs?state=bogus").await.status, 400);
}

/// A failure is final, shown to the operator, and can be acknowledged
/// once; content is then refused.
#[tokio::test]
async fn failure_final_and_acknowledged() {
    let h = Harness::m3().await;
    let rd = h.ready_device("failure", &["02:00:00:00:01:07"]).await;
    let job = start(&h, &rd).await;
    let sha = image_sha(&h, &job).await;
    let tok = rd.session.token.as_str();
    let mut f = ev(1, 1, "failed");
    f["failure"] = serde_json::json!({
        "step": 1, "category": "integrity", "code": "chunk_digest_mismatch",
        "files": [{"role": "image", "name": "install.wim"}], "count": 1, "attempts": 1
    });
    let r = h.report(tok, &job, f).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["job_state"], "failed");
    let rec = &h.events("job.failed")[0];
    assert_eq!(rec.reason.as_deref(), Some("chunk_digest_mismatch"));
    let r = h
        .dev("GET", &chunk_path(&job, &sha, 0), Some(tok), None)
        .await;
    assert_eq!(r.status, 409);
    assert_eq!(r.code(), "job_not_running");
    let r = h.get(Who::Admin, &format!("/v1/jobs/{job}")).await;
    assert_eq!(r.json()["failure"]["code"], "chunk_digest_mismatch");
    assert_eq!(r.json()["acknowledged"], false);
    let path = format!("/v1/jobs/{job}/acknowledge");
    let r = h.req(Who::Admin, "POST", &path, &[], None).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["acknowledged"], true);
    assert_eq!(r.json()["state"], "failed");
    let r = h.req(Who::Admin, "POST", &path, &[], None).await;
    assert_eq!(r.status, 409);
    assert_eq!(h.events("job.failure.acknowledged").len(), 1);
    // No boot stop for a failed job.
    assert!(h.events("boot_stop.added").is_empty());
}

/// A silent job becomes lost (sweep); its next report resumes it.
#[tokio::test]
async fn lost_and_resumed() {
    let h = Harness::m3().await;
    let rd = h.ready_device("lost", &["02:00:00:00:01:08"]).await;
    let job = start(&h, &rd).await;
    h.clock.advance(Duration::from_secs(901));
    assert_eq!(h.api.mark_lost_jobs().await.unwrap(), 1);
    assert_eq!(h.events("job.lost").len(), 1);
    let mut tx = h.store.begin().await.unwrap();
    let st = tx
        .job(JobId::parse(&job).unwrap())
        .await
        .unwrap()
        .unwrap()
        .state;
    tx.rollback().await;
    assert_eq!(st, JobState::Lost);
    let r = h
        .report(&rd.session.token, &job, ev(1, 1, "step_completed"))
        .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["job_state"], "running");
    assert_eq!(h.events("job.resumed").len(), 1);
}

/// A report for a job of another session is 404 and audited.
#[tokio::test]
async fn progress_from_wrong_session() {
    let h = Harness::m3().await;
    let rd = h.ready_device("wrongsess", &["02:00:00:00:01:09"]).await;
    let job = start(&h, &rd).await;
    let rd2 = second(&h, &rd, &["02:00:00:00:01:0a"]).await;
    let _ = start(&h, &rd2).await;
    let r = h
        .report(&rd2.session.token, &job, ev(1, 1, "step_completed"))
        .await;
    assert_eq!(r.status, 404);
    assert_eq!(h.events("job.progress.refused").len(), 1);
}
