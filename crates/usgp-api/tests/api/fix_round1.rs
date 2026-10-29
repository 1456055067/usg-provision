//! M3 review fix round 1, group A: one test per finding fixed in
//! `usgp-api` (findings SEC-001, SEC-002, SEC-006, NIST-006, NIST-008,
//! NIST-009, NIST-012, NIST-016, BOOT-005; decision 0023 items 1 and 2).
//! Each fails without its fix.

use std::time::Duration;

use usgp_db::{NewDeviceSession, RepoTx, Store};
use usgp_proto::device::{DeviceArch, FirmwareKind, SecureBootState, SessionState};
use usgp_proto::{
    AgentVersion, DisplayCode, MacAddress, MacList, SessionId, SessionToken, UnixMicros,
};

use crate::common::{Harness, Opts, ReadyDevice, Who, hello, nonce, rand16};

fn ev(seq: u64, step: u8, event: &str) -> serde_json::Value {
    serde_json::json!({ "seq": seq, "step": step, "event": event })
}

/// Confirms and returns the job id.
async fn start(h: &Harness, rd: &ReadyDevice) -> String {
    let r = h
        .confirm(&rd.session.token, &rd.pkg, &rd.disk, &nonce())
        .await;
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    r.json()["job_id"].as_str().unwrap().to_owned()
}

/// Runs steps 1 to 4 and reports success.
async fn succeed(h: &Harness, token: &str, job: &str) {
    let mut seq = 1;
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
    let r = h.report(token, job, ev(seq, 5, "succeeded")).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
}

fn harness_with(f: impl FnOnce(&mut usgp_api::ApiConfig) + Send + 'static) -> Opts {
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

/// SEC-001 / NIST-012: pending sessions are capped per boot service.
#[tokio::test]
async fn sec001_pending_capped_per_boot_service() {
    let h = Harness::with(harness_with(|c| {
        c.device.max_pending_sessions_per_boot_service = 2;
    }))
    .await;
    let bs = h.loopback_service("perbs").await;
    h.open_session(&["02:00:00:00:a1:01"]).await;
    h.open_session(&["02:00:00:00:a1:02"]).await;
    let r = h
        .dev(
            "POST",
            "/v1/device/sessions",
            None,
            Some(hello(&["02:00:00:00:a1:03"])),
        )
        .await;
    assert_eq!(r.status, 429, "{}", String::from_utf8_lossy(&r.body));
    let rec = h.events("device.session.open_refused").pop().unwrap();
    assert_eq!(rec.reason.as_deref(), Some("capacity"));
    assert!(rec.detail.contains("\"pending_on_boot_service\":\"2\""));
    assert!(rec.detail.contains(&bs.to_string()));
}

/// SEC-001: a global ceiling on opens per minute, whatever the source.
#[tokio::test]
async fn sec001_global_open_ceiling() {
    let h = Harness::with(harness_with(|c| {
        c.device.session_opens_per_min = 2;
    }))
    .await;
    h.loopback_service("global").await;
    h.open_session(&["02:00:00:00:a2:01"]).await;
    h.open_session(&["02:00:00:00:a2:02"]).await;
    let r = h
        .dev(
            "POST",
            "/v1/device/sessions",
            None,
            Some(hello(&["02:00:00:00:a2:03"])),
        )
        .await;
    assert_eq!(r.status, 429);
    let rec = h.events("device.session.open_refused").pop().unwrap();
    assert!(
        rec.detail.contains("session_opens_per_min"),
        "{}",
        rec.detail
    );
}

/// SEC-001: a session never authorised and not heard from for the idle
/// timeout expires long before its TTL (on its next request, and by the
/// sweep); an authorised one does not.
#[tokio::test]
async fn sec001_idle_unauthorised_sessions_expire() {
    let h = Harness::m3().await;
    let rd = h.ready_device("idle", &["02:00:00:00:a3:01"]).await;
    let a = h.open_session(&["02:00:00:00:a3:02"]).await;
    let b = h.open_session(&["02:00:00:00:a3:03"]).await;
    // The default idle timeout is 120 s; the TTL is 3600 s.
    h.clock.advance(Duration::from_secs(121));
    let (_, code) = h.issue_code().await;
    let r = h.submit_code(&a.token, &code).await;
    assert_eq!(r.status, 403);
    assert_eq!(r.code(), "session_ended");
    let rec = h.events("device.session.expired").pop().unwrap();
    assert!(rec.detail.contains("\"cause\":\"idle_unauthorised\""));
    assert_eq!(h.api.expire_device_sessions().await.unwrap(), 1);
    let mut tx = h.store.begin().await.unwrap();
    let st = |s: &crate::common::Opened| SessionId::parse(&s.id).unwrap();
    let sb = tx.device_session(st(&b)).await.unwrap().unwrap().state;
    let sr = tx
        .device_session(st(&rd.session))
        .await
        .unwrap()
        .unwrap()
        .state;
    tx.rollback().await;
    assert_eq!(sb, SessionState::Expired);
    // The authorised session (no poll for 121 s) is still live.
    assert_eq!(sr, SessionState::Authorised);
}

/// NIST-008 / decision 0023 item 1: a token sent from another source
/// network is refused 401 and audited; the session is untouched.
#[tokio::test]
async fn nist008_token_bound_to_source_network() {
    let h = Harness::m3().await;
    let bs = h.loopback_service("bound").await;
    let mut bytes = [0u8; 32];
    usgp_crypto::fill_random(&mut bytes).unwrap();
    let token = SessionToken::from_random_bytes(&bytes);
    let now = UnixMicros::new(h.api.chain().now_us().unwrap()).unwrap();
    // A session opened from 10.20.1.2 (written directly: the test client
    // always connects from 127.0.0.1).
    let id = SessionId::from_random_bytes(rand16());
    let s = NewDeviceSession {
        id,
        token_sha256: usgp_crypto::sha256(token.expose().as_bytes()),
        boot_service_id: Some(bs),
        source_ip: "10.20.1.2".parse().unwrap(),
        macs: MacList::new(vec![MacAddress::parse("02:00:00:00:a4:01").unwrap()]).unwrap(),
        firmware: FirmwareKind::Uefi,
        arch: DeviceArch::X64,
        secure_boot: SecureBootState::On,
        memory_bytes: 8 << 30,
        agent_version: AgentVersion::new("0.3.0").unwrap(),
        display_code: DisplayCode::from_random_bytes([7, 7, 7, 7]),
        created_at: now,
        expires_at: UnixMicros::new(now.as_micros() + 3_600_000_000).unwrap(),
    };
    let mut tx = h.store.begin().await.unwrap();
    tx.insert_device_session(&s).await.unwrap();
    let d = usgp_audit::AuditDraft::new(
        "device.session.opened",
        usgp_audit::Outcome::Success,
        usgp_audit::Actor::local_user(0, None),
        usgp_audit::Interface::ServerCli,
    );
    h.api.chain().append(&mut tx, &d).await.unwrap();
    tx.commit().await.unwrap();
    let r = h
        .dev("GET", "/v1/device/session", Some(token.expose()), None)
        .await;
    assert_eq!(r.status, 401, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.code(), "invalid_token");
    let rec = h.events("auth.unauthenticated").pop().unwrap();
    assert_eq!(rec.reason.as_deref(), Some("token_source_mismatch"));
    assert_eq!(rec.target_id.as_deref(), Some(id.to_string().as_str()));
    assert!(rec.detail.contains("\"session_source_ip\":\"10.20.1.2\""));
    assert!(!h.all_record_text().contains(token.expose()));
    // A token used from its own network still works.
    let own = h.open_session(&["02:00:00:00:a4:02"]).await;
    let r = h
        .dev("GET", "/v1/device/session", Some(&own.token), None)
        .await;
    assert_eq!(r.status, 200);
}

/// NIST-008 / decision 0023 item 1: a confirmed session lapses with its
/// job's lost-job timeout. A lost job is resumable for one more
/// `lost_after`; after that, and `lost_after` after a job finished, the
/// token is refused 403 on every route (audited).
#[tokio::test]
async fn nist008_confirmed_session_lapses_with_job() {
    let h = Harness::m3().await;
    let rd = h.ready_device("lapse", &["02:00:00:00:a5:01"]).await;
    let job = start(&h, &rd).await;
    // Lost after 900 s silent; resumable until 1800 s.
    h.clock.advance(Duration::from_secs(1801));
    assert_eq!(h.api.mark_lost_jobs().await.unwrap(), 1);
    let r = h
        .report(&rd.session.token, &job, ev(1, 1, "step_completed"))
        .await;
    assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.code(), "session_ended");
    let r = h
        .dev("GET", "/v1/device/session", Some(&rd.session.token), None)
        .await;
    assert_eq!(r.status, 403);
    let rec = h.events("job.progress.refused").pop().unwrap();
    assert!(rec.detail.contains("session_lapsed"), "{}", rec.detail);
    assert!(h.events("job.resumed").is_empty());

    // A finished job: the token reads its status for `lost_after`, then
    // nothing.
    let rd2 = {
        let (session, disk) = h.chosen_session(&rd.pkg, &["02:00:00:00:a5:02"]).await;
        ReadyDevice {
            relay: h.relay_cert("unused"),
            bs: rd.bs,
            pkg: rd.pkg.clone(),
            session,
            disk,
        }
    };
    let job2 = start(&h, &rd2).await;
    succeed(&h, &rd2.session.token, &job2).await;
    let status = |t: String| {
        let h = &h;
        async move { h.dev("GET", "/v1/device/session", Some(&t), None).await }
    };
    assert_eq!(status(rd2.session.token.clone()).await.status, 200);
    h.clock.advance(Duration::from_secs(901));
    assert_eq!(status(rd2.session.token.clone()).await.status, 403);
}

/// SEC-002 / decision 0023 item 2: a claimed MAC that already has a live
/// stop, or a running job under another session, is refused at
/// confirmation (409 `in_use`, audited); clearing the stop lifts it.
#[tokio::test]
async fn sec002_claimed_mac_in_use_refused_at_confirm() {
    let h = Harness::m3().await;
    let mac = "02:00:00:00:a6:01";
    let rd = h.ready_device("claims", &[mac]).await;
    let job = start(&h, &rd).await;
    // Another session claiming the same MAC while the job runs.
    let (s2, d2) = h.chosen_session(&rd.pkg, &[mac, "02:00:00:00:a6:02"]).await;
    let r = h.confirm(&s2.token, &rd.pkg, &d2, &nonce()).await;
    assert_eq!(r.status, 409, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.code(), "in_use");
    let rec = h.events("device.session.confirm_refused").pop().unwrap();
    assert!(rec.detail.contains(&job), "{}", rec.detail);
    assert!(h.events("disk.wipe.authorised").len() == 1);
    // The job succeeds: its MAC is now stopped.
    succeed(&h, &rd.session.token, &job).await;
    let r = h.confirm(&s2.token, &rd.pkg, &d2, &nonce()).await;
    assert_eq!(r.status, 409);
    let rec = h.events("device.session.confirm_refused").pop().unwrap();
    assert!(rec.detail.contains(&format!("\"stopped_macs\":\"{mac}\"")));
    // The operator clears the stop: the confirmation goes ahead.
    let r = h.get(Who::Admin, "/v1/boot-stops").await;
    let stop = r.json()["stops"][0]["id"].as_str().unwrap().to_owned();
    let r = h
        .req(
            Who::Admin,
            "POST",
            &format!("/v1/boot-stops/{stop}/clear"),
            &[],
            None,
        )
        .await;
    assert_eq!(r.status, 200);
    let r = h.confirm(&s2.token, &rd.pkg, &d2, &nonce()).await;
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
}

/// SEC-002 / BOOT-005 / decision 0023 item 2: on success, stops go on
/// every active boot service whose subnets contain the device's source
/// address (not only the job's own), each marked as claimed, with a new
/// generation each; the claimed MACs are in `job.succeeded`.
#[tokio::test]
async fn boot005_stops_on_every_matching_boot_service() {
    let h = Harness::m3().await;
    let mac = "02:00:00:00:a7:01";
    let rd = h.ready_device("everywhere", &[mac]).await;
    let job = start(&h, &rd).await;
    // A second boot service now also serves 127.0.0.1, and a third does
    // not.
    let overlap = h.relay_cert("relay overlap");
    let other = h
        .enrol_boot_service(
            &overlap,
            "Overlap",
            &["127.0.0.1/32"],
            usgp_proto::ops::BootServiceStatus::Active,
        )
        .await;
    let far = h.relay_cert("relay far");
    let far = h
        .enrol_boot_service(
            &far,
            "Far",
            &["10.77.0.0/16"],
            usgp_proto::ops::BootServiceStatus::Active,
        )
        .await;
    succeed(&h, &rd.session.token, &job).await;
    let stops = h.events("boot_stop.added");
    assert_eq!(stops.len(), 2, "{stops:?}");
    for bs in [rd.bs, other] {
        assert!(
            stops
                .iter()
                .any(|r| r.detail.contains(&format!("\"boot_service_id\":\"{bs}\""))),
            "{bs}"
        );
    }
    assert!(stops.iter().all(|r| !r.detail.contains(&far.to_string())));
    assert!(
        stops
            .iter()
            .all(|r| r.detail.contains("\"claimed\":\"mac\""))
    );
    let done = &h.events("job.succeeded")[0];
    assert!(done.detail.contains(&format!("\"macs\":\"{mac}\"")));
    assert!(
        done.detail.contains(&format!("{other}:1")),
        "{}",
        done.detail
    );
    let mut tx = h.store.begin().await.unwrap();
    assert_eq!(tx.boot_policy_generation(other).await.unwrap(), 1);
    assert_eq!(tx.boot_policy_generation(far).await.unwrap(), 0);
    assert_eq!(
        tx.list_boot_stops(Some(other), true).await.unwrap().len(),
        1
    );
    tx.rollback().await;
}

/// NIST-006: the wipe record names how the session was authorised: the
/// code, or the approving operator.
#[tokio::test]
async fn nist006_wipe_record_names_the_authorisation() {
    let h = Harness::m3().await;
    let rd = h.ready_device("wipeauth", &["02:00:00:00:a8:01"]).await;
    start(&h, &rd).await;
    let code_id = h.events("auth_code.used")[0].target_id.clone().unwrap();
    let w = &h.events("disk.wipe.authorised")[0];
    assert!(
        w.detail.contains("\"auth_method\":\"code\""),
        "{}",
        w.detail
    );
    assert!(
        w.detail
            .contains(&format!("\"auth_code_id\":\"{code_id}\""))
    );
    assert!(!w.detail.contains("approved_by_operator"));

    // By approval.
    let s = h.open_session(&["02:00:00:00:a8:02"]).await;
    let r = h
        .post_json(
            Who::Admin,
            &format!("/v1/device-sessions/{}/approve", s.id),
            serde_json::json!({ "display_code": s.display_code }),
        )
        .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let r = h
        .dev(
            "POST",
            "/v1/device/session/package",
            Some(&s.token),
            Some(serde_json::json!({ "package_id": rd.pkg, "revision": 1 })),
        )
        .await;
    assert_eq!(r.status, 200);
    let d = crate::common::disk(1_000_204_886_016, false, usgp_proto::disk::Bus::Nvme);
    assert_eq!(h.choose_disk(&s.token, &d).await.status, 200);
    let r = h.confirm(&s.token, &rd.pkg, &d, &nonce()).await;
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    let w = h.events("disk.wipe.authorised").pop().unwrap();
    assert!(
        w.detail.contains("\"auth_method\":\"approval\""),
        "{}",
        w.detail
    );
    assert!(w.detail.contains("\"approved_by_operator\":\""));
    assert!(!w.detail.contains("auth_code_id"));
}

/// SEC-006: the device listener's 400 has a fixed message naming only the
/// line and column, never the parser's text.
#[tokio::test]
async fn sec006_fixed_parse_error_message() {
    let h = Harness::m3().await;
    h.loopback_service("parse").await;
    let r = h
        .dev_raw(
            "POST",
            "/v1/device/sessions",
            &[("content-type", "application/json")],
            Some(b"{\"schema\": 1,\n  \"agent_version\": tru".to_vec()),
        )
        .await;
    assert_eq!(r.status, 400);
    assert_eq!(r.code(), "invalid_json");
    let msg = r.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(
        msg.starts_with("the request body is not valid for this request (line 2, column "),
        "{msg}"
    );
    for leak in ["expected", "invalid type", "unknown field", "agent_version"] {
        assert!(!msg.contains(leak), "{msg}");
    }
    // Unknown fields: still the fixed text.
    let mut bad = hello(&["02:00:00:00:a9:01"]);
    bad["skip_confirm"] = serde_json::json!(true);
    let r = h.dev("POST", "/v1/device/sessions", None, Some(bad)).await;
    assert_eq!(r.status, 400);
    let msg = r.json()["error"]["message"].as_str().unwrap().to_owned();
    assert!(!msg.contains("skip_confirm"), "{msg}");
}

/// NIST-016: a failed sweep is reported, not discarded; nothing changed,
/// and the next pass completes it.
#[tokio::test]
async fn nist016_sweep_errors_surfaced() {
    let h = Harness::m3().await;
    let rd = h.ready_device("sweep", &["02:00:00:00:aa:01"]).await;
    start(&h, &rd).await;
    h.clock.advance(Duration::from_secs(901));
    h.store.fail_audit_on("job.lost");
    let report = h.api.maintenance().await;
    assert!(
        report.failed.iter().any(|(sweep, _)| *sweep == "lost_jobs"),
        "{report:?}"
    );
    assert!(h.events("job.lost").is_empty());
    h.store.clear_audit_faults();
    let report = h.api.maintenance().await;
    assert!(report.failed.is_empty(), "{report:?}");
    assert_eq!(h.events("job.lost").len(), 1);
}
