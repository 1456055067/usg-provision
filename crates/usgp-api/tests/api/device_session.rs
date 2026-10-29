//! The device session protocol (M3 plan section 3.1): open, code and
//! approval authorisation, package and disk choice, the separate wipe
//! confirmation and the signed plan; and the negatives the plan names
//! (replayed, revoked and expired codes, attempt exhaustion, expired
//! session, wrong token, confirm without a disk, cancel after the wipe,
//! the audit-write failure on `disk.wipe.authorised`).

use std::time::Duration;

use usgp_db::{RepoTx, Store};
use usgp_proto::device::SessionState;
use usgp_proto::disk::Bus;
use usgp_proto::envelope::SignedEnvelopeV1;
use usgp_proto::{
    DiskDescriptorV1, JobId, JobState, PackageId, PlanExpectation, SessionId, VerifiedJobPlan,
};

use crate::common::{Harness, Pinned, Who, disk, hello, nonce};

fn sid(s: &str) -> SessionId {
    SessionId::parse(s).unwrap()
}

/// Every API and device record of the run is free of the code values and
/// session tokens used.
fn assert_no_secrets(h: &Harness, secrets: &[&str]) {
    let text = h.all_record_text();
    for s in secrets {
        let plain: String = s.chars().filter(|c| *c != '-').collect();
        assert!(!text.contains(s), "secret in audit");
        assert!(!text.contains(&plain), "secret in audit");
    }
}

/// The happy path by code, to a verified plan whose wipe record is
/// durable and names the job.
#[tokio::test]
async fn code_flow_to_verified_plan() {
    let h = Harness::m3().await;
    let rd = h
        .ready_device("flow", &["02:00:00:00:00:01", "02:00:00:00:00:02"])
        .await;
    let n = nonce();
    let r = h.confirm(&rd.session.token, &rd.pkg, &rd.disk, &n).await;
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    let j = r.json();
    let job_id = JobId::parse(j["job_id"].as_str().unwrap()).unwrap();
    let plan_env: SignedEnvelopeV1 = serde_json::from_value(j["plan"].clone()).unwrap();
    let content_env: SignedEnvelopeV1 =
        serde_json::from_value(j["content_manifest"].clone()).unwrap();
    let pkg = PackageId::parse(&rd.pkg).unwrap();
    let v = VerifiedJobPlan::verify(
        &plan_env,
        &Pinned(h.plan_pub.clone()),
        &content_env,
        &Pinned(h.content_pub.clone()),
        &usgp_crypto::sha256,
        &PlanExpectation {
            agent_nonce: &n,
            session_id: sid(&rd.session.id),
            job_id,
            package_id: pkg,
            package_revision: 1,
            disk: &rd.disk,
        },
    )
    .expect("the plan verifies with the pinned keys");
    // The plan is not signed with the content key.
    assert!(
        VerifiedJobPlan::verify(
            &plan_env,
            &Pinned(h.content_pub.clone()),
            &content_env,
            &Pinned(h.content_pub.clone()),
            &usgp_crypto::sha256,
            &PlanExpectation {
                agent_nonce: &n,
                session_id: sid(&rd.session.id),
                job_id,
                package_id: pkg,
                package_revision: 1,
                disk: &rd.disk,
            },
        )
        .is_err()
    );
    // The wipe record is durable, names the job, and is the plan's.
    let wipe = h.events("disk.wipe.authorised");
    assert_eq!(wipe.len(), 1);
    let w = &wipe[0];
    assert_eq!(w.outcome, "success");
    assert_eq!(w.target_kind.as_deref(), Some("job"));
    assert_eq!(w.target_id.as_deref(), Some(job_id.to_string().as_str()));
    assert_eq!(v.plan().wipe.audit_seq, w.seq);
    assert_eq!(v.plan().wipe.record_hash, w.record_hash);
    let mut tx = h.store.begin().await.unwrap();
    let job = tx.job(job_id).await.unwrap().unwrap();
    let sess = tx
        .device_session(sid(&rd.session.id))
        .await
        .unwrap()
        .unwrap();
    tx.rollback().await;
    assert_eq!(job.state, JobState::Running);
    assert_eq!(job.wipe_audit_seq, w.seq);
    let plan_pin = Pinned(h.plan_pub.clone());
    let plan_bytes = plan_env
        .verified_payload(usgp_proto::PayloadType::JobPlanV1, &plan_pin)
        .unwrap()
        .bytes
        .to_vec();
    assert_eq!(job.plan_sha256, usgp_crypto::sha256(&plan_bytes));
    assert_eq!(sess.state, SessionState::Confirmed);
    for e in [
        "device.session.opened",
        "auth_code.issued",
        "auth_code.used",
        "device.session.authorised",
        "device.session.package_chosen",
        "device.session.disk_chosen",
        "job.created",
        "job.plan.issued",
        "boot_service.packages.set",
    ] {
        assert!(!h.events(e).is_empty(), "no {e}");
    }
    // Device records name the session as actor and come from 127.0.0.1.
    let opened = h.events("device.session.opened");
    let mine: Vec<_> = opened
        .iter()
        .filter(|r| r.target_id.as_deref() == Some(rd.session.id.as_str()))
        .collect();
    assert_eq!(mine.len(), 1);
    assert_eq!(mine[0].actor_kind, "device_session");
    assert_eq!(mine[0].actor_id.as_deref(), Some(rd.session.id.as_str()));
    assert_eq!(mine[0].interface, "device_api");
    for r in h.events("device.session.disk_chosen") {
        assert_eq!(r.actor_kind, "device_session");
        assert_eq!(r.actor_id.as_deref(), Some(rd.session.id.as_str()));
        assert!(r.actor_label.as_deref().unwrap().contains("(claimed)"));
        assert_eq!(r.interface, "device_api");
        assert!(r.source.as_deref().unwrap().starts_with("127.0.0.1:"));
    }
    // The plan carries neither the token nor anything secret.
    let payload = String::from_utf8(plan_bytes).unwrap();
    assert!(!payload.contains(&rd.session.token));
    assert_no_secrets(&h, &[&rd.session.token]);
}

/// Approval bound to the display code; a wrong code is refused and
/// audited; the device then sees `authorised`.
#[tokio::test]
async fn approval_bound_to_display_code() {
    let h = Harness::m3().await;
    h.loopback_service("approval").await;
    let s = h.open_session(&["02:00:00:00:00:03"]).await;
    let r = h
        .get(
            Who::Admin,
            "/v1/device-sessions?state=awaiting_authorisation",
        )
        .await;
    assert_eq!(r.status, 200);
    let list = r.json();
    let row = list["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == s.id.as_str())
        .unwrap()
        .clone();
    assert_eq!(row["display_code"], s.display_code.as_str());
    let wrong = if s.display_code == "AAA-AAA" {
        "BBB-BBB"
    } else {
        "AAA-AAA"
    };
    let r = h
        .post_json(
            Who::Admin,
            &format!("/v1/device-sessions/{}/approve", s.id),
            serde_json::json!({ "display_code": wrong }),
        )
        .await;
    assert_eq!(r.status, 422);
    assert_eq!(r.code(), "display_code_mismatch");
    assert_eq!(h.events("device.session.approve_refused").len(), 1);
    let r = h
        .dev("GET", "/v1/device/session/packages", Some(&s.token), None)
        .await;
    assert_eq!(r.status, 403);
    assert_eq!(r.code(), "not_authorised");
    // Lower case is accepted (Crockford normalisation).
    let r = h
        .post_json(
            Who::Admin,
            &format!("/v1/device-sessions/{}/approve", s.id),
            serde_json::json!({ "display_code": s.display_code.to_lowercase() }),
        )
        .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["auth_method"], "approval");
    let r = h
        .dev("GET", "/v1/device/session", Some(&s.token), None)
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["state"], "authorised");
    assert_eq!(h.events("device.session.approved").len(), 1);
    // A second approval is refused.
    let r = h
        .post_json(
            Who::Admin,
            &format!("/v1/device-sessions/{}/approve", s.id),
            serde_json::json!({ "display_code": s.display_code }),
        )
        .await;
    assert_eq!(r.status, 409);
}

/// A used, a revoked and an expired code all get the same answer as a
/// wrong one (no oracle), and each costs an attempt.
#[tokio::test]
async fn replayed_revoked_and_expired_codes_refused_alike() {
    let h = Harness::m3().await;
    h.loopback_service("replay").await;
    let a = h.open_session(&["02:00:00:00:00:04"]).await;
    let b = h.open_session(&["02:00:00:00:00:05"]).await;
    let (_, code) = h.issue_code().await;
    let r = h.submit_code(&a.token, &code).await;
    assert_eq!(r.status, 200);
    // Replay on another session.
    let replay = h.submit_code(&b.token, &code).await;
    assert_eq!(replay.status, 422);
    assert_eq!(replay.code(), "code_not_accepted");
    assert_eq!(replay.json()["error"]["attempts_left"], 4);
    // Revoked.
    let (rid, revoked) = h.issue_code().await;
    let r = h
        .req(
            Who::Admin,
            "DELETE",
            &format!("/v1/auth-codes/{rid}"),
            &[],
            None,
        )
        .await;
    assert_eq!(r.status, 200);
    let r = h.submit_code(&b.token, &revoked).await;
    assert_eq!(r.status, 422);
    assert_eq!(r.json()["error"]["attempts_left"], 3);
    // Expired.
    let (_, old) = h.issue_code().await;
    // The device keeps polling while it waits (an unauthorised session
    // idle for 120 s expires, finding SEC-001).
    for _ in 0..10 {
        h.clock.advance(Duration::from_secs(91));
        let r = h
            .dev("GET", "/v1/device/session", Some(&b.token), None)
            .await;
        assert_eq!(r.status, 200);
    }
    let r = h.submit_code(&b.token, &old).await;
    assert_eq!(r.status, 422);
    // Wrong.
    let wrong = h.submit_code(&b.token, "00000-00000").await;
    assert_eq!(wrong.status, 422);
    // Same message for all (attempts_left aside).
    assert_eq!(
        replay.json()["error"]["message"],
        wrong.json()["error"]["message"]
    );
    let refused = h.events("device.session.code_refused");
    assert_eq!(refused.len(), 4);
    assert_no_secrets(&h, &[&code, &revoked, &old, &a.token, &b.token]);
    // The used code is shown used, never its value.
    let r = h.get(Who::Admin, "/v1/auth-codes").await;
    let body = String::from_utf8(r.body.clone()).unwrap();
    assert!(body.contains("\"used\"") && body.contains("\"revoked\""));
    assert!(!body.contains(&code));
}

/// Five failed attempts refuse the session; it then gets nothing.
#[tokio::test]
async fn attempt_exhaustion_refuses_session() {
    let h = Harness::m3().await;
    h.loopback_service("exhaust").await;
    let s = h.open_session(&["02:00:00:00:00:06"]).await;
    for left in (1..=4).rev() {
        let r = h.submit_code(&s.token, "00000-00000").await;
        assert_eq!(r.status, 422);
        assert_eq!(r.json()["error"]["attempts_left"], left);
    }
    let r = h.submit_code(&s.token, "00000-00000").await;
    assert_eq!(r.status, 403);
    assert_eq!(r.code(), "session_refused");
    // Even a valid code is refused now.
    let (_, code) = h.issue_code().await;
    let r = h.submit_code(&s.token, &code).await;
    assert_eq!(r.status, 403);
    assert_eq!(r.code(), "session_refused");
    let r = h
        .dev("GET", "/v1/device/session/packages", Some(&s.token), None)
        .await;
    assert_eq!(r.status, 403);
    let r = h
        .dev("GET", "/v1/device/session", Some(&s.token), None)
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["state"], "refused");
    assert_eq!(r.json()["reason_code"], "code_attempts_exhausted");
    assert_eq!(h.events("device.session.refused").len(), 1);
}

/// Per-source code attempts are rate limited.
#[tokio::test]
async fn code_attempts_rate_limited_per_source() {
    let h = Harness::with(crate::common::Opts {
        config: Box::new(|c| {
            c.unauth_records_per_source_per_min = 10_000;
            c.device.code_attempts_per_ip_per_min = 2;
            c.device.max_pending_sessions_per_ip = 64;
        }),
        ..crate::common::Opts::default()
    })
    .await;
    h.loopback_service("coderate").await;
    let s = h.open_session(&["02:00:00:00:00:07"]).await;
    let t = h.open_session(&["02:00:00:00:00:08"]).await;
    assert_eq!(h.submit_code(&s.token, "00000-00000").await.status, 422);
    assert_eq!(h.submit_code(&t.token, "00000-00000").await.status, 422);
    let r = h.submit_code(&s.token, "00000-00000").await;
    assert_eq!(r.status, 429);
    assert_eq!(r.code(), "rate_limited");
}

/// A pending session expires; then only its status is readable.
#[tokio::test]
async fn expired_session_refused() {
    let h = Harness::m3().await;
    h.loopback_service("expired").await;
    let s = h.open_session(&["02:00:00:00:00:09"]).await;
    let (_, code) = h.issue_code().await;
    h.clock.advance(Duration::from_secs(3601));
    let r = h.submit_code(&s.token, &code).await;
    assert_eq!(r.status, 403);
    assert_eq!(r.code(), "session_ended");
    assert_eq!(h.events("device.session.expired").len(), 1);
    let r = h
        .dev("GET", "/v1/device/session", Some(&s.token), None)
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["state"], "expired");
    // The operator cannot approve it either.
    let r = h
        .post_json(
            Who::Admin,
            &format!("/v1/device-sessions/{}/approve", s.id),
            serde_json::json!({ "display_code": s.display_code }),
        )
        .await;
    assert_eq!(r.status, 409);
    // The sweep expires the others.
    let other = h.open_session(&["02:00:00:00:00:0a"]).await;
    h.clock.advance(Duration::from_secs(3601));
    assert_eq!(h.api.expire_device_sessions().await.unwrap(), 1);
    let mut tx = h.store.begin().await.unwrap();
    let st = tx
        .device_session(sid(&other.id))
        .await
        .unwrap()
        .unwrap()
        .state;
    tx.rollback().await;
    assert_eq!(st, SessionState::Expired);
}

/// A missing, malformed or unknown token is 401 with a Bearer challenge;
/// the connection is closed.
#[tokio::test]
async fn wrong_token_401() {
    let h = Harness::m3().await;
    h.loopback_service("wrongtoken").await;
    let _s = h.open_session(&["02:00:00:00:00:0b"]).await;
    let unknown = "A".repeat(43);
    for token in [None, Some("short"), Some(unknown.as_str())] {
        let r = h.dev("GET", "/v1/device/session", token, None).await;
        assert_eq!(r.status, 401, "{token:?}");
        assert_eq!(r.code(), "invalid_token");
        assert_eq!(
            r.header("www-authenticate").as_deref(),
            Some("Bearer realm=\"usg-provision-device\"")
        );
        assert_eq!(r.header("connection").as_deref(), Some("close"));
    }
    let recs = h.events("auth.unauthenticated");
    assert_eq!(recs.len(), 3);
    assert!(
        recs.iter()
            .any(|r| r.reason.as_deref() == Some("unknown_token"))
    );
    assert!(!h.all_record_text().contains(&unknown));
}

/// Confirm needs a chosen disk; nothing is created without one.
#[tokio::test]
async fn confirm_without_disk_refused() {
    let h = Harness::m3().await;
    let rd = h.ready_device("nodisk", &["02:00:00:00:00:0c"]).await;
    let s = h.open_session(&["02:00:00:00:00:0d"]).await;
    let (_, code) = h.issue_code().await;
    assert_eq!(h.submit_code(&s.token, &code).await.status, 200);
    let r = h
        .dev(
            "POST",
            "/v1/device/session/package",
            Some(&s.token),
            Some(serde_json::json!({ "package_id": rd.pkg, "revision": 1 })),
        )
        .await;
    assert_eq!(r.status, 200);
    let d = disk(1_000_204_886_016, false, Bus::Nvme);
    let r = h.confirm(&s.token, &rd.pkg, &d, &nonce()).await;
    assert_eq!(r.status, 409);
    assert_eq!(r.code(), "wrong_state");
    assert!(h.events("disk.wipe.authorised").is_empty());
    assert!(h.events("job.created").is_empty());
    let mut tx = h.store.begin().await.unwrap();
    assert!(tx.job_by_session(sid(&s.id)).await.unwrap().is_none());
    tx.rollback().await;
    assert_eq!(h.events("device.session.confirm_refused").len(), 1);
    // A confirm naming another disk than the chosen one is refused too.
    let r = h
        .confirm(
            &rd.session.token,
            &rd.pkg,
            &disk(1_000_204_886_016, false, Bus::Nvme),
            &nonce(),
        )
        .await;
    assert_eq!(r.status, 409);
}

/// Cancel works before the wipe confirmation and is refused after it.
#[tokio::test]
async fn cancel_only_before_wipe() {
    let h = Harness::m3().await;
    let rd = h.ready_device("cancel", &["02:00:00:00:00:0e"]).await;
    let r = h
        .confirm(&rd.session.token, &rd.pkg, &rd.disk, &nonce())
        .await;
    assert_eq!(r.status, 201);
    let r = h
        .dev(
            "POST",
            "/v1/device/session/cancel",
            Some(&rd.session.token),
            Some(serde_json::json!({})),
        )
        .await;
    assert_eq!(r.status, 409);
    assert_eq!(r.code(), "job_started");
    assert_eq!(h.events("device.session.cancel_refused").len(), 1);
    // Before the wipe: cancelled, audited, and nothing more is offered.
    let s = h.open_session(&["02:00:00:00:00:0f"]).await;
    let r = h
        .dev(
            "POST",
            "/v1/device/session/cancel",
            Some(&s.token),
            Some(serde_json::json!({})),
        )
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["state"], "cancelled");
    assert_eq!(h.events("device.session.cancelled").len(), 1);
    let (_, code) = h.issue_code().await;
    assert_eq!(h.submit_code(&s.token, &code).await.status, 403);
    // Cancel takes exactly `{}`.
    let t = h.open_session(&["02:00:00:00:00:10"]).await;
    let r = h
        .dev(
            "POST",
            "/v1/device/session/cancel",
            Some(&t.token),
            Some(serde_json::json!({"force": true})),
        )
        .await;
    assert_eq!(r.status, 400);
}

/// Acceptance 3: if `disk.wipe.authorised` cannot be written, no job and
/// no plan exist, the session stays authorised, and the device gets 503.
#[tokio::test]
async fn wipe_record_failure_creates_no_job() {
    let h = Harness::m3().await;
    let rd = h.ready_device("wipefault", &["02:00:00:00:00:11"]).await;
    let head = h.records().len();
    h.store.fail_audit_on("disk.wipe.authorised");
    let r = h
        .confirm(&rd.session.token, &rd.pkg, &rd.disk, &nonce())
        .await;
    assert_eq!(r.status, 503, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.code(), "audit_unavailable");
    assert!(r.json().get("plan").is_none());
    let mut tx = h.store.begin().await.unwrap();
    assert!(
        tx.job_by_session(sid(&rd.session.id))
            .await
            .unwrap()
            .is_none()
    );
    assert!(tx.list_jobs(&[]).await.unwrap().is_empty());
    let st = tx
        .device_session(sid(&rd.session.id))
        .await
        .unwrap()
        .unwrap()
        .state;
    tx.rollback().await;
    assert_eq!(st, SessionState::Authorised);
    // job.created was in the same transaction: it is gone too.
    assert!(h.events("job.created").is_empty());
    assert!(h.events("job.plan.issued").is_empty());
    assert!(
        h.records().len() <= head + 1,
        "only the refusal may be added"
    );
    // After the fault clears, the same confirmation succeeds.
    h.store.clear_audit_faults();
    let r = h
        .confirm(&rd.session.token, &rd.pkg, &rd.disk, &nonce())
        .await;
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
}

/// Disk rules: too small, removable and USB are refused; a disk before a
/// package is refused; an unassigned package is not offered.
#[tokio::test]
async fn disk_and_package_rules() {
    let h = Harness::m3().await;
    let rd = h.ready_device("rules", &["02:00:00:00:00:12"]).await;
    let tok = &rd.session.token;
    let small = disk(63_999_999_488, false, Bus::Nvme);
    let r = h.choose_disk(tok, &small).await;
    assert_eq!(r.status, 422);
    assert_eq!(r.code(), "disk_too_small");
    for d in [
        disk(1_000_204_886_016, true, Bus::Nvme),
        disk(1_000_204_886_016, false, Bus::Usb),
    ] {
        let r = h.choose_disk(tok, &d).await;
        assert_eq!(r.status, 422, "{d:?}");
    }
    assert_eq!(h.events("device.session.disk_refused").len(), 3);
    // A package that is not assigned to this boot service.
    let (other, _, _) = h.ready_package("unassigned").await;
    let r = h
        .dev(
            "POST",
            "/v1/device/session/package",
            Some(tok),
            Some(serde_json::json!({ "package_id": other, "revision": 1 })),
        )
        .await;
    assert_eq!(r.status, 422);
    assert_eq!(r.code(), "package_not_offered");
    // The list holds only the assigned package.
    let r = h
        .dev("GET", "/v1/device/session/packages", Some(tok), None)
        .await;
    assert_eq!(r.status, 200);
    let list = r.json();
    let ids: Vec<_> = list["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["package_id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids, vec![rd.pkg.clone()]);
    assert_eq!(
        list["packages"][0]["required_disk_bytes"],
        64_000_000_000u64
    );
    // A new session must choose a package before a disk.
    let s = h.open_session(&["02:00:00:00:00:13"]).await;
    let (_, code) = h.issue_code().await;
    assert_eq!(h.submit_code(&s.token, &code).await.status, 200);
    let r = h
        .choose_disk(&s.token, &disk(1_000_204_886_016, false, Bus::Nvme))
        .await;
    assert_eq!(r.status, 409);
}

/// Finding SEC-001: a device outside every served subnet gets no
/// session at all (403, one capped refusal record); the operator still
/// sees the boot service's own warning (REQ-TGT-008).
#[tokio::test]
async fn no_session_without_boot_service() {
    let h = Harness::m3().await;
    let relay = h.relay_cert("relay elsewhere");
    let bs = h
        .enrol_boot_service(
            &relay,
            "Elsewhere",
            &["10.99.0.0/16"],
            usgp_proto::ops::BootServiceStatus::Active,
        )
        .await;
    let r = h.get(Who::Admin, &format!("/v1/boot-services/{bs}")).await;
    assert_eq!(r.json()["usable_count"], 0);
    assert_eq!(r.json()["warning"]["code"], "no_usable_package");
    let r = h
        .dev(
            "POST",
            "/v1/device/sessions",
            None,
            Some(hello(&["02:00:00:00:00:14"])),
        )
        .await;
    assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.code(), "forbidden");
    assert!(r.json().get("token").is_none());
    let refused = h.events("device.session.open_refused");
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].reason.as_deref(), Some("no_boot_service"));
    assert!(
        refused[0]
            .detail
            .contains("\"boot_service_resolution\":\"none\"")
    );
    assert!(h.events("device.session.opened").is_empty());
    let mut tx = h.store.begin().await.unwrap();
    assert!(tx.list_device_sessions(&[]).await.unwrap().is_empty());
    tx.rollback().await;
}

/// Session opens are capped per source and in total; refusals audited.
#[tokio::test]
async fn open_caps() {
    let h = Harness::with(crate::common::Opts {
        config: Box::new(|c| {
            c.unauth_records_per_source_per_min = 10_000;
            c.device.max_pending_sessions_per_ip = 2;
        }),
        ..crate::common::Opts::default()
    })
    .await;
    h.loopback_service("caps").await;
    h.open_session(&["02:00:00:00:00:15"]).await;
    h.open_session(&["02:00:00:00:00:16"]).await;
    let r = h
        .dev(
            "POST",
            "/v1/device/sessions",
            None,
            Some(hello(&["02:00:00:00:00:17"])),
        )
        .await;
    assert_eq!(r.status, 429);
    assert_eq!(h.events("device.session.open_refused").len(), 1);
    // Unknown fields are refused.
    let mut bad = hello(&["02:00:00:00:00:18"]);
    bad["skip_confirm"] = serde_json::json!(true);
    let r = h.dev("POST", "/v1/device/sessions", None, Some(bad)).await;
    assert_eq!(r.status, 400);
}

/// Confirm cannot be replayed into a second job, and the session token
/// is no longer good for choices.
#[tokio::test]
async fn confirm_once() {
    let h = Harness::m3().await;
    let rd = h.ready_device("once", &["02:00:00:00:00:19"]).await;
    assert_eq!(
        h.confirm(&rd.session.token, &rd.pkg, &rd.disk, &nonce())
            .await
            .status,
        201
    );
    let r = h
        .confirm(&rd.session.token, &rd.pkg, &rd.disk, &nonce())
        .await;
    assert_eq!(r.status, 409);
    let d: DiskDescriptorV1 = rd.disk.clone();
    assert_eq!(h.choose_disk(&rd.session.token, &d).await.status, 409);
    let mut tx = h.store.begin().await.unwrap();
    assert_eq!(tx.list_jobs(&[]).await.unwrap().len(), 1);
    tx.rollback().await;
}

/// QA-004: a BIOS (or non-x64) device is refused the list for its own
/// firmware, and the boot service, which has a usable package, is not
/// reported as having none.
#[tokio::test]
async fn device_mismatch_is_not_a_boot_service_fault() {
    let h = Harness::m3().await;
    let rd = h.ready_device("bios", &["02:00:00:00:00:20"]).await;
    for (firmware, arch) in [("bios", "x64"), ("uefi", "arm64")] {
        let mut hi = hello(&["02:00:00:00:00:21"]);
        hi["firmware"] = firmware.into();
        hi["arch"] = arch.into();
        let r = h.dev("POST", "/v1/device/sessions", None, Some(hi)).await;
        assert_eq!(r.status, 201);
        let token = r.json()["token"].as_str().unwrap().to_owned();
        let (_, code) = h.issue_code().await;
        assert_eq!(h.submit_code(&token, &code).await.status, 200);
        let r = h
            .dev("GET", "/v1/device/session/packages", Some(&token), None)
            .await;
        assert_eq!(r.status, 200);
        assert_eq!(r.json()["packages"], serde_json::json!([]));
        let rec = h.events("device.session.packages.read").pop().unwrap();
        assert_eq!(rec.outcome, "refused");
        assert_eq!(rec.reason.as_deref(), Some("firmware_unsupported"));
        assert!(rec.detail.contains(&format!("\"firmware\":\"{firmware}\"")));
        assert!(rec.detail.contains(&format!("\"arch\":\"{arch}\"")));
    }
    assert!(h.events("boot_service.no_usable_package").is_empty());
    // The boot service is still shown with its usable package.
    let r = h
        .get(Who::Admin, &format!("/v1/boot-services/{}", rd.bs))
        .await;
    assert_eq!(r.json()["usable_count"], 1);
    // A UEFI x64 device is offered it, and nothing is reported missing.
    let r = h
        .dev(
            "GET",
            "/v1/device/session/packages",
            Some(&rd.session.token),
            None,
        )
        .await;
    assert_eq!(r.json()["packages"].as_array().unwrap().len(), 1);
    assert!(h.events("boot_service.no_usable_package").is_empty());
}

/// `boot_service.no_usable_package` is kept for a boot service that has
/// nothing usable, with its reason.
#[tokio::test]
async fn empty_boot_service_reported_with_reason() {
    let h = Harness::m3().await;
    let relay = h.relay_cert("relay empty");
    let bs = h
        .enrol_boot_service(
            &relay,
            "Empty",
            &["127.0.0.0/8"],
            usgp_proto::ops::BootServiceStatus::Active,
        )
        .await;
    let s = h.open_session(&["02:00:00:00:00:22"]).await;
    let (_, code) = h.issue_code().await;
    assert_eq!(h.submit_code(&s.token, &code).await.status, 200);
    let r = h
        .dev("GET", "/v1/device/session/packages", Some(&s.token), None)
        .await;
    assert_eq!(r.json()["packages"], serde_json::json!([]));
    let recs = h.events("boot_service.no_usable_package");
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].reason.as_deref(), Some("no_usable_package"));
    assert_eq!(recs[0].target_id.as_deref(), Some(bs.to_string().as_str()));
    let read = h.events("device.session.packages.read").pop().unwrap();
    assert_eq!(read.outcome, "success");
    assert_eq!(read.reason.as_deref(), Some("no_usable_package"));
}
