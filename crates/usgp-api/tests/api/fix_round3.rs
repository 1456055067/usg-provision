//! M3 review fix round 3, group A: finding SEC-014. A job past its
//! plan's timeouts, or whose MACs another session's running job now
//! holds, cannot succeed and add boot stops.

use std::time::Duration;

use usgp_db::{RepoTx, Store};
use usgp_proto::{JobId, JobState, MacAddress, MacList};

use crate::common::{Harness, Opts, ReadyDevice, nonce};

fn ev(seq: u64, step: u8, event: &str) -> serde_json::Value {
    serde_json::json!({ "seq": seq, "step": step, "event": event })
}

async fn start(h: &Harness, rd: &ReadyDevice) -> String {
    let r = h
        .confirm(&rd.session.token, &rd.pkg, &rd.disk, &nonce())
        .await;
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    r.json()["job_id"].as_str().unwrap().to_owned()
}

/// Steps 1 to 4 done; returns the next seq.
async fn to_step4(h: &Harness, token: &str, job: &str) -> u64 {
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
    seq
}

async fn job(h: &Harness, id: &str) -> usgp_db::Job {
    let mut tx = h.store.begin().await.unwrap();
    let j = tx.job(JobId::parse(id).unwrap()).await.unwrap().unwrap();
    tx.rollback().await;
    j
}

async fn active_stops(h: &Harness, mac: &str) -> usize {
    let macs = MacList::new(vec![MacAddress::parse(mac).unwrap()]).unwrap();
    let mut tx = h.store.begin().await.unwrap();
    let n = tx.active_boot_stops_for_macs(&macs).await.unwrap().len();
    tx.rollback().await;
    n
}

/// SEC-014: a job past its stall timeout (no sweep has run yet) posting
/// `succeeded` is failed by the server in the same transaction (audited,
/// server actor) and answered 409; no boot stop is added.
#[tokio::test]
async fn overdue_success_refused_no_stops() {
    // A stall timeout shorter than the lost-job interval, so the session
    // token has not lapsed when the late success arrives.
    let h = Harness::with(Opts {
        config: Box::new(|c| {
            c.unauth_records_per_source_per_min = 10_000;
            c.unauth_records_global_per_min = 100_000;
            c.device.max_pending_sessions_per_ip = 64;
            c.device.session_opens_per_ip_per_min = 1000;
            c.device.code_attempts_per_ip_per_min = 1000;
            c.device.jobs.stall_timeout_s = 600;
        }),
        ..Opts::default()
    })
    .await;
    let mac = "02:00:00:00:c1:01";
    let rd = h.ready_device("overdue", &[mac]).await;
    let id = start(&h, &rd).await;
    let seq = to_step4(&h, &rd.session.token, &id).await;
    // Past the 600 s stall timeout since the last report; the lost and
    // timeout sweeps are not run.
    h.clock.advance(Duration::from_secs(601));
    let r = h
        .report(&rd.session.token, &id, ev(seq, 5, "succeeded"))
        .await;
    assert_eq!(r.status, 409, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.code(), "job_not_running");
    let j = job(&h, &id).await;
    assert_eq!(j.state, JobState::Failed);
    assert_eq!(j.failure.unwrap().code.as_str(), "stall_timeout");
    let failed = h.events("job.failed");
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].actor_kind, "system");
    assert!(failed[0].detail.contains("\"failed_by\":\"server\""));
    assert!(h.events("job.succeeded").is_empty());
    assert!(h.events("boot_stop.added").is_empty());
    assert_eq!(active_stops(&h, mac).await, 0);
    assert!(
        h.events("job.progress.refused")
            .iter()
            .any(|r| r.detail.contains("\"overdue\":\"stall_timeout\""))
    );
}

/// SEC-014: a lost job's MACs are free; another session's job claims one
/// and runs. When the lost job's device reports success (within its
/// timeouts), the claim check under the claim lock refuses it 409
/// `in_use`: no stop, no success, the other job keeps the MAC.
#[tokio::test]
async fn stale_success_blocked_by_other_running_job() {
    let h = Harness::m3().await;
    let mac = "02:00:00:00:c2:01";
    let rd = h.ready_device("stale", &[mac]).await;
    let a = start(&h, &rd).await;
    let seq = to_step4(&h, &rd.session.token, &a).await;
    h.clock.advance(Duration::from_secs(901));
    assert_eq!(h.api.mark_lost_jobs().await.unwrap(), 1);
    // A second device claims the same MAC: allowed, the lost job holds
    // nothing.
    let (s2, d2) = h.chosen_session(&rd.pkg, &[mac]).await;
    let r = h.confirm(&s2.token, &rd.pkg, &d2, &nonce()).await;
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    let b = r.json()["job_id"].as_str().unwrap().to_owned();
    // The first device comes back and reports success.
    let r = h
        .report(&rd.session.token, &a, ev(seq, 5, "succeeded"))
        .await;
    assert_eq!(r.status, 409, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.code(), "in_use");
    let rec = h.events("job.progress.refused").pop().unwrap();
    assert!(rec.detail.contains(&b), "{}", rec.detail);
    assert!(h.events("job.succeeded").is_empty());
    assert!(h.events("boot_stop.added").is_empty());
    assert_eq!(active_stops(&h, mac).await, 0);
    // Nothing of the refused report was kept.
    assert_eq!(job(&h, &a).await.state, JobState::Lost);
    assert_eq!(job(&h, &b).await.state, JobState::Running);
}
