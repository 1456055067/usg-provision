//! SEC-002 and NIST-006: the verifier knows the checkpoint cadence
//! (`VerifyPolicy`) and reports backward timestamps without failing.

use std::time::Duration;

use usgp_audit::canonical::compute_record_hash;
use usgp_audit::verify::checkpoint_slack_records;
use usgp_audit::{
    AuditError, AuditRecord, ChainVerifier, CheckpointPolicy, EVENT_CHECKPOINT, Finding, Notice,
    NoticeKind, VerifyPolicy, Violation, verify_chain, verify_chain_with_policy,
    verify_store_with_policy,
};

use super::common::{Fixture, NowForTest, T0, block_on, fixture, fixture_with};

const EVERY: u64 = 3;

fn tight() -> VerifyPolicy {
    // A checkpoint at s, its record at s + 1, the next due at s + 1 + EVERY.
    VerifyPolicy::records(EVERY + 1)
}

/// Writers assumed for the test server (one appender at a time here).
const WRITERS: u64 = 8;

fn server_policy() -> VerifyPolicy {
    VerifyPolicy::for_writers(
        &CheckpointPolicy {
            every_records: EVERY,
            every: Duration::from_secs(3600),
            ..CheckpointPolicy::default()
        },
        WRITERS,
    )
}

fn chain(ops: usize) -> Fixture {
    let f = fixture(EVERY, Duration::from_secs(3600));
    f.ops(ops);
    f
}

fn check(f: &Fixture, policy: VerifyPolicy) -> usgp_audit::VerifyReport {
    verify_chain_with_policy(
        &f.store.records(),
        &f.store.checkpoints(),
        std::slice::from_ref(&f.public),
        Some(policy),
    )
    .unwrap()
}

/// Re-links and re-hashes every record from position `from`.
fn rechain(records: &mut [AuditRecord], from: usize) {
    for i in from..records.len() {
        if i > 0 {
            records[i].prev_hash = records[i - 1].record_hash;
        }
        records[i].record_hash = compute_record_hash(&records[i]).unwrap();
    }
}

#[test]
fn server_cadence_is_within_the_tight_bound() {
    let f = chain(40);
    let r = check(&f, tight());
    assert!(r.is_intact(), "{r:?}");
    assert_eq!(r.max_unsigned_records, Some(EVERY + 1));
    let r = check(&f, server_policy());
    assert!(r.is_intact(), "{r:?}");
    assert_eq!(
        server_policy().max_unsigned_records,
        EVERY + 1 + checkpoint_slack_records(WRITERS)
    );
}

#[test]
fn rewrite_after_old_checkpoint_is_detected() {
    // SEC-002 scenario: a database owner without the audit key keeps an
    // old checkpoint, deletes every later checkpoint row, rewrites the
    // records after it (turning later checkpoint records into ordinary
    // ones) and sets the head to the new last record.
    let f = chain(60);
    let kept = f.store.checkpoints().iter().map(|c| c.seq).min().unwrap();
    f.store.tamper_for_test(|recs, cps, head| {
        cps.retain(|c| c.seq == kept);
        // Everything after the kept checkpoint's own record.
        let from = recs.iter().position(|r| r.seq == kept + 2).unwrap();
        for r in recs.iter_mut().skip(from) {
            if r.event == EVENT_CHECKPOINT {
                r.event = "package.created".into();
                r.detail = "{}".into();
            }
            r.reason = Some("rewritten".into());
        }
        rechain(recs, from);
        *head = recs.last().map(usgp_audit::ChainHead::from);
    });
    let recs = f.store.records();
    let cps = f.store.checkpoints();
    let keys = std::slice::from_ref(&f.public);

    // Structural rules alone: intact (the stated limit before SEC-002).
    let r = verify_chain(&recs, &cps, keys).unwrap();
    assert!(r.is_intact(), "{r:?}");
    assert!(r.unsigned_tail > server_policy().max_unsigned_records);

    // With the server's cadence: tampered, at the first seq outside the
    // allowed run.
    let p = server_policy();
    let r = block_on(verify_store_with_policy(&f.store, keys, 7, Some(p))).unwrap();
    assert!(!r.is_intact());
    assert_eq!(
        r.findings,
        vec![Finding {
            seq: kept + p.max_unsigned_records + 1,
            violation: Violation::UnsignedTailTooLong
        }]
    );
}

#[test]
fn gap_between_checkpoints_is_detected() {
    let f = fixture(EVERY, Duration::from_secs(3600));
    f.ops(5);
    let before = f.store.checkpoints().iter().map(|c| c.seq).max().unwrap();
    for i in 0..20 {
        f.op_append_only(i);
    }
    f.ops(5);
    let r = check(&f, tight());
    let gap = r
        .findings
        .iter()
        .find(|x| x.violation == Violation::CheckpointGapTooLong)
        .expect("gap finding");
    assert_eq!(gap.seq, before + EVERY + 2);
    assert!(
        r.findings
            .iter()
            .all(|x| x.violation == Violation::CheckpointGapTooLong),
        "{r:?}"
    );
    // A policy wide enough for the run: intact.
    let r = check(&f, VerifyPolicy::records(30));
    assert!(r.is_intact(), "{r:?}");
}

#[test]
fn no_checkpoint_over_the_limit_is_a_finding() {
    let f = fixture(EVERY, Duration::from_secs(3600));
    for i in 0..10 {
        f.op_append_only(i);
    }
    assert!(f.store.checkpoints().is_empty());
    let p = VerifyPolicy::records(5);
    let r = check(&f, p);
    assert_eq!(
        r.findings,
        vec![Finding {
            seq: 6,
            violation: Violation::NoCheckpoint
        }]
    );
    // Within the limit: intact, tail reported.
    let r = check(&f, VerifyPolicy::records(11));
    assert!(r.is_intact(), "{r:?}");
    assert_eq!(r.unsigned_tail, 11);

    // The first checkpoint arriving too late is a gap from seq 0.
    f.ops(1);
    let r = check(&f, p);
    assert_eq!(
        r.findings,
        vec![Finding {
            seq: 6,
            violation: Violation::CheckpointGapTooLong
        }]
    );
}

#[test]
fn deleting_all_checkpoints_and_recomputing_is_caught_by_policy() {
    let f = chain(20);
    let mut recs = f.store.records();
    // Remove every checkpoint record and recompute: no checkpoint record
    // remains to be unmatched.
    recs.retain(|r| r.event != EVENT_CHECKPOINT);
    for (i, r) in recs.iter_mut().enumerate() {
        r.seq = i as u64 + 1;
    }
    rechain(&mut recs, 1);
    let keys = std::slice::from_ref(&f.public);
    assert!(verify_chain(&recs, &[], keys).unwrap().is_intact());
    let r = verify_chain_with_policy(&recs, &[], keys, Some(tight())).unwrap();
    assert_eq!(
        r.first_finding().unwrap().violation,
        Violation::NoCheckpoint
    );
}

#[test]
fn out_of_range_policy_refused() {
    let f = chain(1);
    for bad in [0, usgp_audit::verify::MAX_UNSIGNED_RECORDS + 1] {
        let v = ChainVerifier::new(std::slice::from_ref(&f.public), vec![])
            .unwrap()
            .with_policy(VerifyPolicy::records(bad));
        assert!(matches!(v, Err(AuditError::Config { .. })));
    }
}

#[test]
fn backward_timestamp_is_a_notice_not_a_finding() {
    // NIST-006.
    let f = chain(2);
    let before = f.clock.now_us_for_test();
    f.clock.set(T0 - 5_000_000);
    f.op_append_only(7);
    let back_seq = f.store.records().last().unwrap().seq;
    f.ops(2);
    let r = check(&f, tight());
    assert!(r.is_intact(), "{r:?}");
    assert_eq!(
        r.notices,
        vec![Notice {
            seq: back_seq,
            kind: NoticeKind::TimestampBackwards {
                previous_us: before,
                ts_us: T0 - 5_000_000,
            }
        }]
    );
    assert_eq!(r.notices[0].kind.as_str(), "timestamp_backwards");
    // Equal or rising timestamps give no notice.
    assert!(check(&chain(5), tight()).notices.is_empty());
}

const HOUR: Duration = Duration::from_secs(3600);
const HOUR_US: u64 = 3_600_000_000;

fn heartbeat_fixture() -> Fixture {
    fixture_with(CheckpointPolicy {
        every_records: EVERY,
        every: Duration::from_secs(60),
        heartbeat: Duration::from_secs(900),
    })
}

/// SEC-013: an idle chain still gets a signed checkpoint every heartbeat,
/// and the newest checkpoint time is reported.
#[test]
fn heartbeat_checkpoints_an_idle_chain() {
    let f = heartbeat_fixture();
    f.ops(4);
    // Cover the last operator record, so only the heartbeat is left.
    let _ = f.checkpoint(true);
    assert!(!f.checkpoint(true), "nothing new to force");
    let n = f.store.checkpoints().len();
    // Nothing new: not due before the heartbeat, due after it.
    f.clock.advance(Duration::from_secs(899));
    assert!(!f.checkpoint(false));
    f.clock.advance(Duration::from_secs(1));
    assert!(f.checkpoint(false), "heartbeat");
    assert_eq!(f.store.checkpoints().len(), n + 1);
    // And again one heartbeat later, still with no operator record.
    f.clock.advance(Duration::from_secs(900));
    assert!(f.checkpoint(false));
    let now = f.clock.now_us_for_test();
    let p = server_policy().with_max_checkpoint_age(HOUR_US, now);
    let r = check(&f, p);
    assert!(r.is_intact(), "{r:?}");
    assert_eq!(r.newest_checkpoint_at_us, Some(now));
    assert_eq!(r.max_checkpoint_age_us, Some(HOUR_US));
}

/// SEC-013: a database owner without the audit key truncates the chain
/// back to an old surviving checkpoint (deleting every later checkpoint
/// and record and moving the head back). The chain and cadence rules
/// cannot see it; the checkpoint age rule can.
#[test]
fn truncation_to_an_old_checkpoint_is_caught_by_checkpoint_age() {
    let f = heartbeat_fixture();
    f.ops(6);
    let kept = f.store.checkpoints().iter().map(|c| c.seq).max().unwrap();
    // A day of activity and heartbeats.
    for _ in 0..24 {
        f.clock.advance(HOUR);
        f.ops(2);
    }
    let now = f.clock.now_us_for_test();
    let p = server_policy().with_max_checkpoint_age(HOUR_US, now);
    assert!(check(&f, p).is_intact());
    assert!(f.store.checkpoints().iter().any(|c| c.seq > kept + 2));

    f.store.tamper_for_test(|recs, cps, head| {
        cps.retain(|c| c.seq <= kept);
        // Keep the checkpoint's own record and one more.
        recs.retain(|r| r.seq <= kept + 2);
        *head = recs.last().map(usgp_audit::ChainHead::from);
    });
    // Without an age limit: intact (the stated limit).
    let r = check(&f, server_policy());
    assert!(r.is_intact(), "{r:?}");
    let r = block_on(verify_store_with_policy(
        &f.store,
        std::slice::from_ref(&f.public),
        7,
        Some(server_policy()),
    ))
    .unwrap();
    assert!(r.is_intact(), "{r:?}");
    // With it: the newest checkpoint is a day old.
    let r = block_on(verify_store_with_policy(
        &f.store,
        std::slice::from_ref(&f.public),
        7,
        Some(p),
    ))
    .unwrap();
    assert_eq!(
        r.findings,
        vec![Finding {
            seq: kept,
            violation: Violation::CheckpointStale
        }]
    );
    assert_eq!(Violation::CheckpointStale.as_str(), "checkpoint_stale");
}

/// SEC-013: records written long after the newest checkpoint are stale
/// too, even if the verifier clock is close to it; a chain with no
/// checkpoint is stale under an age limit.
#[test]
fn checkpoint_age_relative_to_the_last_record_and_without_checkpoints() {
    let f = fixture(1_000, Duration::from_secs(3600));
    f.op_append_only(1);
    let now = f.clock.now_us_for_test();
    let r = check(&f, server_policy().with_max_checkpoint_age(HOUR_US, now));
    assert_eq!(
        r.first_finding().unwrap().violation,
        Violation::CheckpointStale
    );

    let f = heartbeat_fixture();
    f.ops(4);
    let signed_at = f.store.checkpoints().last().unwrap().signed_at_us;
    f.clock.advance(HOUR * 2);
    f.op_append_only(9);
    // Verifier clock set back to the checkpoint time: the last record is
    // still two hours newer than the newest checkpoint.
    let r = check(
        &f,
        server_policy().with_max_checkpoint_age(HOUR_US, signed_at),
    );
    assert_eq!(
        r.first_finding().unwrap().violation,
        Violation::CheckpointStale
    );
}
