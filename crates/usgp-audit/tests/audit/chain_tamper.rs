//! REQ-AUD-005: modification, deletion, reordering, insertion and a
//! fully recomputed chain are each detected at the right seq.

use std::time::Duration;

use usgp_audit::canonical::compute_record_hash;
use usgp_audit::{
    AuditRecord, ChainHead, Checkpoint, EVENT_CHECKPOINT, Finding, Violation, seal, verify_chain,
    verify_store,
};
use usgp_crypto::SigningKey;

use super::common::{Fixture, block_on, fixture, op_draft};

/// 1 genesis + 11 ops, checkpoint every 3 records, long timer:
/// checkpoints at 2, 6, 10, 14 (records 3, 7, 11, 15), last seq 16.
fn chain() -> Fixture {
    let f = fixture(3, Duration::from_secs(3600));
    f.ops(11);
    f
}

fn verify(f: &Fixture, records: &[AuditRecord], cps: &[Checkpoint]) -> usgp_audit::VerifyReport {
    verify_chain(records, cps, std::slice::from_ref(&f.public)).unwrap()
}

fn idx(records: &[AuditRecord], seq: u64) -> usize {
    records.iter().position(|r| r.seq == seq).unwrap()
}

/// Re-links and re-hashes every record from position `from`, as an
/// attacker without the audit key would.
fn rechain(records: &mut [AuditRecord], from: usize) {
    for i in from..records.len() {
        if i > 0 {
            records[i].prev_hash = records[i - 1].record_hash;
        }
        records[i].record_hash = compute_record_hash(&records[i]).unwrap();
    }
}

fn first(report: &usgp_audit::VerifyReport) -> Finding {
    *report.first_finding().expect("a finding")
}

#[test]
fn intact_chain_verifies_and_reports_tail() {
    let f = chain();
    let recs = f.store.records();
    let cps = f.store.checkpoints();
    assert!(!cps.is_empty());
    let r = verify(&f, &recs, &cps);
    assert!(r.is_intact(), "{r:?}");
    assert_eq!(r.records_checked, recs.len() as u64);
    assert_eq!(r.checkpoints_matched, cps.len() as u64);
    let last_cp = cps.iter().map(|c| c.seq).max().unwrap();
    assert_eq!(r.last_checkpoint_seq, Some(last_cp));
    assert_eq!(r.unsigned_tail, r.last_seq.unwrap() - last_cp);
    // Every checkpoint is followed by its own chain record.
    for c in &cps {
        assert_eq!(recs[idx(&recs, c.seq + 1)].event, EVENT_CHECKPOINT);
    }
}

#[test]
fn modified_record_detected_at_its_seq() {
    let f = chain();
    let mut recs = f.store.records();
    let i = idx(&recs, 5);
    recs[i].actor_label = Some("Mallory".into());
    let r = verify(&f, &recs, &f.store.checkpoints());
    assert_eq!(
        r.findings,
        vec![Finding {
            seq: 5,
            violation: Violation::RecordHashMismatch
        }]
    );

    // Each stored field is covered by the hash.
    let base = f.store.records();
    let edits: [fn(&mut AuditRecord); 8] = [
        |r| r.ts_us += 1,
        |r| r.outcome = "failure".into(),
        |r| r.detail = r.detail.replace("\"n\"", "\"m\""),
        |r| r.source = None,
        |r| r.interface = "server-cli".into(),
        |r| r.node = "other".into(),
        |r| r.initiating_seq = Some(2),
        |r| r.event = "package.deleted".into(),
    ];
    for edit in edits {
        let mut recs = base.clone();
        let i = idx(&recs, 6);
        edit(&mut recs[i]);
        let r = verify(&f, &recs, &f.store.checkpoints());
        assert_eq!(first(&r).seq, 6);
        assert_eq!(first(&r).violation, Violation::RecordHashMismatch);
    }
}

#[test]
fn deleted_record_detected() {
    let f = chain();
    let mut recs = f.store.records();
    let i = idx(&recs, 5);
    recs.remove(i);
    let r = verify(&f, &recs, &f.store.checkpoints());
    assert_eq!(
        first(&r),
        Finding {
            seq: 6,
            violation: Violation::SeqNotContiguous {
                expected: 5,
                found: 6
            }
        }
    );
    assert!(r.findings.contains(&Finding {
        seq: 6,
        violation: Violation::PrevHashMismatch
    }));
}

#[test]
fn deleted_genesis_detected() {
    let f = chain();
    let mut recs = f.store.records();
    recs.remove(0);
    let r = verify(&f, &recs, &f.store.checkpoints());
    assert_eq!(
        first(&r).violation,
        Violation::SeqNotContiguous {
            expected: 1,
            found: 2
        }
    );
}

#[test]
fn reordered_records_detected() {
    let f = chain();
    // Rows returned in a different order.
    let mut recs = f.store.records();
    let (a, b) = (idx(&recs, 5), idx(&recs, 6));
    recs.swap(a, b);
    let r = verify(&f, &recs, &f.store.checkpoints());
    assert_eq!(first(&r).seq, 5);
    assert!(r.findings.contains(&Finding {
        seq: 6,
        violation: Violation::SeqNotContiguous {
            expected: 5,
            found: 6
        }
    }));

    // Contents swapped between seq 5 and 6, seq numbers kept.
    let mut recs = f.store.records();
    let (a, b) = (idx(&recs, 5), idx(&recs, 6));
    let (ra, rb) = (recs[a].clone(), recs[b].clone());
    recs[a] = AuditRecord { seq: 5, ..rb };
    recs[b] = AuditRecord { seq: 6, ..ra };
    let r = verify(&f, &recs, &f.store.checkpoints());
    assert_eq!(first(&r).seq, 5);
    assert!(r.findings.iter().any(|x| x.seq == 6));
}

#[test]
fn inserted_record_detected() {
    let f = chain();
    let mut recs = f.store.records();
    let i4 = idx(&recs, 4);
    // A well-formed record chained onto seq 4 by someone without the key.
    let forged = seal(
        Some(&ChainHead::from(&recs[i4])),
        &op_draft(99),
        1,
        "ctl-01",
    )
    .unwrap();
    assert_eq!(forged.seq, 5);
    recs.insert(i4 + 1, forged.clone());
    let r = verify(&f, &recs, &f.store.checkpoints());
    // The original seq 5 now follows the forged one.
    assert_eq!(
        first(&r),
        Finding {
            seq: 5,
            violation: Violation::SeqNotContiguous {
                expected: 6,
                found: 5
            }
        }
    );
    assert!(r.findings.contains(&Finding {
        seq: 5,
        violation: Violation::PrevHashMismatch
    }));

    // Inserted and every later record renumbered: hashes break.
    let mut recs = f.store.records();
    recs.insert(i4 + 1, forged);
    for r in recs.iter_mut().skip(i4 + 2) {
        r.seq += 1;
    }
    let r = verify(&f, &recs, &f.store.checkpoints());
    assert_eq!(
        first(&r),
        Finding {
            seq: 6,
            violation: Violation::PrevHashMismatch
        }
    );
}

#[test]
fn recomputed_chain_caught_by_checkpoint() {
    let f = chain();
    let cps = f.store.checkpoints();
    let mut recs = f.store.records();
    let i = idx(&recs, 3);
    recs[i].actor_label = Some("Mallory".into());
    rechain(&mut recs, i);
    // The hash chain alone is consistent again (only the checkpoint
    // cross-check complains when no checkpoints are given)...
    let r = verify(&f, &recs, &[]);
    assert!(
        r.findings
            .iter()
            .all(|x| x.violation == Violation::CheckpointRecordUnmatched),
        "{r:?}"
    );
    // ...but the first checkpoint at or after seq 3 no longer matches.
    let r = verify(&f, &recs, &cps);
    let first_cp = cps.iter().map(|c| c.seq).filter(|s| *s >= 3).min().unwrap();
    assert_eq!(
        first(&r),
        Finding {
            seq: first_cp,
            violation: Violation::CheckpointHashMismatch
        }
    );
}

#[test]
fn recomputed_chain_with_checkpoints_deleted_caught_by_checkpoint_records() {
    let f = chain();
    let mut recs = f.store.records();
    let i = idx(&recs, 2);
    recs[i].reason = Some("x".into());
    rechain(&mut recs, i);
    let r = verify(&f, &recs, &[]);
    assert!(!r.is_intact());
    assert!(
        r.findings
            .iter()
            .all(|x| x.violation == Violation::CheckpointRecordUnmatched)
    );
    assert_eq!(r.last_checkpoint_seq, None);
}

#[test]
fn checkpoints_under_another_key_are_not_trusted() {
    let f = chain();
    let recs = f.store.records();
    let cps = f.store.checkpoints();
    let other = SigningKey::generate().unwrap();
    let r = verify_chain(&recs, &cps, std::slice::from_ref(other.verifying_key())).unwrap();
    assert_eq!(
        first(&r).violation,
        Violation::CheckpointUntrustedKey,
        "{r:?}"
    );
    assert_eq!(r.checkpoints_matched, 0);

    // An attacker re-signs a recomputed chain with their own key.
    let mut recs = f.store.records();
    let i = idx(&recs, 3);
    recs[i].detail = "{}".into();
    rechain(&mut recs, i);
    let forged: Vec<Checkpoint> = cps
        .iter()
        .map(|c| {
            let h = ChainHead::from(&recs[idx(&recs, c.seq)]);
            Checkpoint::sign(&other, &h, c.signed_at_us).unwrap()
        })
        .collect();
    let r = verify(&f, &recs, &forged);
    assert!(
        r.findings
            .iter()
            .any(|x| x.violation == Violation::CheckpointUntrustedKey)
    );
    assert!(!r.is_intact());
}

#[test]
fn tampered_checkpoint_signature_detected() {
    let f = chain();
    let recs = f.store.records();
    let mut cps = f.store.checkpoints();
    cps[0].signed_at_us += 1;
    let r = verify(&f, &recs, &cps);
    assert!(r.findings.contains(&Finding {
        seq: cps[0].seq,
        violation: Violation::CheckpointBadSignature
    }));
}

#[test]
fn truncated_tail_reported() {
    let f = chain();
    let recs = f.store.records();
    let cps = f.store.checkpoints();
    let last_cp = cps.iter().map(|c| c.seq).max().unwrap();
    let last = recs.last().unwrap().seq;

    // Tail cut to before the last checkpoint: the checkpoint is beyond it.
    let cut: Vec<_> = recs.iter().filter(|r| r.seq < last_cp).cloned().collect();
    let r = verify(&f, &cut, &cps);
    assert!(r.findings.contains(&Finding {
        seq: last_cp,
        violation: Violation::CheckpointBeyondChain
    }));

    // Tail after the last checkpoint cut, head row not rewritten.
    let keep = last_cp + 1;
    assert!(last > keep, "fixture needs an unsigned tail");
    let cut: Vec<_> = recs.iter().filter(|r| r.seq <= keep).cloned().collect();
    let mut v = usgp_audit::ChainVerifier::new(std::slice::from_ref(&f.public), cps.clone())
        .unwrap()
        .expect_head(f.store.current_head());
    for r in &cut {
        v.push(r);
    }
    let r = v.finish();
    assert_eq!(
        first(&r),
        Finding {
            seq: last,
            violation: Violation::HeadMismatch
        }
    );

    // Stated limit: with the head rewritten too, only the external copy
    // shows it; the report still states the unsigned tail.
    let r = verify(&f, &cut, &cps);
    assert!(r.is_intact());
    assert_eq!(r.last_checkpoint_seq, Some(last_cp));
    assert_eq!(r.unsigned_tail, 1);
}

#[test]
fn verify_store_pages_and_detects_tampering() {
    let f = chain();
    let keys = std::slice::from_ref(&f.public);
    for page in [1, 2, 5, 1000] {
        let r = block_on(verify_store(&f.store, keys, page)).unwrap();
        assert!(r.is_intact(), "page {page}: {r:?}");
        assert_eq!(r.records_checked, f.store.records().len() as u64);
    }
    f.store.tamper_for_test(|recs, _, _| {
        let i = idx(recs, 7);
        recs.remove(i);
    });
    let r = block_on(verify_store(&f.store, keys, 3)).unwrap();
    assert_eq!(
        first(&r).violation,
        Violation::SeqNotContiguous {
            expected: 7,
            found: 8
        }
    );
}

#[test]
fn verify_store_flags_records_after_head() {
    // SEC-002: a record above the stored head that is still there after
    // the head is read again was not appended concurrently (an append
    // moves the head in the same transaction): the head was moved back.
    let f = chain();
    let extra = {
        let recs = f.store.records();
        seal(
            Some(&ChainHead::from(recs.last().unwrap())),
            &op_draft(1),
            1,
            "n",
        )
        .unwrap()
    };
    let extra_seq = extra.seq;
    f.store.tamper_for_test(|recs, _, _| recs.push(extra));
    let r = block_on(verify_store(&f.store, std::slice::from_ref(&f.public), 4)).unwrap();
    assert_eq!(
        r.findings,
        vec![Finding {
            seq: extra_seq,
            violation: Violation::RecordBeyondHead
        }]
    );
}

#[test]
fn many_findings_are_capped() {
    let f = fixture(1_000_000, Duration::from_secs(86_400));
    f.ops(1100);
    let mut recs = f.store.records();
    for r in &mut recs {
        r.node = "x".into();
    }
    let cps = f.store.checkpoints();
    let r = verify_chain(&recs, &cps, std::slice::from_ref(&f.public)).unwrap();
    assert_eq!(r.findings.len(), usgp_audit::verify::MAX_FINDINGS);
    assert_eq!(r.findings_omitted, recs.len() as u64 - 1000);
}
