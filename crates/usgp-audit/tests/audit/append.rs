//! Appending: fail closed on store failure (REQ-AUD-006), serialised
//! appends, draft validation, genesis, and no key material in records
//! (REQ-AUD-003).

use std::sync::Arc;
use std::time::Duration;

use usgp_audit::canonical::encode;
use usgp_audit::memory::{ManualClock, MemoryAuditStore};
use usgp_audit::mirror::mirror_fields;
use usgp_audit::{
    Actor, AuditChain, AuditDraft, AuditError, CheckpointPolicy, Checkpointer, EVENT_GENESIS,
    Interface, Outcome, StoreErrorKind, verify_chain,
};
use usgp_crypto::SigningKey;

use super::common::{NowForTest, T0, block_on, fixture, op_draft};

#[test]
fn store_failure_refuses_and_changes_nothing() {
    let f = fixture(1000, Duration::from_secs(3600));
    f.ops(3);
    let before = f.store.records();
    f.store.fail_next_writes(1);
    let mut tx = f.store.begin();
    let r = block_on(f.chain.append(&mut tx, &op_draft(9)));
    match r {
        Err(AuditError::Store(e)) => assert_eq!(e.kind(), StoreErrorKind::Injected),
        other => panic!("expected a store error, got {other:?}"),
    }
    // The caller rolls back: nothing was written.
    tx.rollback();
    assert_eq!(f.store.records(), before);
    // The chain continues intact afterwards.
    f.op(10);
    let r = verify_chain(
        &f.store.records(),
        &f.store.checkpoints(),
        std::slice::from_ref(&f.public),
    )
    .unwrap();
    assert!(r.is_intact(), "{r:?}");
}

#[test]
fn persistent_failure_refuses_every_append() {
    let f = fixture(1000, Duration::from_secs(3600));
    f.store.set_fail_writes(true);
    for i in 0..3 {
        let mut tx = f.store.begin();
        assert!(block_on(f.chain.append(&mut tx, &op_draft(i))).is_err());
    }
    f.store.set_fail_writes(false);
    assert_eq!(f.store.records().len(), 1);
}

#[test]
fn rolled_back_append_leaves_no_record() {
    let f = fixture(1000, Duration::from_secs(3600));
    let mut tx = f.store.begin();
    let rec = block_on(f.chain.append(&mut tx, &op_draft(1))).unwrap();
    assert_eq!(rec.seq, 2);
    drop(tx);
    assert_eq!(f.store.records().len(), 1);
    assert_eq!(f.store.current_head().unwrap().seq, 1);
}

#[test]
fn concurrent_appends_are_serialised() {
    let f = fixture(1000, Duration::from_secs(3600));
    let mut a = f.store.begin();
    let mut b = f.store.begin();
    let ra = block_on(f.chain.append(&mut a, &op_draft(1))).unwrap();
    let rb = block_on(f.chain.append(&mut b, &op_draft(2))).unwrap();
    assert_eq!(ra.seq, rb.seq);
    a.commit().unwrap();
    let e = b.commit().unwrap_err();
    assert_eq!(e.kind(), StoreErrorKind::Conflict);
    assert_eq!(f.store.records().len(), 2);
}

#[test]
fn invalid_draft_refused_before_the_store() {
    let f = fixture(1000, Duration::from_secs(3600));
    let d = AuditDraft::new(
        "authz.denied",
        Outcome::Refused,
        Actor::unauthenticated(None),
        Interface::Api,
    );
    let mut tx = f.store.begin();
    assert!(matches!(
        block_on(f.chain.append(&mut tx, &d)),
        Err(AuditError::InvalidDraft {
            field: "reason",
            ..
        })
    ));
    tx.commit().unwrap();
    assert_eq!(f.store.records().len(), 1);
}

#[test]
fn genesis_first_and_once() {
    let store = MemoryAuditStore::new();
    let chain = AuditChain::with_clock("n", Arc::new(ManualClock::new(T0))).unwrap();
    let mut tx = store.begin();
    assert!(matches!(
        block_on(chain.append(&mut tx, &op_draft(1))),
        Err(AuditError::NotInitialised)
    ));
    let key = SigningKey::generate().unwrap();
    let g = block_on(chain.ensure_genesis(&mut tx, &key.key_id()))
        .unwrap()
        .unwrap();
    assert_eq!((g.seq, g.event.as_str(), g.ts_us), (1, EVENT_GENESIS, T0));
    assert!(g.detail.contains(&key.key_id().to_hex()));
    assert!(
        block_on(chain.ensure_genesis(&mut tx, &key.key_id()))
            .unwrap()
            .is_none()
    );
    tx.commit().unwrap();
}

#[test]
fn record_carries_au3_fields_and_initiating_seq() {
    let f = fixture(1000, Duration::from_secs(3600));
    let d = AuditDraft::new(
        "content.ready",
        Outcome::Success,
        Actor::system(),
        Interface::System,
    )
    .target("content", "c-1")
    .initiated_by(1);
    let mut tx = f.store.begin();
    let r = block_on(f.chain.append(&mut tx, &d)).unwrap();
    tx.commit().unwrap();
    assert_eq!(r.initiating_seq, Some(1));
    assert_eq!(r.node, "ctl-01");
    assert_eq!(r.interface, "system");
    assert_eq!(r.outcome, "success");
    assert_eq!(r.ts_us, f.clock.now_us_for_test());
    let o = op_draft(4);
    let mut tx = f.store.begin();
    let r = block_on(f.chain.append(&mut tx, &o)).unwrap();
    assert_eq!(r.actor_kind, "operator");
    assert_eq!(r.source.as_deref(), Some("192.0.2.10:50000"));
    assert_eq!(r.target_kind.as_deref(), Some("package"));
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn detail_never_contains_key_material() {
    let key = SigningKey::generate().unwrap();
    let der = key.to_pkcs8_der().unwrap();
    let pem = key.to_pkcs8_pem().unwrap();
    let pem_text = String::from_utf8(pem.to_vec()).unwrap();
    let der_hex: String = der.iter().map(|b| format!("{b:02x}")).collect();
    let chain = AuditChain::with_clock("n", Arc::new(ManualClock::new(T0))).unwrap();
    let cp = Checkpointer::new(
        SigningKey::from_pkcs8_der(&der).unwrap(),
        CheckpointPolicy {
            every_records: 2,
            every: Duration::from_secs(60),
            ..CheckpointPolicy::default()
        },
    )
    .unwrap();
    let store = MemoryAuditStore::new();
    let mut tx = store.begin();
    block_on(chain.ensure_genesis(&mut tx, &cp.key_id())).unwrap();
    tx.commit().unwrap();
    for i in 0..6 {
        let mut tx = store.begin();
        block_on(chain.append(&mut tx, &op_draft(i))).unwrap();
        block_on(cp.checkpoint_if_due(&chain, &mut tx, false)).unwrap();
        tx.commit().unwrap();
    }
    assert!(!store.checkpoints().is_empty());
    // The private scalar sits at the end of the PKCS#8 body; check
    // 16-byte windows of the whole DER, the hex form, and PEM lines.
    let mut texts: Vec<Vec<u8>> = Vec::new();
    for r in store.records() {
        texts.push(encode(&r).unwrap());
        for (_, v) in mirror_fields(&r, true) {
            texts.push(v.into_bytes());
        }
    }
    texts.push(format!("{cp:?}").into_bytes());
    for t in &texts {
        for w in der.chunks(16).filter(|c| c.len() == 16) {
            assert!(!contains(t, w));
        }
        assert!(!contains(t, der_hex.as_bytes()));
        for line in pem_text.lines().filter(|l| !l.starts_with("-----")) {
            assert!(!contains(t, line.as_bytes()));
        }
    }
}
