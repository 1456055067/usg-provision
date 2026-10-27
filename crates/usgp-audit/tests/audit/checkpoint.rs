//! Signed checkpoints: cadence, signature, domain separation, and the
//! mirrored checkpoint record as an external anchor.

use std::collections::BTreeMap;
use std::time::Duration;

use usgp_audit::checkpoint::MAX_CHECKPOINT_SIGNATURE_LEN;
use usgp_audit::memory::MemoryAuditStore;
use usgp_audit::{
    AuditChain, AuditError, CHECKPOINT_PAYLOAD_TYPE, ChainHead, Checkpoint, CheckpointFault,
    CheckpointPolicy, Checkpointer, EVENT_CHECKPOINT,
};
use usgp_common::Sha256Digest;
use usgp_crypto::{KeyId, SigningKey, sign_typed};

use super::common::{block_on, fixture};

fn cp_seqs(f: &super::common::Fixture) -> Vec<u64> {
    f.store.checkpoints().iter().map(|c| c.seq).collect()
}

#[test]
fn every_n_records() {
    let f = fixture(5, Duration::from_secs(3600));
    f.ops(40);
    let seqs = cp_seqs(&f);
    assert!(seqs.len() >= 6, "{seqs:?}");
    // First on the timer (no checkpoint yet), then every 5 records plus
    // the checkpoint's own record.
    for w in seqs.windows(2) {
        assert_eq!(w[1] - w[0], 6, "{seqs:?}");
    }
    let last = f.store.current_head().unwrap().seq;
    assert!(last - (seqs.last().unwrap() + 1) < 5);
}

#[test]
fn timer_checkpoints_only_new_records() {
    let f = fixture(1000, Duration::from_secs(10));
    f.ops(3);
    assert_eq!(cp_seqs(&f), vec![2]);
    assert!(!f.checkpoint(false), "timer not elapsed");
    f.clock.advance(Duration::from_secs(10));
    assert!(f.checkpoint(false));
    // Idle: only the checkpoint's own record is new.
    f.clock.advance(Duration::from_secs(60));
    assert!(!f.checkpoint(false));
    // A new record after the interval has passed is checkpointed at once.
    f.op_append_only(9);
    assert!(f.checkpoint(false));
    // A new record within the interval waits for it.
    f.op_append_only(10);
    assert!(!f.checkpoint(false));
    f.clock.advance(Duration::from_secs(10));
    assert!(f.checkpoint(false));
}

#[test]
fn shutdown_forces_checkpoint_of_new_records() {
    let f = fixture(1000, Duration::from_secs(3600));
    f.ops(2);
    assert!(f.checkpoint(true));
    let head = f.store.current_head().unwrap();
    let last = f.store.checkpoints().last().unwrap().clone();
    assert_eq!(last.seq + 1, head.seq);
    assert!(
        !f.checkpoint(true),
        "nothing new after the forced checkpoint"
    );
}

#[test]
fn empty_chain_has_no_checkpoint() {
    let store = MemoryAuditStore::new();
    let chain = AuditChain::new("n").unwrap();
    let cp =
        Checkpointer::new(SigningKey::generate().unwrap(), CheckpointPolicy::default()).unwrap();
    let mut tx = store.begin();
    assert!(
        block_on(cp.checkpoint_if_due(&chain, &mut tx, true))
            .unwrap()
            .is_none()
    );
}

#[test]
fn bad_policy_refused() {
    let k = SigningKey::generate().unwrap();
    let p = CheckpointPolicy {
        every_records: 1_000_001,
        every: Duration::from_secs(60),
        ..CheckpointPolicy::default()
    };
    assert!(matches!(
        Checkpointer::new(k, p),
        Err(AuditError::Config { .. })
    ));
}

#[test]
fn signature_binds_every_field_and_the_type() {
    let k = SigningKey::generate().unwrap();
    let trusted = [k.verifying_key().clone()];
    let head = ChainHead {
        seq: 42,
        record_hash: Sha256Digest([3; 32]),
    };
    let cp = Checkpoint::sign(&k, &head, 1_000).unwrap();
    assert_eq!(cp.key_id, k.key_id());
    assert_eq!(cp.verify(&trusted), Ok(()));

    let edits: [fn(&mut Checkpoint); 4] = [
        |c| c.seq += 1,
        |c| c.record_hash = Sha256Digest([4; 32]),
        |c| c.signed_at_us += 1,
        |c| c.signature[10] ^= 1,
    ];
    for e in edits {
        let mut c = cp.clone();
        e(&mut c);
        assert_eq!(c.verify(&trusted), Err(CheckpointFault::BadSignature));
    }

    let mut c = cp.clone();
    c.key_id = KeyId(Sha256Digest([5; 32]));
    assert_eq!(c.verify(&trusted), Err(CheckpointFault::UntrustedKey));

    let mut c = cp.clone();
    c.signature = vec![0; MAX_CHECKPOINT_SIGNATURE_LEN + 1];
    assert_eq!(c.verify(&trusted), Err(CheckpointFault::BadSignature));

    // A signature over the same bytes under another payload type (for
    // example a content manifest) is not a checkpoint signature.
    let mut c = cp.clone();
    c.signature = sign_typed(
        &k,
        "application/vnd.usgp.content-manifest.v1+json",
        &cp.signed_bytes(),
    )
    .unwrap();
    assert_eq!(c.verify(&trusted), Err(CheckpointFault::BadSignature));
    assert_eq!(
        CHECKPOINT_PAYLOAD_TYPE,
        "application/vnd.usgp.audit-checkpoint.v1"
    );
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn checkpoint_record_carries_a_verifiable_checkpoint() {
    let f = fixture(3, Duration::from_secs(3600));
    f.ops(6);
    let recs = f.store.records();
    let stored = f.store.checkpoints();
    for cp in &stored {
        let rec = recs.iter().find(|r| r.seq == cp.seq + 1).unwrap();
        assert_eq!(rec.event, EVENT_CHECKPOINT);
        assert_eq!(rec.actor_kind, "system");
        assert_eq!(rec.target_id.as_deref(), Some(cp.seq.to_string().as_str()));
        // What an external party sees on the mirrored line is enough to
        // rebuild and verify the checkpoint without the database.
        let d: BTreeMap<String, String> = serde_json::from_str(&rec.detail).unwrap();
        assert_eq!(d["alg"], "ecdsa-p384-sha384");
        let rebuilt = Checkpoint {
            seq: d["checkpoint_seq"].parse().unwrap(),
            record_hash: Sha256Digest::from_hex(&d["record_hash"]).unwrap(),
            signed_at_us: d["signed_at_us"].parse().unwrap(),
            key_id: KeyId::from_hex(&d["key_id"]).unwrap(),
            signature: hex_decode(&d["signature"]),
        };
        assert_eq!(&rebuilt, cp);
        assert_eq!(rebuilt.verify(std::slice::from_ref(&f.public)), Ok(()));
    }
}

#[test]
fn checkpoint_store_failure_changes_nothing() {
    let f = fixture(1, Duration::from_secs(3600));
    f.ops(2);
    let before = (f.store.records(), f.store.checkpoints());
    f.op_append_only(7);
    let before_cp = f.store.checkpoints();
    f.store.fail_next_writes(1);
    let mut tx = f.store.begin();
    let r = block_on(f.checkpointer.checkpoint_if_due(&f.chain, &mut tx, false));
    assert!(matches!(r, Err(AuditError::Store(_))));
    drop(tx);
    assert_eq!(f.store.checkpoints(), before_cp);
    assert_eq!(f.store.records().len(), before.0.len() + 1);
    // The next pass succeeds.
    assert!(f.checkpoint(false));
}
