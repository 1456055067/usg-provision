//! Shared fixtures: a memory-store chain built through the public API.

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use usgp_audit::memory::{ManualClock, MemoryAuditStore};
use usgp_audit::{
    Actor, AuditChain, AuditDraft, CheckpointPolicy, Checkpointer, Detail, Interface, Outcome,
};
use usgp_crypto::{SigningKey, VerifyingKey};

/// Runs a future that never waits (the memory store completes at once).
pub fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("memory store future was pending"),
    }
}

pub struct Fixture {
    pub store: MemoryAuditStore,
    pub chain: AuditChain,
    pub checkpointer: Checkpointer,
    pub clock: Arc<ManualClock>,
    pub public: VerifyingKey,
}

pub const T0: i64 = 1_800_000_000_000_000;

pub fn fixture(every_records: u64, every: Duration) -> Fixture {
    fixture_with(CheckpointPolicy {
        every_records,
        every,
        // Fixtures advance the clock by hours at most.
        heartbeat: usgp_audit::checkpoint::MAX_HEARTBEAT,
    })
}

pub fn fixture_with(policy: CheckpointPolicy) -> Fixture {
    let clock = Arc::new(ManualClock::new(T0));
    let chain = AuditChain::with_clock("ctl-01", clock.clone()).unwrap();
    let key = SigningKey::generate().unwrap();
    let public = key.verifying_key().clone();
    let checkpointer = Checkpointer::new(key, policy).unwrap();
    let store = MemoryAuditStore::new();
    let mut tx = store.begin();
    let g = block_on(chain.ensure_genesis(&mut tx, &checkpointer.key_id())).unwrap();
    assert!(g.is_some());
    tx.commit().unwrap();
    Fixture {
        store,
        chain,
        checkpointer,
        clock,
        public,
    }
}

pub fn op_draft(i: usize) -> AuditDraft {
    AuditDraft::new(
        "package.created",
        Outcome::Success,
        Actor::operator("0f8e5c3a-0000-4000-8000-000000000001", "Alice; cert ab12"),
        Interface::Api,
    )
    .source("192.0.2.10:50000")
    .target("package", &format!("pkg-{i}"))
    .detail(Detail::new().with("n", &i))
}

impl Fixture {
    /// One operator action: append in its own transaction and commit,
    /// then a checkpoint pass in another, as the server does.
    pub fn op(&self, i: usize) {
        self.clock.advance(Duration::from_millis(1));
        let mut tx = self.store.begin();
        block_on(self.chain.append(&mut tx, &op_draft(i))).unwrap();
        tx.commit().unwrap();
        self.checkpoint(false);
    }

    pub fn checkpoint(&self, force: bool) -> bool {
        let mut tx = self.store.begin();
        let w = block_on(
            self.checkpointer
                .checkpoint_if_due(&self.chain, &mut tx, force),
        )
        .unwrap();
        tx.commit().unwrap();
        w.is_some()
    }

    pub fn ops(&self, n: usize) {
        for i in 0..n {
            self.op(i);
        }
    }
}

impl Fixture {
    /// Appends and commits without a checkpoint pass.
    pub fn op_append_only(&self, i: usize) {
        let mut tx = self.store.begin();
        block_on(self.chain.append(&mut tx, &op_draft(i))).unwrap();
        tx.commit().unwrap();
    }
}

/// Reads a manual clock in tests.
pub trait NowForTest {
    fn now_us_for_test(&self) -> i64;
}

impl NowForTest for ManualClock {
    fn now_us_for_test(&self) -> i64 {
        use usgp_audit::Clock as _;
        self.now_us().unwrap()
    }
}
