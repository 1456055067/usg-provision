//! In-memory audit store for tests (plan WU-2; used by `usgp-api` tests
//! through the `usgp-db` memory repository).
//!
//! Transactions buffer their writes and apply them on
//! [`MemoryAuditTx::commit`]; dropping a transaction rolls it back.
//! Appends are serialised optimistically: a commit whose head moved
//! since `lock_head` fails with [`StoreErrorKind::Conflict`]. PostgreSQL
//! blocks on `FOR UPDATE` instead; both give one total order.
//!
//! Fault injection ([`MemoryAuditStore::fail_next_writes`],
//! [`MemoryAuditStore::set_fail_writes`]) lets callers test that an
//! audit write failure refuses the action (REQ-AUD-006).
//!
//! Not for production: nothing here is durable.

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-5 (Response to Audit Logging Process Failures) -
//   fault injection for the fail-closed tests.
// - SPEC: specs/operator-access.md#REQ-AUD-006

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::checkpoint::Checkpoint;
use crate::error::{AuditError, StoreError, StoreErrorKind};
use crate::record::{AuditRecord, ChainHead};
use crate::store::{AuditRead, AuditTx, Clock};

#[derive(Debug, Default)]
struct State {
    records: Vec<AuditRecord>,
    checkpoints: Vec<Checkpoint>,
    head: Option<ChainHead>,
    fail_next: u32,
    fail_all: bool,
}

impl State {
    fn injected_fault(&mut self) -> Result<(), StoreError> {
        if self.fail_all {
            return Err(StoreError::new(StoreErrorKind::Injected, "memory write"));
        }
        if self.fail_next > 0 {
            self.fail_next -= 1;
            return Err(StoreError::new(StoreErrorKind::Injected, "memory write"));
        }
        Ok(())
    }
}

/// A shared in-memory audit store.
#[derive(Debug, Clone, Default)]
pub struct MemoryAuditStore {
    inner: Arc<Mutex<State>>,
}

impl MemoryAuditStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts a transaction.
    #[must_use]
    pub fn begin(&self) -> MemoryAuditTx {
        MemoryAuditTx {
            store: self.clone(),
            base: None,
            working: None,
            records: Vec::new(),
            checkpoints: Vec::new(),
        }
    }

    /// The committed records.
    #[must_use]
    pub fn records(&self) -> Vec<AuditRecord> {
        self.state().records.clone()
    }

    /// The committed checkpoints.
    #[must_use]
    pub fn checkpoints(&self) -> Vec<Checkpoint> {
        self.state().checkpoints.clone()
    }

    /// The committed head.
    #[must_use]
    pub fn current_head(&self) -> Option<ChainHead> {
        self.state().head
    }

    /// Makes the next `n` writes (record or checkpoint inserts) fail.
    pub fn fail_next_writes(&self, n: u32) {
        self.state().fail_next = n;
    }

    /// Makes every write fail while `on`.
    pub fn set_fail_writes(&self, on: bool) {
        self.state().fail_all = on;
    }

    /// Gives a test direct access to the stored rows, to simulate an
    /// attacker with database access.
    pub fn tamper_for_test(
        &self,
        f: impl FnOnce(&mut Vec<AuditRecord>, &mut Vec<Checkpoint>, &mut Option<ChainHead>),
    ) {
        let mut s = self.state();
        let State {
            records,
            checkpoints,
            head,
            ..
        } = &mut *s;
        f(records, checkpoints, head);
    }
}

/// One transaction on a [`MemoryAuditStore`].
#[derive(Debug)]
pub struct MemoryAuditTx {
    store: MemoryAuditStore,
    /// The committed head seen by `lock_head` (outer `None`: not read).
    base: Option<Option<ChainHead>>,
    working: Option<ChainHead>,
    records: Vec<AuditRecord>,
    checkpoints: Vec<Checkpoint>,
}

impl MemoryAuditTx {
    /// Applies the buffered writes.
    ///
    /// # Errors
    ///
    /// [`StoreErrorKind::Conflict`] if another transaction moved the head
    /// first; nothing is applied then.
    pub fn commit(self) -> Result<(), StoreError> {
        let Some(base) = self.base else {
            return Ok(());
        };
        let mut s = self.store.state();
        if s.head != base {
            return Err(StoreError::new(
                StoreErrorKind::Conflict,
                "audit head moved",
            ));
        }
        s.records.extend(self.records);
        s.checkpoints.extend(self.checkpoints);
        s.head = self.working;
        Ok(())
    }

    /// Discards the buffered writes (same as dropping).
    pub fn rollback(self) {}
}

impl AuditTx for MemoryAuditTx {
    async fn lock_head(&mut self) -> Result<Option<ChainHead>, StoreError> {
        if self.base.is_none() {
            let head = self.store.state().head;
            self.base = Some(head);
            self.working = head;
        }
        Ok(self.working)
    }

    async fn insert_record(&mut self, record: &AuditRecord) -> Result<(), StoreError> {
        if self.base.is_none() {
            return Err(StoreError::new(
                StoreErrorKind::Conflict,
                "insert_record without lock_head",
            ));
        }
        self.store.state().injected_fault()?;
        self.records.push(record.clone());
        self.working = Some(ChainHead::from(record));
        Ok(())
    }

    async fn insert_checkpoint(&mut self, checkpoint: &Checkpoint) -> Result<(), StoreError> {
        self.store.state().injected_fault()?;
        self.checkpoints.push(checkpoint.clone());
        Ok(())
    }

    async fn last_checkpoint(&mut self) -> Result<Option<Checkpoint>, StoreError> {
        if let Some(c) = self.checkpoints.iter().max_by_key(|c| c.seq) {
            return Ok(Some(c.clone()));
        }
        Ok(self
            .store
            .state()
            .checkpoints
            .iter()
            .max_by_key(|c| c.seq)
            .cloned())
    }
}

impl AuditRead for MemoryAuditStore {
    async fn head(&self) -> Result<Option<ChainHead>, StoreError> {
        Ok(self.state().head)
    }

    async fn records_after(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<AuditRecord>, StoreError> {
        let mut out: Vec<AuditRecord> = self
            .state()
            .records
            .iter()
            .filter(|r| r.seq > after_seq)
            .cloned()
            .collect();
        out.sort_by_key(|r| r.seq);
        out.truncate(limit);
        Ok(out)
    }

    async fn checkpoints(&self) -> Result<Vec<Checkpoint>, StoreError> {
        let mut out = self.state().checkpoints.clone();
        out.sort_by_key(|c| c.seq);
        Ok(out)
    }
}

/// A settable clock for tests.
#[derive(Debug, Default)]
pub struct ManualClock {
    now_us: AtomicI64,
}

impl ManualClock {
    /// A clock at `now_us`.
    #[must_use]
    pub const fn new(now_us: i64) -> Self {
        Self {
            now_us: AtomicI64::new(now_us),
        }
    }

    /// Sets the time.
    pub fn set(&self, now_us: i64) {
        self.now_us.store(now_us, Ordering::SeqCst);
    }

    /// Moves the time forward by `by`.
    pub fn advance(&self, by: Duration) {
        let us = i64::try_from(by.as_micros()).unwrap_or(i64::MAX);
        let _ = self
            .now_us
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |t| {
                Some(t.saturating_add(us))
            });
    }
}

impl Clock for ManualClock {
    fn now_us(&self) -> Result<i64, AuditError> {
        Ok(self.now_us.load(Ordering::SeqCst))
    }
}
