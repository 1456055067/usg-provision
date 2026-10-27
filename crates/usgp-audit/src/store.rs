//! The storage interface `usgp-db` implements (WU-3a), and the clock.
//!
//! The chain logic never talks to a database. A backend provides:
//!
//! - [`AuditTx`]: the audit part of **the caller's own transaction**. A
//!   repository method opens one transaction, makes its state change,
//!   calls [`crate::chain::AuditChain::append`] with an `AuditTx` bound
//!   to that same transaction, and commits. If the append fails, the
//!   method rolls back and the action is refused (decision 0015 item 1,
//!   REQ-AUD-006). Nothing in this crate commits or rolls back.
//! - [`AuditRead`]: read access for the local verifier command
//!   (REQ-AUD-007).
//!
//! PostgreSQL mapping (plan section 3.4):
//!
//! - `lock_head`: `SELECT seq, record_hash FROM audit_head WHERE id = 1
//!   FOR UPDATE` (no row, or a row with `seq = 0`, means an empty chain).
//!   The lock serialises appends until the transaction ends.
//! - `insert_record`: `INSERT INTO audit_record` with every
//!   [`AuditRecord`] field, then upsert `audit_head` to the record's
//!   `(seq, record_hash)`, both in the transaction.
//! - `insert_checkpoint`: `INSERT INTO audit_checkpoint`.
//! - `last_checkpoint`: the row with the highest `seq`, or none.

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-9 (Protection of Audit Information) - appends only;
//   the interface has no update or delete.
// - NIST 800-53: AU-5 (Response to Audit Logging Process Failures) - the
//   record is written in the transaction of the change it records.
// - NIST 800-53: AU-8 (Time Stamps) - UTC microseconds from the system
//   clock.
// - SPEC: specs/operator-access.md#REQ-AUD-005, #REQ-AUD-006, #REQ-AUD-007

use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::checkpoint::Checkpoint;
use crate::error::{AuditError, StoreError};
use crate::record::{AuditRecord, ChainHead};

/// The audit operations available inside one storage transaction.
///
/// Implementations must make every write part of the caller's
/// transaction, so a rollback removes the record together with the
/// change it records.
pub trait AuditTx: Send {
    /// Reads the chain head and locks it until the transaction ends.
    /// `None` means the chain is empty.
    fn lock_head(&mut self) -> impl Future<Output = Result<Option<ChainHead>, StoreError>> + Send;

    /// Inserts `record` and moves the head to `(record.seq,
    /// record.record_hash)`.
    fn insert_record(
        &mut self,
        record: &AuditRecord,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Inserts a signed checkpoint.
    fn insert_checkpoint(
        &mut self,
        checkpoint: &Checkpoint,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// The checkpoint with the highest `seq`, if any.
    fn last_checkpoint(
        &mut self,
    ) -> impl Future<Output = Result<Option<Checkpoint>, StoreError>> + Send;
}

/// Read access for verification.
pub trait AuditRead: Sync {
    /// The current head, or `None` for an empty chain.
    fn head(&self) -> impl Future<Output = Result<Option<ChainHead>, StoreError>> + Send;

    /// Up to `limit` records with `seq > after_seq`, in ascending `seq`.
    fn records_after(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<AuditRecord>, StoreError>> + Send;

    /// Every stored checkpoint, in ascending `seq`.
    fn checkpoints(&self) -> impl Future<Output = Result<Vec<Checkpoint>, StoreError>> + Send;
}

/// Source of record timestamps.
pub trait Clock: Send + Sync {
    /// UTC microseconds since 1970-01-01.
    ///
    /// # Errors
    ///
    /// [`AuditError::Clock`] if the time is not representable.
    fn now_us(&self) -> Result<i64, AuditError>;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_us(&self) -> Result<i64, AuditError> {
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AuditError::Clock)?;
        i64::try_from(d.as_micros()).map_err(|_| AuditError::Clock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_is_after_2020() {
        // 2020-01-01T00:00:00Z in microseconds.
        assert!(SystemClock.now_us().unwrap() > 1_577_836_800_000_000);
    }
}
