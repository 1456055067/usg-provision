//! Appending to the hash chain (plan section 5.6).
//!
//! [`AuditChain::append`] runs inside the caller's transaction: it locks
//! the head, seals the draft into the next record, and inserts it. The
//! caller commits the record together with the change it describes, or
//! rolls both back.

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-9 (Protection of Audit Information) - SHA-256 hash
//   chain from a fixed genesis.
// - NIST 800-53: AU-12 (Audit Record Generation) - one append path for
//   every server component.
// - NIST 800-53: AU-5 (Response to Audit Logging Process Failures) - any
//   failure is returned to the caller, which refuses the action.
// - SPEC: specs/operator-access.md#REQ-AUD-001, #REQ-AUD-005, #REQ-AUD-006

use std::sync::Arc;

use usgp_crypto::KeyId;

use crate::canonical::{GENESIS_PREV_HASH, compute_record_hash};
use crate::error::AuditError;
use crate::record::{
    AuditDraft, AuditRecord, ChainHead, Detail, EVENT_GENESIS, MAX_TEXT_LEN, clean_text,
};
use crate::store::{AuditTx, Clock, SystemClock};

/// Highest sequence number (the `bigint` column range).
pub const MAX_SEQ: u64 = i64::MAX.unsigned_abs();

/// Format name written in the genesis record.
pub const CHAIN_FORMAT: &str = "usgp-audit-v1";

/// Seals `draft` into the record that follows `head` (`None` for an empty
/// chain).
///
/// # Errors
///
/// - [`AuditError::InvalidDraft`] from [`AuditDraft::validate`];
/// - [`AuditError::NotInitialised`] if the chain is empty and the draft is
///   not the genesis; [`AuditError::AlreadyInitialised`] for a second
///   genesis;
/// - [`AuditError::ChainFull`] past [`MAX_SEQ`];
/// - [`AuditError::Encoding`] for an unencodable field.
pub fn seal(
    head: Option<&ChainHead>,
    draft: &AuditDraft,
    ts_us: i64,
    node: &str,
) -> Result<AuditRecord, AuditError> {
    let genesis = draft.event() == EVENT_GENESIS;
    let (seq, prev_hash) = match head {
        None if genesis => (1, GENESIS_PREV_HASH),
        None => return Err(AuditError::NotInitialised),
        Some(_) if genesis => return Err(AuditError::AlreadyInitialised),
        Some(h) => (
            h.seq
                .checked_add(1)
                .filter(|s| *s <= MAX_SEQ)
                .ok_or(AuditError::ChainFull)?,
            h.record_hash,
        ),
    };
    let mut record = draft.to_record(seq, ts_us, &clean_text(node, MAX_TEXT_LEN), prev_hash)?;
    record.record_hash = compute_record_hash(&record)?;
    Ok(record)
}

/// The append side of the audit log.
#[derive(Clone)]
pub struct AuditChain {
    node: String,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for AuditChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditChain")
            .field("node", &self.node)
            .finish_non_exhaustive()
    }
}

impl AuditChain {
    /// A chain writer for server `node`, on the system clock.
    ///
    /// # Errors
    ///
    /// [`AuditError::Config`] if `node` is empty.
    pub fn new(node: &str) -> Result<Self, AuditError> {
        Self::with_clock(node, Arc::new(SystemClock))
    }

    /// A chain writer with an explicit clock (tests).
    ///
    /// # Errors
    ///
    /// [`AuditError::Config`] if `node` is empty.
    pub fn with_clock(node: &str, clock: Arc<dyn Clock>) -> Result<Self, AuditError> {
        if node.is_empty() {
            return Err(AuditError::Config {
                what: "node",
                reason: "empty",
            });
        }
        Ok(Self {
            node: clean_text(node, MAX_TEXT_LEN),
            clock,
        })
    }

    /// The node name written on every record.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }

    /// The current time from this chain's clock.
    ///
    /// # Errors
    ///
    /// [`AuditError::Clock`].
    pub fn now_us(&self) -> Result<i64, AuditError> {
        self.clock.now_us()
    }

    /// Appends `draft` in the caller's transaction and returns the stored
    /// record. Mirror it with [`crate::mirror::emit_json`] after commit.
    ///
    /// # Errors
    ///
    /// As [`seal`], plus [`AuditError::Store`] and [`AuditError::Clock`].
    /// On any error the caller must roll back and refuse the action.
    pub async fn append<T: AuditTx>(
        &self,
        tx: &mut T,
        draft: &AuditDraft,
    ) -> Result<AuditRecord, AuditError> {
        // Validate before taking the head lock.
        draft.validate()?;
        let head = tx.lock_head().await?;
        let ts_us = self.clock.now_us()?;
        let record = seal(head.as_ref(), draft, ts_us, &self.node)?;
        tx.insert_record(&record).await?;
        Ok(record)
    }

    /// Writes the genesis record (seq 1, naming the audit key) if the
    /// chain is empty. Returns `None` if a chain already exists.
    ///
    /// # Errors
    ///
    /// As [`AuditChain::append`].
    pub async fn ensure_genesis<T: AuditTx>(
        &self,
        tx: &mut T,
        audit_key_id: &KeyId,
    ) -> Result<Option<AuditRecord>, AuditError> {
        if tx.lock_head().await?.is_some() {
            return Ok(None);
        }
        let draft = genesis_draft(audit_key_id);
        self.append(tx, &draft).await.map(Some)
    }
}

/// The genesis draft: format and audit key id.
fn genesis_draft(audit_key_id: &KeyId) -> AuditDraft {
    let detail = Detail::new()
        .with("format", CHAIN_FORMAT)
        .with("key_id", audit_key_id);
    AuditDraft::internal(EVENT_GENESIS, detail, "1".to_owned())
}

#[cfg(test)]
mod tests {
    use usgp_common::Sha256Digest;
    use usgp_common::event::Outcome;

    use super::*;
    use crate::record::{Actor, Interface};

    fn key_id() -> KeyId {
        KeyId(Sha256Digest([7; 32]))
    }

    fn draft() -> AuditDraft {
        AuditDraft::new("x.y", Outcome::Success, Actor::system(), Interface::System)
    }

    #[test]
    fn genesis_rules() {
        assert!(matches!(
            seal(None, &draft(), 1, "n"),
            Err(AuditError::NotInitialised)
        ));
        let g = seal(None, &genesis_draft(&key_id()), 1, "n").unwrap();
        assert_eq!(g.seq, 1);
        assert_eq!(g.prev_hash, GENESIS_PREV_HASH);
        assert_eq!(g.event, EVENT_GENESIS);
        assert!(g.detail.contains(&key_id().to_hex()));
        let head = ChainHead::from(&g);
        assert!(matches!(
            seal(Some(&head), &genesis_draft(&key_id()), 2, "n"),
            Err(AuditError::AlreadyInitialised)
        ));
        let r = seal(Some(&head), &draft(), 2, "n").unwrap();
        assert_eq!(r.seq, 2);
        assert_eq!(r.prev_hash, g.record_hash);
        assert_eq!(compute_record_hash(&r).unwrap(), r.record_hash);
    }

    #[test]
    fn seq_bounded_by_bigint() {
        let head = ChainHead {
            seq: MAX_SEQ,
            record_hash: GENESIS_PREV_HASH,
        };
        assert!(matches!(
            seal(Some(&head), &draft(), 1, "n"),
            Err(AuditError::ChainFull)
        ));
    }

    #[test]
    fn empty_node_refused() {
        assert!(AuditChain::new("").is_err());
        assert_eq!(AuditChain::new("ctl\n01").unwrap().node(), "ctl\u{FFFD}01");
    }
}
