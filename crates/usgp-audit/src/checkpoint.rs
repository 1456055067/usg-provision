//! Signed checkpoints (plan sections 5.3 and 5.6).
//!
//! A checkpoint signs the chain head `(seq, record_hash)` with the audit
//! key. The signed bytes are
//!
//! ```text
//! seq (u64 BE) || record_hash (32) || signed_at_us (i64 BE) || key_id (32)
//! ```
//!
//! under payload type [`CHECKPOINT_PAYLOAD_TYPE`] through
//! `usgp_crypto::sign_typed`, so a checkpoint signature cannot be replayed
//! as a manifest signature or the reverse.
//!
//! Each checkpoint is stored (`audit_checkpoint`) and also written into
//! the chain as an [`EVENT_CHECKPOINT`] record carrying the full
//! checkpoint, signature included. Mirroring that record to stdout
//! ([`crate::mirror`]) gives the external anchor: a party holding the
//! forwarded line can verify the checkpoint without the database.
//!
//! The [`Checkpointer`] signs when at least `every_records` records were
//! appended since the last checkpoint, or when at least one was and
//! `every` has passed, and on demand at shutdown (`force`). The record of
//! a checkpoint itself does not count as new. An idle chain is still
//! re-checkpointed every `heartbeat` (default 15 minutes; finding
//! SEC-013): the heartbeat signs the head even with no new record, so the
//! newest checkpoint's `signed_at_us` shows the chain was intact at that
//! time and `audit verify --max-checkpoint-age` can tell a chain truncated
//! back to an old checkpoint from a quiet one.

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-9(3) (Cryptographic Protection) - ECDSA P-384
//   signatures over the chain head.
// - NIST 800-53: AU-10 (Non-repudiation) - basis: signed, attributable
//   checkpoints over operator-attributed records.
// - NIST 800-53: AU-9(3) - periodic heartbeat checkpoints bound how old
//   the newest signed statement about the chain can be while the server
//   runs (finding SEC-013).
// - NIST 800-53: AU-9(2) (Store on Separate Physical Systems) - partial:
//   the checkpoint record is mirrored to stdout for external forwarding.
// - NIST 800-53: SC-13 (Cryptographic Protection) - FIPS module via
//   usgp-crypto.
// - SPEC: specs/operator-access.md#REQ-AUD-005

// POAM: the audit signing key is a file on the server host (no HSM, plan
// section 5.2). A holder of the key can forge checkpoints after the last
// externally forwarded one.

use std::time::Duration;

use usgp_common::Sha256Digest;
use usgp_crypto::{KeyId, SIGNATURE_ALGORITHM, SigningKey, VerifyingKey, sign_typed, verify_typed};

use crate::chain::AuditChain;
use crate::error::AuditError;
use crate::record::{AuditDraft, AuditRecord, ChainHead, Detail, EVENT_CHECKPOINT};
use crate::store::AuditTx;

/// Payload type of checkpoint signatures (also
/// `usgp_proto::envelope::PayloadType::AuditCheckpointV1`).
pub const CHECKPOINT_PAYLOAD_TYPE: &str = "application/vnd.usgp.audit-checkpoint.v1";

/// Length of the signed checkpoint bytes.
pub const CHECKPOINT_SIGNED_LEN: usize = 8 + 32 + 8 + 32;

/// Largest accepted signature, in bytes (DER ECDSA P-384 is at most 104).
pub const MAX_CHECKPOINT_SIGNATURE_LEN: usize = 104;

/// Most records between checkpoints that a policy may set.
pub const MAX_EVERY_RECORDS: u64 = 1_000_000;
/// Longest checkpoint interval a policy may set.
pub const MAX_EVERY: Duration = Duration::from_secs(86_400);
/// Default heartbeat: a checkpoint at least this often while the server
/// runs, even with no new record (finding SEC-013).
pub const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(900);
/// Shortest heartbeat a policy may set.
pub const MIN_HEARTBEAT: Duration = Duration::from_secs(60);
/// Longest heartbeat a policy may set.
pub const MAX_HEARTBEAT: Duration = MAX_EVERY;

/// A signed statement that the chain had `record_hash` at `seq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// The seq covered.
    pub seq: u64,
    /// The `record_hash` of record `seq`.
    pub record_hash: Sha256Digest,
    /// When it was signed, UTC microseconds.
    pub signed_at_us: i64,
    /// The signing key's id.
    pub key_id: KeyId,
    /// DER ECDSA P-384/SHA-384 signature over [`Checkpoint::signed_bytes`].
    pub signature: Vec<u8>,
}

/// Why a checkpoint failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckpointFault {
    /// No trusted key has the checkpoint's key id.
    UntrustedKey,
    /// The signature does not verify.
    BadSignature,
}

impl Checkpoint {
    /// The bytes that are signed.
    #[must_use]
    pub fn signed_bytes(&self) -> [u8; CHECKPOINT_SIGNED_LEN] {
        signed_bytes(self.seq, &self.record_hash, self.signed_at_us, &self.key_id)
    }

    /// Signs `head` at `signed_at_us` with `key`.
    ///
    /// # Errors
    ///
    /// [`AuditError::Crypto`] if signing fails.
    pub fn sign(key: &SigningKey, head: &ChainHead, signed_at_us: i64) -> Result<Self, AuditError> {
        let key_id = key.key_id();
        let bytes = signed_bytes(head.seq, &head.record_hash, signed_at_us, &key_id);
        let signature = sign_typed(key, CHECKPOINT_PAYLOAD_TYPE, &bytes)?;
        Ok(Self {
            seq: head.seq,
            record_hash: head.record_hash,
            signed_at_us,
            key_id,
            signature,
        })
    }

    /// Verifies the signature with the trusted key of the same key id.
    ///
    /// # Errors
    ///
    /// [`CheckpointFault`].
    pub fn verify(&self, trusted: &[VerifyingKey]) -> Result<(), CheckpointFault> {
        let key = trusted
            .iter()
            .find(|k| k.key_id() == self.key_id)
            .ok_or(CheckpointFault::UntrustedKey)?;
        if self.signature.len() > MAX_CHECKPOINT_SIGNATURE_LEN {
            return Err(CheckpointFault::BadSignature);
        }
        verify_typed(
            key,
            CHECKPOINT_PAYLOAD_TYPE,
            &self.signed_bytes(),
            &self.signature,
        )
        .map_err(|_| CheckpointFault::BadSignature)
    }

    /// The detail written in the checkpoint's chain record.
    pub(crate) fn detail(&self) -> Detail {
        Detail::new()
            .with("checkpoint_seq", &self.seq)
            .with("record_hash", &self.record_hash)
            .with("signed_at_us", &self.signed_at_us)
            .with("key_id", &self.key_id)
            .with("alg", SIGNATURE_ALGORITHM)
            .with("signature", &hex(&self.signature))
    }
}

fn signed_bytes(
    seq: u64,
    record_hash: &Sha256Digest,
    signed_at_us: i64,
    key_id: &KeyId,
) -> [u8; CHECKPOINT_SIGNED_LEN] {
    let mut out = [0u8; CHECKPOINT_SIGNED_LEN];
    let parts: [&[u8]; 4] = [
        &seq.to_be_bytes(),
        record_hash.as_bytes(),
        &signed_at_us.to_be_bytes(),
        key_id.0.as_bytes(),
    ];
    let mut pos = 0;
    for p in parts {
        if let Some(dst) = out.get_mut(pos..pos + p.len()) {
            dst.copy_from_slice(p);
        }
        pos += p.len();
    }
    out
}

/// Lowercase hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// When to checkpoint (config `[audit]`: `checkpoint_every_records`,
/// `checkpoint_every_s`, `checkpoint_heartbeat_s`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointPolicy {
    /// Checkpoint after this many new records.
    pub every_records: u64,
    /// Checkpoint after this long, if there is at least one new record.
    pub every: Duration,
    /// Checkpoint after this long even with no new record (heartbeat).
    pub heartbeat: Duration,
}

impl Default for CheckpointPolicy {
    /// 100 records or 60 s (plan section 5.6); heartbeat 15 minutes
    /// (finding SEC-013; our choice).
    fn default() -> Self {
        Self {
            every_records: 100,
            every: Duration::from_secs(60),
            heartbeat: DEFAULT_HEARTBEAT,
        }
    }
}

impl CheckpointPolicy {
    /// Checks the ranges: 1 to [`MAX_EVERY_RECORDS`] records, 1 s to
    /// [`MAX_EVERY`].
    ///
    /// # Errors
    ///
    /// [`AuditError::Config`].
    pub fn validate(&self) -> Result<(), AuditError> {
        if !(1..=MAX_EVERY_RECORDS).contains(&self.every_records) {
            return Err(AuditError::Config {
                what: "checkpoint_every_records",
                reason: "must be 1 to 1000000",
            });
        }
        if self.every < Duration::from_secs(1) || self.every > MAX_EVERY {
            return Err(AuditError::Config {
                what: "checkpoint_every_s",
                reason: "must be 1 to 86400",
            });
        }
        if self.heartbeat < MIN_HEARTBEAT || self.heartbeat > MAX_HEARTBEAT {
            return Err(AuditError::Config {
                what: "checkpoint_heartbeat_s",
                reason: "must be 60 to 86400",
            });
        }
        Ok(())
    }

    /// True if a checkpoint is due for `head`, given the `last` checkpoint
    /// and the time `now_us`. `force` (shutdown) makes any new record
    /// enough. With no new record, a checkpoint is due once `heartbeat`
    /// has passed since the last one.
    #[must_use]
    pub fn is_due(
        &self,
        head: &ChainHead,
        last: Option<&Checkpoint>,
        now_us: i64,
        force: bool,
    ) -> bool {
        // The record after a checkpoint is the checkpoint's own record.
        let covered = last.map_or(0, |c| c.seq.saturating_add(1));
        let since = head.seq.saturating_sub(covered);
        if since == 0 {
            let heartbeat_us = i64::try_from(self.heartbeat.as_micros()).unwrap_or(i64::MAX);
            return last.is_some_and(|c| now_us.saturating_sub(c.signed_at_us) >= heartbeat_us);
        }
        if force || since >= self.every_records {
            return true;
        }
        let every_us = i64::try_from(self.every.as_micros()).unwrap_or(i64::MAX);
        last.is_none_or(|c| now_us.saturating_sub(c.signed_at_us) >= every_us)
    }
}

/// A checkpoint and its chain record, written in one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointWritten {
    /// The stored checkpoint.
    pub checkpoint: Checkpoint,
    /// The [`EVENT_CHECKPOINT`] record; mirror it after commit.
    pub record: AuditRecord,
}

/// Signs checkpoints with the audit key.
#[derive(Debug)]
pub struct Checkpointer {
    key: SigningKey,
    policy: CheckpointPolicy,
}

impl Checkpointer {
    /// A checkpointer with `key` (purpose `audit`, plan section 5.2).
    ///
    /// # Errors
    ///
    /// [`AuditError::Config`] for an out-of-range policy.
    pub fn new(key: SigningKey, policy: CheckpointPolicy) -> Result<Self, AuditError> {
        policy.validate()?;
        Ok(Self { key, policy })
    }

    /// The audit key id.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.key.key_id()
    }

    /// The policy.
    #[must_use]
    pub const fn policy(&self) -> &CheckpointPolicy {
        &self.policy
    }

    /// In the caller's transaction: if a checkpoint is due (or `force` and
    /// there is any new record), signs the head, stores the checkpoint and
    /// appends its [`EVENT_CHECKPOINT`] record. Returns `None` if nothing
    /// was due or the chain is empty.
    ///
    /// The server calls this after committed appends and on a timer (every
    /// 60 s, which serves `policy.every` and the heartbeat), and with
    /// `force` at clean shutdown.
    ///
    /// # Errors
    ///
    /// [`AuditError::Store`], [`AuditError::Crypto`], [`AuditError::Clock`].
    /// The caller rolls back.
    pub async fn checkpoint_if_due<T: AuditTx>(
        &self,
        chain: &AuditChain,
        tx: &mut T,
        force: bool,
    ) -> Result<Option<CheckpointWritten>, AuditError> {
        let Some(head) = tx.lock_head().await? else {
            return Ok(None);
        };
        let last = tx.last_checkpoint().await?;
        let now_us = chain.now_us()?;
        if !self.policy.is_due(&head, last.as_ref(), now_us, force) {
            return Ok(None);
        }
        let checkpoint = Checkpoint::sign(&self.key, &head, now_us)?;
        tx.insert_checkpoint(&checkpoint).await?;
        let draft = AuditDraft::internal(
            EVENT_CHECKPOINT,
            checkpoint.detail(),
            checkpoint.seq.to_string(),
        );
        let record = chain.append(tx, &draft).await?;
        Ok(Some(CheckpointWritten { checkpoint, record }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(seq: u64) -> ChainHead {
        ChainHead {
            seq,
            record_hash: Sha256Digest([9; 32]),
        }
    }

    fn cp(seq: u64, at: i64) -> Checkpoint {
        Checkpoint {
            seq,
            record_hash: Sha256Digest([0; 32]),
            signed_at_us: at,
            key_id: KeyId(Sha256Digest([1; 32])),
            signature: Vec::new(),
        }
    }

    #[test]
    fn signed_bytes_layout() {
        let c = Checkpoint {
            seq: 0x0102,
            record_hash: Sha256Digest([0xaa; 32]),
            signed_at_us: -1,
            key_id: KeyId(Sha256Digest([0xbb; 32])),
            signature: Vec::new(),
        };
        let b = c.signed_bytes();
        let mut want = 0x0102_u64.to_be_bytes().to_vec();
        want.extend_from_slice(&[0xaa; 32]);
        want.extend_from_slice(&(-1_i64).to_be_bytes());
        want.extend_from_slice(&[0xbb; 32]);
        assert_eq!(b.to_vec(), want);
    }

    #[test]
    fn policy_ranges() {
        assert!(CheckpointPolicy::default().validate().is_ok());
        let p = CheckpointPolicy {
            every_records: 0,
            ..CheckpointPolicy::default()
        };
        assert!(p.validate().is_err());
        let p = CheckpointPolicy {
            every: Duration::from_millis(10),
            ..CheckpointPolicy::default()
        };
        assert!(p.validate().is_err());
        for heartbeat in [
            Duration::from_secs(59),
            MAX_HEARTBEAT + Duration::from_secs(1),
        ] {
            let p = CheckpointPolicy {
                heartbeat,
                ..CheckpointPolicy::default()
            };
            assert!(p.validate().is_err());
        }
    }

    #[test]
    fn due_rules() {
        let p = CheckpointPolicy {
            every_records: 3,
            every: Duration::from_secs(10),
            heartbeat: Duration::from_secs(120),
        };
        // No checkpoint yet: any record is due on the timer.
        assert!(p.is_due(&head(1), None, 0, false));
        // Last checkpoint at 5, its record at 6.
        let last = cp(5, 0);
        assert!(!p.is_due(&head(6), Some(&last), 100_000_000, false));
        assert!(!p.is_due(&head(6), Some(&last), 0, true));
        assert!(!p.is_due(&head(7), Some(&last), 1, false));
        assert!(p.is_due(&head(7), Some(&last), 10_000_000, false));
        assert!(p.is_due(&head(7), Some(&last), 1, true));
        assert!(p.is_due(&head(9), Some(&last), 1, false));
        // SEC-013 heartbeat: nothing new, but the last checkpoint is old.
        assert!(!p.is_due(&head(6), Some(&last), 119_999_999, false));
        assert!(p.is_due(&head(6), Some(&last), 120_000_000, false));
    }

    #[test]
    fn hex_lowercase() {
        assert_eq!(hex(&[0x00, 0xab, 0x0f]), "00ab0f");
    }
}
