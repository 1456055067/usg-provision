//! The chain verifier (plan section 5.6; `usgp-server audit verify`).
//!
//! Rules, each reported with the seq where it breaks:
//!
//! | Rule | Catches |
//! |---|---|
//! | seq starts at 1 and is contiguous | deletion, reordering |
//! | record 1 is the genesis with a zero `prev_hash` | deletion or replacement of the start |
//! | each `prev_hash` equals the previous stored `record_hash` | reordering, insertion |
//! | the recomputed `record_hash` equals the stored one | modification |
//! | every checkpoint verifies with a trusted key and equals the stored hash at its seq | a fully recomputed chain |
//! | no verified checkpoint lies beyond the last record | deletion of a checkpointed tail |
//! | every `audit.checkpoint` record matches a stored, verified checkpoint | deletion of checkpoints |
//! | the stored head equals the last record | tail deletion without a head rewrite |
//! | no stored record has a seq above the stored head | a head moved back over kept records |
//!
//! With a [`VerifyPolicy`] (the command always passes one), the verifier
//! also knows how often the server signs checkpoints and reports:
//!
//! | Rule | Catches |
//! |---|---|
//! | matched checkpoints are at most `max_unsigned_records` apart (from seq 0 for the first) | checkpoint rows deleted and the records after an old checkpoint rewritten, then later re-checkpointed |
//! | the tail after the last matched checkpoint is at most `max_unsigned_records` | checkpoint rows after an old checkpoint deleted and the records after it rewritten (SEC-002) |
//! | a chain longer than `max_unsigned_records` has a matched checkpoint | every checkpoint deleted and the chain recomputed |
//! | with `max_checkpoint_age`: the newest matched checkpoint was signed at most that long before the verification time and before the last record | the chain truncated back to an older surviving checkpoint (all later checkpoints and records deleted, SEC-013) |
//!
//! Non-fatal notices (reported, the chain is still intact): a record whose
//! timestamp is earlier than the previous record's (a backward clock step,
//! AU-8).
//!
//! Stated limits: a database owner without the audit key can delete every
//! checkpoint after any surviving one, delete the records after it and
//! move the head back (adding up to `max_unsigned_records` recomputed
//! records). The chain rules alone cannot see that; the
//! `max_checkpoint_age` rule sees it only if the surviving checkpoint is
//! older than the allowed age (the server signs a heartbeat checkpoint
//! every `checkpoint_heartbeat_s`, so a truncation to a checkpoint older
//! than that is caught); a truncation within the allowed age is
//! detectable only against the external stdout copy. A holder of the
//! audit key can forge everything after the last externally forwarded
//! checkpoint.
//!
//! Trusted keys come from files given to the command, never from the
//! database (plan section 5.2).

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-9 (Protection of Audit Information) - detects
//   modification, deletion, reordering and insertion.
// - NIST 800-53: AU-9(3) (Cryptographic Protection) - checkpoint
//   signatures checked against trusted keys only.
// - NIST 800-53: AU-10 (Non-repudiation) - basis: integrity of
//   attributed records is checkable.
// - NIST 800-53: AU-9(3) - the checkpoint cadence is enforced: a run of
//   unsigned records longer than the policy allows is a finding.
// - NIST 800-53: AU-9(3), AU-6 - a stale newest checkpoint is a finding
//   when an age limit is given (finding SEC-013).
// - NIST 800-53: AU-8 (Time Stamps) - backward timestamps reported.
// - NIST 800-53: SI-10 (Information Input Validation) - stored rows are
//   untrusted input: bounded parsing, no panics.
// - SPEC: specs/operator-access.md#REQ-AUD-005, #REQ-AUD-007

use std::collections::{BTreeMap, BTreeSet};

use usgp_common::Sha256Digest;
use usgp_crypto::VerifyingKey;

use crate::canonical::{GENESIS_PREV_HASH, compute_record_hash};
use crate::checkpoint::{Checkpoint, CheckpointFault, CheckpointPolicy, hex};
use crate::error::{AuditError, StoreError, StoreErrorKind};
use crate::record::{AuditRecord, ChainHead, EVENT_CHECKPOINT, EVENT_GENESIS, MAX_DETAIL_LEN};
use crate::store::AuditRead;

/// Most findings kept in a report; further ones are only counted.
pub const MAX_FINDINGS: usize = 1000;
/// Largest page size for [`verify_store`].
pub const MAX_PAGE: usize = 10_000;
/// Most notices kept in a report; further ones are only counted.
pub const MAX_NOTICES: usize = 1000;

/// Most records one writer appends in one transaction (the API's upload
/// completion writes two; every other action one).
pub const MAX_RECORDS_PER_TRANSACTION: u64 = 2;
/// Records allowed for local administrative commands (operator enrol and
/// disable, audit verify), which append without a checkpoint pass, for
/// example while the server is stopped.
pub const LOCAL_COMMAND_SLACK_RECORDS: u64 = 16;
/// Concurrent audit writers assumed when none is given: the API defaults
/// (64 connections, one content check) plus two background writers.
pub const DEFAULT_MAX_WRITERS: u64 = 64 + 1 + 2;
/// Largest number of concurrent writers [`checkpoint_slack_records`]
/// accepts (larger values are clamped).
pub const MAX_WRITERS: u64 = 10_000;
/// Largest `max_unsigned_records` a policy may set.
pub const MAX_UNSIGNED_RECORDS: u64 = 1_100_000;

/// Records allowed on top of `every_records + 1` between two matched
/// checkpoints (finding SEC-015).
///
/// A checkpoint signs whatever head it locks. After the append that
/// crosses the threshold, every other writer may commit one transaction
/// (up to [`MAX_RECORDS_PER_TRANSACTION`] records) before a checkpoint
/// pass gets the head lock: each writer runs a checkpoint pass right after
/// each commit, before it can append again. So the slack is
/// `max_writers x MAX_RECORDS_PER_TRANSACTION`, plus
/// [`LOCAL_COMMAND_SLACK_RECORDS`]. `max_writers` is the configured
/// number of concurrent writers (`api.max_connections` +
/// `content.check_concurrency` + background tasks), clamped to
/// [`MAX_WRITERS`].
#[must_use]
pub const fn checkpoint_slack_records(max_writers: u64) -> u64 {
    let w = if max_writers > MAX_WRITERS {
        MAX_WRITERS
    } else {
        max_writers
    };
    w.saturating_mul(MAX_RECORDS_PER_TRANSACTION)
        .saturating_add(LOCAL_COMMAND_SLACK_RECORDS)
}

/// The age limit for the newest checkpoint (`--max-checkpoint-age`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointAge {
    /// Largest allowed age, microseconds.
    pub max_age_us: u64,
    /// The verification time, UTC microseconds (the verifier's clock).
    pub now_us: i64,
}

/// What the verifier knows about the checkpoint cadence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyPolicy {
    /// Longest run of records not covered by a matched checkpoint: between
    /// two matched checkpoints, before the first, and after the last.
    pub max_unsigned_records: u64,
    /// If set, the newest matched checkpoint must not be older than this
    /// (finding SEC-013).
    pub max_checkpoint_age: Option<CheckpointAge>,
}

impl VerifyPolicy {
    /// A policy with only the record limit.
    #[must_use]
    pub const fn records(max_unsigned_records: u64) -> Self {
        Self {
            max_unsigned_records,
            max_checkpoint_age: None,
        }
    }

    /// The policy for a server signing with `checkpoint` and the default
    /// number of writers ([`DEFAULT_MAX_WRITERS`]); see
    /// [`Self::for_writers`].
    #[must_use]
    pub const fn from_checkpoint_policy(checkpoint: &CheckpointPolicy) -> Self {
        Self::for_writers(checkpoint, DEFAULT_MAX_WRITERS)
    }

    /// The policy for a server signing with `checkpoint` with at most
    /// `max_writers` concurrent audit writers: a checkpoint at seq `s` is
    /// followed by its own record `s + 1`, and the next is due
    /// `every_records` records later, so at most `every_records + 1`
    /// records separate them, plus [`checkpoint_slack_records`].
    #[must_use]
    pub const fn for_writers(checkpoint: &CheckpointPolicy, max_writers: u64) -> Self {
        Self::records(
            checkpoint
                .every_records
                .saturating_add(1)
                .saturating_add(checkpoint_slack_records(max_writers)),
        )
    }

    /// The same policy, also requiring the newest matched checkpoint to be
    /// at most `max_age_us` old at `now_us`.
    #[must_use]
    pub const fn with_max_checkpoint_age(mut self, max_age_us: u64, now_us: i64) -> Self {
        self.max_checkpoint_age = Some(CheckpointAge { max_age_us, now_us });
        self
    }

    /// Checks the range 1 to [`MAX_UNSIGNED_RECORDS`].
    ///
    /// # Errors
    ///
    /// [`AuditError::Config`].
    pub fn validate(&self) -> Result<(), AuditError> {
        if (1..=MAX_UNSIGNED_RECORDS).contains(&self.max_unsigned_records) {
            Ok(())
        } else {
            Err(AuditError::Config {
                what: "max_unsigned_records",
                reason: "must be 1 to 1100000",
            })
        }
    }
}

impl Default for VerifyPolicy {
    /// From [`CheckpointPolicy::default`] (100 records) and
    /// [`DEFAULT_MAX_WRITERS`] (67): 100 + 1 + 67 x 2 + 16 = 251.
    fn default() -> Self {
        Self::from_checkpoint_policy(&CheckpointPolicy::default())
    }
}

/// A broken rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Violation {
    /// A record's seq is not the one expected.
    SeqNotContiguous {
        /// The seq that should have come next.
        expected: u64,
        /// The seq found.
        found: u64,
    },
    /// Record 1 is not a genesis record with a zero `prev_hash`.
    GenesisInvalid,
    /// `prev_hash` differs from the previous record's stored hash.
    PrevHashMismatch,
    /// The recomputed hash differs from the stored one.
    RecordHashMismatch,
    /// The record cannot be encoded (a field is too long).
    Unencodable,
    /// A checkpoint's key id is not among the trusted keys.
    CheckpointUntrustedKey,
    /// A checkpoint's signature does not verify.
    CheckpointBadSignature,
    /// A verified checkpoint's hash differs from the record at its seq.
    CheckpointHashMismatch,
    /// A verified checkpoint names a seq after the last record.
    CheckpointBeyondChain,
    /// A verified checkpoint names a seq that is missing from the chain.
    CheckpointRecordMissing,
    /// An `audit.checkpoint` record has no matching verified checkpoint.
    CheckpointRecordUnmatched,
    /// The stored head differs from the last record.
    HeadMismatch,
    /// A stored record has a seq above the stored head.
    RecordBeyondHead,
    /// Two consecutive matched checkpoints (or seq 0 and the first) are
    /// further apart than the policy allows; reported at the first seq
    /// outside the allowed run.
    CheckpointGapTooLong,
    /// The records after the last matched checkpoint exceed the policy;
    /// reported at the first seq outside the allowed run.
    UnsignedTailTooLong,
    /// No checkpoint matched although the chain is longer than the policy
    /// allows; reported at the first seq outside the allowed run.
    NoCheckpoint,
    /// The newest matched checkpoint is older than `max_checkpoint_age`
    /// at the verification time, or than the last record by more than
    /// that (or no checkpoint matched at all); reported at the newest
    /// checkpoint's seq (the last seq if none matched).
    CheckpointStale,
}

impl Violation {
    /// Rule name for reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SeqNotContiguous { .. } => "seq_not_contiguous",
            Self::GenesisInvalid => "genesis_invalid",
            Self::PrevHashMismatch => "prev_hash_mismatch",
            Self::RecordHashMismatch => "record_hash_mismatch",
            Self::Unencodable => "unencodable",
            Self::CheckpointUntrustedKey => "checkpoint_untrusted_key",
            Self::CheckpointBadSignature => "checkpoint_bad_signature",
            Self::CheckpointHashMismatch => "checkpoint_hash_mismatch",
            Self::CheckpointBeyondChain => "checkpoint_beyond_chain",
            Self::CheckpointRecordMissing => "checkpoint_record_missing",
            Self::CheckpointRecordUnmatched => "checkpoint_record_unmatched",
            Self::HeadMismatch => "head_mismatch",
            Self::RecordBeyondHead => "record_beyond_head",
            Self::CheckpointGapTooLong => "checkpoint_gap_too_long",
            Self::UnsignedTailTooLong => "unsigned_tail_too_long",
            Self::NoCheckpoint => "no_checkpoint",
            Self::CheckpointStale => "checkpoint_stale",
        }
    }
}

/// A broken rule at a seq.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finding {
    /// Where the rule breaks.
    pub seq: u64,
    /// Which rule.
    pub violation: Violation,
}

/// Something worth an operator's attention that does not break the
/// chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NoticeKind {
    /// The record's timestamp is earlier than the previous record's (a
    /// backward step of the server clock, AU-8).
    TimestampBackwards {
        /// The previous record's `ts_us`.
        previous_us: i64,
        /// This record's `ts_us`.
        ts_us: i64,
    },
}

impl NoticeKind {
    /// Name for reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TimestampBackwards { .. } => "timestamp_backwards",
        }
    }
}

/// A notice at a seq.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notice {
    /// Where.
    pub seq: u64,
    /// What.
    pub kind: NoticeKind,
}

/// The verifier's result.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VerifyReport {
    /// Records examined.
    pub records_checked: u64,
    /// Seq of the last record examined.
    pub last_seq: Option<u64>,
    /// Checkpoints given.
    pub checkpoints_total: u64,
    /// Checkpoints whose signature verified and whose hash matched.
    pub checkpoints_matched: u64,
    /// Highest seq covered by a matched checkpoint.
    pub last_checkpoint_seq: Option<u64>,
    /// Records after `last_checkpoint_seq`: protected only by the hash
    /// chain and external forwarding.
    pub unsigned_tail: u64,
    /// Findings in ascending seq, at most [`MAX_FINDINGS`].
    pub findings: Vec<Finding>,
    /// Findings beyond [`MAX_FINDINGS`], counted only.
    pub findings_omitted: u64,
    /// The policy's `max_unsigned_records`, if a policy was applied.
    pub max_unsigned_records: Option<u64>,
    /// Non-fatal notices in ascending seq, at most [`MAX_NOTICES`].
    pub notices: Vec<Notice>,
    /// Notices beyond [`MAX_NOTICES`], counted only.
    pub notices_omitted: u64,
    /// `signed_at_us` of the most recently signed matched checkpoint.
    pub newest_checkpoint_at_us: Option<i64>,
    /// The policy's `max_checkpoint_age`, in microseconds, if given.
    pub max_checkpoint_age_us: Option<u64>,
}

impl VerifyReport {
    /// True if no rule broke. Notices do not count.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        self.findings.is_empty() && self.findings_omitted == 0
    }

    /// The finding with the lowest seq.
    #[must_use]
    pub fn first_finding(&self) -> Option<&Finding> {
        self.findings.first()
    }
}

/// Incremental verifier: give it records in ascending seq with
/// [`ChainVerifier::push`], then call [`ChainVerifier::finish`]. Memory
/// use is independent of the number of records.
#[derive(Debug)]
pub struct ChainVerifier {
    /// Verified checkpoints by seq.
    verified: BTreeMap<u64, Vec<Checkpoint>>,
    /// Seqs of verified checkpoints not yet reached.
    pending: BTreeSet<u64>,
    expected_head: Option<Option<ChainHead>>,
    policy: Option<VerifyPolicy>,
    next_seq: u64,
    prev_hash: Option<Sha256Digest>,
    prev_ts_us: Option<i64>,
    last: Option<ChainHead>,
    /// `ts_us` of the last record pushed.
    last_ts_us: i64,
    /// Seq of the checkpoint with the newest `signed_at_us`.
    newest_checkpoint_seq: Option<u64>,
    report: VerifyReport,
}

impl ChainVerifier {
    /// A verifier for a chain with the stored `checkpoints`, trusting only
    /// `trusted` keys.
    ///
    /// # Errors
    ///
    /// [`AuditError::Config`] if `trusted` is empty: without a trusted key
    /// a recomputed chain cannot be told apart, so the verifier refuses to
    /// run (fail closed).
    pub fn new(trusted: &[VerifyingKey], checkpoints: Vec<Checkpoint>) -> Result<Self, AuditError> {
        if trusted.is_empty() {
            return Err(AuditError::Config {
                what: "trusted_keys",
                reason: "at least one trusted audit key is required",
            });
        }
        let mut v = Self {
            verified: BTreeMap::new(),
            pending: BTreeSet::new(),
            expected_head: None,
            policy: None,
            next_seq: 1,
            prev_hash: None,
            prev_ts_us: None,
            last: None,
            last_ts_us: i64::MIN,
            newest_checkpoint_seq: None,
            report: VerifyReport::default(),
        };
        for cp in checkpoints {
            v.report.checkpoints_total = v.report.checkpoints_total.saturating_add(1);
            match cp.verify(trusted) {
                Ok(()) => {
                    v.pending.insert(cp.seq);
                    v.verified.entry(cp.seq).or_default().push(cp);
                }
                Err(CheckpointFault::UntrustedKey) => {
                    v.find(cp.seq, Violation::CheckpointUntrustedKey);
                }
                Err(CheckpointFault::BadSignature) => {
                    v.find(cp.seq, Violation::CheckpointBadSignature);
                }
            }
        }
        Ok(v)
    }

    /// Also checks that the stored head (`audit_head`) equals the last
    /// record. `None` means the store says the chain is empty.
    #[must_use]
    pub const fn expect_head(mut self, head: Option<ChainHead>) -> Self {
        self.expected_head = Some(head);
        self
    }

    /// Also enforces the checkpoint cadence (see the module table).
    ///
    /// # Errors
    ///
    /// [`AuditError::Config`] if `policy` is out of range.
    pub fn with_policy(mut self, policy: VerifyPolicy) -> Result<Self, AuditError> {
        policy.validate()?;
        self.policy = Some(policy);
        self.report.max_unsigned_records = Some(policy.max_unsigned_records);
        self.report.max_checkpoint_age_us = policy.max_checkpoint_age.map(|a| a.max_age_us);
        Ok(self)
    }

    /// Reports a stored record with a seq above the stored head (seen by
    /// [`verify_store`] after the verified range).
    pub fn record_beyond_head(&mut self, seq: u64) {
        self.find(seq, Violation::RecordBeyondHead);
    }

    /// Checks the next record.
    pub fn push(&mut self, record: &AuditRecord) {
        let seq = record.seq;
        self.report.records_checked = self.report.records_checked.saturating_add(1);
        if seq != self.next_seq {
            self.find(
                seq,
                Violation::SeqNotContiguous {
                    expected: self.next_seq,
                    found: seq,
                },
            );
        }
        if seq == 1 && (record.event != EVENT_GENESIS || record.prev_hash != GENESIS_PREV_HASH) {
            self.find(seq, Violation::GenesisInvalid);
        }
        if let Some(prev) = self.prev_hash
            && record.prev_hash != prev
        {
            self.find(seq, Violation::PrevHashMismatch);
        }
        match compute_record_hash(record) {
            Ok(h) if h == record.record_hash => {}
            Ok(_) => self.find(seq, Violation::RecordHashMismatch),
            Err(_) => self.find(seq, Violation::Unencodable),
        }
        if let Some(prev) = self.prev_ts_us
            && record.ts_us < prev
        {
            self.notice(
                seq,
                NoticeKind::TimestampBackwards {
                    previous_us: prev,
                    ts_us: record.ts_us,
                },
            );
        }
        self.prev_ts_us = Some(record.ts_us);
        self.last_ts_us = record.ts_us;
        self.check_checkpoints_at(record);
        if record.event == EVENT_CHECKPOINT && !self.checkpoint_record_matches(record) {
            self.find(seq, Violation::CheckpointRecordUnmatched);
        }
        self.prev_hash = Some(record.record_hash);
        self.next_seq = seq.saturating_add(1);
        self.last = Some(ChainHead::from(record));
        self.report.last_seq = Some(seq);
    }

    /// Finishes and returns the report.
    #[must_use]
    pub fn finish(mut self) -> VerifyReport {
        let last_seq = self.report.last_seq.unwrap_or(0);
        for seq in std::mem::take(&mut self.pending) {
            let v = if seq > last_seq {
                Violation::CheckpointBeyondChain
            } else {
                Violation::CheckpointRecordMissing
            };
            self.find(seq, v);
        }
        if let Some(expected) = self.expected_head
            && expected != self.last
        {
            let at = expected.map_or(last_seq, |h| h.seq);
            self.find(at, Violation::HeadMismatch);
        }
        let covered = self.report.last_checkpoint_seq.unwrap_or(0);
        self.report.unsigned_tail = last_seq.saturating_sub(covered);
        if let Some(p) = self.policy
            && self.report.unsigned_tail > p.max_unsigned_records
        {
            let at = covered
                .saturating_add(p.max_unsigned_records)
                .saturating_add(1);
            let v = if self.report.last_checkpoint_seq.is_some() {
                Violation::UnsignedTailTooLong
            } else {
                Violation::NoCheckpoint
            };
            self.find(at, v);
        }
        if let Some(age) = self.policy.and_then(|p| p.max_checkpoint_age)
            && let Some(last) = self.last
        {
            let limit = i64::try_from(age.max_age_us).unwrap_or(i64::MAX);
            let stale = self.report.newest_checkpoint_at_us.is_none_or(|at| {
                age.now_us.saturating_sub(at) > limit || self.last_ts_us.saturating_sub(at) > limit
            });
            if stale {
                let at = self.newest_checkpoint_seq.unwrap_or(last.seq);
                self.find(at, Violation::CheckpointStale);
            }
        }
        self.report.findings.sort_by_key(|f| f.seq);
        self.report.notices.sort_by_key(|n| n.seq);
        self.report
    }

    fn check_checkpoints_at(&mut self, record: &AuditRecord) {
        let seq = record.seq;
        if !self.pending.remove(&seq) {
            return;
        }
        let mut matched = false;
        let mut mismatched = false;
        for cp in self.verified.get(&seq).into_iter().flatten() {
            if cp.record_hash == record.record_hash {
                matched = true;
            } else {
                mismatched = true;
            }
        }
        if mismatched {
            self.find(seq, Violation::CheckpointHashMismatch);
        } else if matched {
            let newest = self
                .verified
                .get(&seq)
                .into_iter()
                .flatten()
                .map(|cp| cp.signed_at_us)
                .max();
            if let Some(at) = newest
                && self.report.newest_checkpoint_at_us.is_none_or(|n| at > n)
            {
                self.report.newest_checkpoint_at_us = Some(at);
                self.newest_checkpoint_seq = Some(seq);
            }
            let previous = self.report.last_checkpoint_seq.unwrap_or(0);
            if let Some(p) = self.policy
                && seq.saturating_sub(previous) > p.max_unsigned_records
            {
                let at = previous
                    .saturating_add(p.max_unsigned_records)
                    .saturating_add(1);
                self.find(at, Violation::CheckpointGapTooLong);
            }
            self.report.checkpoints_matched = self.report.checkpoints_matched.saturating_add(
                self.verified
                    .get(&seq)
                    .map_or(0, |v| u64::try_from(v.len()).unwrap_or(u64::MAX)),
            );
            self.report.last_checkpoint_seq =
                Some(self.report.last_checkpoint_seq.map_or(seq, |s| s.max(seq)));
        }
    }

    /// An `audit.checkpoint` record must name a verified checkpoint with
    /// the same seq, hash, key id and signature.
    fn checkpoint_record_matches(&self, record: &AuditRecord) -> bool {
        if record.detail.len() > MAX_DETAIL_LEN {
            return false;
        }
        let Ok(d) = serde_json::from_str::<BTreeMap<String, String>>(&record.detail) else {
            return false;
        };
        let Some(seq) = d.get("checkpoint_seq").and_then(|s| s.parse::<u64>().ok()) else {
            return false;
        };
        self.verified.get(&seq).into_iter().flatten().any(|cp| {
            d.get("record_hash").map(String::as_str) == Some(cp.record_hash.to_hex().as_str())
                && d.get("key_id").map(String::as_str) == Some(cp.key_id.to_hex().as_str())
                && d.get("signature").map(String::as_str) == Some(hex(&cp.signature).as_str())
                && d.get("signed_at_us").map(String::as_str)
                    == Some(cp.signed_at_us.to_string().as_str())
        })
    }

    fn notice(&mut self, seq: u64, kind: NoticeKind) {
        if self.report.notices.len() < MAX_NOTICES {
            self.report.notices.push(Notice { seq, kind });
        } else {
            self.report.notices_omitted = self.report.notices_omitted.saturating_add(1);
        }
    }

    fn find(&mut self, seq: u64, violation: Violation) {
        if self.report.findings.len() < MAX_FINDINGS {
            self.report.findings.push(Finding { seq, violation });
        } else {
            self.report.findings_omitted = self.report.findings_omitted.saturating_add(1);
        }
    }
}

/// Verifies `records` (ascending seq) against `checkpoints` with
/// `trusted` keys. Structural rules only: no checkpoint cadence (see
/// [`verify_chain_with_policy`]).
///
/// # Errors
///
/// [`AuditError::Config`] if `trusted` is empty.
pub fn verify_chain(
    records: &[AuditRecord],
    checkpoints: &[Checkpoint],
    trusted: &[VerifyingKey],
) -> Result<VerifyReport, AuditError> {
    verify_chain_with_policy(records, checkpoints, trusted, None)
}

/// As [`verify_chain`], also enforcing `policy` if given.
///
/// # Errors
///
/// [`AuditError::Config`] if `trusted` is empty or `policy` is out of
/// range.
pub fn verify_chain_with_policy(
    records: &[AuditRecord],
    checkpoints: &[Checkpoint],
    trusted: &[VerifyingKey],
    policy: Option<VerifyPolicy>,
) -> Result<VerifyReport, AuditError> {
    let mut v = ChainVerifier::new(trusted, checkpoints.to_vec())?;
    if let Some(p) = policy {
        v = v.with_policy(p)?;
    }
    for r in records {
        v.push(r);
    }
    Ok(v.finish())
}

/// Verifies a whole store, reading records in pages of `page` (clamped to
/// 1..=[`MAX_PAGE`]). Structural rules only: no checkpoint cadence (see
/// [`verify_store_with_policy`]).
///
/// # Errors
///
/// As [`verify_store_with_policy`].
pub async fn verify_store<R: AuditRead>(
    store: &R,
    trusted: &[VerifyingKey],
    page: usize,
) -> Result<VerifyReport, AuditError> {
    verify_store_with_policy(store, trusted, page, None).await
}

/// Verifies a whole store, also enforcing `policy` if given.
///
/// Checkpoints are read first, then the head, then records up to the
/// head. Records committed after the head was read are not examined, so
/// concurrent appends cause no false findings, while a checkpoint beyond
/// a deleted tail is still seen.
///
/// Afterwards the store is probed for a record above the head: the head
/// is read again, then the first record after it, then the head once
/// more. An append writes its record and moves the head in one
/// transaction, so a record still above the last head read was not
/// appended concurrently: it is [`Violation::RecordBeyondHead`].
///
/// # Errors
///
/// [`AuditError::Config`] if `trusted` is empty or `policy` is out of
/// range; [`AuditError::Store`] if reading fails or the store returns
/// records out of order.
pub async fn verify_store_with_policy<R: AuditRead>(
    store: &R,
    trusted: &[VerifyingKey],
    page: usize,
    policy: Option<VerifyPolicy>,
) -> Result<VerifyReport, AuditError> {
    let page = page.clamp(1, MAX_PAGE);
    let checkpoints = store.checkpoints().await?;
    let head = store.head().await?;
    let mut v = ChainVerifier::new(trusted, checkpoints)?.expect_head(head);
    if let Some(p) = policy {
        v = v.with_policy(p)?;
    }
    let limit = head.map_or(0, |h| h.seq);
    let mut after = 0_u64;
    'pages: loop {
        let batch = store.records_after(after, page).await?;
        let n = batch.len();
        for r in &batch {
            if r.seq <= after {
                return Err(StoreError::new(StoreErrorKind::Corrupt, "records_after order").into());
            }
            if r.seq > limit {
                break 'pages;
            }
            v.push(r);
            after = r.seq;
        }
        if n < page {
            break;
        }
    }
    let probe_from = store.head().await?.map_or(0, |h| h.seq).max(limit);
    if let Some(r) = store.records_after(probe_from, 1).await?.first() {
        let now = store.head().await?.map_or(0, |h| h.seq);
        if r.seq > now {
            v.record_beyond_head(r.seq);
        }
    }
    Ok(v.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::MAX_EVERY_RECORDS;

    #[test]
    fn rule_names_unique() {
        let all = [
            Violation::SeqNotContiguous {
                expected: 1,
                found: 2,
            },
            Violation::GenesisInvalid,
            Violation::PrevHashMismatch,
            Violation::RecordHashMismatch,
            Violation::Unencodable,
            Violation::CheckpointUntrustedKey,
            Violation::CheckpointBadSignature,
            Violation::CheckpointHashMismatch,
            Violation::CheckpointBeyondChain,
            Violation::CheckpointRecordMissing,
            Violation::CheckpointRecordUnmatched,
            Violation::HeadMismatch,
            Violation::RecordBeyondHead,
            Violation::CheckpointGapTooLong,
            Violation::UnsignedTailTooLong,
            Violation::NoCheckpoint,
            Violation::CheckpointStale,
        ];
        let names: BTreeSet<_> = all.iter().map(|v| v.as_str()).collect();
        assert_eq!(names.len(), all.len());
    }

    #[test]
    fn policy_from_checkpoint_policy_and_ranges() {
        assert_eq!(VerifyPolicy::default().max_unsigned_records, 251);
        let p = VerifyPolicy::for_writers(
            &CheckpointPolicy {
                every_records: MAX_EVERY_RECORDS,
                ..CheckpointPolicy::default()
            },
            u64::MAX,
        );
        assert_eq!(
            p.max_unsigned_records,
            MAX_EVERY_RECORDS + 1 + MAX_WRITERS * 2 + LOCAL_COMMAND_SLACK_RECORDS
        );
        assert!(p.max_unsigned_records <= MAX_UNSIGNED_RECORDS);
        assert!(p.validate().is_ok());
        for bad in [0, MAX_UNSIGNED_RECORDS + 1] {
            assert!(VerifyPolicy::records(bad).validate().is_err());
        }
    }

    /// SEC-015: the slack grows with the configured writers.
    #[test]
    fn slack_from_writers() {
        assert_eq!(checkpoint_slack_records(0), LOCAL_COMMAND_SLACK_RECORDS);
        assert_eq!(checkpoint_slack_records(64 + 4 + 2), 70 * 2 + 16);
        assert_eq!(
            checkpoint_slack_records(u64::MAX),
            checkpoint_slack_records(MAX_WRITERS)
        );
        let cp = CheckpointPolicy::default();
        assert!(
            VerifyPolicy::for_writers(&cp, 4096).max_unsigned_records
                > VerifyPolicy::for_writers(&cp, 64).max_unsigned_records
        );
    }

    #[test]
    fn no_trusted_key_refused() {
        assert!(matches!(
            verify_chain(&[], &[], &[]),
            Err(AuditError::Config { .. })
        ));
    }
}
