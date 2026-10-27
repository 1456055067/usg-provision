//! usgp-audit: the tamper-evident audit log (plan M2 section 5.6).
//!
//! - [`record`]: [`AuditDraft`] (what callers build) and [`AuditRecord`]
//!   (what is stored and hashed), with the AU-3 fields who, what, when,
//!   where, source and outcome.
//! - [`canonical`]: canonical record bytes and the SHA-256 record hash.
//! - [`chain`]: [`AuditChain::append`] seals a draft into the next record
//!   inside the caller's storage transaction.
//! - [`checkpoint`]: signed checkpoints over the chain head (ECDSA P-384
//!   through `usgp-crypto`), every N records or T seconds, and at
//!   shutdown.
//! - [`verify`]: the verifier ([`verify_chain`], [`verify_store`]).
//! - [`store`]: the storage traits `usgp-db` implements ([`AuditTx`],
//!   [`AuditRead`]) and the [`Clock`].
//! - [`memory`]: an in-memory store with fault injection, for tests.
//! - [`mirror`]: the stdout JSON copy of each record (external anchor).
//!
//! Records hold no secrets (REQ-AUD-003): detail values are limited to
//! types implementing [`DetailValue`], which no key or `Zeroizing` type
//! does. Export (REQ-AUD-004) is OPEN and not provided; in M2 records are
//! read only by the local verifier command (REQ-AUD-007).

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-2 (Event Logging), AU-3 (Content of Audit Records),
//   AU-8 (Time Stamps), AU-9 (Protection of Audit Information), AU-9(3)
//   (Cryptographic Protection), AU-10 (Non-repudiation, basis), AU-12
//   (Audit Record Generation), AU-5 (fail-closed append).
// - SPEC: specs/operator-access.md#REQ-AUD-001, #REQ-AUD-002,
//   #REQ-AUD-003, #REQ-AUD-005, #REQ-AUD-006, #REQ-AUD-007
// - Decisions: docs/decisions/0010, 0011 (item 2), 0015 (items 1 and 3)

// POAM: AU-9 / AU-9(3) - truncation residual (finding SEC-013). A
// database owner without the audit key can delete every checkpoint after
// any surviving one, delete all records after it, move the head back and
// add up to max_unsigned_records recomputed records; the hash chain and
// cadence rules then verify intact. `audit verify --max-checkpoint-age`
// detects it only when the surviving checkpoint is older than the allowed
// age (the server signs a heartbeat checkpoint every
// checkpoint_heartbeat_s while it runs); a truncation to a checkpoint
// within that age, and any change to the records after the newest
// checkpoint, is detectable only against the externally forwarded stdout
// mirror (plan section 5.6).

// Reads stored rows (untrusted on verification): panicking indexing is
// denied (CLAUDE.md, Engineering Rules).
#![deny(clippy::indexing_slicing)]

pub mod canonical;
pub mod chain;
pub mod checkpoint;
pub mod error;
pub mod memory;
pub mod mirror;
pub mod record;
pub mod store;
pub mod verify;

pub use chain::{AuditChain, seal};
pub use checkpoint::{
    CHECKPOINT_PAYLOAD_TYPE, Checkpoint, CheckpointFault, CheckpointPolicy, CheckpointWritten,
    Checkpointer,
};
pub use error::{AuditError, StoreError, StoreErrorKind};
pub use record::{
    Actor, ActorKind, AuditDraft, AuditRecord, ChainHead, Detail, DetailValue, EVENT_CHECKPOINT,
    EVENT_GENESIS, Interface, parse_outcome,
};
pub use store::{AuditRead, AuditTx, Clock, SystemClock};
pub use usgp_common::event::Outcome;
pub use verify::{
    ChainVerifier, CheckpointAge, Finding, Notice, NoticeKind, VerifyPolicy, VerifyReport,
    Violation, checkpoint_slack_records, verify_chain, verify_chain_with_policy, verify_store,
    verify_store_with_policy,
};
