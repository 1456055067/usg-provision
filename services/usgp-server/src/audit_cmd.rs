//! `audit verify`: verifies the tamper-evident audit chain (plan M2
//! section 5.6; decision 0015 item 3: no audit API in M2, records are read
//! only by this local administrative command on the server host).
//!
//! Trusted audit public keys come from files given with `--trusted-key`,
//! never from the database (a database attacker could insert a key).
//! Exit 0 means intact, 1 tampered (first bad seq and the rule broken),
//! 69 the chain could not be read.
//!
//! The verifier always applies the checkpoint cadence ([`VerifyPolicy`],
//! SEC-002): from `[audit] checkpoint_every_records` in server.toml plus a
//! slack derived from the configured number of concurrent audit writers
//! (`api.max_connections` + `content.check_concurrency` + background
//! tasks; finding SEC-015), or `--max-unsigned-records` when given
//! ([`verify_policy`]). A run of unsigned records longer than that,
//! between checkpoints or after the last, is tampering (exit 1), as is a
//! record above the stored head.
//!
//! With `--max-checkpoint-age DUR` (finding SEC-013) the newest matched
//! checkpoint must have been signed at most DUR before now and before the
//! last record (`checkpoint_stale`, exit 1). The server signs a heartbeat
//! checkpoint every `[audit] checkpoint_heartbeat_s` while it runs, so a
//! chain truncated back to an older checkpoint is caught; while the
//! server is stopped the newest checkpoint ages, so give an age that
//! covers the downtime. Backward timestamps are printed as notices and do
//! not change the exit status (AU-8).
//!
//! The run itself is recorded as `audit.verify` with the result, after
//! the verification and outside the verified range. If that record
//! cannot be written (for example the chain head was damaged so that no
//! record can extend it), the record is mirrored as unpersisted and the
//! verification result stands: refusing to report a broken chain because
//! the broken chain cannot be appended to would hide the tampering.

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-9, AU-9(3) (Protection of Audit Information;
//   Cryptographic Protection) - chain and checkpoint signatures verified
//   against keys from trusted files only.
// - NIST 800-53: AU-9(3) - the checkpoint cadence is enforced, so the
//   unsigned tail an attacker without the key can rewrite is bounded.
// - NIST 800-53: AU-9(3), AU-6 - optional age limit on the newest
//   checkpoint detects truncation to an old checkpoint (SEC-013).
// - NIST 800-53: AU-6 (Audit Record Review) - the local review tool.
// - NIST 800-53: AU-8 - backward timestamps reported.
// - NIST 800-53: AU-12 - the verification is itself recorded.
// - SPEC: specs/operator-access.md#REQ-AUD-005, #REQ-AUD-007;
//   decision 0015 item 3

use std::fmt::Write as _;
use std::time::Duration;

use usgp_audit::{
    AuditChain, AuditError, AuditRead, CheckpointPolicy, Detail, NoticeKind, Outcome, VerifyPolicy,
    VerifyReport, verify_store_with_policy,
};
use usgp_crypto::VerifyingKey;
use usgp_db::Store;

use crate::events::{self, LocalUser};
use crate::{EXIT_FAILURE, EXIT_OK};

/// Records per page read from the store.
pub const PAGE: usize = 1000;

/// The command-line options that shape the verifier policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VerifyOptions {
    /// `--max-unsigned-records`.
    pub max_unsigned_records: Option<u64>,
    /// `--max-checkpoint-age`.
    pub max_checkpoint_age: Option<Duration>,
}

/// The verifier policy: `max_unsigned_records` (the
/// `--max-unsigned-records` option) if given, otherwise derived from the
/// configured checkpoint cadence (`[audit] checkpoint_every_records`) and
/// `max_writers` concurrent audit writers
/// (`usgp_api::ApiConfig::max_audit_writers`; SEC-015). With
/// `--max-checkpoint-age`, the age limit applies at `now_us`.
///
/// # Errors
///
/// [`AuditError::Config`] if the value is out of range (1 to
/// `usgp_audit::verify::MAX_UNSIGNED_RECORDS`); a usage error (exit 2).
pub fn verify_policy(
    checkpoint: &CheckpointPolicy,
    max_writers: u64,
    opts: VerifyOptions,
    now_us: i64,
) -> Result<VerifyPolicy, AuditError> {
    let mut p = opts.max_unsigned_records.map_or_else(
        || VerifyPolicy::for_writers(checkpoint, max_writers),
        VerifyPolicy::records,
    );
    if let Some(age) = opts.max_checkpoint_age {
        let us = u64::try_from(age.as_micros()).unwrap_or(u64::MAX);
        p = p.with_max_checkpoint_age(us, now_us);
    }
    p.validate()?;
    Ok(p)
}

/// Verifies the chain in `store` with `trusted` keys under the default
/// checkpoint cadence ([`VerifyPolicy::default`]: 100 records). Callers
/// that know the configured cadence use [`verify_with_policy`].
///
/// # Errors
///
/// [`AuditError`] if the chain cannot be read or no key is given.
pub async fn verify<S: AuditRead>(
    store: &S,
    trusted: &[VerifyingKey],
) -> Result<VerifyReport, AuditError> {
    verify_with_policy(store, trusted, VerifyPolicy::default()).await
}

/// Verifies the chain in `store` with `trusted` keys and `policy`.
///
/// # Errors
///
/// [`AuditError`] if the chain cannot be read, no key is given or the
/// policy is out of range.
pub async fn verify_with_policy<S: AuditRead>(
    store: &S,
    trusted: &[VerifyingKey],
    policy: VerifyPolicy,
) -> Result<VerifyReport, AuditError> {
    verify_store_with_policy(store, trusted, PAGE, Some(policy)).await
}

/// The exit status for a report: 0 intact, 1 tampered.
#[must_use]
pub fn exit_code(report: &VerifyReport) -> u8 {
    if report.is_intact() {
        EXIT_OK
    } else {
        EXIT_FAILURE
    }
}

/// The report as operator text.
#[must_use]
pub fn render(report: &VerifyReport) -> String {
    let mut out = String::new();
    let opt = |v: Option<u64>| v.map_or_else(|| "none".to_owned(), |n| n.to_string());
    let _ = writeln!(
        out,
        "audit chain: {}",
        if report.is_intact() {
            "intact"
        } else {
            "TAMPERED"
        }
    );
    let _ = writeln!(out, "records checked: {}", report.records_checked);
    let _ = writeln!(out, "last seq: {}", opt(report.last_seq));
    let _ = writeln!(
        out,
        "checkpoints matched: {} of {}",
        report.checkpoints_matched, report.checkpoints_total
    );
    let _ = writeln!(
        out,
        "last checkpoint seq: {}",
        opt(report.last_checkpoint_seq)
    );
    let _ = writeln!(
        out,
        "unsigned tail: {} record(s) (protected only by the hash chain and the external stdout copy)",
        report.unsigned_tail
    );
    let _ = writeln!(
        out,
        "max unsigned records: {}",
        opt(report.max_unsigned_records)
    );
    let _ = writeln!(
        out,
        "newest checkpoint signed at: {}",
        report
            .newest_checkpoint_at_us
            .map_or_else(|| "none".to_owned(), |us| format!("{us} us (UTC)"))
    );
    if let Some(max) = report.max_checkpoint_age_us {
        let _ = writeln!(out, "max checkpoint age: {} s", max / 1_000_000);
    }
    if report.last_checkpoint_seq.is_none() && report.records_checked > 0 {
        let _ = writeln!(
            out,
            "WARNING: no trusted checkpoint covers any record; a fully recomputed chain would not be detected"
        );
    }
    for f in &report.findings {
        let _ = writeln!(out, "finding: seq {} rule {}", f.seq, f.violation.as_str());
    }
    if report.findings_omitted > 0 {
        let _ = writeln!(out, "findings omitted: {}", report.findings_omitted);
    }
    for n in &report.notices {
        match n.kind {
            NoticeKind::TimestampBackwards { previous_us, ts_us } => {
                let _ = writeln!(
                    out,
                    "notice: seq {} {} (previous {previous_us} us, this {ts_us} us; check time synchronisation)",
                    n.seq,
                    n.kind.as_str()
                );
            }
            other => {
                let _ = writeln!(out, "notice: seq {} {}", n.seq, other.as_str());
            }
        }
    }
    if report.notices_omitted > 0 {
        let _ = writeln!(out, "notices omitted: {}", report.notices_omitted);
    }
    out
}

/// Records the verification as `audit.verify` (best effort; see the
/// module documentation).
pub async fn record_result<S: Store>(
    store: &S,
    chain: &AuditChain,
    who: &LocalUser,
    report: &VerifyReport,
    trusted: &[VerifyingKey],
) {
    let intact = report.is_intact();
    let mut d = Detail::new()
        .with("intact", &intact)
        .with("records_checked", &report.records_checked)
        .with("checkpoints_matched", &report.checkpoints_matched)
        .with("unsigned_tail", &report.unsigned_tail)
        .with("notices", &report.notices.len())
        .with("trusted_keys", &trusted.len());
    if let Some(m) = report.max_unsigned_records {
        d = d.with("max_unsigned_records", &m);
    }
    if let Some(m) = report.max_checkpoint_age_us {
        d = d.with("max_checkpoint_age_s", &(m / 1_000_000));
    }
    if let Some(at) = report.newest_checkpoint_at_us {
        d = d.with("newest_checkpoint_at_us", &at);
    }
    if let Some(s) = report.last_checkpoint_seq {
        d = d.with("last_checkpoint_seq", &s);
    }
    let mut draft = who.draft(
        events::AUDIT_VERIFY,
        if intact {
            Outcome::Success
        } else {
            Outcome::Failure
        },
    );
    if let Some(f) = report.first_finding() {
        d = d
            .with("first_bad_seq", &f.seq)
            .with("rule", f.violation.as_str());
        draft = draft.reason("chain_tampered");
    }
    let _ = events::record(store, chain, &draft.detail(d)).await;
}
