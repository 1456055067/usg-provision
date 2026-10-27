//! The API's shared state ([`Api`]) and the audit helpers every handler
//! uses.
//!
//! Pattern for a mutation (plan M2 section 1.1, decision 0015 item 1):
//!
//! 1. `let mut tx = api.store().begin()`;
//! 2. read and lock; refuse (return an error, dropping `tx`) if needed;
//! 3. change, and `Api::append` the record **in the same transaction**;
//! 4. `Api::commit`: commit, then mirror the records to stdout.
//!
//! If the append fails the action is refused with `audit_unavailable` and
//! nothing changes (REQ-AUD-006). Refusals write their record in a
//! transaction of their own (`Api::record_refusal`); if that fails the
//! refusal still stands and the record is mirrored as unpersisted.

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-2, AU-3, AU-12 (Event Logging, Content of Audit
//   Records, Audit Record Generation) - who, what, when, where, source,
//   outcome on every record.
// - NIST 800-53: AU-5 (Response to Audit Logging Process Failures) - an
//   action whose record cannot be written is refused.
// - NIST 800-53: AU-9(3) - signed checkpoints after commits.
// - NIST 800-53: AU-5 - a failed checkpoint raises a rate-limited,
//   unpersisted `audit.checkpoint.failed` mirror line (finding NIST-003).
// - SPEC: specs/operator-access.md#REQ-AUD-001, #REQ-AUD-002, #REQ-AUD-006
// - Decisions 0010, 0015

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use usgp_audit::{
    Actor, AuditChain, AuditDraft, AuditRecord, Checkpointer, Detail, Interface, Outcome, mirror,
};
use usgp_db::{RepoTx, Store};
use usgp_proto::UnixMicros;

use crate::authn::{Principal, UnauthLimiter};
use crate::checker::ContentChecker;
use crate::error::{ApiError, ApiInitError};
use crate::limits::ApiConfig;
use crate::manifest::ContentKeys;
use crate::routes::{Params, RouteSpec};
use crate::store::ContentStore;

/// Component name on mirrored audit lines.
pub const COMPONENT: &str = "usgp-server";

/// The API: store, configuration, keys, audit chain and content store.
/// Cheap to clone.
pub struct Api<S: Store> {
    pub(crate) inner: Arc<Inner<S>>,
}

impl<S: Store> Clone for Api<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<S: Store> std::fmt::Debug for Api<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api")
            .field("node", &self.inner.chain.node())
            .field("keys", &self.inner.keys)
            .finish_non_exhaustive()
    }
}

pub(crate) struct Inner<S> {
    pub(crate) store: S,
    pub(crate) config: ApiConfig,
    pub(crate) chain: AuditChain,
    pub(crate) keys: ContentKeys,
    pub(crate) checkpointer: Option<Checkpointer>,
    pub(crate) files: ContentStore,
    pub(crate) checker: Arc<dyn ContentChecker>,
    pub(crate) check_slots: Arc<Semaphore>,
    pub(crate) unauth: UnauthLimiter,
    pub(crate) checkpoint_alarm: Mutex<AlarmGate>,
}

/// How often at most a failed checkpoint is reported on the mirror.
pub const CHECKPOINT_ALARM_EVERY: Duration = Duration::from_secs(60);

/// Rate limit for a repeated alarm: the first occurrence is reported,
/// then at most one report per interval, carrying the number suppressed
/// in between.
#[derive(Debug)]
pub struct AlarmGate {
    every: Duration,
    last: Option<Instant>,
    suppressed: u64,
}

impl AlarmGate {
    /// A gate reporting at most once per `every`.
    #[must_use]
    pub const fn new(every: Duration) -> Self {
        Self {
            every,
            last: None,
            suppressed: 0,
        }
    }

    /// `Some(n)` if this occurrence is to be reported (`n` occurrences
    /// were suppressed since the last report), `None` if it is suppressed.
    pub fn fire(&mut self, now: Instant) -> Option<u64> {
        match self.last {
            Some(t) if now.saturating_duration_since(t) < self.every => {
                self.suppressed = self.suppressed.saturating_add(1);
                None
            }
            _ => {
                self.last = Some(now);
                Some(std::mem::take(&mut self.suppressed))
            }
        }
    }
}

/// What [`Api::checkpoint`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointStatus {
    /// No checkpointer is configured.
    Disabled,
    /// No checkpoint was due.
    NotDue,
    /// A checkpoint was signed and stored, covering this seq.
    Signed(u64),
    /// The checkpoint failed for this reason (reported on the mirror,
    /// rate-limited); it is retried at the next call.
    Failed(&'static str),
}

/// Builds an [`Api`].
pub struct ApiBuilder<S: Store> {
    store: S,
    config: ApiConfig,
    chain: AuditChain,
    keys: ContentKeys,
    checkpointer: Option<Checkpointer>,
    checker: Option<Arc<dyn ContentChecker>>,
}

impl<S: Store> std::fmt::Debug for ApiBuilder<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiBuilder").finish_non_exhaustive()
    }
}

impl<S: Store + 'static> ApiBuilder<S> {
    /// Uses `checker` instead of the WIM checker (tests).
    #[must_use]
    pub fn checker(mut self, checker: Arc<dyn ContentChecker>) -> Self {
        self.checker = Some(checker);
        self
    }

    /// Signs audit checkpoints after commits when due (plan section 5.6).
    #[must_use]
    pub fn checkpointer(mut self, checkpointer: Checkpointer) -> Self {
        self.checkpointer = Some(checkpointer);
        self
    }

    /// Validates the configuration and opens the content store.
    ///
    /// # Errors
    ///
    /// [`ApiInitError`].
    pub fn build(self) -> Result<Api<S>, ApiInitError> {
        self.config.validate()?;
        let files = ContentStore::open(&self.config.content.root).map_err(|source| {
            ApiInitError::Store {
                what: "open content root",
                source,
            }
        })?;
        let checker = self.checker.unwrap_or_else(|| {
            Arc::new(crate::checker::WimChecker::new(
                self.config.wim_limits.clone(),
            ))
        });
        let slots = self.config.content.check_concurrency;
        let unauth = UnauthLimiter::new(self.config.unauth_caps());
        Ok(Api {
            inner: Arc::new(Inner {
                store: self.store,
                config: self.config,
                chain: self.chain,
                keys: self.keys,
                checkpointer: self.checkpointer,
                files,
                checker,
                check_slots: Arc::new(Semaphore::new(slots)),
                unauth,
                checkpoint_alarm: Mutex::new(AlarmGate::new(CHECKPOINT_ALARM_EVERY)),
            }),
        })
    }
}

/// One authenticated request: who, from where, which route.
#[derive(Debug, Clone)]
pub struct RequestCtx {
    /// The operator.
    pub principal: Principal,
    /// Peer `ip:port`.
    pub source: String,
    /// The matched route.
    pub route: &'static RouteSpec,
    /// Its path parameters.
    pub params: Params,
}

impl RequestCtx {
    /// A draft for this request: operator actor, interface `api`, source.
    #[must_use]
    pub fn draft(&self, event: &str, outcome: Outcome) -> AuditDraft {
        AuditDraft::new(event, outcome, self.principal.actor(), Interface::Api).source(&self.source)
    }

    /// A success draft.
    #[must_use]
    pub fn ok(&self, event: &str) -> AuditDraft {
        self.draft(event, Outcome::Success)
    }
}

/// A draft for a server-initiated state change.
#[must_use]
pub fn system_draft(event: &str, outcome: Outcome) -> AuditDraft {
    AuditDraft::new(event, outcome, Actor::system(), Interface::System)
}

impl<S: Store + 'static> Api<S> {
    /// Starts building an API on `store`. `chain` must already hold its
    /// genesis record (`AuditChain::ensure_genesis`, run by the server at
    /// start-up).
    #[must_use]
    pub fn builder(
        store: S,
        config: ApiConfig,
        chain: AuditChain,
        keys: ContentKeys,
    ) -> ApiBuilder<S> {
        ApiBuilder {
            store,
            config,
            chain,
            keys,
            checkpointer: None,
            checker: None,
        }
    }

    /// The store.
    #[must_use]
    pub fn store(&self) -> &S {
        &self.inner.store
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &ApiConfig {
        &self.inner.config
    }

    /// The content store.
    #[must_use]
    pub fn files(&self) -> &ContentStore {
        &self.inner.files
    }

    /// The content keys.
    #[must_use]
    pub fn keys(&self) -> &ContentKeys {
        &self.inner.keys
    }

    /// The audit chain.
    #[must_use]
    pub fn chain(&self) -> &AuditChain {
        &self.inner.chain
    }

    /// Now, from the audit chain's clock (one time source for records and
    /// rows).
    pub(crate) fn now(&self) -> Result<UnixMicros, ApiError> {
        self.inner
            .chain
            .now_us()
            .ok()
            .and_then(|us| UnixMicros::new(us).ok())
            .ok_or_else(|| ApiError::internal_error("clock unavailable"))
    }

    /// Appends `draft` in `tx`. On failure the draft is mirrored as
    /// unpersisted and the action must be refused (the caller returns the
    /// error, dropping `tx`).
    pub(crate) async fn append(
        &self,
        tx: &mut S::Tx,
        draft: &AuditDraft,
    ) -> Result<AuditRecord, ApiError> {
        match self.inner.chain.append(tx, draft).await {
            Ok(r) => Ok(r),
            Err(e) => {
                mirror::emit_unpersisted(COMPONENT, &self.inner.chain, draft);
                Err(ApiError::audit_unavailable(e))
            }
        }
    }

    /// Commits `tx`, then mirrors `records` and checkpoints if due.
    pub(crate) async fn commit(&self, tx: S::Tx, records: &[AuditRecord]) -> Result<(), ApiError> {
        if let Err(e) = tx.commit().await {
            for r in records {
                mirror::emit_json(COMPONENT, r, false);
            }
            return Err(ApiError::commit_failed(&e));
        }
        for r in records {
            mirror::emit_json(COMPONENT, r, true);
        }
        self.checkpoint(false).await;
        Ok(())
    }

    /// Writes `draft` in a transaction of its own (reads, system events).
    pub(crate) async fn record(&self, draft: &AuditDraft) -> Result<AuditRecord, ApiError> {
        let mut tx = match self.inner.store.begin().await {
            Ok(tx) => tx,
            Err(e) => {
                mirror::emit_unpersisted(COMPONENT, &self.inner.chain, draft);
                return Err(ApiError::audit_unavailable(e));
            }
        };
        let rec = self.append(&mut tx, draft).await?;
        match tx.commit().await {
            Ok(()) => {
                mirror::emit_json(COMPONENT, &rec, true);
                self.checkpoint(false).await;
                Ok(rec)
            }
            Err(e) => {
                mirror::emit_json(COMPONENT, &rec, false);
                if e.outcome_unknown() {
                    Err(ApiError::commit_failed(&e).audited())
                } else {
                    Err(ApiError::audit_unavailable(e))
                }
            }
        }
    }

    /// Writes a refusal record; the refusal stands whether or not the
    /// record could be stored (plan section 1.1).
    pub(crate) async fn record_refusal(&self, draft: &AuditDraft) {
        let _ = self.record(draft).await;
    }

    /// Signs a checkpoint if one is due (or, with `force`, if any record
    /// is new), in its own transaction, and mirrors its record. The server
    /// calls this on a timer and with `force` at clean shutdown; the API
    /// calls it after every commit. The chain itself is already committed,
    /// so a failure does not refuse anything: it is retried at the next
    /// call and reported as an unpersisted `audit.checkpoint.failed`
    /// mirror line with the reason, at most once per
    /// [`CHECKPOINT_ALARM_EVERY`] (AU-5; finding NIST-003).
    pub async fn checkpoint(&self, force: bool) -> CheckpointStatus {
        let Some(cp) = &self.inner.checkpointer else {
            return CheckpointStatus::Disabled;
        };
        let mut tx = match self.inner.store.begin().await {
            Ok(tx) => tx,
            Err(_) => return self.checkpoint_failed("begin_failed"),
        };
        match cp
            .checkpoint_if_due(&self.inner.chain, &mut tx, force)
            .await
        {
            Ok(Some(w)) => {
                let persisted = tx.commit().await.is_ok();
                mirror::emit_json(COMPONENT, &w.record, persisted);
                if persisted {
                    CheckpointStatus::Signed(w.record.seq)
                } else {
                    self.checkpoint_failed("commit_failed")
                }
            }
            Ok(None) => {
                tx.rollback().await;
                CheckpointStatus::NotDue
            }
            Err(_) => {
                tx.rollback().await;
                self.checkpoint_failed("sign_or_write_failed")
            }
        }
    }

    fn checkpoint_failed(&self, reason: &'static str) -> CheckpointStatus {
        let fire = self
            .inner
            .checkpoint_alarm
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .fire(Instant::now());
        if let Some(suppressed) = fire {
            let d = system_draft("audit.checkpoint.failed", Outcome::Failure)
                .reason(reason)
                .detail(Detail::new().with("suppressed_since_last", &suppressed));
            mirror::emit_unpersisted(COMPONENT, &self.inner.chain, &d);
        }
        CheckpointStatus::Failed(reason)
    }

    /// Writes `auth.unauthenticated.summary` if refusals over a cap were
    /// suppressed since the last call (plan section 3.2), with the total,
    /// the number of sources and a count per refusal reason (detail key =
    /// the reason, for example `no_client_certificate` or `revoked`). The
    /// server calls this every 60 s and before `server.stop`.
    pub async fn flush_unauthenticated_summary(&self) {
        let Some(s) = self.inner.unauth.take_summary() else {
            return;
        };
        let mut detail = Detail::new()
            .with("suppressed", &s.suppressed)
            .with("sources", &s.sources);
        for (reason, n) in &s.by_reason {
            detail = detail.with(reason, n);
        }
        let d = system_draft("auth.unauthenticated.summary", Outcome::Refused)
            .reason("rate_capped")
            .detail(detail);
        self.record_refusal(&d).await;
    }
}
