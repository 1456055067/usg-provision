//! In-memory [`Store`] for tests (`usgp-api` runs on it without
//! PostgreSQL). Always compiled; holds no secrets; nothing is durable.
//!
//! It keeps the PostgreSQL rules that callers can observe:
//!
//! - transactions are isolated and atomic: a transaction works on a copy
//!   and publishes it on commit; dropping it discards the copy;
//! - transactions are serialised (one at a time, like the `FOR UPDATE`
//!   locks on the audit head that every audited PostgreSQL transaction
//!   takes). **Do not hold two transactions of one store in the same
//!   task**: the second `begin` waits for the first to end;
//! - the constraints of migration 0001 that a caller can trip (unique
//!   certificate, one live item per digest, image/edition/PE references,
//!   Ready needs a manifest, Failed needs a reason, audit records extend
//!   the head) give the same [`DbError`] classes;
//! - a constraint or audit-write failure poisons the transaction
//!   ([`DbError::TxFailed`] at commit), as PostgreSQL aborts it;
//! - a state change without an audit record cannot commit
//!   ([`DbError::Unaudited`]);
//! - migration 0004's rules: unique tokens, HMACs and live display codes,
//!   compare-and-set session, code, job and step transitions, the guards
//!   (used codes, finished jobs, cleared stops stay so), and the deferred
//!   wipe guard (a job commits only with its `disk.wipe.authorised`
//!   record, which targets it).
//!
//! Audit fault injection ([`MemoryStore::fail_next_audit_writes`],
//! [`MemoryStore::set_fail_audit_writes`], [`MemoryStore::fail_audit_on`])
//! makes audit writes fail, so
//! callers can show that the action is then refused and nothing changes
//! (REQ-AUD-006).

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-5 (Response to Audit Logging Process Failures) -
//   fault injection for the fail-closed tests; unaudited changes refused.
// - SPEC: specs/operator-access.md#REQ-AUD-006
// - Decision 0015 item 1

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::OwnedMutexGuard;
use usgp_audit::{
    AuditRead, AuditRecord, AuditTx, ChainHead, Checkpoint, StoreError, StoreErrorKind,
};
use usgp_common::Sha256Digest;
use usgp_crypto::HmacTag;
use usgp_proto::device::SessionState;
use usgp_proto::limits::MAX_BOOT_SERVICE_PACKAGES;
use usgp_proto::ops::BootServiceStatus;
use usgp_proto::{
    AgentPackageId, AgentPackageManifestV1, AuthCodeId, BootServiceId, BootStopId, ContentId,
    ContentKind, ContentKindV2, ContentState, DiskDescriptorV1, DriverArchiveId, ErrorCode,
    FailureV1, FailureV2, JobId, JobState, LayoutReportV1, MacAddress, MacList, OperatorId,
    PackageId, PackageStatus, SessionId, Step, StepState, StepV2, SupportState, UnixMicros,
    UploadId, UploadState,
};

use crate::error::DbError;
use crate::model::{
    AgentPackage, AgentPackageStatus, AgentSigner, AgentSignerId, ArchiveContent, DeviceValues,
    DriverArchive, DriverArchiveStatus, EscrowRecord, EscrowState, JobStepV2, JobV2,
    NewAgentPackage, NewArchiveContent, NewDriverArchive, NewEscrow, NewJobV2, NewResumeNonce,
    NewResumeToken, NonceIssue, PackageConfig, ReadyArchiveContent, ResumeToken, SealedPassword,
    SignerRevocation,
};
use crate::model::{
    AuthCodeRecord, BootService, BootServicePackage, BootStop, ChosenPackage, Content,
    DeviceSession, Edition, EditionDeclaration, Job, JobStep, NewAuthCode, NewBootStop, NewContent,
    NewDeviceSession, NewJob, Operator, OperatorStatus, Package, PackageRef, ReadyContent, Reason,
    SessionAuth, SessionScope, StoredManifest, Upload,
};
use crate::repo::{RepoTx, Store};

#[derive(Debug, Clone, Default)]
struct State {
    operators: Vec<Operator>,
    content: Vec<Content>,
    editions: Vec<Edition>,
    uploads: Vec<Upload>,
    packages: Vec<Package>,
    boot_services: Vec<BootService>,
    assignments: Vec<BootServicePackage>,
    /// Codes by HMAC; the record never carries the HMAC.
    auth_codes: Vec<(HmacTag, AuthCodeRecord)>,
    sessions: Vec<DeviceSession>,
    jobs: Vec<Job>,
    job_steps: Vec<JobStep>,
    // M4 (migration 0005).
    archives: Vec<ArchiveContent>,
    driver_archives: Vec<DriverArchive>,
    /// Ordered driver lists by package.
    package_drivers: Vec<(PackageId, Vec<DriverArchiveId>)>,
    agent_signers: Vec<AgentSigner>,
    agent_packages: Vec<AgentPackage>,
    package_configs: Vec<PackageConfig>,
    device_values: Vec<DeviceValues>,
    jobs_v2: Vec<JobV2>,
    job_steps_v2: Vec<JobStepV2>,
    /// Nonces by SHA-256: job, issued, expires, used.
    resume_nonces: Vec<MemNonce>,
    /// Tokens by SHA-256.
    resume_tokens: Vec<(Sha256Digest, ResumeToken)>,
    escrows: Vec<(EscrowRecord, SealedPassword)>,
    boot_stops: Vec<BootStop>,
    generations: Vec<(BootServiceId, u64)>,
    records: Vec<AuditRecord>,
    checkpoints: Vec<Checkpoint>,
    head: Option<ChainHead>,
}

#[derive(Debug, Clone)]
struct MemNonce {
    hash: Sha256Digest,
    job_id: JobId,
    expires_at: UnixMicros,
    used_at: Option<UnixMicros>,
}

#[derive(Debug, Default)]
struct Faults {
    fail_next: u32,
    fail_all: bool,
    /// Record writes of these events fail (plan WU-7 `fail_audit_on`).
    fail_events: Vec<String>,
}

impl Faults {
    fn take(&mut self) -> bool {
        if self.fail_all {
            return true;
        }
        if self.fail_next > 0 {
            self.fail_next -= 1;
            return true;
        }
        false
    }
}

#[derive(Debug, Default)]
struct Shared {
    state: Mutex<State>,
    faults: Mutex<Faults>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A shared in-memory store. Clones share the data.
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    shared: Arc<Shared>,
    writer: Arc<tokio::sync::Mutex<()>>,
}

impl MemoryStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes the next `n` audit writes (record or checkpoint) fail.
    pub fn fail_next_audit_writes(&self, n: u32) {
        lock(&self.shared.faults).fail_next = n;
    }

    /// Makes every audit write fail while `on`.
    pub fn set_fail_audit_writes(&self, on: bool) {
        lock(&self.shared.faults).fail_all = on;
    }

    /// Makes every write of an audit record with this event fail (for
    /// example `disk.wipe.authorised`, acceptance criterion 3), until
    /// [`MemoryStore::clear_audit_faults`].
    pub fn fail_audit_on(&self, event: &str) {
        lock(&self.shared.faults).fail_events.push(event.to_owned());
    }

    /// Removes every audit fault.
    pub fn clear_audit_faults(&self) {
        *lock(&self.shared.faults) = Faults::default();
    }

    /// The committed audit records.
    #[must_use]
    pub fn audit_records(&self) -> Vec<AuditRecord> {
        lock(&self.shared.state).records.clone()
    }

    /// The committed checkpoints.
    #[must_use]
    pub fn audit_checkpoints(&self) -> Vec<Checkpoint> {
        lock(&self.shared.state).checkpoints.clone()
    }

    /// Direct access to the committed audit rows, to simulate an attacker
    /// with database access in tests.
    pub fn tamper_audit_for_test(
        &self,
        f: impl FnOnce(&mut Vec<AuditRecord>, &mut Vec<Checkpoint>, &mut Option<ChainHead>),
    ) {
        let mut s = lock(&self.shared.state);
        let State {
            records,
            checkpoints,
            head,
            ..
        } = &mut *s;
        f(records, checkpoints, head);
    }
}

impl Store for MemoryStore {
    type Tx = MemoryTx;

    async fn begin(&self) -> Result<MemoryTx, DbError> {
        let guard = Arc::clone(&self.writer).lock_owned().await;
        let work = lock(&self.shared.state).clone();
        Ok(MemoryTx {
            shared: Arc::clone(&self.shared),
            _guard: guard,
            work,
            mutated: false,
            audited: false,
            failed: false,
        })
    }
}

impl AuditRead for MemoryStore {
    async fn head(&self) -> Result<Option<ChainHead>, StoreError> {
        Ok(lock(&self.shared.state).head)
    }

    async fn records_after(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<AuditRecord>, StoreError> {
        let mut out: Vec<AuditRecord> = lock(&self.shared.state)
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
        let mut out = lock(&self.shared.state).checkpoints.clone();
        out.sort_by_key(|c| c.seq);
        Ok(out)
    }
}

/// One in-memory transaction.
#[derive(Debug)]
pub struct MemoryTx {
    shared: Arc<Shared>,
    _guard: OwnedMutexGuard<()>,
    work: State,
    mutated: bool,
    audited: bool,
    failed: bool,
}

/// Session states in which the display code must be unique (migration
/// 0004 partial index) and which expire.
const LIVE_SESSION: [SessionState; 2] = [
    SessionState::AwaitingAuthorisation,
    SessionState::Authorised,
];

/// The event a job's wipe reference must name (migration 0004).
const WIPE_EVENT: &str = "disk.wipe.authorised";

const LIVE: [ContentState; 3] = [
    ContentState::Receiving,
    ContentState::Checking,
    ContentState::Ready,
];

impl MemoryTx {
    fn check(&self) -> Result<(), DbError> {
        if self.failed {
            return Err(DbError::TxFailed);
        }
        Ok(())
    }

    /// A write is starting.
    fn write(&mut self) -> Result<(), DbError> {
        self.check()?;
        self.mutated = true;
        Ok(())
    }

    /// A constraint failed: PostgreSQL aborts the transaction.
    fn abort(&mut self, e: DbError) -> DbError {
        self.failed = true;
        e
    }

    fn content_ref(&self, id: ContentId) -> Option<&Content> {
        self.work.content.iter().find(|c| c.id == id)
    }

    fn content_mut(&mut self, id: ContentId) -> Option<&mut Content> {
        self.work.content.iter_mut().find(|c| c.id == id)
    }

    fn operator_exists(&self, id: OperatorId) -> bool {
        self.work.operators.iter().any(|o| o.id == id)
    }

    fn session_ref(&self, id: SessionId) -> Option<&DeviceSession> {
        self.work.sessions.iter().find(|s| s.id == id)
    }

    fn session_mut(&mut self, id: SessionId) -> Option<&mut DeviceSession> {
        self.work.sessions.iter_mut().find(|s| s.id == id)
    }

    fn job_ref(&self, id: JobId) -> Option<&Job> {
        self.work.jobs.iter().find(|j| j.id == id)
    }

    fn job_mut(&mut self, id: JobId) -> Option<&mut Job> {
        self.work.jobs.iter_mut().find(|j| j.id == id)
    }

    /// The deferred wipe guard of migration 0004: every job names a
    /// stored, successful `disk.wipe.authorised` record that targets it.
    fn wipe_records_ok(&self) -> bool {
        let ok = |id: JobId, seq: u64, hash: Sha256Digest| {
            let target = id.to_string();
            self.work.records.iter().any(|r| {
                r.seq == seq
                    && r.record_hash == hash
                    && r.event == WIPE_EVENT
                    && r.outcome == "success"
                    && r.target_kind.as_deref() == Some("job")
                    && r.target_id.as_deref() == Some(target.as_str())
            })
        };
        self.work
            .jobs
            .iter()
            .all(|j| ok(j.id, j.wipe_audit_seq, j.wipe_record_hash))
            && self
                .work
                .jobs_v2
                .iter()
                .all(|j| ok(j.id, j.wipe_audit_seq, j.wipe_record_hash))
    }

    /// Any content item (any kind) has this id.
    fn content_id_taken(&self, id: ContentId) -> bool {
        self.content_ref(id).is_some() || self.work.archives.iter().any(|a| a.id == id)
    }

    /// A live item (any kind) has this digest (0001 partial index).
    fn live_digest(&self, sha: &Sha256Digest) -> bool {
        self.work
            .content
            .iter()
            .any(|x| x.sha256 == *sha && LIVE.contains(&x.state))
            || self
                .work
                .archives
                .iter()
                .any(|x| x.sha256 == *sha && LIVE.contains(&x.state))
    }

    /// A job of either schema exists.
    fn job_exists(&self, id: JobId) -> bool {
        self.job_ref(id).is_some() || self.work.jobs_v2.iter().any(|j| j.id == id)
    }

    /// The unique job columns of 0004 (id, session, wipe record) across
    /// both schemas.
    fn job_identity_taken(&self, id: JobId, session: SessionId, wipe_seq: u64) -> bool {
        self.work
            .jobs
            .iter()
            .any(|x| x.id == id || x.session_id == session || x.wipe_audit_seq == wipe_seq)
            || self
                .work
                .jobs_v2
                .iter()
                .any(|x| x.id == id || x.session_id == session || x.wipe_audit_seq == wipe_seq)
    }

    /// `set_job_state` for a v2 job: success needs step 9 done.
    fn set_job_v2_state(
        &mut self,
        id: JobId,
        from: &[JobState],
        to: JobState,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        let step9_done = self.work.job_steps_v2.iter().any(|s| {
            s.job_id == id && s.step == StepV2::REPORT_READY && s.state == StepState::Done
        });
        let Some(j) = self.work.jobs_v2.iter_mut().find(|j| j.id == id) else {
            return Err(DbError::NotFound { what: "job" });
        };
        if !from.contains(&j.state) || (to == JobState::Succeeded && !step9_done) {
            return Err(DbError::Conflict { what: "job" });
        }
        if j.state != to && !j.state.can_become(to) {
            self.failed = true;
            return Err(DbError::Constraint {
                what: "update job state",
            });
        }
        j.state = to;
        j.finished_at = (to == JobState::Succeeded).then_some(at);
        Ok(())
    }

    fn package_refs(&self, f: impl Fn(&Package) -> bool) -> Vec<PackageRef> {
        let mut v: Vec<&Package> = self.work.packages.iter().filter(|p| f(p)).collect();
        v.sort_by_key(|p| (p.created_at, p.id));
        v.into_iter()
            .map(|p| PackageRef {
                id: p.id,
                name: p.name.clone(),
            })
            .collect()
    }

    /// The package references of 0001: image is an image with that
    /// edition, PE is a PE, creator exists.
    fn check_package_refs(&self, p: &Package) -> Result<(), DbError> {
        let image_ok = self
            .content_ref(p.image_id)
            .is_some_and(|c| c.kind == ContentKind::Image)
            && self
                .work
                .editions
                .iter()
                .any(|e| e.content_id == p.image_id && e.index == p.edition_index);
        let pe_ok = self
            .content_ref(p.pe_id)
            .is_some_and(|c| c.kind == ContentKind::Pe);
        let by_ok = self.work.operators.iter().any(|o| o.id == p.created_by);
        let manifest_ok = p.status != PackageStatus::Ready || p.manifest.is_some();
        let reason_ok = p.status == PackageStatus::Ready || p.status_reason.is_some();
        if image_ok && pe_ok && by_ok && manifest_ok && reason_ok {
            Ok(())
        } else {
            Err(DbError::Constraint { what: "package" })
        }
    }
}

fn faulted(shared: &Shared, ctx: &'static str) -> Result<(), StoreError> {
    if lock(&shared.faults).take() {
        return Err(StoreError::new(StoreErrorKind::Injected, ctx));
    }
    Ok(())
}

fn faulted_event(shared: &Shared, ctx: &'static str, event: &str) -> Result<(), StoreError> {
    if lock(&shared.faults).fail_events.iter().any(|e| e == event) {
        return Err(StoreError::new(StoreErrorKind::Injected, ctx));
    }
    faulted(shared, ctx)
}

impl AuditTx for MemoryTx {
    async fn lock_head(&mut self) -> Result<Option<ChainHead>, StoreError> {
        self.check().map_err(|e| e.into_store("lock audit_head"))?;
        Ok(self.work.head)
    }

    async fn insert_record(&mut self, rec: &AuditRecord) -> Result<(), StoreError> {
        let ctx = "insert audit_record";
        self.write().map_err(|e| e.into_store(ctx))?;
        if let Err(e) = faulted_event(&self.shared, ctx, &rec.event) {
            self.failed = true;
            return Err(e);
        }
        // As the 0001 trigger: the record must extend the head.
        let (next, prev) = match self.work.head {
            Some(h) => (h.seq.checked_add(1), h.record_hash),
            None => (Some(1), Sha256Digest([0; 32])),
        };
        if next != Some(rec.seq) || prev != rec.prev_hash {
            self.failed = true;
            return Err(StoreError::new(StoreErrorKind::Conflict, ctx));
        }
        self.work.records.push(rec.clone());
        self.work.head = Some(ChainHead::from(rec));
        self.audited = true;
        Ok(())
    }

    async fn insert_checkpoint(&mut self, cp: &Checkpoint) -> Result<(), StoreError> {
        let ctx = "insert audit_checkpoint";
        self.write().map_err(|e| e.into_store(ctx))?;
        if let Err(e) = faulted(&self.shared, ctx) {
            self.failed = true;
            return Err(e);
        }
        let matches = self
            .work
            .records
            .iter()
            .any(|r| r.seq == cp.seq && r.record_hash == cp.record_hash);
        if !matches || self.work.checkpoints.iter().any(|c| c.seq == cp.seq) {
            self.failed = true;
            return Err(StoreError::new(StoreErrorKind::Conflict, ctx));
        }
        self.work.checkpoints.push(cp.clone());
        Ok(())
    }

    async fn last_checkpoint(&mut self) -> Result<Option<Checkpoint>, StoreError> {
        self.check()
            .map_err(|e| e.into_store("read audit_checkpoint"))?;
        Ok(self.work.checkpoints.iter().max_by_key(|c| c.seq).cloned())
    }
}

impl RepoTx for MemoryTx {
    async fn operator(&mut self, id: OperatorId) -> Result<Option<Operator>, DbError> {
        self.check()?;
        Ok(self.work.operators.iter().find(|o| o.id == id).cloned())
    }

    async fn operator_by_cert(&mut self, sha: &Sha256Digest) -> Result<Option<Operator>, DbError> {
        self.check()?;
        Ok(self
            .work
            .operators
            .iter()
            .find(|o| o.cert_sha256 == *sha)
            .cloned())
    }

    async fn list_operators(&mut self) -> Result<Vec<Operator>, DbError> {
        self.check()?;
        let mut v = self.work.operators.clone();
        v.sort_by_key(|o| (o.created_at, o.id));
        Ok(v)
    }

    async fn insert_operator(&mut self, op: &Operator) -> Result<(), DbError> {
        self.write()?;
        if self
            .work
            .operators
            .iter()
            .any(|o| o.id == op.id || o.cert_sha256 == op.cert_sha256)
        {
            return Err(self.abort(DbError::Conflict {
                what: "insert operator",
            }));
        }
        self.work.operators.push(op.clone());
        Ok(())
    }

    async fn set_operator_status(
        &mut self,
        id: OperatorId,
        status: OperatorStatus,
    ) -> Result<(), DbError> {
        self.write()?;
        match self.work.operators.iter_mut().find(|o| o.id == id) {
            Some(o) => {
                o.status = status;
                Ok(())
            }
            None => Err(DbError::NotFound { what: "operator" }),
        }
    }

    async fn content(&mut self, id: ContentId) -> Result<Option<Content>, DbError> {
        self.check()?;
        Ok(self.content_ref(id).cloned())
    }

    async fn lock_content(&mut self, id: ContentId) -> Result<Option<Content>, DbError> {
        self.content(id).await
    }

    async fn content_by_sha256(&mut self, sha: &Sha256Digest) -> Result<Option<Content>, DbError> {
        self.check()?;
        Ok(self
            .work
            .content
            .iter()
            .find(|c| c.sha256 == *sha && LIVE.contains(&c.state))
            .cloned())
    }

    async fn list_content(
        &mut self,
        kind: Option<ContentKind>,
        states: &[ContentState],
    ) -> Result<Vec<Content>, DbError> {
        self.check()?;
        let mut v: Vec<Content> = self
            .work
            .content
            .iter()
            .filter(|c| kind.is_none_or(|k| c.kind == k))
            .filter(|c| states.is_empty() || states.contains(&c.state))
            .cloned()
            .collect();
        v.sort_by_key(|c| (c.created_at, c.id));
        Ok(v)
    }

    async fn create_upload(&mut self, c: &NewContent, u: &Upload) -> Result<(), DbError> {
        if (c.kind == ContentKind::Pe) != c.pe.is_some() {
            return Err(DbError::InvalidArgument {
                what: "pe declaration",
            });
        }
        if u.content_id != c.id || u.declared_size != c.size || u.declared_sha256 != c.sha256 {
            return Err(DbError::InvalidArgument {
                what: "upload does not match content",
            });
        }
        if i64::try_from(c.size).is_err() || c.size == 0 {
            return Err(DbError::InvalidArgument { what: "size" });
        }
        self.write()?;
        if self.content_id_taken(c.id) || self.live_digest(&c.sha256) {
            return Err(self.abort(DbError::Conflict {
                what: "insert content",
            }));
        }
        if self
            .work
            .uploads
            .iter()
            .any(|x| x.id == u.id || x.staging_name == u.staging_name)
        {
            return Err(self.abort(DbError::Conflict {
                what: "insert upload",
            }));
        }
        if !self.work.operators.iter().any(|o| o.id == c.created_by)
            || !self.work.operators.iter().any(|o| o.id == u.operator_id)
        {
            return Err(self.abort(DbError::Constraint {
                what: "insert content",
            }));
        }
        self.work.content.push(Content {
            id: c.id,
            kind: c.kind,
            display_name: c.display_name.clone(),
            file_name: c.file_name.clone(),
            size: c.size,
            sha256: c.sha256,
            state: ContentState::Receiving,
            reason: None,
            created_by: c.created_by,
            initiating_audit_seq: c.initiating_audit_seq,
            created_at: c.created_at,
            updated_at: c.created_at,
            ready_at: None,
            wim: None,
            usable_index: None,
            pe: c.pe.clone(),
            manifest: None,
        });
        self.work.uploads.push(u.clone());
        Ok(())
    }

    async fn set_content_state(
        &mut self,
        id: ContentId,
        from: &[ContentState],
        to: ContentState,
        reason: Option<&Reason>,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        if to == ContentState::Ready {
            return Err(DbError::InvalidArgument {
                what: "use set_content_ready",
            });
        }
        if to == ContentState::Failed && reason.is_none() {
            return Err(DbError::InvalidArgument {
                what: "reason required for failed",
            });
        }
        self.write()?;
        if let Some(a) = self.work.archives.iter_mut().find(|a| a.id == id) {
            if !from.contains(&a.state) {
                return Err(DbError::Conflict { what: "content" });
            }
            a.state = to;
            if let Some(r) = reason {
                a.reason = Some(r.clone());
            }
            a.updated_at = at;
            return Ok(());
        }
        let c = self
            .content_mut(id)
            .ok_or(DbError::NotFound { what: "content" })?;
        if !from.contains(&c.state) {
            return Err(DbError::Conflict { what: "content" });
        }
        c.state = to;
        if let Some(r) = reason {
            c.reason = Some(r.clone());
        }
        c.updated_at = at;
        Ok(())
    }

    async fn set_content_ready(&mut self, id: ContentId, r: &ReadyContent) -> Result<(), DbError> {
        let count = usize::try_from(r.wim.image_count).map_err(|_| DbError::InvalidArgument {
            what: "image_count",
        })?;
        if r.editions.len() != count
            || r.editions
                .iter()
                .enumerate()
                .any(|(i, e)| usize::try_from(e.index).ok() != Some(i + 1))
        {
            return Err(DbError::InvalidArgument {
                what: "editions must be 1..=image_count",
            });
        }
        self.write()?;
        let c = self
            .content_mut(id)
            .ok_or(DbError::NotFound { what: "content" })?;
        if c.state != ContentState::Checking {
            return Err(DbError::Conflict { what: "content" });
        }
        if c.kind == ContentKind::Pe && r.usable_index.is_none() {
            return Err(self.abort(DbError::Constraint {
                what: "update content ready",
            }));
        }
        let c = self
            .content_mut(id)
            .ok_or(DbError::NotFound { what: "content" })?;
        c.state = ContentState::Ready;
        c.reason = None;
        c.updated_at = r.at;
        c.ready_at = Some(r.at);
        c.wim = Some(r.wim);
        c.usable_index = r.usable_index;
        c.manifest = Some(r.manifest.clone());
        if let Some(pe) = &r.pe {
            c.pe = Some(pe.clone());
        }
        for e in &r.editions {
            self.work.editions.push(Edition {
                content_id: id,
                index: e.index,
                name: e.name.clone(),
                description: e.description.clone(),
                total_bytes: e.total_bytes,
                declaration: None,
                support: SupportState::Unknown,
                support_reason: None,
            });
        }
        Ok(())
    }

    async fn editions(&mut self, content_id: ContentId) -> Result<Vec<Edition>, DbError> {
        self.check()?;
        let mut v: Vec<Edition> = self
            .work
            .editions
            .iter()
            .filter(|e| e.content_id == content_id)
            .cloned()
            .collect();
        v.sort_by_key(|e| e.index);
        Ok(v)
    }

    async fn edition(
        &mut self,
        content_id: ContentId,
        index: u32,
    ) -> Result<Option<Edition>, DbError> {
        self.check()?;
        Ok(self
            .work
            .editions
            .iter()
            .find(|e| e.content_id == content_id && e.index == index)
            .cloned())
    }

    async fn set_edition_declaration(
        &mut self,
        content_id: ContentId,
        index: u32,
        d: &EditionDeclaration,
        support: SupportState,
        support_reason: Option<&str>,
    ) -> Result<(), DbError> {
        self.write()?;
        if !self.work.operators.iter().any(|o| o.id == d.declared_by) {
            return Err(self.abort(DbError::Constraint {
                what: "update edition declaration",
            }));
        }
        let e = self
            .work
            .editions
            .iter_mut()
            .find(|e| e.content_id == content_id && e.index == index)
            .ok_or(DbError::NotFound { what: "edition" })?;
        e.declaration = Some(d.clone());
        e.support = support;
        e.support_reason = support_reason.map(str::to_owned);
        Ok(())
    }

    async fn upload(&mut self, id: UploadId) -> Result<Option<Upload>, DbError> {
        self.check()?;
        Ok(self.work.uploads.iter().find(|u| u.id == id).cloned())
    }

    async fn lock_upload(&mut self, id: UploadId) -> Result<Option<Upload>, DbError> {
        self.upload(id).await
    }

    async fn list_uploads(&mut self, states: &[UploadState]) -> Result<Vec<Upload>, DbError> {
        self.check()?;
        let mut v: Vec<Upload> = self
            .work
            .uploads
            .iter()
            .filter(|u| states.is_empty() || states.contains(&u.state))
            .cloned()
            .collect();
        v.sort_by_key(|u| (u.created_at, u.id));
        Ok(v)
    }

    async fn lock_upload_quota(&mut self) -> Result<(), DbError> {
        // Transactions on the memory store are already serialised (the
        // writer lock is held from `begin` to the end).
        self.check()
    }

    async fn count_active_uploads(&mut self, operator: Option<OperatorId>) -> Result<u64, DbError> {
        self.check()?;
        let n = self
            .work
            .uploads
            .iter()
            .filter(|u| matches!(u.state, UploadState::Open | UploadState::Streaming))
            .filter(|u| operator.is_none_or(|o| u.operator_id == o))
            .count();
        u64::try_from(n).map_err(|_| DbError::Corrupt { what: "count" })
    }

    async fn set_upload_state(
        &mut self,
        id: UploadId,
        from: &[UploadState],
        to: UploadState,
    ) -> Result<(), DbError> {
        self.write()?;
        let u = self
            .work
            .uploads
            .iter_mut()
            .find(|u| u.id == id)
            .ok_or(DbError::NotFound { what: "upload" })?;
        if !from.contains(&u.state) {
            return Err(DbError::Conflict { what: "upload" });
        }
        u.state = to;
        Ok(())
    }

    async fn package(&mut self, id: PackageId) -> Result<Option<Package>, DbError> {
        self.check()?;
        Ok(self.work.packages.iter().find(|p| p.id == id).cloned())
    }

    async fn lock_package(&mut self, id: PackageId) -> Result<Option<Package>, DbError> {
        self.package(id).await
    }

    async fn list_packages(&mut self) -> Result<Vec<Package>, DbError> {
        self.check()?;
        let mut v = self.work.packages.clone();
        v.sort_by_key(|p| (p.created_at, p.id));
        Ok(v)
    }

    async fn packages_using_content(&mut self, id: ContentId) -> Result<Vec<PackageRef>, DbError> {
        self.check()?;
        Ok(self.package_refs(|p| p.image_id == id || p.pe_id == id))
    }

    async fn packages_using_edition(
        &mut self,
        content_id: ContentId,
        index: u32,
    ) -> Result<Vec<PackageRef>, DbError> {
        self.check()?;
        Ok(self.package_refs(|p| p.image_id == content_id && p.edition_index == index))
    }

    async fn insert_package(&mut self, p: &Package) -> Result<(), DbError> {
        if p.revision != 1 {
            return Err(DbError::InvalidArgument {
                what: "new package revision must be 1",
            });
        }
        self.write()?;
        if self.work.packages.iter().any(|x| x.id == p.id) {
            return Err(self.abort(DbError::Conflict {
                what: "insert package",
            }));
        }
        if let Err(e) = self.check_package_refs(p) {
            return Err(self.abort(e));
        }
        self.work.packages.push(p.clone());
        Ok(())
    }

    async fn update_package(&mut self, p: &Package, expected: u64) -> Result<(), DbError> {
        if Some(p.revision) != expected.checked_add(1) {
            return Err(DbError::InvalidArgument {
                what: "revision must be expected + 1",
            });
        }
        self.write()?;
        let Some(cur) = self.work.packages.iter().find(|x| x.id == p.id) else {
            return Err(DbError::NotFound { what: "package" });
        };
        if cur.revision != expected {
            return Err(DbError::Conflict { what: "package" });
        }
        if let Err(e) = self.check_package_refs(p) {
            return Err(self.abort(e));
        }
        let mut new = p.clone();
        new.created_at = cur.created_at;
        new.created_by = cur.created_by;
        if let Some(slot) = self.work.packages.iter_mut().find(|x| x.id == p.id) {
            *slot = new;
        }
        Ok(())
    }

    async fn set_package_status(
        &mut self,
        id: PackageId,
        status: PackageStatus,
        reason: Option<&str>,
        manifest: Option<&StoredManifest>,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        self.write()?;
        if (status == PackageStatus::Ready && manifest.is_none())
            || (status != PackageStatus::Ready && reason.is_none())
        {
            return Err(self.abort(DbError::Constraint {
                what: "update package status",
            }));
        }
        let p = self
            .work
            .packages
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or(DbError::NotFound { what: "package" })?;
        p.status = status;
        p.status_reason = reason.map(str::to_owned);
        p.manifest = manifest.cloned();
        p.updated_at = at;
        Ok(())
    }

    async fn delete_package(&mut self, id: PackageId, expected: u64) -> Result<(), DbError> {
        self.write()?;
        let Some(pos) = self.work.packages.iter().position(|p| p.id == id) else {
            return Err(DbError::NotFound { what: "package" });
        };
        if self.work.packages.get(pos).map(|p| p.revision) != Some(expected) {
            return Err(DbError::Conflict { what: "package" });
        }
        // Migration 0004: an assigned package cannot be deleted.
        if self.work.assignments.iter().any(|a| a.package_id == id) {
            return Err(self.abort(DbError::Constraint {
                what: "delete package",
            }));
        }
        self.work.packages.remove(pos);
        // Migration 0005: configuration and driver list go with it.
        self.work.package_drivers.retain(|(p, _)| *p != id);
        self.work.package_configs.retain(|c| c.package_id != id);
        Ok(())
    }

    async fn boot_service(&mut self, id: BootServiceId) -> Result<Option<BootService>, DbError> {
        self.check()?;
        Ok(self.work.boot_services.iter().find(|b| b.id == id).cloned())
    }

    async fn boot_service_by_cert(
        &mut self,
        sha: &Sha256Digest,
    ) -> Result<Option<BootService>, DbError> {
        self.check()?;
        Ok(self
            .work
            .boot_services
            .iter()
            .find(|b| b.cert_sha256 == *sha)
            .cloned())
    }

    async fn list_boot_services(&mut self) -> Result<Vec<BootService>, DbError> {
        self.check()?;
        let mut v = self.work.boot_services.clone();
        v.sort_by_key(|b| (b.created_at, b.id));
        Ok(v)
    }

    async fn insert_boot_service(&mut self, b: &BootService) -> Result<(), DbError> {
        if b.created_by.contains('\0') {
            return Err(DbError::InvalidArgument { what: "created_by" });
        }
        self.write()?;
        if self
            .work
            .boot_services
            .iter()
            .any(|x| x.id == b.id || x.name == b.name || x.cert_sha256 == b.cert_sha256)
        {
            return Err(self.abort(DbError::Conflict {
                what: "insert boot_service",
            }));
        }
        self.work.boot_services.push(b.clone());
        Ok(())
    }

    async fn set_boot_service_status(
        &mut self,
        id: BootServiceId,
        status: BootServiceStatus,
    ) -> Result<(), DbError> {
        self.write()?;
        match self.work.boot_services.iter_mut().find(|b| b.id == id) {
            Some(b) => {
                b.status = status;
                Ok(())
            }
            None => Err(DbError::NotFound {
                what: "boot service",
            }),
        }
    }

    async fn boot_service_packages(
        &mut self,
        id: BootServiceId,
    ) -> Result<Vec<BootServicePackage>, DbError> {
        self.check()?;
        let mut v: Vec<BootServicePackage> = self
            .work
            .assignments
            .iter()
            .filter(|a| a.boot_service_id == id)
            .cloned()
            .collect();
        v.sort_by_key(|a| (a.added_at, a.package_id));
        Ok(v)
    }

    async fn set_boot_service_packages(
        &mut self,
        id: BootServiceId,
        package_ids: &[PackageId],
        by: OperatorId,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        let mut wanted = package_ids.to_vec();
        wanted.sort();
        wanted.dedup();
        if wanted.len() != package_ids.len() || wanted.len() > MAX_BOOT_SERVICE_PACKAGES {
            return Err(DbError::InvalidArgument {
                what: "package ids (distinct, at most 256)",
            });
        }
        self.check()?;
        if !self.work.boot_services.iter().any(|b| b.id == id) {
            return Err(DbError::NotFound {
                what: "boot service",
            });
        }
        self.write()?;
        self.work
            .assignments
            .retain(|a| a.boot_service_id != id || wanted.contains(&a.package_id));
        for p in wanted {
            if self
                .work
                .assignments
                .iter()
                .any(|a| a.boot_service_id == id && a.package_id == p)
            {
                continue;
            }
            if !self.work.packages.iter().any(|x| x.id == p) || !self.operator_exists(by) {
                return Err(self.abort(DbError::Constraint {
                    what: "insert boot_service_package",
                }));
            }
            self.work.assignments.push(BootServicePackage {
                boot_service_id: id,
                package_id: p,
                added_by: by,
                added_at: at,
            });
        }
        Ok(())
    }

    async fn boot_services_using_package(
        &mut self,
        id: PackageId,
    ) -> Result<Vec<BootServiceId>, DbError> {
        self.check()?;
        let mut v: Vec<BootServiceId> = self
            .work
            .assignments
            .iter()
            .filter(|a| a.package_id == id)
            .map(|a| a.boot_service_id)
            .collect();
        v.sort();
        Ok(v)
    }

    async fn boot_stop(&mut self, id: BootStopId) -> Result<Option<BootStop>, DbError> {
        self.check()?;
        Ok(self.work.boot_stops.iter().find(|s| s.id == id).copied())
    }

    async fn list_boot_stops(
        &mut self,
        boot_service: Option<BootServiceId>,
        active_only: bool,
    ) -> Result<Vec<BootStop>, DbError> {
        self.check()?;
        let mut v: Vec<BootStop> = self
            .work
            .boot_stops
            .iter()
            .filter(|s| boot_service.is_none_or(|b| s.boot_service_id == b))
            .filter(|s| !active_only || s.cleared_at.is_none())
            .copied()
            .collect();
        v.sort_by_key(|s| (s.created_at, s.id));
        Ok(v)
    }

    async fn add_boot_stop(&mut self, s: &NewBootStop) -> Result<bool, DbError> {
        self.write()?;
        if self.work.boot_stops.iter().any(|x| x.id == s.id) {
            return Err(self.abort(DbError::Conflict {
                what: "insert boot_stop",
            }));
        }
        if !self
            .work
            .boot_services
            .iter()
            .any(|b| b.id == s.boot_service_id)
            // `REFERENCES job (id)`: a job of either schema (M4 stops are
            // added at step 6 of a v2 job).
            || !self.job_exists(s.job_id)
        {
            return Err(self.abort(DbError::Constraint {
                what: "insert boot_stop",
            }));
        }
        if self.work.boot_stops.iter().any(|x| {
            x.boot_service_id == s.boot_service_id && x.mac == s.mac && x.cleared_at.is_none()
        }) {
            return Ok(false);
        }
        self.work.boot_stops.push(BootStop {
            id: s.id,
            boot_service_id: s.boot_service_id,
            mac: s.mac,
            job_id: s.job_id,
            created_at: s.created_at,
            cleared_at: None,
            cleared_by: None,
        });
        Ok(true)
    }

    async fn clear_boot_stop(
        &mut self,
        id: BootStopId,
        by: OperatorId,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        self.write()?;
        let Some(cleared) = self
            .work
            .boot_stops
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.cleared_at.is_some())
        else {
            return Err(DbError::NotFound { what: "boot stop" });
        };
        if cleared {
            return Err(DbError::Conflict { what: "boot stop" });
        }
        if !self.operator_exists(by) {
            return Err(self.abort(DbError::Constraint {
                what: "update boot_stop",
            }));
        }
        if let Some(s) = self.work.boot_stops.iter_mut().find(|s| s.id == id) {
            s.cleared_at = Some(at);
            s.cleared_by = Some(by);
        }
        Ok(())
    }

    async fn boot_policy_generation(&mut self, id: BootServiceId) -> Result<u64, DbError> {
        self.check()?;
        Ok(self
            .work
            .generations
            .iter()
            .find(|(b, _)| *b == id)
            .map_or(0, |(_, g)| *g))
    }

    async fn active_boot_stops_for_macs(
        &mut self,
        macs: &MacList,
    ) -> Result<Vec<BootStop>, DbError> {
        self.check()?;
        let mut v: Vec<BootStop> = self
            .work
            .boot_stops
            .iter()
            .filter(|s| s.cleared_at.is_none() && macs.as_slice().contains(&s.mac))
            .copied()
            .collect();
        v.sort_by_key(|s| (s.created_at, s.id));
        Ok(v)
    }

    async fn raise_boot_policy_generation(
        &mut self,
        id: BootServiceId,
        to: u64,
    ) -> Result<(), DbError> {
        if to == 0 || i64::try_from(to).is_err() {
            return Err(DbError::InvalidArgument { what: "generation" });
        }
        self.check()?;
        if !self.work.boot_services.iter().any(|b| b.id == id) {
            return Err(self.abort(DbError::Constraint {
                what: "update boot_policy_generation",
            }));
        }
        match self.work.generations.iter_mut().find(|(b, _)| *b == id) {
            Some((_, g)) if *g >= to => {
                return Err(DbError::Conflict {
                    what: "boot_policy_generation",
                });
            }
            Some((_, g)) => *g = to,
            None => self.work.generations.push((id, to)),
        }
        self.write()
    }

    async fn bump_boot_policy_generation(&mut self, id: BootServiceId) -> Result<u64, DbError> {
        self.write()?;
        if !self.work.boot_services.iter().any(|b| b.id == id) {
            return Err(self.abort(DbError::Constraint {
                what: "update boot_policy_generation",
            }));
        }
        if let Some((_, g)) = self.work.generations.iter_mut().find(|(b, _)| *b == id) {
            let Some(next) = g.checked_add(1).filter(|n| i64::try_from(*n).is_ok()) else {
                self.failed = true;
                return Err(DbError::Constraint {
                    what: "update boot_policy_generation",
                });
            };
            *g = next;
            return Ok(next);
        }
        self.work.generations.push((id, 1));
        Ok(1)
    }

    async fn insert_auth_code(&mut self, c: &NewAuthCode) -> Result<(), DbError> {
        if c.expires_at <= c.issued_at {
            return Err(DbError::InvalidArgument {
                what: "code expiry must follow issue",
            });
        }
        self.write()?;
        if self
            .work
            .auth_codes
            .iter()
            .any(|(h, r)| r.id == c.id || *h == c.code_hmac)
        {
            return Err(self.abort(DbError::Conflict {
                what: "insert auth_code",
            }));
        }
        if !self.operator_exists(c.issued_by) {
            return Err(self.abort(DbError::Constraint {
                what: "insert auth_code",
            }));
        }
        self.work.auth_codes.push((
            c.code_hmac,
            AuthCodeRecord {
                id: c.id,
                issued_by: c.issued_by,
                issued_at: c.issued_at,
                expires_at: c.expires_at,
                used_at: None,
                used_by_session: None,
                revoked_at: None,
                revoked_by: None,
                note: c.note.clone(),
            },
        ));
        Ok(())
    }

    async fn auth_code(&mut self, id: AuthCodeId) -> Result<Option<AuthCodeRecord>, DbError> {
        self.check()?;
        Ok(self
            .work
            .auth_codes
            .iter()
            .find(|(_, r)| r.id == id)
            .map(|(_, r)| r.clone()))
    }

    async fn list_auth_codes(&mut self) -> Result<Vec<AuthCodeRecord>, DbError> {
        self.check()?;
        let mut v: Vec<AuthCodeRecord> = self
            .work
            .auth_codes
            .iter()
            .map(|(_, r)| r.clone())
            .collect();
        v.sort_by_key(|r| (r.issued_at, r.id));
        Ok(v)
    }

    async fn consume_auth_code(
        &mut self,
        code_hmac: &HmacTag,
        session: SessionId,
        at: UnixMicros,
    ) -> Result<Option<AuthCodeId>, DbError> {
        self.check()?;
        let usable =
            |r: &AuthCodeRecord| r.used_at.is_none() && r.revoked_at.is_none() && r.expires_at > at;
        let Some(id) = self
            .work
            .auth_codes
            .iter()
            .find(|(h, r)| h == code_hmac && usable(r))
            .map(|(_, r)| r.id)
        else {
            return Ok(None);
        };
        self.write()?;
        if !self.work.sessions.iter().any(|s| s.id == session) {
            return Err(self.abort(DbError::Constraint {
                what: "use auth_code",
            }));
        }
        if let Some((_, r)) = self.work.auth_codes.iter_mut().find(|(_, r)| r.id == id) {
            r.used_at = Some(at);
            r.used_by_session = Some(session);
        }
        Ok(Some(id))
    }

    async fn revoke_auth_code(
        &mut self,
        id: AuthCodeId,
        by: OperatorId,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        self.write()?;
        let Some(open) = self
            .work
            .auth_codes
            .iter()
            .find(|(_, r)| r.id == id)
            .map(|(_, r)| r.used_at.is_none() && r.revoked_at.is_none())
        else {
            return Err(DbError::NotFound { what: "auth code" });
        };
        if !open {
            return Err(DbError::Conflict { what: "auth code" });
        }
        if !self.operator_exists(by) {
            return Err(self.abort(DbError::Constraint {
                what: "revoke auth_code",
            }));
        }
        if let Some((_, r)) = self.work.auth_codes.iter_mut().find(|(_, r)| r.id == id) {
            r.revoked_at = Some(at);
            r.revoked_by = Some(by);
        }
        Ok(())
    }

    async fn insert_device_session(&mut self, s: &NewDeviceSession) -> Result<(), DbError> {
        if s.expires_at < s.created_at {
            return Err(DbError::InvalidArgument {
                what: "session expiry before creation",
            });
        }
        if i64::try_from(s.memory_bytes).is_err() {
            return Err(DbError::InvalidArgument {
                what: "memory_bytes",
            });
        }
        self.write()?;
        if self.work.sessions.iter().any(|x| {
            x.id == s.id
                || x.token_sha256 == s.token_sha256
                || (x.display_code == s.display_code && LIVE_SESSION.contains(&x.state))
        }) {
            return Err(self.abort(DbError::Conflict {
                what: "insert device_session",
            }));
        }
        if let Some(b) = s.boot_service_id
            && !self.work.boot_services.iter().any(|x| x.id == b)
        {
            return Err(self.abort(DbError::Constraint {
                what: "insert device_session",
            }));
        }
        self.work.sessions.push(DeviceSession {
            id: s.id,
            token_sha256: s.token_sha256,
            boot_service_id: s.boot_service_id,
            source_ip: s.source_ip,
            macs: s.macs.clone(),
            firmware: s.firmware,
            arch: s.arch,
            secure_boot: s.secure_boot,
            memory_bytes: s.memory_bytes,
            agent_version: s.agent_version.clone(),
            display_code: s.display_code,
            state: SessionState::AwaitingAuthorisation,
            auth: None,
            failed_code_attempts: 0,
            chosen_package: None,
            chosen_disk: None,
            created_at: s.created_at,
            last_seen_at: s.created_at,
            expires_at: s.expires_at,
            ended_at: None,
            end_reason: None,
        });
        Ok(())
    }

    async fn device_session(&mut self, id: SessionId) -> Result<Option<DeviceSession>, DbError> {
        self.check()?;
        Ok(self.session_ref(id).cloned())
    }

    async fn lock_device_session(
        &mut self,
        id: SessionId,
    ) -> Result<Option<DeviceSession>, DbError> {
        self.device_session(id).await
    }

    async fn device_session_by_token(
        &mut self,
        sha: &Sha256Digest,
    ) -> Result<Option<DeviceSession>, DbError> {
        self.check()?;
        Ok(self
            .work
            .sessions
            .iter()
            .find(|s| s.token_sha256 == *sha)
            .cloned())
    }

    async fn list_device_sessions(
        &mut self,
        states: &[SessionState],
    ) -> Result<Vec<DeviceSession>, DbError> {
        self.check()?;
        let mut v: Vec<DeviceSession> = self
            .work
            .sessions
            .iter()
            .filter(|s| states.is_empty() || states.contains(&s.state))
            .cloned()
            .collect();
        v.sort_by_key(|s| (s.created_at, s.id));
        Ok(v)
    }

    async fn lock_device_session_quota(&mut self) -> Result<(), DbError> {
        // Transactions on the memory store are already serialised.
        self.check()
    }

    async fn count_device_sessions(
        &mut self,
        states: &[SessionState],
        scope: SessionScope,
    ) -> Result<u64, DbError> {
        self.check()?;
        let n = self
            .work
            .sessions
            .iter()
            .filter(|s| states.is_empty() || states.contains(&s.state))
            .filter(|s| scope.contains(s))
            .count();
        u64::try_from(n).map_err(|_| DbError::Corrupt { what: "count" })
    }

    async fn touch_device_session(&mut self, id: SessionId, at: UnixMicros) -> Result<(), DbError> {
        // Bookkeeping, not a state change (no `write`, no audit needed).
        self.check()?;
        let s = self.session_mut(id).ok_or(DbError::NotFound {
            what: "device session",
        })?;
        s.last_seen_at = s.last_seen_at.max(at);
        Ok(())
    }

    async fn authorise_device_session(
        &mut self,
        id: SessionId,
        auth: SessionAuth,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        self.write()?;
        let s = self.session_ref(id).ok_or(DbError::NotFound {
            what: "device session",
        })?;
        if s.state != SessionState::AwaitingAuthorisation || s.expires_at <= at {
            return Err(DbError::Conflict {
                what: "device session",
            });
        }
        let refs_ok = match auth {
            SessionAuth::Code(c) => self.work.auth_codes.iter().any(|(_, r)| r.id == c),
            SessionAuth::Approval(o) => self.operator_exists(o),
        };
        if !refs_ok {
            return Err(self.abort(DbError::Constraint {
                what: "authorise device_session",
            }));
        }
        let s = self.session_mut(id).ok_or(DbError::NotFound {
            what: "device session",
        })?;
        s.state = SessionState::Authorised;
        s.auth = Some(auth);
        s.last_seen_at = s.last_seen_at.max(at);
        Ok(())
    }

    async fn record_failed_code_attempt(&mut self, id: SessionId) -> Result<u32, DbError> {
        self.check()?;
        let s = self.session_ref(id).ok_or(DbError::NotFound {
            what: "device session",
        })?;
        if s.state != SessionState::AwaitingAuthorisation {
            return Err(DbError::Conflict {
                what: "device session",
            });
        }
        // PostgreSQL `smallint`.
        let Some(next) = s
            .failed_code_attempts
            .checked_add(1)
            .filter(|n| i16::try_from(*n).is_ok())
        else {
            self.failed = true;
            return Err(DbError::TxFailed);
        };
        self.write()?;
        if let Some(s) = self.session_mut(id) {
            s.failed_code_attempts = next;
        }
        Ok(next)
    }

    async fn choose_session_package(
        &mut self,
        id: SessionId,
        p: ChosenPackage,
    ) -> Result<(), DbError> {
        if i64::try_from(p.revision).is_err() {
            return Err(DbError::InvalidArgument {
                what: "package revision",
            });
        }
        self.write()?;
        let s = self.session_mut(id).ok_or(DbError::NotFound {
            what: "device session",
        })?;
        if s.state != SessionState::Authorised {
            return Err(DbError::Conflict {
                what: "device session",
            });
        }
        s.chosen_package = Some(p);
        s.chosen_disk = None;
        Ok(())
    }

    async fn choose_session_disk(
        &mut self,
        id: SessionId,
        disk: &DiskDescriptorV1,
    ) -> Result<(), DbError> {
        // The same rendering and size limit as the PostgreSQL column.
        let json = crate::repo::conv::to_json(disk, "disk descriptor")?;
        let disk: DiskDescriptorV1 = crate::repo::conv::from_json(&json, "chosen_disk")?;
        self.write()?;
        let s = self.session_mut(id).ok_or(DbError::NotFound {
            what: "device session",
        })?;
        if s.state != SessionState::Authorised || s.chosen_package.is_none() {
            return Err(DbError::Conflict {
                what: "device session",
            });
        }
        s.chosen_disk = Some(disk);
        Ok(())
    }

    async fn set_device_session_state(
        &mut self,
        id: SessionId,
        from: &[SessionState],
        to: SessionState,
        reason: Option<&ErrorCode>,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        crate::repo::devices::check_target(to)?;
        self.write()?;
        let s = self.session_mut(id).ok_or(DbError::NotFound {
            what: "device session",
        })?;
        if !from.contains(&s.state)
            || s.state.is_final()
            || (to == SessionState::Confirmed && s.chosen_disk.is_none())
        {
            return Err(DbError::Conflict {
                what: "device session",
            });
        }
        s.state = to;
        s.ended_at = (to != SessionState::Confirmed).then_some(at);
        s.end_reason = reason.cloned();
        Ok(())
    }

    async fn expire_device_sessions(
        &mut self,
        at: UnixMicros,
        idle_before: UnixMicros,
    ) -> Result<Vec<SessionId>, DbError> {
        self.check()?;
        let reason = ErrorCode::new(crate::repo::devices::EXPIRED_REASON)
            .map_err(|_| DbError::Corrupt { what: "end_reason" })?;
        let mut ids = Vec::new();
        for s in &mut self.work.sessions {
            let due = LIVE_SESSION.contains(&s.state) && s.expires_at <= at;
            let idle =
                s.state == SessionState::AwaitingAuthorisation && s.last_seen_at <= idle_before;
            if due || idle {
                s.state = SessionState::Expired;
                s.ended_at = Some(at);
                s.end_reason = Some(reason.clone());
                ids.push(s.id);
            }
        }
        if !ids.is_empty() {
            self.write()?;
        }
        ids.sort();
        Ok(ids)
    }

    async fn insert_job(&mut self, j: &NewJob) -> Result<(), DbError> {
        if j.previous_job_id == Some(j.id) {
            return Err(DbError::InvalidArgument {
                what: "previous job is the job itself",
            });
        }
        if i64::try_from(j.wipe_audit_seq).is_err()
            || i64::try_from(j.package.revision).is_err()
            || j.bytes_total.is_some_and(|b| i64::try_from(b).is_err())
            || !j.timeouts.valid()
        {
            return Err(DbError::InvalidArgument { what: "job" });
        }
        let json = crate::repo::conv::to_json(&j.disk, "disk descriptor")?;
        let disk: DiskDescriptorV1 = crate::repo::conv::from_json(&json, "disk")?;
        self.write()?;
        if self.job_identity_taken(j.id, j.session_id, j.wipe_audit_seq) {
            return Err(self.abort(DbError::Conflict { what: "insert job" }));
        }
        let refs_ok = self.session_ref(j.session_id).is_some()
            && self
                .work
                .boot_services
                .iter()
                .any(|b| b.id == j.boot_service_id)
            && self.content_ref(j.image_content_id).is_some()
            && j.previous_job_id.is_none_or(|p| self.job_exists(p));
        if !refs_ok {
            return Err(self.abort(DbError::Constraint { what: "insert job" }));
        }
        self.work.jobs.push(Job {
            id: j.id,
            session_id: j.session_id,
            boot_service_id: j.boot_service_id,
            package: j.package,
            image_content_id: j.image_content_id,
            edition_index: j.edition_index,
            disk,
            layout: None,
            macs: j.macs.clone(),
            state: JobState::Running,
            current_step: Step::VERIFY_CONTENT,
            failure: None,
            attempts: 0,
            bytes_done: None,
            bytes_total: j.bytes_total,
            last_seq: 0,
            started_at: j.started_at,
            last_report_at: None,
            finished_at: None,
            previous_job_id: j.previous_job_id,
            wipe_audit_seq: j.wipe_audit_seq,
            wipe_record_hash: j.wipe_record_hash,
            plan_sha256: j.plan_sha256,
            plan_key_id: j.plan_key_id,
            timeouts: j.timeouts,
            acknowledged: None,
        });
        for step in Step::ALL {
            let first = step == Step::VERIFY_CONTENT;
            self.work.job_steps.push(JobStep {
                job_id: j.id,
                step,
                state: if first {
                    StepState::Running
                } else {
                    StepState::Pending
                },
                started_at: first.then_some(j.started_at),
                finished_at: None,
            });
        }
        Ok(())
    }

    async fn job(&mut self, id: JobId) -> Result<Option<Job>, DbError> {
        self.check()?;
        Ok(self.job_ref(id).cloned())
    }

    async fn lock_job(&mut self, id: JobId) -> Result<Option<Job>, DbError> {
        self.job(id).await
    }

    async fn job_by_session(&mut self, session: SessionId) -> Result<Option<Job>, DbError> {
        self.check()?;
        Ok(self
            .work
            .jobs
            .iter()
            .find(|j| j.session_id == session)
            .cloned())
    }

    async fn list_jobs(&mut self, states: &[JobState]) -> Result<Vec<Job>, DbError> {
        self.check()?;
        let mut v: Vec<Job> = self
            .work
            .jobs
            .iter()
            .filter(|j| states.is_empty() || states.contains(&j.state))
            .cloned()
            .collect();
        v.sort_by_key(|j| (j.started_at, j.id));
        Ok(v)
    }

    async fn job_steps(&mut self, id: JobId) -> Result<Vec<JobStep>, DbError> {
        self.check()?;
        let mut v: Vec<JobStep> = self
            .work
            .job_steps
            .iter()
            .filter(|s| s.job_id == id)
            .copied()
            .collect();
        v.sort_by_key(|s| s.step);
        Ok(v)
    }

    async fn lock_mac_claims(&mut self) -> Result<(), DbError> {
        // Transactions on the memory store are already serialised.
        self.check()
    }

    async fn running_jobs_for_macs(&mut self, macs: &MacList) -> Result<Vec<JobId>, DbError> {
        self.check()?;
        let mut v: Vec<(UnixMicros, JobId)> = self
            .work
            .jobs
            .iter()
            .filter(|j| j.state == JobState::Running && j.macs.overlaps(macs))
            .map(|j| (j.started_at, j.id))
            .chain(
                self.work
                    .jobs_v2
                    .iter()
                    .filter(|j| j.state == JobState::Running && j.macs.overlaps(macs))
                    .map(|j| (j.started_at, j.id)),
            )
            .collect();
        v.sort();
        Ok(v.into_iter().map(|(_, id)| id).collect())
    }

    async fn previous_failed_job(&mut self, macs: &MacList) -> Result<Option<JobId>, DbError> {
        self.check()?;
        let failed = |s: JobState| matches!(s, JobState::Failed | JobState::Lost);
        Ok(self
            .work
            .jobs
            .iter()
            .filter(|j| failed(j.state) && j.macs.overlaps(macs))
            .map(|j| (j.started_at, j.id))
            .chain(
                self.work
                    .jobs_v2
                    .iter()
                    .filter(|j| failed(j.state) && j.macs.overlaps(macs))
                    .map(|j| (j.started_at, j.id)),
            )
            .max()
            .map(|(_, id)| id))
    }

    async fn set_job_step(
        &mut self,
        id: JobId,
        step: Step,
        to: StepState,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        let from = crate::repo::jobs::step_from_state(to)?;
        self.check()?;
        let job = self.job_ref(id).ok_or(DbError::NotFound { what: "job" })?;
        if job.state.is_final() {
            return Err(DbError::Conflict { what: "job" });
        }
        let steps: Vec<JobStep> = self
            .work
            .job_steps
            .iter()
            .filter(|s| s.job_id == id)
            .copied()
            .collect();
        let earlier_open = steps
            .iter()
            .any(|s| s.step < step && s.state != StepState::Done);
        let current = steps.iter().find(|s| s.step == step).map(|s| s.state);
        if current != Some(from) || (to == StepState::Running && earlier_open) {
            return Err(DbError::Conflict { what: "job step" });
        }
        self.write()?;
        if let Some(s) = self
            .work
            .job_steps
            .iter_mut()
            .find(|s| s.job_id == id && s.step == step)
        {
            s.state = to;
            if to == StepState::Running {
                s.started_at = Some(at);
            } else {
                s.finished_at = Some(at);
            }
        }
        if to == StepState::Running
            && let Some(j) = self.job_mut(id)
        {
            j.current_step = j.current_step.max(step);
        }
        Ok(())
    }

    async fn set_job_state(
        &mut self,
        id: JobId,
        from: &[JobState],
        to: JobState,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        if to == JobState::Failed {
            return Err(DbError::InvalidArgument {
                what: "use fail_job",
            });
        }
        self.write()?;
        if self.work.jobs_v2.iter().any(|j| j.id == id) {
            return self.set_job_v2_state(id, from, to, at);
        }
        let step4_done =
            self.work.job_steps.iter().any(|s| {
                s.job_id == id && s.step == Step::MAKE_BOOTABLE && s.state == StepState::Done
            });
        let j = self.job_mut(id).ok_or(DbError::NotFound { what: "job" })?;
        if !from.contains(&j.state) || (to == JobState::Succeeded && !step4_done) {
            return Err(DbError::Conflict { what: "job" });
        }
        if j.state != to && !j.state.can_become(to) {
            // As the 0004 guard: a refused transition aborts.
            self.failed = true;
            return Err(DbError::Constraint {
                what: "update job state",
            });
        }
        j.state = to;
        j.finished_at = (to == JobState::Succeeded).then_some(at);
        Ok(())
    }

    async fn fail_job(
        &mut self,
        id: JobId,
        from: &[JobState],
        failure: &FailureV1,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        failure
            .validate()
            .map_err(|_| DbError::InvalidArgument { what: "failure" })?;
        let json = crate::repo::conv::to_json(failure, "failure")?;
        let failure: FailureV1 = crate::repo::conv::from_json(&json, "failure_detail")?;
        self.write()?;
        if self.work.jobs_v2.iter().any(|j| j.id == id) {
            // As PostgreSQL: the row exists but is not a v1 job.
            return Err(DbError::Conflict { what: "job" });
        }
        let j = self.job_mut(id).ok_or(DbError::NotFound { what: "job" })?;
        if !from.contains(&j.state) {
            return Err(DbError::Conflict { what: "job" });
        }
        if !j.state.can_become(JobState::Failed) {
            self.failed = true;
            return Err(DbError::Constraint {
                what: "update job failed",
            });
        }
        j.state = JobState::Failed;
        j.attempts = failure.attempts;
        j.failure = Some(failure);
        j.finished_at = Some(at);
        Ok(())
    }

    async fn set_job_layout(&mut self, id: JobId, layout: &LayoutReportV1) -> Result<(), DbError> {
        let json = crate::repo::conv::to_json(layout, "layout")?;
        let layout: LayoutReportV1 = crate::repo::conv::from_json(&json, "layout")?;
        self.write()?;
        if let Some(j) = self.work.jobs_v2.iter_mut().find(|j| j.id == id) {
            if j.state.is_final() {
                return Err(DbError::Conflict { what: "job" });
            }
            j.layout = Some(layout);
            return Ok(());
        }
        let j = self.job_mut(id).ok_or(DbError::NotFound { what: "job" })?;
        if j.state.is_final() {
            return Err(DbError::Conflict { what: "job" });
        }
        j.layout = Some(layout);
        Ok(())
    }

    async fn record_job_progress(
        &mut self,
        id: JobId,
        seq: u64,
        bytes_done: Option<u64>,
        bytes_total: Option<u64>,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        if let (Some(d), Some(t)) = (bytes_done, bytes_total)
            && d > t
        {
            return Err(DbError::InvalidArgument {
                what: "bytes_done above bytes_total",
            });
        }
        if [Some(seq), bytes_done, bytes_total]
            .into_iter()
            .flatten()
            .any(|v| i64::try_from(v).is_err())
        {
            return Err(DbError::InvalidArgument { what: "progress" });
        }
        // Bookkeeping, not a state change (no `write`, no audit needed).
        self.check()?;
        let (state, last_seq, cur_done, cur_total) =
            if let Some(j) = self.work.jobs_v2.iter().find(|j| j.id == id) {
                (j.state, j.last_seq, j.bytes_done, j.bytes_total)
            } else {
                let j = self.job_ref(id).ok_or(DbError::NotFound { what: "job" })?;
                (j.state, j.last_seq, j.bytes_done, j.bytes_total)
            };
        let done = bytes_done.or(cur_done);
        let total = bytes_total.or(cur_total);
        if state.is_final()
            || seq <= last_seq
            || matches!((done, total), (Some(d), Some(t)) if d > t)
        {
            return Err(DbError::Conflict { what: "job" });
        }
        if let Some(j) = self.work.jobs_v2.iter_mut().find(|j| j.id == id) {
            j.last_seq = seq;
            j.last_report_at = Some(at);
            j.bytes_done = done;
            j.bytes_total = total;
        } else if let Some(j) = self.job_mut(id) {
            j.last_seq = seq;
            j.last_report_at = Some(at);
            j.bytes_done = done;
            j.bytes_total = total;
        }
        Ok(())
    }

    async fn acknowledge_job_failure(
        &mut self,
        id: JobId,
        by: OperatorId,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        self.write()?;
        let (state, acked) = if let Some(j) = self.work.jobs_v2.iter().find(|j| j.id == id) {
            (j.state, j.acknowledged.is_some())
        } else {
            let j = self.job_ref(id).ok_or(DbError::NotFound { what: "job" })?;
            (j.state, j.acknowledged.is_some())
        };
        if state != JobState::Failed || acked {
            return Err(DbError::Conflict { what: "job" });
        }
        if !self.operator_exists(by) {
            return Err(self.abort(DbError::Constraint {
                what: "update job acknowledged",
            }));
        }
        if let Some(j) = self.work.jobs_v2.iter_mut().find(|j| j.id == id) {
            j.acknowledged = Some((by, at));
        } else if let Some(j) = self.job_mut(id) {
            j.acknowledged = Some((by, at));
        }
        Ok(())
    }

    async fn mark_lost_jobs(&mut self, silent_before: UnixMicros) -> Result<Vec<JobId>, DbError> {
        self.check()?;
        let mut ids = Vec::new();
        for j in &mut self.work.jobs {
            if j.state == JobState::Running
                && j.last_report_at.unwrap_or(j.started_at) < silent_before
            {
                j.state = JobState::Lost;
                ids.push(j.id);
            }
        }
        for j in &mut self.work.jobs_v2 {
            if j.state == JobState::Running
                && j.last_report_at.unwrap_or(j.started_at) < silent_before
            {
                j.state = JobState::Lost;
                ids.push(j.id);
            }
        }
        if !ids.is_empty() {
            self.write()?;
        }
        ids.sort();
        Ok(ids)
    }

    async fn archive_content(&mut self, id: ContentId) -> Result<Option<ArchiveContent>, DbError> {
        self.check()?;
        Ok(self.work.archives.iter().find(|a| a.id == id).cloned())
    }

    async fn lock_archive_content(
        &mut self,
        id: ContentId,
    ) -> Result<Option<ArchiveContent>, DbError> {
        self.archive_content(id).await
    }

    async fn archive_content_by_sha256(
        &mut self,
        sha: &Sha256Digest,
    ) -> Result<Option<ArchiveContent>, DbError> {
        self.check()?;
        Ok(self
            .work
            .archives
            .iter()
            .find(|c| c.sha256 == *sha && LIVE.contains(&c.state))
            .cloned())
    }

    async fn list_archive_content(
        &mut self,
        kind: Option<ContentKindV2>,
        states: &[ContentState],
    ) -> Result<Vec<ArchiveContent>, DbError> {
        self.check()?;
        let mut v: Vec<ArchiveContent> = self
            .work
            .archives
            .iter()
            .filter(|c| kind.is_none_or(|k| c.kind == k))
            .filter(|c| states.is_empty() || states.contains(&c.state))
            .cloned()
            .collect();
        v.sort_by_key(|c| (c.created_at, c.id));
        Ok(v)
    }

    async fn create_archive_upload(
        &mut self,
        c: &NewArchiveContent,
        u: &Upload,
    ) -> Result<(), DbError> {
        if u.content_id != c.id || u.declared_size != c.size || u.declared_sha256 != c.sha256 {
            return Err(DbError::InvalidArgument {
                what: "upload does not match content",
            });
        }
        if i64::try_from(c.size).is_err() || c.size == 0 {
            return Err(DbError::InvalidArgument { what: "size" });
        }
        self.write()?;
        if self.content_id_taken(c.id) || self.live_digest(&c.sha256) {
            return Err(self.abort(DbError::Conflict {
                what: "insert archive content",
            }));
        }
        if self
            .work
            .uploads
            .iter()
            .any(|x| x.id == u.id || x.staging_name == u.staging_name)
        {
            return Err(self.abort(DbError::Conflict {
                what: "insert upload",
            }));
        }
        if !self.operator_exists(c.created_by) || !self.operator_exists(u.operator_id) {
            return Err(self.abort(DbError::Constraint {
                what: "insert archive content",
            }));
        }
        self.work.archives.push(ArchiveContent {
            id: c.id,
            kind: c.kind,
            display_name: c.display_name.clone(),
            file_name: c.file_name.clone(),
            size: c.size,
            sha256: c.sha256,
            state: ContentState::Receiving,
            reason: None,
            created_by: c.created_by,
            initiating_audit_seq: c.initiating_audit_seq,
            created_at: c.created_at,
            updated_at: c.created_at,
            ready_at: None,
            archive: None,
            manifest: None,
            superseded_at: None,
        });
        self.work.uploads.push(u.clone());
        Ok(())
    }

    async fn set_archive_content_ready(
        &mut self,
        id: ContentId,
        r: &ReadyArchiveContent,
    ) -> Result<(), DbError> {
        self.check()?;
        let Some(cur) = self.work.archives.iter().find(|a| a.id == id) else {
            return Err(DbError::NotFound { what: "content" });
        };
        if cur.state != ContentState::Checking {
            return Err(DbError::Conflict { what: "content" });
        }
        let facts = crate::repo::content::archive_facts_of(
            &r.manifest.payload,
            cur.id,
            cur.kind,
            cur.size,
            &cur.sha256,
            r.at,
        )
        .ok_or(DbError::InvalidArgument {
            what: "manifest does not describe this content",
        })?;
        self.write()?;
        if let Some(a) = self.work.archives.iter_mut().find(|a| a.id == id) {
            a.state = ContentState::Ready;
            a.reason = None;
            a.updated_at = r.at;
            a.ready_at = Some(r.at);
            a.archive = Some(facts);
            a.manifest = Some(r.manifest.clone());
        }
        Ok(())
    }

    async fn insert_driver_archive(&mut self, a: &NewDriverArchive) -> Result<(), DbError> {
        self.write()?;
        if self
            .work
            .driver_archives
            .iter()
            .any(|x| x.id == a.id || x.content_id == a.content_id)
        {
            return Err(self.abort(DbError::Conflict {
                what: "insert driver_archive",
            }));
        }
        let content_ok = self.work.archives.iter().any(|c| {
            c.id == a.content_id
                && c.kind == ContentKindV2::DriverArchive
                && c.superseded_at.is_none()
        });
        if !content_ok || !self.operator_exists(a.created_by) {
            return Err(self.abort(DbError::Constraint {
                what: "insert driver_archive",
            }));
        }
        self.work.driver_archives.push(DriverArchive {
            id: a.id,
            content_id: a.content_id,
            name: a.name.clone(),
            format: None,
            status: DriverArchiveStatus::Checking,
            refusal: None,
            infs: Vec::new(),
            expanded_bytes: None,
            created_by: a.created_by,
            created_at: a.created_at,
            updated_at: a.created_at,
            replaced_at: None,
        });
        Ok(())
    }

    async fn driver_archive(
        &mut self,
        id: DriverArchiveId,
    ) -> Result<Option<DriverArchive>, DbError> {
        self.check()?;
        Ok(self
            .work
            .driver_archives
            .iter()
            .find(|a| a.id == id)
            .cloned())
    }

    async fn lock_driver_archive(
        &mut self,
        id: DriverArchiveId,
    ) -> Result<Option<DriverArchive>, DbError> {
        self.driver_archive(id).await
    }

    async fn list_driver_archives(
        &mut self,
        statuses: &[DriverArchiveStatus],
    ) -> Result<Vec<DriverArchive>, DbError> {
        self.check()?;
        let mut v: Vec<DriverArchive> = self
            .work
            .driver_archives
            .iter()
            .filter(|a| statuses.is_empty() || statuses.contains(&a.status))
            .cloned()
            .collect();
        v.sort_by_key(|a| (a.created_at, a.id));
        Ok(v)
    }

    async fn set_driver_archive_ready(
        &mut self,
        id: DriverArchiveId,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        self.check()?;
        let Some(cur) = self.work.driver_archives.iter().find(|a| a.id == id) else {
            return Err(DbError::NotFound {
                what: "driver archive",
            });
        };
        if cur.status != DriverArchiveStatus::Checking {
            return Err(DbError::Conflict {
                what: "driver archive",
            });
        }
        let content_id = cur.content_id;
        let (format, infs, expanded) = self
            .work
            .archives
            .iter()
            .find(|c| c.id == content_id)
            .and_then(crate::repo::drivers::ready_facts)
            .ok_or(DbError::Conflict {
                what: "driver archive content not ready",
            })?;
        self.write()?;
        if let Some(a) = self.work.driver_archives.iter_mut().find(|a| a.id == id) {
            a.status = DriverArchiveStatus::Ready;
            a.format = Some(format);
            a.infs = infs;
            a.expanded_bytes = Some(expanded);
            a.updated_at = at;
        }
        Ok(())
    }

    async fn refuse_driver_archive(
        &mut self,
        id: DriverArchiveId,
        reason: &ErrorCode,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        self.write()?;
        let a = self
            .work
            .driver_archives
            .iter_mut()
            .find(|a| a.id == id)
            .ok_or(DbError::NotFound {
                what: "driver archive",
            })?;
        if a.status != DriverArchiveStatus::Checking {
            return Err(DbError::Conflict {
                what: "driver archive",
            });
        }
        a.status = DriverArchiveStatus::Refused;
        a.refusal = Some(reason.clone());
        a.updated_at = at;
        Ok(())
    }

    async fn replace_driver_archive(
        &mut self,
        id: DriverArchiveId,
        content_id: ContentId,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        self.write()?;
        let Some(cur) = self.work.driver_archives.iter().find(|a| a.id == id) else {
            return Err(DbError::NotFound {
                what: "driver archive",
            });
        };
        let cur_content = cur.content_id;
        if !matches!(
            cur.status,
            DriverArchiveStatus::Ready | DriverArchiveStatus::Refused
        ) || cur.content_id == content_id
        {
            return Err(DbError::Conflict {
                what: "driver archive",
            });
        }
        let taken = self
            .work
            .driver_archives
            .iter()
            .any(|a| a.content_id == content_id);
        if taken {
            return Err(self.abort(DbError::Conflict {
                what: "update driver_archive replaced",
            }));
        }
        let content_ok = self.work.archives.iter().any(|c| {
            c.id == content_id
                && c.kind == ContentKindV2::DriverArchive
                && c.superseded_at.is_none()
        });
        if !content_ok {
            return Err(self.abort(DbError::Constraint {
                what: "update driver_archive replaced",
            }));
        }
        if let Some(a) = self.work.driver_archives.iter_mut().find(|a| a.id == id) {
            a.status = DriverArchiveStatus::Checking;
            a.content_id = content_id;
            a.format = None;
            a.infs = Vec::new();
            a.expanded_bytes = None;
            a.refusal = None;
            a.updated_at = at;
            a.replaced_at = Some(at);
        }
        // U-4: the old file is superseded (still served, never attached).
        let old = cur_content;
        if let Some(c) = self
            .work
            .archives
            .iter_mut()
            .find(|c| c.id == old && c.superseded_at.is_none())
        {
            c.superseded_at = Some(at);
        }
        Ok(())
    }

    async fn delete_driver_archive(
        &mut self,
        id: DriverArchiveId,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        self.write()?;
        let used = self
            .work
            .package_drivers
            .iter()
            .any(|(_, ids)| ids.contains(&id));
        let a = self
            .work
            .driver_archives
            .iter_mut()
            .find(|a| a.id == id)
            .ok_or(DbError::NotFound {
                what: "driver archive",
            })?;
        if a.status == DriverArchiveStatus::Deleted || used {
            return Err(DbError::Conflict {
                what: "driver archive",
            });
        }
        a.status = DriverArchiveStatus::Deleted;
        a.updated_at = at;
        Ok(())
    }

    async fn packages_using_driver_archive(
        &mut self,
        id: DriverArchiveId,
    ) -> Result<Vec<PackageRef>, DbError> {
        self.check()?;
        let users: Vec<PackageId> = self
            .work
            .package_drivers
            .iter()
            .filter(|(_, ids)| ids.contains(&id))
            .map(|(p, _)| *p)
            .collect();
        Ok(self.package_refs(|p| users.contains(&p.id)))
    }

    async fn package_drivers(
        &mut self,
        package: PackageId,
    ) -> Result<Vec<DriverArchiveId>, DbError> {
        self.check()?;
        Ok(self
            .work
            .package_drivers
            .iter()
            .find(|(p, _)| *p == package)
            .map(|(_, ids)| ids.clone())
            .unwrap_or_default())
    }

    async fn set_package_drivers(
        &mut self,
        package: PackageId,
        archives: &[DriverArchiveId],
    ) -> Result<(), DbError> {
        crate::repo::drivers::check_driver_list(archives)?;
        self.check()?;
        if !self.work.packages.iter().any(|p| p.id == package) {
            return Err(DbError::NotFound { what: "package" });
        }
        let all_live = archives.iter().all(|id| {
            self.work
                .driver_archives
                .iter()
                .any(|a| a.id == *id && a.status != DriverArchiveStatus::Deleted)
        });
        if !all_live {
            return Err(self.abort(DbError::Constraint {
                what: "package driver archive",
            }));
        }
        self.write()?;
        self.work.package_drivers.retain(|(p, _)| *p != package);
        if !archives.is_empty() {
            self.work.package_drivers.push((package, archives.to_vec()));
        }
        Ok(())
    }

    async fn insert_agent_signer(&mut self, s: &AgentSigner) -> Result<(), DbError> {
        if s.revoked.is_some() || !crate::repo::agent_packages::key_id_matches(&s.spki, &s.key_id) {
            return Err(DbError::InvalidArgument {
                what: "agent signer",
            });
        }
        self.write()?;
        if self
            .work
            .agent_signers
            .iter()
            .any(|x| x.id == s.id || x.spki == s.spki || x.key_id == s.key_id)
        {
            return Err(self.abort(DbError::Conflict {
                what: "insert agent_signer",
            }));
        }
        if !self.operator_exists(s.added_by) {
            return Err(self.abort(DbError::Constraint {
                what: "insert agent_signer",
            }));
        }
        self.work.agent_signers.push(s.clone());
        Ok(())
    }

    async fn agent_signer(&mut self, id: AgentSignerId) -> Result<Option<AgentSigner>, DbError> {
        self.check()?;
        Ok(self.work.agent_signers.iter().find(|s| s.id == id).cloned())
    }

    async fn agent_signer_by_key_id(
        &mut self,
        key_id: &Sha256Digest,
    ) -> Result<Option<AgentSigner>, DbError> {
        self.check()?;
        Ok(self
            .work
            .agent_signers
            .iter()
            .find(|s| s.key_id == *key_id)
            .cloned())
    }

    async fn list_agent_signers(&mut self) -> Result<Vec<AgentSigner>, DbError> {
        self.check()?;
        let mut v = self.work.agent_signers.clone();
        v.sort_by_key(|s| (s.added_at, s.id));
        Ok(v)
    }

    async fn revoke_agent_signer(
        &mut self,
        id: AgentSignerId,
        by: OperatorId,
        at: UnixMicros,
    ) -> Result<SignerRevocation, DbError> {
        self.write()?;
        let known = self.operator_exists(by);
        let s = self
            .work
            .agent_signers
            .iter_mut()
            .find(|s| s.id == id)
            .ok_or(DbError::NotFound {
                what: "agent signer",
            })?;
        if s.revoked.is_some() {
            return Err(DbError::Conflict {
                what: "agent signer",
            });
        }
        if !known {
            return Err(self.abort(DbError::Constraint {
                what: "update agent_signer revoked",
            }));
        }
        s.revoked = Some((by, at));
        // U-3, as the PostgreSQL statements.
        let mut refused_agent_packages = Vec::new();
        for p in &mut self.work.agent_packages {
            if p.signer_id == Some(id) && p.status == AgentPackageStatus::Ready {
                p.status = AgentPackageStatus::Refused;
                p.refusal = Some(crate::repo::agent_packages::signer_revoked_code()?);
                p.updated_at = at;
                refused_agent_packages.push(p.id);
            }
        }
        refused_agent_packages.sort();
        let users: Vec<PackageId> = self
            .work
            .package_configs
            .iter()
            .filter(|c| refused_agent_packages.contains(&c.agent_package_id))
            .map(|c| c.package_id)
            .collect();
        let mut packages_not_ready = Vec::new();
        for p in &mut self.work.packages {
            if users.contains(&p.id) && p.status == PackageStatus::Ready {
                p.status = PackageStatus::NotUsable;
                p.status_reason = Some(crate::model::AGENT_PACKAGE_REFUSED.to_owned());
                p.manifest = None;
                p.updated_at = at;
                packages_not_ready.push(p.id);
            }
        }
        packages_not_ready.sort();
        Ok(SignerRevocation {
            refused_agent_packages,
            packages_not_ready,
        })
    }

    async fn insert_agent_package(&mut self, p: &NewAgentPackage) -> Result<(), DbError> {
        self.write()?;
        if self
            .work
            .agent_packages
            .iter()
            .any(|x| x.id == p.id || x.content_id == p.content_id)
        {
            return Err(self.abort(DbError::Conflict {
                what: "insert agent_package",
            }));
        }
        let content_ok = self
            .work
            .archives
            .iter()
            .any(|c| c.id == p.content_id && c.kind == ContentKindV2::AgentPackage);
        if !content_ok || !self.operator_exists(p.created_by) {
            return Err(self.abort(DbError::Constraint {
                what: "insert agent_package",
            }));
        }
        self.work.agent_packages.push(AgentPackage {
            id: p.id,
            content_id: p.content_id,
            signer_id: None,
            manifest: None,
            status: AgentPackageStatus::Checking,
            refusal: None,
            created_by: p.created_by,
            created_at: p.created_at,
            updated_at: p.created_at,
        });
        Ok(())
    }

    async fn agent_package(&mut self, id: AgentPackageId) -> Result<Option<AgentPackage>, DbError> {
        self.check()?;
        Ok(self
            .work
            .agent_packages
            .iter()
            .find(|p| p.id == id)
            .cloned())
    }

    async fn lock_agent_package(
        &mut self,
        id: AgentPackageId,
    ) -> Result<Option<AgentPackage>, DbError> {
        self.agent_package(id).await
    }

    async fn list_agent_packages(
        &mut self,
        statuses: &[AgentPackageStatus],
    ) -> Result<Vec<AgentPackage>, DbError> {
        self.check()?;
        let mut v: Vec<AgentPackage> = self
            .work
            .agent_packages
            .iter()
            .filter(|p| statuses.is_empty() || statuses.contains(&p.status))
            .cloned()
            .collect();
        v.sort_by_key(|p| (p.created_at, p.id));
        Ok(v)
    }

    async fn set_agent_package_ready(
        &mut self,
        id: AgentPackageId,
        signer: AgentSignerId,
        manifest: &AgentPackageManifestV1,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        let json = crate::repo::agent_packages::manifest_to_json(manifest)?;
        let manifest = crate::repo::agent_packages::manifest_from_json(&json)?;
        self.check()?;
        let Some(cur) = self.work.agent_packages.iter().find(|p| p.id == id) else {
            return Err(DbError::NotFound {
                what: "agent package",
            });
        };
        if cur.status != AgentPackageStatus::Checking {
            return Err(DbError::Conflict {
                what: "agent package",
            });
        }
        let content_id = cur.content_id;
        let content_ready = self.work.archives.iter().any(|c| {
            c.id == content_id
                && c.state == ContentState::Ready
                && c.kind == ContentKindV2::AgentPackage
                && c.manifest.is_some()
        });
        if !content_ready {
            return Err(DbError::Conflict {
                what: "agent package content not ready",
            });
        }
        let signer_live = self
            .work
            .agent_signers
            .iter()
            .any(|s| s.id == signer && s.revoked.is_none());
        if !signer_live {
            return Err(DbError::Conflict {
                what: "agent signer",
            });
        }
        self.write()?;
        if let Some(p) = self.work.agent_packages.iter_mut().find(|p| p.id == id) {
            p.status = AgentPackageStatus::Ready;
            p.signer_id = Some(signer);
            p.manifest = Some(manifest);
            p.updated_at = at;
        }
        Ok(())
    }

    async fn refuse_agent_package(
        &mut self,
        id: AgentPackageId,
        reason: &ErrorCode,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        self.write()?;
        let p = self
            .work
            .agent_packages
            .iter_mut()
            .find(|p| p.id == id)
            .ok_or(DbError::NotFound {
                what: "agent package",
            })?;
        if p.status != AgentPackageStatus::Checking {
            return Err(DbError::Conflict {
                what: "agent package",
            });
        }
        p.status = AgentPackageStatus::Refused;
        p.refusal = Some(reason.clone());
        p.updated_at = at;
        Ok(())
    }

    async fn packages_using_agent_package(
        &mut self,
        id: AgentPackageId,
    ) -> Result<Vec<PackageRef>, DbError> {
        self.check()?;
        let users: Vec<PackageId> = self
            .work
            .package_configs
            .iter()
            .filter(|c| c.agent_package_id == id)
            .map(|c| c.package_id)
            .collect();
        Ok(self.package_refs(|p| users.contains(&p.id)))
    }

    async fn package_config(
        &mut self,
        package: PackageId,
    ) -> Result<Option<PackageConfig>, DbError> {
        self.check()?;
        Ok(self
            .work
            .package_configs
            .iter()
            .find(|c| c.package_id == package)
            .cloned())
    }

    async fn set_package_config(&mut self, c: &PackageConfig) -> Result<(), DbError> {
        if !c.values.valid() {
            return Err(DbError::InvalidArgument {
                what: "config values",
            });
        }
        if !c.answer_ok() {
            return Err(DbError::InvalidArgument {
                what: "answer template",
            });
        }
        crate::repo::package_config::tag_params(&c.tags)?;
        crate::repo::conv::to_json(&c.values, "config values")?;
        self.write()?;
        let refs_ok = self.work.packages.iter().any(|p| p.id == c.package_id)
            && self
                .work
                .agent_packages
                .iter()
                .any(|p| p.id == c.agent_package_id)
            && self.operator_exists(c.updated_by);
        if !refs_ok {
            return Err(self.abort(DbError::Constraint {
                what: "upsert package_config",
            }));
        }
        self.work
            .package_configs
            .retain(|x| x.package_id != c.package_id);
        self.work.package_configs.push(c.clone());
        Ok(())
    }

    async fn device_values(&mut self, mac: MacAddress) -> Result<Option<DeviceValues>, DbError> {
        self.check()?;
        Ok(self
            .work
            .device_values
            .iter()
            .find(|v| v.mac == mac)
            .cloned())
    }

    async fn set_device_values(&mut self, v: &DeviceValues) -> Result<(), DbError> {
        crate::repo::device_values::values_json(v)?;
        self.write()?;
        if !self.operator_exists(v.updated_by) {
            return Err(self.abort(DbError::Constraint {
                what: "upsert device_value",
            }));
        }
        self.work.device_values.retain(|x| x.mac != v.mac);
        self.work.device_values.push(v.clone());
        Ok(())
    }

    async fn delete_device_values(&mut self, mac: MacAddress) -> Result<(), DbError> {
        self.write()?;
        let before = self.work.device_values.len();
        self.work.device_values.retain(|x| x.mac != mac);
        if self.work.device_values.len() == before {
            return Err(DbError::NotFound {
                what: "device values",
            });
        }
        Ok(())
    }

    async fn insert_job_v2(&mut self, j: &NewJobV2) -> Result<(), DbError> {
        if j.previous_job_id == Some(j.id) {
            return Err(DbError::InvalidArgument {
                what: "previous job is the job itself",
            });
        }
        if i64::try_from(j.wipe_audit_seq).is_err()
            || i64::try_from(j.package.revision).is_err()
            || j.bytes_total.is_some_and(|b| i64::try_from(b).is_err())
            || !j.timeouts.valid()
        {
            return Err(DbError::InvalidArgument { what: "job" });
        }
        if usgp_crypto::sha256(j.job_key_spki.as_der()) != j.job_key_id {
            return Err(DbError::InvalidArgument { what: "job key id" });
        }
        crate::repo::package_config::tag_params(&j.tags)?;
        let json = crate::repo::conv::to_json(&j.disk, "disk descriptor")?;
        let disk: DiskDescriptorV1 = crate::repo::conv::from_json(&json, "disk")?;
        self.write()?;
        if self.job_identity_taken(j.id, j.session_id, j.wipe_audit_seq) {
            return Err(self.abort(DbError::Conflict { what: "insert job" }));
        }
        let refs_ok = self.session_ref(j.session_id).is_some()
            && self
                .work
                .boot_services
                .iter()
                .any(|b| b.id == j.boot_service_id)
            && self.content_ref(j.image_content_id).is_some()
            && j.previous_job_id.is_none_or(|p| self.job_exists(p));
        if !refs_ok {
            return Err(self.abort(DbError::Constraint { what: "insert job" }));
        }
        self.work.jobs_v2.push(JobV2 {
            id: j.id,
            session_id: j.session_id,
            boot_service_id: j.boot_service_id,
            package: j.package,
            image_content_id: j.image_content_id,
            edition_index: j.edition_index,
            disk,
            layout: None,
            macs: j.macs.clone(),
            state: JobState::Running,
            current_step: StepV2::VERIFY_CONTENT,
            failure: None,
            attempts: 0,
            bytes_done: None,
            bytes_total: j.bytes_total,
            last_seq: 0,
            started_at: j.started_at,
            last_report_at: None,
            finished_at: None,
            previous_job_id: j.previous_job_id,
            wipe_audit_seq: j.wipe_audit_seq,
            wipe_record_hash: j.wipe_record_hash,
            plan_sha256: j.plan_sha256,
            plan_key_id: j.plan_key_id,
            timeouts: j.timeouts,
            acknowledged: None,
            job_key_spki: j.job_key_spki.clone(),
            job_key_id: j.job_key_id,
            rendered_answer_sha256: j.rendered_answer_sha256,
            tags: j.tags.clone(),
            restart_pending: false,
        });
        for step in StepV2::ALL {
            let first = step == StepV2::VERIFY_CONTENT;
            self.work.job_steps_v2.push(JobStepV2 {
                job_id: j.id,
                step,
                state: if first {
                    StepState::Running
                } else {
                    StepState::Pending
                },
                started_at: first.then_some(j.started_at),
                finished_at: None,
            });
        }
        Ok(())
    }

    async fn job_v2(&mut self, id: JobId) -> Result<Option<JobV2>, DbError> {
        self.check()?;
        Ok(self.work.jobs_v2.iter().find(|j| j.id == id).cloned())
    }

    async fn lock_job_v2(&mut self, id: JobId) -> Result<Option<JobV2>, DbError> {
        self.job_v2(id).await
    }

    async fn job_v2_by_session(&mut self, session: SessionId) -> Result<Option<JobV2>, DbError> {
        self.check()?;
        Ok(self
            .work
            .jobs_v2
            .iter()
            .find(|j| j.session_id == session)
            .cloned())
    }

    async fn list_jobs_v2(&mut self, states: &[JobState]) -> Result<Vec<JobV2>, DbError> {
        self.check()?;
        let mut v: Vec<JobV2> = self
            .work
            .jobs_v2
            .iter()
            .filter(|j| states.is_empty() || states.contains(&j.state))
            .cloned()
            .collect();
        v.sort_by_key(|j| (j.started_at, j.id));
        Ok(v)
    }

    async fn job_plan_schema(&mut self, id: JobId) -> Result<Option<u8>, DbError> {
        self.check()?;
        if self.work.jobs_v2.iter().any(|j| j.id == id) {
            return Ok(Some(2));
        }
        Ok(self.job_ref(id).map(|_| 1))
    }

    async fn job_steps_v2(&mut self, id: JobId) -> Result<Vec<JobStepV2>, DbError> {
        self.check()?;
        let mut v: Vec<JobStepV2> = self
            .work
            .job_steps_v2
            .iter()
            .filter(|s| s.job_id == id)
            .copied()
            .collect();
        v.sort_by_key(|s| s.step);
        Ok(v)
    }

    async fn set_job_step_v2(
        &mut self,
        id: JobId,
        step: StepV2,
        to: StepState,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        let from = crate::repo::jobs::step_from_state(to)?;
        self.check()?;
        let job = self
            .work
            .jobs_v2
            .iter()
            .find(|j| j.id == id)
            .ok_or(DbError::NotFound { what: "job" })?;
        if job.state.is_final() {
            return Err(DbError::Conflict { what: "job" });
        }
        let steps: Vec<JobStepV2> = self
            .work
            .job_steps_v2
            .iter()
            .filter(|s| s.job_id == id)
            .copied()
            .collect();
        let earlier_open = steps
            .iter()
            .any(|s| s.step < step && s.state != StepState::Done);
        let current = steps.iter().find(|s| s.step == step).map(|s| s.state);
        if current != Some(from) || (to == StepState::Running && earlier_open) {
            return Err(DbError::Conflict { what: "job step" });
        }
        self.write()?;
        if let Some(s) = self
            .work
            .job_steps_v2
            .iter_mut()
            .find(|s| s.job_id == id && s.step == step)
        {
            s.state = to;
            if to == StepState::Running {
                s.started_at = Some(at);
            } else {
                s.finished_at = Some(at);
            }
        }
        if to == StepState::Running
            && let Some(j) = self.work.jobs_v2.iter_mut().find(|j| j.id == id)
        {
            j.current_step = j.current_step.max(step);
        }
        Ok(())
    }

    async fn fail_job_v2(
        &mut self,
        id: JobId,
        from: &[JobState],
        failure: &FailureV2,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        failure
            .validate()
            .map_err(|_| DbError::InvalidArgument { what: "failure" })?;
        let json = crate::repo::conv::to_json(failure, "failure")?;
        let failure: FailureV2 = crate::repo::conv::from_json(&json, "failure_detail")?;
        self.write()?;
        if self.job_ref(id).is_some() {
            return Err(DbError::Conflict { what: "job" });
        }
        let Some(j) = self.work.jobs_v2.iter_mut().find(|j| j.id == id) else {
            return Err(DbError::NotFound { what: "job" });
        };
        if !from.contains(&j.state) {
            return Err(DbError::Conflict { what: "job" });
        }
        if !j.state.can_become(JobState::Failed) {
            self.failed = true;
            return Err(DbError::Constraint {
                what: "update job failed",
            });
        }
        j.state = JobState::Failed;
        j.attempts = failure.attempts;
        j.failure = Some(failure);
        j.finished_at = Some(at);
        Ok(())
    }

    async fn set_job_restart_pending(&mut self, id: JobId) -> Result<(), DbError> {
        self.write()?;
        let Some(j) = self.work.jobs_v2.iter_mut().find(|j| j.id == id) else {
            return Err(if self.job_ref(id).is_some() {
                DbError::Conflict { what: "job" }
            } else {
                DbError::NotFound { what: "job" }
            });
        };
        if j.state.is_final() {
            return Err(DbError::Conflict { what: "job" });
        }
        j.restart_pending = true;
        Ok(())
    }

    async fn close_confirmed_session(
        &mut self,
        id: SessionId,
        reason: &ErrorCode,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        self.write()?;
        let s = self.session_mut(id).ok_or(DbError::NotFound {
            what: "device session",
        })?;
        if s.state != SessionState::Confirmed {
            return Err(DbError::Conflict {
                what: "device session",
            });
        }
        s.state = SessionState::Ended;
        s.ended_at = Some(at);
        s.end_reason = Some(reason.clone());
        Ok(())
    }

    async fn insert_resume_nonce(&mut self, n: &NewResumeNonce) -> Result<NonceIssue, DbError> {
        crate::repo::resume::check_window(n.issued_at, n.expires_at, "nonce expiry")?;
        // Bookkeeping, as the PostgreSQL statement (no `write`).
        self.check()?;
        let eligible = self
            .work
            .jobs_v2
            .iter()
            .any(|j| j.id == n.job_id && matches!(j.state, JobState::Running | JobState::Lost))
            && self.work.job_steps_v2.iter().any(|s| {
                s.job_id == n.job_id
                    && s.step == StepV2::MAKE_BOOTABLE_RESTART
                    && s.state == StepState::Done
            });
        let live = self
            .work
            .resume_nonces
            .iter()
            .filter(|x| x.job_id == n.job_id && x.used_at.is_none() && x.expires_at > n.issued_at)
            .count();
        if !eligible {
            return Ok(NonceIssue::NotEligible);
        }
        if u64::try_from(live).unwrap_or(u64::MAX)
            >= u64::from(crate::model::MAX_LIVE_RESUME_NONCES)
        {
            return Ok(NonceIssue::OverCap);
        }
        if self
            .work
            .resume_nonces
            .iter()
            .any(|x| x.hash == n.nonce_hash)
        {
            return Err(self.abort(DbError::Conflict {
                what: "insert job_resume_nonce",
            }));
        }
        self.work.resume_nonces.push(MemNonce {
            hash: n.nonce_hash,
            job_id: n.job_id,
            expires_at: n.expires_at,
            used_at: None,
        });
        Ok(NonceIssue::Issued)
    }

    async fn consume_resume_nonce(
        &mut self,
        job: JobId,
        nonce_hash: &Sha256Digest,
        at: UnixMicros,
    ) -> Result<bool, DbError> {
        self.check()?;
        let Some(n) = self.work.resume_nonces.iter_mut().find(|x| {
            x.hash == *nonce_hash && x.job_id == job && x.used_at.is_none() && x.expires_at > at
        }) else {
            return Ok(false);
        };
        n.used_at = Some(at);
        self.mutated = true;
        Ok(true)
    }

    async fn insert_resume_token(&mut self, t: &NewResumeToken) -> Result<(), DbError> {
        crate::repo::resume::check_window(t.issued_at, t.expires_at, "token expiry")?;
        self.write()?;
        if self
            .work
            .resume_tokens
            .iter()
            .any(|(h, _)| *h == t.token_hash)
        {
            return Err(self.abort(DbError::Conflict {
                what: "insert job_resume_token",
            }));
        }
        if !self.work.jobs_v2.iter().any(|j| j.id == t.job_id) {
            return Err(self.abort(DbError::Constraint {
                what: "insert job_resume_token",
            }));
        }
        self.work.resume_tokens.push((
            t.token_hash,
            ResumeToken {
                job_id: t.job_id,
                issued_at: t.issued_at,
                expires_at: t.expires_at,
                revoked_at: None,
            },
        ));
        Ok(())
    }

    async fn count_resume_tokens(&mut self, job: JobId) -> Result<u64, DbError> {
        self.check()?;
        let n = self
            .work
            .resume_tokens
            .iter()
            .filter(|(_, t)| t.job_id == job)
            .count();
        u64::try_from(n).map_err(|_| DbError::Corrupt { what: "count" })
    }

    async fn resume_token(&mut self, hash: &Sha256Digest) -> Result<Option<ResumeToken>, DbError> {
        self.check()?;
        Ok(self
            .work
            .resume_tokens
            .iter()
            .find(|(h, _)| h == hash)
            .map(|(_, t)| *t))
    }

    async fn revoke_resume_tokens(&mut self, job: JobId, at: UnixMicros) -> Result<u64, DbError> {
        self.check()?;
        let mut n: u64 = 0;
        for (_, t) in &mut self.work.resume_tokens {
            if t.job_id == job && t.revoked_at.is_none() {
                t.revoked_at = Some(at);
                n = n.saturating_add(1);
            }
        }
        if n > 0 {
            self.mutated = true;
        }
        Ok(n)
    }

    async fn insert_escrow(&mut self, e: &NewEscrow) -> Result<(), DbError> {
        if !e.sealed.valid() {
            return Err(DbError::InvalidArgument {
                what: "sealed password",
            });
        }
        self.write()?;
        if self.work.escrows.iter().any(|(r, _)| r.job_id == e.job_id) {
            return Err(self.abort(DbError::Conflict {
                what: "insert admin_password_escrow",
            }));
        }
        if !self.work.jobs_v2.iter().any(|j| j.id == e.job_id) {
            return Err(self.abort(DbError::Constraint {
                what: "insert admin_password_escrow",
            }));
        }
        self.work.escrows.push((
            EscrowRecord {
                job_id: e.job_id,
                account: e.account,
                key_id: e.key_id,
                state: EscrowState::Received,
                received_at: e.received_at,
                applied_at: None,
                reveal_count: 0,
            },
            e.sealed.clone(),
        ));
        Ok(())
    }

    async fn escrow(&mut self, job: JobId) -> Result<Option<EscrowRecord>, DbError> {
        self.check()?;
        Ok(self
            .work
            .escrows
            .iter()
            .find(|(r, _)| r.job_id == job)
            .map(|(r, _)| r.clone()))
    }

    async fn lock_escrow(&mut self, job: JobId) -> Result<Option<EscrowRecord>, DbError> {
        self.escrow(job).await
    }

    async fn escrow_sealed(&mut self, job: JobId) -> Result<Option<SealedPassword>, DbError> {
        self.check()?;
        Ok(self
            .work
            .escrows
            .iter()
            .find(|(r, _)| r.job_id == job)
            .map(|(_, s)| s.clone()))
    }

    async fn set_escrow_outcome(
        &mut self,
        job: JobId,
        applied: bool,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        self.write()?;
        let (r, _) = self
            .work
            .escrows
            .iter_mut()
            .find(|(r, _)| r.job_id == job)
            .ok_or(DbError::NotFound { what: "escrow" })?;
        if r.state != EscrowState::Received {
            return Err(DbError::Conflict { what: "escrow" });
        }
        r.state = if applied {
            EscrowState::Applied
        } else {
            EscrowState::NotApplied
        };
        r.applied_at = Some(at);
        Ok(())
    }

    async fn record_escrow_reveal(&mut self, job: JobId) -> Result<u32, DbError> {
        self.check()?;
        let (r, _) = self
            .work
            .escrows
            .iter_mut()
            .find(|(r, _)| r.job_id == job)
            .ok_or(DbError::NotFound { what: "escrow" })?;
        let n = r.reveal_count.checked_add(1).ok_or(DbError::Constraint {
            what: "update admin_password_escrow reveal",
        })?;
        r.reveal_count = n;
        self.mutated = true;
        Ok(n)
    }

    async fn commit(self) -> Result<(), DbError> {
        if self.failed {
            return Err(DbError::TxFailed);
        }
        if self.mutated && !self.audited {
            return Err(DbError::Unaudited);
        }
        // The audit-sequence foreign keys are DEFERRABLE INITIALLY DEFERRED
        // in 0001: checked at commit.
        let has = |seq: u64| self.work.records.iter().any(|r| r.seq == seq);
        let content_ok = self
            .work
            .content
            .iter()
            .filter_map(|c| c.initiating_audit_seq)
            .chain(
                self.work
                    .archives
                    .iter()
                    .filter_map(|c| c.initiating_audit_seq),
            )
            .all(has);
        let editions_ok = self
            .work
            .editions
            .iter()
            .filter_map(|e| e.declaration.as_ref().map(|d| d.declared_audit_seq))
            .all(has);
        if !content_ok || !editions_ok {
            return Err(DbError::Constraint {
                what: "commit (audit reference)",
            });
        }
        // Migration 0004 (deferred): the wipe guard.
        if !self.wipe_records_ok() {
            return Err(DbError::Constraint {
                what: "commit (wipe authorisation)",
            });
        }
        *lock(&self.shared.state) = self.work;
        Ok(())
    }

    async fn rollback(self) {}
}
