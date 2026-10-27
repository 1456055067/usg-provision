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
//!   ([`DbError::Unaudited`]).
//!
//! Audit fault injection ([`MemoryStore::fail_next_audit_writes`],
//! [`MemoryStore::set_fail_audit_writes`]) makes audit writes fail, so
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
use usgp_proto::{
    ContentId, ContentKind, ContentState, OperatorId, PackageId, PackageStatus, SupportState,
    UnixMicros, UploadId, UploadState,
};

use crate::error::DbError;
use crate::model::{
    Content, Edition, EditionDeclaration, NewContent, Operator, OperatorStatus, Package,
    PackageRef, ReadyContent, Reason, StoredManifest, Upload,
};
use crate::repo::{RepoTx, Store};

#[derive(Debug, Clone, Default)]
struct State {
    operators: Vec<Operator>,
    content: Vec<Content>,
    editions: Vec<Edition>,
    uploads: Vec<Upload>,
    packages: Vec<Package>,
    records: Vec<AuditRecord>,
    checkpoints: Vec<Checkpoint>,
    head: Option<ChainHead>,
}

#[derive(Debug, Default)]
struct Faults {
    fail_next: u32,
    fail_all: bool,
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

impl AuditTx for MemoryTx {
    async fn lock_head(&mut self) -> Result<Option<ChainHead>, StoreError> {
        self.check().map_err(|e| e.into_store("lock audit_head"))?;
        Ok(self.work.head)
    }

    async fn insert_record(&mut self, rec: &AuditRecord) -> Result<(), StoreError> {
        let ctx = "insert audit_record";
        self.write().map_err(|e| e.into_store(ctx))?;
        if let Err(e) = faulted(&self.shared, ctx) {
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
        if self.content_ref(c.id).is_some()
            || self
                .work
                .content
                .iter()
                .any(|x| x.sha256 == c.sha256 && LIVE.contains(&x.state))
        {
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
        self.work.packages.remove(pos);
        Ok(())
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
        *lock(&self.shared.state) = self.work;
        Ok(())
    }

    async fn rollback(self) {}
}
