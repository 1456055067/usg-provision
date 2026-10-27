//! Repository interface: one transaction ([`RepoTx`]) carries the state
//! change and its audit record together (plan section 1.1, decision 0015
//! item 1).
//!
//! Usage (WU-6):
//!
//! 1. `let mut tx = store.begin().await?;`
//! 2. read and lock what the action needs (`lock_*`);
//! 3. make the change (`insert_*`, `set_*`, …);
//! 4. `chain.append(&mut tx, &draft).await?` ([`usgp_audit::AuditChain`];
//!    `RepoTx` is an [`AuditTx`] bound to the same transaction);
//! 5. `tx.commit().await?`, then mirror the record.
//!
//! Any error before commit → drop or `rollback` the transaction and
//! refuse the action. **A transaction that changed state but holds no
//! audit record cannot commit** ([`crate::DbError::Unaudited`]): the rule
//! "every state change emits an audit event" is structural, not a
//! convention.
//!
//! Two implementations keep the same rules: PostgreSQL
//! ([`crate::pool::PgStore`]) and in-memory ([`crate::memory::MemoryStore`],
//! for `usgp-api` tests).

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-2, AU-12 (Audit Record Generation) - commit requires
//   an audit record for any state change.
// - NIST 800-53: AU-5 (Response to Audit Logging Process Failures) - the
//   record and the change commit or roll back together.
// - NIST 800-53: SI-10 (Information Input Validation) - stored values are
//   re-validated on read.
// - SPEC: specs/operator-access.md#REQ-AUD-001, #REQ-AUD-006;
//   specs/os-images.md#REQ-IMG-020
// - Decision 0015

pub(crate) mod audit;
pub(crate) mod content;
pub(crate) mod conv;
pub(crate) mod operators;
pub(crate) mod packages;

use std::future::Future;

use usgp_audit::AuditTx;
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

/// A source of transactions.
pub trait Store: Send + Sync {
    /// The transaction type.
    type Tx: RepoTx;

    /// Starts a transaction.
    ///
    /// # Errors
    ///
    /// [`DbError::Connect`] or [`DbError::Query`] if the database cannot be
    /// reached.
    fn begin(&self) -> impl Future<Output = Result<Self::Tx, DbError>> + Send;
}

/// The operations available inside one transaction.
///
/// `lock_*` methods take a row lock until the transaction ends (PostgreSQL
/// `FOR UPDATE`; the in-memory store serialises whole transactions).
/// `set_*` methods are compare-and-set on the current state where a `from`
/// set is given: [`DbError::Conflict`] if the row is not in one of those
/// states, [`DbError::NotFound`] if it does not exist.
pub trait RepoTx: AuditTx + Send + Sized {
    // ---------------------------------------------------------- operators

    /// The operator with this id.
    fn operator(
        &mut self,
        id: OperatorId,
    ) -> impl Future<Output = Result<Option<Operator>, DbError>> + Send;

    /// The operator bound to this certificate fingerprint.
    fn operator_by_cert(
        &mut self,
        cert_sha256: &Sha256Digest,
    ) -> impl Future<Output = Result<Option<Operator>, DbError>> + Send;

    /// Every operator, ordered by creation time.
    fn list_operators(&mut self) -> impl Future<Output = Result<Vec<Operator>, DbError>> + Send;

    /// Enrols an operator. [`DbError::Conflict`] if the id or certificate
    /// is already enrolled.
    fn insert_operator(
        &mut self,
        op: &Operator,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Sets an operator's status.
    fn set_operator_status(
        &mut self,
        id: OperatorId,
        status: OperatorStatus,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    // ------------------------------------------------------------ content

    /// The content item with this id.
    fn content(
        &mut self,
        id: ContentId,
    ) -> impl Future<Output = Result<Option<Content>, DbError>> + Send;

    /// As [`RepoTx::content`], locking the row.
    fn lock_content(
        &mut self,
        id: ContentId,
    ) -> impl Future<Output = Result<Option<Content>, DbError>> + Send;

    /// The live (receiving, checking or ready) item with this digest.
    fn content_by_sha256(
        &mut self,
        sha256: &Sha256Digest,
    ) -> impl Future<Output = Result<Option<Content>, DbError>> + Send;

    /// Items of `kind` (any kind if `None`) whose state is in `states`
    /// (every state if empty), ordered by creation time.
    fn list_content(
        &mut self,
        kind: Option<ContentKind>,
        states: &[ContentState],
    ) -> impl Future<Output = Result<Vec<Content>, DbError>> + Send;

    /// Creates an upload session: the content row (state `receiving`) and
    /// the upload row (state `open`). [`DbError::Conflict`] if a live item
    /// with the same digest exists (look it up with
    /// [`RepoTx::content_by_sha256`] first to name it).
    fn create_upload(
        &mut self,
        content: &NewContent,
        upload: &Upload,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Moves content `id` from one of `from` to `to`, recording `reason`
    /// (required for `failed`) at time `at`. Use
    /// [`RepoTx::set_content_ready`] for `ready`.
    fn set_content_state(
        &mut self,
        id: ContentId,
        from: &[ContentState],
        to: ContentState,
        reason: Option<&Reason>,
        at: UnixMicros,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Moves content `id` from `checking` to `ready` with its WIM facts,
    /// editions and signed manifest.
    fn set_content_ready(
        &mut self,
        id: ContentId,
        ready: &ReadyContent,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// The editions of an image, by index.
    fn editions(
        &mut self,
        content_id: ContentId,
    ) -> impl Future<Output = Result<Vec<Edition>, DbError>> + Send;

    /// One edition.
    fn edition(
        &mut self,
        content_id: ContentId,
        index: u32,
    ) -> impl Future<Output = Result<Option<Edition>, DbError>> + Send;

    /// Records a declaration and the resulting support status of an
    /// edition (decision 0013).
    fn set_edition_declaration(
        &mut self,
        content_id: ContentId,
        index: u32,
        declaration: &EditionDeclaration,
        support: SupportState,
        support_reason: Option<&str>,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    // ------------------------------------------------------------ uploads

    /// The upload session with this id.
    fn upload(
        &mut self,
        id: UploadId,
    ) -> impl Future<Output = Result<Option<Upload>, DbError>> + Send;

    /// As [`RepoTx::upload`], locking the row.
    fn lock_upload(
        &mut self,
        id: UploadId,
    ) -> impl Future<Output = Result<Option<Upload>, DbError>> + Send;

    /// Upload sessions whose state is in `states`, ordered by creation.
    fn list_uploads(
        &mut self,
        states: &[UploadState],
    ) -> impl Future<Output = Result<Vec<Upload>, DbError>> + Send;

    /// Serialises upload-quota decisions: held until the transaction
    /// ends, so two transactions cannot both count the open sessions,
    /// both see room, and both create one (finding SEC-009). Call before
    /// [`RepoTx::count_active_uploads`] when the count decides whether to
    /// create a session. PostgreSQL: a transaction-scoped advisory lock on
    /// a constant key; the in-memory store already serialises
    /// transactions.
    fn lock_upload_quota(&mut self) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Number of `open` or `streaming` sessions, for one operator or all
    /// (plan 3.2 upload caps).
    fn count_active_uploads(
        &mut self,
        operator: Option<OperatorId>,
    ) -> impl Future<Output = Result<u64, DbError>> + Send;

    /// Moves upload `id` from one of `from` to `to`.
    fn set_upload_state(
        &mut self,
        id: UploadId,
        from: &[UploadState],
        to: UploadState,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    // ----------------------------------------------------------- packages

    /// The package with this id.
    fn package(
        &mut self,
        id: PackageId,
    ) -> impl Future<Output = Result<Option<Package>, DbError>> + Send;

    /// As [`RepoTx::package`], locking the row.
    fn lock_package(
        &mut self,
        id: PackageId,
    ) -> impl Future<Output = Result<Option<Package>, DbError>> + Send;

    /// Every package, ordered by creation time.
    fn list_packages(&mut self) -> impl Future<Output = Result<Vec<Package>, DbError>> + Send;

    /// Packages that use content `id` as image or PE (decision 0015 item 2).
    fn packages_using_content(
        &mut self,
        id: ContentId,
    ) -> impl Future<Output = Result<Vec<PackageRef>, DbError>> + Send;

    /// Packages that use one edition.
    fn packages_using_edition(
        &mut self,
        content_id: ContentId,
        index: u32,
    ) -> impl Future<Output = Result<Vec<PackageRef>, DbError>> + Send;

    /// Inserts a package; `revision` must be 1. The image must be an image
    /// with that edition and the PE a PE ([`DbError::Constraint`]
    /// otherwise).
    fn insert_package(&mut self, p: &Package) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Replaces a package if its stored revision is `expected_revision`;
    /// `p.revision` must be `expected_revision + 1`. [`DbError::Conflict`]
    /// on a revision mismatch (HTTP 412).
    fn update_package(
        &mut self,
        p: &Package,
        expected_revision: u64,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Sets a package's status, reason and manifest (`None` clears it)
    /// without changing its revision.
    fn set_package_status(
        &mut self,
        id: PackageId,
        status: PackageStatus,
        reason: Option<&str>,
        manifest: Option<&StoredManifest>,
        at: UnixMicros,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Deletes a package if its stored revision is `expected_revision`.
    fn delete_package(
        &mut self,
        id: PackageId,
        expected_revision: u64,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    // ---------------------------------------------------------- lifecycle

    /// Commits. Refused with [`DbError::Unaudited`] (and rolled back) if
    /// the transaction changed state without appending an audit record,
    /// and with [`DbError::TxFailed`] if an earlier statement failed.
    fn commit(self) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Rolls back. Dropping a transaction also rolls it back.
    fn rollback(self) -> impl Future<Output = ()> + Send;
}

impl RepoTx for crate::pool::PgTx {
    async fn operator(&mut self, id: OperatorId) -> Result<Option<Operator>, DbError> {
        operators::get(self, id).await
    }

    async fn operator_by_cert(
        &mut self,
        cert_sha256: &Sha256Digest,
    ) -> Result<Option<Operator>, DbError> {
        operators::by_cert(self, cert_sha256).await
    }

    async fn list_operators(&mut self) -> Result<Vec<Operator>, DbError> {
        operators::list(self).await
    }

    async fn insert_operator(&mut self, op: &Operator) -> Result<(), DbError> {
        operators::insert(self, op).await
    }

    async fn set_operator_status(
        &mut self,
        id: OperatorId,
        status: OperatorStatus,
    ) -> Result<(), DbError> {
        operators::set_status(self, id, status).await
    }

    async fn content(&mut self, id: ContentId) -> Result<Option<Content>, DbError> {
        content::get(self, id, false).await
    }

    async fn lock_content(&mut self, id: ContentId) -> Result<Option<Content>, DbError> {
        content::get(self, id, true).await
    }

    async fn content_by_sha256(
        &mut self,
        sha256: &Sha256Digest,
    ) -> Result<Option<Content>, DbError> {
        content::by_sha256(self, sha256).await
    }

    async fn list_content(
        &mut self,
        kind: Option<ContentKind>,
        states: &[ContentState],
    ) -> Result<Vec<Content>, DbError> {
        content::list(self, kind, states).await
    }

    async fn create_upload(&mut self, c: &NewContent, u: &Upload) -> Result<(), DbError> {
        content::create_upload(self, c, u).await
    }

    async fn set_content_state(
        &mut self,
        id: ContentId,
        from: &[ContentState],
        to: ContentState,
        reason: Option<&Reason>,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        content::set_state(self, id, from, to, reason, at).await
    }

    async fn set_content_ready(&mut self, id: ContentId, r: &ReadyContent) -> Result<(), DbError> {
        content::set_ready(self, id, r).await
    }

    async fn editions(&mut self, content_id: ContentId) -> Result<Vec<Edition>, DbError> {
        content::editions(self, content_id).await
    }

    async fn edition(
        &mut self,
        content_id: ContentId,
        index: u32,
    ) -> Result<Option<Edition>, DbError> {
        content::edition(self, content_id, index).await
    }

    async fn set_edition_declaration(
        &mut self,
        content_id: ContentId,
        index: u32,
        d: &EditionDeclaration,
        support: SupportState,
        support_reason: Option<&str>,
    ) -> Result<(), DbError> {
        content::set_declaration(self, content_id, index, d, support, support_reason).await
    }

    async fn upload(&mut self, id: UploadId) -> Result<Option<Upload>, DbError> {
        content::upload(self, id, false).await
    }

    async fn lock_upload(&mut self, id: UploadId) -> Result<Option<Upload>, DbError> {
        content::upload(self, id, true).await
    }

    async fn list_uploads(&mut self, states: &[UploadState]) -> Result<Vec<Upload>, DbError> {
        content::list_uploads(self, states).await
    }

    async fn lock_upload_quota(&mut self) -> Result<(), DbError> {
        content::lock_upload_quota(self).await
    }

    async fn count_active_uploads(&mut self, operator: Option<OperatorId>) -> Result<u64, DbError> {
        content::count_active(self, operator).await
    }

    async fn set_upload_state(
        &mut self,
        id: UploadId,
        from: &[UploadState],
        to: UploadState,
    ) -> Result<(), DbError> {
        content::set_upload_state(self, id, from, to).await
    }

    async fn package(&mut self, id: PackageId) -> Result<Option<Package>, DbError> {
        packages::get(self, id, false).await
    }

    async fn lock_package(&mut self, id: PackageId) -> Result<Option<Package>, DbError> {
        packages::get(self, id, true).await
    }

    async fn list_packages(&mut self) -> Result<Vec<Package>, DbError> {
        packages::list(self).await
    }

    async fn packages_using_content(&mut self, id: ContentId) -> Result<Vec<PackageRef>, DbError> {
        packages::using_content(self, id).await
    }

    async fn packages_using_edition(
        &mut self,
        content_id: ContentId,
        index: u32,
    ) -> Result<Vec<PackageRef>, DbError> {
        packages::using_edition(self, content_id, index).await
    }

    async fn insert_package(&mut self, p: &Package) -> Result<(), DbError> {
        packages::insert(self, p).await
    }

    async fn update_package(&mut self, p: &Package, expected_revision: u64) -> Result<(), DbError> {
        packages::update(self, p, expected_revision).await
    }

    async fn set_package_status(
        &mut self,
        id: PackageId,
        status: PackageStatus,
        reason: Option<&str>,
        manifest: Option<&StoredManifest>,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        packages::set_status(self, id, status, reason, manifest, at).await
    }

    async fn delete_package(
        &mut self,
        id: PackageId,
        expected_revision: u64,
    ) -> Result<(), DbError> {
        packages::delete(self, id, expected_revision).await
    }

    async fn commit(self) -> Result<(), DbError> {
        self.finish_commit().await
    }

    async fn rollback(self) {
        self.finish_rollback().await;
    }
}
