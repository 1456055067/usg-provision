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
pub(crate) mod boot_services;
pub(crate) mod codes;
pub(crate) mod content;
pub(crate) mod conv;
pub(crate) mod devices;
pub(crate) mod jobs;
pub(crate) mod operators;
pub(crate) mod packages;

use std::future::Future;
use std::net::IpAddr;

use usgp_audit::AuditTx;
use usgp_common::Sha256Digest;
use usgp_crypto::HmacTag;
use usgp_proto::device::SessionState;
use usgp_proto::ops::BootServiceStatus;
use usgp_proto::{
    AuthCodeId, BootServiceId, BootStopId, ContentId, ContentKind, ContentState, DiskDescriptorV1,
    ErrorCode, FailureV1, JobId, JobState, LayoutReportV1, MacList, OperatorId, PackageId,
    PackageStatus, SessionId, Step, StepState, SupportState, UnixMicros, UploadId, UploadState,
};

use crate::error::DbError;
use crate::model::{
    AuthCodeRecord, BootService, BootServicePackage, BootStop, ChosenPackage, Content,
    DeviceSession, Edition, EditionDeclaration, Job, JobStep, NewAuthCode, NewBootStop, NewContent,
    NewDeviceSession, NewJob, Operator, OperatorStatus, Package, PackageRef, ReadyContent, Reason,
    SessionAuth, StoredManifest, Upload,
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

    // ------------------------------------------------------ boot services

    /// The boot service with this id.
    fn boot_service(
        &mut self,
        id: BootServiceId,
    ) -> impl Future<Output = Result<Option<BootService>, DbError>> + Send;

    /// The boot service bound to this client-certificate fingerprint
    /// (relay authentication, decision 0021).
    fn boot_service_by_cert(
        &mut self,
        cert_sha256: &Sha256Digest,
    ) -> impl Future<Output = Result<Option<BootService>, DbError>> + Send;

    /// Every boot service, ordered by creation time. Resolving a device's
    /// boot service from its source address is the caller's: more than
    /// one active service containing the address is ambiguous and must be
    /// refused.
    fn list_boot_services(
        &mut self,
    ) -> impl Future<Output = Result<Vec<BootService>, DbError>> + Send;

    /// Enrols a boot service (administrative role only on PostgreSQL).
    /// [`DbError::Conflict`] if the id, name or certificate is enrolled.
    fn insert_boot_service(
        &mut self,
        b: &BootService,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Sets a boot service's status (administrative role only).
    fn set_boot_service_status(
        &mut self,
        id: BootServiceId,
        status: BootServiceStatus,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// The packages assigned to a boot service, ordered by assignment time.
    fn boot_service_packages(
        &mut self,
        id: BootServiceId,
    ) -> impl Future<Output = Result<Vec<BootServicePackage>, DbError>> + Send;

    /// Replaces a boot service's assignments with `package_ids` (distinct,
    /// at most 256). Kept assignments keep their original `added_by` and
    /// `added_at`. Serialised per boot service. [`DbError::NotFound`] for
    /// an unknown service; [`DbError::Constraint`] for an unknown package.
    fn set_boot_service_packages(
        &mut self,
        id: BootServiceId,
        package_ids: &[PackageId],
        by: OperatorId,
        at: UnixMicros,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Boot services a package is assigned to. An assigned package cannot
    /// be deleted ([`DbError::Constraint`] from
    /// [`RepoTx::delete_package`]); name these instead.
    fn boot_services_using_package(
        &mut self,
        id: PackageId,
    ) -> impl Future<Output = Result<Vec<BootServiceId>, DbError>> + Send;

    // --------------------------------------------------------- boot stops

    /// The boot stop with this id.
    fn boot_stop(
        &mut self,
        id: BootStopId,
    ) -> impl Future<Output = Result<Option<BootStop>, DbError>> + Send;

    /// Boot stops of one service (every service if `None`), only the
    /// uncleared ones if `active_only`, ordered by creation time.
    fn list_boot_stops(
        &mut self,
        boot_service: Option<BootServiceId>,
        active_only: bool,
    ) -> impl Future<Output = Result<Vec<BootStop>, DbError>> + Send;

    /// Adds a stop for a device MAC (REQ-BOOT-067). `false` (nothing
    /// written) if an uncleared stop for that service and MAC exists.
    fn add_boot_stop(
        &mut self,
        s: &NewBootStop,
    ) -> impl Future<Output = Result<bool, DbError>> + Send;

    /// Clears a stop (the minimal reversal). [`DbError::Conflict`] if
    /// already cleared.
    fn clear_boot_stop(
        &mut self,
        id: BootStopId,
        by: OperatorId,
        at: UnixMicros,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// The current boot-policy generation of a service (0 before the
    /// first).
    fn boot_policy_generation(
        &mut self,
        id: BootServiceId,
    ) -> impl Future<Output = Result<u64, DbError>> + Send;

    /// Increments the generation (from 0 to 1 the first time) and returns
    /// the new value. Call with every change to the service's stop set.
    fn bump_boot_policy_generation(
        &mut self,
        id: BootServiceId,
    ) -> impl Future<Output = Result<u64, DbError>> + Send;

    // ---------------------------------------------------- operator codes

    /// Stores a new code by its HMAC. [`DbError::Conflict`] if the id or
    /// HMAC exists (draw a new code).
    fn insert_auth_code(
        &mut self,
        c: &NewAuthCode,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// One code's record (no value, no HMAC).
    fn auth_code(
        &mut self,
        id: AuthCodeId,
    ) -> impl Future<Output = Result<Option<AuthCodeRecord>, DbError>> + Send;

    /// Every code's record, ordered by issue time.
    fn list_auth_codes(
        &mut self,
    ) -> impl Future<Output = Result<Vec<AuthCodeRecord>, DbError>> + Send;

    /// Uses the code with this HMAC for `session` at `at`, atomically.
    /// `None` for a wrong, expired, used or revoked code alike (no
    /// oracle); nothing changes then.
    fn consume_auth_code(
        &mut self,
        code_hmac: &HmacTag,
        session: SessionId,
        at: UnixMicros,
    ) -> impl Future<Output = Result<Option<AuthCodeId>, DbError>> + Send;

    /// Revokes an unused code. [`DbError::Conflict`] if used or revoked.
    fn revoke_auth_code(
        &mut self,
        id: AuthCodeId,
        by: OperatorId,
        at: UnixMicros,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    // --------------------------------------------------- device sessions

    /// Opens a session in state `awaiting_authorisation`.
    /// [`DbError::Conflict`] if the id or token exists or the display code
    /// is in use by a live session (draw a new one).
    fn insert_device_session(
        &mut self,
        s: &NewDeviceSession,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// The session with this id.
    fn device_session(
        &mut self,
        id: SessionId,
    ) -> impl Future<Output = Result<Option<DeviceSession>, DbError>> + Send;

    /// As [`RepoTx::device_session`], locking the row.
    fn lock_device_session(
        &mut self,
        id: SessionId,
    ) -> impl Future<Output = Result<Option<DeviceSession>, DbError>> + Send;

    /// The session whose bearer token has this SHA-256.
    fn device_session_by_token(
        &mut self,
        token_sha256: &Sha256Digest,
    ) -> impl Future<Output = Result<Option<DeviceSession>, DbError>> + Send;

    /// Sessions whose state is in `states` (every state if empty), ordered
    /// by creation time.
    fn list_device_sessions(
        &mut self,
        states: &[SessionState],
    ) -> impl Future<Output = Result<Vec<DeviceSession>, DbError>> + Send;

    /// Serialises session-cap decisions until the transaction ends (as
    /// [`RepoTx::lock_upload_quota`]).
    fn lock_device_session_quota(&mut self) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Number of sessions in `states` (every state if empty), from one
    /// source address or all.
    fn count_device_sessions(
        &mut self,
        states: &[SessionState],
        source_ip: Option<IpAddr>,
    ) -> impl Future<Output = Result<u64, DbError>> + Send;

    /// Records that the device was seen at `at` (never moves back). Not a
    /// state change: needs no audit record (plan section 3.1, poll).
    fn touch_device_session(
        &mut self,
        id: SessionId,
        at: UnixMicros,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// `awaiting_authorisation` → `authorised` by a code or an approval,
    /// if not expired at `at`. [`DbError::Conflict`] otherwise.
    fn authorise_device_session(
        &mut self,
        id: SessionId,
        auth: SessionAuth,
        at: UnixMicros,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Counts a failed code attempt on a waiting session and returns the
    /// new count. [`DbError::Conflict`] if the session is not waiting.
    fn record_failed_code_attempt(
        &mut self,
        id: SessionId,
    ) -> impl Future<Output = Result<u32, DbError>> + Send;

    /// Records the chosen package on an authorised session and clears any
    /// chosen disk (its size is checked against the package again).
    fn choose_session_package(
        &mut self,
        id: SessionId,
        p: ChosenPackage,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Records the chosen disk on an authorised session that has a
    /// package. [`DbError::Conflict`] otherwise.
    fn choose_session_disk(
        &mut self,
        id: SessionId,
        disk: &DiskDescriptorV1,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Moves a session from one of `from` to `to` (`confirmed`, `refused`,
    /// `cancelled`, `expired` or `ended`; use
    /// [`RepoTx::authorise_device_session`] for `authorised`). Every
    /// target but `confirmed` records `at` as the end and `reason`.
    /// `confirmed` needs a chosen disk. [`DbError::Conflict`] otherwise.
    fn set_device_session_state(
        &mut self,
        id: SessionId,
        from: &[SessionState],
        to: SessionState,
        reason: Option<&ErrorCode>,
        at: UnixMicros,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Expires every waiting or authorised session whose expiry is at or
    /// before `at`, and returns their ids (one `device.session.expired`
    /// record each is the caller's).
    fn expire_device_sessions(
        &mut self,
        at: UnixMicros,
    ) -> impl Future<Output = Result<Vec<SessionId>, DbError>> + Send;

    // --------------------------------------------------------------- jobs

    /// Creates a job (state `running`, step 1 running, steps 2 to 5
    /// pending). The transaction must also hold the `disk.wipe.authorised`
    /// record that `j.wipe_audit_seq` and `j.wipe_record_hash` name, with
    /// outcome success and target (`job`, the job id): otherwise the
    /// commit is refused ([`DbError::Constraint`]) and nothing is written
    /// (the wipe guard, REQ-DISK-006). [`DbError::Conflict`] if the job,
    /// its session or its wipe record already has a job.
    fn insert_job(&mut self, j: &NewJob) -> impl Future<Output = Result<(), DbError>> + Send;

    /// The job with this id.
    fn job(&mut self, id: JobId) -> impl Future<Output = Result<Option<Job>, DbError>> + Send;

    /// As [`RepoTx::job`], locking the row.
    fn lock_job(&mut self, id: JobId) -> impl Future<Output = Result<Option<Job>, DbError>> + Send;

    /// The job of a session.
    fn job_by_session(
        &mut self,
        session: SessionId,
    ) -> impl Future<Output = Result<Option<Job>, DbError>> + Send;

    /// Jobs whose state is in `states` (every state if empty), ordered by
    /// start time.
    fn list_jobs(
        &mut self,
        states: &[JobState],
    ) -> impl Future<Output = Result<Vec<Job>, DbError>> + Send;

    /// The five steps of a job, in order.
    fn job_steps(
        &mut self,
        id: JobId,
    ) -> impl Future<Output = Result<Vec<JobStep>, DbError>> + Send;

    /// The latest failed or lost job sharing a MAC with `macs`
    /// (REQ-JOB-009 `previous_job_id`).
    fn previous_failed_job(
        &mut self,
        macs: &MacList,
    ) -> impl Future<Output = Result<Option<JobId>, DbError>> + Send;

    /// Moves a step: pending → running (every earlier step must be done;
    /// the job's current step follows), running → done or failed.
    /// [`DbError::Conflict`] for any other move or a finished job.
    fn set_job_step(
        &mut self,
        id: JobId,
        step: Step,
        to: StepState,
        at: UnixMicros,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Moves a job from one of `from` to `to` (`running`, `lost` or
    /// `succeeded`; use [`RepoTx::fail_job`] for `failed`). `succeeded`
    /// needs step 4 done (REQ-JOB-013) and records `at` as the finish.
    /// [`DbError::Conflict`] otherwise; a finished job never changes.
    fn set_job_state(
        &mut self,
        id: JobId,
        from: &[JobState],
        to: JobState,
        at: UnixMicros,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Fails a job from one of `from` with its failure (final).
    fn fail_job(
        &mut self,
        id: JobId,
        from: &[JobState],
        failure: &FailureV1,
        at: UnixMicros,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Records the layout written (step 2) on an unfinished job.
    fn set_job_layout(
        &mut self,
        id: JobId,
        layout: &LayoutReportV1,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Records an accepted report's sequence number, time and byte counts
    /// (`None` keeps the stored count) on an unfinished job. Not a state
    /// change: needs no audit record (plan section 3.4, `progress`).
    /// [`DbError::Conflict`] if `seq` is not above the last one, the job
    /// is finished, or the done count would exceed the total.
    fn record_job_progress(
        &mut self,
        id: JobId,
        seq: u64,
        bytes_done: Option<u64>,
        bytes_total: Option<u64>,
        at: UnixMicros,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Acknowledges a failed job once. [`DbError::Conflict`] otherwise.
    fn acknowledge_job_failure(
        &mut self,
        id: JobId,
        by: OperatorId,
        at: UnixMicros,
    ) -> impl Future<Output = Result<(), DbError>> + Send;

    /// Marks every running job not heard from since before `silent_before`
    /// as lost and returns their ids (one `job.lost` record each is the
    /// caller's).
    fn mark_lost_jobs(
        &mut self,
        silent_before: UnixMicros,
    ) -> impl Future<Output = Result<Vec<JobId>, DbError>> + Send;

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

    async fn boot_service(&mut self, id: BootServiceId) -> Result<Option<BootService>, DbError> {
        boot_services::get(self, id).await
    }

    async fn boot_service_by_cert(
        &mut self,
        cert_sha256: &Sha256Digest,
    ) -> Result<Option<BootService>, DbError> {
        boot_services::by_cert(self, cert_sha256).await
    }

    async fn list_boot_services(&mut self) -> Result<Vec<BootService>, DbError> {
        boot_services::list(self).await
    }

    async fn insert_boot_service(&mut self, b: &BootService) -> Result<(), DbError> {
        boot_services::insert(self, b).await
    }

    async fn set_boot_service_status(
        &mut self,
        id: BootServiceId,
        status: BootServiceStatus,
    ) -> Result<(), DbError> {
        boot_services::set_status(self, id, status).await
    }

    async fn boot_service_packages(
        &mut self,
        id: BootServiceId,
    ) -> Result<Vec<BootServicePackage>, DbError> {
        boot_services::packages(self, id).await
    }

    async fn set_boot_service_packages(
        &mut self,
        id: BootServiceId,
        package_ids: &[PackageId],
        by: OperatorId,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        boot_services::set_packages(self, id, package_ids, by, at).await
    }

    async fn boot_services_using_package(
        &mut self,
        id: PackageId,
    ) -> Result<Vec<BootServiceId>, DbError> {
        boot_services::using_package(self, id).await
    }

    async fn boot_stop(&mut self, id: BootStopId) -> Result<Option<BootStop>, DbError> {
        boot_services::stop(self, id).await
    }

    async fn list_boot_stops(
        &mut self,
        boot_service: Option<BootServiceId>,
        active_only: bool,
    ) -> Result<Vec<BootStop>, DbError> {
        boot_services::stops(self, boot_service, active_only).await
    }

    async fn add_boot_stop(&mut self, s: &NewBootStop) -> Result<bool, DbError> {
        boot_services::add_stop(self, s).await
    }

    async fn clear_boot_stop(
        &mut self,
        id: BootStopId,
        by: OperatorId,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        boot_services::clear_stop(self, id, by, at).await
    }

    async fn boot_policy_generation(&mut self, id: BootServiceId) -> Result<u64, DbError> {
        boot_services::generation(self, id).await
    }

    async fn bump_boot_policy_generation(&mut self, id: BootServiceId) -> Result<u64, DbError> {
        boot_services::bump_generation(self, id).await
    }

    async fn insert_auth_code(&mut self, c: &NewAuthCode) -> Result<(), DbError> {
        codes::insert(self, c).await
    }

    async fn auth_code(&mut self, id: AuthCodeId) -> Result<Option<AuthCodeRecord>, DbError> {
        codes::get(self, id).await
    }

    async fn list_auth_codes(&mut self) -> Result<Vec<AuthCodeRecord>, DbError> {
        codes::list(self).await
    }

    async fn consume_auth_code(
        &mut self,
        code_hmac: &HmacTag,
        session: SessionId,
        at: UnixMicros,
    ) -> Result<Option<AuthCodeId>, DbError> {
        codes::consume(self, code_hmac, session, at).await
    }

    async fn revoke_auth_code(
        &mut self,
        id: AuthCodeId,
        by: OperatorId,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        codes::revoke(self, id, by, at).await
    }

    async fn insert_device_session(&mut self, s: &NewDeviceSession) -> Result<(), DbError> {
        devices::insert(self, s).await
    }

    async fn device_session(&mut self, id: SessionId) -> Result<Option<DeviceSession>, DbError> {
        devices::get(self, id, false).await
    }

    async fn lock_device_session(
        &mut self,
        id: SessionId,
    ) -> Result<Option<DeviceSession>, DbError> {
        devices::get(self, id, true).await
    }

    async fn device_session_by_token(
        &mut self,
        token_sha256: &Sha256Digest,
    ) -> Result<Option<DeviceSession>, DbError> {
        devices::by_token(self, token_sha256).await
    }

    async fn list_device_sessions(
        &mut self,
        states: &[SessionState],
    ) -> Result<Vec<DeviceSession>, DbError> {
        devices::list(self, states).await
    }

    async fn lock_device_session_quota(&mut self) -> Result<(), DbError> {
        devices::lock_quota(self).await
    }

    async fn count_device_sessions(
        &mut self,
        states: &[SessionState],
        source_ip: Option<IpAddr>,
    ) -> Result<u64, DbError> {
        devices::count(self, states, source_ip).await
    }

    async fn touch_device_session(&mut self, id: SessionId, at: UnixMicros) -> Result<(), DbError> {
        devices::touch(self, id, at).await
    }

    async fn authorise_device_session(
        &mut self,
        id: SessionId,
        auth: SessionAuth,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        devices::authorise(self, id, auth, at).await
    }

    async fn record_failed_code_attempt(&mut self, id: SessionId) -> Result<u32, DbError> {
        devices::failed_code_attempt(self, id).await
    }

    async fn choose_session_package(
        &mut self,
        id: SessionId,
        p: ChosenPackage,
    ) -> Result<(), DbError> {
        devices::choose_package(self, id, p).await
    }

    async fn choose_session_disk(
        &mut self,
        id: SessionId,
        disk: &DiskDescriptorV1,
    ) -> Result<(), DbError> {
        devices::choose_disk(self, id, disk).await
    }

    async fn set_device_session_state(
        &mut self,
        id: SessionId,
        from: &[SessionState],
        to: SessionState,
        reason: Option<&ErrorCode>,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        devices::set_state(self, id, from, to, reason, at).await
    }

    async fn expire_device_sessions(&mut self, at: UnixMicros) -> Result<Vec<SessionId>, DbError> {
        devices::expire(self, at).await
    }

    async fn insert_job(&mut self, j: &NewJob) -> Result<(), DbError> {
        jobs::insert(self, j).await
    }

    async fn job(&mut self, id: JobId) -> Result<Option<Job>, DbError> {
        jobs::get(self, id, false).await
    }

    async fn lock_job(&mut self, id: JobId) -> Result<Option<Job>, DbError> {
        jobs::get(self, id, true).await
    }

    async fn job_by_session(&mut self, session: SessionId) -> Result<Option<Job>, DbError> {
        jobs::by_session(self, session).await
    }

    async fn list_jobs(&mut self, states: &[JobState]) -> Result<Vec<Job>, DbError> {
        jobs::list(self, states).await
    }

    async fn job_steps(&mut self, id: JobId) -> Result<Vec<JobStep>, DbError> {
        jobs::steps(self, id).await
    }

    async fn previous_failed_job(&mut self, macs: &MacList) -> Result<Option<JobId>, DbError> {
        jobs::previous_failed(self, macs).await
    }

    async fn set_job_step(
        &mut self,
        id: JobId,
        step: Step,
        to: StepState,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        jobs::set_step(self, id, step, to, at).await
    }

    async fn set_job_state(
        &mut self,
        id: JobId,
        from: &[JobState],
        to: JobState,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        jobs::set_state(self, id, from, to, at).await
    }

    async fn fail_job(
        &mut self,
        id: JobId,
        from: &[JobState],
        failure: &FailureV1,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        jobs::fail(self, id, from, failure, at).await
    }

    async fn set_job_layout(&mut self, id: JobId, layout: &LayoutReportV1) -> Result<(), DbError> {
        jobs::set_layout(self, id, layout).await
    }

    async fn record_job_progress(
        &mut self,
        id: JobId,
        seq: u64,
        bytes_done: Option<u64>,
        bytes_total: Option<u64>,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        jobs::record_progress(self, id, seq, bytes_done, bytes_total, at).await
    }

    async fn acknowledge_job_failure(
        &mut self,
        id: JobId,
        by: OperatorId,
        at: UnixMicros,
    ) -> Result<(), DbError> {
        jobs::acknowledge(self, id, by, at).await
    }

    async fn mark_lost_jobs(&mut self, silent_before: UnixMicros) -> Result<Vec<JobId>, DbError> {
        jobs::mark_lost(self, silent_before).await
    }

    async fn commit(self) -> Result<(), DbError> {
        self.finish_commit().await
    }

    async fn rollback(self) {
        self.finish_rollback().await;
    }
}
