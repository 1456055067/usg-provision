//! Row types of the M2 schema (plan section 3.4) and the M3 additions
//! (plan section 3.8: boot services, codes, device sessions, jobs, boot
//! stops).
//!
//! M4 rows (migration 0005) are in [`m4`] and re-exported here.
//!
//! Values use the `usgp-proto` types, so a row read back from the database
//! is re-validated: a value that no longer parses (a tampered or foreign
//! row) is [`crate::DbError::Corrupt`], never a panic.

use std::net::IpAddr;

use usgp_common::Sha256Digest;
use usgp_crypto::{HmacTag, KeyId};
use usgp_proto::device::{DeviceArch, FirmwareKind, SecureBootState, SessionState};
use usgp_proto::ops::{
    AuthCodeState, AuthCodeView, AuthMethod, BootServiceStatus, BootStopView, DeviceSessionView,
    JobStepView, JobView, SubnetList,
};
use usgp_proto::{
    AgentVersion, Architecture, AuthCodeId, BootServiceId, BootStopId, ContentId, ContentKind,
    ContentState, Description, DiskDescriptorV1, DisplayCode, DisplayName, EditionFacts,
    EditionIndex, ErrorCode, Fact, FailureV1, FileName, JobId, JobState, KitVersion,
    LayoutReportV1, MacAddress, MacList, Note, OperatorId, PackageId, PackageStatus, SessionId,
    Step, StepState, SupportState, UnixMicros, UploadId, UploadState, WimCompression, WimText,
};

mod m4;

pub use m4::{
    AGENT_PACKAGE_REFUSED, AdminPasswordMode, AgentPackage, AgentPackageStatus, AgentSigner,
    AgentSignerId, ArchiveContent, ArchiveFacts, DeviceValues, DriverArchive, DriverArchiveStatus,
    EscrowRecord, EscrowState, JobStepV2, JobTimeoutsV2, JobV2, MAX_CONFIG_VALUE_CHARS,
    MAX_DEVICE_VALUE_KEY_BYTES, MAX_DEVICE_VALUES, MAX_LIVE_RESUME_NONCES, NewAgentPackage,
    NewArchiveContent, NewDriverArchive, NewEscrow, NewJobV2, NewResumeNonce, NewResumeToken,
    NonceIssue, PackageConfig, PackageValues, ReadyArchiveContent, ResumeToken, SIGNER_REVOKED,
    SealedPassword, SignerRevocation, config_value_ok, device_value_key_ok,
};

/// Role of an operator (M2 has one built-in role, REQ-RBAC-004).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperatorRole {
    /// Holds every permission.
    Administrator,
}

impl OperatorRole {
    /// Every value (database check constraint).
    pub const ALL: &'static [Self] = &[Self::Administrator];

    /// Stored text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Administrator => "administrator",
        }
    }

    /// Parses the stored text.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "administrator" => Some(Self::Administrator),
            _ => None,
        }
    }
}

/// Whether an operator may authenticate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperatorStatus {
    /// May authenticate.
    Active,
    /// Refused with 401 (plan section 6).
    Disabled,
}

impl OperatorStatus {
    /// Every value (database check constraint).
    pub const ALL: &'static [Self] = &[Self::Active, Self::Disabled];

    /// Stored text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }

    /// Parses the stored text.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

/// An enrolled operator, bound to one certificate by its SHA-256
/// (decision 0007).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operator {
    /// Identifier.
    pub id: OperatorId,
    /// Display name.
    pub display_name: DisplayName,
    /// SHA-256 of the end-entity certificate DER.
    pub cert_sha256: Sha256Digest,
    /// Certificate subject (display only).
    pub cert_subject: String,
    /// Certificate issuer (display only).
    pub cert_issuer: String,
    /// Certificate serial, lower-case hex.
    pub cert_serial: String,
    /// Certificate notAfter.
    pub cert_not_after: UnixMicros,
    /// Role, or none (every route then answers 403, REQ-RBAC-003).
    pub role: Option<OperatorRole>,
    /// Status.
    pub status: OperatorStatus,
    /// Enrolment time.
    pub created_at: UnixMicros,
    /// Who enrolled it (the local user of the server command).
    pub created_by: String,
}

/// A failure reason: a code from the operator-facing set and its text
/// (REQ-IMG-022).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    /// Reason code (for example `digest_mismatch`).
    pub code: String,
    /// Operator text.
    pub text: String,
}

/// A PE's declared architecture and kit version (decision 0013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeDeclaration {
    /// Architecture with its source.
    pub architecture: Fact<Architecture>,
    /// Kit version with its source.
    pub kit_version: Fact<KitVersion>,
}

/// WIM-level facts recorded when the check passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WimFacts {
    /// Compression of the resources.
    pub compression: WimCompression,
    /// Number of images.
    pub image_count: u32,
    /// Boot index (0 = none).
    pub boot_index: u32,
}

/// A signed manifest as stored: the exact payload bytes, the signature
/// and the signing key id (plan sections 3.3 and 5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredManifest {
    /// The exact signed payload bytes.
    pub payload: Vec<u8>,
    /// DER ECDSA signature.
    pub signature: Vec<u8>,
    /// Signing key id.
    pub key_id: KeyId,
}

/// An image or PE in the content store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    /// Identifier.
    pub id: ContentId,
    /// Image or PE.
    pub kind: ContentKind,
    /// Operator-chosen name.
    pub display_name: DisplayName,
    /// Original file name.
    pub file_name: FileName,
    /// Size in bytes (declared at creation, verified at receipt).
    pub size: u64,
    /// SHA-256 (declared by the client; equal to the computed digest once
    /// Ready).
    pub sha256: Sha256Digest,
    /// State.
    pub state: ContentState,
    /// Reason for Failed (and for other states where given).
    pub reason: Option<Reason>,
    /// Creating operator.
    pub created_by: OperatorId,
    /// Audit record of the creating action (REQ-AUD-002).
    pub initiating_audit_seq: Option<u64>,
    /// Creation time.
    pub created_at: UnixMicros,
    /// Last change.
    pub updated_at: UnixMicros,
    /// When it became Ready.
    pub ready_at: Option<UnixMicros>,
    /// WIM facts (set at Ready).
    pub wim: Option<WimFacts>,
    /// The PE's usable image index (set at Ready for PEs, REQ-PE-004).
    pub usable_index: Option<u32>,
    /// The PE declaration (PEs only).
    pub pe: Option<PeDeclaration>,
    /// The signed content manifest (set at Ready).
    pub manifest: Option<StoredManifest>,
}

/// A new upload session's content row (state `receiving`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewContent {
    /// Identifier.
    pub id: ContentId,
    /// Image or PE.
    pub kind: ContentKind,
    /// Operator-chosen name.
    pub display_name: DisplayName,
    /// Original file name.
    pub file_name: FileName,
    /// Declared size.
    pub size: u64,
    /// Declared SHA-256.
    pub sha256: Sha256Digest,
    /// Creating operator.
    pub created_by: OperatorId,
    /// Audit record of the creating action.
    pub initiating_audit_seq: Option<u64>,
    /// Creation time.
    pub created_at: UnixMicros,
    /// PE declaration; required for PEs, forbidden for images.
    pub pe: Option<PeDeclaration>,
}

/// An upload session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upload {
    /// Identifier.
    pub id: UploadId,
    /// The content it fills.
    pub content_id: ContentId,
    /// The operator who may send the body.
    pub operator_id: OperatorId,
    /// Declared size.
    pub declared_size: u64,
    /// Declared SHA-256.
    pub declared_sha256: Sha256Digest,
    /// State.
    pub state: UploadState,
    /// Staging file name (under the content root's staging directory).
    pub staging_name: String,
    /// Creation time.
    pub created_at: UnixMicros,
    /// Session expiry.
    pub expires_at: UnixMicros,
}

/// One WIM image (edition) as listed by the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEdition {
    /// 1-based index.
    pub index: u32,
    /// `NAME` text.
    pub name: WimText,
    /// `DESCRIPTION` text.
    pub description: WimText,
    /// `TOTALBYTES`, when stated.
    pub total_bytes: Option<u64>,
}

/// An operator's declaration of an edition's facts (decision 0013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditionDeclaration {
    /// The facts, each with its source.
    pub facts: EditionFacts,
    /// Declaring operator.
    pub declared_by: OperatorId,
    /// When.
    pub declared_at: UnixMicros,
    /// The audit record of the declaration.
    pub declared_audit_seq: u64,
}

/// A stored edition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edition {
    /// The image it belongs to.
    pub content_id: ContentId,
    /// 1-based index.
    pub index: u32,
    /// `NAME` text.
    pub name: WimText,
    /// `DESCRIPTION` text.
    pub description: WimText,
    /// `TOTALBYTES`, when stated.
    pub total_bytes: Option<u64>,
    /// The declaration, if any.
    pub declaration: Option<EditionDeclaration>,
    /// Support status (`unknown` while undeclared, REQ-OS-009).
    pub support: SupportState,
    /// Reason for `not_supported` or `unknown`.
    pub support_reason: Option<String>,
}

/// Everything recorded when a check passes (state `checking` → `ready`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyContent {
    /// WIM facts.
    pub wim: WimFacts,
    /// Usable index (PEs only).
    pub usable_index: Option<u32>,
    /// The editions, indexes 1..=image_count.
    pub editions: Vec<NewEdition>,
    /// The signed content manifest.
    pub manifest: StoredManifest,
    /// The PE declaration after reconciliation with the file (PEs only;
    /// `None` keeps the stored one).
    pub pe: Option<PeDeclaration>,
    /// Time of the transition.
    pub at: UnixMicros,
}

/// A deployment package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// Identifier.
    pub id: PackageId,
    /// Name.
    pub name: DisplayName,
    /// Description.
    pub description: Option<Description>,
    /// The image.
    pub image_id: ContentId,
    /// The chosen edition index.
    pub edition_index: u32,
    /// The PE.
    pub pe_id: ContentId,
    /// Revision (ETag `"r<revision>"`); starts at 1.
    pub revision: u64,
    /// Status.
    pub status: PackageStatus,
    /// Reason when not usable.
    pub status_reason: Option<String>,
    /// The signed package manifest (Ready only).
    pub manifest: Option<StoredManifest>,
    /// Creating operator.
    pub created_by: OperatorId,
    /// Creation time.
    pub created_at: UnixMicros,
    /// Last change.
    pub updated_at: UnixMicros,
}

/// A package named as a dependant (409 `in_use`, decision 0015 item 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRef {
    /// Identifier.
    pub id: PackageId,
    /// Name.
    pub name: DisplayName,
}

// ---------------------------------------------------------------------------
// M3 (plan section 3.8): boot services, codes, device sessions, jobs, stops
// ---------------------------------------------------------------------------

/// An enrolled boot service (relay), bound to one client certificate
/// (decision 0021 item 1). Written only by the administrative role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootService {
    /// Identifier.
    pub id: BootServiceId,
    /// Unique name.
    pub name: DisplayName,
    /// SHA-256 of the relay's client certificate DER.
    pub cert_sha256: Sha256Digest,
    /// Certificate notAfter.
    pub cert_not_after: UnixMicros,
    /// The subnets it serves (REQ-TGT-001).
    pub served_subnets: SubnetList,
    /// Status.
    pub status: BootServiceStatus,
    /// Enrolment time.
    pub created_at: UnixMicros,
    /// Who enrolled it (the local user of the server command).
    pub created_by: String,
}

/// A package offered through a boot service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootServicePackage {
    /// The boot service.
    pub boot_service_id: BootServiceId,
    /// The package.
    pub package_id: PackageId,
    /// Who assigned it.
    pub added_by: OperatorId,
    /// When.
    pub added_at: UnixMicros,
}

/// A new operator code. Only the HMAC of the code is stored, never the
/// value (plan sections 3.8 and 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAuthCode {
    /// Identifier.
    pub id: AuthCodeId,
    /// HMAC-SHA-256 of the normalised code under the server's code key.
    pub code_hmac: HmacTag,
    /// Issuing operator.
    pub issued_by: OperatorId,
    /// Issue time.
    pub issued_at: UnixMicros,
    /// Expiry; after `issued_at`.
    pub expires_at: UnixMicros,
    /// Operator note.
    pub note: Option<Note>,
}

/// A stored operator code, without its HMAC (callers never need it back).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthCodeRecord {
    /// Identifier.
    pub id: AuthCodeId,
    /// Issuing operator.
    pub issued_by: OperatorId,
    /// Issue time.
    pub issued_at: UnixMicros,
    /// Expiry.
    pub expires_at: UnixMicros,
    /// When it was used.
    pub used_at: Option<UnixMicros>,
    /// The session that used it.
    pub used_by_session: Option<SessionId>,
    /// When it was revoked.
    pub revoked_at: Option<UnixMicros>,
    /// Who revoked it.
    pub revoked_by: Option<OperatorId>,
    /// Operator note.
    pub note: Option<Note>,
}

impl AuthCodeRecord {
    /// The state at time `now`: used and revoked are final; otherwise
    /// expired from `expires_at` on.
    #[must_use]
    pub fn state(&self, now: UnixMicros) -> AuthCodeState {
        if self.used_at.is_some() {
            AuthCodeState::Used
        } else if self.revoked_at.is_some() {
            AuthCodeState::Revoked
        } else if now >= self.expires_at {
            AuthCodeState::Expired
        } else {
            AuthCodeState::Active
        }
    }

    /// The operator view (no code value).
    #[must_use]
    pub fn view(&self, now: UnixMicros) -> AuthCodeView {
        AuthCodeView {
            id: self.id,
            state: self.state(now),
            issued_by: self.issued_by,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            used_at: self.used_at,
            used_by_session: self.used_by_session,
            revoked_at: self.revoked_at,
            revoked_by: self.revoked_by,
            note: self.note.clone(),
        }
    }
}

/// How a session was authorised, with who or what authorised it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAuth {
    /// By this operator-issued code (REQ-TGT-013).
    Code(AuthCodeId),
    /// By this operator's approval (REQ-TGT-014).
    Approval(OperatorId),
}

impl SessionAuth {
    /// The method.
    #[must_use]
    pub const fn method(self) -> AuthMethod {
        match self {
            Self::Code(_) => AuthMethod::Code,
            Self::Approval(_) => AuthMethod::Approval,
        }
    }
}

/// A package and the revision the device chose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChosenPackage {
    /// Package.
    pub id: PackageId,
    /// Revision offered.
    pub revision: u64,
}

/// The source network of an address: the IPv4 address itself, or the
/// IPv6 /64 that contains it (the per-source key of the device rate
/// limits and the token binding, decision 0023 item 1; an IPv4-mapped
/// IPv6 address counts as its IPv4 address). Returns the network address
/// and its prefix length.
#[must_use]
pub fn source_network(ip: IpAddr) -> (IpAddr, u8) {
    match ip {
        IpAddr::V4(_) => (ip, 32),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => (IpAddr::V4(v4), 32),
            None => {
                let bits = u128::from(v6) & !(u128::from(u64::MAX));
                (IpAddr::V6(std::net::Ipv6Addr::from(bits)), 64)
            }
        },
    }
}

/// Which sessions [`crate::RepoTx::count_device_sessions`] counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionScope {
    /// Every session.
    All,
    /// Sessions from the source network of this address
    /// ([`source_network`]).
    SourceNetwork(IpAddr),
    /// Sessions resolved to this boot service.
    BootService(BootServiceId),
}

impl SessionScope {
    /// True if `s` is in this scope.
    #[must_use]
    pub fn contains(&self, s: &DeviceSession) -> bool {
        match *self {
            Self::All => true,
            Self::SourceNetwork(ip) => source_network(s.source_ip) == source_network(ip),
            Self::BootService(b) => s.boot_service_id == Some(b),
        }
    }
}

/// A new device session (state `awaiting_authorisation`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDeviceSession {
    /// Identifier.
    pub id: SessionId,
    /// SHA-256 of the bearer token (the token is never stored).
    pub token_sha256: Sha256Digest,
    /// The boot service resolved from the source address, if any.
    pub boot_service_id: Option<BootServiceId>,
    /// Source address of the request.
    pub source_ip: IpAddr,
    /// Claimed MAC addresses.
    pub macs: MacList,
    /// Claimed firmware.
    pub firmware: FirmwareKind,
    /// Claimed architecture.
    pub arch: DeviceArch,
    /// Claimed Secure Boot state.
    pub secure_boot: SecureBootState,
    /// Claimed memory.
    pub memory_bytes: u64,
    /// Agent version.
    pub agent_version: AgentVersion,
    /// Code shown on the device's screen (unique among live sessions).
    pub display_code: DisplayCode,
    /// Creation time (also the first `last_seen_at`).
    pub created_at: UnixMicros,
    /// Expiry of the pending session.
    pub expires_at: UnixMicros,
}

/// A stored device session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceSession {
    /// Identifier.
    pub id: SessionId,
    /// SHA-256 of the bearer token.
    pub token_sha256: Sha256Digest,
    /// Boot service.
    pub boot_service_id: Option<BootServiceId>,
    /// Source address.
    pub source_ip: IpAddr,
    /// Claimed MAC addresses.
    pub macs: MacList,
    /// Claimed firmware.
    pub firmware: FirmwareKind,
    /// Claimed architecture.
    pub arch: DeviceArch,
    /// Claimed Secure Boot state.
    pub secure_boot: SecureBootState,
    /// Claimed memory.
    pub memory_bytes: u64,
    /// Agent version.
    pub agent_version: AgentVersion,
    /// Display code.
    pub display_code: DisplayCode,
    /// State.
    pub state: SessionState,
    /// How it was authorised.
    pub auth: Option<SessionAuth>,
    /// Failed code attempts.
    pub failed_code_attempts: u32,
    /// The chosen package.
    pub chosen_package: Option<ChosenPackage>,
    /// The chosen disk, as the device described it.
    pub chosen_disk: Option<DiskDescriptorV1>,
    /// Creation time.
    pub created_at: UnixMicros,
    /// Last request from the device.
    pub last_seen_at: UnixMicros,
    /// Expiry.
    pub expires_at: UnixMicros,
    /// When it reached `refused`, `cancelled`, `expired` or `ended`.
    pub ended_at: Option<UnixMicros>,
    /// Why it ended (a reason code).
    pub end_reason: Option<ErrorCode>,
}

impl DeviceSession {
    /// The operator view, with the boot service's name if known.
    #[must_use]
    pub fn view(&self, boot_service_name: Option<DisplayName>) -> DeviceSessionView {
        DeviceSessionView {
            id: self.id,
            state: self.state,
            macs: self.macs.clone(),
            source_ip: self.source_ip,
            firmware: self.firmware,
            arch: self.arch,
            secure_boot: self.secure_boot,
            memory_bytes: self.memory_bytes,
            agent_version: self.agent_version.clone(),
            boot_service_id: self.boot_service_id,
            boot_service_name,
            display_code: self.display_code,
            auth_method: self.auth.map(SessionAuth::method),
            failed_code_attempts: self.failed_code_attempts,
            created_at: self.created_at,
            last_seen_at: self.last_seen_at,
            expires_at: self.expires_at,
            chosen_package_id: self.chosen_package.map(|p| p.id),
            chosen_package_revision: self.chosen_package.map(|p| p.revision),
            chosen_disk: self.chosen_disk.clone(),
        }
    }
}

/// The timeouts a job's signed plan carries (finding SEC-012: the server
/// enforces them too).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobTimeouts {
    /// Per step, steps 1 to 5, seconds (each at least 1).
    pub steps_s: [u32; 5],
    /// Seconds without an accepted report before the job is stalled.
    pub stall_s: u32,
}

impl JobTimeouts {
    /// The timeout of `step`, seconds.
    #[must_use]
    pub fn step_s(&self, step: Step) -> u32 {
        let i = usize::from(step.get().saturating_sub(1));
        self.steps_s.get(i).copied().unwrap_or(1)
    }

    /// True if every value is at least 1 and fits an `i32`.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.steps_s
            .iter()
            .chain([&self.stall_s])
            .all(|v| *v >= 1 && i32::try_from(*v).is_ok())
    }
}

/// A new job (state `running`, step 1 running), written in the same
/// transaction as its `job.created` and `disk.wipe.authorised` records
/// (plan section 3.1, confirm).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewJob {
    /// Identifier.
    pub id: JobId,
    /// The confirmed session.
    pub session_id: SessionId,
    /// The boot service.
    pub boot_service_id: BootServiceId,
    /// The package and revision.
    pub package: ChosenPackage,
    /// The image content.
    pub image_content_id: ContentId,
    /// The edition.
    pub edition_index: EditionIndex,
    /// The disk.
    pub disk: DiskDescriptorV1,
    /// The device's MACs.
    pub macs: MacList,
    /// A failed or lost job of the same device (REQ-JOB-009).
    pub previous_job_id: Option<JobId>,
    /// Sequence number of the `disk.wipe.authorised` record. Its target
    /// must be this job (`job`, the job id).
    pub wipe_audit_seq: u64,
    /// Record hash of that record.
    pub wipe_record_hash: Sha256Digest,
    /// SHA-256 of the plan payload.
    pub plan_sha256: Sha256Digest,
    /// The plan signing key.
    pub plan_key_id: KeyId,
    /// The plan's timeouts.
    pub timeouts: JobTimeouts,
    /// Bytes the job will move, if known.
    pub bytes_total: Option<u64>,
    /// Start time.
    pub started_at: UnixMicros,
}

/// A stored job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// Identifier.
    pub id: JobId,
    /// The session.
    pub session_id: SessionId,
    /// The boot service.
    pub boot_service_id: BootServiceId,
    /// Package and revision.
    pub package: ChosenPackage,
    /// Image content.
    pub image_content_id: ContentId,
    /// Edition.
    pub edition_index: EditionIndex,
    /// Disk.
    pub disk: DiskDescriptorV1,
    /// Layout written (after step 2).
    pub layout: Option<LayoutReportV1>,
    /// MACs.
    pub macs: MacList,
    /// State.
    pub state: JobState,
    /// Current step.
    pub current_step: Step,
    /// Failure (state `failed` only).
    pub failure: Option<FailureV1>,
    /// Attempts made (from the failure; 0 otherwise).
    pub attempts: u32,
    /// Bytes done in the current step.
    pub bytes_done: Option<u64>,
    /// Bytes the current step will handle.
    pub bytes_total: Option<u64>,
    /// Highest accepted report sequence number.
    pub last_seq: u64,
    /// Start time.
    pub started_at: UnixMicros,
    /// Last accepted report.
    pub last_report_at: Option<UnixMicros>,
    /// When it succeeded or failed.
    pub finished_at: Option<UnixMicros>,
    /// Previous failed or lost job of the same device.
    pub previous_job_id: Option<JobId>,
    /// The `disk.wipe.authorised` record's sequence number.
    pub wipe_audit_seq: u64,
    /// Its record hash.
    pub wipe_record_hash: Sha256Digest,
    /// SHA-256 of the plan payload.
    pub plan_sha256: Sha256Digest,
    /// Plan signing key.
    pub plan_key_id: KeyId,
    /// The plan's timeouts.
    pub timeouts: JobTimeouts,
    /// Who acknowledged the failure, and when.
    pub acknowledged: Option<(OperatorId, UnixMicros)>,
}

/// One step of a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobStep {
    /// The job.
    pub job_id: JobId,
    /// Step number.
    pub step: Step,
    /// State.
    pub state: StepState,
    /// When it started.
    pub started_at: Option<UnixMicros>,
    /// When it finished.
    pub finished_at: Option<UnixMicros>,
}

impl JobStep {
    /// The view.
    #[must_use]
    pub const fn view(&self) -> JobStepView {
        JobStepView {
            step: self.step,
            kind: self.step.kind(),
            state: self.state,
            started_at: self.started_at,
            finished_at: self.finished_at,
        }
    }
}

impl Job {
    /// The operator view with its steps.
    #[must_use]
    pub fn view(&self, steps: &[JobStep]) -> JobView {
        let percent = match (self.bytes_done, self.bytes_total) {
            (Some(d), Some(t)) => usgp_proto::ops::percent(d, t),
            _ => None,
        };
        JobView {
            id: self.id,
            session_id: self.session_id,
            boot_service_id: self.boot_service_id,
            package_id: self.package.id,
            package_revision: self.package.revision,
            edition_index: self.edition_index,
            macs: self.macs.clone(),
            disk: self.disk.clone(),
            layout: self.layout.clone(),
            state: self.state,
            current_step: self.current_step,
            steps: steps.iter().map(JobStep::view).collect(),
            bytes_done: self.bytes_done,
            bytes_total: self.bytes_total,
            percent,
            failure: self.failure.clone(),
            failed_at: if self.state == JobState::Failed {
                self.finished_at
            } else {
                None
            },
            attempts: self.attempts,
            previous_job_id: self.previous_job_id,
            acknowledged: self.acknowledged.is_some(),
            started_at: self.started_at,
            last_report_at: self.last_report_at,
            finished_at: self.finished_at,
        }
    }
}

/// A new boot stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewBootStop {
    /// Identifier.
    pub id: BootStopId,
    /// The boot service.
    pub boot_service_id: BootServiceId,
    /// The device MAC.
    pub mac: MacAddress,
    /// The job that succeeded.
    pub job_id: JobId,
    /// Creation time.
    pub created_at: UnixMicros,
}

/// A stored boot stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootStop {
    /// Identifier.
    pub id: BootStopId,
    /// The boot service.
    pub boot_service_id: BootServiceId,
    /// The device MAC.
    pub mac: MacAddress,
    /// The job that succeeded.
    pub job_id: JobId,
    /// Creation time.
    pub created_at: UnixMicros,
    /// When an operator cleared it.
    pub cleared_at: Option<UnixMicros>,
    /// Who cleared it.
    pub cleared_by: Option<OperatorId>,
}

impl BootStop {
    /// The view.
    #[must_use]
    pub const fn view(&self) -> BootStopView {
        BootStopView {
            id: self.id,
            boot_service_id: self.boot_service_id,
            mac: self.mac,
            job_id: self.job_id,
            created_at: self.created_at,
            cleared_at: self.cleared_at,
            cleared_by: self.cleared_by,
        }
    }
}
