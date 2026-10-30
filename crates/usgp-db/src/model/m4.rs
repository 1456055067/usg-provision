//! Row types of the M4 additions (M4 plan section 3.5, migration 0005):
//! archive content, driver archives, agent signers and packages, package
//! configuration, device values, the nine-step job, resume nonces and
//! tokens, and the administrator-password escrow.
//!
//! As for the M2/M3 rows, values use the `usgp-proto` types where one
//! exists and are re-validated when read back.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-28, SC-28(1) - the escrow types carry only the sealed
//   password; their `Debug` shows lengths, never bytes.
// - NIST 800-53: IA-5 - resume nonces and tokens appear only as SHA-256.
// - NIST 800-53: SI-10 - bounds checked before a write and on read.
// - SPEC: specs/drivers.md#REQ-DRV-003, #REQ-DRV-006;
//   specs/configuration.md#REQ-CFG-004, #REQ-CFG-008, #REQ-CFG-009;
//   specs/workflow.md#REQ-SEQ-002; specs/agent-handoff.md#REQ-AGT-001
// - Decisions 0024, 0025

use std::collections::BTreeMap;
use std::fmt;

use usgp_common::Sha256Digest;
use usgp_crypto::KeyId;
use usgp_proto::escrow::{GCM_NONCE_LEN, MIN_ESCROW_CT_BYTES, P384_POINT_LEN};
use usgp_proto::limits::{MAX_ANSWER_FILE_BYTES, MAX_ESCROW_CT_BYTES, MAX_STEP_TIMEOUT_S};
use usgp_proto::{
    AgentPackageId, AgentPackageManifestV1, ArchiveFormat, BootServiceId, ContentId, ContentKindV2,
    ContentState, DiskDescriptorV1, DisplayName, DriverArchiveId, EditionIndex, ErrorCode,
    EscrowAccount, FailureV2, FileName, JobId, JobState, LayoutReportV1, MacAddress, MacList,
    OperatorId, P384Spki, PackageId, RelPath, SessionId, StepState, StepV2, Tag, UnixMicros,
};

use super::{ChosenPackage, Reason, StoredManifest};

macro_rules! db_enum {
    ($(#[$doc:meta])* $name:ident { $( $(#[$vdoc:meta])* $variant:ident => $text:literal, )+ }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $( $(#[$vdoc])* $variant, )+
        }

        impl $name {
            /// Every value (database check constraint).
            pub const ALL: &'static [Self] = &[ $( Self::$variant ),+ ];

            /// Stored text.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $text, )+
                }
            }

            /// Parses the stored text.
            #[must_use]
            pub fn parse(s: &str) -> Option<Self> {
                match s {
                    $( $text => Some(Self::$variant), )+
                    _ => None,
                }
            }
        }
    };
}

db_enum!(
    /// Status of a driver archive record.
    DriverArchiveStatus {
        /// Uploaded (or replaced); the archive check has not passed yet.
        Checking => "checking",
        /// Checked; its INF list is known.
        Ready => "ready",
        /// The check refused it (reason in `refusal`).
        Refused => "refused",
        /// Deleted by an operator (final; kept as history).
        Deleted => "deleted",
    }
);

db_enum!(
    /// Status of an agent package.
    AgentPackageStatus {
        /// Uploaded; signature and content checks have not passed yet.
        Checking => "checking",
        /// Signed by a registered signer and checked (final).
        Ready => "ready",
        /// Refused (final; reason in `refusal`).
        Refused => "refused",
    }
);

db_enum!(
    /// What a package does with the local administrator password
    /// (REQ-CFG-008, decision 0024).
    AdminPasswordMode {
        /// The device generates a password and escrows it before setting
        /// it.
        GenerateAndEscrow => "generate_and_escrow",
        /// No password is set (the account stays disabled).
        None => "none",
    }
);

db_enum!(
    /// State of an escrowed administrator password.
    EscrowState {
        /// Stored; the device has not confirmed yet.
        Received => "received",
        /// The device set the password on the account.
        Applied => "applied",
        /// The device could not set it.
        NotApplied => "not_applied",
    }
);

/// An agent-package signer key record (decision 0025 item 5).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentSignerId(uuid::Uuid);

impl AgentSignerId {
    /// A version-4 layout identifier from 16 bytes drawn from the
    /// `usgp-crypto` DRBG.
    #[must_use]
    pub const fn from_random_bytes(bytes: [u8; 16]) -> Self {
        Self(uuid::Builder::from_random_bytes(bytes).into_uuid())
    }

    /// Rebuilds an identifier from stored bytes; `None` for the nil UUID.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Option<Self> {
        let u = uuid::Uuid::from_bytes(bytes);
        (!u.is_nil()).then_some(Self(u))
    }

    /// Parses the hyphenated form; `None` if malformed or nil.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() != 36 {
            return None;
        }
        uuid::Uuid::try_parse(text)
            .ok()
            .filter(|u| !u.is_nil())
            .map(Self)
    }

    /// The 16 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl fmt::Display for AgentSignerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0.hyphenated(), f)
    }
}

impl fmt::Debug for AgentSignerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AgentSignerId({})", self.0.hyphenated())
    }
}

// ------------------------------------------------------- archive content --

/// A new driver-archive or agent-package upload (content state
/// `receiving`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewArchiveContent {
    /// Identifier.
    pub id: ContentId,
    /// Driver archive or agent package.
    pub kind: ContentKindV2,
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
}

/// Archive facts recorded at Ready, copied from the signed v2 manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveFacts {
    /// ZIP or CAB.
    pub format: ArchiveFormat,
    /// Number of entries.
    pub entries: u32,
    /// Total expanded bytes.
    pub expanded_bytes: u64,
}

/// A driver archive or agent package in the content store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveContent {
    /// Identifier.
    pub id: ContentId,
    /// Driver archive or agent package.
    pub kind: ContentKindV2,
    /// Operator-chosen name.
    pub display_name: DisplayName,
    /// Original file name.
    pub file_name: FileName,
    /// Size in bytes.
    pub size: u64,
    /// SHA-256.
    pub sha256: Sha256Digest,
    /// State.
    pub state: ContentState,
    /// Reason for Failed.
    pub reason: Option<Reason>,
    /// Creating operator.
    pub created_by: OperatorId,
    /// Audit record of the creating action.
    pub initiating_audit_seq: Option<u64>,
    /// Creation time.
    pub created_at: UnixMicros,
    /// Last change.
    pub updated_at: UnixMicros,
    /// When it became Ready.
    pub ready_at: Option<UnixMicros>,
    /// Archive facts (set at Ready).
    pub archive: Option<ArchiveFacts>,
    /// The signed v2 content manifest (set at Ready).
    pub manifest: Option<StoredManifest>,
    /// When a driver-archive replacement superseded this file (it is still
    /// served to packages that pin it, never attached again; U-4).
    pub superseded_at: Option<UnixMicros>,
}

/// What `checking` → `ready` records for archive content: the signed
/// `ContentManifestV2`. Its id, kind, size, digest and ready time must
/// match the row; the archive facts are taken from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyArchiveContent {
    /// The signed manifest (payload is a `ContentManifestV2`).
    pub manifest: StoredManifest,
    /// Time of the transition (the manifest's `ready_at`).
    pub at: UnixMicros,
}

// ------------------------------------------------------- driver archives --

/// A new driver archive record (status `checking`) for uploaded content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDriverArchive {
    /// Identifier (kept across replacements, REQ-DRV-003).
    pub id: DriverArchiveId,
    /// The archive content (kind `driver_archive`).
    pub content_id: ContentId,
    /// Operator-chosen name.
    pub name: DisplayName,
    /// Creating operator.
    pub created_by: OperatorId,
    /// Creation time.
    pub created_at: UnixMicros,
}

/// A stored driver archive record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverArchive {
    /// Identifier.
    pub id: DriverArchiveId,
    /// The current archive content.
    pub content_id: ContentId,
    /// Name.
    pub name: DisplayName,
    /// ZIP or CAB (set at ready).
    pub format: Option<ArchiveFormat>,
    /// Status.
    pub status: DriverArchiveStatus,
    /// Why it was refused.
    pub refusal: Option<ErrorCode>,
    /// The INF packages (set at ready; empty before).
    pub infs: Vec<RelPath>,
    /// Total expanded bytes (set at ready).
    pub expanded_bytes: Option<u64>,
    /// Creating operator.
    pub created_by: OperatorId,
    /// Creation time.
    pub created_at: UnixMicros,
    /// Last change.
    pub updated_at: UnixMicros,
    /// When the file was last replaced.
    pub replaced_at: Option<UnixMicros>,
}

// -------------------------------------------------------- agent packages --

/// A registered agent-package signer key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSigner {
    /// Identifier.
    pub id: AgentSignerId,
    /// The public key (P-384 SPKI DER).
    pub spki: P384Spki,
    /// SHA-256 of the SPKI DER.
    pub key_id: Sha256Digest,
    /// Name.
    pub name: DisplayName,
    /// Registering operator.
    pub added_by: OperatorId,
    /// Registration time.
    pub added_at: UnixMicros,
    /// Who revoked it, and when.
    pub revoked: Option<(OperatorId, UnixMicros)>,
}

/// A new agent package record (status `checking`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAgentPackage {
    /// Identifier.
    pub id: AgentPackageId,
    /// The package content (kind `agent_package`).
    pub content_id: ContentId,
    /// Creating operator.
    pub created_by: OperatorId,
    /// Creation time.
    pub created_at: UnixMicros,
}

/// A stored agent package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentPackage {
    /// Identifier.
    pub id: AgentPackageId,
    /// The package content.
    pub content_id: ContentId,
    /// The signer whose signature verified (set at ready).
    pub signer_id: Option<AgentSignerId>,
    /// `agent.json` (set at ready).
    pub manifest: Option<AgentPackageManifestV1>,
    /// Status.
    pub status: AgentPackageStatus,
    /// Why it was refused.
    pub refusal: Option<ErrorCode>,
    /// Creating operator.
    pub created_by: OperatorId,
    /// Creation time.
    pub created_at: UnixMicros,
    /// Last change.
    pub updated_at: UnixMicros,
}

// ------------------------------------------------- package configuration --

/// Longest stored configuration or device value, in characters.
pub const MAX_CONFIG_VALUE_CHARS: usize = 2048;

/// Most per-device values for one MAC (M4 plan section 3.2).
pub const MAX_DEVICE_VALUES: usize = 32;

/// Longest per-device value key, in bytes (`device.<key>` stays within
/// the 64-byte reference name of M4 plan section 1.6).
pub const MAX_DEVICE_VALUE_KEY_BYTES: usize = 57;

/// A stored value: 1 to [`MAX_CONFIG_VALUE_CHARS`] characters, no control
/// characters. The value rules of `usgp-wincfg` (computer name, time zone)
/// are the caller's; these are the storage bounds only.
#[must_use]
pub fn config_value_ok(v: &str) -> bool {
    let n = v.chars().count();
    (1..=MAX_CONFIG_VALUE_CHARS).contains(&n) && !v.chars().any(char::is_control)
}

/// A per-device value key: `[a-z][a-z0-9_]*`, at most
/// [`MAX_DEVICE_VALUE_KEY_BYTES`] bytes.
#[must_use]
pub fn device_value_key_ok(k: &str) -> bool {
    let mut bytes = k.bytes();
    k.len() <= MAX_DEVICE_VALUE_KEY_BYTES
        && bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// A package's literal values (M4 plan section 3.2). Stored as a JSON
/// object holding only the set fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageValues {
    /// Computer name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computer_name: Option<String>,
    /// Time zone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_zone: Option<String>,
    /// Domain to join.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Machine OU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_ou: Option<String>,
}

impl PackageValues {
    /// True if every set value meets [`config_value_ok`].
    #[must_use]
    pub fn valid(&self) -> bool {
        [
            &self.computer_name,
            &self.time_zone,
            &self.domain,
            &self.machine_ou,
        ]
        .into_iter()
        .flatten()
        .all(|v| config_value_ok(v))
    }
}

/// A package's configuration (one per package).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageConfig {
    /// The package.
    pub package_id: PackageId,
    /// The answer-file template (1 byte to 1 MiB, stored inline; U-1).
    pub answer_template: Vec<u8>,
    /// SHA-256 of `answer_template`.
    pub answer_sha256: Sha256Digest,
    /// Literal values.
    pub values: PackageValues,
    /// Tags (at most 64, REQ-CFG-009).
    pub tags: Vec<Tag>,
    /// The agent package installed at step 8.
    pub agent_package_id: AgentPackageId,
    /// Administrator password handling.
    pub admin_password: AdminPasswordMode,
    /// Last editor.
    pub updated_by: OperatorId,
    /// Last change.
    pub updated_at: UnixMicros,
}

impl PackageConfig {
    /// True if the template is 1 byte to 1 MiB and `answer_sha256` is its
    /// SHA-256 (through `usgp-crypto`).
    #[must_use]
    pub fn answer_ok(&self) -> bool {
        (1..=MAX_ANSWER_FILE_BYTES).contains(&self.answer_template.len())
            && usgp_crypto::sha256(&self.answer_template) == self.answer_sha256
    }
}

/// Per-device values, keyed by MAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceValues {
    /// The device MAC.
    pub mac: MacAddress,
    /// Values by key (1 to [`MAX_DEVICE_VALUES`]).
    pub values: BTreeMap<String, String>,
    /// Last editor.
    pub updated_by: OperatorId,
    /// Last change.
    pub updated_at: UnixMicros,
}

impl DeviceValues {
    /// True if the keys and values meet the storage bounds.
    #[must_use]
    pub fn valid(&self) -> bool {
        (1..=MAX_DEVICE_VALUES).contains(&self.values.len())
            && self
                .values
                .iter()
                .all(|(k, v)| device_value_key_ok(k) && config_value_ok(v))
    }
}

// ---------------------------------------------------------------- jobs v2 --

/// The timeouts of a v2 job's signed plan (steps 1 to 9 and the stall
/// timeout), enforced by the server too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobTimeoutsV2 {
    /// Per step, steps 1 to 9, seconds (each 1 to `MAX_STEP_TIMEOUT_S`).
    pub steps_s: [u32; 9],
    /// Seconds without an accepted report before the job is stalled.
    pub stall_s: u32,
}

impl JobTimeoutsV2 {
    /// The timeout of `step`, seconds.
    #[must_use]
    pub fn step_s(&self, step: StepV2) -> u32 {
        let i = usize::from(step.get().saturating_sub(1));
        self.steps_s.get(i).copied().unwrap_or(1)
    }

    /// True if every step value is 1 to `MAX_STEP_TIMEOUT_S` and the
    /// stall value is at least 1 and fits an `i32`.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.steps_s
            .iter()
            .all(|v| (1..=MAX_STEP_TIMEOUT_S).contains(v))
            && self.stall_s >= 1
            && i32::try_from(self.stall_s).is_ok()
    }
}

/// A new v2 (nine-step) job, written with its `job.created` and
/// `disk.wipe.authorised` records, as [`super::NewJob`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewJobV2 {
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
    /// A failed or lost job of the same device.
    pub previous_job_id: Option<JobId>,
    /// Sequence number of the `disk.wipe.authorised` record.
    pub wipe_audit_seq: u64,
    /// Its record hash.
    pub wipe_record_hash: Sha256Digest,
    /// SHA-256 of the plan payload.
    pub plan_sha256: Sha256Digest,
    /// The plan signing key.
    pub plan_key_id: KeyId,
    /// The plan's timeouts.
    pub timeouts: JobTimeoutsV2,
    /// Bytes the job will move, if known.
    pub bytes_total: Option<u64>,
    /// Start time.
    pub started_at: UnixMicros,
    /// The device's job key (P-384 SPKI DER).
    pub job_key_spki: P384Spki,
    /// SHA-256 of `job_key_spki` (the plan's `job_key_id`).
    pub job_key_id: Sha256Digest,
    /// SHA-256 of the rendered answer file.
    pub rendered_answer_sha256: Sha256Digest,
    /// Tags carried in the plan.
    pub tags: Vec<Tag>,
}

/// A stored v2 job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobV2 {
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
    pub current_step: StepV2,
    /// Failure (state `failed` only).
    pub failure: Option<FailureV2>,
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
    pub timeouts: JobTimeoutsV2,
    /// Who acknowledged the failure, and when.
    pub acknowledged: Option<(OperatorId, UnixMicros)>,
    /// The device's job key.
    pub job_key_spki: P384Spki,
    /// SHA-256 of the job key.
    pub job_key_id: Sha256Digest,
    /// SHA-256 of the rendered answer file.
    pub rendered_answer_sha256: Sha256Digest,
    /// Tags.
    pub tags: Vec<Tag>,
    /// The agent installer asked for a restart (never performed).
    pub restart_pending: bool,
}

/// One step of a v2 job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobStepV2 {
    /// The job.
    pub job_id: JobId,
    /// Step number.
    pub step: StepV2,
    /// State.
    pub state: StepState,
    /// When it started.
    pub started_at: Option<UnixMicros>,
    /// When it finished.
    pub finished_at: Option<UnixMicros>,
}

// ---------------------------------------------------------------- resume --

/// A challenge nonce, by SHA-256 only (60 s, single use).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewResumeNonce {
    /// SHA-256 of the nonce.
    pub nonce_hash: Sha256Digest,
    /// The job.
    pub job_id: JobId,
    /// Issue time.
    pub issued_at: UnixMicros,
    /// Expiry (after `issued_at`).
    pub expires_at: UnixMicros,
}

/// A new resume token, by SHA-256 only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewResumeToken {
    /// SHA-256 of the token.
    pub token_hash: Sha256Digest,
    /// The job it is scoped to.
    pub job_id: JobId,
    /// Issue time.
    pub issued_at: UnixMicros,
    /// Expiry (after `issued_at`).
    pub expires_at: UnixMicros,
}

/// A stored resume token (without its hash).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumeToken {
    /// The job it is scoped to.
    pub job_id: JobId,
    /// Issue time.
    pub issued_at: UnixMicros,
    /// Expiry.
    pub expires_at: UnixMicros,
    /// When it was revoked.
    pub revoked_at: Option<UnixMicros>,
}

impl ResumeToken {
    /// True if usable at `now`: not revoked and not expired.
    #[must_use]
    pub fn live(&self, now: UnixMicros) -> bool {
        self.revoked_at.is_none() && now < self.expires_at
    }
}

// ---------------------------------------------------------------- escrow --

/// The sealed administrator password as the device sent it (M4 plan
/// section 1.3). Only this form is ever stored (SC-28). `Debug` shows
/// lengths only.
#[derive(Clone, PartialEq, Eq)]
pub struct SealedPassword {
    /// Ephemeral ECDH public key, uncompressed point.
    pub eph_pub: [u8; P384_POINT_LEN],
    /// AES-GCM nonce.
    pub nonce: [u8; GCM_NONCE_LEN],
    /// Ciphertext with tag (17 to 512 bytes).
    pub ciphertext: Vec<u8>,
}

impl SealedPassword {
    /// True if the point form and the lengths are as the wire allows.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.eph_pub.first() == Some(&0x04)
            && (MIN_ESCROW_CT_BYTES..=MAX_ESCROW_CT_BYTES).contains(&self.ciphertext.len())
    }
}

impl fmt::Debug for SealedPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedPassword")
            .field("eph_pub", &format_args!("<{} bytes>", self.eph_pub.len()))
            .field("nonce", &format_args!("<{} bytes>", self.nonce.len()))
            .field(
                "ciphertext",
                &format_args!("<{} bytes>", self.ciphertext.len()),
            )
            .finish()
    }
}

/// A new escrow (state `received`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEscrow {
    /// The job (a v2 job).
    pub job_id: JobId,
    /// The account.
    pub account: EscrowAccount,
    /// The escrow key id it was sealed to.
    pub key_id: Sha256Digest,
    /// The sealed password.
    pub sealed: SealedPassword,
    /// Receipt time.
    pub received_at: UnixMicros,
}

/// Escrow metadata (no sealed bytes): what `GET …/admin-password`
/// shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowRecord {
    /// The job.
    pub job_id: JobId,
    /// The account.
    pub account: EscrowAccount,
    /// The escrow key id.
    pub key_id: Sha256Digest,
    /// State.
    pub state: EscrowState,
    /// Receipt time.
    pub received_at: UnixMicros,
    /// When the device confirmed (applied or not).
    pub applied_at: Option<UnixMicros>,
    /// How many times it was revealed.
    pub reveal_count: u32,
}

/// What revoking a signer changed in the same transaction (U-3). The
/// caller appends one `agent_package.refused` record (reason
/// `signer_revoked`) per agent package, and a status record per package.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignerRevocation {
    /// Ready agent packages of the signer, now `refused`.
    pub refused_agent_packages: Vec<AgentPackageId>,
    /// Ready packages whose configuration named one of them, now
    /// `not_usable` (reason [`AGENT_PACKAGE_REFUSED`]).
    pub packages_not_ready: Vec<PackageId>,
}

/// The refusal reason of an agent package whose signer was revoked.
pub const SIGNER_REVOKED: &str = "signer_revoked";

/// The status reason of a package taken out of ready by U-3.
pub const AGENT_PACKAGE_REFUSED: &str = "agent_package_refused";

/// Most live (unused, unexpired) challenge nonces per job.
pub const MAX_LIVE_RESUME_NONCES: u32 = 16;

/// The result of a resume challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceIssue {
    /// Stored.
    Issued,
    /// No such v2 job, or it is finished, or step 6 is not done (404).
    NotEligible,
    /// The job already holds [`MAX_LIVE_RESUME_NONCES`] live nonces (429).
    OverCap,
}
