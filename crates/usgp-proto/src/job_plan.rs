//! Signed job plan, version 1 (M3 plan section 3.2): what the agent must
//! do for one job, bound to the session, the job, the agent's nonce, the
//! device's MACs, the package, the image edition and the chosen disk, and
//! to the audit record of the wipe authorisation. Signed with the server's
//! **plan key** (ECDSA P-384, payload type
//! `application/vnd.usgp.job-plan.v1+json`).
//!
//! The signed bytes are exactly [`JobPlanV1::to_payload`]'s output (compact
//! JSON in struct field order, no maps), as for the M2 manifests.
//!
//! [`VerifiedJobPlan::verify`] runs the agent's checks in the plan's order:
//!
//! 1. the plan envelope's signature with the pinned plan key (nothing is
//!    parsed before this succeeds);
//! 2. payload type (bound in the signing input) and schema, and the plan's
//!    `key_id` is the key that verified it;
//! 3. the nonce the agent sent;
//! 4. `session_id` and `job_id` (and the chosen package);
//! 5. the disk equals the chosen descriptor;
//! 6. the content manifest: its signature with the pinned content key, the
//!    SHA-256 of its payload against `content_manifest_sha256`, and its
//!    image facts against the plan.
//!
//! There is no expiry check against the device clock (the RTC is not
//! trusted; freshness comes from the nonce). The plan carries **no
//! secrets** in M3 (REQ-TGT-015): no field can hold one.
//!
//! This crate does no cryptography: the caller passes the SHA-256 function
//! from `usgp-crypto` and [`SignatureVerifier`]s built from pinned keys.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7, SI-7(6) (Software, Firmware, and Information
//   Integrity; Cryptographic Protection) - signed plan, verify before
//   parse; content manifest bound by digest and signature.
// - NIST 800-53: SC-23 (Session Authenticity) - plan bound to the session,
//   job and a fresh agent nonce (replay and transplant refused).
// - NIST 800-53: SI-10 (Information Input Validation) - strict parse,
//   every field bounded; layout policy must be the fixed one.
// - NIST 800-53: AU-10 (Non-repudiation, basis) - the wipe authorisation's
//   audit sequence and record hash are in the signed plan.
// - SPEC: specs/preinstall-env.md#REQ-PE-016 (verify before use),
//   specs/progress.md#REQ-JOB-007, #REQ-JOB-008, #REQ-JOB-011 (retry,
//   nothing applied after a failed check, timeouts)
// - SPEC: specs/disk.md#REQ-DISK-004 (minimum size), #REQ-DISK-006 (wipe
//   recorded before any write), #REQ-DISK-008, #REQ-DISK-010 (layout
//   sizes, alignment), #REQ-DISK-015 (only the chosen disk)
// - SPEC: specs/targeting.md#REQ-TGT-015 (no secrets in the plan)
// - FIPS 186-5 (ECDSA), FIPS 180-4 (SHA-256)

use usgp_common::Sha256Digest;

use crate::SignedManifestError;
use crate::b64::{B64Bytes, P384Spki};
use crate::content_manifest::ContentManifestV1;
use crate::device::{AgentNonce, MacList};
use crate::disk::{DiskDescriptorV1, PlanDiskV1};
use crate::envelope::{PayloadType, SignatureVerifier, SignedEnvelopeV1};
use crate::error_code::{ErrorCode, codes};
use crate::ids::{AgentPackageId, DriverArchiveId};
use crate::ids::{BootServiceId, JobId, PackageId, SessionId, UnixMicros};
use crate::limits::{MAX_ANSWER_FILE_BYTES, MAX_ARCHIVE_INFS, MAX_PLAN_DRIVERS, MAX_TAGS};
use crate::limits::{
    MAX_CONTENT_BYTES, MAX_MANIFEST_PAYLOAD_BYTES, MAX_REPORT_INTERVAL_S, MAX_RETRY_ATTEMPTS,
    MAX_RETRY_DELAY_MS, MAX_STEP_TIMEOUT_S,
};
use crate::names::{EditionIndex, RelPath, Tag, UrlPath, WimText};
use crate::progress::{FailureCategory, Step, StepKind, StepKindV2, StepV2};
use crate::status::ContentKind;

/// The v1 plan schema version.
pub const SCHEMA_V1: u32 = 1;

/// The v2 plan schema version (M4).
pub const SCHEMA_V2: u32 = 2;

/// The device the plan is for.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanDeviceV1 {
    /// MAC addresses from the session.
    pub macs: MacList,
}

/// The package the plan installs.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanPackageV1 {
    /// Package id.
    pub id: PackageId,
    /// Revision (at least 1).
    pub revision: u64,
    /// SHA-256 of the M2 signed package manifest payload.
    pub manifest_sha256: Sha256Digest,
}

/// The image edition the plan applies.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanImageV1 {
    /// SHA-256 of the image file.
    pub content_sha256: Sha256Digest,
    /// Size of the image file (1 byte to 1 TiB).
    pub size: u64,
    /// SHA-256 of the signed content manifest's payload.
    pub content_manifest_sha256: Sha256Digest,
    /// Edition to apply.
    pub edition_index: EditionIndex,
    /// Its name.
    pub edition_name: WimText,
    /// Its expanded size as the file states it.
    pub total_bytes: u64,
}

/// Partition sizes and limits (REQ-DISK-004, REQ-DISK-008, REQ-DISK-010).
/// These are fixed (plan section 3.9); a plan with other values is
/// refused, except that `min_disk_bytes` may be larger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LayoutPolicyV1 {
    /// ESP size on 512-byte logical sector disks, MiB.
    pub esp_mib_512: u32,
    /// ESP size on 4K-native disks, MiB.
    pub esp_mib_4k: u32,
    /// MSR size, MiB.
    pub msr_mib: u32,
    /// Smallest recovery partition, MiB.
    pub recovery_min_mib: u32,
    /// Free space kept in the recovery partition, MiB.
    pub recovery_free_mib: u32,
    /// Partition alignment, MiB.
    pub align_mib: u32,
    /// Smallest eligible disk, bytes.
    pub min_disk_bytes: u64,
}

impl LayoutPolicyV1 {
    /// The fixed M3 values (plan sections 3.2 and 3.9).
    pub const STANDARD: Self = Self {
        esp_mib_512: 200,
        esp_mib_4k: 300,
        msr_mib: 16,
        recovery_min_mib: 990,
        recovery_free_mib: 250,
        align_mib: 1,
        min_disk_bytes: 64_000_000_000,
    };

    /// `true` if every value is the fixed one and `min_disk_bytes` is at
    /// least the fixed minimum.
    #[must_use]
    pub const fn is_standard(&self) -> bool {
        let s = Self::STANDARD;
        self.esp_mib_512 == s.esp_mib_512
            && self.esp_mib_4k == s.esp_mib_4k
            && self.msr_mib == s.msr_mib
            && self.recovery_min_mib == s.recovery_min_mib
            && self.recovery_free_mib == s.recovery_free_mib
            && self.align_mib == s.align_mib
            && self.min_disk_bytes >= s.min_disk_bytes
    }
}

closed_enum!(
    /// What the wipe covers (plan section 3.2): the partition tables and
    /// the first MiB of each existing volume (REQ-DISK-007).
    WipeScope, "wipe scope" {
        /// Primary and backup GPT, MBR, and volume heads (1 MiB each).
        TablesAndVolumeHeads1Mib => "tables+volume-heads-1mib",
    }
);

/// The durable record of the wipe authorisation (REQ-DISK-006, decision
/// 0018 item 7), committed before the plan was signed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanWipeV1 {
    /// Audit sequence number of `disk.wipe.authorised` (at least 1).
    pub audit_seq: u64,
    /// That record's hash.
    pub record_hash: Sha256Digest,
    /// What is wiped.
    pub scope: WipeScope,
}

/// One step and its timeout (REQ-JOB-011).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanStepV1 {
    /// Step number.
    pub step: Step,
    /// What it does; must match the number.
    pub kind: StepKind,
    /// Timeout in seconds (1 to [`MAX_STEP_TIMEOUT_S`]).
    pub timeout_s: u32,
}

/// Retry policy for transient failures (REQ-JOB-007; values OPEN-JOB-4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryPolicyV1 {
    /// Attempts (1 to [`MAX_RETRY_ATTEMPTS`]).
    pub attempts: u32,
    /// First delay, ms (at least 1, at most `max_ms`).
    pub base_ms: u32,
    /// Largest delay, ms (at most [`MAX_RETRY_DELAY_MS`]).
    pub max_ms: u32,
}

/// Job plan, version 1 (plan section 3.2).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobPlanV1 {
    /// Always [`SCHEMA_V1`].
    pub schema: u32,
    /// Job.
    pub job_id: JobId,
    /// Session that confirmed it.
    pub session_id: SessionId,
    /// Boot service the session came through.
    pub boot_service_id: BootServiceId,
    /// When the plan was signed (not checked on the device).
    pub issued_at_us: UnixMicros,
    /// Key id (SHA-256 of the SPKI DER) of the plan key.
    pub key_id: Sha256Digest,
    /// The nonce from the agent's confirm request.
    pub agent_nonce: AgentNonce,
    /// Device.
    pub device: PlanDeviceV1,
    /// Package.
    pub package: PlanPackageV1,
    /// Image edition.
    pub image: PlanImageV1,
    /// Disk.
    pub disk: PlanDiskV1,
    /// Layout sizes.
    pub layout_policy: LayoutPolicyV1,
    /// Wipe authorisation record.
    pub wipe: PlanWipeV1,
    /// The five steps in order.
    pub steps: Vec<PlanStepV1>,
    /// Retry policy.
    pub retry: RetryPolicyV1,
    /// Seconds without progress before the job is stalled (REQ-JOB-011).
    pub stall_timeout_s: u32,
    /// Seconds between progress reports.
    pub report_interval_s: u32,
}

impl JobPlanV1 {
    /// Checks every rule a v1 plan must meet beyond its types.
    ///
    /// # Errors
    ///
    /// [`SignedManifestError::UnsupportedSchema`] or
    /// [`SignedManifestError::Invalid`] naming the first rule broken.
    pub fn validate(&self) -> Result<(), SignedManifestError> {
        use SignedManifestError::Invalid;
        if self.schema != SCHEMA_V1 {
            return Err(SignedManifestError::UnsupportedSchema(self.schema));
        }
        if self.package.revision == 0 {
            return Err(Invalid("package.revision must be at least 1"));
        }
        if self.image.size == 0 || self.image.size > MAX_CONTENT_BYTES {
            return Err(Invalid("image.size must be 1 byte to 1 TiB"));
        }
        if self.disk.validate().is_err() {
            return Err(Invalid("disk geometry is invalid"));
        }
        if !self.layout_policy.is_standard() {
            return Err(Invalid("layout_policy is not the fixed layout"));
        }
        if self.disk.size_bytes < self.layout_policy.min_disk_bytes {
            return Err(Invalid("disk is below layout_policy.min_disk_bytes"));
        }
        if self.wipe.audit_seq == 0 {
            return Err(Invalid("wipe.audit_seq must be at least 1"));
        }
        let steps_ok = self.steps.len() == Step::ALL.len()
            && self.steps.iter().zip(Step::ALL).all(|(s, want)| {
                s.step == want
                    && s.kind == want.kind()
                    && s.timeout_s >= 1
                    && s.timeout_s <= MAX_STEP_TIMEOUT_S
            });
        if !steps_ok {
            return Err(Invalid(
                "steps must be steps 1 to 5 in order with matching kinds and timeouts of 1 s to 7 days",
            ));
        }
        let r = self.retry;
        if r.attempts == 0
            || r.attempts > MAX_RETRY_ATTEMPTS
            || r.base_ms == 0
            || r.base_ms > r.max_ms
            || r.max_ms > MAX_RETRY_DELAY_MS
        {
            return Err(Invalid(
                "retry must have 1 to 100 attempts and 1 ms <= base_ms <= max_ms <= 1 hour",
            ));
        }
        if self.stall_timeout_s == 0 || self.stall_timeout_s > MAX_STEP_TIMEOUT_S {
            return Err(Invalid("stall_timeout_s must be 1 s to 7 days"));
        }
        if self.report_interval_s == 0 || self.report_interval_s > MAX_REPORT_INTERVAL_S {
            return Err(Invalid("report_interval_s must be 1 s to 1 hour"));
        }
        Ok(())
    }

    /// The timeout of `step`, in seconds.
    #[must_use]
    pub fn timeout_s(&self, step: Step) -> Option<u32> {
        self.steps
            .iter()
            .find(|s| s.step == step)
            .map(|s| s.timeout_s)
    }

    /// The exact bytes to sign: compact JSON in field order.
    ///
    /// # Errors
    ///
    /// As [`JobPlanV1::validate`]; [`SignedManifestError::TooLarge`].
    pub fn to_payload(&self) -> Result<Vec<u8>, SignedManifestError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(SignedManifestError::Json)?;
        if bytes.len() > MAX_MANIFEST_PAYLOAD_BYTES {
            return Err(SignedManifestError::TooLarge { len: bytes.len() });
        }
        Ok(bytes)
    }

    /// Parses and validates payload bytes. Use only on bytes whose
    /// signature has been verified, or on the server's own stored copy;
    /// [`JobPlanV1::open`] does both steps.
    ///
    /// # Errors
    ///
    /// [`SignedManifestError::TooLarge`] before parsing;
    /// [`SignedManifestError::Json`]; or as [`JobPlanV1::validate`].
    pub fn from_payload(bytes: &[u8]) -> Result<Self, SignedManifestError> {
        if bytes.len() > MAX_MANIFEST_PAYLOAD_BYTES {
            return Err(SignedManifestError::TooLarge { len: bytes.len() });
        }
        let p: Self = serde_json::from_slice(bytes).map_err(SignedManifestError::Json)?;
        p.validate()?;
        Ok(p)
    }

    /// Verifies the envelope (payload type and a trusted plan-key
    /// signature), then parses and validates the payload, then checks that
    /// `key_id` is the key that verified it.
    ///
    /// # Errors
    ///
    /// [`SignedManifestError::Envelope`] if verification fails (nothing is
    /// parsed); otherwise as [`JobPlanV1::from_payload`], or
    /// [`SignedManifestError::KeyIdMismatch`].
    pub fn open(
        envelope: &SignedEnvelopeV1,
        verifier: &dyn SignatureVerifier,
    ) -> Result<Self, SignedManifestError> {
        let verified = envelope.verified_payload(PayloadType::JobPlanV1, verifier)?;
        let p = Self::from_payload(verified.bytes)?;
        if p.key_id != verified.key_id {
            return Err(SignedManifestError::KeyIdMismatch);
        }
        Ok(p)
    }
}

/// Why the agent refused a plan. Every case is an integrity failure
/// (REQ-JOB-005 item 3): nothing is written.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PlanError {
    /// Check 1 or 2: signature, payload type, schema, shape or key id.
    #[error("job plan did not verify: {0}")]
    Plan(#[source] SignedManifestError),
    /// Check 3: the nonce is not the one the agent sent.
    #[error("job plan does not carry this device's nonce")]
    NonceMismatch,
    /// Check 4: another session.
    #[error("job plan names another session")]
    SessionMismatch,
    /// Check 4: another job.
    #[error("job plan names another job")]
    JobMismatch,
    /// Check 4: another package or revision than the one chosen.
    #[error("job plan names another package")]
    PackageMismatch,
    /// Check 5: another disk.
    #[error("job plan names another disk")]
    DiskMismatch,
    /// Check 6: the content manifest did not verify or parse.
    #[error("content manifest did not verify: {0}")]
    ContentManifest(#[source] SignedManifestError),
    /// Check 6: the content manifest's digest is not the plan's.
    #[error("content manifest digest does not match the job plan")]
    ContentManifestDigest,
    /// Check 6: the content manifest describes other content than the
    /// plan; the text names the field.
    #[error("content manifest does not match the job plan: {0}")]
    ContentMismatch(&'static str),
    /// v2: the plan's `job_key_id` is not the key this agent generated.
    #[error("job plan names another job key")]
    JobKeyMismatch,
    /// v2: the escrow key id is not the SHA-256 of the escrow key.
    #[error("job plan escrow key id does not match its key")]
    EscrowKeyIdMismatch,
    /// v2: the answer file's SHA-256 is not the one the plan states.
    #[error("job plan answer file does not match its digest")]
    AnswerFileDigest,
    /// v2: the number of driver manifests is not the plan's.
    #[error("driver manifests do not match the job plan's driver list")]
    DriverManifestCount,
}

impl PlanError {
    /// Failure category: always integrity.
    #[must_use]
    pub const fn category(&self) -> FailureCategory {
        FailureCategory::Integrity
    }

    /// The reason code for the failure report.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Plan(_) => codes::PLAN_SIGNATURE_INVALID,
            Self::NonceMismatch => codes::PLAN_NONCE_MISMATCH,
            Self::SessionMismatch
            | Self::JobMismatch
            | Self::PackageMismatch
            | Self::DiskMismatch => codes::PLAN_BINDING_MISMATCH,
            Self::JobKeyMismatch => codes::JOB_KEY_MISMATCH,
            Self::EscrowKeyIdMismatch | Self::AnswerFileDigest => codes::PLAN_BINDING_MISMATCH,
            Self::ContentManifest(_)
            | Self::ContentManifestDigest
            | Self::ContentMismatch(_)
            | Self::DriverManifestCount => codes::CONTENT_MANIFEST_MISMATCH,
        }
    }
}

/// What the agent expects the plan to say (plan section 3.2 checks 3 to 5).
#[derive(Debug, Clone, Copy)]
pub struct PlanExpectation<'a> {
    /// The nonce sent with the confirm request.
    pub agent_nonce: &'a AgentNonce,
    /// The agent's session.
    pub session_id: SessionId,
    /// The job id in the confirm response.
    pub job_id: JobId,
    /// The package chosen.
    pub package_id: PackageId,
    /// Its revision.
    pub package_revision: u64,
    /// The disk chosen.
    pub disk: &'a DiskDescriptorV1,
}

/// A job plan and its content manifest, both verified and bound to this
/// device's session, job, nonce and disk. Only [`VerifiedJobPlan::verify`]
/// builds one; `usgp-deploy` builds its wipe authorisation only from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedJobPlan {
    plan: JobPlanV1,
    content: ContentManifestV1,
}

impl VerifiedJobPlan {
    /// Runs checks 1 to 6 of plan section 3.2, in order, and stops at the
    /// first failure.
    ///
    /// `plan_keys` trusts only the pinned plan key and `content_keys` only
    /// the pinned content key; `sha256` is `usgp-crypto`'s SHA-256.
    ///
    /// # Errors
    ///
    /// [`PlanError`] naming the check that failed.
    pub fn verify(
        plan_envelope: &SignedEnvelopeV1,
        plan_keys: &dyn SignatureVerifier,
        content_envelope: &SignedEnvelopeV1,
        content_keys: &dyn SignatureVerifier,
        sha256: &dyn Fn(&[u8]) -> Sha256Digest,
        expect: &PlanExpectation<'_>,
    ) -> Result<Self, PlanError> {
        // 1 and 2.
        let plan = JobPlanV1::open(plan_envelope, plan_keys).map_err(PlanError::Plan)?;
        // 3.
        if plan.agent_nonce != *expect.agent_nonce {
            return Err(PlanError::NonceMismatch);
        }
        // 4.
        if plan.session_id != expect.session_id {
            return Err(PlanError::SessionMismatch);
        }
        if plan.job_id != expect.job_id {
            return Err(PlanError::JobMismatch);
        }
        if plan.package.id != expect.package_id || plan.package.revision != expect.package_revision
        {
            return Err(PlanError::PackageMismatch);
        }
        // 5.
        if !plan.disk.matches(expect.disk) {
            return Err(PlanError::DiskMismatch);
        }
        // 6: signature first, then digest of the exact payload, then parse.
        let verified = content_envelope
            .verified_payload(PayloadType::ContentManifestV1, content_keys)
            .map_err(|e| PlanError::ContentManifest(e.into()))?;
        if sha256(verified.bytes) != plan.image.content_manifest_sha256 {
            return Err(PlanError::ContentManifestDigest);
        }
        let content =
            ContentManifestV1::from_payload(verified.bytes).map_err(PlanError::ContentManifest)?;
        if content.key_id != verified.key_id {
            return Err(PlanError::ContentManifest(
                SignedManifestError::KeyIdMismatch,
            ));
        }
        check_content(&plan, &content)?;
        Ok(Self { plan, content })
    }

    /// The plan.
    #[must_use]
    pub const fn plan(&self) -> &JobPlanV1 {
        &self.plan
    }

    /// The image's content manifest (chunk digests).
    #[must_use]
    pub const fn content_manifest(&self) -> &ContentManifestV1 {
        &self.content
    }
}

fn check_content(plan: &JobPlanV1, content: &ContentManifestV1) -> Result<(), PlanError> {
    check_image(&plan.image, content)
}

fn check_image(img: &PlanImageV1, content: &ContentManifestV1) -> Result<(), PlanError> {
    use PlanError::ContentMismatch;
    if content.kind != ContentKind::Image {
        return Err(ContentMismatch("kind"));
    }
    if content.sha256 != img.content_sha256 {
        return Err(ContentMismatch("sha256"));
    }
    if content.size != img.size {
        return Err(ContentMismatch("size"));
    }
    let edition = img
        .edition_index
        .check(content.wim.image_count)
        .ok()
        .and_then(|i| content.wim.editions.iter().find(|e| e.index == i))
        .ok_or(ContentMismatch("edition_index"))?;
    if edition.name != img.edition_name {
        return Err(ContentMismatch("edition_name"));
    }
    if edition.total_bytes.is_some_and(|t| t != img.total_bytes) {
        return Err(ContentMismatch("total_bytes"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Job plan, version 2 (M4 plan WU-4)
// ---------------------------------------------------------------------------
//
// The server issues only v2 plans from M4 on; `JobPlanV1` stays so that
// stored v1 plans still decode. A v2 plan adds the nine steps of
// REQ-SEQ-002, the rendered answer file, the driver archives with their
// INF lists, the agent package, the tags, the escrow public key, the id of
// the device-generated job key and the post-setup resume path. It still
// carries no secret: the answer file is linted to hold none, and only
// public keys and key ids appear (M4 plan section 0 item 1).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7, SI-7(6) - signed plan; answer file, driver and
//   agent content bound by SHA-256 and signed manifests.
// - NIST 800-53: SC-23 (Session Authenticity) - plan bound to the agent's
//   nonce and to the job key the agent generated (job_key_id).
// - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management) -
//   escrow public key and key id; job key id.
// - NIST 800-53: SI-10 - strict parse; every list and text bounded.
// - SPEC: specs/workflow.md#REQ-SEQ-002 (nine steps)
// - SPEC: specs/configuration.md#REQ-CFG-004 (values resolved before any
//   disk write), #REQ-CFG-009 (tags)
// - SPEC: specs/drivers.md#REQ-DRV-006 (INF list)
// - SPEC: specs/agent-handoff.md#REQ-AGT-001 (agent always installed)
// - DECISION: docs/decisions/0024, 0025 items 1 and 2
// - FIPS 186-5 (ECDSA P-384), FIPS 180-4 (SHA-256), RFC 5480 (SPKI)

/// One v2 step and its timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanStepV2 {
    /// Step number.
    pub step: StepV2,
    /// What it does; must match the number.
    pub kind: StepKindV2,
    /// Timeout in seconds (1 to [`MAX_STEP_TIMEOUT_S`]).
    pub timeout_s: u32,
}

/// The rendered answer file (M4 plan section 1.6): written by the agent
/// at step 5 to `\Windows\Panther\unattend.xml` after it checks the
/// SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanAnswerFileV2 {
    /// SHA-256 of the bytes.
    pub sha256: Sha256Digest,
    /// The bytes (1 byte to [`MAX_ANSWER_FILE_BYTES`]), padded base64.
    pub b64: B64Bytes<1, MAX_ANSWER_FILE_BYTES>,
}

/// One driver archive to add at step 4, in order (M4 plan section 1.4).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanDriverV2 {
    /// The driver archive record.
    pub archive_id: DriverArchiveId,
    /// SHA-256 of the archive file.
    pub content_sha256: Sha256Digest,
    /// SHA-256 of its signed content manifest's payload.
    pub content_manifest_sha256: Sha256Digest,
    /// The INF packages the archive holds (relative paths, each ending in
    /// `.inf`; 1 to [`MAX_ARCHIVE_INFS`]); every one must be staged.
    pub infs: Vec<RelPath>,
}

/// The agent package installed at step 8 (M4 plan section 1.7).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanAgentV2 {
    /// The agent package record.
    pub agent_package_id: AgentPackageId,
    /// SHA-256 of the package file (the whole file is re-hashed before
    /// use).
    pub content_sha256: Sha256Digest,
    /// SHA-256 of its signed content manifest's payload.
    pub content_manifest_sha256: Sha256Digest,
}

closed_enum!(
    /// The account whose password is escrowed (decision 0025 item 2: the
    /// built-in Administrator, located by RID 500, never by name).
    EscrowAccount, "escrow account" {
        /// The built-in Administrator account.
        Administrator => "administrator",
    }
);

/// The escrow public key (M4 plan section 1.3). Present only when the
/// package's `admin_password` mode is `generate_and_escrow`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanEscrowV2 {
    /// SHA-256 of `spki_b64`'s DER.
    pub key_id: Sha256Digest,
    /// The server's ECDH P-384 escrow public key.
    pub spki_b64: P384Spki,
    /// The account.
    pub account: EscrowAccount,
}

/// Where the post-setup runner re-contacts the server (M4 plan section
/// 3.1).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanPostSetupV2 {
    /// URL path of the resume route on the device listener; the
    /// challenge route is this path plus `/challenge`.
    pub resume_url_path: UrlPath,
}

/// Job plan, version 2 (M4 plan WU-4). Payload type
/// `application/vnd.usgp.job-plan.v2+json`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobPlanV2 {
    /// Always [`SCHEMA_V2`].
    pub schema: u32,
    /// Job.
    pub job_id: JobId,
    /// Session that confirmed it.
    pub session_id: SessionId,
    /// Boot service the session came through.
    pub boot_service_id: BootServiceId,
    /// When the plan was signed (not checked on the device).
    pub issued_at_us: UnixMicros,
    /// Key id (SHA-256 of the SPKI DER) of the plan key.
    pub key_id: Sha256Digest,
    /// The nonce from the agent's confirm request.
    pub agent_nonce: AgentNonce,
    /// Device.
    pub device: PlanDeviceV1,
    /// Package.
    pub package: PlanPackageV1,
    /// Image edition.
    pub image: PlanImageV1,
    /// Disk.
    pub disk: PlanDiskV1,
    /// Layout sizes.
    pub layout_policy: LayoutPolicyV1,
    /// Wipe authorisation record.
    pub wipe: PlanWipeV1,
    /// The nine steps in order.
    pub steps: Vec<PlanStepV2>,
    /// Retry policy.
    pub retry: RetryPolicyV1,
    /// Seconds without progress before the job is stalled.
    pub stall_timeout_s: u32,
    /// Seconds between progress reports.
    pub report_interval_s: u32,
    /// The rendered answer file.
    pub answer_file: PlanAnswerFileV2,
    /// Driver archives in the order they are added (0 to
    /// [`MAX_PLAN_DRIVERS`]).
    pub drivers: Vec<PlanDriverV2>,
    /// The agent package.
    pub agent: PlanAgentV2,
    /// Tags (0 to [`MAX_TAGS`]).
    pub tags: Vec<Tag>,
    /// The escrow key, or `None` when no password is set.
    pub escrow: Option<PlanEscrowV2>,
    /// Key id (SHA-256 of the SPKI DER) of the device's job key, as sent
    /// in the confirm request.
    pub job_key_id: Sha256Digest,
    /// Post-setup contact.
    pub postsetup: PlanPostSetupV2,
}

impl JobPlanV2 {
    /// Checks every rule a v2 plan must meet beyond its types (the v1
    /// rules, the nine steps, and the M4 lists). Digest relations need a
    /// hash function and are checked by [`VerifiedJobPlanV2::verify`].
    ///
    /// # Errors
    ///
    /// [`SignedManifestError::UnsupportedSchema`] or
    /// [`SignedManifestError::Invalid`] naming the first rule broken.
    pub fn validate(&self) -> Result<(), SignedManifestError> {
        use SignedManifestError::Invalid;
        if self.schema != SCHEMA_V2 {
            return Err(SignedManifestError::UnsupportedSchema(self.schema));
        }
        if self.package.revision == 0 {
            return Err(Invalid("package.revision must be at least 1"));
        }
        if self.image.size == 0 || self.image.size > MAX_CONTENT_BYTES {
            return Err(Invalid("image.size must be 1 byte to 1 TiB"));
        }
        if self.disk.validate().is_err() {
            return Err(Invalid("disk geometry is invalid"));
        }
        if !self.layout_policy.is_standard() {
            return Err(Invalid("layout_policy is not the fixed layout"));
        }
        if self.disk.size_bytes < self.layout_policy.min_disk_bytes {
            return Err(Invalid("disk is below layout_policy.min_disk_bytes"));
        }
        if self.wipe.audit_seq == 0 {
            return Err(Invalid("wipe.audit_seq must be at least 1"));
        }
        let steps_ok = self.steps.len() == StepV2::ALL.len()
            && self.steps.iter().zip(StepV2::ALL).all(|(s, want)| {
                s.step == want
                    && s.kind == want.kind()
                    && s.timeout_s >= 1
                    && s.timeout_s <= MAX_STEP_TIMEOUT_S
            });
        if !steps_ok {
            return Err(Invalid(
                "steps must be steps 1 to 9 in order with matching kinds and timeouts of 1 s to 7 days",
            ));
        }
        let r = self.retry;
        if r.attempts == 0
            || r.attempts > MAX_RETRY_ATTEMPTS
            || r.base_ms == 0
            || r.base_ms > r.max_ms
            || r.max_ms > MAX_RETRY_DELAY_MS
        {
            return Err(Invalid(
                "retry must have 1 to 100 attempts and 1 ms <= base_ms <= max_ms <= 1 hour",
            ));
        }
        if self.stall_timeout_s == 0 || self.stall_timeout_s > MAX_STEP_TIMEOUT_S {
            return Err(Invalid("stall_timeout_s must be 1 s to 7 days"));
        }
        if self.report_interval_s == 0 || self.report_interval_s > MAX_REPORT_INTERVAL_S {
            return Err(Invalid("report_interval_s must be 1 s to 1 hour"));
        }
        if self.drivers.len() > MAX_PLAN_DRIVERS {
            return Err(Invalid("drivers must list at most 64 archives"));
        }
        for (i, d) in self.drivers.iter().enumerate() {
            if self
                .drivers
                .iter()
                .take(i)
                .any(|o| o.archive_id == d.archive_id)
            {
                return Err(Invalid("drivers must not list an archive twice"));
            }
            if d.infs.is_empty() || d.infs.len() > MAX_ARCHIVE_INFS {
                return Err(Invalid("drivers[].infs must list 1 to 4096 INF paths"));
            }
            if !d.infs.iter().all(|p| p.has_extension(".inf")) {
                return Err(Invalid("drivers[].infs entries must end in .inf"));
            }
        }
        if self.tags.len() > MAX_TAGS {
            return Err(Invalid("tags must list at most 64 tags"));
        }
        Ok(())
    }

    /// The timeout of `step`, in seconds.
    #[must_use]
    pub fn timeout_s(&self, step: StepV2) -> Option<u32> {
        self.steps
            .iter()
            .find(|s| s.step == step)
            .map(|s| s.timeout_s)
    }

    /// The exact bytes to sign: compact JSON in field order.
    ///
    /// # Errors
    ///
    /// As [`JobPlanV2::validate`]; [`SignedManifestError::TooLarge`].
    pub fn to_payload(&self) -> Result<Vec<u8>, SignedManifestError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(SignedManifestError::Json)?;
        if bytes.len() > MAX_MANIFEST_PAYLOAD_BYTES {
            return Err(SignedManifestError::TooLarge { len: bytes.len() });
        }
        Ok(bytes)
    }

    /// Parses and validates payload bytes. Use only on bytes whose
    /// signature has been verified, or on the server's own stored copy.
    ///
    /// # Errors
    ///
    /// [`SignedManifestError::TooLarge`] before parsing;
    /// [`SignedManifestError::Json`]; or as [`JobPlanV2::validate`].
    pub fn from_payload(bytes: &[u8]) -> Result<Self, SignedManifestError> {
        if bytes.len() > MAX_MANIFEST_PAYLOAD_BYTES {
            return Err(SignedManifestError::TooLarge { len: bytes.len() });
        }
        let p: Self = serde_json::from_slice(bytes).map_err(SignedManifestError::Json)?;
        p.validate()?;
        Ok(p)
    }

    /// Verifies the envelope (payload type `job-plan.v2` and a trusted
    /// plan-key signature), then parses and validates, then checks that
    /// `key_id` is the key that verified it.
    ///
    /// # Errors
    ///
    /// [`SignedManifestError::Envelope`] if verification fails (nothing is
    /// parsed); otherwise as [`JobPlanV2::from_payload`], or
    /// [`SignedManifestError::KeyIdMismatch`].
    pub fn open(
        envelope: &SignedEnvelopeV1,
        verifier: &dyn SignatureVerifier,
    ) -> Result<Self, SignedManifestError> {
        let verified = envelope.verified_payload(PayloadType::JobPlanV2, verifier)?;
        let p = Self::from_payload(verified.bytes)?;
        if p.key_id != verified.key_id {
            return Err(SignedManifestError::KeyIdMismatch);
        }
        Ok(p)
    }
}

/// What the agent expects a v2 plan to say: the v1 expectations plus the
/// id of the job key it generated.
#[derive(Debug, Clone, Copy)]
pub struct PlanExpectationV2<'a> {
    /// The v1 checks (nonce, session, job, package, disk).
    pub base: PlanExpectation<'a>,
    /// SHA-256 of the job key's SPKI DER sent in the confirm request.
    pub job_key_id: Sha256Digest,
}

/// The signed content manifests that come with a v2 plan.
#[derive(Debug, Clone, Copy)]
pub struct PlanContentV2<'a> {
    /// The image's manifest.
    pub image: &'a SignedEnvelopeV1,
    /// One manifest per driver archive, in plan order.
    pub drivers: &'a [SignedEnvelopeV1],
    /// The agent package's manifest.
    pub agent: &'a SignedEnvelopeV1,
}

/// A v2 plan and its content manifests, all verified and bound to this
/// device's session, job, nonce, disk and job key. Only
/// [`VerifiedJobPlanV2::verify`] builds one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedJobPlanV2 {
    plan: JobPlanV2,
    image: ContentManifestV1,
    drivers: Vec<ContentManifestV1>,
    agent: ContentManifestV1,
}

impl VerifiedJobPlanV2 {
    /// Runs the v1 checks 1 to 6 on a v2 plan, then:
    ///
    /// 7. `job_key_id` is the agent's job key;
    /// 8. the escrow key id is the SHA-256 of the escrow key, and the
    ///    answer file's SHA-256 is the plan's;
    /// 9. each driver and the agent manifest: signature with the content
    ///    key, SHA-256 of the payload against the plan, parse, and the
    ///    file SHA-256 against the plan.
    ///
    /// It stops at the first failure.
    ///
    /// # Errors
    ///
    /// [`PlanError`] naming the check that failed.
    pub fn verify(
        plan_envelope: &SignedEnvelopeV1,
        plan_keys: &dyn SignatureVerifier,
        content: &PlanContentV2<'_>,
        content_keys: &dyn SignatureVerifier,
        sha256: &dyn Fn(&[u8]) -> Sha256Digest,
        expect: &PlanExpectationV2<'_>,
    ) -> Result<Self, PlanError> {
        let base = &expect.base;
        // 1 and 2.
        let plan = JobPlanV2::open(plan_envelope, plan_keys).map_err(PlanError::Plan)?;
        // 3.
        if plan.agent_nonce != *base.agent_nonce {
            return Err(PlanError::NonceMismatch);
        }
        // 4.
        if plan.session_id != base.session_id {
            return Err(PlanError::SessionMismatch);
        }
        if plan.job_id != base.job_id {
            return Err(PlanError::JobMismatch);
        }
        if plan.package.id != base.package_id || plan.package.revision != base.package_revision {
            return Err(PlanError::PackageMismatch);
        }
        // 5.
        if !plan.disk.matches(base.disk) {
            return Err(PlanError::DiskMismatch);
        }
        // 6.
        let image = open_manifest(
            content.image,
            content_keys,
            sha256,
            &plan.image.content_manifest_sha256,
        )?;
        check_image(&plan.image, &image)?;
        // 7.
        if plan.job_key_id != expect.job_key_id {
            return Err(PlanError::JobKeyMismatch);
        }
        // 8.
        if let Some(e) = &plan.escrow
            && sha256(e.spki_b64.as_der()) != e.key_id
        {
            return Err(PlanError::EscrowKeyIdMismatch);
        }
        if sha256(plan.answer_file.b64.as_bytes()) != plan.answer_file.sha256 {
            return Err(PlanError::AnswerFileDigest);
        }
        // 9.
        if content.drivers.len() != plan.drivers.len() {
            return Err(PlanError::DriverManifestCount);
        }
        let mut drivers = Vec::with_capacity(plan.drivers.len());
        for (env, d) in content.drivers.iter().zip(&plan.drivers) {
            let m = open_manifest(env, content_keys, sha256, &d.content_manifest_sha256)?;
            if m.sha256 != d.content_sha256 {
                return Err(PlanError::ContentMismatch("drivers[].content_sha256"));
            }
            drivers.push(m);
        }
        let agent = open_manifest(
            content.agent,
            content_keys,
            sha256,
            &plan.agent.content_manifest_sha256,
        )?;
        if agent.sha256 != plan.agent.content_sha256 {
            return Err(PlanError::ContentMismatch("agent.content_sha256"));
        }
        Ok(Self {
            plan,
            image,
            drivers,
            agent,
        })
    }

    /// The plan.
    #[must_use]
    pub const fn plan(&self) -> &JobPlanV2 {
        &self.plan
    }

    /// The image's content manifest.
    #[must_use]
    pub const fn content_manifest(&self) -> &ContentManifestV1 {
        &self.image
    }

    /// The driver archives' content manifests, in plan order.
    #[must_use]
    pub fn driver_manifests(&self) -> &[ContentManifestV1] {
        &self.drivers
    }

    /// The agent package's content manifest.
    #[must_use]
    pub const fn agent_manifest(&self) -> &ContentManifestV1 {
        &self.agent
    }
}

/// Signature first, then the digest of the exact payload, then parse and
/// the key id.
fn open_manifest(
    env: &SignedEnvelopeV1,
    keys: &dyn SignatureVerifier,
    sha256: &dyn Fn(&[u8]) -> Sha256Digest,
    want: &Sha256Digest,
) -> Result<ContentManifestV1, PlanError> {
    let verified = env
        .verified_payload(PayloadType::ContentManifestV1, keys)
        .map_err(|e| PlanError::ContentManifest(e.into()))?;
    if sha256(verified.bytes) != *want {
        return Err(PlanError::ContentManifestDigest);
    }
    let m = ContentManifestV1::from_payload(verified.bytes).map_err(PlanError::ContentManifest)?;
    if m.key_id != verified.key_id {
        return Err(PlanError::ContentManifest(
            SignedManifestError::KeyIdMismatch,
        ));
    }
    Ok(m)
}
