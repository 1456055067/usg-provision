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
use crate::content_manifest::ContentManifestV1;
use crate::device::{AgentNonce, MacList};
use crate::disk::{DiskDescriptorV1, PlanDiskV1};
use crate::envelope::{PayloadType, SignatureVerifier, SignedEnvelopeV1};
use crate::error_code::{ErrorCode, codes};
use crate::ids::{BootServiceId, JobId, PackageId, SessionId, UnixMicros};
use crate::limits::{
    MAX_CONTENT_BYTES, MAX_MANIFEST_PAYLOAD_BYTES, MAX_REPORT_INTERVAL_S, MAX_RETRY_ATTEMPTS,
    MAX_RETRY_DELAY_MS, MAX_STEP_TIMEOUT_S,
};
use crate::names::{EditionIndex, WimText};
use crate::progress::{FailureCategory, Step, StepKind};
use crate::status::ContentKind;

/// The only plan schema version.
pub const SCHEMA_V1: u32 = 1;

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
            Self::ContentManifest(_) | Self::ContentManifestDigest | Self::ContentMismatch(_) => {
                codes::CONTENT_MANIFEST_MISMATCH
            }
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
    use PlanError::ContentMismatch;
    let img = &plan.image;
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
