//! Job states, steps and progress reports (M3 plan section 3.4).
//!
//! `POST /v1/device/jobs/{job_id}/progress` carries a [`ProgressV1`]; the
//! server answers [`ProgressAckV1`]. A failure is a [`FailureV1`], the same
//! fields the device shows and the operator sees (REQ-JOB-005,
//! REQ-JOB-006).
//!
//! This module checks what one report can say about itself (for example a
//! `failed` event carries a failure for the same step). The rules that
//! need the job's history (sequence numbers, step order, `succeeded` only
//! after step 4) are the server's (`usgp-api`), using
//! [`JobState::can_become`] and [`Step::next`].
//!
//! M4 (M4 plan WU-4): progress schema 2 for v2 jobs, with the nine steps
//! of REQ-SEQ-002 ([`StepV2`], [`StepKindV2`]), [`ProgressV2`] and
//! [`FailureV2`]. The v1 types are unchanged and stay for v1 jobs.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - closed value sets,
//   bounded lists and text, self-consistency of each report.
// - NIST 800-53: SI-11 (Error Handling) - failure reports carry a category
//   and code, never secrets (no field can hold one).
// - NIST 800-53: AU-12 (Audit Record Generation, basis) - the closed state
//   and step sets the server audits on every change.
// - SPEC: specs/progress.md#REQ-JOB-002 (step list and states),
//   #REQ-JOB-003 (bytes and file role), #REQ-JOB-005 (step, files, count,
//   category), #REQ-JOB-006 (attempts), #REQ-JOB-011 (timeout named),
//   #REQ-JOB-012 (states and transitions), #REQ-JOB-013 (success after
//   step 4), #REQ-JOB-014 (no secrets)
// - SPEC: specs/disk.md#REQ-DISK-014 (layout reported)

use std::fmt;

use crate::disk::LayoutReportV1;
use crate::error_code::ErrorCode;
use crate::limits::{MAX_FAILED_FILES, MAX_REPORTED_ATTEMPTS};
use crate::names::ItemName;

closed_enum!(
    /// State of a job (REQ-JOB-012). There is no cancelled state: a job
    /// starts at the wipe confirmation and cannot be cancelled.
    JobState, "job state" {
        /// Running, with a current step.
        Running => "running",
        /// Every step succeeded and the device reported it.
        Succeeded => "succeeded",
        /// Failed, with a reason.
        Failed => "failed",
        /// Not heard from for longer than the allowed interval.
        Lost => "lost",
    }
);

impl JobState {
    /// `true` for `succeeded` and `failed`, which never change.
    #[must_use]
    pub const fn is_final(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed)
    }

    /// Whether a job may move from `self` to `to` (`specs/progress.md`,
    /// "States and transitions"): running to succeeded, failed or lost;
    /// lost back to running, or to failed or succeeded.
    #[must_use]
    pub const fn can_become(self, to: Self) -> bool {
        matches!(
            (self, to),
            (Self::Running, Self::Succeeded | Self::Failed | Self::Lost)
                | (Self::Lost, Self::Running | Self::Failed | Self::Succeeded)
        )
    }
}

closed_enum!(
    /// What a step does (`specs/progress.md` definitions; plan section 3.2).
    StepKind, "step kind" {
        /// Step 1: download and verify content (REQ-PE-016).
        VerifyContent => "verify_content",
        /// Step 2: wipe, partition and format (REQ-DISK-007 to 010).
        PartitionFormat => "partition_format",
        /// Step 3: apply the image (REQ-PE-017).
        ApplyImage => "apply_image",
        /// Step 4: make the disk bootable (REQ-BOOT-065, REQ-BOOT-066).
        MakeBootable => "make_bootable",
        /// Step 5: report and restart (REQ-PE-019).
        ReportRestart => "report_restart",
    }
);

/// A job step, 1 to 5 (JSON integer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(transparent)]
pub struct Step(u8);

/// A step number outside 1 to 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("step must be 1 to 5")]
pub struct BadStep;

impl Step {
    /// Step 1, verify content.
    pub const VERIFY_CONTENT: Self = Self(1);
    /// Step 2, partition and format.
    pub const PARTITION_FORMAT: Self = Self(2);
    /// Step 3, apply the image.
    pub const APPLY_IMAGE: Self = Self(3);
    /// Step 4, make bootable.
    pub const MAKE_BOOTABLE: Self = Self(4);
    /// Step 5, report and restart.
    pub const REPORT_RESTART: Self = Self(5);
    /// All steps in order.
    pub const ALL: [Self; 5] = [
        Self::VERIFY_CONTENT,
        Self::PARTITION_FORMAT,
        Self::APPLY_IMAGE,
        Self::MAKE_BOOTABLE,
        Self::REPORT_RESTART,
    ];

    /// The step with this number.
    ///
    /// # Errors
    ///
    /// [`BadStep`] outside 1 to 5.
    pub const fn new(n: u8) -> Result<Self, BadStep> {
        if n >= 1 && n <= 5 {
            Ok(Self(n))
        } else {
            Err(BadStep)
        }
    }

    /// The number, 1 to 5.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// What the step does.
    #[must_use]
    pub const fn kind(self) -> StepKind {
        match self.0 {
            1 => StepKind::VerifyContent,
            2 => StepKind::PartitionFormat,
            3 => StepKind::ApplyImage,
            4 => StepKind::MakeBootable,
            _ => StepKind::ReportRestart,
        }
    }

    /// The step after this one, or `None` after step 5.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        if self.0 < 5 {
            Some(Self(self.0 + 1))
        } else {
            None
        }
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.0, self.kind())
    }
}

impl<'de> serde::Deserialize<'de> for Step {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let n = u8::deserialize(d)?;
        Self::new(n).map_err(serde::de::Error::custom)
    }
}

closed_enum!(
    /// State of one step in the operator and device views (REQ-JOB-002;
    /// plan section 3.8 `job_step.state`).
    StepState, "step state" {
        /// Not started.
        Pending => "pending",
        /// Running.
        Running => "running",
        /// Done.
        Done => "done",
        /// Failed.
        Failed => "failed",
    }
);

closed_enum!(
    /// What a progress report says happened.
    ProgressEvent, "progress event" {
        /// A step started.
        StepStarted => "step_started",
        /// Bytes or the current item changed.
        Progress => "progress",
        /// A step completed.
        StepCompleted => "step_completed",
        /// The job failed (final).
        Failed => "failed",
        /// The job succeeded (final; REQ-JOB-013).
        Succeeded => "succeeded",
    }
);

closed_enum!(
    /// Role of a file in the package (REQ-JOB-003, REQ-JOB-005 item 2).
    FileRole, "file role" {
        /// The image file.
        Image => "image",
        /// Image metadata.
        Metadata => "metadata",
        /// A driver archive (M4).
        DriverArchive => "driver_archive",
        /// The agent package (M4).
        AgentPackage => "agent_package",
        /// The answer file (M4).
        AnswerFile => "answer_file",
    }
);

closed_enum!(
    /// Kind of failure (REQ-JOB-005 item 3, with timeouts named,
    /// REQ-JOB-011).
    FailureCategory, "failure category" {
        /// A network problem.
        Network => "network",
        /// An integrity-check failure (not retried, REQ-JOB-007).
        Integrity => "integrity",
        /// A refusal by the product.
        Refused => "refused",
        /// A local problem (disk, memory).
        Local => "local",
        /// A step or stall timeout.
        Timeout => "timeout",
    }
);

impl FailureCategory {
    /// `true` only for network failures, the one category that may be
    /// transient (REQ-JOB-007: integrity failures and refusals are not
    /// retried).
    #[must_use]
    pub const fn may_retry(self) -> bool {
        matches!(self, Self::Network)
    }
}

/// A file named in a progress report or failure.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgressItemV1 {
    /// Role.
    pub role: FileRole,
    /// File name or description.
    pub name: ItemName,
}

/// Why a report was refused. Values are never echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProgressDataError {
    /// More than [`MAX_FAILED_FILES`] files.
    #[error("failure lists more than 32 files")]
    TooManyFiles,
    /// `count` is below the number of files listed.
    #[error("failure count is below the number of files listed")]
    CountBelowFiles,
    /// `attempts` is 0 or over [`MAX_REPORTED_ATTEMPTS`].
    #[error("attempts must be 1 to 10000")]
    BadAttempts,
    /// `seq` is 0.
    #[error("seq must be at least 1")]
    BadSeq,
    /// `bytes_done` is above `bytes_total`.
    #[error("bytes_done is above bytes_total")]
    BytesOverTotal,
    /// A `failed` event without a failure, or a failure on another event.
    #[error("a failure is required on, and only on, a failed event")]
    FailureMismatch,
    /// The failure names a different step from the report.
    #[error("the failure's step differs from the report's step")]
    FailureStepMismatch,
    /// `schema` is not [`PROGRESS_SCHEMA_V2`] (v2 reports only).
    #[error("progress schema must be 2")]
    BadSchema,
    /// A `succeeded` event on a step other than the last (v2 reports
    /// only; REQ-SEQ-006).
    #[error("succeeded may be reported only on step 9")]
    SucceededBeforeLastStep,
    /// `restart_pending` on anything but step 8 `step_completed`.
    #[error("restart_pending is allowed only on step 8 step_completed")]
    RestartPendingMisplaced,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FailureWire {
    step: Step,
    category: FailureCategory,
    code: ErrorCode,
    #[serde(default)]
    files: Vec<ProgressItemV1>,
    count: u32,
    attempts: u32,
}

/// A failure (REQ-JOB-005 items 1 to 3, REQ-JOB-006): the step, the
/// category, a code, the files that failed and how many, and the attempts
/// made.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "FailureWire")]
pub struct FailureV1 {
    /// Step that failed.
    pub step: Step,
    /// Category.
    pub category: FailureCategory,
    /// Reason code (for example `chunk_digest_mismatch`).
    pub code: ErrorCode,
    /// Files that failed (at most [`MAX_FAILED_FILES`]).
    pub files: Vec<ProgressItemV1>,
    /// How many files failed (at least `files.len()`).
    pub count: u32,
    /// Attempts made (1 to [`MAX_REPORTED_ATTEMPTS`]).
    pub attempts: u32,
}

impl TryFrom<FailureWire> for FailureV1 {
    type Error = ProgressDataError;

    fn try_from(w: FailureWire) -> Result<Self, Self::Error> {
        let f = Self {
            step: w.step,
            category: w.category,
            code: w.code,
            files: w.files,
            count: w.count,
            attempts: w.attempts,
        };
        f.validate()?;
        Ok(f)
    }
}

impl FailureV1 {
    /// Checks the bounds.
    ///
    /// # Errors
    ///
    /// [`ProgressDataError`].
    pub fn validate(&self) -> Result<(), ProgressDataError> {
        if self.files.len() > MAX_FAILED_FILES {
            return Err(ProgressDataError::TooManyFiles);
        }
        if usize::try_from(self.count).is_ok_and(|c| c < self.files.len()) {
            return Err(ProgressDataError::CountBelowFiles);
        }
        if self.attempts == 0 || self.attempts > MAX_REPORTED_ATTEMPTS {
            return Err(ProgressDataError::BadAttempts);
        }
        Ok(())
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgressWire {
    seq: u64,
    step: Step,
    event: ProgressEvent,
    #[serde(default)]
    bytes_done: Option<u64>,
    #[serde(default)]
    bytes_total: Option<u64>,
    #[serde(default)]
    item: Option<ProgressItemV1>,
    #[serde(default)]
    layout: Option<LayoutReportV1>,
    #[serde(default)]
    failure: Option<FailureV1>,
}

/// A progress report (plan section 3.4).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "ProgressWire")]
pub struct ProgressV1 {
    /// Strictly increasing per job, from 1.
    pub seq: u64,
    /// Current step.
    pub step: Step,
    /// What happened.
    pub event: ProgressEvent,
    /// Bytes done in the step.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_done: Option<u64>,
    /// Bytes the step will handle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_total: Option<u64>,
    /// File being fetched or written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item: Option<ProgressItemV1>,
    /// The layout written (after step 2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout: Option<LayoutReportV1>,
    /// The failure, on and only on a `failed` event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<FailureV1>,
}

impl TryFrom<ProgressWire> for ProgressV1 {
    type Error = ProgressDataError;

    fn try_from(w: ProgressWire) -> Result<Self, Self::Error> {
        let p = Self {
            seq: w.seq,
            step: w.step,
            event: w.event,
            bytes_done: w.bytes_done,
            bytes_total: w.bytes_total,
            item: w.item,
            layout: w.layout,
            failure: w.failure,
        };
        p.validate()?;
        Ok(p)
    }
}

impl ProgressV1 {
    /// Checks what one report can say about itself.
    ///
    /// # Errors
    ///
    /// [`ProgressDataError`].
    pub fn validate(&self) -> Result<(), ProgressDataError> {
        if self.seq == 0 {
            return Err(ProgressDataError::BadSeq);
        }
        if let (Some(done), Some(total)) = (self.bytes_done, self.bytes_total)
            && done > total
        {
            return Err(ProgressDataError::BytesOverTotal);
        }
        match (&self.failure, self.event == ProgressEvent::Failed) {
            (Some(f), true) => {
                f.validate()?;
                if f.step != self.step {
                    return Err(ProgressDataError::FailureStepMismatch);
                }
            }
            (None, false) => {}
            _ => return Err(ProgressDataError::FailureMismatch),
        }
        Ok(())
    }
}

/// `200` response to a progress report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgressAckV1 {
    /// Highest sequence number the server has accepted.
    pub ack_seq: u64,
    /// The job's state now.
    pub job_state: JobState,
}

// ---------------------------------------------------------------------------
// M4: progress schema 2, nine steps (M4 plan WU-4, section 0 item 4)
// ---------------------------------------------------------------------------

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - closed step set,
//   self-consistency of each v2 report.
// - NIST 800-53: AU-12 (Audit Record Generation, basis) - steps 1 to 9
//   are the units the server audits (REQ-SEQ-007).
// - SPEC: specs/workflow.md#REQ-SEQ-002 (nine steps in order),
//   #REQ-SEQ-006 (success only after the last step), #REQ-SEQ-007

/// The progress schema of v2 jobs.
pub const PROGRESS_SCHEMA_V2: u32 = 2;

closed_enum!(
    /// What a v2 step does (REQ-SEQ-002; M4 plan section 1.1).
    StepKindV2, "step kind" {
        /// Step 1: download and verify all content (image, driver
        /// archives, agent package).
        VerifyContent => "verify_content",
        /// Step 2: wipe, partition and format.
        PartitionFormat => "partition_format",
        /// Step 3: apply the image.
        ApplyImage => "apply_image",
        /// Step 4: add drivers to the applied image.
        AddDrivers => "add_drivers",
        /// Step 5: place the answer file and post-setup files.
        PlaceConfig => "place_config",
        /// Step 6: make the disk bootable and restart.
        MakeBootableRestart => "make_bootable_restart",
        /// Step 7: Windows setup, tags, administrator password.
        WindowsSetup => "windows_setup",
        /// Step 8: install the management agent.
        InstallAgent => "install_agent",
        /// Step 9: report the endpoint ready.
        ReportReady => "report_ready",
    }
);

/// A v2 job step, 1 to 9 (JSON integer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(transparent)]
pub struct StepV2(u8);

/// A step number outside 1 to 9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("step must be 1 to 9")]
pub struct BadStepV2;

impl StepV2 {
    /// Step 1, verify content.
    pub const VERIFY_CONTENT: Self = Self(1);
    /// Step 2, partition and format.
    pub const PARTITION_FORMAT: Self = Self(2);
    /// Step 3, apply the image.
    pub const APPLY_IMAGE: Self = Self(3);
    /// Step 4, add drivers.
    pub const ADD_DRIVERS: Self = Self(4);
    /// Step 5, place configuration.
    pub const PLACE_CONFIG: Self = Self(5);
    /// Step 6, make bootable and restart.
    pub const MAKE_BOOTABLE_RESTART: Self = Self(6);
    /// Step 7, Windows setup.
    pub const WINDOWS_SETUP: Self = Self(7);
    /// Step 8, install the agent.
    pub const INSTALL_AGENT: Self = Self(8);
    /// Step 9, report ready.
    pub const REPORT_READY: Self = Self(9);
    /// The last step.
    pub const LAST: Self = Self::REPORT_READY;
    /// All steps in order.
    pub const ALL: [Self; 9] = [
        Self::VERIFY_CONTENT,
        Self::PARTITION_FORMAT,
        Self::APPLY_IMAGE,
        Self::ADD_DRIVERS,
        Self::PLACE_CONFIG,
        Self::MAKE_BOOTABLE_RESTART,
        Self::WINDOWS_SETUP,
        Self::INSTALL_AGENT,
        Self::REPORT_READY,
    ];

    /// The step with this number.
    ///
    /// # Errors
    ///
    /// [`BadStepV2`] outside 1 to 9.
    pub const fn new(n: u8) -> Result<Self, BadStepV2> {
        if n >= 1 && n <= 9 {
            Ok(Self(n))
        } else {
            Err(BadStepV2)
        }
    }

    /// The number, 1 to 9.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// What the step does.
    #[must_use]
    pub const fn kind(self) -> StepKindV2 {
        match self.0 {
            1 => StepKindV2::VerifyContent,
            2 => StepKindV2::PartitionFormat,
            3 => StepKindV2::ApplyImage,
            4 => StepKindV2::AddDrivers,
            5 => StepKindV2::PlaceConfig,
            6 => StepKindV2::MakeBootableRestart,
            7 => StepKindV2::WindowsSetup,
            8 => StepKindV2::InstallAgent,
            _ => StepKindV2::ReportReady,
        }
    }

    /// The step after this one, or `None` after step 9.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        if self.0 < 9 {
            Some(Self(self.0 + 1))
        } else {
            None
        }
    }

    /// `true` for steps 7 to 9, which run in the installed Windows and
    /// report with the resume token, not the session token (M4 plan
    /// section 3.1).
    #[must_use]
    pub const fn runs_after_restart(self) -> bool {
        self.0 >= 7
    }
}

impl fmt::Display for StepV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.0, self.kind())
    }
}

impl<'de> serde::Deserialize<'de> for StepV2 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let n = u8::deserialize(d)?;
        Self::new(n).map_err(serde::de::Error::custom)
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FailureV2Wire {
    step: StepV2,
    category: FailureCategory,
    code: ErrorCode,
    #[serde(default)]
    files: Vec<ProgressItemV1>,
    count: u32,
    attempts: u32,
}

/// A v2 failure: as [`FailureV1`], for steps 1 to 9.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "FailureV2Wire")]
pub struct FailureV2 {
    /// Step that failed.
    pub step: StepV2,
    /// Category.
    pub category: FailureCategory,
    /// Reason code (for example `driver_not_staged:<archive>:<inf>`).
    pub code: ErrorCode,
    /// Files that failed (at most [`MAX_FAILED_FILES`]).
    pub files: Vec<ProgressItemV1>,
    /// How many files failed (at least `files.len()`).
    pub count: u32,
    /// Attempts made (1 to [`MAX_REPORTED_ATTEMPTS`]).
    pub attempts: u32,
}

impl TryFrom<FailureV2Wire> for FailureV2 {
    type Error = ProgressDataError;

    fn try_from(w: FailureV2Wire) -> Result<Self, Self::Error> {
        let f = Self {
            step: w.step,
            category: w.category,
            code: w.code,
            files: w.files,
            count: w.count,
            attempts: w.attempts,
        };
        f.validate()?;
        Ok(f)
    }
}

impl FailureV2 {
    /// Checks the bounds (as [`FailureV1::validate`]).
    ///
    /// # Errors
    ///
    /// [`ProgressDataError`].
    pub fn validate(&self) -> Result<(), ProgressDataError> {
        if self.files.len() > MAX_FAILED_FILES {
            return Err(ProgressDataError::TooManyFiles);
        }
        if usize::try_from(self.count).is_ok_and(|c| c < self.files.len()) {
            return Err(ProgressDataError::CountBelowFiles);
        }
        if self.attempts == 0 || self.attempts > MAX_REPORTED_ATTEMPTS {
            return Err(ProgressDataError::BadAttempts);
        }
        Ok(())
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgressV2Wire {
    schema: u32,
    seq: u64,
    step: StepV2,
    event: ProgressEvent,
    #[serde(default)]
    bytes_done: Option<u64>,
    #[serde(default)]
    bytes_total: Option<u64>,
    #[serde(default)]
    item: Option<ProgressItemV1>,
    #[serde(default)]
    layout: Option<LayoutReportV1>,
    #[serde(default)]
    restart_pending: Option<bool>,
    #[serde(default)]
    failure: Option<FailureV2>,
}

/// A v2 progress report (schema 2; M4 plan section 3.1). Steps 1 to 6
/// are sent with the session token, steps 7 to 9 with the resume token
/// (the server enforces which).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "ProgressV2Wire")]
pub struct ProgressV2 {
    /// Always [`PROGRESS_SCHEMA_V2`].
    pub schema: u32,
    /// Strictly increasing per job, from 1 (continues across the
    /// restart).
    pub seq: u64,
    /// Current step.
    pub step: StepV2,
    /// What happened.
    pub event: ProgressEvent,
    /// Bytes done in the step.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_done: Option<u64>,
    /// Bytes the step will handle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_total: Option<u64>,
    /// File being fetched or written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub item: Option<ProgressItemV1>,
    /// The layout written (after step 2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout: Option<LayoutReportV1>,
    /// The agent installer asked for a restart (exit 3010), which the
    /// runner never performs; only on step 8 `step_completed` (M4 plan
    /// section 1.7).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_pending: Option<bool>,
    /// The failure, on and only on a `failed` event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<FailureV2>,
}

impl TryFrom<ProgressV2Wire> for ProgressV2 {
    type Error = ProgressDataError;

    fn try_from(w: ProgressV2Wire) -> Result<Self, Self::Error> {
        let p = Self {
            schema: w.schema,
            seq: w.seq,
            step: w.step,
            event: w.event,
            bytes_done: w.bytes_done,
            bytes_total: w.bytes_total,
            item: w.item,
            layout: w.layout,
            restart_pending: w.restart_pending,
            failure: w.failure,
        };
        p.validate()?;
        Ok(p)
    }
}

impl ProgressV2 {
    /// Checks what one report can say about itself.
    ///
    /// # Errors
    ///
    /// [`ProgressDataError`].
    pub fn validate(&self) -> Result<(), ProgressDataError> {
        if self.schema != PROGRESS_SCHEMA_V2 {
            return Err(ProgressDataError::BadSchema);
        }
        if self.seq == 0 {
            return Err(ProgressDataError::BadSeq);
        }
        if let (Some(done), Some(total)) = (self.bytes_done, self.bytes_total)
            && done > total
        {
            return Err(ProgressDataError::BytesOverTotal);
        }
        if self.event == ProgressEvent::Succeeded && self.step != StepV2::LAST {
            return Err(ProgressDataError::SucceededBeforeLastStep);
        }
        if self.restart_pending.is_some()
            && !(self.step == StepV2::INSTALL_AGENT && self.event == ProgressEvent::StepCompleted)
        {
            return Err(ProgressDataError::RestartPendingMisplaced);
        }
        match (&self.failure, self.event == ProgressEvent::Failed) {
            (Some(f), true) => {
                f.validate()?;
                if f.step != self.step {
                    return Err(ProgressDataError::FailureStepMismatch);
                }
            }
            (None, false) => {}
            _ => return Err(ProgressDataError::FailureMismatch),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_match_spec() {
        use JobState::*;
        let allowed = [
            (Running, Succeeded),
            (Running, Failed),
            (Running, Lost),
            (Lost, Running),
            (Lost, Failed),
            (Lost, Succeeded),
        ];
        for from in JobState::ALL {
            for to in JobState::ALL {
                assert_eq!(
                    from.can_become(*to),
                    allowed.contains(&(*from, *to)),
                    "{from} -> {to}"
                );
            }
        }
        assert!(Succeeded.is_final() && Failed.is_final());
        assert!(!Running.is_final() && !Lost.is_final());
        let states: Vec<_> = JobState::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(states, ["running", "succeeded", "failed", "lost"]);
    }

    #[test]
    fn steps() {
        assert!(Step::new(0).is_err());
        assert!(Step::new(6).is_err());
        let kinds: Vec<_> = Step::ALL.iter().map(|s| s.kind().as_str()).collect();
        assert_eq!(
            kinds,
            [
                "verify_content",
                "partition_format",
                "apply_image",
                "make_bootable",
                "report_restart"
            ]
        );
        assert_eq!(Step::MAKE_BOOTABLE.next(), Some(Step::REPORT_RESTART));
        assert_eq!(Step::REPORT_RESTART.next(), None);
        assert!(serde_json::from_str::<Step>("0").is_err());
        assert!(serde_json::from_str::<Step>("6").is_err());
        assert!(serde_json::from_str::<Step>("-1").is_err());
        assert!(serde_json::from_str::<Step>("\"1\"").is_err());
        assert_eq!(
            serde_json::from_str::<Step>("3").unwrap(),
            Step::APPLY_IMAGE
        );
    }

    #[test]
    fn only_network_is_retried() {
        for c in FailureCategory::ALL {
            assert_eq!(c.may_retry(), *c == FailureCategory::Network);
        }
    }

    #[test]
    fn steps_v2() {
        assert!(StepV2::new(0).is_err());
        assert!(StepV2::new(10).is_err());
        let kinds: Vec<_> = StepV2::ALL.iter().map(|s| s.kind().as_str()).collect();
        assert_eq!(
            kinds,
            [
                "verify_content",
                "partition_format",
                "apply_image",
                "add_drivers",
                "place_config",
                "make_bootable_restart",
                "windows_setup",
                "install_agent",
                "report_ready"
            ]
        );
        let all: Vec<_> = StepKindV2::ALL.to_vec();
        let by_step: Vec<_> = StepV2::ALL.iter().map(|s| s.kind()).collect();
        assert_eq!(all, by_step);
        for (i, s) in StepV2::ALL.iter().enumerate() {
            assert_eq!(usize::from(s.get()), i + 1);
            assert_eq!(s.runs_after_restart(), s.get() >= 7);
        }
        assert_eq!(StepV2::INSTALL_AGENT.next(), Some(StepV2::REPORT_READY));
        assert_eq!(StepV2::REPORT_READY.next(), None);
        assert!(serde_json::from_str::<StepV2>("10").is_err());
        assert_eq!(serde_json::from_str::<StepV2>("9").unwrap(), StepV2::LAST);
    }

    fn v2(json: &str) -> Result<ProgressV2, serde_json::Error> {
        serde_json::from_str(json)
    }

    #[test]
    fn progress_v2_rules() {
        let ok = v2(r#"{"schema":2,"seq":1,"step":7,"event":"step_started"}"#).unwrap();
        assert_eq!(ok.step, StepV2::WINDOWS_SETUP);
        let back = serde_json::to_string(&ok).unwrap();
        assert_eq!(v2(&back).unwrap(), ok);
        // Schema 1 or missing schema refused.
        assert!(v2(r#"{"schema":1,"seq":1,"step":1,"event":"step_started"}"#).is_err());
        assert!(v2(r#"{"seq":1,"step":1,"event":"step_started"}"#).is_err());
        // Succeeded only on step 9.
        assert!(v2(r#"{"schema":2,"seq":5,"step":6,"event":"succeeded"}"#).is_err());
        assert!(v2(r#"{"schema":2,"seq":5,"step":9,"event":"succeeded"}"#).is_ok());
        // restart_pending only on step 8 step_completed.
        assert!(
            v2(r#"{"schema":2,"seq":5,"step":8,"event":"step_completed","restart_pending":true}"#)
                .is_ok()
        );
        assert!(
            v2(r#"{"schema":2,"seq":5,"step":9,"event":"step_completed","restart_pending":true}"#)
                .is_err()
        );
        // Failures, with M4 codes and roles.
        let f = r#"{"schema":2,"seq":3,"step":4,"event":"failed","failure":{"step":4,"category":"local","code":"driver_not_staged:abc:x.inf","files":[{"role":"driver_archive","name":"net.zip"}],"count":1,"attempts":1}}"#;
        assert_eq!(
            v2(f).unwrap().failure.unwrap().code.base(),
            "driver_not_staged"
        );
        let wrong_step = f.replace(r#""failure":{"step":4"#, r#""failure":{"step":5"#);
        assert!(v2(&wrong_step).is_err());
        assert!(v2(r#"{"schema":2,"seq":3,"step":4,"event":"failed"}"#).is_err());
        assert!(v2(r#"{"schema":2,"seq":3,"step":4,"event":"progress","x":1}"#).is_err());
    }
}
