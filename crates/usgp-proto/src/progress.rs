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
}
