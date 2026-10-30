//! The job's failure: what the device shows until the person acts, and
//! what the operator sees (REQ-JOB-005, REQ-JOB-006).
//!
//! A [`JobFailure`] names the step, the category (network, integrity,
//! refusal, local, timeout), a stable reason code, the files that failed
//! and how many, and the attempts made. Its text is built from fixed words
//! and numbers only: never a secret, a token, a key or disk content
//! (REQ-JOB-014, REQ-DISK-016).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-11 (Error Handling) - named, persistent failures; no
//   secrets or content in messages.
// - SPEC: specs/progress.md#REQ-JOB-005, #REQ-JOB-006, #REQ-JOB-011,
//   #REQ-JOB-014; specs/disk.md#REQ-DISK-013

use std::fmt;

use usgp_proto::ErrorCode;
use usgp_proto::codes;
use usgp_proto::progress::{FailureCategory, FailureV1, FailureV2, ProgressItemV1, Step, StepV2};

/// Reason codes this crate adds to the shared table in `usgp-proto`
/// (syntax checked by a unit test; same rules as every other code).
pub mod code {
    /// The opened disk is ineligible now (removable, boot media, USB, too
    /// small, ...), although the plan named it.
    pub const DISK_NOT_ELIGIBLE: &str = "disk_not_eligible";
    /// The platform could not open the planned disk.
    pub const DISK_OPEN_FAILED: &str = "disk_open_failed";
    /// The wipe guard refused: no durable wipe record in the plan.
    pub const WIPE_NOT_AUTHORISED: &str = "wipe_not_authorised";
    /// A write to the disk failed.
    pub const DISK_WRITE_FAILED: &str = "disk_write_failed";
    /// The GPT read back after writing is invalid or differs from the plan.
    pub const GPT_READBACK_FAILED: &str = "gpt_readback_failed";
    /// The layout could not be planned for the disk.
    pub const LAYOUT_FAILED: &str = "layout_failed";
    /// Formatting the volumes failed, or the result differs from the plan.
    pub const FORMAT_FAILED: &str = "format_failed";
    /// Creating the boot files failed.
    pub const BOOT_FILES_FAILED: &str = "boot_files_failed";
    /// Writing or reading back the firmware boot option or `BootOrder`
    /// failed.
    pub const BOOT_ENTRY_FAILED: &str = "boot_entry_failed";
    /// The random source failed.
    pub const RANDOM_FAILED: &str = "random_failed";
    /// A content chunk is not on the server (404).
    pub const CONTENT_NOT_FOUND: &str = "content_not_found";
    /// The server refused the request (for example, the job is not running).
    pub const SERVER_REFUSED: &str = "server_refused";
    /// The server could not be reached, after every retry.
    pub const SERVER_UNREACHABLE: &str = "server_unreachable";
    /// The server did not accept the success report.
    pub const SUCCESS_NOT_ACCEPTED: &str = "success_not_accepted";
    /// The Windows volume's apply root is not a bare drive letter, or none
    /// is free (same text as `usgp-image`'s `ApplyRootError` code).
    pub const APPLY_ROOT_UNSUPPORTED: &str = "apply_root_unsupported";
    /// M4: the driver listing could not be read or parsed (step 4).
    pub const DRIVER_LIST_FAILED: &str = "driver_list_failed";
    /// M4: a file could not be written to the Windows volume (step 5).
    pub const CONFIG_WRITE_FAILED: &str = "config_write_failed";
    /// M4: the answer file at the Panther path could not be deleted, or
    /// is still there after deletion (step 7).
    pub const ANSWER_FILE_NOT_REMOVED: &str = "answer_file_not_removed";
    /// M4: the administrator password's memory could not be locked
    /// (step 7; nothing was generated or sent).
    pub const SECRET_MEMORY_LOCK_FAILED: &str = "secret_memory_lock_failed";
    /// M4: the agent package could not be extracted or its `agent.json` is
    /// missing or invalid (step 8).
    pub const AGENT_PACKAGE_INVALID: &str = "agent_package_invalid";

    /// Every code above.
    pub const ALL: &[&str] = &[
        DISK_NOT_ELIGIBLE,
        DISK_OPEN_FAILED,
        WIPE_NOT_AUTHORISED,
        DISK_WRITE_FAILED,
        GPT_READBACK_FAILED,
        LAYOUT_FAILED,
        FORMAT_FAILED,
        BOOT_FILES_FAILED,
        BOOT_ENTRY_FAILED,
        RANDOM_FAILED,
        CONTENT_NOT_FOUND,
        SERVER_REFUSED,
        SERVER_UNREACHABLE,
        SUCCESS_NOT_ACCEPTED,
        APPLY_ROOT_UNSUPPORTED,
        DRIVER_LIST_FAILED,
        CONFIG_WRITE_FAILED,
        ANSWER_FILE_NOT_REMOVED,
        SECRET_MEMORY_LOCK_FAILED,
        AGENT_PACKAGE_INVALID,
    ];
}

/// A code from text this crate controls. Falls back to `internal` if the
/// text breaks the syntax rules (a unit test shows none does).
pub(crate) fn code_of(text: &'static str) -> ErrorCode {
    ErrorCode::new(text).unwrap_or(codes::INTERNAL)
}

/// Design bound on a failure message, in characters.
pub const MAX_MESSAGE_CHARS: usize = 512;

/// Text safe for the device console: control characters become `?` (no
/// terminal escape sequences, even from a signed plan's parse error), and
/// at most [`MAX_MESSAGE_CHARS`] characters are kept.
fn screen_text(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .take(MAX_MESSAGE_CHARS)
        .collect()
}

/// A failed job, as shown at the device and reported to the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobFailure {
    /// The step that failed.
    pub step: Step,
    /// Network, integrity, refusal, local or timeout.
    pub category: FailureCategory,
    /// Stable reason code.
    pub code: ErrorCode,
    /// The files that failed (at most 32), for content failures.
    pub files: Vec<ProgressItemV1>,
    /// How many files failed (at least `files.len()`).
    pub count: u32,
    /// Attempts made (1 if the failure is not retried).
    pub attempts: u32,
    /// Fixed words and numbers for the person and the operator.
    pub message: String,
    /// `false` if the job failed before anything was written to the disk.
    pub disk_written: bool,
}

impl JobFailure {
    /// A failure with no file list and one attempt.
    pub(crate) fn new(
        step: Step,
        category: FailureCategory,
        code: ErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            step,
            category,
            code,
            files: Vec::new(),
            count: 0,
            attempts: 1,
            message: screen_text(&message.into()),
            disk_written: false,
        }
    }

    /// The wire form for the progress report (plan section 3.4).
    #[must_use]
    pub fn to_wire(&self) -> FailureV1 {
        let max = usgp_proto::limits::MAX_FAILED_FILES;
        let files: Vec<ProgressItemV1> = self.files.iter().take(max).cloned().collect();
        let listed = u32::try_from(files.len()).unwrap_or(u32::MAX);
        FailureV1 {
            step: self.step,
            category: self.category,
            code: self.code.clone(),
            files,
            count: self.count.max(listed),
            attempts: self
                .attempts
                .clamp(1, usgp_proto::limits::MAX_REPORTED_ATTEMPTS),
        }
    }
}

impl fmt::Display for JobFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "step {} failed ({}, {}): {}",
            self.step, self.category, self.code, self.message
        )
    }
}

impl std::error::Error for JobFailure {}

/// A failed v2 job step (M4: steps 4 to 9), as shown at the device or
/// recorded by the post-setup runner, and reported to the server. Same
/// rules as [`JobFailure`]: fixed words and numbers, never a secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobFailureV2 {
    /// The step that failed.
    pub step: StepV2,
    /// Network, integrity, refusal, local or timeout.
    pub category: FailureCategory,
    /// Stable reason code, possibly with parameters
    /// (`driver_not_staged:<archive>:<inf>`).
    pub code: ErrorCode,
    /// Attempts made (1 if the failure is not retried).
    pub attempts: u32,
    /// Fixed words and numbers for the person and the operator.
    pub message: String,
}

impl JobFailureV2 {
    /// A failure with one attempt.
    pub(crate) fn new(
        step: StepV2,
        category: FailureCategory,
        code: ErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            step,
            category,
            code,
            attempts: 1,
            message: screen_text(&message.into()),
        }
    }

    /// The wire form for the v2 progress report.
    #[must_use]
    pub fn to_wire(&self) -> FailureV2 {
        FailureV2 {
            step: self.step,
            category: self.category,
            code: self.code.clone(),
            files: Vec::new(),
            count: 0,
            attempts: self
                .attempts
                .clamp(1, usgp_proto::limits::MAX_REPORTED_ATTEMPTS),
        }
    }
}

impl fmt::Display for JobFailureV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "step {} failed ({}, {}): {}",
            self.step, self.category, self.code, self.message
        )
    }
}

impl std::error::Error for JobFailureV2 {}

/// `base:<p1>:<p2>…` with each parameter reduced to the code alphabet
/// (lower case; any other byte becomes `_`) and the whole kept within the
/// code length limit; if even the base does not fit, the base alone.
pub(crate) fn code_with(base: &ErrorCode, params: &[&str]) -> ErrorCode {
    let mut text = base.as_str().to_owned();
    for p in params {
        let clean: String = p
            .chars()
            .map(|c| {
                let c = c.to_ascii_lowercase();
                if c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '.' | '-') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        text.push(':');
        text.push_str(if clean.is_empty() { "_" } else { &clean });
    }
    let max = usgp_proto::limits::MAX_ERROR_CODE_BYTES;
    if text.len() > max {
        // Only ASCII is pushed above, so any byte index is a boundary.
        text.truncate(max);
    }
    ErrorCode::new(text).unwrap_or_else(|_| base.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_codes_are_valid_and_distinct() {
        for (i, c) in code::ALL.iter().enumerate() {
            assert!(ErrorCode::new(*c).is_ok(), "{c}");
            assert_eq!(code_of(c).as_str(), *c);
            assert!(!code::ALL.iter().skip(i + 1).any(|d| d == c), "{c}");
            assert!(!codes::ALL.iter().any(|d| d.as_str() == *c), "{c}");
        }
    }

    #[test]
    fn messages_are_screen_safe_and_bounded() {
        let f = JobFailure::new(
            Step::VERIFY_CONTENT,
            FailureCategory::Integrity,
            codes::INTERNAL,
            format!("a\u{1b}[2Jb\n{}", "x".repeat(2000)),
        );
        assert!(f.message.starts_with("a?[2Jb?x"));
        assert_eq!(f.message.chars().count(), MAX_MESSAGE_CHARS);
    }

    #[test]
    fn wire_form_is_valid() {
        let mut f = JobFailure::new(
            Step::APPLY_IMAGE,
            FailureCategory::Local,
            code_of(code::FORMAT_FAILED),
            "x",
        );
        f.attempts = 0;
        assert!(f.to_wire().validate().is_ok());
        assert_eq!(f.to_wire().attempts, 1);
    }

    #[test]
    fn parameterised_codes_are_valid_and_bounded() {
        let c = code_with(
            &codes::DRIVER_NOT_STAGED,
            &["0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f", "Net Card/E1000.INF"],
        );
        assert_eq!(
            c.as_str(),
            "driver_not_staged:0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f:net_card_e1000.inf"
        );
        let long = "x".repeat(400);
        let c = code_with(&codes::DRIVER_NOT_STAGED, &[&long]);
        assert_eq!(c.as_str().len(), usgp_proto::limits::MAX_ERROR_CODE_BYTES);
        assert_eq!(c.base(), "driver_not_staged");
        assert_eq!(
            code_with(&codes::ESCROW_REFUSED, &[""]).as_str(),
            "escrow_refused:_"
        );
    }

    #[test]
    fn v2_wire_form_is_valid() {
        let mut f = JobFailureV2::new(
            StepV2::ADD_DRIVERS,
            FailureCategory::Local,
            codes::STAGING_NOT_REMOVED,
            "x\u{1b}",
        );
        f.attempts = 0;
        assert!(f.to_wire().validate().is_ok());
        assert_eq!(f.message, "x?");
    }
}
