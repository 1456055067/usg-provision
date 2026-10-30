//! M4 job steps 4 to 6 in Windows PE (M4 plan WU-7, §1.1).
//!
//! [`PrebootTail`] runs the steps of a verified v2 plan that follow the
//! apply, driven by the plan's own step table (each entry's kind picks the
//! step, its timeout bounds it):
//!
//! - 4 `add_drivers` ([`drivers`]);
//! - 5 `place_config` ([`config`]);
//! - 6 `make_bootable_restart`: boot files and the firmware option first
//!   in `BootOrder` (as M3 step 4), then `step_completed` is delivered and
//!   acknowledged, which makes the server add the boot stop and close the
//!   Windows PE session (M4 plan §3.1). The caller then restarts.
//!
//! Steps 7 to 9 run after the restart in the post-setup runner
//! ([`crate::postsetup`]). A failure stops the job, is reported `failed`
//! (best effort) and is returned.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 - content re-verified before use (steps 4, 5).
// - NIST 800-53: AU-12 (basis) - every step start, completion and failure
//   reported (REQ-SEQ-007).
// - NIST 800-53: SC-5 - per-step timeouts from the signed plan.
// - NIST 800-53: SI-11 - named failures without secrets.
// - SPEC: specs/workflow.md#REQ-SEQ-001, #REQ-SEQ-002, #REQ-SEQ-008
// - DECISION: docs/decisions/0024, 0025

pub mod config;
pub mod drivers;

use std::time::Duration;

use usgp_crypto::CryptoProvider;
use usgp_disk::Part;
use usgp_disk::uefi::UefiLimits;
use usgp_proto::job_plan::{RetryPolicyV1, VerifiedJobPlanV2};
use usgp_proto::progress::{FailureCategory, ProgressEvent, ProgressV2, StepKindV2, StepV2};
use usgp_proto::{ErrorCode, JobId, codes};

use crate::bootentry::{BootEntry, make_windows_first};
use crate::clock::{Clock, TimeLimit, Watch};
use crate::content::{ChunkError, ChunkErrorKind};
use crate::error::{JobFailureV2, code, code_of};
use crate::link::ServerLinkV2;
use crate::platform::{FormattedVolume, Platform, PlatformError, PlatformErrorKind};
use crate::report_v2::{Must, ReporterV2};

pub use config::{PostSetupInputs, SETUP_COMPLETE_CMD};
pub use drivers::{DriverArchive, DriverCheck, DriverStepConfig};

/// What one step needs besides the platform and the link.
pub struct StepCtx<'a> {
    /// Digests and the DRBG.
    pub(crate) crypto: &'a dyn CryptoProvider,
    /// Time.
    pub(crate) clock: &'a dyn Clock,
    /// The job.
    pub(crate) job: JobId,
    /// The plan's retry policy.
    pub(crate) retry: RetryPolicyV1,
    /// The step's time limits.
    pub(crate) watch: &'a Watch<'a>,
}

/// A failure of category `local`.
pub(crate) fn local(s: StepV2, c: ErrorCode, msg: impl Into<String>) -> JobFailureV2 {
    JobFailureV2::new(s, FailureCategory::Local, c, msg)
}

/// A platform failure, by kind.
pub(crate) fn platform_failure(s: StepV2, c: ErrorCode, e: PlatformError) -> JobFailureV2 {
    let category = match e.kind {
        PlatformErrorKind::IdentityMismatch | PlatformErrorKind::Refused => {
            FailureCategory::Refused
        }
        PlatformErrorKind::Timeout => FailureCategory::Timeout,
        _ => FailureCategory::Local,
    };
    JobFailureV2::new(s, category, c, e.to_string())
}

/// A content failure while re-verifying `what`.
pub(crate) fn chunk_failure(s: StepV2, what: &str, c: ChunkError) -> JobFailureV2 {
    let (category, code) = match c.kind {
        ChunkErrorKind::Network => (FailureCategory::Network, code_of(code::SERVER_UNREACHABLE)),
        ChunkErrorKind::Protocol => (FailureCategory::Network, code_of(code::SERVER_REFUSED)),
        ChunkErrorKind::NotFound => (FailureCategory::Refused, code_of(code::CONTENT_NOT_FOUND)),
        ChunkErrorKind::Refused => (FailureCategory::Refused, code_of(code::SERVER_REFUSED)),
        ChunkErrorKind::ServerIntegrity => (FailureCategory::Integrity, codes::INTEGRITY_FAILED),
        ChunkErrorKind::Digest => (FailureCategory::Integrity, codes::CHUNK_DIGEST_MISMATCH),
        ChunkErrorKind::Length if c.attempts == 0 => (
            FailureCategory::Refused,
            code_of(code::AGENT_PACKAGE_INVALID),
        ),
        ChunkErrorKind::Length => (FailureCategory::Integrity, codes::CHUNK_DIGEST_MISMATCH),
        ChunkErrorKind::NoDigest => (FailureCategory::Integrity, codes::CONTENT_MANIFEST_MISMATCH),
        ChunkErrorKind::StepTimeout => (FailureCategory::Timeout, codes::STEP_TIMEOUT),
        ChunkErrorKind::Stalled => (FailureCategory::Timeout, codes::STALLED),
    };
    let mut f = JobFailureV2::new(s, category, code, format!("{what}: {c}"));
    f.attempts = c.attempts.max(1);
    f
}

/// Fails the step if its time ran out.
pub(crate) fn time_check(s: StepV2, w: &Watch<'_>) -> Result<(), JobFailureV2> {
    match w.check() {
        Ok(()) => Ok(()),
        Err(TimeLimit::Step) => Err(JobFailureV2::new(
            s,
            FailureCategory::Timeout,
            codes::STEP_TIMEOUT,
            "the step ran past its time limit",
        )),
        Err(TimeLimit::Stall) => Err(JobFailureV2::new(
            s,
            FailureCategory::Timeout,
            codes::STALLED,
            "the step made no progress for too long",
        )),
    }
}

/// The step's watch: the plan's timeout, and the stall limit for steps
/// that move content.
pub(crate) fn watch_for<'c>(
    clock: &'c dyn Clock,
    timeout_s: Option<u32>,
    stall_s: Option<u32>,
) -> Watch<'c> {
    // `validate` guarantees every step has a timeout; the fallback is the
    // shortest allowed value (fail early, never late).
    let t = Duration::from_secs(u64::from(timeout_s.unwrap_or(1)));
    let stall = stall_s.map_or(Duration::MAX, |s| Duration::from_secs(u64::from(s)));
    Watch::start(clock, t, stall)
}

/// Settings for steps 4 to 6 that are not in the signed plan.
#[derive(Debug, Clone, Default)]
pub struct TailConfig {
    /// Step 4 bounds.
    pub drivers: DriverStepConfig,
    /// Largest agent package held in memory at step 5, in bytes; 0 means
    /// the default of 2 GiB (`agent_package.max_bytes`, M4 plan §3.6).
    pub max_agent_package_bytes: u64,
    /// Bounds for parsing firmware variables (step 6).
    pub uefi_limits: UefiLimits,
}

/// The state after step 3: the formatted volumes and the ESP partition.
#[derive(Debug, Clone, Copy)]
pub struct AfterApply<'v> {
    /// The EFI system volume.
    pub esp: &'v FormattedVolume,
    /// The Windows volume.
    pub windows: &'v FormattedVolume,
    /// The ESP partition as written (for the firmware boot option).
    pub esp_part: &'v Part,
    /// The last progress sequence number sent in steps 1 to 3.
    pub last_seq: u64,
}

/// Steps 4 to 6 done; the caller restarts the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TailDone {
    /// What step 4 checked.
    pub drivers: DriverCheck,
    /// The boot option made first.
    pub boot: BootEntry,
    /// The reports the server acknowledged, in order.
    pub reports: Vec<ProgressV2>,
}

/// Runs steps 4 to 6 of a verified v2 plan.
pub struct PrebootTail<'a> {
    crypto: &'a dyn CryptoProvider,
    clock: &'a dyn Clock,
    config: TailConfig,
}

impl std::fmt::Debug for PrebootTail<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrebootTail")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<'a> PrebootTail<'a> {
    /// Steps 4 to 6 with `crypto` and `clock`.
    #[must_use]
    pub fn new(crypto: &'a dyn CryptoProvider, clock: &'a dyn Clock, config: TailConfig) -> Self {
        Self {
            crypto,
            clock,
            config,
        }
    }

    /// Runs steps 4, 5 and 6 in the plan's order, stopping at the first
    /// failure, which is reported `failed` (best effort) and returned.
    ///
    /// # Errors
    ///
    /// [`JobFailureV2`].
    pub fn run(
        &self,
        plan: &VerifiedJobPlanV2,
        after: &AfterApply<'_>,
        inputs: &PostSetupInputs<'_>,
        platform: &mut dyn Platform,
        link: &mut dyn ServerLinkV2,
    ) -> Result<TailDone, JobFailureV2> {
        let p = plan.plan();
        let mut rep = ReporterV2::new(p.job_id, after.last_seq);
        match self.steps(plan, after, inputs, platform, link, &mut rep) {
            Ok(mut done) => {
                done.reports = rep.delivered().to_vec();
                Ok(done)
            }
            Err(f) => {
                // Best effort: the device shows the failure either way.
                let _ = rep.deliver(
                    &mut *link,
                    self.clock,
                    &p.retry,
                    None,
                    Must::failed(f.to_wire()),
                );
                Err(f)
            }
        }
    }

    fn steps(
        &self,
        plan: &VerifiedJobPlanV2,
        after: &AfterApply<'_>,
        inputs: &PostSetupInputs<'_>,
        platform: &mut dyn Platform,
        link: &mut dyn ServerLinkV2,
        rep: &mut ReporterV2,
    ) -> Result<TailDone, JobFailureV2> {
        let p = plan.plan();
        let mut drivers = None;
        let mut boot = None;
        for entry in p.steps.iter().filter(|s| {
            matches!(
                s.kind,
                StepKindV2::AddDrivers | StepKindV2::PlaceConfig | StepKindV2::MakeBootableRestart
            )
        }) {
            let s = entry.step;
            let stall = (s != StepV2::MAKE_BOOTABLE_RESTART).then_some(p.stall_timeout_s);
            let watch = watch_for(self.clock, Some(entry.timeout_s), stall);
            rep.state(&mut *link, s, ProgressEvent::StepStarted);
            let ctx = StepCtx {
                crypto: self.crypto,
                clock: self.clock,
                job: p.job_id,
                retry: p.retry,
                watch: &watch,
            };
            match entry.kind {
                StepKindV2::AddDrivers => {
                    let archives: Vec<DriverArchive<'_>> = p
                        .drivers
                        .iter()
                        .zip(plan.driver_manifests())
                        .map(|(plan, manifest)| DriverArchive { plan, manifest })
                        .collect();
                    drivers = Some(drivers::add_drivers(
                        &ctx,
                        &archives,
                        &self.config.drivers,
                        platform,
                        &mut *link,
                    )?);
                    rep.state(&mut *link, s, ProgressEvent::StepCompleted);
                }
                StepKindV2::PlaceConfig => {
                    let max = match self.config.max_agent_package_bytes {
                        0 => 2 << 30,
                        n => n,
                    };
                    config::place_config(
                        &ctx,
                        p,
                        plan.agent_manifest(),
                        inputs,
                        max,
                        platform,
                        &mut *link,
                    )?;
                    rep.state(&mut *link, s, ProgressEvent::StepCompleted);
                }
                _ => {
                    boot = Some(self.make_bootable(s, after, platform, &watch)?);
                    // Must reach the server: it adds the boot stop and
                    // allows the resume only after this (M4 plan §3.1).
                    match rep.deliver(
                        &mut *link,
                        self.clock,
                        &p.retry,
                        Some(&watch),
                        Must::event(s, ProgressEvent::StepCompleted),
                    ) {
                        Ok(_) => {}
                        Err(e) => {
                            let mut f = JobFailureV2::new(
                                s,
                                if e.is_transient() {
                                    FailureCategory::Network
                                } else {
                                    FailureCategory::Refused
                                },
                                if e.is_transient() {
                                    code_of(code::SERVER_UNREACHABLE)
                                } else {
                                    code_of(code::SERVER_REFUSED)
                                },
                                "the server did not accept the restart report",
                            );
                            f.attempts = p.retry.attempts;
                            return Err(f);
                        }
                    }
                }
            }
        }
        match (drivers, boot) {
            (Some(drivers), Some(boot)) => Ok(TailDone {
                drivers,
                boot,
                reports: Vec::new(),
            }),
            _ => Err(local(
                StepV2::ADD_DRIVERS,
                codes::INTERNAL,
                "the plan's step table is incomplete",
            )),
        }
    }

    /// Step 6 before its report: boot files, then the firmware option
    /// first (as M3 step 4; REQ-BOOT-065, REQ-BOOT-066).
    fn make_bootable(
        &self,
        s: StepV2,
        after: &AfterApply<'_>,
        platform: &mut dyn Platform,
        watch: &Watch<'_>,
    ) -> Result<BootEntry, JobFailureV2> {
        platform
            .boot_files()
            .create(after.esp, after.windows)
            .map_err(|e| platform_failure(s, code_of(code::BOOT_FILES_FAILED), e))?;
        time_check(s, watch)?;
        let boot = make_windows_first(
            platform.firmware(),
            after.esp_part,
            &self.config.uefi_limits,
        )
        .map_err(|e| local(s, code_of(code::BOOT_ENTRY_FAILED), e.to_string()))?;
        time_check(s, watch)?;
        Ok(boot)
    }
}
