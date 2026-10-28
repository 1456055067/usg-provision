//! The step engine: one job, from the verified plan to the success report
//! (plan sections 1.1 and 3.2 to 3.4).
//!
//! Order, and what each step guarantees before the next starts:
//!
//! 1. `verify_content`: the layout is planned from the signed disk facts
//!    (no I/O) to fix the apply budget; then every chunk the edition needs
//!    is fetched, verified and discarded, and the image is checked as an
//!    apply would ([`verify_pass`]). A tampered chunk, an unsupported
//!    image or a too-large image fails here, **before any disk write**
//!    (decision 0021 item 4; REQ-JOB-008).
//! 2. `partition_format`: the planned disk is opened; its facts must equal
//!    the signed plan's and still be eligible. Only then is the
//!    [`WipeAuthorisation`] built, from the verified plan's durable audit
//!    record (DEC-0018 item 7), and the GPT written and read back
//!    ([`wipe_and_write`]). The volumes are formatted and checked.
//! 3. `apply_image`: the edition is applied to the Windows volume, every
//!    chunk fetched and verified again.
//! 4. `make_bootable`: boot files (BCDBoot through the platform), then the
//!    firmware option, first in `BootOrder` ([`make_windows_first`]).
//! 5. `report_restart`: `succeeded` is delivered and acknowledged
//!    (REQ-JOB-013). The caller then restarts the device (REQ-PE-019).
//!
//! Each step reports `step_started` and `step_completed` (and byte
//! progress while content moves) to the server and the device's screen.
//! A failure stops the job, is shown at the device until the person acts
//! (the engine returns it and never retries the job), and is reported as
//! `failed` (REQ-JOB-005, REQ-JOB-006). There is no cancel: the engine
//! starts after the wipe confirmation (REQ-TGT-011).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7, SI-7(1), SI-7(6) - verify plan, then all content,
//   before any write; verify again during apply.
// - NIST 800-53: AC-3 (Access Enforcement) - WipeAuthorisation built only
//   here, only from a VerifiedJobPlan, after the opened disk matches it.
// - NIST 800-53: AU-10 (Non-repudiation, basis) - the authorisation names
//   the audit sequence and record hash of `disk.wipe.authorised`.
// - NIST 800-53: SC-5 (Denial of Service Protection) - step timeouts,
//   stall detection, bounded retries.
// - NIST 800-53: SI-11 (Error Handling) - named, persistent failures.
// - SPEC: specs/progress.md#REQ-JOB-002..008, #REQ-JOB-011..014
// - SPEC: specs/preinstall-env.md#REQ-PE-016, #REQ-PE-017, #REQ-PE-019
// - SPEC: specs/disk.md#REQ-DISK-004..009, #REQ-DISK-012..015
// - SPEC: specs/boot-network.md#REQ-BOOT-065, #REQ-BOOT-066
// - SPEC: specs/targeting.md#REQ-TGT-011
// - DECISION: docs/decisions/0011, 0018 items 7 to 10, 0021 item 4

use std::cell::{Cell, RefCell};
use std::ops::ControlFlow;
use std::time::Duration;

use usgp_crypto::CryptoProvider;
use usgp_disk::layout::{PartRole, WindowsUefiLayout, minimum_disk_bytes};
use usgp_disk::uefi::UefiLimits;
use usgp_disk::{
    DiskError, DiskFacts, DiskIdentity, EligibilityPolicy, WipeAuthorisation, WipeEvidence,
    WipePlan, assess, wipe_and_write,
};
use usgp_image::apply::{ApplyError, ApplyLimits, ApplyPreview, ApplyRoot, apply, verify_pass};
use usgp_proto::disk::{
    Bus, DiskGuid, LayoutReportV1, PartitionKind, PlanDiskV1, WrittenPartitionV1,
};
use usgp_proto::envelope::SignedEnvelopeV1;
use usgp_proto::job_plan::{PlanExpectation, RetryPolicyV1, VerifiedJobPlan};
use usgp_proto::progress::{
    FailureCategory, FileRole, JobState, ProgressEvent, ProgressItemV1, ProgressV1, Step,
};
use usgp_proto::{DiskText, ItemName, JobId, PartitionLabel, codes};

use crate::bootentry::{BootEntry, make_windows_first};
use crate::clock::{Clock, TimeLimit, Watch};
use crate::content::{ChunkError, ChunkErrorKind, FetchHook, VerifiedChunks};
use crate::error::{JobFailure, code, code_of};
use crate::link::ServerLink;
use crate::plan::{PlanKeys, verify_plan};
use crate::platform::{FormattedVolume, Platform, PlatformError, PlatformErrorKind, VolumeSpec};
use crate::report::Reporter;

/// Design value: the device screen's byte counter moves in steps of at
/// least this much (and at the end).
const VIEW_STEP_BYTES: u64 = 1 << 20;

/// What the device's screen is told (REQ-JOB-002 to REQ-JOB-005). The view
/// keeps a failure on screen until the person acts; the engine never
/// clears it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ViewEvent<'a> {
    /// The job started: what is being installed and the step list.
    Started {
        /// The job.
        job_id: JobId,
        /// The image's display name.
        package: &'a str,
        /// The edition's name.
        edition: &'a str,
        /// Every step, in order.
        steps: &'a [Step],
    },
    /// A step started.
    StepStarted(Step),
    /// Bytes moved in a content step.
    Progress {
        /// The step.
        step: Step,
        /// Bytes done.
        bytes_done: u64,
        /// Bytes in all.
        bytes_total: u64,
        /// The file being fetched.
        item: Option<&'a ProgressItemV1>,
    },
    /// A step completed.
    StepCompleted(Step),
    /// The job failed. Stays on screen until the person acts.
    Failed(&'a JobFailure),
    /// Every step succeeded and the server has the report.
    Succeeded,
}

/// The device's screen.
pub trait JobView {
    /// Shows `event`.
    fn show(&mut self, event: &ViewEvent<'_>);
}

/// Engine settings that are not in the signed plan.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Disk eligibility rules re-checked on the opened disk. The release
    /// default allows no file-backed virtual disk.
    pub eligibility: EligibilityPolicy,
    // POAM: the recovery image size is not known on the device in M3
    // (OPEN-DISK-3); the recovery partition gets the 990 MiB minimum.
    /// Size of the recovery image the recovery partition is sized for.
    /// Not known on the device in M3 (OPEN-DISK-3); 0 gives the minimum
    /// 990 MiB partition (REQ-DISK-008 item 4).
    pub recovery_image_bytes: u64,
    /// Bounds for parsing firmware variables.
    pub uefi_limits: UefiLimits,
    /// Retry for reporting a plan that failed to verify (the plan's own
    /// policy cannot be trusted then).
    pub unverified_report_retry: RetryPolicyV1,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            eligibility: EligibilityPolicy::default(),
            recovery_image_bytes: 0,
            uefi_limits: UefiLimits::default(),
            unverified_report_retry: RetryPolicyV1 {
                attempts: 3,
                base_ms: 2000,
                max_ms: 10_000,
            },
        }
    }
}

/// The signed plan as the confirm response delivered it, with what the
/// device expects it to say (plan section 3.2).
#[derive(Debug, Clone, Copy)]
pub struct SignedJob<'s> {
    /// The job plan envelope.
    pub plan: &'s SignedEnvelopeV1,
    /// The content manifest envelope.
    pub content: &'s SignedEnvelopeV1,
    /// The pinned plan and content keys.
    pub keys: &'s PlanKeys,
    /// The nonce, session, job, package and disk the device expects.
    pub expect: PlanExpectation<'s>,
}

/// A job that succeeded and whose success the server acknowledged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Succeeded {
    /// The job.
    pub job_id: JobId,
    /// The layout written (REQ-DISK-014).
    pub layout: LayoutReportV1,
    /// The boot option made first.
    pub boot: BootEntry,
    /// Bytes the image expanded to on the Windows volume.
    pub image_bytes: u64,
    /// Bytes written by the apply.
    pub bytes_written: u64,
    /// The progress reports the server acknowledged, in order.
    pub reports: Vec<ProgressV1>,
}

/// The engine. Holds no job state; [`Engine::run`] drives one job.
pub struct Engine<'a> {
    crypto: &'a dyn CryptoProvider,
    clock: &'a dyn Clock,
    config: EngineConfig,
}

impl std::fmt::Debug for Engine<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Byte progress of one content step, shared by the chunk source (which
/// sends reports while it holds the link) and the reader's progress hook.
struct Meter<'r> {
    step: Step,
    total: u64,
    item: Option<ProgressItemV1>,
    done: Cell<u64>,
    rep: RefCell<&'r mut Reporter>,
    clock: &'r dyn Clock,
}

impl FetchHook for Meter<'_> {
    fn fetched(&self, link: &mut dyn ServerLink) {
        // The hook is never re-entered; if it were, the report is skipped.
        if let Ok(mut r) = self.rep.try_borrow_mut() {
            r.progress(
                link,
                self.clock.now(),
                self.step,
                self.done.get(),
                self.total,
                self.item.clone(),
            );
        }
    }
}

impl<'a> Engine<'a> {
    /// An engine using `crypto` for digests and the DRBG and `clock` for
    /// time limits.
    #[must_use]
    pub fn new(crypto: &'a dyn CryptoProvider, clock: &'a dyn Clock, config: EngineConfig) -> Self {
        Self {
            crypto,
            clock,
            config,
        }
    }

    /// Verifies the plan and content manifest ([`verify_plan`]), then runs
    /// the job. A plan that does not verify fails step 1 with an integrity
    /// failure, and nothing else happens: no disk is opened.
    ///
    /// # Errors
    ///
    /// [`JobFailure`].
    pub fn verify_and_run(
        &self,
        job: &SignedJob<'_>,
        platform: &mut dyn Platform,
        link: &mut dyn ServerLink,
        view: &mut dyn JobView,
    ) -> Result<Succeeded, JobFailure> {
        match verify_plan(job.plan, job.content, job.keys, &job.expect, self.crypto) {
            Ok(v) => self.run(&v, platform, link, view),
            Err(e) => {
                let f =
                    JobFailure::new(Step::VERIFY_CONTENT, e.category(), e.code(), e.to_string());
                view.show(&ViewEvent::Failed(&f));
                let mut rep = Reporter::new(job.expect.job_id, Duration::from_secs(1));
                // Best effort: the device shows the failure either way.
                let _ = rep.finish(
                    link,
                    self.clock,
                    &self.config.unverified_report_retry,
                    None,
                    f.step,
                    Some(f.to_wire()),
                );
                Err(f)
            }
        }
    }

    /// Runs a verified job: steps 1 to 5, stopping at the first failure.
    ///
    /// # Errors
    ///
    /// [`JobFailure`], already shown on `view` and (if the server can be
    /// reached) reported as `failed`.
    pub fn run(
        &self,
        plan: &VerifiedJobPlan,
        platform: &mut dyn Platform,
        link: &mut dyn ServerLink,
        view: &mut dyn JobView,
    ) -> Result<Succeeded, JobFailure> {
        let p = plan.plan();
        view.show(&ViewEvent::Started {
            job_id: p.job_id,
            package: plan.content_manifest().display_name.as_str(),
            edition: p.image.edition_name.as_str(),
            steps: &Step::ALL,
        });
        let mut run = Run {
            engine: self,
            plan,
            link,
            view,
            rep: Reporter::new(
                p.job_id,
                Duration::from_secs(u64::from(p.report_interval_s)),
            ),
        };
        match run.steps(platform) {
            Ok(mut s) => {
                s.reports = run.rep.delivered().to_vec();
                run.view.show(&ViewEvent::Succeeded);
                Ok(s)
            }
            Err(f) => {
                run.view.show(&ViewEvent::Failed(&f));
                // Best effort: the device keeps showing the failure.
                let _ = run.rep.finish(
                    run.link,
                    self.clock,
                    &p.retry,
                    None,
                    f.step,
                    Some(f.to_wire()),
                );
                Err(f)
            }
        }
    }
}

/// One job in progress.
struct Run<'e, 'a> {
    engine: &'e Engine<'a>,
    plan: &'e VerifiedJobPlan,
    link: &'e mut dyn ServerLink,
    view: &'e mut dyn JobView,
    rep: Reporter,
}

impl<'a> Run<'_, 'a> {
    fn start(&mut self, s: Step) -> Watch<'a> {
        self.view.show(&ViewEvent::StepStarted(s));
        self.rep
            .state(self.link, s, ProgressEvent::StepStarted, None);
        let p = self.plan.plan();
        // `validate` guarantees every step has a timeout; the fallback is
        // the shortest allowed value (fail early, never late).
        let t = p.timeout_s(s).unwrap_or(1);
        // Stall detection applies to the steps that move content; the
        // others make no byte progress to measure.
        let stall = if s == Step::VERIFY_CONTENT || s == Step::APPLY_IMAGE {
            Duration::from_secs(u64::from(p.stall_timeout_s))
        } else {
            Duration::MAX
        };
        Watch::start(self.engine.clock, Duration::from_secs(u64::from(t)), stall)
    }

    fn complete(&mut self, s: Step, layout: Option<LayoutReportV1>) {
        self.view.show(&ViewEvent::StepCompleted(s));
        self.rep
            .state(self.link, s, ProgressEvent::StepCompleted, layout);
    }

    fn steps(&mut self, platform: &mut dyn Platform) -> Result<Succeeded, JobFailure> {
        let p = self.plan.plan();
        let index = p.image.edition_index.get();
        let crypto = self.engine.crypto;

        // ---- Step 1: verify all content; nothing is written. ----
        let s = Step::VERIFY_CONTENT;
        let watch = self.start(s);
        let layout = self.plan_layout(s, &p.disk)?;
        let limits = ApplyLimits::new(layout.windows_bytes());
        // The apply root is fixed now, before the wipe, so the verify pass
        // re-bases links exactly as the apply will (decision 0022).
        let root = windows_root(s, platform)?;
        let preview = self.content_pass(s, &watch, |src, progress| {
            verify_pass(src, index, &root, &limits, progress, crypto)
        })?;
        check_time(s, &watch, false)?;
        self.complete(s, None);

        // ---- Step 2: identity, wipe guard, GPT, format. ----
        let s = Step::PARTITION_FORMAT;
        let watch = self.start(s);
        let (vols, layout_report) = self.partition_format(s, &layout, &preview, &root, platform)?;
        check_time(s, &watch, true)?;
        self.complete(s, Some(layout_report.clone()));

        // ---- Step 3: apply, verifying every chunk again. ----
        let s = Step::APPLY_IMAGE;
        let watch = self.start(s);
        let windows = volume(&vols, PartRole::Windows)
            .ok_or_else(|| local(s, code::FORMAT_FAILED, "no Windows volume", true))?;
        let report = {
            let mut sink = platform
                .volumes()
                .windows_sink(windows)
                .map_err(|e| platform_failure(s, code::FORMAT_FAILED, e, true))?;
            self.content_pass(s, &watch, |src, progress| {
                apply(src, index, &root, &mut *sink, &limits, progress, crypto)
            })
            .map_err(|mut f| {
                f.disk_written = true;
                f
            })?
        };
        check_time(s, &watch, true)?;
        self.complete(s, None);

        // ---- Step 4: boot files, then the firmware option first. ----
        let s = Step::MAKE_BOOTABLE;
        let watch = self.start(s);
        let esp = volume(&vols, PartRole::Esp)
            .ok_or_else(|| local(s, code::FORMAT_FAILED, "no EFI system volume", true))?;
        platform
            .boot_files()
            .create(esp, windows)
            .map_err(|e| platform_failure(s, code::BOOT_FILES_FAILED, e, true))?;
        check_time(s, &watch, true)?;
        let boot = make_windows_first(
            platform.firmware(),
            &layout.esp,
            &self.engine.config.uefi_limits,
        )
        .map_err(|e| local(s, code::BOOT_ENTRY_FAILED, e.to_string(), true))?;
        check_time(s, &watch, true)?;
        self.complete(s, None);

        // ---- Step 5: report success; the caller restarts. ----
        let s = Step::REPORT_RESTART;
        let watch = self.start(s);
        self.report_success(s, &watch)?;
        Ok(Succeeded {
            job_id: p.job_id,
            layout: layout_report,
            boot,
            image_bytes: report.preview.total_bytes,
            bytes_written: report.bytes_written,
            reports: Vec::new(),
        })
    }

    /// Step 5: `succeeded` delivered and acknowledged as Succeeded
    /// (REQ-JOB-013).
    fn report_success(&mut self, s: Step, watch: &Watch<'_>) -> Result<(), JobFailure> {
        let retry = self.plan.plan().retry;
        match self
            .rep
            .finish(self.link, self.engine.clock, &retry, Some(watch), s, None)
        {
            Ok(ack) if ack.job_state == JobState::Succeeded => Ok(()),
            Ok(_) => Err(refused(
                s,
                code::SUCCESS_NOT_ACCEPTED,
                "the server did not record the job as succeeded",
                true,
            )),
            Err(e) => {
                check_time(s, watch, true)?;
                Err(if e.is_transient() {
                    let mut f = JobFailure::new(
                        s,
                        FailureCategory::Network,
                        code_of(code::SERVER_UNREACHABLE),
                        "the success report could not be delivered",
                    );
                    f.attempts = retry.attempts;
                    f.disk_written = true;
                    f
                } else {
                    refused(
                        s,
                        code::SUCCESS_NOT_ACCEPTED,
                        "the server refused the success report",
                        true,
                    )
                })
            }
        }
    }

    /// Plans the layout from the signed disk facts (no I/O). GUIDs come
    /// from the DRBG; a DRBG failure stops the step.
    fn plan_layout(&self, s: Step, disk: &PlanDiskV1) -> Result<WindowsUefiLayout, JobFailure> {
        let facts = facts_from_plan(disk);
        let crypto = self.engine.crypto;
        let rng_failed = Cell::new(false);
        let mut rng = |buf: &mut [u8]| {
            if crypto.fill_random(buf).is_err() {
                rng_failed.set(true);
                buf.fill(0);
            }
        };
        let r =
            WindowsUefiLayout::compute(&facts, self.engine.config.recovery_image_bytes, &mut rng);
        if rng_failed.get() {
            return Err(local(s, code::RANDOM_FAILED, "random source failed", false));
        }
        r.map_err(|e| local(s, code::LAYOUT_FAILED, e.to_string(), false))
    }

    /// Runs a content pass (`verify_pass` or `apply`) over freshly verified
    /// chunks, with byte progress to the screen and the server and the
    /// step's time limits, and names the failure.
    fn content_pass<T>(
        &mut self,
        s: Step,
        watch: &Watch<'_>,
        pass: impl FnOnce(
            &mut VerifiedChunks<'_>,
            &mut dyn usgp_image::Progress,
        ) -> Result<T, ApplyError>,
    ) -> Result<T, JobFailure> {
        let manifest = self.plan.content_manifest();
        let total = manifest.size;
        let item = ItemName::new(manifest.file_name.as_str())
            .ok()
            .map(|name| ProgressItemV1 {
                role: FileRole::Image,
                name,
            });
        let clock = self.engine.clock;
        let meter = Meter {
            step: s,
            total,
            item: item.clone(),
            done: Cell::new(0),
            rep: RefCell::new(&mut self.rep),
            clock,
        };
        let view = &mut *self.view;
        let mut shown: u64 = 0;
        let mut progress = |b: u64| -> ControlFlow<()> {
            let d = meter.done.get().saturating_add(b).min(total);
            meter.done.set(d);
            watch.progress();
            if d >= shown.saturating_add(VIEW_STEP_BYTES) || d == total {
                shown = d;
                view.show(&ViewEvent::Progress {
                    step: s,
                    bytes_done: d,
                    bytes_total: total,
                    item: item.as_ref(),
                });
            }
            if watch.check().is_err() {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        };
        let mut src = VerifiedChunks::new(&mut *self.link, self.engine.crypto, clock, self.plan)
            .with_watch(watch)
            .with_hook(&meter);
        let r = pass(&mut src, &mut progress);
        let chunk = src.failure();
        r.map_err(|e| content_failure(s, &e, chunk, watch, item.as_ref()))
    }

    /// Step 2 after the start report: open, check, authorise, write, read
    /// back, format.
    fn partition_format(
        &self,
        s: Step,
        layout: &WindowsUefiLayout,
        preview: &ApplyPreview,
        root: &ApplyRoot,
        platform: &mut dyn Platform,
    ) -> Result<(Vec<FormattedVolume>, LayoutReportV1), JobFailure> {
        let p = self.plan.plan();
        let config = &self.engine.config;
        let disk_text = format!(
            "disk {} ({} bytes)",
            p.disk.model.as_str(),
            p.disk.size_bytes
        );
        let target = platform.open_target(&p.disk).map_err(|e| {
            let mut f = platform_failure(s, code::DISK_OPEN_FAILED, e, false);
            f.message = format!("{disk_text}: {}", f.message);
            f
        })?;
        if let Err(why) = check_target(&p.disk, &target.facts) {
            return Err(refused_with(
                s,
                codes::DISK_IDENTITY_MISMATCH,
                format!("{disk_text}: {why}"),
                false,
            ));
        }
        let min = minimum_disk_bytes(
            p.disk.logical_sector,
            config.recovery_image_bytes,
            preview.total_bytes,
        )
        .map_err(|e| local(s, code::LAYOUT_FAILED, e.to_string(), false))?;
        if let Err(why) = assess(&target.facts, &config.eligibility, min) {
            return Err(refused(
                s,
                code::DISK_NOT_ELIGIBLE,
                format!("{disk_text}: {why}"),
                false,
            ));
        }
        let wipe = WipePlan::for_disk(layout, &target.facts.partitions)
            .map_err(|e| local(s, code::LAYOUT_FAILED, format!("{disk_text}: {e}"), false))?;

        // The only place a WipeAuthorisation is built: from the verified
        // plan's durable `disk.wipe.authorised` record and the disk the
        // opened device was just checked to be (DEC-0018 item 7).
        let auth = WipeAuthorisation::new(WipeEvidence {
            job_id: p.job_id.to_string(),
            audit_seq: p.wipe.audit_seq,
            audit_record_hash: p.wipe.record_hash.0,
            disk: target.facts.identity.clone(),
            size_bytes: p.disk.size_bytes,
            logical_sector: p.disk.logical_sector,
        });
        let mut device = target.device;
        wipe_and_write(&mut *device, &auth, &wipe, layout)
            .map_err(|e| disk_failure(s, &disk_text, &e))?;

        let specs = VolumeSpec::for_layout(layout);
        let vols = platform
            .volumes()
            .format(&mut *device, layout, &specs, root)
            .map_err(|e| {
                let mut f = platform_failure(s, code::FORMAT_FAILED, e, true);
                f.message = format!("{disk_text}: {}", f.message);
                f
            })?;
        drop(device);
        check_volumes(&specs, &vols, root)
            .map_err(|why| local(s, code::FORMAT_FAILED, format!("{disk_text}: {why}"), true))?;
        let report = layout_report(layout, &vols)
            .ok_or_else(|| local(s, code::LAYOUT_FAILED, "layout cannot be reported", true))?;
        Ok((vols, report))
    }
}

/// A failure of category `local`.
fn local(s: Step, c: &'static str, msg: impl Into<String>, written: bool) -> JobFailure {
    let mut f = JobFailure::new(s, FailureCategory::Local, code_of(c), msg);
    f.disk_written = written;
    f
}

/// A failure of category `refused`.
fn refused(s: Step, c: &'static str, msg: impl Into<String>, written: bool) -> JobFailure {
    refused_with(s, code_of(c), msg, written)
}

fn refused_with(
    s: Step,
    c: usgp_proto::ErrorCode,
    msg: impl Into<String>,
    written: bool,
) -> JobFailure {
    let mut f = JobFailure::new(s, FailureCategory::Refused, c, msg);
    f.disk_written = written;
    f
}

/// Fails the step if its time ran out.
fn check_time(s: Step, w: &Watch<'_>, written: bool) -> Result<(), JobFailure> {
    match w.check() {
        Ok(()) => Ok(()),
        Err(t) => Err(timeout(s, t, written)),
    }
}

fn timeout(s: Step, t: TimeLimit, written: bool) -> JobFailure {
    let (c, msg) = match t {
        TimeLimit::Step => (&codes::STEP_TIMEOUT, "the step ran past its time limit"),
        TimeLimit::Stall => (&codes::STALLED, "the step made no progress for too long"),
    };
    let mut f = JobFailure::new(s, FailureCategory::Timeout, c.clone(), msg);
    f.disk_written = written;
    f
}

fn platform_failure(s: Step, c: &'static str, e: PlatformError, written: bool) -> JobFailure {
    let category = match e.kind {
        PlatformErrorKind::IdentityMismatch => FailureCategory::Refused,
        PlatformErrorKind::Timeout => FailureCategory::Timeout,
        _ => FailureCategory::Local,
    };
    let c = if e.kind == PlatformErrorKind::IdentityMismatch {
        codes::DISK_IDENTITY_MISMATCH
    } else {
        code_of(c)
    };
    let mut f = JobFailure::new(s, category, c, e.to_string());
    f.disk_written = written;
    f
}

fn disk_failure(s: Step, disk: &str, e: &DiskError) -> JobFailure {
    let msg = format!("{disk}: {e}");
    match e {
        DiskError::NotAuthorised(_) => refused(s, code::WIPE_NOT_AUTHORISED, msg, false),
        DiskError::IdentityMismatch(_) => {
            refused_with(s, codes::DISK_IDENTITY_MISMATCH, msg, false)
        }
        DiskError::BadPlan(_) => local(s, code::LAYOUT_FAILED, msg, false),
        DiskError::Write(_) => local(s, code::DISK_WRITE_FAILED, msg, true),
        DiskError::ReadBack(_) | DiskError::ReadBackMismatch(_) => {
            local(s, code::GPT_READBACK_FAILED, msg, true)
        }
        // A future variant: assume the disk may have been written.
        _ => local(s, code::DISK_WRITE_FAILED, msg, true),
    }
}

/// Names a content-pass failure (REQ-JOB-005 items 1 to 3; REQ-JOB-011).
fn content_failure(
    s: Step,
    e: &ApplyError,
    chunk: Option<ChunkError>,
    watch: &Watch<'_>,
    item: Option<&ProgressItemV1>,
) -> JobFailure {
    let mut f = if let Some(c) = chunk {
        let (category, c_code) = match c.kind {
            ChunkErrorKind::Network => {
                (FailureCategory::Network, code_of(code::SERVER_UNREACHABLE))
            }
            ChunkErrorKind::Protocol => (FailureCategory::Network, code_of(code::SERVER_REFUSED)),
            ChunkErrorKind::NotFound => {
                (FailureCategory::Refused, code_of(code::CONTENT_NOT_FOUND))
            }
            ChunkErrorKind::Refused => (FailureCategory::Refused, code_of(code::SERVER_REFUSED)),
            ChunkErrorKind::ServerIntegrity => {
                (FailureCategory::Integrity, codes::INTEGRITY_FAILED)
            }
            ChunkErrorKind::Digest | ChunkErrorKind::Length => {
                (FailureCategory::Integrity, codes::CHUNK_DIGEST_MISMATCH)
            }
            ChunkErrorKind::NoDigest => {
                (FailureCategory::Integrity, codes::CONTENT_MANIFEST_MISMATCH)
            }
            ChunkErrorKind::StepTimeout => (FailureCategory::Timeout, codes::STEP_TIMEOUT),
            ChunkErrorKind::Stalled => (FailureCategory::Timeout, codes::STALLED),
        };
        let mut f = JobFailure::new(s, category, c_code, c.to_string());
        f.attempts = c.attempts.max(1);
        f.files.extend(item.cloned());
        f.count = 1;
        f
    } else if let Some(t) = watch.tripped() {
        timeout(s, t, false)
    } else {
        let category = match e {
            ApplyError::ContentIntegrity { .. } | ApplyError::ResourceHashMismatch => {
                FailureCategory::Integrity
            }
            ApplyError::ContentUnavailable { .. } => FailureCategory::Network,
            ApplyError::Sink(_) | ApplyError::LimitExceeded { .. } => FailureCategory::Local,
            _ => FailureCategory::Refused,
        };
        let c = match e {
            ApplyError::ContentIntegrity { .. } => codes::CHUNK_DIGEST_MISMATCH,
            other => code_of(other.reason_code()),
        };
        let mut f = JobFailure::new(s, category, c, e.operator_message());
        let role = match e {
            ApplyError::Metadata(_) => FileRole::Metadata,
            _ => FileRole::Image,
        };
        f.files
            .extend(item.cloned().map(|i| ProgressItemV1 { role, ..i }));
        f.count = 1;
        f
    };
    f.step = s;
    f
}

/// The disk facts the layout is planned from, taken from the signed plan.
fn facts_from_plan(d: &PlanDiskV1) -> DiskFacts {
    DiskFacts {
        identity: DiskIdentity {
            device_number: 0,
            model: d.model.as_str().to_owned(),
            serial: Some(d.serial.as_str().to_owned()),
        },
        bus: usgp_disk::Bus::Other(0),
        removable: false,
        read_only: false,
        logical_sector: d.logical_sector,
        physical_sector: d.physical_sector,
        size_bytes: d.size_bytes,
        hosts_boot_environment: false,
        partitions: Vec::new(),
    }
}

/// The wire bus for a platform bus.
fn bus_of(b: usgp_disk::Bus) -> Bus {
    use usgp_disk::Bus as D;
    match b {
        D::Sata => Bus::Sata,
        D::Ata => Bus::Ata,
        D::Sas => Bus::Sas,
        D::Scsi => Bus::Scsi,
        D::Nvme => Bus::Nvme,
        D::Raid => Bus::Raid,
        D::Usb => Bus::Usb,
        D::Sd => Bus::Sd,
        D::Mmc => Bus::Mmc,
        D::Virtual => Bus::Virtual,
        D::FileBackedVirtual => Bus::FileBacked,
        _ => Bus::Other,
    }
}

/// The opened disk must be the one in the signed plan: same geometry, bus,
/// model and serial (as the descriptor sanitised them; a missing serial is
/// the empty text). The disk token was resolved to this device by the
/// platform.
fn check_target(want: &PlanDiskV1, f: &DiskFacts) -> Result<(), &'static str> {
    if f.size_bytes != want.size_bytes {
        return Err("size differs from the confirmed disk");
    }
    if f.logical_sector != want.logical_sector || f.physical_sector != want.physical_sector {
        return Err("sector sizes differ from the confirmed disk");
    }
    if bus_of(f.bus) != want.bus {
        return Err("bus differs from the confirmed disk");
    }
    if DiskText::sanitized(&f.identity.model) != want.model {
        return Err("model differs from the confirmed disk");
    }
    let serial = f.identity.serial.as_deref().unwrap_or("");
    if DiskText::sanitized(serial) != want.serial {
        return Err("serial number differs from the confirmed disk");
    }
    Ok(())
}

/// The apply root the platform promises for the Windows volume, before the
/// wipe. Only a bare drive-letter root is accepted: a mounted folder or a
/// directory cannot be told apart from text (decision 0022, findings R4).
fn windows_root(s: Step, platform: &mut dyn Platform) -> Result<ApplyRoot, JobFailure> {
    let text = platform
        .volumes()
        .windows_root()
        .map_err(|e| platform_failure(s, code::APPLY_ROOT_UNSUPPORTED, e, false))?;
    drive_root(&text).map_err(|why| {
        local(
            s,
            code::APPLY_ROOT_UNSUPPORTED,
            format!("apply root not supported ({why})"),
            false,
        )
    })
}

/// `text` as an [`ApplyRoot`], if it is exactly a drive letter (`L:` or
/// `L:\`).
fn drive_root(text: &str) -> Result<ApplyRoot, &'static str> {
    let r = ApplyRoot::parse(text).map_err(|e| e.what)?;
    // Normalised text of a bare root is `L:`; anything longer names a
    // directory below it, which may be a mounted folder.
    if r.to_text().len() != 2 {
        return Err("not a bare drive-letter root");
    }
    Ok(r)
}

/// The platform must have formatted exactly the planned volumes, with the
/// planned file systems and labels, and the Windows volume must be on the
/// drive letter promised before the wipe.
fn check_volumes(
    specs: &[VolumeSpec],
    vols: &[FormattedVolume],
    root: &ApplyRoot,
) -> Result<(), &'static str> {
    if vols.len() != specs.len() {
        return Err("formatted volumes differ from the plan");
    }
    for spec in specs {
        let mut found = vols.iter().filter(|v| v.spec == *spec);
        let (Some(v), None) = (found.next(), found.next()) else {
            return Err("formatted volumes differ from the plan");
        };
        if v.fs != spec.fs {
            return Err("a volume has the wrong file system");
        }
        if v.label != spec.label {
            return Err("a volume has the wrong label");
        }
        if spec.role == PartRole::Windows
            && v.root.as_deref().map(drive_root) != Some(Ok(root.clone()))
        {
            return Err("the Windows volume is not on the planned drive letter");
        }
    }
    Ok(())
}

fn volume(vols: &[FormattedVolume], role: PartRole) -> Option<&FormattedVolume> {
    vols.iter().find(|v| v.spec.role == role)
}

/// The layout written, for the operator (REQ-DISK-014).
fn layout_report(layout: &WindowsUefiLayout, vols: &[FormattedVolume]) -> Option<LayoutReportV1> {
    let block = u64::from(layout.block);
    let partitions = layout
        .parts()
        .iter()
        .map(|p| {
            let v = volume(vols, p.role);
            WrittenPartitionV1 {
                index: p.number,
                kind: match p.role {
                    PartRole::Esp => PartitionKind::Esp,
                    PartRole::Msr => PartitionKind::Msr,
                    PartRole::Windows => PartitionKind::Basic,
                    PartRole::Recovery => PartitionKind::Recovery,
                },
                start_bytes: p.first_lba.saturating_mul(block),
                size_bytes: p.len_lbas().saturating_mul(block),
                fs: v.map(|v| v.fs),
                label: v.and_then(|v| PartitionLabel::sanitized(&v.label)),
            }
        })
        .collect();
    let guid = DiskGuid::parse(&layout.disk_guid.to_string()).ok()?;
    LayoutReportV1::new(partitions, guid).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use usgp_proto::disk::FileSystem;

    fn plan_disk() -> PlanDiskV1 {
        PlanDiskV1 {
            disk_token: usgp_proto::DiskToken::from_random_bytes([1; 16]),
            bus: Bus::Nvme,
            model: DiskText::sanitized("Model\u{7}X"),
            serial: DiskText::sanitized(""),
            size_bytes: 64_000_000_000,
            logical_sector: 512,
            physical_sector: 4096,
        }
    }

    fn facts() -> DiskFacts {
        DiskFacts {
            identity: DiskIdentity {
                device_number: 3,
                model: "Model\u{7}X".to_owned(),
                serial: None,
            },
            bus: usgp_disk::Bus::Nvme,
            removable: false,
            read_only: false,
            logical_sector: 512,
            physical_sector: 4096,
            size_bytes: 64_000_000_000,
            hosts_boot_environment: false,
            partitions: Vec::new(),
        }
    }

    #[test]
    fn target_must_match_plan() {
        assert!(check_target(&plan_disk(), &facts()).is_ok());
        let cases: [fn(&mut DiskFacts); 6] = [
            |f| f.size_bytes += 512,
            |f| f.logical_sector = 4096,
            |f| f.physical_sector = 512,
            |f| f.bus = usgp_disk::Bus::Sata,
            |f| f.identity.model = "Other".to_owned(),
            |f| f.identity.serial = Some("S".to_owned()),
        ];
        for c in cases {
            let mut f = facts();
            c(&mut f);
            assert!(check_target(&plan_disk(), &f).is_err());
        }
    }

    #[test]
    fn every_bus_maps() {
        use usgp_disk::Bus as D;
        assert_eq!(bus_of(D::FileBackedVirtual), Bus::FileBacked);
        assert_eq!(bus_of(D::Ieee1394), Bus::Other);
        assert_eq!(bus_of(D::Other(77)), Bus::Other);
    }

    #[test]
    fn file_system_values() {
        let s = VolumeSpec {
            role: PartRole::Esp,
            number: 1,
            start_bytes: 0,
            size_bytes: 1,
            fs: FileSystem::Fat32,
            label: "System",
        };
        let v = FormattedVolume {
            spec: s,
            fs: FileSystem::Ntfs,
            label: "System".to_owned(),
            locator: String::new(),
            root: None,
        };
        let w = drive_root("W:\\").unwrap();
        assert_eq!(
            check_volumes(&[s], std::slice::from_ref(&v), &w),
            Err("a volume has the wrong file system")
        );
        assert!(check_volumes(&[s], &[v.clone(), v], &w).is_err());

        let win = VolumeSpec {
            role: PartRole::Windows,
            fs: FileSystem::Ntfs,
            label: "Windows",
            ..s
        };
        let mut wv = FormattedVolume {
            spec: win,
            fs: FileSystem::Ntfs,
            label: "Windows".to_owned(),
            locator: String::new(),
            root: Some("W:\\".to_owned()),
        };
        assert_eq!(check_volumes(&[win], std::slice::from_ref(&wv), &w), Ok(()));
        for other in [None, Some("V:\\"), Some("W:\\mnt"), Some("w:")] {
            wv.root = other.map(str::to_owned);
            assert!(check_volumes(&[win], std::slice::from_ref(&wv), &w).is_err());
        }
    }

    #[test]
    fn apply_root_is_a_bare_drive_letter() {
        assert_eq!(drive_root("W:").unwrap().to_text(), "W:");
        assert_eq!(drive_root("W:\\").unwrap().to_text(), "W:");
        for bad in ["W:\\Windows", "W:\\mnt\\", "w:\\", "\\\\?\\W:\\", "W", ""] {
            assert!(drive_root(bad).is_err(), "{bad:?}");
        }
    }
}
