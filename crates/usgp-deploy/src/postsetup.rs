//! The post-setup runner: job steps 7 to 9 in the installed Windows (M4
//! plan §1.2, §1.3, §1.7; decisions 0024 and 0025).
//!
//! Windows Setup starts the agent in `postsetup` mode from
//! `SetupComplete.cmd` as SYSTEM. [`PostSetupRunner::run`]:
//!
//! 1. reads `job.json` and checks, before acting:
//!    - the plan signature again, with the plan key in `job.json`;
//!    - that the plan is this job's;
//!    - that `job.key` is the key the plan names (`job_key_mismatch`);
//!    - that the agent package's SHA-256 is the plan's
//!      (`agent_digest_mismatch`);
//! 2. re-contacts the server: challenge, then the challenge signed with
//!    the job key, which gives the link a job-scoped token. Transient
//!    failures are retried until the step 7 deadline (the network may come
//!    up late);
//! 3. step 7 `windows_setup`: writes the tags; if the plan has an escrow
//!    key, **escrow first, then set** (§1.3): generate the password with
//!    the FIPS DRBG into locked memory, seal it to the escrow key, post
//!    it, and only after the server's acknowledgement set it on the
//!    built-in Administrator (RID 500) and confirm. If the escrow fails
//!    the password is never set and the account stays disabled (fail
//!    secure). Then the Panther answer file is deleted and its absence
//!    checked;
//! 4. step 8 `install_agent`: the package is re-hashed, extracted with the
//!    bounded archive reader, `agent.json` parsed, and the installer run
//!    (argument vector, no shell, cleared environment, timeout). The exit
//!    code must be in the success list; 3010 is recorded as
//!    `restart_pending`, and the runner never restarts;
//! 5. step 9 `report_ready`: `succeeded` delivered and acknowledged.
//!
//! On every exit, `job.key`, the answer file and our `SetupComplete.cmd`
//! are deleted; the script's own second line removes the folder. A
//! failure is reported `failed` if the server was reached, and always
//! recorded on the device ([`PostSetupPlatform::record_failure`]).
//!
//! The password is never written to disk, a command line, an environment
//! variable, a log, a report or an error.

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-3 (Device Identification and Authentication) - job-key
//   possession proof (resume).
// - NIST 800-53: IA-5(1) - generated password; SC-12, SC-13 - sealed
//   through usgp-crypto (ECDH P-384, HKDF-SHA-384, AES-256-GCM).
// - NIST 800-53: SC-28 - the password leaves the device only encrypted.
// - NIST 800-53: SI-16 (Memory Protection) - locked, zeroized buffer.
// - NIST 800-53: SI-7, SI-7(6) - plan signature and agent package digest
//   re-checked before use.
// - NIST 800-53: CM-7 - installer by argument vector, cleared environment.
// - NIST 800-53: AU-12 (basis) - every step reported (REQ-SEQ-007).
// - SPEC: specs/configuration.md#REQ-CFG-008 (as modified by decision
//   0024), #REQ-CFG-009, #REQ-CFG-010
// - SPEC: specs/workflow.md#REQ-SEQ-003, #REQ-SEQ-006
// - SPEC: specs/agent-handoff.md#REQ-AGT-001, #REQ-AGT-005, #REQ-AGT-006
// - DECISION: docs/decisions/0024, 0025

use std::fmt;
use std::time::Duration;

use usgp_crypto::{
    CryptoProvider, EscrowContext, EscrowPublicKey, SigningKey, VerifyingKey, random_password,
    sign_typed,
};
use usgp_proto::agent_package::InstallerKind;
use usgp_proto::envelope::PayloadType;
use usgp_proto::job_plan::{EscrowAccount, JobPlanV2, PlanEscrowV2, RetryPolicyV1};
use usgp_proto::limits::{MAX_AGENT_MANIFEST_BYTES, MAX_POSTSETUP_CONFIG_BYTES};
use usgp_proto::postsetup::PostSetupConfigV1;
use usgp_proto::progress::{FailureCategory, JobState, ProgressEvent, ProgressV2, StepV2};
use usgp_proto::resume::{ResumeSignature, resume_payload};
use usgp_proto::{
    AgentPackageManifestV1, B64Bytes, ErrorCode, EscrowConfirmV1, EscrowSubmitV1, InstallerArg,
    JobId, RelPath, ResumeChallengeV1, ResumeRequestV1, codes,
};
use usgp_wincfg::archive::{ArchiveError, ArchiveLimits, ExtractSink, extract_archive};
use zeroize::Zeroizing;

use crate::clock::{Clock, Watch, backoff};
use crate::error::{JobFailureV2, code, code_of, code_with};
use crate::link::{LinkError, ProgressLinkV2};
use crate::plan::PinnedKey;
use crate::platform::PlatformError;
use crate::report_v2::{Must, POSTSETUP_SEQ_BASE, ReporterV2};
use crate::steps::{local, platform_failure, time_check, watch_for};

/// Largest `job.key` read, in bytes (a P-384 PKCS#8 is far smaller).
const MAX_JOB_KEY_BYTES: u64 = 16 * 1024;

/// Generated password length (M4 plan §1.3: 24 characters, 144 bits).
pub const PASSWORD_LEN: usize = 24;

/// The exit code with which an installer asks for a restart (M4 plan
/// §1.7); accepted only if in the success list, and never acted on.
pub const RESTART_PENDING_EXIT: u32 = 3010;

/// A file the runner reads or deletes in the installed Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunnerFile {
    /// `%ProgramData%\usgp\postsetup\job.json`.
    JobJson,
    /// `%ProgramData%\usgp\postsetup\job.key`.
    JobKey,
    /// `%ProgramData%\usgp\postsetup\agent-package.zip`.
    AgentPackage,
    /// `%WINDIR%\Panther\unattend.xml`.
    AnswerFile,
    /// `%WINDIR%\Setup\Scripts\SetupComplete.cmd`.
    SetupComplete,
}

/// Setting the account password or enabling it failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the account could not be set (error {win32})")]
pub struct AccountError {
    /// The Win32 or network-management status code.
    pub win32: u32,
}

/// The installer to run (M4 plan §1.7). The platform runs it with an
/// argument vector, no shell, the working folder at the extracted package,
/// a cleared environment plus `SystemRoot`, `Path`, `TEMP` and
/// `USGP_TAGS`, and kills it at the timeout. An `.msi` is run as
/// `msiexec.exe /i <installer> /qn /norestart` followed by `args`.
#[derive(Debug, Clone, Copy)]
pub struct InstallerCommand<'a> {
    /// `.exe` or `.msi`.
    pub kind: InstallerKind,
    /// The installer, relative to the extracted package folder.
    pub installer: &'a RelPath,
    /// Arguments (none contains `{{`).
    pub args: &'a [InstallerArg],
    /// The time limit.
    pub timeout: Duration,
    /// The tags as a JSON array, for `USGP_TAGS` (not secret).
    pub tags_json: &'a str,
}

/// How the installer ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    /// It exited with this code.
    Exited(u32),
    /// It ran past its time limit and was killed.
    TimedOut,
}

/// What the runner needs from the installed Windows. The agent (WU-10)
/// implements it on `usgp-winapi`; tests use a directory tree.
pub trait PostSetupPlatform {
    /// The bytes of `f`, refusing a file over `max` bytes.
    ///
    /// # Errors
    ///
    /// [`PlatformError`].
    fn read_file(&mut self, f: RunnerFile, max: u64) -> Result<Zeroizing<Vec<u8>>, PlatformError>;

    /// Deletes `f`; succeeds if it is absent.
    ///
    /// # Errors
    ///
    /// [`PlatformError`].
    fn delete_file(&mut self, f: RunnerFile) -> Result<(), PlatformError>;

    /// `true` if `f` exists.
    ///
    /// # Errors
    ///
    /// [`PlatformError`].
    fn file_exists(&mut self, f: RunnerFile) -> Result<bool, PlatformError>;

    /// Writes `%ProgramData%\usgp\tags.json` (DACL: SYSTEM full, Users
    /// read), replacing it.
    ///
    /// # Errors
    ///
    /// [`PlatformError`].
    fn write_tags(&mut self, json: &[u8]) -> Result<(), PlatformError>;

    /// Locks the pages holding `region` in memory (`VirtualLock`).
    ///
    /// # Errors
    ///
    /// [`PlatformError`]; the runner then fails before any secret exists
    /// beyond this buffer.
    fn lock_memory(&mut self, region: &[u8]) -> Result<(), PlatformError>;

    /// Unlocks what [`PostSetupPlatform::lock_memory`] locked.
    fn unlock_memory(&mut self, region: &[u8]);

    /// Sets the built-in Administrator's (RID 500) password, then enables
    /// the account. The password must not be copied anywhere else.
    ///
    /// # Errors
    ///
    /// [`AccountError`] with the status code.
    fn set_admin_password(&mut self, password: &Zeroizing<String>) -> Result<(), AccountError>;

    /// A sink that creates the agent package's files in
    /// `%ProgramData%\usgp\postsetup\agent\`, which must not exist yet.
    ///
    /// # Errors
    ///
    /// [`PlatformError`].
    fn agent_sink(&mut self) -> Result<Box<dyn ExtractSink + '_>, PlatformError>;

    /// Runs the installer.
    ///
    /// # Errors
    ///
    /// [`PlatformError`] if it could not be started.
    fn run_installer(
        &mut self,
        cmd: &InstallerCommand<'_>,
    ) -> Result<InstallOutcome, PlatformError>;

    /// Records a terminal failure on the device
    /// (`%ProgramData%\usgp\postsetup-error.txt` and the event log). The
    /// text holds no secret.
    fn record_failure(&mut self, text: &str);
}

/// The server, as the runner uses it. The implementation holds the
/// resume token it receives; the runner never sees it.
pub trait ResumeLink: ProgressLinkV2 {
    /// `POST /v1/device/jobs/{job}/resume/challenge`.
    ///
    /// # Errors
    ///
    /// [`LinkError`].
    fn challenge(&mut self, job: JobId) -> Result<ResumeChallengeV1, LinkError>;

    /// `POST /v1/device/jobs/{job}/resume`; on success the link keeps the
    /// token for later calls.
    ///
    /// # Errors
    ///
    /// [`LinkError`].
    fn resume(&mut self, job: JobId, req: &ResumeRequestV1) -> Result<(), LinkError>;

    /// `POST /v1/device/jobs/{job}/escrow` (201 on commit).
    ///
    /// # Errors
    ///
    /// [`LinkError`]; `Refused` for 409.
    fn submit_escrow(&mut self, job: JobId, body: &EscrowSubmitV1) -> Result<(), LinkError>;

    /// `POST /v1/device/jobs/{job}/escrow/confirm`.
    ///
    /// # Errors
    ///
    /// [`LinkError`].
    fn confirm_escrow(&mut self, job: JobId, body: &EscrowConfirmV1) -> Result<(), LinkError>;
}

/// Runner settings that are not in the signed plan.
#[derive(Debug, Clone)]
pub struct RunnerConfig {
    /// Bounds for extracting the agent package.
    pub archive_limits: ArchiveLimits,
    /// Largest agent package read, in bytes (`agent_package.max_bytes`).
    pub max_agent_package_bytes: u64,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            archive_limits: ArchiveLimits::default(),
            max_agent_package_bytes: 2 << 30,
        }
    }
}

/// The job is ready: step 9 delivered and acknowledged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready {
    /// The job.
    pub job_id: JobId,
    /// `true` if a password was escrowed and set.
    pub password_set: bool,
    /// The installer asked for a restart (not performed).
    pub restart_pending: bool,
    /// The reports the server acknowledged, in order.
    pub reports: Vec<ProgressV2>,
}

/// The post-setup runner.
pub struct PostSetupRunner<'a> {
    crypto: &'a dyn CryptoProvider,
    clock: &'a dyn Clock,
    config: RunnerConfig,
}

impl fmt::Debug for PostSetupRunner<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostSetupRunner")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// The checked inputs.
struct Loaded {
    plan: JobPlanV2,
    job_key: SigningKey,
}

/// One run: the reporter exists once the server accepted the resume.
struct Session<'r> {
    rep: Option<ReporterV2>,
    retry: RetryPolicyV1,
    platform: &'r mut dyn PostSetupPlatform,
    link: &'r mut dyn ResumeLink,
}

fn invalid(msg: impl Into<String>) -> JobFailureV2 {
    JobFailureV2::new(
        StepV2::WINDOWS_SETUP,
        FailureCategory::Integrity,
        codes::POSTSETUP_CONFIG_INVALID,
        msg,
    )
}

fn link_failure(s: StepV2, c: ErrorCode, e: LinkError, msg: &str) -> JobFailureV2 {
    let category = if e.is_transient() {
        FailureCategory::Network
    } else {
        FailureCategory::Refused
    };
    JobFailureV2::new(s, category, c, format!("{msg} ({e})"))
}

impl<'a> PostSetupRunner<'a> {
    /// A runner using `crypto` (digests, DRBG, escrow sealing) and
    /// `clock`.
    #[must_use]
    pub fn new(crypto: &'a dyn CryptoProvider, clock: &'a dyn Clock, config: RunnerConfig) -> Self {
        Self {
            crypto,
            clock,
            config,
        }
    }

    /// Runs steps 7 to 9 (module documentation). Cleans up on every
    /// exit.
    ///
    /// # Errors
    ///
    /// [`JobFailureV2`], already recorded on the device and, if the server
    /// was reached, reported `failed`.
    pub fn run(
        &self,
        platform: &mut dyn PostSetupPlatform,
        link: &mut dyn ResumeLink,
    ) -> Result<Ready, JobFailureV2> {
        let mut s = Session {
            rep: None,
            retry: RetryPolicyV1 {
                attempts: 1,
                base_ms: 1,
                max_ms: 1,
            },
            platform,
            link,
        };
        let result = self.steps(&mut s);
        let cleanup = cleanup(&mut *s.platform);
        let result = match (result, cleanup) {
            (Ok(r), Ok(())) => Ok(r),
            (Ok(_), Err(f)) => Err(f),
            (Err(f), _) => Err(f),
        };
        if let Err(f) = &result {
            s.platform.record_failure(&f.to_string());
            if let Some(rep) = s.rep.as_mut() {
                // Best effort: the failure is recorded on the device too.
                let _ = rep.deliver(
                    &mut *s.link,
                    self.clock,
                    &s.retry,
                    None,
                    Must::failed(f.to_wire()),
                );
            }
        }
        result
    }

    fn load(&self, platform: &mut dyn PostSetupPlatform) -> Result<Loaded, JobFailureV2> {
        let max = u64::try_from(MAX_POSTSETUP_CONFIG_BYTES).unwrap_or(u64::MAX);
        let json = platform
            .read_file(RunnerFile::JobJson, max)
            .map_err(|e| invalid(format!("job.json could not be read: {e}")))?;
        let config = PostSetupConfigV1::from_json(&json)
            .map_err(|e| invalid(format!("job.json is invalid: {e}")))?;
        let plan_key = VerifyingKey::from_spki_pem(config.plan_key_pem.as_bytes())
            .map_err(|_| invalid("job.json plan key is invalid"))?;
        let plan = JobPlanV2::open(&config.plan, &PinnedKey::new(plan_key))
            .map_err(|e| invalid(format!("the job plan does not verify: {e}")))?;
        if plan.job_id != config.job_id {
            return Err(invalid("job.json names another job"));
        }
        let der = platform
            .read_file(RunnerFile::JobKey, MAX_JOB_KEY_BYTES)
            .map_err(|e| invalid(format!("job.key could not be read: {e}")))?;
        let job_key = SigningKey::from_pkcs8_der(&der).map_err(|_| {
            JobFailureV2::new(
                StepV2::WINDOWS_SETUP,
                FailureCategory::Integrity,
                codes::JOB_KEY_MISMATCH,
                "job.key is not a valid key",
            )
        })?;
        drop(der);
        if job_key.key_id().0 != plan.job_key_id {
            return Err(JobFailureV2::new(
                StepV2::WINDOWS_SETUP,
                FailureCategory::Integrity,
                codes::JOB_KEY_MISMATCH,
                "job.key is not the key the plan names",
            ));
        }
        self.check_agent_package(platform, &plan, StepV2::WINDOWS_SETUP)?;
        Ok(Loaded { plan, job_key })
    }

    /// Reads the agent package and checks its whole-file SHA-256.
    fn check_agent_package(
        &self,
        platform: &mut dyn PostSetupPlatform,
        plan: &JobPlanV2,
        s: StepV2,
    ) -> Result<Zeroizing<Vec<u8>>, JobFailureV2> {
        let pkg = platform
            .read_file(
                RunnerFile::AgentPackage,
                self.config.max_agent_package_bytes,
            )
            .map_err(|e| platform_failure(s, codes::AGENT_DIGEST_MISMATCH, e))?;
        if self.crypto.sha256(&pkg) != plan.agent.content_sha256 {
            return Err(JobFailureV2::new(
                s,
                FailureCategory::Integrity,
                codes::AGENT_DIGEST_MISMATCH,
                "the agent package does not match the plan",
            ));
        }
        Ok(pkg)
    }

    /// Calls `f` until it succeeds or fails for good. Transient failures
    /// are retried with growing delays: at most `retry.attempts` times, or
    /// (with `until_deadline`) for as long as `watch` allows.
    fn retrying<T>(
        &self,
        retry: &RetryPolicyV1,
        watch: &Watch<'_>,
        until_deadline: bool,
        mut f: impl FnMut() -> Result<T, LinkError>,
    ) -> Result<T, LinkError> {
        let mut failures: u32 = 0;
        loop {
            match f() {
                Ok(v) => return Ok(v),
                Err(e) if e.is_transient() => {
                    failures = failures.saturating_add(1);
                    if !until_deadline && failures >= retry.attempts {
                        return Err(e);
                    }
                    let d = backoff(retry.base_ms, retry.max_ms, failures);
                    if watch.check_wait(d).is_err() {
                        return Err(e);
                    }
                    self.clock.sleep(d);
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn steps(&self, s: &mut Session<'_>) -> Result<Ready, JobFailureV2> {
        let Loaded { plan, job_key } = self.load(&mut *s.platform)?;
        s.retry = plan.retry;
        let job = plan.job_id;

        // ---- Step 7: resume, tags, escrow then set, answer file. ----
        let st = StepV2::WINDOWS_SETUP;
        let watch = watch_for(self.clock, plan.timeout_s(st), None);
        self.resume(s, job, &job_key, &watch)?;
        drop(job_key);
        let mut rep = ReporterV2::new(job, POSTSETUP_SEQ_BASE);
        rep.state(&mut *s.link, st, ProgressEvent::StepStarted);
        s.rep = Some(rep);

        let tags_json = serde_json::to_string(&plan.tags).map_err(|_| {
            local(
                st,
                codes::TAGS_WRITE_FAILED,
                "the tags could not be encoded",
            )
        })?;
        s.platform
            .write_tags(tags_json.as_bytes())
            .map_err(|e| platform_failure(st, codes::TAGS_WRITE_FAILED, e))?;
        time_check(st, &watch)?;

        let password_set = match &plan.escrow {
            Some(e) => {
                self.escrow_then_set(s, job, e, &watch)?;
                true
            }
            None => false,
        };
        time_check(st, &watch)?;

        let not_removed = |why: String| {
            local(
                st,
                code_of(code::ANSWER_FILE_NOT_REMOVED),
                format!("the answer file could not be removed ({why})"),
            )
        };
        s.platform
            .delete_file(RunnerFile::AnswerFile)
            .map_err(|e| not_removed(e.to_string()))?;
        match s.platform.file_exists(RunnerFile::AnswerFile) {
            Ok(false) => {}
            Ok(true) => return Err(not_removed("it is still present".to_owned())),
            Err(e) => return Err(not_removed(e.to_string())),
        }
        self.state(s, st, ProgressEvent::StepCompleted, None);

        // ---- Step 8: install the agent. ----
        let st = StepV2::INSTALL_AGENT;
        let watch = watch_for(self.clock, plan.timeout_s(st), None);
        self.state(s, st, ProgressEvent::StepStarted, None);
        let restart_pending = self.install_agent(s, &plan, &tags_json, &watch)?;
        time_check(st, &watch)?;
        self.state(s, st, ProgressEvent::StepCompleted, Some(restart_pending));

        // ---- Step 9: report ready. ----
        let st = StepV2::REPORT_READY;
        let watch = watch_for(self.clock, plan.timeout_s(st), None);
        self.state(s, st, ProgressEvent::StepStarted, None);
        let Some(rep) = s.rep.as_mut() else {
            return Err(local(st, codes::INTERNAL, "no report channel"));
        };
        let ack = rep.deliver(
            &mut *s.link,
            self.clock,
            &plan.retry,
            Some(&watch),
            Must::event(st, ProgressEvent::Succeeded),
        );
        match ack {
            Ok(a) if a.job_state == JobState::Succeeded => Ok(Ready {
                job_id: job,
                password_set,
                restart_pending,
                reports: rep.delivered().to_vec(),
            }),
            Ok(_) => Err(JobFailureV2::new(
                st,
                FailureCategory::Refused,
                code_of(code::SUCCESS_NOT_ACCEPTED),
                "the server did not record the job as succeeded",
            )),
            Err(e) => Err(link_failure(
                st,
                if e.is_transient() {
                    code_of(code::SERVER_UNREACHABLE)
                } else {
                    code_of(code::SUCCESS_NOT_ACCEPTED)
                },
                e,
                "the ready report could not be delivered",
            )),
        }
    }

    /// A state report through the session's reporter.
    fn state(
        &self,
        s: &mut Session<'_>,
        st: StepV2,
        e: ProgressEvent,
        restart_pending: Option<bool>,
    ) {
        if let Some(rep) = s.rep.as_mut() {
            rep.state_with(&mut *s.link, st, e, restart_pending);
        }
    }

    /// Challenge, sign with the job key, resume.
    fn resume(
        &self,
        s: &mut Session<'_>,
        job: JobId,
        key: &SigningKey,
        watch: &Watch<'_>,
    ) -> Result<(), JobFailureV2> {
        let st = StepV2::WINDOWS_SETUP;
        let retry = s.retry;
        let link = &mut *s.link;
        let crypto_failed = std::cell::Cell::new(false);
        let r = self.retrying(&retry, watch, true, || {
            let ch = link.challenge(job)?;
            let payload = resume_payload(&job, &ch.nonce);
            let Ok(sig) = sign_typed(key, PayloadType::ResumeV1.as_str(), &payload)
                .map_err(|_| ())
                .and_then(|v| ResumeSignature::new(v).map_err(|_| ()))
            else {
                crypto_failed.set(true);
                return Err(LinkError::Protocol);
            };
            link.resume(
                job,
                &ResumeRequestV1 {
                    nonce: ch.nonce,
                    sig,
                },
            )
        });
        if crypto_failed.get() {
            return Err(local(
                st,
                codes::RESUME_REFUSED,
                "the resume proof could not be signed",
            ));
        }
        r.map_err(|e| {
            link_failure(
                st,
                codes::RESUME_REFUSED,
                e,
                "the server did not accept the resume",
            )
        })
    }

    /// Decision 0024 / M4 plan §1.3: generate, seal, post, and only after
    /// the server's acknowledgement set and confirm. The password exists
    /// only in a locked, zeroized buffer in this function.
    fn escrow_then_set(
        &self,
        s: &mut Session<'_>,
        job: JobId,
        e: &PlanEscrowV2,
        watch: &Watch<'_>,
    ) -> Result<(), JobFailureV2> {
        let st = StepV2::WINDOWS_SETUP;
        let refused =
            |msg: &str| JobFailureV2::new(st, FailureCategory::Refused, codes::ESCROW_REFUSED, msg);
        let pk = EscrowPublicKey::from_spki_der(e.spki_b64.as_der())
            .map_err(|_| refused("the escrow key is invalid"))?;
        if pk.key_id().0 != e.key_id {
            return Err(refused("the escrow key does not match its id"));
        }
        let account = EscrowAccount::Administrator.as_str();
        let password = random_password(PASSWORD_LEN)
            .map_err(|_| local(st, code_of(code::RANDOM_FAILED), "random source failed"))?;
        s.platform
            .lock_memory(password.as_bytes())
            .map_err(|e| platform_failure(st, code_of(code::SECRET_MEMORY_LOCK_FAILED), e))?;
        let r = self.seal_post_set(s, job, &pk, account, &password, watch);
        s.platform.unlock_memory(password.as_bytes());
        drop(password);
        r
    }

    fn seal_post_set(
        &self,
        s: &mut Session<'_>,
        job: JobId,
        pk: &EscrowPublicKey,
        account: &str,
        password: &Zeroizing<String>,
        watch: &Watch<'_>,
    ) -> Result<(), JobFailureV2> {
        let st = StepV2::WINDOWS_SETUP;
        let refused =
            |msg: &str| JobFailureV2::new(st, FailureCategory::Refused, codes::ESCROW_REFUSED, msg);
        let ctx = EscrowContext {
            job_id: *job.as_bytes(),
            account,
        };
        let sealed = self
            .crypto
            .escrow_seal(pk, &ctx, password.as_bytes())
            .map_err(|_| refused("the password could not be sealed"))?;
        let body = match (
            B64Bytes::new(sealed.eph_pub.clone()),
            B64Bytes::new(sealed.nonce.to_vec()),
            B64Bytes::new(sealed.ct.clone()),
        ) {
            (Ok(eph_pub_b64), Ok(nonce_b64), Ok(ct_b64)) => EscrowSubmitV1 {
                key_id: sealed.key_id.0,
                eph_pub_b64,
                nonce_b64,
                ct_b64,
                account: EscrowAccount::Administrator,
            },
            _ => return Err(refused("the sealed password has an unexpected form")),
        };
        let retry = s.retry;
        let link = &mut *s.link;
        // 1 and 2: post, and wait for the server's commit.
        self.retrying(&retry, watch, false, || link.submit_escrow(job, &body))
            .map_err(|e| {
                link_failure(
                    st,
                    codes::ESCROW_REFUSED,
                    e,
                    "the server did not store the escrowed password; it was not set",
                )
            })?;
        // 3: only now set it on the account.
        match s.platform.set_admin_password(password) {
            Ok(()) => {
                let ok = EscrowConfirmV1 {
                    set: true,
                    code: None,
                };
                self.retrying(&retry, watch, false, || link.confirm_escrow(job, &ok))
                    .map_err(|e| {
                        link_failure(
                            st,
                            codes::ESCROW_REFUSED,
                            e,
                            "the server did not accept the password confirmation",
                        )
                    })
            }
            Err(a) => {
                let c = code_with(&codes::ADMIN_PASSWORD_SET_FAILED, &[&a.win32.to_string()]);
                let not_set = EscrowConfirmV1 {
                    set: false,
                    code: Some(c.clone()),
                };
                // Best effort: the step fails either way.
                let _ = self.retrying(&retry, watch, false, || link.confirm_escrow(job, &not_set));
                Err(local(st, c, a.to_string()))
            }
        }
    }

    /// Step 8 after its start report. Returns `restart_pending`.
    fn install_agent(
        &self,
        s: &mut Session<'_>,
        plan: &JobPlanV2,
        tags_json: &str,
        watch: &Watch<'_>,
    ) -> Result<bool, JobFailureV2> {
        let st = StepV2::INSTALL_AGENT;
        let invalid = |msg: String| {
            JobFailureV2::new(
                st,
                FailureCategory::Refused,
                code_of(code::AGENT_PACKAGE_INVALID),
                msg,
            )
        };
        let pkg = self.check_agent_package(&mut *s.platform, plan, st)?;
        let len = u64::try_from(pkg.len()).unwrap_or(u64::MAX);
        let mut tee = {
            let mut sink = s
                .platform
                .agent_sink()
                .map_err(|e| platform_failure(st, code_of(code::AGENT_PACKAGE_INVALID), e))?;
            let mut tee = Tee::new(&mut *sink);
            match extract_archive(&pkg.as_slice(), len, &self.config.archive_limits, &mut tee) {
                // The reader's driver-package rule (REQ-DRV-006) is checked
                // last, after every entry was decoded, checked and written;
                // an agent package holds no INF, so that refusal alone is
                // the expected result here.
                Ok(_) | Err(ArchiveError::NoInfPackages) => {}
                Err(e) => {
                    return Err(invalid(format!(
                        "the agent package could not be extracted: {e}"
                    )));
                }
            }
            tee.finish()
        };
        drop(pkg);
        time_check(st, watch)?;
        let Some(json) = tee.manifest.take() else {
            return Err(invalid("the agent package has no agent.json".to_owned()));
        };
        let m = AgentPackageManifestV1::from_json(&json)
            .map_err(|e| invalid(format!("agent.json is invalid: {e}")))?;
        let installer = m.installer.as_str().to_lowercase();
        if !tee.files.contains(&installer) {
            return Err(invalid(
                "the installer named in agent.json is not in the package".to_owned(),
            ));
        }
        let Some(kind) = m.installer_kind() else {
            return Err(invalid("the installer kind is not supported".to_owned()));
        };
        let cmd = InstallerCommand {
            kind,
            installer: &m.installer,
            args: &m.args,
            timeout: Duration::from_secs(u64::from(m.timeout_s)),
            tags_json,
        };
        match s
            .platform
            .run_installer(&cmd)
            .map_err(|e| platform_failure(st, codes::AGENT_INSTALL_FAILED, e))?
        {
            InstallOutcome::Exited(exit) if m.success_exit_codes.contains(&exit) => {
                Ok(exit == RESTART_PENDING_EXIT)
            }
            InstallOutcome::Exited(exit) => Err(JobFailureV2::new(
                st,
                FailureCategory::Local,
                code_with(&codes::AGENT_INSTALL_FAILED, &[&exit.to_string()]),
                format!("the agent installer failed (exit {exit})"),
            )),
            InstallOutcome::TimedOut => Err(JobFailureV2::new(
                st,
                FailureCategory::Timeout,
                codes::AGENT_INSTALL_TIMEOUT,
                "the agent installer ran past its time limit",
            )),
        }
    }
}

/// Deletes `job.key`, the answer file and our `SetupComplete.cmd`. The
/// first failure is returned after every deletion was tried.
fn cleanup(platform: &mut dyn PostSetupPlatform) -> Result<(), JobFailureV2> {
    let mut first = None;
    for f in [
        RunnerFile::JobKey,
        RunnerFile::AnswerFile,
        RunnerFile::SetupComplete,
    ] {
        if let Err(e) = platform.delete_file(f) {
            first.get_or_insert(local(
                StepV2::REPORT_READY,
                codes::INTERNAL,
                format!("post-setup cleanup failed: {e}"),
            ));
        }
    }
    first.map_or(Ok(()), Err)
}

/// An extraction sink that passes everything on and also keeps the list of
/// file names (lower case) and the bytes of the root `agent.json`.
struct Tee<'s> {
    inner: &'s mut dyn ExtractSink,
    files: Vec<String>,
    in_manifest: bool,
    manifest: Option<Vec<u8>>,
}

/// What the tee saw.
struct Seen {
    files: Vec<String>,
    manifest: Option<Vec<u8>>,
}

impl<'s> Tee<'s> {
    fn new(inner: &'s mut dyn ExtractSink) -> Self {
        Self {
            inner,
            files: Vec::new(),
            in_manifest: false,
            manifest: None,
        }
    }

    fn finish(self) -> Seen {
        Seen {
            files: self.files,
            manifest: self.manifest,
        }
    }
}

impl ExtractSink for Tee<'_> {
    fn create_dir(&mut self, path: &usgp_wincfg::archive::RelPath) -> std::io::Result<()> {
        self.inner.create_dir(path)
    }

    fn begin_file(
        &mut self,
        path: &usgp_wincfg::archive::RelPath,
        size: u64,
    ) -> std::io::Result<()> {
        self.files.push(path.as_str().to_lowercase());
        self.in_manifest = path.as_str() == "agent.json";
        if self.in_manifest {
            self.manifest = Some(Vec::new());
        }
        self.inner.begin_file(path, size)
    }

    fn write(&mut self, data: &[u8]) -> std::io::Result<()> {
        if self.in_manifest
            && let Some(m) = self.manifest.as_mut()
        {
            // One byte over the limit is kept so the parser refuses it.
            let room = MAX_AGENT_MANIFEST_BYTES
                .saturating_add(1)
                .saturating_sub(m.len());
            m.extend_from_slice(data.get(..room.min(data.len())).unwrap_or_default());
        }
        self.inner.write(data)
    }

    fn end_file(&mut self) -> std::io::Result<()> {
        self.in_manifest = false;
        self.inner.end_file()
    }
}
