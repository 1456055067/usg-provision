//! The device session (plan sections 1.1 and 3.1): open, authorise, choose
//! a package and a disk, confirm the wipe, then run the job.
//!
//! The order is fixed and fails closed:
//!
//! 1. **Open.** The hello carries the device's claims; the server returns
//!    a token (kept in the client, zeroized) and a display code.
//! 2. **Firmware.** Not UEFI or not x64: the session ends with
//!    `firmware_unsupported` and a persistent error (REQ-PE-020,
//!    REQ-DISK-011).
//! 3. **Authorise.** The person types the operator code (echo off; if echo
//!    cannot be turned off, only console approval is offered), or the
//!    agent polls until an operator approves the display code. Nothing is
//!    listed before (REQ-TGT-013, REQ-TGT-014).
//! 4. **Package**, then **disk**: every disk is listed; ineligible disks
//!    with every reason. No package or no eligible disk ends the session
//!    with that reason (REQ-TGT-008, REQ-DISK-003).
//! 5. **Wipe confirmation**, a separate screen and a separate word (`WIPE`)
//!    (REQ-DISK-006). Cancel is offered on every screen up to here and on
//!    no screen after (REQ-TGT-010, REQ-TGT-011).
//! 6. **Job.** The engine verifies the signed plan (bound to the fresh
//!    nonce, the session, the job, the package and the disk) before
//!    anything else, then runs; a failure stays on screen until the person
//!    acts (REQ-JOB-005).

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 (Access Enforcement) - no package list before
//   authorisation; the wipe only after the separate confirmation and a
//   verified plan naming the durable wipe record.
// - NIST 800-53: IA-6 (Authentication Feedback) - code entry with echo
//   off; refusals do not say why a code failed.
// - NIST 800-53: SC-23 (Session Authenticity) - fresh DRBG nonce per
//   confirmation; plan bound to it.
// - NIST 800-53: SI-11 - persistent errors; no secrets shown.
// - SPEC: specs/targeting.md#REQ-TGT-004..006, #REQ-TGT-008..011,
//   #REQ-TGT-013, #REQ-TGT-014
// - SPEC: specs/disk.md#REQ-DISK-001..006, #REQ-DISK-011
// - SPEC: specs/preinstall-env.md#REQ-PE-016, #REQ-PE-020
// - SPEC: specs/progress.md#REQ-JOB-005
// - DECISION: docs/decisions/0018 items 1, 7, 8, 10; 0020

use std::time::Duration;

use usgp_crypto::CryptoProvider;
use usgp_deploy::{Clock, Engine, PlanKeys, SignedJob, verify_plan};
use usgp_proto::device::{
    ChoosePackageV1, ConfirmV1, DeviceArch, DeviceHelloV1, DevicePackageV1, EndReason,
    EndSessionV1, FirmwareKind, SCHEMA_V1, SessionOpenedV1, SessionState, WipeConfirmation,
};
use usgp_proto::job_plan::{JobPlanV1, PlanExpectation};
use usgp_proto::progress::{FailureCategory, FailureV1, ProgressEvent, ProgressV1, Step};
use usgp_proto::{AgentNonce, AgentVersion, AuthCode, DiskToken, JobId, MacList, codes};

use crate::client::{ApiFailure, DeviceApi};
use crate::disks::{DiskEntry, Inventory};
use crate::host::{Host, HostFacts, PowerAction, WaitBudget};
use crate::link::ApiLink;
use crate::ui::{self, Console, ConsoleClosed, ConsoleView, Input};

/// How long one wait for a choice lasts before it is simply repeated.
const CHOICE_WAIT: Duration = Duration::from_secs(3600);
/// Poll interval bounds (the server suggests `poll_ms`).
const POLL_MS: (u64, u64) = (500, 10_000);
/// Design caps on the job's own I/O waits (below the plan's limits).
const MAX_REQUEST: Duration = Duration::from_secs(300);
const MAX_IO: Duration = Duration::from_secs(60);

/// Why the session stopped before a job started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// The boot service offered no package (REQ-TGT-008).
    NothingToOffer,
    /// No eligible disk (REQ-DISK-003).
    NoDisk,
    /// Not UEFI or not x64 (REQ-PE-020).
    FirmwareUnsupported,
    /// The server refused the session (code attempts, or an operator).
    SessionRefused,
    /// The session expired or ended on the server.
    SessionEnded,
    /// The agent could not go on (the text says why).
    AgentError(String),
}

/// How the run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The job succeeded and the server recorded it.
    Succeeded(JobId),
    /// The job failed (shown and reported by the engine).
    JobFailed {
        /// Whether anything was written to the disk.
        written: bool,
        /// The reason code.
        code: String,
    },
    /// The wipe confirmation was not accepted; nothing was written.
    NotConfirmed(String),
    /// Stopped before the confirmation; nothing was written.
    Stopped(StopReason),
    /// Cancelled by the person; nothing was written.
    Cancelled,
    /// A start-up check failed (FIPS, facts, configuration).
    StartupFailed(String),
    /// The server could not be reached or authenticated.
    Unreachable(String),
}

impl Outcome {
    /// The process exit code (used by the simulation and CI):
    /// 0 success, 1 start-up failure, 2 stopped before confirmation
    /// (nothing to offer, no disk, firmware, session refused or ended),
    /// 3 confirmation not accepted, 4 job failed before any disk write,
    /// 5 job failed after a disk write, 6 cancelled, 7 server unreachable.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Succeeded(_) => 0,
            Self::StartupFailed(_) => 1,
            Self::Stopped(_) => 2,
            Self::NotConfirmed(_) => 3,
            Self::JobFailed { written: false, .. } => 4,
            Self::JobFailed { written: true, .. } => 5,
            Self::Cancelled => 6,
            Self::Unreachable(_) => 7,
        }
    }
}

/// How the run ended, and what the person chose to do next (restart or
/// shut down), if anything. On success the action is always a restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ending {
    /// The outcome.
    pub outcome: Outcome,
    /// The power action to take.
    pub action: Option<PowerAction>,
}

/// One device session.
pub struct Agent<'a> {
    /// The server.
    pub api: &'a mut dyn DeviceApi,
    /// The machine.
    pub host: &'a mut dyn Host,
    /// The screen and keyboard.
    pub console: &'a mut dyn Console,
    /// The pinned plan and content keys.
    pub keys: &'a PlanKeys,
    /// The FIPS provider.
    pub crypto: &'a dyn CryptoProvider,
    /// The engine's clock.
    pub clock: &'a dyn Clock,
}

impl std::fmt::Debug for Agent<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Agent").finish_non_exhaustive()
    }
}

/// What a choice screen returned.
enum Flow<T> {
    Next(T),
    Back,
}

impl Agent<'_> {
    /// Shows a persistent screen and waits for the person's restart or
    /// shutdown choice (REQ-JOB-005 item 4).
    pub fn stop(&mut self, title: &str, lines: &[String], outcome: Outcome) -> Ending {
        self.console.show(&ui::stop_screen(title, lines));
        let action = self.wait_for_person();
        Ending { outcome, action }
    }

    /// Waits for `R` or `S`. `None` if the console closed.
    fn wait_for_person(&mut self) -> Option<PowerAction> {
        loop {
            match self.console.line(CHOICE_WAIT) {
                Ok(Some(l)) => match Input::parse(&l) {
                    Input::Restart => return Some(PowerAction::Restart),
                    Input::Shutdown => return Some(PowerAction::Shutdown),
                    _ => {}
                },
                Ok(None) => {}
                Err(ConsoleClosed) => return None,
            }
        }
    }

    /// Runs the session with an already reachable server.
    pub fn run(&mut self, facts: &HostFacts) -> Ending {
        let hello = match hello(facts) {
            Ok(h) => h,
            Err(why) => {
                return self.stop(
                    "Cannot start a session",
                    &[why.to_owned()],
                    Outcome::StartupFailed(why.to_owned()),
                );
            }
        };
        let opened = match self.api.open(&hello) {
            Ok(o) => o,
            Err(e) => {
                let why = e.describe();
                return self.stop(
                    "Cannot reach the provisioning server",
                    &[why.clone(), "Nothing was written to any disk.".to_owned()],
                    Outcome::Unreachable(why),
                );
            }
        };
        if facts.firmware != FirmwareKind::Uefi || facts.arch != DeviceArch::X64 {
            self.end(EndReason::FirmwareUnsupported, Vec::new());
            return self.stop(
                "This device cannot be installed",
                &[
                    format!(
                        "The environment started in {} mode on {}. This package needs UEFI \
                         mode on x64: set the firmware to boot in UEFI mode and start again.",
                        facts.firmware.as_str(),
                        facts.arch.as_str()
                    ),
                    "Nothing was written to any disk.".to_owned(),
                ],
                Outcome::Stopped(StopReason::FirmwareUnsupported),
            );
        }
        if let Err(end) = self.authorise(&opened) {
            return end;
        }
        loop {
            let pkg = match self.choose_package() {
                Ok(p) => p,
                Err(end) => return end,
            };
            loop {
                let (inv, token) = match self.choose_disk(&pkg) {
                    Ok(Flow::Next(x)) => x,
                    Ok(Flow::Back) => break,
                    Err(end) => return end,
                };
                let Some(entry) = inv.by_token(token).cloned() else {
                    continue;
                };
                match self.confirm_wipe(&pkg, &entry) {
                    Ok(Flow::Next(())) => {}
                    Ok(Flow::Back) => continue,
                    Err(end) => return end,
                }
                match self.confirm_and_run(&opened, &pkg, &entry) {
                    Ok(end) => return end,
                    Err(note) => {
                        // Refused with the session still open: choose again.
                        self.console.show(&ui::status_screen(
                            "The confirmation was not accepted",
                            &[
                                &note,
                                "Nothing was written to any disk. Choose the disk again.",
                            ],
                        ));
                    }
                }
            }
        }
    }

    /// Ends the session before confirmation (best effort: the device shows
    /// its screen either way).
    fn end(&mut self, reason: EndReason, refused: Vec<usgp_proto::device::RefusedDiskV1>) {
        let _ = self.api.end(&EndSessionV1 {
            reason,
            refused_disks: refused,
        });
    }

    /// Cancels before the wipe confirmation (REQ-TGT-010).
    fn cancel(&mut self) -> Ending {
        let note = match self.api.cancel() {
            Ok(()) => "The session was cancelled.".to_owned(),
            Err(e) => format!(
                "The cancellation could not be recorded on the server: {}",
                e.describe()
            ),
        };
        self.stop(
            "Cancelled",
            &[note, "Nothing was written to any disk.".to_owned()],
            Outcome::Cancelled,
        )
    }

    /// The stop for a session the server no longer accepts.
    fn session_over(&mut self, e: &ApiFailure) -> Option<Ending> {
        let refused = e.is(403, codes::SESSION_REFUSED);
        if !refused && !e.is(403, codes::SESSION_ENDED) {
            return None;
        }
        Some(self.state_stop(if refused {
            SessionState::Refused
        } else {
            SessionState::Expired
        }))
    }

    fn state_stop(&mut self, s: SessionState) -> Ending {
        let (title, line, reason) = match s {
            SessionState::Refused => (
                "This device was refused",
                "The server refused this session (an operator refused it, or too many codes \
                 were wrong).",
                StopReason::SessionRefused,
            ),
            _ => (
                "The session has ended",
                "The session expired or ended on the server. Restart the device to try again.",
                StopReason::SessionEnded,
            ),
        };
        self.stop(
            title,
            &[
                line.to_owned(),
                "Nothing was written to any disk.".to_owned(),
            ],
            Outcome::Stopped(reason),
        )
    }

    fn agent_error(&mut self, title: &str, why: String) -> Ending {
        self.end(EndReason::AgentError, Vec::new());
        self.stop(
            title,
            &[why.clone(), "Nothing was written to any disk.".to_owned()],
            Outcome::Stopped(StopReason::AgentError(why)),
        )
    }

    /// Code or approval (REQ-TGT-013, REQ-TGT-014).
    fn authorise(&mut self, opened: &SessionOpenedV1) -> Result<(), Ending> {
        let codes_allowed = self.console.set_echo(false).is_ok();
        let r = self.authorise_loop(opened, codes_allowed);
        let _ = self.console.set_echo(true);
        r
    }

    fn authorise_loop(
        &mut self,
        opened: &SessionOpenedV1,
        codes_allowed: bool,
    ) -> Result<(), Ending> {
        let poll = Duration::from_millis(u64::from(opened.poll_ms).clamp(POLL_MS.0, POLL_MS.1));
        let mut display = opened.display_code;
        let mut attempts = 0u32;
        let mut service: Option<String> = None;
        let mut note: Option<String> = (!codes_allowed).then(|| {
            "Code entry is not available on this console; ask an operator to approve this \
             device."
                .to_owned()
        });
        let mut console_open = true;
        loop {
            match self.api.status() {
                Ok(st) => match st.state {
                    SessionState::Authorised => return Ok(()),
                    SessionState::AwaitingAuthorisation => {
                        attempts = st.code_attempts_left;
                        display = st.display_code;
                        service = st.boot_service_name.map(|n| n.as_str().to_owned());
                    }
                    s => return Err(self.state_stop(s)),
                },
                Err(e) => {
                    if let Some(end) = self.session_over(&e) {
                        return Err(end);
                    }
                    note = Some(format!("Waiting for the server: {}", e.describe()));
                }
            }
            self.console.show(&ui::authorise_screen(
                &display,
                attempts,
                service.as_deref(),
                note.as_deref(),
            ));
            if !console_open {
                std::thread::sleep(poll);
                continue;
            }
            let line = match self.console.line(poll) {
                Ok(Some(l)) => l,
                Ok(None) => continue,
                Err(ConsoleClosed) => {
                    // Approval can still arrive.
                    console_open = false;
                    continue;
                }
            };
            // The newline was not echoed.
            match Input::parse(&line) {
                Input::Cancel => return Err(self.cancel()),
                Input::Empty => continue,
                _ if !codes_allowed => continue,
                _ => {}
            }
            let Ok(code) = AuthCode::parse(&line) else {
                note = Some(
                    "That is not a code. A code has 10 letters and digits (hyphens and spaces \
                     are ignored)."
                        .to_owned(),
                );
                continue;
            };
            match self.api.submit_code(&code) {
                Ok(st) if st.state == SessionState::Authorised => return Ok(()),
                Ok(st) => {
                    attempts = st.code_attempts_left;
                }
                Err(e) if e.is(422, codes::CODE_NOT_ACCEPTED) => {
                    if let ApiFailure::Status {
                        attempts_left: Some(a),
                        ..
                    } = e
                    {
                        attempts = a;
                    }
                    note = Some("That code was not accepted.".to_owned());
                }
                Err(e) => {
                    if let Some(end) = self.session_over(&e) {
                        return Err(end);
                    }
                    note = Some(format!("The code could not be checked: {}", e.describe()));
                }
            }
        }
    }

    /// The package choice (REQ-TGT-004, REQ-TGT-008).
    fn choose_package(&mut self) -> Result<DevicePackageV1, Ending> {
        let mut note: Option<String> = None;
        loop {
            let list = match self.api.packages() {
                Ok(l) => l,
                Err(e) => {
                    if let Some(end) = self.session_over(&e) {
                        return Err(end);
                    }
                    return Err(self.agent_error(
                        "Cannot list the packages",
                        format!("The package list could not be read: {}", e.describe()),
                    ));
                }
            };
            let packages = list.packages().to_vec();
            if packages.is_empty() {
                self.end(EndReason::NothingToOffer, Vec::new());
                return Err(self.stop(
                    "No deployment is available",
                    &[
                        "This boot service has no package to offer to this device.".to_owned(),
                        "The operator has been told. Nothing was written to any disk.".to_owned(),
                    ],
                    Outcome::Stopped(StopReason::NothingToOffer),
                ));
            }
            loop {
                self.console
                    .show(&ui::packages_screen(&packages, note.as_deref()));
                let line = match self.console.line(CHOICE_WAIT) {
                    Ok(Some(l)) => l,
                    Ok(None) => continue,
                    Err(ConsoleClosed) => return Err(self.cancel()),
                };
                match Input::parse(&line) {
                    Input::Cancel => return Err(self.cancel()),
                    Input::Number(n) => {
                        let Some(p) = n.checked_sub(1).and_then(|i| packages.get(i)) else {
                            note = Some("Type a number from the list.".to_owned());
                            continue;
                        };
                        let choice = ChoosePackageV1 {
                            package_id: p.package_id,
                            revision: p.revision,
                        };
                        match self.api.choose_package(&choice) {
                            Ok(()) => return Ok(p.clone()),
                            Err(e) => {
                                if let Some(end) = self.session_over(&e) {
                                    return Err(end);
                                }
                                note = Some(format!(
                                    "That package could not be chosen: {}",
                                    e.describe()
                                ));
                                // The list may have changed.
                                break;
                            }
                        }
                    }
                    _ => note = Some("Type a number from the list, or C.".to_owned()),
                }
            }
        }
    }

    /// The disk choice (REQ-DISK-001..005, REQ-TGT-009).
    fn choose_disk(
        &mut self,
        pkg: &DevicePackageV1,
    ) -> Result<Flow<(Inventory, DiskToken)>, Ending> {
        let found = match self.host.disks() {
            Ok(f) => f,
            Err(e) => {
                return Err(self.agent_error(
                    "Cannot list the disks",
                    format!("The disks could not be listed: {e}"),
                ));
            }
        };
        let seen = found.len();
        let crypto = self.crypto;
        let mut rng_failed = false;
        let mut token = || {
            let mut b = [0u8; 16];
            if crypto.fill_random(&mut b).is_err() {
                rng_failed = true;
            }
            DiskToken::from_random_bytes(b)
        };
        let inv = Inventory::build(
            found,
            &self.host.eligibility(),
            pkg.required_disk_bytes,
            &mut token,
        );
        if rng_failed {
            return Err(self.agent_error(
                "Cannot list the disks",
                "The random number generator failed.".to_owned(),
            ));
        }
        if inv.eligible().next().is_none() {
            self.end(EndReason::NoDisk, inv.refused_report());
            let mut lines = Vec::new();
            if seen == 0 {
                lines.push("No disk was found on this device.".to_owned());
            } else {
                lines.push("Disks were found, but none can be used:".to_owned());
                for e in inv.refused() {
                    let f = &e.found.facts;
                    lines.push(format!(
                        "  - {} {} ({})",
                        crate::disks::gb(f.size_bytes),
                        usgp_proto::DiskText::sanitized(&f.identity.model).as_str(),
                        f.bus
                    ));
                    for r in &e.refusals {
                        lines.push(format!("      because: {r}"));
                    }
                }
            }
            lines.push(
                "A storage driver may be missing from this environment. The operator has been \
                 told. Nothing was written to any disk."
                    .to_owned(),
            );
            return Err(self.stop(
                "No disk can be used",
                &lines,
                Outcome::Stopped(StopReason::NoDisk),
            ));
        }
        let eligible: Vec<DiskEntry> = inv.eligible().cloned().collect();
        let mut note: Option<String> = None;
        loop {
            self.console
                .show(&ui::disks_screen(pkg.name.as_str(), &inv, note.as_deref()));
            let line = match self.console.line(CHOICE_WAIT) {
                Ok(Some(l)) => l,
                Ok(None) => continue,
                Err(ConsoleClosed) => return Err(self.cancel()),
            };
            match Input::parse(&line) {
                Input::Cancel => return Err(self.cancel()),
                Input::Back => return Ok(Flow::Back),
                Input::Number(n) => {
                    let Some(e) = n.checked_sub(1).and_then(|i| eligible.get(i)) else {
                        note = Some("Type a number from the list.".to_owned());
                        continue;
                    };
                    let Some(desc) = &e.descriptor else {
                        continue;
                    };
                    match self.api.choose_disk(desc) {
                        Ok(()) => return Ok(Flow::Next((inv.clone(), e.token))),
                        Err(err) => {
                            if let Some(end) = self.session_over(&err) {
                                return Err(end);
                            }
                            note =
                                Some(format!("That disk could not be chosen: {}", err.describe()));
                        }
                    }
                }
                _ => note = Some("Type a number from the list, B or C.".to_owned()),
            }
        }
    }

    /// The separate wipe confirmation (REQ-DISK-006).
    fn confirm_wipe(&mut self, pkg: &DevicePackageV1, e: &DiskEntry) -> Result<Flow<()>, Ending> {
        loop {
            self.console.show(&ui::wipe_screen(pkg, e));
            let line = match self.console.line(CHOICE_WAIT) {
                Ok(Some(l)) => l,
                Ok(None) => continue,
                Err(ConsoleClosed) => return Err(self.cancel()),
            };
            match Input::parse(&line) {
                Input::Wipe => return Ok(Flow::Next(())),
                Input::Back => return Ok(Flow::Back),
                Input::Cancel => return Err(self.cancel()),
                _ => {}
            }
        }
    }

    /// Sends the confirmation and runs the job. `Err(note)` if the server
    /// refused the confirmation while the session stays open (the person
    /// chooses again).
    fn confirm_and_run(
        &mut self,
        opened: &SessionOpenedV1,
        pkg: &DevicePackageV1,
        e: &DiskEntry,
    ) -> Result<Ending, String> {
        let Some(desc) = e.descriptor.clone() else {
            return Err("the disk has no descriptor".to_owned());
        };
        let mut nb = [0u8; 32];
        if self.crypto.fill_random(&mut nb).is_err() {
            return Ok(self.agent_error(
                "Cannot confirm",
                "The random number generator failed.".to_owned(),
            ));
        }
        let nonce = AgentNonce::from_random_bytes(nb);
        let req = ConfirmV1 {
            package_id: pkg.package_id,
            revision: pkg.revision,
            disk_token: e.token,
            confirm: WipeConfirmation::WipeDisk,
            agent_nonce: nonce,
        };
        let confirmed = match self.api.confirm(&req) {
            Ok(c) => c,
            Err(f) if f.is(503, codes::AUDIT_UNAVAILABLE) => {
                let why = "The server could not durably record the wipe authorisation, so it did \
                           not start the install."
                    .to_owned();
                return Ok(self.stop(
                    "The install did not start",
                    &[why.clone(), "Nothing was written to any disk.".to_owned()],
                    Outcome::NotConfirmed(why),
                ));
            }
            Err(f) if matches!(f.status(), Some(409 | 422)) => return Err(f.describe()),
            Err(f) => {
                if let Some(end) = self.session_over(&f) {
                    return Ok(end);
                }
                let why = f.describe();
                return Ok(self.stop(
                    "The install did not start",
                    &[
                        format!("The confirmation did not complete: {why}"),
                        "Nothing was written to any disk.".to_owned(),
                    ],
                    Outcome::NotConfirmed(why),
                ));
            }
        };
        Ok(self.run_job(opened, pkg, e, &desc, &nonce, &confirmed))
    }

    fn run_job(
        &mut self,
        opened: &SessionOpenedV1,
        pkg: &DevicePackageV1,
        e: &DiskEntry,
        desc: &usgp_proto::DiskDescriptorV1,
        nonce: &AgentNonce,
        confirmed: &usgp_proto::device::ConfirmedV1,
    ) -> Ending {
        let expect = PlanExpectation {
            agent_nonce: nonce,
            session_id: opened.session_id,
            job_id: confirmed.job_id,
            package_id: pkg.package_id,
            package_revision: pkg.revision,
            disk: desc,
        };
        let engine = Engine::new(self.crypto, self.clock, self.host.engine_config());
        // Verify first so the waits can be sized from the signed plan; a
        // plan that does not verify goes through `verify_and_run`, which
        // shows and reports the integrity failure and touches nothing.
        let verified = verify_plan(
            &confirmed.plan,
            &confirmed.content_manifest,
            self.keys,
            &expect,
            self.crypto,
        )
        .ok();
        let budget = verified.as_ref().map_or_else(WaitBudget::default, |v| {
            let (request, io, budget) = budgets(v.plan());
            self.api.bound_waits(request, io);
            budget
        });
        let job_id = confirmed.job_id;
        let result = match self.host.platform(e, budget) {
            Err(err) => Err(format!("The disk platform could not be prepared: {err}")),
            Ok(mut platform) => {
                let mut link = ApiLink::new(&mut *self.api);
                let mut view = ConsoleView::new(&mut *self.console);
                Ok(match &verified {
                    Some(v) => engine.run(v, &mut *platform, &mut link, &mut view),
                    None => engine.verify_and_run(
                        &SignedJob {
                            plan: &confirmed.plan,
                            content: &confirmed.content_manifest,
                            keys: self.keys,
                            expect,
                        },
                        &mut *platform,
                        &mut link,
                        &mut view,
                    ),
                })
            }
        };
        let result = match result {
            Ok(r) => r,
            Err(why) => {
                report_local_failure(&mut *self.api, job_id);
                return self.stop(
                    "INSTALL FAILED",
                    &[
                        "Failed step: 1 - Download and verify the content".to_owned(),
                        why,
                        "Nothing was written to any disk.".to_owned(),
                    ],
                    Outcome::JobFailed {
                        written: false,
                        code: codes::INTERNAL.as_str().to_owned(),
                    },
                );
            }
        };
        match result {
            Ok(s) => Ending {
                outcome: Outcome::Succeeded(s.job_id),
                action: Some(PowerAction::Restart),
            },
            Err(f) => {
                // The failure is on screen (ConsoleView keeps it).
                let action = self.wait_for_person();
                Ending {
                    outcome: Outcome::JobFailed {
                        written: f.disk_written,
                        code: f.code.as_str().to_owned(),
                    },
                    action,
                }
            }
        }
    }
}

/// The hello from the host's facts.
fn hello(f: &HostFacts) -> Result<DeviceHelloV1, &'static str> {
    Ok(DeviceHelloV1 {
        schema: SCHEMA_V1,
        agent_version: AgentVersion::new(crate::AGENT_VERSION)
            .map_err(|_| "the agent version is not reportable")?,
        firmware: f.firmware,
        arch: f.arch,
        secure_boot: f.secure_boot,
        memory_bytes: f.memory_bytes,
        macs: MacList::new(f.macs.clone())
            .map_err(|_| "no usable network adapter address (MAC) was found")?,
    })
}

/// Waits sized from the verified plan: every request and every platform
/// tool well below the stall limit and the shortest step timeout (WU-8
/// POAM: the engine checks its limits only between calls).
#[must_use]
pub fn budgets(p: &JobPlanV1) -> (Duration, Duration, WaitBudget) {
    let shortest = p
        .steps
        .iter()
        .map(|s| s.timeout_s)
        .chain(std::iter::once(p.stall_timeout_s))
        .min()
        .unwrap_or(1);
    let half = Duration::from_secs(u64::from(shortest) / 2).max(Duration::from_secs(1));
    let request = MAX_REQUEST.min(half);
    let io = MAX_IO.min(half);
    let tool = WaitBudget::default().tool.min(half);
    let volume_arrival = WaitBudget::default().volume_arrival.min(half);
    (
        request,
        io,
        WaitBudget {
            tool,
            volume_arrival,
        },
    )
}

/// Reports a step-1 local failure when the engine could not be started
/// (best effort; the device shows the failure either way).
fn report_local_failure(api: &mut dyn DeviceApi, job: JobId) {
    let failure = FailureV1 {
        step: Step::VERIFY_CONTENT,
        category: FailureCategory::Local,
        code: codes::INTERNAL,
        files: Vec::new(),
        count: 0,
        attempts: 1,
    };
    let report = ProgressV1 {
        seq: 1,
        step: Step::VERIFY_CONTENT,
        event: ProgressEvent::Failed,
        bytes_done: None,
        bytes_total: None,
        item: None,
        layout: None,
        failure: Some(failure),
    };
    let _ = api.report(job, &report);
}
