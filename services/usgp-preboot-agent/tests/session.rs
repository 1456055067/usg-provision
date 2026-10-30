//! The session flow against a fake server (no network): authorisation,
//! cancellation, the "nothing to offer" and "no disk" endings, firmware
//! refusal and a refused wipe record (REQ-TGT-008..014, REQ-DISK-003,
//! REQ-DISK-006, REQ-PE-020; decision 0018 items 1, 7, 10).

#![cfg(test)]
#![cfg(not(windows))]

mod common;

use std::collections::VecDeque;
use std::time::Duration;

use usgp_common::Sha256Digest;
use usgp_preboot_agent::client::{ApiFailure, DeviceApi};
use usgp_preboot_agent::host::PowerAction;
use usgp_preboot_agent::session::{Agent, Outcome, StopReason};
use usgp_preboot_agent::sim::{SimDiskSpec, SimHost};
use usgp_proto::device::{
    ChoosePackageV1, ConfirmV2, ConfirmedV2, DeviceArch, DeviceHelloV1, DevicePackageListV1,
    DiskRefusal, EndReason, EndSessionV1, SessionOpenedV1, SessionState, SessionStatusV1,
};
use usgp_proto::progress::{ProgressAckV1, ProgressV1, ProgressV2};
use usgp_proto::{
    AuthCode, DiskDescriptorV1, DisplayCode, JobId, SessionId, SessionToken, UnixMicros, codes,
};

use common::{GB, console, disk_file, mac, temp_dir};

#[derive(Default)]
struct Fake {
    state: Option<SessionState>,
    good_code: String,
    attempts: u32,
    packages: Vec<serde_json::Value>,
    confirm_failure: Option<ApiFailure>,
    open_failure: Option<ApiFailure>,
    calls: Vec<String>,
    ends: Vec<EndSessionV1>,
    hellos: Vec<DeviceHelloV1>,
    statuses: VecDeque<SessionState>,
}

fn status(s: SessionState, attempts: u32) -> SessionStatusV1 {
    SessionStatusV1 {
        state: s,
        display_code: DisplayCode::parse("ABC-DEF").unwrap(),
        code_attempts_left: attempts,
        expires_at: UnixMicros::new(4_000_000_000_000_000).unwrap(),
        boot_service_name: None,
        reason_code: None,
    }
}

fn refusal(status: u16, code: usgp_proto::ErrorCode, left: Option<u32>) -> ApiFailure {
    ApiFailure::Status {
        status,
        code: Some(code),
        message: None,
        attempts_left: left,
    }
}

impl DeviceApi for Fake {
    fn open(&mut self, hello: &DeviceHelloV1) -> Result<SessionOpenedV1, ApiFailure> {
        self.calls.push("open".into());
        self.hellos.push(hello.clone());
        if let Some(f) = self.open_failure.clone() {
            return Err(f);
        }
        self.state = Some(SessionState::AwaitingAuthorisation);
        Ok(SessionOpenedV1 {
            session_id: SessionId::from_random_bytes([3; 16]),
            token: SessionToken::from_random_bytes(&[9; 32]),
            display_code: DisplayCode::parse("ABC-DEF").unwrap(),
            state: SessionState::AwaitingAuthorisation,
            poll_ms: 500,
            expires_at: UnixMicros::new(4_000_000_000_000_000).unwrap(),
        })
    }

    fn status(&mut self) -> Result<SessionStatusV1, ApiFailure> {
        if let Some(s) = self.statuses.pop_front() {
            self.state = Some(s);
        }
        Ok(status(self.state.unwrap(), self.attempts))
    }

    fn submit_code(&mut self, code: &AuthCode) -> Result<SessionStatusV1, ApiFailure> {
        self.calls.push("code".into());
        if code.normalized() == self.good_code {
            self.state = Some(SessionState::Authorised);
            return Ok(status(SessionState::Authorised, self.attempts));
        }
        self.attempts = self.attempts.saturating_sub(1);
        Err(refusal(422, codes::CODE_NOT_ACCEPTED, Some(self.attempts)))
    }

    fn packages(&mut self) -> Result<DevicePackageListV1, ApiFailure> {
        self.calls.push("packages".into());
        assert_eq!(
            self.state,
            Some(SessionState::Authorised),
            "listed before authorisation"
        );
        Ok(serde_json::from_value(serde_json::json!({ "packages": self.packages })).unwrap())
    }

    fn choose_package(&mut self, _c: &ChoosePackageV1) -> Result<(), ApiFailure> {
        self.calls.push("package".into());
        Ok(())
    }

    fn choose_disk(&mut self, _d: &DiskDescriptorV1) -> Result<(), ApiFailure> {
        self.calls.push("disk".into());
        Ok(())
    }

    fn confirm(&mut self, c: &ConfirmV2) -> Result<ConfirmedV2, ApiFailure> {
        self.calls.push("confirm".into());
        assert_ne!(c.agent_nonce.as_bytes(), &[0u8; 32]);
        // The job key's public half (M4): a P-384 SPKI generated here.
        assert!(usgp_crypto::VerifyingKey::from_spki_der(c.job_key_spki_b64.as_der()).is_ok());
        Err(self
            .confirm_failure
            .clone()
            .unwrap_or(refusal(503, codes::AUDIT_UNAVAILABLE, None)))
    }

    fn cancel(&mut self) -> Result<(), ApiFailure> {
        self.calls.push("cancel".into());
        Ok(())
    }

    fn end(&mut self, e: &EndSessionV1) -> Result<(), ApiFailure> {
        self.calls.push("end".into());
        self.ends.push(e.clone());
        Ok(())
    }

    fn fetch_chunk(&mut self, _: JobId, _: &Sha256Digest, _: u64) -> Result<Vec<u8>, ApiFailure> {
        panic!("no content may be fetched in these tests");
    }

    fn report(&mut self, _: JobId, _: &ProgressV1) -> Result<ProgressAckV1, ApiFailure> {
        panic!("no job runs in these tests");
    }

    fn report_v2(&mut self, _: JobId, _: &ProgressV2) -> Result<ProgressAckV1, ApiFailure> {
        panic!("no job runs in these tests");
    }

    fn bound_waits(&mut self, _: Duration, _: Duration) {}
}

fn package() -> serde_json::Value {
    serde_json::json!({
        "package_id": "1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516", "revision": 1,
        "name": "Windows Test", "description": null,
        "os": {"release": "windows-11", "edition": "enterprise", "architecture": "x64", "source": "declared"},
        "image_bytes": 1_000_000u64, "required_disk_bytes": 64_000_000_000u64
    })
}

fn fake() -> Fake {
    Fake {
        good_code: "0123456789".into(),
        attempts: 5,
        packages: vec![package()],
        ..Fake::default()
    }
}

fn spec(path: std::path::PathBuf, n: u32) -> SimDiskSpec {
    SimDiskSpec {
        path,
        facts: usgp_disk::DiskFacts {
            identity: usgp_disk::DiskIdentity {
                device_number: n,
                model: format!("Sim {n}"),
                serial: Some(format!("SIM-{n}")),
            },
            bus: usgp_disk::Bus::Nvme,
            removable: false,
            read_only: false,
            logical_sector: 512,
            physical_sector: 4096,
            size_bytes: 0,
            hosts_boot_environment: false,
            partitions: vec![usgp_disk::ExistingPartition {
                start_bytes: 1 << 20,
                size_bytes: 1 << 30,
                label: Some("Old data".into()),
            }],
        },
        kinds: vec![usgp_proto::disk::PartitionKind::Basic],
        volumes_known: true,
    }
}

/// Runs an agent with `lines` queued, then closes the console.
fn run(
    api: &mut Fake,
    host: &mut SimHost,
    lines: &[&str],
) -> (usgp_preboot_agent::session::Ending, String, Vec<bool>) {
    let (mut con, mut drv, echo) = console();
    for l in lines {
        drv.send(l);
    }
    drv.close();
    let clock = usgp_deploy::SystemClock::new();
    let facts = {
        use usgp_preboot_agent::host::Host;
        host.facts().unwrap()
    };
    let keys = keys();
    let handoff = handoff();
    let end = Agent {
        api,
        host,
        console: &mut con,
        keys: &keys,
        handoff: &handoff,
        crypto: usgp_crypto::provider(),
        clock: &clock,
    }
    .run(&facts);
    drop(con);
    drv.drain();
    let echo = echo.lock().unwrap().clone();
    (end, drv.all(), echo)
}

fn handoff() -> usgp_preboot_agent::session::Handoff {
    usgp_preboot_agent::session::Handoff {
        server_url: "https://server.test".to_owned(),
        server_name: "server.test".to_owned(),
        trust_anchors_pem: String::new(),
        plan_key_pem: String::new(),
        tail: usgp_deploy::TailConfig::default(),
    }
}

fn keys() -> usgp_deploy::PlanKeys {
    let a = usgp_crypto::SigningKey::generate().unwrap();
    let b = usgp_crypto::SigningKey::generate().unwrap();
    usgp_deploy::PlanKeys {
        plan: usgp_deploy::PinnedKey::new(a.verifying_key().clone()),
        content: usgp_deploy::PinnedKey::new(b.verifying_key().clone()),
    }
}

fn host(tag: &str) -> SimHost {
    let d = temp_dir(tag);
    SimHost::new(&d, &d.join("fw.json"), mac(1))
}

#[test]
fn wrong_code_then_right_code_then_cancel() {
    let mut api = fake();
    let mut h = host("code");
    let (end, screens, echo) = run(&mut api, &mut h, &["9999999999", "0123-456789", "c", "s"]);
    assert_eq!(end.outcome, Outcome::Cancelled);
    assert_eq!(end.outcome.exit_code(), 6);
    assert_eq!(end.action, Some(PowerAction::Shutdown));
    assert_eq!(api.calls, ["open", "code", "code", "packages", "cancel"]);
    assert!(screens.contains("That code was not accepted."));
    assert!(screens.contains("Code attempts left: 4"));
    assert!(
        !screens.contains("0123") && !screens.contains("9999999999"),
        "code shown"
    );
    // Echo off for the code, back on after.
    assert_eq!(echo, [false, true]);
    assert!(screens.contains("Nothing was written to any disk."));
}

#[test]
fn not_a_code_is_not_sent() {
    let mut api = fake();
    let mut h = host("notcode");
    let (end, screens, _) = run(&mut api, &mut h, &["hello", "c", "r"]);
    assert_eq!(end.outcome, Outcome::Cancelled);
    assert_eq!(api.calls, ["open", "cancel"]);
    assert!(screens.contains("That is not a code"));
}

#[test]
fn approval_without_any_typing() {
    let mut api = fake();
    api.statuses = VecDeque::from([
        SessionState::AwaitingAuthorisation,
        SessionState::Authorised,
    ]);
    let mut h = host("approve");
    let facts = {
        use usgp_preboot_agent::host::Host;
        h.facts().unwrap()
    };
    let (mut con, mut drv, _) = console();
    let keys = keys();
    let handoff = handoff();
    let clock = usgp_deploy::SystemClock::new();
    let end = std::thread::scope(|sc| {
        let agent = sc.spawn(|| {
            Agent {
                api: &mut api,
                host: &mut h,
                console: &mut con,
                keys: &keys,
                handoff: &handoff,
                crypto: usgp_crypto::provider(),
                clock: &clock,
            }
            .run(&facts)
        });
        // Nothing is typed while waiting: the approval arrives by polling.
        // A failed check closes the input so the agent ends and the panic
        // is re-raised, rather than the scope hanging (round 3).
        let driven = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drv.wait_for("Display code:   ABC-DEF");
            drv.wait_for("Choose what to install");
            drv.send("c");
            drv.wait_for("Cancelled");
            drv.send("s");
        }));
        if let Err(p) = driven {
            drv.close();
            let _ = agent.join();
            std::panic::resume_unwind(p);
        }
        agent.join().unwrap()
    });
    assert_eq!(end.outcome, Outcome::Cancelled);
    assert_eq!(end.action, Some(PowerAction::Shutdown));
    assert_eq!(api.calls, ["open", "packages", "cancel"]);
}

#[test]
fn eof_while_waiting_for_authorisation_cancels() {
    let mut api = fake();
    let mut h = host("eofauth");
    let (end, screens, _) = run(&mut api, &mut h, &[]);
    assert_eq!(end.outcome, Outcome::Cancelled);
    assert_eq!(end.action, None, "EOF never restarts or shuts down");
    assert_eq!(api.calls, ["open", "cancel"]);
    assert!(screens.contains("Nothing was written to any disk."));
}

#[test]
fn eof_at_a_persistent_screen_ends_with_no_power_action() {
    let mut api = fake();
    api.packages.clear();
    let mut h = host("eofstop");
    let (end, _, _) = run(&mut api, &mut h, &["0123456789"]);
    assert_eq!(end.outcome, Outcome::Stopped(StopReason::NothingToOffer));
    assert_eq!(end.action, None);
}

#[test]
fn refused_session_stops() {
    let mut api = fake();
    api.statuses = VecDeque::from([SessionState::Refused]);
    let mut h = host("refused");
    let (end, screens, _) = run(&mut api, &mut h, &["r"]);
    assert_eq!(end.outcome, Outcome::Stopped(StopReason::SessionRefused));
    assert_eq!(end.action, Some(PowerAction::Restart));
    assert!(screens.contains("This device was refused"));
}

#[test]
fn nothing_to_offer_ends_the_session() {
    let mut api = fake();
    api.packages.clear();
    let mut h = host("nothing");
    let (end, screens, _) = run(&mut api, &mut h, &["0123456789", "s"]);
    assert_eq!(end.outcome, Outcome::Stopped(StopReason::NothingToOffer));
    assert_eq!(end.outcome.exit_code(), 2);
    assert_eq!(api.ends.first().unwrap().reason, EndReason::NothingToOffer);
    assert!(screens.contains("No deployment is available"));
}

#[test]
fn firmware_must_be_uefi_x64() {
    let mut api = fake();
    let mut h = host("bios");
    h.facts.arch = DeviceArch::X86;
    let (end, screens, _) = run(&mut api, &mut h, &["s"]);
    assert_eq!(
        end.outcome,
        Outcome::Stopped(StopReason::FirmwareUnsupported)
    );
    assert_eq!(api.calls, ["open", "end"]);
    assert_eq!(
        api.ends.first().unwrap().reason,
        EndReason::FirmwareUnsupported
    );
    assert!(screens.contains("UEFI"));
}

#[test]
fn no_eligible_disk_lists_every_reason_and_reports_it() {
    let d = temp_dir("nodisk");
    let mut api = fake();
    let mut h = SimHost::new(&d, &d.join("fw.json"), mac(2));
    let mut small = spec(disk_file(&d, "small.img", 10 * GB), 0);
    small.facts.partitions.clear();
    small.kinds.clear();
    let mut usb = spec(disk_file(&d, "usb.img", 70 * GB), 1);
    usb.facts.bus = usgp_disk::Bus::Usb;
    usb.facts.removable = true;
    let mut boot = spec(disk_file(&d, "boot.img", 70 * GB), 2);
    boot.facts.hosts_boot_environment = true;
    h.disks = vec![small, usb, boot];
    let (end, screens, _) = run(&mut api, &mut h, &["0123456789", "1", "s"]);
    assert_eq!(end.outcome, Outcome::Stopped(StopReason::NoDisk));
    assert_eq!(end.outcome.exit_code(), 2);
    let e = api.ends.first().unwrap();
    assert_eq!(e.reason, EndReason::NoDisk);
    let reasons: Vec<_> = e.refused_disks.iter().map(|r| r.reason).collect();
    assert_eq!(
        reasons,
        [
            DiskRefusal::TooSmall,
            DiskRefusal::Removable,
            DiskRefusal::BootMedia
        ]
    );
    assert!(screens.contains("Disks were found, but none can be used"));
    assert!(screens.contains("because: USB-attached disk"));
    assert!(screens.contains("storage driver may be missing"));
    assert!(!api.calls.contains(&"disk".to_owned()));
}

#[test]
fn wipe_needs_its_own_word_and_a_refused_record_writes_nothing() {
    let d = temp_dir("wipe");
    let mut api = fake();
    let mut h = SimHost::new(&d, &d.join("fw.json"), mac(3));
    let target = disk_file(&d, "target.img", 70 * GB);
    h.disks = vec![spec(target.clone(), 0)];
    let before = common::ends_digest(&target, 4 << 20);
    // "1" at the wipe screen is not a confirmation; "b" goes back to the
    // disk list; then the wipe is confirmed and the server cannot record
    // it (503 audit_unavailable).
    let (end, screens, _) = run(
        &mut api,
        &mut h,
        &["0123456789", "1", "1", "1", "b", "1", "WIPE", "s"],
    );
    assert!(
        matches!(end.outcome, Outcome::NotConfirmed(_)),
        "{:?}",
        end.outcome
    );
    assert_eq!(end.outcome.exit_code(), 3);
    assert_eq!(
        api.calls,
        [
            "open", "code", "packages", "package", "disk", "disk", "confirm"
        ]
    );
    assert!(screens.contains("EVERY PARTITION AND ALL DATA"));
    assert!(screens.contains("\"Old data\""));
    assert!(screens.contains("could not durably record the wipe authorisation"));
    assert_eq!(common::ends_digest(&target, 4 << 20), before);
    assert!(
        std::fs::read_dir(&d).unwrap().all(|e| !e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("vol-"))
    );
}

#[test]
fn a_refused_confirmation_returns_to_the_disk_choice() {
    let d = temp_dir("refusedconfirm");
    let mut api = fake();
    api.confirm_failure = Some(refusal(422, codes::DISK_TOO_SMALL, None));
    let mut h = SimHost::new(&d, &d.join("fw.json"), mac(4));
    h.disks = vec![spec(disk_file(&d, "t.img", 70 * GB), 0)];
    let (end, screens, _) = run(
        &mut api,
        &mut h,
        &["0123456789", "1", "1", "WIPE", "c", "s"],
    );
    assert_eq!(end.outcome, Outcome::Cancelled);
    assert!(screens.contains("The confirmation was not accepted"));
    assert_eq!(api.calls.last().map(String::as_str), Some("cancel"));
}

/// SEC-001 / decision 0023: no boot service serves this device's network,
/// so the server opens no session (403 `forbidden`). A named screen, not
/// "cannot reach the server".
#[test]
fn no_boot_service_has_its_own_screen() {
    let mut api = fake();
    api.open_failure = Some(refusal(403, codes::FORBIDDEN, None));
    let mut h = host("noservice");
    let (end, screens, _) = run(&mut api, &mut h, &["s"]);
    assert_eq!(
        end.outcome,
        Outcome::Stopped(usgp_preboot_agent::session::StopReason::NoBootService)
    );
    assert_eq!(end.outcome.exit_code(), 2);
    assert!(screens.contains("This boot service is not set up for this device"));
    assert!(!screens.contains("Cannot reach the provisioning server"));
    assert_eq!(api.calls, ["open"]);
}

/// Decision 0023 item 2: the claimed MACs are on the wipe screen, and 409
/// `in_use` at confirmation stops with a named reason (choosing another
/// disk cannot help).
#[test]
fn claimed_macs_are_shown_and_in_use_stops() {
    let d = temp_dir("inuse");
    let mut api = fake();
    api.confirm_failure = Some(refusal(409, codes::IN_USE, None));
    let mut h = SimHost::new(&d, &d.join("fw.json"), mac(5));
    let target = disk_file(&d, "t.img", 70 * GB);
    h.disks = vec![spec(target.clone(), 0)];
    let before = common::ends_digest(&target, 4 << 20);
    let (end, screens, _) = run(&mut api, &mut h, &["0123456789", "1", "1", "WIPE", "s"]);
    assert!(
        matches!(end.outcome, Outcome::NotConfirmed(_)),
        "{:?}",
        end.outcome
    );
    assert!(screens.contains("network boot is stopped for these addresses"));
    assert!(screens.contains(&mac(5).to_string()));
    assert!(screens.contains("already in a provisioning job or stopped from network boot"));
    assert!(!screens.contains("Choose the disk again"));
    assert_eq!(api.calls.last().map(String::as_str), Some("confirm"));
    assert_eq!(common::ends_digest(&target, 4 << 20), before);
}
