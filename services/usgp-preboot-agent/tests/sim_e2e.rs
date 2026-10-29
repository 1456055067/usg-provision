//! End to end on the simulated platform against the real `usgp-api`
//! (in-process, real TLS, the production WIM checker, the in-memory store):
//! plan section 10.1 `agent-sim-e2e` and the negative cases.
//!
//! - Code path: session → package → disk → WIPE → GPT on a loopback file,
//!   the image applied into a directory, `BootOrder` with our option
//!   first, the job Succeeded and audited, a boot stop added, the other
//!   disk file unchanged, no code or token on any screen.
//! - Approval path with a wrong pinned plan key: the plan fails to verify,
//!   nothing is written (exit 4), the job is failed on the server.
//! - A chunk tampered in transit: fails in the verify pass, nothing
//!   written (exit 4).
//! - The wipe record cannot be written: no plan, nothing written (exit 3).
//! - The binary with `--sim` and a scripted standard input.

#![cfg(test)]
#![cfg(not(windows))]

mod common;
mod proc;

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use usgp_common::Sha256Digest;
use usgp_crypto::tls::{BlockingClientTls, ClientAlpn, ClientTlsSettings, TlsMinVersion};
use usgp_disk::gpt::{GptLimits, parse_gpt};
use usgp_disk::{BlockDevice as _, FileBlockDevice};
use usgp_preboot_agent::app;
use usgp_preboot_agent::client::{ApiFailure, DeviceApi, DeviceClient};
use usgp_preboot_agent::config::AgentConfig;
use usgp_preboot_agent::host::{Host, PowerAction};
use usgp_preboot_agent::http::{HttpClient, HttpLimits};
use usgp_preboot_agent::session::{Agent, Ending, Outcome};
use usgp_preboot_agent::sim::{SimDiskSpec, SimHost};
use usgp_proto::device::*;
use usgp_proto::progress::{FailureCategory, JobState, ProgressAckV1, ProgressV1};
use usgp_proto::{AuthCode, DiskDescriptorV1, JobId};

use common::{
    Driver, GB, Server, console, disk_file, display_code, ends_digest, file_digest, mac, temp_dir,
};

fn spec(path: std::path::PathBuf, n: u32, model: &str) -> SimDiskSpec {
    SimDiskSpec {
        path,
        facts: usgp_disk::DiskFacts {
            identity: usgp_disk::DiskIdentity {
                device_number: n,
                model: model.to_owned(),
                serial: Some(format!("SIM-{n}")),
            },
            bus: usgp_disk::Bus::Nvme,
            removable: false,
            read_only: false,
            logical_sector: 512,
            physical_sector: 4096,
            size_bytes: 0,
            hosts_boot_environment: false,
            partitions: Vec::new(),
        },
        kinds: Vec::new(),
        volumes_known: true,
    }
}

struct Device {
    dir: std::path::PathBuf,
    host: SimHost,
    target: std::path::PathBuf,
    other: std::path::PathBuf,
}

/// A device with a 70 GB target disk and a small second disk with data.
fn device(tag: &str, n: u8) -> Device {
    let dir = temp_dir(tag);
    let work = dir.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let mut host = SimHost::new(&work, &dir.join("firmware.json"), mac(n));
    let target = disk_file(&dir, "target.img", 70 * GB);
    let other = dir.join("other.img");
    std::fs::write(&other, vec![0x5a; 4 << 20]).unwrap();
    host.disks = vec![
        spec(target.clone(), 0, "Sim Target"),
        spec(other.clone(), 1, "Sim Other"),
    ];
    Device {
        dir,
        host,
        target,
        other,
    }
}

type AgentThread = std::thread::JoinHandle<(Ending, SimHost)>;
type EchoLog = std::sync::Arc<std::sync::Mutex<Vec<bool>>>;

/// The agent and simulation files for running the binary against `s`.
fn binary_files(s: &Server, d: &Device) -> (std::path::PathBuf, std::path::PathBuf) {
    let anchors = d.dir.join("anchors.pem");
    std::fs::write(&anchors, s.pki.root.cert_pem().unwrap()).unwrap();
    std::fs::write(d.dir.join("plan.pub"), s.plan_pub.to_spki_pem().unwrap()).unwrap();
    std::fs::write(
        d.dir.join("content.pub"),
        s.content_pub.to_spki_pem().unwrap(),
    )
    .unwrap();
    let cfg = d.dir.join("agent.toml");
    std::fs::write(
        &cfg,
        format!(
            "server_url = \"https://127.0.0.1:{}\"\nserver_name = \"localhost\"\n\
             trust_anchors = \"anchors.pem\"\nplan_key_pub = \"plan.pub\"\n\
             content_key_pub = \"content.pub\"\nnetwork_wait_s = 10\n",
            s.dev_addr.port()
        ),
    )
    .unwrap();
    let sim = d.dir.join("sim.toml");
    std::fs::write(
        &sim,
        format!(
            "work_dir = {:?}\nfirmware_file = {:?}\ndhcp_addresses = [\"192.0.2.10\"]\n\
             firmware = \"uefi\"\narch = \"x64\"\nsecure_boot = \"on\"\nmemory_bytes = 8589934592\n\
             macs = [\"02:00:00:00:10:05\"]\n\n[[disk]]\npath = {:?}\nbus = \"nvme\"\n\
             model = \"Sim Target\"\nserial = \"SIM-0\"\nlogical_sector = 512\nphysical_sector = 4096\n",
            d.host.work_dir, d.host.firmware_file, d.target
        ),
    )
    .unwrap();
    (cfg, sim)
}

/// Runs `app::run` on its own thread.
fn start(cfg: AgentConfig, mut host: SimHost) -> (AgentThread, Driver, EchoLog) {
    let (mut con, drv, echo) = console();
    let t = std::thread::spawn(move || {
        let end = app::run(&cfg, &mut host, &mut con, usgp_crypto::provider());
        (end, host)
    });
    (t, drv, echo)
}

fn no_volumes(work: &Path) -> bool {
    std::fs::read_dir(work).unwrap().next().is_none()
}

#[test]
fn code_path_installs_and_is_audited() {
    let s = Server::start();
    s.ready_package();
    let code = s.issue_code();
    let d = device("code", 1);
    let other_before = file_digest(&d.other);
    let (t, mut drv, echo) = start(s.agent_config(&s.plan_pub), d.host.clone());
    drv.wait_for("Display code:");
    drv.send(&code);
    drv.wait_for("Choose what to install");
    drv.send("1");
    let disks = drv.wait_for("Choose the disk to install to");
    assert!(
        disks.contains("  1) 70.0 GB - Sim Target - NVMe"),
        "{disks}"
    );
    assert!(disks.contains("because: too small"), "{disks}");
    drv.send("1");
    drv.wait_for("Type WIPE");
    drv.send("WIPE");
    drv.wait_for("Install complete");
    let (end, host) = t.join().unwrap();
    drv.drain();
    assert!(
        matches!(end.outcome, Outcome::Succeeded(_)),
        "{:?}\n{}",
        end.outcome,
        drv.all()
    );
    assert_eq!(end.action, Some(PowerAction::Restart));
    assert_eq!(end.outcome.exit_code(), 0);
    assert_eq!(echo.lock().unwrap().as_slice(), [false, true]);

    // No secret on any screen.
    let screens = drv.all();
    assert!(!screens.contains(&code));
    assert!(!screens.contains(&AuthCode::parse(&code).unwrap().normalized().to_owned()));

    // GPT on the loopback file, valid by our parser.
    let mut dev = FileBlockDevice::open(&d.target, 512, false).unwrap();
    assert_eq!(dev.len(), 70 * GB);
    let gpt = parse_gpt(&mut dev, &GptLimits::default()).unwrap();
    assert_eq!(gpt.entries.len(), 4);
    // The image applied into the Windows volume's directory.
    let work = &host.work_dir;
    let hello = std::fs::read_dir(work)
        .unwrap()
        .map(|e| e.unwrap().path().join("hello.txt"))
        .find(|p| p.is_file())
        .expect("applied file");
    assert_eq!(
        std::fs::read(hello).unwrap(),
        b"hello from the synthetic image\n"
    );
    // BootOrder: our option first.
    let fw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(d.dir.join("firmware.json")).unwrap()).unwrap();
    let order = fw["BootOrder"].as_str().unwrap();
    let first = u16::from_str_radix(&format!("{}{}", &order[2..4], &order[0..2]), 16).unwrap();
    assert!(fw.get(format!("Boot{first:04X}")).is_some(), "{fw}");
    // The other disk is untouched.
    assert_eq!(file_digest(&d.other), other_before);

    // Server: job Succeeded, boot stop, and the device's choices audited.
    let jobs = s.jobs();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].state, JobState::Succeeded);
    for e in [
        "device.session.opened",
        "auth_code.used",
        "device.session.authorised",
        "device.session.package_chosen",
        "device.session.disk_chosen",
        "disk.wipe.authorised",
        "job.created",
        "boot_stop.added",
    ] {
        assert!(!s.events(e).is_empty(), "no {e} record");
    }
    let text = format!("{:?}", s.records());
    assert!(!text.contains(&code));
}

#[test]
fn approval_path_with_a_wrong_plan_key_writes_nothing() {
    let s = Server::start();
    s.ready_package();
    let d = device("wrongkey", 2);
    let wrong = usgp_crypto::SigningKey::generate().unwrap();
    let before = ends_digest(&d.target, 4 << 20);
    let (t, mut drv, _) = start(s.agent_config(wrong.verifying_key()), d.host.clone());
    let auth = drv.wait_for("Display code:");
    s.approve(&display_code(&auth));
    drv.wait_for("Choose what to install");
    drv.send("1");
    drv.wait_for("Choose the disk");
    drv.send("1");
    drv.wait_for("Type WIPE");
    drv.send("WIPE");
    let failed = drv.wait_for("INSTALL FAILED");
    assert!(failed.contains("an integrity-check failure"), "{failed}");
    assert!(
        failed.contains("Nothing was written to any disk."),
        "{failed}"
    );
    drv.send("s");
    let (end, host) = t.join().unwrap();
    assert!(
        matches!(end.outcome, Outcome::JobFailed { written: false, .. }),
        "{:?}",
        end.outcome
    );
    assert_eq!(end.outcome.exit_code(), 4);
    assert_eq!(end.action, Some(PowerAction::Shutdown));
    assert_eq!(ends_digest(&d.target, 4 << 20), before);
    assert!(no_volumes(&host.work_dir));
    assert!(!d.dir.join("firmware.json").exists());
    assert!(!s.events("device.session.approved").is_empty());
    let jobs = s.jobs();
    assert_eq!(jobs[0].state, JobState::Failed);
    assert_eq!(
        jobs[0].failure.as_ref().unwrap().category,
        FailureCategory::Integrity
    );
}

/// Flips one byte of every chunk the server sends (a tampering path).
struct Tamper(DeviceClient);

impl DeviceApi for Tamper {
    fn open(&mut self, h: &DeviceHelloV1) -> Result<SessionOpenedV1, ApiFailure> {
        self.0.open(h)
    }
    fn status(&mut self) -> Result<SessionStatusV1, ApiFailure> {
        self.0.status()
    }
    fn submit_code(&mut self, c: &AuthCode) -> Result<SessionStatusV1, ApiFailure> {
        self.0.submit_code(c)
    }
    fn packages(&mut self) -> Result<DevicePackageListV1, ApiFailure> {
        self.0.packages()
    }
    fn choose_package(&mut self, c: &ChoosePackageV1) -> Result<(), ApiFailure> {
        self.0.choose_package(c)
    }
    fn choose_disk(&mut self, d: &DiskDescriptorV1) -> Result<(), ApiFailure> {
        self.0.choose_disk(d)
    }
    fn confirm(&mut self, c: &ConfirmV1) -> Result<ConfirmedV1, ApiFailure> {
        self.0.confirm(c)
    }
    fn cancel(&mut self) -> Result<(), ApiFailure> {
        self.0.cancel()
    }
    fn end(&mut self, e: &EndSessionV1) -> Result<(), ApiFailure> {
        self.0.end(e)
    }
    fn fetch_chunk(&mut self, j: JobId, c: &Sha256Digest, n: u64) -> Result<Vec<u8>, ApiFailure> {
        let mut b = self.0.fetch_chunk(j, c, n)?;
        let mid = b.len() / 2;
        if let Some(x) = b.get_mut(mid) {
            *x ^= 0x01;
        }
        Ok(b)
    }
    fn report(&mut self, j: JobId, r: &ProgressV1) -> Result<ProgressAckV1, ApiFailure> {
        self.0.report(j, r)
    }
    fn bound_waits(&mut self, r: Duration, i: Duration) {
        self.0.bound_waits(r, i);
    }
}

#[test]
fn tampered_chunk_fails_before_any_write() {
    let s = Server::start();
    s.ready_package();
    let code = s.issue_code();
    let mut d = device("tamper", 3);
    let cfg = s.agent_config(&s.plan_pub);
    let before = ends_digest(&d.target, 4 << 20);
    let tls = BlockingClientTls::new(&ClientTlsSettings {
        trust_anchors_pem: cfg.trust_anchors_pem.clone(),
        client_cert_chain_pem: None,
        client_key_pem: None,
        min_version: TlsMinVersion::Tls12,
        alpn: ClientAlpn::Http11,
    })
    .unwrap();
    let mut api = Tamper(DeviceClient::new(HttpClient::new(
        tls,
        cfg.endpoint.clone(),
        HttpLimits::new(cfg.connect_timeout),
    )));
    let (mut con, mut drv, _) = console();
    for l in [code.as_str(), "1", "1", "WIPE", "r"] {
        drv.send(l);
    }
    let facts = d.host.facts().unwrap();
    let clock = usgp_deploy::SystemClock::new();
    let end = Agent {
        api: &mut api,
        host: &mut d.host,
        console: &mut con,
        keys: &cfg.keys,
        crypto: usgp_crypto::provider(),
        clock: &clock,
    }
    .run(&facts);
    drv.drain();
    match &end.outcome {
        Outcome::JobFailed { written, code } => {
            assert!(!written);
            assert_eq!(code, "chunk_digest_mismatch");
        }
        other => panic!("{other:?}\n{}", drv.all()),
    }
    assert_eq!(end.outcome.exit_code(), 4);
    assert!(drv.all().contains("Failed step: 1"));
    assert_eq!(ends_digest(&d.target, 4 << 20), before);
    assert!(no_volumes(&d.host.work_dir));
    assert_eq!(s.jobs()[0].state, JobState::Failed);
}

#[test]
fn wipe_record_failure_starts_nothing() {
    let s = Server::start();
    s.ready_package();
    let code = s.issue_code();
    let d = device("auditfail", 4);
    let before = ends_digest(&d.target, 4 << 20);
    s.store.fail_audit_on("disk.wipe.authorised");
    let (t, mut drv, _) = start(s.agent_config(&s.plan_pub), d.host.clone());
    for l in [code.as_str(), "1", "1", "WIPE"] {
        drv.send(l);
    }
    let screen = drv.wait_for("The install did not start");
    assert!(screen.contains("could not durably record the wipe authorisation"));
    drv.send("s");
    let (end, host) = t.join().unwrap();
    assert!(
        matches!(end.outcome, Outcome::NotConfirmed(_)),
        "{:?}",
        end.outcome
    );
    assert_eq!(end.outcome.exit_code(), 3);
    assert_eq!(ends_digest(&d.target, 4 << 20), before);
    assert!(no_volumes(&host.work_dir));
    assert!(s.jobs().is_empty());
}

#[test]
fn the_binary_runs_the_simulation_from_scripted_input() {
    let s = Server::start();
    s.ready_package();
    let code = s.issue_code();
    let d = device("binary", 5);
    let (cfg, sim) = binary_files(&s, &d);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_usgp-preboot-agent"));
    cmd.arg("--config").arg(&cfg).arg("--sim").arg(&sim);
    let script = format!("{code}\n1\n1\nWIPE\n");
    let out = proc::run(cmd, Some(script.as_bytes()), proc::LIMIT);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("outcome: succeeded"), "{stdout}");
    assert!(stdout.contains("power: Restart"), "{stdout}");
    assert!(!stdout.contains(&code));
    assert_eq!(s.jobs()[0].state, JobState::Succeeded);
}

#[test]
fn the_binary_with_no_input_cancels_and_exits() {
    let s = Server::start();
    s.ready_package();
    let d = device("eof", 6);
    let before = ends_digest(&d.target, 4 << 20);
    let (cfg, sim) = binary_files(&s, &d);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_usgp-preboot-agent"));
    cmd.arg("--config").arg(&cfg).arg("--sim").arg(&sim);
    // Standard input is null: EOF at the authorisation screen.
    let out = proc::run(cmd, None, proc::LIMIT);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(6), "{stdout}");
    assert!(stdout.contains("Cancelled"), "{stdout}");
    assert!(
        !stdout.contains("power:"),
        "no power action on EOF: {stdout}"
    );
    assert_eq!(ends_digest(&d.target, 4 << 20), before);
    assert!(!s.events("device.session.cancelled").is_empty());
    assert!(s.jobs().is_empty());
}
