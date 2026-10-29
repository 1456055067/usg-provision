//! QA M3 (qa-engineer): end-to-end gaps on the simulated platform against
//! the real `usgp-api` (in-process, real TLS, in-memory store).
//!
//! - Acceptance 4: a plan whose payload or signature is changed in transit
//!   fails before any disk write; the device's error stays until the
//!   person acts; the job status shows the same step and category.
//! - A tampered chunk: the failure fields on the device screen and in the
//!   server's job view agree (REQ-JOB-005, REQ-JOB-006).
//! - REQ-DISK-005, REQ-DISK-015: with a removable disk and the boot-media
//!   disk present, neither can be chosen and neither is written by a
//!   whole install.
//! - REQ-JOB-014, REQ-TGT-015: the session bearer token never appears on
//!   a screen, in an audit record or in the binary's output.
//! - Decision 0018 item 10: the whole run's job state changes are audited
//!   in order, after the wipe record.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SI-7, AU-3, AU-12, SC-28, SI-11, SA-11
//! - SPEC: specs/disk.md, specs/progress.md, specs/targeting.md

#![cfg(test)]
#![cfg(not(windows))]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use usgp_common::Sha256Digest;
use usgp_crypto::tls::{BlockingClientTls, ClientAlpn, ClientTlsSettings, TlsMinVersion};
use usgp_preboot_agent::client::{ApiFailure, DeviceApi, DeviceClient};
use usgp_preboot_agent::config::AgentConfig;
use usgp_preboot_agent::host::{Host, PowerAction};
use usgp_preboot_agent::http::{HttpClient, HttpLimits};
use usgp_preboot_agent::session::{Agent, Ending, Outcome};
use usgp_preboot_agent::sim::{SimDiskSpec, SimHost};
use usgp_proto::device::*;
use usgp_proto::progress::{FailureCategory, JobState, ProgressAckV1, ProgressV1};
use usgp_proto::{AuthCode, DiskDescriptorV1, JobId};

use common::{Driver, GB, Server, console, disk_file, ends_digest, file_digest, mac, temp_dir};

/// What the wrapper changes on the way in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tamper {
    None,
    PlanPayload,
    PlanSignature,
    Chunk,
}

/// A device client that records the bearer token it was given and can
/// change the server's answers in transit (a test link double).
struct Wire {
    inner: DeviceClient,
    token: Arc<Mutex<Option<String>>>,
    tamper: Tamper,
}

/// Changes one base64 character in the middle of `field` of an envelope
/// (still valid base64, different bytes).
fn flip_b64(env: &mut serde_json::Value, path: &[&str]) {
    let mut v = env;
    for p in path {
        v = if let Ok(i) = p.parse::<usize>() {
            &mut v[i]
        } else {
            &mut v[*p]
        };
    }
    let s = v.as_str().unwrap().to_owned();
    let mut b = s.into_bytes();
    let i = b.len() / 2;
    b[i] = if b[i] == b'A' { b'B' } else { b'A' };
    *v = serde_json::Value::String(String::from_utf8(b).unwrap());
}

impl DeviceApi for Wire {
    fn open(&mut self, h: &DeviceHelloV1) -> Result<SessionOpenedV1, ApiFailure> {
        let o = self.inner.open(h)?;
        *self.token.lock().unwrap() = Some(o.token.expose().to_owned());
        Ok(o)
    }
    fn status(&mut self) -> Result<SessionStatusV1, ApiFailure> {
        self.inner.status()
    }
    fn submit_code(&mut self, c: &AuthCode) -> Result<SessionStatusV1, ApiFailure> {
        self.inner.submit_code(c)
    }
    fn packages(&mut self) -> Result<DevicePackageListV1, ApiFailure> {
        self.inner.packages()
    }
    fn choose_package(&mut self, c: &ChoosePackageV1) -> Result<(), ApiFailure> {
        self.inner.choose_package(c)
    }
    fn choose_disk(&mut self, d: &DiskDescriptorV1) -> Result<(), ApiFailure> {
        self.inner.choose_disk(d)
    }
    fn confirm(&mut self, c: &ConfirmV1) -> Result<ConfirmedV1, ApiFailure> {
        let ok = self.inner.confirm(c)?;
        let path: &[&str] = match self.tamper {
            Tamper::PlanPayload => &["plan", "payload_b64"],
            Tamper::PlanSignature => &["plan", "signatures", "0", "sig_b64"],
            _ => return Ok(ok),
        };
        let mut v = serde_json::to_value(&ok).unwrap();
        flip_b64(&mut v, path);
        Ok(ConfirmedV1::from_json(&serde_json::to_vec(&v).unwrap()).unwrap())
    }
    fn cancel(&mut self) -> Result<(), ApiFailure> {
        self.inner.cancel()
    }
    fn end(&mut self, e: &EndSessionV1) -> Result<(), ApiFailure> {
        self.inner.end(e)
    }
    fn fetch_chunk(&mut self, j: JobId, c: &Sha256Digest, n: u64) -> Result<Vec<u8>, ApiFailure> {
        let mut b = self.inner.fetch_chunk(j, c, n)?;
        if self.tamper == Tamper::Chunk
            && let Some(x) = b.first_mut()
        {
            *x ^= 0x80;
        }
        Ok(b)
    }
    fn report(&mut self, j: JobId, r: &ProgressV1) -> Result<ProgressAckV1, ApiFailure> {
        self.inner.report(j, r)
    }
    fn bound_waits(&mut self, r: Duration, i: Duration) {
        self.inner.bound_waits(r, i);
    }
}

fn wire(cfg: &AgentConfig, tamper: Tamper) -> (Wire, Arc<Mutex<Option<String>>>) {
    let tls = BlockingClientTls::new(&ClientTlsSettings {
        trust_anchors_pem: cfg.trust_anchors_pem.clone(),
        client_cert_chain_pem: None,
        client_key_pem: None,
        min_version: TlsMinVersion::Tls12,
        alpn: ClientAlpn::Http11,
    })
    .unwrap();
    let token = Arc::new(Mutex::new(None));
    (
        Wire {
            inner: DeviceClient::new(HttpClient::new(
                tls,
                cfg.endpoint.clone(),
                HttpLimits::new(cfg.connect_timeout),
            )),
            token: Arc::clone(&token),
            tamper,
        },
        token,
    )
}

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

/// A device with one 70 GB target disk.
fn device(tag: &str, n: u8) -> (std::path::PathBuf, SimHost, std::path::PathBuf) {
    let dir = temp_dir(tag);
    let work = dir.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let mut host = SimHost::new(&work, &dir.join("firmware.json"), mac(n));
    let target = disk_file(&dir, "target.img", 70 * GB);
    host.disks = vec![spec(target.clone(), 0, "Sim Target")];
    (dir, host, target)
}

fn no_volumes(work: &std::path::Path) -> bool {
    std::fs::read_dir(work).unwrap().next().is_none()
}

/// Runs the agent on a thread; `drive` types into its console. Returns
/// the ending and every screen.
fn run_scoped(
    api: &mut Wire,
    host: &mut SimHost,
    cfg: &AgentConfig,
    drive: impl FnOnce(&mut Driver, &dyn Fn() -> bool),
) -> (Ending, String) {
    let (mut con, mut drv, _) = console();
    let facts = host.facts().unwrap();
    let clock = usgp_deploy::SystemClock::new();
    let end = std::thread::scope(|sc| {
        let agent = sc.spawn(|| {
            Agent {
                api,
                host,
                console: &mut con,
                keys: &cfg.keys,
                crypto: usgp_crypto::provider(),
                clock: &clock,
            }
            .run(&facts)
        });
        let done = || agent.is_finished();
        drive(&mut drv, &done);
        agent.join().unwrap()
    });
    drv.drain();
    (end, drv.all())
}

/// The persistent-error check: after the failure screen, the agent waits
/// for the person (REQ-JOB-005 item 4) and does not restart by itself.
fn fail_then_wait(code: &str) -> impl FnOnce(&mut Driver, &dyn Fn() -> bool) + '_ {
    move |drv, done| {
        drv.wait_for("Display code:");
        drv.send(code);
        drv.wait_for("Choose what to install");
        drv.send("1");
        drv.wait_for("Choose the disk");
        drv.send("1");
        drv.wait_for("Type WIPE");
        drv.send("WIPE");
        drv.wait_for("INSTALL FAILED");
        std::thread::sleep(Duration::from_secs(3));
        assert!(!done(), "the error screen did not wait for the person");
        drv.send("s");
    }
}

fn plan_tamper(tamper: Tamper) {
    let s = Server::start();
    s.ready_package();
    let code = s.issue_code();
    let (dir, mut host, target) = device(&format!("{tamper:?}"), 0x21);
    let before = ends_digest(&target, 4 << 20);
    let cfg = s.agent_config(&s.plan_pub);
    let (mut api, _) = wire(&cfg, tamper);
    let (end, screens) = run_scoped(&mut api, &mut host, &cfg, fail_then_wait(&code));
    match &end.outcome {
        Outcome::JobFailed { written, .. } => assert!(!written, "{screens}"),
        other => panic!("{other:?}\n{screens}"),
    }
    assert_eq!(end.outcome.exit_code(), 4);
    assert_eq!(end.action, Some(PowerAction::Shutdown));
    assert!(screens.contains("an integrity-check failure"), "{screens}");
    assert!(
        screens.contains("Nothing was written to any disk."),
        "{screens}"
    );
    assert!(screens.contains("Failed step: 1"), "{screens}");
    // Nothing written: disk, volumes, firmware variables.
    assert_eq!(ends_digest(&target, 4 << 20), before);
    assert!(no_volumes(&host.work_dir));
    assert!(!dir.join("firmware.json").exists());
    // The job status shows the same step and category.
    let jobs = s.jobs();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].state, JobState::Failed);
    let f = jobs[0].failure.as_ref().unwrap();
    assert_eq!(f.category, FailureCategory::Integrity);
    assert_eq!(f.step, usgp_proto::progress::Step::VERIFY_CONTENT);
    assert!(!s.events("job.failed").is_empty());
    assert!(s.events("job.step.completed").is_empty());
    assert!(s.events("boot_stop.added").is_empty());
}

/// Acceptance 4: the plan's payload changed in transit.
#[test]
fn plan_payload_changed_in_transit_fails_before_any_write() {
    plan_tamper(Tamper::PlanPayload);
}

/// Acceptance 4: the plan's signature changed in transit.
#[test]
fn plan_signature_changed_in_transit_fails_before_any_write() {
    plan_tamper(Tamper::PlanSignature);
}

/// REQ-JOB-005 / REQ-JOB-006: a tampered chunk; the device names the
/// step, the file's role, the count and the category; the server's job
/// shows the same; the screen waits; nothing is written.
#[test]
fn tampered_chunk_failure_fields_match_on_device_and_server() {
    let s = Server::start();
    s.ready_package();
    let code = s.issue_code();
    let (_dir, mut host, target) = device("chunkfields", 0x22);
    let before = ends_digest(&target, 4 << 20);
    let cfg = s.agent_config(&s.plan_pub);
    let (mut api, _) = wire(&cfg, Tamper::Chunk);
    let (end, screens) = run_scoped(&mut api, &mut host, &cfg, fail_then_wait(&code));
    assert!(
        matches!(end.outcome, Outcome::JobFailed { written: false, .. }),
        "{:?}",
        end.outcome
    );
    assert_eq!(ends_digest(&target, 4 << 20), before);
    let job = &s.jobs()[0];
    assert_eq!(job.state, JobState::Failed);
    let f = job.failure.as_ref().unwrap();
    assert_eq!(f.category, FailureCategory::Integrity);
    assert_eq!(f.step, usgp_proto::progress::Step::VERIFY_CONTENT);
    assert!(!f.files.is_empty());
    assert!(screens.contains("Failed step: 1"), "{screens}");
    assert!(screens.contains("an integrity-check failure"), "{screens}");
    for file in &f.files {
        let shown = serde_json::to_value(file).unwrap();
        let role = shown["role"].as_str().unwrap_or_default().to_owned();
        assert!(
            screens.to_lowercase().contains(&role.to_lowercase()),
            "role {role} not on the device: {screens}"
        );
    }
    let rec = &s.events("job.failed")[0];
    assert_eq!(rec.reason.as_deref(), Some(f.code.as_str()));
}

/// REQ-DISK-005, REQ-DISK-015: a removable disk and the disk the
/// environment booted from are listed with their reason, cannot be picked
/// by number, and are not written by a whole install on the third disk.
/// REQ-JOB-014: the bearer token is on no screen and in no record.
/// Decision 0018 item 10: every state change of the job is audited after
/// the wipe record.
#[test]
fn install_beside_removable_and_boot_disks_touches_only_the_target() {
    let s = Server::start();
    s.ready_package();
    let code = s.issue_code();
    let (dir, mut host, _target) = device("threedisks", 0x23);
    let removable = dir.join("removable.img");
    let boot = dir.join("boot.img");
    std::fs::write(&removable, vec![0x5a; 4 << 20]).unwrap();
    std::fs::write(&boot, vec![0xa5; 4 << 20]).unwrap();
    let mut r = spec(removable.clone(), 1, "Sim Removable");
    r.facts.removable = true;
    let mut b = spec(boot.clone(), 2, "Sim Boot");
    b.facts.hosts_boot_environment = true;
    host.disks.push(r);
    host.disks.push(b);
    let (rem0, boot0) = (file_digest(&removable), file_digest(&boot));
    let cfg = s.agent_config(&s.plan_pub);
    let (mut api, token) = wire(&cfg, Tamper::None);
    let (end, screens) = run_scoped(&mut api, &mut host, &cfg, |drv, _| {
        drv.wait_for("Display code:");
        drv.send(&code);
        drv.wait_for("Choose what to install");
        drv.send("1");
        let list = drv.wait_for("Choose the disk to install to");
        assert!(list.contains("Sim Removable"), "{list}");
        assert!(list.contains("Sim Boot"), "{list}");
        assert!(
            !list.contains("  2) "),
            "an ineligible disk has a number: {list}"
        );
        // Numbers that name no eligible disk, and nothing typed.
        for bad in ["2", "3", "0", "", "-1", "1 2"] {
            drv.send(bad);
        }
        drv.send("1");
        let wipe = drv.wait_for("Type WIPE");
        assert!(wipe.contains("Sim Target"), "{wipe}");
        drv.send("WIPE");
        drv.wait_for("Install complete");
    });
    assert!(
        matches!(end.outcome, Outcome::Succeeded(_)),
        "{:?}\n{screens}",
        end.outcome
    );
    assert_eq!(file_digest(&removable), rem0, "removable disk written");
    assert_eq!(file_digest(&boot), boot0, "boot-media disk written");
    let chosen = s.events("device.session.disk_chosen");
    assert_eq!(chosen.len(), 1, "{chosen:?}");
    assert!(
        chosen[0].detail.contains("Sim Target"),
        "{}",
        chosen[0].detail
    );

    // The bearer token: never on a screen, in a record or a job view.
    let token = token.lock().unwrap().clone().expect("token recorded");
    assert!(token.len() >= 32);
    assert!(!screens.contains(&token));
    let records = format!("{:?}", s.records());
    assert!(!records.contains(&token), "token in an audit record");
    assert!(!format!("{:?}", s.jobs()).contains(&token));
    assert!(!records.contains(&code));

    // The job's state changes, in order after the wipe record.
    let job = s.jobs()[0].id.to_string();
    let wipe = s.events("disk.wipe.authorised");
    assert_eq!(wipe.len(), 1);
    // plan issued < every step completed < succeeded; the boot stop is
    // written in the success transaction, so it is checked against the
    // steps only.
    let mut last = wipe[0].seq;
    for e in ["job.plan.issued", "job.step.completed", "job.succeeded"] {
        let recs = s.events(e);
        assert!(!recs.is_empty(), "no {e}");
        for r in &recs {
            assert!(r.seq > wipe[0].seq, "{e} before the wipe record");
            assert_eq!(r.actor_kind, "device_session", "{e}");
        }
        let first = recs.iter().map(|r| r.seq).min().unwrap();
        assert!(first > last, "{e} out of order");
        last = recs.iter().map(|r| r.seq).max().unwrap();
    }
    let last_step = s
        .events("job.step.completed")
        .iter()
        .map(|r| r.seq)
        .max()
        .unwrap();
    let stops = s.events("boot_stop.added");
    assert_eq!(stops.len(), 1);
    assert!(stops[0].seq > last_step);
    assert_eq!(stops[0].actor_kind, "device_session");
    let completed = s.events("job.step.completed");
    assert_eq!(
        completed.len(),
        5,
        "one record per completed step 1..5 (NIST-009)"
    );
    assert!(
        completed
            .iter()
            .all(|r| r.target_id.as_deref() == Some(job.as_str()))
    );
    assert_eq!(s.events("job.step.started").len(), 4, "steps 2..5 started");

    // REQ-DISK-014: the operator's job view shows the disk chosen and the
    // layout written (four partitions, REQ-DISK-008).
    let r = s.op("GET", &format!("/v1/jobs/{job}"), &[], None);
    assert_eq!(r.status, 200);
    let v = r.json();
    assert_eq!(v["disk"]["model"], "Sim Target", "{v}");
    assert_eq!(v["disk"]["size_bytes"], 70 * GB, "{v}");
    let parts = v["layout"]["partitions"]
        .as_array()
        .expect("layout reported");
    assert_eq!(parts.len(), 4, "{v}");
    assert!(!String::from_utf8_lossy(&r.body).contains(&token));
}
