//! M4 engine steps 4 to 9 (plan WU-7): driver staging and its checks,
//! configuration placement, make-bootable with the restart report, and the
//! post-setup runner (resume, tags, escrow then set, answer file removal,
//! agent install, ready), on a directory tree standing in for the Windows
//! volume. Real ECDSA, SHA-256 and escrow sealing through usgp-crypto.
//!
//! No test touches a real disk or account: the "volume" is a folder under
//! `CARGO_TARGET_TMPDIR`, DISM and the installer are doubles.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation)
// - SPEC: specs/drivers.md#REQ-DRV-004, #REQ-DRV-008, #REQ-DRV-010
// - SPEC: specs/configuration.md#REQ-CFG-008, #REQ-CFG-009, #REQ-CFG-010
// - SPEC: specs/workflow.md#REQ-SEQ-002, #REQ-SEQ-003, #REQ-SEQ-006,
//   #REQ-SEQ-008; specs/agent-handoff.md#REQ-AGT-001, #REQ-AGT-005
#![cfg(test)]

pub mod common;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use common::*;
use usgp_common::Sha256Digest;
use usgp_crypto::{EscrowKey, SigningKey, sign_typed, verify_typed};
use usgp_deploy::link::ProgressLinkV2;
use usgp_deploy::platform::{
    BootFiles, FileProtection, FirmwareVars, FormattedVolume, OpenedTarget, Platform,
    PlatformError, PlatformErrorKind, STAGE_ROOT, StagePath, TargetPath, ToolOutcome, VolumeOps,
    VolumeSpec,
};
use usgp_deploy::postsetup::{
    AccountError, InstallOutcome, InstallerCommand, PostSetupPlatform, PostSetupRunner, Ready,
    ResumeLink, RunnerConfig, RunnerFile,
};
use usgp_deploy::steps::{
    AfterApply, PostSetupInputs, PrebootTail, SETUP_COMPLETE_CMD, TailConfig, TailDone,
};
use usgp_deploy::{JobFailureV2, LinkError, POSTSETUP_SEQ_BASE, ServerLink};
use usgp_disk::layout::PartRole;
use usgp_image::chunks::ContentHasher;
use usgp_proto::content_manifest::{ArchiveSummaryV1, ContentManifestV2};
use usgp_proto::disk::{FileSystem, PlanDiskV1};
use usgp_proto::envelope::{PayloadType, SignatureAlg, SignatureV1, SignedEnvelopeV1};
use usgp_proto::job_plan::{
    EscrowAccount, JobPlanV2, PlanAgentV2, PlanAnswerFileV2, PlanContentV2, PlanDriverV2,
    PlanEscrowV2, PlanExpectationV2, PlanPostSetupV2, PlanStepV2, VerifiedJobPlanV2,
};
use usgp_proto::limits::CHUNK_SIZE;
use usgp_proto::progress::{JobState, ProgressAckV1, ProgressEvent, ProgressV2, StepV2};
use usgp_proto::resume::{ResumeNonce, resume_payload};
use usgp_proto::{
    AgentPackageId, ArchiveFormat, B64Bytes, ContentId, ContentKindV2, DisplayName,
    DriverArchiveId, EscrowConfirmV1, EscrowSubmitV1, FileName, JobId, P384Spki, RelPath,
    ResumeChallengeV1, ResumeRequestV1, Tag, UnixMicros, UrlPath,
};
use usgp_wincfg::archive::testkit::{ZipBuilder, ZipEntrySpec};
use usgp_wincfg::archive::{ExtractSink, RelPath as ArcPath};
use zeroize::Zeroizing;

const DRIVER_A: &str = "1a2b3c4d-0000-4000-8000-00000000000a";
const DRIVER_B: &str = "1a2b3c4d-0000-4000-8000-00000000000b";
const AGENT_PKG: &str = "1a2b3c4d-0000-4000-8000-0000000000ac";
const INF_A: &[u8] = b"[Version]\r\nSignature=\"$Windows NT$\"\r\nCatalogFile=e1000.cat\r\n";
const INF_B: &[u8] = b"[Version]\r\nSignature=$Chicago$\r\nCatalogFile=stor.cat\r\n";
const ANSWER: &[u8] =
    b"<?xml version=\"1.0\"?><unattend xmlns=\"urn:schemas-microsoft-com:unattend\"/>";

// ---------------------------------------------------------------------------
// Fixture: a signed v2 plan with two driver archives and an agent package
// ---------------------------------------------------------------------------

fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    entries
        .iter()
        .fold(ZipBuilder::default(), |b, (n, d)| {
            b.entry(ZipEntrySpec::stored(n, d))
        })
        .build()
}

fn seal_env(key: &SigningKey, ty: PayloadType, payload: Vec<u8>) -> SignedEnvelopeV1 {
    let sig = sign_typed(key, ty.as_str(), &payload).unwrap();
    let s = SignatureV1::new(key.key_id().0, SignatureAlg::EcdsaP384Sha384, sig).unwrap();
    SignedEnvelopeV1::new(ty, payload, vec![s]).unwrap()
}

fn manifest_v2(
    key: &SigningKey,
    kind: ContentKindV2,
    id: &str,
    bytes: &[u8],
    infs: &[&str],
) -> ContentManifestV2 {
    let mut h = ContentHasher::new(crypto());
    h.update(bytes);
    let d = h.finish();
    ContentManifestV2 {
        schema: 2,
        kind,
        content_id: ContentId::parse(id).unwrap(),
        display_name: DisplayName::new("archive").unwrap(),
        file_name: FileName::new("archive.zip").unwrap(),
        size: bytes.len() as u64,
        sha256: d.total,
        chunk_size: CHUNK_SIZE,
        chunk_sha256: d.chunks,
        archive: ArchiveSummaryV1 {
            format: ArchiveFormat::Zip,
            entries: 2,
            expanded_bytes: 1,
            infs: infs.iter().map(|s| RelPath::new(*s).unwrap()).collect(),
        },
        ready_at: UnixMicros::new(1_793_000_000_000_000).unwrap(),
        key_id: key.key_id().0,
    }
}

struct M4 {
    base: Fixture,
    plan: JobPlanV2,
    drivers: Vec<(Vec<u8>, ContentManifestV2)>,
    agent: (Vec<u8>, ContentManifestV2),
    escrow_key: EscrowKey,
    job_key: SigningKey,
}

impl M4 {
    fn new(escrow: bool) -> Self {
        let base = Fixture::new(small_wim());
        let ck = &base.content_key;
        let za = zip(&[
            ("net/E1000.inf", INF_A),
            ("net/e1000.cat", b"catalog"),
            ("net/e1000.sys", b"driver"),
        ]);
        let zb = zip(&[("stor/stor.inf", INF_B), ("stor/stor.cat", b"catalog")]);
        let drivers = vec![
            (
                za.clone(),
                manifest_v2(
                    ck,
                    ContentKindV2::DriverArchive,
                    DRIVER_A,
                    &za,
                    &["net/E1000.inf"],
                ),
            ),
            (
                zb.clone(),
                manifest_v2(
                    ck,
                    ContentKindV2::DriverArchive,
                    DRIVER_B,
                    &zb,
                    &["stor/stor.inf"],
                ),
            ),
        ];
        let agent_zip = zip(&[
            (
                "agent.json",
                br#"{"installer":"setup.exe","args":["/quiet"]}"#,
            ),
            ("setup.exe", b"MZ installer"),
        ]);
        let agent = (
            agent_zip.clone(),
            manifest_v2(ck, ContentKindV2::AgentPackage, AGENT_PKG, &agent_zip, &[]),
        );
        let escrow_key = EscrowKey::generate().unwrap();
        let job_key = SigningKey::generate().unwrap();
        let p = &base.plan;
        let spki = P384Spki::from_der(escrow_key.public().spki_der()).unwrap();
        let plan = JobPlanV2 {
            schema: 2,
            job_id: p.job_id,
            session_id: p.session_id,
            boot_service_id: p.boot_service_id,
            issued_at_us: p.issued_at_us,
            key_id: p.key_id,
            agent_nonce: p.agent_nonce,
            device: p.device.clone(),
            package: p.package.clone(),
            image: p.image.clone(),
            disk: p.disk.clone(),
            layout_policy: p.layout_policy,
            wipe: p.wipe.clone(),
            steps: StepV2::ALL
                .iter()
                .map(|s| PlanStepV2 {
                    step: *s,
                    kind: s.kind(),
                    timeout_s: 3600,
                })
                .collect(),
            retry: p.retry,
            stall_timeout_s: p.stall_timeout_s,
            report_interval_s: p.report_interval_s,
            answer_file: PlanAnswerFileV2 {
                sha256: crypto().sha256(ANSWER),
                b64: B64Bytes::new(ANSWER.to_vec()).unwrap(),
            },
            drivers: [DRIVER_A, DRIVER_B]
                .iter()
                .zip(&drivers)
                .map(|(id, (_, m))| PlanDriverV2 {
                    archive_id: DriverArchiveId::parse(id).unwrap(),
                    content_sha256: m.sha256,
                    content_manifest_sha256: crypto().sha256(&m.to_payload().unwrap()),
                    infs: m.archive.infs.clone(),
                })
                .collect(),
            agent: PlanAgentV2 {
                agent_package_id: AgentPackageId::parse(AGENT_PKG).unwrap(),
                content_sha256: agent.1.sha256,
                content_manifest_sha256: crypto().sha256(&agent.1.to_payload().unwrap()),
            },
            tags: vec![Tag::new("site:hq").unwrap(), Tag::new("floor 2").unwrap()],
            escrow: escrow.then(|| PlanEscrowV2 {
                key_id: crypto().sha256(spki.as_der()),
                spki_b64: spki,
                account: EscrowAccount::Administrator,
            }),
            job_key_id: job_key.key_id().0,
            postsetup: PlanPostSetupV2 {
                resume_url_path: UrlPath::new(format!("/v1/device/jobs/{}/resume", p.job_id))
                    .unwrap(),
            },
        };
        Self {
            base,
            plan,
            drivers,
            agent,
            escrow_key,
            job_key,
        }
    }

    fn plan_env(&self) -> SignedEnvelopeV1 {
        seal_env(
            &self.base.plan_key,
            PayloadType::JobPlanV2,
            self.plan.to_payload().unwrap(),
        )
    }

    fn verified(&self) -> VerifiedJobPlanV2 {
        let ck = &self.base.content_key;
        let ty = PayloadType::ContentManifestV2;
        let drivers: Vec<SignedEnvelopeV1> = self
            .drivers
            .iter()
            .map(|(_, m)| seal_env(ck, ty, m.to_payload().unwrap()))
            .collect();
        let agent = seal_env(ck, ty, self.agent.1.to_payload().unwrap());
        let image = self.base.content_env();
        VerifiedJobPlanV2::verify(
            &self.plan_env(),
            &self.base.keys.plan,
            &PlanContentV2 {
                image: &image,
                drivers: &drivers,
                agent: &agent,
            },
            &self.base.keys.content,
            &|b| crypto().sha256(b),
            &PlanExpectationV2 {
                base: self.base.expect(),
                job_key_id: self.job_key.key_id().0,
            },
        )
        .unwrap()
    }

    fn job(&self) -> JobId {
        self.plan.job_id
    }
}

// ---------------------------------------------------------------------------
// The server
// ---------------------------------------------------------------------------

/// Shared, ordered record of what the doubles saw (for order checks).
type Log = Rc<RefCell<Vec<String>>>;

struct M4Link {
    content: BTreeMap<[u8; 32], Vec<u8>>,
    fetched: Vec<Sha256Digest>,
    tamper: Option<Sha256Digest>,
    reports: Vec<ProgressV2>,
    job_key: Option<usgp_crypto::VerifyingKey>,
    nonce: Option<ResumeNonce>,
    resumed: bool,
    resume_transient: u32,
    refuse_resume: bool,
    refuse_escrow: bool,
    escrow: Option<EscrowSubmitV1>,
    confirms: Vec<EscrowConfirmV1>,
    refuse_step6: bool,
    log: Log,
}

impl M4Link {
    fn new(m: &M4, log: Log) -> Self {
        let mut content = BTreeMap::new();
        for (b, man) in &m.drivers {
            content.insert(man.sha256.0, b.clone());
        }
        content.insert(m.agent.1.sha256.0, m.agent.0.clone());
        Self {
            content,
            fetched: Vec::new(),
            tamper: None,
            reports: Vec::new(),
            job_key: Some(m.job_key.verifying_key().clone()),
            nonce: None,
            resumed: false,
            resume_transient: 0,
            refuse_resume: false,
            refuse_escrow: false,
            escrow: None,
            confirms: Vec::new(),
            refuse_step6: false,
            log,
        }
    }

    fn states(&self) -> Vec<(u8, ProgressEvent)> {
        self.reports
            .iter()
            .map(|r| (r.step.get(), r.event))
            .collect()
    }
}

impl ServerLink for M4Link {
    fn fetch_chunk(
        &mut self,
        _job: JobId,
        content: &Sha256Digest,
        n: u64,
    ) -> Result<Vec<u8>, LinkError> {
        self.fetched.push(*content);
        let bytes = self.content.get(&content.0).ok_or(LinkError::NotFound)?;
        let start = usize::try_from(n * CHUNK_SIZE).unwrap();
        let end = (start + CHUNK_SIZE as usize).min(bytes.len());
        let mut v = bytes.get(start..end).ok_or(LinkError::NotFound)?.to_vec();
        if self.tamper == Some(*content) {
            v[0] ^= 1;
        }
        Ok(v)
    }

    fn report(
        &mut self,
        _job: JobId,
        _r: &usgp_proto::progress::ProgressV1,
    ) -> Result<ProgressAckV1, LinkError> {
        panic!("a v2 job must not send v1 reports");
    }
}

impl ProgressLinkV2 for M4Link {
    fn report_v2(&mut self, _job: JobId, r: &ProgressV2) -> Result<ProgressAckV1, LinkError> {
        assert!(r.validate().is_ok(), "invalid report {r:?}");
        if let Some(last) = self.reports.last() {
            assert!(r.seq > last.seq, "sequence must increase");
        }
        if r.step.runs_after_restart() {
            assert!(self.resumed, "steps 7 to 9 need the resume token");
        }
        if self.refuse_step6
            && r.step == StepV2::MAKE_BOOTABLE_RESTART
            && r.event == ProgressEvent::StepCompleted
        {
            return Err(LinkError::Refused);
        }
        self.reports.push(r.clone());
        self.log
            .borrow_mut()
            .push(format!("report {} {:?}", r.step.get(), r.event));
        let job_state = match r.event {
            ProgressEvent::Succeeded => JobState::Succeeded,
            ProgressEvent::Failed => JobState::Failed,
            _ => JobState::Running,
        };
        Ok(ProgressAckV1 {
            ack_seq: r.seq,
            job_state,
        })
    }
}

impl ResumeLink for M4Link {
    fn challenge(&mut self, _job: JobId) -> Result<ResumeChallengeV1, LinkError> {
        if self.resume_transient > 0 {
            self.resume_transient -= 1;
            return Err(LinkError::Transient);
        }
        let nonce = ResumeNonce::new(vec![0x33; 32]).unwrap();
        self.nonce = Some(nonce.clone());
        Ok(ResumeChallengeV1 {
            nonce,
            expires_at: UnixMicros::new(1_793_000_060_000_000).unwrap(),
        })
    }

    fn resume(&mut self, job: JobId, req: &ResumeRequestV1) -> Result<(), LinkError> {
        if self.refuse_resume {
            return Err(LinkError::Refused);
        }
        assert_eq!(Some(&req.nonce), self.nonce.as_ref());
        let key = self.job_key.as_ref().ok_or(LinkError::Refused)?;
        verify_typed(
            key,
            PayloadType::ResumeV1.as_str(),
            &resume_payload(&job, &req.nonce),
            req.sig.as_bytes(),
        )
        .map_err(|_| LinkError::Refused)?;
        self.resumed = true;
        self.log.borrow_mut().push("resumed".to_owned());
        Ok(())
    }

    fn submit_escrow(&mut self, _job: JobId, body: &EscrowSubmitV1) -> Result<(), LinkError> {
        assert!(self.resumed);
        self.log.borrow_mut().push("escrow submitted".to_owned());
        if self.refuse_escrow || self.escrow.is_some() {
            return Err(LinkError::Refused);
        }
        self.escrow = Some(body.clone());
        Ok(())
    }

    fn confirm_escrow(&mut self, _job: JobId, body: &EscrowConfirmV1) -> Result<(), LinkError> {
        self.log
            .borrow_mut()
            .push(format!("escrow confirmed {}", body.set));
        self.confirms.push(body.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The Windows volume as a directory, DISM as a double
// ---------------------------------------------------------------------------

/// Extracts below `root`.
struct DirExtract {
    root: PathBuf,
    file: Option<fs::File>,
}

impl ExtractSink for DirExtract {
    fn create_dir(&mut self, p: &ArcPath) -> io::Result<()> {
        fs::create_dir_all(self.root.join(p.as_str()))
    }
    fn begin_file(&mut self, p: &ArcPath, _size: u64) -> io::Result<()> {
        let path = self.root.join(p.as_str());
        if let Some(d) = path.parent() {
            fs::create_dir_all(d)?;
        }
        self.file = Some(
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)?,
        );
        Ok(())
    }
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("no file"))?
            .write_all(data)
    }
    fn end_file(&mut self) -> io::Result<()> {
        self.file = None;
        Ok(())
    }
}

fn win_path(vol: &Path, rel: &str) -> PathBuf {
    rel.split('\\').fold(vol.to_path_buf(), |p, s| p.join(s))
}

fn fresh_dir(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

struct WinPe {
    inner: TestPlatform,
    vol: PathBuf,
    /// Drivers in the offline image: (published, original).
    store: Vec<(String, String)>,
    /// Original file names DISM silently skips (unsigned, say).
    skip: Vec<String>,
    add_exit: i32,
    adds: Vec<u16>,
    sinks: u32,
    keep_staging: bool,
    protections: Vec<(String, FileProtection)>,
    writes: Vec<String>,
}

impl WinPe {
    fn new(name: &str) -> Self {
        let (inner, _) = TestPlatform::mem();
        Self {
            inner,
            vol: fresh_dir(name),
            store: vec![("oem0.inf".to_owned(), "inbox.inf".to_owned())],
            skip: Vec::new(),
            add_exit: 0,
            adds: Vec::new(),
            sinks: 0,
            keep_staging: false,
            protections: Vec::new(),
            writes: Vec::new(),
        }
    }

    fn stage_root(&self) -> PathBuf {
        self.vol.join(STAGE_ROOT)
    }
}

fn find_infs(dir: &Path, out: &mut Vec<String>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            find_infs(&p, out);
        } else if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("inf")) {
            out.push(p.file_name().unwrap().to_string_lossy().into_owned());
        }
    }
}

impl Platform for WinPe {
    fn open_target(&mut self, want: &PlanDiskV1) -> Result<OpenedTarget, PlatformError> {
        self.inner.open_target(want)
    }
    fn volumes(&mut self) -> &mut dyn VolumeOps {
        self.inner.volumes()
    }
    fn boot_files(&mut self) -> &mut dyn BootFiles {
        self.inner.boot_files()
    }
    fn firmware(&mut self) -> &mut dyn FirmwareVars {
        self.inner.firmware()
    }
    fn stage_sink(&mut self, dir: &StagePath) -> Result<Box<dyn ExtractSink + '_>, PlatformError> {
        self.sinks += 1;
        let root = win_path(&self.vol, &dir.relative());
        assert!(root.starts_with(self.stage_root()));
        assert!(!root.exists());
        fs::create_dir_all(&root).unwrap();
        Ok(Box::new(DirExtract { root, file: None }))
    }
    fn dism_add_driver(&mut self, dir: &StagePath) -> Result<ToolOutcome, PlatformError> {
        self.adds.push(dir.index());
        let mut infs = Vec::new();
        find_infs(&win_path(&self.vol, &dir.relative()), &mut infs);
        for i in infs {
            if !self.skip.contains(&i.to_lowercase()) {
                let n = self.store.len();
                self.store.push((format!("oem{n}.inf"), i));
            }
        }
        Ok(ToolOutcome {
            exit_code: self.add_exit,
            log_tail: "log".to_owned(),
        })
    }
    fn dism_list_drivers(&mut self) -> Result<String, PlatformError> {
        Ok(self
            .store
            .iter()
            .map(|(p, o)| {
                format!(
                    "Published Name : {p}\nOriginal File Name : {o}\nInbox : No\n\
                     Class Name : Net\nProvider Name : P\nDate : 1/1/2026\nVersion : 1.0\n\n"
                )
            })
            .collect())
    }
    fn remove_staging(&mut self) -> Result<(), PlatformError> {
        if !self.keep_staging && self.stage_root().exists() {
            fs::remove_dir_all(self.stage_root()).unwrap();
        }
        Ok(())
    }
    fn staging_exists(&mut self) -> Result<bool, PlatformError> {
        Ok(self.stage_root().exists())
    }
    fn write_protected_file(&mut self, p: &TargetPath, bytes: &[u8]) -> Result<(), PlatformError> {
        let path = win_path(&self.vol, &p.relative());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| PlatformError::new(PlatformErrorKind::Io(e.kind()), "write"))?;
        f.write_all(bytes).unwrap();
        self.protections.push((p.relative(), p.protection()));
        self.writes.push(p.relative());
        Ok(())
    }
    fn agent_binary(&mut self) -> Result<Vec<u8>, PlatformError> {
        Ok(b"agent binary".to_vec())
    }
}

fn vol(n: u32, role: PartRole, fs: FileSystem, label: &str) -> FormattedVolume {
    FormattedVolume {
        spec: VolumeSpec {
            role,
            number: n,
            start_bytes: 0,
            size_bytes: 1,
            fs,
            label: "x",
        },
        fs,
        label: label.to_owned(),
        locator: format!("vol-{n}"),
        root: None,
    }
}

const TRUST_PEM: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";

/// Runs steps 4 to 6.
fn run_tail(m: &M4, pf: &mut WinPe, link: &mut M4Link) -> Result<TailDone, JobFailureV2> {
    let clock = FakeClock::default();
    let v = m.verified();
    let esp = vol(1, PartRole::Esp, FileSystem::Fat32, "System");
    let win = vol(3, PartRole::Windows, FileSystem::Ntfs, "Windows");
    let part = test_esp(7);
    let plan_key_pem = m.base.plan_key.verifying_key().to_spki_pem().unwrap();
    let key_der = m.job_key.to_pkcs8_der().unwrap();
    let env = m.plan_env();
    let inputs = PostSetupInputs {
        server_url: "https://server.example:8443/",
        server_name: "server.example",
        trust_anchors_pem: TRUST_PEM,
        plan_key_pem: &plan_key_pem,
        plan_envelope: &env,
        job_key_pkcs8: &key_der,
    };
    let after = AfterApply {
        esp: &esp,
        windows: &win,
        esp_part: &part,
        last_seq: 12,
    };
    PrebootTail::new(crypto(), &clock, TailConfig::default()).run(&v, &after, &inputs, pf, link)
}

// ---------------------------------------------------------------------------
// Steps 4 to 6
// ---------------------------------------------------------------------------

#[test]
fn steps_4_to_6_stage_check_place_and_report_restart() {
    let m = M4::new(true);
    let mut pf = WinPe::new("m4-tail-ok");
    let log = Log::default();
    let mut link = M4Link::new(&m, log);
    let done = run_tail(&m, &mut pf, &mut link).expect("steps 4 to 6 succeed");

    // Step 4: one DISM call per archive, in plan order; both INFs staged;
    // staging removed.
    assert_eq!(pf.adds, [0, 1]);
    assert_eq!(done.drivers.archives, 2);
    assert_eq!(done.drivers.infs, 2);
    assert_eq!(done.drivers.new_drivers, 2);
    assert!(!pf.stage_root().exists());

    // Step 5: every file, SetupComplete.cmd last; job.key SYSTEM only.
    assert_eq!(
        pf.writes,
        [
            "ProgramData\\usgp\\postsetup\\usgp-agent.exe",
            "ProgramData\\usgp\\postsetup\\agent-package.zip",
            "ProgramData\\usgp\\postsetup\\job.key",
            "ProgramData\\usgp\\postsetup\\job.json",
            "Windows\\Panther\\unattend.xml",
            "Windows\\Setup\\Scripts\\SetupComplete.cmd",
        ]
    );
    for (p, prot) in &pf.protections {
        let want = if p.ends_with("job.key") {
            FileProtection::SystemOnly
        } else {
            FileProtection::Inherited
        };
        assert_eq!(*prot, want, "{p}");
    }
    let panther = win_path(&pf.vol, "Windows\\Panther\\unattend.xml");
    assert_eq!(fs::read(panther).unwrap(), ANSWER);
    let script = win_path(&pf.vol, "Windows\\Setup\\Scripts\\SetupComplete.cmd");
    assert_eq!(fs::read(script).unwrap(), SETUP_COMPLETE_CMD.as_bytes());
    let pkg = win_path(&pf.vol, "ProgramData\\usgp\\postsetup\\agent-package.zip");
    assert_eq!(fs::read(pkg).unwrap(), m.agent.0);
    let json = fs::read(win_path(&pf.vol, "ProgramData\\usgp\\postsetup\\job.json")).unwrap();
    let cfg = usgp_proto::PostSetupConfigV1::from_json(&json).unwrap();
    assert_eq!(cfg.job_id, m.job());
    assert_eq!(cfg.agent_sha256, crypto().sha256(b"agent binary"));
    assert!(!String::from_utf8_lossy(&json).contains("PRIVATE"));

    // Step 6: boot files and boot option, then the restart report.
    assert_eq!(pf.inner.boot.calls, 1);
    assert_eq!(boot_order_of(&pf.inner.fw)[0], done.boot.option);
    use ProgressEvent::{StepCompleted as C, StepStarted as S};
    assert_eq!(
        link.states(),
        [(4, S), (4, C), (5, S), (5, C), (6, S), (6, C)]
    );
    assert_eq!(link.reports[0].seq, 13);
}

#[test]
fn tampered_driver_chunk_fails_before_extraction() {
    let m = M4::new(true);
    let mut pf = WinPe::new("m4-tamper");
    let mut link = M4Link::new(&m, Log::default());
    link.tamper = Some(m.drivers[1].1.sha256);
    let f = run_tail(&m, &mut pf, &mut link).unwrap_err();
    assert_eq!(f.step, StepV2::ADD_DRIVERS);
    assert_eq!(f.code.as_str(), "chunk_digest_mismatch");
    // The first archive was added; the tampered one never reached a sink.
    assert_eq!(pf.sinks, 1);
    assert_eq!(pf.adds, [0]);
    assert!(!pf.stage_root().exists());
    assert_eq!(link.reports.last().unwrap().event, ProgressEvent::Failed);
    assert!(pf.writes.is_empty(), "step 5 never ran");
}

#[test]
fn missing_inf_fails_step_4() {
    let m = M4::new(true);
    let mut pf = WinPe::new("m4-missing-inf");
    pf.skip.push("stor.inf".to_owned());
    let mut link = M4Link::new(&m, Log::default());
    let f = run_tail(&m, &mut pf, &mut link).unwrap_err();
    assert_eq!(f.step, StepV2::ADD_DRIVERS);
    assert_eq!(
        f.code.as_str(),
        format!("driver_not_staged:{DRIVER_B}:stor.inf")
    );
    assert!(!pf.stage_root().exists());
}

#[test]
fn dism_failure_and_staging_left_behind_fail_step_4() {
    let m = M4::new(true);
    let mut pf = WinPe::new("m4-dism-exit");
    pf.add_exit = 5;
    let mut link = M4Link::new(&m, Log::default());
    let f = run_tail(&m, &mut pf, &mut link).unwrap_err();
    assert_eq!(f.code.as_str(), format!("driver_add_failed:{DRIVER_A}:5"));

    let mut pf = WinPe::new("m4-staging-kept");
    pf.keep_staging = true;
    let mut link = M4Link::new(&m, Log::default());
    let f = run_tail(&m, &mut pf, &mut link).unwrap_err();
    assert_eq!(f.step, StepV2::ADD_DRIVERS);
    assert_eq!(f.code.as_str(), "staging_not_removed");
}

#[test]
fn an_existing_answer_file_is_never_overwritten() {
    let m = M4::new(true);
    let mut pf = WinPe::new("m4-answer-exists");
    let panther = win_path(&pf.vol, "Windows\\Panther\\unattend.xml");
    fs::create_dir_all(panther.parent().unwrap()).unwrap();
    fs::write(&panther, b"operator content").unwrap();
    let mut link = M4Link::new(&m, Log::default());
    let f = run_tail(&m, &mut pf, &mut link).unwrap_err();
    assert_eq!(f.step, StepV2::PLACE_CONFIG);
    assert_eq!(f.code.as_str(), "answer_file_exists");
    assert_eq!(fs::read(&panther).unwrap(), b"operator content");
    assert!(!pf.writes.iter().any(|w| w.ends_with("SetupComplete.cmd")));
}

#[test]
fn step_6_fails_if_the_server_does_not_take_the_restart_report() {
    let m = M4::new(true);
    let mut pf = WinPe::new("m4-step6-refused");
    let mut link = M4Link::new(&m, Log::default());
    link.refuse_step6 = true;
    let f = run_tail(&m, &mut pf, &mut link).unwrap_err();
    assert_eq!(f.step, StepV2::MAKE_BOOTABLE_RESTART);
    assert_eq!(f.code.as_str(), "server_refused");
}

// ---------------------------------------------------------------------------
// Steps 7 to 9: the post-setup runner on the same tree
// ---------------------------------------------------------------------------

struct Installed {
    vol: PathBuf,
    log: Log,
    tags: Option<Vec<u8>>,
    password: Option<Zeroizing<String>>,
    set_fails: Option<u32>,
    locked: u32,
    unlocked: u32,
    installs: Vec<(String, Vec<String>, String)>,
    outcome: InstallOutcome,
    failures: Vec<String>,
}

impl Installed {
    fn on(vol: &Path, log: Log) -> Self {
        Self {
            vol: vol.to_path_buf(),
            log,
            tags: None,
            password: None,
            set_fails: None,
            locked: 0,
            unlocked: 0,
            installs: Vec::new(),
            outcome: InstallOutcome::Exited(0),
            failures: Vec::new(),
        }
    }

    fn path(&self, f: RunnerFile) -> PathBuf {
        let rel = match f {
            RunnerFile::JobJson => "ProgramData\\usgp\\postsetup\\job.json",
            RunnerFile::JobKey => "ProgramData\\usgp\\postsetup\\job.key",
            RunnerFile::AgentPackage => "ProgramData\\usgp\\postsetup\\agent-package.zip",
            RunnerFile::AnswerFile => "Windows\\Panther\\unattend.xml",
            RunnerFile::SetupComplete => "Windows\\Setup\\Scripts\\SetupComplete.cmd",
        };
        win_path(&self.vol, rel)
    }
}

fn io_pf(e: io::Error) -> PlatformError {
    PlatformError::new(PlatformErrorKind::Io(e.kind()), "file")
}

impl PostSetupPlatform for Installed {
    fn read_file(&mut self, f: RunnerFile, max: u64) -> Result<Zeroizing<Vec<u8>>, PlatformError> {
        let b = fs::read(self.path(f)).map_err(io_pf)?;
        assert!(b.len() as u64 <= max);
        Ok(Zeroizing::new(b))
    }
    fn delete_file(&mut self, f: RunnerFile) -> Result<(), PlatformError> {
        match fs::remove_file(self.path(f)) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(io_pf(e)),
            _ => Ok(()),
        }
    }
    fn file_exists(&mut self, f: RunnerFile) -> Result<bool, PlatformError> {
        Ok(self.path(f).exists())
    }
    fn write_tags(&mut self, json: &[u8]) -> Result<(), PlatformError> {
        self.tags = Some(json.to_vec());
        Ok(())
    }
    fn lock_memory(&mut self, region: &[u8]) -> Result<(), PlatformError> {
        assert!(!region.is_empty());
        self.locked += 1;
        Ok(())
    }
    fn unlock_memory(&mut self, _region: &[u8]) {
        self.unlocked += 1;
    }
    fn set_admin_password(&mut self, pw: &Zeroizing<String>) -> Result<(), AccountError> {
        self.log.borrow_mut().push("password set".to_owned());
        if let Some(win32) = self.set_fails {
            return Err(AccountError { win32 });
        }
        self.password = Some(pw.clone());
        Ok(())
    }
    fn agent_sink(&mut self) -> Result<Box<dyn ExtractSink + '_>, PlatformError> {
        let root = win_path(&self.vol, "ProgramData\\usgp\\postsetup\\agent");
        fs::create_dir_all(&root).unwrap();
        Ok(Box::new(DirExtract { root, file: None }))
    }
    fn run_installer(
        &mut self,
        cmd: &InstallerCommand<'_>,
    ) -> Result<InstallOutcome, PlatformError> {
        self.log.borrow_mut().push("installer run".to_owned());
        self.installs.push((
            cmd.installer.as_str().to_owned(),
            cmd.args.iter().map(|a| a.as_str().to_owned()).collect(),
            cmd.tags_json.to_owned(),
        ));
        Ok(self.outcome)
    }
    fn record_failure(&mut self, text: &str) {
        self.failures.push(text.to_owned());
    }
}

/// Steps 4 to 6 in Windows PE, then the runner on the same tree.
fn whole(
    name: &str,
    escrow: bool,
    tweak: impl FnOnce(&mut Installed, &mut M4Link),
) -> (M4, Installed, M4Link, Result<Ready, JobFailureV2>) {
    let m = M4::new(escrow);
    let mut pf = WinPe::new(name);
    let log = Log::default();
    let mut link = M4Link::new(&m, Rc::clone(&log));
    run_tail(&m, &mut pf, &mut link).expect("steps 4 to 6");
    // "Restart": the session token is gone; the runner must resume.
    let mut inst = Installed::on(&pf.vol, log);
    tweak(&mut inst, &mut link);
    let clock = FakeClock::default();
    let r =
        PostSetupRunner::new(crypto(), &clock, RunnerConfig::default()).run(&mut inst, &mut link);
    (m, inst, link, r)
}

#[test]
fn runner_escrows_then_sets_then_installs_and_reports_ready() {
    let (m, inst, link, r) = whole("m4-runner-ok", true, |_, _| {});
    let ready = r.expect("job ready");
    assert!(ready.password_set);
    assert!(!ready.restart_pending);

    // Order (REQ-SEQ-003, decision 0024): resume, escrow committed, then
    // set, then confirmed, then the agent.
    let log = inst.log.borrow().clone();
    let pos = |s: &str| {
        log.iter()
            .position(|l| l == s)
            .unwrap_or_else(|| panic!("{s}"))
    };
    assert!(pos("resumed") < pos("escrow submitted"));
    assert!(pos("escrow submitted") < pos("password set"));
    assert!(pos("password set") < pos("escrow confirmed true"));
    assert!(pos("escrow confirmed true") < pos("installer run"));
    assert_eq!(inst.locked, 1);
    assert_eq!(inst.unlocked, 1);

    // The server can open exactly the password that was set.
    let body = link.escrow.clone().unwrap();
    let sealed = usgp_crypto::SealedV1 {
        key_id: m.escrow_key.key_id(),
        eph_pub: body.eph_pub_b64.as_bytes().to_vec(),
        nonce: body.nonce_b64.as_bytes().try_into().unwrap(),
        ct: body.ct_b64.as_bytes().to_vec(),
    };
    let ctx = usgp_crypto::EscrowContext {
        job_id: *m.job().as_bytes(),
        account: "administrator",
    };
    let opened = crypto().escrow_open(&m.escrow_key, &ctx, &sealed).unwrap();
    let set = inst.password.clone().unwrap();
    assert_eq!(opened.as_slice(), set.as_bytes());
    assert_eq!(set.len(), 24);

    // Tags, agent, answer file and key gone, reports from the high base.
    assert_eq!(
        inst.tags.as_deref(),
        Some(br#"["site:hq","floor 2"]"#.as_slice())
    );
    assert_eq!(
        inst.installs,
        [(
            "setup.exe".to_owned(),
            vec!["/quiet".to_owned()],
            r#"["site:hq","floor 2"]"#.to_owned()
        )]
    );
    assert!(!inst.path(RunnerFile::AnswerFile).exists());
    assert!(!inst.path(RunnerFile::JobKey).exists());
    assert!(!inst.path(RunnerFile::SetupComplete).exists());
    let after: Vec<_> = link
        .reports
        .iter()
        .filter(|r| r.step.runs_after_restart())
        .collect();
    assert_eq!(after[0].seq, POSTSETUP_SEQ_BASE + 1);
    use ProgressEvent::{StepCompleted as C, StepStarted as S, Succeeded};
    assert_eq!(
        link.states()[6..],
        [(7, S), (7, C), (8, S), (8, C), (9, S), (9, Succeeded)]
    );
    assert_eq!(after[3].restart_pending, Some(false));

    // No report, failure or log line holds the password.
    let pw = set.as_str();
    for r in &link.reports {
        assert!(!format!("{r:?}").contains(pw));
    }
    assert!(!log.iter().any(|l| l.contains(pw)));
}

#[test]
fn refused_escrow_means_the_password_is_never_set() {
    let (_, inst, link, r) = whole("m4-escrow-refused", true, |_, l| l.refuse_escrow = true);
    let f = r.unwrap_err();
    assert_eq!(f.step, StepV2::WINDOWS_SETUP);
    assert_eq!(f.code.as_str(), "escrow_refused");
    assert!(inst.password.is_none());
    assert!(!inst.log.borrow().iter().any(|l| l == "password set"));
    assert!(inst.installs.is_empty());
    assert_eq!(inst.unlocked, 1);
    assert_eq!(inst.failures.len(), 1);
    assert_eq!(link.reports.last().unwrap().event, ProgressEvent::Failed);
    assert!(!inst.path(RunnerFile::JobKey).exists());
}

#[test]
fn a_failed_set_is_confirmed_as_not_applied() {
    let (_, inst, link, r) = whole("m4-set-fails", true, |i, _| i.set_fails = Some(2221));
    let f = r.unwrap_err();
    assert_eq!(f.code.as_str(), "admin_password_set_failed:2221");
    assert_eq!(link.confirms.len(), 1);
    assert!(!link.confirms[0].set);
    assert!(inst.installs.is_empty());
}

#[test]
fn no_escrow_key_means_no_password() {
    let (_, inst, link, r) = whole("m4-no-escrow", false, |_, _| {});
    assert!(!r.unwrap().password_set);
    assert!(link.escrow.is_none());
    assert!(inst.password.is_none());
    assert_eq!(inst.locked, 0);
}

#[test]
fn installer_exit_codes() {
    let (_, _, link, r) = whole("m4-3010", false, |i, _| {
        i.outcome = InstallOutcome::Exited(3010);
    });
    assert!(r.unwrap().restart_pending);
    let s8 = link
        .reports
        .iter()
        .find(|r| r.step == StepV2::INSTALL_AGENT && r.event == ProgressEvent::StepCompleted)
        .unwrap();
    assert_eq!(s8.restart_pending, Some(true));

    let (_, _, link, r) = whole("m4-exit-1603", false, |i, _| {
        i.outcome = InstallOutcome::Exited(1603);
    });
    let f = r.unwrap_err();
    assert_eq!(f.step, StepV2::INSTALL_AGENT);
    assert_eq!(f.code.as_str(), "agent_install_failed:1603");
    assert!(!link.states().contains(&(9, ProgressEvent::Succeeded)));

    let (_, _, _, r) = whole("m4-timeout", false, |i, _| {
        i.outcome = InstallOutcome::TimedOut;
    });
    assert_eq!(r.unwrap_err().code.as_str(), "agent_install_timeout");
}

#[test]
fn runner_checks_its_inputs_before_contact() {
    // Another key in job.key.
    let (_, inst, link, r) = whole("m4-key-mismatch", true, |i, _| {
        let other = SigningKey::generate().unwrap().to_pkcs8_der().unwrap();
        fs::write(i.path(RunnerFile::JobKey), other.as_slice()).unwrap();
    });
    assert_eq!(r.unwrap_err().code.as_str(), "job_key_mismatch");
    assert!(!link.resumed);
    assert_eq!(inst.failures.len(), 1);

    // A changed agent package.
    let (_, _, link, r) = whole("m4-agent-digest", true, |i, _| {
        fs::write(i.path(RunnerFile::AgentPackage), b"PK other").unwrap();
    });
    assert_eq!(r.unwrap_err().code.as_str(), "agent_digest_mismatch");
    assert!(!link.resumed);

    // A tampered job.json plan.
    let (_, _, _, r) = whole("m4-plan-tamper", true, |i, _| {
        let p = i.path(RunnerFile::JobJson);
        let text = fs::read_to_string(&p).unwrap();
        // `{"schema":2,` becomes `{"schema":3,`: valid base64, bad signature.
        assert!(text.contains("eyJzY2hlbWEiOjIs"));
        fs::write(&p, text.replacen("eyJzY2hlbWEiOjIs", "eyJzY2hlbWEiOjMs", 1)).unwrap();
    });
    assert_eq!(r.unwrap_err().code.as_str(), "postsetup_config_invalid");
}

#[test]
fn resume_waits_for_the_network_and_fails_closed_when_refused() {
    let (_, _, link, r) = whole("m4-resume-late", false, |_, l| l.resume_transient = 7);
    assert!(r.is_ok());
    assert!(link.resumed);

    let (_, inst, link, r) = whole("m4-resume-refused", true, |_, l| l.refuse_resume = true);
    assert_eq!(r.unwrap_err().code.as_str(), "resume_refused");
    assert!(inst.password.is_none());
    assert!(link.escrow.is_none());
    assert_eq!(inst.failures.len(), 1);
    assert!(!inst.path(RunnerFile::JobKey).exists());
}
