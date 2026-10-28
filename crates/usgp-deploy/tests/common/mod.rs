//! Test doubles for the engine tests: a signed plan and content manifest
//! over a synthetic WIM (real ECDSA and SHA-256 through usgp-crypto), a
//! server link, a platform over an in-memory disk or a loopback file, a
//! firmware-variable store, a fake clock and a recording screen.
//!
//! No test opens a block device: disks are `MemBlockDevice` or regular
//! files under `CARGO_TARGET_TMPDIR` through `FileBlockDevice`.
//!
//! Declared `pub mod common` by each test crate, so helpers one binary
//! does not use are not dead code.

#![cfg(test)]

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use usgp_common::Sha256Digest;
use usgp_crypto::{CryptoProvider, SigningKey, sign_typed};
use usgp_deploy::platform::{
    BootFiles, FirmwareVars, FormattedVolume, FwError, OpenedTarget, Platform, PlatformError,
    VolumeOps, VolumeSpec,
};
use usgp_deploy::{
    Clock, Engine, EngineConfig, JobFailure, JobView, LinkError, PinnedKey, PlanKeys, ServerLink,
    SignedJob, Succeeded, ViewEvent,
};
use usgp_disk::layout::WindowsUefiLayout;
use usgp_disk::uefi::BootVarName;
use usgp_disk::{BlockDevice, Bus, DiskFacts, DiskIdentity, FileBlockDevice, MemBlockDevice};
use usgp_image::Compression;
use usgp_image::apply::{ApplyRoot, ApplySink, MemorySink, ReparseBuffer, SinkResult};
use usgp_image::chunks::ContentHasher;
use usgp_image::testkit::builder::pseudorandom;
use usgp_image::testkit::{NodeSpec, TreeSpec, WimBuilder};
use usgp_image::wim::metadata::{Attributes, FileTimes};
use usgp_image::wim::names::{ImagePath, ShortName, StreamName};
use usgp_proto::content_manifest::{ContentManifestV1, ManifestEdition, WimSummaryV1};
use usgp_proto::device::{AgentNonce, MacAddress, MacList};
use usgp_proto::disk::{DiskDescriptorParts, DiskDescriptorV1, PlanDiskV1};
use usgp_proto::envelope::{PayloadType, SignatureAlg, SignatureV1, SignedEnvelopeV1};
use usgp_proto::job_plan::{
    JobPlanV1, LayoutPolicyV1, PlanDeviceV1, PlanExpectation, PlanImageV1, PlanPackageV1,
    PlanStepV1, PlanWipeV1, RetryPolicyV1, VerifiedJobPlan, WipeScope,
};
use usgp_proto::limits::CHUNK_SIZE;
use usgp_proto::progress::{JobState, ProgressAckV1, ProgressEvent, ProgressV1, Step};
use usgp_proto::{
    BootServiceId, ContentId, ContentKind, DiskText, DiskToken, DisplayName, EditionIndex,
    FileName, JobId, PackageId, SessionId, UnixMicros, WimCompression, WimText,
};

/// 10⁹ bytes.
pub const GB: u64 = 1_000_000_000;
/// The test disk: 70 GB, 512e.
pub const DISK_BYTES: u64 = 70 * GB;

const SESSION: &str = "5a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
const JOB: &str = "6b2c3d4e-5f60-4b7c-9d8e-0f1a2b3c4d5e";
const BOOT_SERVICE: &str = "7c3d4e5f-6071-4c8d-ae9f-1a2b3c4d5e6f";
const PACKAGE: &str = "1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516";
const CONTENT: &str = "0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f";

/// The FIPS provider.
pub fn crypto() -> &'static dyn CryptoProvider {
    usgp_crypto::provider()
}

// ---------------------------------------------------------------------------
// Synthetic images
// ---------------------------------------------------------------------------

/// Two editions: the testkit's sample tree (index 1) and a one-file tree.
pub fn small_wim() -> Vec<u8> {
    WimBuilder::new(Compression::Xpress)
        .tree_image("Edition 1", "first", TreeSpec::sample())
        .tree_image(
            "Edition 2",
            "second",
            TreeSpec::new(vec![NodeSpec::file("only.txt", b"second edition\n")]),
        )
        .build()
        .unwrap()
        .0
}

/// Edition 1 holds links DISM rewrote at capture (+92 = 0, header
/// `RP_FIX`), stored against drive `T:`: a junction and a directory
/// symbolic link into the tree (re-based onto the apply root, decision
/// 0022), and a junction out of the tree (copied).
pub fn link_wim() -> Vec<u8> {
    use usgp_image::testkit::tree::abs_link_data;
    WimBuilder::new(Compression::Xpress)
        .tree_image(
            "Edition 1",
            "links",
            TreeSpec::new(vec![NodeSpec::dir(
                "links",
                vec![
                    NodeSpec::file("target-file.txt", b"t\n"),
                    NodeSpec::dir("target-dir", vec![]),
                    NodeSpec::junction("junction", &abs_link_data("T:\\links\\target-dir", true))
                        .field_92(0),
                    NodeSpec::symlink(
                        "abs-dir",
                        true,
                        &abs_link_data("T:\\links\\target-dir", false),
                    )
                    .field_92(0),
                    NodeSpec::junction("junction-out", &abs_link_data("T:\\outside", true)),
                ],
            )]),
        )
        .image("Edition 2", "plain")
        .build()
        .unwrap()
        .0
}

/// One uncompressed edition holding a 9 MiB file, so the content spans
/// two 8 MiB chunks.
pub fn two_chunk_wim() -> Vec<u8> {
    let big = pseudorandom(9 * 1024 * 1024, 7);
    let wim = WimBuilder::new(Compression::None)
        .tree_image(
            "Edition 1",
            "big",
            TreeSpec::new(vec![NodeSpec::file("big.bin", &big)]),
        )
        .image("Edition 2", "plain")
        .build()
        .unwrap()
        .0;
    assert!(wim.len() as u64 > CHUNK_SIZE);
    wim
}

// ---------------------------------------------------------------------------
// Signed plan fixture
// ---------------------------------------------------------------------------

/// What the person chose: the disk the platform double reports.
pub fn facts() -> DiskFacts {
    DiskFacts {
        identity: DiskIdentity {
            device_number: 2,
            model: "Test NVMe".to_owned(),
            serial: Some("SN-0001".to_owned()),
        },
        bus: Bus::Nvme,
        removable: false,
        read_only: false,
        logical_sector: 512,
        physical_sector: 4096,
        size_bytes: DISK_BYTES,
        hosts_boot_environment: false,
        partitions: vec![usgp_disk::ExistingPartition {
            start_bytes: 1 << 20,
            size_bytes: 10 * GB,
            label: Some("Old data".to_owned()),
        }],
    }
}

/// The descriptor the agent sent for `f` (no existing partitions listed).
pub fn descriptor(f: &DiskFacts) -> DiskDescriptorV1 {
    DiskDescriptorV1::new(DiskDescriptorParts {
        disk_token: DiskToken::from_random_bytes([0x5a; 16]),
        bus: usgp_proto::disk::Bus::Nvme,
        model: DiskText::sanitized(&f.identity.model),
        serial: DiskText::sanitized(f.identity.serial.as_deref().unwrap_or("")),
        size_bytes: f.size_bytes,
        logical_sector: f.logical_sector,
        physical_sector: f.physical_sector,
        removable: f.removable,
        partitions: Vec::new(),
    })
    .unwrap()
}

/// The image, its signed manifest, the plan, and the keys.
pub struct Fixture {
    /// The image bytes.
    pub wim: Vec<u8>,
    /// Its content manifest.
    pub manifest: ContentManifestV1,
    /// The job plan (re-signed by each `plan_env` call).
    pub plan: JobPlanV1,
    /// The disk the person chose.
    pub disk: DiskDescriptorV1,
    /// The nonce the agent sent.
    pub nonce: AgentNonce,
    /// The server's plan key.
    pub plan_key: SigningKey,
    /// The server's content key.
    pub content_key: SigningKey,
    /// The pinned public keys.
    pub keys: PlanKeys,
}

/// Signs `payload`; with `tamper = Some(at)`, flips byte `at` afterwards
/// and keeps the original signature.
fn seal(
    key: &SigningKey,
    ty: PayloadType,
    mut payload: Vec<u8>,
    tamper: Option<usize>,
) -> SignedEnvelopeV1 {
    let sig = sign_typed(key, ty.as_str(), &payload).unwrap();
    let s = SignatureV1::new(key.key_id().0, SignatureAlg::EcdsaP384Sha384, sig).unwrap();
    if let Some(at) = tamper {
        payload[at] ^= 0x01;
    }
    SignedEnvelopeV1::new(ty, payload, vec![s]).unwrap()
}

impl Fixture {
    /// A fixture over `wim`, editions 1 and 2, edition 1 chosen.
    pub fn new(wim: Vec<u8>) -> Self {
        let plan_key = SigningKey::generate().unwrap();
        let content_key = SigningKey::generate().unwrap();
        let mut h = ContentHasher::new(crypto());
        h.update(&wim);
        let digests = h.finish();
        let size = wim.len() as u64;
        let manifest = ContentManifestV1 {
            schema: 1,
            kind: ContentKind::Image,
            content_id: ContentId::parse(CONTENT).unwrap(),
            display_name: DisplayName::new("Synthetic Windows").unwrap(),
            file_name: FileName::new("install.wim").unwrap(),
            size,
            sha256: digests.total,
            chunk_size: CHUNK_SIZE,
            chunk_sha256: digests.chunks,
            wim: WimSummaryV1 {
                compression: WimCompression::Xpress,
                image_count: 2,
                boot_index: 0,
                editions: (1..=2u32)
                    .map(|i| ManifestEdition {
                        index: EditionIndex::new(u64::from(i)).unwrap(),
                        name: WimText::new(format!("Edition {i}")).unwrap(),
                        description: WimText::new("d").unwrap(),
                        total_bytes: None,
                    })
                    .collect(),
            },
            ready_at: UnixMicros::new(1_793_000_000_000_000).unwrap(),
            key_id: content_key.key_id().0,
        };
        let disk = descriptor(&facts());
        let nonce = AgentNonce::from_random_bytes([0x42; 32]);
        let cm_payload = manifest.to_payload().unwrap();
        let plan = JobPlanV1 {
            schema: 1,
            job_id: JobId::parse(JOB).unwrap(),
            session_id: SessionId::parse(SESSION).unwrap(),
            boot_service_id: BootServiceId::parse(BOOT_SERVICE).unwrap(),
            issued_at_us: UnixMicros::new(1_793_000_000_000_123).unwrap(),
            key_id: plan_key.key_id().0,
            agent_nonce: nonce,
            device: PlanDeviceV1 {
                macs: MacList::new(vec![MacAddress::new([2, 0, 0, 0, 0, 1]).unwrap()]).unwrap(),
            },
            package: PlanPackageV1 {
                id: PackageId::parse(PACKAGE).unwrap(),
                revision: 3,
                manifest_sha256: Sha256Digest([0xcc; 32]),
            },
            image: PlanImageV1 {
                content_sha256: manifest.sha256,
                size,
                content_manifest_sha256: crypto().sha256(&cm_payload),
                edition_index: EditionIndex::new(1).unwrap(),
                edition_name: WimText::new("Edition 1").unwrap(),
                total_bytes: 1,
            },
            disk: PlanDiskV1::from(&disk),
            layout_policy: LayoutPolicyV1::STANDARD,
            wipe: PlanWipeV1 {
                audit_seq: 4242,
                record_hash: Sha256Digest([0xdd; 32]),
                scope: WipeScope::TablesAndVolumeHeads1Mib,
            },
            steps: Step::ALL
                .iter()
                .map(|s| PlanStepV1 {
                    step: *s,
                    kind: s.kind(),
                    timeout_s: 21_600,
                })
                .collect(),
            retry: RetryPolicyV1 {
                attempts: 5,
                base_ms: 2000,
                max_ms: 60_000,
            },
            stall_timeout_s: 1800,
            report_interval_s: 30,
        };
        let keys = PlanKeys {
            plan: PinnedKey::new(plan_key.verifying_key().clone()),
            content: PinnedKey::new(content_key.verifying_key().clone()),
        };
        Self {
            wim,
            manifest,
            plan,
            disk,
            nonce,
            plan_key,
            content_key,
            keys,
        }
    }

    /// The plan envelope, signed with the plan key.
    pub fn plan_env(&self) -> SignedEnvelopeV1 {
        self.plan_env_tampered(None)
    }

    /// The plan envelope, with payload byte `at` flipped after signing.
    pub fn plan_env_tampered(&self, at: Option<usize>) -> SignedEnvelopeV1 {
        let payload = self.plan.to_payload().unwrap();
        seal(&self.plan_key, PayloadType::JobPlanV1, payload, at)
    }

    /// The content envelope, signed with the content key.
    pub fn content_env(&self) -> SignedEnvelopeV1 {
        self.content_env_tampered(None)
    }

    /// The content envelope, with payload byte `at` flipped after signing.
    pub fn content_env_tampered(&self, at: Option<usize>) -> SignedEnvelopeV1 {
        let payload = self.manifest.to_payload().unwrap();
        seal(
            &self.content_key,
            PayloadType::ContentManifestV1,
            payload,
            at,
        )
    }

    /// The plan signed by `key` instead of the pinned plan key.
    pub fn plan_env_signed_by(&self, key: &SigningKey) -> SignedEnvelopeV1 {
        let mut plan = self.plan.clone();
        plan.key_id = key.key_id().0;
        seal(
            key,
            PayloadType::JobPlanV1,
            plan.to_payload().unwrap(),
            None,
        )
    }

    /// What the agent expects the plan to say.
    pub fn expect(&self) -> PlanExpectation<'_> {
        PlanExpectation {
            agent_nonce: &self.nonce,
            session_id: self.plan.session_id,
            job_id: self.plan.job_id,
            package_id: self.plan.package.id,
            package_revision: self.plan.package.revision,
            disk: &self.disk,
        }
    }

    /// The plan, verified.
    pub fn verified(&self) -> VerifiedJobPlan {
        usgp_deploy::verify_plan(
            &self.plan_env(),
            &self.content_env(),
            &self.keys,
            &self.expect(),
            crypto(),
        )
        .unwrap()
    }
}

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

/// Time moves only when slept on or advanced by a double.
#[derive(Default)]
pub struct FakeClock {
    now: Cell<Duration>,
    /// Total time slept.
    pub slept: Cell<Duration>,
}

impl FakeClock {
    /// Moves time forward by `d`.
    pub fn advance(&self, d: Duration) {
        self.now.set(self.now.get() + d);
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Duration {
        self.now.get()
    }
    fn sleep(&self, d: Duration) {
        self.slept.set(self.slept.get() + d);
        self.advance(d);
    }
}

// ---------------------------------------------------------------------------
// Server link
// ---------------------------------------------------------------------------

/// A server over an image in memory, with injected faults.
pub struct FakeLink {
    /// The image the server holds.
    pub content: Vec<u8>,
    /// The clock fetches advance.
    pub clock: Rc<FakeClock>,
    /// Chunk numbers fetched, in order.
    pub fetches: Vec<u64>,
    /// Flip the first byte of the response to fetch number `k` (0-based).
    pub tamper_fetch: Option<usize>,
    /// Fail the next `n` fetches as transient.
    pub transient_fetches: u32,
    /// Fail every fetch with this error.
    pub fetch_error: Option<LinkError>,
    /// Time each fetch takes.
    pub fetch_delay: Duration,
    /// Fail fetches transiently once this many have succeeded.
    pub fail_after: Option<usize>,
    /// Every report received (successful or not), in order.
    pub reports: Vec<ProgressV1>,
    /// Reports acknowledged, in order.
    pub acked: Vec<ProgressV1>,
    /// Fail the next `n` reports as transient.
    pub transient_reports: u32,
    /// Answer `succeeded` with this error.
    pub success_error: Option<LinkError>,
    /// The state the server reports after `succeeded`.
    pub success_state: JobState,
}

impl FakeLink {
    /// A server that answers everything.
    pub fn new(content: Vec<u8>, clock: Rc<FakeClock>) -> Self {
        Self {
            content,
            clock,
            fetches: Vec::new(),
            tamper_fetch: None,
            transient_fetches: 0,
            fetch_error: None,
            fetch_delay: Duration::ZERO,
            fail_after: None,
            reports: Vec::new(),
            acked: Vec::new(),
            transient_reports: 0,
            success_error: None,
            success_state: JobState::Succeeded,
        }
    }

    /// State events acknowledged (no `progress`), as (step, event).
    pub fn states(&self) -> Vec<(u8, ProgressEvent)> {
        self.acked
            .iter()
            .filter(|r| r.event != ProgressEvent::Progress)
            .map(|r| (r.step.get(), r.event))
            .collect()
    }

    /// Chunks in the image.
    pub fn chunk_count(&self) -> u64 {
        (self.content.len() as u64).div_ceil(CHUNK_SIZE)
    }
}

impl ServerLink for FakeLink {
    fn fetch_chunk(
        &mut self,
        _job: JobId,
        _content: &Sha256Digest,
        n: u64,
    ) -> Result<Vec<u8>, LinkError> {
        self.clock.advance(self.fetch_delay);
        if let Some(e) = self.fetch_error {
            return Err(e);
        }
        if self.transient_fetches > 0 {
            self.transient_fetches -= 1;
            return Err(LinkError::Transient);
        }
        if self.fail_after.is_some_and(|k| self.fetches.len() >= k) {
            return Err(LinkError::Transient);
        }
        let k = self.fetches.len();
        self.fetches.push(n);
        let start = usize::try_from(n * CHUNK_SIZE).unwrap();
        if start >= self.content.len() {
            return Err(LinkError::NotFound);
        }
        let end = (start + CHUNK_SIZE as usize).min(self.content.len());
        let mut v = self.content[start..end].to_vec();
        if self.tamper_fetch == Some(k) {
            v[0] ^= 0x01;
        }
        Ok(v)
    }

    fn report(&mut self, _job: JobId, r: &ProgressV1) -> Result<ProgressAckV1, LinkError> {
        assert!(r.validate().is_ok(), "invalid report {r:?}");
        self.reports.push(r.clone());
        if self.transient_reports > 0 {
            self.transient_reports -= 1;
            return Err(LinkError::Transient);
        }
        let job_state = match r.event {
            ProgressEvent::Succeeded => {
                if let Some(e) = self.success_error {
                    return Err(e);
                }
                self.success_state
            }
            ProgressEvent::Failed => JobState::Failed,
            _ => JobState::Running,
        };
        self.acked.push(r.clone());
        Ok(ProgressAckV1 {
            ack_seq: r.seq,
            job_state,
        })
    }
}

// ---------------------------------------------------------------------------
// Screen
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
/// What the screen was shown.
pub enum Shown {
    /// The job started.
    Started,
    /// A step started.
    StepStarted(u8),
    /// Byte progress in a step.
    Progress(u8),
    /// A step completed.
    StepCompleted(u8),
    /// The job failed.
    Failed(JobFailure),
    /// The job succeeded.
    Succeeded,
}

#[derive(Default)]
/// A screen that records what it was shown.
pub struct RecordingView(pub Vec<Shown>);

impl JobView for RecordingView {
    fn show(&mut self, e: &ViewEvent<'_>) {
        let s = match e {
            ViewEvent::Started { .. } => Shown::Started,
            ViewEvent::StepStarted(s) => Shown::StepStarted(s.get()),
            ViewEvent::Progress {
                step,
                bytes_done,
                bytes_total,
                ..
            } => {
                assert!(bytes_done <= bytes_total);
                Shown::Progress(step.get())
            }
            ViewEvent::StepCompleted(s) => Shown::StepCompleted(s.get()),
            ViewEvent::Failed(f) => Shown::Failed((*f).clone()),
            ViewEvent::Succeeded => Shown::Succeeded,
            _ => return,
        };
        self.0.push(s);
    }
}

impl RecordingView {
    /// Events other than byte progress.
    pub fn states(&self) -> Vec<Shown> {
        self.0
            .iter()
            .filter(|s| !matches!(s, Shown::Progress(_)))
            .cloned()
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Platform
// ---------------------------------------------------------------------------

/// An in-memory disk shared between the platform and the test.
#[derive(Clone)]
pub struct SharedDev(pub Rc<RefCell<MemBlockDevice>>);

impl SharedDev {
    /// A zeroed disk of `len` bytes.
    pub fn new(len: u64, sector: u32) -> Self {
        Self(Rc::new(RefCell::new(
            MemBlockDevice::new(len, sector).unwrap(),
        )))
    }
    /// Writes so far.
    pub fn writes(&self) -> u64 {
        self.0.borrow().write_count()
    }
}

impl BlockDevice for SharedDev {
    fn len(&self) -> u64 {
        self.0.borrow().len()
    }
    fn logical_sector(&self) -> u32 {
        self.0.borrow().logical_sector()
    }
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        self.0.borrow_mut().read_at(off, buf)
    }
    fn write_at(&mut self, off: u64, buf: &[u8]) -> io::Result<()> {
        self.0.borrow_mut().write_at(off, buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.borrow_mut().flush()
    }
}

/// Where the platform's target disk lives.
pub enum DevSource {
    /// In memory.
    Mem(SharedDev),
    /// A regular file, with its sector size.
    File(PathBuf, u32),
}

/// Formatting double around a `MemorySink`.
pub struct TestVolumes {
    /// Format calls.
    pub formats: u32,
    /// Fail with this error.
    pub fail: Option<PlatformError>,
    /// Report a label other than the planned one.
    pub wrong_label: bool,
    /// The apply target.
    pub sink: MemorySink,
    /// `true` once the apply target was handed out.
    pub sink_opened: bool,
    /// What `windows_root` answers.
    pub windows_root: String,
    /// The root `format` reports for the Windows volume (`None`: the
    /// promised one).
    pub reported_root: Option<Option<String>>,
    /// Roots `format` was asked to use.
    pub format_roots: Vec<String>,
}

/// Forwards to a borrowed `MemorySink`, so the test can inspect it.
struct Fwd<'s>(&'s mut MemorySink);

impl ApplySink for Fwd<'_> {
    fn create_dir(&mut self, p: &ImagePath) -> SinkResult {
        self.0.create_dir(p)
    }
    fn create_file(&mut self, p: &ImagePath) -> SinkResult {
        self.0.create_file(p)
    }
    fn create_stream(&mut self, p: &ImagePath, s: &StreamName) -> SinkResult {
        self.0.create_stream(p, s)
    }
    fn write(
        &mut self,
        p: &ImagePath,
        s: Option<&StreamName>,
        off: u64,
        data: &[u8],
    ) -> SinkResult {
        self.0.write(p, s, off, data)
    }
    fn hard_link(&mut self, a: &ImagePath, b: &ImagePath) -> SinkResult {
        self.0.hard_link(a, b)
    }
    fn set_reparse(&mut self, p: &ImagePath, buf: &ReparseBuffer) -> SinkResult {
        self.0.set_reparse(p, buf)
    }
    fn set_security(&mut self, p: &ImagePath, sd: &[u8]) -> SinkResult {
        self.0.set_security(p, sd)
    }
    fn set_short_name(&mut self, p: &ImagePath, n: &ShortName) -> SinkResult {
        self.0.set_short_name(p, n)
    }
    fn set_times(&mut self, p: &ImagePath, t: &FileTimes) -> SinkResult {
        self.0.set_times(p, t)
    }
    fn set_attributes(&mut self, p: &ImagePath, a: Attributes) -> SinkResult {
        self.0.set_attributes(p, a)
    }
}

impl VolumeOps for TestVolumes {
    fn windows_root(&mut self) -> Result<String, PlatformError> {
        Ok(self.windows_root.clone())
    }

    fn format(
        &mut self,
        device: &mut dyn BlockDevice,
        layout: &WindowsUefiLayout,
        specs: &[VolumeSpec],
        windows_root: &ApplyRoot,
    ) -> Result<Vec<FormattedVolume>, PlatformError> {
        assert_eq!(device.len(), layout.disk_bytes());
        self.formats += 1;
        self.format_roots.push(windows_root.to_text());
        let promised = format!("{}\\", windows_root.to_text());
        if let Some(e) = self.fail {
            return Err(e);
        }
        Ok(specs
            .iter()
            .map(|s| FormattedVolume {
                spec: *s,
                fs: s.fs,
                label: if self.wrong_label {
                    "Other".to_owned()
                } else {
                    s.label.to_owned()
                },
                locator: format!("vol-{}", s.number),
                root: (s.role == usgp_disk::PartRole::Windows)
                    .then(|| {
                        self.reported_root
                            .clone()
                            .unwrap_or_else(|| Some(promised.clone()))
                    })
                    .flatten(),
            })
            .collect())
    }

    fn windows_sink(
        &mut self,
        windows: &FormattedVolume,
    ) -> Result<Box<dyn ApplySink + '_>, PlatformError> {
        assert_eq!(windows.locator, "vol-3");
        self.sink_opened = true;
        Ok(Box::new(Fwd(&mut self.sink)))
    }
}

/// Boot-file double.
pub struct TestBoot {
    /// Calls so far.
    pub calls: u32,
    /// Fail with this error.
    pub fail: Option<PlatformError>,
    /// Time the call takes on this clock.
    pub delay: Option<(Rc<FakeClock>, Duration)>,
}

impl BootFiles for TestBoot {
    fn create(
        &mut self,
        esp: &FormattedVolume,
        windows: &FormattedVolume,
    ) -> Result<(), PlatformError> {
        assert_eq!(esp.locator, "vol-1");
        assert_eq!(windows.locator, "vol-3");
        self.calls += 1;
        if let Some((c, d)) = &self.delay {
            c.advance(*d);
        }
        self.fail.map_or(Ok(()), Err)
    }
}

/// Firmware variables in memory.
#[derive(Default)]
pub struct MemFirmware {
    /// Variables by name.
    pub vars: BTreeMap<String, Vec<u8>>,
    /// Names written, in order.
    pub written: Vec<String>,
    /// Fail every write with this error.
    pub fail_set: Option<FwError>,
    /// Accept writes but keep nothing.
    pub drop_writes: bool,
}

impl FirmwareVars for MemFirmware {
    fn get(&mut self, n: &BootVarName) -> Result<Option<Vec<u8>>, FwError> {
        Ok(self.vars.get(&n.to_string()).cloned())
    }
    fn set(&mut self, n: &BootVarName, data: &[u8]) -> Result<(), FwError> {
        if let Some(e) = self.fail_set {
            return Err(e);
        }
        self.written.push(n.to_string());
        if !self.drop_writes {
            self.vars.insert(n.to_string(), data.to_vec());
        }
        Ok(())
    }
}

/// A platform over one target disk.
pub struct TestPlatform {
    /// The facts reported for the target.
    pub facts: DiskFacts,
    /// The target device.
    pub dev: DevSource,
    /// `open_target` calls.
    pub opens: u32,
    /// Fail `open_target` with this error.
    pub fail_open: Option<PlatformError>,
    /// Formatting and apply target.
    pub vols: TestVolumes,
    /// Boot files.
    pub boot: TestBoot,
    /// Firmware variables (a network option `Boot0000` first).
    pub fw: MemFirmware,
}

impl TestPlatform {
    /// A platform over a fresh in-memory disk, and that disk.
    pub fn mem() -> (Self, SharedDev) {
        let dev = SharedDev::new(DISK_BYTES, 512);
        (Self::with(DevSource::Mem(dev.clone())), dev)
    }

    /// A platform over `dev`.
    pub fn with(dev: DevSource) -> Self {
        let mut fw = MemFirmware::default();
        // A network boot option the firmware already has (opaque bytes to
        // us; it need not parse) and its order.
        fw.vars.insert("Boot0000".to_owned(), vec![1, 2, 3]);
        fw.vars.insert("BootOrder".to_owned(), vec![0, 0]);
        Self {
            facts: facts(),
            dev,
            opens: 0,
            fail_open: None,
            vols: TestVolumes {
                formats: 0,
                fail: None,
                wrong_label: false,
                sink: MemorySink::new(),
                sink_opened: false,
                windows_root: "W:\\".to_owned(),
                reported_root: None,
                format_roots: Vec::new(),
            },
            boot: TestBoot {
                calls: 0,
                fail: None,
                delay: None,
            },
            fw,
        }
    }
}

impl Platform for TestPlatform {
    fn open_target(&mut self, want: &PlanDiskV1) -> Result<OpenedTarget, PlatformError> {
        self.opens += 1;
        if let Some(e) = self.fail_open {
            return Err(e);
        }
        assert_eq!(want.disk_token, DiskToken::from_random_bytes([0x5a; 16]));
        let device: Box<dyn BlockDevice> = match &self.dev {
            DevSource::Mem(d) => Box::new(d.clone()),
            DevSource::File(p, s) => Box::new(FileBlockDevice::open(p, *s, true).unwrap()),
        };
        Ok(OpenedTarget {
            facts: self.facts.clone(),
            device,
        })
    }
    fn volumes(&mut self) -> &mut dyn VolumeOps {
        &mut self.vols
    }
    fn boot_files(&mut self) -> &mut dyn BootFiles {
        &mut self.boot
    }
    fn firmware(&mut self) -> &mut dyn FirmwareVars {
        &mut self.fw
    }
}

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

/// The result of a run and what the screen showed.
pub struct Outcome {
    /// The engine's result.
    pub result: Result<Succeeded, JobFailure>,
    /// The screen.
    pub view: RecordingView,
}

/// Verifies and runs `fx`'s plan with the given envelopes.
pub fn run_envs(
    fx: &Fixture,
    plan: &SignedEnvelopeV1,
    content: &SignedEnvelopeV1,
    platform: &mut dyn Platform,
    link: &mut FakeLink,
    config: EngineConfig,
) -> Outcome {
    let clock = Rc::clone(&link.clock);
    let engine = Engine::new(crypto(), &*clock, config);
    let mut view = RecordingView::default();
    let job = SignedJob {
        plan,
        content,
        keys: &fx.keys,
        expect: fx.expect(),
    };
    let result = engine.verify_and_run(&job, platform, link, &mut view);
    Outcome { result, view }
}

/// Verifies and runs `fx` as signed.
pub fn run(fx: &Fixture, platform: &mut dyn Platform, link: &mut FakeLink) -> Outcome {
    run_envs(
        fx,
        &fx.plan_env(),
        &fx.content_env(),
        platform,
        link,
        EngineConfig::default(),
    )
}

/// A link over `fx`'s image with a fresh clock.
pub fn link_for(fx: &Fixture) -> FakeLink {
    FakeLink::new(fx.wim.clone(), Rc::new(FakeClock::default()))
}

/// The failure, after checking it is the last thing shown and was
/// reported as `failed` with the same fields.
pub fn failure(o: &Outcome, link: &FakeLink) -> JobFailure {
    let f = o.result.clone().expect_err("job should fail");
    assert_eq!(o.view.0.last(), Some(&Shown::Failed(f.clone())));
    assert!(!o.view.0.contains(&Shown::Succeeded));
    let last = link.reports.last().expect("failure reported");
    assert_eq!(last.event, ProgressEvent::Failed);
    assert_eq!(last.failure.as_ref(), Some(&f.to_wire()));
    f
}

/// An image path from its `\\`-separated text.
pub fn path(s: &str) -> ImagePath {
    ImagePath::parse(s).unwrap()
}

/// The ESP of a layout planned for [`facts`] with GUIDs from `seed`
/// (xorshift; not a DRBG).
pub fn test_esp(seed: u64) -> usgp_disk::Part {
    let mut x = seed.max(1);
    let mut rng = |b: &mut [u8]| {
        for v in b.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *v = x.to_be_bytes()[0];
        }
    };
    WindowsUefiLayout::compute(&facts(), 0, &mut rng)
        .unwrap()
        .esp
}

/// `BootOrder` as stored in `fw`.
pub fn boot_order_of(fw: &MemFirmware) -> Vec<u16> {
    usgp_disk::uefi::parse_boot_order(
        &fw.vars["BootOrder"],
        &usgp_disk::uefi::UefiLimits::default(),
    )
    .unwrap()
}
