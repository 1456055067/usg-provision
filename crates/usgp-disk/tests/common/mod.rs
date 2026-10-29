//! Shared helpers for the usgp-disk integration tests. Everything runs on
//! in-memory devices or regular files under `CARGO_TARGET_TMPDIR`; no test
//! opens a block device.
//!
//! Declared `pub mod common` by each test crate, so helpers one binary
//! does not use are not dead code.

use usgp_common::Sha256Digest;
use usgp_disk::{Bus, DiskFacts, DiskIdentity, LayoutError, WindowsUefiLayout, WipeAuthorisation};
use usgp_proto::content_manifest::{ContentManifestV1, ManifestEdition, WimSummaryV1, chunk_count};
use usgp_proto::device::{AgentNonce, MacAddress, MacList};
use usgp_proto::disk::{DiskDescriptorParts, DiskDescriptorV1, DiskToken, PlanDiskV1};
use usgp_proto::envelope::{
    PayloadType, SignatureAlg, SignatureV1, SignatureVerifier, SignedEnvelopeV1, signing_input,
};
use usgp_proto::job_plan::{
    JobPlanV1, LayoutPolicyV1, PlanDeviceV1, PlanError, PlanExpectation, PlanImageV1,
    PlanPackageV1, PlanStepV1, PlanWipeV1, RetryPolicyV1, VerifiedJobPlan, WipeScope,
};
use usgp_proto::limits::CHUNK_SIZE;
use usgp_proto::progress::Step;
use usgp_proto::{
    BootServiceId, ContentId, ContentKind, DiskText, DisplayName, EditionIndex, JobId, PackageId,
    SessionId, UnixMicros, WimCompression, WimText,
};

/// 10⁹ bytes.
pub const GB: u64 = 1_000_000_000;
/// 2²⁰ bytes.
pub const MIB: u64 = 1 << 20;
/// 2³⁰ bytes.
pub const GIB: u64 = 1 << 30;

/// Deterministic test byte source (xorshift64*). Not a DRBG: production
/// passes the FIPS DRBG from usgp-crypto.
pub struct TestRng(u64);

impl TestRng {
    /// A source seeded with `seed` (zero is replaced by one).
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    /// Next 64 bits.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Fills `buf`.
    pub fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            *b = self.next_u64().to_be_bytes()[0];
        }
    }
}

/// An eligible internal NVMe disk description.
pub fn facts(size_bytes: u64, logical: u32, physical: u32) -> DiskFacts {
    DiskFacts {
        identity: DiskIdentity {
            device_number: 1,
            model: "Test NVMe".to_owned(),
            serial: Some("SN-0001".to_owned()),
        },
        bus: Bus::Nvme,
        removable: false,
        read_only: false,
        logical_sector: logical,
        physical_sector: physical,
        size_bytes,
        hosts_boot_environment: false,
        partitions: Vec::new(),
    }
}

/// Rounds `n` down to a multiple of `sector`.
pub fn round_down(n: u64, sector: u32) -> u64 {
    n - n % u64::from(sector)
}

/// The layout for a disk, with a 600 MiB recovery image.
pub fn layout(
    size_bytes: u64,
    logical: u32,
    physical: u32,
    seed: u64,
) -> Result<WindowsUefiLayout, LayoutError> {
    let mut rng = TestRng::new(seed);
    WindowsUefiLayout::compute(&facts(size_bytes, logical, physical), 600 * MIB, &mut |b| {
        rng.fill(b)
    })
}

/// An authorisation for the disk from [`facts`], built the only way there
/// is: from a verified plan (NIST-007).
pub fn auth_for(size_bytes: u64, logical: u32) -> Fallible<WipeAuthorisation> {
    let plan = verified_plan(size_bytes, logical, 42, [0xAB; 32])?;
    Ok(WipeAuthorisation::from_verified_plan(
        &plan,
        facts(size_bytes, logical, logical).identity,
    ))
}

/// Result of a fixture helper (helpers outside `#[test]` do not unwrap).
pub type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

// ---------------------------------------------------------------------------
// A verified job plan. No cryptography: the verifier and the digest are
// test doubles (keyed checksums), as in usgp-proto's own tests. Real ECDSA
// and SHA-256 are exercised by usgp-crypto and usgp-deploy's engine tests.
// ---------------------------------------------------------------------------

const PLAN_KEY: u8 = 11;
const CONTENT_KEY: u8 = 12;
const SESSION: &str = "5a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
/// The job id every test plan carries.
pub const JOB: &str = "6b2c3d4e-5f60-4b7c-9d8e-0f1a2b3c4d5e";
const BOOT_SERVICE: &str = "7c3d4e5f-6071-4c8d-ae9f-1a2b3c4d5e6f";
const PACKAGE: &str = "1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516";
const CONTENT: &str = "0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f";

/// FNV-1a spread to 32 bytes; not a cryptographic hash.
fn fake_sha(data: &[u8]) -> Sha256Digest {
    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ (i as u64);
        for b in data {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        chunk.copy_from_slice(&h.to_be_bytes());
    }
    Sha256Digest(out)
}

fn key(n: u8) -> Sha256Digest {
    Sha256Digest([n; 32])
}

fn fake_sign(k: u8, message: &[u8]) -> Vec<u8> {
    let mut v = vec![k];
    v.extend_from_slice(&fake_sha(message).0);
    v
}

struct Keys(Sha256Digest);

impl SignatureVerifier for Keys {
    fn verify(&self, key_id: &Sha256Digest, _: SignatureAlg, msg: &[u8], sig: &[u8]) -> bool {
        *key_id == self.0 && sig == fake_sign(key_id.0[0], msg)
    }
}

fn seal(ty: PayloadType, payload: Vec<u8>, k: u8) -> Fallible<SignedEnvelopeV1> {
    let sig = fake_sign(k, &signing_input(ty, &payload));
    let s = SignatureV1::new(key(k), SignatureAlg::EcdsaP384Sha384, sig)?;
    Ok(SignedEnvelopeV1::new(ty, payload, vec![s])?)
}

fn content_manifest() -> Fallible<ContentManifestV1> {
    let size = 3 * CHUNK_SIZE + 17;
    let n = usize::try_from(chunk_count(size))?;
    Ok(ContentManifestV1 {
        schema: 1,
        kind: ContentKind::Image,
        content_id: ContentId::parse(CONTENT)?,
        display_name: DisplayName::new("Test image")?,
        file_name: usgp_proto::FileName::new("install.wim")?,
        size,
        sha256: Sha256Digest([0xaa; 32]),
        chunk_size: CHUNK_SIZE,
        chunk_sha256: (0..n).map(|i| Sha256Digest([i as u8; 32])).collect(),
        wim: WimSummaryV1 {
            compression: WimCompression::Xpress,
            image_count: 1,
            boot_index: 0,
            editions: vec![ManifestEdition {
                index: EditionIndex::new(1)?,
                name: WimText::new("Edition 1")?,
                description: WimText::new("d")?,
                total_bytes: Some(20_000_000_000),
            }],
        },
        ready_at: UnixMicros::new(1_793_000_000_000_000)?,
        key_id: key(CONTENT_KEY),
    })
}

fn disk_descriptor(size_bytes: u64, logical: u32) -> Fallible<DiskDescriptorV1> {
    Ok(DiskDescriptorV1::new(DiskDescriptorParts {
        disk_token: DiskToken::from_random_bytes([0x5a; 16]),
        bus: usgp_proto::disk::Bus::Nvme,
        model: DiskText::sanitized("Test NVMe"),
        serial: DiskText::sanitized("SN-0001"),
        size_bytes,
        logical_sector: logical,
        physical_sector: logical,
        removable: false,
        partitions: Vec::new(),
    })?)
}

/// A plan for the disk from [`facts`], naming the durable wipe record
/// `audit_seq` / `record_hash`, put through `VerifiedJobPlan::verify`.
pub fn verified_plan(
    size_bytes: u64,
    logical: u32,
    audit_seq: u64,
    record_hash: [u8; 32],
) -> Fallible<VerifiedJobPlan> {
    let disk = disk_descriptor(size_bytes, logical)?;
    let cm = content_manifest()?;
    let cm_payload = cm.to_payload()?;
    let nonce = AgentNonce::from_random_bytes([0x42; 32]);
    let plan = JobPlanV1 {
        schema: 1,
        job_id: JobId::parse(JOB)?,
        session_id: SessionId::parse(SESSION)?,
        boot_service_id: BootServiceId::parse(BOOT_SERVICE)?,
        issued_at_us: UnixMicros::new(1_793_000_000_000_123)?,
        key_id: key(PLAN_KEY),
        agent_nonce: nonce,
        device: PlanDeviceV1 {
            macs: MacList::new(vec![MacAddress::new([0x02, 0, 0, 0, 0, 1])?])?,
        },
        package: PlanPackageV1 {
            id: PackageId::parse(PACKAGE)?,
            revision: 3,
            manifest_sha256: Sha256Digest([0xcc; 32]),
        },
        image: PlanImageV1 {
            content_sha256: cm.sha256,
            size: cm.size,
            content_manifest_sha256: fake_sha(&cm_payload),
            edition_index: EditionIndex::new(1)?,
            edition_name: WimText::new("Edition 1")?,
            total_bytes: 20_000_000_000,
        },
        disk: PlanDiskV1::from(&disk),
        layout_policy: LayoutPolicyV1::STANDARD,
        wipe: PlanWipeV1 {
            audit_seq,
            record_hash: Sha256Digest(record_hash),
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
    // A plan that fails its own validation cannot be sealed either.
    let payload = plan.to_payload().map_err(PlanError::Plan)?;
    let plan_env = seal(PayloadType::JobPlanV1, payload, PLAN_KEY)?;
    let content_env = seal(PayloadType::ContentManifestV1, cm_payload, CONTENT_KEY)?;
    Ok(VerifiedJobPlan::verify(
        &plan_env,
        &Keys(key(PLAN_KEY)),
        &content_env,
        &Keys(key(CONTENT_KEY)),
        &fake_sha,
        &PlanExpectation {
            agent_nonce: &nonce,
            session_id: SessionId::parse(SESSION)?,
            job_id: JobId::parse(JOB)?,
            package_id: PackageId::parse(PACKAGE)?,
            package_revision: 3,
            disk: &disk,
        },
    )?)
}
