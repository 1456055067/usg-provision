//! Shared helpers for the usgp-disk integration tests. Everything runs on
//! in-memory devices or regular files under `CARGO_TARGET_TMPDIR`; no test
//! opens a block device.
//!
//! Declared `pub mod common` by each test crate, so helpers one binary
//! does not use are not dead code.

use usgp_disk::{
    Bus, DiskFacts, DiskIdentity, LayoutError, WindowsUefiLayout, WipeAuthorisation, WipeEvidence,
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

/// An authorisation for the disk from [`facts`].
pub fn auth_for(size_bytes: u64, logical: u32) -> WipeAuthorisation {
    WipeAuthorisation::new(WipeEvidence {
        job_id: "job-1".to_owned(),
        audit_seq: 42,
        audit_record_hash: [0xAB; 32],
        disk: facts(size_bytes, logical, logical).identity,
        size_bytes,
        logical_sector: logical,
    })
}
