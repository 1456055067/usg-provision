//! The only code path in this crate that writes to a disk.
//!
//! [`wipe_and_write`] needs a [`WipeAuthorisation`]. Its only constructor,
//! [`WipeAuthorisation::from_verified_plan`], takes a [`VerifiedJobPlan`]
//! (which only `VerifiedJobPlan::verify` builds, after the signature,
//! nonce, session, job and disk checks) and copies the audit sequence
//! number and record hash of the durably committed `disk.wipe.authorised`
//! record that the signed plan carries (plan §1.1 step 7-8; REQ-DISK-006,
//! DEC-0018 item 7; NIST-007). The fields are private, so the guard is
//! enforced by the type system, not by convention.
//!
//! Before writing anything, the executor checks that the opened device's
//! size and logical sector size match both the authorisation and the
//! layout. The platform backend checks the rest of the disk identity
//! (serial, device number) when it opens the device (plan §6, wipe guard).
//! Then it zeroes the [`WipePlan`] ranges, writes the GPT backup-first,
//! flushes, reads the table back and compares it with the plan
//! (REQ-DISK-009). A failure at any point stops the step (REQ-DISK-013).

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 (Access Enforcement) - write needs an authorisation
//   that can be built only from a verified, signed plan naming a durable
//   audit record
// - NIST 800-53: AU-10 (Non-repudiation, basis) - the authorisation names
//   the audit record of the confirmation; the person who confirms at the
//   device is not individually identified (NIST-005)
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   read-back check before formatting
// - SPEC: specs/disk.md#REQ-DISK-006, #REQ-DISK-007, #REQ-DISK-009,
//   #REQ-DISK-013, #REQ-DISK-015
// - specs/standards/gpt.md §7 (backup first)

use usgp_proto::job_plan::VerifiedJobPlan;

use crate::device::BlockDevice;
use crate::eligibility::DiskIdentity;
use crate::error::DiskError;
use crate::gpt::{GptLimits, GptView, parse_gpt};
use crate::layout::WindowsUefiLayout;
use crate::mbr;
use crate::wipe::WipePlan;

/// Design value: largest single zeroing write (1 MiB).
const ZERO_CHUNK_BYTES: usize = 1 << 20;

/// What a [`WipeAuthorisation`] holds: the durable wipe record named by the
/// verified plan, and the disk. Building one grants nothing; only a
/// [`WipeAuthorisation`] lets [`wipe_and_write`] write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WipeEvidence {
    /// The job the wipe belongs to.
    pub job_id: String,
    /// Audit sequence number of `disk.wipe.authorised`.
    pub audit_seq: u64,
    /// Record hash of `disk.wipe.authorised` (SHA-256).
    pub audit_record_hash: [u8; 32],
    /// The disk the person confirmed.
    pub disk: DiskIdentity,
    /// Its size in bytes, as confirmed.
    pub size_bytes: u64,
    /// Its logical sector size, as confirmed.
    pub logical_sector: u32,
}

/// Proof that the wipe of one disk was confirmed and durably recorded.
///
/// Sealed: the field is private and the only constructor is
/// [`WipeAuthorisation::from_verified_plan`] (NIST-007). Neither of these
/// compiles outside this crate:
///
/// ```compile_fail
/// # use usgp_disk::{WipeAuthorisation, WipeEvidence, DiskIdentity};
/// let e = WipeEvidence {
///     job_id: "j".into(), audit_seq: 1, audit_record_hash: [1; 32],
///     disk: DiskIdentity { device_number: 0, model: String::new(), serial: None },
///     size_bytes: 64_000_000_000, logical_sector: 512,
/// };
/// let _ = WipeAuthorisation::new(e);
/// ```
///
/// ```compile_fail
/// # use usgp_disk::{WipeAuthorisation, WipeEvidence, DiskIdentity};
/// # let e: WipeEvidence = todo!();
/// let _ = WipeAuthorisation { evidence: e };
/// ```
#[derive(Debug)]
pub struct WipeAuthorisation {
    evidence: WipeEvidence,
}

impl WipeAuthorisation {
    /// The authorisation the verified plan carries, for the disk the
    /// caller opened and checked against the plan (`opened`).
    ///
    /// The job, the durable record (sequence number and hash), and the
    /// confirmed size and sector size all come from the plan; nothing the
    /// caller passes can change them. [`wipe_and_write`] then checks the
    /// opened device's geometry against them before any write.
    #[must_use]
    pub fn from_verified_plan(plan: &VerifiedJobPlan, opened: DiskIdentity) -> Self {
        let p = plan.plan();
        Self {
            evidence: WipeEvidence {
                job_id: p.job_id.to_string(),
                audit_seq: p.wipe.audit_seq,
                audit_record_hash: p.wipe.record_hash.0,
                disk: opened,
                size_bytes: p.disk.size_bytes,
                logical_sector: p.disk.logical_sector,
            },
        }
    }

    /// The evidence.
    #[must_use]
    pub fn evidence(&self) -> &WipeEvidence {
        &self.evidence
    }
}

fn mismatch(r: &'static str) -> DiskError {
    DiskError::IdentityMismatch(r)
}

/// Checks everything that can be checked before the first write.
fn preflight(
    dev: &dyn BlockDevice,
    auth: &WipeAuthorisation,
    wipe: &WipePlan,
    layout: &WindowsUefiLayout,
) -> Result<(), DiskError> {
    let e = &auth.evidence;
    if e.audit_seq == 0 || e.audit_record_hash == [0u8; 32] || e.job_id.is_empty() {
        return Err(DiskError::NotAuthorised("no durable wipe record"));
    }
    if dev.len() != e.size_bytes {
        return Err(mismatch("device size differs from the confirmed disk"));
    }
    if dev.logical_sector() != e.logical_sector {
        return Err(mismatch("sector size differs from the confirmed disk"));
    }
    if layout.disk_bytes() != dev.len() || layout.block != dev.logical_sector() {
        return Err(mismatch("layout was planned for another geometry"));
    }
    if wipe.disk_bytes() != dev.len() || wipe.block() != layout.block {
        return Err(DiskError::BadPlan("wipe plan was built for another disk"));
    }
    if wipe.ranges().iter().any(|r| r.end > dev.len()) {
        return Err(DiskError::BadPlan("wipe range past the end of the disk"));
    }
    Ok(())
}

/// Wipes the disk and writes `layout`'s GPT, then reads it back and checks
/// it against the plan.
///
/// Nothing is written if the authorisation, device geometry or plans do
/// not match. After the first write, a failure leaves the disk partly
/// written and the job must stop (REQ-DISK-013).
///
/// # Errors
/// [`DiskError`]: `NotAuthorised`, `IdentityMismatch` or `BadPlan` before
/// any write; `Write`, `ReadBack` or `ReadBackMismatch` after.
pub fn wipe_and_write(
    dev: &mut dyn BlockDevice,
    auth: &WipeAuthorisation,
    wipe: &WipePlan,
    layout: &WindowsUefiLayout,
) -> Result<GptView, DiskError> {
    preflight(dev, auth, wipe, layout)?;
    let plan = layout
        .gpt_plan()
        .map_err(|_| DiskError::BadPlan("layout breaks a GPT rule"))?;
    let writes = plan
        .writes()
        .map_err(|_| DiskError::BadPlan("cannot encode table"))?;

    // 1. Zero the wipe ranges.
    let zeros = vec![0u8; ZERO_CHUNK_BYTES];
    for r in wipe.ranges() {
        let mut off = r.start;
        while off < r.end {
            let n = usize::try_from(r.end - off)
                .unwrap_or(ZERO_CHUNK_BYTES)
                .min(ZERO_CHUNK_BYTES);
            let buf = zeros
                .get(..n)
                .ok_or(DiskError::BadPlan("zero chunk size"))?;
            dev.write_at(off, buf).map_err(DiskError::Write)?;
            off = off.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        }
    }

    // 2. Backup array, backup header, primary array, primary header, LBA 0.
    for (off, block) in &writes {
        dev.write_at(*off, block).map_err(DiskError::Write)?;
    }
    dev.flush().map_err(DiskError::Write)?;

    // 3. Read back and compare before anything is formatted.
    let view = parse_gpt(dev, &GptLimits::default()).map_err(DiskError::ReadBack)?;
    if !plan.matches(&view) {
        return Err(DiskError::ReadBackMismatch("table differs from plan"));
    }
    let blen = usize::try_from(layout.block).map_err(|_| DiskError::BadPlan("block size"))?;
    let mut lba0 = vec![0u8; blen];
    dev.read_at(0, &mut lba0)
        .map_err(|e| DiskError::ReadBack(e.into()))?;
    if !mbr::is_our_protective(&lba0, layout.total_lbas) {
        return Err(DiskError::ReadBackMismatch("protective MBR differs"));
    }
    Ok(view)
}
