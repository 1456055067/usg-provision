//! usgp-deploy: the OS-neutral engine that drives one provisioning job on
//! the device, from the signed plan to the success report (M3 plan WU-8,
//! sections 1.1 and 3.2 to 3.4).
//!
//! The engine runs, in this order, and stops at the first failure:
//!
//! 0. [`plan::verify_plan`]: the job plan and content manifest signatures
//!    and bindings (plan section 3.2). Nothing else happens before this
//!    succeeds.
//! 1. Step 1, `verify_content`: the Windows volume's apply root (a bare
//!    drive letter the platform promises, [`platform::VolumeOps::windows_root`])
//!    is fixed; then every chunk the chosen edition needs is fetched,
//!    verified and discarded ([`usgp_image::apply::verify_pass`] with that
//!    root; decision 0021 item 4, decision 0022).
//! 2. Step 2, `partition_format`: the opened disk is checked against the
//!    plan, the wipe authorisation is built from the verified plan, the
//!    GPT is written and read back ([`usgp_disk::wipe_and_write`]), and the
//!    volumes are formatted through [`platform::VolumeOps`].
//! 3. Step 3, `apply_image`: the edition is applied through
//!    [`usgp_image::apply::ApplySink`], every chunk fetched and verified
//!    again.
//! 4. Step 4, `make_bootable`: the boot files are created
//!    ([`platform::BootFiles`]), then the Windows boot option is written and
//!    put first in `BootOrder` ([`bootentry`], [`platform::FirmwareVars`]).
//! 5. Step 5, `report_restart`: success is reported and acknowledged. The
//!    caller restarts the device.
//!
//! A tampered plan or chunk fails before any disk write. Every failure is a
//! persistent, named [`JobFailure`] (REQ-JOB-005). There is no cancel
//! operation: the engine starts after the wipe confirmation (REQ-TGT-011).
//!
//! Platform work (raw disk, formatting, boot files, firmware variables) is
//! behind the traits in [`platform`]; the pre-boot agent implements them on
//! `usgp-winapi`, and tests use in-memory doubles and loopback files.
//!
//! Filled in: M3 (docs/ROADMAP.md section 3; plan WU-8).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7, SI-7(1), SI-7(6) (Software, Firmware, and
//   Information Integrity) - signed plan and content manifest verified
//   first; every chunk verified before use, twice (before the wipe and
//   during apply).
// - NIST 800-53: AC-3 (Access Enforcement) - the wipe authorisation is
//   built only from a verified plan that names the durable audit record.
// - NIST 800-53: SI-11 (Error Handling) - persistent named failures, no
//   secrets in messages.
// - NIST 800-53: CM-7 (Least Functionality) - only `BootOrder` and
//   `Boot####` can be written; no Secure Boot variable can be named.
// - SPEC: specs/progress.md#REQ-JOB-002..008, #REQ-JOB-011..014
// - SPEC: specs/preinstall-env.md#REQ-PE-016, #REQ-PE-017, #REQ-PE-019
// - SPEC: specs/disk.md#REQ-DISK-006, #REQ-DISK-007, #REQ-DISK-012..015
// - SPEC: specs/boot-network.md#REQ-BOOT-065, #REQ-BOOT-066
// - SPEC: specs/targeting.md#REQ-TGT-011, #REQ-TGT-015
// - DECISION: docs/decisions/0011, 0018 items 7 to 10, 0021 item 4

// Parses firmware variables and checks network input: indexing and slicing
// that can panic are denied (CLAUDE.md, Engineering Rules).
#![deny(clippy::indexing_slicing)]

pub mod bootentry;
pub mod clock;
pub mod content;
pub mod engine;
pub mod error;
pub mod link;
pub mod plan;
pub mod platform;
mod report;
#[cfg(feature = "sim")]
pub mod sim;

pub use bootentry::{BootEntry, BootEntryError, make_windows_first};
pub use clock::{Clock, SystemClock};
pub use content::{ChunkError, ChunkErrorKind, VerifiedChunks};
pub use engine::{Engine, EngineConfig, JobView, SignedJob, Succeeded, ViewEvent};
pub use error::JobFailure;
pub use link::{LinkError, ServerLink};
pub use plan::{PinnedKey, PlanKeys, verify_plan};
pub use platform::{
    BootFiles, FirmwareVars, FormattedVolume, FwError, OpenedTarget, Platform, PlatformError,
    PlatformErrorKind, VolumeOps, VolumeSpec,
};
