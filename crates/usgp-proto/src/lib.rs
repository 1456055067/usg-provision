//! usgp-proto: wire types shared by server, relay, agent, and cli.
//!
//! - M1: the boot manifest ([`BootManifest`]) and the published boot file
//!   name type ([`BootFileName`]).
//! - M2 (plan WU-4): the operator API request, response and error types
//!   ([`api`]), validated names ([`names`]), identifiers ([`ids`]), the
//!   declared/verified fact model ([`facts`]), lifecycle states
//!   ([`status`]), reason codes ([`error_code`]), the signed envelope
//!   ([`envelope`]), and the content and package manifests
//!   ([`content_manifest`], [`package_manifest`]).
//! - M3 (plan WU-2): the device session protocol ([`device`]), disk
//!   descriptors and layout reports ([`disk`]), the signed job plan
//!   ([`job_plan`]), job states and progress reports ([`progress`]), the
//!   signed boot-policy list ([`boot_policy`]), and the operator API
//!   additions ([`ops`]), the boot manifest's `[pe_kit]` section
//!   ([`pe_kit`]), the pre-boot agent's public configuration
//!   ([`agent_config`]), and a PE/COFF header check for boot programs
//!   ([`pe_coff`]).
//! - M4 (plan WU-4): the v2 job plan with nine steps, answer file,
//!   drivers, agent package, tags and escrow key ([`job_plan::JobPlanV2`]),
//!   progress schema 2 ([`progress::ProgressV2`]), the confirm with the
//!   job key ([`device::ConfirmV2`]), the escrow bodies ([`escrow`]), the
//!   resume challenge ([`resume`]), the post-setup `job.json`
//!   ([`postsetup`]), the agent package manifest ([`agent_package`]), and
//!   bounded base64 and P-384 key forms ([`b64`]).
//!
//! This crate does no cryptography and no I/O. See docs/ARCHITECTURE.md.

// Parses untrusted input: indexing and slicing that can panic are denied
// (CLAUDE.md, Engineering Rules: parsers never panic on input).
#![deny(clippy::indexing_slicing)]

#[macro_use]
mod macros;

pub mod agent_config;
pub mod agent_package;
pub mod api;
pub mod b64;
pub mod boot_file_name;
pub mod boot_manifest;
pub mod boot_policy;
pub mod content_manifest;
pub mod device;
pub mod disk;
pub mod envelope;
pub mod error_code;
pub mod escrow;
pub mod facts;
pub mod ids;
pub mod job_plan;
pub mod limits;
pub mod names;
pub mod ops;
pub mod package_manifest;
pub mod pe_coff;
pub mod pe_kit;
pub mod postsetup;
pub mod progress;
pub mod resume;
pub mod status;

pub use agent_package::AgentPackageManifestV1;
pub use b64::{B64Bytes, B64Error, P384Spki};
pub use boot_file_name::{BootFileName, BootFileNameError};
pub use boot_manifest::{BootManifest, DigestName, ManifestEntry, ManifestError};
pub use boot_policy::{BootPolicyError, BootPolicyV1, BootStopEntryV1};
pub use content_manifest::{ContentManifestV1, ManifestEdition, WimSummaryV1};
pub use device::{
    AgentNonce, AuthCode, ConfirmV2, ConfirmedV2, DisplayCode, MacAddress, MacList, SessionToken,
};
pub use disk::{DiskDescriptorV1, DiskGuid, DiskToken, LayoutReportV1, PlanDiskV1};
pub use envelope::{
    EnvelopeError, PayloadType, SignatureAlg, SignatureV1, SignatureVerifier, SignedEnvelopeV1,
    VerifiedPayload, signing_input,
};
pub use error_code::{ErrorCode, ErrorCodeError, codes};
pub use escrow::{EscrowConfirmV1, EscrowSubmitV1};
pub use facts::{
    Architecture, Edition, EditionFacts, Fact, FactSource, KitVersion, KitVersionError, Release,
    SupportState,
};
pub use ids::{
    AgentPackageId, AuthCodeId, BootServiceId, BootStopId, ContentId, DriverArchiveId, IdError,
    JobId, OperatorId, PackageId, SessionId, UnixMicros, UploadId,
};
pub use job_plan::{
    EscrowAccount, JobPlanV1, JobPlanV2, PlanContentV2, PlanError, PlanExpectation,
    PlanExpectationV2, VerifiedJobPlan, VerifiedJobPlanV2,
};
pub use names::{
    AgentVersion, Description, DiskText, DisplayName, EditionIndex, EditionIndexError, FileName,
    InstallerArg, ItemName, NameError, Note, PartitionLabel, RelPath, ServiceName, Tag, UrlPath,
    WimText,
};
pub use package_manifest::{PackageImageV1, PackageManifestV1, PackagePeV1};
pub use pe_kit::{KitProblem, KitRole, PeKitError, PeKitV1};
pub use postsetup::PostSetupConfigV1;
pub use progress::{
    FailureCategory, FailureV1, FailureV2, JobState, ProgressAckV1, ProgressEvent, ProgressV1,
    ProgressV2, Step, StepKind, StepKindV2, StepState, StepV2,
};
pub use resume::{ResumeChallengeV1, ResumeRequestV1, ResumedV1};
pub use status::{ContentKind, ContentState, PackageStatus, UploadState, WimCompression};

/// Errors from building, parsing or opening a signed payload (content or
/// package manifest, job plan, boot-policy list).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignedManifestError {
    /// The payload is over [`limits::MAX_MANIFEST_PAYLOAD_BYTES`].
    #[error(
        "manifest payload is {len} bytes; the limit is {}",
        limits::MAX_MANIFEST_PAYLOAD_BYTES
    )]
    TooLarge {
        /// Length in bytes.
        len: usize,
    },
    /// The payload is not JSON of the manifest shape.
    #[error("manifest is not valid JSON of the expected shape")]
    Json(#[source] serde_json::Error),
    /// `schema` is not 1.
    #[error("manifest schema {0} is not supported (expected 1)")]
    UnsupportedSchema(u32),
    /// A manifest rule is broken; the text names it.
    #[error("manifest is invalid: {0}")]
    Invalid(&'static str),
    /// The envelope failed to parse or verify.
    #[error(transparent)]
    Envelope(#[from] EnvelopeError),
    /// The manifest's `key_id` is not the key whose signature verified.
    #[error("manifest key_id does not match the verifying key")]
    KeyIdMismatch,
}
