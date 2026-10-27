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
//!
//! This crate does no cryptography and no I/O. See docs/ARCHITECTURE.md.

// Parses untrusted input: indexing and slicing that can panic are denied
// (CLAUDE.md, Engineering Rules: parsers never panic on input).
#![deny(clippy::indexing_slicing)]

#[macro_use]
mod macros;

pub mod api;
pub mod boot_file_name;
pub mod boot_manifest;
pub mod content_manifest;
pub mod envelope;
pub mod error_code;
pub mod facts;
pub mod ids;
pub mod limits;
pub mod names;
pub mod package_manifest;
pub mod status;

pub use boot_file_name::{BootFileName, BootFileNameError};
pub use boot_manifest::{BootManifest, DigestName, ManifestEntry, ManifestError};
pub use content_manifest::{ContentManifestV1, ManifestEdition, WimSummaryV1};
pub use envelope::{
    EnvelopeError, PayloadType, SignatureAlg, SignatureV1, SignatureVerifier, SignedEnvelopeV1,
    VerifiedPayload, signing_input,
};
pub use error_code::{ErrorCode, ErrorCodeError, codes};
pub use facts::{
    Architecture, Edition, EditionFacts, Fact, FactSource, KitVersion, KitVersionError, Release,
    SupportState,
};
pub use ids::{ContentId, IdError, OperatorId, PackageId, UnixMicros, UploadId};
pub use names::{
    Description, DisplayName, EditionIndex, EditionIndexError, FileName, NameError, WimText,
};
pub use package_manifest::{PackageImageV1, PackageManifestV1, PackagePeV1};
pub use status::{ContentKind, ContentState, PackageStatus, UploadState, WimCompression};

/// Errors from building, parsing or opening a signed manifest (content or
/// package).
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
