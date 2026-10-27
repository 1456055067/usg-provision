//! Row types of the M2 schema (plan section 3.4).
//!
//! Values use the `usgp-proto` types, so a row read back from the database
//! is re-validated: a value that no longer parses (a tampered or foreign
//! row) is [`crate::DbError::Corrupt`], never a panic.

use usgp_common::Sha256Digest;
use usgp_crypto::KeyId;
use usgp_proto::{
    Architecture, ContentId, ContentKind, ContentState, Description, DisplayName, EditionFacts,
    Fact, FileName, KitVersion, OperatorId, PackageId, PackageStatus, SupportState, UnixMicros,
    UploadId, UploadState, WimCompression, WimText,
};

/// Role of an operator (M2 has one built-in role, REQ-RBAC-004).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperatorRole {
    /// Holds every permission.
    Administrator,
}

impl OperatorRole {
    /// Every value (database check constraint).
    pub const ALL: &'static [Self] = &[Self::Administrator];

    /// Stored text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Administrator => "administrator",
        }
    }

    /// Parses the stored text.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "administrator" => Some(Self::Administrator),
            _ => None,
        }
    }
}

/// Whether an operator may authenticate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperatorStatus {
    /// May authenticate.
    Active,
    /// Refused with 401 (plan section 6).
    Disabled,
}

impl OperatorStatus {
    /// Every value (database check constraint).
    pub const ALL: &'static [Self] = &[Self::Active, Self::Disabled];

    /// Stored text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }

    /// Parses the stored text.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

/// An enrolled operator, bound to one certificate by its SHA-256
/// (decision 0007).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operator {
    /// Identifier.
    pub id: OperatorId,
    /// Display name.
    pub display_name: DisplayName,
    /// SHA-256 of the end-entity certificate DER.
    pub cert_sha256: Sha256Digest,
    /// Certificate subject (display only).
    pub cert_subject: String,
    /// Certificate issuer (display only).
    pub cert_issuer: String,
    /// Certificate serial, lower-case hex.
    pub cert_serial: String,
    /// Certificate notAfter.
    pub cert_not_after: UnixMicros,
    /// Role, or none (every route then answers 403, REQ-RBAC-003).
    pub role: Option<OperatorRole>,
    /// Status.
    pub status: OperatorStatus,
    /// Enrolment time.
    pub created_at: UnixMicros,
    /// Who enrolled it (the local user of the server command).
    pub created_by: String,
}

/// A failure reason: a code from the operator-facing set and its text
/// (REQ-IMG-022).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    /// Reason code (for example `digest_mismatch`).
    pub code: String,
    /// Operator text.
    pub text: String,
}

/// A PE's declared architecture and kit version (decision 0013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeDeclaration {
    /// Architecture with its source.
    pub architecture: Fact<Architecture>,
    /// Kit version with its source.
    pub kit_version: Fact<KitVersion>,
}

/// WIM-level facts recorded when the check passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WimFacts {
    /// Compression of the resources.
    pub compression: WimCompression,
    /// Number of images.
    pub image_count: u32,
    /// Boot index (0 = none).
    pub boot_index: u32,
}

/// A signed manifest as stored: the exact payload bytes, the signature
/// and the signing key id (plan sections 3.3 and 5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredManifest {
    /// The exact signed payload bytes.
    pub payload: Vec<u8>,
    /// DER ECDSA signature.
    pub signature: Vec<u8>,
    /// Signing key id.
    pub key_id: KeyId,
}

/// An image or PE in the content store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    /// Identifier.
    pub id: ContentId,
    /// Image or PE.
    pub kind: ContentKind,
    /// Operator-chosen name.
    pub display_name: DisplayName,
    /// Original file name.
    pub file_name: FileName,
    /// Size in bytes (declared at creation, verified at receipt).
    pub size: u64,
    /// SHA-256 (declared by the client; equal to the computed digest once
    /// Ready).
    pub sha256: Sha256Digest,
    /// State.
    pub state: ContentState,
    /// Reason for Failed (and for other states where given).
    pub reason: Option<Reason>,
    /// Creating operator.
    pub created_by: OperatorId,
    /// Audit record of the creating action (REQ-AUD-002).
    pub initiating_audit_seq: Option<u64>,
    /// Creation time.
    pub created_at: UnixMicros,
    /// Last change.
    pub updated_at: UnixMicros,
    /// When it became Ready.
    pub ready_at: Option<UnixMicros>,
    /// WIM facts (set at Ready).
    pub wim: Option<WimFacts>,
    /// The PE's usable image index (set at Ready for PEs, REQ-PE-004).
    pub usable_index: Option<u32>,
    /// The PE declaration (PEs only).
    pub pe: Option<PeDeclaration>,
    /// The signed content manifest (set at Ready).
    pub manifest: Option<StoredManifest>,
}

/// A new upload session's content row (state `receiving`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewContent {
    /// Identifier.
    pub id: ContentId,
    /// Image or PE.
    pub kind: ContentKind,
    /// Operator-chosen name.
    pub display_name: DisplayName,
    /// Original file name.
    pub file_name: FileName,
    /// Declared size.
    pub size: u64,
    /// Declared SHA-256.
    pub sha256: Sha256Digest,
    /// Creating operator.
    pub created_by: OperatorId,
    /// Audit record of the creating action.
    pub initiating_audit_seq: Option<u64>,
    /// Creation time.
    pub created_at: UnixMicros,
    /// PE declaration; required for PEs, forbidden for images.
    pub pe: Option<PeDeclaration>,
}

/// An upload session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upload {
    /// Identifier.
    pub id: UploadId,
    /// The content it fills.
    pub content_id: ContentId,
    /// The operator who may send the body.
    pub operator_id: OperatorId,
    /// Declared size.
    pub declared_size: u64,
    /// Declared SHA-256.
    pub declared_sha256: Sha256Digest,
    /// State.
    pub state: UploadState,
    /// Staging file name (under the content root's staging directory).
    pub staging_name: String,
    /// Creation time.
    pub created_at: UnixMicros,
    /// Session expiry.
    pub expires_at: UnixMicros,
}

/// One WIM image (edition) as listed by the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEdition {
    /// 1-based index.
    pub index: u32,
    /// `NAME` text.
    pub name: WimText,
    /// `DESCRIPTION` text.
    pub description: WimText,
    /// `TOTALBYTES`, when stated.
    pub total_bytes: Option<u64>,
}

/// An operator's declaration of an edition's facts (decision 0013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditionDeclaration {
    /// The facts, each with its source.
    pub facts: EditionFacts,
    /// Declaring operator.
    pub declared_by: OperatorId,
    /// When.
    pub declared_at: UnixMicros,
    /// The audit record of the declaration.
    pub declared_audit_seq: u64,
}

/// A stored edition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edition {
    /// The image it belongs to.
    pub content_id: ContentId,
    /// 1-based index.
    pub index: u32,
    /// `NAME` text.
    pub name: WimText,
    /// `DESCRIPTION` text.
    pub description: WimText,
    /// `TOTALBYTES`, when stated.
    pub total_bytes: Option<u64>,
    /// The declaration, if any.
    pub declaration: Option<EditionDeclaration>,
    /// Support status (`unknown` while undeclared, REQ-OS-009).
    pub support: SupportState,
    /// Reason for `not_supported` or `unknown`.
    pub support_reason: Option<String>,
}

/// Everything recorded when a check passes (state `checking` → `ready`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyContent {
    /// WIM facts.
    pub wim: WimFacts,
    /// Usable index (PEs only).
    pub usable_index: Option<u32>,
    /// The editions, indexes 1..=image_count.
    pub editions: Vec<NewEdition>,
    /// The signed content manifest.
    pub manifest: StoredManifest,
    /// The PE declaration after reconciliation with the file (PEs only;
    /// `None` keeps the stored one).
    pub pe: Option<PeDeclaration>,
    /// Time of the transition.
    pub at: UnixMicros,
}

/// A deployment package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// Identifier.
    pub id: PackageId,
    /// Name.
    pub name: DisplayName,
    /// Description.
    pub description: Option<Description>,
    /// The image.
    pub image_id: ContentId,
    /// The chosen edition index.
    pub edition_index: u32,
    /// The PE.
    pub pe_id: ContentId,
    /// Revision (ETag `"r<revision>"`); starts at 1.
    pub revision: u64,
    /// Status.
    pub status: PackageStatus,
    /// Reason when not usable.
    pub status_reason: Option<String>,
    /// The signed package manifest (Ready only).
    pub manifest: Option<StoredManifest>,
    /// Creating operator.
    pub created_by: OperatorId,
    /// Creation time.
    pub created_at: UnixMicros,
    /// Last change.
    pub updated_at: UnixMicros,
}

/// A package named as a dependant (409 `in_use`, decision 0015 item 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRef {
    /// Identifier.
    pub id: PackageId,
    /// Name.
    pub name: DisplayName,
}
