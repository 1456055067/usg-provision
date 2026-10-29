//! Operator API (`/v1`, JSON over HTTP/1.1 with mTLS): request, response
//! and error bodies (plan section 3.2).
//!
//! **Requests** come in two forms:
//!
//! - a wire form (`*Request`) with plain JSON field types and
//!   `deny_unknown_fields`, so a body of the right shape always parses
//!   (shape errors are 400 `invalid_json`); and
//! - a validated form, produced by `validate()`, with strong types. A
//!   failed rule gives a [`FieldError`] whose code names the field (422,
//!   REQ-IMG-022), for example `too_long:display_name` or
//!   `invalid_value:release`.
//!
//! Clients (the CLI) build the validated form and convert it to the wire
//! form with `From`, so the server sees only values that pass the same
//! rules.
//!
//! **Responses** use strong types throughout and also deny unknown fields,
//! so a client refuses anything the server did not mean to send.
//!
//! No type here has a field for a secret value (REQ-IMG-054,
//! REQ-RBAC-006, REQ-AUD-003): M2 packages hold none.
//!
//! Route table, permissions, audit events and HTTP status mapping are
//! `usgp-api`'s job (WU-6); the codes are in [`crate::codes`].

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - size-capped strict
//   JSON; unknown and duplicate fields refused; every value validated.
// - NIST 800-53: SI-11 (Error Handling) - error bodies carry a code and
//   operator text, no internals; validation errors never echo values.
// - NIST 800-53: AC-3 (Access Enforcement) - path IDs parse only as UUIDs.
// - SPEC: specs/os-images.md#REQ-IMG-004 (size 0 refused: `empty_file`)
// - SPEC: specs/os-images.md#REQ-IMG-010, #REQ-IMG-011, #REQ-IMG-012,
//   #REQ-IMG-013 (package create, view, edit, clone bodies)
// - SPEC: specs/os-images.md#REQ-IMG-015 (in-use refusal names dependants)
// - SPEC: specs/os-images.md#REQ-IMG-020 (state and reason visible)
// - SPEC: specs/os-images.md#REQ-IMG-022 (reason codes and messages)
// - SPEC: specs/os-images.md#REQ-IMG-031 (limit stated: /v1/limits, 413)
// - SPEC: specs/os-images.md#REQ-IMG-033 (file names with spaces)
// - SPEC: specs/os-images.md#REQ-IMG-040, #REQ-IMG-041, #REQ-IMG-043
//   (editions, index choice, facts with source)
// - SPEC: specs/os-images.md#REQ-IMG-054, specs/operator-access.md
//   #REQ-RBAC-006, #REQ-AUD-003 (no secret fields)
// - SPEC: specs/preinstall-env.md#REQ-PE-005 (PE declaration at import),
//   #REQ-PE-006 (PE view), #REQ-PE-009 (kit warning)
// - SPEC: specs/os-support.md#REQ-OS-005, #REQ-OS-009 (support status and
//   reason shown)
// - RFC 9110 §8.8.3 (entity tags), §13.1.1 (If-Match), §11.6.1
//   (WWW-Authenticate)
// - RFC 8259 (JSON)

use std::fmt;

use serde::de::DeserializeOwned;
use usgp_common::Sha256Digest;

use crate::error_code::{ErrorCode, codes};
use crate::facts::{Architecture, Edition, EditionFacts, Fact, KitVersion, Release, SupportState};
use crate::ids::{ContentId, OperatorId, PackageId, UnixMicros, UploadId};
use crate::limits::{
    CHUNK_SIZE, MAX_DESCRIPTION_CHARS, MAX_DISPLAY_NAME_CHARS, MAX_FILE_NAME_BYTES,
    MAX_MESSAGE_CHARS,
};
use crate::names::{Description, DisplayName, EditionIndex, FileName, NameError, WimText};
use crate::status::{ContentKind, ContentState, PackageStatus, UploadState, WimCompression};

/// `WWW-Authenticate` value sent with every 401 (plan section 3.2; our own
/// auth-scheme token, RFC 9110 §11.6.1).
pub const WWW_AUTHENTICATE: &str = "usgp-client-cert realm=\"usg-provision\"";

/// Media type of every JSON body.
pub const JSON_MEDIA_TYPE: &str = "application/json";

// ---------------------------------------------------------------------------
// Parsing request bodies
// ---------------------------------------------------------------------------

/// Longest piece of parser text copied into an `invalid_json` message, in
/// characters.
const MAX_PARSER_TEXT_CHARS: usize = 200;

/// A JSON request body that could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RequestError {
    /// The body is over the configured cap (413 `body_too_large`).
    #[error("request body is {len} bytes; the limit is {max}")]
    TooLarge {
        /// Body length.
        len: usize,
        /// The cap.
        max: usize,
    },
    /// Not JSON of the expected shape (400 `invalid_json`).
    #[error("request body is not valid JSON of the expected shape: {detail}")]
    Json {
        /// Parser description with line and column, at most 200
        /// characters.
        detail: String,
    },
}

impl RequestError {
    /// The reason code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::TooLarge { .. } => codes::BODY_TOO_LARGE,
            Self::Json { .. } => codes::INVALID_JSON,
        }
    }

    /// The error body for the response.
    #[must_use]
    pub fn to_error_body(&self) -> ErrorBody {
        let mut body = ErrorBody::new(self.code(), Message::truncated(self.to_string()));
        if let Self::TooLarge { max, .. } = self {
            body.error.limit_bytes = u64::try_from(*max).ok();
        }
        body
    }
}

/// Parses a JSON request body after checking its size against `max_bytes`
/// (the server's `api.max_json_bytes`, default
/// [`crate::limits::DEFAULT_MAX_JSON_BYTES`]).
///
/// Unknown fields, duplicate fields, wrong types and trailing data are all
/// refused. Nesting depth is bounded by `serde_json`'s recursion limit.
///
/// # Errors
///
/// [`RequestError::TooLarge`] before any parsing; [`RequestError::Json`]
/// otherwise.
pub fn parse_request<T: DeserializeOwned>(
    body: &[u8],
    max_bytes: usize,
) -> Result<T, RequestError> {
    if body.len() > max_bytes {
        return Err(RequestError::TooLarge {
            len: body.len(),
            max: max_bytes,
        });
    }
    serde_json::from_slice(body).map_err(|e| RequestError::Json {
        detail: e.to_string().chars().take(MAX_PARSER_TEXT_CHARS).collect(),
    })
}

// ---------------------------------------------------------------------------
// Field validation errors
// ---------------------------------------------------------------------------

/// A request value that broke a rule (422). The code names the rule and
/// the field; the message states the limit. Neither contains the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldError {
    /// The JSON field name.
    pub field: &'static str,
    /// Reason code, for example `too_long:display_name`.
    pub code: ErrorCode,
    /// Operator text.
    pub message: String,
}

impl fmt::Display for FieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for FieldError {}

fn param(base: &ErrorCode, field: &'static str) -> ErrorCode {
    // Field names are static snake_case, valid in a code; if one were not,
    // the base code alone is still correct.
    base.with_param(field).unwrap_or_else(|_| base.clone())
}

impl FieldError {
    pub(crate) fn new(field: &'static str, base: &ErrorCode, message: String) -> Self {
        Self {
            field,
            code: param(base, field),
            message,
        }
    }

    pub(crate) fn name(field: &'static str, e: NameError) -> Self {
        let base = match e {
            NameError::Empty => &codes::EMPTY,
            NameError::TooLong { .. } => &codes::TOO_LONG,
            NameError::InvalidCharacter { .. } => &codes::INVALID_CHARACTER,
            NameError::Reserved => &codes::INVALID_VALUE,
        };
        Self::new(field, base, format!("{field} {e}"))
    }

    pub(crate) fn invalid(field: &'static str, why: impl fmt::Display) -> Self {
        Self::new(field, &codes::INVALID_VALUE, format!("{field}: {why}"))
    }

    fn one_of(field: &'static str, allowed: &[&str]) -> Self {
        Self::invalid(field, format_args!("must be one of {}", allowed.join(", ")))
    }

    fn required(field: &'static str, why: &str) -> Self {
        Self::new(
            field,
            &codes::REQUIRED,
            format!("{field} is required {why}"),
        )
    }

    fn not_allowed(field: &'static str, why: &str) -> Self {
        Self::new(
            field,
            &codes::NOT_ALLOWED,
            format!("{field} is not allowed {why}"),
        )
    }

    /// The error body for the response.
    #[must_use]
    pub fn to_error_body(&self) -> ErrorBody {
        ErrorBody::new(self.code.clone(), Message::truncated(self.message.clone()))
    }
}

macro_rules! closed_field {
    ($ty:ty, $field:literal, $text:expr) => {{
        let text: &str = $text;
        <$ty>::parse(text).ok_or_else(|| {
            let allowed: Vec<&str> = <$ty>::ALL.iter().map(|v| v.as_str()).collect();
            FieldError::one_of($field, &allowed)
        })
    }};
}

fn content_id(field: &'static str, text: &str) -> Result<ContentId, FieldError> {
    ContentId::parse(text).map_err(|e| FieldError::invalid(field, e))
}

// ---------------------------------------------------------------------------
// Declarations (decision 0013)
// ---------------------------------------------------------------------------

/// Wire body of `PUT /v1/images/{id}/editions/{index}/declaration`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EditionDeclarationRequest {
    /// `windows-11`, `windows-10` or `other`.
    pub release: String,
    /// `enterprise`, `enterprise-ltsc`, `iot-enterprise`, `education`,
    /// `pro`, `home` or `other`.
    pub edition: String,
    /// `x64`, `x86`, `arm64` or `arm`.
    pub architecture: String,
}

/// A validated edition declaration. Out-of-scope values are valid here;
/// they are recorded and judged by `usgp-image::os_support` (plan section
/// 3.2: "recorded even when out of scope").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EditionDeclaration {
    /// Declared release.
    pub release: Release,
    /// Declared edition.
    pub edition: Edition,
    /// Declared architecture.
    pub architecture: Architecture,
}

impl EditionDeclarationRequest {
    /// Validates the values against the closed sets.
    ///
    /// # Errors
    ///
    /// [`FieldError`] `invalid_value:<field>` for the first unknown value.
    pub fn validate(&self) -> Result<EditionDeclaration, FieldError> {
        Ok(EditionDeclaration {
            release: closed_field!(Release, "release", &self.release)?,
            edition: closed_field!(Edition, "edition", &self.edition)?,
            architecture: closed_field!(Architecture, "architecture", &self.architecture)?,
        })
    }
}

impl From<&EditionDeclaration> for EditionDeclarationRequest {
    fn from(d: &EditionDeclaration) -> Self {
        Self {
            release: d.release.as_str().to_owned(),
            edition: d.edition.as_str().to_owned(),
            architecture: d.architecture.as_str().to_owned(),
        }
    }
}

/// Wire form of a PE declaration, part of a PE upload request.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeDeclarationRequest {
    /// `x64`, `x86`, `arm64` or `arm`. Only `x64` is accepted in M2; that
    /// is decided by the server (REQ-PE-005), not by this syntax check.
    pub architecture: String,
    /// Kit version, for example `10.1.26100.1`.
    pub kit_version: String,
}

/// A validated PE declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeDeclaration {
    /// Declared architecture.
    pub architecture: Architecture,
    /// Declared kit version.
    pub kit_version: KitVersion,
}

impl PeDeclarationRequest {
    /// Validates the values.
    ///
    /// # Errors
    ///
    /// [`FieldError`] `invalid_value:architecture` or
    /// `invalid_value:kit_version`.
    pub fn validate(&self) -> Result<PeDeclaration, FieldError> {
        Ok(PeDeclaration {
            architecture: closed_field!(Architecture, "architecture", &self.architecture)?,
            kit_version: KitVersion::parse(&self.kit_version)
                .map_err(|e| FieldError::invalid("kit_version", e))?,
        })
    }
}

impl From<&PeDeclaration> for PeDeclarationRequest {
    fn from(d: &PeDeclaration) -> Self {
        Self {
            architecture: d.architecture.as_str().to_owned(),
            kit_version: d.kit_version.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Uploads
// ---------------------------------------------------------------------------

/// Wire body of `POST /v1/uploads`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateUploadRequest {
    /// `image` or `pe`.
    pub kind: String,
    /// Display name.
    pub display_name: String,
    /// File name (spaces allowed).
    pub file_name: String,
    /// Exact size in bytes.
    pub size: u64,
    /// SHA-256 of the file, computed by the client (64 hex digits).
    pub sha256: String,
    /// Required for `pe`, forbidden for `image`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pe_declaration: Option<PeDeclarationRequest>,
}

/// A validated upload request. The size limit and the PE architecture
/// scope are checked by the server against its configuration and
/// `usgp-image::os_support`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateUpload {
    /// Content kind.
    pub kind: ContentKind,
    /// Display name.
    pub display_name: DisplayName,
    /// File name.
    pub file_name: FileName,
    /// Size in bytes (at least 1).
    pub size: u64,
    /// Client-computed SHA-256.
    pub sha256: Sha256Digest,
    /// PE declaration (present exactly when `kind` is `pe`).
    pub pe_declaration: Option<PeDeclaration>,
}

impl CreateUploadRequest {
    /// Validates every field, in field order.
    ///
    /// # Errors
    ///
    /// The first [`FieldError`]: `invalid_value:kind`; a name rule on
    /// `display_name` or `file_name`; `empty_file` for size 0
    /// (REQ-IMG-004); `invalid_value:sha256`;
    /// `required:pe_declaration` (PE without one);
    /// `not_allowed:pe_declaration` (image with one); or a declaration
    /// value error.
    pub fn validate(&self) -> Result<CreateUpload, FieldError> {
        let kind = closed_field!(ContentKind, "kind", &self.kind)?;
        let display_name = DisplayName::new(self.display_name.as_str())
            .map_err(|e| FieldError::name("display_name", e))?;
        let file_name =
            FileName::new(self.file_name.as_str()).map_err(|e| FieldError::name("file_name", e))?;
        if self.size == 0 {
            return Err(FieldError {
                field: "size",
                code: codes::EMPTY_FILE,
                message: "the file is empty (size 0); empty files are refused".to_owned(),
            });
        }
        let sha256 =
            Sha256Digest::from_hex(&self.sha256).map_err(|e| FieldError::invalid("sha256", e))?;
        let pe_declaration = match (kind, &self.pe_declaration) {
            (ContentKind::Pe, Some(d)) => Some(d.validate()?),
            (ContentKind::Pe, None) => {
                return Err(FieldError::required(
                    "pe_declaration",
                    "for a PE import (architecture and kit_version)",
                ));
            }
            (ContentKind::Image, Some(_)) => {
                return Err(FieldError::not_allowed(
                    "pe_declaration",
                    "for an image upload; declare each edition after the check",
                ));
            }
            (ContentKind::Image, None) => None,
        };
        Ok(CreateUpload {
            kind,
            display_name,
            file_name,
            size: self.size,
            sha256,
            pe_declaration,
        })
    }
}

impl From<&CreateUpload> for CreateUploadRequest {
    fn from(u: &CreateUpload) -> Self {
        Self {
            kind: u.kind.as_str().to_owned(),
            display_name: u.display_name.as_str().to_owned(),
            file_name: u.file_name.as_str().to_owned(),
            size: u.size,
            sha256: u.sha256.to_hex(),
            pe_declaration: u.pe_declaration.as_ref().map(PeDeclarationRequest::from),
        }
    }
}

/// Response of `POST /v1/uploads` (201).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateUploadResponse {
    /// Upload session; the body goes to `PUT /v1/uploads/{upload_id}`.
    pub upload_id: UploadId,
    /// The content item the upload will become.
    pub content_id: ContentId,
    /// Session state (`open`).
    pub state: UploadState,
    /// When the session expires unless the body has arrived.
    pub expires_at: UnixMicros,
}

/// Response of `PUT /v1/uploads/{id}` (202): the body arrived and the
/// content is being checked.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadAccepted {
    /// The content item.
    pub content_id: ContentId,
    /// Its state (`checking`).
    pub state: ContentState,
}

// ---------------------------------------------------------------------------
// Packages
// ---------------------------------------------------------------------------

/// Wire body of `POST /v1/packages` and `PUT /v1/packages/{id}` (full
/// replacement).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageRequest {
    /// Package name.
    pub name: String,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Image file id.
    pub image_id: String,
    /// 1-based edition index in that file.
    pub edition_index: u64,
    /// PE kit id.
    pub pe_id: String,
}

/// A validated package definition. Whether the image and PE exist, are
/// Ready, and whether the index is within the image count, are checked by
/// the server ([`EditionIndex::check`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageSpec {
    /// Package name.
    pub name: DisplayName,
    /// Description.
    pub description: Option<Description>,
    /// Image file.
    pub image_id: ContentId,
    /// Edition index (at least 1).
    pub edition_index: EditionIndex,
    /// PE kit.
    pub pe_id: ContentId,
}

impl PackageRequest {
    /// Validates every field, in field order.
    ///
    /// # Errors
    ///
    /// The first [`FieldError`]: a name rule on `name` or `description`;
    /// `invalid_value:image_id` / `pe_id`; `out_of_range:edition_index`.
    pub fn validate(&self) -> Result<PackageSpec, FieldError> {
        let name = DisplayName::new(self.name.as_str()).map_err(|e| FieldError::name("name", e))?;
        let description = self
            .description
            .as_deref()
            .map(Description::new)
            .transpose()
            .map_err(|e| FieldError::name("description", e))?;
        let image_id = content_id("image_id", &self.image_id)?;
        let edition_index = EditionIndex::new(self.edition_index).map_err(|_| {
            FieldError::new(
                "edition_index",
                &codes::OUT_OF_RANGE,
                "edition_index must be at least 1".to_owned(),
            )
        })?;
        let pe_id = content_id("pe_id", &self.pe_id)?;
        Ok(PackageSpec {
            name,
            description,
            image_id,
            edition_index,
            pe_id,
        })
    }
}

impl From<&PackageSpec> for PackageRequest {
    fn from(p: &PackageSpec) -> Self {
        Self {
            name: p.name.as_str().to_owned(),
            description: p.description.as_ref().map(|d| d.as_str().to_owned()),
            image_id: p.image_id.to_string(),
            edition_index: u64::from(p.edition_index.get()),
            pe_id: p.pe_id.to_string(),
        }
    }
}

/// Wire body of `POST /v1/packages/{id}/clone`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClonePackageRequest {
    /// Name of the clone.
    pub name: String,
}

impl ClonePackageRequest {
    /// Validates the name.
    ///
    /// # Errors
    ///
    /// [`FieldError`] for a name rule on `name`.
    pub fn validate(&self) -> Result<DisplayName, FieldError> {
        DisplayName::new(self.name.as_str()).map_err(|e| FieldError::name("name", e))
    }
}

impl From<&DisplayName> for ClonePackageRequest {
    fn from(n: &DisplayName) -> Self {
        Self {
            name: n.as_str().to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// Errors and reasons
// ---------------------------------------------------------------------------

/// Operator-facing text: up to [`MAX_MESSAGE_CHARS`] Unicode scalar values.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(transparent)]
pub struct Message(String);

/// A message over [`MAX_MESSAGE_CHARS`] characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("message is {len} characters; the limit is 2048")]
pub struct MessageTooLong {
    /// Length in characters.
    pub len: usize,
}

impl Message {
    /// Wraps `text` if it is within the limit.
    ///
    /// # Errors
    ///
    /// [`MessageTooLong`].
    pub fn new(text: impl Into<String>) -> Result<Self, MessageTooLong> {
        let text = text.into();
        let len = text.chars().count();
        if len > MAX_MESSAGE_CHARS {
            return Err(MessageTooLong { len });
        }
        Ok(Self(text))
    }

    /// Server-side convenience for text the server composed itself: keeps
    /// at most [`MAX_MESSAGE_CHARS`] characters, ending in `…` when cut.
    /// Never use it on operator-supplied values.
    #[must_use]
    pub fn truncated(text: impl Into<String>) -> Self {
        let text = text.into();
        if text.chars().count() <= MAX_MESSAGE_CHARS {
            return Self(text);
        }
        let mut cut: String = text.chars().take(MAX_MESSAGE_CHARS - 1).collect();
        cut.push('…');
        Self(cut)
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Message {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::new(s).map_err(serde::de::Error::custom)
    }
}

/// A reason: code plus operator text. Used for failed content, not-usable
/// packages and kit warnings.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reason {
    /// Reason code.
    pub code: ErrorCode,
    /// Operator text.
    pub message: Message,
}

/// A package named in an `in_use` refusal or a "used by" list.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageRef {
    /// Package id.
    pub id: PackageId,
    /// Package name.
    pub name: DisplayName,
}

/// The `error` member of an error body.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorDetail {
    /// Reason code.
    pub code: ErrorCode,
    /// Operator text.
    pub message: Message,
    /// The limit, for `too_large` and `body_too_large` (REQ-IMG-031).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_bytes: Option<u64>,
    /// The existing content, for `duplicate`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing_id: Option<ContentId>,
    /// The packages that depend on the item, for `in_use`
    /// (decision 0015 item 2, REQ-IMG-015).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependants: Vec<PackageRef>,
    /// Code attempts left in the device session, for `code_not_accepted`
    /// (M3 plan section 3.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempts_left: Option<u32>,
}

/// Every error response: `{"error": {"code": ..., "message": ...}}` plus
/// the optional members of [`ErrorDetail`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    /// The error.
    pub error: ErrorDetail,
}

impl ErrorBody {
    /// An error with only a code and a message.
    #[must_use]
    pub fn new(code: ErrorCode, message: Message) -> Self {
        Self {
            error: ErrorDetail {
                code,
                message,
                limit_bytes: None,
                existing_id: None,
                dependants: Vec::new(),
                attempts_left: None,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

/// Response of `GET /v1/limits`: the limits the server applies, so the
/// operator learns them before trying (REQ-IMG-031, REQ-IMG-002).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsView {
    /// Largest upload accepted (`content.max_upload_bytes`).
    pub max_upload_bytes: u64,
    /// Largest JSON request body (`api.max_json_bytes`).
    pub max_json_bytes: u64,
    /// Longest display or package name, in characters.
    pub max_display_name_chars: u64,
    /// Longest package description, in characters.
    pub max_description_chars: u64,
    /// Longest file name, in bytes of UTF-8.
    pub max_file_name_bytes: u64,
    /// Chunk size of per-chunk digests.
    pub chunk_size: u64,
}

impl LimitsView {
    /// The view for the given configured limits; the name and chunk
    /// limits come from [`crate::limits`].
    #[must_use]
    pub fn new(max_upload_bytes: u64, max_json_bytes: u64) -> Self {
        Self {
            max_upload_bytes,
            max_json_bytes,
            max_display_name_chars: u64::try_from(MAX_DISPLAY_NAME_CHARS).unwrap_or(u64::MAX),
            max_description_chars: u64::try_from(MAX_DESCRIPTION_CHARS).unwrap_or(u64::MAX),
            max_file_name_bytes: u64::try_from(MAX_FILE_NAME_BYTES).unwrap_or(u64::MAX),
            chunk_size: CHUNK_SIZE,
        }
    }
}

/// Support status with its reason (REQ-OS-005, REQ-OS-009), for example
/// `not_supported` + `edition_not_supported:pro`, or `unknown` +
/// `os_support_unknown`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportView {
    /// Status.
    pub status: SupportState,
    /// Reason code; absent only when `supported`.
    pub reason: Option<ErrorCode>,
}

/// One edition of an image file (REQ-IMG-040, REQ-IMG-043).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EditionView {
    /// 1-based index.
    pub index: EditionIndex,
    /// Name from the file.
    pub name: WimText,
    /// Description from the file.
    pub description: WimText,
    /// Size the file states, if any.
    pub total_bytes: Option<u64>,
    /// Declared facts with sources; `None` until declared.
    pub facts: Option<EditionFacts>,
    /// Who declared them.
    pub declared_by: Option<OperatorId>,
    /// When.
    pub declared_at: Option<UnixMicros>,
    /// Support status against the M2 scope.
    pub support: SupportView,
}

/// An image file (`GET /v1/images/{id}`; also each item of the list).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageView {
    /// Content id.
    pub id: ContentId,
    /// Display name.
    pub display_name: DisplayName,
    /// File name.
    pub file_name: FileName,
    /// Size in bytes.
    pub size: u64,
    /// Verified SHA-256; set once Ready.
    pub sha256: Option<Sha256Digest>,
    /// State (REQ-IMG-020).
    pub state: ContentState,
    /// Reason when Failed (REQ-IMG-022).
    pub reason: Option<Reason>,
    /// Uploading operator.
    pub created_by: OperatorId,
    /// Upload time.
    pub created_at: UnixMicros,
    /// Last state change.
    pub updated_at: UnixMicros,
    /// Compression; set once checked.
    pub compression: Option<WimCompression>,
    /// Image count; set once checked.
    pub image_count: Option<u32>,
    /// Boot index; set once checked (0 = none).
    pub boot_index: Option<u32>,
    /// Editions; empty until Ready.
    pub editions: Vec<EditionView>,
}

/// Response of `GET /v1/images`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageList {
    /// Image files.
    pub images: Vec<ImageView>,
}

/// A PE kit (`GET /v1/pe/{id}`; REQ-PE-006).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeView {
    /// Content id.
    pub id: ContentId,
    /// Display name.
    pub display_name: DisplayName,
    /// File name.
    pub file_name: FileName,
    /// Size in bytes.
    pub size: u64,
    /// Verified SHA-256; set once Ready.
    pub sha256: Option<Sha256Digest>,
    /// State.
    pub state: ContentState,
    /// Reason when Failed.
    pub reason: Option<Reason>,
    /// Importing operator.
    pub imported_by: OperatorId,
    /// Import time.
    pub imported_at: UnixMicros,
    /// Last state change.
    pub updated_at: UnixMicros,
    /// Index of the usable image (REQ-PE-004); set once checked.
    pub usable_index: Option<EditionIndex>,
    /// Architecture with its source (REQ-PE-005).
    pub architecture: Fact<Architecture>,
    /// Kit version with its source (REQ-PE-005).
    pub kit_version: Fact<KitVersion>,
    /// Warning when the kit version is known bad (REQ-PE-009).
    pub kit_warning: Option<Reason>,
    /// Packages that use this PE.
    pub used_by: Vec<PackageRef>,
}

/// Response of `GET /v1/pe`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeList {
    /// PE kits.
    pub pe: Vec<PeView>,
}

/// The image part of a package view (REQ-IMG-011, REQ-IMG-041).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageImageView {
    /// Image file id.
    pub image_id: ContentId,
    /// Image display name.
    pub display_name: DisplayName,
    /// Chosen edition.
    pub edition_index: EditionIndex,
    /// Edition name from the file.
    pub edition_name: WimText,
    /// Facts with sources; `None` if the edition is undeclared.
    pub facts: Option<EditionFacts>,
    /// Support status of the chosen edition.
    pub support: SupportView,
}

/// The PE part of a package view.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackagePeView {
    /// PE kit id.
    pub pe_id: ContentId,
    /// PE display name.
    pub display_name: DisplayName,
    /// Architecture with its source.
    pub architecture: Fact<Architecture>,
    /// Kit version with its source.
    pub kit_version: Fact<KitVersion>,
    /// Kit warning, if any (REQ-PE-009).
    pub kit_warning: Option<Reason>,
}

/// A package (`GET /v1/packages/{id}`; `ETag: "r<revision>"`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageView {
    /// Package id.
    pub id: PackageId,
    /// Name.
    pub name: DisplayName,
    /// Description.
    pub description: Option<Description>,
    /// Revision (at least 1).
    pub revision: u64,
    /// `ready` or `not_usable`.
    pub status: PackageStatus,
    /// Reason when `not_usable`.
    pub status_reason: Option<Reason>,
    /// Image edition.
    pub image: PackageImageView,
    /// PE kit.
    pub pe: PackagePeView,
    /// Creating operator.
    pub created_by: OperatorId,
    /// Creation time.
    pub created_at: UnixMicros,
    /// Last change.
    pub updated_at: UnixMicros,
}

/// Response of `GET /v1/packages`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageList {
    /// Packages.
    pub packages: Vec<PackageView>,
}

// ---------------------------------------------------------------------------
// Entity tags
// ---------------------------------------------------------------------------

/// Longest entity tag a client keeps and sends back in `If-Match`, and the
/// longest `If-Match` value parsed, in bytes. Every tag the server issues
/// must fit: the content tag [`content_etag`] is 73 bytes (`"sha256:"`
/// plus 64 hex digits, quoted). It was 64, which silently dropped content
/// tags in the CLI (M3 review, boot-smoke S9).
pub const MAX_IF_MATCH_BYTES: usize = 128;

/// `ETag` of a package revision: `"r<revision>"` (strong).
#[must_use]
pub fn package_etag(revision: u64) -> String {
    format!("\"r{revision}\"")
}

/// `ETag` of content: `"sha256:<hex>"` (strong).
#[must_use]
pub fn content_etag(sha256: &Sha256Digest) -> String {
    format!("\"sha256:{}\"", sha256.to_hex())
}

/// The revision named by an `If-Match` value, or `None` if it is not
/// exactly one strong tag `"r<decimal>"`.
///
/// `*`, lists, weak tags (`W/`), leading zeros and anything over
/// [`MAX_IF_MATCH_BYTES`] give `None`; the caller answers 412, which is
/// fail-closed: a delete or edit proceeds only when the client names the
/// exact current revision (RFC 9110 §13.1.1 uses strong comparison for
/// `If-Match`).
#[must_use]
pub fn if_match_revision(value: &[u8]) -> Option<u64> {
    if value.len() > MAX_IF_MATCH_BYTES {
        return None;
    }
    let inner = value.strip_prefix(b"\"r")?.strip_suffix(b"\"")?;
    if inner.is_empty()
        || !inner.iter().all(u8::is_ascii_digit)
        || (inner.len() > 1 && inner.first() == Some(&b'0'))
    {
        return None;
    }
    std::str::from_utf8(inner).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etags() {
        assert_eq!(package_etag(7), "\"r7\"");
        assert_eq!(if_match_revision(b"\"r7\""), Some(7));
        assert_eq!(
            if_match_revision(b"\"r18446744073709551615\""),
            Some(u64::MAX)
        );
        for bad in [
            &b"*"[..],
            b"W/\"r7\"",
            b"\"r7\", \"r8\"",
            b"r7",
            b"\"r\"",
            b"\"r07\"",
            b"\"r-7\"",
            b"\"r+7\"",
            b"\"r 7\"",
            b"\"R7\"",
            b"\"r18446744073709551616\"",
            b" \"r7\"",
        ] {
            assert_eq!(
                if_match_revision(bad),
                None,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
        assert_eq!(if_match_revision(&[b'"'; 100]), None);
        // Over the cap: refused before parsing.
        let mut long = b"\"r1".to_vec();
        long.extend(std::iter::repeat_n(b'0', MAX_IF_MATCH_BYTES));
        long.push(b'"');
        assert_eq!(if_match_revision(&long), None);
    }

    /// Every entity tag the server issues fits [`MAX_IF_MATCH_BYTES`], so
    /// a client can send it back (the full-digest content tag included).
    #[test]
    fn issued_etags_fit_if_match() {
        let c = content_etag(&Sha256Digest([0xab; 32]));
        assert_eq!(c.len(), 73);
        assert!(c.contains(&"ab".repeat(32)), "names the full digest");
        assert!(c.len() <= MAX_IF_MATCH_BYTES);
        assert!(package_etag(u64::MAX).len() <= MAX_IF_MATCH_BYTES);
        let d = Sha256Digest([0xab; 32]);
        assert_eq!(content_etag(&d), format!("\"sha256:{}\"", "ab".repeat(32)));
    }

    #[test]
    fn message_limits() {
        assert!(Message::new("x".repeat(2048)).is_ok());
        assert_eq!(
            Message::new("x".repeat(2049)),
            Err(MessageTooLong { len: 2049 })
        );
        let t = Message::truncated("é".repeat(3000));
        assert_eq!(t.as_str().chars().count(), 2048);
        assert!(t.as_str().ends_with('…'));
        assert_eq!(Message::truncated("short").as_str(), "short");
    }

    #[test]
    fn field_error_codes() {
        let e = FieldError::name(
            "display_name",
            NameError::TooLong {
                len: 200,
                max: 128,
                unit: "characters",
            },
        );
        assert_eq!(e.code.as_str(), "too_long:display_name");
        assert_eq!(
            e.message,
            "display_name is 200 characters long; the limit is 128"
        );
        let b = e.to_error_body();
        assert_eq!(b.error.code.as_str(), "too_long:display_name");
    }
}
