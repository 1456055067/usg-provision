//! Machine-readable reason codes for API errors, failed content and
//! not-usable packages, and (M3) device session refusals and job failures.
//!
//! A code is short ASCII: it starts with `a`-`z` and continues with
//! `a`-`z`, `0`-`9`, `_`, `.`, `-` or `:`, up to
//! [`MAX_ERROR_CODE_BYTES`]. A parameter may follow a base code after a
//! colon, for example `pe_architecture_not_supported:arm64` or
//! `too_long:display_name` ([`ErrorCode::with_param`]).
//!
//! The constants in [`codes`] are the codes named by the M2 plan (sections
//! 3.2, 5.7 and 7) and the M3 plan (sections 3.1 to 3.6). Codes produced
//! by other crates (for example `usgp-image` WIM check reasons) are
//! wrapped with [`ErrorCode::new`].
//! A code never contains operator text or secrets; the message that goes
//! with it is separate.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-11 (Error Handling) - stable codes and operator text
//   without internals.
// - NIST 800-53: SI-10 (Information Input Validation) - strict code syntax.
// - SPEC: specs/os-images.md#REQ-IMG-022 (clear failure reasons)
// - SPEC: specs/operator-access.md#REQ-AUD-006 (the operator is told an
//   action failed because it could not be recorded: `audit_unavailable`)
// - SPEC: specs/targeting.md#REQ-TGT-013 (one refusal code for every bad
//   code), specs/progress.md#REQ-JOB-005 (failure reasons named)

use std::borrow::Cow;
use std::fmt;

use crate::limits::MAX_ERROR_CODE_BYTES;

/// A validated reason code.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ErrorCode(Cow<'static, str>);

/// Why a code was rejected. The text is never echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ErrorCodeError {
    /// Empty, or longer than [`MAX_ERROR_CODE_BYTES`].
    #[error("reason code must be 1 to 128 bytes, got {len}")]
    BadLength {
        /// Length in bytes.
        len: usize,
    },
    /// A byte outside the allowed set, or a first byte that is not `a`-`z`.
    #[error("reason code has a disallowed byte at offset {offset}")]
    InvalidByte {
        /// Offset of the first bad byte.
        offset: usize,
    },
}

const fn valid_byte(b: u8, first: bool) -> bool {
    if first {
        b.is_ascii_lowercase()
    } else {
        b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-' | b':')
    }
}

fn validate(s: &str) -> Result<(), ErrorCodeError> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_ERROR_CODE_BYTES {
        return Err(ErrorCodeError::BadLength { len: bytes.len() });
    }
    if let Some(offset) = bytes
        .iter()
        .enumerate()
        .position(|(i, &b)| !valid_byte(b, i == 0))
    {
        return Err(ErrorCodeError::InvalidByte { offset });
    }
    Ok(())
}

impl ErrorCode {
    /// Constant constructor for the [`codes`] table; each constant is
    /// checked by a unit test.
    const fn from_static(s: &'static str) -> Self {
        Self(Cow::Borrowed(s))
    }

    /// Validates and wraps a code.
    ///
    /// # Errors
    ///
    /// [`ErrorCodeError`] if the syntax rules are broken.
    pub fn new(code: impl Into<Cow<'static, str>>) -> Result<Self, ErrorCodeError> {
        let code = code.into();
        validate(&code)?;
        Ok(Self(code))
    }

    /// `<self>:<param>`, for example `too_long` with `display_name` gives
    /// `too_long:display_name`.
    ///
    /// # Errors
    ///
    /// [`ErrorCodeError`] if the result breaks the syntax rules (the
    /// parameter is checked as part of the whole code).
    pub fn with_param(&self, param: &str) -> Result<Self, ErrorCodeError> {
        Self::new(format!("{}:{param}", self.0))
    }

    /// The code text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The base code: the text before the first `:`.
    #[must_use]
    pub fn base(&self) -> &str {
        self.0.split(':').next().unwrap_or(&self.0)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ErrorCode({})", self.0)
    }
}

impl serde::Serialize for ErrorCode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for ErrorCode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;

        impl serde::de::Visitor<'_> for V {
            type Value = ErrorCode;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a reason code")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<ErrorCode, E> {
                ErrorCode::new(v.to_owned()).map_err(E::custom)
            }
        }

        d.deserialize_str(V)
    }
}

/// Reason codes named by the plan. The HTTP status in each comment is the
/// one plan section 3.2 gives; `usgp-api` owns the mapping.
pub mod codes {
    use super::ErrorCode;

    macro_rules! code {
        ($($(#[$doc:meta])* $name:ident = $text:literal;)+) => {
            $( $(#[$doc])* pub const $name: ErrorCode = ErrorCode::from_static($text); )+

            /// Every constant in this module (for tests and documentation).
            pub const ALL: &[ErrorCode] = &[ $( $name ),+ ];
        };
    }

    code! {
        // Authentication and authorization.
        /// 401: no client certificate, unknown certificate, or disabled
        /// operator (REQ-RBAC-005).
        UNAUTHENTICATED = "unauthenticated";
        /// 403: the operator lacks the route's permission; never reveals
        /// whether the item exists (REQ-RBAC-003).
        FORBIDDEN = "forbidden";

        // Request shape.
        /// 404: no such route or item.
        NOT_FOUND = "not_found";
        /// 405: the route exists but not for this method.
        METHOD_NOT_ALLOWED = "method_not_allowed";
        /// 400: the body is not JSON of the expected shape (unknown or
        /// duplicate fields, wrong types, trailing data).
        INVALID_JSON = "invalid_json";
        /// 400: a path or header value is malformed.
        BAD_REQUEST = "bad_request";
        /// 413: a JSON body is over `api.max_json_bytes`.
        BODY_TOO_LARGE = "body_too_large";
        /// 415: a JSON route received another media type.
        UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type";
        /// 422 base for field errors: `empty:<field>`.
        EMPTY = "empty";
        /// 422 base: `too_long:<field>`.
        TOO_LONG = "too_long";
        /// 422 base: `invalid_character:<field>`.
        INVALID_CHARACTER = "invalid_character";
        /// 422 base: `invalid_value:<field>` (includes unknown declaration
        /// values).
        INVALID_VALUE = "invalid_value";
        /// 422 base: `out_of_range:<field>` (for example an edition index
        /// above the image count, REQ-IMG-041).
        OUT_OF_RANGE = "out_of_range";
        /// 422 base: `required:<field>` (for example `pe_declaration` on a
        /// PE upload).
        REQUIRED = "required";
        /// 422 base: `not_allowed:<field>` (for example `pe_declaration` on
        /// an image upload).
        NOT_ALLOWED = "not_allowed";

        // Uploads.
        /// 422: declared size 0 (REQ-IMG-004).
        EMPTY_FILE = "empty_file";
        /// 413: declared size above `content.max_upload_bytes`, refused
        /// before any body (REQ-IMG-031).
        TOO_LARGE = "too_large";
        /// 409: content with this digest already exists (the existing id
        /// is given).
        DUPLICATE = "duplicate";
        /// 429: too many open uploads.
        QUOTA = "quota";
        /// 411: `Content-Length` missing, or chunked transfer coding.
        LENGTH_REQUIRED = "length_required";
        /// 400: `Content-Length` differs from the declared size.
        SIZE_MISMATCH = "size_mismatch";
        /// Failed: server digest differs from the declared SHA-256.
        DIGEST_MISMATCH = "digest_mismatch";
        /// Failed: the body stopped early (REQ-IMG-035).
        INTERRUPTED = "interrupted";
        /// Failed: Receiving or Checking when the server restarted.
        INTERRUPTED_BY_RESTART = "interrupted_by_restart";
        /// Failed: a storage write failed.
        STORAGE_ERROR = "storage_error";
        /// Upload cancelled by the operator.
        CANCELLED = "cancelled";
        /// 422 base: `pe_architecture_not_supported:<arch>` (REQ-PE-005).
        PE_ARCHITECTURE_NOT_SUPPORTED = "pe_architecture_not_supported";

        // State and concurrency.
        /// 409: the image or PE is not Ready.
        NOT_READY = "not_ready";
        /// 409: a package refers to content that is not Ready.
        NOT_READY_CONTENT = "not_ready_content";
        /// 409: the package manifest is requested but the package is not
        /// Ready.
        PACKAGE_NOT_READY = "package_not_ready";
        /// 409: the item is used by packages, which are named
        /// (decision 0015 item 2, REQ-IMG-015).
        IN_USE = "in_use";
        /// 428: `If-Match` is required.
        PRECONDITION_REQUIRED = "precondition_required";
        /// 412: `If-Match` does not match the current revision.
        PRECONDITION_FAILED = "precondition_failed";

        // Facts and scope (decision 0013).
        /// 422 base: `declaration_contradicts_file:<fact>`.
        DECLARATION_CONTRADICTS_FILE = "declaration_contradicts_file";
        /// 422: an out-of-scope edition chosen for a package (REQ-OS-005);
        /// the message names the failing fact.
        OS_SCOPE = "os_scope";
        /// Not usable: no declaration for the edition (REQ-OS-009).
        OS_SUPPORT_UNKNOWN = "os_support_unknown";
        /// Support reason base: `release_not_supported:<release>`.
        RELEASE_NOT_SUPPORTED = "release_not_supported";
        /// Support reason base: `edition_not_supported:<edition>`.
        EDITION_NOT_SUPPORTED = "edition_not_supported";
        /// Support reason base: `architecture_not_supported:<arch>`.
        ARCHITECTURE_NOT_SUPPORTED = "architecture_not_supported";
        /// Warning: the PE kit version is on `pe.known_bad_kit_versions`
        /// (REQ-PE-009).
        KIT_VERSION_KNOWN_BAD = "kit_version_known_bad";

        // Integrity and server faults.
        /// 500 (or an aborted stream): a chunk failed verification on use
        /// (REQ-IMG-050).
        INTEGRITY_FAILED = "integrity_failed";
        /// Failed: content marked failed after an integrity failure on use.
        INTEGRITY_FAILED_ON_USE = "integrity_failed_on_use";
        /// 500: the audit record could not be written, so the action was
        /// refused and nothing changed (REQ-AUD-006, decision 0015 item 1).
        AUDIT_UNAVAILABLE = "audit_unavailable";
        /// 503: the server is at its connection or worker limit.
        UNAVAILABLE = "unavailable";
        /// 500: an internal error; details are in the server log only.
        INTERNAL = "internal";

        // M3 device session (plan section 3.1).
        /// 401: no bearer token, or one that names no live session.
        INVALID_TOKEN = "invalid_token";
        /// 429: a session-open, code-attempt or capacity limit was hit.
        RATE_LIMITED = "rate_limited";
        /// 403: the session is not authorised yet; nothing is listed.
        NOT_AUTHORISED = "not_authorised";
        /// 422: the code was not accepted. The same code for a wrong,
        /// expired, used or revoked code (no oracle, REQ-TGT-013); the
        /// error carries `attempts_left`.
        CODE_NOT_ACCEPTED = "code_not_accepted";
        /// 403: the session was refused (attempts exhausted or an
        /// operator refused it).
        SESSION_REFUSED = "session_refused";
        /// 403: the session has expired or ended.
        SESSION_ENDED = "session_ended";
        /// 409: the request does not fit the session's state (for example a
        /// disk before a package, or a confirm that does not match the
        /// choices).
        WRONG_STATE = "wrong_state";
        /// 409: cancel after the wipe confirmation (REQ-TGT-011).
        JOB_STARTED = "job_started";
        /// 409: chunk fetch or report for a job that is not running.
        JOB_NOT_RUNNING = "job_not_running";
        /// 422: the chosen package was not offered to this session.
        PACKAGE_NOT_OFFERED = "package_not_offered";
        /// 422: the chosen disk is smaller than the package needs
        /// (REQ-DISK-004).
        DISK_TOO_SMALL = "disk_too_small";
        /// 422: the approval's display code is not the session's
        /// (plan section 3.5).
        DISPLAY_CODE_MISMATCH = "display_code_mismatch";

        // M3 agent-side failures (plan sections 3.2 to 3.4; REQ-JOB-005).
        /// The job plan's signature, type, schema or key did not verify.
        PLAN_SIGNATURE_INVALID = "plan_signature_invalid";
        /// The job plan does not carry the nonce the agent sent.
        PLAN_NONCE_MISMATCH = "plan_nonce_mismatch";
        /// The job plan names another session, job or disk.
        PLAN_BINDING_MISMATCH = "plan_binding_mismatch";
        /// The content manifest's signature or digest does not match the
        /// plan.
        CONTENT_MANIFEST_MISMATCH = "content_manifest_mismatch";
        /// A chunk's SHA-256 does not match the signed content manifest
        /// (REQ-PE-016, REQ-JOB-008).
        CHUNK_DIGEST_MISMATCH = "chunk_digest_mismatch";
        /// The opened disk is not the one the plan names (REQ-DISK-015).
        DISK_IDENTITY_MISMATCH = "disk_identity_mismatch";
        /// A step ran past its timeout (REQ-JOB-011).
        STEP_TIMEOUT = "step_timeout";
        /// No progress for longer than the stall timeout (REQ-JOB-011).
        STALLED = "stalled";
        /// Transient failures went past the retry bound (REQ-JOB-007).
        RETRIES_EXHAUSTED = "retries_exhausted";

        // M3 progress and boot policy (plan sections 3.4 and 3.6).
        /// 409: the report breaks the step order (REQ-JOB-013).
        PROGRESS_OUT_OF_ORDER = "progress_out_of_order";
        /// The boot-policy list failed its signature, boot-service or
        /// generation check; the last good list is kept.
        BOOT_POLICY_REJECTED = "boot_policy_rejected";
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_constant_is_valid_and_unique() {
        let mut seen = std::collections::HashSet::new();
        for c in codes::ALL {
            assert_eq!(validate(c.as_str()), Ok(()), "{c:?}");
            assert!(seen.insert(c.as_str()), "duplicate {c:?}");
            assert!(!c.as_str().contains(':'), "constants are base codes");
        }
    }

    #[test]
    fn syntax() {
        assert!(ErrorCode::new("not_found").is_ok());
        assert!(ErrorCode::new("release_not_supported:windows-10").is_ok());
        assert!(ErrorCode::new("x.y-z:1").is_ok());
        assert_eq!(
            ErrorCode::new(""),
            Err(ErrorCodeError::BadLength { len: 0 })
        );
        assert_eq!(
            ErrorCode::new("a".repeat(129)),
            Err(ErrorCodeError::BadLength { len: 129 })
        );
        assert!(ErrorCode::new("a".repeat(128)).is_ok());
        for (bad, offset) in [
            ("Not", 0),
            ("1x", 0),
            ("_x", 0),
            ("a b", 1),
            ("a\"b", 1),
            ("aé", 1),
            ("a\n", 1),
            ("a/b", 1),
        ] {
            assert_eq!(
                ErrorCode::new(bad),
                Err(ErrorCodeError::InvalidByte { offset }),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn params_and_base() {
        let c = codes::PE_ARCHITECTURE_NOT_SUPPORTED
            .with_param("arm64")
            .unwrap();
        assert_eq!(c.as_str(), "pe_architecture_not_supported:arm64");
        assert_eq!(c.base(), "pe_architecture_not_supported");
        assert_eq!(codes::IN_USE.base(), "in_use");
        assert!(codes::TOO_LONG.with_param("Display Name").is_err());
    }

    #[test]
    fn serde() {
        let c: ErrorCode = serde_json::from_str("\"in_use\"").unwrap();
        assert_eq!(c, codes::IN_USE);
        assert_eq!(serde_json::to_string(&c).unwrap(), "\"in_use\"");
        assert!(serde_json::from_str::<ErrorCode>("\"In Use\"").is_err());
    }
}
