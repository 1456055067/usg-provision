//! API errors: one HTTP status, one reason code and operator text per
//! refusal, plus what the router needs to audit it.
//!
//! Every error a handler returns is audited by the router
//! ([`crate::router`]) unless the handler already wrote a record for it
//! (`audited`), so "every refusal is audited" (REQ-AUD-001) does not depend
//! on each handler remembering it. The operator sees the code and message
//! only; the internal cause (a static description from the failing layer)
//! goes to the audit record, never to the client (SI-11).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-11 (Error Handling) - stable codes and operator text;
//   internal causes only in the audit record; a commit whose outcome is
//   unknown is not reported as "nothing changed".
// - NIST 800-53: AU-2, AU-12 (Event Logging, Audit Record Generation) -
//   errors carry the audit event and target.
// - SPEC: specs/os-images.md#REQ-IMG-022 (clear failure reasons)
// - SPEC: specs/operator-access.md#REQ-AUD-006 (`audit_unavailable`)
// - RFC 9110 §15.5 (4xx status codes), §11.6.1 (WWW-Authenticate)

use std::fmt;

use hyper::StatusCode;
use usgp_audit::Detail;
use usgp_db::DbError;
use usgp_proto::api::{ErrorBody, Message, PackageRef};
use usgp_proto::{ContentId, ErrorCode, codes};

/// A refused or failed request. Boxed, so `Result<_, ApiError>` stays
/// small; the parts are reached through `Deref`.
#[derive(Clone)]
pub struct ApiError(Box<ErrorParts>);

impl std::ops::Deref for ApiError {
    type Target = ErrorParts;

    fn deref(&self) -> &ErrorParts {
        &self.0
    }
}

impl std::ops::DerefMut for ApiError {
    fn deref_mut(&mut self) -> &mut ErrorParts {
        &mut self.0
    }
}

/// The parts of an [`ApiError`].
#[derive(Clone)]
pub struct ErrorParts {
    /// HTTP status.
    pub status: StatusCode,
    /// The JSON body.
    pub body: ErrorBody,
    /// Audit event for the refusal; the route's refusal event if `None`.
    pub event: Option<&'static str>,
    /// Audit target (kind, id); the route's default if `None`.
    pub target: Option<(&'static str, String)>,
    /// Extra audit detail. The router adds `http_status`, `http_route`
    /// and `internal_cause`; handlers must not use those keys (a duplicate
    /// key makes the record invalid).
    pub detail: Option<Detail>,
    /// Internal cause, for the audit record only.
    pub internal: Option<String>,
    /// True if a record for this error was already written (or could not
    /// be written and was mirrored as unpersisted), so the router writes
    /// none.
    pub audited: bool,
    /// Send `WWW-Authenticate` (401 only).
    pub www_authenticate: bool,
}

impl fmt::Debug for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiError")
            .field("status", &self.status)
            .field("code", &self.body.error.code)
            .field("event", &self.event)
            .field("internal", &self.internal)
            .finish_non_exhaustive()
    }
}

impl ApiError {
    /// An error with a status, code and server-composed message.
    #[must_use]
    pub fn new(status: StatusCode, code: ErrorCode, message: impl Into<String>) -> Self {
        Self(Box::new(ErrorParts {
            status,
            body: ErrorBody::new(code, Message::truncated(message)),
            event: None,
            target: None,
            detail: None,
            internal: None,
            audited: false,
            www_authenticate: false,
        }))
    }

    /// The reason code.
    #[must_use]
    pub fn code(&self) -> &ErrorCode {
        &self.body.error.code
    }

    /// Sets the audit event.
    #[must_use]
    pub fn event(mut self, event: &'static str) -> Self {
        self.event = Some(event);
        self
    }

    /// Sets the audit target.
    #[must_use]
    pub fn target(mut self, kind: &'static str, id: impl fmt::Display) -> Self {
        self.target = Some((kind, id.to_string()));
        self
    }

    /// Sets the audit detail.
    #[must_use]
    pub fn detail(mut self, detail: Detail) -> Self {
        self.detail = Some(detail);
        self
    }

    /// Records an internal cause (audit only).
    #[must_use]
    pub fn internal(mut self, cause: impl fmt::Display) -> Self {
        self.internal = Some(cause.to_string());
        self
    }

    /// Marks the error as already audited.
    #[must_use]
    pub fn audited(mut self) -> Self {
        self.audited = true;
        self
    }

    /// Adds the limit (413).
    #[must_use]
    pub fn limit(mut self, bytes: u64) -> Self {
        self.body.error.limit_bytes = Some(bytes);
        self
    }

    /// Adds the existing item (409 duplicate).
    #[must_use]
    pub fn existing(mut self, id: ContentId) -> Self {
        self.body.error.existing_id = Some(id);
        self
    }

    /// Adds the dependants (409 in_use, decision 0015 item 2).
    #[must_use]
    pub fn dependants(mut self, deps: Vec<PackageRef>) -> Self {
        self.body.error.dependants = deps;
        self
    }

    // ------------------------------------------------------- common errors

    /// 401 with `WWW-Authenticate` (REQ-RBAC-005).
    #[must_use]
    pub fn unauthenticated() -> Self {
        let mut e = Self::new(
            StatusCode::UNAUTHORIZED,
            codes::UNAUTHENTICATED,
            "a valid operator client certificate is required",
        );
        e.www_authenticate = true;
        e
    }

    /// 403; never says whether the item exists (REQ-RBAC-003).
    #[must_use]
    pub fn forbidden() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            codes::FORBIDDEN,
            "your role does not permit this action",
        )
    }

    /// 404.
    #[must_use]
    pub fn not_found(what: &str) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            codes::NOT_FOUND,
            format!("no such {what}"),
        )
    }

    /// 400 `bad_request`.
    #[must_use]
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, codes::BAD_REQUEST, message)
    }

    /// 409 with a code.
    #[must_use]
    pub fn conflict(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    /// 422 with a code.
    #[must_use]
    pub fn unprocessable(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, code, message)
    }

    /// 428: `If-Match` is required.
    #[must_use]
    pub fn precondition_required() -> Self {
        Self::new(
            StatusCode::PRECONDITION_REQUIRED,
            codes::PRECONDITION_REQUIRED,
            "If-Match with the current ETag is required",
        )
    }

    /// 412: `If-Match` does not name the current version.
    #[must_use]
    pub fn precondition_failed() -> Self {
        Self::new(
            StatusCode::PRECONDITION_FAILED,
            codes::PRECONDITION_FAILED,
            "If-Match does not match the current ETag; read the item again",
        )
    }

    /// 500 `audit_unavailable`: the action was refused because its audit
    /// record could not be written; nothing changed (REQ-AUD-006). The
    /// record was mirrored as unpersisted, so the router writes none.
    #[must_use]
    pub fn audit_unavailable(cause: impl fmt::Display) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::AUDIT_UNAVAILABLE,
            "the action was refused because its audit record could not be written; nothing changed",
        )
        .internal(cause)
        .audited()
    }

    /// 500 `internal`; the cause goes to the audit record only.
    #[must_use]
    pub fn internal_error(cause: impl fmt::Display) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTERNAL,
            "internal error; nothing changed",
        )
        .internal(cause)
    }

    /// 500 from a database error.
    #[must_use]
    pub fn db(e: &DbError) -> Self {
        if e.outcome_unknown() {
            return Self::commit_failed(e);
        }
        Self::internal_error(e)
    }

    /// 500 for a failed commit. If the database may have applied the
    /// commit before the error (the connection failed during `COMMIT`),
    /// the operator is told the outcome may be unknown instead of
    /// "nothing changed" (finding NIST-013).
    #[must_use]
    pub fn commit_failed(e: &DbError) -> Self {
        if e.outcome_unknown() {
            Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTERNAL,
                "internal error; the outcome may be unknown, check before retrying",
            )
            .internal(e)
        } else {
            Self::internal_error(e)
        }
    }
}

impl From<DbError> for ApiError {
    fn from(e: DbError) -> Self {
        Self::db(&e)
    }
}

/// Errors building the API (start-up; WU-7 refuses to start on these).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ApiInitError {
    /// A configuration value is out of range.
    #[error(transparent)]
    Config(#[from] crate::limits::ConfigError),
    /// The content store could not be prepared.
    #[error("content store: {what}")]
    Store {
        /// What failed.
        what: &'static str,
        /// The I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The content signing key is not among the trusted keys.
    #[error("the content signing key is not trusted for verification")]
    KeyNotTrusted,
    /// One key is configured for two purposes (content, plan or boot
    /// policy); each purpose needs its own key.
    #[error("a signing key is configured for more than one purpose")]
    KeyReuse,
    /// A database or audit step failed during recovery.
    #[error("start-up recovery failed: {0}")]
    Recovery(String),
}
