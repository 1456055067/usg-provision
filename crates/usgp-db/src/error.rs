//! Errors returned by `usgp-db`.
//!
//! Error text names the failing step and a static description only. It
//! never contains row content, configuration values or key material, so an
//! error can be logged or mapped to an operator-facing code without
//! leaking data (SI-11). The driver's own error is kept as the `source`
//! for diagnostics by the caller.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-11 (Error Handling) - static messages, no data echoed.
// - NIST 800-53: AU-5 (Response to Audit Logging Process Failures) -
//   `Unaudited` refuses a commit that would change state without a record.
// - Decision 0012 - `ConnectFailure::AuthMethodRefused`.

use std::error::Error as StdError;

use usgp_audit::{StoreError, StoreErrorKind};

/// A boxed driver or pool error kept as a source.
pub type BoxError = Box<dyn StdError + Send + Sync + 'static>;

/// Why a connection to PostgreSQL could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectFailure {
    /// The server asked for a password (cleartext, MD5 or SCRAM); no
    /// password exists, so the driver refused before any hash was computed
    /// (decision 0012, plan section 5.5).
    AuthMethodRefused,
    /// The server does not offer TLS; the connection is never made in
    /// plaintext.
    TlsNotOffered,
    /// The TLS handshake failed (class from `usgp-crypto`).
    Tls(usgp_crypto::tls::TlsFailureClass),
    /// The server refused the login (for example certificate CN mismatch).
    Rejected,
    /// No connection within the configured timeout.
    Timeout,
    /// Network or protocol failure.
    Other,
}

impl ConnectFailure {
    /// Short reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthMethodRefused => "auth_method_refused",
            Self::TlsNotOffered => "tls_not_offered",
            Self::Tls(c) => c.as_str(),
            Self::Rejected => "login_rejected",
            Self::Timeout => "timeout",
            Self::Other => "connect_failed",
        }
    }
}

/// Errors from `usgp-db`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DbError {
    /// The configuration is not acceptable.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    /// A connection could not be made.
    #[error("database connection failed: {}", .class.as_str())]
    Connect {
        /// Why.
        class: ConnectFailure,
        /// The driver or pool error.
        #[source]
        source: Option<BoxError>,
    },
    /// The schema is missing, older or newer than this build, or an applied
    /// migration was altered.
    #[error(transparent)]
    Migration(#[from] crate::migrate::MigrationError),
    /// A statement failed for a reason not listed below.
    #[error("database statement failed at {context}")]
    Query {
        /// The step that failed.
        context: &'static str,
        /// The driver error.
        #[source]
        source: tokio_postgres::Error,
    },
    /// A compare-and-set or uniqueness rule failed: the row changed, or an
    /// equal item exists.
    #[error("conflict at {what}")]
    Conflict {
        /// What conflicted.
        what: &'static str,
    },
    /// A database constraint refused the write.
    #[error("constraint violated at {what}")]
    Constraint {
        /// The step that failed.
        what: &'static str,
    },
    /// The database denied the statement to this role.
    #[error("permission denied at {what}")]
    Denied {
        /// The step that failed.
        what: &'static str,
    },
    /// The item does not exist.
    #[error("not found: {what}")]
    NotFound {
        /// What was looked up.
        what: &'static str,
    },
    /// A stored value cannot be represented (a tampered or foreign row).
    #[error("stored value not representable: {what}")]
    Corrupt {
        /// Which value.
        what: &'static str,
    },
    /// An argument cannot be stored (for example a size above `i64::MAX`).
    #[error("invalid argument: {what}")]
    InvalidArgument {
        /// Which argument.
        what: &'static str,
    },
    /// The transaction changed state but holds no audit record; it was
    /// rolled back (decision 0015 item 1).
    #[error("state change without an audit record refused")]
    Unaudited,
    /// An earlier statement in this transaction failed; it can only be
    /// rolled back.
    #[error("transaction already failed")]
    TxFailed,
    /// The transaction was already committed or rolled back.
    #[error("transaction already finished")]
    TxFinished,
}

impl DbError {
    /// Maps a driver error at `context` onto the error classes callers act
    /// on (conflict, constraint, denied), or `Query`.
    pub(crate) fn from_pg(context: &'static str, source: tokio_postgres::Error) -> Self {
        use tokio_postgres::error::SqlState;
        match source.code() {
            Some(c)
                if *c == SqlState::UNIQUE_VIOLATION
                    || *c == SqlState::T_R_SERIALIZATION_FAILURE =>
            {
                Self::Conflict { what: context }
            }
            Some(c)
                if *c == SqlState::CHECK_VIOLATION
                    || *c == SqlState::FOREIGN_KEY_VIOLATION
                    || *c == SqlState::NOT_NULL_VIOLATION
                    || *c == SqlState::INTEGRITY_CONSTRAINT_VIOLATION =>
            {
                Self::Constraint { what: context }
            }
            Some(c) if *c == SqlState::INSUFFICIENT_PRIVILEGE => Self::Denied { what: context },
            _ => Self::Query { context, source },
        }
    }

    /// True for [`DbError::Conflict`].
    #[must_use]
    pub const fn is_conflict(&self) -> bool {
        matches!(self, Self::Conflict { .. })
    }

    /// True if the error came from `COMMIT` itself without a server
    /// answer (for example the connection broke): the transaction may or
    /// may not have been applied. A constraint, conflict or permission
    /// error at commit is a definite rollback and is not "unknown".
    #[must_use]
    pub fn outcome_unknown(&self) -> bool {
        matches!(
            self,
            Self::Query { context, source } if *context == "commit" && source.as_db_error().is_none()
        )
    }

    /// True for [`DbError::NotFound`].
    #[must_use]
    pub const fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }

    /// The audit-store view of this error (for [`usgp_audit::AuditTx`]).
    pub(crate) fn into_store(self, context: &'static str) -> StoreError {
        let kind = match &self {
            Self::Corrupt { .. } => StoreErrorKind::Corrupt,
            Self::Conflict { .. } => StoreErrorKind::Conflict,
            _ => StoreErrorKind::Unavailable,
        };
        StoreError::new(kind, context).with_source(self)
    }
}

/// Classifies a connection error from the driver or the pool.
///
/// The driver reports a missing password as a configuration error whose
/// text is "password missing" and a server without TLS as "server does not
/// support TLS"; it exposes no structured kind for either, so the text is
/// matched (pinned by unit tests against the real driver).
pub(crate) fn classify_connect(err: &(dyn StdError + 'static)) -> ConnectFailure {
    let mut cur: Option<&(dyn StdError + 'static)> = Some(err);
    let mut text = String::new();
    while let Some(e) = cur {
        if let Some(t) = e.downcast_ref::<crate::tls::TlsHookError>() {
            return ConnectFailure::Tls(t.class());
        }
        if let Some(pg) = e.downcast_ref::<tokio_postgres::Error>()
            && pg.as_db_error().is_some()
        {
            return ConnectFailure::Rejected;
        }
        text.push_str(&e.to_string());
        text.push('\n');
        cur = e.source();
    }
    if text.contains("password missing") {
        ConnectFailure::AuthMethodRefused
    } else if text.contains("server does not support TLS") {
        ConnectFailure::TlsNotOffered
    } else if text.contains("timeout") || text.contains("timed out") {
        ConnectFailure::Timeout
    } else {
        ConnectFailure::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_are_static() {
        assert_eq!(
            DbError::Conflict {
                what: "insert content"
            }
            .to_string(),
            "conflict at insert content"
        );
        assert_eq!(
            DbError::Unaudited.to_string(),
            "state change without an audit record refused"
        );
        let e = DbError::Connect {
            class: ConnectFailure::AuthMethodRefused,
            source: None,
        };
        assert_eq!(
            e.to_string(),
            "database connection failed: auth_method_refused"
        );
    }

    #[test]
    fn store_error_kind_mapping() {
        let s = DbError::Corrupt { what: "seq" }.into_store("lock_head");
        assert_eq!(s.kind(), StoreErrorKind::Corrupt);
        let s = DbError::TxFailed.into_store("insert_record");
        assert_eq!(s.kind(), StoreErrorKind::Unavailable);
    }
}
