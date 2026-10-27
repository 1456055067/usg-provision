//! Errors returned by the audit chain and its storage interface.
//!
//! Error values never carry record content beyond static field names, so
//! an error cannot leak anything a caller put in a draft. They carry no
//! key material (REQ-AUD-003).
//!
//! `thiserror` is not a dependency of this crate (plan section 4 lists
//! only `serde_json` for it), so `Display` and `Error` are written by
//! hand. See impl notes WU-2.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-11 (Error Handling) - errors name the failing step,
//   never record content or secrets.
// - NIST 800-53: AU-5 (Response to Audit Logging Process Failures) - a
//   store failure surfaces as an error the caller must turn into a
//   refusal (decision 0015 item 1).
// - SPEC: specs/operator-access.md#REQ-AUD-006

use std::error::Error;
use std::fmt;

use usgp_crypto::CryptoError;

/// Why a storage backend failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreErrorKind {
    /// The backend could not be reached or the write failed.
    Unavailable,
    /// Another writer moved the chain head (memory store only; PostgreSQL
    /// serialises with `FOR UPDATE` instead).
    Conflict,
    /// The stored data cannot be represented (for example a negative
    /// `seq` in a `bigint` column).
    Corrupt,
    /// A fault injected by a test (memory store only).
    Injected,
}

impl StoreErrorKind {
    /// Short text for the kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Conflict => "conflict",
            Self::Corrupt => "corrupt",
            Self::Injected => "injected",
        }
    }
}

/// A failure of an [`crate::store::AuditTx`] or [`crate::store::AuditRead`]
/// backend.
#[derive(Debug)]
pub struct StoreError {
    kind: StoreErrorKind,
    context: &'static str,
    source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

impl StoreError {
    /// A store error of `kind` at step `context` (a static description such
    /// as `"insert audit_record"`).
    #[must_use]
    pub const fn new(kind: StoreErrorKind, context: &'static str) -> Self {
        Self {
            kind,
            context,
            source: None,
        }
    }

    /// Attaches the backend's own error as the source.
    #[must_use]
    pub fn with_source(mut self, source: impl Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// The kind of failure.
    #[must_use]
    pub const fn kind(&self) -> StoreErrorKind {
        self.kind
    }

    /// The step that failed.
    #[must_use]
    pub const fn context(&self) -> &'static str {
        self.context
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "audit store {} at {}", self.kind.as_str(), self.context)
    }
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref().map(|e| e as &(dyn Error + 'static))
    }
}

/// Errors from `usgp-audit`.
#[derive(Debug)]
#[non_exhaustive]
pub enum AuditError {
    /// A draft field is not acceptable. Names the field only.
    InvalidDraft {
        /// Which field.
        field: &'static str,
        /// Why it was refused.
        reason: &'static str,
    },
    /// The chain has no genesis record yet; call
    /// [`crate::chain::AuditChain::ensure_genesis`] first.
    NotInitialised,
    /// A second genesis record was requested.
    AlreadyInitialised,
    /// The next sequence number would exceed `i64::MAX` (the `bigint`
    /// column range).
    ChainFull,
    /// The system clock is before 1970 or beyond the `i64` microsecond
    /// range.
    Clock,
    /// A configuration value is out of range.
    Config {
        /// Which setting.
        what: &'static str,
        /// Why it was refused.
        reason: &'static str,
    },
    /// A record field cannot be encoded (length above `u32::MAX - 1`).
    Encoding {
        /// Which field.
        field: &'static str,
    },
    /// The storage backend failed. The action must be refused
    /// (decision 0015 item 1).
    Store(StoreError),
    /// Signing or verification failed in `usgp-crypto`.
    Crypto(CryptoError),
}

impl fmt::Display for AuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDraft { field, reason } => {
                write!(f, "invalid audit draft field {field}: {reason}")
            }
            Self::NotInitialised => f.write_str("audit chain has no genesis record"),
            Self::AlreadyInitialised => f.write_str("audit chain already has a genesis record"),
            Self::ChainFull => f.write_str("audit chain sequence space exhausted"),
            Self::Clock => f.write_str("system clock outside the audit timestamp range"),
            Self::Config { what, reason } => write!(f, "invalid audit setting {what}: {reason}"),
            Self::Encoding { field } => write!(f, "audit record field {field} cannot be encoded"),
            Self::Store(e) => write!(f, "{e}"),
            Self::Crypto(e) => write!(f, "audit crypto failure: {e}"),
        }
    }
}

impl Error for AuditError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(e) => Some(e),
            Self::Crypto(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StoreError> for AuditError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<CryptoError> for AuditError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_error_display_and_source() {
        let inner = std::io::Error::other("disk");
        let e =
            StoreError::new(StoreErrorKind::Unavailable, "insert audit_record").with_source(inner);
        assert_eq!(
            e.to_string(),
            "audit store unavailable at insert audit_record"
        );
        assert!(e.source().is_some());
        assert_eq!(e.kind(), StoreErrorKind::Unavailable);
        let a = AuditError::from(e);
        assert!(a.source().is_some());
        assert!(a.to_string().contains("unavailable"));
    }

    #[test]
    fn draft_error_names_field_only() {
        let e = AuditError::InvalidDraft {
            field: "event",
            reason: "not a dotted lowercase name",
        };
        assert_eq!(
            e.to_string(),
            "invalid audit draft field event: not a dotted lowercase name"
        );
    }
}
