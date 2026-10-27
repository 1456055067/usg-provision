//! API configuration: request limits, content-store settings and their
//! secure defaults (plan M2 sections 3.2 and 3.5).
//!
//! `usgp-server` (WU-7) maps `server.toml` onto [`ApiConfig`] and calls
//! [`ApiConfig::validate`] before start-up; an invalid value refuses
//! start-up there.

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 (Configuration Settings) - secure defaults; every
//   value range-checked.
// - NIST 800-53: SC-5 (Denial-of-Service Protection) - header, body,
//   connection (total and per source), upload and audit-volume caps;
//   idle (progress-based) timeouts.
// - NIST 800-53: AC-12, SC-23 - connection lifetime cap.
// - SPEC: specs/os-images.md#REQ-IMG-031 (stated upload limit, at most
//   1 TiB here), #REQ-IMG-032 (progress-based timeouts, never a total
//   deadline)
// - SPEC: specs/preinstall-env.md#REQ-PE-009 (known-bad kit list)

use std::path::PathBuf;
use std::time::Duration;

use usgp_image::WimLimits;
use usgp_proto::KitVersion;
use usgp_proto::limits::{DEFAULT_MAX_JSON_BYTES, MAX_CONTENT_BYTES};

/// Default `content.max_upload_bytes`: 32 GiB (plan section 3.5).
pub const DEFAULT_MAX_UPLOAD_BYTES: u64 = 32 * 1024 * 1024 * 1024;

/// Request and connection limits (plan section 3.2, "Request limits").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiLimits {
    /// Time allowed for a whole request head (10 s).
    pub header_timeout: Duration,
    /// Idle read or write timeout on a connection (120 s). Reset by any
    /// byte moved in either direction, so it is never a total deadline
    /// (REQ-IMG-032).
    pub idle_timeout: Duration,
    /// Time allowed for the TLS handshake (5 s; our choice, the plan
    /// names none). Short on purpose: a connection holds one of the
    /// `max_connections` slots while it handshakes (finding SEC-001
    /// residual, see the SC-5 POAM in `server.rs`).
    pub handshake_timeout: Duration,
    /// Largest JSON request body (64 KiB).
    pub max_json_bytes: usize,
    /// Concurrent connections (64).
    pub max_connections: usize,
    /// Concurrent connections from one source (IPv4 address or IPv6 /64)
    /// (16; finding SEC-001).
    pub max_connections_per_source: usize,
    /// Concurrent TLS handshakes from one source (8).
    pub max_handshakes_per_source: usize,
    /// Connection slots that only connections with a validated client
    /// certificate may hold after the handshake (16). A connection without
    /// a certificate that finds the rest full is closed after the
    /// handshake.
    pub reserved_cert_connections: usize,
    /// Longest life of one connection (300 s). After it the connection is
    /// closed once the request in progress (if any) completes, so every
    /// operator reconnects and is checked against the current CRLs
    /// (findings SEC-007, NIST-010).
    pub max_connection_age: Duration,
    /// Request header fields (64).
    pub max_headers: usize,
    /// Request head size, start line included (16 KiB).
    pub max_header_bytes: usize,
}

impl Default for ApiLimits {
    fn default() -> Self {
        Self {
            header_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(120),
            handshake_timeout: Duration::from_secs(5),
            max_json_bytes: DEFAULT_MAX_JSON_BYTES,
            max_connections: 64,
            max_connections_per_source: 16,
            max_handshakes_per_source: 8,
            reserved_cert_connections: 16,
            max_connection_age: Duration::from_secs(300),
            max_headers: 64,
            max_header_bytes: 16 * 1024,
        }
    }
}

/// Content-store settings (`[content]`, plan section 3.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentConfig {
    /// Root directory (0700, service user). Holds `staging/` and
    /// `objects/`.
    pub root: PathBuf,
    /// Largest upload accepted, stated by `GET /v1/limits`.
    pub max_upload_bytes: u64,
    /// Open upload sessions allowed in total.
    pub max_open_uploads: u64,
    /// Open upload sessions allowed per operator.
    pub max_open_uploads_per_operator: u64,
    /// Longest pause between body bytes of an upload (300 s). The
    /// connection's `idle_timeout` also applies; the shorter one wins.
    pub upload_idle_timeout: Duration,
    /// How long a session waits for its body before it expires (24 h).
    pub upload_session_ttl: Duration,
    /// Checks run at the same time (1).
    pub check_concurrency: usize,
    /// A check that makes no progress for this long fails (600 s;
    /// REQ-IMG-021).
    pub check_stall_timeout: Duration,
}

impl ContentConfig {
    /// Defaults for a content root.
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
            max_open_uploads: 4,
            max_open_uploads_per_operator: 2,
            upload_idle_timeout: Duration::from_secs(300),
            upload_session_ttl: Duration::from_secs(86_400),
            check_concurrency: 1,
            check_stall_timeout: Duration::from_secs(600),
        }
    }
}

/// Everything the API needs besides its store, keys and audit chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiConfig {
    /// Request and connection limits.
    pub limits: ApiLimits,
    /// Content store.
    pub content: ContentConfig,
    /// Anonymous unauthenticated audit records (no certificate, TLS
    /// protocol failure, handshake timeout) per source (IPv4 address or
    /// IPv6 /64) per minute (10). Refusals over a cap are still refused and
    /// are summarised every 60 s as `auth.unauthenticated.summary`.
    pub unauth_records_per_source_per_min: u32,
    /// Anonymous unauthenticated audit records per minute in total (300).
    pub unauth_records_global_per_min: u32,
    /// Audit records of refusals that presented a certificate (unknown,
    /// disabled, or failing validation) per source per minute (60).
    pub credential_failure_records_per_source_per_min: u32,
    /// The same in total per minute (600).
    pub credential_failure_records_global_per_min: u32,
    /// PE kit versions known to be bad (`pe.known_bad_kit_versions`;
    /// default empty, REQ-PE-009: no source names one).
    pub known_bad_kit_versions: Vec<KitVersion>,
    /// WIM check limits (`[wim]` overrides).
    pub wim_limits: WimLimits,
}

/// Audit writers besides connections and content checks: the maintenance
/// task (summary, upload expiry, checkpoint timer) and the server's own
/// lifecycle events (start, stop, CRL reload).
pub const BACKGROUND_AUDIT_WRITERS: usize = 2;

impl ApiConfig {
    /// The most tasks that can append audit records at the same time:
    /// `api.max_connections` + `content.check_concurrency` +
    /// [`BACKGROUND_AUDIT_WRITERS`]. `audit verify` derives its checkpoint
    /// slack from it (finding SEC-015,
    /// `usgp_audit::checkpoint_slack_records`).
    #[must_use]
    pub fn max_audit_writers(&self) -> u64 {
        let n = self
            .limits
            .max_connections
            .saturating_add(self.content.check_concurrency)
            .saturating_add(BACKGROUND_AUDIT_WRITERS);
        u64::try_from(n).unwrap_or(u64::MAX)
    }

    /// Defaults with the given content root.
    #[must_use]
    pub fn new(content_root: PathBuf) -> Self {
        Self {
            limits: ApiLimits::default(),
            content: ContentConfig::new(content_root),
            unauth_records_per_source_per_min: 10,
            unauth_records_global_per_min: 300,
            credential_failure_records_per_source_per_min: 60,
            credential_failure_records_global_per_min: 600,
            known_bad_kit_versions: Vec::new(),
            wim_limits: WimLimits::DEFAULT,
        }
    }

    /// Checks every value against its allowed range.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming the first bad setting.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let l = &self.limits;
        let c = &self.content;
        let secs = |d: Duration, lo: u64, hi: u64| (lo..=hi).contains(&d.as_secs());
        let checks: [(bool, &'static str, &'static str); 13] = [
            (
                secs(l.header_timeout, 1, 300),
                "api.header_timeout_s",
                "1 to 300",
            ),
            (
                secs(l.idle_timeout, 1, 3600),
                "api.idle_timeout_s",
                "1 to 3600",
            ),
            (
                secs(l.handshake_timeout, 1, 300),
                "api.handshake_timeout_s",
                "1 to 300",
            ),
            (
                (1024..=1024 * 1024).contains(&l.max_json_bytes),
                "api.max_json_bytes",
                "1024 to 1048576",
            ),
            (
                (1..=4096).contains(&l.max_connections),
                "api.max_connections",
                "1 to 4096",
            ),
            (
                (8..=256).contains(&l.max_headers),
                "api.max_headers",
                "8 to 256",
            ),
            (
                (8192..=1024 * 1024).contains(&l.max_header_bytes),
                "api.max_header_bytes",
                "8192 to 1048576",
            ),
            (
                (1..=MAX_CONTENT_BYTES).contains(&c.max_upload_bytes),
                "content.max_upload_bytes",
                "1 to 1099511627776 (1 TiB, the manifest limit)",
            ),
            (
                (1..=1024).contains(&c.max_open_uploads)
                    && (1..=c.max_open_uploads).contains(&c.max_open_uploads_per_operator),
                "content.max_open_uploads",
                "1 to 1024, and per operator 1 to the total",
            ),
            (
                secs(c.upload_idle_timeout, 1, 3600),
                "content.upload_idle_timeout_s",
                "1 to 3600",
            ),
            (
                secs(c.upload_session_ttl, 60, 7 * 86_400),
                "content.upload_session_ttl_s",
                "60 to 604800",
            ),
            (
                (1..=64).contains(&c.check_concurrency),
                "content.check_concurrency",
                "1 to 64",
            ),
            (
                secs(c.check_stall_timeout, 1, 86_400),
                "content.check_stall_timeout_s",
                "1 to 86400",
            ),
        ];
        for (ok, setting, range) in checks {
            if !ok {
                return Err(ConfigError { setting, range });
            }
        }
        let more: [(bool, &'static str, &'static str); 8] = [
            (
                (1..=l.max_connections).contains(&l.max_connections_per_source),
                "api.max_connections_per_source",
                "1 to api.max_connections",
            ),
            (
                (1..=l.max_connections_per_source).contains(&l.max_handshakes_per_source),
                "api.max_handshakes_per_source",
                "1 to api.max_connections_per_source",
            ),
            (
                l.reserved_cert_connections < l.max_connections,
                "api.reserved_cert_connections",
                "0 to api.max_connections - 1",
            ),
            (
                secs(l.max_connection_age, 1, 86_400),
                "api.max_connection_age_s",
                "1 to 86400",
            ),
            (
                (1..=10_000).contains(&self.unauth_records_per_source_per_min),
                "audit.unauth_records_per_source_per_min",
                "1 to 10000",
            ),
            (
                (1..=100_000).contains(&self.unauth_records_global_per_min),
                "audit.unauth_records_global_per_min",
                "1 to 100000",
            ),
            (
                (1..=10_000).contains(&self.credential_failure_records_per_source_per_min),
                "audit.credential_failure_records_per_source_per_min",
                "1 to 10000",
            ),
            (
                (1..=100_000).contains(&self.credential_failure_records_global_per_min),
                "audit.credential_failure_records_global_per_min",
                "1 to 100000",
            ),
        ];
        for (ok, setting, range) in more {
            if !ok {
                return Err(ConfigError { setting, range });
            }
        }
        if !c.root.is_absolute() {
            return Err(ConfigError {
                setting: "content.root",
                range: "an absolute path",
            });
        }
        Ok(())
    }
}

impl ApiConfig {
    /// The unauthenticated audit caps.
    #[must_use]
    pub fn unauth_caps(&self) -> crate::authn::UnauthCaps {
        crate::authn::UnauthCaps {
            anonymous_per_source: self.unauth_records_per_source_per_min,
            anonymous_global: self.unauth_records_global_per_min,
            credential_per_source: self.credential_failure_records_per_source_per_min,
            credential_global: self.credential_failure_records_global_per_min,
        }
    }
}

/// A configuration value outside its range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("setting {setting} is out of range; it must be {range}")]
pub struct ConfigError {
    /// The setting.
    pub setting: &'static str,
    /// The allowed range.
    pub range: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid_and_match_the_plan() {
        let c = ApiConfig::new(PathBuf::from("/var/lib/usgp-server/content"));
        c.validate().unwrap();
        assert_eq!(c.limits.max_json_bytes, 65_536);
        assert_eq!(c.limits.max_connections, 64);
        assert_eq!(c.content.max_upload_bytes, 34_359_738_368);
        assert_eq!(c.content.max_open_uploads, 4);
        assert_eq!(c.content.max_open_uploads_per_operator, 2);
        assert_eq!(c.unauth_records_per_source_per_min, 10);
        assert_eq!(c.limits.max_connections_per_source, 16);
        assert_eq!(c.limits.max_connection_age, Duration::from_secs(300));
        assert_eq!(c.limits.handshake_timeout, Duration::from_secs(5));
        // SEC-015: 64 connections + 1 check + 2 background tasks.
        assert_eq!(c.max_audit_writers(), 67);
    }

    #[test]
    fn out_of_range_refused() {
        let base = ApiConfig::new(PathBuf::from("/srv/content"));
        let mut c = base.clone();
        c.content.max_upload_bytes = MAX_CONTENT_BYTES + 1;
        assert_eq!(
            c.validate().unwrap_err().setting,
            "content.max_upload_bytes"
        );
        let mut c = base.clone();
        c.content.max_open_uploads_per_operator = 5;
        assert!(c.validate().is_err());
        let mut c = base.clone();
        c.limits.idle_timeout = Duration::ZERO;
        assert!(c.validate().is_err());
        let mut c = base.clone();
        c.content.root = PathBuf::from("relative");
        assert_eq!(c.validate().unwrap_err().setting, "content.root");
        let mut c = base.clone();
        c.unauth_records_per_source_per_min = 0;
        assert!(c.validate().is_err());
        let mut c = base.clone();
        c.limits.reserved_cert_connections = c.limits.max_connections;
        assert_eq!(
            c.validate().unwrap_err().setting,
            "api.reserved_cert_connections"
        );
        let mut c = base.clone();
        c.limits.max_handshakes_per_source = c.limits.max_connections_per_source + 1;
        assert_eq!(
            c.validate().unwrap_err().setting,
            "api.max_handshakes_per_source"
        );
        let mut c = base;
        c.limits.max_connection_age = Duration::ZERO;
        assert_eq!(
            c.validate().unwrap_err().setting,
            "api.max_connection_age_s"
        );
    }
}
