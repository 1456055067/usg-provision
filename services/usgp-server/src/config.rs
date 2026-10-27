//! Server configuration `server.toml` (plan M2 section 3.5): document
//! types, defaults and validation.
//!
//! Loading is in two steps, as for the relay:
//!
//! 1. the TOML text (a trusted file of at most 64 KiB, read with
//!    [`usgp_common::config::read_trusted`]) becomes a [`ConfigDocument`]
//!    with every key optional and unknown keys refused
//!    (`deny_unknown_fields`);
//! 2. [`ServerConfig::from_document`] applies the defaults and every range
//!    rule.
//!
//! Files the configuration names (certificates, keys, CRLs) are not read
//! here; [`crate::material`] and [`crate::keys`] read them under the same
//! trust rules.
//!
//! There is **no password key** in `[database]` (decision 0012): a
//! `password`, `url` or connection-string key is an unknown key and refuses
//! start-up. [`usgp_db::assert_certificate_only`] runs again on the built
//! database settings.
//!
//! Every limit not listed in the plan's example, and every range, is
//! project design (CM-6), not product behaviour.

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 (Configuration Settings) - documented secure
//   defaults (loopback listener, TLS 1.2 minimum, CRLs required), strict
//   ranges; any violation refuses start-up (exit 78).
// - NIST 800-53: CM-7 (Least Functionality) - unknown keys refused.
// - NIST 800-53: SI-10 (Information Input Validation) - size bound,
//   every value range-checked, paths absolute.
// - NIST 800-53: CM-5 / SI-7 - the file is read with the trusted-file
//   rules (usgp_common::config::read_trusted).
// - NIST 800-53: IA-5(2) - certificate-only database login (decision 0012).
// - SPEC: specs/os-images.md#REQ-IMG-031 (stated upload limit, at most
//   1 TiB), #REQ-IMG-032; specs/preinstall-env.md#REQ-PE-009

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use usgp_api::ApiConfig;
use usgp_audit::CheckpointPolicy;
use usgp_common::Sha256Digest;
use usgp_common::config::{ConfigError, TrustPolicy, parse_toml, read_trusted};
use usgp_common::telemetry::{self, Level};
use usgp_crypto::tls::TlsMinVersion;
use usgp_image::WimLimits;
use usgp_proto::KitVersion;

/// Largest accepted configuration file.
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;
/// The only supported `schema_version`.
pub const SCHEMA_VERSION: i64 = 1;
/// Longest `node_name`.
pub const MAX_NODE_NAME_LEN: usize = 64;
/// Longest accepted path value, in bytes.
pub const MAX_PATH_LEN: usize = 4096;
/// Default listener: loopback only (secure default, plan section 3.5).
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8443";
/// Most `tls.client_crls` entries.
pub const MAX_CRL_FILES: usize = 64;
/// Most `tls.acceptable_policy_oids` entries.
pub const MAX_POLICY_OIDS: usize = 64;
/// Most `signing.previous_content_pubs` entries.
pub const MAX_PREVIOUS_CONTENT_PUBS: usize = 64;
/// Most `pe.known_bad_kit_versions` entries.
pub const MAX_KNOWN_BAD_KITS: usize = 256;
/// Default `tls.crl_reload_s` (plan section 3.5).
pub const DEFAULT_CRL_RELOAD_S: u64 = 300;
/// `application_name` reported to PostgreSQL.
pub const DB_APPLICATION_NAME: &str = "usgp-server";

// ---------------------------------------------------------------------------
// Document types (file layout; every key optional so defaults can apply)
// ---------------------------------------------------------------------------

/// The configuration file as written. Integers are `i64` (the TOML
/// integer type) so range checks see negative values too.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigDocument {
    /// `schema_version` (required, must be 1).
    pub schema_version: Option<i64>,
    /// AU-3 "where" label; the host name if absent.
    pub node_name: Option<String>,
    /// `[api]`.
    pub api: Option<ApiDocument>,
    /// `[tls]` (required).
    pub tls: Option<TlsDocument>,
    /// `[database]` (required).
    pub database: Option<DatabaseDocument>,
    /// `[content]` (required: `root`).
    pub content: Option<ContentDocument>,
    /// `[signing]` (required).
    pub signing: Option<SigningDocument>,
    /// `[audit]`.
    pub audit: Option<AuditDocument>,
    /// `[pe]`.
    pub pe: Option<PeDocument>,
    /// `[wim]`: lower the WIM check limits.
    pub wim: Option<WimDocument>,
    /// `[log]`.
    pub log: Option<LogDocument>,
}

/// `[api]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiDocument {
    /// Listener address (default `127.0.0.1:8443`).
    pub listen: Option<String>,
    /// Concurrent connections (default 64).
    pub max_connections: Option<i64>,
    /// Request head timeout in seconds (default 10).
    pub header_timeout_s: Option<i64>,
    /// Idle read/write timeout in seconds (default 120).
    pub idle_timeout_s: Option<i64>,
    /// TLS handshake timeout in seconds (default 5; finding SEC-001).
    pub handshake_timeout_s: Option<i64>,
    /// Largest JSON body (default 65536).
    pub max_json_bytes: Option<i64>,
    /// Request header fields (default 64).
    pub max_headers: Option<i64>,
    /// Request head size (default 16384).
    pub max_header_bytes: Option<i64>,
    /// Connections per source, IPv4 address or IPv6 /64 (default 16).
    pub max_connections_per_source: Option<i64>,
    /// TLS handshakes in progress per source (default 8).
    pub max_handshakes_per_source: Option<i64>,
    /// Slots only certificate holders may use (default a quarter of
    /// `max_connections`).
    pub reserved_cert_connections: Option<i64>,
    /// Longest connection life in seconds (default 300).
    pub max_connection_age_s: Option<i64>,
}

/// `[tls]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsDocument {
    /// Server certificate chain (PEM).
    pub cert_chain: Option<String>,
    /// Server private key (PKCS#8 PEM).
    pub private_key: Option<String>,
    /// `"1.2"` (default) or `"1.3"`.
    pub min_version: Option<String>,
    /// Operator CA certificates (PEM; required).
    pub client_trust_anchors: Option<String>,
    /// CRL files (PEM or DER; at least one required).
    pub client_crls: Option<Vec<String>>,
    /// Seconds between CRL reloads (default 300).
    pub crl_reload_s: Option<i64>,
    /// If non-empty, the operator certificate must assert one of these.
    pub acceptable_policy_oids: Option<Vec<String>>,
}

/// `[database]`. No password key exists (decision 0012).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseDocument {
    /// Host name or address.
    pub host: Option<String>,
    /// Port (default 5432).
    pub port: Option<i64>,
    /// Database name.
    pub dbname: Option<String>,
    /// Role (the application role).
    pub user: Option<String>,
    /// Database server CA (PEM).
    pub server_ca: Option<String>,
    /// Name the server certificate must carry (default: `host`).
    pub server_name: Option<String>,
    /// Client certificate (PEM).
    pub client_cert: Option<String>,
    /// Client key (PKCS#8 PEM).
    pub client_key: Option<String>,
    /// Pool size (default 8).
    pub pool_size: Option<i64>,
    /// Connect timeout in seconds (default 10).
    pub connect_timeout_s: Option<i64>,
    /// `[database.admin]`: the administrative role used only by local
    /// administrative commands (decision 0016).
    pub admin: Option<DatabaseAdminDocument>,
}

/// `[database.admin]`: role and client certificate of the administrative
/// role (decision 0016). No password key exists (decision 0012).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseAdminDocument {
    /// Role name (for example `usgp_admin`).
    pub user: Option<String>,
    /// Client certificate (PEM).
    pub client_cert: Option<String>,
    /// Client key (PKCS#8 PEM; readable by root only).
    pub client_key: Option<String>,
}

/// `[content]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentDocument {
    /// Content root (0700, owned by the service uid).
    pub root: Option<String>,
    /// Largest upload (default 32 GiB; at most 1 TiB).
    pub max_upload_bytes: Option<i64>,
    /// Open upload sessions (default 4).
    pub max_open_uploads: Option<i64>,
    /// Open upload sessions per operator (default 2).
    pub max_open_uploads_per_operator: Option<i64>,
    /// Longest pause in an upload body, seconds (default 300).
    pub upload_idle_timeout_s: Option<i64>,
    /// Session lifetime before the body, seconds (default 86400).
    pub upload_session_ttl_s: Option<i64>,
    /// Concurrent checks (default 1).
    pub check_concurrency: Option<i64>,
    /// Check stall timeout, seconds (default 600).
    pub check_stall_timeout_s: Option<i64>,
}

/// `[signing]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningDocument {
    /// Content signing key (PKCS#8 PEM).
    pub content_key: Option<String>,
    /// Audit checkpoint signing key (PKCS#8 PEM).
    pub audit_key: Option<String>,
    /// Public keys of earlier content keys (SPKI PEM), so manifests they
    /// signed still verify after a rotation (plan section 5.2).
    pub previous_content_pubs: Option<Vec<String>>,
}

/// `[audit]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditDocument {
    /// Checkpoint after this many records (default 100).
    pub checkpoint_every_records: Option<i64>,
    /// Checkpoint after this many seconds with new records (default 60).
    pub checkpoint_every_s: Option<i64>,
    /// Checkpoint after this many seconds even with no new record
    /// (heartbeat; default 900, 60 to 86400; finding SEC-013).
    pub checkpoint_heartbeat_s: Option<i64>,
    /// Anonymous unauthenticated audit records per source per minute
    /// (default 10).
    pub unauth_records_per_source_per_min: Option<i64>,
    /// Anonymous unauthenticated audit records per minute in total
    /// (default 300).
    pub unauth_records_global_per_min: Option<i64>,
    /// Records of certificate-presenting failures per source per minute
    /// (default 60).
    pub credential_failure_records_per_source_per_min: Option<i64>,
    /// The same in total per minute (default 600).
    pub credential_failure_records_global_per_min: Option<i64>,
}

/// `[pe]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeDocument {
    /// Kit versions that get a warning (REQ-PE-009; default empty).
    pub known_bad_kit_versions: Option<Vec<String>>,
}

/// `[wim]`: each value may only lower the built-in limit.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WimDocument {
    /// See [`WimLimits::max_xml_bytes`].
    pub max_xml_bytes: Option<i64>,
    /// See [`WimLimits::max_images`].
    pub max_images: Option<i64>,
    /// See [`WimLimits::max_lookup_bytes`].
    pub max_lookup_bytes: Option<i64>,
    /// See [`WimLimits::max_metadata_bytes`].
    pub max_metadata_bytes: Option<i64>,
    /// See [`WimLimits::max_metadata_total_bytes`].
    pub max_metadata_total_bytes: Option<i64>,
    /// See [`WimLimits::max_name_chars`].
    pub max_name_chars: Option<i64>,
    /// See [`WimLimits::max_xml_depth`].
    pub max_xml_depth: Option<i64>,
    /// See [`WimLimits::max_xml_elements_per_image`].
    pub max_xml_elements_per_image: Option<i64>,
    /// See [`WimLimits::max_integrity_bytes`].
    pub max_integrity_bytes: Option<i64>,
}

/// `[log]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogDocument {
    /// `error`, `warn`, `info` (default) or `debug`.
    pub level: Option<String>,
}

// ---------------------------------------------------------------------------
// Validated configuration
// ---------------------------------------------------------------------------

/// `[tls]`, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
    /// Server certificate chain.
    pub cert_chain: PathBuf,
    /// Server private key.
    pub private_key: PathBuf,
    /// Lowest TLS version.
    pub min_version: TlsMinVersion,
    /// Operator trust anchors.
    pub client_trust_anchors: PathBuf,
    /// CRL files (at least one).
    pub client_crls: Vec<PathBuf>,
    /// CRL reload interval.
    pub crl_reload: Duration,
    /// Acceptable end-entity policy OIDs (empty: any).
    pub acceptable_policy_oids: Vec<String>,
}

/// `[database]`, validated (paths only; the files are read later).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseConfig {
    /// Host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Database.
    pub dbname: String,
    /// Application role.
    pub user: String,
    /// Server CA file.
    pub server_ca: PathBuf,
    /// TLS server name (default: host).
    pub server_name: Option<String>,
    /// Client certificate file.
    pub client_cert: PathBuf,
    /// Client key file.
    pub client_key: PathBuf,
    /// Pool size.
    pub pool_size: usize,
    /// Connect timeout.
    pub connect_timeout: Duration,
    /// The administrative role (decision 0016), if configured. Local
    /// administrative commands refuse to run without it.
    pub admin: Option<DatabaseAdminConfig>,
}

/// `[database.admin]`, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatabaseAdminConfig {
    /// Role name.
    pub user: String,
    /// Client certificate file.
    pub client_cert: PathBuf,
    /// Client key file.
    pub client_key: PathBuf,
}

/// `[signing]`, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningConfig {
    /// Content signing key file.
    pub content_key: PathBuf,
    /// Audit signing key file.
    pub audit_key: PathBuf,
    /// Earlier content public keys.
    pub previous_content_pubs: Vec<PathBuf>,
}

/// The validated configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    /// AU-3 "where" label (configured, or the host name).
    pub node_name: String,
    /// Listener address.
    pub listen: SocketAddr,
    /// API limits, content store and WIM limits (`usgp-api`).
    pub api: ApiConfig,
    /// TLS.
    pub tls: TlsConfig,
    /// Database.
    pub database: DatabaseConfig,
    /// Signing keys.
    pub signing: SigningConfig,
    /// Audit checkpoint cadence.
    pub checkpoint: CheckpointPolicy,
    /// Log level.
    pub log_level: Level,
}

/// A configuration value was refused. Names the key; never echoes a
/// value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{key} {reason}")]
pub struct ConfigInvalid {
    /// The key (for example `tls.client_crls[1]`).
    pub key: String,
    /// What is wrong.
    pub reason: String,
}

fn invalid(key: impl Into<String>, reason: impl Into<String>) -> ConfigInvalid {
    ConfigInvalid {
        key: key.into(),
        reason: reason.into(),
    }
}

/// Why the configuration could not be loaded (exit 78).
#[derive(Debug, thiserror::Error)]
pub enum ConfigLoadError {
    /// The file could not be read, failed a trust rule, or did not parse.
    #[error(transparent)]
    File(#[from] ConfigError),
    /// A value is missing or out of range.
    #[error("invalid configuration: {0}")]
    Invalid(#[from] ConfigInvalid),
}

impl ConfigLoadError {
    /// The key or rule to name in the refusal record.
    #[must_use]
    pub fn field(&self) -> String {
        match self {
            Self::File(_) => "file".to_owned(),
            Self::Invalid(i) => i.key.clone(),
        }
    }
}

/// A loaded configuration and the SHA-256 of its exact text (recorded in
/// `server.start`).
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    /// The file.
    pub path: PathBuf,
    /// SHA-256 of the file text.
    pub sha256: Sha256Digest,
    /// The validated configuration.
    pub config: ServerConfig,
}

/// Reads and validates the configuration file under `policy`.
///
/// # Errors
///
/// [`ConfigLoadError`].
pub fn load(path: &Path, policy: &TrustPolicy) -> Result<LoadedConfig, ConfigLoadError> {
    let text = read_trusted(path, MAX_CONFIG_BYTES, policy)?;
    let sha256 = usgp_crypto::sha256(text.as_bytes());
    let doc: ConfigDocument = parse_toml(&text)?;
    let config = ServerConfig::from_document(&doc, usgp_common::process::hostname())?;
    Ok(LoadedConfig {
        path: path.to_path_buf(),
        sha256,
        config,
    })
}

/// Parses TOML text (no file access; tests and tools).
///
/// # Errors
///
/// [`ConfigLoadError`].
pub fn parse_text(text: &str, hostname: Option<String>) -> Result<ServerConfig, ConfigLoadError> {
    let doc: ConfigDocument = parse_toml(text)?;
    Ok(ServerConfig::from_document(&doc, hostname)?)
}

// ---------------------------------------------------------------------------
// Value helpers
// ---------------------------------------------------------------------------

/// A non-negative integer within `lo..=hi`, or `default`.
fn int(key: &str, v: Option<i64>, default: u64, lo: u64, hi: u64) -> Result<u64, ConfigInvalid> {
    let Some(v) = v else {
        return Ok(default);
    };
    let n = u64::try_from(v).map_err(|_| invalid(key, format!("must be {lo} to {hi}")))?;
    if !(lo..=hi).contains(&n) {
        return Err(invalid(key, format!("must be {lo} to {hi}")));
    }
    Ok(n)
}

/// A `usize` default as `u64` (saturating; defaults are small).
fn wide_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn to_usize(key: &str, n: u64) -> Result<usize, ConfigInvalid> {
    usize::try_from(n).map_err(|_| invalid(key, "is too large for this platform"))
}

fn to_u32(key: &str, n: u64) -> Result<u32, ConfigInvalid> {
    u32::try_from(n).map_err(|_| invalid(key, "is too large"))
}

fn absolute_path(key: &str, v: Option<&String>) -> Result<PathBuf, ConfigInvalid> {
    let v = v.ok_or_else(|| invalid(key, "is required"))?;
    path_value(key, v)
}

fn path_value(key: &str, v: &str) -> Result<PathBuf, ConfigInvalid> {
    if v.is_empty() || v.len() > MAX_PATH_LEN || v.contains('\0') {
        return Err(invalid(
            key,
            "must be an absolute path of 1 to 4096 bytes without NUL",
        ));
    }
    let p = PathBuf::from(v);
    if !p.is_absolute() {
        return Err(invalid(key, "must be an absolute path"));
    }
    Ok(p)
}

fn required_text(key: &str, v: Option<&String>) -> Result<String, ConfigInvalid> {
    match v {
        Some(s) if !s.is_empty() => Ok(s.clone()),
        Some(_) => Err(invalid(key, "must not be empty")),
        None => Err(invalid(key, "is required")),
    }
}

fn node_name_ok(n: &str) -> bool {
    let len = n.chars().count();
    (1..=MAX_NODE_NAME_LEN).contains(&len) && !n.chars().any(char::is_control)
}

impl ServerConfig {
    /// Applies defaults and validates every rule. `hostname` is the
    /// fallback `node_name`.
    ///
    /// # Errors
    ///
    /// [`ConfigInvalid`] naming the first failing key.
    pub fn from_document(
        doc: &ConfigDocument,
        hostname: Option<String>,
    ) -> Result<Self, ConfigInvalid> {
        match doc.schema_version {
            Some(SCHEMA_VERSION) => {}
            Some(_) => return Err(invalid("schema_version", "must be 1")),
            None => return Err(invalid("schema_version", "is required")),
        }
        let node_name = match (&doc.node_name, hostname) {
            (Some(n), _) if node_name_ok(n) => n.clone(),
            (Some(_), _) => {
                return Err(invalid(
                    "node_name",
                    "must be 1 to 64 characters without control characters",
                ));
            }
            (None, Some(h)) => h,
            (None, None) => {
                return Err(invalid(
                    "node_name",
                    "is required when the host name is not available",
                ));
            }
        };

        let content_doc = doc
            .content
            .as_ref()
            .ok_or_else(|| invalid("content", "is required"))?;
        let root = absolute_path("content.root", content_doc.root.as_ref())?;
        let mut api = ApiConfig::new(root);
        let listen = api_section(doc.api.as_ref(), &mut api)?;
        content_section(content_doc, &mut api)?;
        let audit_doc = doc.audit.clone().unwrap_or_default();
        let cap = |key: &str, v: Option<i64>, default: u32| {
            to_u32(key, int(key, v, u64::from(default), 0, u64::MAX)?)
        };
        api.unauth_records_per_source_per_min = cap(
            "audit.unauth_records_per_source_per_min",
            audit_doc.unauth_records_per_source_per_min,
            api.unauth_records_per_source_per_min,
        )?;
        api.unauth_records_global_per_min = cap(
            "audit.unauth_records_global_per_min",
            audit_doc.unauth_records_global_per_min,
            api.unauth_records_global_per_min,
        )?;
        api.credential_failure_records_per_source_per_min = cap(
            "audit.credential_failure_records_per_source_per_min",
            audit_doc.credential_failure_records_per_source_per_min,
            api.credential_failure_records_per_source_per_min,
        )?;
        api.credential_failure_records_global_per_min = cap(
            "audit.credential_failure_records_global_per_min",
            audit_doc.credential_failure_records_global_per_min,
            api.credential_failure_records_global_per_min,
        )?;
        if let Some(pe) = &doc.pe {
            let list = pe.known_bad_kit_versions.clone().unwrap_or_default();
            if list.len() > MAX_KNOWN_BAD_KITS {
                return Err(invalid(
                    "pe.known_bad_kit_versions",
                    "has more than 256 entries",
                ));
            }
            for (i, v) in list.iter().enumerate() {
                let kv = KitVersion::parse(v).map_err(|e| {
                    invalid(format!("pe.known_bad_kit_versions[{i}]"), e.to_string())
                })?;
                api.known_bad_kit_versions.push(kv);
            }
        }
        if let Some(w) = &doc.wim {
            api.wim_limits = wim_section(w)?;
        }
        api.validate()
            .map_err(|e| invalid(e.setting, format!("must be {}", e.range)))?;

        let tls = tls_section(doc.tls.as_ref())?;
        let database = database_section(doc.database.as_ref())?;
        let signing = signing_section(doc.signing.as_ref())?;
        let checkpoint = CheckpointPolicy {
            every_records: int(
                "audit.checkpoint_every_records",
                audit_doc.checkpoint_every_records,
                100,
                1,
                usgp_audit::checkpoint::MAX_EVERY_RECORDS,
            )?,
            every: Duration::from_secs(int(
                "audit.checkpoint_every_s",
                audit_doc.checkpoint_every_s,
                60,
                1,
                usgp_audit::checkpoint::MAX_EVERY.as_secs(),
            )?),
            heartbeat: Duration::from_secs(int(
                "audit.checkpoint_heartbeat_s",
                audit_doc.checkpoint_heartbeat_s,
                usgp_audit::checkpoint::DEFAULT_HEARTBEAT.as_secs(),
                usgp_audit::checkpoint::MIN_HEARTBEAT.as_secs(),
                usgp_audit::checkpoint::MAX_HEARTBEAT.as_secs(),
            )?),
        };
        checkpoint
            .validate()
            .map_err(|e| invalid("audit", e.to_string()))?;
        let log_level = match doc.log.as_ref().and_then(|l| l.level.as_deref()) {
            None => Level::INFO,
            Some(t) => {
                telemetry::parse_level(t).map_err(|e| invalid("log.level", e.to_string()))?
            }
        };
        Ok(Self {
            node_name,
            listen,
            api,
            tls,
            database,
            signing,
            checkpoint,
            log_level,
        })
    }
}

/// `[api]` onto `api.limits`; returns the listener address.
fn api_section(
    doc: Option<&ApiDocument>,
    api: &mut ApiConfig,
) -> Result<SocketAddr, ConfigInvalid> {
    let d = doc.cloned().unwrap_or_default();
    let listen_text = d.listen.as_deref().unwrap_or(DEFAULT_LISTEN);
    let listen: SocketAddr = listen_text
        .parse()
        .map_err(|_| invalid("api.listen", "must be an IP address and port"))?;
    let l = &mut api.limits;
    // Ranges are checked by `ApiConfig::validate`; here only the
    // conversion (non-negative, fits) is checked.
    let wide = |key: &str, v: Option<i64>, default: u64| int(key, v, default, 0, u64::MAX);
    l.max_connections = to_usize(
        "api.max_connections",
        wide(
            "api.max_connections",
            d.max_connections,
            wide_u64(l.max_connections),
        )?,
    )?;
    l.header_timeout = Duration::from_secs(wide(
        "api.header_timeout_s",
        d.header_timeout_s,
        l.header_timeout.as_secs(),
    )?);
    l.idle_timeout = Duration::from_secs(wide(
        "api.idle_timeout_s",
        d.idle_timeout_s,
        l.idle_timeout.as_secs(),
    )?);
    l.handshake_timeout = Duration::from_secs(wide(
        "api.handshake_timeout_s",
        d.handshake_timeout_s,
        l.handshake_timeout.as_secs(),
    )?);
    l.max_json_bytes = to_usize(
        "api.max_json_bytes",
        wide(
            "api.max_json_bytes",
            d.max_json_bytes,
            wide_u64(l.max_json_bytes),
        )?,
    )?;
    l.max_headers = to_usize(
        "api.max_headers",
        wide("api.max_headers", d.max_headers, wide_u64(l.max_headers))?,
    )?;
    l.max_header_bytes = to_usize(
        "api.max_header_bytes",
        wide(
            "api.max_header_bytes",
            d.max_header_bytes,
            wide_u64(l.max_header_bytes),
        )?,
    )?;
    l.max_connections_per_source = to_usize(
        "api.max_connections_per_source",
        wide(
            "api.max_connections_per_source",
            d.max_connections_per_source,
            wide_u64(l.max_connections_per_source.min(l.max_connections)),
        )?,
    )?;
    l.max_handshakes_per_source = to_usize(
        "api.max_handshakes_per_source",
        wide(
            "api.max_handshakes_per_source",
            d.max_handshakes_per_source,
            wide_u64(
                l.max_handshakes_per_source
                    .min(l.max_connections_per_source),
            ),
        )?,
    )?;
    // Default: a quarter of the connection slots.
    l.reserved_cert_connections = to_usize(
        "api.reserved_cert_connections",
        wide(
            "api.reserved_cert_connections",
            d.reserved_cert_connections,
            wide_u64(l.max_connections / 4),
        )?,
    )?;
    l.max_connection_age = Duration::from_secs(wide(
        "api.max_connection_age_s",
        d.max_connection_age_s,
        l.max_connection_age.as_secs(),
    )?);
    Ok(listen)
}

fn content_section(d: &ContentDocument, api: &mut ApiConfig) -> Result<(), ConfigInvalid> {
    let c = &mut api.content;
    let wide = |key: &str, v: Option<i64>, default: u64| int(key, v, default, 0, u64::MAX);
    c.max_upload_bytes = wide(
        "content.max_upload_bytes",
        d.max_upload_bytes,
        c.max_upload_bytes,
    )?;
    c.max_open_uploads = wide(
        "content.max_open_uploads",
        d.max_open_uploads,
        c.max_open_uploads,
    )?;
    c.max_open_uploads_per_operator = wide(
        "content.max_open_uploads_per_operator",
        d.max_open_uploads_per_operator,
        c.max_open_uploads_per_operator,
    )?;
    c.upload_idle_timeout = Duration::from_secs(wide(
        "content.upload_idle_timeout_s",
        d.upload_idle_timeout_s,
        c.upload_idle_timeout.as_secs(),
    )?);
    c.upload_session_ttl = Duration::from_secs(wide(
        "content.upload_session_ttl_s",
        d.upload_session_ttl_s,
        c.upload_session_ttl.as_secs(),
    )?);
    c.check_concurrency = to_usize(
        "content.check_concurrency",
        wide(
            "content.check_concurrency",
            d.check_concurrency,
            wide_u64(c.check_concurrency),
        )?,
    )?;
    c.check_stall_timeout = Duration::from_secs(wide(
        "content.check_stall_timeout_s",
        d.check_stall_timeout_s,
        c.check_stall_timeout.as_secs(),
    )?);
    Ok(())
}

/// `[wim]`: every value 1 to the built-in default (lowering only).
fn wim_section(d: &WimDocument) -> Result<WimLimits, ConfigInvalid> {
    let def = WimLimits::DEFAULT;
    let lower = |key: &str, v: Option<i64>, default: u64| int(key, v, default, 1, default);
    Ok(WimLimits {
        max_xml_bytes: lower("wim.max_xml_bytes", d.max_xml_bytes, def.max_xml_bytes)?,
        max_images: to_u32(
            "wim.max_images",
            lower("wim.max_images", d.max_images, u64::from(def.max_images))?,
        )?,
        max_lookup_bytes: lower(
            "wim.max_lookup_bytes",
            d.max_lookup_bytes,
            def.max_lookup_bytes,
        )?,
        max_metadata_bytes: lower(
            "wim.max_metadata_bytes",
            d.max_metadata_bytes,
            def.max_metadata_bytes,
        )?,
        max_metadata_total_bytes: lower(
            "wim.max_metadata_total_bytes",
            d.max_metadata_total_bytes,
            def.max_metadata_total_bytes,
        )?,
        max_name_chars: to_usize(
            "wim.max_name_chars",
            lower(
                "wim.max_name_chars",
                d.max_name_chars,
                wide_u64(def.max_name_chars),
            )?,
        )?,
        max_xml_depth: to_usize(
            "wim.max_xml_depth",
            lower(
                "wim.max_xml_depth",
                d.max_xml_depth,
                wide_u64(def.max_xml_depth),
            )?,
        )?,
        max_xml_elements_per_image: to_usize(
            "wim.max_xml_elements_per_image",
            lower(
                "wim.max_xml_elements_per_image",
                d.max_xml_elements_per_image,
                wide_u64(def.max_xml_elements_per_image),
            )?,
        )?,
        max_integrity_bytes: lower(
            "wim.max_integrity_bytes",
            d.max_integrity_bytes,
            def.max_integrity_bytes,
        )?,
    })
}

fn tls_section(d: Option<&TlsDocument>) -> Result<TlsConfig, ConfigInvalid> {
    let d = d.ok_or_else(|| invalid("tls", "is required"))?;
    let min_version = match d.min_version.as_deref() {
        None => TlsMinVersion::Tls12,
        Some(t) => t
            .parse()
            .map_err(|_| invalid("tls.min_version", "must be \"1.2\" or \"1.3\""))?,
    };
    let crl_texts = d
        .client_crls
        .as_ref()
        .ok_or_else(|| invalid("tls.client_crls", "is required (at least one CRL file)"))?;
    if crl_texts.is_empty() {
        return Err(invalid(
            "tls.client_crls",
            "must list at least one CRL file",
        ));
    }
    if crl_texts.len() > MAX_CRL_FILES {
        return Err(invalid("tls.client_crls", "has more than 64 entries"));
    }
    let mut client_crls = Vec::with_capacity(crl_texts.len());
    for (i, t) in crl_texts.iter().enumerate() {
        client_crls.push(path_value(&format!("tls.client_crls[{i}]"), t)?);
    }
    let oids = d.acceptable_policy_oids.clone().unwrap_or_default();
    if oids.len() > MAX_POLICY_OIDS {
        return Err(invalid(
            "tls.acceptable_policy_oids",
            "has more than 64 entries",
        ));
    }
    usgp_crypto::x509::parse_policy_oids(&oids).map_err(|_| {
        invalid(
            "tls.acceptable_policy_oids",
            "must hold dotted object identifiers",
        )
    })?;
    Ok(TlsConfig {
        cert_chain: absolute_path("tls.cert_chain", d.cert_chain.as_ref())?,
        private_key: absolute_path("tls.private_key", d.private_key.as_ref())?,
        min_version,
        client_trust_anchors: absolute_path(
            "tls.client_trust_anchors",
            d.client_trust_anchors.as_ref(),
        )?,
        client_crls,
        crl_reload: Duration::from_secs(int(
            "tls.crl_reload_s",
            d.crl_reload_s,
            DEFAULT_CRL_RELOAD_S,
            1,
            86_400,
        )?),
        acceptable_policy_oids: oids,
    })
}

fn database_section(d: Option<&DatabaseDocument>) -> Result<DatabaseConfig, ConfigInvalid> {
    let d = d.ok_or_else(|| invalid("database", "is required"))?;
    let port = int("database.port", d.port, 5432, 1, 65_535)?;
    let server_name = match &d.server_name {
        Some(s) if s.is_empty() => {
            return Err(invalid("database.server_name", "must not be empty"));
        }
        other => other.clone(),
    };
    Ok(DatabaseConfig {
        host: required_text("database.host", d.host.as_ref())?,
        port: u16::try_from(port).map_err(|_| invalid("database.port", "must be 1 to 65535"))?,
        dbname: required_text("database.dbname", d.dbname.as_ref())?,
        user: required_text("database.user", d.user.as_ref())?,
        server_ca: absolute_path("database.server_ca", d.server_ca.as_ref())?,
        server_name,
        client_cert: absolute_path("database.client_cert", d.client_cert.as_ref())?,
        client_key: absolute_path("database.client_key", d.client_key.as_ref())?,
        pool_size: to_usize(
            "database.pool_size",
            int(
                "database.pool_size",
                d.pool_size,
                wide_u64(usgp_db::config::DEFAULT_POOL_SIZE),
                1,
                wide_u64(usgp_db::config::MAX_POOL_SIZE),
            )?,
        )?,
        connect_timeout: Duration::from_secs(int(
            "database.connect_timeout_s",
            d.connect_timeout_s,
            usgp_db::config::DEFAULT_CONNECT_TIMEOUT.as_secs(),
            1,
            300,
        )?),
        admin: d.admin.as_ref().map(admin_section).transpose()?,
    })
    .and_then(|c| {
        if let Some(a) = &c.admin {
            // Decision 0016: a separate role with its own certificate.
            if a.user == c.user {
                return Err(invalid(
                    "database.admin.user",
                    "must differ from database.user (a separate role)",
                ));
            }
            if a.client_key == c.client_key || a.client_cert == c.client_cert {
                return Err(invalid(
                    "database.admin.client_key",
                    "must be a different certificate and key from the application role's",
                ));
            }
        }
        Ok(c)
    })
}

fn admin_section(d: &DatabaseAdminDocument) -> Result<DatabaseAdminConfig, ConfigInvalid> {
    Ok(DatabaseAdminConfig {
        user: required_text("database.admin.user", d.user.as_ref())?,
        client_cert: absolute_path("database.admin.client_cert", d.client_cert.as_ref())?,
        client_key: absolute_path("database.admin.client_key", d.client_key.as_ref())?,
    })
}

fn signing_section(d: Option<&SigningDocument>) -> Result<SigningConfig, ConfigInvalid> {
    let d = d.ok_or_else(|| invalid("signing", "is required"))?;
    let content_key = absolute_path("signing.content_key", d.content_key.as_ref())?;
    let audit_key = absolute_path("signing.audit_key", d.audit_key.as_ref())?;
    if content_key == audit_key {
        return Err(invalid(
            "signing.audit_key",
            "must be a different file from signing.content_key (one key per purpose)",
        ));
    }
    let prev = d.previous_content_pubs.clone().unwrap_or_default();
    if prev.len() > MAX_PREVIOUS_CONTENT_PUBS {
        return Err(invalid(
            "signing.previous_content_pubs",
            "has more than 64 entries",
        ));
    }
    let mut previous_content_pubs = Vec::with_capacity(prev.len());
    for (i, t) in prev.iter().enumerate() {
        previous_content_pubs.push(path_value(
            &format!("signing.previous_content_pubs[{i}]"),
            t,
        )?);
    }
    Ok(SigningConfig {
        content_key,
        audit_key,
        previous_content_pubs,
    })
}
