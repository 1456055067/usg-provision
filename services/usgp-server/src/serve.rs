//! `serve`: start-up, serving, CRL reload and graceful shutdown (plan M2
//! sections 1.1, 3.4, 5.4, 5.6; order in the crate documentation).
//!
//! [`prepare`] reads every file and builds the TLS acceptor and keys (no
//! network, no database); `--check-config` stops there. [`run`] takes a
//! store that has already passed the database checks (`main`: certificate
//! only, ping, schema version) and serves until `shutdown` completes. It
//! is generic over [`usgp_db::Store`] so tests run it on the in-memory
//! store.

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-2 / AU-12 - server.start, server.start.refused,
//   server.stop, auth.tls.crl_reloaded; restart recovery audited by the API.
// - NIST 800-53: AU-9(3) - final signed checkpoint at clean shutdown.
// - NIST 800-53: IA-5(2) - CRLs reloaded every `tls.crl_reload_s`; a
//   failed reload keeps the previous acceptor, whose CRLs expire and then
//   refuse every certificate (fail closed). A reload that would lower an
//   issuer's cRLNumber is refused and audited (RFC 5280 §5.2.3; finding
//   SEC-007).
// - NIST 800-53: SC-12 - one key per purpose: content and audit keys must
//   differ; the M3 plan and boot-policy keys differ from both and from
//   each other; the code HMAC key is exactly 32 bytes.
// - NIST 800-53: SC-8, SC-13, CM-7 - the device listener (M3) runs only
//   when `device_api.enabled`, on its own server-authenticated FIPS TLS
//   configuration, and stops with the operator listener.
// - NIST 800-53: AC-12, AU-12 - device-session expiry and the lost-job
//   sweep run in the API's maintenance pass (both audited by usgp-api).
// - NIST 800-53: AC-6 / CM-5 - the server does not run as the uid that
//   owns its trusted files unless explicitly allowed; content root owned
//   by the service uid, mode 0700.
// - NIST 800-53: AC-6, AC-6(1) - the server refuses to start if it can
//   read the administrative database key (decision 0016; SEC-011).
// - SPEC: specs/os-images.md#REQ-IMG-021 (restart recovery);
//   specs/operator-access.md#REQ-RBAC-005, #REQ-AUD-005; decisions 0007,
//   0010, 0011, 0015; M3: specs/targeting.md#REQ-TGT-012, #REQ-TGT-014;
//   specs/progress.md#REQ-JOB-006; decisions 0016, 0018, 0020, 0021

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};
use usgp_api::{Api, ApiInitError, ContentKeys, ProvisioningKeys, TlsAcceptorHandle};
use usgp_audit::{AuditChain, Checkpointer, Detail, Outcome};
use usgp_common::config::TrustPolicy;
use usgp_crypto::tls::{DeviceServerTls, ServerTls, TlsMinVersion};
use usgp_crypto::{KeyId, VerifyingKey};
use usgp_db::Store;

use crate::config::{LoadedConfig, ProvisioningKeyFiles, ServerConfig, TlsConfig};
use crate::events::{self, RecordError, system_draft};
use crate::keys::{KeyLoadError, load_hmac_key, load_signing_key, load_verifying_key};
use crate::material::{CrlSet, MaterialError, build_device_tls, build_server_tls, read_crls};
use crate::{EXIT_CONFIG, EXIT_FAILURE};

/// Why the server refused to start or stopped with an error.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// Configuration invalid (exit 78).
    #[error(transparent)]
    Config(#[from] crate::config::ConfigLoadError),
    /// TLS or database files unusable (exit 78).
    #[error(transparent)]
    Material(#[from] MaterialError),
    /// A key file unusable (exit 78).
    #[error(transparent)]
    Key(#[from] KeyLoadError),
    /// A configuration or deployment rule refused start-up (exit 78).
    #[error("{field}: {reason}")]
    Refused {
        /// The key or option named.
        field: &'static str,
        /// Short reason code.
        reason: &'static str,
    },
    /// The database was unreachable or its schema is not the expected one
    /// (exit 1).
    #[error("database {stage} failed: {source}")]
    Database {
        /// Which step.
        stage: &'static str,
        /// The error (static text, no data).
        #[source]
        source: usgp_db::DbError,
    },
    /// The audit chain could not be written (exit 1).
    #[error("audit chain unavailable: {0}")]
    Audit(#[from] RecordError),
    /// The API could not be built (exit 78 for a configuration value,
    /// otherwise 1).
    #[error(transparent)]
    Api(#[from] ApiInitError),
    /// Restart recovery failed (exit 1).
    #[error("restart recovery failed: {0}")]
    Recovery(String),
    /// The listener could not be bound (exit 1).
    #[error("cannot listen on {addr}: {kind}")]
    Bind {
        /// The address.
        addr: SocketAddr,
        /// The I/O error kind.
        kind: std::io::ErrorKind,
    },
    /// Another runtime failure (exit 1).
    #[error("{0}")]
    Runtime(&'static str),
}

impl ServeError {
    /// The process exit status for this error.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Config(_) | Self::Material(_) | Self::Key(_) | Self::Refused { .. } => {
                EXIT_CONFIG
            }
            Self::Database {
                source: usgp_db::DbError::Config(_),
                ..
            } => EXIT_CONFIG,
            Self::Api(
                ApiInitError::Config(_) | ApiInitError::KeyNotTrusted | ApiInitError::KeyReuse,
            ) => EXIT_CONFIG,
            _ => EXIT_FAILURE,
        }
    }

    /// Short reason code for `server.start.refused`.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Config(_) => "config_invalid",
            Self::Material(_) | Self::Key(_) => "config_material_invalid",
            Self::Refused { reason, .. } => reason,
            Self::Database { stage, .. } => stage,
            Self::Audit(_) => "audit_unavailable",
            Self::Api(_) => "api_init_failed",
            Self::Recovery(_) => "recovery_failed",
            Self::Bind { .. } => "bind_failed",
            Self::Runtime(_) => "runtime_failure",
        }
    }

    /// The configuration key or option to name, if any.
    #[must_use]
    pub fn field(&self) -> Option<String> {
        match self {
            Self::Config(e) => Some(e.field()),
            Self::Material(e) => Some(e.key()),
            Self::Key(e) => Some(e.key().to_owned()),
            Self::Refused { field, .. } => Some((*field).to_owned()),
            Self::Api(ApiInitError::Config(c)) => Some(c.setting.to_owned()),
            _ => None,
        }
    }
}

/// Everything `serve` loads from files before touching the network.
#[derive(Debug)]
pub struct Prepared {
    /// The TLS acceptor.
    pub server_tls: ServerTls,
    /// The CRLs it was built with.
    pub crls: CrlSet,
    /// Content signing key and trusted content keys.
    pub content_keys: ContentKeys,
    /// Audit checkpoint signer.
    pub checkpointer: Checkpointer,
    /// Content key id.
    pub content_key_id: KeyId,
    /// Audit key id.
    pub audit_key_id: KeyId,
    /// The plan, boot-policy and code keys (M3), if configured.
    pub provisioning: Option<ProvisioningKeys>,
    /// The device listener's TLS configuration, if the listener is
    /// enabled.
    pub device_tls: Option<DeviceServerTls>,
}

/// Reads and checks every file the configuration names: keys (content and
/// audit must differ), earlier content public keys, the TLS chain, key,
/// trust anchors and CRLs. Builds the TLS acceptor (FIPS asserted).
///
/// # Errors
///
/// [`ServeError`] (exit 78).
pub fn prepare(cfg: &ServerConfig, policy: &TrustPolicy) -> Result<Prepared, ServeError> {
    let content = load_signing_key("signing.content_key", &cfg.signing.content_key, policy)?;
    let audit = load_signing_key("signing.audit_key", &cfg.signing.audit_key, policy)?;
    let content_key_id = content.key_id();
    let audit_key_id = audit.key_id();
    if content_key_id == audit_key_id {
        return Err(ServeError::Refused {
            field: "signing.audit_key",
            reason: "audit_key_equals_content_key",
        });
    }
    let mut trusted: Vec<VerifyingKey> = vec![content.verifying_key().clone()];
    for (i, p) in cfg.signing.previous_content_pubs.iter().enumerate() {
        let k = load_verifying_key(&format!("signing.previous_content_pubs[{i}]"), p, policy)?;
        if k.key_id() == audit_key_id {
            return Err(ServeError::Refused {
                field: "signing.previous_content_pubs",
                reason: "audit_key_trusted_for_content",
            });
        }
        trusted.push(k);
    }
    let content_keys = ContentKeys::new(content, trusted)?;
    let checkpointer =
        Checkpointer::new(audit, cfg.checkpoint).map_err(|_| ServeError::Refused {
            field: "audit",
            reason: "checkpoint_policy_invalid",
        })?;
    let crls = read_crls(&cfg.tls, policy)?;
    let server_tls = build_server_tls(&cfg.tls, &crls, policy)?;
    if !server_tls.is_fips() {
        return Err(ServeError::Runtime("the TLS configuration is not FIPS"));
    }
    let provisioning = cfg
        .provisioning
        .as_ref()
        .map(|files| load_provisioning_keys(files, &[content_key_id, audit_key_id], policy))
        .transpose()?;
    let device_tls = cfg
        .device_listener
        .as_ref()
        .map(|d| build_device_tls(d, policy))
        .transpose()?;
    if device_tls.as_ref().is_some_and(|t| !t.is_fips()) {
        return Err(ServeError::Runtime(
            "the device TLS configuration is not FIPS",
        ));
    }
    Ok(Prepared {
        server_tls,
        crls,
        content_keys,
        checkpointer,
        content_key_id,
        audit_key_id,
        provisioning,
        device_tls,
    })
}

/// Loads the plan and boot-policy signing keys and the code HMAC key
/// (M3 plan sections 3.9 and 5) under the trusted-file rules. One key,
/// one purpose: neither signing key may be the content or audit key
/// (`taken`), and they must differ from each other.
///
/// # Errors
///
/// [`ServeError`] (exit 78).
pub fn load_provisioning_keys(
    files: &ProvisioningKeyFiles,
    taken: &[KeyId],
    policy: &TrustPolicy,
) -> Result<ProvisioningKeys, ServeError> {
    let plan = load_signing_key("signing.plan_key", &files.plan_key, policy)?;
    let boot_policy = load_signing_key("signing.boot_policy_key", &files.boot_policy_key, policy)?;
    if taken.contains(&plan.key_id()) {
        return Err(ServeError::Refused {
            field: "signing.plan_key",
            reason: "plan_key_reused",
        });
    }
    if taken.contains(&boot_policy.key_id()) || boot_policy.key_id() == plan.key_id() {
        return Err(ServeError::Refused {
            field: "signing.boot_policy_key",
            reason: "boot_policy_key_reused",
        });
    }
    let hmac = load_hmac_key("codes.hmac_key", &files.code_hmac_key, policy)?;
    Ok(ProvisioningKeys::new(plan, boot_policy, hmac)?)
}

/// Process options of [`run`] from the command line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunOptions {
    /// Trusted-file policy (`--admin-uid`).
    pub trust: TrustPolicy,
    /// `--allow-shared-admin-uid` (recorded in `server.start`).
    pub allow_shared_admin_uid: bool,
    /// The service's effective uid, if known.
    pub service_uid: Option<u32>,
}

/// Whether `serve` must refuse to start because it would run as the
/// administrator uid that owns its trusted files (CM-5, AC-6; same rule
/// as the relay). Returns the reason label, or `None` to go ahead.
#[must_use]
pub fn shared_admin_uid_refusal(
    service_uid: Option<u32>,
    trust: &TrustPolicy,
    allow: bool,
) -> Option<&'static str> {
    let admin = trust.admin_uid.filter(|&u| u != 0)?;
    if allow {
        return None;
    }
    match service_uid {
        Some(uid) if uid == admin => Some("service_uid_is_admin_uid"),
        Some(_) => None,
        None => Some("service_uid_unknown"),
    }
}

/// Whether `serve` must refuse to start because it can read the
/// administrative database role's client key (`[database.admin]
/// client_key`; decision 0016 item 3, finding SEC-011). That key is the
/// control on operator management: the service account must never be
/// able to read it, so an API compromise cannot log in as `usgp_admin`.
/// The test is the real one: the server tries to open the file for
/// reading (so it also covers ACLs and running as root).
///
/// The owner (migration) role's key is never named in the configuration
/// (`migrate --owner-key`), so `serve` cannot check it; `migrate` refuses
/// it unless it is readable by its owner only.
#[must_use]
pub fn admin_key_refusal(cfg: &ServerConfig) -> Option<ServeError> {
    let admin = cfg.database.admin.as_ref()?;
    std::fs::File::open(&admin.client_key)
        .is_ok()
        .then_some(ServeError::Refused {
            field: "database.admin.client_key",
            reason: "admin_key_readable_by_service",
        })
}

/// Checks the content root: owned by the service uid and not accessible
/// by group or others (plan section 3.5: 0700, service uid).
///
/// # Errors
///
/// [`ServeError::Refused`].
pub fn check_content_root(
    root: &std::path::Path,
    service_uid: Option<u32>,
) -> Result<(), ServeError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let refused = |reason| ServeError::Refused {
            field: "content.root",
            reason,
        };
        let meta =
            std::fs::symlink_metadata(root).map_err(|_| refused("content_root_unreadable"))?;
        if !meta.is_dir() {
            return Err(refused("content_root_not_a_directory"));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(refused("content_root_mode_not_0700"));
        }
        if service_uid != Some(meta.uid()) {
            return Err(refused("content_root_not_owned_by_service"));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (root, service_uid);
        Err(ServeError::Refused {
            field: "content.root",
            reason: "unsupported_platform",
        })
    }
}

/// Runs the server on `store` (already checked by the caller: certificate
/// only, reachable, schema version `schema_version`) until `shutdown`
/// completes with a reason (for example `"SIGTERM"`).
///
/// `ready` (if given) receives the bound addresses once serving begins.
/// With `device_api.enabled`, the device listener ([`usgp_api::serve_device`])
/// runs beside the operator listener and stops with it.
///
/// # Errors
///
/// [`ServeError`]; every start-up failure is recorded as
/// `server.start.refused`.
pub async fn run<S, F>(
    store: S,
    loaded: &LoadedConfig,
    prepared: Prepared,
    opts: RunOptions,
    schema_version: u32,
    shutdown: F,
    ready: Option<oneshot::Sender<Listening>>,
) -> Result<(), ServeError>
where
    S: Store + 'static,
    F: Future<Output = &'static str>,
{
    let cfg = &loaded.config;
    let chain = AuditChain::new(&cfg.node_name).map_err(|e| {
        refuse_unpersisted(cfg, "audit_unavailable", None);
        ServeError::Audit(RecordError::Audit(e))
    })?;
    if let Err(e) = events::ensure_genesis(&store, &chain, &prepared.audit_key_id).await {
        refuse_unpersisted(cfg, "audit_unavailable", None);
        return Err(e.into());
    }
    // An existing content root is checked before the content store opens
    // it (which would quietly reset its mode): a loosened root refuses
    // start-up. A missing root is created 0700 by the store and checked
    // after.
    if std::fs::symlink_metadata(&cfg.api.content.root).is_ok()
        && let Err(e) = check_content_root(&cfg.api.content.root, opts.service_uid)
    {
        let _ = events::record(&store, &chain, &refusal_draft(e.reason(), e.field())).await;
        return Err(e);
    }
    let Prepared {
        server_tls,
        crls,
        content_keys,
        checkpointer,
        content_key_id,
        audit_key_id,
        provisioning,
        device_tls,
    } = prepared;
    let key_ids = provisioning
        .as_ref()
        .map(|k| (k.plan_key_id(), k.boot_policy_key_id()));
    let mut builder =
        Api::builder(store, cfg.api.clone(), chain, content_keys).checkpointer(checkpointer);
    if let Some(k) = provisioning {
        builder = builder.provisioning_keys(k);
    }
    let api = match builder.build() {
        Ok(api) => api,
        Err(e) => {
            let e = ServeError::from(e);
            refuse_unpersisted(cfg, e.reason(), e.field().as_deref());
            return Err(e);
        }
    };
    let started = start(&api, cfg, opts).await;
    let (listener, device_listener) = match started {
        Ok(l) => l,
        Err(e) => {
            refuse(&api, &e).await;
            return Err(e);
        }
    };
    let local = listener
        .local_addr()
        .map_err(|_| ServeError::Runtime("cannot read the bound address"))?;
    let device_local = device_listener
        .as_ref()
        .map(TcpListener::local_addr)
        .transpose()
        .map_err(|_| ServeError::Runtime("cannot read the bound device address"))?;
    let key_text = |k: Option<KeyId>| k.map_or_else(|| "none".to_owned(), |k| k.to_string());
    let detail = Detail::new()
        .with("version", env!("CARGO_PKG_VERSION"))
        .with("config_sha256", &loaded.sha256)
        .with("listen", &local.to_string())
        .with(
            "device_listen",
            &device_local.map_or_else(|| "off".to_owned(), |a| a.to_string()),
        )
        .with("content_key_id", &content_key_id)
        .with("audit_key_id", &audit_key_id)
        .with("plan_key_id", &key_text(key_ids.map(|k| k.0)))
        .with("boot_policy_key_id", &key_text(key_ids.map(|k| k.1)))
        .with("schema_version", &schema_version)
        .with("tls_min_version", tls_min_text(cfg.tls.min_version))
        .with("crl_set_sha256", &crls.digest)
        .with(
            "service_uid",
            &opts
                .service_uid
                .map_or_else(|| "unknown".to_owned(), |u| u.to_string()),
        )
        .with("allow_shared_admin_uid", &opts.allow_shared_admin_uid);
    let start_draft = system_draft(events::SERVER_START, Outcome::Success).detail(detail);
    // Fail closed: a server whose start cannot be recorded does not serve
    // (decision 0015 item 1).
    events::record(api.store(), api.chain(), &start_draft).await?;
    if let Some(tx) = ready {
        let _ = tx.send(Listening {
            api: local,
            device: device_local,
        });
    }

    let tls = Arc::new(TlsAcceptorHandle::new(server_tls));
    let reloader = tokio::spawn(crl_reload_loop(
        api.clone(),
        cfg.tls.clone(),
        opts.trust,
        Arc::clone(&tls),
        crls,
    ));
    // One stop signal for both listeners: the shutdown reason, or the
    // operator listener ending on its own.
    let (halt_tx, halt_rx) = watch::channel(false);
    let device_task = match (device_listener, device_tls) {
        (Some(l), Some(t)) => {
            let mut rx = halt_rx.clone();
            let halted = async move {
                let _ = rx.wait_for(|h| *h).await;
            };
            Some(tokio::spawn(usgp_api::serve_device(
                api.clone(),
                l,
                Arc::new(t),
                halted,
            )))
        }
        _ => None,
    };
    let why: Arc<OnceLock<&'static str>> = Arc::new(OnceLock::new());
    let why_set = Arc::clone(&why);
    let stop = async move {
        let reason = shutdown.await;
        let _ = why_set.set(reason);
    };
    // Maintenance (device-session expiry, lost jobs, upload expiry,
    // checkpoints) runs inside `usgp_api::serve` every MAINTENANCE_EVERY
    // (`Api::maintenance`), for both listeners' state.
    let served = usgp_api::serve(api.clone(), listener, Arc::clone(&tls), stop).await;
    let _ = halt_tx.send(true);
    let device_served = match device_task {
        Some(t) => match tokio::time::timeout(DEVICE_STOP_GRACE, t).await {
            Ok(Ok(r)) => r.map_err(|e| e.kind()),
            Ok(Err(_)) | Err(_) => Err(std::io::ErrorKind::Other),
        },
        None => Ok(()),
    };
    reloader.abort();
    let reason = why.get().copied().unwrap_or("listener_failed");
    let (outcome, detail) = match &served {
        Ok(()) => (
            Outcome::Success,
            Detail::new()
                .with("reason", reason)
                .with("listen", &local.to_string()),
        ),
        Err(e) => (
            Outcome::Failure,
            Detail::new()
                .with("reason", reason)
                .with("error_kind", &format!("{:?}", e.kind())),
        ),
    };
    // NIST-001: counts of refusals over the caps are not lost at shutdown.
    api.flush_unauthenticated_summary().await;
    let detail = match &device_served {
        Ok(()) => detail,
        Err(kind) => detail.with("device_error_kind", &format!("{kind:?}")),
    };
    let outcome = if device_served.is_err() {
        Outcome::Failure
    } else {
        outcome
    };
    let mut stop_draft = system_draft(events::SERVER_STOP, outcome).detail(detail);
    if served.is_err() {
        stop_draft = stop_draft.reason("listener_failed");
    } else if device_served.is_err() {
        stop_draft = stop_draft.reason("device_listener_failed");
    }
    let _ = events::record(api.store(), api.chain(), &stop_draft).await;
    // Final checkpoint, covering server.stop (plan section 5.6).
    api.checkpoint(true).await;
    served.map_err(|_| ServeError::Runtime("the listener failed"))?;
    device_served.map_err(|_| ServeError::Runtime("the device listener failed"))
}

/// The bound addresses, sent to `run`'s `ready` channel once serving
/// begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Listening {
    /// The operator listener.
    pub api: SocketAddr,
    /// The device listener, if enabled.
    pub device: Option<SocketAddr>,
}

/// How long shutdown waits for the device accept loop to end.
const DEVICE_STOP_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

fn tls_min_text(v: TlsMinVersion) -> &'static str {
    match v {
        TlsMinVersion::Tls12 => "1.2",
        TlsMinVersion::Tls13 => "1.3",
    }
}

/// Content root check, restart recovery, bind (the operator listener,
/// and the device listener if enabled).
async fn start<S: Store + 'static>(
    api: &Api<S>,
    cfg: &ServerConfig,
    opts: RunOptions,
) -> Result<(TcpListener, Option<TcpListener>), ServeError> {
    check_content_root(&cfg.api.content.root, opts.service_uid)?;
    api.recover()
        .await
        .map_err(|e| ServeError::Recovery(e.code().as_str().to_owned()))?;
    let bind = |addr: SocketAddr| async move {
        TcpListener::bind(addr).await.map_err(|e| ServeError::Bind {
            addr,
            kind: e.kind(),
        })
    };
    let operator = bind(cfg.listen).await?;
    let device = match &cfg.device_listener {
        Some(d) => Some(bind(d.listen).await?),
        None => None,
    };
    Ok((operator, device))
}

/// Records `server.start.refused` in the chain (best effort; mirrored as
/// unpersisted if the chain is unreachable).
async fn refuse<S: Store + 'static>(api: &Api<S>, e: &ServeError) {
    let _ = events::record(
        api.store(),
        api.chain(),
        &refusal_draft(e.reason(), e.field()),
    )
    .await;
}

/// Mirrors `server.start.refused` without the database.
pub fn refuse_unpersisted(cfg: &ServerConfig, reason: &str, field: Option<&str>) {
    events::unpersisted(
        Some(&cfg.node_name),
        &refusal_draft(reason, field.map(str::to_owned)),
    );
}

/// The `server.start.refused` draft.
#[must_use]
pub fn refusal_draft(reason: &str, field: Option<String>) -> usgp_audit::AuditDraft {
    let mut d = Detail::new().with("version", env!("CARGO_PKG_VERSION"));
    if let Some(f) = &field {
        d = d.with("field", f);
    }
    system_draft(events::SERVER_START_REFUSED, Outcome::Refused)
        .reason(reason)
        .detail(d)
}

/// What one CRL reload pass did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadOutcome {
    /// The CRL files are unchanged; nothing rebuilt.
    Unchanged,
    /// The acceptor was rebuilt with the new CRL set.
    Reloaded(CrlSet),
    /// Reading or rebuilding failed; the previous acceptor stays.
    Failed(String),
    /// The new set would roll an issuer's CRL back to a lower cRLNumber;
    /// refused, the previous acceptor stays (finding SEC-007).
    RolledBack(crate::material::CrlRollback),
}

/// What the blocking part of a reload produced.
enum Built {
    Unchanged,
    Rollback(crate::material::CrlRollback),
    New(Box<ServerTls>, CrlSet),
}

/// One reload pass: re-reads the CRL files; if their set changed from
/// `last`, checks that no issuer's CRL number goes down, re-reads the TLS
/// files, rebuilds the acceptor and swaps it in (connections from before
/// close gracefully), and records `auth.tls.crl_reloaded`. A failure or a
/// rollback keeps the previous acceptor and is recorded with outcome
/// `failure` (reason `crl_reload_failed` or `crl_number_rollback`).
pub async fn reload_tls_once<S: Store + 'static>(
    api: &Api<S>,
    tls_cfg: &TlsConfig,
    trust: TrustPolicy,
    handle: &TlsAcceptorHandle,
    last: &CrlSet,
) -> ReloadOutcome {
    let cfg = tls_cfg.clone();
    let last = last.clone();
    let built = tokio::task::spawn_blocking(move || {
        let crls = read_crls(&cfg, &trust)?;
        if crls.digest == last.digest {
            return Ok(Built::Unchanged);
        }
        // SEC-007: never go back to an older CRL for an issuer.
        if let Some(r) = crls.rollback_from(&last) {
            return Ok(Built::Rollback(r));
        }
        let tls = build_server_tls(&cfg, &crls, &trust)?;
        Ok::<_, MaterialError>(Built::New(Box::new(tls), crls))
    })
    .await;
    let (field, error) = match built {
        Ok(Ok(Built::Unchanged)) => return ReloadOutcome::Unchanged,
        Ok(Ok(Built::Rollback(r))) => {
            let d = system_draft(events::CRL_RELOADED, Outcome::Failure)
                .reason("crl_number_rollback")
                .detail(
                    Detail::new()
                        .with("issuer", &r.issuer)
                        .with("loaded_crl_number", &r.loaded.to_string())
                        .with(
                            "offered_crl_number",
                            &r.offered
                                .as_ref()
                                .map_or_else(|| "none".to_owned(), ToString::to_string),
                        ),
                );
            let _ = events::record(api.store(), api.chain(), &d).await;
            return ReloadOutcome::RolledBack(r);
        }
        Ok(Ok(Built::New(tls, crls))) => {
            handle.replace(*tls);
            let d = system_draft(events::CRL_RELOADED, Outcome::Success).detail(
                Detail::new()
                    .with("crl_files", &crls.crls.len())
                    .with("crl_set_sha256", &crls.digest),
            );
            let _ = events::record(api.store(), api.chain(), &d).await;
            return ReloadOutcome::Reloaded(crls);
        }
        Ok(Err(e)) => (e.key(), e.to_string()),
        Err(_) => ("tls".to_owned(), "reload task failed".to_owned()),
    };
    let d = system_draft(events::CRL_RELOADED, Outcome::Failure)
        .reason("crl_reload_failed")
        .detail(Detail::new().with("field", &field).with("error", &error));
    let _ = events::record(api.store(), api.chain(), &d).await;
    ReloadOutcome::Failed(error)
}

async fn crl_reload_loop<S: Store + 'static>(
    api: Api<S>,
    tls_cfg: TlsConfig,
    trust: TrustPolicy,
    handle: Arc<TlsAcceptorHandle>,
    mut last: CrlSet,
) {
    loop {
        tokio::time::sleep(tls_cfg.crl_reload).await;
        if let ReloadOutcome::Reloaded(set) =
            reload_tls_once(&api, &tls_cfg, trust, &handle, &last).await
        {
            last = set;
        }
    }
}
