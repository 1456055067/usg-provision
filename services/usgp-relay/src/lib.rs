//! usgp-relay: per-segment boot service (ProxyDHCP + read-only TFTP).
//!
//! M1 (docs/ROADMAP.md §M1; plan WU-6). The binary (`main.rs`) parses the
//! command line, checks FIPS mode, loads the configuration and calls
//! [`run`] or [`check`]. The library is public so integration tests can
//! drive [`dhcp::DhcpService`] and [`tftp::TftpListener`] in-process.
//!
//! Start-up order in [`run`]: manifest → verify every published file →
//! suppression list → bind every socket → `relay.start` → serve until
//! SIGTERM/SIGINT → `relay.stop`. Any failure before serving refuses
//! start-up and is recorded as `relay.start` with outcome `failure` and
//! the reason; a serving task that ends unexpectedly stops the process
//! (fail closed) and is recorded as `relay.stop` with outcome `failure`.

// Handles network input and operator files: indexing and slicing that can
// panic are denied (CLAUDE.md, Engineering Rules).
#![deny(clippy::indexing_slicing)]

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-13 - FIPS status is checked by main before anything
//   else (docs/decisions/0001).
// - NIST 800-53: CM-6 / CM-7 / SC-5 / SC-7 / SI-7 / SI-10 - see modules.
// - NIST 800-53: AU-2 / AU-12 - relay.start / relay.stop and every state
//   change are events.
// - SPEC: specs/boot-network.md (REQ-BOOT-001..053, 070 in M1 scope)
// - DECISION: docs/decisions/0003-proxy-dhcp-only.md,
//   docs/decisions/0004 (UEFI x86-64 + IPv4)

pub mod cli;
pub mod config;
pub mod content;
pub mod dhcp;
pub mod events;
pub mod limits;
pub mod net;
pub mod state;
pub mod suppress;
pub mod tftp;

use std::io;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use usgp_dhcp::ListenPort;

use crate::config::{ConfigLoadError, InterfaceConfig, LoadedConfig, RelayConfig};
use crate::content::{ContentLoadError, ContentStore};
use crate::dhcp::DhcpService;
use crate::events::Outcome;
use crate::limits::Counters;
use crate::net::{NetError, UdpTidFactory, bind_plan};
use crate::state::{FileStatus, ServiceState};
use crate::suppress::{Suppression, SuppressionError};
use crate::tftp::{TftpListener, TftpShared};
use usgp_common::config::TrustPolicy;

/// Exit code for an invalid configuration (sysexits `EX_CONFIG`).
pub const EXIT_CONFIG: u8 = 78;
/// Exit code of `--check-config` when content is missing.
pub const EXIT_MISSING_CONTENT: u8 = 3;
/// Exit code for usage errors.
pub const EXIT_USAGE: u8 = 2;
/// Exit code for FIPS, bind and runtime failures.
pub const EXIT_FAILURE: u8 = 1;

/// Interval of the drop and shed summary events (plan section 7).
pub const SUMMARY_INTERVAL: Duration = Duration::from_secs(60);

/// Largest datagram read from a listening socket. DHCP messages over 1472
/// octets and TFTP requests over 512 octets are refused by the parsers, so
/// a longer datagram (truncated here) is dropped as malformed either way.
const LISTEN_RECV_BUF: usize = 2048;

/// Why the relay stopped or refused to start.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RelayError {
    /// Configuration invalid (exit 78).
    #[error(transparent)]
    Config(#[from] ConfigLoadError),
    /// Boot manifest invalid (exit 78).
    #[error(transparent)]
    Content(#[from] ContentLoadError),
    /// Suppression file invalid at start-up (exit 78).
    #[error(transparent)]
    Suppression(#[from] SuppressionError),
    /// Socket set-up failed or the platform is unsupported (exit 1).
    #[error(transparent)]
    Net(#[from] NetError),
    /// A serving task ended unexpectedly (exit 1).
    #[error("a serving task ended unexpectedly")]
    TaskEnded,
    /// Signal handlers could not be installed (exit 1).
    #[error("cannot install signal handlers: {0}")]
    Signal(io::ErrorKind),
    /// The relay would run as the `--admin-uid` that owns its trusted
    /// files, without `--allow-shared-admin-uid` (exit 78; CM-5).
    #[error(
        "refusing to run as the --admin-uid that owns the trusted files ({0}); \
         run the relay under its own uid or pass --allow-shared-admin-uid"
    )]
    SharedAdminUid(&'static str),
    /// An interface's subnet prefix is neither configured nor derivable
    /// from the interface (exit 78).
    #[error(
        "invalid configuration: {0}: not set and not found as a connected \
         route of the interface"
    )]
    PrefixUnknown(String),
}

impl RelayError {
    /// The process exit code for this error (plan section 3.6).
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Config(_)
            | Self::Content(_)
            | Self::Suppression(_)
            | Self::SharedAdminUid(_)
            | Self::PrefixUnknown(_) => EXIT_CONFIG,
            Self::Net(_) | Self::TaskEnded | Self::Signal(_) => EXIT_FAILURE,
        }
    }

    /// The failing configuration key, for `relay.config.rejected`.
    #[must_use]
    pub fn field(&self) -> String {
        match self {
            Self::Config(e) => e.field(),
            Self::Content(_) => "boot.manifest".to_owned(),
            Self::Suppression(_) => "suppression.file".to_owned(),
            Self::SharedAdminUid(_) => "--admin-uid".to_owned(),
            Self::PrefixUnknown(field) => field.clone(),
            Self::Net(_) | Self::TaskEnded | Self::Signal(_) => String::new(),
        }
    }
}

/// Locks a mutex, ignoring poisoning: the guarded values are counters and
/// tables that stay consistent between statements, and a panic elsewhere
/// already stops the relay (fail closed in [`run`]).
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn read_lock<T>(m: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    m.read().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn write_lock<T>(m: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    m.write().unwrap_or_else(PoisonError::into_inner)
}

/// Content and suppression state, loaded and verified (shared by [`run`]
/// and [`check`]).
#[derive(Debug)]
pub struct Prepared {
    /// The published content.
    pub content: Arc<ContentStore>,
    /// The suppression list.
    pub suppression: Arc<Suppression>,
}

/// Loads the manifest, verifies every published file, and loads the
/// suppression file (if configured).
///
/// # Errors
///
/// [`RelayError::Content`] or [`RelayError::Suppression`] (exit 78).
pub async fn prepare(config: &RelayConfig) -> Result<Prepared, RelayError> {
    let content = Arc::new(ContentStore::load(
        &config.boot.manifest,
        &config.boot.root,
        &config.boot.uefi_x64_program,
        config.tftp.max_file_size,
        config.limits.verify_concurrency,
        &config.trust,
    )?);
    content.recheck_all("startup").await;
    let suppression = Arc::new(match &config.suppression.file {
        Some(path) => {
            let p = path.clone();
            let trust = config.trust;
            tokio::task::spawn_blocking(move || Suppression::load_initial(&p, trust))
                .await
                .map_err(|_| RelayError::TaskEnded)??
        }
        None => Suppression::disabled(),
    });
    Ok(Prepared {
        content,
        suppression,
    })
}

/// Result of [`check`] (`--check-config`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReport {
    /// Service state the relay would start in.
    pub state: ServiceState,
    /// Status of every published file.
    pub files: Vec<(String, FileStatus)>,
    /// Suppression entries, if a file is configured.
    pub suppression_entries: Option<usize>,
}

impl CheckReport {
    /// Exit code: 0 Running, 3 missing content.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        if self.state == ServiceState::Running {
            0
        } else {
            EXIT_MISSING_CONTENT
        }
    }
}

/// Validates content and suppression for `--check-config` without binding
/// any socket.
///
/// # Errors
///
/// As [`prepare`].
pub async fn check(config: &RelayConfig) -> Result<CheckReport, RelayError> {
    let p = prepare(config).await?;
    Ok(CheckReport {
        state: p.content.state().current(),
        files: p.content.state().files(),
        suppression_entries: config
            .suppression
            .file
            .as_ref()
            .map(|_| p.suppression.current().len()),
    })
}

struct BoundInterface {
    iface: InterfaceConfig,
    dhcp: UdpSocket,
    boot_server: UdpSocket,
    tftp: UdpSocket,
}

/// The AU-3 "where" label: `log.node_name` if configured, otherwise the
/// system host name (Linux), with where it came from (`config`,
/// `hostname`).
#[must_use]
pub fn node_name(config: &RelayConfig) -> Option<(String, &'static str)> {
    match &config.log.node_name {
        Some(n) => Some((n.clone(), "config")),
        None => usgp_common::process::hostname().map(|h| (h, "hostname")),
    }
}

/// Process options of [`run`] that come from the command line, not the
/// configuration file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunOptions {
    /// `--allow-shared-admin-uid`: run even when the effective uid is the
    /// `--admin-uid` (recorded in `relay.start`).
    pub allow_shared_admin_uid: bool,
}

/// Whether `--config` must refuse to start because the relay would run as
/// the administrator uid that owns its trusted files (CM-5). Returns
/// the reason label, or `None` to go ahead.
///
/// Refused, unless `allow` (`--allow-shared-admin-uid`) is set, when
/// `--admin-uid` is non-zero and the effective uid equals it, or cannot be
/// determined (fail closed). Root (`--admin-uid 0`, or no `--admin-uid`)
/// is outside this rule; running as root is reported by
/// [`privilege_warning`].
///
// COMPLIANCE MAPPING:
// - NIST 800-53: CM-5 (Access Restrictions for Change) - the service
//   cannot also be the owner of its own manifest, boot root and
//   suppression list unless the operator opts in explicitly.
// - NIST 800-53: AC-6 (Least Privilege); SI-7 (trust anchor protection)
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

/// Least-privilege and trust warnings for `relay.start` (AC-6, CM-5): the
/// relay should run as its own unprivileged uid (with only the two network
/// capabilities), distinct from root and from the administrator uid that
/// owns its trusted files.
#[must_use]
pub fn privilege_warning(service_uid: Option<u32>, trust: &TrustPolicy) -> Option<&'static str> {
    match service_uid {
        None => Some("service_uid_unknown"),
        Some(0) => Some("running_as_root"),
        Some(uid) if trust.service_is_trusted_owner(uid) => Some("service_uid_owns_trusted_files"),
        Some(_) => None,
    }
}

/// Emits `relay.start` with outcome `failure` for a start-up error.
fn start_failed(e: &RelayError, opts: RunOptions) {
    let detail = [
        ("version", env!("CARGO_PKG_VERSION").to_owned()),
        ("reason", e.to_string()),
        (
            "allow_shared_admin_uid",
            opts.allow_shared_admin_uid.to_string(),
        ),
    ];
    events::emit_simple(events::RELAY_START, Outcome::Failure, &detail);
}

/// Where an interface's prefix came from, for `relay.start`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrefixSource {
    Config,
    Interface,
}

async fn prepare_and_bind(
    cfg: &RelayConfig,
) -> Result<(Prepared, Vec<(BoundInterface, PrefixSource)>), RelayError> {
    let prepared = prepare(cfg).await?;
    let mut bound = Vec::with_capacity(cfg.interfaces.len());
    for (i, iface) in cfg.interfaces.iter().enumerate() {
        let [d, b, t] = bind_plan(iface);
        let (dhcp, boot_server, tftp) = (net::bind(&d)?, net::bind(&b)?, net::bind(&t)?);
        // Same-segment vs routed needs the subnet (SC-5): configured,
        // else the interface's connected route; neither refuses start-up.
        let mut iface = iface.clone();
        let source = if iface.prefix_len.is_some() {
            PrefixSource::Config
        } else {
            iface.prefix_len = net::interface_prefix(&iface.name, iface.address);
            if iface.prefix_len.is_none() {
                return Err(RelayError::PrefixUnknown(format!(
                    "interface[{i}].prefix_len"
                )));
            }
            PrefixSource::Interface
        };
        bound.push((
            BoundInterface {
                iface,
                dhcp,
                boot_server,
                tftp,
            },
            source,
        ));
    }
    Ok((prepared, bound))
}

/// `name=a.b.c.d/len(source)` for every interface, for `relay.start`.
fn prefix_summary(bound: &[(BoundInterface, PrefixSource)]) -> String {
    bound
        .iter()
        .map(|(b, src)| {
            let len = b.iface.prefix_len.unwrap_or(32);
            let net =
                std::net::Ipv4Addr::from(u32::from(b.iface.address) & config::prefix_mask(len));
            let src = match src {
                PrefixSource::Config => "config",
                PrefixSource::Interface => "interface",
            };
            format!("{}={net}/{len}({src})", b.iface.name)
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Runs the relay until SIGTERM or SIGINT.
///
/// # Errors
///
/// [`RelayError`]; see [`RelayError::exit_code`].
pub async fn run(loaded: LoadedConfig, opts: RunOptions) -> Result<(), RelayError> {
    let cfg = loaded.config;
    let (prepared, bound) = match prepare_and_bind(&cfg).await {
        Ok(v) => v,
        Err(e) => {
            start_failed(&e, opts);
            return Err(e);
        }
    };

    let now = tokio::time::Instant::now().into_std();
    let shed = Arc::new(Mutex::new(Counters::default()));
    let dhcp = Arc::new(DhcpService::new(
        Arc::clone(&prepared.content),
        Arc::clone(&prepared.suppression),
        cfg.local_addresses(),
        &cfg.limits,
        Arc::clone(&shed),
        now,
    ));
    let tftp_shared = TftpShared::new(&cfg.limits, Arc::clone(&shed), now);
    let prefixes = prefix_summary(&bound);

    let names: Vec<&str> = cfg.interfaces.iter().map(|i| i.name.as_str()).collect();
    let service_uid = usgp_common::process::effective_uid().ok();
    let mut start_detail = vec![
        ("version", env!("CARGO_PKG_VERSION").to_owned()),
        ("config_sha256", loaded.sha256.to_hex()),
        (
            "manifest_sha256",
            prepared.content.manifest_sha256().to_hex(),
        ),
        ("interfaces", names.join(",")),
        (
            "state",
            prepared.content.state().current().as_str().to_owned(),
        ),
        (
            "node_name",
            usgp_common::event::node_name()
                .unwrap_or("unset")
                .to_owned(),
        ),
        (
            "node_name_source",
            node_name(&cfg).map_or("unset", |(_, src)| src).to_owned(),
        ),
        (
            "service_uid",
            service_uid.map_or_else(|| "unknown".to_owned(), |u| u.to_string()),
        ),
        (
            "admin_uid",
            cfg.trust
                .admin_uid
                .map_or_else(|| "none".to_owned(), |u| u.to_string()),
        ),
        (
            "allow_shared_admin_uid",
            opts.allow_shared_admin_uid.to_string(),
        ),
        ("interface_prefixes", prefixes),
    ];
    if let Some(w) = privilege_warning(service_uid, &cfg.trust) {
        start_detail.push(("warning", w.to_owned()));
    }
    events::emit_simple(events::RELAY_START, Outcome::Success, &start_detail);

    let mut tasks = JoinSet::new();
    for (b, _) in bound {
        let BoundInterface {
            iface,
            dhcp: dhcp_sock,
            boot_server,
            tftp,
        } = b;
        let svc = Arc::clone(&dhcp);
        let i = iface.clone();
        tasks.spawn(dhcp_loop(svc, i, ListenPort::Dhcp67, dhcp_sock));
        let svc = Arc::clone(&dhcp);
        let i = iface.clone();
        tasks.spawn(dhcp_loop(svc, i, ListenPort::BootServer4011, boot_server));
        let listener = TftpListener::new(
            iface.clone(),
            Arc::clone(&prepared.content),
            cfg.tftp_listener_config(),
            UdpTidFactory::new(&iface),
            Arc::clone(&tftp_shared),
        );
        tasks.spawn(tftp_loop(listener, tftp));
    }
    tasks.spawn(recheck_loop(
        Arc::clone(&prepared.content),
        cfg.recheck_interval,
    ));
    if cfg.suppression.file.is_some() {
        tasks.spawn(suppress::reload_loop(
            Arc::clone(&prepared.suppression),
            cfg.suppression.reload_interval,
        ));
    }
    tasks.spawn(summary_loop(
        Arc::clone(&dhcp),
        Arc::clone(&tftp_shared),
        Arc::clone(&shed),
    ));

    let result = tokio::select! {
        sig = shutdown_signal() => sig.map_err(|e| RelayError::Signal(e.kind())),
        _ = tasks.join_next() => Err(RelayError::TaskEnded),
    };
    tasks.abort_all();
    let (outcome, reason) = match &result {
        Ok(sig) => (Outcome::Success, (*sig).to_owned()),
        Err(e) => (Outcome::Failure, e.to_string()),
    };
    events::emit_simple(events::RELAY_STOP, outcome, &[("reason", reason)]);
    result.map(|_| ())
}

async fn shutdown_signal() -> io::Result<&'static str> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate())?;
        let mut int = signal(SignalKind::interrupt())?;
        tokio::select! {
            _ = term.recv() => Ok("SIGTERM"),
            _ = int.recv() => Ok("SIGINT"),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.map(|()| "SIGINT")
    }
}

/// Pause after a receive or send error so a broken socket cannot spin.
const IO_ERROR_PAUSE: Duration = Duration::from_millis(10);

async fn dhcp_loop(
    svc: Arc<DhcpService>,
    iface: InterfaceConfig,
    port: ListenPort,
    sock: UdpSocket,
) {
    let mut buf = vec![0u8; LISTEN_RECV_BUF];
    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(_) => {
                tokio::time::sleep(IO_ERROR_PAUSE).await;
                continue;
            }
        };
        let SocketAddr::V4(src) = src else {
            continue;
        };
        let pkt = buf.get(..n).unwrap_or(&[]);
        let now = tokio::time::Instant::now().into_std();
        if let Some(out) = svc.handle(&iface, port, src, pkt, now) {
            let dst: SocketAddrV4 = out.addr();
            if sock.send_to(&out.bytes, dst).await.is_err() {
                tokio::time::sleep(IO_ERROR_PAUSE).await;
            }
        }
    }
}

async fn tftp_loop(listener: Arc<TftpListener<UdpTidFactory>>, sock: UdpSocket) {
    let mut buf = vec![0u8; LISTEN_RECV_BUF];
    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(_) => {
                tokio::time::sleep(IO_ERROR_PAUSE).await;
                continue;
            }
        };
        let pkt = buf.get(..n).unwrap_or(&[]);
        let _ = listener.handle_request(src, pkt);
    }
}

async fn recheck_loop(content: Arc<ContentStore>, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tick.tick().await;
        content.recheck_all("recheck").await;
    }
}

async fn summary_loop(dhcp: Arc<DhcpService>, tftp: Arc<TftpShared>, shed: Arc<Mutex<Counters>>) {
    let mut tick = tokio::time::interval(SUMMARY_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await;
    loop {
        tick.tick().await;
        emit_summaries(&dhcp, &tftp, &shed);
    }
}

/// Emits `dhcp.drop.summary`, `tftp.drop.summary` and `limits.shed` for
/// every non-zero counter set, and clears them.
pub fn emit_summaries(dhcp: &DhcpService, tftp: &TftpShared, shed: &Mutex<Counters>) {
    let emit = |event: &str, counts: Vec<(&'static str, u64)>| {
        if counts.is_empty() {
            return;
        }
        let detail: Vec<(&str, String)> = counts
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect();
        events::emit_simple(event, Outcome::Dropped, &detail);
    };
    emit(events::DHCP_DROP_SUMMARY, dhcp.take_drop_counts());
    emit(events::TFTP_DROP_SUMMARY, tftp.take_drop_counts());
    emit(events::LIMITS_SHED, lock(shed).drain());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_admin_uid_refused_unless_allowed() {
        let admin = TrustPolicy::with_admin(1000);
        assert_eq!(
            shared_admin_uid_refusal(Some(1000), &admin, false),
            Some("service_uid_is_admin_uid")
        );
        assert_eq!(shared_admin_uid_refusal(Some(1000), &admin, true), None);
        assert_eq!(shared_admin_uid_refusal(Some(999), &admin, false), None);
        assert_eq!(shared_admin_uid_refusal(Some(0), &admin, false), None);
        assert_eq!(
            shared_admin_uid_refusal(None, &admin, false),
            Some("service_uid_unknown")
        );
        assert_eq!(shared_admin_uid_refusal(None, &admin, true), None);
        // Root-only trust, or --admin-uid 0: outside this rule.
        for t in [TrustPolicy::root_only(), TrustPolicy::with_admin(0)] {
            assert_eq!(shared_admin_uid_refusal(Some(0), &t, false), None);
            assert_eq!(shared_admin_uid_refusal(Some(1000), &t, false), None);
            assert_eq!(shared_admin_uid_refusal(None, &t, false), None);
        }
        let e = RelayError::SharedAdminUid("service_uid_is_admin_uid");
        assert_eq!(e.exit_code(), EXIT_CONFIG);
        assert_eq!(e.field(), "--admin-uid");
        assert!(e.to_string().contains("--allow-shared-admin-uid"));
    }

    #[test]
    fn privilege_warnings() {
        let root_only = TrustPolicy::root_only();
        let admin = TrustPolicy::with_admin(1000);
        assert_eq!(
            privilege_warning(Some(0), &root_only),
            Some("running_as_root")
        );
        assert_eq!(privilege_warning(Some(0), &admin), Some("running_as_root"));
        assert_eq!(
            privilege_warning(Some(1000), &admin),
            Some("service_uid_owns_trusted_files")
        );
        assert_eq!(privilege_warning(Some(999), &admin), None);
        assert_eq!(privilege_warning(Some(999), &root_only), None);
        assert_eq!(
            privilege_warning(None, &root_only),
            Some("service_uid_unknown")
        );
    }
}
