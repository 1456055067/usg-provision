//! Relay configuration: document types, defaults and validation (plan
//! section 3.4).
//!
//! Loading is in two steps:
//!
//! 1. the TOML text becomes a [`ConfigDocument`], which mirrors the file
//!    layout with every key optional;
//! 2. [`RelayConfig::from_document`] applies the defaults and every range
//!    rule and produces the validated [`RelayConfig`].
//!
//! Every numeric limit and its default is **project design (OPEN-BOOT-L1),
//! not product behaviour**.
//!
//! The file is read-only to the relay: it is opened for reading once at
//! start-up and never written (REQ-BOOT-053).
//!
//! M3 (plan WU-11, section 3.9) adds `[tftp] max_window_size` and
//! `block_wrap`, raises the `[tftp]` file-size and duration defaults for
//! Windows PE images, and adds the `[server_feed]` section (the signed
//! boot-policy pull of decision 0021).

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 (Configuration Settings) - documented defaults,
//   strict ranges; any violation refuses start-up (exit 78).
// - NIST 800-53: CM-7 (Least Functionality) - fixed ports, no test hooks.
// - NIST 800-53: SC-7 (Boundary Protection) - interfaces listed explicitly;
//   no wildcard.
// - NIST 800-53: SI-10 (Information Input Validation) - size bound, unknown
//   keys rejected, every value range-checked.
// - NIST 800-53: CM-5 (Access Restrictions for Change) / SI-7 - the
//   configuration, manifest and suppression files and every directory
//   above them must be owned by root or the administrator uid and not
//   writable by anyone else (usgp_common::config::read_trusted).
// - SPEC: specs/boot-network.md#REQ-BOOT-022 (reachable server address),
//   #REQ-BOOT-044 (limits), #REQ-BOOT-053 (settings survive updates:
//   schema_version, read-only)

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use usgp_common::Sha256Digest;
use usgp_common::config::{
    ConfigError, TrustPolicy, ensure_trusted_dir, ensure_trusted_file, read_trusted,
};
use usgp_common::telemetry::{self, Level};
use usgp_proto::BootFileName;
use usgp_proto::ids::BootServiceId;
use usgp_tftp::{BlockWrap, MAX_WINDOW_SIZE, WindowConfig};

/// Largest accepted configuration file.
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;
/// The only supported `schema_version`.
pub const SCHEMA_VERSION: i64 = 1;
/// Largest number of `[[interface]]` entries.
pub const MAX_INTERFACES: usize = 16;
/// Longest interface name (Linux `IFNAMSIZ` minus the NUL).
pub const MAX_INTERFACE_NAME_LEN: usize = 15;
/// Shortest accepted `interface.prefix_len`.
pub const MIN_PREFIX_LEN: u8 = 8;
/// Longest accepted `interface.prefix_len` (a /31 link has two hosts,
/// RFC 3021; a /32 would leave no other host on the segment).
pub const MAX_PREFIX_LEN: u8 = 31;
/// Longest `log.node_name`.
pub const MAX_NODE_NAME_LEN: usize = 64;
/// Longest accepted path value, in bytes.
pub const MAX_PATH_LEN: usize = 4096;

// ---------------------------------------------------------------------------
// Document types (file layout; every key optional so defaults can apply)
// ---------------------------------------------------------------------------

/// The configuration file as written. Integers are `i64` (the TOML integer
/// type) so that range checks see negative values too.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigDocument {
    /// `schema_version` (required, must be 1).
    pub schema_version: Option<i64>,
    /// `[[interface]]` entries.
    #[serde(default)]
    pub interface: Vec<InterfaceDocument>,
    /// `[boot]` (required).
    pub boot: Option<BootDocument>,
    /// `[limits]`.
    pub limits: Option<LimitsDocument>,
    /// `[tftp]`.
    pub tftp: Option<TftpDocument>,
    /// `[content]`.
    pub content: Option<ContentDocument>,
    /// `[suppression]`.
    pub suppression: Option<SuppressionDocument>,
    /// `[server_feed]` (M3).
    pub server_feed: Option<ServerFeedDocument>,
    /// `[log]`.
    pub log: Option<LogDocument>,
}

/// One `[[interface]]` entry.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceDocument {
    /// OS interface name.
    pub name: Option<String>,
    /// The interface's unicast IPv4 address.
    pub address: Option<String>,
    /// Prefix length of the interface's subnet (8 to 31). Optional: on
    /// Linux it is taken from the interface's connected route when absent.
    pub prefix_len: Option<i64>,
}

/// `[boot]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootDocument {
    /// Absolute path of the boot manifest.
    pub manifest: Option<String>,
    /// Absolute path of the boot root directory.
    pub root: Option<String>,
    /// Published name of the UEFI x86-64 boot program.
    pub uefi_x64_program: Option<String>,
}

/// `[limits]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsDocument {
    /// Per-chaddr reply bucket size (default 8, 1 to 100).
    pub dhcp_client_burst: Option<i64>,
    /// Per-chaddr refill interval in ms (default 2000, 100 to 60000).
    pub dhcp_client_refill_ms: Option<i64>,
    /// Per relay-agent source bucket size (default 200, 1 to 10000).
    pub dhcp_relay_burst: Option<i64>,
    /// Per relay-agent source refill per second (default 50, 1 to 10000).
    pub dhcp_relay_per_sec: Option<i64>,
    /// Replies to same-segment requests (not relayed, from a source on the
    /// receiving interface's subnet or 0.0.0.0) per second, all interfaces
    /// together (default 200, 1 to 10000).
    pub dhcp_global_per_sec: Option<i64>,
    /// Replies to routed requests per second (relayed, or sent to 4011
    /// from another subnet), all sources together (default 200, 1 to
    /// 10000).
    pub dhcp_relayed_global_per_sec: Option<i64>,
    /// Bucket table size (default 4096, 64 to 65536).
    pub tracked_clients: Option<i64>,
    /// Established TFTP transfers (default 64, 1 to 1024).
    pub tftp_max_transfers: Option<i64>,
    /// TFTP transfers before the first ACK (default 256, 1 to 4096).
    pub tftp_max_pending: Option<i64>,
    /// TFTP transfers per source IP (default 4, 1 to 64).
    pub tftp_per_client_transfers: Option<i64>,
    /// TFTP requests per source IP: bucket size (default 8, 1 to 100).
    pub tftp_rrq_burst: Option<i64>,
    /// TFTP requests per source IP: refill interval in ms (default 1000, 100 to 60000).
    pub tftp_rrq_refill_ms: Option<i64>,
    /// TFTP read requests admitted per second on each interface, all
    /// sources together (default 50, 1 to 10000).
    pub tftp_rrq_global_per_sec: Option<i64>,
    /// TFTP read requests admitted at once on each interface before the
    /// rate applies (default 100, 1 to 10000).
    pub tftp_rrq_global_burst: Option<i64>,
    /// TFTP ERROR replies per second (default 20, 1 to 1000).
    pub tftp_error_per_sec: Option<i64>,
    /// File reads and hashes at once (default 2, 1 to 16).
    pub verify_concurrency: Option<i64>,
}

/// `[tftp]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TftpDocument {
    /// Largest block size granted (default 1468, 8 to 65464).
    pub max_block_size: Option<i64>,
    /// Initial RTO in ms (default 1000, 100 to 60000).
    pub initial_timeout_ms: Option<i64>,
    /// RTO floor in ms (default 250, 100 to 60000).
    pub min_timeout_ms: Option<i64>,
    /// RTO ceiling in ms (default 8000, 100 to 60000).
    pub max_timeout_ms: Option<i64>,
    /// Resends per packet after the first ACK (default 5, 1 to 10).
    pub max_retries: Option<i64>,
    /// Resends of the first packet (default 1, 1 to 10).
    pub handshake_retries: Option<i64>,
    /// Longest wait for the first ACK, in ms (default 2000, 100 to 60000).
    pub handshake_timeout_ms: Option<i64>,
    /// Hard limit on a transfer in seconds (default 1800, 10 to 7200).
    pub max_transfer_secs: Option<i64>,
    /// Largest file served (default 1073741824, 1 to 4294967295).
    pub max_file_size_bytes: Option<i64>,
    /// Largest RFC 7440 `windowsize` granted (default 8, 1 to 64; 1 never
    /// acknowledges the option).
    pub max_window_size: Option<i64>,
    /// What the block number becomes after 65535: `zero` (default), `one`
    /// or `off` (refuse files that need more than 65535 blocks).
    pub block_wrap: Option<String>,
}

/// `[content]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentDocument {
    /// Seconds between re-checks of every published file.
    pub recheck_interval_secs: Option<i64>,
}

/// `[suppression]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuppressionDocument {
    /// Absolute path of the suppression file.
    pub file: Option<String>,
    /// Seconds between polls of the suppression file.
    pub reload_interval_secs: Option<i64>,
}

/// `[server_feed]`: the signed boot-policy pull (plan section 3.6;
/// decision 0021). Every key other than `enabled` is read only when
/// `enabled = true`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerFeedDocument {
    /// Pull the boot policy from the server (default false).
    pub enabled: Option<bool>,
    /// `https://host[:port]` of the server's operator listener.
    pub url: Option<String>,
    /// Name to verify in the server certificate (default: the URL host).
    pub server_name: Option<String>,
    /// Absolute path of the PEM trust anchors for the server certificate.
    pub trust_anchors: Option<String>,
    /// Absolute path of the relay's client certificate chain (PEM).
    pub client_cert: Option<String>,
    /// Absolute path of the relay's client private key (PKCS#8 PEM).
    pub client_key: Option<String>,
    /// Absolute path of the pinned boot-policy public key (SPKI PEM).
    pub boot_policy_key_pub: Option<String>,
    /// The boot service this relay is enrolled as (UUID).
    pub boot_service_id: Option<String>,
    /// Seconds between pulls (default 30, 5 to 3600), with jitter.
    pub poll_interval_s: Option<i64>,
    /// Absolute path of the optional cache of the last applied list.
    pub cache_file: Option<String>,
}

/// `[log]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogDocument {
    /// `error`, `warn`, `info` or `debug`.
    pub level: Option<String>,
    /// AU-3 "where" label on every event.
    pub node_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Validated configuration
// ---------------------------------------------------------------------------

/// One configured interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceConfig {
    /// OS interface name (`SO_BINDTODEVICE`).
    pub name: String,
    /// Unicast address: `siaddr` and option 54 in replies (REQ-BOOT-022),
    /// and the bind address for ports 4011 and 69.
    pub address: Ipv4Addr,
    /// Prefix length of the segment this interface serves: from the
    /// configuration, or derived from the interface at start-up (Linux).
    /// Used to tell same-segment senders from routed ones (SC-5). `None`
    /// means unknown, and then only a 0.0.0.0 source counts as
    /// same-segment (fail closed; see `dhcp::Origin`).
    pub prefix_len: Option<u8>,
}

impl InterfaceConfig {
    /// Whether `ip` is inside this interface's subnet. Always `false`
    /// while the prefix is unknown.
    #[must_use]
    pub fn on_segment(&self, ip: Ipv4Addr) -> bool {
        let Some(len) = self.prefix_len else {
            return false;
        };
        let mask = prefix_mask(len);
        u32::from(ip) & mask == u32::from(self.address) & mask
    }
}

/// The netmask for a prefix length (lengths above 32 are treated as 32).
#[must_use]
pub fn prefix_mask(len: u8) -> u32 {
    match u32::from(len.min(32)) {
        0 => 0,
        n => u32::MAX << (32 - n),
    }
}

/// `[boot]`, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootConfig {
    /// Boot manifest path.
    pub manifest: PathBuf,
    /// Boot root directory.
    pub root: PathBuf,
    /// UEFI x86-64 boot program (architecture 7 only, DEC-0004).
    pub uefi_x64_program: BootFileName,
}

/// `[limits]`, validated (project design, OPEN-BOOT-L1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Replies per chaddr: bucket size.
    pub dhcp_client_burst: u32,
    /// Replies per chaddr: one token per this interval.
    pub dhcp_client_refill: Duration,
    /// Replies per relay-agent source: bucket size.
    pub dhcp_relay_burst: u32,
    /// Replies per relay-agent source: tokens per second.
    pub dhcp_relay_per_sec: u32,
    /// Replies to same-segment requests: tokens per second (bucket size
    /// is the same).
    pub dhcp_global_per_sec: u32,
    /// Replies to routed requests: tokens per second (bucket size is the
    /// same). Separate from `dhcp_global_per_sec` so off-segment traffic
    /// cannot use up the local budget (SC-5).
    pub dhcp_relayed_global_per_sec: u32,
    /// Size of each per-key bucket table.
    pub tracked_clients: usize,
    /// Established TFTP transfers at once.
    pub tftp_max_transfers: usize,
    /// TFTP transfers before their first ACK.
    pub tftp_max_pending: usize,
    /// TFTP transfers per source IP.
    pub tftp_per_client_transfers: usize,
    /// TFTP requests per source IP: bucket size.
    pub tftp_rrq_burst: u32,
    /// TFTP requests per source IP: one token per this interval.
    pub tftp_rrq_refill: Duration,
    /// TFTP read requests admitted to a transfer slot, per interface:
    /// tokens per second.
    pub tftp_rrq_global_per_sec: u32,
    /// TFTP read requests admitted to a transfer slot, per interface:
    /// bucket size.
    pub tftp_rrq_global_burst: u32,
    /// TFTP ERROR replies (including ERROR 5): tokens per second.
    pub tftp_error_per_sec: u32,
    /// File reads and hashes at once.
    pub verify_concurrency: usize,
}

/// `[tftp]`, validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TftpConfig {
    /// Largest block size granted.
    pub max_block_size: u16,
    /// RTO before any sample.
    pub initial_timeout: Duration,
    /// RTO floor.
    pub min_timeout: Duration,
    /// RTO ceiling.
    pub max_timeout: Duration,
    /// Resends per packet after the first ACK (REQ-BOOT-032).
    pub max_retries: u8,
    /// Resends of the first packet.
    pub handshake_retries: u8,
    /// Longest time a transfer may wait for its first ACK (a pending
    /// slot is never held longer; SC-5).
    pub handshake_timeout: Duration,
    /// Hard limit on one transfer's duration.
    pub max_transfer: Duration,
    /// Largest file read and served (memory bound).
    pub max_file_size: u64,
    /// Largest RFC 7440 `windowsize` granted (1 to 64).
    pub max_window_size: u16,
    /// Block-number wraparound after 65535 (DEC-0018 item 2).
    pub block_wrap: BlockWrap,
}

/// `[server_feed]`, validated (only present when `enabled = true`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerFeedConfig {
    /// The server.
    pub url: FeedUrl,
    /// Name verified in the server certificate.
    pub server_name: String,
    /// Server trust anchors (PEM).
    pub trust_anchors: PathBuf,
    /// Relay client certificate chain (PEM).
    pub client_cert: PathBuf,
    /// Relay client private key (PKCS#8 PEM; read into a wiped buffer).
    pub client_key: PathBuf,
    /// Pinned boot-policy verifying key (SPKI PEM).
    pub boot_policy_key_pub: PathBuf,
    /// This relay's boot service.
    pub boot_service_id: BootServiceId,
    /// Pull interval (jitter is added).
    pub poll_interval: Duration,
    /// Cache of the last applied signed list, if configured.
    pub cache_file: Option<PathBuf>,
}

/// An `https://host[:port]` URL with no path, query, fragment or user
/// information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedUrl {
    /// Host: a DNS name or an IPv4 or IPv6 literal (without brackets).
    pub host: String,
    /// TCP port (default 443).
    pub port: u16,
}

impl FeedUrl {
    /// Longest accepted URL text.
    pub const MAX_LEN: usize = 512;

    /// Parses `https://host[:port][/]`.
    ///
    /// # Errors
    ///
    /// A short reason; the value itself is never echoed.
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        if text.is_empty() || text.len() > Self::MAX_LEN {
            return Err("must be 1 to 512 characters");
        }
        let rest = text
            .strip_prefix("https://")
            .ok_or("must start with https://")?;
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        if authority.is_empty()
            || !authority
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
        {
            return Err("must be https://host[:port] with no path, query or user information");
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, after) = v6.split_once(']').ok_or("unterminated IPv6 literal")?;
            if h.parse::<std::net::Ipv6Addr>().is_err() {
                return Err("bad IPv6 literal");
            }
            let port = match after {
                "" => None,
                p => Some(p.strip_prefix(':').ok_or("bad port")?),
            };
            (h, port)
        } else {
            match authority.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            }
        };
        if host.is_empty() || host.contains('[') || host.contains(']') {
            return Err("bad host");
        }
        if !host.contains(':') && !valid_dns_or_ipv4(host) {
            return Err("bad host");
        }
        let port = match port {
            None => 443,
            Some(p) if !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) => {
                match p.parse::<u16>() {
                    Ok(0) | Err(_) => return Err("port must be 1 to 65535"),
                    Ok(n) => n,
                }
            }
            Some(_) => return Err("port must be 1 to 65535"),
        };
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    /// The `Host` header value (RFC 9110 §7.2; IPv6 in brackets).
    #[must_use]
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// A DNS host name (labels of 1 to 63 `[A-Za-z0-9-]`, not starting or
/// ending with `-`, at most 253 characters) or a dotted-quad IPv4 address.
fn valid_dns_or_ipv4(host: &str) -> bool {
    if host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    host.len() <= 253
        && host.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
        // A name made only of digits and dots would read as an address.
        && !host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

/// `[suppression]`, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressionConfig {
    /// Suppression file, if any.
    pub file: Option<PathBuf>,
    /// Poll interval.
    pub reload_interval: Duration,
}

/// `[log]`, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogConfig {
    /// Level for non-audit records (audit records are always written).
    pub level: Level,
    /// AU-3 "where" label.
    pub node_name: Option<String>,
}

/// The validated relay configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayConfig {
    /// Interfaces to serve (1 to 16).
    pub interfaces: Vec<InterfaceConfig>,
    /// Boot content.
    pub boot: BootConfig,
    /// Load-shedding limits.
    pub limits: Limits,
    /// TFTP parameters.
    pub tftp: TftpConfig,
    /// Interval between content re-checks.
    pub recheck_interval: Duration,
    /// Device suppression.
    pub suppression: SuppressionConfig,
    /// Boot-policy pull from the server (`None`: disabled, M1 behaviour).
    pub server_feed: Option<ServerFeedConfig>,
    /// Logging.
    pub log: LogConfig,
    /// Who may own the trusted files (manifest, suppression list). Not
    /// part of the file: set by [`load`] from the command line, and
    /// root-only after [`RelayConfig::from_document`].
    pub trust: TrustPolicy,
}

/// A configuration rule violation. Names the key and the rule; it never
/// echoes the value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid configuration: {field}: {reason}")]
pub struct ConfigInvalid {
    /// The key (dotted path, with an index for interfaces).
    pub field: String,
    /// The rule that failed.
    pub reason: String,
}

fn invalid(field: impl Into<String>, reason: impl Into<String>) -> ConfigInvalid {
    ConfigInvalid {
        field: field.into(),
        reason: reason.into(),
    }
}

/// Why loading the configuration failed. Every variant means exit 78.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigLoadError {
    /// Reading the file (or a file it names) failed, or it breaks a
    /// trusted-file rule.
    #[error(transparent)]
    File(#[from] ConfigError),
    /// A rule in section 3.4 failed.
    #[error(transparent)]
    Invalid(#[from] ConfigInvalid),
}

impl ConfigLoadError {
    /// The failing key, for the `relay.config.rejected` event.
    #[must_use]
    pub fn field(&self) -> String {
        match self {
            Self::File(_) => "file".to_owned(),
            Self::Invalid(i) => i.field.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn int_in(
    field: &str,
    v: Option<i64>,
    default: i64,
    min: i64,
    max: i64,
) -> Result<i64, ConfigInvalid> {
    let v = v.unwrap_or(default);
    if v < min || v > max {
        return Err(invalid(field, format!("must be between {min} and {max}")));
    }
    Ok(v)
}

fn u32_in(
    field: &str,
    v: Option<i64>,
    default: i64,
    min: i64,
    max: i64,
) -> Result<u32, ConfigInvalid> {
    let v = int_in(field, v, default, min, max)?;
    u32::try_from(v).map_err(|_| invalid(field, "out of range"))
}

fn usize_in(
    field: &str,
    v: Option<i64>,
    default: i64,
    min: i64,
    max: i64,
) -> Result<usize, ConfigInvalid> {
    let v = int_in(field, v, default, min, max)?;
    usize::try_from(v).map_err(|_| invalid(field, "out of range"))
}

fn u8_in(
    field: &str,
    v: Option<i64>,
    default: i64,
    min: i64,
    max: i64,
) -> Result<u8, ConfigInvalid> {
    let v = int_in(field, v, default, min, max)?;
    u8::try_from(v).map_err(|_| invalid(field, "out of range"))
}

fn ms_in(
    field: &str,
    v: Option<i64>,
    default: i64,
    min: i64,
    max: i64,
) -> Result<Duration, ConfigInvalid> {
    let v = int_in(field, v, default, min, max)?;
    let v = u64::try_from(v).map_err(|_| invalid(field, "out of range"))?;
    Ok(Duration::from_millis(v))
}

fn secs_in(
    field: &str,
    v: Option<i64>,
    default: i64,
    min: i64,
    max: i64,
) -> Result<Duration, ConfigInvalid> {
    let v = int_in(field, v, default, min, max)?;
    let v = u64::try_from(v).map_err(|_| invalid(field, "out of range"))?;
    Ok(Duration::from_secs(v))
}

fn absolute_path(field: &str, v: Option<&String>) -> Result<PathBuf, ConfigInvalid> {
    let v = v.ok_or_else(|| invalid(field, "is required"))?;
    if v.is_empty() || v.len() > MAX_PATH_LEN {
        return Err(invalid(field, format!("must be 1 to {MAX_PATH_LEN} bytes")));
    }
    if v.contains('\0') {
        return Err(invalid(field, "must not contain NUL"));
    }
    let p = PathBuf::from(v);
    if !p.is_absolute() {
        return Err(invalid(field, "must be an absolute path"));
    }
    Ok(p)
}

/// Interface name rule: 1 to 15 characters of `[A-Za-z0-9._-]`, not `.`
/// or `..`.
fn valid_interface_name(name: &str) -> bool {
    (1..=MAX_INTERFACE_NAME_LEN).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && name != "."
        && name != ".."
}

/// Address rule (REQ-BOOT-022): a unicast IPv4 host address that a device
/// on another subnet can reach. Refuses 0/8, 127/8, 169.254/16, 224/4
/// (multicast), 240/4 (reserved) and 255.255.255.255.
#[must_use]
pub fn is_servable_address(a: Ipv4Addr) -> bool {
    let [first, ..] = a.octets();
    !(first == 0 || a.is_loopback() || a.is_link_local() || first >= 224)
}

fn node_name_ok(n: &str) -> bool {
    let len = n.chars().count();
    (1..=MAX_NODE_NAME_LEN).contains(&len) && !n.chars().any(char::is_control)
}

impl RelayConfig {
    /// Applies defaults and validates every rule of plan section 3.4.
    ///
    /// # Errors
    ///
    /// [`ConfigInvalid`] naming the first failing key.
    pub fn from_document(doc: &ConfigDocument) -> Result<Self, ConfigInvalid> {
        match doc.schema_version {
            Some(SCHEMA_VERSION) => {}
            Some(_) => return Err(invalid("schema_version", "must be 1")),
            None => return Err(invalid("schema_version", "is required")),
        }

        let interfaces = interfaces(&doc.interface)?;

        let boot_doc = doc
            .boot
            .as_ref()
            .ok_or_else(|| invalid("boot", "is required"))?;
        let boot = BootConfig {
            manifest: absolute_path("boot.manifest", boot_doc.manifest.as_ref())?,
            root: absolute_path("boot.root", boot_doc.root.as_ref())?,
            uefi_x64_program: {
                let raw = boot_doc
                    .uefi_x64_program
                    .as_deref()
                    .ok_or_else(|| invalid("boot.uefi_x64_program", "is required"))?;
                BootFileName::try_from(raw).map_err(|e| {
                    invalid(
                        "boot.uefi_x64_program",
                        format!("not a valid boot file name: {e}"),
                    )
                })?
            },
        };

        let l = doc.limits.clone().unwrap_or_default();
        let limits = Limits {
            dhcp_client_burst: u32_in("limits.dhcp_client_burst", l.dhcp_client_burst, 8, 1, 100)?,
            dhcp_client_refill: ms_in(
                "limits.dhcp_client_refill_ms",
                l.dhcp_client_refill_ms,
                2000,
                100,
                60_000,
            )?,
            dhcp_relay_burst: u32_in(
                "limits.dhcp_relay_burst",
                l.dhcp_relay_burst,
                200,
                1,
                10_000,
            )?,
            dhcp_relay_per_sec: u32_in(
                "limits.dhcp_relay_per_sec",
                l.dhcp_relay_per_sec,
                50,
                1,
                10_000,
            )?,
            dhcp_global_per_sec: u32_in(
                "limits.dhcp_global_per_sec",
                l.dhcp_global_per_sec,
                200,
                1,
                10_000,
            )?,
            dhcp_relayed_global_per_sec: u32_in(
                "limits.dhcp_relayed_global_per_sec",
                l.dhcp_relayed_global_per_sec,
                200,
                1,
                10_000,
            )?,
            tracked_clients: usize_in(
                "limits.tracked_clients",
                l.tracked_clients,
                4096,
                64,
                65_536,
            )?,
            tftp_max_transfers: usize_in(
                "limits.tftp_max_transfers",
                l.tftp_max_transfers,
                64,
                1,
                1024,
            )?,
            // Well above the established cap: with the short handshake
            // lifetime and the global admission bucket, spoofed requests
            // that never ACK cannot hold every pending slot (SC-5,
            // project design).
            tftp_max_pending: usize_in(
                "limits.tftp_max_pending",
                l.tftp_max_pending,
                256,
                1,
                4096,
            )?,
            tftp_per_client_transfers: usize_in(
                "limits.tftp_per_client_transfers",
                l.tftp_per_client_transfers,
                4,
                1,
                64,
            )?,
            // Ranges for the two TFTP request-bucket keys are not in the
            // plan table; they mirror the per-chaddr DHCP bucket (project
            // design, impl-notes-wu6).
            tftp_rrq_burst: u32_in("limits.tftp_rrq_burst", l.tftp_rrq_burst, 8, 1, 100)?,
            tftp_rrq_refill: ms_in(
                "limits.tftp_rrq_refill_ms",
                l.tftp_rrq_refill_ms,
                1000,
                100,
                60_000,
            )?,
            tftp_rrq_global_per_sec: u32_in(
                "limits.tftp_rrq_global_per_sec",
                l.tftp_rrq_global_per_sec,
                50,
                1,
                10_000,
            )?,
            tftp_rrq_global_burst: u32_in(
                "limits.tftp_rrq_global_burst",
                l.tftp_rrq_global_burst,
                100,
                1,
                10_000,
            )?,
            tftp_error_per_sec: u32_in(
                "limits.tftp_error_per_sec",
                l.tftp_error_per_sec,
                20,
                1,
                1000,
            )?,
            verify_concurrency: usize_in(
                "limits.verify_concurrency",
                l.verify_concurrency,
                2,
                1,
                16,
            )?,
        };

        let t = doc.tftp.clone().unwrap_or_default();
        let tftp = TftpConfig {
            max_block_size: {
                let v = int_in("tftp.max_block_size", t.max_block_size, 1468, 8, 65_464)?;
                u16::try_from(v).map_err(|_| invalid("tftp.max_block_size", "out of range"))?
            },
            initial_timeout: ms_in(
                "tftp.initial_timeout_ms",
                t.initial_timeout_ms,
                1000,
                100,
                60_000,
            )?,
            min_timeout: ms_in("tftp.min_timeout_ms", t.min_timeout_ms, 250, 100, 60_000)?,
            max_timeout: ms_in("tftp.max_timeout_ms", t.max_timeout_ms, 8000, 100, 60_000)?,
            max_retries: u8_in("tftp.max_retries", t.max_retries, 5, 1, 10)?,
            // One resend before the first ACK (project design, SC-5): a
            // client that lost the first packet repeats its request.
            handshake_retries: u8_in("tftp.handshake_retries", t.handshake_retries, 1, 1, 10)?,
            handshake_timeout: ms_in(
                "tftp.handshake_timeout_ms",
                t.handshake_timeout_ms,
                2000,
                100,
                60_000,
            )?,
            // M3 defaults (plan section 3.9): a Windows PE image is held
            // as one verified in-memory copy, as in M1; the ceilings are
            // usgp-tftp's hard limits.
            max_transfer: secs_in(
                "tftp.max_transfer_secs",
                t.max_transfer_secs,
                i64::try_from(usgp_tftp::LARGE_FILE_MAX_DURATION.as_secs()).unwrap_or(1800),
                10,
                i64::try_from(usgp_tftp::MAX_DURATION_CEILING.as_secs()).unwrap_or(7200),
            )?,
            max_file_size: {
                let v = int_in(
                    "tftp.max_file_size_bytes",
                    t.max_file_size_bytes,
                    i64::try_from(usgp_tftp::LARGE_FILE_MAX_SIZE).unwrap_or(1_073_741_824),
                    1,
                    i64::try_from(usgp_tftp::MAX_FILE_SIZE_CEILING).unwrap_or(4_294_967_295),
                )?;
                u64::try_from(v).map_err(|_| invalid("tftp.max_file_size_bytes", "out of range"))?
            },
            max_window_size: {
                let v = int_in(
                    "tftp.max_window_size",
                    t.max_window_size,
                    8,
                    1,
                    i64::from(MAX_WINDOW_SIZE),
                )?;
                u16::try_from(v).map_err(|_| invalid("tftp.max_window_size", "out of range"))?
            },
            block_wrap: match t.block_wrap.as_deref() {
                None => BlockWrap::Zero,
                Some(label) => BlockWrap::from_label(label)
                    .ok_or_else(|| invalid("tftp.block_wrap", "must be zero, one or off"))?,
            },
        };
        if tftp.min_timeout > tftp.initial_timeout {
            return Err(invalid(
                "tftp.min_timeout_ms",
                "must not exceed tftp.initial_timeout_ms",
            ));
        }
        if tftp.handshake_timeout > tftp.max_transfer {
            return Err(invalid(
                "tftp.handshake_timeout_ms",
                "must not exceed tftp.max_transfer_secs",
            ));
        }
        if tftp.initial_timeout > tftp.max_timeout {
            return Err(invalid(
                "tftp.initial_timeout_ms",
                "must not exceed tftp.max_timeout_ms",
            ));
        }

        let c = doc.content.clone().unwrap_or_default();
        let recheck_interval = secs_in(
            "content.recheck_interval_secs",
            c.recheck_interval_secs,
            60,
            5,
            3600,
        )?;

        let s = doc.suppression.clone().unwrap_or_default();
        let suppression = SuppressionConfig {
            file: match s.file.as_ref() {
                Some(f) => Some(absolute_path("suppression.file", Some(f))?),
                None => None,
            },
            reload_interval: secs_in(
                "suppression.reload_interval_secs",
                s.reload_interval_secs,
                2,
                1,
                300,
            )?,
        };

        let server_feed = server_feed(doc.server_feed.as_ref())?;

        let lg = doc.log.clone().unwrap_or_default();
        let level = telemetry::parse_level(lg.level.as_deref().unwrap_or("info"))
            .map_err(|_| invalid("log.level", "must be error, warn, info or debug"))?;
        if let Some(n) = lg.node_name.as_deref()
            && !node_name_ok(n)
        {
            return Err(invalid(
                "log.node_name",
                format!("must be 1 to {MAX_NODE_NAME_LEN} characters with no control characters"),
            ));
        }
        let log = LogConfig {
            level,
            node_name: lg.node_name.clone(),
        };

        Ok(Self {
            interfaces,
            boot,
            limits,
            tftp,
            recheck_interval,
            suppression,
            server_feed,
            log,
            trust: TrustPolicy::root_only(),
        })
    }

    /// The sans-IO TFTP server parameters.
    #[must_use]
    pub fn tftp_server_config(&self) -> usgp_tftp::ServerConfig {
        usgp_tftp::ServerConfig {
            max_block_size: self.tftp.max_block_size,
            initial_rto: self.tftp.initial_timeout,
            min_rto: self.tftp.min_timeout,
            max_rto: self.tftp.max_timeout,
            max_retries: self.tftp.max_retries,
            handshake_retries: self.tftp.handshake_retries,
            max_duration: self.tftp.max_transfer,
            max_file_size: self.tftp.max_file_size,
        }
    }

    /// The window and wraparound parameters (`usgp_tftp::admit_read_with`;
    /// RFC 7440, DEC-0018 item 2).
    #[must_use]
    pub fn tftp_window_config(&self) -> WindowConfig {
        WindowConfig {
            max_window_size: self.tftp.max_window_size,
            block_wrap: self.tftp.block_wrap,
        }
    }

    /// The TFTP listener parameters (transfer settings, window settings,
    /// and the relay's handshake timeout).
    #[must_use]
    pub fn tftp_listener_config(&self) -> crate::tftp::ListenerConfig {
        crate::tftp::ListenerConfig {
            server: self.tftp_server_config(),
            window: self.tftp_window_config(),
            handshake_timeout: self.tftp.handshake_timeout,
        }
    }

    /// Every configured interface address.
    #[must_use]
    pub fn local_addresses(&self) -> Vec<Ipv4Addr> {
        self.interfaces.iter().map(|i| i.address).collect()
    }
}

/// Validates `[server_feed]` (plan section 3.9). `None` unless
/// `enabled = true`.
///
// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 - the feed is off unless configured; every key is
//   checked; there is no setting that skips TLS or signature checks.
// - NIST 800-53: SC-8 / IA-3 - only `https` URLs; the server name is
//   checked by usgp-crypto's rules.
// - SPEC: specs/boot-network.md#REQ-BOOT-067 (status note: DEC-0021)
fn server_feed(
    doc: Option<&ServerFeedDocument>,
) -> Result<Option<ServerFeedConfig>, ConfigInvalid> {
    let Some(d) = doc else {
        return Ok(None);
    };
    if d.enabled != Some(true) {
        return Ok(None);
    }
    let raw_url = d
        .url
        .as_deref()
        .ok_or_else(|| invalid("server_feed.url", "is required"))?;
    let url = FeedUrl::parse(raw_url).map_err(|r| invalid("server_feed.url", r))?;
    let server_name = d.server_name.clone().unwrap_or_else(|| url.host.clone());
    if server_name.is_empty()
        || server_name.len() > 253
        || usgp_crypto::tls::ClientTls::check_server_name(&server_name).is_err()
    {
        return Err(invalid(
            "server_feed.server_name",
            "must be a DNS name or IP address",
        ));
    }
    let raw_id = d
        .boot_service_id
        .as_deref()
        .ok_or_else(|| invalid("server_feed.boot_service_id", "is required"))?;
    let boot_service_id = BootServiceId::parse(raw_id)
        .map_err(|_| invalid("server_feed.boot_service_id", "must be a non-nil UUID"))?;
    let cfg = ServerFeedConfig {
        url,
        server_name,
        trust_anchors: absolute_path("server_feed.trust_anchors", d.trust_anchors.as_ref())?,
        client_cert: absolute_path("server_feed.client_cert", d.client_cert.as_ref())?,
        client_key: absolute_path("server_feed.client_key", d.client_key.as_ref())?,
        boot_policy_key_pub: absolute_path(
            "server_feed.boot_policy_key_pub",
            d.boot_policy_key_pub.as_ref(),
        )?,
        boot_service_id,
        poll_interval: secs_in(
            "server_feed.poll_interval_s",
            d.poll_interval_s,
            30,
            5,
            3600,
        )?,
        cache_file: match d.cache_file.as_ref() {
            Some(f) => Some(absolute_path("server_feed.cache_file", Some(f))?),
            None => None,
        },
    };
    if cfg.client_cert == cfg.client_key {
        return Err(invalid(
            "server_feed.client_key",
            "must not be the client certificate file",
        ));
    }
    Ok(Some(cfg))
}

fn interfaces(docs: &[InterfaceDocument]) -> Result<Vec<InterfaceConfig>, ConfigInvalid> {
    if docs.is_empty() {
        return Err(invalid(
            "interface",
            "at least one [[interface]] is required",
        ));
    }
    if docs.len() > MAX_INTERFACES {
        return Err(invalid(
            "interface",
            format!("at most {MAX_INTERFACES} entries"),
        ));
    }
    let mut names = HashSet::new();
    let mut addrs = HashSet::new();
    let mut out = Vec::with_capacity(docs.len());
    for (i, d) in docs.iter().enumerate() {
        let name_field = format!("interface[{i}].name");
        let addr_field = format!("interface[{i}].address");
        let name = d
            .name
            .as_deref()
            .ok_or_else(|| invalid(&name_field, "is required"))?;
        if !valid_interface_name(name) {
            return Err(invalid(
                &name_field,
                format!("must be 1 to {MAX_INTERFACE_NAME_LEN} characters of [A-Za-z0-9._-]"),
            ));
        }
        if !names.insert(name.to_owned()) {
            return Err(invalid(&name_field, "duplicate interface name"));
        }
        let raw = d
            .address
            .as_deref()
            .ok_or_else(|| invalid(&addr_field, "is required"))?;
        let address = Ipv4Addr::from_str(raw)
            .map_err(|_| invalid(&addr_field, "must be a dotted-quad IPv4 address"))?;
        if !is_servable_address(address) {
            return Err(invalid(
                &addr_field,
                "must be a unicast address (not 0/8, 127/8, 169.254/16, 224/4, 240/4 or broadcast)",
            ));
        }
        if !addrs.insert(address) {
            return Err(invalid(&addr_field, "duplicate interface address"));
        }
        let prefix_len = match d.prefix_len {
            None => None,
            Some(v) => Some(u8_in(
                &format!("interface[{i}].prefix_len"),
                Some(v),
                0,
                i64::from(MIN_PREFIX_LEN),
                i64::from(MAX_PREFIX_LEN),
            )?),
        };
        out.push(InterfaceConfig {
            name: name.to_owned(),
            address,
            prefix_len,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// A validated configuration and the SHA-256 of the file it came from
/// (reported in `relay.start`).
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    /// The configuration.
    pub config: RelayConfig,
    /// SHA-256 of the configuration file bytes.
    pub sha256: Sha256Digest,
}

/// Turns TOML text into a [`ConfigDocument`]. Unknown keys at any level
/// and values of the wrong type are refused.
///
/// # Errors
///
/// [`ConfigLoadError::File`] with [`ConfigError::Parse`] (line and column).
pub fn parse_document(text: &str) -> Result<ConfigDocument, ConfigLoadError> {
    usgp_common::config::parse_toml(text).map_err(ConfigLoadError::File)
}

/// Reads, parses and validates the configuration at `path` under the
/// trusted-file rules of `trust` (usgp_common::config::read_trusted), then
/// checks the files it names (section 3.4, CM-5): the manifest follows the
/// same rules, and the boot root is a trusted directory. The boot root in
/// the returned configuration is the canonical path that was checked, and
/// every boot file is read below it. The suppression file is checked each
/// time it is loaded.
///
/// # Errors
///
/// [`ConfigLoadError`]; the caller exits 78.
pub fn load(path: &Path, trust: TrustPolicy) -> Result<LoadedConfig, ConfigLoadError> {
    let text = read_trusted(path, MAX_CONFIG_BYTES, &trust)?;
    let sha256 = usgp_crypto::sha256(text.as_bytes());
    let doc = parse_document(&text)?;
    let mut config = RelayConfig::from_document(&doc)?;
    config.trust = trust;
    // SI-7 / REQ-BOOT-041: resolve the boot root once, check that exact directory, and
    // read every boot file through it. A symbolic link in the configured
    // path that is retargeted later then has no effect.
    config.boot.root = canonical_root(&config.boot.root)?;
    check_trust_paths(&config)?;
    Ok(LoadedConfig { config, sha256 })
}

/// The canonical form of the configured boot root (every symbolic link
/// resolved).
fn canonical_root(root: &Path) -> Result<PathBuf, ConfigLoadError> {
    std::fs::canonicalize(root).map_err(|e| {
        ConfigLoadError::File(ConfigError::Io {
            path: root.to_path_buf(),
            kind: e.kind(),
        })
    })
}

/// Trust checks on the manifest and boot root named by `config`, under
/// `config.trust`.
///
/// # Errors
///
/// [`ConfigLoadError::File`] if a path cannot be inspected or breaks a
/// trust rule, or [`ConfigLoadError::Invalid`] if the root is not a
/// directory.
pub fn check_trust_paths(config: &RelayConfig) -> Result<(), ConfigLoadError> {
    ensure_trusted_file(&config.boot.manifest, &config.trust)?;
    if let Some(f) = &config.server_feed {
        // The feed's anchors, certificate, key and pinned public key are
        // trust anchors too (CM-5, SC-12); the key's mode rule is applied
        // when it is read (crate::files).
        for p in [
            &f.trust_anchors,
            &f.client_cert,
            &f.client_key,
            &f.boot_policy_key_pub,
        ] {
            ensure_trusted_file(p, &config.trust)?;
        }
    }
    let root = &config.boot.root;
    let meta = std::fs::metadata(root).map_err(|e| ConfigError::Io {
        path: root.clone(),
        kind: e.kind(),
    })?;
    if !meta.is_dir() {
        return Err(invalid("boot.root", "must be a directory").into());
    }
    ensure_trusted_dir(root, &config.trust)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn servable_address_rules() {
        for ok in [
            "10.0.0.1",
            "192.168.1.2",
            "172.16.0.1",
            "8.8.8.8",
            "223.255.255.254",
        ] {
            assert!(is_servable_address(ok.parse().unwrap()), "{ok}");
        }
        for bad in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "127.255.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!is_servable_address(bad.parse().unwrap()), "{bad}");
        }
    }

    #[test]
    fn interface_name_rules() {
        for ok in ["eth0", "enp0s3", "br-a", "vlan.10", "a", "abcdefghijklmno"] {
            assert!(valid_interface_name(ok), "{ok}");
        }
        for bad in [
            "",
            "abcdefghijklmnop",
            "eth 0",
            "eth0/1",
            "*",
            ".",
            "..",
            "eth0:1",
            "é",
        ] {
            assert!(!valid_interface_name(bad), "{bad}");
        }
    }

    #[test]
    fn parse_document_minimal() {
        let d = parse_document(
            "schema_version = 1\n[[interface]]\nname = \"eth0\"\naddress = \"10.0.0.2\"\n",
        )
        .unwrap();
        assert_eq!(d.schema_version, Some(1));
        assert_eq!(d.interface.len(), 1);
        assert_eq!(d.boot, None);
    }

    #[test]
    fn parse_document_refuses_unknown_keys_at_every_level() {
        for text in [
            "schema_version = 1\nbogus = 1\n",
            "[[interface]]\nname = \"eth0\"\nmtu = 1500\n",
            "[boot]\nmanifests = \"/x\"\n",
            "[limits]\ndhcp_client_burstt = 1\n",
            "[tftp]\nwindowsize = 4\n",
            "[server_feed]\npoll_interval = 30\n",
            "[content]\nx = 1\n",
            "[suppression]\npath = \"/x\"\n",
            "[log]\nformat = \"json\"\n",
            "[dhcp]\ntrusted_relay_agents = []\n",
        ] {
            assert!(
                matches!(
                    parse_document(text),
                    Err(ConfigLoadError::File(ConfigError::Parse { .. }))
                ),
                "{text}"
            );
        }
    }

    #[test]
    fn parse_document_refuses_wrong_types() {
        for text in [
            "schema_version = \"1\"\n",
            "schema_version = 1.0\n",
            "[limits]\ndhcp_client_burst = \"8\"\n",
            "interface = \"eth0\"\n",
            "[[interface]]\naddress = 167772162\n",
            "not toml at all",
        ] {
            assert!(parse_document(text).is_err(), "{text}");
        }
    }
}
