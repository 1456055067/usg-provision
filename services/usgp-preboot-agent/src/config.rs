//! The public agent configuration, `agent.toml` (plan section 3.9).
//!
//! The operator places it next to the agent in their Windows PE
//! (decision 0020). It is readable by anyone on the boot segment, so it
//! holds no secret: the server address, the server trust anchors, and the
//! two public keys the device pins for the signed job plan and the signed
//! content manifest (plan section 0 item 1). There is no setting that
//! skips the TLS or signature checks.
//!
//! ```toml
//! server_url = "https://provision.example.gov:8444"
//! server_name = "provision.example.gov"   # optional; default: the URL host
//! trust_anchors = "trust-anchors.pem"     # relative to this file
//! plan_key_pub = "plan.pub"
//! content_key_pub = "content.pub"
//! network_wait_s = 120                    # 10 to 600
//! connect_timeout_s = 15                  # 1 to 120
//! ```

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 (Configuration Settings) - secure defaults; unknown
//   keys refuse start; no option weakens TLS or signature checks.
// - NIST 800-53: SI-10 (Information Input Validation) - bounded file
//   sizes, validated URL, host name and ranges.
// - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management) -
//   pinned public keys, one per purpose.
// - SPEC: specs/preinstall-env.md#REQ-PE-015
// - DECISION: docs/decisions/0020 (public configuration, no secret)

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use usgp_crypto::VerifyingKey;
use usgp_deploy::{PinnedKey, PlanKeys};

/// Largest `agent.toml` read (plan section 3.9).
pub const MAX_CONFIG_BYTES: u64 = 64 * 1024;
/// Largest trust-anchor PEM file read (design bound).
pub const MAX_ANCHORS_BYTES: u64 = 256 * 1024;
/// Largest public-key PEM file read (design bound).
pub const MAX_KEY_BYTES: u64 = 16 * 1024;
/// Network wait bounds and default in seconds (plan section 3.9).
pub const NETWORK_WAIT_S: (u64, u64, u64) = (10, 600, 120);
/// Connect timeout bounds and default in seconds (plan section 3.9 gives
/// the default; the bounds are a design choice).
pub const CONNECT_TIMEOUT_S: (u64, u64, u64) = (1, 120, 15);
/// Longest DNS name accepted (RFC 1035 §2.3.4).
const MAX_HOST_LEN: usize = 253;

/// Why the configuration was refused. Never carries file content.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A file could not be read or parsed.
    #[error(transparent)]
    Read(#[from] usgp_common::config::ConfigError),
    /// A value is not acceptable.
    #[error("agent.toml: {key}: {reason}")]
    Invalid {
        /// The key.
        key: &'static str,
        /// Why.
        reason: &'static str,
    },
}

fn invalid(key: &'static str, reason: &'static str) -> ConfigError {
    ConfigError::Invalid { key, reason }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentToml {
    server_url: String,
    server_name: Option<String>,
    trust_anchors: PathBuf,
    plan_key_pub: PathBuf,
    content_key_pub: PathBuf,
    network_wait_s: Option<u64>,
    connect_timeout_s: Option<u64>,
}

/// Where the server is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Host to connect to: a DNS name or an IP literal (IPv6 without
    /// brackets).
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// The name the server certificate must carry.
    pub server_name: String,
}

/// The validated configuration.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// The server.
    pub endpoint: Endpoint,
    /// Trust anchors for the server certificate, PEM.
    pub trust_anchors_pem: Vec<u8>,
    /// The pinned plan and content keys.
    pub keys: PlanKeys,
    /// How long to wait for a DHCP address (REQ-PE-014).
    pub network_wait: Duration,
    /// TCP connect timeout.
    pub connect_timeout: Duration,
}

/// Reads and validates `path` and the files it names (relative paths are
/// taken from the configuration file's directory).
///
/// # Errors
///
/// [`ConfigError`] naming the file or key.
pub fn load(path: &Path) -> Result<AgentConfig, ConfigError> {
    let text = usgp_common::config::read_bounded(path, MAX_CONFIG_BYTES)?;
    let raw: AgentToml = usgp_common::config::parse_toml(&text)?;
    let base = path.parent().unwrap_or(Path::new("."));
    let resolve = |p: &Path| {
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            base.join(p)
        }
    };
    let anchors =
        usgp_common::config::read_bounded(&resolve(&raw.trust_anchors), MAX_ANCHORS_BYTES)?;
    let plan_pem = usgp_common::config::read_bounded(&resolve(&raw.plan_key_pub), MAX_KEY_BYTES)?;
    let content_pem =
        usgp_common::config::read_bounded(&resolve(&raw.content_key_pub), MAX_KEY_BYTES)?;
    from_parts(
        &raw.server_url,
        raw.server_name.as_deref(),
        anchors.into_bytes(),
        plan_pem.as_bytes(),
        content_pem.as_bytes(),
        raw.network_wait_s,
        raw.connect_timeout_s,
    )
}

/// Validates the configuration from its parts (also used by tests and the
/// simulation, which hold the keys in memory).
///
/// # Errors
///
/// [`ConfigError::Invalid`].
pub fn from_parts(
    server_url: &str,
    server_name: Option<&str>,
    trust_anchors_pem: Vec<u8>,
    plan_key_pem: &[u8],
    content_key_pem: &[u8],
    network_wait_s: Option<u64>,
    connect_timeout_s: Option<u64>,
) -> Result<AgentConfig, ConfigError> {
    let (host, port) = parse_server_url(server_url).map_err(|r| invalid("server_url", r))?;
    let server_name = match server_name {
        Some(n) => {
            check_host(n).map_err(|r| invalid("server_name", r))?;
            n.to_owned()
        }
        None => host.clone(),
    };
    if trust_anchors_pem.is_empty() {
        return Err(invalid("trust_anchors", "the file is empty"));
    }
    let plan = VerifyingKey::from_spki_pem(plan_key_pem)
        .map_err(|_| invalid("plan_key_pub", "not a P-384 public key in PEM"))?;
    let content = VerifyingKey::from_spki_pem(content_key_pem)
        .map_err(|_| invalid("content_key_pub", "not a P-384 public key in PEM"))?;
    let keys = PlanKeys {
        plan: PinnedKey::new(plan),
        content: PinnedKey::new(content),
    };
    // One key, one purpose (plan section 5): a plan key that could also
    // verify content manifests, or the reverse, is refused.
    if keys.plan.key_id() == keys.content.key_id() {
        return Err(invalid(
            "plan_key_pub",
            "must differ from content_key_pub (one key per purpose)",
        ));
    }
    let network_wait_s = in_range(network_wait_s, NETWORK_WAIT_S)
        .ok_or_else(|| invalid("network_wait_s", "must be 10 to 600"))?;
    let connect_timeout_s = in_range(connect_timeout_s, CONNECT_TIMEOUT_S)
        .ok_or_else(|| invalid("connect_timeout_s", "must be 1 to 120"))?;
    Ok(AgentConfig {
        endpoint: Endpoint {
            host,
            port,
            server_name,
        },
        trust_anchors_pem,
        keys,
        network_wait: Duration::from_secs(network_wait_s),
        connect_timeout: Duration::from_secs(connect_timeout_s),
    })
}

fn in_range(v: Option<u64>, (min, max, default): (u64, u64, u64)) -> Option<u64> {
    let v = v.unwrap_or(default);
    (min..=max).contains(&v).then_some(v)
}

/// Splits `https://host[:port][/]` into host and port (default 443).
///
/// Only `https` is accepted (plan section 3.9). No user information,
/// path, query or fragment. IPv6 literals are written in brackets and
/// returned without them.
///
/// # Errors
///
/// A fixed reason.
pub fn parse_server_url(url: &str) -> Result<(String, u16), &'static str> {
    const SCHEME: &str = "https://";
    let scheme = url.get(..SCHEME.len()).ok_or("must start with https://")?;
    if !scheme.eq_ignore_ascii_case(SCHEME) {
        return Err("must start with https://");
    }
    let rest = url.get(SCHEME.len()..).ok_or("must start with https://")?;
    let authority = match rest.find('/') {
        Some(i) => {
            if rest.get(i..) != Some("/") {
                return Err("must not have a path");
            }
            rest.get(..i).ok_or("bad authority")?
        }
        None => rest,
    };
    if authority.contains(['@', '?', '#']) {
        return Err("must not have user information, a query or a fragment");
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']').ok_or("unclosed IPv6 bracket")?;
        if !matches!(h.parse::<IpAddr>(), Ok(IpAddr::V6(_))) {
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
    if !host.contains(':') {
        check_host(host)?;
    }
    let port = match port {
        None => 443,
        Some(p) => parse_port(p)?,
    };
    Ok((host.to_owned(), port))
}

fn parse_port(p: &str) -> Result<u16, &'static str> {
    if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
        return Err("bad port");
    }
    match p.parse::<u16>() {
        Ok(0) | Err(_) => Err("bad port"),
        Ok(n) => Ok(n),
    }
}

/// Accepts an IP literal or a DNS name (letters, digits and hyphens in
/// labels of 1 to 63 characters, no leading or trailing hyphen).
fn check_host(h: &str) -> Result<(), &'static str> {
    if h.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if h.is_empty() || h.len() > MAX_HOST_LEN {
        return Err("bad host name length");
    }
    let ok = h.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    if ok { Ok(()) } else { Err("bad host name") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_url_forms() {
        assert_eq!(
            parse_server_url("https://prov.example.gov:8444"),
            Ok(("prov.example.gov".to_owned(), 8444))
        );
        assert_eq!(
            parse_server_url("HTTPS://prov.example.gov/"),
            Ok(("prov.example.gov".to_owned(), 443))
        );
        assert_eq!(
            parse_server_url("https://10.0.0.5:8444"),
            Ok(("10.0.0.5".to_owned(), 8444))
        );
        assert_eq!(
            parse_server_url("https://[fd00::5]:8444"),
            Ok(("fd00::5".to_owned(), 8444))
        );
        for bad in [
            "http://prov.example.gov",
            "https://",
            "https://prov.example.gov:0",
            "https://prov.example.gov:65536",
            "https://prov.example.gov:84a4",
            "https://user@prov.example.gov",
            "https://prov.example.gov/v1",
            "https://prov.example.gov?x",
            "https://prov.example.gov#x",
            "https://-bad.example.gov",
            "https://bad_host.example.gov",
            "https://[fd00::5",
            "https://[10.0.0.5]:1",
            "https://a..b",
            "ftp://x",
            "",
        ] {
            assert!(parse_server_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ranges() {
        assert_eq!(in_range(None, NETWORK_WAIT_S), Some(120));
        assert_eq!(in_range(Some(9), NETWORK_WAIT_S), None);
        assert_eq!(in_range(Some(600), NETWORK_WAIT_S), Some(600));
        assert_eq!(in_range(Some(601), NETWORK_WAIT_S), None);
        assert_eq!(in_range(Some(0), CONNECT_TIMEOUT_S), None);
    }
}
