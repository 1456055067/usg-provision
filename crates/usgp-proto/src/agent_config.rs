//! The pre-boot agent's public configuration file, `agent.toml` (M3 plan
//! section 3.9; decision 0020 as clarified). One type shared by the agent,
//! which reads it, and `usgp-cli pe agent-config`, which writes it.
//!
//! The operator places the file next to the agent in their own Windows PE.
//! It is served to any device that boots that PE, so it holds no secret:
//! the server address, the server trust anchors, and the two public keys
//! the device pins for the signed job plan and the signed content
//! manifest. There is no setting that skips the TLS or signature checks.
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
//!
//! This module checks the text: size, keys, URL, host name and ranges. The
//! referenced PEM files are checked by the reader (the agent parses the
//! keys through `usgp-crypto`); this crate does no cryptography and no I/O.

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 (Configuration Settings) - secure defaults; unknown
//   keys refused; no option weakens TLS or signature checks.
// - NIST 800-53: SI-10 (Information Input Validation) - bounded text,
//   validated URL, host name and ranges.
// - SPEC: specs/preinstall-env.md#REQ-PE-015
// - DECISION: docs/decisions/0020 (public configuration, no secret)

use std::net::IpAddr;
use std::path::PathBuf;

use usgp_common::config::{ConfigError, parse_toml};

/// Largest `agent.toml` accepted (plan section 3.9).
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;
/// Network wait (min, max, default) in seconds (plan section 3.9).
pub const NETWORK_WAIT_S: (u64, u64, u64) = (10, 600, 120);
/// Connect timeout (min, max, default) in seconds (plan section 3.9 gives
/// the default; the bounds are a design choice).
pub const CONNECT_TIMEOUT_S: (u64, u64, u64) = (1, 120, 15);
/// Longest DNS name accepted (RFC 1035 §2.3.4).
const MAX_HOST_LEN: usize = 253;
/// Longest DNS label accepted (RFC 1035 §2.3.4).
const MAX_LABEL_LEN: usize = 63;

/// `agent.toml` as written. Paths are taken relative to the file's own
/// directory when they are not absolute.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfigFile {
    /// `https://host[:port][/]`.
    pub server_url: String,
    /// The name the server certificate must carry; default: the URL host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    /// PEM file of the server trust anchors.
    pub trust_anchors: PathBuf,
    /// PEM file of the public key that verifies signed job plans.
    pub plan_key_pub: PathBuf,
    /// PEM file of the public key that verifies signed content manifests.
    pub content_key_pub: PathBuf,
    /// Seconds to wait for a network address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_wait_s: Option<u64>,
    /// TCP connect timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_s: Option<u64>,
}

/// Why `agent.toml` was refused. Never carries file content beyond the
/// parser's position.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AgentConfigError {
    /// The text is larger than [`MAX_CONFIG_BYTES`].
    #[error("agent.toml is larger than the {MAX_CONFIG_BYTES}-byte limit")]
    TooLarge,
    /// The text is not TOML of the expected shape (includes unknown keys).
    #[error(transparent)]
    Parse(#[from] ConfigError),
    /// A value is not acceptable.
    #[error("agent.toml: {key}: {reason}")]
    Invalid {
        /// The key.
        key: &'static str,
        /// Why.
        reason: &'static str,
    },
    /// The file could not be written as TOML (a path is not UTF-8).
    #[error("agent.toml: cannot be written: a path is not valid UTF-8")]
    NotWritable,
}

/// The checked, non-file settings of `agent.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSettings {
    /// Host to connect to: a DNS name or an IP literal (IPv6 without
    /// brackets).
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// The name the server certificate must carry.
    pub server_name: String,
    /// Seconds to wait for a network address.
    pub network_wait_s: u64,
    /// TCP connect timeout in seconds.
    pub connect_timeout_s: u64,
}

fn invalid(key: &'static str, reason: &'static str) -> AgentConfigError {
    AgentConfigError::Invalid { key, reason }
}

impl AgentConfigFile {
    /// Parses and checks `agent.toml` text ([`Self::settings`]).
    ///
    /// # Errors
    ///
    /// [`AgentConfigError`].
    pub fn from_toml(text: &str) -> Result<Self, AgentConfigError> {
        if text.len() > MAX_CONFIG_BYTES {
            return Err(AgentConfigError::TooLarge);
        }
        let file: Self = parse_toml(text)?;
        file.settings()?;
        for (key, p) in [
            ("trust_anchors", &file.trust_anchors),
            ("plan_key_pub", &file.plan_key_pub),
            ("content_key_pub", &file.content_key_pub),
        ] {
            if p.as_os_str().is_empty() {
                return Err(invalid(key, "must name a file"));
            }
        }
        Ok(file)
    }

    /// TOML text that [`Self::from_toml`] reads back unchanged.
    ///
    /// # Errors
    ///
    /// [`AgentConfigError::NotWritable`] if a path is not UTF-8.
    pub fn to_toml(&self) -> Result<String, AgentConfigError> {
        toml::to_string(self).map_err(|_| AgentConfigError::NotWritable)
    }

    /// Checks the URL, server name and ranges.
    ///
    /// # Errors
    ///
    /// [`AgentConfigError::Invalid`] naming the key.
    pub fn settings(&self) -> Result<AgentSettings, AgentConfigError> {
        settings(
            &self.server_url,
            self.server_name.as_deref(),
            self.network_wait_s,
            self.connect_timeout_s,
        )
    }
}

/// Checks the non-file settings from their parts (also for callers that
/// hold them in memory, such as tests and the simulation).
///
/// # Errors
///
/// [`AgentConfigError::Invalid`] naming the key.
pub fn settings(
    server_url: &str,
    server_name: Option<&str>,
    network_wait_s: Option<u64>,
    connect_timeout_s: Option<u64>,
) -> Result<AgentSettings, AgentConfigError> {
    let (host, port) = parse_server_url(server_url).map_err(|r| invalid("server_url", r))?;
    let server_name = match server_name {
        Some(n) => {
            check_host(n).map_err(|r| invalid("server_name", r))?;
            n.to_owned()
        }
        None => host.clone(),
    };
    let network_wait_s = in_range(network_wait_s, NETWORK_WAIT_S)
        .ok_or_else(|| invalid("network_wait_s", "must be 10 to 600"))?;
    let connect_timeout_s = in_range(connect_timeout_s, CONNECT_TIMEOUT_S)
        .ok_or_else(|| invalid("connect_timeout_s", "must be 1 to 120"))?;
    Ok(AgentSettings {
        host,
        port,
        server_name,
        network_wait_s,
        connect_timeout_s,
    })
}

/// `v`, or the default, if it lies in `min..=max`.
#[must_use]
pub fn in_range(v: Option<u64>, (min, max, default): (u64, u64, u64)) -> Option<u64> {
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
///
/// # Errors
///
/// A fixed reason.
pub fn check_host(h: &str) -> Result<(), &'static str> {
    if h.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if h.is_empty() || h.len() > MAX_HOST_LEN {
        return Err("bad host name length");
    }
    let ok = h.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
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

    const DOC: &str = "server_url = \"https://provision.example.gov:8444\"\n\
                       server_name = \"provision.example.gov\"\n\
                       trust_anchors = \"trust-anchors.pem\"\n\
                       plan_key_pub = \"plan.pub\"\n\
                       content_key_pub = \"content.pub\"\n\
                       network_wait_s = 120\n\
                       connect_timeout_s = 15\n";

    #[test]
    fn module_doc_example_parses() {
        let f = AgentConfigFile::from_toml(DOC).unwrap();
        let s = f.settings().unwrap();
        assert_eq!(s.host, "provision.example.gov");
        assert_eq!(s.port, 8444);
        assert_eq!(f.plan_key_pub, PathBuf::from("plan.pub"));
        assert_eq!(
            AgentConfigFile::from_toml(&f.to_toml().unwrap()).unwrap(),
            f
        );
    }

    #[test]
    fn minimal_round_trip_writes_no_optional_keys() {
        let f = AgentConfigFile {
            server_url: "https://10.0.0.5".into(),
            server_name: None,
            trust_anchors: "a.pem".into(),
            plan_key_pub: "p.pub".into(),
            content_key_pub: "c.pub".into(),
            network_wait_s: None,
            connect_timeout_s: None,
        };
        let text = f.to_toml().unwrap();
        assert!(
            !text.contains("server_name") && !text.contains("_s ="),
            "{text}"
        );
        assert_eq!(AgentConfigFile::from_toml(&text).unwrap(), f);
        let s = f.settings().unwrap();
        assert_eq!((s.network_wait_s, s.connect_timeout_s), (120, 15));
        assert_eq!(s.server_name, "10.0.0.5");
    }

    #[test]
    fn refusals() {
        for bad in [
            format!("{DOC}skip_tls = true\n"),
            DOC.replace("https://", "http://"),
            DOC.replace("network_wait_s = 120", "network_wait_s = 9"),
            DOC.replace("connect_timeout_s = 15", "connect_timeout_s = 0"),
            DOC.replace(
                "server_name = \"provision.example.gov\"",
                "server_name = \"a_b\"",
            ),
            DOC.replace("plan_key_pub = \"plan.pub\"", "plan_key_pub = \"\""),
            DOC.replace("plan_key_pub = \"plan.pub\"\n", ""),
            format!("{DOC}{}", "#".repeat(MAX_CONFIG_BYTES)),
        ] {
            assert!(AgentConfigFile::from_toml(&bad).is_err(), "{bad}");
        }
    }

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
