//! The public agent configuration, `agent.toml` (plan section 3.9).
//!
//! The operator places it next to the agent in their Windows PE
//! (decision 0020). It is readable by anyone on the boot segment, so it
//! holds no secret: the server address, the server trust anchors, and the
//! two public keys the device pins for the signed job plan and the signed
//! content manifest (plan section 0 item 1). There is no setting that
//! skips the TLS or signature checks.
//!
//! The file format, its size limit, the URL and host rules and the ranges
//! are shared with `usgp-cli pe agent-config`, which writes the file
//! ([`usgp_proto::agent_config`]). This module reads the files it names
//! and parses the keys through `usgp-crypto`.

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 (Configuration Settings) - secure defaults; unknown
//   keys refuse start; no option weakens TLS or signature checks.
// - NIST 800-53: SI-10 (Information Input Validation) - bounded file
//   sizes, validated URL, host name and ranges.
// - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management) -
//   pinned public keys, one per purpose.
// - SPEC: specs/preinstall-env.md#REQ-PE-015
// - DECISION: docs/decisions/0020 (public configuration, no secret)

use std::path::Path;
use std::time::Duration;

use usgp_crypto::VerifyingKey;
use usgp_deploy::{PinnedKey, PlanKeys};
use usgp_proto::agent_config::{AgentConfigError, AgentConfigFile};

pub use usgp_proto::agent_config::{CONNECT_TIMEOUT_S, NETWORK_WAIT_S, parse_server_url};

pub use usgp_proto::agent_config::MAX_CONFIG_BYTES;
/// Largest trust-anchor PEM file read (design bound).
pub const MAX_ANCHORS_BYTES: u64 = 256 * 1024;
/// Largest public-key PEM file read (design bound).
pub const MAX_KEY_BYTES: u64 = 16 * 1024;

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

impl From<AgentConfigError> for ConfigError {
    fn from(e: AgentConfigError) -> Self {
        match e {
            AgentConfigError::Parse(p) => Self::Read(p),
            AgentConfigError::Invalid { key, reason } => Self::Invalid { key, reason },
            AgentConfigError::TooLarge => invalid("agent.toml", "larger than 64 KiB"),
            // Only from writing; not reachable when reading. Fail closed.
            _ => invalid("agent.toml", "not acceptable"),
        }
    }
}

fn invalid(key: &'static str, reason: &'static str) -> ConfigError {
    ConfigError::Invalid { key, reason }
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
    let max = u64::try_from(MAX_CONFIG_BYTES).unwrap_or(u64::MAX);
    let text = usgp_common::config::read_bounded(path, max)?;
    let raw = AgentConfigFile::from_toml(&text)?;
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
    let settings = usgp_proto::agent_config::settings(
        server_url,
        server_name,
        network_wait_s,
        connect_timeout_s,
    )?;
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
    Ok(AgentConfig {
        endpoint: Endpoint {
            host: settings.host,
            port: settings.port,
            server_name: settings.server_name,
        },
        trust_anchors_pem,
        keys,
        network_wait: Duration::from_secs(settings.network_wait_s),
        connect_timeout: Duration::from_secs(settings.connect_timeout_s),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_rules_apply() {
        // The URL, host and range rules are `usgp_proto::agent_config`'s
        // (tested there); this checks the mapping of its refusals.
        let e = from_parts("http://x", None, b"x".to_vec(), b"", b"", None, None).unwrap_err();
        assert!(
            matches!(
                e,
                ConfigError::Invalid {
                    key: "server_url",
                    ..
                }
            ),
            "{e}"
        );
        let e = from_parts("https://x", None, b"x".to_vec(), b"", b"", Some(9), None).unwrap_err();
        assert!(
            matches!(
                e,
                ConfigError::Invalid {
                    key: "network_wait_s",
                    ..
                }
            ),
            "{e}"
        );
        assert_eq!(
            parse_server_url("https://[fd00::5]:8444"),
            Ok(("fd00::5".to_owned(), 8444))
        );
    }
}
