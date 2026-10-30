//! The agent package manifest `agent.json` (M4 plan section 1.7;
//! decision 0024 item 2).
//!
//! An agent package is a ZIP the operator uploads with a detached
//! signature by a registered signer key. `agent.json` at its root says how
//! to run the installer at step 8. The rest of the ZIP is the enrolment
//! configuration, which is opaque and holds no secret.
//!
//! - `installer`: a relative path inside the ZIP ending in `.exe` or
//!   `.msi` (an `.msi` runs as `msiexec.exe /i <path> /qn /norestart`
//!   plus `args`);
//! - `args`: at most 32, each at most 1 024 characters, without `{{`;
//! - `success_exit_codes`: default `[0, 3010]`;
//! - `timeout_s`: 1 s to 6 h, default 3 h (REQ-SEQ-005);
//! - `service_name`: optional; checked for Running within 600 s.
//!
//! The runner never uses a shell and never restarts the machine.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 - size cap before parsing; strict serde; bounded
//   lists and text; relative paths without traversal.
// - NIST 800-53: CM-7 (Least Functionality, basis) - argv only, no shell,
//   no template references in arguments.
// - NIST 800-53: SI-7 (basis) - the package is signed and its digest is
//   in the signed plan; this manifest is read only after those checks.
// - SPEC: specs/agent-handoff.md#REQ-AGT-001,
//   specs/workflow.md#REQ-SEQ-005 (install timeout)
// - DECISION: docs/decisions/0024 item 2, 0025 item 5

use crate::limits::{MAX_AGENT_ARGS, MAX_AGENT_EXIT_CODES, MAX_AGENT_MANIFEST_BYTES};
use crate::names::{InstallerArg, RelPath, ServiceName};

/// Default install timeout (3 h).
pub const DEFAULT_AGENT_TIMEOUT_S: u32 = 3 * 3600;

/// Longest install timeout (6 h).
pub const MAX_AGENT_TIMEOUT_S: u32 = 6 * 3600;

/// Default accepted exit codes: success, and success with a restart
/// pending.
pub const DEFAULT_SUCCESS_EXIT_CODES: [u32; 2] = [0, 3010];

/// How the installer is run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallerKind {
    /// An executable, run directly.
    Exe,
    /// A Windows Installer package, run through `msiexec.exe`.
    Msi,
}

/// Why `agent.json` was refused. Never carries file content.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AgentPackageManifestError {
    /// Over [`MAX_AGENT_MANIFEST_BYTES`].
    #[error("agent.json is {len} bytes; the limit is {MAX_AGENT_MANIFEST_BYTES}")]
    TooLarge {
        /// Length in bytes.
        len: usize,
    },
    /// Not JSON of the expected shape.
    #[error("agent.json is not valid JSON of the expected shape")]
    Json(#[source] serde_json::Error),
    /// A value is not acceptable; the text names the key and the rule.
    #[error("agent.json: {0}")]
    Invalid(&'static str),
}

fn default_exit_codes() -> Vec<u32> {
    DEFAULT_SUCCESS_EXIT_CODES.to_vec()
}

const fn default_timeout() -> u32 {
    DEFAULT_AGENT_TIMEOUT_S
}

/// `agent.json`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPackageManifestV1 {
    /// The installer, relative to the ZIP root.
    pub installer: RelPath,
    /// Arguments (after the `msiexec` ones for an `.msi`).
    #[serde(default)]
    pub args: Vec<InstallerArg>,
    /// Exit codes that mean success (1 to 32 values).
    #[serde(default = "default_exit_codes")]
    pub success_exit_codes: Vec<u32>,
    /// Timeout in seconds (1 to [`MAX_AGENT_TIMEOUT_S`]).
    #[serde(default = "default_timeout")]
    pub timeout_s: u32,
    /// A service that must be Running within 600 s after the install.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<ServiceName>,
}

impl AgentPackageManifestV1 {
    /// Checks every rule beyond the types.
    ///
    /// # Errors
    ///
    /// [`AgentPackageManifestError::Invalid`] naming the first rule
    /// broken.
    pub fn validate(&self) -> Result<(), AgentPackageManifestError> {
        use AgentPackageManifestError::Invalid;
        if self.installer_kind().is_none() {
            return Err(Invalid("installer must end in .exe or .msi"));
        }
        if self.args.len() > MAX_AGENT_ARGS {
            return Err(Invalid("args must list at most 32 arguments"));
        }
        if self.success_exit_codes.is_empty()
            || self.success_exit_codes.len() > MAX_AGENT_EXIT_CODES
        {
            return Err(Invalid("success_exit_codes must list 1 to 32 codes"));
        }
        if self.timeout_s == 0 || self.timeout_s > MAX_AGENT_TIMEOUT_S {
            return Err(Invalid("timeout_s must be 1 s to 6 h"));
        }
        Ok(())
    }

    /// How the installer runs, from its extension.
    #[must_use]
    pub fn installer_kind(&self) -> Option<InstallerKind> {
        if self.installer.has_extension(".exe") {
            Some(InstallerKind::Exe)
        } else if self.installer.has_extension(".msi") {
            Some(InstallerKind::Msi)
        } else {
            None
        }
    }

    /// Parses and validates `agent.json`, checking the size first.
    ///
    /// # Errors
    ///
    /// [`AgentPackageManifestError`].
    pub fn from_json(bytes: &[u8]) -> Result<Self, AgentPackageManifestError> {
        if bytes.len() > MAX_AGENT_MANIFEST_BYTES {
            return Err(AgentPackageManifestError::TooLarge { len: bytes.len() });
        }
        let m: Self = serde_json::from_slice(bytes).map_err(AgentPackageManifestError::Json)?;
        m.validate()?;
        Ok(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<AgentPackageManifestV1, AgentPackageManifestError> {
        AgentPackageManifestV1::from_json(s.as_bytes())
    }

    #[test]
    fn defaults_and_kinds() {
        let m = p(r#"{"installer":"setup/Agent.MSI"}"#).unwrap();
        assert_eq!(m.installer_kind(), Some(InstallerKind::Msi));
        assert_eq!(m.success_exit_codes, [0, 3010]);
        assert_eq!(m.timeout_s, 10_800);
        assert!(m.args.is_empty() && m.service_name.is_none());
        let m = p(r#"{"installer":"a.exe","args":["/S"],"success_exit_codes":[0],"timeout_s":21600,"service_name":"agentsvc"}"#).unwrap();
        assert_eq!(m.installer_kind(), Some(InstallerKind::Exe));
    }

    #[test]
    fn refusals() {
        let too_many = format!(
            r#"{{"installer":"a.exe","args":[{}]}}"#,
            vec!["\"x\""; 33].join(",")
        );
        for bad in [
            r#"{"installer":"a.bat"}"#,
            r#"{"installer":"../a.exe"}"#,
            r#"{"installer":"/a.exe"}"#,
            r#"{"installer":"a.exe","args":["X={{computer_name}}"]}"#,
            r#"{"installer":"a.exe","timeout_s":0}"#,
            r#"{"installer":"a.exe","timeout_s":21601}"#,
            r#"{"installer":"a.exe","success_exit_codes":[]}"#,
            r#"{"installer":"a.exe","service_name":"a\\b"}"#,
            r#"{"installer":"a.exe","shell":true}"#,
            too_many.as_str(),
        ] {
            assert!(p(bad).is_err(), "{bad}");
        }
        let big = vec![b' '; MAX_AGENT_MANIFEST_BYTES + 1];
        assert!(matches!(
            AgentPackageManifestV1::from_json(&big),
            Err(AgentPackageManifestError::TooLarge { .. })
        ));
    }
}
