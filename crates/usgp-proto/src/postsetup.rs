//! The post-setup configuration `job.json` (M4 plan section 1.2).
//!
//! The Windows PE agent writes it at step 5 to
//! `<W>:\ProgramData\usgp\postsetup\job.json` next to the agent binary,
//! the agent package and `job.key`. After the restart, `SetupComplete.cmd`
//! starts the same binary in `postsetup` mode, which reads this file.
//!
//! It holds **no secret**: the server URL and name, the server trust
//! anchors and the pinned plan key as PEM text (the Windows PE files are
//! not on the installed volume), the full signed plan envelope, the job
//! id, the agent binary's SHA-256, and the *names* of the agent package
//! and job key files in the same folder. The job private key is in
//! `job.key`, written with a SYSTEM-only DACL, never here.
//!
//! Before acting, the runner checks the plan signature again, that the
//! plan's `job_key_id` is the key in `job.key`, and the agent package's
//! SHA-256 against the plan (those checks need `usgp-crypto`).

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 (Configuration Settings) - strict parse, unknown
//   keys refused; nothing can weaken TLS or signature checks.
// - NIST 800-53: SI-7 (basis) - the signed plan is re-verified after the
//   restart; the agent binary's digest is recorded.
// - NIST 800-53: SI-10 - size cap before parsing; bounded text; file
//   names only (no paths, no traversal).
// - SPEC: specs/workflow.md (post-setup steps 7 to 9)
// - DECISION: docs/decisions/0024 item 1, 0025 item 1

use usgp_common::Sha256Digest;

use crate::agent_config::{check_host, parse_server_url};
use crate::envelope::{PayloadType, SignedEnvelopeV1};
use crate::ids::JobId;
use crate::limits::{MAX_POSTSETUP_CONFIG_BYTES, MAX_POSTSETUP_PEM_BYTES};
use crate::names::FileName;

/// The only `job.json` schema version.
pub const POSTSETUP_SCHEMA_V1: u32 = 1;

/// Why `job.json` was refused. Never carries file content.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PostSetupConfigError {
    /// Over [`MAX_POSTSETUP_CONFIG_BYTES`].
    #[error("job.json is {len} bytes; the limit is {MAX_POSTSETUP_CONFIG_BYTES}")]
    TooLarge {
        /// Length in bytes.
        len: usize,
    },
    /// Not JSON of the expected shape.
    #[error("job.json is not valid JSON of the expected shape")]
    Json(#[source] serde_json::Error),
    /// A value is not acceptable; the text names the key and the rule.
    #[error("job.json: {0}")]
    Invalid(&'static str),
}

/// `job.json` (non-secret).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostSetupConfigV1 {
    /// Always [`POSTSETUP_SCHEMA_V1`].
    pub schema: u32,
    /// `https://host[:port][/]` of the device listener.
    pub server_url: String,
    /// The name the server certificate must carry.
    pub server_name: String,
    /// PEM text of the server trust anchors (`CERTIFICATE` blocks).
    pub trust_anchors_pem: String,
    /// PEM text of the public key that verifies signed job plans.
    pub plan_key_pem: String,
    /// The signed v2 job plan, as received at confirm.
    pub plan: SignedEnvelopeV1,
    /// The job.
    pub job_id: JobId,
    /// SHA-256 of the agent binary copied beside this file.
    pub agent_sha256: Sha256Digest,
    /// File name of the agent package, in this file's folder.
    pub agent_package_file: FileName,
    /// File name of the job private key, in this file's folder.
    pub job_key_file: FileName,
}

fn pem_ok(text: &str, label: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_POSTSETUP_PEM_BYTES
        && text.contains(&format!("-----BEGIN {label}-----"))
        && !text.contains("PRIVATE KEY")
}

impl PostSetupConfigV1 {
    /// Checks every rule beyond the types.
    ///
    /// # Errors
    ///
    /// [`PostSetupConfigError::Invalid`] naming the first rule broken.
    pub fn validate(&self) -> Result<(), PostSetupConfigError> {
        use PostSetupConfigError::Invalid;
        if self.schema != POSTSETUP_SCHEMA_V1 {
            return Err(Invalid("schema must be 1"));
        }
        parse_server_url(&self.server_url).map_err(|_| Invalid("server_url is not valid"))?;
        check_host(&self.server_name).map_err(|_| Invalid("server_name is not valid"))?;
        if !pem_ok(&self.trust_anchors_pem, "CERTIFICATE") {
            return Err(Invalid(
                "trust_anchors_pem must hold CERTIFICATE blocks, no private key, at most 256 KiB",
            ));
        }
        if !pem_ok(&self.plan_key_pem, "PUBLIC KEY") {
            return Err(Invalid(
                "plan_key_pem must hold a PUBLIC KEY block, no private key, at most 256 KiB",
            ));
        }
        if self.plan.payload_type() != PayloadType::JobPlanV2 {
            return Err(Invalid("plan must be a v2 job plan envelope"));
        }
        if self.agent_package_file == self.job_key_file {
            return Err(Invalid("agent_package_file and job_key_file must differ"));
        }
        Ok(())
    }

    /// Parses and validates `job.json` bytes, checking the size first.
    ///
    /// # Errors
    ///
    /// [`PostSetupConfigError`].
    pub fn from_json(bytes: &[u8]) -> Result<Self, PostSetupConfigError> {
        if bytes.len() > MAX_POSTSETUP_CONFIG_BYTES {
            return Err(PostSetupConfigError::TooLarge { len: bytes.len() });
        }
        let c: Self = serde_json::from_slice(bytes).map_err(PostSetupConfigError::Json)?;
        c.validate()?;
        Ok(c)
    }

    /// The bytes to write.
    ///
    /// # Errors
    ///
    /// As [`Self::validate`]; [`PostSetupConfigError::Json`].
    pub fn to_json(&self) -> Result<Vec<u8>, PostSetupConfigError> {
        self.validate()?;
        serde_json::to_vec_pretty(self).map_err(PostSetupConfigError::Json)
    }
}
