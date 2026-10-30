//! Step 5, `place_config` (M4 plan §1.1, §1.2, §1.6).
//!
//! Writes, on the applied Windows volume, each file create-new:
//!
//! 1. `ProgramData\usgp\postsetup\usgp-agent.exe`: the running agent
//!    binary; its SHA-256 goes into `job.json`;
//! 2. `ProgramData\usgp\postsetup\agent-package.zip`: the agent package,
//!    re-verified chunk by chunk and as a whole against the plan;
//! 3. `ProgramData\usgp\postsetup\job.key`: the job private key generated
//!    on the device at confirm (SYSTEM-only DACL);
//! 4. `ProgramData\usgp\postsetup\job.json`: `PostSetupConfigV1`
//!    (non-secret);
//! 5. `Windows\Panther\unattend.xml`: the rendered answer file, after its
//!    SHA-256 is checked against the signed plan (an existing file fails
//!    the step: `answer_file_exists`);
//! 6. `Windows\Setup\Scripts\SetupComplete.cmd`: the two-line script that
//!    starts the post-setup runner and then removes its folder (an
//!    existing file fails the step: `setupcomplete_exists`).
//!
//! `SetupComplete.cmd` is written last, so a failure part-way never
//! leaves a script that would start the runner.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   answer file and agent package checked against the signed plan before
//   they are written.
// - NIST 800-53: SC-28 (Protection of Information at Rest) - no secret is
//   written except the device-generated job key, under a SYSTEM-only
//   DACL; the answer file holds no secret by construction (lint, WU-3).
// - NIST 800-53: CM-6 - operator content is never silently overwritten
//   (create-new).
// - SPEC: specs/configuration.md#REQ-CFG-003, #REQ-CFG-010
// - SPEC: specs/agent-handoff.md#REQ-AGT-001
// - DECISION: docs/decisions/0024 items 1 and 2, 0025 item 1

use std::io;

use usgp_proto::codes;
use usgp_proto::content_manifest::ContentManifestV2;
use usgp_proto::envelope::SignedEnvelopeV1;
use usgp_proto::job_plan::JobPlanV2;
use usgp_proto::postsetup::{POSTSETUP_SCHEMA_V1, PostSetupConfigV1};
use usgp_proto::progress::{FailureCategory, StepV2};
use usgp_proto::{ErrorCode, FileName};
use zeroize::Zeroizing;

use super::{StepCtx, chunk_failure, local, platform_failure, time_check};
use crate::content::VerifiedChunks;
use crate::error::{JobFailureV2, code, code_of};
use crate::link::ServerLink;
use crate::platform::{Platform, PlatformErrorKind, PostSetupFile, TargetPath};

const STEP: StepV2 = StepV2::PLACE_CONFIG;

/// The contents of `SetupComplete.cmd` (M4 plan §1.2): start the runner,
/// then remove its folder. Windows Setup runs it as SYSTEM and ignores
/// its exit code (`unattend.md` §5).
pub const SETUP_COMPLETE_CMD: &str = "\"%ProgramData%\\usgp\\postsetup\\usgp-agent.exe\" postsetup\r\n\
rd /s /q \"%ProgramData%\\usgp\\postsetup\"\r\n";

/// What the WinPE agent gives step 5 for `job.json` and `job.key`. None
/// of it is from the server except the plan envelope.
pub struct PostSetupInputs<'a> {
    /// `https://host[:port][/]` of the device listener.
    pub server_url: &'a str,
    /// The name the server certificate must carry.
    pub server_name: &'a str,
    /// PEM text of the server trust anchors.
    pub trust_anchors_pem: &'a str,
    /// PEM text of the plan public key.
    pub plan_key_pem: &'a str,
    /// The signed v2 plan as received.
    pub plan_envelope: &'a SignedEnvelopeV1,
    /// The job private key (PKCS#8 DER), generated on the device.
    pub job_key_pkcs8: &'a Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for PostSetupInputs<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PostSetupInputs")
            .field("server_url", &self.server_url)
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

/// Writes one file; an existing file gives `exists` (when set), any other
/// failure `config_write_failed`.
fn write(
    platform: &mut dyn Platform,
    p: TargetPath,
    bytes: &[u8],
    exists: Option<ErrorCode>,
) -> Result<(), JobFailureV2> {
    platform
        .write_protected_file(&p, bytes)
        .map_err(|e| match (e.kind, exists) {
            (PlatformErrorKind::Io(io::ErrorKind::AlreadyExists), Some(c)) => JobFailureV2::new(
                STEP,
                FailureCategory::Refused,
                c,
                format!("{} already exists on the installed volume", p.relative()),
            ),
            _ => platform_failure(STEP, code_of(code::CONFIG_WRITE_FAILED), e),
        })
}

/// Runs step 5 after its start report.
///
/// # Errors
///
/// [`JobFailureV2`] for step 5.
pub fn place_config(
    ctx: &StepCtx<'_>,
    plan: &JobPlanV2,
    agent_manifest: &ContentManifestV2,
    inputs: &PostSetupInputs<'_>,
    max_agent_bytes: u64,
    platform: &mut dyn Platform,
    link: &mut dyn ServerLink,
) -> Result<(), JobFailureV2> {
    let integrity = |msg: &str| {
        JobFailureV2::new(
            STEP,
            FailureCategory::Integrity,
            codes::INTEGRITY_FAILED,
            msg.to_owned(),
        )
    };
    // The answer file: checked against the signed plan before anything is
    // written (the plan verification checked it too).
    let answer = plan.answer_file.b64.as_bytes();
    if ctx.crypto.sha256(answer) != plan.answer_file.sha256 {
        return Err(integrity("the answer file does not match the plan"));
    }
    if agent_manifest.sha256 != plan.agent.content_sha256 {
        return Err(integrity(
            "the agent package manifest does not match the plan",
        ));
    }

    // 1. The runner binary.
    let exe = platform
        .agent_binary()
        .map_err(|e| platform_failure(STEP, code_of(code::CONFIG_WRITE_FAILED), e))?;
    let agent_sha256 = ctx.crypto.sha256(&exe);
    write(
        platform,
        TargetPath::PostSetup(PostSetupFile::AgentExe),
        &exe,
        None,
    )?;
    drop(exe);
    time_check(STEP, ctx.watch)?;

    // 2. The agent package, re-verified.
    let pkg = {
        let mut src = VerifiedChunks::for_archive(
            &mut *link,
            ctx.crypto,
            ctx.clock,
            ctx.job,
            ctx.retry,
            agent_manifest,
        )
        .with_watch(ctx.watch);
        src.read_all(max_agent_bytes)
            .map_err(|c| chunk_failure(STEP, "agent package", c))?
    };
    write(
        platform,
        TargetPath::PostSetup(PostSetupFile::AgentPackage),
        &pkg,
        None,
    )?;
    drop(pkg);
    time_check(STEP, ctx.watch)?;

    // 3. The job key (SYSTEM only).
    write(
        platform,
        TargetPath::PostSetup(PostSetupFile::JobKey),
        inputs.job_key_pkcs8,
        None,
    )?;

    // 4. job.json.
    let file = |f: PostSetupFile| FileName::new(f.file_name());
    let config = match (
        file(PostSetupFile::AgentPackage),
        file(PostSetupFile::JobKey),
    ) {
        (Ok(agent_package_file), Ok(job_key_file)) => PostSetupConfigV1 {
            schema: POSTSETUP_SCHEMA_V1,
            server_url: inputs.server_url.to_owned(),
            server_name: inputs.server_name.to_owned(),
            trust_anchors_pem: inputs.trust_anchors_pem.to_owned(),
            plan_key_pem: inputs.plan_key_pem.to_owned(),
            plan: inputs.plan_envelope.clone(),
            job_id: plan.job_id,
            agent_sha256,
            agent_package_file,
            job_key_file,
        },
        _ => {
            return Err(local(
                STEP,
                codes::POSTSETUP_CONFIG_INVALID,
                "post-setup file names are invalid",
            ));
        }
    };
    let json = config.to_json().map_err(|e| {
        local(
            STEP,
            codes::POSTSETUP_CONFIG_INVALID,
            format!("job.json could not be built: {e}"),
        )
    })?;
    write(
        platform,
        TargetPath::PostSetup(PostSetupFile::JobJson),
        &json,
        None,
    )?;

    // 5 and 6.
    write(
        platform,
        TargetPath::AnswerFile,
        answer,
        Some(codes::ANSWER_FILE_EXISTS),
    )?;
    write(
        platform,
        TargetPath::SetupComplete,
        SETUP_COMPLETE_CMD.as_bytes(),
        Some(codes::SETUPCOMPLETE_EXISTS),
    )?;
    time_check(STEP, ctx.watch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_complete_has_two_crlf_lines() {
        let lines: Vec<&str> = SETUP_COMPLETE_CMD.split("\r\n").collect();
        assert_eq!(
            lines,
            [
                "\"%ProgramData%\\usgp\\postsetup\\usgp-agent.exe\" postsetup",
                "rd /s /q \"%ProgramData%\\usgp\\postsetup\"",
                ""
            ]
        );
    }
}
