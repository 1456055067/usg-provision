//! The `postsetup` mode (M4 plan WU-10; §1.2): started by our
//! `SetupComplete.cmd` as SYSTEM in the installed Windows, it runs job
//! steps 7 to 9 with `usgp_deploy::PostSetupRunner`.
//!
//! Order, failing closed:
//!
//! 1. FIPS mode (decision 0001). If it is not active nothing is sent; the
//!    failure is recorded on the device and the server's deadline sweep
//!    fails the job.
//! 2. `job.json` is read only for the server address and trust anchors,
//!    to build the TLS client (server-authenticated, pinned anchors, the
//!    certificate name from `job.json`). If it cannot be used, the runner
//!    still runs with a link that refuses every call, so its own checks,
//!    clean-up and device-side record happen exactly as for any other
//!    failure.
//! 3. The runner: read inputs, resume with the job key, verify the plan
//!    again, steps 7 to 9 (`usgp_deploy::postsetup`).
//!
//! The runner never restarts the machine, and the mode needs no console.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-13 - FIPS checked before any network use.
// - NIST 800-53: SC-8, IA-5(2) - the server is authenticated with the
//   anchors and name written by the Windows PE agent at step 5.
// - NIST 800-53: SI-11 - every failure recorded on the device.
// - SPEC: specs/workflow.md#REQ-SEQ-006
// - DECISION: docs/decisions/0001, 0024

use std::time::Duration;

use usgp_crypto::CryptoProvider;
use usgp_crypto::tls::{BlockingClientTls, ClientAlpn, ClientTlsSettings, TlsMinVersion};
use usgp_deploy::postsetup::{Ready, RunnerFile};
use usgp_deploy::{
    Clock, JobFailureV2, LinkError, PostSetupPlatform, PostSetupRunner, ProgressLinkV2, ResumeLink,
    RunnerConfig,
};
use usgp_proto::limits::MAX_POSTSETUP_CONFIG_BYTES;
use usgp_proto::postsetup::PostSetupConfigV1;
use usgp_proto::progress::{ProgressAckV1, ProgressV2};
use usgp_proto::{EscrowConfirmV1, EscrowSubmitV1, JobId, ResumeChallengeV1, ResumeRequestV1};

use crate::client::DeviceClient;
use crate::config::{CONNECT_TIMEOUT_S, Endpoint, parse_server_url};
use crate::http::{HttpClient, HttpLimits};
use crate::link::ResumeApiLink;

/// How the mode ended.
#[derive(Debug)]
pub enum PostSetupOutcome {
    /// Step 9 was acknowledged.
    Ready(Ready),
    /// The cryptographic module is not in FIPS mode; nothing was sent.
    NotFips,
    /// The job failed (recorded on the device; reported if the server was
    /// reached).
    Failed(JobFailureV2),
}

impl PostSetupOutcome {
    /// The process exit code: 0 ready, 1 not FIPS, 2 failed. Windows Setup
    /// ignores it (M4 plan §1.2); it is for the lab and the logs.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Ready(_) => 0,
            Self::NotFips => 1,
            Self::Failed(_) => 2,
        }
    }
}

/// A link for a runner that has no usable server address: every call is
/// refused, so the runner fails at once (`resume_refused`) instead of
/// waiting for a network it cannot use.
#[derive(Debug, Default)]
pub struct NoServer;

impl ProgressLinkV2 for NoServer {
    fn report_v2(&mut self, _: JobId, _: &ProgressV2) -> Result<ProgressAckV1, LinkError> {
        Err(LinkError::Refused)
    }
}

impl ResumeLink for NoServer {
    fn challenge(&mut self, _: JobId) -> Result<ResumeChallengeV1, LinkError> {
        Err(LinkError::Refused)
    }
    fn resume(&mut self, _: JobId, _: &ResumeRequestV1) -> Result<u64, LinkError> {
        Err(LinkError::Refused)
    }
    fn submit_escrow(&mut self, _: JobId, _: &EscrowSubmitV1) -> Result<(), LinkError> {
        Err(LinkError::Refused)
    }
    fn confirm_escrow(&mut self, _: JobId, _: &EscrowConfirmV1) -> Result<(), LinkError> {
        Err(LinkError::Refused)
    }
}

/// The TLS client for the server `job.json` names, or `None` if
/// `job.json` cannot be read or used (the runner then reports why).
fn client_for(platform: &mut dyn PostSetupPlatform) -> Option<DeviceClient> {
    let max = u64::try_from(MAX_POSTSETUP_CONFIG_BYTES).unwrap_or(u64::MAX);
    let json = platform.read_file(RunnerFile::JobJson, max).ok()?;
    let c = PostSetupConfigV1::from_json(&json).ok()?;
    let (host, port) = parse_server_url(&c.server_url).ok()?;
    let tls = BlockingClientTls::new(&ClientTlsSettings {
        trust_anchors_pem: c.trust_anchors_pem.into_bytes(),
        client_cert_chain_pem: None,
        client_key_pem: None,
        min_version: TlsMinVersion::Tls12,
        alpn: ClientAlpn::Http11,
    })
    .ok()?;
    let endpoint = Endpoint {
        host,
        port,
        server_name: c.server_name,
    };
    let (_, _, connect_default) = CONNECT_TIMEOUT_S;
    Some(DeviceClient::new(HttpClient::new(
        tls,
        endpoint,
        HttpLimits::new(Duration::from_secs(connect_default)),
    )))
}

/// Runs the mode on `platform` (module documentation).
pub fn run(
    platform: &mut dyn PostSetupPlatform,
    crypto: &dyn CryptoProvider,
    clock: &dyn Clock,
    config: RunnerConfig,
) -> PostSetupOutcome {
    if crypto.fips_status().is_err() {
        platform.record_failure(
            "postsetup: the cryptographic module is not in FIPS mode; nothing was sent \
             (code fips_not_active)",
        );
        return PostSetupOutcome::NotFips;
    }
    let runner = PostSetupRunner::new(crypto, clock, config);
    let result = match client_for(platform) {
        Some(mut client) => {
            let mut link = ResumeApiLink::new(&mut client);
            runner.run(platform, &mut link)
        }
        None => runner.run(platform, &mut NoServer),
    };
    match result {
        Ok(r) => PostSetupOutcome::Ready(r),
        Err(f) => PostSetupOutcome::Failed(f),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use usgp_deploy::SystemClock;

    use super::*;
    use crate::installed::{AccountOps, InstalledPaths, InstalledPlatform};

    struct NoAccount;

    impl AccountOps for NoAccount {
        fn lock(&mut self) -> Result<(), usgp_deploy::PlatformError> {
            panic!("no secret before the inputs are checked")
        }
        fn unlock(&mut self) {}
        fn set_admin_password(
            &mut self,
            _: &zeroize::Zeroizing<String>,
        ) -> Result<(), usgp_deploy::postsetup::AccountError> {
            panic!("no password before the inputs are checked")
        }
    }

    fn none(_: &fs::File) -> std::io::Result<()> {
        Ok(())
    }

    /// An unusable `job.json` fails at once, is recorded on the device,
    /// and the clean-up still removes the job key and our script.
    #[test]
    fn an_unusable_job_json_fails_closed_and_cleans_up() {
        let root = std::env::temp_dir().join(format!("usgp-ps-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let postsetup = root.join("ProgramData/usgp/postsetup");
        let windows = root.join("Windows");
        fs::create_dir_all(&postsetup).unwrap();
        fs::create_dir_all(windows.join("Setup/Scripts")).unwrap();
        fs::write(postsetup.join("job.json"), b"{}").unwrap();
        fs::write(postsetup.join("job.key"), b"k").unwrap();
        fs::write(windows.join("Setup/Scripts/SetupComplete.cmd"), b"x").unwrap();
        let paths = InstalledPaths::for_runner(
            &postsetup.join("usgp-agent.exe"),
            &windows,
            &windows.join("System32"),
        )
        .unwrap();
        let mut p = InstalledPlatform::new(paths, none, NoAccount);
        let clock = SystemClock::new();
        let out = run(
            &mut p,
            usgp_crypto::provider(),
            &clock,
            RunnerConfig::default(),
        );
        let PostSetupOutcome::Failed(f) = &out else {
            panic!("{out:?}");
        };
        assert_eq!(f.code.as_str(), "postsetup_config_invalid");
        assert_eq!(out.exit_code(), 2);
        assert!(!postsetup.join("job.key").exists());
        assert!(!windows.join("Setup/Scripts/SetupComplete.cmd").exists());
        let err = fs::read_to_string(root.join("ProgramData/usgp/postsetup-error.txt")).unwrap();
        assert!(err.contains("postsetup_config_invalid"), "{err}");
    }
}
