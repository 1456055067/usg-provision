//! Start-up checks and the whole run (plan section 1.1, device flow steps 2
//! to 8; REQ-PE-013 to REQ-PE-020).
//!
//! Order, each step failing closed to a persistent screen:
//!
//! 1. FIPS mode (decision 0001; plan section 5: "failure gives a
//!    persistent error and no network").
//! 2. The device's facts (firmware, architecture, Secure Boot, memory,
//!    MACs).
//! 3. A bounded wait for a DHCP address (REQ-PE-014). If none comes, the
//!    screen says a network driver may be missing.
//! 4. The TLS connection to the server with the configured anchors
//!    (REQ-PE-015). A certificate validity failure says the device clock
//!    may be wrong (R-5).
//! 5. The session and the job ([`crate::session`]).

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-13 (Cryptographic Protection) - FIPS checked before
//   any network use.
// - NIST 800-53: SC-8, IA-3 - server authenticated with pinned anchors and
//   name before anything else is sent.
// - NIST 800-53: SI-11 - persistent, named start-up errors.
// - SPEC: specs/preinstall-env.md#REQ-PE-013, #REQ-PE-014, #REQ-PE-015,
//   #REQ-PE-020
// - DECISION: docs/decisions/0001, 0020

use std::time::{Duration, Instant};

use usgp_crypto::CryptoProvider;
use usgp_crypto::tls::{BlockingClientTls, ClientAlpn, ClientTlsSettings, TlsMinVersion};
use usgp_deploy::SystemClock;

use crate::client::{ApiFailure, DeviceClient};
use crate::config::AgentConfig;
use crate::host::{Host, PowerAction};
use crate::http::{HttpClient, HttpLimits};
use crate::session::{Agent, Ending, Outcome};
use crate::ui::{self, Console};

/// How often the network wait looks again.
const NETWORK_POLL: Duration = Duration::from_secs(1);

/// Runs the agent to its end.
pub fn run(
    config: &AgentConfig,
    host: &mut dyn Host,
    console: &mut dyn Console,
    crypto: &dyn CryptoProvider,
) -> Ending {
    console.show(&ui::status_screen("Starting", &["Checking this device..."]));
    if crypto.fips_status().is_err() {
        return stop_early(
            console,
            "Cannot start",
            "The cryptographic module is not in FIPS mode, so this program will not run.",
            Outcome::StartupFailed("FIPS mode is not active".to_owned()),
        );
    }
    let facts = match host.facts() {
        Ok(f) => f,
        Err(e) => {
            return stop_early(
                console,
                "Cannot start",
                &format!("This device's details could not be read: {e}"),
                Outcome::StartupFailed(e.0),
            );
        }
    };
    if let Err(end) = wait_for_network(host, console, config.network_wait) {
        return end;
    }
    let server = format!("{}:{}", config.endpoint.server_name, config.endpoint.port);
    console.show(&ui::status_screen(
        "Connecting",
        &[&format!(
            "Connecting to the provisioning server {server}..."
        )],
    ));
    let tls = match BlockingClientTls::new(&ClientTlsSettings {
        trust_anchors_pem: config.trust_anchors_pem.clone(),
        client_cert_chain_pem: None,
        client_key_pem: None,
        min_version: TlsMinVersion::Tls12,
        alpn: ClientAlpn::Http11,
    }) {
        Ok(t) => t,
        Err(_) => {
            return stop_early(
                console,
                "Cannot start",
                "The trust anchors in the agent configuration could not be used.",
                Outcome::StartupFailed("bad trust anchors".to_owned()),
            );
        }
    };
    let mut client = DeviceClient::new(HttpClient::new(
        tls,
        config.endpoint.clone(),
        HttpLimits::new(config.connect_timeout),
    ));
    if let Err(e) = client.http().check_connect() {
        let why = ApiFailure::from(e).describe();
        return stop_early(
            console,
            "Cannot reach the provisioning server",
            &format!("{why}\nServer: {server}"),
            Outcome::Unreachable(why),
        );
    }
    let clock = SystemClock::new();
    let mut agent = Agent {
        api: &mut client,
        host,
        console,
        keys: &config.keys,
        crypto,
        clock: &clock,
    };
    agent.run(&facts)
}

/// A start-up refusal after the configuration loaded (FIPS, device facts,
/// network, trust anchors, server unreachable): a persistent error screen
/// that stays until the person restarts or shuts down (REQ-PE-014,
/// REQ-PE-015, REQ-JOB-005). The wait is bounded by [`ui::MAX_IDLE_WAIT`];
/// EOF or the limit ends it with no power action. Nothing is ever written.
#[must_use]
pub fn refuse(console: &mut dyn Console, title: &str, line: &str) -> Option<PowerAction> {
    console.show(&ui::stop_screen(
        title,
        &[
            line.to_owned(),
            "Nothing was written to any disk.".to_owned(),
        ],
    ));
    ui::wait_for_choice(console, ui::MAX_IDLE_WAIT)
}

fn stop_early(console: &mut dyn Console, title: &str, line: &str, outcome: Outcome) -> Ending {
    let action = refuse(console, title, line);
    Ending { outcome, action }
}

/// Waits, bounded, for a usable DHCP address (REQ-PE-014).
fn wait_for_network(
    host: &mut dyn Host,
    console: &mut dyn Console,
    wait: Duration,
) -> Result<(), Ending> {
    let start = Instant::now();
    loop {
        match host.dhcp_addresses() {
            Ok(a) if !a.is_empty() => return Ok(()),
            Ok(_) | Err(_) => {}
        }
        let elapsed = start.elapsed();
        if elapsed >= wait {
            return Err(stop_early(
                console,
                "No network",
                &format!(
                    "No network address was received from DHCP within {} seconds. A network \
                     driver may be missing from this environment, or the cable may be \
                     unplugged.",
                    wait.as_secs()
                ),
                Outcome::Unreachable("no DHCP address".to_owned()),
            ));
        }
        let left = wait.saturating_sub(elapsed).as_secs();
        console.show(&ui::status_screen(
            "Waiting for the network",
            &[&format!("Waiting for a network address ({left} s left)...")],
        ));
        std::thread::sleep(NETWORK_POLL.min(wait.saturating_sub(elapsed)));
    }
}
