//! usgp-relay: per-segment boot service (ProxyDHCP + read-only TFTP).
//!
//! Process contract: plan section 3.6 and [`usgp_relay::cli`]. The FIPS
//! check is always the first action.

use std::process::ExitCode;

use usgp_common::config::TrustPolicy;
use usgp_common::event::{self, AuditEvent};
use usgp_common::telemetry::{self, Level, LogFormat};
use usgp_relay::cli::{self, Command, ConfigArgs, USAGE};
use usgp_relay::config::{self, LoadedConfig};
use usgp_relay::events::{self as relay_events, COMPONENT, Outcome};
use usgp_relay::{EXIT_CONFIG, EXIT_FAILURE, EXIT_USAGE, RelayError, RunOptions};

fn main() -> ExitCode {
    // COMPLIANCE MAPPING:
    // - NIST 800-53: SC-13 (Cryptographic Protection) - fail closed if the
    //   validated module is not in FIPS mode (docs/decisions/0001).
    // - NIST 800-53: AU-2 / AU-12 - the refusal is audited (relay.start,
    //   outcome failure) before the process exits.
    if let Err(e) = usgp_crypto::fips_status() {
        eprintln!("usgp-relay: refusing to start: {e}");
        let _ = telemetry::init(Level::INFO, LogFormat::Json);
        let detail = [
            ("version", env!("CARGO_PKG_VERSION").to_owned()),
            ("reason", "fips_inactive".to_owned()),
        ];
        relay_events::emit_simple(relay_events::RELAY_START, Outcome::Failure, &detail);
        return ExitCode::from(EXIT_FAILURE);
    }
    match cli::parse(std::env::args_os().skip(1)) {
        Err(e) => {
            eprintln!("usgp-relay: {e}");
            eprintln!("{USAGE}");
            ExitCode::from(EXIT_USAGE)
        }
        Ok(Command::Help) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Command::SelfCheck) => ExitCode::SUCCESS,
        Ok(Command::CheckConfig(args)) => check_config(&args),
        Ok(Command::Run(args)) => run(&args),
    }
}

fn runtime() -> Option<tokio::runtime::Runtime> {
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => Some(rt),
        Err(e) => {
            eprintln!("usgp-relay: cannot start the async runtime: {}", e.kind());
            None
        }
    }
}

fn trust(args: &ConfigArgs) -> TrustPolicy {
    TrustPolicy {
        admin_uid: args.admin_uid,
    }
}

/// Sets the AU-3 "where" label: `log.node_name`, else the host name.
fn set_node_name(config: &usgp_relay::config::RelayConfig) {
    if let Some((name, _)) = usgp_relay::node_name(config) {
        event::set_node_name(&name);
    }
}

/// Sets the AU-3 "where" label to the host name when the configuration
/// could not be loaded, so `relay.config.rejected` still says where it
/// happened (AU-3). The label can be set once per process, so this is
/// done only on the refusal path; a loaded configuration's `log.node_name`
/// takes effect through [`set_node_name`].
fn set_host_node_name() {
    if let Some(name) = usgp_common::process::hostname() {
        event::set_node_name(&name);
    }
}

/// `--check-config`: validate everything the relay would load, verify
/// every published file, bind nothing, and report the state. Audit events
/// (integrity failures, refusals) are written like in a real start.
fn check_config(args: &ConfigArgs) -> ExitCode {
    // Logging first, so every integrity event of the check is recorded
    // (AU-12).
    let _ = telemetry::init(Level::INFO, LogFormat::Json);
    let loaded = match config::load(&args.path, trust(args)) {
        Ok(l) => l,
        Err(e) => {
            set_host_node_name();
            reject(&RelayError::Config(e));
            return ExitCode::from(EXIT_CONFIG);
        }
    };
    set_node_name(&loaded.config);
    let Some(rt) = runtime() else {
        return ExitCode::from(EXIT_FAILURE);
    };
    match rt.block_on(usgp_relay::check(&loaded.config)) {
        Ok(report) => {
            println!("configuration: valid");
            println!("state: {}", report.state.as_str());
            for (name, status) in &report.files {
                println!("file {name}: {}", status.as_str());
            }
            if let Some(n) = report.suppression_entries {
                println!("suppression entries: {n}");
            }
            match report.boot_policy {
                ("disabled", _) => {}
                (state, Some(g)) => println!("boot policy: {state} (generation {g})"),
                (state, None) => println!("boot policy: {state}"),
            }
            ExitCode::from(report.exit_code())
        }
        Err(e) => {
            if e.exit_code() == EXIT_CONFIG {
                reject(&e);
            } else {
                eprintln!("usgp-relay: {e}");
            }
            ExitCode::from(e.exit_code())
        }
    }
}

/// `--config`: run until SIGTERM/SIGINT.
fn run(args: &ConfigArgs) -> ExitCode {
    let loaded = match config::load(&args.path, trust(args)) {
        Ok(l) => l,
        Err(e) => {
            // The configured level is unknown; audit records are written
            // at any level anyway.
            let _ = telemetry::init(Level::INFO, LogFormat::Json);
            set_host_node_name();
            reject(&RelayError::Config(e));
            return ExitCode::from(EXIT_CONFIG);
        }
    };
    if let Err(e) = telemetry::init(loaded.config.log.level, LogFormat::Json) {
        eprintln!("usgp-relay: cannot start logging: {e}");
        return ExitCode::from(EXIT_FAILURE);
    }
    set_node_name(&loaded.config);
    // CM-5 / AC-6: never run as the administrator uid that owns the trusted
    // files unless the operator opted in (CM-5, AC-6).
    let service_uid = usgp_common::process::effective_uid().ok();
    if let Some(reason) = usgp_relay::shared_admin_uid_refusal(
        service_uid,
        &loaded.config.trust,
        args.allow_shared_admin_uid,
    ) {
        reject(&RelayError::SharedAdminUid(reason));
        return ExitCode::from(EXIT_CONFIG);
    }
    let opts = RunOptions {
        allow_shared_admin_uid: args.allow_shared_admin_uid,
    };
    let Some(rt) = runtime() else {
        let detail = [
            ("reason", "async runtime unavailable".to_owned()),
            (
                "allow_shared_admin_uid",
                opts.allow_shared_admin_uid.to_string(),
            ),
        ];
        relay_events::emit_simple(relay_events::RELAY_START, Outcome::Failure, &detail);
        return ExitCode::from(EXIT_FAILURE);
    };
    run_loaded(&rt, loaded, opts)
}

/// Runs the loaded relay. Every error is audited: start-up errors as
/// `relay.start` (failure) inside [`usgp_relay::run`], configuration
/// errors also as `relay.config.rejected`, and errors after start as
/// `relay.stop` (failure).
fn run_loaded(rt: &tokio::runtime::Runtime, loaded: LoadedConfig, opts: RunOptions) -> ExitCode {
    match rt.block_on(usgp_relay::run(loaded, opts)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            if e.exit_code() == EXIT_CONFIG {
                reject(&e);
            } else {
                eprintln!("usgp-relay: {e}");
            }
            ExitCode::from(e.exit_code())
        }
    }
}

/// Reports a refused configuration on stderr and as
/// `relay.config.rejected`.
fn reject(e: &RelayError) {
    eprintln!("usgp-relay: {e}");
    let detail = [("field", e.field()), ("reason", e.to_string())];
    relay_events::emit(AuditEvent {
        detail: &detail,
        ..AuditEvent::new(relay_events::CONFIG_REJECTED, Outcome::Refused, COMPONENT)
    });
}
