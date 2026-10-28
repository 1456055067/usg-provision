//! usgp-preboot-agent: start-up wrapper (plan WU-12; section 1.3).
//!
//! ```text
//! usgp-preboot-agent [--config <agent.toml>]     run (default: agent.toml next to the program)
//! usgp-preboot-agent --self-test                 FIPS self-test; exit 0 only in FIPS mode
//! usgp-preboot-agent --config <f> --sim <sim>    the simulated platform (CI; non-Windows or `sim`)
//! ```
//!
//! In Windows PE the agent never exits on its own: it ends in a restart or
//! shutdown the person chose, or the restart after success. A panic shows
//! a persistent error and waits (plan R-6).

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-13 - FIPS self-test mode; FIPS checked first on run.
// - NIST 800-53: SI-11 - persistent error on any failure, including a
//   panic.
// - SPEC: specs/preinstall-env.md#REQ-PE-013, #REQ-PE-019
// - DECISION: docs/decisions/0001, 0018 item 6

use std::path::PathBuf;
use std::process::ExitCode;

use usgp_preboot_agent::host::Host;
use usgp_preboot_agent::session::Outcome;
use usgp_preboot_agent::ui::StdConsole;
use usgp_preboot_agent::{app, config, selftest};

const USAGE: &str = "usage: usgp-preboot-agent [--config <agent.toml>] [--sim <sim.toml>] | --self-test | --version";

#[derive(Debug, Default)]
struct Args {
    self_test: bool,
    version: bool,
    config: Option<PathBuf>,
    sim: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = std::env::args_os().skip(1);
    while let Some(arg) = it.next() {
        match arg.to_str() {
            Some("--self-test") => a.self_test = true,
            Some("--version") => a.version = true,
            Some("--help" | "-h") => return Err(USAGE.to_owned()),
            Some("--config") if a.config.is_none() => {
                a.config = Some(it.next().ok_or("--config needs a path")?.into());
            }
            Some("--sim") if a.sim.is_none() => {
                a.sim = Some(it.next().ok_or("--sim needs a path")?.into());
            }
            _ => return Err(USAGE.to_owned()),
        }
    }
    Ok(a)
}

/// Keeps the process alive after a persistent screen or a requested
/// restart, so Windows PE never falls back to a shell (plan R-6).
#[cfg(windows)]
fn hold() -> ! {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let place = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        // Fixed text and the source location only: a panic message could
        // quote data.
        eprintln!(
            "\n\nINTERNAL ERROR in usgp-preboot-agent ({place}).\n\
             The install stopped. Report this to the operator, then restart the device."
        );
        #[cfg(windows)]
        hold();
    }));
}

#[cfg(windows)]
fn real_host() -> Result<Box<dyn Host>, String> {
    usgp_preboot_agent::platform_win::WinHost::open()
        .map(|h| Box::new(h) as Box<dyn Host>)
        .map_err(|e| e.to_string())
}

#[cfg(not(windows))]
fn real_host() -> Result<Box<dyn Host>, String> {
    Err("this build has no device platform; use --sim <file>".to_owned())
}

#[cfg(any(not(windows), feature = "sim"))]
fn sim_host(path: &std::path::Path) -> Result<Box<dyn Host>, String> {
    usgp_preboot_agent::sim::SimHost::from_file(path)
        .map(|h| Box::new(h) as Box<dyn Host>)
        .map_err(|e| e.to_string())
}

#[cfg(not(any(not(windows), feature = "sim")))]
fn sim_host(_path: &std::path::Path) -> Result<Box<dyn Host>, String> {
    Err("this build has no simulation".to_owned())
}

fn default_config() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("agent.toml")))
        .unwrap_or_else(|| PathBuf::from("agent.toml"))
}

fn main() -> ExitCode {
    install_panic_hook();
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    if args.version {
        println!("usgp-preboot-agent {}", usgp_preboot_agent::AGENT_VERSION);
        return ExitCode::SUCCESS;
    }
    if args.self_test {
        let t = selftest::run(usgp_crypto::provider());
        print!("{}", t.report);
        return if t.passed {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }
    // COMPLIANCE MAPPING:
    // - NIST 800-53: SC-13 - fail closed before reading anything if the
    //   validated module is not in FIPS mode (decision 0001).
    if let Err(e) = usgp_crypto::fips_status() {
        eprintln!("usgp-preboot-agent: refusing to start: {e}");
        #[cfg(windows)]
        hold();
        #[cfg(not(windows))]
        return ExitCode::from(1);
    }
    let config_path = args.config.unwrap_or_else(default_config);
    let cfg = match config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("usgp-preboot-agent: cannot start: {e}");
            #[cfg(windows)]
            hold();
            #[cfg(not(windows))]
            return ExitCode::from(1);
        }
    };
    let host = match &args.sim {
        Some(p) => sim_host(p),
        None => real_host(),
    };
    let mut host = match host {
        Ok(h) => h,
        Err(e) => {
            eprintln!("usgp-preboot-agent: cannot start: {e}");
            #[cfg(windows)]
            hold();
            #[cfg(not(windows))]
            return ExitCode::from(1);
        }
    };
    let mut console = match StdConsole::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("usgp-preboot-agent: cannot read the console: {}", e.kind());
            return ExitCode::from(1);
        }
    };
    let ending = app::run(&cfg, &mut *host, &mut console, usgp_crypto::provider());
    let summary = match &ending.outcome {
        Outcome::Succeeded(j) => format!("succeeded (job {j})"),
        Outcome::JobFailed { written, code } => {
            format!("job failed ({code}; disk written: {written})")
        }
        other => format!("{other:?}"),
    };
    println!("\noutcome: {summary}");
    if let Some(action) = ending.action {
        if let Err(e) = host.power(action) {
            eprintln!("usgp-preboot-agent: {action:?} failed: {e}");
        }
        // A real restart or shutdown is under way: wait for it.
        #[cfg(windows)]
        if args.sim.is_none() {
            hold();
        }
        println!("power: {action:?}");
    }
    #[cfg(windows)]
    if args.sim.is_none() {
        hold();
    }
    ExitCode::from(ending.outcome.exit_code())
}
