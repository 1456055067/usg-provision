//! usgp-preboot-agent: start-up wrapper (plan WU-12; section 1.3).
//!
//! ```text
//! usgp-preboot-agent [--config <agent.toml>]     run (default: agent.toml next to the program)
//! usgp-preboot-agent --self-test                 FIPS self-test; exit 0 only in FIPS mode
//! usgp-preboot-agent --config <f> --sim <sim>    the simulated platform (CI; non-Windows or `sim`)
//! usgp-agent.exe postsetup                       job steps 7 to 9 in the installed Windows (M4)
//! ```
//!
//! `postsetup` (M4 plan §1.2) is started by our `SetupComplete.cmd` as
//! SYSTEM from `%ProgramData%\usgp\postsetup\` and must be the only
//! argument. It needs no console and never restarts the machine; its
//! outcome is reported to the server and recorded in
//! `%ProgramData%\usgp\postsetup-error.txt` on failure ([`postsetup`]).
//!
//! Start-up refusals come in two kinds:
//!
//! - Before the configuration is usable (usage, a missing or invalid
//!   `agent.toml`, no console): the reason is printed and the program exits
//!   1 at once. There is nothing more to show.
//! - After it loads (FIPS, the platform, device facts, the network wait,
//!   the trust anchors, an unreachable server): a persistent error screen
//!   stays until the person restarts or shuts down (REQ-PE-014,
//!   REQ-PE-015, REQ-JOB-005). The wait is bounded (2 hours); EOF on
//!   standard input or the limit ends it with no power action, and the
//!   program exits with the refusal's code.
//!
//! After a session, the agent ends in the restart or shutdown the person
//! chose, the restart after success, or (EOF, idle limit) no power action.
//! After a requested restart or shutdown it waits at most `POWER_GRACE`
//! (300 s); a panic's message stays at most `PANIC_HOLD` (600 s; plan R-6).

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-13 - FIPS self-test mode; FIPS checked first on run.
// - NIST 800-53: SI-11 - persistent error on any failure, including a
//   panic.
// - SPEC: specs/preinstall-env.md#REQ-PE-013, #REQ-PE-019
// - DECISION: docs/decisions/0001, 0018 item 6

use std::path::PathBuf;
use std::process::ExitCode;

use usgp_preboot_agent::host::{Host, PowerAction};
#[cfg(windows)]
use usgp_preboot_agent::postsetup;
use usgp_preboot_agent::session::Outcome;
use usgp_preboot_agent::ui::StdConsole;
use usgp_preboot_agent::{app, config, selftest};

const USAGE: &str = "usage: usgp-preboot-agent [--config <agent.toml>] [--sim <sim.toml>] | --self-test | --version | postsetup";

#[derive(Debug, Default)]
struct Args {
    self_test: bool,
    version: bool,
    postsetup: bool,
    config: Option<PathBuf>,
    sim: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args::default();
    let mut it = std::env::args_os().skip(1).peekable();
    // `postsetup` is a mode of its own: the only argument.
    if it.peek().and_then(|f| f.to_str()) == Some("postsetup") {
        let _ = it.next();
        if it.next().is_some() {
            return Err(USAGE.to_owned());
        }
        a.postsetup = true;
        return Ok(a);
    }
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

/// Most time the agent waits for a restart or shutdown it requested.
const POWER_GRACE: std::time::Duration = std::time::Duration::from_secs(300);
/// Most time a panic's error stays on screen before the process ends
/// (Windows PE only).
#[cfg(windows)]
const PANIC_HOLD: std::time::Duration = std::time::Duration::from_secs(600);

fn install_panic_hook(hold: bool) {
    std::panic::set_hook(Box::new(move |info| {
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
        // Windows PE: keep the message readable, bounded. Not in
        // `postsetup`, where nobody watches and Setup waits for the script.
        #[cfg(windows)]
        if hold {
            std::thread::sleep(PANIC_HOLD);
        }
        #[cfg(not(windows))]
        let _ = hold;
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

/// After a start-up refusal that has no platform yet (FIPS, platform
/// preparation): records the person's choice and exits 1. Without a
/// platform the agent cannot restart or shut down the device itself.
fn after_refusal(action: Option<PowerAction>) -> ExitCode {
    if let Some(a) = action {
        println!("power: {a:?} (not available before the platform is ready)");
    }
    ExitCode::from(1)
}

fn default_config() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("agent.toml")))
        .unwrap_or_else(|| PathBuf::from("agent.toml"))
}

/// The `postsetup` mode on the installed Windows.
#[cfg(windows)]
fn run_postsetup() -> ExitCode {
    let mut platform = match usgp_preboot_agent::postsetup_win::open() {
        Ok(p) => p,
        Err(e) => {
            // No folder to record in: the server's deadline sweep fails the
            // job (M4 plan §1.2).
            eprintln!("usgp-agent postsetup: cannot start: {e}");
            return ExitCode::from(3);
        }
    };
    let clock = usgp_deploy::SystemClock::new();
    let out = postsetup::run(
        &mut platform,
        usgp_crypto::provider(),
        &clock,
        usgp_deploy::RunnerConfig::default(),
    );
    report_postsetup(&out);
    ExitCode::from(out.exit_code())
}

#[cfg(not(windows))]
fn run_postsetup() -> ExitCode {
    eprintln!("usgp-agent postsetup: this mode runs only in the installed Windows");
    ExitCode::from(3)
}

/// One summary line on standard output (no secret: job id, flags, code).
#[cfg(windows)]
fn report_postsetup(out: &postsetup::PostSetupOutcome) {
    match out {
        postsetup::PostSetupOutcome::Ready(r) => println!(
            "postsetup: job {} ready (password set: {}, restart pending: {})",
            r.job_id, r.password_set, r.restart_pending
        ),
        postsetup::PostSetupOutcome::NotFips => println!("postsetup: FIPS mode is not active"),
        postsetup::PostSetupOutcome::Failed(f) => {
            println!(
                "postsetup: failed at step {} ({})",
                f.step.get(),
                f.code.as_str()
            );
        }
    }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            install_panic_hook(false);
            eprintln!("{e}");
            return ExitCode::from(1);
        }
    };
    install_panic_hook(!args.postsetup);
    if args.postsetup {
        return run_postsetup();
    }
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
    let mut console = match StdConsole::new() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("usgp-preboot-agent: cannot read the console: {}", e.kind());
            return ExitCode::from(1);
        }
    };
    // COMPLIANCE MAPPING:
    // - NIST 800-53: SC-13 - fail closed before the configuration is
    //   read if the validated module is not in FIPS mode (decision 0001);
    //   the refusal stays on screen (bounded wait).
    if let Err(e) = usgp_crypto::fips_status() {
        eprintln!("usgp-preboot-agent: refusing to start: {e}");
        let action = app::refuse(
            &mut console,
            "Cannot start",
            "The cryptographic module is not in FIPS mode, so this program will not run.",
        );
        return after_refusal(action);
    }
    let config_path = args.config.unwrap_or_else(default_config);
    let cfg = match config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("usgp-preboot-agent: cannot start: {e}");
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
            // The configuration is usable: the refusal stays on screen.
            eprintln!("usgp-preboot-agent: cannot start: {e}");
            let action = app::refuse(
                &mut console,
                "Cannot start",
                &format!("This device's platform could not be prepared: {e}"),
            );
            return after_refusal(action);
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
        println!("power: {action:?}");
        // A real restart or shutdown is under way: give it time, bounded.
        if args.sim.is_none() {
            std::thread::sleep(POWER_GRACE);
        }
    }
    ExitCode::from(ending.outcome.exit_code())
}
