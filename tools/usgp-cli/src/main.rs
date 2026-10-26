//! usgp-cli: operator CLI.
//!
//! M1: `boot-manifest create | verify` (plan WU-7). Deployment packages,
//! boot media and jobs arrive in M2 (docs/ROADMAP.md section 3). See
//! docs/ARCHITECTURE.md.
//!
//! Process contract (plan section 3.6):
//!
//! | Command | Exit |
//! |---------|------|
//! | `usgp-cli` (no args) | FIPS check, usage on stdout, 0 (1 if FIPS is inactive) |
//! | `usgp-cli --help` | usage on stdout, 0 |
//! | `usgp-cli boot-manifest create\|verify ...` | 0 ok, 1 failure, 2 usage |
//!
//! Audit events are JSON lines on stdout; operator messages go to stderr.

// Reads operator files: indexing and slicing that can panic are denied
// (CLAUDE.md, Engineering Rules).
#![deny(clippy::indexing_slicing)]

mod args;
mod boot_manifest;

use std::process::ExitCode;

use usgp_common::telemetry::{self, Level, LogFormat};

use crate::args::Command;

const USAGE: &str = "\
usage: usgp-cli [-h | --help]
       usgp-cli boot-manifest create --root DIR --out FILE [--] NAME...
       usgp-cli boot-manifest verify --root DIR --manifest FILE

boot-manifest create  hash each NAME (relative to DIR) with SHA-256 and write
                      a new boot manifest to FILE (never overwrites FILE)
boot-manifest verify  check every file listed in FILE against DIR

exit status: 0 ok, 1 failure, 2 usage error
";

/// Exit status for a usage error (plan section 3.6).
const EXIT_USAGE: u8 = 2;

fn main() -> ExitCode {
    // COMPLIANCE MAPPING:
    // - NIST 800-53: SC-13 (Cryptographic Protection) - fail closed if the
    //   validated module is not in FIPS mode (docs/decisions/0001).
    if let Err(e) = usgp_crypto::fips_status() {
        eprintln!("usgp-cli: refusing to start: {e}");
        return ExitCode::FAILURE;
    }

    let command = match args::parse(std::env::args_os().skip(1)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("usgp-cli: {e}\n\n{USAGE}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    match command {
        Command::Usage | Command::Help => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Command::Create(a) => with_audit(|| boot_manifest::run_create(&a)),
        Command::Verify(a) => with_audit(|| boot_manifest::run_verify(&a)),
    }
}

/// Installs the JSON audit/log subscriber, then runs `f`.
fn with_audit(f: impl FnOnce() -> u8) -> ExitCode {
    // COMPLIANCE MAPPING:
    // - NIST 800-53: AU-12 (Audit Record Generation) - no audited action
    //   runs unless the audit subscriber is installed.
    if let Err(e) = telemetry::init(Level::INFO, LogFormat::Json) {
        eprintln!("usgp-cli: cannot start audit logging: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::from(f())
}
