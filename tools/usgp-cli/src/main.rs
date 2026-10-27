//! usgp-cli: operator CLI.
//!
//! M1: `boot-manifest create | verify` (plan WU-7).
//! M2 (plan WU-8): operator API commands for image files, PE kits and
//! deployment packages over HTTPS with the operator's client certificate
//! (`limits`, `image ...`, `pe ...`, `package ...`). See
//! docs/ARCHITECTURE.md.
//!
//! Process contract (plan section 3.6):
//!
//! | Command | Exit |
//! |---------|------|
//! | `usgp-cli` (no args) | FIPS check, usage on stdout, 0 (1 if FIPS is inactive) |
//! | `usgp-cli --help` | usage on stdout, 0 |
//! | `usgp-cli boot-manifest create\|verify ...` | 0 ok, 1 failure, 2 usage |
//! | `usgp-cli limits\|image\|pe\|package ...` | 0 ok, 1 failure, 2 usage |
//!
//! `boot-manifest`: audit events are JSON lines on stdout; operator
//! messages go to stderr. M2 commands: results on stdout, errors and
//! confirmation prompts on stderr; the server records the audit events
//! for the authenticated operator (plan section 7).

// Reads operator files: indexing and slicing that can panic are denied
// (CLAUDE.md, Engineering Rules).
#![deny(clippy::indexing_slicing)]

#[macro_use]
mod client;
mod args;
mod boot_manifest;
mod cmd_content;
mod cmd_image;
mod cmd_package;
mod cmd_pe;
mod config;
mod display;
mod https;

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use usgp_common::telemetry::{self, Level, LogFormat};
use usgp_proto::status::ContentKind;

use crate::args::{Action, ApiCommand, Command};
use crate::client::{ApiClient, Transport};
use crate::cmd_content::{CmdError, PinnedKey, content_id};
use crate::cmd_package::package_id;

const USAGE: &str = "\
usage: usgp-cli [-h | --help]
       usgp-cli boot-manifest create --root DIR --out FILE [--] NAME...
       usgp-cli boot-manifest verify --root DIR --manifest FILE
       usgp-cli limits [CONN]
       usgp-cli image upload FILE --name NAME [CONN]
       usgp-cli image list | view ID | delete ID [--yes] [CONN]
       usgp-cli image declare ID --index N --release R --edition E --arch A [CONN]
       usgp-cli image download ID --out FILE [CONN]
       usgp-cli pe import FILE --name NAME --arch A --kit-version V [CONN]
       usgp-cli pe list | view ID | delete ID [--yes] [CONN]
       usgp-cli pe download ID --out FILE [CONN]
       usgp-cli package create --name N [--description D] --image ID --index N --pe ID [CONN]
       usgp-cli package edit ID [--name N] [--description D] [--image ID] [--index N] [--pe ID] [CONN]
       usgp-cli package list | view ID | clone ID --name N | delete ID [--yes] [CONN]
       usgp-cli package manifest ID --out FILE [CONN]

CONN: [--config FILE] [--server https://HOST[:PORT]] [--server-ca FILE]
      [--client-cert FILE] [--client-key FILE] [--content-key-pub FILE]
      (defaults from $HOME/.config/usgp/cli.toml; the key file must be 0600)

boot-manifest create  hash each NAME (relative to DIR) with SHA-256 and write
                      a new boot manifest to FILE (never overwrites FILE)
boot-manifest verify  check every file listed in FILE against DIR
image declare         declare an edition's release (windows-11, windows-10,
                      other), edition (enterprise, enterprise-ltsc,
                      iot-enterprise, education, pro, home, other) and
                      architecture (x64, x86, arm64, arm)
image|pe download     verify the signed manifest with --content-key-pub, then
                      each 8 MiB chunk, before writing FILE (never overwrites)
package manifest      verify the signed package manifest, then write it to FILE
delete                warns and asks for confirmation unless --yes is given

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
        Command::Api(cmd) => ExitCode::from(run_api(*cmd)),
    }
}

/// Whether the action verifies signed content (and so needs the pinned
/// content public key).
const fn needs_content_key(a: &Action) -> bool {
    matches!(
        a,
        Action::ImageDownload(..) | Action::PeDownload(..) | Action::PackageManifest(..)
    )
}

/// Runs an M2 command: resolves settings, pins the content key when it is
/// needed, builds TLS, connects, and dispatches. Returns 0 or 1.
fn run_api(cmd: ApiCommand) -> u8 {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let prepared = config::resolve(&cmd.conn, home.as_deref()).and_then(|s| {
        let key = if needs_content_key(&cmd.action) {
            Some(PinnedKey::new(config::content_key(&s)?))
        } else {
            None
        };
        Ok((config::client_tls(&s)?, s, key))
    });
    let (tls, settings, key) = match prepared {
        Ok(p) => p,
        Err(e) => {
            eprintln!("usgp-cli: {e}");
            return 1;
        }
    };
    let transport = match https::HttpsTransport::new(settings.server, tls) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("usgp-cli: {e}");
            return 1;
        }
    };
    let mut api = ApiClient::new(transport);
    let mut input = io::stdin().lock();
    let mut out = io::stdout().lock();
    let mut err = io::stderr().lock();
    let result = dispatch(
        &mut api,
        cmd.action,
        key.as_ref(),
        &mut input,
        &mut out,
        &mut err,
    )
    .and_then(|()| out.flush().map_err(CmdError::from));
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("usgp-cli: {e}");
            1
        }
    }
}

/// The pinned key, which [`run_api`] loads for every action that needs
/// one.
fn pinned(key: Option<&PinnedKey>) -> Result<&PinnedKey, CmdError> {
    key.ok_or_else(|| CmdError::Invalid("--content-key-pub is required".into()))
}

/// `image|pe download ID --out FILE`.
fn download<T: Transport>(
    api: &mut ApiClient<T>,
    kind: ContentKind,
    id: &str,
    file: &std::path::Path,
    key: Option<&PinnedKey>,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    let key = pinned(key)?;
    let d = cmd_content::download(api, kind, content_id(id)?, file, key)?;
    cmd_content::print_downloaded(out, &d, key)
}

/// Runs `action` against the API.
fn dispatch<T: Transport>(
    api: &mut ApiClient<T>,
    action: Action,
    key: Option<&PinnedKey>,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CmdError> {
    match action {
        Action::Limits => cmd_image::limits(api, out),
        Action::ImageUpload { file, name } => {
            let u = cmd_content::upload(api, ContentKind::Image, &file, &name, None)?;
            cmd_content::print_uploaded(out, ContentKind::Image, &u)
        }
        Action::ImageList => cmd_image::list(api, out),
        Action::ImageView(id) => cmd_image::view(api, content_id(&id)?, out),
        Action::ImageDeclare(id, d) => cmd_image::declare(api, content_id(&id)?, &d, out),
        Action::ImageDelete(id, yes) => {
            cmd_image::delete(api, content_id(&id)?, yes, input, out, err)
        }
        Action::ImageDownload(id, file) => download(api, ContentKind::Image, &id, &file, key, out),
        Action::PeDownload(id, file) => download(api, ContentKind::Pe, &id, &file, key, out),
        Action::PeImport {
            file,
            name,
            arch,
            kit_version,
        } => cmd_pe::import(api, &file, &name, &arch, &kit_version, out),
        Action::PeList => cmd_pe::list(api, out),
        Action::PeView(id) => cmd_pe::view(api, content_id(&id)?, out),
        Action::PeDelete(id, yes) => cmd_pe::delete(api, content_id(&id)?, yes, input, out, err),
        Action::PackageCreate(d) => cmd_package::create(api, &d, out),
        Action::PackageList => cmd_package::list(api, out),
        Action::PackageView(id) => cmd_package::view(api, package_id(&id)?, out),
        Action::PackageEdit(id, d) => cmd_package::edit(api, package_id(&id)?, &d, out),
        Action::PackageClone(id, name) => cmd_package::clone(api, package_id(&id)?, &name, out),
        Action::PackageDelete(id, yes) => {
            cmd_package::delete(api, package_id(&id)?, yes, input, out, err)
        }
        Action::PackageManifest(id, file) => {
            cmd_package::manifest(api, package_id(&id)?, &file, pinned(key)?, out)
        }
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
