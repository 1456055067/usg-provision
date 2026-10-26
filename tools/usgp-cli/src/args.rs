//! Command-line parsing (std only, no parser crate; plan WU-7).
//!
//! Grammar (plan section 3.6):
//!
//! ```text
//! usgp-cli [-h | --help]
//! usgp-cli boot-manifest create --root DIR --out FILE [--] NAME...
//! usgp-cli boot-manifest verify --root DIR --manifest FILE
//! ```
//!
//! Options take their value as the next argument. Each option may appear
//! once, in any order, before `--`. Every argument after `--` is a name, so
//! names that start with `-` can be given. Any other shape is a usage error
//! (exit 2). Names are not validated here; [`crate::boot_manifest`] refuses
//! invalid names as a failure (exit 1), so the refusal is audited.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - operator input is
//   checked for shape before any file is touched; anything unexpected is
//   refused, never guessed.

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

/// A parsed command line.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// No arguments: print usage on stdout, exit 0 (plan section 3.6).
    Usage,
    /// `-h` / `--help` at any level: print usage on stdout, exit 0.
    Help,
    /// `boot-manifest create`.
    Create(CreateArgs),
    /// `boot-manifest verify`.
    Verify(VerifyArgs),
}

/// Arguments of `boot-manifest create`.
#[derive(Debug, PartialEq, Eq)]
pub struct CreateArgs {
    /// Boot root directory the names are relative to.
    pub root: PathBuf,
    /// Manifest file to write; must not exist.
    pub out: PathBuf,
    /// Requested boot file names, unvalidated, in command-line order.
    pub names: Vec<OsString>,
}

/// Arguments of `boot-manifest verify`.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifyArgs {
    /// Boot root directory.
    pub root: PathBuf,
    /// Manifest file to check.
    pub manifest: PathBuf,
}

/// A malformed command line. The message is shown with the usage text.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct UsageError(String);

fn is_help(a: &OsStr) -> bool {
    a == "-h" || a == "--help"
}

/// Parses the arguments after the program name.
///
/// # Errors
///
/// [`UsageError`] for an unknown command or option, a missing or repeated
/// option, a missing option value, or missing names.
pub fn parse<I>(args: I) -> Result<Command, UsageError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut it = args.into_iter();
    let Some(first) = it.next() else {
        return Ok(Command::Usage);
    };
    if is_help(&first) {
        return Ok(Command::Help);
    }
    if first != "boot-manifest" {
        return Err(UsageError(format!("unknown command {first:?}")));
    }
    let Some(sub) = it.next() else {
        return Err(UsageError("boot-manifest needs create or verify".into()));
    };
    if is_help(&sub) {
        return Ok(Command::Help);
    }
    let rest: Vec<OsString> = it.collect();
    if sub == "create" {
        parse_create(rest)
    } else if sub == "verify" {
        parse_verify(rest)
    } else {
        Err(UsageError(format!("unknown boot-manifest command {sub:?}")))
    }
}

/// Options seen so far for one subcommand.
#[derive(Default)]
struct Options {
    root: Option<PathBuf>,
    out: Option<PathBuf>,
    manifest: Option<PathBuf>,
    positional: Vec<OsString>,
    help: bool,
}

/// Splits `rest` into the options in `allowed` and positional arguments.
fn scan(rest: Vec<OsString>, allowed: &[&str]) -> Result<Options, UsageError> {
    let mut o = Options::default();
    let mut it = rest.into_iter();
    while let Some(a) = it.next() {
        if a == "--" {
            o.positional.extend(it);
            break;
        }
        if is_help(&a) {
            o.help = true;
            continue;
        }
        let Some(text) = a.to_str().filter(|t| t.starts_with('-')) else {
            o.positional.push(a);
            continue;
        };
        if !allowed.contains(&text) {
            return Err(UsageError(format!("unknown option {text:?}")));
        }
        let slot = match text {
            "--root" => &mut o.root,
            "--out" => &mut o.out,
            _ => &mut o.manifest,
        };
        if slot.is_some() {
            return Err(UsageError(format!("{text} given more than once")));
        }
        let Some(value) = it.next() else {
            return Err(UsageError(format!("{text} needs a value")));
        };
        if value.is_empty() {
            return Err(UsageError(format!("{text} value is empty")));
        }
        *slot = Some(PathBuf::from(value));
    }
    Ok(o)
}

fn required(v: Option<PathBuf>, name: &str) -> Result<PathBuf, UsageError> {
    v.ok_or_else(|| UsageError(format!("{name} is required")))
}

fn parse_create(rest: Vec<OsString>) -> Result<Command, UsageError> {
    let o = scan(rest, &["--root", "--out"])?;
    if o.help {
        return Ok(Command::Help);
    }
    let root = required(o.root, "--root")?;
    let out = required(o.out, "--out")?;
    if o.positional.is_empty() {
        return Err(UsageError("create needs at least one NAME".into()));
    }
    Ok(Command::Create(CreateArgs {
        root,
        out,
        names: o.positional,
    }))
}

fn parse_verify(rest: Vec<OsString>) -> Result<Command, UsageError> {
    let o = scan(rest, &["--root", "--manifest"])?;
    if o.help {
        return Ok(Command::Help);
    }
    if let Some(extra) = o.positional.first() {
        return Err(UsageError(format!("unexpected argument {extra:?}")));
    }
    Ok(Command::Verify(VerifyArgs {
        root: required(o.root, "--root")?,
        manifest: required(o.manifest, "--manifest")?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Command, UsageError> {
        parse(args.iter().map(OsString::from))
    }

    fn create(root: &str, out: &str, names: &[&str]) -> Command {
        Command::Create(CreateArgs {
            root: root.into(),
            out: out.into(),
            names: names.iter().map(OsString::from).collect(),
        })
    }

    #[test]
    fn no_args_is_usage() {
        assert_eq!(p(&[]), Ok(Command::Usage));
    }

    #[test]
    fn help_at_every_level() {
        assert_eq!(p(&["--help"]), Ok(Command::Help));
        assert_eq!(p(&["-h"]), Ok(Command::Help));
        assert_eq!(p(&["boot-manifest", "-h"]), Ok(Command::Help));
        assert_eq!(p(&["boot-manifest", "create", "--help"]), Ok(Command::Help));
        assert_eq!(p(&["boot-manifest", "verify", "-h"]), Ok(Command::Help));
    }

    #[test]
    fn create_any_order() {
        let want = create("/r", "/o", &["a.efi", "b/c.efi"]);
        assert_eq!(
            p(&[
                "boot-manifest",
                "create",
                "--root",
                "/r",
                "--out",
                "/o",
                "a.efi",
                "b/c.efi"
            ]),
            Ok(want)
        );
        let want = create("/r", "/o", &["a.efi", "b/c.efi"]);
        assert_eq!(
            p(&[
                "boot-manifest",
                "create",
                "a.efi",
                "--out",
                "/o",
                "b/c.efi",
                "--root",
                "/r"
            ]),
            Ok(want)
        );
    }

    #[test]
    fn create_double_dash_allows_dash_names() {
        assert_eq!(
            p(&[
                "boot-manifest",
                "create",
                "--root",
                "/r",
                "--out",
                "/o",
                "--",
                "-x",
                "--root"
            ]),
            Ok(create("/r", "/o", &["-x", "--root"]))
        );
    }

    #[test]
    fn verify_ok() {
        assert_eq!(
            p(&[
                "boot-manifest",
                "verify",
                "--manifest",
                "/m",
                "--root",
                "/r"
            ]),
            Ok(Command::Verify(VerifyArgs {
                root: "/r".into(),
                manifest: "/m".into()
            }))
        );
    }

    #[test]
    fn usage_errors() {
        let bad: &[&[&str]] = &[
            &["frobnicate"],
            &["boot-manifest"],
            &["boot-manifest", "sign"],
            &["boot-manifest", "create", "--out", "/o", "a"],
            &["boot-manifest", "create", "--root", "/r", "a"],
            &["boot-manifest", "create", "--root", "/r", "--out", "/o"],
            &[
                "boot-manifest",
                "create",
                "--root",
                "/r",
                "--out",
                "/o",
                "--",
            ],
            &[
                "boot-manifest",
                "create",
                "--root",
                "/r",
                "--root",
                "/s",
                "--out",
                "/o",
                "a",
            ],
            &["boot-manifest", "create", "--root", "/r", "--out"],
            &["boot-manifest", "create", "--root", "", "--out", "/o", "a"],
            &[
                "boot-manifest",
                "create",
                "--root",
                "/r",
                "--out",
                "/o",
                "--manifest",
                "/m",
                "a",
            ],
            &["boot-manifest", "create", "--root=/r", "--out", "/o", "a"],
            &[
                "boot-manifest",
                "create",
                "--root",
                "/r",
                "--out",
                "/o",
                "-x",
            ],
            &["boot-manifest", "verify", "--root", "/r"],
            &["boot-manifest", "verify", "--manifest", "/m"],
            &[
                "boot-manifest",
                "verify",
                "--root",
                "/r",
                "--manifest",
                "/m",
                "extra",
            ],
            &[
                "boot-manifest",
                "verify",
                "--root",
                "/r",
                "--manifest",
                "/m",
                "--out",
                "/o",
            ],
        ];
        for args in bad {
            assert!(p(args).is_err(), "{args:?} should be a usage error");
        }
    }
}
