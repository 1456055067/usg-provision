//! Command-line parsing (plan section 3.6). Standard library only.
//!
//! | Command | Exit |
//! |---------|------|
//! | `usgp-relay --self-check` | 0, or 1 if FIPS is inactive |
//! | `usgp-relay --check-config PATH [--admin-uid UID]` | 0 Running, 3 missing content, 78 invalid, 1 FIPS |
//! | `usgp-relay --config PATH [--admin-uid UID] [--allow-shared-admin-uid]` | 0 clean stop, 78 config, 1 FIPS or bind failure |
//! | `usgp-relay -h` / `--help` | usage on stdout, 0 |
//! | `usgp-relay` (no args) or anything else | usage on stderr, 2 |
//!
//! The FIPS check runs before any of these, in `main`.
//!
//! `--admin-uid UID` names one uid that may own the trusted files and
//! directories besides uid 0 (`usgp_common::config::TrustPolicy`). It is a
//! command-line option, not a configuration key, because the
//! configuration file is itself checked against it. It is set in the
//! service unit, which only root can change.
//!
//! With `--config`, the relay refuses to start (exit 78, audited as
//! `relay.config.rejected`) when its effective uid is a non-zero
//! `--admin-uid`, because the process could then rewrite its own trust
//! anchors (CM-5, AC-6). `--allow-shared-admin-uid` overrides
//! this; `relay.start` then records `allow_shared_admin_uid=true`. The
//! options after PATH may come in either order, each at most once.

use std::ffi::OsString;
use std::path::PathBuf;

/// Usage text.
pub const USAGE: &str = "\
usage: usgp-relay --config PATH [--admin-uid UID] [--allow-shared-admin-uid]
                                                         run the boot service
       usgp-relay --check-config PATH [--admin-uid UID]  validate configuration and content
       usgp-relay --self-check                           FIPS start-up check only
       usgp-relay --help

  --admin-uid UID           uid trusted, besides root, to own the configuration,
                            manifest and suppression files and their directories
  --allow-shared-admin-uid  (--config only) run even though the relay's own
                            uid is the --admin-uid; without it the relay
                            refuses to start in that case (exit 78), because
                            it could then rewrite its own trusted files";

/// The arguments of `--config` and `--check-config`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigArgs {
    /// The configuration file.
    pub path: PathBuf,
    /// `--admin-uid`, if given.
    pub admin_uid: Option<u32>,
    /// `--allow-shared-admin-uid` (accepted with `--config` only).
    pub allow_shared_admin_uid: bool,
}

/// A parsed command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `--self-check`.
    SelfCheck,
    /// `--check-config PATH [--admin-uid UID]`.
    CheckConfig(ConfigArgs),
    /// `--config PATH [--admin-uid UID] [--allow-shared-admin-uid]`.
    Run(ConfigArgs),
    /// `-h` / `--help`.
    Help,
}

/// Why the command line was refused (exit 2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UsageError {
    /// No arguments.
    #[error("no command given")]
    NoArguments,
    /// An option that needs a path had none.
    #[error("{0} needs a path")]
    MissingPath(&'static str),
    /// An empty path.
    #[error("{0} needs a non-empty path")]
    EmptyPath(&'static str),
    /// `--admin-uid` without a decimal uid.
    #[error("--admin-uid needs a decimal uid")]
    BadUid,
    /// Unknown option or extra argument.
    #[error("unexpected argument")]
    Unexpected,
}

/// Parses the arguments after the program name.
///
/// # Errors
///
/// [`UsageError`].
pub fn parse<I>(args: I) -> Result<Command, UsageError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut it = args.into_iter();
    let Some(first) = it.next() else {
        return Err(UsageError::NoArguments);
    };
    let cmd = match first.to_str() {
        Some("--self-check") => Command::SelfCheck,
        Some("-h" | "--help") => Command::Help,
        Some("--check-config") => {
            Command::CheckConfig(config_args(&mut it, "--check-config", false)?)
        }
        Some("--config") => Command::Run(config_args(&mut it, "--config", true)?),
        _ => return Err(UsageError::Unexpected),
    };
    if it.next().is_some() {
        return Err(UsageError::Unexpected);
    }
    Ok(cmd)
}

/// PATH, then `--admin-uid UID` and (if `accept_allow_shared`)
/// `--allow-shared-admin-uid`, in either order, each at most once.
fn config_args(
    it: &mut impl Iterator<Item = OsString>,
    opt: &'static str,
    accept_allow_shared: bool,
) -> Result<ConfigArgs, UsageError> {
    let path = path_arg(it.next(), opt)?;
    let mut args = ConfigArgs {
        path,
        admin_uid: None,
        allow_shared_admin_uid: false,
    };
    // At most two options follow PATH; anything further is refused by
    // `parse`.
    for _ in 0..2 {
        let Some(flag) = it.next() else {
            break;
        };
        match flag.to_str() {
            Some("--admin-uid") if args.admin_uid.is_none() => {
                let v = it.next().ok_or(UsageError::BadUid)?;
                args.admin_uid = Some(parse_uid(&v)?);
            }
            Some("--allow-shared-admin-uid")
                if accept_allow_shared && !args.allow_shared_admin_uid =>
            {
                args.allow_shared_admin_uid = true;
            }
            _ => return Err(UsageError::Unexpected),
        }
    }
    Ok(args)
}

/// A decimal uid: 1 to 10 ASCII digits, fitting in `u32`.
fn parse_uid(v: &std::ffi::OsStr) -> Result<u32, UsageError> {
    let s = v.to_str().ok_or(UsageError::BadUid)?;
    if s.is_empty() || s.len() > 10 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(UsageError::BadUid);
    }
    s.parse().map_err(|_| UsageError::BadUid)
}

fn path_arg(v: Option<OsString>, opt: &'static str) -> Result<PathBuf, UsageError> {
    let v = v.ok_or(UsageError::MissingPath(opt))?;
    if v.is_empty() {
        return Err(UsageError::EmptyPath(opt));
    }
    Ok(PathBuf::from(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Command, UsageError> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn commands() {
        assert_eq!(p(&["--self-check"]), Ok(Command::SelfCheck));
        assert_eq!(p(&["--help"]), Ok(Command::Help));
        assert_eq!(p(&["-h"]), Ok(Command::Help));
        assert_eq!(
            p(&["--check-config", "/etc/usgp-relay/relay.toml"]),
            Ok(Command::CheckConfig(args(
                "/etc/usgp-relay/relay.toml",
                None
            )))
        );
        assert_eq!(
            p(&["--config", "relay.toml"]),
            Ok(Command::Run(args("relay.toml", None)))
        );
        assert_eq!(
            p(&["--config", "relay.toml", "--admin-uid", "1000"]),
            Ok(Command::Run(args("relay.toml", Some(1000))))
        );
        assert_eq!(
            p(&["--check-config", "r.toml", "--admin-uid", "0"]),
            Ok(Command::CheckConfig(args("r.toml", Some(0))))
        );
    }

    fn args(path: &str, admin_uid: Option<u32>) -> ConfigArgs {
        ConfigArgs {
            path: path.into(),
            admin_uid,
            allow_shared_admin_uid: false,
        }
    }

    #[test]
    fn allow_shared_admin_uid_flag() {
        let shared = |uid| ConfigArgs {
            allow_shared_admin_uid: true,
            ..args("r.toml", uid)
        };
        assert_eq!(
            p(&[
                "--config",
                "r.toml",
                "--admin-uid",
                "7",
                "--allow-shared-admin-uid"
            ]),
            Ok(Command::Run(shared(Some(7))))
        );
        assert_eq!(
            p(&[
                "--config",
                "r.toml",
                "--allow-shared-admin-uid",
                "--admin-uid",
                "7"
            ]),
            Ok(Command::Run(shared(Some(7))))
        );
        assert_eq!(
            p(&["--config", "r.toml", "--allow-shared-admin-uid"]),
            Ok(Command::Run(shared(None)))
        );
        for bad in [
            &["--check-config", "r.toml", "--allow-shared-admin-uid"][..],
            &[
                "--check-config",
                "r.toml",
                "--admin-uid",
                "7",
                "--allow-shared-admin-uid",
            ],
            &[
                "--config",
                "r.toml",
                "--allow-shared-admin-uid",
                "--allow-shared-admin-uid",
            ],
            &["--config", "r.toml", "--admin-uid", "7", "--admin-uid", "7"],
            &[
                "--config",
                "r.toml",
                "--admin-uid",
                "7",
                "--allow-shared-admin-uid",
                "x",
            ],
            &["--allow-shared-admin-uid", "--config", "r.toml"],
        ] {
            assert_eq!(p(bad), Err(UsageError::Unexpected), "{bad:?}");
        }
    }

    #[test]
    fn admin_uid_errors() {
        for bad in [
            &["--config", "r.toml", "--admin-uid"][..],
            &["--config", "r.toml", "--admin-uid", ""],
            &["--config", "r.toml", "--admin-uid", "-1"],
            &["--config", "r.toml", "--admin-uid", "+5"],
            &["--config", "r.toml", "--admin-uid", "4294967296"],
            &["--config", "r.toml", "--admin-uid", "12345678901"],
            &["--config", "r.toml", "--admin-uid", "1a"],
        ] {
            assert_eq!(p(bad), Err(UsageError::BadUid), "{bad:?}");
        }
        assert_eq!(
            p(&["--config", "r.toml", "--admin-uid", "5", "x"]),
            Err(UsageError::Unexpected)
        );
        assert_eq!(
            p(&["--config", "r.toml", "--admin", "5"]),
            Err(UsageError::Unexpected)
        );
        assert_eq!(
            p(&["--self-check", "--admin-uid", "5"]),
            Err(UsageError::Unexpected)
        );
    }

    #[test]
    fn usage_errors() {
        assert_eq!(p(&[]), Err(UsageError::NoArguments));
        assert_eq!(p(&["--config"]), Err(UsageError::MissingPath("--config")));
        assert_eq!(p(&["--config", ""]), Err(UsageError::EmptyPath("--config")));
        assert_eq!(p(&["--self-check", "x"]), Err(UsageError::Unexpected));
        assert_eq!(p(&["--config", "a", "b"]), Err(UsageError::Unexpected));
        assert_eq!(p(&["--bogus"]), Err(UsageError::Unexpected));
        assert_eq!(p(&["--config=a"]), Err(UsageError::Unexpected));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_option_refused_but_path_kept() {
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![0xff]);
        assert_eq!(parse([bad.clone()]), Err(UsageError::Unexpected));
        assert_eq!(
            parse([OsString::from("--config"), bad.clone()]),
            Ok(Command::Run(ConfigArgs {
                path: PathBuf::from(bad),
                admin_uid: None,
                allow_shared_admin_uid: false,
            }))
        );
    }
}
