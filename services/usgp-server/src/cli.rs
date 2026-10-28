//! Command-line parsing (plan M2 WU-7). Standard library only.
//!
//! | Command | Exit |
//! |---------|------|
//! | `usgp-server --self-check` | 0, or 1 if FIPS is inactive |
//! | `usgp-server --check-config PATH [--admin-uid UID]` | 0 valid, 78 invalid, 1 FIPS |
//! | `usgp-server serve --config PATH [--admin-uid UID] [--allow-shared-admin-uid]` | 0 clean stop, 78 config, 1 FIPS, database or bind failure |
//! | `usgp-server migrate --config PATH --owner-user U --owner-cert P --owner-key P [--admin-uid UID]` | 0, 78, 77, 1 |
//! | `usgp-server keygen --purpose content\|audit\|plan\|boot-policy --out-key K --out-pub P` | 0, 1 |
//! | `usgp-server keygen --purpose code-hmac --out-key K` | 0, 1 |
//! | `usgp-server operator enrol --config PATH --cert PEM --name N --role administrator\|none [--admin-uid UID]` | 0, 78, 77, 1 |
//! | `usgp-server operator disable --config PATH --id UUID [--admin-uid UID]` | 0, 78, 77, 1 |
//! | `usgp-server audit verify --config PATH --trusted-key P [--trusted-key P ...] [--admin-uid UID]` | 0 intact, 1 tampered, 69 unreadable, 78, 77 |
//! | `usgp-server boot-service enrol --config PATH --cert PEM --name N --subnet CIDR [--subnet CIDR ...] [--admin-uid UID]` | 0, 78, 77, 1 |
//! | `usgp-server boot-service disable --config PATH --id UUID [--admin-uid UID]` | 0, 78, 77, 1 |
//! | `usgp-server -h` / `--help` | usage on stdout, 0 |
//! | `usgp-server` (no args) or anything else | usage on stderr, 2 |
//!
//! The FIPS check runs before any of these, in `main`.
//!
//! `--admin-uid UID` names one uid that may own the trusted files besides
//! uid 0 (`usgp_common::config::TrustPolicy`), as for the relay. The
//! local administrative commands (`migrate`, `operator`, `audit verify`,
//! `boot-service`)
//! run only as root or as that uid (decision 0015 item 3: audit records
//! are read only by a local administrative command).

use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

/// Usage text.
pub const USAGE: &str = "\
usage: usgp-server serve --config PATH [--admin-uid UID] [--allow-shared-admin-uid]
       usgp-server --check-config PATH [--admin-uid UID]
       usgp-server --self-check
       usgp-server migrate --config PATH --owner-user NAME --owner-cert PEM --owner-key PEM
                           [--admin-uid UID]
       usgp-server keygen --purpose content|audit|plan|boot-policy --out-key FILE --out-pub FILE
       usgp-server keygen --purpose code-hmac --out-key FILE
       usgp-server operator enrol --config PATH --cert PEM --name NAME
                                  --role administrator|none [--admin-uid UID]
       usgp-server operator disable --config PATH --id UUID [--admin-uid UID]
       usgp-server audit verify --config PATH --trusted-key PEM [--trusted-key PEM ...]
                                [--max-unsigned-records N] [--max-checkpoint-age DUR]
                                [--admin-uid UID]
       usgp-server boot-service enrol --config PATH --cert PEM --name NAME
                                      --subnet CIDR [--subnet CIDR ...] [--admin-uid UID]
       usgp-server boot-service disable --config PATH --id UUID [--admin-uid UID]
       usgp-server --help

  --admin-uid UID           uid trusted, besides root, to own the configuration, keys,
                            certificates and CRLs; local administrative commands
                            (migrate, operator, audit verify, boot-service) run
                            only as root or as the owner of the configuration file
  --subnet CIDR             (boot-service enrol) a subnet the boot service serves,
                            for example 10.20.0.0/16; 1 to 64
  --max-unsigned-records N  (audit verify) longest run of records allowed without a
                            signed checkpoint; default from the configured cadence
                            and the number of concurrent writers
  --max-checkpoint-age DUR  (audit verify) the newest signed checkpoint must be at most
                            this old (now, and relative to the last record); DUR is
                            N followed by s, m, h or d (for example 30m); 1s to 366d.
                            Use about twice [audit] checkpoint_heartbeat_s while the
                            server runs
  --allow-shared-admin-uid  (serve only) run even though the server's own uid is the
                            --admin-uid; without it the server refuses to start (78)";

/// Largest number of `--trusted-key` options.
pub const MAX_TRUSTED_KEYS: usize = 16;
/// Largest number of `--subnet` options (the boot-service record holds
/// 1 to 64 subnets, plan M3 section 3.8).
pub const MAX_SUBNETS: usize = 64;

/// `--config PATH [--admin-uid UID] [--allow-shared-admin-uid]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigArgs {
    /// The configuration file.
    pub path: PathBuf,
    /// `--admin-uid`, if given.
    pub admin_uid: Option<u32>,
    /// `--allow-shared-admin-uid` (`serve` only).
    pub allow_shared_admin_uid: bool,
}

/// Key purpose for `keygen` (plan section 5.2: one key per purpose).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    /// Signs content and package manifests.
    Content,
    /// Signs audit checkpoints.
    Audit,
    /// Signs job plans (M3 plan section 5).
    Plan,
    /// Signs boot-policy lists for relays (M3 plan section 5).
    BootPolicy,
    /// Keys the HMAC under which operator codes are stored (M3 plan
    /// section 5): 32 raw bytes, no public half.
    CodeHmac,
}

impl KeyPurpose {
    /// The option value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Content => "content",
            Self::Audit => "audit",
            Self::Plan => "plan",
            Self::BootPolicy => "boot-policy",
            Self::CodeHmac => "code-hmac",
        }
    }

    /// True for the signing purposes (an ECDSA key pair; `--out-pub`
    /// required); false for the code HMAC key (`--out-pub` refused).
    #[must_use]
    pub const fn is_signing(self) -> bool {
        !matches!(self, Self::CodeHmac)
    }
}

/// `--role` of `operator enrol`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleArg {
    /// The built-in role holding every permission (REQ-RBAC-004).
    Administrator,
    /// No role: every route answers 403 (REQ-RBAC-003).
    None,
}

/// A parsed command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `--self-check`.
    SelfCheck,
    /// `-h` / `--help`.
    Help,
    /// `--check-config PATH [--admin-uid UID]`.
    CheckConfig(ConfigArgs),
    /// `serve --config PATH ...`.
    Serve(ConfigArgs),
    /// `migrate ...`.
    Migrate {
        /// Configuration.
        config: ConfigArgs,
        /// Owner role name.
        owner_user: String,
        /// Owner client certificate (PEM).
        owner_cert: PathBuf,
        /// Owner client key (PKCS#8 PEM).
        owner_key: PathBuf,
    },
    /// `keygen ...`.
    Keygen {
        /// Purpose.
        purpose: KeyPurpose,
        /// Private key output (PKCS#8 PEM, or 32 raw bytes for
        /// `code-hmac`; created 0600).
        out_key: PathBuf,
        /// Public key output (SPKI PEM); `None` for `code-hmac`.
        out_pub: Option<PathBuf>,
    },
    /// `operator enrol ...`.
    OperatorEnrol {
        /// Configuration.
        config: ConfigArgs,
        /// Operator certificate (PEM).
        cert: PathBuf,
        /// Display name.
        name: String,
        /// Role.
        role: RoleArg,
    },
    /// `operator disable ...`.
    OperatorDisable {
        /// Configuration.
        config: ConfigArgs,
        /// Operator id (UUID text).
        id: String,
    },
    /// `audit verify ...`.
    AuditVerify {
        /// Configuration.
        config: ConfigArgs,
        /// Trusted audit public keys (SPKI PEM files).
        trusted_keys: Vec<PathBuf>,
        /// `--max-unsigned-records` (finding SEC-002), if given.
        max_unsigned_records: Option<u64>,
        /// `--max-checkpoint-age` (finding SEC-013), if given.
        max_checkpoint_age: Option<std::time::Duration>,
    },
    /// `boot-service enrol ...` (decision 0021 item 1).
    BootServiceEnrol {
        /// Configuration.
        config: ConfigArgs,
        /// The relay's client certificate (PEM).
        cert: PathBuf,
        /// Unique name.
        name: String,
        /// Served subnets (CIDR text, 1 to 64; parsed by the command).
        subnets: Vec<String>,
    },
    /// `boot-service disable ...`.
    BootServiceDisable {
        /// Configuration.
        config: ConfigArgs,
        /// Boot-service id (UUID text).
        id: String,
    },
}

/// Why the command line was refused (exit 2). Never echoes arguments.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UsageError {
    /// No arguments.
    #[error("no command given")]
    NoArguments,
    /// An option that needs a value had none.
    #[error("{0} needs a value")]
    MissingValue(&'static str),
    /// An empty value.
    #[error("{0} needs a non-empty value")]
    EmptyValue(&'static str),
    /// A required option is absent.
    #[error("{0} is required")]
    Required(&'static str),
    /// An option given twice.
    #[error("{0} given more than once")]
    Repeated(&'static str),
    /// `--admin-uid` without a decimal uid.
    #[error("--admin-uid needs a decimal uid")]
    BadUid,
    /// A value outside its closed set.
    #[error("{0} has an unsupported value")]
    BadValue(&'static str),
    /// Too many `--trusted-key` options.
    #[error("at most 16 --trusted-key options are accepted")]
    TooManyKeys,
    /// Too many `--subnet` options.
    #[error("at most 64 --subnet options are accepted")]
    TooManySubnets,
    /// Unknown option, subcommand or extra argument.
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
    let rest: Vec<OsString> = it.collect();
    match first.to_str() {
        Some("--self-check") => no_more(&rest).map(|()| Command::SelfCheck),
        Some("-h" | "--help") => no_more(&rest).map(|()| Command::Help),
        Some("--check-config") => check_config(&rest),
        Some("serve") => serve(&rest),
        Some("migrate") => migrate(&rest),
        Some("keygen") => keygen(&rest),
        Some("operator") => operator(&rest),
        Some("audit") => audit(&rest),
        Some("boot-service") => boot_service(&rest),
        _ => Err(UsageError::Unexpected),
    }
}

fn no_more(rest: &[OsString]) -> Result<(), UsageError> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(UsageError::Unexpected)
    }
}

/// The options a command accepts: value options and flags.
struct Spec {
    values: &'static [&'static str],
    flags: &'static [&'static str],
    /// The one option that may repeat.
    repeatable: Option<&'static str>,
}

/// Parsed `--option value` pairs and flags.
#[derive(Default)]
struct Opts {
    values: Vec<(&'static str, OsString)>,
    flags: Vec<&'static str>,
}

impl Opts {
    fn get(&self, name: &'static str) -> Option<&OsString> {
        self.values.iter().find(|(k, _)| *k == name).map(|(_, v)| v)
    }

    fn all(&self, name: &'static str) -> impl Iterator<Item = &OsString> {
        self.values
            .iter()
            .filter(move |(k, _)| *k == name)
            .map(|(_, v)| v)
    }

    fn flag(&self, name: &'static str) -> bool {
        self.flags.contains(&name)
    }

    fn path(&self, name: &'static str) -> Result<PathBuf, UsageError> {
        let v = self.get(name).ok_or(UsageError::Required(name))?;
        if v.is_empty() {
            return Err(UsageError::EmptyValue(name));
        }
        Ok(PathBuf::from(v))
    }

    fn text(&self, name: &'static str) -> Result<String, UsageError> {
        let v = self.get(name).ok_or(UsageError::Required(name))?;
        let s = v.to_str().ok_or(UsageError::BadValue(name))?;
        if s.is_empty() {
            return Err(UsageError::EmptyValue(name));
        }
        Ok(s.to_owned())
    }

    fn admin_uid(&self) -> Result<Option<u32>, UsageError> {
        self.get("--admin-uid").map(|v| parse_uid(v)).transpose()
    }

    fn config(&self) -> Result<ConfigArgs, UsageError> {
        Ok(ConfigArgs {
            path: self.path("--config")?,
            admin_uid: self.admin_uid()?,
            allow_shared_admin_uid: self.flag("--allow-shared-admin-uid"),
        })
    }
}

fn options(rest: &[OsString], spec: &Spec) -> Result<Opts, UsageError> {
    let mut opts = Opts::default();
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        let name = arg.to_str().ok_or(UsageError::Unexpected)?;
        if let Some(&flag) = spec.flags.iter().find(|f| **f == name) {
            if opts.flag(flag) {
                return Err(UsageError::Repeated(flag));
            }
            opts.flags.push(flag);
            continue;
        }
        let Some(&key) = spec.values.iter().find(|v| **v == name) else {
            return Err(UsageError::Unexpected);
        };
        if opts.get(key).is_some() && spec.repeatable != Some(key) {
            return Err(UsageError::Repeated(key));
        }
        let value = it.next().ok_or(UsageError::MissingValue(key))?;
        opts.values.push((key, value.clone()));
    }
    Ok(opts)
}

fn check_config(rest: &[OsString]) -> Result<Command, UsageError> {
    // Relay shape: `--check-config PATH [--admin-uid UID]`.
    let (path, more) = rest
        .split_first()
        .ok_or(UsageError::MissingValue("--check-config"))?;
    if path.is_empty() {
        return Err(UsageError::EmptyValue("--check-config"));
    }
    let opts = options(
        more,
        &Spec {
            values: &["--admin-uid"],
            flags: &[],
            repeatable: None,
        },
    )?;
    Ok(Command::CheckConfig(ConfigArgs {
        path: PathBuf::from(path),
        admin_uid: opts.admin_uid()?,
        allow_shared_admin_uid: false,
    }))
}

fn serve(rest: &[OsString]) -> Result<Command, UsageError> {
    let opts = options(
        rest,
        &Spec {
            values: &["--config", "--admin-uid"],
            flags: &["--allow-shared-admin-uid"],
            repeatable: None,
        },
    )?;
    Ok(Command::Serve(opts.config()?))
}

fn migrate(rest: &[OsString]) -> Result<Command, UsageError> {
    let opts = options(
        rest,
        &Spec {
            values: &[
                "--config",
                "--admin-uid",
                "--owner-user",
                "--owner-cert",
                "--owner-key",
            ],
            flags: &[],
            repeatable: None,
        },
    )?;
    Ok(Command::Migrate {
        config: opts.config()?,
        owner_user: opts.text("--owner-user")?,
        owner_cert: opts.path("--owner-cert")?,
        owner_key: opts.path("--owner-key")?,
    })
}

fn keygen(rest: &[OsString]) -> Result<Command, UsageError> {
    let opts = options(
        rest,
        &Spec {
            values: &["--purpose", "--out-key", "--out-pub"],
            flags: &[],
            repeatable: None,
        },
    )?;
    let purpose = match opts.text("--purpose")?.as_str() {
        "content" => KeyPurpose::Content,
        "audit" => KeyPurpose::Audit,
        "plan" => KeyPurpose::Plan,
        "boot-policy" => KeyPurpose::BootPolicy,
        "code-hmac" => KeyPurpose::CodeHmac,
        _ => return Err(UsageError::BadValue("--purpose")),
    };
    let out_key = opts.path("--out-key")?;
    // The code HMAC key has no public half.
    let out_pub = if purpose.is_signing() {
        let p = opts.path("--out-pub")?;
        if out_key == p {
            return Err(UsageError::BadValue("--out-pub"));
        }
        Some(p)
    } else {
        if opts.get("--out-pub").is_some() {
            return Err(UsageError::Unexpected);
        }
        None
    };
    Ok(Command::Keygen {
        purpose,
        out_key,
        out_pub,
    })
}

fn operator(rest: &[OsString]) -> Result<Command, UsageError> {
    let (sub, rest) = rest.split_first().ok_or(UsageError::Unexpected)?;
    match sub.to_str() {
        Some("enrol") => {
            let opts = options(
                rest,
                &Spec {
                    values: &["--config", "--admin-uid", "--cert", "--name", "--role"],
                    flags: &[],
                    repeatable: None,
                },
            )?;
            let role = match opts.text("--role")?.as_str() {
                "administrator" => RoleArg::Administrator,
                "none" => RoleArg::None,
                _ => return Err(UsageError::BadValue("--role")),
            };
            Ok(Command::OperatorEnrol {
                config: opts.config()?,
                cert: opts.path("--cert")?,
                name: opts.text("--name")?,
                role,
            })
        }
        Some("disable") => {
            let opts = options(
                rest,
                &Spec {
                    values: &["--config", "--admin-uid", "--id"],
                    flags: &[],
                    repeatable: None,
                },
            )?;
            Ok(Command::OperatorDisable {
                config: opts.config()?,
                id: opts.text("--id")?,
            })
        }
        _ => Err(UsageError::Unexpected),
    }
}

fn audit(rest: &[OsString]) -> Result<Command, UsageError> {
    let (sub, rest) = rest.split_first().ok_or(UsageError::Unexpected)?;
    if sub.to_str() != Some("verify") {
        return Err(UsageError::Unexpected);
    }
    let opts = options(
        rest,
        &Spec {
            values: &[
                "--config",
                "--admin-uid",
                "--trusted-key",
                "--max-unsigned-records",
                "--max-checkpoint-age",
            ],
            flags: &[],
            repeatable: Some("--trusted-key"),
        },
    )?;
    let mut trusted_keys = Vec::new();
    for v in opts.all("--trusted-key") {
        if v.is_empty() {
            return Err(UsageError::EmptyValue("--trusted-key"));
        }
        trusted_keys.push(PathBuf::from(v));
    }
    if trusted_keys.is_empty() {
        return Err(UsageError::Required("--trusted-key"));
    }
    if trusted_keys.len() > MAX_TRUSTED_KEYS {
        return Err(UsageError::TooManyKeys);
    }
    let max_unsigned_records = opts
        .get("--max-unsigned-records")
        .map(|v| {
            let t = v
                .to_str()
                .ok_or(UsageError::BadValue("--max-unsigned-records"))?;
            if t.is_empty() || t.len() > 19 || !t.bytes().all(|b| b.is_ascii_digit()) {
                return Err(UsageError::BadValue("--max-unsigned-records"));
            }
            t.parse::<u64>()
                .map_err(|_| UsageError::BadValue("--max-unsigned-records"))
        })
        .transpose()?;
    let max_checkpoint_age = opts
        .get("--max-checkpoint-age")
        .map(|v| {
            v.to_str()
                .and_then(parse_age)
                .ok_or(UsageError::BadValue("--max-checkpoint-age"))
        })
        .transpose()?;
    Ok(Command::AuditVerify {
        config: opts.config()?,
        trusted_keys,
        max_unsigned_records,
        max_checkpoint_age,
    })
}

fn boot_service(rest: &[OsString]) -> Result<Command, UsageError> {
    let (sub, rest) = rest.split_first().ok_or(UsageError::Unexpected)?;
    match sub.to_str() {
        Some("enrol") => {
            let opts = options(
                rest,
                &Spec {
                    values: &["--config", "--admin-uid", "--cert", "--name", "--subnet"],
                    flags: &[],
                    repeatable: Some("--subnet"),
                },
            )?;
            let mut subnets = Vec::new();
            for v in opts.all("--subnet") {
                let t = v.to_str().ok_or(UsageError::BadValue("--subnet"))?;
                if t.is_empty() {
                    return Err(UsageError::EmptyValue("--subnet"));
                }
                subnets.push(t.to_owned());
            }
            if subnets.is_empty() {
                return Err(UsageError::Required("--subnet"));
            }
            if subnets.len() > MAX_SUBNETS {
                return Err(UsageError::TooManySubnets);
            }
            Ok(Command::BootServiceEnrol {
                config: opts.config()?,
                cert: opts.path("--cert")?,
                name: opts.text("--name")?,
                subnets,
            })
        }
        Some("disable") => {
            let (config, id) = config_and_id(rest)?;
            Ok(Command::BootServiceDisable { config, id })
        }
        _ => Err(UsageError::Unexpected),
    }
}

/// `--config PATH --id UUID [--admin-uid UID]`.
fn config_and_id(rest: &[OsString]) -> Result<(ConfigArgs, String), UsageError> {
    let opts = options(
        rest,
        &Spec {
            values: &["--config", "--admin-uid", "--id"],
            flags: &[],
            repeatable: None,
        },
    )?;
    Ok((opts.config()?, opts.text("--id")?))
}

/// Longest `--max-checkpoint-age`: 366 days.
pub const MAX_CHECKPOINT_AGE_SECS: u64 = 366 * 86_400;

/// A duration `N[s|m|h|d]` (seconds if no unit): 1 to 9 ASCII digits,
/// at least 1 s, at most [`MAX_CHECKPOINT_AGE_SECS`].
fn parse_age(t: &str) -> Option<std::time::Duration> {
    let (digits, unit) = match t.char_indices().last()? {
        (i, c) if c.is_ascii_alphabetic() => (t.get(..i)?, c),
        _ => (t, 's'),
    };
    if digits.is_empty() || digits.len() > 9 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = digits.parse().ok()?;
    let secs = n.checked_mul(match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86_400,
        _ => return None,
    })?;
    (1..=MAX_CHECKPOINT_AGE_SECS)
        .contains(&secs)
        .then(|| std::time::Duration::from_secs(secs))
}

/// A decimal uid: 1 to 10 ASCII digits, fitting in `u32`.
fn parse_uid(v: &OsStr) -> Result<u32, UsageError> {
    let s = v.to_str().ok_or(UsageError::BadUid)?;
    if s.is_empty() || s.len() > 10 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(UsageError::BadUid);
    }
    s.parse().map_err(|_| UsageError::BadUid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Command, UsageError> {
        parse(args.iter().map(OsString::from))
    }

    fn cfg(path: &str, uid: Option<u32>, shared: bool) -> ConfigArgs {
        ConfigArgs {
            path: path.into(),
            admin_uid: uid,
            allow_shared_admin_uid: shared,
        }
    }

    #[test]
    fn simple_commands() {
        assert_eq!(p(&["--self-check"]), Ok(Command::SelfCheck));
        assert_eq!(p(&["--help"]), Ok(Command::Help));
        assert_eq!(p(&["-h"]), Ok(Command::Help));
        assert_eq!(p(&[]), Err(UsageError::NoArguments));
        assert_eq!(p(&["--self-check", "x"]), Err(UsageError::Unexpected));
        assert_eq!(p(&["--bogus"]), Err(UsageError::Unexpected));
        assert_eq!(p(&["--config", "s.toml"]), Err(UsageError::Unexpected));
    }

    #[test]
    fn check_config_and_serve() {
        assert_eq!(
            p(&["--check-config", "s.toml"]),
            Ok(Command::CheckConfig(cfg("s.toml", None, false)))
        );
        assert_eq!(
            p(&["--check-config", "s.toml", "--admin-uid", "7"]),
            Ok(Command::CheckConfig(cfg("s.toml", Some(7), false)))
        );
        assert_eq!(
            p(&["--check-config", "s.toml", "--allow-shared-admin-uid"]),
            Err(UsageError::Unexpected)
        );
        assert_eq!(
            p(&["--check-config"]),
            Err(UsageError::MissingValue("--check-config"))
        );
        assert_eq!(
            p(&["serve", "--config", "s.toml"]),
            Ok(Command::Serve(cfg("s.toml", None, false)))
        );
        assert_eq!(
            p(&[
                "serve",
                "--allow-shared-admin-uid",
                "--admin-uid",
                "5",
                "--config",
                "s.toml"
            ]),
            Ok(Command::Serve(cfg("s.toml", Some(5), true)))
        );
        assert_eq!(p(&["serve"]), Err(UsageError::Required("--config")));
        assert_eq!(
            p(&["serve", "--config", "a", "--config", "b"]),
            Err(UsageError::Repeated("--config"))
        );
        assert_eq!(
            p(&["serve", "--config", ""]),
            Err(UsageError::EmptyValue("--config"))
        );
        assert_eq!(
            p(&["serve", "--config"]),
            Err(UsageError::MissingValue("--config"))
        );
    }

    #[test]
    fn admin_uid_rules() {
        for bad in ["", "-1", "+5", "4294967296", "12345678901", "1a"] {
            assert_eq!(
                p(&["serve", "--config", "s", "--admin-uid", bad]),
                Err(UsageError::BadUid),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn keygen_args() {
        assert_eq!(
            p(&[
                "keygen",
                "--purpose",
                "audit",
                "--out-key",
                "a.p8",
                "--out-pub",
                "a.pub"
            ]),
            Ok(Command::Keygen {
                purpose: KeyPurpose::Audit,
                out_key: "a.p8".into(),
                out_pub: Some("a.pub".into()),
            })
        );
        for (arg, purpose) in [
            ("plan", KeyPurpose::Plan),
            ("boot-policy", KeyPurpose::BootPolicy),
        ] {
            assert_eq!(
                p(&[
                    "keygen",
                    "--purpose",
                    arg,
                    "--out-key",
                    "k",
                    "--out-pub",
                    "p"
                ]),
                Ok(Command::Keygen {
                    purpose,
                    out_key: "k".into(),
                    out_pub: Some("p".into()),
                })
            );
            assert_eq!(
                p(&["keygen", "--purpose", arg, "--out-key", "k"]),
                Err(UsageError::Required("--out-pub"))
            );
        }
        // The code HMAC key has no public half.
        assert_eq!(
            p(&["keygen", "--purpose", "code-hmac", "--out-key", "c.key"]),
            Ok(Command::Keygen {
                purpose: KeyPurpose::CodeHmac,
                out_key: "c.key".into(),
                out_pub: None,
            })
        );
        assert_eq!(
            p(&[
                "keygen",
                "--purpose",
                "code-hmac",
                "--out-key",
                "c.key",
                "--out-pub",
                "c.pub"
            ]),
            Err(UsageError::Unexpected)
        );
        assert_eq!(
            p(&[
                "keygen",
                "--purpose",
                "tls",
                "--out-key",
                "a",
                "--out-pub",
                "b"
            ]),
            Err(UsageError::BadValue("--purpose"))
        );
        assert_eq!(
            p(&[
                "keygen",
                "--purpose",
                "content",
                "--out-key",
                "a",
                "--out-pub",
                "a"
            ]),
            Err(UsageError::BadValue("--out-pub"))
        );
    }

    #[test]
    fn operator_and_audit_args() {
        assert_eq!(
            p(&[
                "operator", "enrol", "--config", "s", "--cert", "c.pem", "--name", "Jane Doe",
                "--role", "none"
            ]),
            Ok(Command::OperatorEnrol {
                config: cfg("s", None, false),
                cert: "c.pem".into(),
                name: "Jane Doe".into(),
                role: RoleArg::None,
            })
        );
        assert_eq!(
            p(&[
                "operator", "enrol", "--config", "s", "--cert", "c", "--name", "n", "--role",
                "root"
            ]),
            Err(UsageError::BadValue("--role"))
        );
        assert_eq!(
            p(&[
                "operator",
                "enrol",
                "--config",
                "s",
                "--cert",
                "c",
                "--name",
                "n",
                "--role",
                "none",
                "--allow-shared-admin-uid"
            ]),
            Err(UsageError::Unexpected)
        );
        assert_eq!(
            p(&["operator", "disable", "--config", "s", "--id", "x"]),
            Ok(Command::OperatorDisable {
                config: cfg("s", None, false),
                id: "x".into(),
            })
        );
        assert_eq!(p(&["operator", "list"]), Err(UsageError::Unexpected));
        assert_eq!(
            p(&[
                "audit",
                "verify",
                "--config",
                "s",
                "--trusted-key",
                "a.pub",
                "--trusted-key",
                "b.pub"
            ]),
            Ok(Command::AuditVerify {
                config: cfg("s", None, false),
                trusted_keys: vec!["a.pub".into(), "b.pub".into()],
                max_unsigned_records: None,
                max_checkpoint_age: None,
            })
        );
        assert_eq!(
            p(&[
                "audit",
                "verify",
                "--config",
                "s",
                "--trusted-key",
                "a.pub",
                "--max-unsigned-records",
                "500"
            ]),
            Ok(Command::AuditVerify {
                config: cfg("s", None, false),
                trusted_keys: vec!["a.pub".into()],
                max_unsigned_records: Some(500),
                max_checkpoint_age: None,
            })
        );
        for bad in ["", "-1", "1e3", "99999999999999999999"] {
            assert_eq!(
                p(&[
                    "audit",
                    "verify",
                    "--config",
                    "s",
                    "--trusted-key",
                    "a.pub",
                    "--max-unsigned-records",
                    bad
                ]),
                Err(UsageError::BadValue("--max-unsigned-records")),
                "{bad}"
            );
        }
        // SEC-013: --max-checkpoint-age.
        for (arg, secs) in [("90", 90), ("30m", 1800), ("2h", 7200), ("1d", 86_400)] {
            assert_eq!(
                p(&[
                    "audit",
                    "verify",
                    "--config",
                    "s",
                    "--trusted-key",
                    "a.pub",
                    "--max-checkpoint-age",
                    arg
                ]),
                Ok(Command::AuditVerify {
                    config: cfg("s", None, false),
                    trusted_keys: vec!["a.pub".into()],
                    max_unsigned_records: None,
                    max_checkpoint_age: Some(std::time::Duration::from_secs(secs)),
                }),
                "{arg}"
            );
        }
        for bad in [
            "",
            "0",
            "0s",
            "m",
            "-5m",
            "5w",
            "1.5h",
            "367d",
            "9999999999s",
        ] {
            assert_eq!(
                p(&[
                    "audit",
                    "verify",
                    "--config",
                    "s",
                    "--trusted-key",
                    "a.pub",
                    "--max-checkpoint-age",
                    bad
                ]),
                Err(UsageError::BadValue("--max-checkpoint-age")),
                "{bad}"
            );
        }
        assert_eq!(
            p(&["audit", "verify", "--config", "s"]),
            Err(UsageError::Required("--trusted-key"))
        );
        assert_eq!(p(&["audit", "export"]), Err(UsageError::Unexpected));
        let mut many = vec!["audit", "verify", "--config", "s"];
        for _ in 0..=MAX_TRUSTED_KEYS {
            many.extend(["--trusted-key", "k"]);
        }
        assert_eq!(p(&many), Err(UsageError::TooManyKeys));
    }

    #[test]
    fn boot_service_args() {
        assert_eq!(
            p(&[
                "boot-service",
                "enrol",
                "--config",
                "s",
                "--cert",
                "r.pem",
                "--name",
                "Relay A",
                "--subnet",
                "10.20.0.0/16",
                "--subnet",
                "192.0.2.0/24",
                "--admin-uid",
                "9"
            ]),
            Ok(Command::BootServiceEnrol {
                config: cfg("s", Some(9), false),
                cert: "r.pem".into(),
                name: "Relay A".into(),
                subnets: vec!["10.20.0.0/16".into(), "192.0.2.0/24".into()],
            })
        );
        assert_eq!(
            p(&[
                "boot-service",
                "enrol",
                "--config",
                "s",
                "--cert",
                "r.pem",
                "--name",
                "n"
            ]),
            Err(UsageError::Required("--subnet"))
        );
        assert_eq!(
            p(&[
                "boot-service",
                "enrol",
                "--config",
                "s",
                "--cert",
                "r.pem",
                "--name",
                "n",
                "--subnet",
                ""
            ]),
            Err(UsageError::EmptyValue("--subnet"))
        );
        let mut many = vec![
            "boot-service",
            "enrol",
            "--config",
            "s",
            "--cert",
            "c",
            "--name",
            "n",
        ];
        for _ in 0..=MAX_SUBNETS {
            many.extend(["--subnet", "10.0.0.0/8"]);
        }
        assert_eq!(p(&many), Err(UsageError::TooManySubnets));
        assert_eq!(
            p(&["boot-service", "disable", "--config", "s", "--id", "x"]),
            Ok(Command::BootServiceDisable {
                config: cfg("s", None, false),
                id: "x".into(),
            })
        );
        assert_eq!(
            p(&["boot-service", "list", "--config", "s"]),
            Err(UsageError::Unexpected)
        );
        assert_eq!(
            p(&["boot-stop", "clear", "--config", "s", "--id", "y"]),
            Err(UsageError::Unexpected)
        );
    }

    #[test]
    fn migrate_args() {
        assert_eq!(
            p(&[
                "migrate",
                "--config",
                "s",
                "--owner-user",
                "usgp_owner",
                "--owner-cert",
                "o.pem",
                "--owner-key",
                "o.key"
            ]),
            Ok(Command::Migrate {
                config: cfg("s", None, false),
                owner_user: "usgp_owner".into(),
                owner_cert: "o.pem".into(),
                owner_key: "o.key".into(),
            })
        );
        assert_eq!(
            p(&["migrate", "--config", "s"]),
            Err(UsageError::Required("--owner-user"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_option_refused_but_path_kept() {
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![0xff]);
        assert_eq!(parse([bad.clone()]), Err(UsageError::Unexpected));
        assert_eq!(
            parse([
                OsString::from("serve"),
                OsString::from("--config"),
                bad.clone()
            ]),
            Ok(Command::Serve(ConfigArgs {
                path: PathBuf::from(bad),
                admin_uid: None,
                allow_shared_admin_uid: false,
            }))
        );
    }
}
