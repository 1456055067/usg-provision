//! Command-line parsing (std only, no parser crate; plan WU-7, WU-8).
//!
//! Grammar (M1 plan section 3.6; M2 plan WU-8):
//!
//! ```text
//! usgp-cli [-h | --help]
//! usgp-cli boot-manifest create --root DIR --out FILE [--] NAME...
//! usgp-cli boot-manifest verify --root DIR --manifest FILE
//! usgp-cli limits
//! usgp-cli image upload FILE --name NAME
//! usgp-cli image list | view ID | delete ID [--yes]
//! usgp-cli image declare ID --index N --release R --edition E --arch A
//! usgp-cli image download ID --out FILE
//! usgp-cli pe import FILE --name NAME --arch A --kit-version V
//! usgp-cli pe list | view ID | delete ID [--yes] | download ID --out FILE
//! usgp-cli package create --name N [--description D] --image ID --index N --pe ID
//! usgp-cli package edit ID [--name N] [--description D] [--image ID] [--index N] [--pe ID]
//! usgp-cli package list | view ID | clone ID --name N | delete ID [--yes]
//! usgp-cli package manifest ID --out FILE
//! ```
//!
//! M3 (plan WU-13):
//!
//! ```text
//! usgp-cli boot-manifest create --pe-kit --root DIR --out FILE --pe ID
//!          --boot-program NAME --bcd NAME --sdi NAME --wim NAME
//!          [--font NAME]... [CONN] [--] [NAME...]
//! usgp-cli code issue [--ttl SECONDS] [--note TEXT] | list | revoke ID
//! usgp-cli session list [--state S] | show ID
//! usgp-cli session approve --display-code CODE [ID] | refuse ID [--note TEXT]
//! usgp-cli job list [--state S] | show ID | ack ID
//! usgp-cli boot-service list | show ID
//! usgp-cli boot-service set-packages ID (PACKAGE_ID... | --none) [--if-match TAG]
//! usgp-cli boot-stop list | clear ID
//! ```
//!
//! `--font` is the only option that may be repeated. With `--pe-kit`,
//! `boot-manifest create` takes the connection options too, since it reads
//! the PE's record from the server.
//!
//! Every M2 command also takes the connection options `--config FILE`,
//! `--server URL`, `--server-ca FILE`, `--client-cert FILE`,
//! `--client-key FILE` and `--content-key-pub FILE` (see
//! [`crate::config`]).
//!
//! Options take their value as the next argument. Each option may appear
//! once, in any order, before `--`. Every argument after `--` is a name, so
//! names that start with `-` can be given. Any other shape is a usage error
//! (exit 2). Names are not validated here; [`crate::boot_manifest`] refuses
//! invalid names as a failure (exit 1), so the refusal is audited.
//!
//! For M2 commands, shape errors (unknown or repeated option, missing
//! value or argument, a non-numeric `--index`, text that is not UTF-8)
//! are usage errors (exit 2). Value rules (names, ids, closed value sets)
//! are checked by the command against the `usgp-proto` types before
//! anything is sent (exit 1).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - operator input is
//   checked for shape before any file is touched; anything unexpected is
//   refused, never guessed.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use crate::cmd_image::Declare;
use crate::cmd_package::Definition;

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
    /// `boot-manifest create --pe-kit`.
    CreateKit(Box<KitCreateArgs>),
    /// `pe agent-config` (local; no server connection).
    AgentConfig(Box<AgentConfigArgs>),
    /// An M2 command that talks to the server.
    Api(Box<ApiCommand>),
}

/// Connection options of the M2 commands (see [`crate::config`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConnArgs {
    /// `--config FILE`.
    pub config: Option<PathBuf>,
    /// `--server URL`.
    pub server: Option<String>,
    /// `--server-ca FILE`.
    pub server_ca: Option<PathBuf>,
    /// `--client-cert FILE`.
    pub client_cert: Option<PathBuf>,
    /// `--client-key FILE`.
    pub client_key: Option<PathBuf>,
    /// `--content-key-pub FILE`.
    pub content_key_pub: Option<PathBuf>,
}

/// An M2 command with its connection options.
#[derive(Debug, PartialEq, Eq)]
pub struct ApiCommand {
    /// Connection options.
    pub conn: ConnArgs,
    /// What to do.
    pub action: Action,
}

/// What an M2 command does. Ids and names are unvalidated text here.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// `limits`.
    Limits,
    /// `image upload FILE --name N`.
    ImageUpload {
        /// The file.
        file: PathBuf,
        /// Display name.
        name: String,
    },
    /// `image list`.
    ImageList,
    /// `image view ID`.
    ImageView(String),
    /// `image declare ID ...`.
    ImageDeclare(String, Declare),
    /// `image delete ID [--yes]`.
    ImageDelete(String, bool),
    /// `image download ID --out FILE`.
    ImageDownload(String, PathBuf),
    /// `pe import FILE --name N --arch A --kit-version V`.
    PeImport {
        /// The file.
        file: PathBuf,
        /// Display name.
        name: String,
        /// Declared architecture.
        arch: String,
        /// Declared kit version.
        kit_version: String,
    },
    /// `pe list`.
    PeList,
    /// `pe view ID`.
    PeView(String),
    /// `pe delete ID [--yes]`.
    PeDelete(String, bool),
    /// `pe download ID --out FILE`.
    PeDownload(String, PathBuf),
    /// `package create ...`.
    PackageCreate(Definition),
    /// `package list`.
    PackageList,
    /// `package view ID`.
    PackageView(String),
    /// `package edit ID ...`.
    PackageEdit(String, Definition),
    /// `package clone ID --name N`.
    PackageClone(String, String),
    /// `package delete ID [--yes]`.
    PackageDelete(String, bool),
    /// `package manifest ID --out FILE`.
    PackageManifest(String, PathBuf),
    /// `code issue [--ttl S] [--note T]`.
    CodeIssue {
        /// Lifetime in seconds; the server default if absent.
        ttl_s: Option<u64>,
        /// Operator note.
        note: Option<String>,
    },
    /// `code list`.
    CodeList,
    /// `code revoke ID`.
    CodeRevoke(String),
    /// `session list [--state S]`.
    SessionList(Option<String>),
    /// `session show ID`.
    SessionShow(String),
    /// `session approve --display-code CODE [ID]`.
    SessionApprove {
        /// The session; found by its display code among the waiting
        /// sessions if absent.
        id: Option<String>,
        /// The display code read from the device's screen.
        display_code: String,
    },
    /// `session refuse ID [--note T]`.
    SessionRefuse {
        /// The session.
        id: String,
        /// Operator note.
        note: Option<String>,
    },
    /// `job list [--state S]`.
    JobList(Option<String>),
    /// `job show ID`.
    JobShow(String),
    /// `job ack ID`.
    JobAck(String),
    /// `boot-service list`.
    BootServiceList,
    /// `boot-service show ID`.
    BootServiceShow(String),
    /// `boot-service set-packages ID (PACKAGE_ID... | --none) [--if-match TAG]`.
    BootServiceSetPackages {
        /// The boot service.
        id: String,
        /// The complete new list (empty with `--none`).
        packages: Vec<String>,
        /// The assignment tag the operator reviewed; read just before the
        /// change if absent.
        if_match: Option<String>,
    },
    /// `boot-stop list`.
    BootStopList,
    /// `boot-stop clear ID`.
    BootStopClear(String),
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

/// Arguments of `boot-manifest create --pe-kit`.
#[derive(Debug, PartialEq, Eq)]
pub struct KitCreateArgs {
    /// Root, output and any further published names (may be empty).
    pub create: CreateArgs,
    /// `--boot-program NAME`.
    pub boot_program: OsString,
    /// `--bcd NAME` (the operator-built store; never generated).
    pub bcd: OsString,
    /// `--sdi NAME`.
    pub sdi: OsString,
    /// `--wim NAME`.
    pub wim: OsString,
    /// `--font NAME`, in order.
    pub fonts: Vec<OsString>,
    /// `--pe ID`: the imported PE the WIM must be.
    pub pe: String,
    /// Connection options.
    pub conn: ConnArgs,
}

/// Arguments of `pe agent-config`. Values are checked by
/// [`crate::cmd_agent_config::create`], so a refusal is audited.
#[derive(Debug, PartialEq, Eq)]
pub struct AgentConfigArgs {
    /// `--out DIR`: the directory to create.
    pub out: PathBuf,
    /// `--server-url URL`: the device listener, `https://HOST[:PORT]`.
    pub server_url: String,
    /// `--server-name NAME`.
    pub server_name: Option<String>,
    /// `--trust-anchors FILE`.
    pub trust_anchors: PathBuf,
    /// `--plan-key-pub FILE`.
    pub plan_key_pub: PathBuf,
    /// `--content-key-pub FILE`.
    pub content_key_pub: PathBuf,
    /// `--network-wait-s N`.
    pub network_wait_s: Option<u64>,
    /// `--connect-timeout-s N`.
    pub connect_timeout_s: Option<u64>,
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
    if [
        "limits",
        "image",
        "pe",
        "package",
        "code",
        "session",
        "job",
        "boot-service",
        "boot-stop",
    ]
    .iter()
    .any(|g| first == *g)
    {
        let rest: Vec<OsString> = it.collect();
        if first == "pe" && rest.first().is_some_and(|a| a == "agent-config") {
            return parse_agent_config(rest.into_iter().skip(1).collect());
        }
        return parse_api(&first, rest);
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
    let kit = rest
        .iter()
        .take_while(|a| a.as_os_str() != "--")
        .any(|a| a == "--pe-kit");
    if sub == "create" && kit {
        parse_create_kit(rest)
    } else if sub == "create" {
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

/// `boot-manifest create --pe-kit ...` (M3 plan WU-13). Shape only; names
/// and the PE id are checked by [`crate::boot_manifest::create_kit`], so a
/// refusal is audited.
fn parse_create_kit(rest: Vec<OsString>) -> Result<Command, UsageError> {
    let mut s = scan_m2(
        rest,
        &[
            "--root",
            "--out",
            "--pe",
            "--boot-program",
            "--bcd",
            "--sdi",
            "--wim",
        ],
        &["--pe-kit"],
        &["--font"],
    )?;
    if s.help {
        return Ok(Command::Help);
    }
    let conn = s.conn()?;
    let mut need = |opt: &str| {
        s.values
            .remove(opt)
            .ok_or_else(|| UsageError(format!("{opt} is required with --pe-kit")))
    };
    let root = PathBuf::from(need("--root")?);
    let out = PathBuf::from(need("--out")?);
    let boot_program = need("--boot-program")?;
    let bcd = need("--bcd")?;
    let sdi = need("--sdi")?;
    let wim = need("--wim")?;
    let pe = s.required("--pe")?;
    let fonts = s.multi.remove("--font").unwrap_or_default();
    Ok(Command::CreateKit(Box::new(KitCreateArgs {
        create: CreateArgs {
            root,
            out,
            names: std::mem::take(&mut s.positional),
        },
        boot_program,
        bcd,
        sdi,
        wim,
        fonts,
        pe,
        conn,
    })))
}

/// `pe agent-config ...` (M3 plan WU-13). Shape only. Of the connection
/// options only `--content-key-pub` is taken (the content key the agent
/// pins); the others are refused, as no server is contacted.
fn parse_agent_config(rest: Vec<OsString>) -> Result<Command, UsageError> {
    let mut s = scan_m2(
        rest,
        &[
            "--out",
            "--server-url",
            "--server-name",
            "--trust-anchors",
            "--plan-key-pub",
            "--network-wait-s",
            "--connect-timeout-s",
        ],
        &[],
        &[],
    )?;
    if s.help {
        return Ok(Command::Help);
    }
    if let Some(opt) = [
        "--config",
        "--server",
        "--server-ca",
        "--client-cert",
        "--client-key",
    ]
    .into_iter()
    .find(|o| s.values.contains_key(o))
    {
        return Err(UsageError(format!(
            "{opt} is not used by pe agent-config (no server is contacted)"
        )));
    }
    if let Some(extra) = s.positional.first() {
        return Err(UsageError(format!("unexpected argument {extra:?}")));
    }
    let mut path = |opt: &str| {
        s.path(opt)
            .ok_or_else(|| UsageError(format!("{opt} is required")))
    };
    let out = path("--out")?;
    let trust_anchors = path("--trust-anchors")?;
    let plan_key_pub = path("--plan-key-pub")?;
    let content_key_pub = path("--content-key-pub")?;
    Ok(Command::AgentConfig(Box::new(AgentConfigArgs {
        out,
        server_url: s.required("--server-url")?,
        server_name: s.text("--server-name")?,
        trust_anchors,
        plan_key_pub,
        content_key_pub,
        network_wait_s: s.number("--network-wait-s")?,
        connect_timeout_s: s.number("--connect-timeout-s")?,
    })))
}

// ---------------------------------------------------------------------------
// M2 commands (plan WU-8)
// ---------------------------------------------------------------------------

/// Connection options accepted by every M2 command.
const CONN_OPTS: &[&str] = &[
    "--config",
    "--server",
    "--server-ca",
    "--client-cert",
    "--client-key",
    "--content-key-pub",
];

/// Options and positional arguments of one M2 command.
#[derive(Default)]
struct Scanned {
    values: BTreeMap<&'static str, OsString>,
    flags: BTreeSet<&'static str>,
    multi: BTreeMap<&'static str, Vec<OsString>>,
    positional: Vec<OsString>,
    help: bool,
}

/// Splits `rest` into value options (`values` plus [`CONN_OPTS`]), flag
/// options (`flags`), repeatable value options (`multi`) and positional
/// arguments.
fn scan_m2(
    rest: Vec<OsString>,
    values: &[&'static str],
    flags: &[&'static str],
    multi: &[&'static str],
) -> Result<Scanned, UsageError> {
    let mut s = Scanned::default();
    let mut it = rest.into_iter();
    while let Some(a) = it.next() {
        if a == "--" {
            s.positional.extend(it);
            break;
        }
        if is_help(&a) {
            s.help = true;
            continue;
        }
        let Some(text) = a.to_str().filter(|t| t.starts_with('-')) else {
            s.positional.push(a);
            continue;
        };
        if let Some(&f) = flags.iter().find(|f| **f == text) {
            if !s.flags.insert(f) {
                return Err(UsageError(format!("{f} given more than once")));
            }
            continue;
        }
        if let Some(&m) = multi.iter().find(|m| **m == text) {
            let Some(value) = it.next().filter(|v| !v.is_empty()) else {
                return Err(UsageError(format!("{m} needs a value")));
            };
            s.multi.entry(m).or_default().push(value);
            continue;
        }
        let Some(&opt) = values.iter().chain(CONN_OPTS).find(|o| **o == text) else {
            return Err(UsageError(format!("unknown option {text:?}")));
        };
        let Some(value) = it.next() else {
            return Err(UsageError(format!("{opt} needs a value")));
        };
        if value.is_empty() {
            return Err(UsageError(format!("{opt} value is empty")));
        }
        if s.values.insert(opt, value).is_some() {
            return Err(UsageError(format!("{opt} given more than once")));
        }
    }
    Ok(s)
}

impl Scanned {
    fn path(&mut self, opt: &str) -> Option<PathBuf> {
        self.values.remove(opt).map(PathBuf::from)
    }

    fn text(&mut self, opt: &str) -> Result<Option<String>, UsageError> {
        self.values
            .remove(opt)
            .map(|v| {
                v.into_string()
                    .map_err(|_| UsageError(format!("{opt} value is not valid UTF-8")))
            })
            .transpose()
    }

    fn required(&mut self, opt: &str) -> Result<String, UsageError> {
        self.text(opt)?
            .ok_or_else(|| UsageError(format!("{opt} is required")))
    }

    fn number(&mut self, opt: &str) -> Result<Option<u64>, UsageError> {
        self.text(opt)?
            .map(|t| {
                if t.is_empty() || t.len() > 20 || !t.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(UsageError(format!("{opt} must be a decimal number")));
                }
                t.parse()
                    .map_err(|_| UsageError(format!("{opt} must be a decimal number")))
            })
            .transpose()
    }

    /// Exactly `names.len()` positional arguments.
    fn positional(&mut self, names: &[&str]) -> Result<Vec<OsString>, UsageError> {
        let got = std::mem::take(&mut self.positional);
        if got.len() < names.len() {
            let missing = names.get(got.len()).copied().unwrap_or("argument");
            return Err(UsageError(format!("{missing} is required")));
        }
        if let Some(extra) = got.get(names.len()) {
            return Err(UsageError(format!("unexpected argument {extra:?}")));
        }
        Ok(got)
    }

    fn id(&mut self) -> Result<String, UsageError> {
        let mut p = self.positional(&["ID"])?.into_iter();
        p.next()
            .unwrap_or_default()
            .into_string()
            .map_err(|_| UsageError("ID is not valid UTF-8".into()))
    }

    fn file(&mut self) -> Result<PathBuf, UsageError> {
        let mut p = self.positional(&["FILE"])?.into_iter();
        Ok(PathBuf::from(p.next().unwrap_or_default()))
    }

    fn conn(&mut self) -> Result<ConnArgs, UsageError> {
        Ok(ConnArgs {
            config: self.path("--config"),
            server: self.text("--server")?,
            server_ca: self.path("--server-ca"),
            client_cert: self.path("--client-cert"),
            client_key: self.path("--client-key"),
            content_key_pub: self.path("--content-key-pub"),
        })
    }
}

/// The value and flag options of each M2 subcommand.
fn options(group: &str, sub: &str) -> Option<(&'static [&'static str], &'static [&'static str])> {
    const NONE: &[&str] = &[];
    const DEF: &[&str] = &["--name", "--description", "--image", "--index", "--pe"];
    Some(match (group, sub) {
        ("limits", "")
        | ("image" | "pe" | "package", "list")
        | ("image" | "pe" | "package", "view") => (NONE, NONE),
        ("image" | "pe" | "package", "delete") => (NONE, &["--yes"]),
        ("image" | "pe", "download") | ("package", "manifest") => (&["--out"], NONE),
        ("image", "upload") => (&["--name"], NONE),
        ("image", "declare") => (&["--index", "--release", "--edition", "--arch"], NONE),
        ("pe", "import") => (&["--name", "--arch", "--kit-version"], NONE),
        ("package", "create" | "edit") => (DEF, NONE),
        ("package", "clone") => (&["--name"], NONE),
        ("code", "issue") => (&["--ttl", "--note"], NONE),
        ("code" | "boot-service" | "boot-stop", "list")
        | ("code", "revoke")
        | ("session" | "job" | "boot-service", "show")
        | ("job", "ack")
        | ("boot-stop", "clear") => (NONE, NONE),
        ("session" | "job", "list") => (&["--state"], NONE),
        ("session", "approve") => (&["--display-code"], NONE),
        ("session", "refuse") => (&["--note"], NONE),
        ("boot-service", "set-packages") => (&["--if-match"], &["--none"]),
        _ => return None,
    })
}

fn definition(s: &mut Scanned) -> Result<Definition, UsageError> {
    Ok(Definition {
        name: s.text("--name")?,
        description: s.text("--description")?,
        image: s.text("--image")?,
        index: s.number("--index")?,
        pe: s.text("--pe")?,
    })
}

fn parse_api(group: &OsStr, rest: Vec<OsString>) -> Result<Command, UsageError> {
    let group = group.to_str().unwrap_or_default();
    let mut rest = rest.into_iter();
    let sub = if group == "limits" {
        OsString::new()
    } else {
        match rest.next() {
            None => return Err(UsageError(format!("{group} needs a subcommand"))),
            Some(s) if is_help(&s) => return Ok(Command::Help),
            Some(s) => s,
        }
    };
    let sub_text = sub.to_str().unwrap_or("\u{fffd}");
    let Some((values, flags)) = options(group, sub_text) else {
        return Err(UsageError(format!("unknown {group} command {sub:?}")));
    };
    let mut s = scan_m2(rest.collect(), values, flags, &[])?;
    if s.help {
        return Ok(Command::Help);
    }
    let conn = s.conn()?;
    let yes = s.flags.contains("--yes");
    let out = |s: &mut Scanned| {
        s.path("--out")
            .ok_or_else(|| UsageError("--out is required".into()))
    };
    let action = match (group, sub_text) {
        ("limits", _) => {
            s.positional(&[])?;
            Action::Limits
        }
        ("image", "upload") => Action::ImageUpload {
            file: s.file()?,
            name: s.required("--name")?,
        },
        ("image", "list") => {
            s.positional(&[])?;
            Action::ImageList
        }
        ("image", "view") => Action::ImageView(s.id()?),
        ("image", "declare") => {
            let id = s.id()?;
            let index = s
                .number("--index")?
                .ok_or_else(|| UsageError("--index is required".into()))?;
            Action::ImageDeclare(
                id,
                Declare {
                    index,
                    release: s.required("--release")?,
                    edition: s.required("--edition")?,
                    architecture: s.required("--arch")?,
                },
            )
        }
        ("image", "delete") => Action::ImageDelete(s.id()?, yes),
        ("image", "download") => Action::ImageDownload(s.id()?, out(&mut s)?),
        ("pe", "import") => Action::PeImport {
            file: s.file()?,
            name: s.required("--name")?,
            arch: s.required("--arch")?,
            kit_version: s.required("--kit-version")?,
        },
        ("pe", "list") => {
            s.positional(&[])?;
            Action::PeList
        }
        ("pe", "view") => Action::PeView(s.id()?),
        ("pe", "delete") => Action::PeDelete(s.id()?, yes),
        ("pe", "download") => Action::PeDownload(s.id()?, out(&mut s)?),
        ("package", "create") => {
            s.positional(&[])?;
            let d = definition(&mut s)?;
            for (v, flag) in [
                (d.name.is_none(), "--name"),
                (d.image.is_none(), "--image"),
                (d.index.is_none(), "--index"),
                (d.pe.is_none(), "--pe"),
            ] {
                if v {
                    return Err(UsageError(format!("{flag} is required")));
                }
            }
            Action::PackageCreate(d)
        }
        ("package", "list") => {
            s.positional(&[])?;
            Action::PackageList
        }
        ("package", "view") => Action::PackageView(s.id()?),
        ("package", "edit") => {
            let id = s.id()?;
            Action::PackageEdit(id, definition(&mut s)?)
        }
        ("package", "clone") => Action::PackageClone(s.id()?, s.required("--name")?),
        ("package", "delete") => Action::PackageDelete(s.id()?, yes),
        ("package", "manifest") => Action::PackageManifest(s.id()?, out(&mut s)?),
        ("code", "issue") => {
            s.positional(&[])?;
            Action::CodeIssue {
                ttl_s: s.number("--ttl")?,
                note: s.text("--note")?,
            }
        }
        ("code", "list") => {
            s.positional(&[])?;
            Action::CodeList
        }
        ("code", "revoke") => Action::CodeRevoke(s.id()?),
        ("session", "list") => {
            s.positional(&[])?;
            Action::SessionList(s.text("--state")?)
        }
        ("session", "show") => Action::SessionShow(s.id()?),
        ("session", "approve") => {
            let id = match s.positional.len() {
                0 => None,
                _ => Some(s.id()?),
            };
            Action::SessionApprove {
                id,
                display_code: s.required("--display-code")?,
            }
        }
        ("session", "refuse") => Action::SessionRefuse {
            id: s.id()?,
            note: s.text("--note")?,
        },
        ("job", "list") => {
            s.positional(&[])?;
            Action::JobList(s.text("--state")?)
        }
        ("job", "show") => Action::JobShow(s.id()?),
        ("job", "ack") => Action::JobAck(s.id()?),
        ("boot-service", "list") => {
            s.positional(&[])?;
            Action::BootServiceList
        }
        ("boot-service", "show") => Action::BootServiceShow(s.id()?),
        ("boot-service", "set-packages") => {
            let mut ids = std::mem::take(&mut s.positional).into_iter().map(|a| {
                a.into_string()
                    .map_err(|_| UsageError("ID is not valid UTF-8".into()))
            });
            let id = ids
                .next()
                .ok_or_else(|| UsageError("ID is required".into()))??;
            let packages: Vec<String> = ids.collect::<Result<_, _>>()?;
            let none = s.flags.contains("--none");
            if none && !packages.is_empty() {
                return Err(UsageError(
                    "--none removes every package; do not list packages with it".into(),
                ));
            }
            if !none && packages.is_empty() {
                return Err(UsageError(
                    "give the complete package list, or --none to remove every package".into(),
                ));
            }
            Action::BootServiceSetPackages {
                id,
                packages,
                if_match: s.text("--if-match")?,
            }
        }
        ("boot-stop", "list") => {
            s.positional(&[])?;
            Action::BootStopList
        }
        ("boot-stop", "clear") => Action::BootStopClear(s.id()?),
        _ => return Err(UsageError(format!("unknown {group} command {sub:?}"))),
    };
    Ok(Command::Api(Box::new(ApiCommand { conn, action })))
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

    fn api(args: &[&str]) -> ApiCommand {
        match p(args) {
            Ok(Command::Api(c)) => *c,
            other => panic!("{args:?}: {other:?}"),
        }
    }

    const ID: &str = "0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f";

    #[test]
    fn m2_commands_parse() {
        assert_eq!(api(&["limits"]).action, Action::Limits);
        assert_eq!(
            api(&["image", "upload", "my image.wim", "--name", "Win 11"]).action,
            Action::ImageUpload {
                file: "my image.wim".into(),
                name: "Win 11".into()
            }
        );
        assert_eq!(api(&["image", "list"]).action, Action::ImageList);
        assert_eq!(
            api(&["image", "view", ID]).action,
            Action::ImageView(ID.into())
        );
        assert_eq!(
            api(&[
                "image",
                "declare",
                ID,
                "--index",
                "1",
                "--release",
                "windows-11",
                "--edition",
                "enterprise",
                "--arch",
                "x64"
            ])
            .action,
            Action::ImageDeclare(
                ID.into(),
                Declare {
                    index: 1,
                    release: "windows-11".into(),
                    edition: "enterprise".into(),
                    architecture: "x64".into()
                }
            )
        );
        assert_eq!(
            api(&["image", "delete", ID]).action,
            Action::ImageDelete(ID.into(), false)
        );
        assert_eq!(
            api(&["pe", "delete", "--yes", ID]).action,
            Action::PeDelete(ID.into(), true)
        );
        assert_eq!(
            api(&["pe", "download", ID, "--out", "/o"]).action,
            Action::PeDownload(ID.into(), "/o".into())
        );
        assert_eq!(
            api(&[
                "pe",
                "import",
                "boot.wim",
                "--name",
                "PE",
                "--arch",
                "x64",
                "--kit-version",
                "10.1.26100.1"
            ])
            .action,
            Action::PeImport {
                file: "boot.wim".into(),
                name: "PE".into(),
                arch: "x64".into(),
                kit_version: "10.1.26100.1".into()
            }
        );
        assert_eq!(
            api(&[
                "package", "create", "--name", "L", "--image", ID, "--index", "2", "--pe", ID
            ])
            .action,
            Action::PackageCreate(Definition {
                name: Some("L".into()),
                description: None,
                image: Some(ID.into()),
                index: Some(2),
                pe: Some(ID.into()),
            })
        );
        assert_eq!(
            api(&["package", "edit", ID, "--pe", ID]).action,
            Action::PackageEdit(
                ID.into(),
                Definition {
                    pe: Some(ID.into()),
                    ..Definition::default()
                }
            )
        );
        assert_eq!(
            api(&["package", "clone", ID, "--name", "copy"]).action,
            Action::PackageClone(ID.into(), "copy".into())
        );
        assert_eq!(
            api(&["package", "manifest", ID, "--out", "/m.json"]).action,
            Action::PackageManifest(ID.into(), "/m.json".into())
        );
    }

    #[test]
    fn m2_connection_options() {
        let c = api(&[
            "image",
            "list",
            "--server",
            "https://ctl:8443",
            "--server-ca",
            "/ca.pem",
            "--client-cert",
            "/c.pem",
            "--client-key",
            "/c.key",
            "--content-key-pub",
            "/k.pub",
            "--config",
            "/cfg.toml",
        ]);
        assert_eq!(
            c.conn,
            ConnArgs {
                config: Some("/cfg.toml".into()),
                server: Some("https://ctl:8443".into()),
                server_ca: Some("/ca.pem".into()),
                client_cert: Some("/c.pem".into()),
                client_key: Some("/c.key".into()),
                content_key_pub: Some("/k.pub".into()),
            }
        );
    }

    #[test]
    fn m2_help() {
        for args in [
            &["image", "--help"][..],
            &["pe", "-h"],
            &["package", "create", "--help"],
            &["limits", "-h"],
        ] {
            assert_eq!(p(args), Ok(Command::Help), "{args:?}");
        }
    }

    #[test]
    fn m2_usage_errors() {
        let bad: &[&[&str]] = &[
            &["image"],
            &["image", "frob"],
            &["limits", "extra"],
            &["image", "list", "extra"],
            &["image", "view"],
            &["image", "view", ID, ID],
            &["image", "upload", "f.wim"],
            &["image", "upload", "--name", "n"],
            &[
                "image",
                "declare",
                ID,
                "--index",
                "x",
                "--release",
                "r",
                "--edition",
                "e",
                "--arch",
                "a",
            ],
            &[
                "image",
                "declare",
                ID,
                "--index",
                "-1",
                "--release",
                "r",
                "--edition",
                "e",
                "--arch",
                "a",
            ],
            &[
                "image",
                "declare",
                ID,
                "--release",
                "r",
                "--edition",
                "e",
                "--arch",
                "a",
            ],
            &[
                "image",
                "declare",
                ID,
                "--index",
                "1",
                "--edition",
                "e",
                "--arch",
                "a",
            ],
            &["image", "delete", ID, "--yes", "--yes"],
            &["image", "download", ID],
            &["pe", "import", "f", "--name", "n", "--arch", "x64"],
            &["pe", "import", "f", "--name", "n", "--kit-version", "10.1"],
            &["pe", "declare", ID],
            &[
                "package", "create", "--name", "n", "--image", ID, "--index", "1",
            ],
            &[
                "package", "create", ID, "--name", "n", "--image", ID, "--index", "1", "--pe", ID,
            ],
            &["package", "clone", ID],
            &["package", "manifest", ID],
            &["package", "view", ID, "--out", "/x"],
            &["package", "list", "--server"],
            &["package", "list", "--server", ""],
            &["package", "list", "--server", "a", "--server", "b"],
            &["package", "list", "--yes"],
            &["package", "edit", ID, "--description", ""],
        ];
        for args in bad {
            assert!(p(args).is_err(), "{args:?} should be a usage error");
        }
    }

    #[test]
    fn m3_commands_parse() {
        assert_eq!(
            api(&["code", "issue"]).action,
            Action::CodeIssue {
                ttl_s: None,
                note: None
            }
        );
        assert_eq!(
            api(&["code", "issue", "--ttl", "600", "--note", "bench 4"]).action,
            Action::CodeIssue {
                ttl_s: Some(600),
                note: Some("bench 4".into())
            }
        );
        assert_eq!(api(&["code", "list"]).action, Action::CodeList);
        assert_eq!(
            api(&["code", "revoke", ID]).action,
            Action::CodeRevoke(ID.into())
        );
        assert_eq!(api(&["session", "list"]).action, Action::SessionList(None));
        assert_eq!(
            api(&["session", "list", "--state", "authorised"]).action,
            Action::SessionList(Some("authorised".into()))
        );
        assert_eq!(
            api(&["session", "show", ID]).action,
            Action::SessionShow(ID.into())
        );
        assert_eq!(
            api(&["session", "approve", "--display-code", "ABC-123"]).action,
            Action::SessionApprove {
                id: None,
                display_code: "ABC-123".into()
            }
        );
        assert_eq!(
            api(&["session", "approve", ID, "--display-code", "abc123"]).action,
            Action::SessionApprove {
                id: Some(ID.into()),
                display_code: "abc123".into()
            }
        );
        assert_eq!(
            api(&["session", "refuse", ID, "--note", "not ours"]).action,
            Action::SessionRefuse {
                id: ID.into(),
                note: Some("not ours".into())
            }
        );
        assert_eq!(api(&["job", "list"]).action, Action::JobList(None));
        assert_eq!(
            api(&["job", "list", "--state", "failed"]).action,
            Action::JobList(Some("failed".into()))
        );
        assert_eq!(api(&["job", "show", ID]).action, Action::JobShow(ID.into()));
        assert_eq!(api(&["job", "ack", ID]).action, Action::JobAck(ID.into()));
        assert_eq!(
            api(&["boot-service", "list"]).action,
            Action::BootServiceList
        );
        assert_eq!(
            api(&["boot-service", "show", ID]).action,
            Action::BootServiceShow(ID.into())
        );
        assert_eq!(
            api(&["boot-service", "set-packages", ID, "p1", "p2"]).action,
            Action::BootServiceSetPackages {
                id: ID.into(),
                packages: vec!["p1".into(), "p2".into()],
                if_match: None
            }
        );
        assert_eq!(
            api(&[
                "boot-service",
                "set-packages",
                ID,
                "--none",
                "--if-match",
                "\"bsp-1\""
            ])
            .action,
            Action::BootServiceSetPackages {
                id: ID.into(),
                packages: Vec::new(),
                if_match: Some("\"bsp-1\"".into())
            }
        );
        assert_eq!(api(&["boot-stop", "list"]).action, Action::BootStopList);
        assert_eq!(
            api(&["boot-stop", "clear", ID]).action,
            Action::BootStopClear(ID.into())
        );
    }

    #[test]
    fn m3_usage_errors() {
        let bad: &[&[&str]] = &[
            &["code"],
            &["code", "show", ID],
            &["code", "issue", "extra"],
            &["code", "issue", "--ttl", "ten"],
            &["code", "issue", "--ttl", "-1"],
            &["code", "issue", "--note"],
            &["code", "issue", "--ttl", "1", "--ttl", "2"],
            &["code", "revoke"],
            &["code", "list", "--state", "x"],
            &["session", "approve"],
            &["session", "approve", ID],
            &["session", "approve", ID, ID, "--display-code", "ABC-123"],
            &["session", "refuse"],
            &["session", "list", "extra"],
            &[
                "session",
                "approve",
                "--display-code",
                "A",
                "--display-code",
                "B",
            ],
            &["job", "show"],
            &["job", "ack", ID, "--yes"],
            &["job", "retry", ID],
            &["boot-service", "set-packages", ID],
            &["boot-service", "set-packages"],
            &["boot-service", "set-packages", ID, "p1", "--none"],
            &["boot-service", "set-packages", ID, "--none", "--none"],
            &["boot-service", "enrol"],
            &["boot-stop", "clear"],
            &["boot-stop", "add", ID],
        ];
        for args in bad {
            assert!(p(args).is_err(), "{args:?} should be a usage error");
        }
    }

    fn kit_args(extra: &[&str]) -> Vec<String> {
        let base = [
            "boot-manifest",
            "create",
            "--pe-kit",
            "--root",
            "/r",
            "--out",
            "/o",
            "--pe",
            ID,
            "--boot-program",
            "bootmgfw.efi",
            "--bcd",
            "Boot/BCD",
            "--sdi",
            "Boot/boot.sdi",
            "--wim",
            "Boot/boot.wim",
        ];
        base.iter().chain(extra).map(|s| (*s).to_owned()).collect()
    }

    fn pk(args: &[String]) -> Result<Command, UsageError> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn pe_kit_create_parses() {
        let got = pk(&kit_args(&[
            "--font",
            "Boot/Fonts/a.ttf",
            "--server",
            "https://ctl:8443",
            "--font",
            "Boot/Fonts/b.ttf",
            "--",
            "extra.bin",
        ]));
        let Ok(Command::CreateKit(k)) = got else {
            panic!("{got:?}");
        };
        assert_eq!(k.create.root, PathBuf::from("/r"));
        assert_eq!(k.create.out, PathBuf::from("/o"));
        assert_eq!(k.create.names, vec![OsString::from("extra.bin")]);
        assert_eq!(k.boot_program, "bootmgfw.efi");
        assert_eq!(k.bcd, "Boot/BCD");
        assert_eq!(k.sdi, "Boot/boot.sdi");
        assert_eq!(k.wim, "Boot/boot.wim");
        assert_eq!(
            k.fonts,
            vec![
                OsString::from("Boot/Fonts/a.ttf"),
                OsString::from("Boot/Fonts/b.ttf")
            ]
        );
        assert_eq!(k.pe, ID);
        assert_eq!(k.conn.server.as_deref(), Some("https://ctl:8443"));
        // No NAME is needed: the kit files are published by themselves.
        assert!(matches!(pk(&kit_args(&[])), Ok(Command::CreateKit(_))));
        // `--pe-kit` after `--` is a name, so this is the M1 create.
        assert!(matches!(
            p(&[
                "boot-manifest",
                "create",
                "--root",
                "/r",
                "--out",
                "/o",
                "--",
                "--pe-kit"
            ]),
            Ok(Command::Create(_))
        ));
    }

    #[test]
    fn pe_kit_create_usage_errors() {
        let full = kit_args(&[]);
        // Each required option left out in turn.
        for opt in [
            "--root",
            "--out",
            "--pe",
            "--boot-program",
            "--bcd",
            "--sdi",
            "--wim",
        ] {
            let i = full.iter().position(|a| a == opt).unwrap();
            let mut args = full.clone();
            args.drain(i..i + 2);
            assert!(pk(&args).is_err(), "without {opt}");
        }
        for extra in [
            &["--font"][..],
            &["--font", ""],
            &["--wim", "x.wim"],
            &["--pe-kit"],
            &["--manifest", "/m"],
            &["--generate-bcd"],
        ] {
            assert!(pk(&kit_args(extra)).is_err(), "{extra:?}");
        }
        // Connection options stay refused on the M1 create.
        assert!(
            p(&[
                "boot-manifest",
                "create",
                "--root",
                "/r",
                "--out",
                "/o",
                "--server",
                "https://ctl",
                "a"
            ])
            .is_err()
        );
        assert_eq!(pk(&kit_args(&["--help"])), Ok(Command::Help));
    }

    #[test]
    fn agent_config_grammar() {
        let full = [
            "pe",
            "agent-config",
            "--out",
            "/o",
            "--server-url",
            "https://h:8444",
            "--trust-anchors",
            "/a.pem",
            "--plan-key-pub",
            "/p.pub",
            "--content-key-pub",
            "/c.pub",
            "--network-wait-s",
            "60",
        ];
        let Ok(Command::AgentConfig(a)) = p(&full) else {
            panic!("not parsed");
        };
        assert_eq!(a.out, PathBuf::from("/o"));
        assert_eq!(a.server_url, "https://h:8444");
        assert_eq!(a.server_name, None);
        assert_eq!(a.network_wait_s, Some(60));
        assert_eq!(a.connect_timeout_s, None);
        assert_eq!(a.content_key_pub, PathBuf::from("/c.pub"));
        assert_eq!(p(&["pe", "agent-config", "--help"]), Ok(Command::Help));
        // A server connection option, a missing option, a stray argument,
        // a bad number.
        let mut with_server = full.to_vec();
        with_server.extend(["--server", "https://x"]);
        let mut stray = full.to_vec();
        stray.push("extra");
        for bad in [
            with_server,
            full.get(..full.len() - 4).unwrap().to_vec(),
            stray,
            [full.get(..full.len() - 1).unwrap(), &["6x"]].concat(),
        ] {
            assert!(p(&bad).is_err(), "{bad:?}");
        }
    }
}
