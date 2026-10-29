//! `usgp-cli pe agent-config`: writes the pre-boot agent's public
//! configuration (M3 plan WU-13 and section 1.3; decision 0020 as
//! clarified).
//!
//! The operator copies the output directory into their own Windows PE next
//! to the agent (`X:\usgp\`). This command never opens, mounts or modifies
//! a PE. It writes a new directory holding exactly four public files:
//!
//! | File | Content |
//! |------|---------|
//! | `agent.toml` | [`usgp_proto::agent_config::AgentConfigFile`], naming the three files below by relative name |
//! | `trust-anchors.pem` | the server trust anchors, re-encoded: one `CERTIFICATE` block per certificate given, nothing else |
//! | `plan.pub` | the plan public key, re-encoded as one `PUBLIC KEY` block |
//! | `content.pub` | the content public key, re-encoded the same way |
//!
//! Every value is checked the way the agent checks it before anything is
//! written: the URL, server name and ranges by the shared type; the trust
//! anchors by building the agent's TLS client configuration from them; the
//! keys by parsing them as P-384 public keys, which must differ (one key
//! per purpose). An input file holding a `PRIVATE KEY` block is refused,
//! so no secret can be copied into the PE.
//!
//! The trust-anchor file is never copied (SEC-009): each `CERTIFICATE`
//! block is decoded by `usgp-crypto` to its DER certificate and written
//! back as a fresh PEM block (RFC 7468 §2, §5: 64-character lines, the
//! standard base64 alphabet with padding). Text between blocks is
//! dropped; a block with any other label, or one that is not closed, is
//! refused. The agent's TLS settings are then built from the re-encoded
//! text, which is what is written. The directory must not exist
//! (nothing is overwritten); on a write error what was written is removed.
//!
//! One `pe.agent_config.created` audit event is emitted per run.

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 (Configuration Settings) - the agent's settings are
//   checked by the agent's own rules before they are written.
// - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management) -
//   pinned public keys, one per purpose; SC-28 / IA-5 - no private key is
//   ever written (decision 0020 item 2: the device carries no secret).
// - NIST 800-53: SC-13 - key and certificate parsing only through
//   usgp-crypto (decision 0001).
// - NIST 800-53: AU-2, AU-3, AU-12 - one audit event per run.
// - SPEC: specs/preinstall-env.md#REQ-PE-015
// - DECISION: docs/decisions/0020 (public configuration, no secret)

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use usgp_common::Sha256Digest;
use usgp_common::config::{ConfigError, read_bounded};
use usgp_common::event::Outcome;
use usgp_crypto::VerifyingKey;
use usgp_crypto::tls::{BlockingClientTls, ClientAlpn, ClientTlsSettings, TlsMinVersion};
use usgp_proto::agent_config::{AgentConfigError, AgentConfigFile};

use usgp_crypto::PeerCertificate;

use crate::args::AgentConfigArgs;
use crate::boot_manifest::{audit, who};

/// The configuration file's name.
pub const AGENT_TOML: &str = "agent.toml";
/// The trust-anchor file's name.
pub const ANCHORS_FILE: &str = "trust-anchors.pem";
/// The plan key file's name.
pub const PLAN_KEY_FILE: &str = "plan.pub";
/// The content key file's name.
pub const CONTENT_KEY_FILE: &str = "content.pub";

/// Largest trust-anchor file read (the agent's limit).
const MAX_ANCHORS_BYTES: u64 = 256 * 1024;
/// Largest public-key file read (the agent's limit).
const MAX_KEY_BYTES: u64 = 16 * 1024;
/// Audit event name.
const EVENT: &str = "pe.agent_config.created";

/// Why `pe agent-config` wrote nothing.
#[derive(Debug, thiserror::Error)]
pub enum AgentConfigCliError {
    /// A setting breaks the agent's rules.
    #[error(transparent)]
    Setting(#[from] AgentConfigError),
    /// An input file could not be read.
    #[error(transparent)]
    Read(#[from] ConfigError),
    /// An input file holds a private key.
    #[error("{0} holds a PRIVATE KEY block; agent.toml and its files must hold no secret")]
    PrivateKey(&'static str),
    /// The trust anchors are not usable by the agent.
    #[error("--trust-anchors is not a usable PEM certificate bundle: {0}")]
    Anchors(String),
    /// A key is not a P-384 public key in PEM.
    #[error("{0} is not a P-384 public key in PEM")]
    Key(&'static str),
    /// Both keys are the same key.
    #[error("--plan-key-pub must differ from --content-key-pub (one key per purpose)")]
    SameKey,
    /// The output directory exists.
    #[error("{} already exists; refusing to overwrite it", .0.display())]
    OutputExists(PathBuf),
    /// The output could not be written (what was written is removed).
    #[error("cannot write {}: {kind}", path.display())]
    Write {
        /// The file or directory.
        path: PathBuf,
        /// The I/O error kind.
        kind: io::ErrorKind,
    },
}

impl AgentConfigCliError {
    /// Audit outcome: refusals by rule are `refused`, I/O is `failure`.
    #[must_use]
    pub const fn outcome(&self) -> Outcome {
        match self {
            Self::Read(_) | Self::Write { .. } => Outcome::Failure,
            _ => Outcome::Refused,
        }
    }
}

/// What was written.
#[derive(Debug)]
pub struct Written {
    /// The configuration as written.
    pub file: AgentConfigFile,
    /// SHA-256 of `agent.toml`.
    pub toml_sha256: Sha256Digest,
    /// SHA-256 of the trust-anchor file.
    pub anchors_sha256: Sha256Digest,
    /// The plan key's id (SHA-256 of its SPKI).
    pub plan_key_id: String,
    /// The content key's id.
    pub content_key_id: String,
}

fn refuse_private(what: &'static str, text: &str) -> Result<(), AgentConfigCliError> {
    if text.contains("PRIVATE KEY") {
        return Err(AgentConfigCliError::PrivateKey(what));
    }
    Ok(())
}

/// Most certificates accepted in the trust-anchor file (design bound).
const MAX_ANCHORS: usize = 64;

const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_CERT_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_CERT_END: &str = "-----END CERTIFICATE-----";

/// RFC 4648 §4 base64 of `der`, padded, as RFC 7468 §2 lines of 64
/// characters each ending in LF. Output only: its input is DER that
/// `usgp-crypto` has already decoded.
fn base64_lines(der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let sym = |v: u32| {
        let i = usize::try_from(v & 63).unwrap_or(0);
        char::from(ALPHABET.get(i).copied().unwrap_or(b'A'))
    };
    let mut flat = String::with_capacity(der.len().div_ceil(3).saturating_mul(4));
    for chunk in der.chunks(3) {
        let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let v = (b(0) << 16) | (b(1) << 8) | b(2);
        flat.push(sym(v >> 18));
        flat.push(sym(v >> 12));
        flat.push(if chunk.len() > 1 { sym(v >> 6) } else { '=' });
        flat.push(if chunk.len() > 2 { sym(v) } else { '=' });
    }
    let mut out = String::with_capacity(flat.len().saturating_add(flat.len() / 64 + 1));
    let mut line = String::with_capacity(64);
    for c in flat.chars() {
        line.push(c);
        if line.len() == 64 {
            out.push_str(&line);
            out.push('\n');
            line.clear();
        }
    }
    if !line.is_empty() {
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// The trust anchors as written to the PE (SEC-009): every `CERTIFICATE`
/// block of `text`, decoded by `usgp-crypto` and re-encoded; nothing else.
fn reencode_anchors(text: &str) -> Result<String, AgentConfigCliError> {
    let bad = |why: &str| AgentConfigCliError::Anchors(why.to_owned());
    let mut out = String::new();
    let mut block: Option<String> = None;
    let mut count = 0usize;
    for raw in text.lines() {
        let line = raw.trim_end();
        match block.as_mut() {
            None if line == PEM_CERT_BEGIN => {
                let mut b = String::from(PEM_CERT_BEGIN);
                b.push('\n');
                block = Some(b);
            }
            None if line.starts_with(PEM_BEGIN) => {
                return Err(bad("holds a PEM block other than CERTIFICATE"));
            }
            // Explanatory text between blocks (RFC 7468 §2) is dropped.
            None => {}
            Some(_) if line.starts_with(PEM_BEGIN) => {
                return Err(bad("a CERTIFICATE block is not closed"));
            }
            Some(b) if line == PEM_CERT_END => {
                b.push_str(PEM_CERT_END);
                b.push('\n');
                let cert = PeerCertificate::from_pem(b.as_bytes())
                    .map_err(|e| AgentConfigCliError::Anchors(e.to_string()))?;
                count = count.saturating_add(1);
                if count > MAX_ANCHORS {
                    return Err(bad("more than 64 certificates"));
                }
                out.push_str(PEM_CERT_BEGIN);
                out.push('\n');
                out.push_str(&base64_lines(&cert.der));
                out.push_str(PEM_CERT_END);
                out.push('\n');
                block = None;
            }
            Some(b) => {
                b.push_str(line);
                b.push('\n');
            }
        }
    }
    if block.is_some() {
        return Err(bad("a CERTIFICATE block is not closed"));
    }
    if count == 0 {
        return Err(bad("no CERTIFICATE block"));
    }
    Ok(out)
}

fn read_key(path: &Path, what: &'static str) -> Result<VerifyingKey, AgentConfigCliError> {
    let text = read_bounded(path, MAX_KEY_BYTES)?;
    refuse_private(what, &text)?;
    VerifyingKey::from_spki_pem(text.as_bytes()).map_err(|_| AgentConfigCliError::Key(what))
}

/// Checks everything, then writes the directory (module docs).
///
/// # Errors
///
/// [`AgentConfigCliError`]; nothing is left behind on error.
pub fn create(a: &AgentConfigArgs) -> Result<Written, AgentConfigCliError> {
    let file = AgentConfigFile {
        server_url: a.server_url.clone(),
        server_name: a.server_name.clone(),
        trust_anchors: ANCHORS_FILE.into(),
        plan_key_pub: PLAN_KEY_FILE.into(),
        content_key_pub: CONTENT_KEY_FILE.into(),
        network_wait_s: a.network_wait_s,
        connect_timeout_s: a.connect_timeout_s,
    };
    file.settings()?;
    if fs::symlink_metadata(&a.out).is_ok() {
        return Err(AgentConfigCliError::OutputExists(a.out.clone()));
    }

    let given = read_bounded(&a.trust_anchors, MAX_ANCHORS_BYTES)?;
    refuse_private("--trust-anchors", &given)?;
    let anchors = reencode_anchors(&given)?;
    // The agent's own client configuration (app.rs), on the text that is
    // written: the same parse, the same anchor rules, FIPS asserted.
    BlockingClientTls::new(&ClientTlsSettings {
        trust_anchors_pem: anchors.as_bytes().to_vec(),
        client_cert_chain_pem: None,
        client_key_pem: None,
        min_version: TlsMinVersion::Tls12,
        alpn: ClientAlpn::Http11,
    })
    .map_err(|e| AgentConfigCliError::Anchors(e.to_string()))?;
    let plan = read_key(&a.plan_key_pub, "--plan-key-pub")?;
    let content = read_key(&a.content_key_pub, "--content-key-pub")?;
    if plan.key_id() == content.key_id() {
        return Err(AgentConfigCliError::SameKey);
    }
    let plan_pem = plan
        .to_spki_pem()
        .map_err(|_| AgentConfigCliError::Key("--plan-key-pub"))?;
    let content_pem = content
        .to_spki_pem()
        .map_err(|_| AgentConfigCliError::Key("--content-key-pub"))?;

    let text = file.to_toml()?;
    // Self-check: the agent's parser reads back exactly what was built.
    if AgentConfigFile::from_toml(&text)? != file {
        return Err(AgentConfigCliError::Setting(AgentConfigError::NotWritable));
    }
    write_dir(
        &a.out,
        &[
            (AGENT_TOML, text.as_bytes()),
            (ANCHORS_FILE, anchors.as_bytes()),
            (PLAN_KEY_FILE, plan_pem.as_bytes()),
            (CONTENT_KEY_FILE, content_pem.as_bytes()),
        ],
    )?;
    Ok(Written {
        file,
        toml_sha256: usgp_crypto::sha256(text.as_bytes()),
        anchors_sha256: usgp_crypto::sha256(anchors.as_bytes()),
        plan_key_id: plan.key_id().to_hex(),
        content_key_id: content.key_id().to_hex(),
    })
}

/// Creates `dir` (must not exist; 0755 on Unix) and the files in it
/// (create-new, 0644). On any error everything created is removed.
fn write_dir(dir: &Path, files: &[(&str, &[u8])]) -> Result<(), AgentConfigCliError> {
    let werr = |path: &Path, e: &io::Error| AgentConfigCliError::Write {
        path: path.to_path_buf(),
        kind: e.kind(),
    };
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o755);
    }
    builder.create(dir).map_err(|e| match e.kind() {
        io::ErrorKind::AlreadyExists => AgentConfigCliError::OutputExists(dir.to_path_buf()),
        _ => werr(dir, &e),
    })?;
    for (name, bytes) in files {
        let path = dir.join(name);
        if let Err(e) = write_new(&path, bytes) {
            // Best effort: remove what this run created.
            for (n, _) in files {
                let _ = fs::remove_file(dir.join(n));
            }
            let _ = fs::remove_dir(dir);
            return Err(werr(&path, &e));
        }
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o644);
    }
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// Runs the command, reports on stderr, emits `pe.agent_config.created`,
/// and returns the exit status (0 or 1).
pub fn run(a: &AgentConfigArgs) -> u8 {
    let mut detail = who();
    detail.extend([
        ("out", a.out.display().to_string()),
        ("server_url", a.server_url.clone()),
    ]);
    match create(a) {
        Ok(w) => {
            detail.extend([
                ("agent_toml_sha256", w.toml_sha256.to_hex()),
                ("trust_anchors_sha256", w.anchors_sha256.to_hex()),
                ("plan_key_id", w.plan_key_id.clone()),
                ("content_key_id", w.content_key_id.clone()),
                (
                    "server_name",
                    w.file
                        .server_name
                        .clone()
                        .unwrap_or_else(|| "(the URL host)".to_owned()),
                ),
            ]);
            audit(EVENT, Outcome::Success, &detail);
            eprintln!(
                "usgp-cli: wrote {} ({AGENT_TOML}, {ANCHORS_FILE}, {PLAN_KEY_FILE}, \
                 {CONTENT_KEY_FILE}); agent.toml sha256 {}",
                a.out.display(),
                w.toml_sha256
            );
            eprintln!("usgp-cli: plan key {}", w.plan_key_id);
            eprintln!("usgp-cli: content key {}", w.content_key_id);
            eprintln!(
                "usgp-cli: copy the directory's files next to the agent in your Windows PE \
                 (they hold no secret)"
            );
            0
        }
        Err(e) => {
            detail.push(("reason", e.to_string()));
            audit(EVENT, e.outcome(), &detail);
            eprintln!("usgp-cli: pe agent-config: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use usgp_crypto::SigningKey;
    use usgp_crypto::test_pki::TestCa;

    use super::*;

    struct Dir(PathBuf);

    impl Dir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "usgp-cli-agent-config-{tag}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }

        fn put(&self, name: &str, text: &str) -> PathBuf {
            let p = self.0.join(name);
            fs::write(&p, text).unwrap();
            p
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn args(d: &Dir) -> AgentConfigArgs {
        let ca = TestCa::root("usgp test agent anchor").unwrap();
        let plan = SigningKey::generate().unwrap();
        let content = SigningKey::generate().unwrap();
        AgentConfigArgs {
            out: d.0.join("out"),
            server_url: "https://provision.example.gov:8444".into(),
            server_name: None,
            trust_anchors: d.put("ca.pem", &ca.cert_pem().unwrap()),
            plan_key_pub: d.put("p.pub", &plan.verifying_key().to_spki_pem().unwrap()),
            content_key_pub: d.put("c.pub", &content.verifying_key().to_spki_pem().unwrap()),
            network_wait_s: Some(60),
            connect_timeout_s: None,
        }
    }

    #[test]
    fn writes_four_public_files_the_agent_reads() {
        let d = Dir::new("ok");
        let a = args(&d);
        let w = create(&a).unwrap();
        let mut names: Vec<String> = fs::read_dir(&a.out)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(
            names,
            ["agent.toml", "content.pub", "plan.pub", "trust-anchors.pem"]
        );
        let text = fs::read_to_string(a.out.join(AGENT_TOML)).unwrap();
        assert_eq!(usgp_crypto::sha256(text.as_bytes()), w.toml_sha256);
        let back = AgentConfigFile::from_toml(&text).unwrap();
        assert_eq!(back, w.file);
        assert_eq!(back.network_wait_s, Some(60));
        assert_eq!(back.plan_key_pub, PathBuf::from(PLAN_KEY_FILE));
        let s = back.settings().unwrap();
        assert_eq!((s.host.as_str(), s.port), ("provision.example.gov", 8444));
        // The written keys are the given keys.
        let plan = fs::read(a.out.join(PLAN_KEY_FILE)).unwrap();
        assert_eq!(
            VerifyingKey::from_spki_pem(&plan)
                .unwrap()
                .key_id()
                .to_hex(),
            w.plan_key_id
        );
        // No secret anywhere in the output.
        for n in &names {
            let t = fs::read_to_string(a.out.join(n)).unwrap();
            assert!(!t.contains("PRIVATE"), "{n}");
        }
        // Never overwrites.
        assert!(matches!(
            create(&a),
            Err(AgentConfigCliError::OutputExists(_))
        ));
    }

    #[test]
    fn refusals_write_nothing() {
        let d = Dir::new("refuse");
        let base = args(&d);
        let key = SigningKey::generate().unwrap();
        let secret = String::from_utf8(key.to_pkcs8_pem().unwrap().to_vec()).unwrap();
        let cases: Vec<(AgentConfigArgs, Want)> = vec![
            (
                AgentConfigArgs {
                    server_url: "http://provision.example.gov".into(),
                    ..clone_args(&base)
                },
                |e| matches!(e, AgentConfigCliError::Setting(_)),
            ),
            (
                AgentConfigArgs {
                    network_wait_s: Some(5),
                    ..clone_args(&base)
                },
                |e| matches!(e, AgentConfigCliError::Setting(_)),
            ),
            (
                AgentConfigArgs {
                    content_key_pub: base.plan_key_pub.clone(),
                    ..clone_args(&base)
                },
                |e| matches!(e, AgentConfigCliError::SameKey),
            ),
            (
                AgentConfigArgs {
                    plan_key_pub: d.put("secret.pem", &secret),
                    ..clone_args(&base)
                },
                |e| matches!(e, AgentConfigCliError::PrivateKey(_)),
            ),
            (
                AgentConfigArgs {
                    trust_anchors: d.put(
                        "bundle.pem",
                        &format!(
                            "{}{secret}",
                            fs::read_to_string(&base.trust_anchors).unwrap()
                        ),
                    ),
                    ..clone_args(&base)
                },
                |e| matches!(e, AgentConfigCliError::PrivateKey(_)),
            ),
            (
                AgentConfigArgs {
                    trust_anchors: d.put("junk.pem", "not a certificate"),
                    ..clone_args(&base)
                },
                |e| matches!(e, AgentConfigCliError::Anchors(_)),
            ),
            (
                AgentConfigArgs {
                    plan_key_pub: d.put("junk.pub", "junk"),
                    ..clone_args(&base)
                },
                |e| matches!(e, AgentConfigCliError::Key(_)),
            ),
        ];
        for (a, want) in cases {
            let e = create(&a).unwrap_err();
            assert!(want(&e), "{e}");
            assert_eq!(e.outcome(), Outcome::Refused);
            assert!(!a.out.exists(), "{e}");
            assert!(!e.to_string().contains("BEGIN"), "{e}");
        }
    }

    #[test]
    fn base64_is_rfc4648_with_64_character_lines() {
        // RFC 4648 §10 test vectors.
        for (raw, enc) in [
            ("", ""),
            ("f", "Zg==\n"),
            ("fo", "Zm8=\n"),
            ("foo", "Zm9v\n"),
            ("foob", "Zm9vYg==\n"),
            ("fooba", "Zm9vYmE=\n"),
            ("foobar", "Zm9vYmFy\n"),
        ] {
            assert_eq!(base64_lines(raw.as_bytes()), enc, "{raw}");
        }
        let long = base64_lines(&[0xFFu8; 100]);
        let lines: Vec<&str> = long.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines.first().unwrap().len(), 64);
        assert_eq!(lines.get(1).unwrap().len(), 64);
        assert!(long.ends_with("==\n"));
    }

    /// SEC-009: only re-encoded CERTIFICATE blocks are written; text
    /// around them is dropped and the DER is unchanged.
    #[test]
    fn anchors_are_written_as_reencoded_certificates_only() {
        let d = Dir::new("reencode");
        let a = args(&d);
        let given = fs::read_to_string(&a.trust_anchors).unwrap();
        let second = TestCa::root("usgp test second anchor").unwrap();
        let noisy = format!(
            "Explanatory text before\r\n{}\r\ntext between\n{}trailing words\n",
            given.replace('\n', "\r\n"),
            second.cert_pem().unwrap()
        );
        let a = AgentConfigArgs {
            trust_anchors: d.put("noisy.pem", &noisy),
            ..clone_args(&a)
        };
        let w = create(&a).unwrap();
        let written = fs::read_to_string(a.out.join(ANCHORS_FILE)).unwrap();
        assert!(!written.contains("text") && !written.contains("words"));
        assert!(!written.contains('\r'));
        assert_eq!(written.matches(PEM_CERT_BEGIN).count(), 2);
        assert_eq!(usgp_crypto::sha256(written.as_bytes()), w.anchors_sha256);
        // Each block decodes to the same DER as was given.
        let blocks: Vec<String> = written
            .split_inclusive(&format!("{PEM_CERT_END}\n"))
            .map(str::to_owned)
            .collect();
        assert_eq!(blocks.len(), 2);
        let first = PeerCertificate::from_pem(blocks.first().unwrap().as_bytes()).unwrap();
        assert_eq!(
            first.der,
            PeerCertificate::from_pem(given.as_bytes()).unwrap().der
        );
        let other = PeerCertificate::from_pem(blocks.get(1).unwrap().as_bytes()).unwrap();
        assert_eq!(other.der, second.cert_der());
        // Re-encoding is stable.
        assert_eq!(reencode_anchors(&written).unwrap(), written);
    }

    #[test]
    fn anchor_files_with_other_or_broken_blocks_are_refused() {
        let ca = TestCa::root("usgp test anchor").unwrap();
        let pem = ca.cert_pem().unwrap();
        let key = SigningKey::generate().unwrap();
        let public = key.verifying_key().to_spki_pem().unwrap();
        for (text, why) in [
            (format!("{pem}{public}"), "PUBLIC KEY block"),
            (pem.replace(PEM_CERT_END, ""), "not closed"),
            (
                format!("{}{pem}", pem.replace(PEM_CERT_END, "")),
                "BEGIN inside a block",
            ),
            ("no blocks at all\n".to_owned(), "no certificate"),
            (
                pem.replace(PEM_CERT_BEGIN, &format!("{PEM_CERT_BEGIN}\n!!!!")),
                "bad base64",
            ),
        ] {
            assert!(
                matches!(
                    reencode_anchors(&text),
                    Err(AgentConfigCliError::Anchors(_))
                ),
                "{why}"
            );
        }
        let many = pem.repeat(MAX_ANCHORS + 1);
        assert!(reencode_anchors(&many).is_err());
        assert!(reencode_anchors(&pem.repeat(2)).is_ok());
    }

    /// Which refusal a case expects.
    type Want = fn(&AgentConfigCliError) -> bool;

    fn clone_args(a: &AgentConfigArgs) -> AgentConfigArgs {
        AgentConfigArgs {
            out: a.out.clone(),
            server_url: a.server_url.clone(),
            server_name: a.server_name.clone(),
            trust_anchors: a.trust_anchors.clone(),
            plan_key_pub: a.plan_key_pub.clone(),
            content_key_pub: a.content_key_pub.clone(),
            network_wait_s: a.network_wait_s,
            connect_timeout_s: a.connect_timeout_s,
        }
    }
}
