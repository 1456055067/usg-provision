//! Connection settings for the M2 API commands (plan section 3.5, "CLI
//! config"; decision 0007).
//!
//! Settings come from command-line flags, then from the config file
//! (`--config FILE`, else `$HOME/.config/usgp/cli.toml` if it exists).
//! A flag wins over the file. The file holds only these keys, all
//! optional, and paths in it must be absolute:
//!
//! ```toml
//! server = "https://ctl-01.example:8443"
//! server_ca = "/home/op/.config/usgp/server-ca.pem"
//! client_cert = "/home/op/.config/usgp/operator.pem"
//! client_key = "/home/op/.config/usgp/operator.key"
//! content_key_pub = "/home/op/.config/usgp/content.pub"
//! ```
//!
//! Trust inputs (the config file, the server CA and the content public
//! key) are read only if they and every directory above them are owned by
//! root or by this user and are not writable by group or others
//! (`usgp_common::config::read_trusted`). The client private key must be a
//! regular file owned by this user with no group or other permission bits
//! (0600 or 0400), or the CLI refuses it (plan section 3.5). It is read
//! into a zeroizing buffer and handed to `usgp-crypto`; it is never
//! logged or shown.

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-2, IA-5(2) - the operator authenticates with a client
//   certificate validated by the server (decision 0007).
// - NIST 800-53: SC-12 - the client private key is read only from a
//   private file and held in `Zeroizing` memory.
// - NIST 800-53: SC-8, SC-8(1), SC-13 - the server is reached only over
//   TLS from `usgp-crypto` (FIPS provider), verified against a pinned CA.
// - NIST 800-53: CM-6 - strict config: unknown keys refused; trust files
//   permission-checked.
// - NIST 800-53: SI-7 - the content signing public key is pinned from a
//   trusted file, never taken from the server (plan section 5.2).
// POAM: IA-2(12) - the CLI uses a software key file; hardware PIV/CAC
// tokens are not supported (PKCS#11 needs a C library; plan section 9).

use std::io::Read;
use std::path::{Path, PathBuf};

use usgp_common::config::{ConfigError, TrustPolicy, parse_toml, read_bounded, read_trusted};
use usgp_crypto::pem::{MAX_CERT_PEM_BYTES, MAX_KEY_PEM_BYTES, MAX_PUBLIC_KEY_PEM_BYTES};
use usgp_crypto::tls::{ClientAlpn, ClientTls, ClientTlsSettings, TlsMinVersion};
use usgp_crypto::{CryptoError, VerifyingKey};
use zeroize::Zeroizing;

use crate::args::ConnArgs;

/// Largest config file read.
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

/// Longest server URL accepted.
const MAX_URL_LEN: usize = 300;

/// Default config file, relative to `$HOME`.
pub const DEFAULT_CONFIG: &str = ".config/usgp/cli.toml";

/// Why the connection settings could not be set up.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SetupError {
    /// A file could not be read or failed a trust rule.
    #[error(transparent)]
    File(#[from] ConfigError),
    /// The config file has an unknown key or a value of the wrong type.
    #[error("{}: {detail}", path.display())]
    Config {
        /// The config file.
        path: PathBuf,
        /// What is wrong (key names only; values are not echoed).
        detail: String,
    },
    /// A required setting is missing.
    #[error("{0} is not set (give the flag or set it in the config file)")]
    Missing(&'static str),
    /// The server URL is not `https://HOST[:PORT]`.
    #[error("server URL is not valid: {0}")]
    Url(&'static str),
    /// The client private key file breaks a rule.
    #[error("client key {}: {rule}", path.display())]
    KeyFile {
        /// The key file.
        path: PathBuf,
        /// The rule.
        rule: &'static str,
    },
    /// `usgp-crypto` refused a certificate, key or the TLS configuration.
    #[error("{0}")]
    Crypto(#[from] CryptoError),
}

/// A server address from `https://HOST[:PORT]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerUrl {
    /// DNS name or IP literal (IPv6 without brackets), checked as a TLS
    /// server name.
    pub host: String,
    /// TCP port (default 443).
    pub port: u16,
}

impl ServerUrl {
    /// Parses `https://HOST[:PORT][/]`. No user info, path, query or
    /// fragment; the scheme must be `https`.
    ///
    /// # Errors
    ///
    /// [`SetupError::Url`] naming the rule that failed.
    pub fn parse(text: &str) -> Result<Self, SetupError> {
        if text.len() > MAX_URL_LEN {
            return Err(SetupError::Url("longer than 300 bytes"));
        }
        let rest = text
            .strip_prefix("https://")
            .ok_or(SetupError::Url("must start with https://"))?;
        let authority = rest.strip_suffix('/').unwrap_or(rest);
        if authority.is_empty() {
            return Err(SetupError::Url("host is missing"));
        }
        if authority
            .chars()
            .any(|c| matches!(c, '/' | '?' | '#' | '@' | '\\') || !c.is_ascii_graphic())
        {
            return Err(SetupError::Url(
                "only https://HOST[:PORT] is allowed (no path, query, user or spaces)",
            ));
        }
        let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
            let (h, after) = v6
                .split_once(']')
                .ok_or(SetupError::Url("unclosed '[' in IPv6 host"))?;
            if h.parse::<std::net::Ipv6Addr>().is_err() {
                return Err(SetupError::Url("bracketed host is not an IPv6 address"));
            }
            match after {
                "" => (h, None),
                p => (
                    h,
                    Some(
                        p.strip_prefix(':')
                            .ok_or(SetupError::Url("text after the IPv6 host"))?,
                    ),
                ),
            }
        } else {
            match authority.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            }
        };
        let port = match port {
            None => 443,
            Some(p) => parse_port(p)?,
        };
        if host.is_empty() {
            return Err(SetupError::Url("host is missing"));
        }
        ClientTls::check_server_name(host)
            .map_err(|_| SetupError::Url("host is not a DNS name or IP address"))?;
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }
}

fn parse_port(p: &str) -> Result<u16, SetupError> {
    if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
        return Err(SetupError::Url("port must be 1 to 65535"));
    }
    match p.parse::<u16>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err(SetupError::Url("port must be 1 to 65535")),
    }
}

/// Resolved connection settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// The server.
    pub server: ServerUrl,
    /// PEM trust anchors for the server certificate.
    pub server_ca: PathBuf,
    /// PEM operator certificate chain, end entity first.
    pub client_cert: PathBuf,
    /// PKCS#8 PEM operator private key.
    pub client_key: PathBuf,
    /// SPKI PEM content signing public key (needed to verify manifests
    /// and downloads).
    pub content_key_pub: Option<PathBuf>,
}

/// Values found in a config file.
#[derive(Debug, Default)]
struct FileValues {
    server: Option<String>,
    server_ca: Option<PathBuf>,
    client_cert: Option<PathBuf>,
    client_key: Option<PathBuf>,
    content_key_pub: Option<PathBuf>,
}

fn trust_policy() -> Result<TrustPolicy, SetupError> {
    let uid = usgp_common::process::effective_uid().map_err(|e| {
        SetupError::File(ConfigError::Io {
            path: PathBuf::from("<effective uid>"),
            kind: e.kind(),
        })
    })?;
    Ok(TrustPolicy::with_admin(uid))
}

fn parse_file(path: &Path, text: &str) -> Result<FileValues, SetupError> {
    let bad = |detail: String| SetupError::Config {
        path: path.to_path_buf(),
        detail,
    };
    let value: serde_json::Value = parse_toml(text)?;
    let serde_json::Value::Object(map) = value else {
        return Err(bad("not a table".into()));
    };
    let mut v = FileValues::default();
    for (key, val) in map {
        let serde_json::Value::String(s) = val else {
            return Err(bad(format!("{key:?} must be a string")));
        };
        let abs = |s: String| {
            let p = PathBuf::from(s);
            if p.is_absolute() {
                Ok(Some(p))
            } else {
                Err(bad(format!("{key:?} must be an absolute path")))
            }
        };
        match key.as_str() {
            "server" => v.server = Some(s),
            "server_ca" => v.server_ca = abs(s)?,
            "client_cert" => v.client_cert = abs(s)?,
            "client_key" => v.client_key = abs(s)?,
            "content_key_pub" => v.content_key_pub = abs(s)?,
            _ => {
                let shown: String = key.chars().take(64).collect();
                return Err(bad(format!("unknown key {shown:?}")));
            }
        }
    }
    Ok(v)
}

/// Resolves the settings from flags and the config file. `home` is
/// `$HOME`, used only for the default config path.
///
/// # Errors
///
/// [`SetupError`] if the config file is unreadable, untrusted or invalid,
/// or a required setting is missing or invalid.
pub fn resolve(args: &ConnArgs, home: Option<&Path>) -> Result<Settings, SetupError> {
    let file = match (&args.config, home) {
        (Some(p), _) => Some(p.clone()),
        (None, Some(h)) => {
            let p = h.join(DEFAULT_CONFIG);
            std::fs::symlink_metadata(&p).is_ok().then_some(p)
        }
        (None, None) => None,
    };
    let fv = match file {
        Some(p) => {
            let text = read_trusted(&p, MAX_CONFIG_BYTES, &trust_policy()?)?;
            parse_file(&p, &text)?
        }
        None => FileValues::default(),
    };
    let server = args
        .server
        .clone()
        .or(fv.server)
        .ok_or(SetupError::Missing("server (--server)"))?;
    Ok(Settings {
        server: ServerUrl::parse(&server)?,
        server_ca: args
            .server_ca
            .clone()
            .or(fv.server_ca)
            .ok_or(SetupError::Missing("server CA (--server-ca)"))?,
        client_cert: args
            .client_cert
            .clone()
            .or(fv.client_cert)
            .ok_or(SetupError::Missing("client certificate (--client-cert)"))?,
        client_key: args
            .client_key
            .clone()
            .or(fv.client_key)
            .ok_or(SetupError::Missing("client key (--client-key)"))?,
        content_key_pub: args.content_key_pub.clone().or(fv.content_key_pub),
    })
}

/// Reads the operator's private key: a regular file (not a symbolic
/// link) owned by this user, with no group or other permission bits, at
/// most [`MAX_KEY_PEM_BYTES`], into a buffer allocated once so no copy is
/// left behind by reallocation.
///
/// # Errors
///
/// [`SetupError::KeyFile`] naming the rule.
pub fn read_private_key(path: &Path) -> Result<Zeroizing<Vec<u8>>, SetupError> {
    let err = |rule| SetupError::KeyFile {
        path: path.to_path_buf(),
        rule,
    };
    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let uid = usgp_common::process::effective_uid()
            .map_err(|_| err("cannot determine the effective uid"))?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|e| {
                if e.raw_os_error() == Some(libc::ELOOP) {
                    err("is a symbolic link")
                } else {
                    err("cannot be opened")
                }
            })?;
        let meta = file.metadata().map_err(|_| err("cannot be inspected"))?;
        if !meta.is_file() {
            return Err(err("is not a regular file"));
        }
        if meta.uid() != uid {
            return Err(err("is not owned by you"));
        }
        if meta.mode() & 0o077 != 0 {
            return Err(err(
                "is readable or writable by group or others (chmod 600)",
            ));
        }
        let max = u64::try_from(MAX_KEY_PEM_BYTES).unwrap_or(u64::MAX);
        if meta.len() > max {
            return Err(err("is larger than the 64 KiB limit"));
        }
        let mut buf = Zeroizing::new(Vec::with_capacity(MAX_KEY_PEM_BYTES.saturating_add(1)));
        (&mut file)
            .take(max.saturating_add(1))
            .read_to_end(&mut buf)
            .map_err(|_| err("cannot be read"))?;
        if buf.len() > MAX_KEY_PEM_BYTES {
            return Err(err("is larger than the 64 KiB limit"));
        }
        Ok(buf)
    }
    #[cfg(not(unix))]
    {
        Err(err("permission checks are not supported on this platform"))
    }
}

fn limit(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Builds the TLS client: the pinned server CA, the operator certificate
/// and key, ALPN `http/1.1`, TLS 1.2 or 1.3 on the FIPS provider.
///
/// # Errors
///
/// [`SetupError`] for an unreadable or untrusted file, or a certificate,
/// key or configuration `usgp-crypto` refuses.
pub fn client_tls(s: &Settings) -> Result<ClientTls, SetupError> {
    let ca = read_trusted(&s.server_ca, limit(MAX_CERT_PEM_BYTES), &trust_policy()?)?;
    let chain = read_bounded(&s.client_cert, limit(MAX_CERT_PEM_BYTES))?;
    let key = read_private_key(&s.client_key)?;
    let tls = ClientTls::new(&ClientTlsSettings {
        trust_anchors_pem: ca.into_bytes(),
        client_cert_chain_pem: Some(chain.into_bytes()),
        client_key_pem: Some(key),
        min_version: TlsMinVersion::Tls12,
        alpn: ClientAlpn::Http11,
    })?;
    Ok(tls)
}

/// Loads the pinned content signing public key (SPKI PEM) from a trusted
/// file.
///
/// # Errors
///
/// [`SetupError::Missing`] if no path is set, otherwise as
/// [`read_trusted`] or a key `usgp-crypto` refuses.
pub fn content_key(s: &Settings) -> Result<VerifyingKey, SetupError> {
    let path = s.content_key_pub.as_ref().ok_or(SetupError::Missing(
        "content public key (--content-key-pub)",
    ))?;
    let text = read_trusted(path, limit(MAX_PUBLIC_KEY_PEM_BYTES), &trust_policy()?)?;
    Ok(VerifyingKey::from_spki_pem(text.as_bytes())?)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU32, Ordering};

    pub(crate) struct TempDir(pub PathBuf);

    impl TempDir {
        pub(crate) fn new(tag: &str) -> Self {
            static N: AtomicU32 = AtomicU32::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let p =
                std::env::temp_dir().join(format!("usgp-cli-ut-{tag}-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            Self(p)
        }

        pub(crate) fn put(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
            let p = self.0.join(name);
            fs::write(&p, bytes).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
            p
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn url_rules() {
        let ok = |s: &str, h: &str, p: u16| {
            assert_eq!(
                ServerUrl::parse(s).unwrap(),
                ServerUrl {
                    host: h.into(),
                    port: p
                },
                "{s}"
            );
        };
        ok("https://ctl-01.example:8443", "ctl-01.example", 8443);
        ok("https://ctl-01.example/", "ctl-01.example", 443);
        ok("https://127.0.0.1:1", "127.0.0.1", 1);
        ok("https://[::1]:8443", "::1", 8443);
        ok("https://[::1]", "::1", 443);
        for bad in [
            "http://ctl",
            "ctl:8443",
            "https://",
            "https://ctl:0",
            "https://ctl:65536",
            "https://ctl:+1",
            "https://ctl:",
            "https://ctl/v1",
            "https://ctl?x",
            "https://user@ctl",
            "https://ct l",
            "https://[::1",
            "https://[x]:1",
            "https://[::1]x",
            "https://ctl:1:2",
            "https://-bad-.example",
            "HTTPS://ctl",
        ] {
            assert!(ServerUrl::parse(bad).is_err(), "{bad}");
        }
        assert!(ServerUrl::parse(&format!("https://{}", "a".repeat(400))).is_err());
    }

    fn conn() -> ConnArgs {
        ConnArgs::default()
    }

    #[test]
    fn flags_only() {
        let a = ConnArgs {
            server: Some("https://ctl:8443".into()),
            server_ca: Some("/ca.pem".into()),
            client_cert: Some("c.pem".into()),
            client_key: Some("c.key".into()),
            ..conn()
        };
        let s = resolve(&a, None).unwrap();
        assert_eq!(s.server.port, 8443);
        assert_eq!(s.content_key_pub, None);
        let missing = ConnArgs {
            client_key: None,
            ..a
        };
        assert!(matches!(
            resolve(&missing, None),
            Err(SetupError::Missing(_))
        ));
    }

    #[test]
    fn file_then_flag_override() {
        let t = TempDir::new("cfg");
        let cfg = t.put(
            "cli.toml",
            b"server = \"https://from-file:1\"\nserver_ca = \"/etc/ca.pem\"\n\
              client_cert = \"/c.pem\"\nclient_key = \"/c.key\"\n\
              content_key_pub = \"/k.pub\"\n",
            0o600,
        );
        let a = ConnArgs {
            config: Some(cfg.clone()),
            server: Some("https://from-flag:2".into()),
            ..conn()
        };
        let s = resolve(&a, None).unwrap();
        assert_eq!(s.server.host, "from-flag");
        assert_eq!(s.server_ca, PathBuf::from("/etc/ca.pem"));
        assert_eq!(s.content_key_pub, Some(PathBuf::from("/k.pub")));

        // Default location under $HOME.
        let home = TempDir::new("home");
        fs::create_dir_all(home.0.join(".config/usgp")).unwrap();
        fs::copy(&cfg, home.0.join(DEFAULT_CONFIG)).unwrap();
        let s = resolve(&conn(), Some(&home.0)).unwrap();
        assert_eq!(s.server.host, "from-file");
    }

    #[test]
    fn file_rules() {
        let t = TempDir::new("cfgbad");
        for (body, mode) in [
            (&b"surprise = \"x\"\n"[..], 0o600),
            (b"server_ca = \"relative.pem\"\n", 0o600),
            (b"server = 5\n", 0o600),
            (b"server = \"https://x\"\n", 0o666),
            (b"server = \"https://x\"\n", 0o620),
        ] {
            let p = t.put("c.toml", body, mode);
            let a = ConnArgs {
                config: Some(p),
                ..conn()
            };
            assert!(
                resolve(&a, None).is_err(),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        // An explicitly named file must exist.
        let a = ConnArgs {
            config: Some(t.0.join("absent.toml")),
            ..conn()
        };
        assert!(resolve(&a, None).is_err());
    }

    #[test]
    fn private_key_rules() {
        let t = TempDir::new("key");
        let good = t.put("k.pem", b"-----BEGIN PRIVATE KEY-----\n", 0o600);
        assert_eq!(
            &*read_private_key(&good).unwrap(),
            b"-----BEGIN PRIVATE KEY-----\n"
        );
        let ro = t.put("ro.pem", b"x", 0o400);
        assert!(read_private_key(&ro).is_ok());
        for mode in [0o640, 0o604, 0o660, 0o644] {
            let p = t.put("bad.pem", b"x", mode);
            let e = read_private_key(&p).unwrap_err().to_string();
            assert!(e.contains("group or others"), "{mode:o}: {e}");
        }
        let link = t.0.join("link.pem");
        std::os::unix::fs::symlink(&good, &link).unwrap();
        assert!(
            read_private_key(&link)
                .unwrap_err()
                .to_string()
                .contains("symbolic link")
        );
        let big = t.put("big.pem", &vec![b'a'; MAX_KEY_PEM_BYTES + 1], 0o600);
        assert!(read_private_key(&big).is_err());
        assert!(read_private_key(&t.0).is_err());
    }

    #[test]
    fn content_key_must_be_set_and_valid() {
        let t = TempDir::new("pub");
        let s = Settings {
            server: ServerUrl::parse("https://x").unwrap(),
            server_ca: "/ca".into(),
            client_cert: "/c".into(),
            client_key: "/k".into(),
            content_key_pub: None,
        };
        assert!(matches!(content_key(&s), Err(SetupError::Missing(_))));
        let key = usgp_crypto::SigningKey::generate().unwrap();
        let pem = key.verifying_key().to_spki_pem().unwrap();
        let p = t.put("content.pub", pem.as_bytes(), 0o644);
        let s = Settings {
            content_key_pub: Some(p),
            ..s
        };
        assert_eq!(&content_key(&s).unwrap(), key.verifying_key());
        let w = t.put("content.pub", pem.as_bytes(), 0o666);
        let s = Settings {
            content_key_pub: Some(w),
            ..s
        };
        assert!(content_key(&s).is_err());
    }
}
