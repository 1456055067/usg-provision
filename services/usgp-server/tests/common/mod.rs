//! Shared helpers for the server integration tests: a scratch directory
//! with the test PKI (usgp-crypto `test-pki`), signing keys and a
//! configuration file, and a minimal HTTPS/1.1 client over the
//! `usgp-crypto` TLS client.
//!
//! Every fixture is generated at test time. Nothing touches a real
//! device, a real certificate authority or a production database.

#[cfg(feature = "pg-integration")]
pub mod flow;
#[cfg(feature = "pg-integration")]
pub mod pg;
#[cfg(feature = "pg-integration")]
pub mod stream;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use usgp_crypto::test_pki::{TestCert, TestPki};
use usgp_crypto::tls::{ClientTls, TlsMinVersion};
use usgp_crypto::{SigningKey, VerifyingKey};

/// A uniquely named scratch directory (0755), removed on drop.
pub struct Scratch {
    /// The directory.
    pub dir: PathBuf,
}

impl Scratch {
    /// Creates `<tmp>/usgp-server-<tag>-<pid>-<n>`.
    pub fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "usgp-server-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        set_mode(&dir, 0o755);
        Self { dir }
    }

    /// A path in the directory.
    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Writes a file with `mode`.
    pub fn write(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
        let p = self.path(name);
        std::fs::write(&p, bytes).unwrap();
        set_mode(&p, mode);
        p
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Sets Unix permission bits.
pub fn set_mode(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// The test's effective uid (passed as `--admin-uid`).
pub fn admin_uid() -> u32 {
    usgp_common::process::effective_uid().unwrap()
}

/// Scratch files for one server: PKI, keys, content root, configuration.
pub struct Fixture {
    /// The directory.
    pub scratch: Scratch,
    /// The test PKI.
    pub pki: TestPki,
    /// Audit public key.
    pub audit_pub: VerifyingKey,
    /// Content public key.
    pub content_pub: VerifyingKey,
}

/// Database settings written into the configuration.
#[derive(Debug, Clone)]
pub struct DbFiles {
    /// Host.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Database.
    pub dbname: String,
    /// Role.
    pub user: String,
    /// TLS server name.
    pub server_name: String,
    /// Server CA file.
    pub server_ca: PathBuf,
    /// Client certificate file.
    pub client_cert: PathBuf,
    /// Client key file.
    pub client_key: PathBuf,
    /// `[database.admin]` (role, certificate, key), if written
    /// (decision 0016).
    pub admin: Option<(String, PathBuf, PathBuf)>,
}

impl Fixture {
    /// Generates everything; the database points at a closed local port
    /// with test-PKI files (enough for configuration checks).
    pub fn new(tag: &str) -> Self {
        let scratch = Scratch::new(tag);
        let pki = TestPki::generate().unwrap();
        scratch.write("server.pem", &pki.server.chain_pem(), 0o644);
        scratch.write("server.key", &pki.server.key_pem().unwrap(), 0o600);
        scratch.write(
            "operator-cas.pem",
            pki.root.cert_pem().unwrap().as_bytes(),
            0o644,
        );
        for (i, crl) in pki.current_crls().unwrap().iter().enumerate() {
            scratch.write(&format!("crl-{i}.der"), crl, 0o644);
        }
        scratch.write("operator.pem", &pki.client.chain_pem(), 0o644);
        scratch.write("db-ca.pem", pki.root.cert_pem().unwrap().as_bytes(), 0o644);
        scratch.write("db-client.pem", &pki.client.chain_pem(), 0o644);
        scratch.write("db-client.key", &pki.client.key_pem().unwrap(), 0o600);
        scratch.write("db-admin.pem", &pki.client.chain_pem(), 0o644);
        scratch.write("db-admin.key", &pki.client.key_pem().unwrap(), 0o600);
        let content = SigningKey::generate().unwrap();
        let audit = SigningKey::generate().unwrap();
        scratch.write("content.p8", &content.to_pkcs8_pem().unwrap(), 0o600);
        scratch.write("audit.p8", &audit.to_pkcs8_pem().unwrap(), 0o600);
        scratch.write(
            "content.pub",
            content.verifying_key().to_spki_pem().unwrap().as_bytes(),
            0o644,
        );
        scratch.write(
            "audit.pub",
            audit.verifying_key().to_spki_pem().unwrap().as_bytes(),
            0o644,
        );
        std::fs::create_dir_all(scratch.path("content")).unwrap();
        set_mode(&scratch.path("content"), 0o700);
        Self {
            audit_pub: audit.verifying_key().clone(),
            content_pub: content.verifying_key().clone(),
            scratch,
            pki,
        }
    }

    /// Database settings pointing at a closed local port.
    pub fn unreachable_db(&self) -> DbFiles {
        DbFiles {
            host: "127.0.0.1".into(),
            port: 1,
            dbname: "usgp".into(),
            user: "usgp_app".into(),
            server_name: "localhost".into(),
            server_ca: self.scratch.path("db-ca.pem"),
            client_cert: self.scratch.path("db-client.pem"),
            client_key: self.scratch.path("db-client.key"),
            admin: Some((
                "usgp_admin".into(),
                self.scratch.path("db-admin.pem"),
                self.scratch.path("db-admin.key"),
            )),
        }
    }

    /// The configuration text.
    pub fn config_text(&self, db: &DbFiles) -> String {
        let p = |n: &str| self.scratch.path(n).display().to_string();
        format!(
            r#"schema_version = 1
node_name = "test-node"

[api]
listen = "127.0.0.1:0"

[tls]
cert_chain = "{server_pem}"
private_key = "{server_key}"
min_version = "1.2"
client_trust_anchors = "{cas}"
client_crls = ["{crl0}", "{crl1}", "{crl2}"]
crl_reload_s = 1

[database]
host = "{host}"
port = {port}
dbname = "{dbname}"
user = "{user}"
server_ca = "{db_ca}"
server_name = "{server_name}"
client_cert = "{db_cert}"
client_key = "{db_key}"
pool_size = 2
connect_timeout_s = 2
{admin}
[content]
root = "{root}"
max_upload_bytes = 1048576

[signing]
content_key = "{content_key}"
audit_key = "{audit_key}"

[audit]
checkpoint_every_records = 100
checkpoint_every_s = 60

[log]
level = "info"
"#,
            server_pem = p("server.pem"),
            server_key = p("server.key"),
            cas = p("operator-cas.pem"),
            crl0 = p("crl-0.der"),
            crl1 = p("crl-1.der"),
            crl2 = p("crl-2.der"),
            host = db.host,
            port = db.port,
            dbname = db.dbname,
            user = db.user,
            db_ca = db.server_ca.display(),
            server_name = db.server_name,
            db_cert = db.client_cert.display(),
            db_key = db.client_key.display(),
            admin = db.admin.as_ref().map_or_else(String::new, |(u, c, k)| format!(
                "\n[database.admin]\nuser = \"{u}\"\nclient_cert = \"{}\"\nclient_key = \"{}\"\n",
                c.display(),
                k.display()
            )),
            root = p("content"),
            content_key = p("content.p8"),
            audit_key = p("audit.p8"),
        )
    }

    /// Writes `text` as `server.toml` (0644) and returns its path.
    pub fn write_config(&self, text: &str) -> PathBuf {
        self.scratch.write("server.toml", text.as_bytes(), 0o644)
    }
}

/// An HTTP response.
#[derive(Debug, Clone)]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Header block (lower-cased names as sent).
    pub head: String,
    /// Body.
    pub body: String,
}

/// Sends one HTTP/1.1 request over mutual TLS (client certificate
/// `cert`, or none) and reads the response to the end. `Err` if no
/// HTTP response arrived (for example the handshake was refused).
pub async fn https(
    addr: SocketAddr,
    pki: &TestPki,
    cert: Option<&TestCert>,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<Response, String> {
    let client = ClientTls::new(&pki.client_settings(cert, TlsMinVersion::Tls12).unwrap())
        .map_err(|e| e.to_string())?;
    let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let mut s = client
        .connect(tcp, "localhost")
        .await
        .map_err(|e| format!("{e:?}"))?;
    let body = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match s.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "no HTTP response".to_owned())?;
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "no status".to_owned())?;
    Ok(Response {
        status,
        head: head.to_ascii_lowercase(),
        body: body.to_owned(),
    })
}

/// The value of `"key":"value"` in a JSON text (tests only; no JSON
/// crate is a dependency of this package).
pub fn json_str(text: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\":\"");
    let start = text.find(&pat)? + pat.len();
    let rest = &text[start..];
    Some(rest[..rest.find('"')?].to_owned())
}
