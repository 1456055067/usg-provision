//! In-process stub API server for the CLI's process tests (plan WU-8):
//! hyper HTTP/1.1 over `usgp_crypto::tls::ServerTls` with the test PKI,
//! requiring an operator client certificate the way the real server does.
//! It replays scripted responses and records each request, including the
//! SHA-256 of the client certificate that made it.
//!
//! [`Env`] also writes the CLI's settings files (server CA, operator
//! certificate, 0600 key, optional content public key) and runs the built
//! binary against the server.

use std::convert::Infallible;
use std::fs;
use std::io::Write as _;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use usgp_crypto::VerifyingKey;
use usgp_crypto::test_pki::TestPki;
use usgp_crypto::tls::{ServerTls, TlsMinVersion};

/// One scripted response.
#[derive(Clone)]
pub struct Route {
    pub method: &'static str,
    pub path: String,
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

pub fn route(method: &'static str, path: &str, status: u16, body: Vec<u8>) -> Route {
    Route {
        method,
        path: path.to_owned(),
        status,
        headers: Vec::new(),
        body,
    }
}

impl Route {
    pub fn with_header(mut self, name: &'static str, value: &str) -> Self {
        self.headers.push((name, value.to_owned()));
        self
    }
}

/// One request the server received.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Hex SHA-256 of the client certificate, if one was presented.
    pub client_cert_sha256: Option<String>,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

type Log = Arc<Mutex<Vec<Seen>>>;

async fn handle(
    req: hyper::Request<Incoming>,
    routes: Arc<Vec<Route>>,
    log: Log,
    peer: Option<String>,
) -> Result<hyper::Response<Full<Bytes>>, Infallible> {
    let (parts, body) = req.into_parts();
    let body = body
        .collect()
        .await
        .map(|b| b.to_bytes().to_vec())
        .unwrap_or_default();
    let method = parts.method.as_str().to_owned();
    let path = parts.uri.path().to_owned();
    log.lock().unwrap().push(Seen {
        method: method.clone(),
        path: path.clone(),
        headers: parts
            .headers
            .iter()
            .map(|(n, v)| (n.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
            .collect(),
        body,
        client_cert_sha256: peer,
    });
    let found = routes.iter().find(|r| r.method == method && r.path == path);
    let mut b = hyper::Response::builder();
    let resp = match found {
        Some(r) => {
            b = b.status(r.status);
            for (n, v) in &r.headers {
                b = b.header(*n, v.as_str());
            }
            b.body(Full::new(Bytes::from(r.body.clone()))).unwrap()
        }
        None => b.status(404).body(Full::new(Bytes::new())).unwrap(),
    };
    Ok(resp)
}

/// Starts the server on 127.0.0.1 in its own thread and runtime.
fn start(pki: &TestPki, routes: Vec<Route>) -> (SocketAddr, Log) {
    let settings = pki
        .server_settings(
            pki.current_crls().unwrap(),
            Vec::new(),
            TlsMinVersion::Tls12,
        )
        .unwrap();
    let tls = Arc::new(ServerTls::new(&settings).unwrap());
    let routes = Arc::new(routes);
    let log: Log = Arc::default();
    let (tx, rx) = std::sync::mpsc::channel();
    let thread_log = Arc::clone(&log);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    continue;
                };
                let (tls, routes, log) = (
                    Arc::clone(&tls),
                    Arc::clone(&routes),
                    Arc::clone(&thread_log),
                );
                tokio::spawn(async move {
                    // A refused handshake simply ends the connection.
                    let Ok((stream, peer)) = tls.accept(tcp).await else {
                        return;
                    };
                    let peer = peer.map(|p| p.sha256.to_hex());
                    let svc = service_fn(move |req| {
                        handle(req, Arc::clone(&routes), Arc::clone(&log), peer.clone())
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
    });
    (rx.recv().unwrap(), log)
}

/// A test directory, test PKI, running stub server and CLI settings.
pub struct Env {
    pub dir: PathBuf,
    pub pki: TestPki,
    log: Log,
    conn: Vec<String>,
}

impl Env {
    /// Starts a server with `routes`. `content_key` is written as the
    /// pinned content public key if given.
    pub fn new(routes: Vec<Route>, content_key: Option<&VerifyingKey>) -> Self {
        Self::with_trust(routes, content_key, false)
    }

    /// As [`Env::new`]; with `wrong_ca`, the CLI is given a CA that did
    /// not issue the server certificate.
    pub fn with_trust(
        routes: Vec<Route>,
        content_key: Option<&VerifyingKey>,
        wrong_ca: bool,
    ) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("usgp-cli-tls-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let pki = TestPki::generate().unwrap();
        let put = |name: &str, bytes: &[u8], mode: u32| {
            let p = dir.join(name);
            fs::write(&p, bytes).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
            p.to_str().unwrap().to_owned()
        };
        let anchor = if wrong_ca {
            &pki.untrusted_root
        } else {
            &pki.root
        };
        let ca = put("ca.pem", anchor.cert_pem().unwrap().as_bytes(), 0o644);
        let cert = put("operator.pem", &pki.client.chain_pem(), 0o644);
        let key = put("operator.key", &pki.client.key_pem().unwrap(), 0o600);
        let (addr, log) = start(&pki, routes);
        let mut conn = vec![
            "--server".to_owned(),
            format!("https://127.0.0.1:{}", addr.port()),
            "--server-ca".to_owned(),
            ca,
            "--client-cert".to_owned(),
            cert,
            "--client-key".to_owned(),
            key,
        ];
        if let Some(k) = content_key {
            let pubk = put("content.pub", k.to_spki_pem().unwrap().as_bytes(), 0o644);
            conn.extend(["--content-key-pub".to_owned(), pubk]);
        }
        Self {
            dir,
            pki,
            log,
            conn,
        }
    }

    /// Runs the CLI with `args` plus the connection options, feeding
    /// `stdin`.
    pub fn run(&self, args: &[&str], stdin: &[u8]) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_usgp-cli"))
            .args(args)
            .args(&self.conn)
            .env("HOME", &self.dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // The CLI may exit before reading; a broken pipe is fine.
        let _ = child.stdin.take().unwrap().write_all(stdin);
        child.wait_with_output().unwrap()
    }

    /// Requests received so far.
    pub fn seen(&self) -> Vec<Seen> {
        self.log.lock().unwrap().clone()
    }

    /// Hex SHA-256 of the operator certificate the CLI presents.
    pub fn operator_sha256(&self) -> String {
        self.pki.client.peer_certificate().unwrap().sha256.to_hex()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}
