//! Test harness: the API on the in-memory store, served over real mutual
//! TLS on 127.0.0.1 with the test PKI, plus a small HTTPS client.
//!
//! Content checks use [`FakeChecker`] (the WIM builder is not a
//! dev-dependency of this crate; see the WU-6 notes); one test per file
//! runs the production [`usgp_api::WimChecker`] on non-WIM bytes.
//!
//! "WIM" files for the fake checker are `FAKEWIM:<n>:<anything>`, with
//! `n` editions; `BAD...` fails the check with `wim_not_wim`; `STALL...`
//! never makes progress.

use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use usgp_api::{
    Api, ApiConfig, CheckReport, ContentChecker, ContentKeys, ProvisioningKeys, TlsAcceptorHandle,
};
use usgp_audit::memory::ManualClock;
use usgp_audit::{Actor, AuditChain, AuditDraft, AuditRecord, Interface, Outcome};
use usgp_crypto::test_pki::{LeafSpec, TestCert, TestPki};
use usgp_crypto::tls::{
    ClientTls, DeviceServerTls, DeviceServerTlsSettings, ServerTls, TlsMinVersion,
};
use usgp_crypto::{EscrowKey, EscrowPublicKey, HmacKey, SigningKey, VerifyingKey};
use usgp_db::BootService;
use usgp_db::{MemoryStore, Operator, OperatorRole, OperatorStatus, RepoTx, Store};
use usgp_image::facts::{FileFact, FileFacts};
use usgp_image::{Compression, EditionInfo, Progress, WimError, WimSummary};
use usgp_proto::disk::{Bus, DiskDescriptorParts, ExistingPartitionV1, PartitionKind};
use usgp_proto::ops::{BootServiceStatus, IpCidr, SubnetList};
use usgp_proto::{
    AgentNonce, BootServiceId, ContentId, ContentKind, ContentState, DiskDescriptorV1, DiskText,
    DiskToken, DisplayName, OperatorId, PartitionLabel, UnixMicros,
};

/// Fake content checker.
#[derive(Debug)]
pub struct FakeChecker {
    /// Facts every image states (default: none).
    pub facts: Mutex<FileFacts>,
}

impl Default for FakeChecker {
    fn default() -> Self {
        Self {
            facts: Mutex::new(FileFacts {
                release: FileFact::NotStated,
                edition: FileFact::NotStated,
                architecture: FileFact::NotStated,
            }),
        }
    }
}

impl ContentChecker for FakeChecker {
    fn check(
        &self,
        path: &Path,
        kind: ContentKind,
        progress: &mut dyn Progress,
    ) -> Result<CheckReport, WimError> {
        let bytes = std::fs::read(path).map_err(|e| WimError::Io(e.kind()))?;
        if bytes.starts_with(b"STALL") {
            loop {
                std::thread::sleep(Duration::from_millis(10));
                if progress.advance(0).is_break() {
                    return Err(WimError::Stalled);
                }
            }
        }
        let text = String::from_utf8_lossy(&bytes[..bytes.len().min(32)]).into_owned();
        let n: u32 = text
            .strip_prefix("FAKEWIM:")
            .and_then(|r| r.split(':').next())
            .and_then(|n| n.parse().ok())
            .ok_or(WimError::NotWim)?;
        if progress.advance(u64::try_from(bytes.len()).unwrap()) == ControlFlow::Break(()) {
            return Err(WimError::Stalled);
        }
        let summary = WimSummary {
            image_count: n,
            compression: Compression::Xpress,
            boot_index: u32::from(kind == ContentKind::Pe),
            has_integrity_table: false,
            raw_sized_file_chunks: 0,
            version: 0x0001_0d00,
            editions: (1..=n)
                .map(|i| EditionInfo {
                    index: i,
                    name: format!("Edition {i}"),
                    description: format!("Description {i}"),
                    total_bytes: Some(1000 * u64::from(i)),
                })
                .collect(),
            xml_images: Vec::new(),
        };
        let facts = *self.facts.lock().unwrap();
        Ok(CheckReport {
            summary,
            usable_index: (kind == ContentKind::Pe).then_some(1),
            file_facts: vec![facts; usize::try_from(n).unwrap()],
        })
    }

    fn file_facts(&self, _path: &Path, _index: u32) -> Result<FileFacts, WimError> {
        Ok(*self.facts.lock().unwrap())
    }
}

/// Verifies signed envelopes with one pinned public key (what the CLI
/// does with `--content-key-pub`).
pub struct Pinned(pub VerifyingKey);

impl usgp_proto::SignatureVerifier for Pinned {
    fn verify(
        &self,
        key_id: &usgp_common::Sha256Digest,
        _alg: usgp_proto::SignatureAlg,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        self.0.key_id().0 == *key_id
            && usgp_crypto::verify_signing_input(&self.0, message, signature).is_ok()
    }
}

/// Who makes a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Who {
    /// The administrator.
    Admin,
    /// A second administrator.
    Admin2,
    /// An enrolled operator with no role.
    NoRole,
    /// An enrolled, disabled administrator.
    Disabled,
    /// A valid certificate that is not enrolled.
    Unknown,
    /// No certificate.
    Anonymous,
    /// An escrow officer (M4).
    Officer,
}

/// A response.
#[derive(Debug)]
pub struct Resp {
    pub status: u16,
    pub headers: hyper::HeaderMap,
    pub body: Vec<u8>,
}

impl Resp {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(&self.body)))
    }

    pub fn code(&self) -> String {
        self.json()["error"]["code"]
            .as_str()
            .unwrap_or("")
            .to_owned()
    }

    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .get(name)
            .map(|v| v.to_str().unwrap().to_owned())
    }
}

/// Settings a test can change before start.
pub struct Opts {
    pub config: Box<dyn FnOnce(&mut ApiConfig) + Send>,
    pub checker: Option<Arc<dyn ContentChecker>>,
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            config: Box::new(|_| {}),
            checker: None,
        }
    }
}

/// A running API.
pub struct Harness {
    pub pki: TestPki,
    pub store: MemoryStore,
    pub api: Api<MemoryStore>,
    pub addr: SocketAddr,
    pub dir: PathBuf,
    pub norole: TestCert,
    pub disabled: TestCert,
    pub unknown: TestCert,
    pub admin2: TestCert,
    pub admin_id: OperatorId,
    pub content_pub: VerifyingKey,
    pub fake: Arc<FakeChecker>,
    /// The API's clock (records and expiry).
    pub clock: Arc<ManualClock>,
    /// The API's TLS acceptor (CRL reload tests).
    pub tls: Arc<TlsAcceptorHandle>,
    /// The device listener (M3), server authentication only.
    pub device_addr: SocketAddr,
    /// The plan key's public half (what the agent pins).
    pub plan_pub: VerifyingKey,
    /// The boot-policy key's public half (what the relay pins).
    pub policy_pub: VerifyingKey,
    /// The escrow officer's certificate (M4).
    pub officer: TestCert,
    /// The escrow key's public half (what a v2 plan carries, M4).
    pub escrow_pub: EscrowPublicKey,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    device_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(s) = self.shutdown.take() {
            let _ = s.send(());
        }
        if let Some(s) = self.device_shutdown.take() {
            let _ = s.send(());
        }
        let _ = make_writable(&self.dir);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn make_writable(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for e in std::fs::read_dir(dir)? {
        let p = e?.path();
        if p.is_dir() {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700))?;
            make_writable(&p)?;
        } else {
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

fn operator(
    cert: &TestCert,
    name: &str,
    role: Option<OperatorRole>,
    status: OperatorStatus,
    n: u8,
) -> Operator {
    let pc = cert.peer_certificate().unwrap();
    Operator {
        id: OperatorId::from_random_bytes([n; 16]),
        display_name: DisplayName::new(name).unwrap(),
        cert_sha256: pc.sha256,
        cert_subject: pc.subject.clone(),
        cert_issuer: pc.issuer.clone(),
        cert_serial: pc.serial.clone(),
        cert_not_after: UnixMicros::new(4_000_000_000_000_000).unwrap(),
        role,
        status,
        created_at: UnixMicros::new(1).unwrap(),
        created_by: "uid:0".to_owned(),
    }
}

impl Harness {
    pub async fn start() -> Self {
        Self::with(Opts::default()).await
    }

    pub async fn with(opts: Opts) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("usgp-api-t-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let pki = TestPki::generate().unwrap();
        let norole = pki
            .intermediate
            .issue(&LeafSpec::client("operator norole"))
            .unwrap();
        let disabled = pki
            .intermediate
            .issue(&LeafSpec::client("operator disabled"))
            .unwrap();
        let unknown = pki
            .intermediate
            .issue(&LeafSpec::client("operator unknown"))
            .unwrap();
        let admin2 = pki
            .intermediate
            .issue(&LeafSpec::client("operator two"))
            .unwrap();
        let officer = pki
            .intermediate
            .issue(&LeafSpec::client("operator officer"))
            .unwrap();

        let store = MemoryStore::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        let clock = Arc::new(ManualClock::new(i64::try_from(now.as_micros()).unwrap()));
        let chain = AuditChain::with_clock(
            "test-node",
            Arc::clone(&clock) as Arc<dyn usgp_audit::Clock>,
        )
        .unwrap();
        let audit_key = SigningKey::generate().unwrap();
        let mut tx = store.begin().await.unwrap();
        chain
            .ensure_genesis(&mut tx, &audit_key.key_id())
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let admin = operator(
            &pki.client,
            "Admin One",
            Some(OperatorRole::Administrator),
            OperatorStatus::Active,
            1,
        );
        let admin_id = admin.id;
        let mut tx = store.begin().await.unwrap();
        for op in [
            admin,
            operator(&norole, "No Role", None, OperatorStatus::Active, 2),
            operator(
                &admin2,
                "Admin Two",
                Some(OperatorRole::Administrator),
                OperatorStatus::Active,
                4,
            ),
            operator(
                &disabled,
                "Disabled Admin",
                Some(OperatorRole::Administrator),
                OperatorStatus::Disabled,
                3,
            ),
            operator(
                &officer,
                "Escrow Officer",
                Some(OperatorRole::EscrowOfficer),
                OperatorStatus::Active,
                5,
            ),
        ] {
            tx.insert_operator(&op).await.unwrap();
            let d = AuditDraft::new(
                "operator.enrolled",
                Outcome::Success,
                Actor::local_user(0, None),
                Interface::ServerCli,
            )
            .target("operator", &op.id.to_string());
            chain.append(&mut tx, &d).await.unwrap();
        }
        tx.commit().await.unwrap();

        let content_key = SigningKey::generate().unwrap();
        let content_pub = content_key.verifying_key().clone();
        let keys = ContentKeys::new(content_key, vec![content_pub.clone()]).unwrap();
        let mut config = ApiConfig::new(dir.join("content"));
        config.device.enabled = true;
        (opts.config)(&mut config);
        let fake = Arc::new(FakeChecker::default());
        let plan_key = SigningKey::generate().unwrap();
        let policy_key = SigningKey::generate().unwrap();
        let plan_pub = plan_key.verifying_key().clone();
        let policy_pub = policy_key.verifying_key().clone();
        let provisioning = ProvisioningKeys::new(
            plan_key,
            policy_key,
            HmacKey::from_key_file(&HmacKey::generate_key_bytes().unwrap()).unwrap(),
        )
        .unwrap();
        let checker: Arc<dyn ContentChecker> = match opts.checker {
            Some(c) => c,
            None => Arc::clone(&fake) as Arc<dyn ContentChecker>,
        };
        let escrow_key = EscrowKey::generate().unwrap();
        let escrow_pub = escrow_key.public();
        let api = Api::builder(store.clone(), config, chain, keys)
            .checker(checker)
            .provisioning_keys(provisioning)
            .escrow_keys(usgp_api::EscrowKeys::new(escrow_key, Vec::new()).unwrap())
            .build()
            .unwrap();

        let settings = pki
            .server_settings(
                pki.current_crls().unwrap(),
                Vec::new(),
                TlsMinVersion::Tls12,
            )
            .unwrap();
        let tls = Arc::new(TlsAcceptorHandle::new(ServerTls::new(&settings).unwrap()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx_s, rx_s) = tokio::sync::oneshot::channel::<()>();
        let serve_api = api.clone();
        let tls_handle = Arc::clone(&tls);
        tokio::spawn(async move {
            usgp_api::serve(serve_api, listener, tls, async {
                let _ = rx_s.await;
            })
            .await
            .unwrap();
        });
        let device_tls = Arc::new(
            DeviceServerTls::new(&DeviceServerTlsSettings {
                cert_chain_pem: pki.server.chain_pem(),
                private_key_pem: pki.server.key_pem().unwrap(),
                min_version: TlsMinVersion::Tls12,
            })
            .unwrap(),
        );
        let device_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let device_addr = device_listener.local_addr().unwrap();
        let (dtx_s, drx_s) = tokio::sync::oneshot::channel::<()>();
        let device_api = api.clone();
        tokio::spawn(async move {
            usgp_api::serve_device(device_api, device_listener, device_tls, async {
                let _ = drx_s.await;
            })
            .await
            .unwrap();
        });
        Self {
            pki,
            store,
            api,
            addr,
            dir,
            norole,
            disabled,
            unknown,
            admin2,
            admin_id,
            content_pub,
            fake,
            clock,
            tls: tls_handle,
            device_addr,
            plan_pub,
            policy_pub,
            officer,
            escrow_pub,
            shutdown: Some(tx_s),
            device_shutdown: Some(dtx_s),
        }
    }

    pub fn cert(&self, who: Who) -> Option<&TestCert> {
        match who {
            Who::Admin => Some(&self.pki.client),
            Who::Admin2 => Some(&self.admin2),
            Who::NoRole => Some(&self.norole),
            Who::Disabled => Some(&self.disabled),
            Who::Unknown => Some(&self.unknown),
            Who::Anonymous => None,
            Who::Officer => Some(&self.officer),
        }
    }

    /// A second server on the same store with other content keys (for
    /// example a key that did not sign the stored manifests).
    pub async fn second_server(&self, keys: ContentKeys) -> SocketAddr {
        let mut config = ApiConfig::new(self.dir.join("content"));
        config.limits = self.api.config().limits.clone();
        let api = Api::builder(
            self.store.clone(),
            config,
            AuditChain::new("test-node").unwrap(),
            keys,
        )
        .checker(Arc::clone(&self.fake) as Arc<dyn ContentChecker>)
        .build()
        .unwrap();
        let settings = self
            .pki
            .server_settings(
                self.pki.current_crls().unwrap(),
                Vec::new(),
                TlsMinVersion::Tls12,
            )
            .unwrap();
        let tls = Arc::new(TlsAcceptorHandle::new(ServerTls::new(&settings).unwrap()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = usgp_api::serve(api, listener, tls, std::future::pending()).await;
        });
        addr
    }

    /// A TLS connection as `cert`.
    pub async fn connect(
        &self,
        cert: Option<&TestCert>,
    ) -> Result<usgp_crypto::tls::ClientTlsStream<TcpStream>, String> {
        self.connect_to(self.addr, cert).await
    }

    /// A TLS connection to `addr` as `cert`.
    pub async fn connect_to(
        &self,
        addr: SocketAddr,
        cert: Option<&TestCert>,
    ) -> Result<usgp_crypto::tls::ClientTlsStream<TcpStream>, String> {
        let tls = ClientTls::new(
            &self
                .pki
                .client_settings(cert, TlsMinVersion::Tls12)
                .unwrap(),
        )
        .unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        tls.connect(tcp, "localhost")
            .await
            .map_err(|e| e.to_string())
    }

    /// One request on a new connection.
    pub async fn req(
        &self,
        who: Who,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Resp {
        self.req_as(self.cert(who), method, path, headers, body)
            .await
    }

    pub async fn req_as(
        &self,
        cert: Option<&TestCert>,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Resp {
        self.req_at(self.addr, cert, method, path, headers, body)
            .await
    }

    pub async fn req_at(
        &self,
        addr: SocketAddr,
        cert: Option<&TestCert>,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Resp {
        let stream = self.connect_to(addr, cert).await.expect("tls connect");
        let (mut send, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut b = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost");
        let has_body = body.is_some();
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        if has_body
            && !headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            b = b.header("content-type", "application/json");
        }
        let req = b
            .body(Full::new(Bytes::from(body.unwrap_or_default())))
            .unwrap();
        let resp = send.send_request(req).await.expect("response");
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = match resp.into_body().collect().await {
            Ok(b) => b.to_bytes().to_vec(),
            Err(_) => b"<aborted>".to_vec(),
        };
        Resp {
            status,
            headers,
            body,
        }
    }

    pub async fn get(&self, who: Who, path: &str) -> Resp {
        self.req(who, "GET", path, &[], None).await
    }

    pub async fn post_json(&self, who: Who, path: &str, v: serde_json::Value) -> Resp {
        self.req(
            who,
            "POST",
            path,
            &[],
            Some(serde_json::to_vec(&v).unwrap()),
        )
        .await
    }

    /// Raw bytes on a new TLS connection; returns what the server sent
    /// before closing (or after `wait`).
    pub async fn raw(&self, who: Who, data: &[u8], close_after_write: bool) -> Vec<u8> {
        let mut s = self.connect(self.cert(who)).await.expect("tls connect");
        s.write_all(data).await.unwrap();
        s.flush().await.unwrap();
        if close_after_write {
            drop(s);
            return Vec::new();
        }
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
        out
    }

    // ------------------------------------------------------------ flows

    /// Creates an upload session for `data`.
    pub async fn create_upload(
        &self,
        kind: &str,
        name: &str,
        data: &[u8],
        pe: Option<(&str, &str)>,
    ) -> Resp {
        let mut v = serde_json::json!({
            "kind": kind,
            "display_name": name,
            "file_name": format!("{name}.wim"),
            "size": data.len(),
            "sha256": usgp_crypto::sha256(data).to_hex(),
        });
        if let Some((arch, kit)) = pe {
            v["pe_declaration"] = serde_json::json!({"architecture": arch, "kit_version": kit});
        }
        self.post_json(Who::Admin, "/v1/uploads", v).await
    }

    /// Uploads `data` fully and returns the content id (state Checking or
    /// later).
    pub async fn upload(
        &self,
        kind: &str,
        name: &str,
        data: &[u8],
        pe: Option<(&str, &str)>,
    ) -> ContentId {
        let r = self.create_upload(kind, name, data, pe).await;
        assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
        let j = r.json();
        let upload = j["upload_id"].as_str().unwrap().to_owned();
        let content = ContentId::parse(j["content_id"].as_str().unwrap()).unwrap();
        let r = self
            .req(
                Who::Admin,
                "PUT",
                &format!("/v1/uploads/{upload}"),
                &[("content-type", "application/octet-stream")],
                Some(data.to_vec()),
            )
            .await;
        assert_eq!(r.status, 202, "{}", String::from_utf8_lossy(&r.body));
        content
    }

    /// Waits until content `id` leaves Receiving/Checking.
    pub async fn wait_settled(&self, id: ContentId) -> usgp_db::Content {
        for _ in 0..500 {
            let mut tx = self.store.begin().await.unwrap();
            let c = tx.content(id).await.unwrap().unwrap();
            tx.rollback().await;
            if !c.state.is_in_progress() {
                return c;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("content {id} did not settle");
    }

    /// Uploads and waits for Ready.
    pub async fn ready(
        &self,
        kind: &str,
        name: &str,
        data: &[u8],
        pe: Option<(&str, &str)>,
    ) -> ContentId {
        let id = self.upload(kind, name, data, pe).await;
        let c = self.wait_settled(id).await;
        assert_eq!(c.state, ContentState::Ready, "{:?}", c.reason);
        id
    }

    /// A Ready image with `n` editions.
    pub async fn ready_image(&self, n: u32, tag: &str) -> ContentId {
        let data = format!("FAKEWIM:{n}:image {tag}").into_bytes();
        self.ready("image", &format!("Image {tag}"), &data, None)
            .await
    }

    /// A Ready x64 PE.
    pub async fn ready_pe(&self, tag: &str) -> ContentId {
        let data = format!("FAKEWIM:1:pe {tag}").into_bytes();
        self.ready(
            "pe",
            &format!("PE {tag}"),
            &data,
            Some(("x64", "10.1.26100.1")),
        )
        .await
    }

    /// Declares edition `index` of `image`.
    pub async fn declare(
        &self,
        image: ContentId,
        index: u32,
        rel: &str,
        ed: &str,
        arch: &str,
    ) -> Resp {
        self.req(
            Who::Admin,
            "PUT",
            &format!("/v1/images/{image}/editions/{index}/declaration"),
            &[],
            Some(
                serde_json::to_vec(&serde_json::json!({
                    "release": rel, "edition": ed, "architecture": arch
                }))
                .unwrap(),
            ),
        )
        .await
    }

    /// Creates a package.
    pub async fn create_package(
        &self,
        name: &str,
        image: ContentId,
        index: u32,
        pe: ContentId,
    ) -> Resp {
        self.post_json(
            Who::Admin,
            "/v1/packages",
            serde_json::json!({
                "name": name, "image_id": image.to_string(),
                "edition_index": index, "pe_id": pe.to_string()
            }),
        )
        .await
    }

    /// A Ready package (image with 3 editions, index 1 declared in scope,
    /// x64 PE).
    pub async fn ready_package(&self, tag: &str) -> (String, ContentId, ContentId) {
        let image = self.ready_image(3, tag).await;
        let pe = self.ready_pe(tag).await;
        let r = self
            .declare(image, 1, "windows-11", "enterprise", "x64")
            .await;
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let r = self
            .create_package(&format!("Package {tag}"), image, 1, pe)
            .await;
        assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
        assert_eq!(r.json()["status"], "ready");
        (r.json()["id"].as_str().unwrap().to_owned(), image, pe)
    }

    // ------------------------------------------------------------ audit

    pub fn records(&self) -> Vec<AuditRecord> {
        self.store.audit_records()
    }

    pub fn events(&self, event: &str) -> Vec<AuditRecord> {
        self.records()
            .into_iter()
            .filter(|r| r.event == event)
            .collect()
    }

    /// Waits until at least `n` records of `event` exist (records written
    /// after the response, such as the end of a download).
    pub async fn wait_events(&self, event: &str, n: usize) -> Vec<AuditRecord> {
        for _ in 0..300 {
            let v = self.events(event);
            if v.len() >= n {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("fewer than {n} {event} records: {:?}", self.events(event));
    }

    /// The whole state as a comparable snapshot (excluding the audit chain).
    pub async fn snapshot(&self) -> String {
        let mut tx = self.store.begin().await.unwrap();
        let content = tx.list_content(None, &[]).await.unwrap();
        let mut editions = Vec::new();
        for c in &content {
            editions.push(tx.editions(c.id).await.unwrap());
        }
        let uploads = tx.list_uploads(&[]).await.unwrap();
        let packages = tx.list_packages().await.unwrap();
        tx.rollback().await;
        format!("{content:?}\n{editions:?}\n{uploads:?}\n{packages:?}")
    }

    // --------------------------------------------------------------- M3

    /// A harness for device tests: per-source caps raised so one test
    /// can open several sessions from 127.0.0.1, and refusal records not
    /// capped (tests count them).
    pub async fn m3() -> Self {
        Self::with(Opts {
            config: Box::new(|c| {
                c.unauth_records_per_source_per_min = 10_000;
                c.unauth_records_global_per_min = 100_000;
                c.device.max_pending_sessions_per_ip = 64;
                c.device.session_opens_per_ip_per_min = 1000;
                c.device.code_attempts_per_ip_per_min = 1000;
                c.device.m4.resume_challenges_per_ip_per_min = 1000;
            }),
            ..Opts::default()
        })
        .await
    }

    /// A client certificate from the test PKI (for a relay).
    pub fn relay_cert(&self, name: &str) -> TestCert {
        self.pki
            .intermediate
            .issue(&LeafSpec::client(name))
            .unwrap()
    }

    /// Enrols a boot service bound to `cert`, as the server's
    /// administrative command does (audited).
    pub async fn enrol_boot_service(
        &self,
        cert: &TestCert,
        name: &str,
        subnets: &[&str],
        status: BootServiceStatus,
    ) -> BootServiceId {
        let b = BootService {
            id: BootServiceId::from_random_bytes(rand16()),
            name: DisplayName::new(name).unwrap(),
            cert_sha256: cert.peer_certificate().unwrap().sha256,
            cert_not_after: UnixMicros::new(4_000_000_000_000_000).unwrap(),
            served_subnets: SubnetList::new(
                subnets.iter().map(|s| IpCidr::parse(s).unwrap()).collect(),
            )
            .unwrap(),
            status,
            created_at: UnixMicros::new(1).unwrap(),
            created_by: "uid:0".to_owned(),
        };
        let mut tx = self.store.begin().await.unwrap();
        tx.insert_boot_service(&b).await.unwrap();
        let d = AuditDraft::new(
            "boot_service.enrolled",
            Outcome::Success,
            Actor::local_user(0, None),
            Interface::ServerCli,
        )
        .target("boot_service", &b.id.to_string());
        self.api.chain().append(&mut tx, &d).await.unwrap();
        tx.commit().await.unwrap();
        // The device listener admits connections by its served-subnet
        // table (finding SEC-001); the server reloads it periodically.
        self.api.refresh_device_boot_services().await.unwrap();
        b.id
    }

    /// An active boot service on 127.0.0.0/8 with nothing assigned, so
    /// the test device (127.0.0.1) may open a session: no session is
    /// opened without one (finding SEC-001).
    pub async fn loopback_service(&self, tag: &str) -> BootServiceId {
        let relay = self.relay_cert(&format!("relay {tag}"));
        self.enrol_boot_service(
            &relay,
            &format!("Loopback {tag}"),
            &["127.0.0.0/8"],
            BootServiceStatus::Active,
        )
        .await
    }

    /// Sets the packages of a boot service (reads the ETag first).
    pub async fn assign(&self, bs: BootServiceId, packages: &[&str]) -> Resp {
        let r = self
            .get(Who::Admin, &format!("/v1/boot-services/{bs}"))
            .await;
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let etag = r.header("etag").unwrap();
        self.req(
            Who::Admin,
            "PUT",
            &format!("/v1/boot-services/{bs}/packages"),
            &[("if-match", &etag)],
            Some(serde_json::to_vec(&serde_json::json!({ "package_ids": packages })).unwrap()),
        )
        .await
    }

    /// One request on the device listener (no client certificate).
    pub async fn dev_raw(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<Vec<u8>>,
    ) -> Resp {
        self.req_at(self.device_addr, None, method, path, headers, body)
            .await
    }

    /// A device request with the session token (if any) and a JSON body.
    pub async fn dev(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> Resp {
        let auth = token.map(|t| format!("Bearer {t}"));
        let mut headers = Vec::new();
        if let Some(a) = &auth {
            headers.push(("authorization", a.as_str()));
        }
        self.dev_raw(
            method,
            path,
            &headers,
            body.map(|b| serde_json::to_vec(&b).unwrap()),
        )
        .await
    }

    /// Opens a device session (UEFI, x64) with `macs`.
    pub async fn open_session(&self, macs: &[&str]) -> Opened {
        let r = self
            .dev("POST", "/v1/device/sessions", None, Some(hello(macs)))
            .await;
        assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
        let j = r.json();
        Opened {
            id: j["session_id"].as_str().unwrap().to_owned(),
            token: j["token"].as_str().unwrap().to_owned(),
            display_code: j["display_code"].as_str().unwrap().to_owned(),
        }
    }

    /// Issues a code; returns (id, code).
    pub async fn issue_code(&self) -> (String, String) {
        let r = self
            .post_json(Who::Admin, "/v1/auth-codes", serde_json::json!({}))
            .await;
        assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
        let j = r.json();
        (
            j["id"].as_str().unwrap().to_owned(),
            j["code"].as_str().unwrap().to_owned(),
        )
    }

    /// Submits a code.
    pub async fn submit_code(&self, token: &str, code: &str) -> Resp {
        self.dev(
            "POST",
            "/v1/device/session/code",
            Some(token),
            Some(serde_json::json!({ "code": code })),
        )
        .await
    }

    /// A boot service on 127.0.0.0/8 offering a Ready package, and a
    /// session from 127.0.0.1 authorised by a code, with the package and
    /// a 1 TB disk chosen.
    pub async fn ready_device(&self, tag: &str, macs: &[&str]) -> ReadyDevice {
        let relay = self.relay_cert(&format!("relay {tag}"));
        let bs = self
            .enrol_boot_service(
                &relay,
                &format!("Relay {tag}"),
                &["127.0.0.0/8"],
                BootServiceStatus::Active,
            )
            .await;
        let (pkg, _, _) = self.ready_package(tag).await;
        let r = self.assign(bs, &[&pkg]).await;
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let s = self.chosen_session(&pkg, macs).await;
        ReadyDevice {
            relay,
            bs,
            pkg,
            session: s.0,
            disk: s.1,
        }
    }

    /// A session authorised by a code with `pkg` and a 1 TB disk chosen.
    pub async fn chosen_session(&self, pkg: &str, macs: &[&str]) -> (Opened, DiskDescriptorV1) {
        let s = self.open_session(macs).await;
        let (_, code) = self.issue_code().await;
        let r = self.submit_code(&s.token, &code).await;
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let r = self
            .dev(
                "POST",
                "/v1/device/session/package",
                Some(&s.token),
                Some(serde_json::json!({ "package_id": pkg, "revision": 1 })),
            )
            .await;
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let d = disk(1_000_204_886_016, false, Bus::Nvme);
        let r = self.choose_disk(&s.token, &d).await;
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        (s, d)
    }

    /// Chooses a disk.
    pub async fn choose_disk(&self, token: &str, d: &DiskDescriptorV1) -> Resp {
        self.dev(
            "POST",
            "/v1/device/session/disk",
            Some(token),
            Some(serde_json::json!({ "disk": d })),
        )
        .await
    }

    /// Confirms the wipe.
    pub async fn confirm(
        &self,
        token: &str,
        pkg: &str,
        d: &DiskDescriptorV1,
        nonce: &AgentNonce,
    ) -> Resp {
        self.dev(
            "POST",
            "/v1/device/session/confirm",
            Some(token),
            Some(serde_json::json!({
                "package_id": pkg, "revision": 1, "disk_token": d.disk_token(),
                "confirm": "wipe-disk", "agent_nonce": nonce,
            })),
        )
        .await
    }

    /// A progress report.
    pub async fn report(&self, token: &str, job: &str, body: serde_json::Value) -> Resp {
        self.dev(
            "POST",
            &format!("/v1/device/jobs/{job}/progress"),
            Some(token),
            Some(body),
        )
        .await
    }

    /// Every audit record as text (for "no secret" checks).
    pub fn all_record_text(&self) -> String {
        self.records()
            .iter()
            .map(|r| format!("{r:?}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// An opened device session.
#[derive(Debug, Clone)]
pub struct Opened {
    pub id: String,
    pub token: String,
    pub display_code: String,
}

/// A device ready to confirm.
pub struct ReadyDevice {
    pub relay: TestCert,
    pub bs: BootServiceId,
    pub pkg: String,
    pub session: Opened,
    pub disk: DiskDescriptorV1,
}

/// 16 random bytes.
pub fn rand16() -> [u8; 16] {
    let mut b = [0u8; 16];
    usgp_crypto::fill_random(&mut b).unwrap();
    b
}

/// A device hello (UEFI, x64).
pub fn hello(macs: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "schema": 1, "agent_version": "0.3.0", "firmware": "uefi", "arch": "x64",
        "secure_boot": "on", "memory_bytes": 8_589_934_592u64, "macs": macs,
    })
}

/// A disk descriptor with one existing partition.
pub fn disk(size: u64, removable: bool, bus: Bus) -> DiskDescriptorV1 {
    DiskDescriptorV1::new(DiskDescriptorParts {
        disk_token: DiskToken::from_random_bytes(rand16()),
        bus,
        model: DiskText::sanitized("Example NVMe 1TB"),
        serial: DiskText::sanitized("SN-0001"),
        size_bytes: size,
        logical_sector: 512,
        physical_sector: 4096,
        removable,
        partitions: vec![ExistingPartitionV1 {
            index: 1,
            kind: PartitionKind::Basic,
            start_bytes: 1_048_576,
            size_bytes: 1_048_576,
            label: PartitionLabel::sanitized("Data"),
        }],
    })
    .unwrap()
}

/// A fresh agent nonce.
pub fn nonce() -> AgentNonce {
    let mut b = [0u8; 32];
    usgp_crypto::fill_random(&mut b).unwrap();
    AgentNonce::from_random_bytes(b)
}
