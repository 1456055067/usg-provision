//! Test harness for the agent: the real `usgp-api` (in-process, on the
//! in-memory store, real TLS on 127.0.0.1 with the test PKI, the
//! production WIM checker), a synthetic WIM and PE from the `usgp-image`
//! testkit, a scripted console on channels, and disk files under
//! `CARGO_TARGET_TMPDIR` (never a block device).
//!
//! Declared `mod common` by each test binary, so helpers one binary does
//! not use are allowed to be unused there.

#![cfg(test)]
#![cfg(not(windows))]
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use usgp_api::{Api, ApiConfig, ContentKeys, ProvisioningKeys, TlsAcceptorHandle, WimChecker};
use usgp_audit::{Actor, AuditChain, AuditDraft, AuditRecord, Interface, Outcome};
use usgp_crypto::test_pki::{LeafSpec, TestPki};
use usgp_crypto::tls::{
    BlockingClientTls, DeviceServerTls, DeviceServerTlsSettings, ServerTls, TlsMinVersion,
};
use usgp_crypto::{HmacKey, SigningKey, VerifyingKey};
use usgp_db::{BootService, MemoryStore, Operator, OperatorRole, OperatorStatus, RepoTx, Store};
use usgp_image::Compression;
use usgp_image::testkit::{NodeSpec, TreeSpec, WimBuilder};
use usgp_preboot_agent::config::{self, AgentConfig};
use usgp_preboot_agent::ui::{Console, ConsoleClosed};
use usgp_proto::ops::{BootServiceStatus, IpCidr, SubnetList};
use usgp_proto::{
    BootServiceId, ContentId, ContentState, DisplayName, OperatorId, PackageId, UnixMicros,
};
use zeroize::Zeroizing;

/// 10⁹ bytes.
pub const GB: u64 = 1_000_000_000;

/// A fresh directory under the test target directory.
pub fn temp_dir(tag: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let d = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("agent-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A sparse disk file of `size` bytes (all zero).
pub fn disk_file(dir: &Path, name: &str, size: u64) -> PathBuf {
    let p = dir.join(name);
    let f = std::fs::File::create(&p).unwrap();
    f.set_len(size).unwrap();
    p
}

/// SHA-256 of the first and last `n` bytes of a file (the regions a GPT
/// write touches), plus its length.
pub fn ends_digest(p: &Path, n: u64) -> String {
    use std::io::{Seek, SeekFrom};
    let mut f = std::fs::File::open(p).unwrap();
    let len = f.metadata().unwrap().len();
    let mut head = vec![0u8; usize::try_from(n.min(len)).unwrap()];
    f.read_exact(&mut head).unwrap();
    f.seek(SeekFrom::Start(len - n.min(len))).unwrap();
    let mut tail = vec![0u8; usize::try_from(n.min(len)).unwrap()];
    f.read_exact(&mut tail).unwrap();
    head.extend_from_slice(&tail);
    format!("{len}:{}", usgp_crypto::sha256(&head).to_hex())
}

/// The whole file's SHA-256.
pub fn file_digest(p: &Path) -> String {
    usgp_crypto::sha256(&std::fs::read(p).unwrap()).to_hex()
}

/// The synthetic image: edition 1 holds a small tree.
pub fn image_wim() -> Vec<u8> {
    WimBuilder::new(Compression::Xpress)
        .tree_image(
            "Windows Test Enterprise",
            "Synthetic edition",
            TreeSpec::new(vec![
                NodeSpec::dir(
                    "Windows",
                    vec![NodeSpec::file("readme.txt", b"applied by the agent\n")],
                ),
                NodeSpec::file("hello.txt", b"hello from the synthetic image\n"),
            ]),
        )
        .build()
        .unwrap()
        .0
}

/// The synthetic Windows PE (x64, boot index 1).
pub fn pe_wim() -> Vec<u8> {
    WimBuilder::new(Compression::Xpress)
        .image("Microsoft Windows PE (amd64)", "PE")
        .boot_index(1)
        .build()
        .unwrap()
        .0
}

/// A response from the operator listener.
#[derive(Debug)]
pub struct OpResp {
    pub status: u16,
    pub body: Vec<u8>,
}

impl OpResp {
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

/// The running server.
pub struct Server {
    pub rt: tokio::runtime::Runtime,
    pub pki: TestPki,
    pub store: MemoryStore,
    pub api: Api<MemoryStore>,
    pub op_addr: SocketAddr,
    pub dev_addr: SocketAddr,
    pub dir: PathBuf,
    pub content_pub: VerifyingKey,
    pub plan_pub: VerifyingKey,
    shutdown: Vec<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        for s in self.shutdown.drain(..) {
            let _ = s.send(());
        }
    }
}

fn operator(pki: &TestPki) -> Operator {
    let pc = pki.client.peer_certificate().unwrap();
    Operator {
        id: OperatorId::from_random_bytes([1; 16]),
        display_name: DisplayName::new("Admin One").unwrap(),
        cert_sha256: pc.sha256,
        cert_subject: pc.subject.clone(),
        cert_issuer: pc.issuer.clone(),
        cert_serial: pc.serial.clone(),
        cert_not_after: UnixMicros::new(4_000_000_000_000_000).unwrap(),
        role: Some(OperatorRole::Administrator),
        status: OperatorStatus::Active,
        created_at: UnixMicros::new(1).unwrap(),
        created_by: "uid:0".to_owned(),
    }
}

impl Server {
    /// Starts the operator and device listeners.
    pub fn start() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let dir = temp_dir("server");
        let pki = TestPki::generate().unwrap();
        let store = MemoryStore::new();
        let chain = AuditChain::new("test-node").unwrap();
        let audit_key = SigningKey::generate().unwrap();
        let op = operator(&pki);
        rt.block_on(async {
            let mut tx = store.begin().await.unwrap();
            chain
                .ensure_genesis(&mut tx, &audit_key.key_id())
                .await
                .unwrap();
            tx.insert_operator(&op).await.unwrap();
            let d = AuditDraft::new(
                "operator.enrolled",
                Outcome::Success,
                Actor::local_user(0, None),
                Interface::ServerCli,
            )
            .target("operator", &op.id.to_string());
            chain.append(&mut tx, &d).await.unwrap();
            tx.commit().await.unwrap();
        });
        let content_key = SigningKey::generate().unwrap();
        let content_pub = content_key.verifying_key().clone();
        let keys = ContentKeys::new(content_key, vec![content_pub.clone()]).unwrap();
        let mut cfg = ApiConfig::new(dir.join("content"));
        cfg.device.enabled = true;
        cfg.device.poll_ms = 500;
        cfg.device.max_pending_sessions_per_ip = 64;
        cfg.device.session_opens_per_ip_per_min = 1000;
        cfg.device.code_attempts_per_ip_per_min = 1000;
        cfg.unauth_records_per_source_per_min = 10_000;
        cfg.unauth_records_global_per_min = 100_000;
        let plan_key = SigningKey::generate().unwrap();
        let plan_pub = plan_key.verifying_key().clone();
        let provisioning = ProvisioningKeys::new(
            plan_key,
            SigningKey::generate().unwrap(),
            HmacKey::from_key_file(&HmacKey::generate_key_bytes().unwrap()).unwrap(),
        )
        .unwrap();
        let api = Api::builder(store.clone(), cfg, chain, keys)
            .checker(Arc::new(WimChecker::new(usgp_image::WimLimits::DEFAULT)))
            .provisioning_keys(provisioning)
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
        let device_tls = Arc::new(
            DeviceServerTls::new(&DeviceServerTlsSettings {
                cert_chain_pem: pki.server.chain_pem(),
                private_key_pem: pki.server.key_pem().unwrap(),
                min_version: TlsMinVersion::Tls12,
            })
            .unwrap(),
        );
        let (op_listener, dev_listener) = rt.block_on(async {
            (
                tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
                tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(),
            )
        });
        let op_addr = op_listener.local_addr().unwrap();
        let dev_addr = dev_listener.local_addr().unwrap();
        let (tx1, rx1) = tokio::sync::oneshot::channel::<()>();
        let (tx2, rx2) = tokio::sync::oneshot::channel::<()>();
        let a1 = api.clone();
        rt.spawn(async move {
            let _ = usgp_api::serve(a1, op_listener, tls, async {
                let _ = rx1.await;
            })
            .await;
        });
        let a2 = api.clone();
        rt.spawn(async move {
            let _ = usgp_api::serve_device(a2, dev_listener, device_tls, async {
                let _ = rx2.await;
            })
            .await;
        });
        Self {
            rt,
            pki,
            store,
            api,
            op_addr,
            dev_addr,
            dir,
            content_pub,
            plan_pub,
            shutdown: vec![tx1, tx2],
        }
    }

    /// The agent configuration for this server (keys pinned in memory).
    pub fn agent_config(&self, plan_pub: &VerifyingKey) -> AgentConfig {
        config::from_parts(
            &format!("https://127.0.0.1:{}", self.dev_addr.port()),
            Some("localhost"),
            self.pki.root.cert_pem().unwrap().into_bytes(),
            plan_pub.to_spki_pem().unwrap().as_bytes(),
            self.content_pub.to_spki_pem().unwrap().as_bytes(),
            Some(10),
            Some(5),
        )
        .unwrap()
    }

    /// One operator request (mTLS as the administrator, one connection).
    pub fn op(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<(&str, &[u8])>,
    ) -> OpResp {
        let tls = BlockingClientTls::new(
            &self
                .pki
                .client_settings(Some(&self.pki.client), TlsMinVersion::Tls12)
                .unwrap(),
        )
        .unwrap();
        let tcp = TcpStream::connect(self.op_addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let mut s = tls.connect(tcp, "localhost").unwrap();
        let mut head =
            format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
        for (k, v) in headers {
            head.push_str(&format!("{k}: {v}\r\n"));
        }
        let data = match body {
            Some((ct, b)) => {
                head.push_str(&format!(
                    "Content-Type: {ct}\r\nContent-Length: {}\r\n",
                    b.len()
                ));
                b
            }
            None => &[][..],
        };
        head.push_str("\r\n");
        s.write_all(head.as_bytes()).unwrap();
        s.write_all(data).unwrap();
        s.flush().unwrap();
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        let mut hs = [httparse::EMPTY_HEADER; 64];
        let mut r = httparse::Response::new(&mut hs);
        let n = match r.parse(&out).unwrap() {
            httparse::Status::Complete(n) => n,
            httparse::Status::Partial => panic!("partial response"),
        };
        OpResp {
            status: r.code.unwrap(),
            body: out.get(n..).unwrap_or_default().to_vec(),
        }
    }

    /// A JSON operator request.
    pub fn op_json(&self, method: &str, path: &str, v: serde_json::Value) -> OpResp {
        let b = serde_json::to_vec(&v).unwrap();
        self.op(method, path, &[], Some(("application/json", &b)))
    }

    /// Uploads `data` and waits for Ready.
    pub fn ready(&self, kind: &str, name: &str, data: &[u8], pe: bool) -> ContentId {
        let mut v = serde_json::json!({
            "kind": kind, "display_name": name, "file_name": format!("{name}.wim"),
            "size": data.len(), "sha256": usgp_crypto::sha256(data).to_hex(),
        });
        if pe {
            v["pe_declaration"] =
                serde_json::json!({"architecture": "x64", "kit_version": "10.1.26100.1"});
        }
        let r = self.op_json("POST", "/v1/uploads", v);
        assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
        let j = r.json();
        let upload = j["upload_id"].as_str().unwrap().to_owned();
        let id = ContentId::parse(j["content_id"].as_str().unwrap()).unwrap();
        let r = self.op(
            "PUT",
            &format!("/v1/uploads/{upload}"),
            &[],
            Some(("application/octet-stream", data)),
        );
        assert_eq!(r.status, 202, "{}", String::from_utf8_lossy(&r.body));
        let t0 = Instant::now();
        loop {
            let c = self.rt.block_on(async {
                let mut tx = self.store.begin().await.unwrap();
                let c = tx.content(id).await.unwrap().unwrap();
                tx.rollback().await;
                c
            });
            if !c.state.is_in_progress() {
                assert_eq!(c.state, ContentState::Ready, "{:?}", c.reason);
                return id;
            }
            assert!(t0.elapsed() < Duration::from_secs(60), "content not ready");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// A Ready package of the synthetic image, assigned to a boot service
    /// serving 127.0.0.0/8. Returns the package id.
    pub fn ready_package(&self) -> PackageId {
        let image = self.ready("image", "Image", &image_wim(), false);
        let pe = self.ready("pe", "PE", &pe_wim(), true);
        let r = self.op_json(
            "PUT",
            &format!("/v1/images/{image}/editions/1/declaration"),
            serde_json::json!({"release": "windows-11", "edition": "enterprise", "architecture": "x64"}),
        );
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let r = self.op_json(
            "POST",
            "/v1/packages",
            serde_json::json!({
                "name": "Windows Test", "image_id": image.to_string(),
                "edition_index": 1, "pe_id": pe.to_string()
            }),
        );
        assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
        let pkg = PackageId::parse(r.json()["id"].as_str().unwrap()).unwrap();
        let bs = self.enrol_boot_service();
        let etag = usgp_api::assignment_etag(&[]);
        let b = serde_json::to_vec(&serde_json::json!({"package_ids": [pkg.to_string()]})).unwrap();
        let r = self.op(
            "PUT",
            &format!("/v1/boot-services/{bs}/packages"),
            &[("If-Match", &etag)],
            Some(("application/json", &b)),
        );
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        pkg
    }

    /// A boot service on 127.0.0.0/8, enrolled as the server command does.
    pub fn enrol_boot_service(&self) -> BootServiceId {
        let relay = self
            .pki
            .intermediate
            .issue(&LeafSpec::client("relay one"))
            .unwrap();
        let mut idb = [0u8; 16];
        usgp_crypto::fill_random(&mut idb).unwrap();
        let b = BootService {
            id: BootServiceId::from_random_bytes(idb),
            name: DisplayName::new("Relay One").unwrap(),
            cert_sha256: relay.peer_certificate().unwrap().sha256,
            cert_not_after: UnixMicros::new(4_000_000_000_000_000).unwrap(),
            served_subnets: SubnetList::new(vec![IpCidr::parse("127.0.0.0/8").unwrap()]).unwrap(),
            status: BootServiceStatus::Active,
            created_at: UnixMicros::new(1).unwrap(),
            created_by: "uid:0".to_owned(),
        };
        self.rt.block_on(async {
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
            // The device listener admits connections only from sources a
            // cached active boot service serves (SEC-001, group A round 2).
            // Its table was loaded at start and a miss reloads it at most
            // once a second, so a device connecting just after enrolment
            // was closed during the TLS handshake. Reload it now, as the
            // listener's own refresh would within `boot_service_refresh`.
            self.api.refresh_device_boot_services().await.unwrap();
        });
        b.id
    }

    /// Issues an operator code.
    pub fn issue_code(&self) -> String {
        let r = self.op_json("POST", "/v1/auth-codes", serde_json::json!({}));
        assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
        r.json()["code"].as_str().unwrap().to_owned()
    }

    /// Approves the waiting session showing `display`.
    pub fn approve(&self, display: &str) {
        let r = self.op("GET", "/v1/device-sessions", &[], None);
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        let j = r.json();
        let list = j
            .get("sessions")
            .or_else(|| j.get("items"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let id = list
            .iter()
            .find(|s| s["display_code"] == display)
            .and_then(|s| s["id"].as_str().or_else(|| s["session_id"].as_str()))
            .unwrap_or_else(|| panic!("no session with {display}: {j}"))
            .to_owned();
        let r = self.op_json(
            "POST",
            &format!("/v1/device-sessions/{id}/approve"),
            serde_json::json!({ "display_code": display }),
        );
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    }

    /// Every audit record.
    pub fn records(&self) -> Vec<AuditRecord> {
        self.store.audit_records()
    }

    /// Records of `event`.
    pub fn events(&self, event: &str) -> Vec<AuditRecord> {
        self.records()
            .into_iter()
            .filter(|r| r.event == event)
            .collect()
    }

    /// Every job.
    pub fn jobs(&self) -> Vec<usgp_db::Job> {
        self.rt.block_on(async {
            let mut tx = self.store.begin().await.unwrap();
            let j = tx.list_jobs(&[]).await.unwrap();
            tx.rollback().await;
            j
        })
    }
}

/// The agent side of a scripted console.
pub struct ChannelConsole {
    screens: Sender<String>,
    lines: Receiver<String>,
    /// Every echo change, in order.
    pub echo: Arc<Mutex<Vec<bool>>>,
}

impl Console for ChannelConsole {
    fn show(&mut self, text: &str) {
        let _ = self.screens.send(text.to_owned());
    }

    fn line(&mut self, wait: Duration) -> Result<Option<Zeroizing<String>>, ConsoleClosed> {
        match self.lines.recv_timeout(wait) {
            Ok(l) => Ok(Some(Zeroizing::new(l))),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(ConsoleClosed),
        }
    }

    fn set_echo(&mut self, on: bool) -> Result<(), &'static str> {
        self.echo.lock().unwrap().push(on);
        Ok(())
    }
}

/// The test side of a scripted console.
pub struct Driver {
    screens: Receiver<String>,
    lines: Option<Sender<String>>,
    /// Every screen seen so far.
    pub seen: Vec<String>,
}

/// A console pair.
pub fn console() -> (ChannelConsole, Driver, Arc<Mutex<Vec<bool>>>) {
    let (stx, srx) = mpsc::channel();
    let (ltx, lrx) = mpsc::channel();
    let echo = Arc::new(Mutex::new(Vec::new()));
    (
        ChannelConsole {
            screens: stx,
            lines: lrx,
            echo: Arc::clone(&echo),
        },
        Driver {
            screens: srx,
            lines: Some(ltx),
            seen: Vec::new(),
        },
        echo,
    )
}

impl Driver {
    /// Waits (up to 120 s) for a screen containing `needle`.
    pub fn wait_for(&mut self, needle: &str) -> String {
        let t0 = Instant::now();
        loop {
            let left = Duration::from_secs(120).saturating_sub(t0.elapsed());
            match self.screens.recv_timeout(left) {
                Ok(s) => {
                    self.seen.push(s.clone());
                    if s.contains(needle) {
                        return s;
                    }
                }
                Err(_) => panic!(
                    "no screen with {needle:?}; last: {}",
                    self.seen.last().cloned().unwrap_or_default()
                ),
            }
        }
    }

    /// Types a line.
    pub fn send(&self, line: &str) {
        if let Some(l) = &self.lines {
            let _ = l.send(line.to_owned());
        }
    }

    /// Closes the input (the agent sees the console closed).
    pub fn close(&mut self) {
        self.lines = None;
    }

    /// Drains the remaining screens (after the agent ended).
    pub fn drain(&mut self) {
        while let Ok(s) = self.screens.try_recv() {
            self.seen.push(s);
        }
    }

    /// Every screen as one text.
    pub fn all(&self) -> String {
        self.seen.join("\n")
    }
}

/// The display code on an authorisation screen.
pub fn display_code(screen: &str) -> String {
    screen
        .lines()
        .find_map(|l| l.strip_prefix("Display code:"))
        .map(|s| s.trim().to_owned())
        .unwrap()
}

/// A test MAC.
pub fn mac(n: u8) -> usgp_proto::MacAddress {
    usgp_proto::MacAddress::new([0x02, 0, 0, 0, 0x10, n]).unwrap()
}
