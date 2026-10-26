//! Shared helpers for the relay integration tests: scratch boot roots,
//! manifests built with `usgp-proto`, configuration documents, and an
//! in-memory UDP network implementing `TransferSocket`.
//!
//! Every fixture is generated here at test time (see
//! `tests/fixtures/SOURCE.md`). Nothing touches a real device or a real
//! network interface.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;
use usgp_common::config::TrustPolicy;
use usgp_proto::{BootFileName, BootManifest, ManifestEntry};
use usgp_relay::config::{
    BootDocument, ConfigDocument, InterfaceConfig, InterfaceDocument, RelayConfig,
};
use usgp_relay::content::ContentStore;
use usgp_relay::tftp::{SocketFactory, TransferSocket};

/// Name of the boot program in every fixture.
pub const PROGRAM: &str = "usgp-test-payload.efi";
/// Interface used by the tests.
pub const IFACE: &str = "relay0";
/// Its address.
pub const IFACE_ADDR: Ipv4Addr = Ipv4Addr::new(10, 20, 1, 2);

/// A uniquely named scratch directory, removed on drop.
pub struct Scratch {
    /// The directory (holds `root/` and the manifest).
    pub dir: PathBuf,
}

impl Scratch {
    /// Creates `<tmp>/usgp-relay-<tag>-<pid>-<n>/root`.
    pub fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "usgp-relay-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("root")).unwrap();
        set_mode(&dir, 0o755);
        set_mode(&dir.join("root"), 0o755);
        Self { dir }
    }

    /// The boot root.
    pub fn root(&self) -> PathBuf {
        self.dir.join("root")
    }

    /// The manifest path.
    pub fn manifest_path(&self) -> PathBuf {
        self.dir.join("boot-manifest.toml")
    }

    /// Writes a boot file below the root.
    pub fn write_boot_file(&self, name: &str, content: &[u8]) -> PathBuf {
        let p = self.root().join(name);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, content).unwrap();
        set_mode(&p, 0o644);
        p
    }

    /// Writes a manifest describing `files` (name, content).
    pub fn write_manifest(&self, files: &[(&str, &[u8])]) {
        let entries = files
            .iter()
            .map(|(name, content)| ManifestEntry {
                name: BootFileName::try_from(*name).unwrap(),
                size: u64::try_from(content.len()).unwrap(),
                sha256: usgp_crypto::sha256(content),
            })
            .collect();
        let m = BootManifest::new(entries).unwrap();
        std::fs::write(self.manifest_path(), m.to_toml()).unwrap();
        set_mode(&self.manifest_path(), 0o644);
    }

    /// Writes `files` to the root and a matching manifest.
    pub fn publish(&self, files: &[(&str, &[u8])]) {
        for (name, content) in files {
            self.write_boot_file(name, content);
        }
        self.write_manifest(files);
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

/// Deterministic pseudo-random bytes (xorshift), so fixtures need no
/// random-number crate.
pub fn bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

/// A minimal valid configuration document for `s`.
pub fn doc(s: &Scratch) -> ConfigDocument {
    ConfigDocument {
        schema_version: Some(1),
        interface: vec![InterfaceDocument {
            name: Some(IFACE.to_owned()),
            address: Some(IFACE_ADDR.to_string()),
            prefix_len: None,
        }],
        boot: Some(BootDocument {
            manifest: Some(s.manifest_path().display().to_string()),
            root: Some(s.root().display().to_string()),
            uefi_x64_program: Some(PROGRAM.to_owned()),
        }),
        ..ConfigDocument::default()
    }
}

/// The test's own uid. The relay trusts files owned by uid 0 or by the
/// administrator uid given with `--admin-uid`; the tests run as an
/// ordinary user, so that uid is configured as the administrator.
pub fn admin_uid() -> u32 {
    usgp_common::process::effective_uid().unwrap()
}

/// Trust policy naming the test's uid as the administrator uid.
pub fn trust() -> TrustPolicy {
    TrustPolicy::with_admin(admin_uid())
}

/// The validated configuration for `s`, trusting files owned by the
/// test's uid.
pub fn config(s: &Scratch) -> RelayConfig {
    let mut c = RelayConfig::from_document(&doc(s)).unwrap();
    c.trust = trust();
    c
}

/// Prefix length of the test interface's subnet (10.20.1.0/24).
pub const IFACE_PREFIX: u8 = 24;

/// The test interface (subnet 10.20.1.0/24).
pub fn iface() -> InterfaceConfig {
    InterfaceConfig {
        name: IFACE.to_owned(),
        address: IFACE_ADDR,
        prefix_len: Some(IFACE_PREFIX),
    }
}

/// Loads the content store for `cfg` and runs the start-up check.
pub async fn content(cfg: &RelayConfig) -> Arc<ContentStore> {
    let c = Arc::new(
        ContentStore::load(
            &cfg.boot.manifest,
            &cfg.boot.root,
            &cfg.boot.uefi_x64_program,
            cfg.tftp.max_file_size,
            cfg.limits.verify_concurrency,
            &cfg.trust,
        )
        .unwrap(),
    );
    c.recheck_all("startup").await;
    c
}

// ---------------------------------------------------------------------------
// In-memory UDP
// ---------------------------------------------------------------------------

type Datagram = (Vec<u8>, SocketAddr);

/// A tiny in-memory UDP network: datagrams to an unbound address vanish,
/// like UDP.
#[derive(Default)]
pub struct MemNet {
    routes: Mutex<HashMap<SocketAddr, mpsc::UnboundedSender<Datagram>>>,
    next_port: AtomicU16,
}

impl MemNet {
    /// An empty network.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            routes: Mutex::new(HashMap::new()),
            next_port: AtomicU16::new(40_000),
        })
    }

    /// Binds a socket at `ip`, on a fresh port.
    pub fn bind(self: &Arc<Self>, ip: IpAddr) -> MemSocket {
        let port = self.next_port.fetch_add(1, Ordering::Relaxed);
        self.bind_at(SocketAddr::new(ip, port))
    }

    /// Binds a socket at `addr`.
    pub fn bind_at(self: &Arc<Self>, addr: SocketAddr) -> MemSocket {
        let (tx, rx) = mpsc::unbounded_channel();
        self.routes.lock().unwrap().insert(addr, tx);
        MemSocket {
            addr,
            net: Arc::clone(self),
            rx: tokio::sync::Mutex::new(rx),
        }
    }

    fn deliver(&self, from: SocketAddr, to: SocketAddr, data: &[u8]) {
        if let Some(tx) = self.routes.lock().unwrap().get(&to) {
            let _ = tx.send((data.to_vec(), from));
        }
    }

    fn unbind(&self, addr: SocketAddr) {
        self.routes.lock().unwrap().remove(&addr);
    }

    /// Number of bound sockets.
    pub fn bound(&self) -> usize {
        self.routes.lock().unwrap().len()
    }
}

/// One in-memory UDP socket.
pub struct MemSocket {
    /// Local address.
    pub addr: SocketAddr,
    net: Arc<MemNet>,
    rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<Datagram>>,
}

impl MemSocket {
    /// Sends synchronously (test clients).
    pub fn send(&self, to: SocketAddr, data: &[u8]) {
        self.net.deliver(self.addr, to, data);
    }

    /// Receives the next datagram.
    pub async fn recv(&self) -> Datagram {
        self.rx.lock().await.recv().await.unwrap()
    }

    /// Receives the next datagram, or `None` after `within` (tokio time).
    pub async fn recv_within(&self, within: std::time::Duration) -> Option<Datagram> {
        tokio::time::timeout(within, self.recv()).await.ok()
    }
}

impl Drop for MemSocket {
    fn drop(&mut self) {
        self.net.unbind(self.addr);
    }
}

impl TransferSocket for MemSocket {
    async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> io::Result<usize> {
        self.net.deliver(self.addr, dst, buf);
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (data, from) = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok((n, from))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.addr)
    }
}

/// Opens server TID sockets on the interface address.
pub struct MemFactory {
    /// The network.
    pub net: Arc<MemNet>,
    /// The interface address.
    pub ip: IpAddr,
}

impl SocketFactory for MemFactory {
    type Socket = MemSocket;

    fn open_tid(&self) -> io::Result<MemSocket> {
        Ok(self.net.bind(self.ip))
    }
}

/// Writes `relay.toml` for `s` (interface, boot section) plus `extra`
/// TOML text, mode 0644, and returns its path.
pub fn write_config_toml(s: &Scratch, extra: &str) -> PathBuf {
    let text = format!(
        "schema_version = 1\n\n[[interface]]\nname = \"{IFACE}\"\naddress = \"{IFACE_ADDR}\"\n\n\
         [boot]\nmanifest = \"{}\"\nroot = \"{}\"\nuefi_x64_program = \"{PROGRAM}\"\n\n{extra}",
        s.manifest_path().display(),
        s.root().display(),
    );
    let p = s.dir.join("relay.toml");
    std::fs::write(&p, text).unwrap();
    set_mode(&p, 0o644);
    p
}
