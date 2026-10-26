//! Socket binding (plan section 3.2).
//!
//! Every socket is tied to one configured interface with
//! `SO_BINDTODEVICE`, so the relay never answers on an interface the
//! operator did not list (exit criterion 4). Port 67 must receive
//! broadcasts, so it binds `0.0.0.0:67` on the device with `SO_BROADCAST`.
//! Ports 4011 and 69 and every transfer socket bind the interface's
//! unicast address, so the kernel does not deliver broadcast datagrams to
//! them (REQ-BOOT-042).
//!
//! Linux only in M1. On any other OS [`bind`] returns
//! [`NetError::UnsupportedPlatform`] and the relay refuses to start; the
//! bind plan itself is portable so it can be tested anywhere.
//!
//! [`interface_prefix`] finds the subnet of an interface that has no
//! `prefix_len` configured, from its connected route in the kernel's IPv4
//! routing table (`/proc/net/route`, proc(5)); the parser
//! [`connected_prefix`] is portable.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-7 (Boundary Protection) - only configured interfaces;
//   no wildcard bind without a device binding.
// - NIST 800-53: CM-7 (Least Functionality) - only ports 67, 4011, 69 and
//   per-transfer ephemeral ports.
// - NIST 800-53: AC-6 (Least Privilege) - designed to need only
//   CAP_NET_BIND_SERVICE and CAP_NET_RAW, not root; enforcement is
//   deployment configuration (service unit), not this code. relay.start
//   carries a warning when the relay runs as root (POAM: AC-6 enforcement).
// - SPEC: specs/boot-network.md#REQ-BOOT-042 (ignore broadcast RRQs)
// - RFC 1123 §4.2.3.5 - broadcast TFTP requests ignored

// POAM: AC-6 - the relay does not drop privileges or refuse to run as
// root; least privilege depends on the service unit (dedicated uid,
// AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW, NoNewPrivileges).
// relay.start reports `warning=running_as_root` when euid is 0.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::config::{InterfaceConfig, MAX_PREFIX_LEN, MIN_PREFIX_LEN, prefix_mask};
use crate::tftp::SocketFactory;

/// DHCP server port.
pub const DHCP_PORT: u16 = 67;
/// PXE boot-server port.
pub const BOOT_SERVER_PORT: u16 = 4011;
/// TFTP server port.
pub const TFTP_PORT: u16 = 69;

/// What a socket is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketRole {
    /// DHCP on port 67 (broadcast and relayed requests).
    Dhcp,
    /// PXE boot-server requests on port 4011.
    BootServer,
    /// TFTP requests on port 69.
    Tftp,
    /// One TFTP transfer (new server TID).
    Transfer,
}

/// How to bind one socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindSpec {
    /// Purpose.
    pub role: SocketRole,
    /// Local address and port.
    pub addr: SocketAddrV4,
    /// Interface name for `SO_BINDTODEVICE`.
    pub device: String,
    /// `SO_BROADCAST` (needed to send to 255.255.255.255).
    pub broadcast: bool,
    /// `SO_REUSEADDR` (one `0.0.0.0:67` socket per device).
    pub reuse_address: bool,
}

/// The three listening sockets for `iface`.
#[must_use]
pub fn bind_plan(iface: &InterfaceConfig) -> [BindSpec; 3] {
    [
        BindSpec {
            role: SocketRole::Dhcp,
            addr: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DHCP_PORT),
            device: iface.name.clone(),
            broadcast: true,
            reuse_address: true,
        },
        BindSpec {
            role: SocketRole::BootServer,
            addr: SocketAddrV4::new(iface.address, BOOT_SERVER_PORT),
            device: iface.name.clone(),
            broadcast: false,
            reuse_address: false,
        },
        BindSpec {
            role: SocketRole::Tftp,
            addr: SocketAddrV4::new(iface.address, TFTP_PORT),
            device: iface.name.clone(),
            broadcast: false,
            reuse_address: false,
        },
    ]
}

/// The spec for a transfer socket on `iface`.
#[must_use]
pub fn transfer_spec(iface: &InterfaceConfig) -> BindSpec {
    BindSpec {
        role: SocketRole::Transfer,
        addr: SocketAddrV4::new(iface.address, 0),
        device: iface.name.clone(),
        broadcast: false,
        reuse_address: false,
    }
}

/// Socket set-up errors. Every variant means exit 1.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NetError {
    /// Interface binding is implemented for Linux only in M1.
    #[error("interface binding is only supported on Linux")]
    UnsupportedPlatform,
    /// A socket call failed.
    #[error("cannot bind {addr} on {device}: {kind}")]
    Bind {
        /// Interface name.
        device: String,
        /// Local address.
        addr: SocketAddrV4,
        /// The I/O error kind.
        kind: io::ErrorKind,
    },
}

#[cfg(target_os = "linux")]
fn bind_std(spec: &BindSpec) -> io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    if spec.reuse_address {
        socket.set_reuse_address(true)?;
    }
    if spec.broadcast {
        socket.set_broadcast(true)?;
    }
    socket.bind_device(Some(spec.device.as_bytes()))?;
    socket.set_nonblocking(true)?;
    socket.bind(&SockAddr::from(spec.addr))?;
    Ok(socket.into())
}

/// Binds `spec` and hands the socket to tokio. Must be called inside a
/// tokio runtime.
///
/// # Errors
///
/// [`NetError::Bind`], or [`NetError::UnsupportedPlatform`] off Linux.
#[cfg(target_os = "linux")]
pub fn bind(spec: &BindSpec) -> Result<tokio::net::UdpSocket, NetError> {
    let err = |e: io::Error| NetError::Bind {
        device: spec.device.clone(),
        addr: spec.addr,
        kind: e.kind(),
    };
    let std_socket = bind_std(spec).map_err(err)?;
    tokio::net::UdpSocket::from_std(std_socket).map_err(err)
}

/// Binds `spec` and hands the socket to tokio.
///
/// # Errors
///
/// Always [`NetError::UnsupportedPlatform`] on this OS.
#[cfg(not(target_os = "linux"))]
pub fn bind(spec: &BindSpec) -> Result<tokio::net::UdpSocket, NetError> {
    let _ = spec;
    Err(NetError::UnsupportedPlatform)
}

/// Largest routing table read (bytes).
#[cfg(target_os = "linux")]
const MAX_ROUTE_TABLE_BYTES: u64 = 1024 * 1024;
/// Most routing-table lines considered.
const MAX_ROUTE_LINES: usize = 16_384;

/// Route flag: route usable (`RTF_UP`).
const RTF_UP: u32 = 0x0001;
/// Route flag: destination reached through a gateway (`RTF_GATEWAY`).
const RTF_GATEWAY: u32 = 0x0002;

/// The prefix length of `address`'s subnet on interface `name`: the
/// longest connected route (up, no gateway) on that interface whose
/// destination contains `address`, limited to
/// `MIN_PREFIX_LEN..=MAX_PREFIX_LEN`. `None` if there is none or the table
/// cannot be read.
#[cfg(target_os = "linux")]
#[must_use]
pub fn interface_prefix(name: &str, address: Ipv4Addr) -> Option<u8> {
    use std::io::Read;
    let file = std::fs::File::open("/proc/net/route").ok()?;
    let mut text = String::new();
    file.take(MAX_ROUTE_TABLE_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    connected_prefix(&text, name, address)
}

/// The prefix length of `address`'s subnet on interface `name`.
///
/// Always `None` on this OS (the relay does not run here in M1).
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn interface_prefix(name: &str, address: Ipv4Addr) -> Option<u8> {
    let _ = (name, address);
    None
}

/// Finds the connected-route prefix for `address` on `name` in the text of
/// `/proc/net/route` (see [`interface_prefix`]). Bounded and
/// panic-free: malformed lines are skipped; at most `MAX_ROUTE_LINES` lines
/// are read.
///
/// Columns (proc(5)): `Iface Destination Gateway Flags RefCnt Use Metric
/// Mask ...`; addresses are the kernel's 32-bit values printed as 8 hex
/// digits in host byte order.
///
// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - bounded parse of a
//   kernel table; no panics; a non-contiguous mask is ignored.
// - NIST 800-53: SC-5 - the prefix decides which requests may use the
//   same-segment budget.
#[must_use]
pub fn connected_prefix(table: &str, name: &str, address: Ipv4Addr) -> Option<u8> {
    let addr = u32::from(address);
    let mut best: Option<u8> = None;
    for line in table.lines().skip(1).take(MAX_ROUTE_LINES) {
        let mut cols = line.split_whitespace();
        let (Some(iface), Some(dest), Some(gw), Some(flags)) =
            (cols.next(), cols.next(), cols.next(), cols.next())
        else {
            continue;
        };
        let Some(mask) = cols.nth(3) else {
            continue;
        };
        if iface != name {
            continue;
        }
        let (Some(dest), Some(gw), Some(flags), Some(mask)) =
            (hex_addr(dest), hex_addr(gw), hex_u32(flags), hex_addr(mask))
        else {
            continue;
        };
        if flags & RTF_UP == 0 || flags & RTF_GATEWAY != 0 || gw != 0 {
            continue;
        }
        let len = mask.leading_ones();
        let Ok(len) = u8::try_from(len) else {
            continue;
        };
        if mask != prefix_mask(len) || !(MIN_PREFIX_LEN..=MAX_PREFIX_LEN).contains(&len) {
            continue;
        }
        if addr & mask != dest & mask {
            continue;
        }
        if best.is_none_or(|b| len > b) {
            best = Some(len);
        }
    }
    best
}

fn hex_u32(s: &str) -> Option<u32> {
    if s.is_empty() || s.len() > 8 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(s, 16).ok()
}

/// A routing-table address: the kernel value in host byte order, so its
/// native-endian bytes are the address octets.
fn hex_addr(s: &str) -> Option<u32> {
    hex_u32(s).map(|v| u32::from_be_bytes(v.to_ne_bytes()))
}

/// Opens transfer sockets on one interface.
#[derive(Debug, Clone)]
pub struct UdpTidFactory {
    spec: BindSpec,
}

impl UdpTidFactory {
    /// A factory for `iface`.
    #[must_use]
    pub fn new(iface: &InterfaceConfig) -> Self {
        Self {
            spec: transfer_spec(iface),
        }
    }
}

impl SocketFactory for UdpTidFactory {
    type Socket = tokio::net::UdpSocket;

    fn open_tid(&self) -> io::Result<Self::Socket> {
        bind(&self.spec).map_err(|e| match e {
            NetError::Bind { kind, .. } => io::Error::from(kind),
            NetError::UnsupportedPlatform => io::Error::from(io::ErrorKind::Unsupported),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface() -> InterfaceConfig {
        InterfaceConfig {
            name: "relay0".to_owned(),
            address: Ipv4Addr::new(10, 20, 1, 2),
            prefix_len: Some(24),
        }
    }

    /// Hex in host byte order, as the kernel prints it.
    fn h(a: [u8; 4]) -> String {
        format!("{:08X}", u32::from_ne_bytes(a))
    }

    /// Interface, destination, gateway, flags (hex text), mask.
    type Row<'a> = (&'a str, [u8; 4], [u8; 4], &'a str, [u8; 4]);

    fn table(rows: &[Row<'_>]) -> String {
        let mut t = String::from(
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n",
        );
        for (iface, dest, gw, flags, mask) in rows {
            t.push_str(&format!(
                "{iface}\t{}\t{}\t{flags}\t0\t0\t0\t{}\t0\t0\t0\n",
                h(*dest),
                h(*gw),
                h(*mask)
            ));
        }
        t
    }

    #[test]
    fn connected_prefix_from_route_table() {
        let a = Ipv4Addr::new(10, 20, 1, 2);
        let t = table(&[
            ("relay0", [0, 0, 0, 0], [10, 20, 1, 1], "0003", [0, 0, 0, 0]),
            (
                "relay0",
                [10, 20, 0, 0],
                [0, 0, 0, 0],
                "0001",
                [255, 255, 0, 0],
            ),
            (
                "relay0",
                [10, 20, 1, 0],
                [0, 0, 0, 0],
                "0001",
                [255, 255, 255, 0],
            ),
            (
                "other0",
                [10, 20, 1, 0],
                [0, 0, 0, 0],
                "0001",
                [255, 255, 255, 128],
            ),
            (
                "relay0",
                [10, 99, 0, 0],
                [0, 0, 0, 0],
                "0001",
                [255, 255, 255, 0],
            ),
        ]);
        // Longest connected route on this interface that holds the address.
        assert_eq!(connected_prefix(&t, "relay0", a), Some(24));
        assert_eq!(connected_prefix(&t, "other0", a), Some(25));
        assert_eq!(connected_prefix(&t, "missing0", a), None);
        assert_eq!(
            connected_prefix(&t, "relay0", Ipv4Addr::new(10, 21, 0, 1)),
            None
        );
    }

    #[test]
    fn connected_prefix_skips_gateway_down_odd_and_malformed_rows() {
        let a = Ipv4Addr::new(10, 20, 1, 2);
        let t = table(&[
            // Through a gateway.
            (
                "relay0",
                [10, 20, 1, 0],
                [10, 20, 1, 1],
                "0003",
                [255, 255, 255, 0],
            ),
            // Down.
            (
                "relay0",
                [10, 20, 1, 0],
                [0, 0, 0, 0],
                "0000",
                [255, 255, 255, 0],
            ),
            // Non-contiguous mask.
            (
                "relay0",
                [10, 20, 1, 0],
                [0, 0, 0, 0],
                "0001",
                [255, 0, 255, 0],
            ),
            // Outside 8..=31: /32 host route and /4.
            (
                "relay0",
                [10, 20, 1, 2],
                [0, 0, 0, 0],
                "0001",
                [255, 255, 255, 255],
            ),
            ("relay0", [0, 0, 0, 0], [0, 0, 0, 0], "0001", [240, 0, 0, 0]),
        ]);
        assert_eq!(connected_prefix(&t, "relay0", a), None);
        for junk in [
            "",
            "header only\n",
            "h\nrelay0\n",
            "h\nrelay0 ZZZZZZZZ 00000000 0001 0 0 0 00FFFFFF\n",
            "h\nrelay0 0001140A 00000000 0001 0 0 0\n",
            "h\nrelay0 0001140A 00000000 0001 0 0 0 1FFFFFFFF\n",
            "h\nrelay0 0001140A 00000000 +1 0 0 0 00FFFFFF\n",
        ] {
            assert_eq!(connected_prefix(junk, "relay0", a), None, "{junk:?}");
        }
    }

    #[test]
    fn bind_plan_tftp_unicast_only() {
        let plan = bind_plan(&iface());
        let tftp = plan.iter().find(|s| s.role == SocketRole::Tftp).unwrap();
        assert_eq!(tftp.addr, "10.20.1.2:69".parse().unwrap());
        assert!(!tftp.broadcast);
        let t = transfer_spec(&iface());
        assert_eq!(*t.addr.ip(), Ipv4Addr::new(10, 20, 1, 2));
        assert_eq!(t.addr.port(), 0);
        assert!(!t.broadcast);
    }

    #[test]
    fn bind_plan_every_socket_has_a_device() {
        for s in bind_plan(&iface()).iter().chain([&transfer_spec(&iface())]) {
            assert_eq!(s.device, "relay0", "{s:?}");
        }
    }

    #[test]
    fn only_dhcp_is_wildcard_and_broadcast() {
        for s in bind_plan(&iface()) {
            let wildcard = s.addr.ip().is_unspecified();
            assert_eq!(wildcard, s.role == SocketRole::Dhcp, "{s:?}");
            assert_eq!(s.broadcast, s.role == SocketRole::Dhcp, "{s:?}");
        }
    }

    #[test]
    fn bind_plan_ports() {
        let ports: Vec<u16> = bind_plan(&iface()).iter().map(|s| s.addr.port()).collect();
        assert_eq!(ports, vec![67, 4011, 69]);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn bind_refuses_off_linux() {
        assert!(matches!(
            bind(&bind_plan(&iface())[0]),
            Err(NetError::UnsupportedPlatform)
        ));
    }
}
