//! Socket set-up for the lab binaries.
//!
//! Linux only: the lab topology (plan section 10.5) puts several tools on
//! one host in network namespaces, and each socket must be tied to its
//! interface with `SO_BINDTODEVICE`. On other systems [`udp`] returns
//! `Unsupported` and the binaries exit with
//! [`EXIT_UNSUPPORTED`](crate::EXIT_UNSUPPORTED) before opening anything.

use std::io;
use std::net::{SocketAddr, SocketAddrV4};

/// Whether the socket code is available on this build target.
pub const SUPPORTED: bool = cfg!(target_os = "linux");

/// How to open one UDP socket.
#[derive(Clone, Copy, Debug)]
pub struct UdpOpts<'a> {
    /// Local address and port.
    pub bind: SocketAddrV4,
    /// Interface to bind to (`SO_BINDTODEVICE`), if any.
    pub device: Option<&'a str>,
    /// Allow sending to broadcast addresses (`SO_BROADCAST`).
    pub broadcast: bool,
    /// `SO_REUSEADDR`, for two sockets on port 67 bound to different devices.
    pub reuse_addr: bool,
}

/// Opens a non-blocking UDP socket and registers it with tokio. Must be
/// called inside a tokio runtime.
#[cfg(target_os = "linux")]
pub fn udp(opts: &UdpOpts<'_>) -> io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    if opts.reuse_addr {
        s.set_reuse_address(true)?;
    }
    if let Some(dev) = opts.device {
        s.bind_device(Some(dev.as_bytes()))?;
    }
    if opts.broadcast {
        s.set_broadcast(true)?;
    }
    s.set_nonblocking(true)?;
    s.bind(&opts.bind.into())?;
    tokio::net::UdpSocket::from_std(s.into())
}

/// Opens a non-blocking UDP socket (not available on this system).
#[cfg(not(target_os = "linux"))]
pub fn udp(_opts: &UdpOpts<'_>) -> io::Result<tokio::net::UdpSocket> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "lab sockets need Linux SO_BINDTODEVICE",
    ))
}

/// The IPv4 form of a received peer address (the sockets are IPv4 only).
pub fn v4(addr: SocketAddr) -> Option<SocketAddrV4> {
    match addr {
        SocketAddr::V4(a) => Some(a),
        SocketAddr::V6(_) => None,
    }
}

/// Prints the NOT SUPPORTED line and exits 77 unless [`SUPPORTED`].
pub fn require_supported(tool: &str) {
    if !SUPPORTED {
        println!("{tool}: NOT SUPPORTED on this OS (lab sockets need Linux SO_BINDTODEVICE)");
        std::process::exit(crate::EXIT_UNSUPPORTED);
    }
}
