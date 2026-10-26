//! usgp-netlab: test-only lab network tools for the M1 boot smoke.
//!
//! Three binaries share this library:
//!
//! - `lab-dhcpd`: a site DHCP server emulator ([`dhcpd`]). It leases
//!   addresses and sends no PXE or boot options (REQ-BOOT-011).
//! - `lab-relay-agent`: an RFC 1542 relay agent with option 82
//!   ([`agent`]), for the cross-subnet scenario (REQ-BOOT-002, 020, 021).
//! - `lab-probe`: crafted DHCP and TFTP traffic with assertions on the
//!   replies ([`probe`], [`tftp`]), for scenario S4.
//!
//! The protocol logic is sans-IO and unit-tested on any host. Socket code
//! ([`net`]) is Linux-only, because the lab needs `SO_BINDTODEVICE`; on other
//! systems the binaries print `NOT SUPPORTED` and exit 77.
//!
//! This crate is not part of the product. It has its own DHCP and TFTP
//! codecs and must never depend on, or be a dependency of, a product crate
//! (plan section 1.2 and WU-10).

pub mod agent;
pub mod args;
pub mod codec;
pub mod dhcpd;
pub mod net;
pub mod probe;
pub mod tftp;

/// Exit status for "cannot run on this host" (the harness reports NOT RUN).
pub const EXIT_UNSUPPORTED: i32 = 77;
/// Exit status for a usage error.
pub const EXIT_USAGE: i32 = 2;
