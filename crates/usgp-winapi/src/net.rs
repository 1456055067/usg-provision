//! Network adapters: hardware addresses for the session hello, and IPv4
//! addresses for the wait for a DHCP lease (REQ-PE-014).
//!
//! SR-3: `GetAdaptersAddresses` is not summarised in topic 23. The list
//! walk (in `ffi.rs`) is bounded in count and checks that every pointer
//! lies inside the returned buffer before following it.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SI-16 (Memory
//   Protection) - bounded, range-checked list walk; supports IA-3 (Device
//   Identification and Authentication) by reporting identifiers only; IA-3
//   is partial (no device authentication; POAM: IA-3 (TB-2) in usgp-api)
// - SPEC: specs/preinstall-env.md REQ-PE-014; plan §3.1 DeviceHelloV1
// - DECISION: docs/decisions/0019-windows-api-binding.md

use std::net::Ipv4Addr;

use windows_sys::Win32::NetworkManagement::IpHelper::IF_TYPE_SOFTWARE_LOOPBACK;

use crate::error::{Result, WinApiError};
use crate::ffi;
use crate::netaddr::{MacAddress, reportable_macs};

/// Most adapters listed.
pub const MAX_ADAPTERS: usize = 256;
/// Most unicast addresses read per adapter.
pub const MAX_ADDRESSES_PER_ADAPTER: usize = 64;

/// One network adapter with IPv4 enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adapter {
    /// Hardware address, when it is 48 bits.
    pub mac: Option<MacAddress>,
    /// Interface type (IANA ifType value).
    pub if_type: u32,
    /// Software loopback.
    pub loopback: bool,
    /// Operationally up.
    pub up: bool,
    /// DHCP enabled on the adapter.
    pub dhcp_enabled: bool,
    /// IPv4 unicast addresses.
    pub ipv4: Vec<Ipv4Addr>,
}

/// Lists IPv4 adapters.
pub fn adapters() -> Result<Vec<Adapter>> {
    let raw = ffi::ipv4_adapters(MAX_ADAPTERS, MAX_ADDRESSES_PER_ADAPTER)
        .map_err(|e| WinApiError::os("list network adapters", e))?;
    Ok(raw
        .into_iter()
        .map(|a| Adapter {
            mac: MacAddress::from_slice(&a.mac),
            if_type: a.if_type,
            loopback: a.if_type == IF_TYPE_SOFTWARE_LOOPBACK,
            up: a.oper_up,
            dhcp_enabled: a.dhcp_enabled,
            ipv4: a.ipv4.into_iter().map(Ipv4Addr::from).collect(),
        })
        .collect())
}

/// The MAC addresses to report: from non-loopback adapters, unicast,
/// non-zero, at most 16 (plan §3.1).
#[must_use]
pub fn hello_macs(adapters: &[Adapter]) -> Vec<MacAddress> {
    reportable_macs(
        adapters
            .iter()
            .filter(|a| !a.loopback)
            .filter_map(|a| a.mac),
    )
}

/// IPv4 addresses of adapters that are up, not loopback, and have DHCP
/// enabled, excluding unspecified and link-local addresses: the addresses
/// that show a DHCP lease was obtained (REQ-PE-014).
#[must_use]
pub fn dhcp_ipv4_addresses(adapters: &[Adapter]) -> Vec<Ipv4Addr> {
    adapters
        .iter()
        .filter(|a| a.up && !a.loopback && a.dhcp_enabled)
        .flat_map(|a| a.ipv4.iter().copied())
        .filter(|ip| !ip.is_unspecified() && !ip.is_link_local() && !ip.is_loopback())
        .collect()
}
