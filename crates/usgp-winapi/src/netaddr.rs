//! Hardware addresses as the device session reports them.
//!
//! The session hello carries at most 16 MAC addresses, each unicast and
//! non-zero, as `aa:bb:cc:dd:ee:ff` (plan §3.1 `DeviceHelloV1`). This
//! module is pure so the rules are tested on every host.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation); supports IA-3
//   (Device Identification and Authentication) - device identifiers
//   reported as-is, filtered to valid unicast addresses (identification
//   only; IA-3 partial, POAM: IA-3 (TB-2) in usgp-api)
// - SPEC: plan §3.1 (DeviceHelloV1 `macs`)

use core::fmt;

/// Most MAC addresses reported in a hello (plan §3.1).
pub const MAX_REPORTED_MACS: usize = 16;

/// A 48-bit MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// Accepts exactly six bytes; any other length is `None` (an adapter
    /// whose hardware address is not 48 bits is not reported).
    #[must_use]
    pub fn from_slice(b: &[u8]) -> Option<Self> {
        <[u8; 6]>::try_from(b).ok().map(Self)
    }

    /// Non-zero and unicast (the group bit of the first octet clear).
    #[must_use]
    pub fn is_reportable(&self) -> bool {
        let [first, ..] = self.0;
        self.0 != [0; 6] && first & 0x01 == 0
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

/// The reportable addresses among `macs`: unicast, non-zero, without
/// duplicates, in first-seen order, at most [`MAX_REPORTED_MACS`].
#[must_use]
pub fn reportable_macs(macs: impl IntoIterator<Item = MacAddress>) -> Vec<MacAddress> {
    let mut out: Vec<MacAddress> = Vec::new();
    for m in macs {
        if out.len() >= MAX_REPORTED_MACS {
            break;
        }
        if m.is_reportable() && !out.contains(&m) {
            out.push(m);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_rules() {
        let m = MacAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        assert_eq!(m.to_string(), "52:54:00:12:34:56");
        assert!(m.is_reportable());
        assert!(!MacAddress([0; 6]).is_reportable());
        assert!(!MacAddress([0x01, 0, 0x5e, 0, 0, 1]).is_reportable());
        assert_eq!(MacAddress::from_slice(&[1, 2, 3]), None);
        assert_eq!(MacAddress::from_slice(&[0; 8]), None);
        assert_eq!(
            MacAddress::from_slice(&[2, 0, 0, 0, 0, 1]),
            Some(MacAddress([2, 0, 0, 0, 0, 1]))
        );
    }

    #[test]
    fn reportable_list_is_filtered_deduplicated_and_capped() {
        let a = MacAddress([2, 0, 0, 0, 0, 1]);
        let list = reportable_macs([a, MacAddress([0; 6]), a, MacAddress([3, 0, 0, 0, 0, 1])]);
        assert_eq!(list, vec![a]);
        let many = (0..40u8).map(|i| MacAddress([2, 0, 0, 0, 0, i]));
        assert_eq!(reportable_macs(many).len(), MAX_REPORTED_MACS);
    }
}
