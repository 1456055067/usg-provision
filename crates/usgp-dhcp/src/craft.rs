//! Client-side request encoder for tests, fuzz seeds, and the relay's
//! integration tests.
//!
//! The responder never uses this module. It can build deliberately broken
//! messages (wrong `op`, missing End, oversize options) so negative tests can
//! exercise every parser rule. It must not be used to answer clients.

use core::net::Ipv4Addr;

use crate::packet::{FLAG_BROADCAST, MAGIC_COOKIE, MIN_REQUEST_LEN};

/// Builds a BOOTREQUEST byte by byte. Defaults describe a UEFI x86-64 PXE
/// client on the local segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestBuilder {
    /// `op` (1 = BOOTREQUEST).
    pub op: u8,
    /// `htype`.
    pub htype: u8,
    /// `hlen`.
    pub hlen: u8,
    /// `hops`.
    pub hops: u8,
    /// `xid`.
    pub xid: u32,
    /// `flags`.
    pub flags: u16,
    /// `ciaddr`.
    pub ciaddr: Ipv4Addr,
    /// `giaddr`.
    pub giaddr: Ipv4Addr,
    /// First six octets of `chaddr`.
    pub chaddr: [u8; 6],
    /// `sname` field content (truncated or zero-padded to 64 octets).
    pub sname: Vec<u8>,
    /// `file` field content (truncated or zero-padded to 128 octets).
    pub file: Vec<u8>,
    /// Magic cookie.
    pub cookie: [u8; 4],
    /// Options in order, each `(code, data)`. Data over 255 octets is
    /// truncated to 255.
    pub options: Vec<(u8, Vec<u8>)>,
    /// Whether to append End.
    pub end: bool,
    /// Raw bytes appended after the options (and End, if any).
    pub trailing: Vec<u8>,
    /// Zero octets are appended until the message is at least this long.
    /// Defaults to the 300-octet BOOTP minimum that clients pad to
    /// (specs/standards/pxe-dhcp.md §3.2); set it to 0 to build a short
    /// message.
    pub pad_to: usize,
}

/// Sample client GUID in wire order.
pub const SAMPLE_GUID_WIRE: [u8; 16] = [
    0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
];

/// Sample client hardware address.
pub const SAMPLE_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x00, 0x01, 0x01];

impl RequestBuilder {
    /// A DHCPDISCOVER as a UEFI x86-64 PXE client sends it (pxe-dhcp.md §7
    /// step 1): options 53, 55, 57, 60, 93, 94, 97.
    #[must_use]
    pub fn pxe_discover() -> Self {
        let mut machine_id = vec![0u8];
        machine_id.extend_from_slice(&SAMPLE_GUID_WIRE);
        Self {
            op: 1,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: 0x1234_5678,
            flags: FLAG_BROADCAST,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: SAMPLE_MAC,
            sname: Vec::new(),
            file: Vec::new(),
            cookie: MAGIC_COOKIE,
            options: vec![
                (53, vec![1]),
                (
                    55,
                    vec![1, 3, 43, 60, 128, 129, 130, 131, 132, 133, 134, 135],
                ),
                (57, 1472u16.to_be_bytes().to_vec()),
                (60, b"PXEClient:Arch:00007:UNDI:003016".to_vec()),
                (93, vec![0, 7]),
                (94, vec![1, 3, 16]),
                (97, machine_id),
            ],
            end: true,
            trailing: Vec::new(),
            pad_to: MIN_REQUEST_LEN,
        }
    }

    /// The same client's DHCPREQUEST, with no server identifier and no
    /// option 43. Add option 54 or a tag-71 option 43 as the test needs.
    #[must_use]
    pub fn pxe_request() -> Self {
        Self::pxe_discover().set_option(53, vec![3])
    }

    /// Appends an option (even if the code is already present).
    #[must_use]
    pub fn option(mut self, code: u8, data: Vec<u8>) -> Self {
        self.options.push((code, data));
        self
    }

    /// Replaces the first occurrence of `code`, or appends it.
    #[must_use]
    pub fn set_option(mut self, code: u8, data: Vec<u8>) -> Self {
        match self.options.iter_mut().find(|(c, _)| *c == code) {
            Some(slot) => slot.1 = data,
            None => self.options.push((code, data)),
        }
        self
    }

    /// Removes every occurrence of `code`.
    #[must_use]
    pub fn without(mut self, code: u8) -> Self {
        self.options.retain(|(c, _)| *c != code);
        self
    }

    /// Sets `giaddr`.
    #[must_use]
    pub fn giaddr(mut self, a: Ipv4Addr) -> Self {
        self.giaddr = a;
        self
    }

    /// Sets `ciaddr`.
    #[must_use]
    pub fn ciaddr(mut self, a: Ipv4Addr) -> Self {
        self.ciaddr = a;
        self
    }

    /// Sets `hops`.
    #[must_use]
    pub fn hops(mut self, h: u8) -> Self {
        self.hops = h;
        self
    }

    /// Sets `flags`.
    #[must_use]
    pub fn flags(mut self, f: u16) -> Self {
        self.flags = f;
        self
    }

    /// Sets `chaddr`.
    #[must_use]
    pub fn chaddr(mut self, m: [u8; 6]) -> Self {
        self.chaddr = m;
        self
    }

    /// Sets the raw `file` field.
    #[must_use]
    pub fn file_area(mut self, f: Vec<u8>) -> Self {
        self.file = f;
        self
    }

    /// Sets the raw `sname` field.
    #[must_use]
    pub fn sname_area(mut self, s: Vec<u8>) -> Self {
        self.sname = s;
        self
    }

    /// Encodes the message.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(548);
        b.extend_from_slice(&[self.op, self.htype, self.hlen, self.hops]);
        b.extend_from_slice(&self.xid.to_be_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&self.flags.to_be_bytes());
        b.extend_from_slice(&self.ciaddr.octets());
        b.extend_from_slice(&[0; 4]); // yiaddr
        b.extend_from_slice(&[0; 4]); // siaddr
        b.extend_from_slice(&self.giaddr.octets());
        b.extend_from_slice(&self.chaddr);
        b.extend_from_slice(&[0; 10]);
        push_fixed(&mut b, &self.sname, 64);
        push_fixed(&mut b, &self.file, 128);
        b.extend_from_slice(&self.cookie);
        for (code, data) in &self.options {
            let data = data.get(..255).unwrap_or(data);
            b.push(*code);
            b.push(u8::try_from(data.len()).unwrap_or(u8::MAX));
            b.extend_from_slice(data);
        }
        if self.end {
            b.push(255);
        }
        b.extend_from_slice(&self.trailing);
        if b.len() < self.pad_to {
            b.resize(self.pad_to, 0);
        }
        b
    }
}

fn push_fixed(b: &mut Vec<u8>, data: &[u8], len: usize) {
    let data = data.get(..len).unwrap_or(data);
    b.extend_from_slice(data);
    b.resize(b.len() + (len - data.len()), 0);
}
