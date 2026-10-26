//! ProxyDHCP reply builder, and a reply inspector for tests and fuzzing.
//!
//! Decision 0003 is enforced by construction: [`ProxyReply`] has no field
//! for `yiaddr` or for any lease, router or subnet option, and offers no
//! way to add arbitrary options. The encoder writes `yiaddr` as 0.0.0.0
//! from a constant. The only options a reply can carry are 53, 54, 60, 93,
//! 94, 97, optionally 43 (a single tag-71 echo), optionally 82 (echoed
//! request data), and End.
//!
//! Options 93, 94 and 97 are always present (RFC 4578 §2.1-§2.3 presence
//! rule for PXE-compliant servers; pxe-dhcp.md §5.5). The RFC gives no
//! value for the server's copy, so the values are project design:
//! - 93: the single architecture the boot program was chosen for;
//! - 94: the client's own option 94 echoed, or type 1 (UNDI) version 3.0
//!   when the client sent none (the UEFI default, pxe-dhcp.md §5.3);
//! - 97: the client's own option 97 echoed (type 0 + GUID), or type 0 with
//!   the nil GUID when the client sent none (nil = "no value present",
//!   uefi-guid-text.md §2).
//!
//! Every value is either the client's own claim or a fixed constant, so no
//! server state or host identity is disclosed.

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-7 (Least Functionality) - the reply carries boot
//   information only, never address configuration.
// - NIST 800-53: SI-10 (Information Input Validation) - size limit
//   enforced on every reply.
// - SPEC: specs/boot-network.md#REQ-BOOT-010, #REQ-BOOT-021, #REQ-BOOT-022
// - DECISION: docs/decisions/0003-proxy-dhcp-only.md
// - RFC 2131 §2 (header); header fields per specs/standards/pxe-dhcp.md
//   §3.1 (RFC 2131 §4.3.1 Table 3); RFC 2132 §9.6/§9.7/§9.13; RFC 4578
//   §2.1
// - specs/standards/pxe-dhcp.md §3.2 [reading] - replies padded to the
//   300-octet BOOTP minimum
// - RFC 4578 §2.1-§2.3 - options 93, 94, 97 present (pxe-dhcp.md §5.5)
// - RFC 3046 §2.2 - option 82 echoed last, omitted if it does not fit
// - RFC 3396 §4 - this sender never splits an option (conservative rule)
// - RFC 1542 §5.4 - BROADCAST flag preserved
// - UEFI 2.10 Appendix E.4.20.2/E.4.20.3 - siaddr and file; option 43
//   only when sub-options are needed
// - draft-henry-remote-boot-protocol-00 §3.3.2 - tag 71 in the ACK;
//   layout per specs/standards/pxe-dhcp.md §6.1 (OPEN-T71-1 byte order and
//   OPEN-T71-2 reply contents are [reading]s there: network order, and the
//   requested type and layer echoed)

use core::net::Ipv4Addr;

use thiserror::Error;

use crate::error::ParseError;
use crate::ident::{ClientArch, Guid, MacAddr};
use crate::options::{self, EndRule, OptionSet, code};
use crate::packet::{
    BootItem, FILE_LEN, FLAG_BROADCAST, MAGIC_COOKIE, MAX_MESSAGE_LEN, MIN_MESSAGE_LEN, OFF_CHADDR,
    OFF_CIADDR, OFF_COOKIE, OFF_FILE, OFF_FLAGS, OFF_GIADDR, OFF_OP, OFF_OPTIONS, OFF_SIADDR,
    OFF_XID, OFF_YIADDR, SNAME_LEN, field, ipv4_at,
};

/// Reply size limit when the client sent no usable option 57: 576 minus IP
/// and UDP headers (RFC 2131 §2).
pub const DEFAULT_REPLY_LIMIT: usize = 548;

/// Every reply is padded with zeros after End to at least this size, the
/// minimum BOOTP message size. specs/standards/pxe-dhcp.md §3.2 [reading]:
/// RFC 1542 §2.1 is a receiver check, and padding protects against
/// receivers that apply it.
pub const MIN_REPLY_LEN: usize = 300;

/// Longest boot program name: the 128-octet `file` field less its NUL.
pub const MAX_BOOT_FILE_LEN: usize = FILE_LEN - 1;

/// Option 60 value in every reply (draft-henry §3.1.2).
const REPLY_CLASS: &[u8] = b"PXEClient";

/// Option 94 value when the client sent none: type 1 (UNDI), version 3.0
/// (UEFI default, pxe-dhcp.md §5.3). Project design (pxe-dhcp.md §5.5).
pub const DEFAULT_NDI: [u8; 3] = [1, 3, 0];

/// yiaddr is always zero. There is no input that can change it (0003).
const YIADDR: [u8; 4] = [0; 4];

/// The reply size limit for a request (plan §3.4): 548 octets, raised to
/// `min(option57 - 28, 1472)` when option 57 is at least 576.
#[must_use]
pub fn reply_size_limit(max_message_size: Option<u16>) -> usize {
    match max_message_size {
        Some(v) => usize::from(v)
            .saturating_sub(28)
            .clamp(DEFAULT_REPLY_LIMIT, MAX_MESSAGE_LEN),
        None => DEFAULT_REPLY_LIMIT,
    }
}

/// The kind of proxy reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyKind {
    /// DHCPOFFER (2), answering a DISCOVER.
    Offer,
    /// DHCPACK (5), answering a REQUEST.
    Ack,
}

impl ReplyKind {
    fn message_type(self) -> u8 {
        match self {
            Self::Offer => 2,
            Self::Ack => 5,
        }
    }
}

/// Why a reply could not be built. The caller drops the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum BuildError {
    /// Boot program name empty, over 127 octets, or containing NUL.
    #[error("boot program name does not fit the file field")]
    BadBootFile,
    /// The reply without option 82 is larger than the size limit.
    #[error("reply exceeds size limit")]
    TooLarge,
}

/// The content of one ProxyDHCP reply. There is deliberately no `yiaddr`
/// and no general option list (decision 0003).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyReply<'a> {
    /// OFFER or ACK.
    pub kind: ReplyKind,
    /// Echoed transaction ID.
    pub xid: u32,
    /// Request `flags`; only the BROADCAST bit is copied (RFC 1542 §5.4).
    pub flags: u16,
    /// Echoed relay agent address.
    pub giaddr: Ipv4Addr,
    /// Echoed client hardware address.
    pub chaddr: MacAddr,
    /// This server's interface address: `siaddr` and option 54.
    pub server_addr: Ipv4Addr,
    /// Boot program name for the `file` field.
    pub boot_file: &'a [u8],
    /// Selected architecture, sent in option 93.
    pub arch: ClientArch,
    /// Client's option 94 to echo; `None` sends [`DEFAULT_NDI`].
    pub client_ndi: Option<[u8; 3]>,
    /// Client's option 97 GUID to echo; `None` sends the nil GUID.
    pub client_guid: Option<Guid>,
    /// Tag 71 to echo in option 43 (ACK to a boot-server request only).
    pub boot_item: Option<BootItem>,
    /// Request option 82 data to echo unchanged, if it fits in one option
    /// instance (at most 255 octets; never split, RFC 3396 §4) and in the
    /// size limit.
    pub relay_info: Option<&'a [u8]>,
}

/// An encoded reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoded {
    /// The DHCP message.
    pub bytes: Vec<u8>,
    /// Whether option 82 was echoed (false if absent or it did not fit).
    pub relay_info_echoed: bool,
}

fn push_option(b: &mut Vec<u8>, code: u8, data: &[u8]) {
    // Callers pass data of at most 255 octets (fixed small options, or
    // option 82 data whose length came from a one-octet length field).
    if let Ok(len) = u8::try_from(data.len()) {
        b.push(code);
        b.push(len);
        b.extend_from_slice(data);
    }
}

impl ProxyReply<'_> {
    /// Encodes the reply within `limit` octets.
    ///
    /// Option 82 is placed last, just before End, and is left out if it
    /// would push the reply past `limit` (RFC 3046 §2.2). `limit` values
    /// outside 300..=1472 are clamped into that range.
    ///
    /// # Errors
    ///
    /// [`BuildError::BadBootFile`] or [`BuildError::TooLarge`].
    pub fn encode(&self, limit: usize) -> Result<Encoded, BuildError> {
        let limit = limit.clamp(MIN_REPLY_LEN, MAX_MESSAGE_LEN);
        let file = self.boot_file;
        if file.is_empty() || file.len() > MAX_BOOT_FILE_LEN || file.contains(&0) {
            return Err(BuildError::BadBootFile);
        }

        // Header fields per specs/standards/pxe-dhcp.md §3.1 (RFC 2131
        // §4.3.1 Table 3), with yiaddr 0 for a proxy reply (decision 0003).
        let mut b = Vec::with_capacity(limit);
        b.extend_from_slice(&[2, 1, 6, 0]); // op BOOTREPLY, Ethernet, hlen 6, hops 0
        b.extend_from_slice(&self.xid.to_be_bytes());
        b.extend_from_slice(&[0, 0]); // secs
        b.extend_from_slice(&(self.flags & FLAG_BROADCAST).to_be_bytes());
        b.extend_from_slice(&[0; 4]); // ciaddr
        b.extend_from_slice(&YIADDR);
        b.extend_from_slice(&self.server_addr.octets()); // siaddr
        b.extend_from_slice(&self.giaddr.octets());
        b.extend_from_slice(&self.chaddr.octets());
        b.extend_from_slice(&[0; 10]); // rest of chaddr
        b.extend_from_slice(&[0; SNAME_LEN]);
        b.extend_from_slice(file);
        b.resize(OFF_FILE + FILE_LEN, 0);
        b.extend_from_slice(&MAGIC_COOKIE);

        push_option(&mut b, code::MESSAGE_TYPE, &[self.kind.message_type()]);
        push_option(&mut b, code::SERVER_ID, &self.server_addr.octets());
        push_option(&mut b, code::VENDOR_CLASS, REPLY_CLASS);
        push_option(&mut b, code::CLIENT_ARCH, &self.arch.to_be_bytes());
        push_option(
            &mut b,
            code::CLIENT_NDI,
            &self.client_ndi.unwrap_or(DEFAULT_NDI),
        );
        let mut machine_id = [0u8; 17];
        if let (Some(g), Some(slot)) = (self.client_guid, machine_id.get_mut(1..)) {
            slot.copy_from_slice(&g.wire_octets());
        }
        push_option(&mut b, code::CLIENT_MACHINE_ID, &machine_id);
        if let Some(item) = self.boot_item {
            // Tag 71 per specs/standards/pxe-dhcp.md §6.1: the requested
            // type and layer echoed (OPEN-T71-2 [reading]) in network byte
            // order (OPEN-T71-1 [reading]); credentials bit never set. Only
            // type 0 / layer 0 reaches here (responder), which encodes the
            // same in either byte order; resolve OPEN-T71-1 before serving
            // any other item.
            let [t0, t1] = item.server_type.to_be_bytes();
            let [l0, l1] = (item.layer & 0x7fff).to_be_bytes();
            push_option(
                &mut b,
                code::VENDOR_SPECIFIC,
                &[code::PXE_BOOT_ITEM, 4, t0, t1, l0, l1, code::END],
            );
        }

        // End needs one more octet.
        if b.len() >= limit {
            return Err(BuildError::TooLarge);
        }
        let mut relay_info_echoed = false;
        // Option 82 header (2) + data + End (1) must fit.
        if let Some(ri) = self.relay_info
            && b.len() + ri.len() + 3 <= limit
            && u8::try_from(ri.len()).is_ok()
        {
            push_option(&mut b, code::RELAY_AGENT_INFO, ri);
            relay_info_echoed = true;
        }
        b.push(code::END);
        if b.len() < MIN_REPLY_LEN {
            b.resize(MIN_REPLY_LEN, 0);
        }
        Ok(Encoded {
            bytes: b,
            relay_info_echoed,
        })
    }
}

/// A decoded BOOTREPLY, for verifying replies in tests and fuzz targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyView<'a> {
    /// Transaction ID.
    pub xid: u32,
    /// `flags`.
    pub flags: u16,
    /// `ciaddr`.
    pub ciaddr: Ipv4Addr,
    /// `yiaddr`.
    pub yiaddr: Ipv4Addr,
    /// `siaddr`.
    pub siaddr: Ipv4Addr,
    /// `giaddr`.
    pub giaddr: Ipv4Addr,
    /// First six octets of `chaddr`.
    pub chaddr: [u8; 6],
    /// `file` up to its first NUL.
    pub file: &'a [u8],
    /// Option 53 value, if present.
    pub msg_type: Option<u8>,
    /// Option 54, if present.
    pub server_id: Option<Ipv4Addr>,
    /// Option 82 data, if present.
    pub relay_info: Option<&'a [u8]>,
    /// Option 43 data, if present.
    pub vendor_specific: Option<&'a [u8]>,
    /// Option 93 data, if present.
    pub arch: Option<&'a [u8]>,
    /// Option 94 data, if present.
    pub ndi: Option<&'a [u8]>,
    /// Option 97 data, if present.
    pub machine_id: Option<&'a [u8]>,
    /// Every option code present in the options field.
    pub codes: OptionSet,
    /// The last option code before End.
    pub last_code: Option<u8>,
}

/// Decodes a BOOTREPLY (op 2). Bounds-checked like [`crate::parse_request`].
///
/// # Errors
///
/// A [`ParseError`] if the message is not a well-formed BOOTREPLY.
pub fn inspect_reply(buf: &[u8]) -> Result<ReplyView<'_>, ParseError> {
    let len = buf.len();
    if len < MIN_MESSAGE_LEN {
        return Err(ParseError::TooShort { len });
    }
    if len > MAX_MESSAGE_LEN {
        return Err(ParseError::TooLong { len });
    }
    let short = ParseError::TooShort { len };
    let [op, htype, hlen, _hops] = field::<4>(buf, OFF_OP).ok_or(short)?;
    if op != 2 {
        return Err(ParseError::NotBootReply { op });
    }
    if htype != 1 {
        return Err(ParseError::BadHardwareType { htype });
    }
    if hlen != 6 {
        return Err(ParseError::BadHardwareLength { hlen });
    }
    if field::<4>(buf, OFF_COOKIE) != Some(MAGIC_COOKIE) {
        return Err(ParseError::BadCookie);
    }
    let file_area = buf.get(OFF_FILE..OFF_FILE + FILE_LEN).ok_or(short)?;
    let file_end = file_area.iter().position(|&c| c == 0).unwrap_or(FILE_LEN);
    let mut view = ReplyView {
        xid: u32::from_be_bytes(field::<4>(buf, OFF_XID).ok_or(short)?),
        flags: u16::from_be_bytes(field::<2>(buf, OFF_FLAGS).ok_or(short)?),
        ciaddr: ipv4_at(buf, OFF_CIADDR).ok_or(short)?,
        yiaddr: ipv4_at(buf, OFF_YIADDR).ok_or(short)?,
        siaddr: ipv4_at(buf, OFF_SIADDR).ok_or(short)?,
        giaddr: ipv4_at(buf, OFF_GIADDR).ok_or(short)?,
        chaddr: field::<6>(buf, OFF_CHADDR).ok_or(short)?,
        file: file_area.get(..file_end).ok_or(short)?,
        msg_type: None,
        server_id: None,
        relay_info: None,
        vendor_specific: None,
        arch: None,
        ndi: None,
        machine_id: None,
        codes: OptionSet::default(),
        last_code: None,
    };
    let opts = buf.get(OFF_OPTIONS..).ok_or(short)?;
    options::walk(opts, EndRule::Required, |c, d| {
        if view.codes.insert(c) {
            return Err(ParseError::DuplicateOption { code: c });
        }
        view.last_code = Some(c);
        match (c, d) {
            (code::MESSAGE_TYPE, [v]) => view.msg_type = Some(*v),
            (code::SERVER_ID, [a, b, cc, dd]) => {
                view.server_id = Some(Ipv4Addr::new(*a, *b, *cc, *dd));
            }
            (code::RELAY_AGENT_INFO, _) => view.relay_info = Some(d),
            (code::VENDOR_SPECIFIC, _) => view.vendor_specific = Some(d),
            (code::CLIENT_ARCH, _) => view.arch = Some(d),
            (code::CLIENT_NDI, _) => view.ndi = Some(d),
            (code::CLIENT_MACHINE_ID, _) => view.machine_id = Some(d),
            _ => {}
        }
        Ok(())
    })?;
    Ok(view)
}

/// Options a proxy reply must never carry: subnet mask, router, lease
/// time, renewal and rebinding times (REQ-BOOT-010).
pub const FORBIDDEN_REPLY_OPTIONS: [u8; 5] = [
    code::SUBNET_MASK,
    code::ROUTER,
    code::LEASE_TIME,
    code::RENEWAL_TIME,
    code::REBINDING_TIME,
];

#[cfg(test)]
mod tests {
    use super::*;

    fn mac() -> MacAddr {
        MacAddr::new([0x52, 0x54, 0, 0x12, 0x34, 0x56]).unwrap()
    }

    fn base<'a>(ri: Option<&'a [u8]>) -> ProxyReply<'a> {
        ProxyReply {
            kind: ReplyKind::Offer,
            xid: 0x0102_0304,
            flags: 0xffff,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: mac(),
            server_addr: Ipv4Addr::new(10, 20, 1, 2),
            boot_file: b"usgp-test-payload.efi",
            arch: ClientArch::X64_UEFI,
            client_ndi: None,
            client_guid: None,
            boot_item: None,
            relay_info: ri,
        }
    }

    #[test]
    fn yiaddr_always_zero() {
        for kind in [ReplyKind::Offer, ReplyKind::Ack] {
            let r = ProxyReply { kind, ..base(None) };
            let e = r.encode(DEFAULT_REPLY_LIMIT).unwrap();
            let v = inspect_reply(&e.bytes).unwrap();
            assert_eq!(v.yiaddr, Ipv4Addr::UNSPECIFIED);
            assert_eq!(v.ciaddr, Ipv4Addr::UNSPECIFIED);
        }
    }

    #[test]
    fn reply_has_no_lease_options() {
        let item = Some(BootItem::DEFAULT);
        let r = ProxyReply {
            kind: ReplyKind::Ack,
            boot_item: item,
            ..base(Some(&[1, 2, b'a', b'b']))
        };
        let e = r.encode(DEFAULT_REPLY_LIMIT).unwrap();
        let v = inspect_reply(&e.bytes).unwrap();
        for c in FORBIDDEN_REPLY_OPTIONS {
            assert!(!v.codes.contains(c), "option {c} present");
        }
        for c in 0..=255u8 {
            let allowed = [53, 54, 60, 93, 94, 97, 43, 82];
            assert_eq!(v.codes.contains(c), allowed.contains(&c), "option {c}");
        }
    }

    #[test]
    fn offer_content() {
        let e = base(None).encode(DEFAULT_REPLY_LIMIT).unwrap();
        assert!(!e.relay_info_echoed);
        assert_eq!(e.bytes.len(), MIN_REPLY_LEN);
        let v = inspect_reply(&e.bytes).unwrap();
        assert!(v.codes.contains(94) && v.codes.contains(97));
        let v = inspect_reply(&e.bytes).unwrap();
        assert_eq!(v.xid, 0x0102_0304);
        assert_eq!(v.flags, FLAG_BROADCAST);
        assert_eq!(v.siaddr, Ipv4Addr::new(10, 20, 1, 2));
        assert_eq!(v.server_id, Some(Ipv4Addr::new(10, 20, 1, 2)));
        assert_eq!(v.chaddr, mac().octets());
        assert_eq!(v.file, b"usgp-test-payload.efi");
        assert_eq!(v.msg_type, Some(2));
        assert_eq!(v.vendor_specific, None, "no option 43 in offers");
        assert!(v.codes.contains(60) && v.codes.contains(93));
    }

    #[test]
    fn pxe_identity_options_always_present() {
        // Defaults when the client sent no 94/97.
        let e = base(None).encode(DEFAULT_REPLY_LIMIT).unwrap();
        let v = inspect_reply(&e.bytes).unwrap();
        assert_eq!(v.arch, Some(&[0, 7][..]));
        assert_eq!(v.ndi, Some(&DEFAULT_NDI[..]));
        assert_eq!(v.machine_id, Some(&[0u8; 17][..]));
        // Client values echoed.
        let wire: [u8; 16] = core::array::from_fn(|i| u8::try_from(i).unwrap() + 1);
        let r = ProxyReply {
            client_ndi: Some([1, 3, 16]),
            client_guid: Some(Guid::from_wire(wire)),
            ..base(None)
        };
        let e = r.encode(DEFAULT_REPLY_LIMIT).unwrap();
        let v = inspect_reply(&e.bytes).unwrap();
        assert_eq!(v.ndi, Some(&[1, 3, 16][..]));
        let mut want = vec![0u8];
        want.extend_from_slice(&wire);
        assert_eq!(v.machine_id, Some(&want[..]));
    }

    #[test]
    fn opt82_over_255_never_split() {
        let ri = [9u8; 300];
        let e = base(Some(&ri)).encode(1472).unwrap();
        assert!(!e.relay_info_echoed);
        assert_eq!(inspect_reply(&e.bytes).unwrap().relay_info, None);
    }

    #[test]
    fn ack_echoes_tag71() {
        let r = ProxyReply {
            kind: ReplyKind::Ack,
            boot_item: Some(BootItem::DEFAULT),
            ..base(None)
        };
        let v_bytes = r.encode(DEFAULT_REPLY_LIMIT).unwrap().bytes;
        let v = inspect_reply(&v_bytes).unwrap();
        assert_eq!(v.msg_type, Some(5));
        assert_eq!(v.vendor_specific, Some(&[71, 4, 0, 0, 0, 0, 255][..]));
    }

    #[test]
    fn opt82_echoed_unchanged_last() {
        let ri: Vec<u8> = (0..255u8).collect();
        let e = base(Some(&ri)).encode(DEFAULT_REPLY_LIMIT).unwrap();
        assert!(e.relay_info_echoed);
        let v = inspect_reply(&e.bytes).unwrap();
        assert_eq!(v.relay_info, Some(&ri[..]));
        assert_eq!(v.last_code, Some(82));
        assert!(e.bytes.len() <= DEFAULT_REPLY_LIMIT);
    }

    #[test]
    fn opt82_omitted_when_too_large() {
        let ri = [7u8; 255];
        let e = base(Some(&ri)).encode(300).unwrap();
        assert!(!e.relay_info_echoed);
        assert!(e.bytes.len() <= 300);
        let v = inspect_reply(&e.bytes).unwrap();
        assert_eq!(v.relay_info, None);
    }

    #[test]
    fn boot_file_limits() {
        let long = [b'a'; 128];
        assert_eq!(
            ProxyReply {
                boot_file: &long,
                ..base(None)
            }
            .encode(548),
            Err(BuildError::BadBootFile)
        );
        assert_eq!(
            ProxyReply {
                boot_file: b"",
                ..base(None)
            }
            .encode(548),
            Err(BuildError::BadBootFile)
        );
        assert_eq!(
            ProxyReply {
                boot_file: b"a\0b",
                ..base(None)
            }
            .encode(548),
            Err(BuildError::BadBootFile)
        );
        let max = [b'a'; 127];
        let e = ProxyReply {
            boot_file: &max,
            ..base(None)
        }
        .encode(548)
        .unwrap();
        assert_eq!(inspect_reply(&e.bytes).unwrap().file, &max[..]);
    }

    #[test]
    fn size_limit_rule() {
        assert_eq!(reply_size_limit(None), 548);
        assert_eq!(reply_size_limit(Some(576)), 548);
        assert_eq!(reply_size_limit(Some(1000)), 972);
        assert_eq!(reply_size_limit(Some(1500)), 1472);
        assert_eq!(reply_size_limit(Some(u16::MAX)), 1472);
    }

    #[test]
    fn inspect_rejects_requests() {
        let mut b = base(None).encode(548).unwrap().bytes;
        *b.first_mut().unwrap() = 1;
        assert_eq!(inspect_reply(&b), Err(ParseError::NotBootReply { op: 1 }));
    }
}
