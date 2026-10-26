//! Parser for incoming BOOTREQUEST messages (DHCPDISCOVER / DHCPREQUEST).
//!
//! The parser borrows from the input buffer and never allocates. Every read
//! is bounds-checked (`get`, `split_first`, `split_at_checked`), and every
//! rule failure returns a [`ParseError`]; the caller drops the message
//! silently (REQ-BOOT-006).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation)
// - SPEC: specs/boot-network.md#REQ-BOOT-006, #REQ-BOOT-007
// - RFC 2131 §2 - fixed header, magic cookie, minimum sizes
// - RFC 2132 §2 (encoding), §9.3 (overload), §9.6 (message type), §9.7
//   (server identifier), §9.10 (maximum message size), §9.13 (vendor class)
// - RFC 3396 §4, §5, §7 - repeated options reassembled in aggregate-buffer
//   order before interpretation (specs/standards/dhcp-long-options.md §2, §3)
// - RFC 4578 §2.1-§2.3 - options 93, 94, 97
// - draft-henry-remote-boot-protocol-00 §3.1.1 (vendor class form), §3.2.3
//   (option 43 sub-options)

use core::net::Ipv4Addr;
use std::borrow::Cow;

use crate::error::ParseError;
use crate::ident::{ArchList, ClientArch, Guid, MacAddr};
use crate::options::{self, EndRule, Pieces, code};

/// Smallest structurally complete message: 236-octet header plus the
/// 4-octet cookie. Replies are inspected against this; requests must also
/// meet [`MIN_REQUEST_LEN`].
pub const MIN_MESSAGE_LEN: usize = 240;
/// Smallest accepted request: the 300-octet minimum BOOTP message, counted
/// in the UDP data (specs/standards/pxe-dhcp.md §3.2; RFC 1542 §2.1, §5.1).
/// A shorter request is dropped silently and counted
/// ([`ParseError::ShortMessage`]).
pub const MIN_REQUEST_LEN: usize = 300;
/// Largest accepted message (Ethernet MTU 1500 minus IP and UDP headers).
pub const MAX_MESSAGE_LEN: usize = 1472;
/// Largest `hops` value a request may carry (RFC 1542 §4.1.1).
pub const MAX_HOPS: u8 = 16;
/// DHCP magic cookie 99.130.83.99 (RFC 2131 §3).
pub const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
/// Smallest meaningful option 57 value (RFC 2132 §9.10).
pub const MIN_MAX_MESSAGE_SIZE: u16 = 576;
/// The BROADCAST bit of `flags` (RFC 2131 §2).
pub const FLAG_BROADCAST: u16 = 0x8000;

/// Prefix of a PXE client's option 60 (draft-henry §3.1.1).
pub const PXE_CLIENT_CLASS: &[u8] = b"PXEClient";

// Fixed header offsets (RFC 2131 §2, Figure 1).
/// Offset of the `op`, `htype`, `hlen`, `hops` octets.
pub(crate) const OFF_OP: usize = 0;
pub(crate) const OFF_XID: usize = 4;
pub(crate) const OFF_FLAGS: usize = 10;
pub(crate) const OFF_CIADDR: usize = 12;
pub(crate) const OFF_YIADDR: usize = 16;
pub(crate) const OFF_SIADDR: usize = 20;
pub(crate) const OFF_GIADDR: usize = 24;
pub(crate) const OFF_CHADDR: usize = 28;
pub(crate) const OFF_SNAME: usize = 44;
pub(crate) const OFF_FILE: usize = 108;
pub(crate) const OFF_COOKIE: usize = 236;
pub(crate) const OFF_OPTIONS: usize = 240;
pub(crate) const SNAME_LEN: usize = 64;
pub(crate) const FILE_LEN: usize = 128;

/// The DHCP message types this service handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// DHCPDISCOVER (1).
    Discover,
    /// DHCPREQUEST (3).
    Request,
}

/// A PXE boot item (option 43 sub-option 71): boot-server type and layer.
///
/// Layout per specs/standards/pxe-dhcp.md §6.1 (draft-henry §3.2.3.6, UEFI
/// 2.10 §24.3.9): length exactly 4; a 2-octet boot-server type, then a
/// 2-octet layer whose most significant bit (0x8000) is the credentials
/// flag and whose low 15 bits (mask 0x7FFF) are the layer number.
///
/// Byte order is OPEN-T71-1: both fields are read in network byte order,
/// which §6.1 marks as a [reading]. Only [`BootItem::DEFAULT`] (all zero,
/// the same in either byte order) is ever answered, so the open point
/// cannot change which requests are served. It must be closed before any
/// non-zero type or layer is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootItem {
    /// Boot-server type requested.
    pub server_type: u16,
    /// Layer number (low 15 bits of the layer field).
    pub layer: u16,
    /// The layer's high bit: the client asks for credentials.
    pub credentials: bool,
}

impl BootItem {
    /// Type 0, layer 0, no credentials: the only item this service answers
    /// (UEFI Appendix E.4.20.3 default when tag 71 is absent).
    pub const DEFAULT: Self = Self {
        server_type: 0,
        layer: 0,
        credentials: false,
    };

    /// Encoded length of tag 71 data.
    pub const LEN: usize = 4;
}

/// A parsed, structurally valid BOOTREQUEST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    /// Transaction ID (echoed in the reply).
    pub xid: u32,
    /// Raw `flags` field.
    pub flags: u16,
    /// Relay hop count.
    pub hops: u8,
    /// Client's current address (0 if none).
    pub ciaddr: Ipv4Addr,
    /// Relay agent address (0 if not relayed).
    pub giaddr: Ipv4Addr,
    /// Claimed hardware address.
    pub chaddr: MacAddr,
    /// Option 53.
    pub msg_type: MessageType,
    /// Option 54, if present.
    pub server_id: Option<Ipv4Addr>,
    /// Option 60 (reassembled) with one trailing NUL removed; empty if
    /// absent.
    pub vendor_class: Cow<'a, [u8]>,
    /// Option 93 list (reassembled); empty if absent.
    pub arch: ArchList<'a>,
    /// Option 94 (type, major, minor), if present.
    pub ndi: Option<[u8; 3]>,
    /// Option 97 GUID, if present.
    pub guid: Option<Guid>,
    /// Option 57, if present and at least 576.
    pub max_message_size: Option<u16>,
    /// Option 82 data (reassembled), if present; echoed unchanged when it
    /// fits in one instance.
    pub relay_info: Option<Cow<'a, [u8]>>,
    /// Option 43 sub-option 71, if present.
    pub boot_item: Option<BootItem>,
}

impl Request<'_> {
    /// Whether the client set the BROADCAST flag.
    #[must_use]
    pub fn broadcast(&self) -> bool {
        self.flags & FLAG_BROADCAST != 0
    }

    /// Whether option 60 identifies a PXE client: exactly `PXEClient`, or
    /// `PXEClient:` followed by fields. Case-sensitive.
    #[must_use]
    pub fn is_pxe_client(&self) -> bool {
        is_pxe_class(&self.vendor_class)
    }
}

fn is_pxe_class(vc: &[u8]) -> bool {
    match vc.strip_prefix(PXE_CLIENT_CLASS) {
        Some(rest) => rest.is_empty() || rest.first() == Some(&b':'),
        None => false,
    }
}

/// Reads `N` octets at `off`.
pub(crate) fn field<const N: usize>(buf: &[u8], off: usize) -> Option<[u8; N]> {
    let end = off.checked_add(N)?;
    buf.get(off..end)?.try_into().ok()
}

pub(crate) fn ipv4_at(buf: &[u8], off: usize) -> Option<Ipv4Addr> {
    field::<4>(buf, off).map(Ipv4Addr::from)
}

/// Whether `a` is usable as a unicast host address on the wire: not 0/8,
/// loopback, multicast, reserved 240/4, or limited broadcast.
#[must_use]
pub fn is_unicast_host(a: Ipv4Addr) -> bool {
    let [first, ..] = a.octets();
    !(first == 0 || a.is_loopback() || a.is_multicast() || first >= 240)
}

fn bad_len(code: u8, data: &[u8]) -> ParseError {
    ParseError::BadOptionLength {
        code,
        len: data.len(),
    }
}

/// Values decoded from the reassembled options.
struct Decoded<'a> {
    msg_type: Option<u8>,
    server_id: Option<Ipv4Addr>,
    vendor_class: Cow<'a, [u8]>,
    arch: ArchList<'a>,
    ndi: Option<[u8; 3]>,
    guid: Option<Guid>,
    max_message_size: Option<u16>,
    relay_info: Option<Cow<'a, [u8]>>,
    boot_item: Option<BootItem>,
}

/// Reads option 52 from the `options` field's own pieces.
///
/// Option 52 decides whether `file`/`sname` are part of the buffer, so it
/// is taken from the `options` field only (dhcp-long-options.md §2); one
/// found inside `file` or `sname` is ignored (plan §6). Repeats are joined
/// like any option, so two copies give length 2, which is malformed.
fn overload(pieces: &Pieces<'_>) -> Result<Option<u8>, ParseError> {
    match pieces.joined(code::OVERLOAD).as_deref() {
        None => Ok(None),
        Some([v @ 1..=3]) => Ok(Some(*v)),
        Some([v]) => Err(ParseError::BadOverload { value: *v }),
        Some(d) => Err(bad_len(code::OVERLOAD, d)),
    }
}

/// Applies each option's own rules to its reassembled value (RFC 3396 §7:
/// the joined result is the one option).
fn decode<'a>(pieces: &Pieces<'a>) -> Result<Decoded<'a>, ParseError> {
    let msg_type = match pieces.joined(code::MESSAGE_TYPE).as_deref() {
        None => None,
        Some([v]) => Some(*v),
        Some(d) => return Err(bad_len(code::MESSAGE_TYPE, d)),
    };
    let server_id = match pieces.joined(code::SERVER_ID).as_deref() {
        None => None,
        Some([a, b, c, d]) => Some(Ipv4Addr::new(*a, *b, *c, *d)),
        Some(d) => return Err(bad_len(code::SERVER_ID, d)),
    };
    let max_message_size = match pieces.joined(code::MAX_MESSAGE_SIZE).as_deref() {
        None => None,
        // Values below 576 are treated as absent (RFC 2132 §9.10).
        Some([hi, lo]) => {
            Some(u16::from_be_bytes([*hi, *lo])).filter(|v| *v >= MIN_MAX_MESSAGE_SIZE)
        }
        Some(d) => return Err(bad_len(code::MAX_MESSAGE_SIZE, d)),
    };
    let vendor_class = match pieces.joined(code::VENDOR_CLASS) {
        None => Cow::Borrowed(&[][..]),
        Some(d) if d.is_empty() => return Err(bad_len(code::VENDOR_CLASS, &d)),
        // Receivers must tolerate one trailing NUL (RFC 2132 §2).
        Some(Cow::Borrowed(d)) => Cow::Borrowed(d.strip_suffix(&[0]).unwrap_or(d)),
        Some(Cow::Owned(mut d)) => {
            if d.last() == Some(&0) {
                d.pop();
            }
            Cow::Owned(d)
        }
    };
    if let Some(d) = pieces.joined(code::CLIENT_ID)
        && d.len() < 2
    {
        return Err(bad_len(code::CLIENT_ID, &d));
    }
    let arch = match pieces.joined(code::CLIENT_ARCH) {
        None => ArchList::EMPTY,
        Some(d) if d.is_empty() || !d.len().is_multiple_of(2) => {
            return Err(bad_len(code::CLIENT_ARCH, &d));
        }
        Some(d) => ArchList::from_checked(d),
    };
    let ndi = match pieces.joined(code::CLIENT_NDI).as_deref() {
        None => None,
        Some([t, major, minor]) => Some([*t, *major, *minor]),
        Some(d) => return Err(bad_len(code::CLIENT_NDI, d)),
    };
    let guid = match pieces.joined(code::CLIENT_MACHINE_ID).as_deref() {
        None => None,
        Some(d) => match d.split_first() {
            Some((0, rest)) => {
                let g: [u8; 16] = rest
                    .try_into()
                    .map_err(|_| bad_len(code::CLIENT_MACHINE_ID, d))?;
                Some(Guid::from_wire(g))
            }
            Some((kind, rest)) if rest.len() == 16 => {
                return Err(ParseError::BadMachineIdType { kind: *kind });
            }
            _ => return Err(bad_len(code::CLIENT_MACHINE_ID, d)),
        },
    };
    // Sub-options are parsed only after reassembly (dhcp-long-options.md §3).
    let boot_item = match pieces.joined(code::VENDOR_SPECIFIC) {
        Some(d) => parse_vendor_specific(&d)?,
        None => None,
    };
    Ok(Decoded {
        msg_type,
        server_id,
        vendor_class,
        arch,
        ndi,
        guid,
        max_message_size,
        relay_info: pieces.joined(code::RELAY_AGENT_INFO),
        boot_item,
    })
}

/// Parses the PXE boot item out of option 43 data.
///
/// The sub-options use the RFC 2132 §8.4 encapsulated format. Only tag 71
/// is read; other tags are skipped. Overruns and a repeated tag 71 are
/// malformed.
///
// COMPLIANCE MAPPING:
// - SPEC: specs/standards/pxe-dhcp.md §6.1 - tag 71 length 4, type then
//   layer, credentials bit 0x8000, layer mask 0x7FFF. Network byte order is
//   the §6.1 [reading] for OPEN-T71-1; it must be resolved before any
//   non-zero type or layer is supported (only type 0 / layer 0 is answered,
//   which encodes the same in either order).
fn parse_vendor_specific(data: &[u8]) -> Result<Option<BootItem>, ParseError> {
    let mut item = None;
    options::walk(data, EndRule::Optional, |tag, val| {
        if tag != code::PXE_BOOT_ITEM {
            return Ok(());
        }
        if item.is_some() {
            return Err(ParseError::BadVendorSubOption { tag });
        }
        match val {
            [t0, t1, l0, l1] => {
                let layer = u16::from_be_bytes([*l0, *l1]);
                item = Some(BootItem {
                    server_type: u16::from_be_bytes([*t0, *t1]),
                    layer: layer & 0x7fff,
                    credentials: layer & 0x8000 != 0,
                });
                Ok(())
            }
            _ => Err(ParseError::BadVendorSubOption { tag }),
        }
    })
    .map_err(|e| match e {
        ParseError::OptionTruncated { code } => ParseError::BadVendorSubOption { tag: code },
        other => other,
    })?;
    Ok(item)
}

/// Checks the `Arch:` field of a PXE vendor class against option 93.
///
/// `PXEClient:Arch:xxxxx[:...]` must carry exactly five decimal digits whose
/// value appears in the option 93 list (draft-henry §3.1.1; plan §6).
fn check_vendor_arch(vc: &[u8], arch: &ArchList<'_>) -> Result<(), ParseError> {
    let Some(rest) = vc.strip_prefix(b"PXEClient:Arch:") else {
        return Ok(());
    };
    let (digits, tail) = rest
        .split_at_checked(5)
        .ok_or(ParseError::BadVendorClassArch)?;
    if !(tail.is_empty() || tail.first() == Some(&b':')) {
        return Err(ParseError::BadVendorClassArch);
    }
    let mut value: u32 = 0;
    for &d in digits {
        if !d.is_ascii_digit() {
            return Err(ParseError::BadVendorClassArch);
        }
        value = value * 10 + u32::from(d - b'0');
    }
    let value = u16::try_from(value).map_err(|_| ParseError::BadVendorClassArch)?;
    if arch.contains(ClientArch(value)) {
        Ok(())
    } else {
        Err(ParseError::VendorClassArchMismatch)
    }
}

/// Parses an incoming BOOTREQUEST.
///
/// Rules (plan §6, SI-10): length 300 to 1472 (300 is the minimum BOOTP
/// message, specs/standards/pxe-dhcp.md §3.2); `op` 1, `htype` 1, `hlen` 6;
/// magic cookie; bounds-checked options walk with End required; option 52
/// values 1 to 3 (overloaded `file` then `sname` parsed once, an overload
/// option inside them ignored); repeated options reassembled in buffer
/// order (RFC 3396, `options::Pieces::joined`); per-option length checks
/// on the joined values; option 53
/// DISCOVER or REQUEST; option 60 `Arch:` consistent with option 93;
/// `chaddr` unicast and non-zero; `ciaddr` zero or unicast.
///
/// `hops` and `giaddr` are policy checks made by
/// [`crate::responder::respond`].
///
/// # Errors
///
/// A [`ParseError`] naming the first rule broken.
pub fn parse_request(buf: &[u8]) -> Result<Request<'_>, ParseError> {
    let len = buf.len();
    if len < OFF_COOKIE {
        return Err(ParseError::TooShort { len });
    }
    if len < MIN_MESSAGE_LEN {
        return Err(ParseError::MissingCookie);
    }
    if len > MAX_MESSAGE_LEN {
        return Err(ParseError::TooLong { len });
    }
    // RFC 1542 §2.1 receiver check (pxe-dhcp.md §3.2): UDP data must hold
    // the 300-octet BOOTP message; shorter ones are discarded and counted.
    if len < MIN_REQUEST_LEN {
        return Err(ParseError::ShortMessage { len });
    }
    let short = ParseError::TooShort { len };
    let [op, htype, hlen, hops] = field::<4>(buf, OFF_OP).ok_or(short)?;
    if op != 1 {
        return Err(ParseError::NotBootRequest { op });
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
    let xid = u32::from_be_bytes(field::<4>(buf, OFF_XID).ok_or(short)?);
    let flags = u16::from_be_bytes(field::<2>(buf, OFF_FLAGS).ok_or(short)?);
    let ciaddr = ipv4_at(buf, OFF_CIADDR).ok_or(short)?;
    let giaddr = ipv4_at(buf, OFF_GIADDR).ok_or(short)?;
    let chaddr = field::<6>(buf, OFF_CHADDR).ok_or(short)?;
    let chaddr = MacAddr::new(chaddr).map_err(|_| ParseError::BadChaddr)?;
    if !ciaddr.is_unspecified() && !is_unicast_host(ciaddr) {
        return Err(ParseError::BadCiaddr);
    }

    let opts = buf.get(OFF_OPTIONS..).ok_or(short)?;
    let file = buf.get(OFF_FILE..OFF_FILE + FILE_LEN).ok_or(short)?;
    let sname = buf.get(OFF_SNAME..OFF_SNAME + SNAME_LEN).ok_or(short)?;

    // Aggregate option buffer, RFC 3396 §5 order: options, file, sname.
    // No single piece may cross a field boundary: `walk` treats an overrun
    // as malformed.
    let mut pieces = Pieces::default();
    options::walk(opts, EndRule::Required, |c, d| {
        pieces.push(c, d);
        Ok(())
    })?;
    let overloaded: &[&[u8]] = match overload(&pieces)? {
        Some(1) => &[file],
        Some(2) => &[sname],
        Some(3) => &[file, sname],
        _ => &[],
    };
    for area in overloaded {
        options::walk(area, EndRule::Optional, |c, d| {
            if c != code::OVERLOAD {
                pieces.push(c, d);
            }
            Ok(())
        })?;
    }
    let dec = decode(&pieces)?;

    let msg_type = match dec.msg_type {
        None => return Err(ParseError::MissingMessageType),
        Some(1) => MessageType::Discover,
        Some(3) => MessageType::Request,
        Some(value) => return Err(ParseError::UnhandledMessageType { value }),
    };
    if is_pxe_class(&dec.vendor_class) {
        check_vendor_arch(&dec.vendor_class, &dec.arch)?;
    }

    Ok(Request {
        xid,
        flags,
        hops,
        ciaddr,
        giaddr,
        chaddr,
        msg_type,
        server_id: dec.server_id,
        vendor_class: dec.vendor_class,
        arch: dec.arch,
        ndi: dec.ndi,
        guid: dec.guid,
        max_message_size: dec.max_message_size,
        relay_info: dec.relay_info,
        boot_item: dec.boot_item,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::craft::RequestBuilder;

    fn put(b: &mut [u8], off: usize, bytes: &[u8]) {
        b.get_mut(off..off + bytes.len())
            .unwrap()
            .copy_from_slice(bytes);
    }

    #[test]
    fn hand_built_discover_parses() {
        // Built byte by byte, independent of RequestBuilder.
        let mut b = vec![0u8; 240];
        put(&mut b, 0, &[1, 1, 6]);
        put(&mut b, 4, &0xdead_beef_u32.to_be_bytes());
        put(&mut b, 10, &[0x80]);
        put(&mut b, 28, &[0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        put(&mut b, 236, &MAGIC_COOKIE);
        b.extend_from_slice(&[53, 1, 1]);
        b.extend_from_slice(&[60, 9]);
        b.extend_from_slice(b"PXEClient");
        b.extend_from_slice(&[93, 2, 0, 7, 255]);
        // 259 octets so far: below the 300-octet BOOTP minimum.
        assert_eq!(
            parse_request(&b),
            Err(ParseError::ShortMessage { len: 259 })
        );
        // Zero padding after End, as clients send it (pxe-dhcp.md §3.2).
        b.resize(MIN_REQUEST_LEN, 0);
        let r = parse_request(&b).unwrap();
        assert_eq!(r.xid, 0xdead_beef);
        assert!(r.broadcast());
        assert_eq!(r.msg_type, MessageType::Discover);
        assert_eq!(r.chaddr.to_string(), "52:54:00:12:34:56");
        assert!(r.is_pxe_client());
        assert!(r.arch.contains(ClientArch::X64_UEFI));
        assert_eq!(r.server_id, None);
        assert_eq!(r.guid, None);
    }

    #[test]
    fn builder_discover_fields() {
        let r_bytes = RequestBuilder::pxe_discover().build();
        let r = parse_request(&r_bytes).unwrap();
        assert_eq!(&*r.vendor_class, b"PXEClient:Arch:00007:UNDI:003016");
        assert_eq!(r.ndi, Some([1, 3, 16]));
        assert_eq!(r.max_message_size, Some(1472));
        assert!(r.guid.is_some());
        assert_eq!(r.boot_item, None);
    }

    #[test]
    fn vendor_class_trailing_nul_tolerated() {
        let b = RequestBuilder::pxe_discover()
            .set_option(60, b"PXEClient\0".to_vec())
            .build();
        assert_eq!(&*parse_request(&b).unwrap().vendor_class, b"PXEClient");
    }

    #[test]
    fn pxe_class_rules() {
        assert!(is_pxe_class(b"PXEClient"));
        assert!(is_pxe_class(b"PXEClient:Arch:00007"));
        assert!(!is_pxe_class(b"PXEClientX"));
        assert!(!is_pxe_class(b"PXECLIENT"));
        assert!(!is_pxe_class(b"PXEClien"));
        assert!(!is_pxe_class(b""));
    }

    #[test]
    fn overload_file_then_sname_order() {
        // Option 54 in `file`, option 93 in `sname`, both found.
        let mut file = vec![54, 4, 10, 0, 0, 2, 255];
        file.resize(128, 0);
        let mut sname = vec![93, 2, 0, 7, 255];
        sname.resize(64, 0);
        let b = RequestBuilder::pxe_discover()
            .without(93)
            .option(52, vec![3])
            .file_area(file)
            .sname_area(sname)
            .build();
        let r = parse_request(&b).unwrap();
        assert_eq!(r.server_id, Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert!(r.arch.contains(ClientArch::X64_UEFI));
    }

    #[test]
    fn vendor_arch_check() {
        let a = [0u8, 7];
        let l = ArchList::from_checked(&a[..]);
        let l = &l;
        assert_eq!(check_vendor_arch(b"PXEClient", l), Ok(()));
        assert_eq!(check_vendor_arch(b"PXEClient:Arch:00007", l), Ok(()));
        assert_eq!(
            check_vendor_arch(b"PXEClient:Arch:00007:UNDI:003016", l),
            Ok(())
        );
        assert_eq!(
            check_vendor_arch(b"PXEClient:Arch:00000", l),
            Err(ParseError::VendorClassArchMismatch)
        );
        for bad in [
            &b"PXEClient:Arch:0007"[..],
            b"PXEClient:Arch:000x7",
            b"PXEClient:Arch:000070",
            b"PXEClient:Arch:99999",
            b"PXEClient:Arch:",
        ] {
            assert_eq!(
                check_vendor_arch(bad, l),
                Err(ParseError::BadVendorClassArch),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn boot_item_parse() {
        assert_eq!(
            parse_vendor_specific(&[71, 4, 0, 0, 0, 0, 255]),
            Ok(Some(BootItem::DEFAULT))
        );
        assert_eq!(
            parse_vendor_specific(&[6, 1, 8, 71, 4, 0, 1, 0x80, 2, 255]),
            Ok(Some(BootItem {
                server_type: 1,
                layer: 2,
                credentials: true
            }))
        );
        assert_eq!(parse_vendor_specific(&[6, 1, 8, 255]), Ok(None));
        assert_eq!(
            parse_vendor_specific(&[71, 3, 0, 0, 0]),
            Err(ParseError::BadVendorSubOption { tag: 71 })
        );
        assert_eq!(
            parse_vendor_specific(&[71, 9, 0]),
            Err(ParseError::BadVendorSubOption { tag: 71 })
        );
        assert_eq!(
            parse_vendor_specific(&[71, 4, 0, 0, 0, 0, 71, 4, 0, 0, 0, 0]),
            Err(ParseError::BadVendorSubOption { tag: 71 })
        );
    }

    #[test]
    fn unicast_host_rules() {
        assert!(is_unicast_host(Ipv4Addr::new(10, 20, 1, 1)));
        assert!(is_unicast_host(Ipv4Addr::new(169, 254, 1, 1)));
        for a in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(0, 1, 2, 3),
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(240, 0, 0, 1),
            Ipv4Addr::BROADCAST,
        ] {
            assert!(!is_unicast_host(a), "{a}");
        }
    }
}
