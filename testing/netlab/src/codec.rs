//! Minimal, independent DHCP message codec for the lab tools.
//!
//! Written from `specs/standards/pxe-dhcp.md` (RFC 2131 §2, RFC 2132 §2),
//! not from `usgp-dhcp`, so the two can check each other (plan section 1.2).
//! It decodes the fixed header and the main options field. It does not act
//! on option 52 (overload): the lab tools never need options carried in
//! `sname` or `file`, and they keep those fields as raw bytes.
//!
//! The raw-edit helpers ([`set_hops`], [`set_giaddr`],
//! [`insert_option_before_end`], [`remove_options`]) let the relay agent
//! change only what RFC 1542 §4.1.1 and RFC 3046 §2.1 allow it to change, and
//! leave every other byte of the message as received.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-10 (input
//!   validation in a test tool that faces the lab network)
//! - RFC 2131 §2 - message format; RFC 2132 §2 - option encoding
//! - RFC 1542 §4.1.1 - relay agent changes only hops and giaddr
//! - RFC 3046 §2.0 - option 82 is the last option, before End

use std::fmt;
use std::net::Ipv4Addr;
use std::ops::Range;

/// Length of the fixed BOOTP header before the magic cookie.
pub const HEADER_LEN: usize = 236;
/// The DHCP magic cookie 99.130.83.99 (RFC 2131 §3).
pub const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
/// Smallest message the lab tools accept: header plus cookie.
pub const MIN_LEN: usize = HEADER_LEN + 4;
/// Largest message the lab tools accept or build (Ethernet MTU 1500 minus
/// IPv4 and UDP headers). Lab choice, not product behaviour.
pub const MAX_LEN: usize = 1472;

/// BOOTREQUEST (RFC 2131 §2).
pub const OP_REQUEST: u8 = 1;
/// BOOTREPLY (RFC 2131 §2).
pub const OP_REPLY: u8 = 2;
/// The BROADCAST bit of `flags` (RFC 2131 §2).
pub const FLAG_BROADCAST: u16 = 0x8000;

/// Byte offset of `hops`.
const OFF_HOPS: usize = 3;
/// Byte range of `giaddr`.
const OFF_GIADDR: Range<usize> = 24..28;

/// Option codes used by the lab tools (RFC 2132, RFC 3046, RFC 4578).
pub mod opt {
    /// Pad.
    pub const PAD: u8 = 0;
    /// Subnet mask.
    pub const SUBNET_MASK: u8 = 1;
    /// Router.
    pub const ROUTER: u8 = 3;
    /// Vendor-specific information.
    pub const VENDOR_SPECIFIC: u8 = 43;
    /// Requested IP address.
    pub const REQUESTED_IP: u8 = 50;
    /// IP address lease time.
    pub const LEASE_TIME: u8 = 51;
    /// Option overload.
    pub const OVERLOAD: u8 = 52;
    /// DHCP message type.
    pub const MESSAGE_TYPE: u8 = 53;
    /// Server identifier.
    pub const SERVER_ID: u8 = 54;
    /// Parameter request list.
    pub const PARAMETER_REQUEST: u8 = 55;
    /// Maximum DHCP message size.
    pub const MAX_MESSAGE_SIZE: u8 = 57;
    /// Renewal (T1) time.
    pub const RENEWAL_TIME: u8 = 58;
    /// Rebinding (T2) time.
    pub const REBINDING_TIME: u8 = 59;
    /// Vendor class identifier.
    pub const VENDOR_CLASS: u8 = 60;
    /// Client identifier.
    pub const CLIENT_ID: u8 = 61;
    /// TFTP server name.
    pub const TFTP_SERVER_NAME: u8 = 66;
    /// Bootfile name.
    pub const BOOTFILE_NAME: u8 = 67;
    /// Relay agent information.
    pub const RELAY_AGENT_INFO: u8 = 82;
    /// Client system architecture.
    pub const CLIENT_ARCH: u8 = 93;
    /// Client network interface identifier.
    pub const CLIENT_NDI: u8 = 94;
    /// Client machine identifier.
    pub const CLIENT_UUID: u8 = 97;
    /// End.
    pub const END: u8 = 255;
}

/// DHCP message types (RFC 2132 §9.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageType {
    /// DHCPDISCOVER.
    Discover,
    /// DHCPOFFER.
    Offer,
    /// DHCPREQUEST.
    Request,
    /// DHCPDECLINE.
    Decline,
    /// DHCPACK.
    Ack,
    /// DHCPNAK.
    Nak,
    /// DHCPRELEASE.
    Release,
    /// DHCPINFORM.
    Inform,
}

impl MessageType {
    /// Wire value.
    pub fn code(self) -> u8 {
        match self {
            Self::Discover => 1,
            Self::Offer => 2,
            Self::Request => 3,
            Self::Decline => 4,
            Self::Ack => 5,
            Self::Nak => 6,
            Self::Release => 7,
            Self::Inform => 8,
        }
    }

    /// Parses a wire value.
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Discover,
            2 => Self::Offer,
            3 => Self::Request,
            4 => Self::Decline,
            5 => Self::Ack,
            6 => Self::Nak,
            7 => Self::Release,
            8 => Self::Inform,
            _ => return None,
        })
    }
}

/// Why a message could not be decoded or encoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// Shorter than [`MIN_LEN`].
    TooShort(usize),
    /// Longer than [`MAX_LEN`].
    TooLong(usize),
    /// The magic cookie is wrong.
    BadCookie,
    /// An option code at the last byte has no length octet.
    MissingLength(usize),
    /// An option's length runs past the end of the message.
    Overrun(usize),
    /// No End option in the options field.
    MissingEnd,
    /// Encoding: option data longer than 255 octets.
    OptionTooLong(u8),
    /// Encoding: Pad or End used as a data option.
    ReservedCode(u8),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "message too short ({n} octets)"),
            Self::TooLong(n) => write!(f, "message too long ({n} octets)"),
            Self::BadCookie => write!(f, "bad magic cookie"),
            Self::MissingLength(at) => write!(f, "option at offset {at} has no length octet"),
            Self::Overrun(at) => write!(f, "option at offset {at} runs past the end"),
            Self::MissingEnd => write!(f, "options field has no End option"),
            Self::OptionTooLong(code) => write!(f, "option {code} data longer than 255 octets"),
            Self::ReservedCode(code) => write!(f, "option code {code} cannot carry data"),
        }
    }
}

impl std::error::Error for CodecError {}

/// One option: code and data, in the order received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhcpOption {
    /// Option code (never Pad or End).
    pub code: u8,
    /// Option data, 0 to 255 octets.
    pub data: Vec<u8>,
}

impl DhcpOption {
    /// Builds an option.
    pub fn new(code: u8, data: impl Into<Vec<u8>>) -> Self {
        Self {
            code,
            data: data.into(),
        }
    }
}

/// A decoded DHCP message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// 1 = request, 2 = reply.
    pub op: u8,
    /// Hardware type.
    pub htype: u8,
    /// Hardware address length.
    pub hlen: u8,
    /// Relay hop count.
    pub hops: u8,
    /// Transaction ID.
    pub xid: u32,
    /// Seconds since the client started.
    pub secs: u16,
    /// Flags (bit 15 = BROADCAST).
    pub flags: u16,
    /// Client address.
    pub ciaddr: Ipv4Addr,
    /// "Your" address.
    pub yiaddr: Ipv4Addr,
    /// Next server address.
    pub siaddr: Ipv4Addr,
    /// Relay agent address.
    pub giaddr: Ipv4Addr,
    /// Client hardware address field.
    pub chaddr: [u8; 16],
    /// Server host name field (raw).
    pub sname: [u8; 64],
    /// Boot file name field (raw).
    pub file: [u8; 128],
    /// Options from the main options field, in order. Duplicates are kept.
    pub options: Vec<DhcpOption>,
}

impl Message {
    /// An all-zero message with Ethernet hardware type and the given op.
    pub fn new(op: u8, xid: u32, mac: [u8; 6]) -> Self {
        let mut chaddr = [0u8; 16];
        for (dst, src) in chaddr.iter_mut().zip(mac) {
            *dst = src;
        }
        Self {
            op,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr,
            sname: [0; 64],
            file: [0; 128],
            options: Vec::new(),
        }
    }

    /// Data of the first option with `code`.
    pub fn option(&self, code: u8) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|o| o.code == code)
            .map(|o| o.data.as_slice())
    }

    /// Number of occurrences of `code`.
    pub fn option_count(&self, code: u8) -> usize {
        self.options.iter().filter(|o| o.code == code).count()
    }

    /// Option 53, if present with length 1 and a known value.
    pub fn message_type(&self) -> Option<MessageType> {
        match self.option(opt::MESSAGE_TYPE) {
            Some([code]) => MessageType::from_code(*code),
            _ => None,
        }
    }

    /// A 4-octet option as an address.
    pub fn option_addr(&self, code: u8) -> Option<Ipv4Addr> {
        match self.option(code) {
            Some(&[a, b, c, d]) => Some(Ipv4Addr::new(a, b, c, d)),
            _ => None,
        }
    }

    /// The first six octets of `chaddr` (Ethernet).
    pub fn mac(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        for (dst, src) in mac.iter_mut().zip(self.chaddr) {
            *dst = src;
        }
        mac
    }

    /// The `file` field up to its first NUL.
    pub fn file_name(&self) -> &[u8] {
        nul_terminated(&self.file)
    }

    /// Whether the BROADCAST flag is set.
    pub fn broadcast(&self) -> bool {
        self.flags & FLAG_BROADCAST != 0
    }

    /// Decodes a message, checking every length (RFC 2131 §2, RFC 2132 §2).
    pub fn decode(buf: &[u8]) -> Result<Self, CodecError> {
        if buf.len() < MIN_LEN {
            return Err(CodecError::TooShort(buf.len()));
        }
        if buf.len() > MAX_LEN {
            return Err(CodecError::TooLong(buf.len()));
        }
        let mut r = Reader { buf, pos: 0 };
        let op = r.u8()?;
        let htype = r.u8()?;
        let hlen = r.u8()?;
        let hops = r.u8()?;
        let xid = u32::from_be_bytes(r.array()?);
        let secs = u16::from_be_bytes(r.array()?);
        let flags = u16::from_be_bytes(r.array()?);
        let ciaddr = Ipv4Addr::from(r.array::<4>()?);
        let yiaddr = Ipv4Addr::from(r.array::<4>()?);
        let siaddr = Ipv4Addr::from(r.array::<4>()?);
        let giaddr = Ipv4Addr::from(r.array::<4>()?);
        let chaddr = r.array()?;
        let sname = r.array()?;
        let file = r.array()?;
        if r.array::<4>()? != MAGIC_COOKIE {
            return Err(CodecError::BadCookie);
        }
        let layout = walk_options(buf)?;
        let mut options = Vec::with_capacity(layout.spans.len());
        for span in &layout.spans {
            let data = buf
                .get(span.data.clone())
                .ok_or(CodecError::Overrun(span.tlv.start))?;
            options.push(DhcpOption::new(span.code, data));
        }
        Ok(Self {
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file,
            options,
        })
    }

    /// Encodes the message with an End option and no trailing padding.
    pub fn encode(&self) -> Result<Vec<u8>, CodecError> {
        let mut out = Vec::with_capacity(MIN_LEN + 64);
        out.extend_from_slice(&[self.op, self.htype, self.hlen, self.hops]);
        out.extend_from_slice(&self.xid.to_be_bytes());
        out.extend_from_slice(&self.secs.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        for addr in [self.ciaddr, self.yiaddr, self.siaddr, self.giaddr] {
            out.extend_from_slice(&addr.octets());
        }
        out.extend_from_slice(&self.chaddr);
        out.extend_from_slice(&self.sname);
        out.extend_from_slice(&self.file);
        out.extend_from_slice(&MAGIC_COOKIE);
        for o in &self.options {
            push_option(&mut out, o.code, &o.data)?;
        }
        out.push(opt::END);
        if out.len() > MAX_LEN {
            return Err(CodecError::TooLong(out.len()));
        }
        Ok(out)
    }
}

/// Appends one encoded option.
pub fn push_option(out: &mut Vec<u8>, code: u8, data: &[u8]) -> Result<(), CodecError> {
    if code == opt::PAD || code == opt::END {
        return Err(CodecError::ReservedCode(code));
    }
    let len = u8::try_from(data.len()).map_err(|_| CodecError::OptionTooLong(code))?;
    out.push(code);
    out.push(len);
    out.extend_from_slice(data);
    Ok(())
}

/// Bytes up to the first NUL.
pub fn nul_terminated(field: &[u8]) -> &[u8] {
    match field.iter().position(|&b| b == 0) {
        Some(n) => field.get(..n).unwrap_or(field),
        None => field,
    }
}

/// Where one option sits in a raw message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OptionSpan {
    /// Option code.
    pub code: u8,
    /// The whole code/length/data TLV.
    pub tlv: Range<usize>,
    /// Just the data.
    pub data: Range<usize>,
}

/// The option layout of a raw message's main options field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OptionsLayout {
    /// Data options in order (Pad skipped).
    pub spans: Vec<OptionSpan>,
    /// Offset of the End option.
    pub end: usize,
}

/// Walks the main options field of a raw message (bounds-checked). The
/// caller has checked the length range and the cookie, or wants this to
/// fail on a short buffer.
pub fn walk_options(buf: &[u8]) -> Result<OptionsLayout, CodecError> {
    if buf.len() < MIN_LEN {
        return Err(CodecError::TooShort(buf.len()));
    }
    let mut pos = MIN_LEN;
    let mut spans = Vec::new();
    loop {
        let Some(&code) = buf.get(pos) else {
            return Err(CodecError::MissingEnd);
        };
        match code {
            opt::PAD => pos += 1,
            opt::END => return Ok(OptionsLayout { spans, end: pos }),
            _ => {
                let Some(&len) = buf.get(pos + 1) else {
                    return Err(CodecError::MissingLength(pos));
                };
                let data = (pos + 2)..(pos + 2 + usize::from(len));
                if data.end > buf.len() {
                    return Err(CodecError::Overrun(pos));
                }
                spans.push(OptionSpan {
                    code,
                    tlv: pos..data.end,
                    data: data.clone(),
                });
                pos = data.end;
            }
        }
    }
}

/// Sets `hops` in a raw message.
pub fn set_hops(buf: &mut [u8], hops: u8) -> Result<(), CodecError> {
    let len = buf.len();
    let slot = buf.get_mut(OFF_HOPS).ok_or(CodecError::TooShort(len))?;
    *slot = hops;
    Ok(())
}

/// Sets `giaddr` in a raw message.
pub fn set_giaddr(buf: &mut [u8], giaddr: Ipv4Addr) -> Result<(), CodecError> {
    let len = buf.len();
    let field = buf.get_mut(OFF_GIADDR).ok_or(CodecError::TooShort(len))?;
    field.copy_from_slice(&giaddr.octets());
    Ok(())
}

/// Returns a copy of `buf` with one option inserted just before End, so it
/// becomes the last option (RFC 3046 §2.0). Every other byte is unchanged.
pub fn insert_option_before_end(buf: &[u8], code: u8, data: &[u8]) -> Result<Vec<u8>, CodecError> {
    let layout = walk_options(buf)?;
    let mut tlv = Vec::with_capacity(data.len() + 2);
    push_option(&mut tlv, code, data)?;
    let (head, tail) = buf
        .split_at_checked(layout.end)
        .ok_or(CodecError::MissingEnd)?;
    let mut out = Vec::with_capacity(buf.len() + tlv.len());
    out.extend_from_slice(head);
    out.extend_from_slice(&tlv);
    out.extend_from_slice(tail);
    if out.len() > MAX_LEN {
        return Err(CodecError::TooLong(out.len()));
    }
    Ok(out)
}

/// Returns a copy of `buf` with every occurrence of `code` removed from the
/// main options field. Every other byte is unchanged.
pub fn remove_options(buf: &[u8], code: u8) -> Result<Vec<u8>, CodecError> {
    let layout = walk_options(buf)?;
    let mut out = Vec::with_capacity(buf.len());
    let mut pos = 0;
    for span in layout.spans.iter().filter(|s| s.code == code) {
        out.extend_from_slice(
            buf.get(pos..span.tlv.start)
                .ok_or(CodecError::Overrun(pos))?,
        );
        pos = span.tlv.end;
    }
    out.extend_from_slice(buf.get(pos..).ok_or(CodecError::Overrun(pos))?);
    Ok(out)
}

/// Encodes option 82 with sub-option 1 (circuit ID) and sub-option 2
/// (remote ID) (RFC 3046 §2.0, §3.1, §3.2). No pad, no end marker.
pub fn relay_agent_info(circuit_id: &[u8], remote_id: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::with_capacity(circuit_id.len() + remote_id.len() + 4);
    for (sub, value) in [(1u8, circuit_id), (2u8, remote_id)] {
        let len = u8::try_from(value.len())
            .map_err(|_| CodecError::OptionTooLong(opt::RELAY_AGENT_INFO))?;
        out.push(sub);
        out.push(len);
        out.extend_from_slice(value);
    }
    if out.len() > 255 {
        return Err(CodecError::OptionTooLong(opt::RELAY_AGENT_INFO));
    }
    Ok(out)
}

/// Bounds-checked sequential reader.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn u8(&mut self) -> Result<u8, CodecError> {
        let [b] = self.array::<1>()?;
        Ok(b)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let end = self.pos + N;
        let bytes = self
            .buf
            .get(self.pos..end)
            .ok_or(CodecError::TooShort(self.buf.len()))?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        self.pos = end;
        Ok(out)
    }
}

/// Formats a MAC address as `aa:bb:cc:dd:ee:ff`.
pub fn fmt_mac(mac: &[u8; 6]) -> String {
    let parts: Vec<String> = mac.iter().map(|b| format!("{b:02x}")).collect();
    parts.join(":")
}

/// Parses `aa:bb:cc:dd:ee:ff` (either case).
pub fn parse_mac(text: &str) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut parts = text.split(':');
    for slot in &mut mac {
        let part = parts.next()?;
        if part.len() != 2 {
            return None;
        }
        *slot = u8::from_str_radix(part, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(mac)
}

/// Text for logs: printable ASCII as is, every other byte as `\xNN`, and
/// `"` and `\` escaped, so a hostile option cannot forge log fields.
pub fn escape_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from(b)),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discover() -> Message {
        let mut m = Message::new(OP_REQUEST, 0x1234_5678, [0x52, 0x54, 0, 0, 1, 1]);
        m.flags = FLAG_BROADCAST;
        m.options.push(DhcpOption::new(opt::MESSAGE_TYPE, [1]));
        m.options.push(DhcpOption::new(
            opt::VENDOR_CLASS,
            b"PXEClient:Arch:00007:UNDI:003000".to_vec(),
        ));
        m.options.push(DhcpOption::new(opt::CLIENT_ARCH, [0, 7]));
        m
    }

    #[test]
    fn roundtrip() {
        let m = discover();
        let bytes = m.encode().unwrap();
        assert_eq!(bytes.len(), MIN_LEN + 3 + 34 + 4 + 1);
        assert_eq!(&bytes[236..240], &MAGIC_COOKIE);
        let back = Message::decode(&bytes).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.message_type(), Some(MessageType::Discover));
        assert!(back.broadcast());
        assert_eq!(back.mac(), [0x52, 0x54, 0, 0, 1, 1]);
    }

    #[test]
    fn header_offsets_match_rfc2131_figure1() {
        let mut m = discover();
        m.hops = 3;
        m.giaddr = Ipv4Addr::new(10, 20, 2, 1);
        m.siaddr = Ipv4Addr::new(10, 20, 1, 2);
        m.file[0] = b'x';
        let b = m.encode().unwrap();
        assert_eq!(b[0], 1);
        assert_eq!(b[3], 3);
        assert_eq!(&b[4..8], &0x1234_5678u32.to_be_bytes());
        assert_eq!(&b[10..12], &[0x80, 0]);
        assert_eq!(&b[20..24], &[10, 20, 1, 2]);
        assert_eq!(&b[24..28], &[10, 20, 2, 1]);
        assert_eq!(&b[28..34], &[0x52, 0x54, 0, 0, 1, 1]);
        assert_eq!(b[108], b'x');
    }

    #[test]
    fn length_limits() {
        assert_eq!(Message::decode(&[]), Err(CodecError::TooShort(0)));
        assert_eq!(Message::decode(&[0; 239]), Err(CodecError::TooShort(239)));
        assert_eq!(
            Message::decode(&[0; MAX_LEN + 1]),
            Err(CodecError::TooLong(MAX_LEN + 1))
        );
    }

    #[test]
    fn bad_cookie() {
        let mut b = discover().encode().unwrap();
        b[239] = 0;
        assert_eq!(Message::decode(&b), Err(CodecError::BadCookie));
    }

    #[test]
    fn options_walk_errors() {
        let base = discover().encode().unwrap();
        // Code at the last byte with no length.
        let mut b = base[..MIN_LEN].to_vec();
        b.push(opt::VENDOR_CLASS);
        assert_eq!(Message::decode(&b), Err(CodecError::MissingLength(MIN_LEN)));
        // Length past the end.
        let mut b = base[..MIN_LEN].to_vec();
        b.extend_from_slice(&[opt::VENDOR_CLASS, 10, b'P']);
        assert_eq!(Message::decode(&b), Err(CodecError::Overrun(MIN_LEN)));
        // No End.
        let b = base[..base.len() - 1].to_vec();
        assert_eq!(Message::decode(&b), Err(CodecError::MissingEnd));
        // Pad only.
        let mut b = base[..MIN_LEN].to_vec();
        b.extend_from_slice(&[0, 0, 0]);
        assert_eq!(Message::decode(&b), Err(CodecError::MissingEnd));
    }

    #[test]
    fn pad_skipped_and_duplicates_kept() {
        let mut b = discover().encode().unwrap();
        b.pop();
        b.extend_from_slice(&[0, opt::MESSAGE_TYPE, 1, 3, 0, opt::END, 0, 0]);
        let m = Message::decode(&b).unwrap();
        assert_eq!(m.option_count(opt::MESSAGE_TYPE), 2);
        assert_eq!(m.message_type(), Some(MessageType::Discover));
    }

    #[test]
    fn encode_rejects_reserved_and_long() {
        let mut m = discover();
        m.options.push(DhcpOption::new(opt::PAD, [1]));
        assert_eq!(m.encode(), Err(CodecError::ReservedCode(0)));
        let mut m = discover();
        m.options.push(DhcpOption::new(12, vec![b'a'; 256]));
        assert_eq!(m.encode(), Err(CodecError::OptionTooLong(12)));
    }

    #[test]
    fn insert_before_end_and_remove_restore_bytes() {
        let mut b = discover().encode().unwrap();
        b.extend_from_slice(&[0, 0, 0, 0]); // trailing pad after End is kept
        let info = relay_agent_info(b"rtB", b"lab").unwrap();
        assert_eq!(info, vec![1, 3, b'r', b't', b'B', 2, 3, b'l', b'a', b'b']);
        let with = insert_option_before_end(&b, opt::RELAY_AGENT_INFO, &info).unwrap();
        let m = Message::decode(&with).unwrap();
        let last = m.options.last().unwrap();
        assert_eq!(last.code, opt::RELAY_AGENT_INFO);
        assert_eq!(last.data, info);
        assert_eq!(&with[..b.len() - 5], &b[..b.len() - 5]);
        let without = remove_options(&with, opt::RELAY_AGENT_INFO).unwrap();
        assert_eq!(without, b);
    }

    #[test]
    fn set_fields_in_place() {
        let mut b = discover().encode().unwrap();
        let before = b.clone();
        set_hops(&mut b, 2).unwrap();
        set_giaddr(&mut b, Ipv4Addr::new(10, 20, 2, 1)).unwrap();
        let m = Message::decode(&b).unwrap();
        assert_eq!(m.hops, 2);
        assert_eq!(m.giaddr, Ipv4Addr::new(10, 20, 2, 1));
        let changed: Vec<usize> = (0..b.len()).filter(|&i| b[i] != before[i]).collect();
        assert!(changed.iter().all(|&i| i == 3 || (24..28).contains(&i)));
        assert!(set_hops(&mut [], 1).is_err());
        assert!(set_giaddr(&mut [0; 27], Ipv4Addr::LOCALHOST).is_err());
    }

    #[test]
    fn mac_text() {
        assert_eq!(
            parse_mac("52:54:00:AB:cd:01"),
            Some([0x52, 0x54, 0, 0xab, 0xcd, 1])
        );
        assert_eq!(
            fmt_mac(&[0x52, 0x54, 0, 0xab, 0xcd, 1]),
            "52:54:00:ab:cd:01"
        );
        for bad in [
            "",
            "52:54:00:ab:cd",
            "52:54:00:ab:cd:01:02",
            "5:54:00:ab:cd:01",
            "zz:54:00:ab:cd:01",
        ] {
            assert_eq!(parse_mac(bad), None, "{bad}");
        }
    }

    #[test]
    fn escape_neutralises_log_injection() {
        assert_eq!(escape_bytes(b"PXEClient"), "PXEClient");
        assert_eq!(
            escape_bytes(b"a\"b\\c\n\x00\xff"),
            "a\\\"b\\\\c\\x0a\\x00\\xff"
        );
    }
}
