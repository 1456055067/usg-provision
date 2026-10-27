//! Sans-IO parts of `lab-probe`: crafted DHCP requests, the vector set,
//! random packets, and the checks applied to every reply.
//!
//! The vector set follows the DHCP list in plan section 10.2, built with this
//! crate's own codec. Almost every vector is a request the boot service must
//! not answer (REQ-BOOT-004, 005, 006; [`Expect::NoReply`]). The exception is
//! repeated options: a receiver joins every instance of a code into one value
//! and judges the joined value (RFC 3396 §4, §7;
//! `specs/standards/dhcp-long-options.md` §3). A request whose repeated or
//! split options join into valid values is a normal PXE request and must get
//! a normal lease-free reply ([`Expect::ProxyReply`]); one whose joined value
//! is invalid must get none. Other vectors that the plan expects to be
//! answered (for example option 57 = 575, or option 52 values 1 to 3 with a
//! well-formed overload area) are not in this set; the product's unit tests
//! cover them.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-10, SC-5
//! - SPEC: specs/boot-network.md#REQ-BOOT-004, #REQ-BOOT-005, #REQ-BOOT-006,
//!   #REQ-BOOT-010, #REQ-BOOT-044
//! - RFC 2131 §2, RFC 2132 §2, §9.3, RFC 4578 §2.1 to §2.3
//! - RFC 3396 §4 to §7 - repeated options are joined before validation

use std::net::Ipv4Addr;

use crate::codec::{self, DhcpOption, MIN_LEN, Message, OP_REPLY, OP_REQUEST, opt};

/// Vendor class a UEFI x86-64 PXE client sends (pxe-dhcp.md §5.1, §7).
pub const PXE_VENDOR_CLASS: &[u8] = b"PXEClient:Arch:00007:UNDI:003000";
/// Options that would mean the reply leases an address (REQ-BOOT-010).
pub const LEASE_OPTIONS: [u8; 5] = [
    opt::SUBNET_MASK,
    opt::ROUTER,
    opt::LEASE_TIME,
    opt::RENEWAL_TIME,
    opt::REBINDING_TIME,
];

/// How the probe addresses the boot service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// As a client on the segment: giaddr 0, BROADCAST set, sent to
    /// 255.255.255.255:67, replies broadcast to port 68.
    Direct,
    /// As a relay agent: giaddr = the probe's address, hops 1, sent by
    /// unicast to the service's port 67, replies to giaddr:67.
    Relayed(Ipv4Addr),
}

impl Mode {
    fn giaddr(self) -> Ipv4Addr {
        match self {
            Self::Direct => Ipv4Addr::UNSPECIFIED,
            Self::Relayed(addr) => addr,
        }
    }
}

/// Identity used for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ident {
    /// Transaction ID.
    pub xid: u32,
    /// Client MAC (locally administered unicast).
    pub mac: [u8; 6],
}

impl Ident {
    /// A distinct identity for request number `n` under `seed`, so vectors
    /// never share a rate-limit bucket.
    pub fn nth(seed: u32, n: u32) -> Self {
        let [_, b, c, d] = n.to_be_bytes();
        Self {
            xid: seed.wrapping_mul(0x0001_0000).wrapping_add(n),
            mac: [0x02, 0x4c, 0x41, b, c, d],
        }
    }
}

/// A PXE DHCPDISCOVER from a UEFI x86-64 client (pxe-dhcp.md §7 step 1).
pub fn pxe_discover(mode: Mode, id: Ident) -> Message {
    let mut m = Message::new(OP_REQUEST, id.xid, id.mac);
    m.giaddr = mode.giaddr();
    if let Mode::Relayed(_) = mode {
        m.hops = 1;
    }
    m.flags = codec::FLAG_BROADCAST;
    m.options = vec![
        DhcpOption::new(opt::MESSAGE_TYPE, [1]),
        DhcpOption::new(
            opt::PARAMETER_REQUEST,
            [1, 3, 43, 60, 66, 67, 128, 129, 130, 131, 132, 133, 134, 135],
        ),
        DhcpOption::new(opt::MAX_MESSAGE_SIZE, 1472u16.to_be_bytes()),
        DhcpOption::new(opt::VENDOR_CLASS, PXE_VENDOR_CLASS.to_vec()),
        DhcpOption::new(opt::CLIENT_ARCH, [0, 7]),
        DhcpOption::new(opt::CLIENT_NDI, [1, 3, 0]),
        DhcpOption::new(opt::CLIENT_UUID, guid_option(id)),
    ];
    m
}

/// A PXE boot-server DHCPREQUEST with option 43 tag 71 (type 0, layer 0)
/// (pxe-dhcp.md §7 step 3b), as sent to port 4011 or 67.
pub fn pxe_boot_request(mode: Mode, id: Ident, ciaddr: Ipv4Addr) -> Message {
    let mut m = pxe_discover(mode, id);
    m.ciaddr = ciaddr;
    set_option(&mut m, opt::MESSAGE_TYPE, vec![3]);
    m.options
        .push(DhcpOption::new(opt::VENDOR_SPECIFIC, tag71(&[0, 0, 0, 0])));
    m
}

fn guid_option(id: Ident) -> Vec<u8> {
    let mut v = vec![0u8];
    v.extend_from_slice(&id.xid.to_be_bytes());
    v.extend_from_slice(&[0x4c, 0x41, 0x42, 0x00]);
    v.extend_from_slice(&[0; 2]);
    v.extend_from_slice(&id.mac);
    v
}

/// Option 43 data holding one tag 71 and End.
fn tag71(value: &[u8]) -> Vec<u8> {
    let mut v = vec![71u8, u8::try_from(value.len()).unwrap_or(u8::MAX)];
    v.extend_from_slice(value);
    v.push(255);
    v
}

/// Replaces the first occurrence of `code`, or appends it.
fn set_option(m: &mut Message, code: u8, data: Vec<u8>) {
    match m.options.iter_mut().find(|o| o.code == code) {
        Some(o) => o.data = data,
        None => m.options.push(DhcpOption::new(code, data)),
    }
}

fn remove_option(m: &mut Message, code: u8) {
    m.options.retain(|o| o.code != code);
}

/// Encodes `code` as one instance per piece, in order (an RFC 3396 §6
/// split): the first piece replaces the existing instance in place, the
/// rest are appended, so the pieces need not be adjacent (RFC 3396 §5).
fn split_option(m: &mut Message, code: u8, pieces: &[&[u8]]) {
    let mut rest = pieces.iter();
    if let Some(first) = rest.next() {
        set_option(m, code, first.to_vec());
    }
    for piece in rest {
        m.options.push(DhcpOption::new(code, piece.to_vec()));
    }
}

/// What the boot service must do with a vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    /// No reply of any kind (REQ-BOOT-004, 005, 006).
    NoReply,
    /// A normal ProxyDHCP reply that passes [`check_proxy_reply`] and
    /// [`check_reply_options`]: the vector is a valid PXE request once its
    /// repeated options are joined (RFC 3396 §7).
    ProxyReply,
}

/// One vector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vector {
    /// Stable name, printed with the result.
    pub name: String,
    /// Transaction ID (for matching the service's logs).
    pub xid: u32,
    /// Bytes to send.
    pub bytes: Vec<u8>,
    /// False when a reply could not reach the probe even if the service
    /// wrongly sent one (giaddr pointing elsewhere); the harness must then
    /// check the service's log for this xid instead.
    pub observable: bool,
    /// The required outcome.
    pub expect: Expect,
}

/// The BOOTP minimum message length a receiver enforces (pxe-dhcp.md
/// §3.2; RFC 1542 §2.1). Vectors other than `size-*` are at least this
/// long, so they reach the check they target instead of being dropped as
/// short.
pub const BOOTP_MIN_LEN: usize = 300;

/// Zero-pads an encoded message after its End option up to
/// [`BOOTP_MIN_LEN`], as real clients do.
fn pad_after_end(mut b: Vec<u8>) -> Vec<u8> {
    if b.len() < BOOTP_MIN_LEN {
        b.resize(BOOTP_MIN_LEN, 0);
    }
    b
}

/// Pad options (code 0) from the end of the header up to `len - tail`
/// octets, so that `tail` octets placed after them end the message at
/// [`BOOTP_MIN_LEN`].
fn pad_options_then(mut b: Vec<u8>, tail: &[u8]) -> Vec<u8> {
    b.truncate(MIN_LEN);
    let fill = BOOTP_MIN_LEN.saturating_sub(MIN_LEN + tail.len());
    b.resize(MIN_LEN + fill, 0);
    b.extend_from_slice(tail);
    b
}

/// Builds the vector set (plan section 10.2, DHCP list). `service_addr` is
/// the boot service's own address, for the "giaddr is ours" vector.
///
/// Option 82 vectors are built only in relayed mode: option 82 is added by
/// relay agents (RFC 3046 §2.1), and what a boot service does with a
/// client-originated option 82 (`giaddr` = 0) is not specified.
pub fn vectors(mode: Mode, seed: u32, service_addr: Ipv4Addr) -> Vec<Vector> {
    let mut out = Vec::new();
    let mut n = 0u32;
    let mut next = || {
        n += 1;
        Ident::nth(seed, n)
    };
    let push_expect = |out: &mut Vec<Vector>, name: &str, id: Ident, m: Message, expect: Expect| {
        if let Ok(bytes) = m.encode() {
            out.push(Vector {
                name: name.to_owned(),
                xid: id.xid,
                bytes: pad_after_end(bytes),
                observable: true,
                expect,
            });
        }
    };
    let push_msg = |out: &mut Vec<Vector>, name: &str, id: Ident, m: Message| {
        push_expect(out, name, id, m, Expect::NoReply);
    };
    let raw = |out: &mut Vec<Vector>, name: &str, id: Ident, bytes: Vec<u8>| {
        out.push(Vector {
            name: name.to_owned(),
            xid: id.xid,
            bytes,
            observable: true,
            expect: Expect::NoReply,
        });
    };
    let relayed = matches!(mode, Mode::Relayed(_));
    let valid = |id: Ident| pxe_discover(mode, id).encode().unwrap_or_default();

    // Size.
    for len in [0usize, 1, 235, 236, 237, 238, 239] {
        let id = next();
        let mut b = valid(id);
        b.truncate(len);
        raw(&mut out, &format!("size-{len}"), id, b);
    }
    let id = next();
    let mut b = valid(id);
    if let Some(c) = b.get_mut(239) {
        *c ^= 0xff;
    }
    raw(&mut out, "bad-cookie", id, b);
    let id = next();
    let mut b = valid(id);
    b.resize(codec::MAX_LEN + 1, 0);
    raw(&mut out, "size-1473", id, b);

    // Header.
    for (name, field) in [
        ("op-2", 0usize),
        ("htype-6", 1),
        ("hlen-16", 2),
        ("hops-17", 3),
    ] {
        let id = next();
        let mut m = pxe_discover(mode, id);
        match field {
            0 => m.op = OP_REPLY,
            1 => m.htype = 6,
            2 => m.hlen = 16,
            _ => m.hops = 17,
        }
        push_msg(&mut out, name, id, m);
    }

    // Options walk. Pad options fill the area so each defect sits at the
    // end of a 300-octet message.
    let id = next();
    let b = pad_options_then(valid(id), &[opt::VENDOR_CLASS]);
    raw(&mut out, "opt-code-last-byte", id, b);
    let id = next();
    let b = pad_options_then(
        valid(id),
        &[opt::MESSAGE_TYPE, 1, 1, opt::VENDOR_CLASS, 200, b'P'],
    );
    raw(&mut out, "opt-length-overrun", id, b);
    let id = next();
    let mut b = valid(id);
    b.pop();
    raw(&mut out, "opt-end-missing", id, b);
    let id = next();
    let b = pad_options_then(valid(id), &[]);
    raw(&mut out, "opt-pad-only", id, b);

    // Option 52.
    for v in [0u8, 4] {
        let id = next();
        let mut m = pxe_discover(mode, id);
        m.options.push(DhcpOption::new(opt::OVERLOAD, [v]));
        push_msg(&mut out, &format!("opt52-value-{v}"), id, m);
    }
    let id = next();
    let mut m = pxe_discover(mode, id);
    m.options.push(DhcpOption::new(opt::OVERLOAD, [1]));
    m.file[0] = opt::VENDOR_CLASS;
    m.file[1] = 200;
    push_msg(&mut out, "opt52-file-overrun", id, m);
    let id = next();
    let mut m = pxe_discover(mode, id);
    m.options.push(DhcpOption::new(opt::OVERLOAD, [2]));
    m.sname[0] = 12;
    m.sname[1] = 100;
    push_msg(&mut out, "opt52-sname-overrun", id, m);

    // Option 53.
    for (name, data) in [("opt53-len-0", vec![]), ("opt53-len-2", vec![1, 1])] {
        let id = next();
        let mut m = pxe_discover(mode, id);
        set_option(&mut m, opt::MESSAGE_TYPE, data);
        push_msg(&mut out, name, id, m);
    }
    for t in [2u8, 4, 5, 6, 7, 8] {
        let id = next();
        let mut m = pxe_discover(mode, id);
        set_option(&mut m, opt::MESSAGE_TYPE, vec![t]);
        push_msg(&mut out, &format!("opt53-type-{t}"), id, m);
    }

    // Options 54 and 57.
    for (name, code, data) in [
        ("opt54-len-3", opt::SERVER_ID, vec![10, 20, 1]),
        ("opt54-len-5", opt::SERVER_ID, vec![10, 20, 1, 2, 0]),
        ("opt57-len-1", opt::MAX_MESSAGE_SIZE, vec![5]),
    ] {
        let id = next();
        let mut m = pxe_discover(mode, id);
        set_option(&mut m, code, data);
        push_msg(&mut out, name, id, m);
    }

    // Option 60 (REQ-BOOT-004 and 005).
    let id = next();
    let mut m = pxe_discover(mode, id);
    remove_option(&mut m, opt::VENDOR_CLASS);
    push_msg(&mut out, "opt60-absent", id, m);
    for (name, value) in [
        ("opt60-empty", &b""[..]),
        ("opt60-upper-case", b"PXECLIENT:Arch:00007:UNDI:003000"),
        ("opt60-truncated-prefix", b"PXEClien"),
        ("opt60-non-pxe", b"usgp-non-pxe-client"),
        (
            "opt60-arch-non-numeric",
            b"PXEClient:Arch:0000x:UNDI:003000",
        ),
        (
            "opt60-arch-disagrees-93",
            b"PXEClient:Arch:00000:UNDI:003000",
        ),
    ] {
        let id = next();
        let mut m = pxe_discover(mode, id);
        set_option(&mut m, opt::VENDOR_CLASS, value.to_vec());
        push_msg(&mut out, name, id, m);
    }

    // Option 93 (REQ-BOOT-005).
    for (name, data) in [
        ("opt93-len-0", vec![]),
        ("opt93-len-1", vec![0]),
        ("opt93-len-3", vec![0, 7, 0]),
        ("opt93-without-7", vec![0, 6, 0, 9]),
    ] {
        let id = next();
        let mut m = pxe_discover(mode, id);
        set_option(&mut m, opt::CLIENT_ARCH, data);
        push_msg(&mut out, name, id, m);
    }
    let id = next();
    let mut m = pxe_discover(mode, id);
    set_option(&mut m, opt::CLIENT_ARCH, vec![0, 0]);
    set_option(
        &mut m,
        opt::VENDOR_CLASS,
        b"PXEClient:Arch:00000:UNDI:002001".to_vec(),
    );
    push_msg(&mut out, "arch-0-bios", id, m);

    // Options 94 and 97.
    for (name, code, data) in [
        ("opt94-len-2", opt::CLIENT_NDI, vec![1, 3]),
        ("opt94-len-4", opt::CLIENT_NDI, vec![1, 3, 0, 0]),
        ("opt97-len-16", opt::CLIENT_UUID, vec![0; 16]),
        ("opt97-len-18", opt::CLIENT_UUID, vec![0; 18]),
        ("opt97-type-1", opt::CLIENT_UUID, {
            let mut v = vec![1u8];
            v.extend_from_slice(&[0x11; 16]);
            v
        }),
    ] {
        let id = next();
        let mut m = pxe_discover(mode, id);
        set_option(&mut m, code, data);
        push_msg(&mut out, name, id, m);
    }

    // Option 43 tag 71 on a boot-server REQUEST (no option 54).
    for (name, value) in [
        ("tag71-wrong-length", vec![0u8, 0, 0]),
        ("tag71-layer-1", vec![0, 0, 0, 1]),
        ("tag71-credentials-bit", vec![0, 0, 0x80, 0]),
        ("tag71-type-1", vec![0, 1, 0, 0]),
    ] {
        let id = next();
        let mut m = pxe_boot_request(mode, id, Ipv4Addr::UNSPECIFIED);
        set_option(&mut m, opt::VENDOR_SPECIFIC, tag71(&value));
        push_msg(&mut out, name, id, m);
    }

    // Two identical copies of each critical option. A receiver joins them
    // (RFC 3396 §4, §7), so the outcome depends on the joined value:
    // - 43 (on a DISCOVER the server ignores vendor data, RFC 2132 §8.4),
    //   60 (still starts with "PXEClient"), 61 (opaque client identifier),
    //   82 (two well-formed sub-options) and 93 (0,7,0,7: even, lists 7)
    //   join into valid values and must be answered normally;
    // - 52 and 53 (one octet each), 54 (4), 57 (2), 94 (3) and 97 (17) have
    //   fixed lengths, so the doubled value is malformed and must be dropped.
    for code in [43u8, 52, 53, 54, 57, 60, 61, 82, 93, 94, 97] {
        if code == opt::RELAY_AGENT_INFO && !relayed {
            continue;
        }
        let id = next();
        let mut m = pxe_discover(mode, id);
        let data = match code {
            opt::VENDOR_SPECIFIC => tag71(&[0, 0, 0, 0]),
            opt::OVERLOAD => {
                m.file[0] = opt::END;
                vec![1]
            }
            opt::MESSAGE_TYPE => vec![1],
            opt::SERVER_ID => service_addr.octets().to_vec(),
            opt::MAX_MESSAGE_SIZE => 1472u16.to_be_bytes().to_vec(),
            opt::VENDOR_CLASS => PXE_VENDOR_CLASS.to_vec(),
            opt::CLIENT_ID => {
                let mut v = vec![1u8];
                v.extend_from_slice(&id.mac);
                v
            }
            opt::RELAY_AGENT_INFO => vec![1, 3, b'l', b'a', b'b'],
            opt::CLIENT_ARCH => vec![0, 7],
            opt::CLIENT_NDI => vec![1, 3, 0],
            _ => guid_option(id),
        };
        split_option(&mut m, code, &[&data, &data]);
        let expect = match code {
            opt::VENDOR_SPECIFIC
            | opt::VENDOR_CLASS
            | opt::CLIENT_ID
            | opt::RELAY_AGENT_INFO
            | opt::CLIENT_ARCH => Expect::ProxyReply,
            _ => Expect::NoReply,
        };
        push_expect(&mut out, &format!("duplicate-opt{code}"), id, m, expect);
    }

    // Split options (RFC 3396 §6): one value cut at an arbitrary octet.
    // Split points carry no meaning (§6, §7), so each joined value is judged
    // as if it had been sent whole.
    let splits: Vec<(&str, u8, Vec<Vec<u8>>, Expect)> = vec![
        // Valid once joined: the "PXEClient" prefix, the architecture
        // pair, the NDI and the GUID straddle the split.
        (
            "split-opt60-prefix",
            opt::VENDOR_CLASS,
            vec![b"PXECl".to_vec(), b"ient:Arch:00007:UNDI:003000".to_vec()],
            Expect::ProxyReply,
        ),
        (
            "split-opt93-pair",
            opt::CLIENT_ARCH,
            vec![vec![0], vec![7]],
            Expect::ProxyReply,
        ),
        (
            "split-opt94",
            opt::CLIENT_NDI,
            vec![vec![1], vec![3, 0]],
            Expect::ProxyReply,
        ),
        // Invalid once joined, though one piece alone would pass: the
        // joined class does not start with "PXEClient" (REQ-BOOT-004), and
        // the joined option 93 has an odd length (RFC 4578 §2.1).
        (
            "split-opt60-non-pxe",
            opt::VENDOR_CLASS,
            vec![b"usgp-".to_vec(), PXE_VENDOR_CLASS.to_vec()],
            Expect::NoReply,
        ),
        (
            "split-opt93-odd",
            opt::CLIENT_ARCH,
            vec![vec![0, 7], vec![0]],
            Expect::NoReply,
        ),
    ];
    for (name, code, pieces, expect) in splits {
        let id = next();
        let mut m = pxe_discover(mode, id);
        let refs: Vec<&[u8]> = pieces.iter().map(Vec::as_slice).collect();
        split_option(&mut m, code, &refs);
        push_expect(&mut out, name, id, m, expect);
    }
    // Option 97: the 17-octet GUID cut in two (valid), and the same with
    // one extra octet (18 joined octets, invalid; RFC 4578 §2.3).
    for (name, extra, expect) in [
        ("split-opt97", &[][..], Expect::ProxyReply),
        ("split-opt97-len-18", &[0u8][..], Expect::NoReply),
    ] {
        let id = next();
        let mut m = pxe_discover(mode, id);
        let g = guid_option(id);
        let (a, b) = g.split_at(9);
        let tail: Vec<u8> = b.iter().chain(extra).copied().collect();
        split_option(&mut m, opt::CLIENT_UUID, &[a, &tail]);
        push_expect(&mut out, name, id, m, expect);
    }
    // Option 43 on a boot-server REQUEST: tag 71 cut inside its value. The
    // sub-options are parsed only after joining (dhcp-long-options.md §3).
    for (name, pieces, expect) in [
        (
            "split-opt43-tag71",
            [&[71u8, 4, 0][..], &[0, 0, 0, 255][..]],
            Expect::ProxyReply,
        ),
        (
            "split-opt43-tag71-len-3",
            [&[71u8, 3, 0][..], &[0, 0, 255][..]],
            Expect::NoReply,
        ),
    ] {
        let id = next();
        let mut m = pxe_boot_request(mode, id, Ipv4Addr::UNSPECIFIED);
        split_option(&mut m, opt::VENDOR_SPECIFIC, &pieces);
        push_expect(&mut out, name, id, m, expect);
    }
    // Option 82 (relayed mode): sub-option 1 cut inside its value; the
    // echo must be the joined value (RFC 3046 §2.2, RFC 3396 §7).
    if relayed {
        let id = next();
        let mut m = pxe_discover(mode, id);
        split_option(&mut m, opt::RELAY_AGENT_INFO, &[&[1, 3, b'l'], b"ab"]);
        push_expect(&mut out, "split-opt82", id, m, Expect::ProxyReply);
    }

    // Addresses: these replies would go to giaddr, not to the probe.
    for (name, giaddr) in [
        ("giaddr-limited-broadcast", Ipv4Addr::BROADCAST),
        ("giaddr-multicast", Ipv4Addr::new(224, 0, 0, 1)),
        ("giaddr-loopback", Ipv4Addr::LOCALHOST),
        ("giaddr-is-service", service_addr),
    ] {
        let id = next();
        let mut m = pxe_discover(mode, id);
        m.giaddr = giaddr;
        m.hops = 1;
        if let Ok(bytes) = m.encode() {
            out.push(Vector {
                name: name.to_owned(),
                xid: id.xid,
                bytes,
                observable: false,
                expect: Expect::NoReply,
            });
        }
    }
    for (name, mac) in [
        ("chaddr-multicast", [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]),
        ("chaddr-all-zero", [0; 6]),
    ] {
        let id = next();
        let m = pxe_discover(mode, Ident { xid: id.xid, mac });
        push_msg(&mut out, name, id, m);
    }
    out
}

/// Checks that apply to every reply the probe captures (REQ-BOOT-010): a
/// BOOTREPLY with `yiaddr` = 0 and no lease options.
pub fn check_lease_free(reply: &Message) -> Result<(), String> {
    if reply.op != OP_REPLY {
        return Err(format!("op={} is not BOOTREPLY", reply.op));
    }
    if !reply.yiaddr.is_unspecified() {
        return Err(format!("yiaddr={} (an address was offered)", reply.yiaddr));
    }
    for code in LEASE_OPTIONS {
        if reply.option(code).is_some() {
            return Err(format!("lease option {code} present"));
        }
    }
    Ok(())
}

/// Option 53 judged on its joined value (RFC 3396 §7): one octet, a known
/// type.
fn joined_message_type(m: &Message) -> Option<codec::MessageType> {
    match m.option_joined(opt::MESSAGE_TYPE).as_deref() {
        Some(&[t]) => codec::MessageType::from_code(t),
        _ => None,
    }
}

/// Options a ProxyDHCP reply may always carry: 53, 54 and 60 (plan
/// section 1.1 "Offer content"; pxe-dhcp.md §7 step 3a) and 93, 94 and 97
/// (pxe-dhcp.md §5.5, RFC 4578 §2.1 to §2.3).
pub const REPLY_OPTIONS: [u8; 6] = [
    opt::MESSAGE_TYPE,
    opt::SERVER_ID,
    opt::VENDOR_CLASS,
    opt::CLIENT_ARCH,
    opt::CLIENT_NDI,
    opt::CLIENT_UUID,
];

/// Checks the option set of a ProxyDHCP reply to `req`: only
/// [`REPLY_OPTIONS`], plus option 43 in answer to a boot-server REQUEST
/// that carried option 43 (tag 71; pxe-dhcp.md §6, §7 step 3b) and option
/// 82 when the request carried it; no code repeated; and an option 82 echo
/// equal to the request's joined option 82 (RFC 3046 §2.2, RFC 3396 §7).
pub fn check_reply_options(req: &Message, reply: &Message) -> Result<(), String> {
    let boot_server_request = joined_message_type(req) == Some(codec::MessageType::Request)
        && req.option(opt::VENDOR_SPECIFIC).is_some();
    let relay_info = req.option_joined(opt::RELAY_AGENT_INFO);
    for o in &reply.options {
        let allowed = REPLY_OPTIONS.contains(&o.code)
            || (o.code == opt::VENDOR_SPECIFIC && boot_server_request)
            || (o.code == opt::RELAY_AGENT_INFO && relay_info.is_some());
        if !allowed {
            return Err(format!("option {} not allowed in a proxy reply", o.code));
        }
        if reply.option_count(o.code) > 1 {
            return Err(format!("option {} repeated in the reply", o.code));
        }
    }
    if let Some(echo) = reply.option(opt::RELAY_AGENT_INFO)
        && relay_info.as_deref() != Some(echo)
    {
        return Err("option 82 echo differs from the request's joined option 82".to_owned());
    }
    Ok(())
}

/// Expectations for a ProxyDHCP reply.
#[derive(Clone, Debug, Default)]
pub struct OfferExpect {
    /// Required option 54 / `siaddr` value.
    pub server: Option<Ipv4Addr>,
    /// Required `file` value.
    pub file: Option<String>,
}

/// Checks a ProxyDHCP reply to `req` (plan section 1.1 "Offer content"):
/// echoes xid and chaddr, no lease, option 60 = `PXEClient`, option 54
/// present, `siaddr` = option 54, `file` non-empty, and option 93 = 7.
pub fn check_proxy_reply(
    req: &Message,
    reply: &Message,
    expect: &OfferExpect,
) -> Result<(), String> {
    check_lease_free(reply)?;
    if reply.xid != req.xid {
        return Err(format!("xid {:#010x} != {:#010x}", reply.xid, req.xid));
    }
    if reply.chaddr != req.chaddr {
        return Err("chaddr not echoed".to_owned());
    }
    if reply.option(opt::VENDOR_CLASS) != Some(&b"PXEClient"[..]) {
        return Err("option 60 is not PXEClient".to_owned());
    }
    let Some(server) = reply.option_addr(opt::SERVER_ID) else {
        return Err("option 54 missing".to_owned());
    };
    if reply.siaddr != server {
        return Err(format!("siaddr {} != option 54 {server}", reply.siaddr));
    }
    if let Some(want) = expect.server
        && server != want
    {
        return Err(format!("option 54 {server} != expected {want}"));
    }
    if reply.option(opt::CLIENT_ARCH) != Some(&[0u8, 7][..]) {
        return Err("option 93 is not 7".to_owned());
    }
    let file = reply.file_name();
    if file.is_empty() {
        return Err("file is empty".to_owned());
    }
    if let Some(want) = &expect.file
        && file != want.as_bytes()
    {
        return Err(format!(
            "file \"{}\" != expected \"{want}\"",
            codec::escape_bytes(file)
        ));
    }
    if req.broadcast() != reply.broadcast() {
        return Err("BROADCAST flag not preserved".to_owned());
    }
    Ok(())
}

/// SplitMix64: a small, deterministic generator for reproducible random
/// packets (the seed is printed, so a failure can be replayed).
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    /// Seeds the generator.
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// Next 64 random bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in `0..=max` (slight modulo bias is irrelevant here).
    pub fn below_or_eq(&mut self, max: usize) -> usize {
        let m = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
        usize::try_from(self.next_u64() % m).unwrap_or(0)
    }

    /// Fills `buf` with random bytes.
    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            for (d, s) in chunk.iter_mut().zip(bytes) {
                *d = s;
            }
        }
    }
}

/// Whether a decoded request is one a correct ProxyDHCP service could
/// legitimately answer: a PXE DISCOVER or REQUEST whose option 93 lists 7,
/// judged on joined option values (RFC 3396 §7). Random packets for which
/// this is true are regenerated.
pub fn could_be_served(m: &Message) -> bool {
    let pxe = m
        .option_joined(opt::VENDOR_CLASS)
        .is_some_and(|v| v.starts_with(b"PXEClient"));
    // RFC 4578 §2.1: even, non-zero length; one of the pairs is 7.
    let arch7 = m
        .option_joined(opt::CLIENT_ARCH)
        .is_some_and(|v| v.len() % 2 == 0 && v.as_chunks::<2>().0.contains(&[0, 7]));
    let kind = matches!(
        joined_message_type(m),
        Some(codec::MessageType::Discover | codec::MessageType::Request)
    );
    m.op == OP_REQUEST && pxe && arch7 && kind
}

/// A random packet the service must not answer. Half are random bytes of
/// random length 0 to 1500; half are a valid BOOTREQUEST header and cookie
/// followed by random option bytes.
pub fn random_packet(rng: &mut Rng) -> Vec<u8> {
    loop {
        let structured = rng.next_u64() & 1 == 1;
        let pkt = if structured {
            let mut b = vec![0u8; MIN_LEN + rng.below_or_eq(1232)];
            rng.fill(&mut b);
            let header = [OP_REQUEST, 1, 6, 0];
            for (d, s) in b.iter_mut().zip(header) {
                *d = s;
            }
            // Unicast, locally administered chaddr; cookie in place.
            if let Some(c) = b.get_mut(28) {
                *c = (*c & 0xfc) | 0x02;
            }
            if let Some(cookie) = b.get_mut(236..240) {
                cookie.copy_from_slice(&codec::MAGIC_COOKIE);
            }
            b
        } else {
            let mut b = vec![0u8; rng.below_or_eq(1500)];
            rng.fill(&mut b);
            b
        };
        match Message::decode(&pkt) {
            Ok(m) if could_be_served(&m) => continue,
            _ => return pkt,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SVC: Ipv4Addr = Ipv4Addr::new(10, 20, 1, 2);

    #[test]
    fn valid_discover_is_servable_and_well_formed() {
        for mode in [Mode::Direct, Mode::Relayed(Ipv4Addr::new(10, 20, 1, 9))] {
            let m = pxe_discover(mode, Ident::nth(1, 1));
            assert!(could_be_served(&m));
            let back = Message::decode(&m.encode().unwrap()).unwrap();
            assert_eq!(back, m);
            assert_eq!(back.option(opt::CLIENT_UUID).map(<[u8]>::len), Some(17));
        }
        let r = pxe_boot_request(Mode::Direct, Ident::nth(1, 2), Ipv4Addr::new(10, 20, 1, 50));
        assert_eq!(
            r.option(opt::VENDOR_SPECIFIC),
            Some(&[71u8, 4, 0, 0, 0, 0, 255][..])
        );
        assert!(could_be_served(&r));
    }

    #[test]
    fn vectors_unique_and_named() {
        let v = vectors(Mode::Relayed(Ipv4Addr::new(10, 20, 1, 9)), 7, SVC);
        let mut names: Vec<&str> = v.iter().map(|x| x.name.as_str()).collect();
        let mut xids: Vec<u32> = v.iter().map(|x| x.xid).collect();
        names.sort_unstable();
        names.dedup();
        xids.sort_unstable();
        xids.dedup();
        assert_eq!(names.len(), v.len());
        assert_eq!(xids.len(), v.len());
        assert!(v.len() >= 70, "{}", v.len());
        for want in [
            "size-0",
            "size-1473",
            "opt60-absent",
            "arch-0-bios",
            "duplicate-opt97",
            "duplicate-opt82",
            "split-opt60-prefix",
            "split-opt82",
            "split-opt43-tag71",
            "chaddr-all-zero",
            "tag71-credentials-bit",
        ] {
            assert!(names.contains(&want), "{want}");
        }
    }

    /// RFC 3396: repeated options are joined, and the joined value decides.
    /// Vectors that must be answered are valid PXE requests once joined;
    /// the split negatives are invalid only once joined.
    #[test]
    fn repeated_option_vectors_follow_rfc3396() {
        let relay = Ipv4Addr::new(10, 20, 1, 9);
        for mode in [Mode::Direct, Mode::Relayed(relay)] {
            let v = vectors(mode, 9, SVC);
            let get = |n: &str| v.iter().find(|x| x.name == n);
            let answered: Vec<&str> = v
                .iter()
                .filter(|x| x.expect == Expect::ProxyReply)
                .map(|x| x.name.as_str())
                .collect();
            for x in v.iter().filter(|x| x.expect == Expect::ProxyReply) {
                let m = Message::decode(&x.bytes).unwrap();
                assert!(could_be_served(&m), "{}", x.name);
                assert!(x.observable, "{}", x.name);
                assert!(x.bytes.len() >= BOOTP_MIN_LEN, "{}", x.name);
                // Something really is repeated.
                assert!(
                    m.options.iter().any(|o| m.option_count(o.code) > 1),
                    "{}",
                    x.name
                );
            }
            for code in [43u8, 60, 61, 93] {
                let n = format!("duplicate-opt{code}");
                assert!(answered.contains(&n.as_str()), "{mode:?} {n}");
            }
            for code in [52u8, 53, 54, 57, 94, 97] {
                let x = get(&format!("duplicate-opt{code}")).unwrap();
                assert_eq!(x.expect, Expect::NoReply, "{code}");
                let m = Message::decode(&x.bytes).unwrap();
                assert_eq!(m.option_count(code), 2, "{code}");
            }
            let m = Message::decode(&get("split-opt60-prefix").unwrap().bytes).unwrap();
            assert_eq!(m.option_count(opt::VENDOR_CLASS), 2);
            assert_eq!(
                m.option_joined(opt::VENDOR_CLASS).as_deref(),
                Some(PXE_VENDOR_CLASS)
            );
            assert!(
                !m.option(opt::VENDOR_CLASS)
                    .unwrap()
                    .starts_with(b"PXEClient")
            );
            let m = Message::decode(&get("split-opt93-pair").unwrap().bytes).unwrap();
            assert_eq!(m.option_joined(opt::CLIENT_ARCH), Some(vec![0, 7]));
            let m = Message::decode(&get("split-opt94").unwrap().bytes).unwrap();
            assert_eq!(m.option_joined(opt::CLIENT_NDI), Some(vec![1, 3, 0]));
            let x = get("split-opt97").unwrap();
            let m = Message::decode(&x.bytes).unwrap();
            assert_eq!(m.option_count(opt::CLIENT_UUID), 2);
            assert_eq!(m.option_joined(opt::CLIENT_UUID).map(|g| g.len()), Some(17));
            let m = Message::decode(&get("split-opt43-tag71").unwrap().bytes).unwrap();
            assert_eq!(
                m.option_joined(opt::VENDOR_SPECIFIC),
                Some(vec![71, 4, 0, 0, 0, 0, 255])
            );
            assert_eq!(joined_message_type(&m), Some(codec::MessageType::Request));
            // Negatives: one piece alone would pass, the joined value fails.
            let x = get("split-opt60-non-pxe").unwrap();
            assert_eq!(x.expect, Expect::NoReply);
            let m = Message::decode(&x.bytes).unwrap();
            assert!(
                m.options
                    .iter()
                    .any(|o| o.code == opt::VENDOR_CLASS && o.data.starts_with(b"PXEClient"))
            );
            assert!(!could_be_served(&m));
            let x = get("split-opt93-odd").unwrap();
            assert_eq!(x.expect, Expect::NoReply);
            let m = Message::decode(&x.bytes).unwrap();
            assert_eq!(m.option(opt::CLIENT_ARCH), Some(&[0u8, 7][..]));
            assert_eq!(m.option_joined(opt::CLIENT_ARCH), Some(vec![0, 7, 0]));
            assert!(!could_be_served(&m));
            let x = get("split-opt97-len-18").unwrap();
            assert_eq!(x.expect, Expect::NoReply);
            let m = Message::decode(&x.bytes).unwrap();
            assert_eq!(m.option_joined(opt::CLIENT_UUID).map(|g| g.len()), Some(18));
            let x = get("split-opt43-tag71-len-3").unwrap();
            assert_eq!(x.expect, Expect::NoReply);
            let m = Message::decode(&x.bytes).unwrap();
            assert_eq!(
                m.option_joined(opt::VENDOR_SPECIFIC),
                Some(vec![71, 3, 0, 0, 0, 255])
            );
            // Option 82 vectors exist only where a relay agent sends them.
            match mode {
                Mode::Direct => {
                    assert!(get("duplicate-opt82").is_none());
                    assert!(get("split-opt82").is_none());
                }
                Mode::Relayed(_) => {
                    assert_eq!(get("duplicate-opt82").unwrap().expect, Expect::ProxyReply);
                    let m = Message::decode(&get("split-opt82").unwrap().bytes).unwrap();
                    assert_eq!(
                        m.option_joined(opt::RELAY_AGENT_INFO),
                        Some(vec![1, 3, b'l', b'a', b'b'])
                    );
                }
            }
        }
    }

    /// Each vector must be something the independent codec either rejects,
    /// or decodes into a request with a defect the plan lists. Structural
    /// spot checks keep the vectors honest.
    #[test]
    fn vectors_have_their_defect() {
        let v = vectors(Mode::Direct, 3, SVC);
        let get = |n: &str| v.iter().find(|x| x.name == n).unwrap();
        assert_eq!(get("size-239").bytes.len(), 239);
        assert_eq!(get("size-1473").bytes.len(), 1473);
        assert!(Message::decode(&get("opt-end-missing").bytes).is_err());
        assert!(Message::decode(&get("opt-length-overrun").bytes).is_err());
        assert!(Message::decode(&get("opt-code-last-byte").bytes).is_err());
        assert!(Message::decode(&get("opt-pad-only").bytes).is_err());
        // BOOT-013: every vector except size-* is at least the BOOTP
        // minimum, so a receiver's size floor does not mask its defect.
        for x in v.iter().filter(|x| !x.name.starts_with("size-")) {
            assert!(
                x.bytes.len() >= BOOTP_MIN_LEN,
                "{}: {}",
                x.name,
                x.bytes.len()
            );
        }
        for n in ["opt-code-last-byte", "opt-length-overrun", "opt-pad-only"] {
            assert_eq!(get(n).bytes.len(), BOOTP_MIN_LEN, "{n}");
        }
        assert_eq!(
            get("opt-code-last-byte").bytes.last(),
            Some(&opt::VENDOR_CLASS)
        );
        let m = Message::decode(&get("opt60-empty").bytes).unwrap();
        assert_eq!(m.option(opt::VENDOR_CLASS), Some(&[][..]));
        let m = Message::decode(&get("duplicate-opt53").bytes).unwrap();
        assert_eq!(m.option_count(opt::MESSAGE_TYPE), 2);
        let m = Message::decode(&get("opt93-without-7").bytes).unwrap();
        assert!(!could_be_served(&m));
        let m = Message::decode(&get("opt60-absent").bytes).unwrap();
        assert!(!could_be_served(&m));
        let m = Message::decode(&get("hops-17").bytes).unwrap();
        assert_eq!(m.hops, 17);
        assert!(!get("giaddr-is-service").observable);
        let m = Message::decode(&get("giaddr-is-service").bytes).unwrap();
        assert_eq!(m.giaddr, SVC);
        let m = Message::decode(&get("chaddr-multicast").bytes).unwrap();
        assert_eq!(m.mac()[0] & 1, 1);
    }

    /// QA final pass (BOOT-013): the 300-octet floor holds for every
    /// non-`size-*` vector in both probe modes and across seeds (the
    /// identities, and so option lengths, vary with the seed), and the
    /// `size-*` vectors keep their exact lengths.
    #[test]
    fn qa_vectors_meet_bootp_minimum_in_every_mode_and_seed() {
        let modes = [Mode::Direct, Mode::Relayed(Ipv4Addr::new(10, 20, 2, 1))];
        for mode in modes {
            for seed in [0u32, 1, 3, 77, 0xdead_beef, u32::MAX] {
                let v = vectors(mode, seed, SVC);
                assert!(!v.is_empty());
                for x in &v {
                    if let Some(n) = x.name.strip_prefix("size-") {
                        let want: usize = n.parse().unwrap();
                        assert_eq!(x.bytes.len(), want, "{mode:?} {seed} {}", x.name);
                    } else {
                        assert!(
                            x.bytes.len() >= BOOTP_MIN_LEN,
                            "{mode:?} seed {seed} {}: {}",
                            x.name,
                            x.bytes.len()
                        );
                    }
                }
            }
        }
    }

    fn good_reply(req: &Message) -> Message {
        let mut r = Message::new(OP_REPLY, req.xid, req.mac());
        r.flags = req.flags;
        r.siaddr = SVC;
        r.file[..9].copy_from_slice(b"boot.efi\0");
        r.options = vec![
            DhcpOption::new(opt::MESSAGE_TYPE, [2]),
            DhcpOption::new(opt::SERVER_ID, SVC.octets()),
            DhcpOption::new(opt::VENDOR_CLASS, b"PXEClient".to_vec()),
            DhcpOption::new(opt::CLIENT_ARCH, [0, 7]),
        ];
        r
    }

    #[test]
    fn proxy_reply_checks() {
        let req = pxe_discover(Mode::Direct, Ident::nth(2, 1));
        let expect = OfferExpect {
            server: Some(SVC),
            file: Some("boot.efi".into()),
        };
        assert_eq!(check_proxy_reply(&req, &good_reply(&req), &expect), Ok(()));
        let mut r = good_reply(&req);
        r.yiaddr = Ipv4Addr::new(10, 20, 1, 50);
        assert!(
            check_proxy_reply(&req, &r, &expect)
                .unwrap_err()
                .contains("yiaddr")
        );
        for code in LEASE_OPTIONS {
            let mut r = good_reply(&req);
            r.options.push(DhcpOption::new(code, [0, 0, 0, 0]));
            assert!(check_lease_free(&r).is_err(), "{code}");
        }
        let mut r = good_reply(&req);
        r.file = [0; 128];
        assert!(check_proxy_reply(&req, &r, &OfferExpect::default()).is_err());
        let mut r = good_reply(&req);
        r.siaddr = Ipv4Addr::new(10, 20, 1, 3);
        assert!(check_proxy_reply(&req, &r, &OfferExpect::default()).is_err());
        let mut r = good_reply(&req);
        r.flags = 0;
        assert!(check_proxy_reply(&req, &r, &OfferExpect::default()).is_err());
        let r = good_reply(&req);
        let other = OfferExpect {
            file: Some("other.efi".into()),
            ..OfferExpect::default()
        };
        assert!(check_proxy_reply(&req, &r, &other).is_err());
    }

    #[test]
    fn reply_option_set_checks() {
        let req = pxe_discover(Mode::Direct, Ident::nth(4, 1));
        let mut good = good_reply(&req);
        good.options
            .push(DhcpOption::new(opt::CLIENT_NDI, [1, 3, 0]));
        good.options.push(DhcpOption::new(
            opt::CLIENT_UUID,
            guid_option(Ident::nth(4, 1)),
        ));
        assert_eq!(check_reply_options(&req, &good), Ok(()));
        // Option 43 only answers a boot-server REQUEST that carried it.
        let mut r = good_reply(&req);
        r.options
            .push(DhcpOption::new(opt::VENDOR_SPECIFIC, tag71(&[0, 0, 0, 0])));
        assert!(check_reply_options(&req, &r).is_err());
        let boot = pxe_boot_request(Mode::Direct, Ident::nth(4, 2), Ipv4Addr::UNSPECIFIED);
        let mut r = good_reply(&boot);
        r.options
            .push(DhcpOption::new(opt::VENDOR_SPECIFIC, tag71(&[0, 0, 0, 0])));
        assert_eq!(check_reply_options(&boot, &r), Ok(()));
        // Anything else, or a repeated code, is refused.
        let mut r = good_reply(&req);
        r.options
            .push(DhcpOption::new(opt::TFTP_SERVER_NAME, b"x".to_vec()));
        assert!(check_reply_options(&req, &r).is_err());
        let mut r = good_reply(&req);
        r.options.push(DhcpOption::new(opt::CLIENT_ARCH, [0, 7]));
        assert!(
            check_reply_options(&req, &r)
                .unwrap_err()
                .contains("repeated")
        );
        // Option 82: only when sent, and echoed as the joined value.
        let mut r = good_reply(&req);
        r.options
            .push(DhcpOption::new(opt::RELAY_AGENT_INFO, [1, 1, b'x']));
        assert!(check_reply_options(&req, &r).is_err());
        let mut relayed = req.clone();
        split_option(&mut relayed, opt::RELAY_AGENT_INFO, &[&[1, 3, b'l'], b"ab"]);
        let mut r = good_reply(&relayed);
        r.options.push(DhcpOption::new(
            opt::RELAY_AGENT_INFO,
            [1, 3, b'l', b'a', b'b'],
        ));
        assert_eq!(check_reply_options(&relayed, &r), Ok(()));
        let mut r = good_reply(&relayed);
        r.options
            .push(DhcpOption::new(opt::RELAY_AGENT_INFO, [1, 3, b'l']));
        assert!(
            check_reply_options(&relayed, &r)
                .unwrap_err()
                .contains("82")
        );
    }

    #[test]
    fn rng_is_deterministic() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        for _ in 0..1000 {
            assert!(a.below_or_eq(10) <= 10);
        }
    }

    #[test]
    fn random_packets_are_never_servable() {
        let mut rng = Rng::new(1);
        for _ in 0..2000 {
            let p = random_packet(&mut rng);
            assert!(p.len() <= 1500);
            if let Ok(m) = Message::decode(&p) {
                assert!(!could_be_served(&m));
            }
        }
    }
}
