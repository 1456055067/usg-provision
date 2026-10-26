//! Sans-IO core of `lab-dhcpd`, the site DHCP server emulator.
//!
//! It stands in for an unmodified site DHCP server (REQ-BOOT-011): it leases
//! addresses and sends only the address options 1, 3, 51 and 54 (plus 53,
//! and an echo of option 82). It never sends PXE or boot options (60, 43,
//! 66, 67), and leaves `siaddr`, `sname` and `file` zero. Leases are kept in
//! memory for the life of the process and do not expire (lab
//! simplification).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Testing and Evaluation)
//! - SPEC: specs/boot-network.md#REQ-BOOT-011 (site DHCP left unmodified)
//! - RFC 2131 §3.1, §4.3 - DISCOVER/OFFER, REQUEST/ACK/NAK
//! - RFC 2131 §4.1 / RFC 1542 §5.4 - reply addressing (pxe-dhcp.md §9)
//! - RFC 3046 §2.2 - echo option 82 last

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::FromStr;

use crate::codec::{self, DhcpOption, Message, MessageType, OP_REPLY, OP_REQUEST, opt};

/// UDP port servers listen on.
pub const SERVER_PORT: u16 = 67;
/// UDP port clients listen on.
pub const CLIENT_PORT: u16 = 68;

/// Options this server may put in a reply (the REQ-BOOT-011 test checks this).
pub const REPLY_OPTION_SET: [u8; 6] = [
    opt::SUBNET_MASK,
    opt::ROUTER,
    opt::LEASE_TIME,
    opt::MESSAGE_TYPE,
    opt::SERVER_ID,
    opt::RELAY_AGENT_INFO,
];

/// An address pool: `NET/PREFIX,FIRST-LAST,ROUTER`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pool {
    /// Network address.
    pub network: Ipv4Addr,
    /// Prefix length, 8 to 30.
    pub prefix: u8,
    /// First leasable address.
    pub first: Ipv4Addr,
    /// Last leasable address.
    pub last: Ipv4Addr,
    /// Router (option 3).
    pub router: Ipv4Addr,
}

impl Pool {
    /// Subnet mask (option 1).
    pub fn mask(&self) -> Ipv4Addr {
        Ipv4Addr::from(mask_bits(self.prefix))
    }

    /// Whether `addr` is inside this pool's network.
    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        let m = mask_bits(self.prefix);
        u32::from(addr) & m == u32::from(self.network) & m
    }
}

fn mask_bits(prefix: u8) -> u32 {
    u32::MAX
        .checked_shl(32 - u32::from(prefix.min(32)))
        .unwrap_or(0)
}

/// Error parsing a pool specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolParseError(pub String);

impl fmt::Display for PoolParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "bad pool (want NET/PREFIX,FIRST-LAST,ROUTER): {}",
            self.0
        )
    }
}

impl std::error::Error for PoolParseError {}

impl FromStr for Pool {
    type Err = PoolParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || PoolParseError(s.to_owned());
        let mut parts = s.split(',');
        let (net, range, router) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(a), Some(b), Some(c), None) => (a, b, c),
            _ => return Err(err()),
        };
        let (network, prefix) = net.split_once('/').ok_or_else(err)?;
        let network: Ipv4Addr = network.parse().map_err(|_| err())?;
        let prefix: u8 = prefix.parse().map_err(|_| err())?;
        if !(8..=30).contains(&prefix) {
            return Err(err());
        }
        let (first, last) = range.split_once('-').ok_or_else(err)?;
        let first: Ipv4Addr = first.parse().map_err(|_| err())?;
        let last: Ipv4Addr = last.parse().map_err(|_| err())?;
        let router: Ipv4Addr = router.parse().map_err(|_| err())?;
        let pool = Self {
            network,
            prefix,
            first,
            last,
            router,
        };
        if u32::from(network) & !mask_bits(prefix) != 0
            || u32::from(first) > u32::from(last)
            || !pool.contains(first)
            || !pool.contains(last)
            || !pool.contains(router)
        {
            return Err(err());
        }
        Ok(pool)
    }
}

/// Server settings.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Server identifier (option 54).
    pub server_id: Ipv4Addr,
    /// Lease time in seconds (option 51).
    pub lease_secs: u32,
    /// Pools, chosen by giaddr or by the receiving interface's address.
    pub pools: Vec<Pool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LeaseState {
    Offered,
    Bound,
}

#[derive(Clone, Debug)]
struct Lease {
    addr: Ipv4Addr,
    state: LeaseState,
}

/// A reply to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outbound {
    /// Destination address and port.
    pub dest: SocketAddrV4,
    /// Encoded message.
    pub payload: Vec<u8>,
}

/// Result of handling one datagram.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Handled {
    /// Log lines (`key=value` fields).
    pub log: Vec<String>,
    /// Reply, if any.
    pub reply: Option<Outbound>,
}

/// The site DHCP server state machine.
#[derive(Debug)]
pub struct Server {
    cfg: ServerConfig,
    leases: HashMap<Vec<u8>, Lease>,
    declined: HashSet<Ipv4Addr>,
}

impl Server {
    /// A server with no leases.
    pub fn new(cfg: ServerConfig) -> Self {
        Self {
            cfg,
            leases: HashMap::new(),
            declined: HashSet::new(),
        }
    }

    /// Handles one datagram received on the interface whose address is
    /// `iface_addr`.
    pub fn handle(&mut self, iface_addr: Ipv4Addr, src: SocketAddrV4, bytes: &[u8]) -> Handled {
        let mut out = Handled::default();
        let msg = match Message::decode(bytes) {
            Ok(m) => m,
            Err(e) => {
                out.log.push(format!("event=drop src={src} reason=\"{e}\""));
                return out;
            }
        };
        if msg.op != OP_REQUEST {
            out.log.push(format!(
                "event=drop src={src} xid={:#010x} reason=not-request",
                msg.xid
            ));
            return out;
        }
        let Some(kind) = msg.message_type() else {
            out.log.push(format!(
                "event=drop src={src} xid={:#010x} reason=no-message-type",
                msg.xid
            ));
            return out;
        };
        let mac = codec::fmt_mac(&msg.mac());
        let opt60 = match msg.option(opt::VENDOR_CLASS) {
            Some(v) => format!("\"{}\"", codec::escape_bytes(v)),
            None => "none".to_owned(),
        };
        let selector = if msg.giaddr.is_unspecified() {
            iface_addr
        } else {
            msg.giaddr
        };
        let Some(pool) = self
            .cfg
            .pools
            .iter()
            .find(|p| p.contains(selector))
            .cloned()
        else {
            out.log.push(format!(
                "event=drop xid={:#010x} chaddr={mac} giaddr={} reason=no-pool",
                msg.xid, msg.giaddr
            ));
            return out;
        };
        let key = client_key(&msg);
        let reply = match kind {
            MessageType::Discover => {
                // Plan WU-10: every DISCOVER's option 60 is logged; the
                // harness preflight greps for PXEClient:Arch:00007.
                out.log.push(format!(
                    "event=discover xid={:#010x} chaddr={mac} giaddr={} opt60={opt60}",
                    msg.xid, msg.giaddr
                ));
                match self.allocate(&key, &pool) {
                    Some(addr) => Some((MessageType::Offer, addr)),
                    None => {
                        out.log.push(format!(
                            "event=drop xid={:#010x} chaddr={mac} reason=pool-exhausted",
                            msg.xid
                        ));
                        None
                    }
                }
            }
            MessageType::Request => self.on_request(&msg, &key, &pool, &mut out.log),
            MessageType::Release => {
                self.leases.remove(&key);
                out.log
                    .push(format!("event=release xid={:#010x} chaddr={mac}", msg.xid));
                None
            }
            MessageType::Decline => {
                if let Some(lease) = self.leases.remove(&key) {
                    self.declined.insert(lease.addr);
                }
                out.log
                    .push(format!("event=decline xid={:#010x} chaddr={mac}", msg.xid));
                None
            }
            other => {
                out.log.push(format!(
                    "event=ignore xid={:#010x} chaddr={mac} type={other:?}",
                    msg.xid
                ));
                None
            }
        };
        let Some((reply_type, addr)) = reply else {
            return out;
        };
        match self.build_reply(&msg, reply_type, addr, &pool) {
            Ok(outbound) => {
                out.log.push(format!(
                    "event={} xid={:#010x} chaddr={mac} yiaddr={addr} dest={}",
                    format!("{reply_type:?}").to_ascii_lowercase(),
                    msg.xid,
                    outbound.dest
                ));
                out.reply = Some(outbound);
            }
            Err(e) => out.log.push(format!(
                "event=drop xid={:#010x} reason=\"encode: {e}\"",
                msg.xid
            )),
        }
        out
    }

    fn on_request(
        &mut self,
        msg: &Message,
        key: &[u8],
        pool: &Pool,
        log: &mut Vec<String>,
    ) -> Option<(MessageType, Ipv4Addr)> {
        let mac = codec::fmt_mac(&msg.mac());
        let lease = self.leases.get(key).cloned();
        if let Some(server_id) = msg.option_addr(opt::SERVER_ID) {
            if server_id != self.cfg.server_id {
                // The client chose another server (RFC 2131 §4.3.2); for a
                // PXE client that may be the boot service. Free our offer.
                if lease
                    .as_ref()
                    .is_some_and(|l| l.state == LeaseState::Offered)
                {
                    self.leases.remove(key);
                }
                log.push(format!("event=ignore xid={:#010x} chaddr={mac} reason=other-server server_id={server_id}", msg.xid));
                return None;
            }
            // SELECTING: option 50 must name the address we offered.
            return match (lease, msg.option_addr(opt::REQUESTED_IP)) {
                (Some(l), Some(req)) if l.addr == req => {
                    self.bind(key, l.addr);
                    Some((MessageType::Ack, l.addr))
                }
                _ => Some((MessageType::Nak, Ipv4Addr::UNSPECIFIED)),
            };
        }
        let requested = if msg.ciaddr.is_unspecified() {
            msg.option_addr(opt::REQUESTED_IP)
        } else {
            Some(msg.ciaddr)
        };
        match (lease, requested) {
            (Some(l), Some(req)) if l.addr == req => {
                self.bind(key, l.addr);
                Some((MessageType::Ack, l.addr))
            }
            // INIT-REBOOT with a wrong address for this network: NAK.
            (_, Some(req)) if msg.ciaddr.is_unspecified() && !pool.contains(req) => {
                Some((MessageType::Nak, Ipv4Addr::UNSPECIFIED))
            }
            // No record of this client: stay silent (RFC 2131 §4.3.2).
            _ => {
                log.push(format!(
                    "event=ignore xid={:#010x} chaddr={mac} reason=no-lease",
                    msg.xid
                ));
                None
            }
        }
    }

    fn bind(&mut self, key: &[u8], addr: Ipv4Addr) {
        self.leases.insert(
            key.to_vec(),
            Lease {
                addr,
                state: LeaseState::Bound,
            },
        );
    }

    fn allocate(&mut self, key: &[u8], pool: &Pool) -> Option<Ipv4Addr> {
        if let Some(lease) = self.leases.get(key)
            && pool.contains(lease.addr)
        {
            return Some(lease.addr);
        }
        let used: HashSet<Ipv4Addr> = self.leases.values().map(|l| l.addr).collect();
        let addr = (u32::from(pool.first)..=u32::from(pool.last))
            .map(Ipv4Addr::from)
            .find(|a| {
                *a != pool.router
                    && *a != self.cfg.server_id
                    && !used.contains(a)
                    && !self.declined.contains(a)
            })?;
        self.leases.insert(
            key.to_vec(),
            Lease {
                addr,
                state: LeaseState::Offered,
            },
        );
        Some(addr)
    }

    fn build_reply(
        &self,
        req: &Message,
        kind: MessageType,
        addr: Ipv4Addr,
        pool: &Pool,
    ) -> Result<Outbound, codec::CodecError> {
        let mut m = Message::new(OP_REPLY, req.xid, [0; 6]);
        m.htype = req.htype;
        m.hlen = req.hlen;
        m.chaddr = req.chaddr;
        m.flags = req.flags;
        m.giaddr = req.giaddr;
        if kind != MessageType::Nak {
            m.ciaddr = req.ciaddr;
            m.yiaddr = addr;
        }
        m.options
            .push(DhcpOption::new(opt::MESSAGE_TYPE, [kind.code()]));
        m.options
            .push(DhcpOption::new(opt::SERVER_ID, self.cfg.server_id.octets()));
        if kind != MessageType::Nak {
            m.options.push(DhcpOption::new(
                opt::LEASE_TIME,
                self.cfg.lease_secs.to_be_bytes(),
            ));
            m.options
                .push(DhcpOption::new(opt::SUBNET_MASK, pool.mask().octets()));
            m.options
                .push(DhcpOption::new(opt::ROUTER, pool.router.octets()));
        }
        let mut payload = m.encode()?;
        // RFC 3046 §2.2: echo option 82 unchanged as the last option, or
        // send the reply without it if it does not fit.
        if let Some(info) = req.option(opt::RELAY_AGENT_INFO)
            && let Ok(with) = codec::insert_option_before_end(&payload, opt::RELAY_AGENT_INFO, info)
        {
            payload = with;
        }
        Ok(Outbound {
            dest: reply_dest(req, kind),
            payload,
        })
    }
}

/// Client identity: option 61 if present, else htype and chaddr
/// (RFC 2131 §4.2).
fn client_key(msg: &Message) -> Vec<u8> {
    if let Some(id) = msg.option(opt::CLIENT_ID) {
        let mut key = vec![0u8];
        key.extend_from_slice(id);
        return key;
    }
    let hlen = usize::from(msg.hlen).min(16);
    let mut key = vec![1u8, msg.htype];
    key.extend_from_slice(msg.chaddr.get(..hlen).unwrap_or(&[]));
    key
}

/// Reply destination (pxe-dhcp.md §9; RFC 2131 §4.1):
/// giaddr:67, else ciaddr:68, else broadcast:68. The unicast-to-yiaddr case
/// is sent as a broadcast because a UDP socket cannot address a client that
/// has no ARP entry yet ("a server that cannot send such a unicast may
/// broadcast instead"). A NAK is never sent to ciaddr.
pub fn reply_dest(req: &Message, kind: MessageType) -> SocketAddrV4 {
    if !req.giaddr.is_unspecified() {
        return SocketAddrV4::new(req.giaddr, SERVER_PORT);
    }
    if kind != MessageType::Nak && !req.ciaddr.is_unspecified() {
        return SocketAddrV4::new(req.ciaddr, CLIENT_PORT);
    }
    SocketAddrV4::new(Ipv4Addr::BROADCAST, CLIENT_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;

    const IFACE: Ipv4Addr = Ipv4Addr::new(10, 20, 1, 3);
    const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68);
    const MAC: [u8; 6] = [0x52, 0x54, 0, 0, 1, 1];

    fn server() -> Server {
        Server::new(ServerConfig {
            server_id: IFACE,
            lease_secs: 600,
            pools: vec![
                "10.20.1.0/24,10.20.1.100-10.20.1.101,10.20.1.1"
                    .parse()
                    .unwrap(),
                "10.20.2.0/24,10.20.2.100-10.20.2.199,10.20.2.1"
                    .parse()
                    .unwrap(),
            ],
        })
    }

    fn pxe_discover(xid: u32, mac: [u8; 6]) -> Message {
        let mut m = Message::new(OP_REQUEST, xid, mac);
        m.flags = codec::FLAG_BROADCAST;
        m.options.push(DhcpOption::new(opt::MESSAGE_TYPE, [1]));
        m.options.push(DhcpOption::new(
            opt::VENDOR_CLASS,
            b"PXEClient:Arch:00007:UNDI:003000".to_vec(),
        ));
        m.options.push(DhcpOption::new(opt::CLIENT_ARCH, [0, 7]));
        m.options.push(DhcpOption::new(
            opt::PARAMETER_REQUEST,
            [1, 3, 43, 60, 66, 67, 128],
        ));
        m
    }

    fn request_for(offer: &Message, server_id: Ipv4Addr) -> Message {
        let mut m = pxe_discover(offer.xid, offer.mac());
        m.options[0] = DhcpOption::new(opt::MESSAGE_TYPE, [3]);
        m.giaddr = offer.giaddr;
        m.options
            .push(DhcpOption::new(opt::SERVER_ID, server_id.octets()));
        m.options
            .push(DhcpOption::new(opt::REQUESTED_IP, offer.yiaddr.octets()));
        m
    }

    fn reply_of(h: &Handled) -> (Message, SocketAddrV4) {
        let r = h.reply.as_ref().expect("reply");
        (Message::decode(&r.payload).unwrap(), r.dest)
    }

    #[test]
    fn discover_offer_request_ack_same_segment() {
        let mut s = server();
        let h = s.handle(IFACE, CLIENT, &pxe_discover(7, MAC).encode().unwrap());
        assert!(h.log[0].contains("event=discover"));
        assert!(h.log[0].contains("opt60=\"PXEClient:Arch:00007:UNDI:003000\""));
        let (offer, dest) = reply_of(&h);
        assert_eq!(dest, SocketAddrV4::new(Ipv4Addr::BROADCAST, 68));
        assert_eq!(offer.message_type(), Some(MessageType::Offer));
        assert_eq!(offer.yiaddr, Ipv4Addr::new(10, 20, 1, 100));
        assert_eq!(offer.option_addr(opt::SERVER_ID), Some(IFACE));
        assert_eq!(
            offer.option_addr(opt::SUBNET_MASK),
            Some(Ipv4Addr::new(255, 255, 255, 0))
        );
        assert_eq!(
            offer.option_addr(opt::ROUTER),
            Some(Ipv4Addr::new(10, 20, 1, 1))
        );
        assert_eq!(
            offer.option(opt::LEASE_TIME),
            Some(&600u32.to_be_bytes()[..])
        );
        assert!(offer.broadcast());

        let h = s.handle(IFACE, CLIENT, &request_for(&offer, IFACE).encode().unwrap());
        let (ack, _) = reply_of(&h);
        assert_eq!(ack.message_type(), Some(MessageType::Ack));
        assert_eq!(ack.yiaddr, offer.yiaddr);
    }

    /// REQ-BOOT-011: the site server stays unmodified, so it sends no PXE
    /// or boot information at all.
    #[test]
    fn replies_carry_no_pxe_or_boot_options() {
        let mut s = server();
        let h = s.handle(IFACE, CLIENT, &pxe_discover(1, MAC).encode().unwrap());
        let (offer, _) = reply_of(&h);
        let h = s.handle(IFACE, CLIENT, &request_for(&offer, IFACE).encode().unwrap());
        let (ack, _) = reply_of(&h);
        let mut nak_req = request_for(&offer, IFACE);
        nak_req.options.pop();
        nak_req
            .options
            .push(DhcpOption::new(opt::REQUESTED_IP, [10, 20, 1, 222]));
        let h = s.handle(IFACE, CLIENT, &nak_req.encode().unwrap());
        let (nak, nak_dest) = reply_of(&h);
        assert_eq!(nak.message_type(), Some(MessageType::Nak));
        assert_eq!(nak.yiaddr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(nak_dest.ip(), &Ipv4Addr::BROADCAST);
        for m in [offer, ack, nak] {
            for o in &m.options {
                assert!(REPLY_OPTION_SET.contains(&o.code), "option {}", o.code);
            }
            assert_eq!(m.siaddr, Ipv4Addr::UNSPECIFIED);
            assert!(m.file.iter().all(|&b| b == 0));
            assert!(m.sname.iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn relayed_discover_uses_giaddr_pool_and_echoes_opt82_last() {
        let mut s = server();
        let mut d = pxe_discover(9, MAC);
        d.giaddr = Ipv4Addr::new(10, 20, 2, 1);
        d.hops = 1;
        let info = codec::relay_agent_info(b"rtB", b"usgp-netlab").unwrap();
        d.options
            .push(DhcpOption::new(opt::RELAY_AGENT_INFO, info.clone()));
        let h = s.handle(
            IFACE,
            SocketAddrV4::new(Ipv4Addr::new(10, 20, 1, 1), 67),
            &d.encode().unwrap(),
        );
        let (offer, dest) = reply_of(&h);
        assert_eq!(dest, SocketAddrV4::new(Ipv4Addr::new(10, 20, 2, 1), 67));
        assert_eq!(offer.yiaddr, Ipv4Addr::new(10, 20, 2, 100));
        assert_eq!(offer.giaddr, d.giaddr);
        assert_eq!(
            offer.option_addr(opt::ROUTER),
            Some(Ipv4Addr::new(10, 20, 2, 1))
        );
        let last = offer.options.last().unwrap();
        assert_eq!((last.code, &last.data), (opt::RELAY_AGENT_INFO, &info));
    }

    #[test]
    fn request_for_other_server_is_ignored_and_frees_offer() {
        let mut s = server();
        let (offer, _) =
            reply_of(&s.handle(IFACE, CLIENT, &pxe_discover(1, MAC).encode().unwrap()));
        let h = s.handle(
            IFACE,
            CLIENT,
            &request_for(&offer, Ipv4Addr::new(10, 20, 1, 2))
                .encode()
                .unwrap(),
        );
        assert!(h.reply.is_none());
        assert!(h.log[0].contains("other-server"));
        // The address is free again for another client.
        let (other, _) = reply_of(&s.handle(
            IFACE,
            CLIENT,
            &pxe_discover(2, [0x52, 0x54, 0, 0, 1, 2]).encode().unwrap(),
        ));
        assert_eq!(other.yiaddr, offer.yiaddr);
    }

    #[test]
    fn pool_exhaustion_and_stable_reoffer() {
        let mut s = server();
        let a = reply_of(&s.handle(
            IFACE,
            CLIENT,
            &pxe_discover(1, [2, 0, 0, 0, 0, 1]).encode().unwrap(),
        ))
        .0;
        let again = reply_of(&s.handle(
            IFACE,
            CLIENT,
            &pxe_discover(2, [2, 0, 0, 0, 0, 1]).encode().unwrap(),
        ))
        .0;
        assert_eq!(a.yiaddr, again.yiaddr);
        let b = reply_of(&s.handle(
            IFACE,
            CLIENT,
            &pxe_discover(3, [2, 0, 0, 0, 0, 2]).encode().unwrap(),
        ))
        .0;
        assert_ne!(a.yiaddr, b.yiaddr);
        let h = s.handle(
            IFACE,
            CLIENT,
            &pxe_discover(4, [2, 0, 0, 0, 0, 3]).encode().unwrap(),
        );
        assert!(h.reply.is_none());
        assert!(h.log.iter().any(|l| l.contains("pool-exhausted")));
    }

    #[test]
    fn renew_unicasts_to_ciaddr() {
        let mut s = server();
        let (offer, _) =
            reply_of(&s.handle(IFACE, CLIENT, &pxe_discover(1, MAC).encode().unwrap()));
        reply_of(&s.handle(IFACE, CLIENT, &request_for(&offer, IFACE).encode().unwrap()));
        let mut renew = pxe_discover(5, MAC);
        renew.options[0] = DhcpOption::new(opt::MESSAGE_TYPE, [3]);
        renew.flags = 0;
        renew.ciaddr = offer.yiaddr;
        let (ack, dest) = reply_of(&s.handle(IFACE, CLIENT, &renew.encode().unwrap()));
        assert_eq!(ack.message_type(), Some(MessageType::Ack));
        assert_eq!(dest, SocketAddrV4::new(offer.yiaddr, 68));
    }

    #[test]
    fn drops_malformed_replies_and_unknown_networks() {
        let mut s = server();
        assert!(s.handle(IFACE, CLIENT, &[0u8; 10]).reply.is_none());
        let mut reply = pxe_discover(1, MAC);
        reply.op = OP_REPLY;
        assert!(
            s.handle(IFACE, CLIENT, &reply.encode().unwrap())
                .reply
                .is_none()
        );
        let mut no_type = pxe_discover(1, MAC);
        no_type.options.remove(0);
        assert!(
            s.handle(IFACE, CLIENT, &no_type.encode().unwrap())
                .reply
                .is_none()
        );
        let mut far = pxe_discover(1, MAC);
        far.giaddr = Ipv4Addr::new(192, 0, 2, 1);
        let h = s.handle(IFACE, CLIENT, &far.encode().unwrap());
        assert!(h.reply.is_none());
        assert!(h.log[0].contains("no-pool"));
    }

    #[test]
    fn opt60_logged_escaped_or_none() {
        let mut s = server();
        let mut d = pxe_discover(1, MAC);
        d.options[1] = DhcpOption::new(opt::VENDOR_CLASS, b"x\" event=fake".to_vec());
        let h = s.handle(IFACE, CLIENT, &d.encode().unwrap());
        assert!(h.log[0].contains("opt60=\"x\\\" event=fake\""));
        let mut d = pxe_discover(2, [0x52, 0, 0, 0, 0, 9]);
        d.options.remove(1);
        let h = s.handle(IFACE, CLIENT, &d.encode().unwrap());
        assert!(h.log[0].ends_with("opt60=none"));
    }

    #[test]
    fn pool_parsing() {
        let p: Pool = "10.20.1.0/24,10.20.1.100-10.20.1.199,10.20.1.1"
            .parse()
            .unwrap();
        assert!(p.contains(Ipv4Addr::new(10, 20, 1, 255)));
        assert!(!p.contains(Ipv4Addr::new(10, 20, 2, 1)));
        for bad in [
            "",
            "10.20.1.0/24,10.20.1.100-10.20.1.199",
            "10.20.1.0/24,10.20.1.100-10.20.1.199,10.20.1.1,x",
            "10.20.1.5/24,10.20.1.100-10.20.1.199,10.20.1.1",
            "10.20.1.0/31,10.20.1.0-10.20.1.1,10.20.1.1",
            "10.20.1.0/24,10.20.1.199-10.20.1.100,10.20.1.1",
            "10.20.1.0/24,10.20.2.100-10.20.2.199,10.20.1.1",
            "10.20.1.0/24,10.20.1.100-10.20.1.199,10.20.9.1",
        ] {
            assert!(bad.parse::<Pool>().is_err(), "{bad}");
        }
    }
}
