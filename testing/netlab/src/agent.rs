//! Sans-IO core of `lab-relay-agent`, an RFC 1542 DHCP relay agent.
//!
//! Requests from the client segment are forwarded by unicast to every
//! configured server (RFC 1542 §4.1.1): `giaddr` is set to the client-side
//! address when it is 0, `hops` is incremented, and option 82 is added as
//! the last option (RFC 3046 §2.0). Nothing else in the message changes.
//!
//! Replies are accepted only when `giaddr` is the client-side address
//! (RFC 1542 §4.1.2). The agent checks that option 82 came back unchanged
//! and logs `opt82=ok|missing|changed`, removes it (RFC 3046 §2.1), and
//! broadcasts the reply on the client segment to port 68. A ProxyDHCP reply
//! has `yiaddr` = 0, so broadcast is what RFC 1542 §4.1.2 asks for. A site
//! reply with `yiaddr` set and BROADCAST clear should be unicast to
//! `yiaddr`/`chaddr`; this test agent broadcasts it too, because a UDP
//! socket cannot unicast to a client that has no ARP entry. That
//! simplification is recorded in testing/boot-smoke/topology.md (BOOT-007).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Testing and Evaluation)
//! - SPEC: specs/boot-network.md#REQ-BOOT-002, #REQ-BOOT-020, #REQ-BOOT-021
//! - RFC 1542 §4.1.1, §4.1.2 - relay agent request and reply handling
//! - RFC 3046 §2.0, §2.1, §2.1.1 - option 82 insert, strip, drop rules

use std::net::{Ipv4Addr, SocketAddrV4};

use crate::codec::{self, Message, OP_REPLY, OP_REQUEST, opt};
use crate::dhcpd::{CLIENT_PORT, SERVER_PORT};

/// Default hop limit (RFC 1542 §4.1.1 recommends 4).
pub const DEFAULT_MAX_HOPS: u8 = 4;
/// Default option 82 remote ID (sub-option 2). A fixed lab label.
pub const DEFAULT_REMOTE_ID: &[u8] = b"usgp-netlab";

/// Relay agent settings.
#[derive(Clone, Debug)]
pub struct AgentConfig {
    /// Client-side interface name; used as the option 82 circuit ID.
    pub client_iface: String,
    /// Client-side interface address; becomes `giaddr`.
    pub client_addr: Ipv4Addr,
    /// Every request is sent to all of these, port 67.
    pub servers: Vec<Ipv4Addr>,
    /// Requests whose `hops` exceeds this are dropped.
    pub max_hops: u8,
    /// Option 82 remote ID.
    pub remote_id: Vec<u8>,
    /// All of this agent's own addresses (RFC 3046 §2.1.1 check).
    pub own_addrs: Vec<Ipv4Addr>,
}

/// Which socket a datagram leaves from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    /// The server-side socket (unicast to a server).
    ServerSide,
    /// The client-side socket (broadcast on the client segment).
    ClientSide,
}

/// One datagram to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Send {
    /// Socket to use.
    pub via: Via,
    /// Destination.
    pub dest: SocketAddrV4,
    /// Bytes.
    pub payload: Vec<u8>,
}

/// Result of handling one datagram.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Handled {
    /// Log lines.
    pub log: Vec<String>,
    /// Datagrams to send.
    pub sends: Vec<Send>,
}

/// The relay agent.
#[derive(Clone, Debug)]
pub struct Agent {
    cfg: AgentConfig,
    opt82: Vec<u8>,
}

impl Agent {
    /// Builds the agent. Fails if the circuit or remote ID is too long for
    /// option 82.
    pub fn new(cfg: AgentConfig) -> Result<Self, codec::CodecError> {
        let opt82 = codec::relay_agent_info(cfg.client_iface.as_bytes(), &cfg.remote_id)?;
        Ok(Self { cfg, opt82 })
    }

    /// The option 82 data this agent adds.
    pub fn opt82(&self) -> &[u8] {
        &self.opt82
    }

    /// A datagram received on the client-side socket.
    pub fn on_client_side(&self, src: SocketAddrV4, bytes: &[u8]) -> Handled {
        let mut out = Handled::default();
        let msg = match Message::decode(bytes) {
            Ok(m) => m,
            Err(e) => {
                out.log
                    .push(format!("event=drop side=client src={src} reason=\"{e}\""));
                return out;
            }
        };
        let xid = msg.xid;
        if msg.op != OP_REQUEST {
            out.log.push(format!(
                "event=drop side=client src={src} xid={xid:#010x} reason=not-request"
            ));
            return out;
        }
        if msg.hops > self.cfg.max_hops {
            out.log.push(format!(
                "event=drop side=client xid={xid:#010x} reason=hops hops={}",
                msg.hops
            ));
            return out;
        }
        if self.cfg.own_addrs.contains(&msg.giaddr) || msg.giaddr == self.cfg.client_addr {
            out.log.push(format!(
                "event=drop side=client xid={xid:#010x} reason=giaddr-is-own"
            ));
            return out;
        }
        let mut buf = bytes.to_vec();
        let mut opt82_state = "not-first-relay";
        if msg.giaddr.is_unspecified() {
            if msg.option(opt::RELAY_AGENT_INFO).is_some() {
                // RFC 3046 §2.1: giaddr 0 with option 82 on an untrusted
                // circuit is dropped.
                out.log.push(format!(
                    "event=drop side=client xid={xid:#010x} reason=opt82-from-client"
                ));
                return out;
            }
            if codec::set_giaddr(&mut buf, self.cfg.client_addr).is_err() {
                return out;
            }
            match codec::insert_option_before_end(&buf, opt::RELAY_AGENT_INFO, self.opt82()) {
                Ok(with) => {
                    buf = with;
                    opt82_state = "added";
                }
                // Too large to add: forward without it (logged).
                Err(_) => opt82_state = "not-added",
            }
        }
        let hops = msg.hops.saturating_add(1);
        if codec::set_hops(&mut buf, hops).is_err() {
            return out;
        }
        for server in &self.cfg.servers {
            out.sends.push(Send {
                via: Via::ServerSide,
                dest: SocketAddrV4::new(*server, SERVER_PORT),
                payload: buf.clone(),
            });
        }
        let servers: Vec<String> = self.cfg.servers.iter().map(|s| s.to_string()).collect();
        out.log.push(format!(
            "event=forward xid={xid:#010x} chaddr={} hops={hops} opt82={opt82_state} servers={}",
            codec::fmt_mac(&msg.mac()),
            servers.join(",")
        ));
        out
    }

    /// A datagram received on the server-side socket.
    pub fn on_server_side(&self, src: SocketAddrV4, bytes: &[u8]) -> Handled {
        let mut out = Handled::default();
        let msg = match Message::decode(bytes) {
            Ok(m) => m,
            Err(e) => {
                out.log
                    .push(format!("event=drop side=server src={src} reason=\"{e}\""));
                return out;
            }
        };
        if msg.op != OP_REPLY {
            // The server-side segment carries other clients' broadcasts;
            // relaying is not configured there (RFC 1542 §4.1.1). Silent.
            return out;
        }
        let xid = msg.xid;
        if msg.giaddr != self.cfg.client_addr {
            out.log.push(format!("event=drop side=server src={src} xid={xid:#010x} reason=giaddr-no-interface giaddr={}", msg.giaddr));
            return out;
        }
        let opt82 = match msg.option(opt::RELAY_AGENT_INFO) {
            None => "missing",
            Some(data) if data == self.opt82() && msg.option_count(opt::RELAY_AGENT_INFO) == 1 => {
                "ok"
            }
            Some(_) => "changed",
        };
        let stripped = match codec::remove_options(bytes, opt::RELAY_AGENT_INFO) {
            Ok(b) => b,
            Err(e) => {
                out.log.push(format!(
                    "event=drop side=server src={src} xid={xid:#010x} reason=\"{e}\""
                ));
                return out;
            }
        };
        out.sends.push(Send {
            via: Via::ClientSide,
            dest: SocketAddrV4::new(Ipv4Addr::BROADCAST, CLIENT_PORT),
            payload: stripped,
        });
        out.log.push(format!(
            "event=reply xid={xid:#010x} from={src} chaddr={} yiaddr={} opt82={opt82}",
            codec::fmt_mac(&msg.mac()),
            msg.yiaddr
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::DhcpOption;

    const RTB: Ipv4Addr = Ipv4Addr::new(10, 20, 2, 1);
    const RTA: Ipv4Addr = Ipv4Addr::new(10, 20, 1, 1);
    const SITE: Ipv4Addr = Ipv4Addr::new(10, 20, 1, 3);
    const BOOT: Ipv4Addr = Ipv4Addr::new(10, 20, 1, 2);
    const FROM_CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68);

    fn agent() -> Agent {
        Agent::new(AgentConfig {
            client_iface: "rtB".into(),
            client_addr: RTB,
            servers: vec![SITE, BOOT],
            max_hops: DEFAULT_MAX_HOPS,
            remote_id: DEFAULT_REMOTE_ID.to_vec(),
            own_addrs: vec![RTA, RTB],
        })
        .unwrap()
    }

    fn discover() -> Message {
        let mut m = Message::new(OP_REQUEST, 0xabcd, [0x52, 0x54, 0, 0, 2, 1]);
        m.flags = codec::FLAG_BROADCAST;
        m.options.push(DhcpOption::new(opt::MESSAGE_TYPE, [1]));
        m.options.push(DhcpOption::new(
            opt::VENDOR_CLASS,
            b"PXEClient:Arch:00007:UNDI:003000".to_vec(),
        ));
        m
    }

    #[test]
    fn request_forwarded_to_every_server_with_giaddr_hops_opt82() {
        let a = agent();
        let raw = discover().encode().unwrap();
        let h = a.on_client_side(FROM_CLIENT, &raw);
        assert_eq!(h.sends.len(), 2);
        assert_eq!(h.sends[0].dest, SocketAddrV4::new(SITE, 67));
        assert_eq!(h.sends[1].dest, SocketAddrV4::new(BOOT, 67));
        assert_eq!(h.sends[0].payload, h.sends[1].payload);
        let fwd = Message::decode(&h.sends[0].payload).unwrap();
        assert_eq!(fwd.giaddr, RTB);
        assert_eq!(fwd.hops, 1);
        let last = fwd.options.last().unwrap();
        assert_eq!(last.code, opt::RELAY_AGENT_INFO);
        assert_eq!(last.data, a.opt82());
        // Only hops, giaddr and the added option changed.
        let mut expect = raw.clone();
        expect[3] = 1;
        expect[24..28].copy_from_slice(&RTB.octets());
        let end = expect.len() - 1;
        let mut tlv = vec![
            opt::RELAY_AGENT_INFO,
            u8::try_from(a.opt82().len()).unwrap(),
        ];
        tlv.extend_from_slice(a.opt82());
        expect.splice(end..end, tlv);
        assert_eq!(h.sends[0].payload, expect);
        assert!(h.log[0].contains("opt82=added"));
    }

    #[test]
    fn existing_giaddr_kept_and_no_opt82_added() {
        let a = agent();
        let mut m = discover();
        m.giaddr = Ipv4Addr::new(10, 30, 0, 1);
        m.hops = 2;
        let h = a.on_client_side(FROM_CLIENT, &m.encode().unwrap());
        let fwd = Message::decode(&h.sends[0].payload).unwrap();
        assert_eq!(fwd.giaddr, Ipv4Addr::new(10, 30, 0, 1));
        assert_eq!(fwd.hops, 3);
        assert_eq!(fwd.option(opt::RELAY_AGENT_INFO), None);
    }

    #[test]
    fn request_drop_rules() {
        let a = agent();
        let mut hops = discover();
        hops.hops = 5;
        assert!(
            a.on_client_side(FROM_CLIENT, &hops.encode().unwrap())
                .sends
                .is_empty()
        );
        let mut at_limit = discover();
        at_limit.hops = 4;
        assert_eq!(
            a.on_client_side(FROM_CLIENT, &at_limit.encode().unwrap())
                .sends
                .len(),
            2
        );
        let mut own = discover();
        own.giaddr = RTA;
        assert!(
            a.on_client_side(FROM_CLIENT, &own.encode().unwrap())
                .sends
                .is_empty()
        );
        let mut spoofed82 = discover();
        spoofed82
            .options
            .push(DhcpOption::new(opt::RELAY_AGENT_INFO, vec![1, 1, b'x']));
        let h = a.on_client_side(FROM_CLIENT, &spoofed82.encode().unwrap());
        assert!(h.sends.is_empty());
        assert!(h.log[0].contains("opt82-from-client"));
        let mut reply = discover();
        reply.op = OP_REPLY;
        assert!(
            a.on_client_side(FROM_CLIENT, &reply.encode().unwrap())
                .sends
                .is_empty()
        );
        assert!(a.on_client_side(FROM_CLIENT, &[1, 2, 3]).sends.is_empty());
    }

    fn reply_with(opt82: Option<Vec<u8>>, giaddr: Ipv4Addr) -> Vec<u8> {
        let mut m = Message::new(OP_REPLY, 0xabcd, [0x52, 0x54, 0, 0, 2, 1]);
        m.giaddr = giaddr;
        m.flags = codec::FLAG_BROADCAST;
        m.options.push(DhcpOption::new(opt::MESSAGE_TYPE, [2]));
        m.options
            .push(DhcpOption::new(opt::SERVER_ID, BOOT.octets()));
        if let Some(d) = opt82 {
            m.options.push(DhcpOption::new(opt::RELAY_AGENT_INFO, d));
        }
        m.encode().unwrap()
    }

    #[test]
    fn reply_checked_stripped_and_broadcast() {
        let a = agent();
        let src = SocketAddrV4::new(BOOT, 67);
        let without = reply_with(None, RTB);
        let h = a.on_server_side(src, &reply_with(Some(a.opt82().to_vec()), RTB));
        assert!(h.log[0].contains("opt82=ok"), "{:?}", h.log);
        assert_eq!(h.sends.len(), 1);
        assert_eq!(h.sends[0].via, Via::ClientSide);
        assert_eq!(h.sends[0].dest, SocketAddrV4::new(Ipv4Addr::BROADCAST, 68));
        assert_eq!(h.sends[0].payload, without);

        let h = a.on_server_side(src, &without);
        assert!(h.log[0].contains("opt82=missing"));
        assert_eq!(h.sends[0].payload, without);

        let h = a.on_server_side(src, &reply_with(Some(vec![1, 1, b'z']), RTB));
        assert!(h.log[0].contains("opt82=changed"));
        assert_eq!(h.sends[0].payload, without);
    }

    #[test]
    fn reply_for_other_interface_or_request_dropped() {
        let a = agent();
        let src = SocketAddrV4::new(BOOT, 67);
        let h = a.on_server_side(src, &reply_with(None, Ipv4Addr::new(10, 20, 3, 1)));
        assert!(h.sends.is_empty());
        assert!(h.log[0].contains("giaddr-no-interface"));
        let h = a.on_server_side(src, &discover().encode().unwrap());
        assert!(h.sends.is_empty());
        assert!(h.log.is_empty());
    }

    #[test]
    fn overlong_circuit_id_rejected() {
        let mut cfg = agent().cfg;
        cfg.client_iface = "x".repeat(256);
        assert!(Agent::new(cfg).is_err());
    }
}
