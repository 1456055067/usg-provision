//! In-memory cross-subnet flow (scenario S2 shape, no sockets): a client on
//! segment B, the relay agent, and the site DHCP server on segment A.
//! Fixtures are built by this crate's own builders (CONTRIBUTING.md).

use std::net::{Ipv4Addr, SocketAddrV4};

use usgp_netlab::agent::{Agent, AgentConfig, DEFAULT_MAX_HOPS, DEFAULT_REMOTE_ID, Via};
use usgp_netlab::codec::{Message, MessageType, opt};
use usgp_netlab::dhcpd::{REPLY_OPTION_SET, Server, ServerConfig};
use usgp_netlab::probe::{self, Ident, Mode};

const RT_A: Ipv4Addr = Ipv4Addr::new(10, 20, 1, 1);
const RT_B: Ipv4Addr = Ipv4Addr::new(10, 20, 2, 1);
const SITE: Ipv4Addr = Ipv4Addr::new(10, 20, 1, 3);
const BOOT: Ipv4Addr = Ipv4Addr::new(10, 20, 1, 2);

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn lab() -> TestResult<(Agent, Server)> {
    let agent = Agent::new(AgentConfig {
        client_iface: "rtB".into(),
        client_addr: RT_B,
        servers: vec![SITE, BOOT],
        max_hops: DEFAULT_MAX_HOPS,
        remote_id: DEFAULT_REMOTE_ID.to_vec(),
        own_addrs: vec![RT_A],
    })?;
    let server = Server::new(ServerConfig {
        server_id: SITE,
        lease_secs: 600,
        pools: vec![
            "10.20.1.0/24,10.20.1.100-10.20.1.199,10.20.1.1".parse()?,
            "10.20.2.0/24,10.20.2.100-10.20.2.199,10.20.2.1".parse()?,
        ],
    });
    Ok((agent, server))
}

#[test]
fn relayed_discover_offer_request_ack() -> TestResult {
    let (agent, mut site) = lab()?;
    let client = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68);
    let discover = probe::pxe_discover(Mode::Direct, Ident::nth(9, 1));

    // Client -> agent: forwarded to both servers.
    let fwd = agent.on_client_side(client, &discover.encode().unwrap());
    assert_eq!(fwd.sends.len(), 2);
    let to_site = fwd.sends.iter().find(|s| s.dest.ip() == &SITE).unwrap();
    assert!(
        fwd.sends
            .iter()
            .any(|s| s.dest == SocketAddrV4::new(BOOT, 67))
    );

    // Site server: the pool is chosen by giaddr (segment B).
    let h = site.handle(SITE, SocketAddrV4::new(RT_A, 67), &to_site.payload);
    assert!(
        h.log
            .iter()
            .any(|l| l.contains("opt60=\"PXEClient:Arch:00007:UNDI:003000\""))
    );
    let offer = h.reply.unwrap();
    assert_eq!(offer.dest, SocketAddrV4::new(RT_B, 67));

    // Agent: option 82 came back unchanged; stripped; broadcast on B.
    let back = agent.on_server_side(SocketAddrV4::new(SITE, 67), &offer.payload);
    assert!(
        back.log.iter().any(|l| l.contains("opt82=ok")),
        "{:?}",
        back.log
    );
    let to_client = &back.sends[0];
    assert_eq!(to_client.via, Via::ClientSide);
    assert_eq!(to_client.dest, SocketAddrV4::new(Ipv4Addr::BROADCAST, 68));
    let offer_msg = Message::decode(&to_client.payload).unwrap();
    assert_eq!(offer_msg.message_type(), Some(MessageType::Offer));
    assert_eq!(offer_msg.yiaddr, Ipv4Addr::new(10, 20, 2, 100));
    assert_eq!(offer_msg.option(opt::RELAY_AGENT_INFO), None);
    for o in &offer_msg.options {
        assert!(REPLY_OPTION_SET.contains(&o.code) && o.code != opt::RELAY_AGENT_INFO);
    }

    // REQUEST naming the site server, relayed the same way, gets an ACK.
    let mut request = discover.clone();
    request.options[0].data = vec![3];
    request.options.push(usgp_netlab::codec::DhcpOption::new(
        opt::SERVER_ID,
        SITE.octets(),
    ));
    request.options.push(usgp_netlab::codec::DhcpOption::new(
        opt::REQUESTED_IP,
        offer_msg.yiaddr.octets(),
    ));
    let fwd = agent.on_client_side(client, &request.encode().unwrap());
    let to_site = fwd.sends.iter().find(|s| s.dest.ip() == &SITE).unwrap();
    let ack = site
        .handle(SITE, SocketAddrV4::new(RT_A, 67), &to_site.payload)
        .reply
        .unwrap();
    let back = agent.on_server_side(SocketAddrV4::new(SITE, 67), &ack.payload);
    let ack_msg = Message::decode(&back.sends[0].payload).unwrap();
    assert_eq!(ack_msg.message_type(), Some(MessageType::Ack));
    assert_eq!(ack_msg.yiaddr, offer_msg.yiaddr);
    Ok(())
}

#[test]
fn every_negative_vector_survives_both_tools() -> TestResult {
    // The lab tools must not panic on the probe's own hostile input.
    let (agent, mut site) = lab()?;
    let src = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68);
    for v in probe::vectors(Mode::Direct, 5, BOOT) {
        let _ = agent.on_client_side(src, &v.bytes);
        let _ = agent.on_server_side(src, &v.bytes);
        let _ = site.handle(SITE, src, &v.bytes);
    }
    let mut rng = probe::Rng::new(77);
    for _ in 0..5000 {
        let p = probe::random_packet(&mut rng);
        let _ = agent.on_client_side(src, &p);
        let _ = agent.on_server_side(src, &p);
        let _ = site.handle(SITE, src, &p);
    }
    Ok(())
}
