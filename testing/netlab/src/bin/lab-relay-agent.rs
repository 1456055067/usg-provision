//! lab-relay-agent: RFC 1542 DHCP relay agent for the boot smoke (test only).
//!
//! Receives client broadcasts on `--client-iface`, forwards them to every
//! `--server` (port 67) with giaddr = `--client-addr`, hops + 1 and option
//! 82 added. Replies addressed to giaddr arrive on `--server-iface`; the
//! agent logs `opt82=ok|missing|changed`, strips option 82 and broadcasts
//! the reply on the client interface to port 68.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::ExitCode;

use usgp_netlab::agent::{Agent, AgentConfig, DEFAULT_MAX_HOPS, DEFAULT_REMOTE_ID, Handled, Via};
use usgp_netlab::args::Args;
use usgp_netlab::dhcpd::SERVER_PORT;
use usgp_netlab::{EXIT_USAGE, net};

const USAGE: &str = "usage: lab-relay-agent --client-iface IFACE --client-addr ADDR \
--server-iface IFACE --server ADDR [--server ...] [--own-addr ADDR ...] [--max-hops N] [--remote-id TEXT]";

struct Setup {
    agent: Agent,
    client_iface: String,
    server_iface: String,
}

fn setup(args: &Args) -> Result<Setup, String> {
    let client_iface: String = args.req("client-iface").map_err(|e| e.to_string())?;
    let server_iface: String = args.req("server-iface").map_err(|e| e.to_string())?;
    let client_addr: Ipv4Addr = args.req("client-addr").map_err(|e| e.to_string())?;
    let servers: Vec<Ipv4Addr> = args.parse_all("server").map_err(|e| e.to_string())?;
    if servers.is_empty() {
        return Err("at least one --server is required".to_owned());
    }
    let mut own_addrs: Vec<Ipv4Addr> = args.parse_all("own-addr").map_err(|e| e.to_string())?;
    own_addrs.push(client_addr);
    let max_hops = args
        .opt("max-hops")
        .map_err(|e| e.to_string())?
        .unwrap_or(DEFAULT_MAX_HOPS);
    if max_hops > 16 {
        return Err("--max-hops must be at most 16 (RFC 1542 §4.1.1)".to_owned());
    }
    let remote_id = args
        .opt::<String>("remote-id")
        .map_err(|e| e.to_string())?
        .map_or_else(|| DEFAULT_REMOTE_ID.to_vec(), String::into_bytes);
    let agent = Agent::new(AgentConfig {
        client_iface: client_iface.clone(),
        client_addr,
        servers,
        max_hops,
        remote_id,
        own_addrs,
    })
    .map_err(|e| e.to_string())?;
    Ok(Setup {
        agent,
        client_iface,
        server_iface,
    })
}

async fn deliver(handled: Handled, client: &tokio::net::UdpSocket, server: &tokio::net::UdpSocket) {
    for line in &handled.log {
        println!("lab-relay-agent {line}");
    }
    for send in handled.sends {
        let sock = match send.via {
            Via::ClientSide => client,
            Via::ServerSide => server,
        };
        if let Err(e) = sock.send_to(&send.payload, send.dest).await {
            println!(
                "lab-relay-agent event=send-error dest={} error=\"{e}\"",
                send.dest
            );
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let keys = [
        "client-iface",
        "client-addr",
        "server-iface",
        "server",
        "own-addr",
        "max-hops",
        "remote-id",
    ];
    let parsed = Args::parse(std::env::args().skip(1), &keys, &[])
        .map_err(|e| e.to_string())
        .and_then(|a| setup(&a));
    let s = match parsed {
        Ok(s) => s,
        Err(e) => {
            eprintln!("lab-relay-agent: {e}\n{USAGE}");
            return ExitCode::from(u8::try_from(EXIT_USAGE).unwrap_or(2));
        }
    };
    net::require_supported("lab-relay-agent");
    let open = |dev: &str| {
        net::udp(&net::UdpOpts {
            bind: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, SERVER_PORT),
            device: Some(dev),
            broadcast: true,
            reuse_addr: true,
        })
    };
    let (client, server) = match (open(&s.client_iface), open(&s.server_iface)) {
        (Ok(c), Ok(v)) => (c, v),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("lab-relay-agent: cannot open port 67 sockets: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "lab-relay-agent event=ready client_iface={} server_iface={}",
        s.client_iface, s.server_iface
    );
    let mut cbuf = vec![0u8; 2048];
    let mut sbuf = vec![0u8; 2048];
    loop {
        let handled = tokio::select! {
            r = client.recv_from(&mut cbuf) => match r {
                Ok((n, src)) => match (net::v4(src), cbuf.get(..n)) {
                    (Some(src), Some(b)) => s.agent.on_client_side(src, b),
                    _ => continue,
                },
                Err(e) => { eprintln!("lab-relay-agent: recv: {e}"); continue; }
            },
            r = server.recv_from(&mut sbuf) => match r {
                Ok((n, src)) => match (net::v4(src), sbuf.get(..n)) {
                    (Some(src), Some(b)) => s.agent.on_server_side(src, b),
                    _ => continue,
                },
                Err(e) => { eprintln!("lab-relay-agent: recv: {e}"); continue; }
            },
        };
        deliver(handled, &client, &server).await;
    }
}
