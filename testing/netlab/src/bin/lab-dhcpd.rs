//! lab-dhcpd: site DHCP server emulator for the boot smoke (test only).
//!
//! Stands in for an unmodified site DHCP server (REQ-BOOT-011): leases
//! addresses from in-memory pools and sends options 1, 3, 51, 53 and 54
//! only, plus an echo of option 82. One socket per `--listen` interface, on
//! 0.0.0.0:67 bound to that device. Every DISCOVER's option 60 is logged on
//! stdout as `opt60=...`.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};

use usgp_netlab::args::Args;
use usgp_netlab::dhcpd::{Pool, SERVER_PORT, Server, ServerConfig};
use usgp_netlab::{EXIT_USAGE, net};

const USAGE: &str = "usage: lab-dhcpd --listen IFACE=ADDR [--listen ...] \
--pool NET/PREFIX,FIRST-LAST,ROUTER [--pool ...] [--server-id ADDR] [--lease-secs N]";

struct Listen {
    iface: String,
    addr: Ipv4Addr,
}

fn parse_listen(spec: &str) -> Option<Listen> {
    let (iface, addr) = spec.split_once('=')?;
    if iface.is_empty() || iface.len() > 15 {
        return None;
    }
    Some(Listen {
        iface: iface.to_owned(),
        addr: addr.parse().ok()?,
    })
}

fn config(args: &Args) -> Result<(Vec<Listen>, ServerConfig), String> {
    let listens = args
        .all("listen")
        .iter()
        .map(|s| parse_listen(s).ok_or_else(|| format!("bad --listen {s} (want IFACE=ADDR)")))
        .collect::<Result<Vec<_>, _>>()?;
    let Some(first) = listens.first() else {
        return Err("at least one --listen is required".to_owned());
    };
    let pools: Vec<Pool> = args.parse_all("pool").map_err(|e| e.to_string())?;
    if pools.is_empty() {
        return Err("at least one --pool is required".to_owned());
    }
    let server_id = args
        .opt("server-id")
        .map_err(|e| e.to_string())?
        .unwrap_or(first.addr);
    let lease_secs = args
        .opt("lease-secs")
        .map_err(|e| e.to_string())?
        .unwrap_or(3600);
    Ok((
        listens,
        ServerConfig {
            server_id,
            lease_secs,
            pools,
        },
    ))
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let parsed = Args::parse(
        std::env::args().skip(1),
        &["listen", "pool", "server-id", "lease-secs"],
        &[],
    )
    .map_err(|e| e.to_string())
    .and_then(|a| config(&a));
    let (listens, cfg) = match parsed {
        Ok(v) => v,
        Err(e) => {
            eprintln!("lab-dhcpd: {e}\n{USAGE}");
            return ExitCode::from(u8::try_from(EXIT_USAGE).unwrap_or(2));
        }
    };
    net::require_supported("lab-dhcpd");
    let server = Arc::new(Mutex::new(Server::new(cfg)));
    let mut tasks = tokio::task::JoinSet::new();
    for listen in listens {
        let opts = net::UdpOpts {
            bind: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, SERVER_PORT),
            device: Some(&listen.iface),
            broadcast: true,
            reuse_addr: true,
        };
        let sock = match net::udp(&opts) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("lab-dhcpd: cannot open {}:67: {e}", listen.iface);
                return ExitCode::FAILURE;
            }
        };
        println!(
            "lab-dhcpd event=ready iface={} addr={}",
            listen.iface, listen.addr
        );
        let server = Arc::clone(&server);
        tasks.spawn(async move {
            let mut buf = vec![0u8; 2048];
            loop {
                let (n, src) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("lab-dhcpd: recv on {}: {e}", listen.iface);
                        continue;
                    }
                };
                let (Some(src), Some(bytes)) = (net::v4(src), buf.get(..n)) else {
                    continue;
                };
                let handled = server
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .handle(listen.addr, src, bytes);
                for line in &handled.log {
                    println!("lab-dhcpd iface={} {line}", listen.iface);
                }
                if let Some(reply) = handled.reply
                    && let Err(e) = sock.send_to(&reply.payload, reply.dest).await
                {
                    println!(
                        "lab-dhcpd iface={} event=send-error dest={} error=\"{e}\"",
                        listen.iface, reply.dest
                    );
                }
            }
        });
    }
    while tasks.join_next().await.is_some() {}
    ExitCode::FAILURE
}
