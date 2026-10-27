//! lab-probe: crafted DHCP and TFTP traffic with assertions on the replies
//! (boot smoke scenario S4; test only).
//!
//! Every subcommand prints one `lab-probe check=... result=PASS|FAIL` line
//! per check and exits 0 only if all passed (1 on any failure, 2 on a usage
//! error, 77 on a non-Linux host). Every DHCP reply the probe captures, in
//! any subcommand, must be a BOOTREPLY with `yiaddr` = 0 and no lease
//! options (REQ-BOOT-010).
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Testing and Evaluation), SC-5, SI-10
//! - SPEC: specs/boot-network.md#REQ-BOOT-004, 005, 006, 010, 040, 041,
//!   042, 044
//! - RFC 1350 §4, §5 - TFTP transfer and TIDs; RFC 2347 - OACK

use std::collections::HashSet;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout_at};
use usgp_netlab::args::{ArgError, Args};
use usgp_netlab::codec::{self, Message};
use usgp_netlab::probe::{self, Expect as VectorExpect, Ident, Mode, OfferExpect, Rng};
use usgp_netlab::tftp::{self, ServerPacket};
use usgp_netlab::{EXIT_USAGE, net};

const USAGE: &str = "\
usage: lab-probe <command> [options]

DHCP commands (common: --iface IFACE --server ADDR [--mode relayed|direct]
  [--local ADDR] [--port 67|4011] [--wait-ms N] [--seed N]):
  dhcp-offer      one valid PXE request; expects a ProxyDHCP reply
                  [--expect-file NAME] [--expect-none] [--mac MAC]
  dhcp-vectors    every negative vector gets no reply, every vector whose
                  repeated options join into valid values (RFC 3396) gets
                  a normal reply, then a valid request is answered
                  [--only NAME] [--list] [--no-valid-after]
  dhcp-random     random packets get no reply, then a valid request is
                  answered [--count N] [--per-sec N] [--no-valid-after]
  dhcp-rate       DISCOVERs from one chaddr at --per-sec N for --secs N get
                  between --min-replies (default 1) and --max-replies replies

TFTP commands (common: --server ADDR [--iface IFACE] [--local ADDR]
  [--timeout-ms N] [--retries N]):
  tftp-rrq        --file NAME --expect ok|none|error:CODE [--blksize N]
                  [--tsize] [--compare PATH] [--max-bytes N]
  tftp-wrq        --file NAME; expects ERROR 2 [--expect ...]
  tftp-traversal  hostile names each get ERROR 1 [--code N]
  tftp-stall      --file NAME --hold-secs N; reads DATA 1 and never ACKs

Modes: relayed = probe acts as a relay agent (giaddr = --local, binds
--local:67, unicast to --server:67); direct = probe acts as a client
(binds 0.0.0.0:68 on --iface, broadcasts to 255.255.255.255:67).
Port 4011 sends a boot-server REQUEST from --local (ephemeral port).";

const DHCP_KEYS: [&str; 18] = [
    "iface",
    "server",
    "mode",
    "local",
    "port",
    "wait-ms",
    "seed",
    "expect-file",
    "mac",
    "only",
    "count",
    "per-sec",
    "secs",
    "min-replies",
    "max-replies",
    "timeout-ms",
    "retries",
    "file",
];
const OTHER_KEYS: [&str; 6] = [
    "expect",
    "blksize",
    "compare",
    "max-bytes",
    "code",
    "hold-secs",
];
const FLAGS: [&str; 4] = ["expect-none", "list", "no-valid-after", "tsize"];

/// Accumulates check results.
#[derive(Default)]
struct Report {
    pass: usize,
    fail: usize,
}

impl Report {
    fn record(&mut self, check: &str, ok: bool, detail: &str) {
        if ok {
            self.pass += 1;
        } else {
            self.fail += 1;
        }
        let result = if ok { "PASS" } else { "FAIL" };
        println!("lab-probe check={check} result={result} {detail}");
    }

    fn exit(&self) -> ExitCode {
        println!("lab-probe summary pass={} fail={}", self.pass, self.fail);
        if self.fail == 0 && self.pass > 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        }
    }
}

enum Failure {
    Usage(String),
    Io(String),
}

impl From<ArgError> for Failure {
    fn from(e: ArgError) -> Self {
        Self::Usage(e.0)
    }
}

impl From<std::io::Error> for Failure {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let mut argv = std::env::args().skip(1);
    let Some(cmd) = argv.next() else {
        eprintln!("{USAGE}");
        return usage_exit();
    };
    let keys: Vec<&str> = DHCP_KEYS.iter().chain(OTHER_KEYS.iter()).copied().collect();
    let args = match Args::parse(argv, &keys, &FLAGS) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("lab-probe: {e}\n{USAGE}");
            return usage_exit();
        }
    };
    if cmd == "dhcp-vectors" && args.flag("list") {
        for v in probe::vectors(Mode::Direct, 1, Ipv4Addr::UNSPECIFIED) {
            println!(
                "{} observable={} expect={}",
                v.name,
                v.observable,
                expect_name(v.expect)
            );
        }
        return ExitCode::SUCCESS;
    }
    let known = [
        "dhcp-offer",
        "dhcp-vectors",
        "dhcp-random",
        "dhcp-rate",
        "tftp-rrq",
        "tftp-wrq",
        "tftp-traversal",
        "tftp-stall",
    ];
    if !known.contains(&cmd.as_str()) {
        eprintln!("lab-probe: unknown command {cmd}\n{USAGE}");
        return usage_exit();
    }
    net::require_supported("lab-probe");
    let mut report = Report::default();
    let result = match cmd.as_str() {
        "dhcp-offer" => dhcp_offer(&args, &mut report).await,
        "dhcp-vectors" => dhcp_vectors(&args, &mut report).await,
        "dhcp-random" => dhcp_random(&args, &mut report).await,
        "dhcp-rate" => dhcp_rate(&args, &mut report).await,
        "tftp-rrq" => tftp_rrq(&args, &mut report).await,
        "tftp-wrq" => tftp_wrq(&args, &mut report).await,
        "tftp-traversal" => tftp_traversal(&args, &mut report).await,
        _ => tftp_stall(&args, &mut report).await,
    };
    match result {
        Ok(()) => report.exit(),
        Err(Failure::Usage(e)) => {
            eprintln!("lab-probe: {e}\n{USAGE}");
            usage_exit()
        }
        Err(Failure::Io(e)) => {
            println!("lab-probe check={cmd} result=FAIL error=\"{e}\"");
            ExitCode::FAILURE
        }
    }
}

fn usage_exit() -> ExitCode {
    ExitCode::from(u8::try_from(EXIT_USAGE).unwrap_or(2))
}

// ---------------------------------------------------------------- DHCP --

struct Dhcp {
    sock: UdpSocket,
    mode: Mode,
    dest: SocketAddrV4,
    server: Ipv4Addr,
    local: Option<Ipv4Addr>,
    alt_port: bool,
    wait: Duration,
    seed: u32,
    /// Lease-free violations seen in any captured reply.
    lease_violations: Vec<String>,
}

impl Dhcp {
    async fn open(args: &Args) -> Result<Self, Failure> {
        let iface: String = args.req("iface")?;
        let server: Ipv4Addr = args.req("server")?;
        let local: Option<Ipv4Addr> = args.opt("local")?;
        let port: u16 = args.opt("port")?.unwrap_or(67);
        let wait = Duration::from_millis(args.opt("wait-ms")?.unwrap_or(500));
        let seed: u32 = args.opt("seed")?.unwrap_or(1);
        let mode = match args.opt::<String>("mode")?.as_deref() {
            None | Some("relayed") => Mode::Relayed(
                local.ok_or_else(|| Failure::Usage("relayed mode needs --local".into()))?,
            ),
            Some("direct") => Mode::Direct,
            Some(other) => return Err(Failure::Usage(format!("bad --mode {other}"))),
        };
        let (bind, dest, alt_port) = match (port, mode) {
            (4011, _) => {
                let l = local.ok_or_else(|| Failure::Usage("--port 4011 needs --local".into()))?;
                (
                    SocketAddrV4::new(l, 0),
                    SocketAddrV4::new(server, 4011),
                    true,
                )
            }
            (67, Mode::Relayed(l)) => (
                SocketAddrV4::new(l, 67),
                SocketAddrV4::new(server, 67),
                false,
            ),
            (67, Mode::Direct) => (
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68),
                SocketAddrV4::new(Ipv4Addr::BROADCAST, 67),
                false,
            ),
            (p, _) => return Err(Failure::Usage(format!("bad --port {p} (67 or 4011)"))),
        };
        let sock = net::udp(&net::UdpOpts {
            bind,
            device: Some(&iface),
            broadcast: true,
            reuse_addr: true,
        })?;
        Ok(Self {
            sock,
            mode,
            dest,
            server,
            local,
            alt_port,
            wait,
            seed,
            lease_violations: Vec::new(),
        })
    }

    /// The valid request for this setup: DISCOVER on 67, boot-server
    /// REQUEST on 4011.
    fn valid_request(&self, id: Ident) -> Message {
        if self.alt_port {
            let mut m = probe::pxe_boot_request(
                Mode::Direct,
                id,
                self.local.unwrap_or(Ipv4Addr::UNSPECIFIED),
            );
            m.flags = 0;
            m
        } else {
            probe::pxe_discover(self.mode, id)
        }
    }

    async fn send(&self, bytes: &[u8]) -> Result<(), Failure> {
        self.sock.send_to(bytes, self.dest).await?;
        Ok(())
    }

    fn note_reply(&mut self, m: &Message) {
        if let Err(e) = probe::check_lease_free(m) {
            self.lease_violations
                .push(format!("xid={:#010x} {e}", m.xid));
        }
    }

    /// Receives until `deadline`; returns decodable BOOTREPLYs.
    async fn collect_until(&mut self, deadline: Instant) -> Vec<Message> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 2048];
        while let Ok(Ok((n, _))) = timeout_at(deadline, self.sock.recv_from(&mut buf)).await {
            if let Some(m) = buf.get(..n).and_then(|b| Message::decode(b).ok())
                && m.op == codec::OP_REPLY
            {
                self.note_reply(&m);
                out.push(m);
            }
        }
        out
    }

    /// Receives whatever is queued now, without waiting.
    fn drain(&mut self) -> Vec<Message> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 2048];
        while let Ok((n, _)) = self.sock.try_recv_from(&mut buf) {
            if let Some(m) = buf.get(..n).and_then(|b| Message::decode(b).ok())
                && m.op == codec::OP_REPLY
            {
                self.note_reply(&m);
                out.push(m);
            }
        }
        out
    }

    /// Sends one valid request and checks the reply.
    async fn valid_probe(
        &mut self,
        check: &str,
        id: Ident,
        expect: &OfferExpect,
        report: &mut Report,
    ) -> Result<(), Failure> {
        let req = self.valid_request(id);
        let bytes = req.encode().map_err(|e| Failure::Io(e.to_string()))?;
        self.send(&bytes).await?;
        let replies = self
            .collect_until(Instant::now() + self.wait.max(Duration::from_secs(2)))
            .await;
        let mine: Vec<&Message> = replies.iter().filter(|r| r.xid == req.xid).collect();
        let Some(first) = mine.first() else {
            report.record(
                check,
                false,
                &format!("xid={:#010x} reason=no-reply", req.xid),
            );
            return Ok(());
        };
        let mut ok = true;
        let mut detail = format!(
            "xid={:#010x} replies={} siaddr={} file=\"{}\"",
            req.xid,
            mine.len(),
            first.siaddr,
            codec::escape_bytes(first.file_name())
        );
        for r in &mine {
            if let Err(e) = probe::check_proxy_reply(&req, r, expect) {
                ok = false;
                detail.push_str(&format!(" reason=\"{e}\""));
            }
        }
        report.record(check, ok, &detail);
        Ok(())
    }

    fn finish(&self, report: &mut Report) {
        let ok = self.lease_violations.is_empty();
        let detail = if ok {
            "every captured reply had yiaddr=0 and no lease options".to_owned()
        } else {
            format!("violations=\"{}\"", self.lease_violations.join("; "))
        };
        report.record("lease-free-replies", ok, &detail);
    }
}

fn expectations(d: &Dhcp, args: &Args) -> Result<OfferExpect, Failure> {
    Ok(OfferExpect {
        server: Some(d.server),
        file: args.opt("expect-file")?,
    })
}

async fn dhcp_offer(args: &Args, report: &mut Report) -> Result<(), Failure> {
    let mut d = Dhcp::open(args).await?;
    let mut id = Ident::nth(d.seed, 0xff00);
    if let Some(mac) = args.opt::<String>("mac")? {
        id.mac =
            codec::parse_mac(&mac).ok_or_else(|| Failure::Usage(format!("bad --mac {mac}")))?;
    }
    if args.flag("expect-none") {
        let req = d.valid_request(id);
        d.send(&req.encode().map_err(|e| Failure::Io(e.to_string()))?)
            .await?;
        let replies = d
            .collect_until(Instant::now() + d.wait.max(Duration::from_secs(2)))
            .await;
        let n = replies.iter().filter(|r| r.xid == req.xid).count();
        report.record(
            "dhcp-no-reply",
            n == 0,
            &format!("xid={:#010x} replies={n}", req.xid),
        );
    } else {
        let expect = expectations(&d, args)?;
        d.valid_probe("dhcp-offer", id, &expect, report).await?;
    }
    d.finish(report);
    Ok(())
}

fn expect_name(e: VectorExpect) -> &'static str {
    match e {
        VectorExpect::NoReply => "no-reply",
        VectorExpect::ProxyReply => "proxy-reply",
    }
}

/// Checks the replies to a vector that must be answered: at least one,
/// and each one a lease-free ProxyDHCP reply (re-parsed by this crate's
/// codec) carrying only the allowed options. Returns the failure reasons.
fn check_answered(v: &probe::Vector, mine: &[&Message], expect: &OfferExpect) -> Vec<String> {
    let Ok(req) = Message::decode(&v.bytes) else {
        return vec!["vector does not decode".to_owned()];
    };
    if mine.is_empty() {
        return vec!["no-reply".to_owned()];
    }
    let mut reasons = Vec::new();
    for r in mine {
        if let Err(e) = probe::check_proxy_reply(&req, r, expect) {
            reasons.push(e);
        }
        if let Err(e) = probe::check_reply_options(&req, r) {
            reasons.push(e);
        }
    }
    reasons
}

async fn dhcp_vectors(args: &Args, report: &mut Report) -> Result<(), Failure> {
    let mut d = Dhcp::open(args).await?;
    let only: Option<String> = args.opt("only")?;
    let expect = expectations(&d, args)?;
    let vectors = probe::vectors(d.mode, d.seed, d.server);
    let mut sent = 0;
    for v in vectors
        .iter()
        .filter(|v| only.as_deref().is_none_or(|o| o == v.name))
    {
        d.send(&v.bytes).await?;
        sent += 1;
        let wait = match v.expect {
            VectorExpect::NoReply => d.wait,
            VectorExpect::ProxyReply => d.wait.max(Duration::from_secs(2)),
        };
        let replies = d.collect_until(Instant::now() + wait).await;
        let mine: Vec<&Message> = replies.iter().filter(|r| r.xid == v.xid).collect();
        let n = mine.len();
        let reasons = match v.expect {
            VectorExpect::NoReply if n == 0 => Vec::new(),
            VectorExpect::NoReply => vec!["unexpected-reply".to_owned()],
            VectorExpect::ProxyReply => check_answered(v, &mine, &expect),
        };
        let mut detail = format!(
            "xid={:#010x} len={} observable={} expect={} replies={n}",
            v.xid,
            v.bytes.len(),
            v.observable,
            expect_name(v.expect)
        );
        for e in &reasons {
            detail.push_str(&format!(" reason=\"{e}\""));
        }
        report.record(&format!("vector:{}", v.name), reasons.is_empty(), &detail);
    }
    if sent == 0 {
        return Err(Failure::Usage("no vector matched --only".into()));
    }
    if !args.flag("no-valid-after") {
        d.valid_probe(
            "valid-after-vectors",
            Ident::nth(d.seed, 0xfe00),
            &expect,
            report,
        )
        .await?;
    }
    d.finish(report);
    Ok(())
}

async fn dhcp_random(args: &Args, report: &mut Report) -> Result<(), Failure> {
    let mut d = Dhcp::open(args).await?;
    let count: usize = args.opt("count")?.unwrap_or(10_000);
    let per_sec: usize = args.opt("per-sec")?.unwrap_or(2000).max(100);
    let mut rng = Rng::new(u64::from(d.seed));
    let batch = per_sec / 100;
    let mut replies = 0usize;
    let mut sent = 0usize;
    let mut tick = tokio::time::interval(Duration::from_millis(10));
    while sent < count {
        tick.tick().await;
        for _ in 0..batch.min(count - sent) {
            let pkt = probe::random_packet(&mut rng);
            d.send(&pkt).await?;
            sent += 1;
        }
        replies += d.drain().len();
    }
    replies += d.collect_until(Instant::now() + d.wait).await.len();
    report.record(
        "random-packets",
        replies == 0,
        &format!("seed={} sent={sent} replies={replies}", d.seed),
    );
    if !args.flag("no-valid-after") {
        let expect = expectations(&d, args)?;
        d.valid_probe(
            "valid-after-random",
            Ident::nth(d.seed, 0xfd00),
            &expect,
            report,
        )
        .await?;
    }
    d.finish(report);
    Ok(())
}

async fn dhcp_rate(args: &Args, report: &mut Report) -> Result<(), Failure> {
    let mut d = Dhcp::open(args).await?;
    let per_sec: u64 = args.opt("per-sec")?.unwrap_or(50).clamp(1, 1000);
    let secs: u64 = args.opt("secs")?.unwrap_or(10);
    let max: usize = args.req("max-replies")?;
    let min: usize = args.opt("min-replies")?.unwrap_or(1);
    let base = Ident::nth(d.seed, 0xfc00);
    let mut xids = HashSet::new();
    let mut matched = 0usize;
    let mut tick = tokio::time::interval(Duration::from_millis(1000 / per_sec));
    for i in 0..per_sec.saturating_mul(secs) {
        tick.tick().await;
        let id = Ident {
            xid: base.xid.wrapping_add(u32::try_from(i).unwrap_or(u32::MAX)),
            mac: base.mac,
        };
        xids.insert(id.xid);
        let bytes = d
            .valid_request(id)
            .encode()
            .map_err(|e| Failure::Io(e.to_string()))?;
        d.send(&bytes).await?;
        matched += d.drain().iter().filter(|r| xids.contains(&r.xid)).count();
    }
    matched += d
        .collect_until(Instant::now() + d.wait)
        .await
        .iter()
        .filter(|r| xids.contains(&r.xid))
        .count();
    report.record(
        "dhcp-rate-limit",
        (min..=max).contains(&matched),
        &format!(
            "chaddr={} sent={} replies={matched} allowed={min}..={max}",
            codec::fmt_mac(&base.mac),
            xids.len()
        ),
    );
    d.finish(report);
    Ok(())
}

// ---------------------------------------------------------------- TFTP --

struct Tftp {
    sock: UdpSocket,
    server: Ipv4Addr,
    timeout: Duration,
    retries: u32,
}

impl Tftp {
    fn open(args: &Args) -> Result<Self, Failure> {
        let server: Ipv4Addr = args.req("server")?;
        let iface: Option<String> = args.opt("iface")?;
        let local: Ipv4Addr = args.opt("local")?.unwrap_or(Ipv4Addr::UNSPECIFIED);
        let sock = net::udp(&net::UdpOpts {
            bind: SocketAddrV4::new(local, 0),
            device: iface.as_deref(),
            broadcast: true,
            reuse_addr: false,
        })?;
        Ok(Self {
            sock,
            server,
            timeout: Duration::from_millis(args.opt("timeout-ms")?.unwrap_or(3000)),
            retries: args.opt("retries")?.unwrap_or(5),
        })
    }

    /// Next packet from anyone, with its source, or `None` on timeout.
    async fn recv(&self, buf: &mut [u8]) -> Option<(SocketAddrV4, Vec<u8>)> {
        let deadline = Instant::now() + self.timeout;
        loop {
            match timeout_at(deadline, self.sock.recv_from(buf)).await {
                Ok(Ok((n, src))) => {
                    if let (Some(src), Some(b)) = (net::v4(src), buf.get(..n)) {
                        return Some((src, b.to_vec()));
                    }
                }
                Ok(Err(_)) => continue,
                Err(_) => return None,
            }
        }
    }

    /// Sends a request and returns the first packet from the server host
    /// (from any host when `any_source`, so a wrong responder still counts).
    async fn first_reply(
        &self,
        req: &[u8],
        resend: bool,
        any_source: bool,
    ) -> Result<Option<(SocketAddrV4, Vec<u8>)>, Failure> {
        let dest = SocketAddrV4::new(self.server, 69);
        let mut buf = vec![0u8; tftp::MAX_DATAGRAM + 1];
        let tries = if resend { self.retries.max(1) } else { 1 };
        for _ in 0..tries {
            self.sock.send_to(req, dest).await?;
            while let Some((src, pkt)) = self.recv(&mut buf).await {
                if any_source || src.ip() == &self.server {
                    return Ok(Some((src, pkt)));
                }
            }
        }
        Ok(None)
    }
}

enum Expect {
    Ok,
    None,
    Error(u16),
}

fn parse_expect(s: &str) -> Option<Expect> {
    match s {
        "ok" => Some(Expect::Ok),
        "none" => Some(Expect::None),
        _ => s
            .strip_prefix("error:")
            .and_then(|c| c.parse().ok())
            .map(Expect::Error),
    }
}

/// Checks the first packet of a request that should be refused.
fn first_is_error(first: Option<&(SocketAddrV4, Vec<u8>)>, code: u16) -> (bool, String) {
    match first.map(|(src, p)| (src, tftp::decode(p))) {
        None => (false, "reason=no-reply".to_owned()),
        Some((src, Ok(ServerPacket::Error { code: got, message }))) => (
            got == code,
            format!(
                "from={src} error={got} message=\"{}\"",
                codec::escape_bytes(&message)
            ),
        ),
        Some((src, Ok(other))) => (false, format!("from={src} reason=\"unexpected {other:?}\"")),
        Some((src, Err(e))) => (false, format!("from={src} reason=\"malformed: {e}\"")),
    }
}

async fn tftp_rrq(args: &Args, report: &mut Report) -> Result<(), Failure> {
    let t = Tftp::open(args)?;
    let file: String = args.req("file")?;
    let expect_s: String = args.req("expect")?;
    let expect = parse_expect(&expect_s)
        .ok_or_else(|| Failure::Usage(format!("bad --expect {expect_s}")))?;
    let blksize: Option<u16> = args.opt("blksize")?;
    let tsize = args.flag("tsize");
    let mut opts: Vec<(&str, String)> = Vec::new();
    if let Some(b) = blksize {
        opts.push(("blksize", b.to_string()));
    }
    if tsize {
        opts.push(("tsize", "0".to_owned()));
    }
    let opt_refs: Vec<(&str, &str)> = opts.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let req = tftp::request(tftp::OP_RRQ, file.as_bytes(), "octet", &opt_refs);
    let check = format!("tftp-rrq:{expect_s}");
    match expect {
        Expect::None => {
            let first = t.first_reply(&req, false, true).await?;
            let detail = match &first {
                None => format!(
                    "dest={} file=\"{}\" replies=0",
                    t.server,
                    codec::escape_bytes(file.as_bytes())
                ),
                Some((src, _)) => format!("dest={} reason=reply-from-{src}", t.server),
            };
            report.record(&check, first.is_none(), &detail);
        }
        Expect::Error(code) => {
            let first = t.first_reply(&req, true, false).await?;
            let (ok, detail) = first_is_error(first.as_ref(), code);
            report.record(&check, ok, &detail);
        }
        Expect::Ok => {
            let max_bytes: usize = args.opt("max-bytes")?.unwrap_or(64 * 1024 * 1024);
            let first = t.first_reply(&req, true, false).await?;
            match download(&t, first, blksize, tsize, max_bytes).await? {
                Ok((data, detail)) => {
                    let mut ok = true;
                    let mut detail = format!("{detail} bytes={}", data.len());
                    if let Some(path) = args.opt::<PathBuf>("compare")? {
                        let want = std::fs::read(&path)?;
                        let same = want == data;
                        ok &= same;
                        detail.push_str(&format!(
                            " compare={}",
                            if same { "identical" } else { "DIFFERENT" }
                        ));
                    }
                    report.record(&check, ok, &detail);
                }
                Err(reason) => report.record(&check, false, &format!("reason=\"{reason}\"")),
            }
        }
    }
    Ok(())
}

/// Lock-step download from the server's TID (RFC 1350 §4, §5; RFC 2347).
/// Returns the file and a detail string, or the reason it failed.
async fn download(
    t: &Tftp,
    first: Option<(SocketAddrV4, Vec<u8>)>,
    asked_blksize: Option<u16>,
    asked_tsize: bool,
    max_bytes: usize,
) -> Result<Result<(Vec<u8>, String), String>, Failure> {
    let Some((tid, first)) = first else {
        return Ok(Err("no reply".into()));
    };
    let mut blksize = 512usize;
    let mut announced: Option<usize> = None;
    let mut pending = Some(first);
    let mut data = Vec::new();
    let mut expected: u16 = 1;
    let mut last_ack: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; tftp::MAX_DATAGRAM + 1];
    let mut retries = 0;
    let mut first_packet = true;
    loop {
        let pkt = match pending.take() {
            Some(p) => p,
            None => match t.recv(&mut buf).await {
                Some((src, p)) if src == tid => p,
                Some((src, _)) => {
                    // RFC 1350 §4: a packet from another TID gets ERROR 5.
                    let _ = t
                        .sock
                        .send_to(&tftp::error(5, "unknown transfer ID"), src)
                        .await;
                    continue;
                }
                None => {
                    retries += 1;
                    if retries > t.retries || last_ack.is_empty() {
                        return Ok(Err(format!("timeout waiting for block {expected}")));
                    }
                    t.sock.send_to(&last_ack, tid).await?;
                    continue;
                }
            },
        };
        let was_first = first_packet;
        first_packet = false;
        match tftp::decode(&pkt) {
            Ok(ServerPacket::Oack(pairs)) if was_first => {
                for (name, value) in &pairs {
                    match name.as_str() {
                        "blksize" => {
                            let v: usize = value
                                .parse()
                                .map_err(|_| Failure::Io(format!("bad blksize {value}")))?;
                            if asked_blksize.is_none_or(|a| v > usize::from(a))
                                || !(8..=65464).contains(&v)
                            {
                                return Ok(Err(format!("OACK blksize {v} not allowed")));
                            }
                            blksize = v;
                        }
                        "tsize" if asked_tsize => announced = value.parse().ok(),
                        other => {
                            return Ok(Err(format!(
                                "OACK has option {other} that was not requested"
                            )));
                        }
                    }
                }
                last_ack = tftp::ack(0);
                t.sock.send_to(&last_ack, tid).await?;
            }
            Ok(ServerPacket::Data { block, data: chunk }) => {
                if block == expected {
                    if chunk.len() > blksize {
                        return Ok(Err(format!(
                            "block {block} has {} > blksize {blksize}",
                            chunk.len()
                        )));
                    }
                    if data.len() + chunk.len() > max_bytes {
                        return Ok(Err("file larger than --max-bytes".into()));
                    }
                    data.extend_from_slice(&chunk);
                    last_ack = tftp::ack(block);
                    t.sock.send_to(&last_ack, tid).await?;
                    retries = 0;
                    if chunk.len() < blksize {
                        let mut detail = format!("tid={tid} blksize={blksize} blocks={block}");
                        if let Some(n) = announced {
                            if n != data.len() {
                                return Ok(Err(format!("tsize {n} != received {}", data.len())));
                            }
                            detail.push_str(&format!(" tsize={n}"));
                        }
                        return Ok(Ok((data, detail)));
                    }
                    let Some(next) = expected.checked_add(1) else {
                        return Ok(Err("block number would wrap".into()));
                    };
                    expected = next;
                } else if Some(block) == expected.checked_sub(1) {
                    // Duplicate of the last block: our ACK was lost.
                    t.sock.send_to(&last_ack, tid).await?;
                } else {
                    return Ok(Err(format!(
                        "block {block} out of order (expected {expected})"
                    )));
                }
            }
            Ok(ServerPacket::Error { code, message }) => {
                return Ok(Err(format!(
                    "ERROR {code} {}",
                    codec::escape_bytes(&message)
                )));
            }
            Ok(other) => return Ok(Err(format!("unexpected {other:?}"))),
            Err(e) => return Ok(Err(format!("malformed packet: {e}"))),
        }
    }
}

async fn tftp_wrq(args: &Args, report: &mut Report) -> Result<(), Failure> {
    let t = Tftp::open(args)?;
    let file: String = args.req("file")?;
    let code = match args.opt::<String>("expect")?.as_deref().map(parse_expect) {
        None => 2,
        Some(Some(Expect::Error(c))) => c,
        Some(_) => return Err(Failure::Usage("tftp-wrq takes --expect error:CODE".into())),
    };
    let req = tftp::request(tftp::OP_WRQ, file.as_bytes(), "octet", &[]);
    let first = t.first_reply(&req, true, false).await?;
    let (ok, detail) = first_is_error(first.as_ref(), code);
    report.record(&format!("tftp-wrq:error:{code}"), ok, &detail);
    Ok(())
}

/// Hostile names from plan section 8, REQ-BOOT-041. A name with an embedded
/// NUL cannot be sent as one RRQ field (NUL ends the field); the product's
/// in-process test covers it.
fn traversal_names() -> Vec<Vec<u8>> {
    vec![
        b"../x".to_vec(),
        b"/etc/passwd".to_vec(),
        b"a/../b".to_vec(),
        b"\\x".to_vec(),
        b"%2e%2e".to_vec(),
        b"..".to_vec(),
        b"../../../../etc/shadow".to_vec(),
        vec![b'a'; 128],
        "caf\u{e9}.efi".as_bytes().to_vec(),
    ]
}

async fn tftp_traversal(args: &Args, report: &mut Report) -> Result<(), Failure> {
    let t = Tftp::open(args)?;
    let code: u16 = args.opt("code")?.unwrap_or(1);
    for name in traversal_names() {
        let req = tftp::request(tftp::OP_RRQ, &name, "octet", &[]);
        let first = t.first_reply(&req, true, false).await?;
        let (ok, detail) = first_is_error(first.as_ref(), code);
        report.record(
            &format!("tftp-traversal:error:{code}"),
            ok,
            &format!("name=\"{}\" {detail}", codec::escape_bytes(&name)),
        );
    }
    Ok(())
}

async fn tftp_stall(args: &Args, report: &mut Report) -> Result<(), Failure> {
    let t = Tftp::open(args)?;
    let file: String = args.req("file")?;
    let hold: u64 = args.req("hold-secs")?;
    let req = tftp::request(tftp::OP_RRQ, file.as_bytes(), "octet", &[]);
    let first = t.first_reply(&req, true, false).await?;
    let ok = matches!(
        first.as_ref().map(|(_, p)| tftp::decode(p)),
        Some(Ok(ServerPacket::Data { block: 1, .. }))
    );
    if !ok {
        report.record("tftp-stall", false, "reason=\"first reply was not DATA 1\"");
        return Ok(());
    }
    // Never ACK. Count the server's retransmissions while holding.
    let deadline = Instant::now() + Duration::from_secs(hold);
    let mut buf = vec![0u8; tftp::MAX_DATAGRAM + 1];
    let mut resent = 0usize;
    while let Ok(Ok(_)) = timeout_at(deadline, t.sock.recv_from(&mut buf)).await {
        resent += 1;
    }
    report.record(
        "tftp-stall",
        true,
        &format!("held_secs={hold} packets_after_first={resent}"),
    );
    Ok(())
}
