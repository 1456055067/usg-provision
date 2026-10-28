//! A minimal blocking HTTP/1.1 client over `usgp-crypto`'s blocking TLS
//! stream (plan section 2 WU-12 `src/http.rs`; section 1.5: no tokio or
//! hyper in the agent).
//!
//! - Responses must carry exactly one `Content-Length`; chunked transfer
//!   coding is refused, as are 1xx responses and anything but HTTP/1.1.
//! - The response head is capped at [`MAX_HEAD_BYTES`] and
//!   [`MAX_HEADERS`] headers; the body at the caller's limit, checked
//!   against `Content-Length` before any body byte is read.
//! - Every wait is bounded: name resolution, connect, TLS handshake, and
//!   each read and write are limited by [`HttpLimits`], and the whole
//!   request by `request_timeout` (the engine's waits are checked only
//!   between calls, so these bounds must sit below its stall limit; WU-8
//!   POAM).
//! - Request heads (they carry the bearer token) and response bodies (the
//!   session-open response carries the token) are held in zeroizing
//!   buffers.
//! - A connection is reused for the next request while it is fresh. A GET
//!   on a reused connection that fails before any response byte is retried
//!   once on a new connection; other requests are never resent.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-8, SC-8(1) (Transmission Confidentiality and
//   Integrity) - every byte over server-authenticated TLS.
// - NIST 800-53: SI-10 (Information Input Validation) - bounded,
//   strictly parsed responses.
// - NIST 800-53: SC-5 (Denial-of-Service Protection) - every wait and
//   every buffer bounded.
// - NIST 800-53: SC-28, IA-5(1)(c) - token-bearing buffers zeroized.
// - SPEC: specs/preinstall-env.md#REQ-PE-015
// - RFC 9112 §6.3 - message body length (Content-Length only here)

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use usgp_crypto::tls::{BlockingClientStream, BlockingClientTls, TlsFailure};
use zeroize::Zeroizing;

use crate::config::Endpoint;

/// Largest response head accepted.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
/// Most response headers accepted.
pub const MAX_HEADERS: usize = 64;
/// Most addresses tried for one name.
const MAX_ADDRESSES: usize = 16;
/// Longest `Content-Type` value kept.
const MAX_CONTENT_TYPE: usize = 128;
/// A kept connection older than this is not reused (the server's idle
/// timeout is 120 s by default; plan section 3.9).
const MAX_IDLE: Duration = Duration::from_secs(5);
/// Read buffer size.
const READ_BUF: usize = 16 * 1024;
/// Smallest socket timeout set (a zero timeout means "none" to the OS).
const MIN_SOCKET_TIMEOUT: Duration = Duration::from_millis(1);

/// Time limits for one client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpLimits {
    /// Name resolution.
    pub resolve_timeout: Duration,
    /// One TCP connect attempt.
    pub connect_timeout: Duration,
    /// One read or write (and each TLS handshake round).
    pub io_timeout: Duration,
    /// The whole request, from connect to the last body byte.
    pub request_timeout: Duration,
}

impl HttpLimits {
    /// Default limits with the configured connect timeout.
    #[must_use]
    pub fn new(connect_timeout: Duration) -> Self {
        Self {
            resolve_timeout: Duration::from_secs(15),
            connect_timeout,
            io_timeout: Duration::from_secs(60),
            request_timeout: Duration::from_secs(300),
        }
    }
}

/// Request method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// GET.
    Get,
    /// POST.
    Post,
    /// PUT.
    Put,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
        }
    }
}

/// One request.
#[derive(Clone, Copy)]
pub struct Request<'a> {
    /// Method.
    pub method: Method,
    /// Absolute path (built by this crate; checked again here).
    pub path: &'a str,
    /// Bearer token text, if any.
    pub bearer: Option<&'a str>,
    /// Body and its media type.
    pub body: Option<(&'a str, &'a [u8])>,
    /// `Accept` value.
    pub accept: &'a str,
}

impl std::fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("bearer", &self.bearer.map(|_| "<redacted>"))
            .field("body_len", &self.body.map(|(_, b)| b.len()))
            .finish()
    }
}

/// A response.
pub struct Response {
    /// Status code.
    pub status: u16,
    /// `Content-Type`, lower case, if present.
    pub content_type: Option<String>,
    /// The body (zeroized on drop).
    pub body: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl Response {
    /// `true` if the media type is `media` (parameters ignored).
    #[must_use]
    pub fn is_media(&self, media: &str) -> bool {
        self.content_type
            .as_deref()
            .and_then(|c| c.split(';').next())
            .is_some_and(|m| m.trim() == media)
    }
}

/// Why a request failed. Carries no request or response data.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum HttpError {
    /// The server name did not resolve in time.
    #[error("the server name could not be resolved")]
    Resolve,
    /// No address accepted a connection.
    #[error("could not connect to the server ({0})")]
    Connect(io::ErrorKind),
    /// The TLS handshake was refused (the detail is about public
    /// certificate data only).
    #[error("{0}")]
    Tls(TlsFailure),
    /// A wait ran out.
    #[error("the server did not answer in time")]
    Timeout,
    /// The connection failed.
    #[error("the connection failed ({0})")]
    Io(io::ErrorKind),
    /// The response broke the rules above.
    #[error("bad response from the server: {0}")]
    Protocol(&'static str),
    /// The body is larger than allowed.
    #[error("response body larger than {limit} bytes")]
    TooLarge {
        /// The limit.
        limit: usize,
    },
}

impl HttpError {
    /// `true` for a TLS failure caused by a certificate validity period,
    /// which on the device usually means the clock is wrong (plan
    /// section 5, R-5).
    #[must_use]
    pub fn is_time_related(&self) -> bool {
        matches!(self, Self::Tls(t) if t.class.is_time_related())
    }
}

struct Conn {
    stream: BlockingClientStream<TcpStream>,
    idle_since: Instant,
}

/// Why one exchange failed, and whether any response byte had arrived.
struct Failed {
    error: HttpError,
    before_response: bool,
}

/// The client: one server, one kept connection at most.
pub struct HttpClient {
    tls: BlockingClientTls,
    endpoint: Endpoint,
    limits: HttpLimits,
    conn: Option<Conn>,
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClient")
            .field("endpoint", &self.endpoint)
            .field("limits", &self.limits)
            .field("connected", &self.conn.is_some())
            .finish()
    }
}

impl HttpClient {
    /// A client for `endpoint` using `tls`.
    #[must_use]
    pub fn new(tls: BlockingClientTls, endpoint: Endpoint, limits: HttpLimits) -> Self {
        Self {
            tls,
            endpoint,
            limits,
            conn: None,
        }
    }

    /// The current limits.
    #[must_use]
    pub fn limits(&self) -> HttpLimits {
        self.limits
    }

    /// Replaces the limits (for example once the job plan's stall limit
    /// is known).
    pub fn set_limits(&mut self, limits: HttpLimits) {
        self.limits = limits;
    }

    /// Drops the kept connection.
    pub fn disconnect(&mut self) {
        self.conn = None;
    }

    /// Opens a connection now (the start-up reachability and TLS check,
    /// REQ-PE-015) and keeps it for the next request.
    ///
    /// # Errors
    ///
    /// [`HttpError`].
    pub fn check_connect(&mut self) -> Result<(), HttpError> {
        let deadline = Instant::now() + self.limits.request_timeout;
        let conn = self.connect(deadline)?;
        self.conn = Some(conn);
        Ok(())
    }

    /// Sends `req` and reads the response, whose body may be at most
    /// `max_body` bytes.
    ///
    /// # Errors
    ///
    /// [`HttpError`].
    pub fn send(&mut self, req: &Request<'_>, max_body: usize) -> Result<Response, HttpError> {
        let head = build_head(req, &self.endpoint.server_name)?;
        let body = req.body.map_or(&[][..], |(_, b)| b);
        let deadline = Instant::now() + self.limits.request_timeout;
        let kept = self
            .conn
            .take()
            .filter(|c| c.idle_since.elapsed() <= MAX_IDLE);
        if let Some(conn) = kept {
            match self.exchange(conn, &head, body, deadline, max_body) {
                Ok(r) => return Ok(r),
                Err(f) if f.before_response && req.method == Method::Get => {}
                Err(f) => return Err(f.error),
            }
        }
        let conn = self.connect(deadline)?;
        self.exchange(conn, &head, body, deadline, max_body)
            .map_err(|f| f.error)
    }

    fn connect(&self, deadline: Instant) -> Result<Conn, HttpError> {
        let addrs = resolve(
            &self.endpoint.host,
            self.endpoint.port,
            self.limits.resolve_timeout,
        )?;
        let mut last = io::ErrorKind::NotFound;
        let mut tcp = None;
        for addr in addrs {
            let wait = remaining(deadline)?.min(self.limits.connect_timeout);
            match TcpStream::connect_timeout(&addr, wait.max(MIN_SOCKET_TIMEOUT)) {
                Ok(s) => {
                    tcp = Some(s);
                    break;
                }
                Err(e) => last = e.kind(),
            }
        }
        let tcp = tcp.ok_or(HttpError::Connect(last))?;
        // Best effort: small requests should not wait for coalescing.
        let _ = tcp.set_nodelay(true);
        set_timeouts(&tcp, deadline, self.limits.io_timeout)?;
        let stream = self
            .tls
            .connect(tcp, &self.endpoint.server_name)
            .map_err(HttpError::Tls)?;
        Ok(Conn {
            stream,
            idle_since: Instant::now(),
        })
    }

    fn exchange(
        &mut self,
        mut conn: Conn,
        head: &[u8],
        body: &[u8],
        deadline: Instant,
        max_body: usize,
    ) -> Result<Response, Failed> {
        let early = |error| Failed {
            error,
            before_response: true,
        };
        let late = |error| Failed {
            error,
            before_response: false,
        };
        let io = self.limits.io_timeout;
        write_all(&mut conn.stream, head, deadline, io).map_err(early)?;
        write_all(&mut conn.stream, body, deadline, io).map_err(early)?;
        set_timeouts(conn.stream.io(), deadline, io).map_err(early)?;
        conn.stream.flush().map_err(|e| early(io_error(&e)))?;

        // Head.
        let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(READ_BUF));
        let mut chunk = Zeroizing::new(vec![0u8; READ_BUF]);
        let parsed = loop {
            let n = read_some(&mut conn.stream, &mut chunk, deadline, io)
                .map_err(|e| if buf.is_empty() { early(e) } else { late(e) })?;
            if n == 0 {
                let e = HttpError::Protocol("connection closed before the response");
                return Err(if buf.is_empty() { early(e) } else { late(e) });
            }
            buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
            match parse_head(&buf).map_err(late)? {
                Some(h) => break h,
                None if buf.len() > MAX_HEAD_BYTES => {
                    return Err(late(HttpError::Protocol("response head too large")));
                }
                None => {}
            }
        };
        let len = usize::try_from(parsed.content_length)
            .ok()
            .filter(|&l| l <= max_body)
            .ok_or(late(HttpError::TooLarge { limit: max_body }))?;
        let already = buf.get(parsed.head_len..).unwrap_or_default();
        if already.len() > len {
            return Err(late(HttpError::Protocol("more data than Content-Length")));
        }
        let mut body_out = Zeroizing::new(Vec::with_capacity(len));
        body_out.extend_from_slice(already);
        while body_out.len() < len {
            let want = (len - body_out.len()).min(chunk.len());
            let slot = chunk.get_mut(..want).unwrap_or_default();
            let n = read_some(&mut conn.stream, slot, deadline, io).map_err(late)?;
            if n == 0 {
                return Err(late(HttpError::Protocol(
                    "body shorter than Content-Length",
                )));
            }
            body_out.extend_from_slice(chunk.get(..n).unwrap_or_default());
        }
        if parsed.keep_alive {
            conn.idle_since = Instant::now();
            self.conn = Some(conn);
        }
        Ok(Response {
            status: parsed.status,
            content_type: parsed.content_type,
            body: body_out,
        })
    }
}

/// The parsed response head.
#[derive(Debug, PartialEq, Eq)]
pub struct Head {
    /// Status.
    pub status: u16,
    /// Bytes of the head, including the blank line.
    pub head_len: usize,
    /// `Content-Length`.
    pub content_length: u64,
    /// `Content-Type`, lower case.
    pub content_type: Option<String>,
    /// The connection may be reused.
    pub keep_alive: bool,
}

/// Parses a response head from `buf`. `Ok(None)` if more bytes are needed.
///
/// # Errors
///
/// [`HttpError::Protocol`] for anything outside the rules in the module
/// documentation.
pub fn parse_head(buf: &[u8]) -> Result<Option<Head>, HttpError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut resp = httparse::Response::new(&mut headers);
    let head_len = match resp.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(httparse::Error::TooManyHeaders) => {
            return Err(HttpError::Protocol("too many response headers"));
        }
        Err(_) => return Err(HttpError::Protocol("malformed response head")),
    };
    if resp.version != Some(1) {
        return Err(HttpError::Protocol("not HTTP/1.1"));
    }
    let status = resp.code.ok_or(HttpError::Protocol("no status code"))?;
    if !(200..=599).contains(&status) {
        return Err(HttpError::Protocol("unexpected status class"));
    }
    let mut content_length = None;
    let mut content_type = None;
    let mut keep_alive = true;
    for h in resp.headers.iter() {
        if h.name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(HttpError::Protocol("repeated Content-Length"));
            }
            content_length = Some(parse_length(h.value)?);
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(HttpError::Protocol("transfer coding not supported"));
        } else if h.name.eq_ignore_ascii_case("connection") {
            let v = std::str::from_utf8(h.value).unwrap_or("close");
            if v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")) {
                keep_alive = false;
            }
        } else if h.name.eq_ignore_ascii_case("content-type") {
            if content_type.is_some() {
                return Err(HttpError::Protocol("repeated Content-Type"));
            }
            let v = std::str::from_utf8(h.value)
                .ok()
                .filter(|v| v.len() <= MAX_CONTENT_TYPE && v.is_ascii())
                .ok_or(HttpError::Protocol("bad Content-Type"))?;
            content_type = Some(v.trim().to_ascii_lowercase());
        }
    }
    let content_length = content_length.ok_or(HttpError::Protocol("no Content-Length"))?;
    Ok(Some(Head {
        status,
        head_len,
        content_length,
        content_type,
        keep_alive,
    }))
}

fn parse_length(v: &[u8]) -> Result<u64, HttpError> {
    let bad = HttpError::Protocol("bad Content-Length");
    if v.is_empty() || v.len() > 19 || !v.iter().all(u8::is_ascii_digit) {
        return Err(bad);
    }
    std::str::from_utf8(v)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(bad)
}

/// Builds the request head into a zeroizing buffer.
fn build_head(req: &Request<'_>, host: &str) -> Result<Zeroizing<Vec<u8>>, HttpError> {
    let clean = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic());
    if !req.path.starts_with('/') || !clean(req.path) {
        return Err(HttpError::Protocol("bad request path"));
    }
    if !clean(host) || !clean(req.accept) || req.bearer.is_some_and(|b| !clean(b)) {
        return Err(HttpError::Protocol("bad request header"));
    }
    let mut h = Zeroizing::new(Vec::with_capacity(512));
    let host_field = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    let start = format!(
        "{} {} HTTP/1.1\r\nHost: {host_field}\r\nUser-Agent: usgp-preboot-agent/{}\r\nAccept: {}\r\n",
        req.method.as_str(),
        req.path,
        crate::AGENT_VERSION,
        req.accept,
    );
    h.extend_from_slice(start.as_bytes());
    if let Some(token) = req.bearer {
        h.extend_from_slice(b"Authorization: Bearer ");
        h.extend_from_slice(token.as_bytes());
        h.extend_from_slice(b"\r\n");
    }
    match req.body {
        Some((media, body)) => {
            if !clean(media) {
                return Err(HttpError::Protocol("bad request header"));
            }
            h.extend_from_slice(
                format!(
                    "Content-Type: {media}\r\nContent-Length: {}\r\n",
                    body.len()
                )
                .as_bytes(),
            );
        }
        None if req.method != Method::Get => h.extend_from_slice(b"Content-Length: 0\r\n"),
        None => {}
    }
    h.extend_from_slice(b"\r\n");
    Ok(h)
}

fn remaining(deadline: Instant) -> Result<Duration, HttpError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(HttpError::Timeout)
    } else {
        Ok(left)
    }
}

fn set_timeouts(tcp: &TcpStream, deadline: Instant, io_timeout: Duration) -> Result<(), HttpError> {
    let t = remaining(deadline)?.min(io_timeout).max(MIN_SOCKET_TIMEOUT);
    tcp.set_read_timeout(Some(t))
        .and_then(|()| tcp.set_write_timeout(Some(t)))
        .map_err(|e| HttpError::Io(e.kind()))
}

fn io_error(e: &io::Error) -> HttpError {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => HttpError::Timeout,
        k => HttpError::Io(k),
    }
}

fn write_all(
    s: &mut BlockingClientStream<TcpStream>,
    mut data: &[u8],
    deadline: Instant,
    io_timeout: Duration,
) -> Result<(), HttpError> {
    while !data.is_empty() {
        set_timeouts(s.io(), deadline, io_timeout)?;
        match s.write(data) {
            Ok(0) => return Err(HttpError::Io(io::ErrorKind::WriteZero)),
            Ok(n) => data = data.get(n..).unwrap_or_default(),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io_error(&e)),
        }
    }
    Ok(())
}

fn read_some(
    s: &mut BlockingClientStream<TcpStream>,
    buf: &mut [u8],
    deadline: Instant,
    io_timeout: Duration,
) -> Result<usize, HttpError> {
    loop {
        set_timeouts(s.io(), deadline, io_timeout)?;
        match s.read(buf) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io_error(&e)),
        }
    }
}

/// Resolves `host:port`, bounded by `timeout`. IP literals need no lookup.
/// A lookup that does not finish in time is abandoned (its thread ends
/// when the system resolver returns).
fn resolve(host: &str, port: u16, timeout: Duration) -> Result<Vec<SocketAddr>, HttpError> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let (tx, rx) = mpsc::channel();
    let name = host.to_owned();
    std::thread::Builder::new()
        .name("resolve".to_owned())
        .spawn(move || {
            let r = (name.as_str(), port)
                .to_socket_addrs()
                .map(|a| a.take(MAX_ADDRESSES).collect::<Vec<_>>());
            // The receiver may have given up; nothing to do then.
            let _ = tx.send(r);
        })
        .map_err(|_| HttpError::Resolve)?;
    match rx.recv_timeout(timeout) {
        Ok(Ok(a)) if !a.is_empty() => Ok(a),
        _ => Err(HttpError::Resolve),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(s: &str) -> Result<Option<Head>, HttpError> {
        parse_head(s.as_bytes())
    }

    #[test]
    fn complete_head() {
        let h = head("HTTP/1.1 200 OK\r\nContent-Type: Application/JSON; charset=utf-8\r\nContent-Length: 12\r\n\r\n{}")
            .unwrap()
            .unwrap();
        assert_eq!(h.status, 200);
        assert_eq!(h.content_length, 12);
        assert_eq!(
            h.content_type.as_deref(),
            Some("application/json; charset=utf-8")
        );
        assert!(h.keep_alive);
        assert_eq!(h.head_len, 86);
    }

    #[test]
    fn partial_then_refusals() {
        assert!(head("HTTP/1.1 200 OK\r\nContent-Le").unwrap().is_none());
        for bad in [
            "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: a\r\nContent-Type: b\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 700 What\r\nContent-Length: 0\r\n\r\n",
            "garbage\r\n\r\n",
        ] {
            assert!(head(bad).is_err(), "{bad:?}");
        }
        let many: String = (0..=MAX_HEADERS).map(|i| format!("X-{i}: y\r\n")).collect();
        assert!(
            head(&format!(
                "HTTP/1.1 200 OK\r\n{many}Content-Length: 0\r\n\r\n"
            ))
            .is_err()
        );
    }

    #[test]
    fn connection_close() {
        let h =
            head("HTTP/1.1 503 x\r\nConnection: keep-alive, Close\r\nContent-Length: 0\r\n\r\n")
                .unwrap()
                .unwrap();
        assert!(!h.keep_alive);
    }

    #[test]
    fn request_head() {
        let req = Request {
            method: Method::Post,
            path: "/v1/device/session/code",
            bearer: Some("tok"),
            body: Some(("application/json", b"{}")),
            accept: "application/json",
        };
        let h = build_head(&req, "localhost").unwrap();
        let s = String::from_utf8(h.to_vec()).unwrap();
        assert!(s.starts_with("POST /v1/device/session/code HTTP/1.1\r\nHost: localhost\r\n"));
        assert!(s.contains("Authorization: Bearer tok\r\n"));
        assert!(s.contains("Content-Length: 2\r\n"));
        assert!(s.ends_with("\r\n\r\n"));
        assert!(!format!("{req:?}").contains("tok"));
        let bad = Request {
            path: "/a b",
            ..req
        };
        assert!(build_head(&bad, "h").is_err());
        let bad = Request {
            bearer: Some("a\r\nX: y"),
            ..req
        };
        assert!(build_head(&bad, "h").is_err());
        let get = Request {
            method: Method::Get,
            body: None,
            bearer: None,
            ..req
        };
        let s = String::from_utf8(build_head(&get, "fd00::1").unwrap().to_vec()).unwrap();
        assert!(s.contains("Host: [fd00::1]\r\n"));
        assert!(!s.contains("Content-Length"));
    }
}
