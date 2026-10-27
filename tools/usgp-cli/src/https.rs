//! HTTPS transport for the operator API: HTTP/1.1 (`hyper` client
//! connection) over `usgp_crypto::tls::ClientTls` with the operator's
//! client certificate (plan WU-8, sections 1.1 and 5.4).
//!
//! - [`to_hyper`] maps a [`Request`] to an HTTP/1.1 request (`Host`,
//!   `Content-Type`, `Content-Length`, `If-Match`). Uploads are never
//!   chunked.
//! - [`ReqBody`] streams the operator's file in 64 KiB frames, so memory
//!   stays bounded.
//! - [`HttpsTransport`] opens one TLS connection per request on a
//!   current-thread runtime it owns. TCP connect and the TLS handshake
//!   are each bounded by [`CONNECT_TIMEOUT`]. After that, the exchange
//!   fails only if no byte moves in either direction for [`IDLE_TIMEOUT`]
//!   (progress-based, never a total deadline, REQ-IMG-032). ALPN must
//!   select `http/1.1`. Response bodies are read one frame at a time.
//!
//! Both timeout values are project-chosen (CM-6); the plan fixes none for
//! the CLI.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-8, SC-8(1), SC-13 - the operator API is reached only
//   over TLS built by usgp-crypto on the FIPS provider; there is no
//   plaintext fallback (this module refuses rather than degrade).
// - NIST 800-53: SI-10 - header values are built only from validated ids
//   and clean entity tags; no operator text reaches a header.
// - SPEC: specs/os-images.md#REQ-IMG-053 (protected channel),
//   #REQ-IMG-031 (Content-Length stated up front, never chunked)
// - RFC 9110 §8.6 (Content-Length), §7.2 (Host), §13.1.1 (If-Match)

use std::future::Future;
use std::io::{self, Read};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::body::{Bytes, Frame, Incoming, SizeHint};
use hyper::header::{self, HeaderValue};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tokio::time::{Sleep, timeout};
use usgp_crypto::tls::{ALPN_HTTP11, ClientTls};

use crate::client::{Body, ClientError, Method, Request, Response, Transport, clean_etag};
use crate::config::ServerUrl;

/// Largest frame read from a streamed body.
const FRAME_BYTES: usize = 64 * 1024;

/// A request body for hyper.
pub enum ReqBody {
    /// No body.
    Empty,
    /// A whole body (JSON).
    Full(Option<Bytes>),
    /// A streamed body of exactly `remaining` more bytes.
    Stream {
        /// Bytes still to send.
        remaining: u64,
        /// The source.
        reader: Box<dyn Read + Send>,
    },
}

impl hyper::body::Body for ReqBody {
    type Data = Bytes;
    type Error = io::Error;

    // The source is a local file: a blocking read of at most 64 KiB is
    // acceptable on the CLI's single-request runtime.
    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let this = self.get_mut();
        match this {
            Self::Empty => Poll::Ready(None),
            Self::Full(b) => Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            Self::Stream { remaining, reader } => {
                if *remaining == 0 {
                    return Poll::Ready(None);
                }
                let want = usize::try_from(*remaining).map_or(FRAME_BYTES, |r| r.min(FRAME_BYTES));
                let mut buf = vec![0u8; want];
                let n = loop {
                    match reader.read(&mut buf) {
                        Ok(n) => break n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Poll::Ready(Some(Err(e))),
                    }
                };
                if n == 0 {
                    // Shorter than the declared length: abort the body so
                    // the server sees an incomplete upload (REQ-IMG-035).
                    return Poll::Ready(Some(Err(io::Error::from(io::ErrorKind::UnexpectedEof))));
                }
                buf.truncate(n);
                *remaining = remaining.saturating_sub(u64::try_from(n).unwrap_or(u64::MAX));
                Poll::Ready(Some(Ok(Frame::data(Bytes::from(buf)))))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Full(b) => b.is_none(),
            Self::Stream { remaining, .. } => *remaining == 0,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Empty => SizeHint::with_exact(0),
            Self::Full(b) => SizeHint::with_exact(
                b.as_ref()
                    .map_or(0, |b| u64::try_from(b.len()).unwrap_or(u64::MAX)),
            ),
            Self::Stream { remaining, .. } => SizeHint::with_exact(*remaining),
        }
    }
}

/// The `Host` value for `server` (RFC 9110 §7.2; IPv6 in brackets).
#[must_use]
pub fn authority(server: &ServerUrl) -> String {
    if server.host.contains(':') {
        format!("[{}]:{}", server.host, server.port)
    } else {
        format!("{}:{}", server.host, server.port)
    }
}

fn bad(what: &'static str) -> ClientError {
    ClientError::Transport(format!("request not built: {what}"))
}

/// Builds the HTTP/1.1 request for `req`.
///
/// # Errors
///
/// [`ClientError::Transport`] if the path is not under `/v1/` or a header
/// value is not acceptable.
pub fn to_hyper(req: Request, server: &ServerUrl) -> Result<hyper::Request<ReqBody>, ClientError> {
    if !req.path.starts_with("/v1/") || !req.path.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(bad("path"));
    }
    let method = match req.method {
        Method::Get => hyper::Method::GET,
        Method::Post => hyper::Method::POST,
        Method::Put => hyper::Method::PUT,
        Method::Delete => hyper::Method::DELETE,
    };
    let host = HeaderValue::from_str(&authority(server)).map_err(|_| bad("host"))?;
    let mut b = hyper::Request::builder()
        .method(method)
        .uri(req.path.as_str())
        .header(header::HOST, host)
        .header(header::ACCEPT, usgp_proto::api::JSON_MEDIA_TYPE);
    if let Some(tag) = req.if_match {
        let tag = clean_etag(tag.as_bytes()).ok_or_else(|| bad("If-Match"))?;
        b = b.header(
            header::IF_MATCH,
            HeaderValue::from_str(&tag).map_err(|_| bad("If-Match"))?,
        );
    }
    let body = match req.body {
        Body::Empty => ReqBody::Empty,
        Body::Json(bytes) => {
            b = b
                .header(header::CONTENT_TYPE, usgp_proto::api::JSON_MEDIA_TYPE)
                .header(header::CONTENT_LENGTH, bytes.len());
            ReqBody::Full(Some(Bytes::from(bytes)))
        }
        Body::Stream { len, reader } => {
            b = b
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::CONTENT_LENGTH, len);
            ReqBody::Stream {
                remaining: len,
                reader,
            }
        }
    };
    b.body(body).map_err(|_| bad("request"))
}

/// TCP connect timeout, and separately the TLS handshake timeout.
/// Project-chosen (CM-6, SC-5): the plan fixes no CLI value.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Idle timeout: the exchange fails if no byte moves in either direction
/// for this long. Progress-based, never a total deadline, so a 10 GB
/// upload or download is never cut off while it is moving (REQ-IMG-032).
/// Project-chosen to match the server's default `api.idle_timeout_s`
/// (plan section 3.5).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Wraps a stream and fails it with `TimedOut` when no byte has moved in
/// either direction for `idle`. Reads and writes share one timer, so a
/// long upload (writes only) does not trip the pending read.
struct IdleIo<T> {
    inner: T,
    idle: Duration,
    timer: Pin<Box<Sleep>>,
}

impl<T> IdleIo<T> {
    /// Must be called inside the runtime (it creates a timer).
    fn new(inner: T, idle: Duration) -> Self {
        Self {
            inner,
            idle,
            timer: Box::pin(tokio::time::sleep(idle)),
        }
    }

    fn progress(&mut self) {
        let next = tokio::time::Instant::now() + self.idle;
        self.timer.as_mut().reset(next);
    }

    /// `Ready(err)` if the idle timer has fired; registers the waker
    /// otherwise.
    fn expired(&mut self, cx: &mut Context<'_>) -> bool {
        self.timer.as_mut().poll(cx).is_ready()
    }

    fn timed_out(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("no data moved for {} s", self.idle.as_secs()),
        )
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for IdleIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(r) => {
                if buf.filled().len() > before {
                    this.progress();
                }
                Poll::Ready(r)
            }
            Poll::Pending if this.expired(cx) => Poll::Ready(Err(this.timed_out())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for IdleIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(r) => {
                if matches!(r, Ok(n) if n > 0) {
                    this.progress();
                }
                Poll::Ready(r)
            }
            Poll::Pending if this.expired(cx) => Poll::Ready(Err(this.timed_out())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Pending if this.expired(cx) => Poll::Ready(Err(this.timed_out())),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Text for a hyper error: the I/O error kind underneath if there is one
/// (for example the idle timeout), otherwise hyper's own description.
/// Never server content.
fn describe(e: &hyper::Error) -> String {
    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
    while let Some(s) = src {
        if let Some(io) = s.downcast_ref::<io::Error>() {
            return if io.kind() == io::ErrorKind::TimedOut {
                format!("idle timeout: {io}")
            } else {
                format!("I/O error: {}", io.kind())
            };
        }
        src = s.source();
    }
    e.to_string()
}

type ConnTask = JoinHandle<Result<(), hyper::Error>>;

/// A response body read one frame at a time: each `read` that needs more
/// data drives the runtime until the next frame arrives, so at most one
/// frame is held in memory.
struct BodyReader {
    rt: Arc<Runtime>,
    body: Incoming,
    buf: Bytes,
    done: bool,
    conn: ConnTask,
}

impl Read for BodyReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if !self.buf.is_empty() {
                let n = self.buf.len().min(out.len());
                let chunk = self.buf.split_to(n);
                if let Some(dst) = out.get_mut(..n) {
                    dst.copy_from_slice(&chunk);
                }
                return Ok(n);
            }
            if self.done || out.is_empty() {
                return Ok(0);
            }
            match self.rt.block_on(self.body.frame()) {
                None => self.done = true,
                Some(Err(e)) => {
                    self.done = true;
                    return Err(io::Error::other(describe(&e)));
                }
                Some(Ok(frame)) => {
                    // Trailers carry nothing we use.
                    if let Ok(data) = frame.into_data() {
                        self.buf = data;
                    }
                }
            }
        }
    }
}

impl Drop for BodyReader {
    fn drop(&mut self) {
        self.conn.abort();
    }
}

/// The HTTPS transport to one server: one TLS connection per request on
/// a current-thread runtime the transport owns.
pub struct HttpsTransport {
    server: ServerUrl,
    tls: ClientTls,
    rt: Arc<Runtime>,
    connect_timeout: Duration,
    idle_timeout: Duration,
}

impl std::fmt::Debug for HttpsTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsTransport")
            .field("server", &self.server)
            .field("tls", &self.tls)
            .finish_non_exhaustive()
    }
}

fn transport(text: impl Into<String>) -> ClientError {
    ClientError::Transport(text.into())
}

impl HttpsTransport {
    /// A transport to `server` with `tls` and the default timeouts.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] if the runtime cannot be created or the
    /// TLS configuration is not in FIPS mode.
    pub fn new(server: ServerUrl, tls: ClientTls) -> Result<Self, ClientError> {
        if !tls.is_fips() {
            return Err(transport("TLS configuration is not in FIPS mode"));
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|e| transport(format!("cannot start the I/O runtime: {}", e.kind())))?;
        Ok(Self {
            server,
            tls,
            rt: Arc::new(rt),
            connect_timeout: CONNECT_TIMEOUT,
            idle_timeout: IDLE_TIMEOUT,
        })
    }

    /// The same with explicit timeouts (tests).
    #[cfg(test)]
    fn with_timeouts(
        server: ServerUrl,
        tls: ClientTls,
        connect: Duration,
        idle: Duration,
    ) -> Result<Self, ClientError> {
        let mut t = Self::new(server, tls)?;
        t.connect_timeout = connect;
        t.idle_timeout = idle;
        Ok(t)
    }

    async fn exchange(
        &self,
        request: hyper::Request<ReqBody>,
    ) -> Result<(hyper::Response<Incoming>, ConnTask), ClientError> {
        let host = self.server.host.as_str();
        let secs = self.connect_timeout.as_secs();
        let tcp = timeout(
            self.connect_timeout,
            TcpStream::connect((host, self.server.port)),
        )
        .await
        .map_err(|_| transport(format!("TCP connect timed out after {secs} s")))?
        .map_err(|e| transport(format!("TCP connect failed: {}", e.kind())))?;
        let _ = tcp.set_nodelay(true);
        let io = IdleIo::new(tcp, self.idle_timeout);
        let tls = timeout(self.connect_timeout, self.tls.connect(io, host))
            .await
            .map_err(|_| transport(format!("TLS handshake timed out after {secs} s")))?
            .map_err(|f| transport(f.to_string()))?;
        if tls.alpn() != Some(ALPN_HTTP11) {
            return Err(transport("server did not agree to HTTP/1.1 (ALPN)"));
        }
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| transport(describe(&e)))?;
        let mut conn_task = tokio::spawn(conn);
        match sender.send_request(request).await {
            Ok(resp) => Ok((resp, conn_task)),
            Err(e) => {
                // The connection task holds the root cause (for example
                // the idle timeout); prefer it.
                let cause = match timeout(Duration::from_secs(1), &mut conn_task).await {
                    Ok(Ok(Err(ce))) => describe(&ce),
                    _ => describe(&e),
                };
                conn_task.abort();
                Err(transport(cause))
            }
        }
    }
}

/// Parses a `Content-Length` value (digits only).
fn content_length(v: &HeaderValue) -> Option<u64> {
    let b = v.as_bytes();
    if b.is_empty() || b.len() > 20 || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(b).ok()?.parse().ok()
}

impl Transport for HttpsTransport {
    fn send(&mut self, req: Request) -> Result<Response, ClientError> {
        let request = to_hyper(req, &self.server)?;
        let rt = Arc::clone(&self.rt);
        let (resp, conn) = rt.block_on(self.exchange(request))?;
        let (parts, body) = resp.into_parts();
        let etag = parts
            .headers
            .get(header::ETAG)
            .and_then(|v| clean_etag(v.as_bytes()));
        let content_length = parts
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(content_length);
        Ok(Response {
            status: parts.status.as_u16(),
            etag,
            content_length,
            body: Box::new(BodyReader {
                rt,
                body,
                buf: Bytes::new(),
                done: false,
                conn,
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body::Body as _;

    fn server() -> ServerUrl {
        ServerUrl::parse("https://ctl.example:8443").unwrap()
    }

    fn drain(mut body: ReqBody) -> Result<Vec<u8>, io::Error> {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut out = Vec::new();
        loop {
            match Pin::new(&mut body).poll_frame(&mut cx) {
                Poll::Ready(None) => return Ok(out),
                Poll::Ready(Some(Ok(f))) => out.extend_from_slice(&f.into_data().unwrap()),
                Poll::Ready(Some(Err(e))) => return Err(e),
                Poll::Pending => unreachable!(),
            }
        }
    }

    #[test]
    fn stream_upload_has_content_length_never_chunked() {
        let data: Vec<u8> = (0..200_000u32)
            .map(|i| u8::try_from(i % 256).unwrap())
            .collect();
        let req = Request {
            method: Method::Put,
            path: "/v1/uploads/5d1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6".into(),
            if_match: None,
            body: Body::Stream {
                len: 200_000,
                reader: Box::new(io::Cursor::new(data.clone())),
            },
        };
        let r = to_hyper(req, &server()).unwrap();
        assert_eq!(r.method(), hyper::Method::PUT);
        assert_eq!(r.headers()[header::HOST], "ctl.example:8443");
        assert_eq!(r.headers()[header::CONTENT_LENGTH], "200000");
        assert!(r.headers().get(header::TRANSFER_ENCODING).is_none());
        assert_eq!(r.body().size_hint().exact(), Some(200_000));
        assert_eq!(drain(r.into_body()).unwrap(), data);
    }

    #[test]
    fn short_stream_aborts() {
        let req = Request {
            method: Method::Put,
            path: "/v1/uploads/x".into(),
            if_match: None,
            body: Body::Stream {
                len: 10,
                reader: Box::new(io::Cursor::new(vec![1u8; 4])),
            },
        };
        let r = to_hyper(req, &server()).unwrap();
        assert_eq!(
            drain(r.into_body()).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn json_and_if_match_headers() {
        let req = Request {
            method: Method::Post,
            path: "/v1/packages".into(),
            if_match: Some("\"r7\"".into()),
            body: Body::Json(b"{}".to_vec()),
        };
        let r = to_hyper(req, &ServerUrl::parse("https://[::1]:9").unwrap()).unwrap();
        assert_eq!(r.headers()[header::HOST], "[::1]:9");
        assert_eq!(r.headers()[header::IF_MATCH], "\"r7\"");
        assert_eq!(r.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(drain(r.into_body()).unwrap(), b"{}");
    }

    #[test]
    fn idle_timeout_is_progress_based() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (a, mut b) = tokio::io::duplex(64);
            let mut io = IdleIo::new(a, Duration::from_millis(150));
            // One byte every 60 ms for 600 ms: well past the idle
            // timeout in total, never idle for 150 ms.
            let peer = tokio::spawn(async move {
                for _ in 0..10 {
                    tokio::time::sleep(Duration::from_millis(60)).await;
                    b.write_all(b"x").await.unwrap();
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
                b
            });
            let mut buf = [0u8; 1];
            for _ in 0..10 {
                io.read_exact(&mut buf).await.unwrap();
            }
            // Then silence: the next read times out.
            let e = io.read(&mut buf).await.unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::TimedOut);
            peer.abort();
        });
    }

    fn client_tls() -> ClientTls {
        let pki = usgp_crypto::test_pki::TestPki::generate().unwrap();
        let s = pki
            .client_settings(Some(&pki.client), usgp_crypto::tls::TlsMinVersion::Tls12)
            .unwrap();
        ClientTls::new(&s).unwrap()
    }

    #[test]
    fn silent_server_hits_handshake_timeout() {
        // Accepts TCP (backlog) but never speaks TLS.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = ServerUrl::parse(&format!("https://127.0.0.1:{port}")).unwrap();
        let mut t = HttpsTransport::with_timeouts(
            server,
            client_tls(),
            Duration::from_millis(200),
            Duration::from_secs(5),
        )
        .unwrap();
        let req = Request {
            method: Method::Get,
            path: "/v1/limits".into(),
            if_match: None,
            body: Body::Empty,
        };
        let started = std::time::Instant::now();
        let e = t.send(req).unwrap_err().to_string();
        assert!(e.contains("TLS handshake timed out"), "{e}");
        assert!(started.elapsed() < Duration::from_secs(3));
        drop(listener);
    }

    #[test]
    fn refused_connection_reported() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let server = ServerUrl::parse(&format!("https://127.0.0.1:{port}")).unwrap();
        let mut t = HttpsTransport::new(server, client_tls()).unwrap();
        let e = t
            .send(Request {
                method: Method::Get,
                path: "/v1/limits".into(),
                if_match: None,
                body: Body::Empty,
            })
            .unwrap_err()
            .to_string();
        assert!(e.contains("TCP connect failed"), "{e}");
    }

    #[test]
    fn unsafe_values_refused() {
        for (path, tag) in [
            ("/other", None),
            ("/v1/a b", None),
            ("/v1/x", Some("\"r7\"\r\nX-Evil: 1")),
            ("/v1/x", Some("")),
        ] {
            let req = Request {
                method: Method::Get,
                path: path.into(),
                if_match: tag.map(str::to_owned),
                body: Body::Empty,
            };
            assert!(to_hyper(req, &server()).is_err(), "{path} {tag:?}");
        }
    }
}
