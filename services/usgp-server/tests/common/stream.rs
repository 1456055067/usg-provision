//! Streaming HTTPS/1.1 helpers for content of any size: an upload whose
//! body is read from a file in 1 MiB pieces, and a download that is
//! hashed as it arrives (whole-file SHA-256 plus one SHA-256 per 8 MiB
//! chunk, plan M2 section 5.7) without ever being held in memory.
//!
//! Also the signature verifier the tests pin to the content public key,
//! and strict parsing of API views through `usgp-proto`.

use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use usgp_crypto::test_pki::{TestCert, TestPki};
use usgp_crypto::tls::{ClientTls, TlsMinVersion};
use usgp_crypto::{Sha256Digest, Sha256Hasher, VerifyingKey};
use usgp_proto::limits::CHUNK_SIZE;

/// Size of one read from the source and one write to the socket.
const IO_BYTES: usize = 1024 * 1024;

/// Largest response head accepted, in bytes.
const MAX_HEAD_BYTES: usize = 64 * 1024;

/// Largest non-download response body kept, in bytes.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Whole-content and per-chunk SHA-256 digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digests {
    /// Bytes hashed.
    pub size: u64,
    /// SHA-256 of all bytes.
    pub total: Sha256Digest,
    /// SHA-256 of each `CHUNK_SIZE` piece, the last one possibly short.
    pub chunks: Vec<Sha256Digest>,
}

/// Incremental [`Digests`], computed independently of the production
/// hasher so that the test is a second implementation.
pub struct ChunkDigester {
    total: Sha256Hasher,
    chunk: Sha256Hasher,
    in_chunk: u64,
    size: u64,
    chunks: Vec<Sha256Digest>,
}

impl Default for ChunkDigester {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkDigester {
    /// An empty digester.
    pub fn new() -> Self {
        Self {
            total: Sha256Hasher::new(),
            chunk: Sha256Hasher::new(),
            in_chunk: 0,
            size: 0,
            chunks: Vec::new(),
        }
    }

    /// Adds bytes.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total.update(data);
        self.size += data.len() as u64;
        while !data.is_empty() {
            let room = usize::try_from(CHUNK_SIZE - self.in_chunk).unwrap();
            let take = room.min(data.len());
            let (now, rest) = data.split_at(take);
            self.chunk.update(now);
            self.in_chunk += take as u64;
            data = rest;
            if self.in_chunk == CHUNK_SIZE {
                let done = std::mem::replace(&mut self.chunk, Sha256Hasher::new());
                self.chunks.push(done.finish());
                self.in_chunk = 0;
            }
        }
    }

    /// The digests.
    pub fn finish(mut self) -> Digests {
        if self.in_chunk > 0 {
            self.chunks.push(self.chunk.finish());
        }
        Digests {
            size: self.size,
            total: self.total.finish(),
            chunks: self.chunks,
        }
    }
}

/// Digests of a file, read in 1 MiB pieces.
pub fn digest_file(path: &Path) -> Digests {
    let mut f = std::fs::File::open(path).unwrap();
    let mut d = ChunkDigester::new();
    let mut buf = vec![0u8; IO_BYTES];
    loop {
        let n = f.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        d.update(&buf[..n]);
    }
    d.finish()
}

/// Digests of bytes in memory.
pub fn digest_bytes(data: &[u8]) -> Digests {
    let mut d = ChunkDigester::new();
    d.update(data);
    d.finish()
}

/// A response whose body is kept as bytes (bounded).
#[derive(Debug, Clone)]
pub struct RawResponse {
    /// Status code.
    pub status: u16,
    /// Header block, lower-cased.
    pub head: String,
    /// Body.
    pub body: Vec<u8>,
}

impl RawResponse {
    /// The body as text (lossy), for messages.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Where an upload body comes from.
pub enum Body<'a> {
    /// A file, streamed.
    File(&'a Path),
    /// Bytes in memory.
    Bytes(&'a [u8]),
}

/// `PUT`s `body` with an exact `Content-Length` over mutual TLS and reads
/// the response. The body is never held in memory when it is a file.
/// A write error (the server answered early and closed) stops sending;
/// the response is still read.
pub async fn put(
    addr: SocketAddr,
    pki: &TestPki,
    cert: &TestCert,
    path: &str,
    body: Body<'_>,
) -> Result<RawResponse, String> {
    let client = ClientTls::new(
        &pki.client_settings(Some(cert), TlsMinVersion::Tls12)
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let mut s = client
        .connect(tcp, "localhost")
        .await
        .map_err(|e| format!("{e:?}"))?;
    let len = match &body {
        Body::File(p) => std::fs::metadata(p).map_err(|e| e.to_string())?.len(),
        Body::Bytes(b) => b.len() as u64,
    };
    let head = format!(
        "PUT {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/octet-stream\r\nContent-Length: {len}\r\n\r\n"
    );
    let mut sent = 0u64;
    let mut write_ok = s.write_all(head.as_bytes()).await.is_ok();
    match body {
        Body::Bytes(b) => {
            if write_ok {
                write_ok = s.write_all(b).await.is_ok();
                sent = b.len() as u64;
            }
        }
        Body::File(p) => {
            let mut f = std::fs::File::open(p).map_err(|e| e.to_string())?;
            let mut buf = vec![0u8; IO_BYTES];
            while write_ok {
                let n = f.read(&mut buf).map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                write_ok = s.write_all(&buf[..n]).await.is_ok();
                if write_ok {
                    sent += n as u64;
                }
            }
        }
    }
    if write_ok {
        let _ = s.flush().await;
    }
    let (status, head, mut rest) = read_head(&mut s).await?;
    read_bounded(&mut s, &mut rest).await;
    if write_ok && sent != len {
        return Err(format!("sent {sent} of {len} bytes"));
    }
    Ok(RawResponse {
        status,
        head,
        body: rest,
    })
}

/// A `GET` over mutual TLS with the body kept in memory (bounded).
pub async fn get(
    addr: SocketAddr,
    pki: &TestPki,
    cert: &TestCert,
    path: &str,
) -> Result<RawResponse, String> {
    let mut s = send_get(addr, pki, cert, path).await?;
    let (status, head, mut rest) = read_head(&mut s).await?;
    read_bounded(&mut s, &mut rest).await;
    Ok(RawResponse {
        status,
        head,
        body: rest,
    })
}

/// A verified-download result: status, head, and the digests of the body
/// as received.
#[derive(Debug, Clone)]
pub struct Downloaded {
    /// Status code.
    pub status: u16,
    /// Header block, lower-cased.
    pub head: String,
    /// `Content-Length` the server sent.
    pub content_length: u64,
    /// Digests of the received body.
    pub digests: Digests,
}

/// `GET`s `path` and hashes the body as it arrives; nothing but the
/// running digests is kept. Fails if the status is not 200, if the
/// response has no `Content-Length` or uses chunked transfer coding, or if
/// the body is shorter or longer than `Content-Length`.
pub async fn download_digests(
    addr: SocketAddr,
    pki: &TestPki,
    cert: &TestCert,
    path: &str,
) -> Result<Downloaded, String> {
    let mut s = send_get(addr, pki, cert, path).await?;
    let (status, head, first) = read_head(&mut s).await?;
    if status != 200 {
        let mut rest = first;
        read_bounded(&mut s, &mut rest).await;
        return Err(format!(
            "download {path}: status {status}: {}",
            String::from_utf8_lossy(&rest)
        ));
    }
    if head.contains("transfer-encoding:") {
        return Err(format!("download {path}: transfer coding used:\n{head}"));
    }
    let content_length = header(&head, "content-length")
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| format!("download {path}: no Content-Length:\n{head}"))?;
    let mut d = ChunkDigester::new();
    d.update(&first);
    let mut buf = vec![0u8; IO_BYTES];
    loop {
        match s.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => d.update(&buf[..n]),
            Err(e) => {
                // A close without TLS close_notify after the full body is
                // tolerated; the length check below decides.
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(format!("download {path}: read: {e}"));
            }
        }
    }
    let digests = d.finish();
    if digests.size != content_length {
        return Err(format!(
            "download {path}: received {} bytes, Content-Length {content_length}",
            digests.size
        ));
    }
    Ok(Downloaded {
        status,
        head,
        content_length,
        digests,
    })
}

/// The value of header `name` (lower case) in a lower-cased head.
pub fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| {
        let (n, v) = l.split_once(':')?;
        (n.trim() == name).then(|| v.trim())
    })
}

async fn send_get(
    addr: SocketAddr,
    pki: &TestPki,
    cert: &TestCert,
    path: &str,
) -> Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin, String> {
    let client = ClientTls::new(
        &pki.client_settings(Some(cert), TlsMinVersion::Tls12)
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let mut s = client
        .connect(tcp, "localhost")
        .await
        .map_err(|e| format!("{e:?}"))?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    s.write_all(req.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    s.flush().await.map_err(|e| e.to_string())?;
    Ok(s)
}

/// Reads up to the end of the head; returns the status, the lower-cased
/// head and any body bytes already read.
async fn read_head<S: tokio::io::AsyncRead + Unpin>(
    s: &mut S,
) -> Result<(u16, String, Vec<u8>), String> {
    let mut buf = Vec::new();
    let mut piece = [0u8; 8192];
    loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..at]).to_ascii_lowercase();
            let rest = buf[at + 4..].to_vec();
            let status = head
                .split_whitespace()
                .nth(1)
                .and_then(|v| v.parse().ok())
                .ok_or_else(|| format!("no status in {head}"))?;
            return Ok((status, head, rest));
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Err("response head too large".into());
        }
        match s.read(&mut piece).await {
            Ok(0) | Err(_) => return Err("no HTTP response".into()),
            Ok(n) => buf.extend_from_slice(&piece[..n]),
        }
    }
}

/// Reads the rest of a (small) body into `out`, up to `MAX_BODY_BYTES`.
async fn read_bounded<S: tokio::io::AsyncRead + Unpin>(s: &mut S, out: &mut Vec<u8>) {
    let mut piece = [0u8; 8192];
    while out.len() <= MAX_BODY_BYTES {
        match s.read(&mut piece).await {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&piece[..n]),
        }
    }
}

/// Verifies signatures with one pinned content public key (the key a
/// client is configured with), using `usgp-crypto`.
pub struct Pinned(pub VerifyingKey);

impl usgp_proto::SignatureVerifier for Pinned {
    fn verify(
        &self,
        key_id: &Sha256Digest,
        _alg: usgp_proto::SignatureAlg,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        self.0.key_id().0 == *key_id
            && usgp_crypto::verify_signing_input(&self.0, message, signature).is_ok()
    }
}

/// Parses an API view strictly (unknown fields refused) through
/// `usgp-proto`.
pub fn view<T: serde::de::DeserializeOwned>(body: &[u8]) -> T {
    usgp_proto::api::parse_request(body, MAX_BODY_BYTES).unwrap_or_else(|e| {
        panic!(
            "unexpected API view: {e}: {}",
            String::from_utf8_lossy(body)
        )
    })
}
