//! Operator API client (plan WU-8, sections 3.2 and 5.4).
//!
//! Commands talk to the server through [`ApiClient`], which sits on a
//! [`Transport`]: one HTTP/1.1 request and response at a time. The
//! production transport is HTTPS over `usgp_crypto::ClientTls` with the
//! operator's client certificate (see [`crate::https`]); tests use an
//! in-memory transport.
//!
//! Every response body is read with a size cap before it is parsed, and
//! every response type denies unknown fields (WU-4), so the client refuses
//! anything the server did not mean to send. Error bodies are parsed into
//! `usgp_proto::api::ErrorBody` and shown escaped.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - response bodies
//   are size-capped and strictly typed before use.
// - NIST 800-53: SI-11 (Error Handling) - server reason codes and text are
//   shown to the operator, escaped; no transport internals beyond the TLS
//   failure class.
// - NIST 800-53: AC-3 - path identifiers are built only from parsed UUIDs.
// - SPEC: specs/os-images.md#REQ-IMG-022 (the reason is shown),
//   #REQ-IMG-015 (dependants named on an in-use refusal),
//   #REQ-IMG-031 (the limit is shown on a 413)
// - RFC 9110 §8.8.3 (ETag), §13.1.1 (If-Match), §15.5.2 (401)

use std::fmt;
use std::io::{self, Read};

use usgp_proto::api::{ErrorBody, MAX_IF_MATCH_BYTES};
use usgp_proto::limits::DEFAULT_MAX_JSON_BYTES;

use crate::display::esc;

/// Largest JSON response body read for a view or list (32 MiB; project
/// limit, CM-6). List routes are not paginated in M2, so this bounds the
/// client's memory instead.
pub const MAX_RESPONSE_JSON_BYTES: u64 = 32 * 1024 * 1024;

/// Largest error body read (the server's JSON cap).
const MAX_ERROR_BODY_BYTES: u64 = DEFAULT_MAX_JSON_BYTES as u64;

/// HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// GET.
    Get,
    /// POST.
    Post,
    /// PUT.
    Put,
    /// DELETE.
    Delete,
}

/// A request body.
pub enum Body {
    /// No body.
    Empty,
    /// A JSON body (`Content-Type: application/json`).
    Json(Vec<u8>),
    /// A streamed body of exactly `len` bytes
    /// (`Content-Type: application/octet-stream`, `Content-Length: len`,
    /// never chunked). The transport reads `reader` in bounded pieces.
    Stream {
        /// Exact length; sent as `Content-Length`.
        len: u64,
        /// The bytes.
        reader: Box<dyn Read + Send>,
    },
}

impl fmt::Debug for Body {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("Empty"),
            Self::Json(b) => write!(f, "Json({} bytes)", b.len()),
            Self::Stream { len, .. } => write!(f, "Stream({len} bytes)"),
        }
    }
}

/// One request.
#[derive(Debug)]
pub struct Request {
    /// Method.
    pub method: Method,
    /// Path and query, starting with `/v1/`.
    pub path: String,
    /// `If-Match` value, if any.
    pub if_match: Option<String>,
    /// Body.
    pub body: Body,
}

/// One response. The body is read lazily, so a large download is never
/// held in memory.
pub struct Response {
    /// Status code.
    pub status: u16,
    /// `ETag`, if present and well formed (see [`clean_etag`]).
    pub etag: Option<String>,
    /// `Content-Length`, if present.
    pub content_length: Option<u64>,
    /// The body.
    pub body: Box<dyn Read + Send>,
}

impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("etag", &self.etag)
            .field("content_length", &self.content_length)
            .finish_non_exhaustive()
    }
}

/// Sends requests to the server.
pub trait Transport {
    /// Sends `req` and returns the response head with a readable body.
    ///
    /// # Errors
    ///
    /// [`ClientError::Transport`] if the connection, the TLS handshake or
    /// the exchange fails.
    fn send(&mut self, req: Request) -> Result<Response, ClientError>;
}

/// An entity tag fit to send in `If-Match`: at most
/// [`MAX_IF_MATCH_BYTES`] bytes of visible ASCII. Anything else is dropped
/// rather than echoed.
#[must_use]
pub fn clean_etag(value: &[u8]) -> Option<String> {
    if value.is_empty()
        || value.len() > MAX_IF_MATCH_BYTES
        || !value.iter().all(|b| b.is_ascii_graphic())
    {
        return None;
    }
    String::from_utf8(value.to_vec()).ok()
}

/// A failed API call.
#[derive(Debug)]
#[non_exhaustive]
pub enum ClientError {
    /// The connection or TLS handshake failed, or the exchange broke off.
    /// The text is ours (TLS failure class, I/O error kind), never server
    /// content.
    Transport(String),
    /// The server refused the request with an error body.
    Api {
        /// Status code.
        status: u16,
        /// The parsed body.
        body: Box<ErrorBody>,
    },
    /// The server refused the request without a readable error body.
    Status(u16),
    /// A response body was over its cap.
    ResponseTooLarge {
        /// The cap in bytes.
        max: u64,
    },
    /// A response body was not what the route returns.
    BadResponse(&'static str),
    /// Reading the response body failed.
    Io(io::ErrorKind),
}

fn status_hint(status: u16) -> &'static str {
    match status {
        401 => {
            " (not authenticated: check that --client-cert and --client-key name \
             an enrolled operator certificate)"
        }
        403 => " (your operator role does not allow this action)",
        412 => " (the item changed since it was read; view it again and retry)",
        _ => "",
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(t) => write!(f, "connection to the server failed: {t}"),
            Self::Api { status, body } => {
                let e = &body.error;
                write!(
                    f,
                    "server refused the request: HTTP {status} {}: {}{}",
                    esc(e.code.as_str()),
                    esc(e.message.as_str()),
                    status_hint(*status)
                )?;
                if let Some(limit) = e.limit_bytes {
                    write!(f, "; limit {limit} bytes")?;
                }
                if let Some(id) = e.existing_id {
                    write!(f, "; existing content {id}")?;
                }
                if !e.dependants.is_empty() {
                    f.write_str("; used by:")?;
                    for p in &e.dependants {
                        write!(f, " {} ({})", p.id, esc(p.name.as_str()))?;
                    }
                }
                Ok(())
            }
            Self::Status(s) => write!(
                f,
                "server refused the request: HTTP {s} with no readable reason{}",
                status_hint(*s)
            ),
            Self::ResponseTooLarge { max } => {
                write!(f, "server response is larger than the {max}-byte limit")
            }
            Self::BadResponse(what) => write!(f, "server response is not valid: {what}"),
            Self::Io(k) => write!(f, "reading the server response failed: {k}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// Reads at most `max` bytes of `r`; more is an error.
///
/// # Errors
///
/// [`ClientError::ResponseTooLarge`] or [`ClientError::Io`].
pub fn read_capped(r: &mut dyn Read, max: u64) -> Result<Vec<u8>, ClientError> {
    let mut buf = Vec::new();
    r.take(max.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| ClientError::Io(e.kind()))?;
    if u64::try_from(buf.len()).map_or(true, |n| n > max) {
        return Err(ClientError::ResponseTooLarge { max });
    }
    Ok(buf)
}

/// A successful response body with its entity tag.
#[derive(Debug)]
pub struct Raw {
    /// The body bytes (at most [`MAX_RESPONSE_JSON_BYTES`]).
    pub bytes: Vec<u8>,
    /// The `ETag`, if the server sent a well-formed one.
    pub etag: Option<String>,
}

/// Parses a [`Raw`] response body as the JSON type the binding asks for.
/// Every API response type denies unknown fields (WU-4).
macro_rules! parse_json {
    ($raw:expr) => {
        serde_json::from_slice(&$raw.bytes).map_err(|_| {
            $crate::client::ClientError::BadResponse("body is not the JSON this route returns")
        })
    };
}

/// Serialises a request value as a JSON [`Body`].
macro_rules! json_body {
    ($value:expr) => {
        serde_json::to_vec($value)
            .map($crate::client::Body::Json)
            .map_err(|_| $crate::client::ClientError::BadResponse("request could not be encoded"))
    };
}

/// The operator API over a transport.
#[derive(Debug)]
pub struct ApiClient<T> {
    transport: T,
}

impl<T: Transport> ApiClient<T> {
    /// A client on `transport`.
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// The transport (tests inspect it).
    #[cfg(test)]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Sends `req`; returns the response if its status is 2xx, otherwise
    /// the server's refusal.
    ///
    /// # Errors
    ///
    /// [`ClientError`].
    pub fn send(&mut self, req: Request) -> Result<Response, ClientError> {
        let mut resp = self.transport.send(req)?;
        if (200..300).contains(&resp.status) {
            return Ok(resp);
        }
        Err(refusal(&mut resp))
    }

    /// GET `path`; the body is capped at [`MAX_RESPONSE_JSON_BYTES`].
    ///
    /// # Errors
    ///
    /// [`ClientError`].
    pub fn get(&mut self, path: String) -> Result<Raw, ClientError> {
        self.call(Method::Get, path, None, Body::Empty)
    }

    /// GET `path` and return the raw body bytes (at most `max`).
    ///
    /// # Errors
    ///
    /// [`ClientError`].
    pub fn get_bytes(&mut self, path: String, max: u64) -> Result<Vec<u8>, ClientError> {
        let mut resp = self.send(Request {
            method: Method::Get,
            path,
            if_match: None,
            body: Body::Empty,
        })?;
        read_capped(&mut resp.body, max)
    }

    /// Sends `body`; the response body is capped at
    /// [`MAX_RESPONSE_JSON_BYTES`].
    ///
    /// # Errors
    ///
    /// [`ClientError`].
    pub fn call(
        &mut self,
        method: Method,
        path: String,
        if_match: Option<String>,
        body: Body,
    ) -> Result<Raw, ClientError> {
        let mut resp = self.send(Request {
            method,
            path,
            if_match,
            body,
        })?;
        let bytes = read_capped(&mut resp.body, MAX_RESPONSE_JSON_BYTES)?;
        Ok(Raw {
            bytes,
            etag: resp.etag,
        })
    }

    /// DELETE `path` with `If-Match: if_match`. Any response body is
    /// drained up to the error cap and ignored.
    ///
    /// # Errors
    ///
    /// [`ClientError`].
    pub fn delete(&mut self, path: String, if_match: Option<String>) -> Result<(), ClientError> {
        let mut resp = self.send(Request {
            method: Method::Delete,
            path,
            if_match,
            body: Body::Empty,
        })?;
        let _ = read_capped(&mut resp.body, MAX_ERROR_BODY_BYTES);
        Ok(())
    }
}

/// The error for a non-2xx response.
fn refusal(resp: &mut Response) -> ClientError {
    let status = resp.status;
    match read_capped(&mut resp.body, MAX_ERROR_BODY_BYTES) {
        Ok(bytes) => match serde_json::from_slice::<ErrorBody>(&bytes) {
            Ok(body) => ClientError::Api {
                status,
                body: Box::new(body),
            },
            Err(_) => ClientError::Status(status),
        },
        Err(_) => ClientError::Status(status),
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! An in-memory [`Transport`] that replays scripted responses and
    //! records every request, reading streamed bodies in full.

    use std::collections::VecDeque;
    use std::io::Cursor;

    use super::*;

    /// A recorded request.
    #[derive(Debug, Clone)]
    pub struct Seen {
        pub if_match: Option<String>,
        pub body: Vec<u8>,
        pub stream_len: Option<u64>,
    }

    /// A scripted response.
    pub struct Scripted {
        pub status: u16,
        pub etag: Option<String>,
        pub content_length: Option<u64>,
        pub body: Box<dyn Read + Send>,
    }

    impl Scripted {
        pub fn bytes(status: u16, b: Vec<u8>) -> Self {
            Self {
                status,
                etag: None,
                content_length: Some(u64::try_from(b.len()).unwrap()),
                body: Box::new(Cursor::new(b)),
            }
        }

        pub fn with_etag(mut self, e: &str) -> Self {
            self.etag = Some(e.to_owned());
            self
        }
    }

    #[derive(Default)]
    pub struct FakeTransport {
        pub script: VecDeque<(Method, String, Scripted)>,
        pub seen: Vec<Seen>,
    }

    impl FakeTransport {
        pub fn expect(mut self, method: Method, path: &str, r: Scripted) -> Self {
            self.script.push_back((method, path.to_owned(), r));
            self
        }

        pub fn done(&self) -> bool {
            self.script.is_empty()
        }
    }

    impl Transport for FakeTransport {
        fn send(&mut self, req: Request) -> Result<Response, ClientError> {
            let (body, stream_len) = match req.body {
                Body::Empty => (Vec::new(), None),
                Body::Json(b) => (b, None),
                Body::Stream { len, mut reader } => {
                    let mut b = Vec::new();
                    reader
                        .read_to_end(&mut b)
                        .map_err(|e| ClientError::Transport(format!("body read: {}", e.kind())))?;
                    (b, Some(len))
                }
            };
            self.seen.push(Seen {
                if_match: req.if_match,
                body,
                stream_len,
            });
            let Some((m, p, r)) = self.script.pop_front() else {
                return Err(ClientError::Transport("unexpected request".into()));
            };
            assert_eq!((m, p.as_str()), (req.method, req.path.as_str()));
            Ok(Response {
                status: r.status,
                etag: r.etag,
                content_length: r.content_length,
                body: r.body,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::*;
    use super::*;
    use usgp_proto::api::{LimitsView, Message, PackageRef};
    use usgp_proto::{DisplayName, ErrorCode, ids::PackageId};

    #[test]
    fn etag_cleaning() {
        assert_eq!(clean_etag(b"\"r7\""), Some("\"r7\"".to_owned()));
        assert_eq!(clean_etag(b""), None);
        assert_eq!(clean_etag(b"\"r7\"\r\nX: y"), None);
        assert_eq!(clean_etag(b"\"r 7\""), None);
        assert_eq!(clean_etag(&[b'a'; MAX_IF_MATCH_BYTES + 1]), None);
        // The server's full-digest content tag (73 bytes) is kept.
        let content = usgp_proto::api::content_etag(&usgp_common::Sha256Digest([7; 32]));
        assert_eq!(clean_etag(content.as_bytes()), Some(content));
        assert_eq!(clean_etag("\"é\"".as_bytes()), None);
    }

    #[test]
    fn read_capped_limits() {
        let mut r: &[u8] = b"12345";
        assert_eq!(read_capped(&mut r, 5).unwrap(), b"12345");
        let mut r: &[u8] = b"123456";
        assert!(matches!(
            read_capped(&mut r, 5),
            Err(ClientError::ResponseTooLarge { max: 5 })
        ));
    }

    #[test]
    fn ok_json_parsed_with_etag() {
        let v = LimitsView::new(1 << 35, 65536);
        let t = FakeTransport::default().expect(
            Method::Get,
            "/v1/limits",
            Scripted::bytes(200, serde_json::to_vec(&v).unwrap()).with_etag("\"x\""),
        );
        let mut api = ApiClient::new(t);
        let raw = api.get("/v1/limits".into()).unwrap();
        let got: LimitsView = parse_json!(raw).unwrap();
        assert_eq!(got, v);
        assert_eq!(raw.etag.as_deref(), Some("\"x\""));
    }

    #[test]
    fn unknown_response_fields_refused() {
        let t = FakeTransport::default().expect(
            Method::Get,
            "/v1/limits",
            Scripted::bytes(200, br#"{"max_upload_bytes":1,"surprise":2}"#.to_vec()),
        );
        let mut api = ApiClient::new(t);
        let raw = api.get("/v1/limits".into()).unwrap();
        let got: Result<LimitsView, ClientError> = parse_json!(raw);
        assert!(matches!(got, Err(ClientError::BadResponse(_))));
    }

    #[test]
    fn error_body_shown_escaped_with_dependants() {
        let mut body = ErrorBody::new(
            ErrorCode::new("in_use").unwrap(),
            Message::new("used\x1b[31m by packages").unwrap(),
        );
        body.error.dependants.push(PackageRef {
            id: PackageId::parse("1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516").unwrap(),
            name: DisplayName::new("Field laptops").unwrap(),
        });
        let t = FakeTransport::default().expect(
            Method::Delete,
            "/v1/images/x",
            Scripted::bytes(409, serde_json::to_vec(&body).unwrap()),
        );
        let mut api = ApiClient::new(t);
        let e = api.delete("/v1/images/x".into(), None).unwrap_err();
        let text = e.to_string();
        assert!(text.contains("HTTP 409 in_use"), "{text}");
        assert!(!text.contains('\x1b'), "{text}");
        assert!(text.contains("\\u{001b}[31m"), "{text}");
        assert!(
            text.contains("used by: 1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516 (Field laptops)"),
            "{text}"
        );
    }

    #[test]
    fn unreadable_error_body_gives_status_only() {
        let t = FakeTransport::default().expect(
            Method::Get,
            "/v1/limits",
            Scripted::bytes(401, b"<html>\x1b</html>".to_vec()),
        );
        let mut api = ApiClient::new(t);
        let e = api.get("/v1/limits".into()).unwrap_err();
        assert!(matches!(e, ClientError::Status(401)));
        let text = e.to_string();
        assert!(text.contains("not authenticated"), "{text}");
        assert!(!text.contains('\x1b'));
    }

    #[test]
    fn oversized_json_refused() {
        let big = vec![b' '; usize::try_from(MAX_RESPONSE_JSON_BYTES).unwrap() + 1];
        let t =
            FakeTransport::default().expect(Method::Get, "/v1/limits", Scripted::bytes(200, big));
        let mut api = ApiClient::new(t);
        assert!(matches!(
            api.get("/v1/limits".into()),
            Err(ClientError::ResponseTooLarge { .. })
        ));
    }
}
