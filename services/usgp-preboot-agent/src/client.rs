//! The device session protocol (plan sections 3.1, 3.3 and 3.4) as typed
//! calls: [`DeviceApi`], implemented over HTTPS by [`DeviceClient`].
//!
//! The client keeps the session token in a zeroizing [`SessionToken`] and
//! sends it only as the bearer of requests inside TLS. Request bodies that
//! hold a secret (the typed code) are built in zeroizing buffers, and every
//! response body is read into one. Responses are size-capped and parsed
//! into the strict `usgp-proto` types (unknown fields refused). Error
//! responses keep only the status, the reason code, a sanitised message
//! and `attempts_left`.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-8, SC-23 (Session Authenticity) - bearer token only
//   inside server-authenticated TLS.
// - NIST 800-53: SI-10 (Information Input Validation) - capped bodies,
//   strict types.
// - NIST 800-53: IA-5(1)(c), SC-28 - token and code in zeroizing buffers;
//   never logged or shown.
// - SPEC: specs/targeting.md#REQ-TGT-012..015
// - SPEC: specs/preinstall-env.md#REQ-PE-015

use std::time::Duration;

use usgp_common::Sha256Digest;
use usgp_proto::api::ErrorBody;
use usgp_proto::device::{
    CancelV1, ChooseDiskV1, ChoosePackageV1, CodeSubmitV1, ConfirmV1, ConfirmedV1, DeviceHelloV1,
    DevicePackageListV1, EndSessionV1, SessionOpenedV1, SessionStatusV1,
};
use usgp_proto::limits::{CHUNK_SIZE, MAX_DEVICE_JSON_BYTES};
use usgp_proto::progress::{ProgressAckV1, ProgressV1};
use usgp_proto::{AuthCode, DiskDescriptorV1, ErrorCode, JobId, SessionToken};
use zeroize::Zeroizing;

use crate::http::{HttpClient, HttpError, HttpLimits, Method, Request};

const JSON: &str = "application/json";
const OCTETS: &str = "application/octet-stream";
/// Largest package list read (design bound: up to 256 packages, each with
/// a description).
pub const MAX_PACKAGE_LIST_BYTES: usize = 1024 * 1024;
/// Longest server message kept for the screen.
const MAX_MESSAGE_CHARS: usize = 200;

/// Why a call failed. Never carries a token, a code or response content
/// beyond the fields below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiFailure {
    /// The request did not complete.
    Transport {
        /// What failed (fixed text and the TLS class).
        what: String,
        /// A TLS certificate validity failure: the clock may be wrong.
        time_related: bool,
        /// A wait ran out or the connection failed (worth retrying).
        transient: bool,
    },
    /// The server answered with an error status.
    Status {
        /// HTTP status.
        status: u16,
        /// Reason code, if the body had one.
        code: Option<ErrorCode>,
        /// The server's message, sanitised.
        message: Option<String>,
        /// Code attempts left (`code_not_accepted`).
        attempts_left: Option<u32>,
    },
    /// A success response broke the protocol.
    BadResponse(&'static str),
}

impl ApiFailure {
    /// `true` if the server answered `status` with reason `code`.
    #[must_use]
    pub fn is(&self, status: u16, code: ErrorCode) -> bool {
        matches!(self, Self::Status { status: s, code: Some(c), .. } if *s == status && *c == code)
    }

    /// The status, if the server answered.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Status { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// One line for the screen.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Transport {
                what, time_related, ..
            } => {
                if *time_related {
                    format!(
                        "{what}. The server certificate is outside its validity period as this \
                         device sees it: the device clock may be wrong."
                    )
                } else {
                    what.clone()
                }
            }
            Self::Status {
                status,
                code,
                message,
                ..
            } => {
                let code = code.as_ref().map_or("unknown", ErrorCode::as_str);
                match message {
                    Some(m) => format!("the server refused the request ({status} {code}): {m}"),
                    None => format!("the server refused the request ({status} {code})"),
                }
            }
            Self::BadResponse(w) => format!("bad response from the server: {w}"),
        }
    }
}

impl From<HttpError> for ApiFailure {
    fn from(e: HttpError) -> Self {
        let transient = matches!(
            e,
            HttpError::Timeout | HttpError::Io(_) | HttpError::Connect(_) | HttpError::Resolve
        );
        Self::Transport {
            time_related: e.is_time_related(),
            what: e.to_string(),
            transient,
        }
    }
}

/// The device routes, as the session flow and the engine link use them.
pub trait DeviceApi {
    /// `POST /v1/device/sessions`; keeps the returned token for later
    /// calls.
    ///
    /// # Errors
    ///
    /// [`ApiFailure`].
    fn open(&mut self, hello: &DeviceHelloV1) -> Result<SessionOpenedV1, ApiFailure>;

    /// `GET /v1/device/session`.
    ///
    /// # Errors
    ///
    /// [`ApiFailure`].
    fn status(&mut self) -> Result<SessionStatusV1, ApiFailure>;

    /// `POST /v1/device/session/code`.
    ///
    /// # Errors
    ///
    /// [`ApiFailure`]; 422 `code_not_accepted` with `attempts_left`, 403
    /// `session_refused`.
    fn submit_code(&mut self, code: &AuthCode) -> Result<SessionStatusV1, ApiFailure>;

    /// `GET /v1/device/session/packages`.
    ///
    /// # Errors
    ///
    /// [`ApiFailure`].
    fn packages(&mut self) -> Result<DevicePackageListV1, ApiFailure>;

    /// `POST /v1/device/session/package`.
    ///
    /// # Errors
    ///
    /// [`ApiFailure`].
    fn choose_package(&mut self, c: &ChoosePackageV1) -> Result<(), ApiFailure>;

    /// `POST /v1/device/session/disk`.
    ///
    /// # Errors
    ///
    /// [`ApiFailure`].
    fn choose_disk(&mut self, d: &DiskDescriptorV1) -> Result<(), ApiFailure>;

    /// `POST /v1/device/session/confirm`.
    ///
    /// # Errors
    ///
    /// [`ApiFailure`]; 503 `audit_unavailable` when the wipe record could
    /// not be written.
    fn confirm(&mut self, c: &ConfirmV1) -> Result<ConfirmedV1, ApiFailure>;

    /// `POST /v1/device/session/cancel`.
    ///
    /// # Errors
    ///
    /// [`ApiFailure`]; 409 `job_started` after the confirmation.
    fn cancel(&mut self) -> Result<(), ApiFailure>;

    /// `POST /v1/device/session/end`.
    ///
    /// # Errors
    ///
    /// [`ApiFailure`].
    fn end(&mut self, e: &EndSessionV1) -> Result<(), ApiFailure>;

    /// `GET /v1/device/jobs/{job}/content/{sha256}/chunks/{n}`: untrusted
    /// bytes, at most one chunk.
    ///
    /// # Errors
    ///
    /// [`ApiFailure`].
    fn fetch_chunk(
        &mut self,
        job: JobId,
        content: &Sha256Digest,
        n: u64,
    ) -> Result<Vec<u8>, ApiFailure>;

    /// `POST /v1/device/jobs/{job}/progress`.
    ///
    /// # Errors
    ///
    /// [`ApiFailure`].
    fn report(&mut self, job: JobId, r: &ProgressV1) -> Result<ProgressAckV1, ApiFailure>;

    /// Bounds every later request by `request` (and each read or write by
    /// at most `io`), so a call never blocks past the engine's limits.
    fn bound_waits(&mut self, request: Duration, io: Duration);
}

/// [`DeviceApi`] over HTTPS.
pub struct DeviceClient {
    http: HttpClient,
    token: Option<SessionToken>,
}

impl std::fmt::Debug for DeviceClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceClient")
            .field("http", &self.http)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl DeviceClient {
    /// A client with no session yet.
    #[must_use]
    pub fn new(http: HttpClient) -> Self {
        Self { http, token: None }
    }

    /// The HTTP client (for the start-up connection check).
    pub fn http(&mut self) -> &mut HttpClient {
        &mut self.http
    }

    fn bearer(&self) -> Result<Zeroizing<String>, ApiFailure> {
        self.token
            .as_ref()
            .map(|t| Zeroizing::new(t.expose().to_owned()))
            .ok_or(ApiFailure::BadResponse("no session"))
    }

    /// Sends a JSON request and returns the 2xx body.
    fn call(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        authed: bool,
        max: usize,
    ) -> Result<Zeroizing<Vec<u8>>, ApiFailure> {
        let token = if authed { Some(self.bearer()?) } else { None };
        let req = Request {
            method,
            path,
            bearer: token.as_ref().map(|t| t.as_str()),
            body: body.map(|b| (JSON, b)),
            accept: JSON,
        };
        let resp = self.http.send(&req, max.max(MAX_DEVICE_JSON_BYTES))?;
        if !(200..300).contains(&resp.status) {
            return Err(error_from(resp.status, &resp.body));
        }
        if !resp.is_media(JSON) {
            return Err(ApiFailure::BadResponse("not JSON"));
        }
        if resp.body.len() > max {
            return Err(ApiFailure::BadResponse("response too large"));
        }
        Ok(resp.body)
    }

    fn json<T: serde::de::DeserializeOwned>(
        &mut self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        max: usize,
    ) -> Result<T, ApiFailure> {
        let b = self.call(method, path, body, true, max)?;
        serde_json::from_slice(&b).map_err(|_| ApiFailure::BadResponse("unexpected JSON"))
    }

    fn post_ok(&mut self, path: &str, body: &[u8]) -> Result<(), ApiFailure> {
        // The choice routes answer with the session status (WU-9); the
        // body is checked to be JSON and otherwise ignored.
        self.call(Method::Post, path, Some(body), true, MAX_DEVICE_JSON_BYTES)
            .map(|_| ())
    }
}

fn to_json<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, ApiFailure> {
    serde_json::to_vec(v).map_err(|_| ApiFailure::BadResponse("cannot encode the request"))
}

/// Builds an [`ApiFailure::Status`] from an error response. A body that is
/// not the error shape keeps only the status.
fn error_from(status: u16, body: &[u8]) -> ApiFailure {
    let parsed = (body.len() <= MAX_DEVICE_JSON_BYTES)
        .then(|| serde_json::from_slice::<ErrorBody>(body).ok())
        .flatten();
    match parsed {
        Some(e) => ApiFailure::Status {
            status,
            code: Some(e.error.code),
            message: Some(sanitise(e.error.message.as_str())),
            attempts_left: e.error.attempts_left,
        },
        None => ApiFailure::Status {
            status,
            code: None,
            message: None,
            attempts_left: None,
        },
    }
}

/// Printable characters only, at most [`MAX_MESSAGE_CHARS`].
#[must_use]
pub fn sanitise(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_MESSAGE_CHARS)
        .collect()
}

impl DeviceApi for DeviceClient {
    fn open(&mut self, hello: &DeviceHelloV1) -> Result<SessionOpenedV1, ApiFailure> {
        let body = to_json(hello)?;
        let b = self.call(
            Method::Post,
            "/v1/device/sessions",
            Some(&body),
            false,
            MAX_DEVICE_JSON_BYTES,
        )?;
        let opened: SessionOpenedV1 =
            serde_json::from_slice(&b).map_err(|_| ApiFailure::BadResponse("unexpected JSON"))?;
        self.token = Some(
            SessionToken::parse(opened.token.expose())
                .map_err(|_| ApiFailure::BadResponse("bad session token"))?,
        );
        Ok(opened)
    }

    fn status(&mut self) -> Result<SessionStatusV1, ApiFailure> {
        self.json(
            Method::Get,
            "/v1/device/session",
            None,
            MAX_DEVICE_JSON_BYTES,
        )
    }

    fn submit_code(&mut self, code: &AuthCode) -> Result<SessionStatusV1, ApiFailure> {
        let code = AuthCode::parse(code.normalized())
            .map_err(|_| ApiFailure::BadResponse("cannot encode the request"))?;
        let body = CodeSubmitV1 { code }
            .to_json_zeroizing()
            .map_err(|_| ApiFailure::BadResponse("cannot encode the request"))?;
        self.json(
            Method::Post,
            "/v1/device/session/code",
            Some(&body),
            MAX_DEVICE_JSON_BYTES,
        )
    }

    fn packages(&mut self) -> Result<DevicePackageListV1, ApiFailure> {
        self.json(
            Method::Get,
            "/v1/device/session/packages",
            None,
            MAX_PACKAGE_LIST_BYTES,
        )
    }

    fn choose_package(&mut self, c: &ChoosePackageV1) -> Result<(), ApiFailure> {
        self.post_ok("/v1/device/session/package", &to_json(c)?)
    }

    fn choose_disk(&mut self, d: &DiskDescriptorV1) -> Result<(), ApiFailure> {
        let body = to_json(&ChooseDiskV1 { disk: d.clone() })?;
        self.post_ok("/v1/device/session/disk", &body)
    }

    fn confirm(&mut self, c: &ConfirmV1) -> Result<ConfirmedV1, ApiFailure> {
        let body = to_json(c)?;
        let b = self.call(
            Method::Post,
            "/v1/device/session/confirm",
            Some(&body),
            true,
            usgp_proto::limits::MAX_CONFIRM_RESPONSE_BYTES,
        )?;
        ConfirmedV1::from_json(&b)
            .map_err(|_| ApiFailure::BadResponse("unexpected confirm response"))
    }

    fn cancel(&mut self) -> Result<(), ApiFailure> {
        self.post_ok("/v1/device/session/cancel", &to_json(&CancelV1 {})?)
    }

    fn end(&mut self, e: &EndSessionV1) -> Result<(), ApiFailure> {
        self.post_ok("/v1/device/session/end", &to_json(e)?)
    }

    fn fetch_chunk(
        &mut self,
        job: JobId,
        content: &Sha256Digest,
        n: u64,
    ) -> Result<Vec<u8>, ApiFailure> {
        let path = format!(
            "/v1/device/jobs/{job}/content/{}/chunks/{n}",
            content.to_hex()
        );
        let token = self.bearer()?;
        let req = Request {
            method: Method::Get,
            path: &path,
            bearer: Some(token.as_str()),
            body: None,
            accept: OCTETS,
        };
        let max = usize::try_from(CHUNK_SIZE).unwrap_or(usize::MAX);
        let resp = self.http.send(&req, max.max(MAX_DEVICE_JSON_BYTES))?;
        if !(200..300).contains(&resp.status) {
            return Err(error_from(resp.status, &resp.body));
        }
        if resp.status != 200 || !resp.is_media(OCTETS) || resp.body.len() > max {
            return Err(ApiFailure::BadResponse("unexpected chunk response"));
        }
        // Chunk bytes are image content, not secrets: moved out of the
        // zeroizing buffer as is (the engine verifies them before use).
        Ok(resp.body.to_vec())
    }

    fn report(&mut self, job: JobId, r: &ProgressV1) -> Result<ProgressAckV1, ApiFailure> {
        let path = format!("/v1/device/jobs/{job}/progress");
        let body = to_json(r)?;
        self.json(Method::Post, &path, Some(&body), MAX_DEVICE_JSON_BYTES)
    }

    fn bound_waits(&mut self, request: Duration, io: Duration) {
        let l = self.http.limits();
        self.http.set_limits(HttpLimits {
            request_timeout: l.request_timeout.min(request),
            io_timeout: l.io_timeout.min(io),
            connect_timeout: l.connect_timeout.min(io),
            resolve_timeout: l.resolve_timeout.min(io),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_body_kept_and_sanitised() {
        let b = br#"{"error":{"code":"code_not_accepted","message":"no\nway","attempts_left":3}}"#;
        let e = error_from(422, b);
        assert!(e.is(422, usgp_proto::codes::CODE_NOT_ACCEPTED));
        match e {
            ApiFailure::Status {
                message,
                attempts_left,
                ..
            } => {
                assert_eq!(message.as_deref(), Some("no way"));
                assert_eq!(attempts_left, Some(3));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(error_from(500, b"<html>").status(), Some(500));
    }

    #[test]
    fn time_related_tls_failure_names_the_clock() {
        let e = ApiFailure::Transport {
            what: "TLS handshake refused (expired)".to_owned(),
            time_related: true,
            transient: false,
        };
        assert!(e.describe().contains("device clock may be wrong"));
    }
}
