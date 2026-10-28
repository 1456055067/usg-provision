//! `usgp-cli code issue | list | revoke`: operator-issued device codes
//! (M3 plan WU-13, section 3.5; REQ-TGT-013).
//!
//! `code issue` is the only command that ever handles a secret from the
//! server. The code is shown once, on standard output, in the
//! `XXXXX-XXXXX` form; nothing else (errors, standard error, any other
//! command) ever prints it. The response is read into one fixed,
//! zeroizing buffer that is never reallocated, parsed straight into the
//! zeroizing `AuthCode`, and both are wiped when the command returns.
//! `code list` shows records only; the server never sends a code value
//! after issue.

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-5 (Authenticator Management) - the code is displayed
//   once to the issuing operator, held in zeroizing memory, never logged.
// - NIST 800-53: SC-28 - the CLI writes no code value to any file.
// - NIST 800-53: SI-10 - request validated locally against the server's
//   own rules; response size-capped and strictly typed.
// - SPEC: specs/targeting.md#REQ-TGT-013 (issue, list, revoke; values
//   never shown again)
// - Decision 0018 item 1

// POAM: IA-5/SC-4 - the response passes through the TLS stream's and
// hyper's own buffers (`Bytes`) before it reaches the zeroizing buffer
// here, and those are not wiped; `serde_json` may also leave a copy if the
// code string were escaped. Same residual as the usgp-proto and usgp-api
// POAM items for codes and tokens.

use std::io::{Read, Write};

use usgp_proto::ids::AuthCodeId;
use usgp_proto::ops::{AuthCodeIssuedV1, AuthCodeList, AuthCodeView, IssueAuthCodeRequest};
use zeroize::Zeroizing;

use crate::client::{ApiClient, ClientError, Method, Transport};
use crate::cmd_content::CmdError;
use crate::display::{esc, utc};

/// Largest issue response read (the real one is about 120 bytes). The
/// buffer is allocated once at this size and never grows.
const MAX_ISSUE_RESPONSE_BYTES: usize = 4096;

/// Parses a code record id given on the command line.
///
/// # Errors
///
/// [`CmdError::Invalid`].
pub fn code_id(text: &str) -> Result<AuthCodeId, CmdError> {
    AuthCodeId::parse(text).map_err(|e| CmdError::Invalid(format!("ID {}: {e}", esc(text))))
}

/// Writes one code record (no value: records never carry one).
///
/// # Errors
///
/// [`CmdError::Output`].
pub fn print_code(out: &mut dyn Write, v: &AuthCodeView) -> Result<(), CmdError> {
    writeln!(out, "code {}", v.id)?;
    writeln!(out, "  state:   {}", v.state)?;
    writeln!(
        out,
        "  issued:  {} by operator {}",
        utc(v.issued_at.as_micros()),
        v.issued_by
    )?;
    writeln!(out, "  expires: {}", utc(v.expires_at.as_micros()))?;
    if let Some(at) = v.used_at {
        match v.used_by_session {
            Some(s) => writeln!(out, "  used:    {} by session {s}", utc(at.as_micros()))?,
            None => writeln!(out, "  used:    {}", utc(at.as_micros()))?,
        }
    }
    if let Some(at) = v.revoked_at {
        match v.revoked_by {
            Some(by) => writeln!(out, "  revoked: {} by operator {by}", utc(at.as_micros()))?,
            None => writeln!(out, "  revoked: {}", utc(at.as_micros()))?,
        }
    }
    if let Some(n) = &v.note {
        writeln!(out, "  note:    {}", esc(n.as_str()))?;
    }
    Ok(())
}

/// Reads at most [`MAX_ISSUE_RESPONSE_BYTES`] into a buffer allocated
/// once, so no partial copy of the code is left behind by a reallocation.
fn read_secret_body(r: &mut dyn Read) -> Result<Zeroizing<Vec<u8>>, ClientError> {
    let mut buf = Zeroizing::new(vec![0u8; MAX_ISSUE_RESPONSE_BYTES]);
    let mut len = 0usize;
    loop {
        let Some(free) = buf.get_mut(len..) else {
            return Err(ClientError::ResponseTooLarge {
                max: MAX_ISSUE_RESPONSE_BYTES as u64,
            });
        };
        if free.is_empty() {
            // Full: anything more is over the cap.
            let mut probe = [0u8; 1];
            return match r.read(&mut probe) {
                Ok(0) => Ok(truncate(buf, len)),
                Ok(_) => Err(ClientError::ResponseTooLarge {
                    max: MAX_ISSUE_RESPONSE_BYTES as u64,
                }),
                Err(e) => Err(ClientError::Io(e.kind())),
            };
        }
        match r.read(free) {
            Ok(0) => return Ok(truncate(buf, len)),
            Ok(n) => len = len.saturating_add(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(ClientError::Io(e.kind())),
        }
    }
}

/// `buf` cut to `len` in place: the unused tail is wiped first, and
/// truncation never reallocates (`Zeroizing` wipes the whole capacity
/// again on drop).
fn truncate(mut buf: Zeroizing<Vec<u8>>, len: usize) -> Zeroizing<Vec<u8>> {
    use zeroize::Zeroize;
    if let Some(tail) = buf.get_mut(len..) {
        tail.zeroize();
    }
    buf.truncate(len);
    buf
}

/// `code issue [--ttl S] [--note T]`: shows the new code once.
///
/// # Errors
///
/// [`CmdError`]. No error text contains the code.
pub fn issue<T: Transport>(
    api: &mut ApiClient<T>,
    ttl_s: Option<u64>,
    note: Option<&str>,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    let req = IssueAuthCodeRequest {
        ttl_s,
        note: note.map(str::to_owned),
    };
    let v = req.validate().map_err(|e| CmdError::Invalid(e.message))?;
    let body = json_body!(&IssueAuthCodeRequest::from(&v))?;
    let mut resp = api.send(crate::client::Request {
        method: Method::Post,
        path: "/v1/auth-codes".into(),
        if_match: None,
        body,
    })?;
    let bytes = read_secret_body(&mut resp.body)?;
    // `AuthCodeIssuedV1` holds the code in a zeroizing buffer; the parse
    // error is fixed text, never the body.
    let issued: AuthCodeIssuedV1 = serde_json::from_slice(&bytes)
        .map_err(|_| ClientError::BadResponse("body is not the JSON this route returns"))?;
    drop(bytes);
    let shown = issued.code.grouped();
    writeln!(out, "code {}", issued.id)?;
    writeln!(out, "  code:    {}", shown.as_str())?;
    writeln!(out, "  expires: {}", utc(issued.expires_at.as_micros()))?;
    writeln!(
        out,
        "  This code is shown only once. Give it to the person at the device; \
         it works for one device session. Revoke it with: usgp-cli code revoke {}",
        issued.id
    )?;
    Ok(())
}

/// `code list`.
///
/// # Errors
///
/// [`CmdError`].
pub fn list<T: Transport>(api: &mut ApiClient<T>, out: &mut dyn Write) -> Result<(), CmdError> {
    let raw = api.get("/v1/auth-codes".into())?;
    let list: AuthCodeList = parse_json!(raw)?;
    if list.codes.is_empty() {
        writeln!(out, "no codes")?;
    }
    for v in &list.codes {
        print_code(out, v)?;
    }
    Ok(())
}

/// `code revoke ID`.
///
/// # Errors
///
/// [`CmdError`].
pub fn revoke<T: Transport>(
    api: &mut ApiClient<T>,
    id: AuthCodeId,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    let raw = api.call(
        Method::Delete,
        format!("/v1/auth-codes/{id}"),
        None,
        crate::client::Body::Empty,
    )?;
    let v: AuthCodeView = parse_json!(raw)?;
    if v.id != id {
        return Err(ClientError::BadResponse("the server returned a different code").into());
    }
    writeln!(out, "revoked code {id}")?;
    print_code(out, &v)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::client::fake::{FakeTransport, Scripted};
    use usgp_proto::AuthCode;
    use usgp_proto::ids::{OperatorId, UnixMicros};
    use usgp_proto::names::Note;
    use usgp_proto::ops::AuthCodeState;

    pub(crate) const CODE_ID: &str = "4a1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6";
    /// A fixed code for tests (10 Crockford symbols).
    pub(crate) const CODE: &str = "7K3QZ-M9XWD";

    pub(crate) fn issued_json() -> Vec<u8> {
        let v = AuthCodeIssuedV1 {
            id: AuthCodeId::parse(CODE_ID).unwrap(),
            code: AuthCode::parse(CODE).unwrap(),
            expires_at: UnixMicros::new(1_793_097_001_000_000).unwrap(),
        };
        v.to_json_zeroizing().unwrap().to_vec()
    }

    pub(crate) fn view(state: AuthCodeState) -> AuthCodeView {
        AuthCodeView {
            id: AuthCodeId::parse(CODE_ID).unwrap(),
            state,
            issued_by: OperatorId::parse("2c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516").unwrap(),
            issued_at: UnixMicros::new(0).unwrap(),
            expires_at: UnixMicros::new(900_000_000).unwrap(),
            used_at: None,
            used_by_session: None,
            revoked_at: Some(UnixMicros::new(1_000_000).unwrap()),
            revoked_by: None,
            note: Some(Note::new("bench 4 \\ x").unwrap()),
        }
    }

    #[test]
    fn issue_shows_code_exactly_once() {
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Post,
            "/v1/auth-codes",
            Scripted::bytes(201, issued_json()),
        ));
        let mut out = Vec::new();
        issue(&mut api, Some(600), Some("bench 4"), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.matches(CODE).count(), 1, "{text}");
        assert_eq!(text.matches("7K3QZM9XWD").count(), 0, "{text}");
        assert!(text.contains("shown only once"), "{text}");
        let sent: IssueAuthCodeRequest =
            serde_json::from_slice(&api.transport().seen.first().unwrap().body).unwrap();
        assert_eq!(sent.ttl_s, Some(600));
        assert_eq!(sent.note.as_deref(), Some("bench 4"));
    }

    #[test]
    fn issue_validates_before_sending() {
        let mut api = ApiClient::new(FakeTransport::default());
        for (ttl, note) in [(Some(0), None), (Some(86_401), None), (None, Some("a\nb"))] {
            let e = issue(&mut api, ttl, note, &mut Vec::new()).unwrap_err();
            assert!(matches!(e, CmdError::Invalid(_)), "{e}");
        }
        assert!(api.transport().seen.is_empty());
    }

    #[test]
    fn issue_errors_never_contain_the_code() {
        // A body with the code and an unknown field: refused, not echoed.
        let mut bad = String::from_utf8(issued_json()).unwrap();
        bad.insert_str(1, "\"surprise\":1,");
        let big = [issued_json(), vec![b' '; MAX_ISSUE_RESPONSE_BYTES]].concat();
        for body in [bad.into_bytes(), big] {
            let mut api = ApiClient::new(FakeTransport::default().expect(
                Method::Post,
                "/v1/auth-codes",
                Scripted::bytes(201, body),
            ));
            let mut out = Vec::new();
            let e = issue(&mut api, None, None, &mut out).unwrap_err();
            let text = format!("{e} {e:?}");
            assert!(!text.contains("7K3QZ"), "{text}");
            assert!(out.is_empty());
        }
    }

    #[test]
    fn secret_reader_bounds() {
        let mut r: &[u8] = &[b'a'; MAX_ISSUE_RESPONSE_BYTES];
        assert_eq!(
            read_secret_body(&mut r).unwrap().len(),
            MAX_ISSUE_RESPONSE_BYTES
        );
        let mut r: &[u8] = &[b'a'; MAX_ISSUE_RESPONSE_BYTES + 1];
        assert!(matches!(
            read_secret_body(&mut r),
            Err(ClientError::ResponseTooLarge { .. })
        ));
        let mut r: &[u8] = b"";
        assert!(read_secret_body(&mut r).unwrap().is_empty());
    }

    #[test]
    fn list_and_revoke_show_records_escaped() {
        let list = AuthCodeList {
            codes: vec![view(AuthCodeState::Revoked)],
        };
        let mut api = ApiClient::new(
            FakeTransport::default()
                .expect(
                    Method::Get,
                    "/v1/auth-codes",
                    Scripted::bytes(200, serde_json::to_vec(&list).unwrap()),
                )
                .expect(
                    Method::Delete,
                    &format!("/v1/auth-codes/{CODE_ID}"),
                    Scripted::bytes(
                        200,
                        serde_json::to_vec(&view(AuthCodeState::Revoked)).unwrap(),
                    ),
                ),
        );
        let mut out = Vec::new();
        list_then_revoke(&mut api, &mut out);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("state:   revoked"), "{text}");
        // Backslashes doubled by the escaper.
        assert!(text.contains("note:    bench 4 \\\\ x"), "{text}");
        assert!(text.contains(&format!("revoked code {CODE_ID}")), "{text}");
        assert!(api.transport().done());
    }

    fn list_then_revoke(api: &mut ApiClient<FakeTransport>, out: &mut Vec<u8>) {
        list(api, out).unwrap();
        revoke(api, code_id(CODE_ID).unwrap(), out).unwrap();
    }
}
