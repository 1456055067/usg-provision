//! Fuzz target `device_session_msgs`: the device session protocol bodies
//! (`usgp-proto` `device`, `progress`), as the server's device listener
//! parses requests (`parse_request` with `MAX_DEVICE_JSON_BYTES`) and as
//! the pre-boot agent parses responses, and the text forms of the
//! session's identifiers and secrets.
//!
//! Octet 0 selects (modulo 14); the rest is the input:
//!
//! - requests: 0 `DeviceHelloV1`, 1 `CodeSubmitV1`, 2 `ChoosePackageV1`,
//!   3 `ChooseDiskV1`, 4 `ConfirmV1`, 5 `CancelV1`, 6 `EndSessionV1`,
//!   7 `ProgressV1` (then `validate`);
//! - responses: 8 `SessionOpenedV1`, 9 `SessionStatusV1`,
//!   10 `DevicePackageListV1`, 11 `ProgressAckV1`,
//!   12 `ConfirmedV1::from_json`;
//! - 13: octet 1 selects a text parser (modulo 8): `MacAddress`,
//!   `SessionToken::parse`, `SessionToken::from_authorization`,
//!   `AuthCode`, `DisplayCode`, `AgentNonce`, `DiskToken`, `DiskGuid`.
//!
//! Invariants (plan WU-14 "server-side body parsing and validation"):
//!
//! - no panic; `body_too_large` exactly over the cap, before parsing; a
//!   parser detail is at most 200 characters;
//! - every accepted body re-serializes and re-parses to itself (types
//!   without `PartialEq`, which hold secrets, to the same JSON);
//! - secrets: a refused `CodeSubmitV1` or `SessionOpenedV1` never echoes
//!   the code or token string in its error, and an accepted one never
//!   shows it in `Debug`;
//! - text forms: MAC addresses follow a reference model (17 characters of
//!   hex pairs and colons, unicast, not all zero) and print in canonical
//!   lower case; codes normalise per the reference model (separators
//!   dropped, Crockford aliases folded, 10 symbols) and their grouped and
//!   normalised forms parse back to the same code; display codes print as
//!   `XXX-XXX` and parse back; tokens and nonces round-trip through their
//!   byte forms; a token is accepted from `Authorization` only after a
//!   case-insensitive `Bearer `; disk tokens are exactly 32 lower-case hex
//!   digits; disk GUIDs are never nil and print in canonical form.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), IA-5 (secret codes
//   and tokens never echoed), SC-8, SA-11 (Developer Testing and
//   Evaluation)
// - SPEC: specs/targeting.md#REQ-TGT-004 to #REQ-TGT-016
// - SPEC: specs/disk.md#REQ-DISK-003, #REQ-DISK-006
// - SPEC: specs/progress.md#REQ-JOB-005, #REQ-JOB-008
// - RFC 8259 (JSON); RFC 6750 §2.1 (Bearer); RFC 4648 §4, §5 (base64);
//   Crockford base32 symbol set

use std::fmt::Debug;

use libfuzzer_sys::fuzz_target;
use serde::Serialize;
use serde::de::DeserializeOwned;
use usgp_proto::api::{RequestError, parse_request};
use usgp_proto::device::{
    AgentNonce, AuthCode, CancelV1, ChooseDiskV1, ChoosePackageV1, CodeSubmitV1, ConfirmV1,
    ConfirmedV1, DeviceHelloV1, DevicePackageListV1, DisplayCode, EndSessionV1, MacAddress,
    SessionOpenedV1, SessionStatusV1, SessionToken,
};
use usgp_proto::disk::{DiskGuid, DiskToken};
use usgp_proto::limits::{MAX_AUTH_CODE_INPUT_BYTES, MAX_DEVICE_JSON_BYTES};
use usgp_proto::progress::{ProgressAckV1, ProgressV1};

fn check_error(e: &RequestError, len: usize) {
    let _ = e.to_error_body();
    match e {
        RequestError::TooLarge { len: l, max } => {
            assert_eq!((*l, *max), (len, MAX_DEVICE_JSON_BYTES));
            assert!(len > MAX_DEVICE_JSON_BYTES, "too large under the cap");
        }
        RequestError::Json { detail } => {
            assert!(len <= MAX_DEVICE_JSON_BYTES, "parsed a body over the cap");
            assert!(detail.chars().count() <= 200, "detail over 200 chars");
        }
        _ => {}
    }
}

/// A request body with `PartialEq`: parse, then the wire round trip.
fn request<T: DeserializeOwned + Serialize + PartialEq + Debug>(body: &[u8]) -> Option<T> {
    match parse_request::<T>(body, MAX_DEVICE_JSON_BYTES) {
        Ok(v) => {
            let json = serde_json::to_vec(&v).expect("body serializes");
            let again: T = parse_request(&json, usize::MAX).expect("own JSON re-parses");
            assert_eq!(again, v, "body does not round-trip");
            Some(v)
        }
        Err(e) => {
            check_error(&e, body.len());
            None
        }
    }
}

/// A body holding a secret (no `PartialEq`): same JSON after a round trip.
fn secret_body<T: DeserializeOwned + Serialize + Debug>(body: &[u8], key: &str) {
    let secret = string_value(body, key);
    let shown = match parse_request::<T>(body, MAX_DEVICE_JSON_BYTES) {
        Ok(v) => {
            let json = serde_json::to_vec(&v).expect("body serializes");
            let again: T = parse_request(&json, usize::MAX).expect("own JSON re-parses");
            assert_eq!(serde_json::to_vec(&again).ok(), Some(json), "not stable");
            format!("{v:?}")
        }
        Err(e) => {
            check_error(&e, body.len());
            format!("{e} {:?}", e.to_error_body())
        }
    };
    // Echo check, differential: the value counts as shown only if it
    // appears in what is shown for this body and not in what is shown when
    // the value is replaced by a placeholder of the same length (so field
    // names and fixed text that happen to contain it do not count).
    if let Some(s) = &secret
        && shown.contains(s.as_str())
    {
        let fill = if s.contains('Q') { "Z" } else { "Q" };
        let text = std::str::from_utf8(body).unwrap_or_default();
        let other = text.replace(s.as_str(), &fill.repeat(s.len()));
        let shown2 = match parse_request::<T>(other.as_bytes(), MAX_DEVICE_JSON_BYTES) {
            Ok(v) => format!("{v:?}"),
            Err(e) => format!("{e} {:?}", e.to_error_body()),
        };
        assert!(
            shown2.contains(s.as_str()),
            "secret echoed in an error or Debug"
        );
    }
}

/// The plain string value of `"key":"..."` if it occurs once in `body`,
/// is at least 6 characters, and occurs nowhere else in the body.
fn string_value(body: &[u8], key: &str) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let pat = format!("\"{key}\":\"");
    let start = text.find(&pat)? + pat.len();
    let len = text.get(start..)?.find('"')?;
    let v = text.get(start..start + len)?;
    if v.len() < 6 || v.contains('\\') || text.matches(v).count() != 1 {
        return None;
    }
    Some(v.to_owned())
}

fn progress(body: &[u8]) {
    if let Some(p) = request::<ProgressV1>(body)
        && p.validate().is_ok()
    {
        let json = serde_json::to_vec(&p).expect("serializes");
        let again: ProgressV1 = serde_json::from_slice(&json).expect("re-parses");
        assert!(again.validate().is_ok(), "validated report no longer valid");
    }
}

fn confirmed(body: &[u8]) {
    if let Ok(c) = ConfirmedV1::from_json(body) {
        let json = serde_json::to_vec(&c).expect("serializes");
        let again = ConfirmedV1::from_json(&json).expect("re-parses");
        assert_eq!(again, c, "confirm response does not round-trip");
    }
}

// ----------------------------------------------------------------- text --

fn hex(b: u8) -> Option<u8> {
    char::from(b)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

fn mac(text: &str) {
    let b = text.as_bytes();
    let model = (b.len() == 17)
        .then(|| {
            let mut o = [0u8; 6];
            for (i, x) in o.iter_mut().enumerate() {
                let (hi, lo) = (hex(b[i * 3])?, hex(b[i * 3 + 1])?);
                if i < 5 && b[i * 3 + 2] != b':' {
                    return None;
                }
                *x = (hi << 4) | lo;
            }
            (o != [0; 6] && o[0] & 1 == 0).then_some(o)
        })
        .flatten();
    let got = MacAddress::parse(text);
    assert_eq!(got.as_ref().ok().map(|m| *m.octets()), model, "MAC model");
    if let Ok(m) = got {
        let s = m.to_string();
        assert_eq!(s, text.to_ascii_lowercase(), "MAC not printed canonically");
        assert_eq!(MacAddress::parse(&s), Ok(m));
    }
}

const BASE32: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Code normalisation, written independently: separators dropped,
/// Crockford aliases folded, upper case, symbols from the set.
fn code_model(text: &str, symbols: usize) -> Option<String> {
    let mut out = String::new();
    for c in text.bytes().filter(|&c| c != b'-' && c != b' ') {
        let c = match c.to_ascii_uppercase() {
            b'I' | b'L' => b'1',
            b'O' => b'0',
            c => c,
        };
        if !BASE32.contains(&c) {
            return None;
        }
        out.push(char::from(c));
    }
    (out.len() == symbols).then_some(out)
}

fn auth_code(text: &str) {
    let model = if text.len() > MAX_AUTH_CODE_INPUT_BYTES {
        None
    } else {
        code_model(text, 10)
    };
    let got = AuthCode::parse(text);
    assert_eq!(
        got.as_ref().ok().map(|c| c.normalized().to_owned()),
        model,
        "code model"
    );
    if let Ok(c) = got {
        let g = c.grouped();
        assert_eq!(g.len(), 11, "grouped form");
        for t in [g.as_str(), c.normalized()] {
            let back = AuthCode::parse(t).expect("own form parses");
            assert_eq!(back.normalized(), c.normalized(), "code form unstable");
        }
        assert!(!format!("{c:?}").contains(c.normalized()), "code in Debug");
    }
}

fn display_code(text: &str) {
    // 16: the crate's input bound for a display code (typed by an operator).
    let model = if text.len() > 16 {
        None
    } else {
        code_model(text, 6)
    };
    let got = DisplayCode::parse(text);
    assert_eq!(got.is_ok(), model.is_some(), "display code model");
    if let (Ok(d), Some(m)) = (got, model) {
        let s = d.as_str();
        assert_eq!(s.len(), 7, "XXX-XXX");
        assert_eq!(s.replace('-', ""), m, "display code symbols");
        assert_eq!(s.as_bytes()[3], b'-', "separator");
        assert_eq!(DisplayCode::parse(s), Ok(d));
    }
}

fn token(text: &str) {
    if let Ok(t) = SessionToken::parse(text) {
        assert_eq!(t.expose(), text, "token text changed");
        assert_eq!(text.len(), 43, "token length");
        assert!(!format!("{t:?}").contains(text), "token in Debug");
        let av = t.authorization_value();
        let back = SessionToken::from_authorization(av.as_bytes()).expect("own header");
        assert_eq!(back.expose(), text);
    }
    // The byte form always round-trips.
    let mut b = [0u8; 32];
    for (d, s) in b.iter_mut().zip(text.bytes()) {
        *d = s;
    }
    let t = SessionToken::from_random_bytes(&b);
    let again = SessionToken::parse(t.expose()).expect("own token parses");
    assert_eq!(again.expose(), t.expose());
}

fn authorization(value: &[u8]) {
    let got = SessionToken::from_authorization(value);
    let model = value
        .get(..7)
        .is_some_and(|s| s.eq_ignore_ascii_case(b"Bearer "))
        && std::str::from_utf8(&value[7..])
            .ok()
            .is_some_and(|r| SessionToken::parse(r).is_ok());
    assert_eq!(got.is_some(), model, "Authorization model");
    if let Some(t) = got {
        assert_eq!(t.expose().as_bytes(), &value[7..]);
    }
}

fn nonce(text: &str) {
    if let Ok(n) = AgentNonce::parse(text) {
        assert_eq!(text.len(), 44, "nonce length");
        let s = n.to_string();
        assert_eq!(AgentNonce::parse(&s), Ok(n), "nonce round trip");
    }
}

fn disk_token(text: &str) {
    let model = text.len() == 32
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let got = DiskToken::parse(text);
    assert_eq!(got.is_ok(), model, "disk token model");
    if let Ok(t) = got {
        assert_eq!(t.to_string(), text, "disk token text");
    }
}

fn disk_guid(text: &str) {
    if let Ok(g) = DiskGuid::parse(text) {
        assert_eq!(text.len(), 36);
        assert_ne!(g.text_order_bytes(), &[0u8; 16], "nil GUID accepted");
        let s = g.to_string();
        assert_eq!(s, text.to_ascii_lowercase(), "GUID not canonical");
        assert_eq!(DiskGuid::parse(&s).ok(), Some(g));
    }
}

fn text_value(body: &[u8]) {
    let Some((&sel, rest)) = body.split_first() else {
        return;
    };
    if sel % 8 == 2 {
        authorization(rest);
        return;
    }
    let Ok(t) = std::str::from_utf8(rest) else {
        return;
    };
    match sel % 8 {
        0 => mac(t),
        1 => token(t),
        3 => auth_code(t),
        4 => display_code(t),
        5 => nonce(t),
        6 => disk_token(t),
        _ => disk_guid(t),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, body)) = data.split_first() else {
        return;
    };
    match sel % 14 {
        0 => {
            let _ = request::<DeviceHelloV1>(body);
        }
        1 => secret_body::<CodeSubmitV1>(body, "code"),
        2 => {
            let _ = request::<ChoosePackageV1>(body);
        }
        3 => {
            let _ = request::<ChooseDiskV1>(body);
        }
        4 => {
            let _ = request::<ConfirmV1>(body);
        }
        5 => {
            let _ = request::<CancelV1>(body);
        }
        6 => {
            let _ = request::<EndSessionV1>(body);
        }
        7 => progress(body),
        8 => secret_body::<SessionOpenedV1>(body, "token"),
        9 => {
            let _ = request::<SessionStatusV1>(body);
        }
        10 => {
            let _ = request::<DevicePackageListV1>(body);
        }
        11 => {
            let _ = request::<ProgressAckV1>(body);
        }
        12 => confirmed(body),
        _ => text_value(body),
    }
});
