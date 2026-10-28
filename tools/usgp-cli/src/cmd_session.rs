//! `usgp-cli session list | show | approve | refuse`: device sessions
//! waiting for authorisation (M3 plan WU-13, section 3.5; REQ-TGT-014,
//! REQ-TGT-016).
//!
//! Approval is bound to the display code on the device's screen: the
//! operator types it, and the server checks it equals the session's. With
//! no session id, `approve` lists the sessions awaiting authorisation and
//! picks the one showing that display code; if none or more than one
//! does, nothing is approved and the operator is asked for the id.
//! Device-reported values are shown as claims.

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-3 (Device Identification and Authentication) -
//   approval names the display code read off the device; ambiguity is
//   refused, never guessed.
// - NIST 800-53: AC-3 - the server enforces `device_session.approve`; the
//   CLI shows its refusal.
// - NIST 800-53: SI-10 - ids, states and display codes parsed locally
//   before anything is sent; device text escaped on output.
// - SPEC: specs/targeting.md#REQ-TGT-014 (approval with display code),
//   #REQ-TGT-016 (device identity shown)
// - Decision 0018 item 1

use std::io::Write;

use usgp_proto::device::SessionState;
use usgp_proto::ids::SessionId;
use usgp_proto::ops::{
    ApproveSessionRequest, DeviceSessionList, DeviceSessionView, RefuseSessionRequest,
};
use usgp_proto::{DiskDescriptorV1, DisplayCode, MacList};

use crate::client::{ApiClient, ClientError, Method, Transport};
use crate::cmd_content::CmdError;
use crate::display::{esc, utc};

/// Parses a session id given on the command line.
///
/// # Errors
///
/// [`CmdError::Invalid`].
pub fn session_id(text: &str) -> Result<SessionId, CmdError> {
    SessionId::parse(text).map_err(|e| CmdError::Invalid(format!("ID {}: {e}", esc(text))))
}

/// Parses `--state` for `session list`.
///
/// # Errors
///
/// [`CmdError::Invalid`] naming the allowed values.
pub fn session_state(text: &str) -> Result<SessionState, CmdError> {
    SessionState::parse(text).ok_or_else(|| {
        CmdError::Invalid(format!(
            "--state {}: must be one of awaiting_authorisation, authorised, confirmed, \
             refused, cancelled, expired, ended",
            esc(text)
        ))
    })
}

/// MAC addresses, comma separated.
#[must_use]
pub fn macs(m: &MacList) -> String {
    m.as_slice()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Writes a disk descriptor (REQ-DISK-014), device text escaped.
///
/// # Errors
///
/// [`CmdError::Output`].
pub fn print_disk(out: &mut dyn Write, indent: &str, d: &DiskDescriptorV1) -> Result<(), CmdError> {
    writeln!(
        out,
        "{indent}disk: {} {} serial {} ({}), {} bytes, sectors {}/{}{}",
        d.bus(),
        esc(d.model().as_str()),
        esc(d.serial().as_str()),
        d.disk_token(),
        d.size_bytes(),
        d.logical_sector(),
        d.physical_sector(),
        if d.removable() { ", removable" } else { "" }
    )?;
    for p in d.partitions() {
        writeln!(
            out,
            "{indent}  existing partition {}: {} at {} size {}{}",
            p.index,
            p.kind,
            p.start_bytes,
            p.size_bytes,
            p.label
                .as_ref()
                .map(|l| format!(" label {}", esc(l.as_str())))
                .unwrap_or_default()
        )?;
    }
    Ok(())
}

/// Writes one session.
///
/// # Errors
///
/// [`CmdError::Output`].
pub fn print_session(out: &mut dyn Write, v: &DeviceSessionView) -> Result<(), CmdError> {
    writeln!(out, "session {}", v.id)?;
    writeln!(out, "  state:        {}", v.state)?;
    writeln!(out, "  display code: {}", v.display_code)?;
    writeln!(out, "  waiting since: {}", utc(v.created_at.as_micros()))?;
    writeln!(out, "  last seen:    {}", utc(v.last_seen_at.as_micros()))?;
    writeln!(out, "  expires:      {}", utc(v.expires_at.as_micros()))?;
    writeln!(out, "  source ip:    {}", v.source_ip)?;
    match (&v.boot_service_id, &v.boot_service_name) {
        (Some(id), Some(n)) => writeln!(out, "  boot service: {id} ({})", esc(n.as_str()))?,
        (Some(id), None) => writeln!(out, "  boot service: {id}")?,
        _ => writeln!(
            out,
            "  boot service: none (nothing is offered to this device)"
        )?,
    }
    writeln!(out, "  device (claimed by the device):")?;
    writeln!(out, "    macs:        {}", macs(&v.macs))?;
    writeln!(out, "    firmware:    {}", v.firmware)?;
    writeln!(out, "    arch:        {}", v.arch)?;
    writeln!(out, "    secure boot: {}", v.secure_boot)?;
    writeln!(out, "    memory:      {} bytes", v.memory_bytes)?;
    writeln!(out, "    agent:       {}", esc(v.agent_version.as_str()))?;
    if let Some(m) = v.auth_method {
        writeln!(out, "  authorised by: {m}")?;
    }
    if v.failed_code_attempts > 0 {
        writeln!(out, "  failed code attempts: {}", v.failed_code_attempts)?;
    }
    if let Some(p) = v.chosen_package_id {
        match v.chosen_package_revision {
            Some(r) => writeln!(out, "  package:      {p} revision {r}")?,
            None => writeln!(out, "  package:      {p}")?,
        }
    }
    if let Some(d) = &v.chosen_disk {
        print_disk(out, "  ", d)?;
    }
    Ok(())
}

fn fetch<T: Transport>(
    api: &mut ApiClient<T>,
    state: Option<SessionState>,
) -> Result<Vec<DeviceSessionView>, CmdError> {
    let path = match state {
        Some(s) => format!("/v1/device-sessions?state={s}"),
        None => "/v1/device-sessions".to_owned(),
    };
    let raw = api.get(path)?;
    let list: DeviceSessionList = parse_json!(raw)?;
    if let Some(s) = state
        && list.sessions.iter().any(|v| v.state != s)
    {
        return Err(
            ClientError::BadResponse("the server returned sessions in another state").into(),
        );
    }
    Ok(list.sessions)
}

/// `session list [--state S]`.
///
/// # Errors
///
/// [`CmdError`].
pub fn list<T: Transport>(
    api: &mut ApiClient<T>,
    state: Option<&str>,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    let state = state.map(session_state).transpose()?;
    let sessions = fetch(api, state)?;
    if sessions.is_empty() {
        writeln!(out, "no device sessions")?;
    }
    for v in &sessions {
        print_session(out, v)?;
    }
    Ok(())
}

/// `session show ID`. There is no single-session route; the list is read
/// and the session picked from it.
///
/// # Errors
///
/// [`CmdError`]; [`CmdError::Invalid`] if no session has that id.
pub fn show<T: Transport>(
    api: &mut ApiClient<T>,
    id: SessionId,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    let sessions = fetch(api, None)?;
    let v = sessions
        .iter()
        .find(|v| v.id == id)
        .ok_or_else(|| CmdError::Invalid(format!("no device session {id}")))?;
    print_session(out, v)
}

/// `session approve --display-code CODE [ID]`.
///
/// # Errors
///
/// [`CmdError`]; [`CmdError::Invalid`] for a malformed display code, or
/// when no id is given and not exactly one waiting session shows it.
pub fn approve<T: Transport>(
    api: &mut ApiClient<T>,
    id: Option<SessionId>,
    display_code: &str,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    let code = DisplayCode::parse(display_code)
        .map_err(|e| CmdError::Invalid(format!("--display-code {}: {e}", esc(display_code))))?;
    let id = match id {
        Some(id) => id,
        None => {
            let waiting = fetch(api, Some(SessionState::AwaitingAuthorisation))?;
            let matching: Vec<&DeviceSessionView> =
                waiting.iter().filter(|v| v.display_code == code).collect();
            match matching.as_slice() {
                [one] => one.id,
                [] => {
                    return Err(CmdError::Invalid(format!(
                        "no session awaiting authorisation shows display code {code}; \
                         read it again from the device, or list with: \
                         usgp-cli session list --state awaiting_authorisation"
                    )));
                }
                many => {
                    let ids: Vec<String> = many.iter().map(|v| v.id.to_string()).collect();
                    return Err(CmdError::Invalid(format!(
                        "{} waiting sessions show display code {code} ({}); \
                         give the session ID",
                        many.len(),
                        ids.join(", ")
                    )));
                }
            }
        }
    };
    let req = ApproveSessionRequest::from(&code);
    let raw = api.call(
        Method::Post,
        format!("/v1/device-sessions/{id}/approve"),
        None,
        json_body!(&req)?,
    )?;
    let v: DeviceSessionView = parse_json!(raw)?;
    if v.id != id {
        return Err(ClientError::BadResponse("the server returned a different session").into());
    }
    writeln!(out, "approved session {id}")?;
    print_session(out, &v)
}

/// `session refuse ID [--note T]`.
///
/// # Errors
///
/// [`CmdError`].
pub fn refuse<T: Transport>(
    api: &mut ApiClient<T>,
    id: SessionId,
    note: Option<&str>,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    let req = RefuseSessionRequest {
        note: note.map(str::to_owned),
    };
    req.validate().map_err(|e| CmdError::Invalid(e.message))?;
    let raw = api.call(
        Method::Post,
        format!("/v1/device-sessions/{id}/refuse"),
        None,
        json_body!(&req)?,
    )?;
    let v: DeviceSessionView = parse_json!(raw)?;
    if v.id != id {
        return Err(ClientError::BadResponse("the server returned a different session").into());
    }
    writeln!(out, "refused session {id}")?;
    print_session(out, &v)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::client::fake::{FakeTransport, Scripted};
    use usgp_proto::device::{DeviceArch, FirmwareKind, SecureBootState};
    use usgp_proto::ids::UnixMicros;
    use usgp_proto::names::AgentVersion;
    use usgp_proto::{MacAddress, api::ErrorBody, api::Message, codes};

    pub(crate) const SID: &str = "6a1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6";
    const SID2: &str = "7a1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6";

    pub(crate) fn session(id: &str, code: &str) -> DeviceSessionView {
        DeviceSessionView {
            id: SessionId::parse(id).unwrap(),
            state: SessionState::AwaitingAuthorisation,
            macs: MacList::new(vec![MacAddress::parse("02:00:00:00:00:01").unwrap()]).unwrap(),
            source_ip: "192.0.2.10".parse().unwrap(),
            firmware: FirmwareKind::Uefi,
            arch: DeviceArch::X64,
            secure_boot: SecureBootState::On,
            memory_bytes: 8 << 30,
            agent_version: AgentVersion::new("0.3.0\u{202e}x")
                .unwrap_or_else(|_| AgentVersion::new("0.3.0").unwrap()),
            boot_service_id: None,
            boot_service_name: None,
            display_code: DisplayCode::parse(code).unwrap(),
            auth_method: None,
            failed_code_attempts: 0,
            created_at: UnixMicros::new(0).unwrap(),
            last_seen_at: UnixMicros::new(0).unwrap(),
            expires_at: UnixMicros::new(900_000_000).unwrap(),
            chosen_package_id: None,
            chosen_package_revision: None,
            chosen_disk: None,
        }
    }

    fn list_body(s: Vec<DeviceSessionView>) -> Vec<u8> {
        serde_json::to_vec(&DeviceSessionList { sessions: s }).unwrap()
    }

    const WAITING: &str = "/v1/device-sessions?state=awaiting_authorisation";

    #[test]
    fn approve_by_display_code_finds_the_one_session() {
        let mut approved = session(SID, "ABC-123");
        approved.state = SessionState::Authorised;
        let mut api = ApiClient::new(
            FakeTransport::default()
                .expect(
                    Method::Get,
                    WAITING,
                    Scripted::bytes(
                        200,
                        list_body(vec![session(SID2, "XYZ-789"), session(SID, "ABC-123")]),
                    ),
                )
                .expect(
                    Method::Post,
                    &format!("/v1/device-sessions/{SID}/approve"),
                    Scripted::bytes(200, serde_json::to_vec(&approved).unwrap()),
                ),
        );
        let mut out = Vec::new();
        // Typed in lower case without the hyphen: normalised.
        approve(&mut api, None, "abc123", &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(&format!("approved session {SID}")), "{text}");
        assert!(text.contains("state:        authorised"), "{text}");
        let sent: ApproveSessionRequest =
            serde_json::from_slice(&api.transport().seen.get(1).unwrap().body).unwrap();
        assert_eq!(sent.display_code, "ABC-123");
    }

    #[test]
    fn approve_refuses_none_or_ambiguous_match() {
        for sessions in [
            vec![session(SID2, "XYZ-789")],
            vec![session(SID, "ABC-123"), session(SID2, "ABC-123")],
        ] {
            let mut api = ApiClient::new(FakeTransport::default().expect(
                Method::Get,
                WAITING,
                Scripted::bytes(200, list_body(sessions)),
            ));
            let e = approve(&mut api, None, "ABC-123", &mut Vec::new()).unwrap_err();
            assert!(matches!(e, CmdError::Invalid(_)), "{e}");
            // Only the list was read; nothing was approved.
            assert_eq!(api.transport().seen.len(), 1);
        }
    }

    #[test]
    fn approve_bad_display_code_sends_nothing() {
        let mut api = ApiClient::new(FakeTransport::default());
        for bad in ["", "ABC-12", "ABC-1234", "ABU-123", "\u{1b}[2J"] {
            let e = approve(
                &mut api,
                Some(session_id(SID).unwrap()),
                bad,
                &mut Vec::new(),
            )
            .unwrap_err();
            assert!(matches!(e, CmdError::Invalid(_)), "{bad:?}");
            assert!(!e.to_string().contains('\x1b'));
        }
        assert!(api.transport().seen.is_empty());
    }

    #[test]
    fn approve_with_id_shows_server_mismatch() {
        let body = ErrorBody::new(
            codes::DISPLAY_CODE_MISMATCH,
            Message::new("the display code does not match this session").unwrap(),
        );
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Post,
            &format!("/v1/device-sessions/{SID}/approve"),
            Scripted::bytes(422, serde_json::to_vec(&body).unwrap()),
        ));
        let e = approve(
            &mut api,
            Some(session_id(SID).unwrap()),
            "ABC-123",
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(e.to_string().contains("display_code_mismatch"), "{e}");
    }

    #[test]
    fn list_filters_by_state_and_escapes_device_text() {
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Get,
            WAITING,
            Scripted::bytes(200, list_body(vec![session(SID, "ABC-123")])),
        ));
        let mut out = Vec::new();
        list(&mut api, Some("awaiting_authorisation"), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("display code: ABC-123"), "{text}");
        assert!(text.contains("macs:        02:00:00:00:00:01"), "{text}");
        assert!(text.contains("claimed"), "{text}");
        assert!(!text.contains('\u{202e}'), "{text}");
        let mut api = ApiClient::new(FakeTransport::default());
        assert!(matches!(
            list(&mut api, Some("pending"), &mut Vec::new()),
            Err(CmdError::Invalid(_))
        ));
        assert!(api.transport().seen.is_empty());
    }

    #[test]
    fn list_refuses_sessions_in_another_state() {
        let mut other = session(SID, "ABC-123");
        other.state = SessionState::Confirmed;
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Get,
            WAITING,
            Scripted::bytes(200, list_body(vec![other])),
        ));
        assert!(matches!(
            list(&mut api, Some("awaiting_authorisation"), &mut Vec::new()),
            Err(CmdError::Client(ClientError::BadResponse(_)))
        ));
    }

    #[test]
    fn show_and_refuse() {
        let mut refused = session(SID, "ABC-123");
        refused.state = SessionState::Refused;
        let mut api = ApiClient::new(
            FakeTransport::default()
                .expect(
                    Method::Get,
                    "/v1/device-sessions",
                    Scripted::bytes(200, list_body(vec![session(SID, "ABC-123")])),
                )
                .expect(
                    Method::Get,
                    "/v1/device-sessions",
                    Scripted::bytes(200, list_body(vec![])),
                )
                .expect(
                    Method::Post,
                    &format!("/v1/device-sessions/{SID}/refuse"),
                    Scripted::bytes(200, serde_json::to_vec(&refused).unwrap()),
                ),
        );
        let id = session_id(SID).unwrap();
        let mut out = Vec::new();
        show(&mut api, id, &mut out).unwrap();
        assert!(matches!(
            show(&mut api, id, &mut Vec::new()),
            Err(CmdError::Invalid(_))
        ));
        refuse(&mut api, id, Some("not ours"), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(&format!("refused session {SID}")), "{text}");
        let sent: RefuseSessionRequest =
            serde_json::from_slice(&api.transport().seen.get(2).unwrap().body).unwrap();
        assert_eq!(sent.note.as_deref(), Some("not ours"));
    }
}
