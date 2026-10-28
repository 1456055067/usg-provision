//! `usgp-cli pe ...`: import, list, view, delete and download Windows PE
//! kits (plan WU-8, section 3.2; decision 0013).
//!
//! `pe import` requires the operator to declare the architecture and the
//! kit version; no default is guessed. The values are checked against the
//! closed sets before anything is sent. Whether the architecture is in
//! scope (x64 only in M2, REQ-PE-005) is the server's decision; its
//! refusal is shown with the reason.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 - declaration checked against closed sets and the
//   kit-version grammar before sending.
// - SPEC: specs/preinstall-env.md#REQ-PE-002 (import), #REQ-PE-005
//   (declared architecture and version, shown with source), #REQ-PE-006
//   (what the operator sees), #REQ-PE-008 (verified download),
//   #REQ-PE-009 (kit warning shown)

use std::io::{BufRead, Write};
use std::path::Path;

use usgp_proto::api::{PeDeclarationRequest, PeList, PeView, content_etag};
use usgp_proto::ids::ContentId;
use usgp_proto::status::ContentKind;

use crate::client::{ApiClient, ClientError, Transport};
use crate::cmd_content::{self, CmdError, confirm};
use crate::cmd_image::print_reason;
use crate::display::{esc, utc};

/// Writes one PE kit.
///
/// # Errors
///
/// [`CmdError::Output`].
pub fn print_pe(out: &mut dyn Write, v: &PeView) -> Result<(), CmdError> {
    writeln!(out, "pe {}", v.id)?;
    writeln!(out, "  name:   {}", esc(v.display_name.as_str()))?;
    writeln!(out, "  file:   {}", esc(v.file_name.as_str()))?;
    writeln!(out, "  size:   {} bytes", v.size)?;
    match &v.sha256 {
        Some(d) => writeln!(out, "  sha256: {d}")?,
        None => writeln!(out, "  sha256: (not yet verified)")?,
    }
    writeln!(out, "  state:  {}", v.state)?;
    print_reason(out, "reason", v.reason.as_ref())?;
    writeln!(
        out,
        "  architecture: {} ({})",
        v.architecture.value, v.architecture.source
    )?;
    writeln!(
        out,
        "  kit version:  {} ({})",
        v.kit_version.value, v.kit_version.source
    )?;
    print_reason(out, "kit warning", v.kit_warning.as_ref())?;
    if let Some(i) = v.usable_index {
        writeln!(out, "  usable image index: {}", i.get())?;
    }
    writeln!(
        out,
        "  imported: {} by operator {}",
        utc(v.imported_at.as_micros()),
        v.imported_by
    )?;
    writeln!(out, "  updated:  {}", utc(v.updated_at.as_micros()))?;
    if v.used_by.is_empty() {
        writeln!(out, "  used by: no packages")?;
    } else {
        writeln!(out, "  used by:")?;
        for p in &v.used_by {
            writeln!(out, "    {} {}", p.id, esc(p.name.as_str()))?;
        }
    }
    Ok(())
}

/// `pe import FILE --name N --arch A --kit-version V`.
///
/// # Errors
///
/// [`CmdError`].
pub fn import<T: Transport>(
    api: &mut ApiClient<T>,
    file: &Path,
    name: &str,
    arch: &str,
    kit_version: &str,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    let decl = PeDeclarationRequest {
        architecture: arch.to_owned(),
        kit_version: kit_version.to_owned(),
    }
    .validate()
    .map_err(|e| CmdError::Invalid(e.message))?;
    let u = cmd_content::upload(api, ContentKind::Pe, file, name, Some(decl))?;
    cmd_content::print_uploaded(out, ContentKind::Pe, &u)
}

/// `pe list`.
///
/// # Errors
///
/// [`CmdError`].
pub fn list<T: Transport>(api: &mut ApiClient<T>, out: &mut dyn Write) -> Result<(), CmdError> {
    let raw = api.get("/v1/pe".into())?;
    let list: PeList = parse_json!(raw)?;
    if list.pe.is_empty() {
        writeln!(out, "no PE kits")?;
    }
    for v in &list.pe {
        print_pe(out, v)?;
    }
    Ok(())
}

/// GET one PE kit and check the server answered for that id.
pub(crate) fn get<T: Transport>(
    api: &mut ApiClient<T>,
    id: ContentId,
) -> Result<(PeView, Option<String>), CmdError> {
    let raw = api.get(format!("/v1/pe/{id}"))?;
    let v: PeView = parse_json!(raw)?;
    if v.id != id {
        return Err(ClientError::BadResponse("the server returned a different PE kit").into());
    }
    Ok((v, raw.etag))
}

/// `pe view ID`.
///
/// # Errors
///
/// [`CmdError`].
pub fn view<T: Transport>(
    api: &mut ApiClient<T>,
    id: ContentId,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    let (v, _) = get(api, id)?;
    print_pe(out, &v)
}

/// `pe delete ID [--yes]`.
///
/// # Errors
///
/// [`CmdError`]; [`CmdError::NotConfirmed`].
pub fn delete<T: Transport>(
    api: &mut ApiClient<T>,
    id: ContentId,
    yes: bool,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CmdError> {
    let (v, etag) = get(api, id)?;
    let tag =
        etag.or_else(|| v.sha256.as_ref().map(content_etag))
            .ok_or(ClientError::BadResponse(
                "the server sent no ETag for the PE kit",
            ))?;
    if !yes {
        let used = if v.used_by.is_empty() {
            String::new()
        } else {
            format!(" It is used by {} package(s).", v.used_by.len())
        };
        confirm(
            &format!(
                "This permanently deletes PE kit {id} ({}).{used}",
                esc(v.display_name.as_str())
            ),
            input,
            err,
        )?;
    }
    api.delete(format!("/v1/pe/{id}"), Some(tag))?;
    writeln!(out, "deleted pe {id}")?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::client::Method;
    use crate::client::fake::{FakeTransport, Scripted};
    use crate::cmd_content::tests::{ID, id};
    use crate::config::tests::TempDir;
    use usgp_proto::api::{CreateUploadRequest, PackageRef, Reason};
    use usgp_proto::facts::{Architecture, Fact, KitVersion};
    use usgp_proto::ids::{OperatorId, PackageId, UnixMicros};
    use usgp_proto::names::{DisplayName, EditionIndex, FileName};
    use usgp_proto::status::ContentState;
    use usgp_proto::{ErrorCode, api::Message};

    pub(crate) fn pe() -> PeView {
        PeView {
            id: id(),
            display_name: DisplayName::new("PE x64").unwrap(),
            file_name: FileName::new("boot.wim").unwrap(),
            size: 3,
            sha256: None,
            state: ContentState::Ready,
            reason: None,
            imported_by: OperatorId::parse("2c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516").unwrap(),
            imported_at: UnixMicros::new(0).unwrap(),
            updated_at: UnixMicros::new(0).unwrap(),
            usable_index: Some(EditionIndex::new(1).unwrap()),
            architecture: Fact::declared(Architecture::X64),
            kit_version: Fact::declared(KitVersion::parse("10.1.26100.1").unwrap()),
            kit_warning: Some(Reason {
                code: ErrorCode::new("kit_known_bad").unwrap(),
                message: Message::new("known bad\x1b[0m").unwrap(),
            }),
            used_by: vec![PackageRef {
                id: PackageId::parse("1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516").unwrap(),
                name: DisplayName::new("Laptops").unwrap(),
            }],
        }
    }

    #[test]
    fn view_shows_declared_facts_and_warning_escaped() {
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Get,
            &format!("/v1/pe/{ID}"),
            Scripted::bytes(200, serde_json::to_vec(&pe()).unwrap()),
        ));
        let mut out = Vec::new();
        view(&mut api, id(), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("architecture: x64 (declared)"), "{text}");
        assert!(
            text.contains("kit version:  10.1.26100.1 (declared)"),
            "{text}"
        );
        assert!(
            text.contains("kit warning: kit_known_bad: known bad\\u{001b}[0m"),
            "{text}"
        );
        assert!(text.contains("Laptops"), "{text}");
        assert!(!text.contains('\x1b'));
    }

    #[test]
    fn import_requires_valid_declaration() {
        let t = TempDir::new("peimp");
        let f = t.put("boot.wim", b"abc", 0o600);
        let mut api = ApiClient::new(FakeTransport::default());
        for (arch, ver) in [
            ("amd64", "10.1.26100.1"),
            ("x64", "10"),
            ("x64", "10.01.1"),
            ("", ""),
        ] {
            let e = import(&mut api, &f, "PE", arch, ver, &mut Vec::new()).unwrap_err();
            assert!(matches!(e, CmdError::Invalid(_)), "{arch} {ver}");
        }
        assert!(api.transport().seen.is_empty());
    }

    #[test]
    fn import_sends_non_x64_and_shows_server_refusal() {
        // Scope is the server's decision (REQ-PE-005); the CLI shows it.
        let t = TempDir::new("pex86");
        let f = t.put("boot.wim", b"abc", 0o600);
        let body = usgp_proto::api::ErrorBody::new(
            ErrorCode::new("pe_architecture_not_supported:x86").unwrap(),
            Message::new("only x64 PE kits are accepted").unwrap(),
        );
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Post,
            "/v1/uploads",
            Scripted::bytes(422, serde_json::to_vec(&body).unwrap()),
        ));
        let e = import(&mut api, &f, "PE", "x86", "10.1.26100.1", &mut Vec::new()).unwrap_err();
        assert!(
            e.to_string().contains("pe_architecture_not_supported:x86"),
            "{e}"
        );
        let sent: CreateUploadRequest =
            serde_json::from_slice(&api.transport().seen.first().unwrap().body).unwrap();
        assert_eq!(sent.kind, "pe");
        assert_eq!(sent.pe_declaration.unwrap().architecture, "x86");
    }

    #[test]
    fn delete_without_etag_or_digest_refused() {
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Get,
            &format!("/v1/pe/{ID}"),
            Scripted::bytes(200, serde_json::to_vec(&pe()).unwrap()),
        ));
        let e = delete(
            &mut api,
            id(),
            true,
            &mut &b""[..],
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(e.to_string().contains("no ETag"), "{e}");
        assert_eq!(api.transport().seen.len(), 1);
    }
}
