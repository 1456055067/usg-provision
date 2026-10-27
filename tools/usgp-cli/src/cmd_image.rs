//! `usgp-cli image ...`: upload, list, view, declare, delete and download
//! image files (plan WU-8, section 3.2).
//!
//! Edition names and descriptions come from the WIM file's XML and are
//! bounded only by length (`WimText`), so they, like every other
//! server-supplied string, are shown through [`crate::display::esc`].
//! Each declared fact is shown with its source (`declared` or
//! `verified`, decision 0013).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 - declaration values checked against the closed
//   sets before sending; WIM text escaped on output.
// - NIST 800-53: AC-3 - deletion sends `If-Match` with the tag just read
//   and asks for confirmation.
// - SPEC: specs/os-images.md#REQ-IMG-020, #REQ-IMG-022 (state and reason
//   shown), #REQ-IMG-030, #REQ-IMG-040, #REQ-IMG-042 (editions listed),
//   #REQ-IMG-043 (declared facts with their source), #REQ-IMG-015
//   (in-use refusal names the dependants)
// - SPEC: specs/os-support.md#REQ-OS-005, #REQ-OS-009 (support status and
//   reason shown)

use std::io::{BufRead, Write};

use usgp_proto::api::{
    EditionDeclarationRequest, EditionView, ImageList, ImageView, LimitsView, Reason, SupportView,
    content_etag,
};
use usgp_proto::facts::{EditionFacts, Fact};
use usgp_proto::ids::ContentId;
use usgp_proto::names::EditionIndex;

use crate::client::{ApiClient, Method, Transport};
use crate::cmd_content::{CmdError, confirm};
use crate::display::{esc, utc};

/// Writes `label: value (source)`.
fn fact<T: std::fmt::Display>(f: &Fact<T>) -> String {
    format!("{} ({})", f.value, f.source)
}

/// Writes declared facts.
pub fn print_facts(
    out: &mut dyn Write,
    indent: &str,
    facts: Option<&EditionFacts>,
) -> Result<(), CmdError> {
    match facts {
        Some(f) => writeln!(
            out,
            "{indent}release: {}  edition: {}  architecture: {}",
            fact(&f.release),
            fact(&f.edition),
            fact(&f.architecture)
        )?,
        None => writeln!(out, "{indent}facts: not declared")?,
    }
    Ok(())
}

/// Writes a support status line.
pub fn print_support(out: &mut dyn Write, indent: &str, s: &SupportView) -> Result<(), CmdError> {
    match &s.reason {
        Some(r) => writeln!(out, "{indent}support: {} ({})", s.status, esc(r.as_str()))?,
        None => writeln!(out, "{indent}support: {}", s.status)?,
    }
    Ok(())
}

/// Writes a reason line.
pub fn print_reason(out: &mut dyn Write, label: &str, r: Option<&Reason>) -> Result<(), CmdError> {
    if let Some(r) = r {
        writeln!(
            out,
            "  {label}: {}: {}",
            esc(r.code.as_str()),
            esc(r.message.as_str())
        )?;
    }
    Ok(())
}

fn print_edition(out: &mut dyn Write, e: &EditionView) -> Result<(), CmdError> {
    writeln!(out, "    [{}] {}", e.index.get(), esc(e.name.as_str()))?;
    if !e.description.as_str().is_empty() {
        writeln!(out, "        description: {}", esc(e.description.as_str()))?;
    }
    if let Some(n) = e.total_bytes {
        writeln!(out, "        size: {n} bytes")?;
    }
    print_facts(out, "        ", e.facts.as_ref())?;
    if let (Some(by), Some(at)) = (e.declared_by, e.declared_at) {
        writeln!(
            out,
            "        declared: {} by operator {by}",
            utc(at.as_micros())
        )?;
    }
    print_support(out, "        ", &e.support)
}

/// Writes one image.
///
/// # Errors
///
/// [`CmdError::Output`].
pub fn print_image(out: &mut dyn Write, v: &ImageView, editions: bool) -> Result<(), CmdError> {
    writeln!(out, "image {}", v.id)?;
    writeln!(out, "  name:   {}", esc(v.display_name.as_str()))?;
    writeln!(out, "  file:   {}", esc(v.file_name.as_str()))?;
    writeln!(out, "  size:   {} bytes", v.size)?;
    match &v.sha256 {
        Some(d) => writeln!(out, "  sha256: {d}")?,
        None => writeln!(out, "  sha256: (not yet verified)")?,
    }
    writeln!(out, "  state:  {}", v.state)?;
    print_reason(out, "reason", v.reason.as_ref())?;
    if let Some(c) = v.compression {
        writeln!(out, "  compression: {c}")?;
    }
    if let Some(n) = v.image_count {
        writeln!(
            out,
            "  editions: {n}{}",
            v.boot_index
                .filter(|&b| b != 0)
                .map(|b| format!(" (boot index {b})"))
                .unwrap_or_default()
        )?;
    }
    writeln!(
        out,
        "  uploaded: {} by operator {}",
        utc(v.created_at.as_micros()),
        v.created_by
    )?;
    writeln!(out, "  updated:  {}", utc(v.updated_at.as_micros()))?;
    if editions {
        for e in &v.editions {
            print_edition(out, e)?;
        }
    }
    Ok(())
}

/// `limits`: the limits the server applies (REQ-IMG-031).
///
/// # Errors
///
/// [`CmdError`].
pub fn limits<T: Transport>(api: &mut ApiClient<T>, out: &mut dyn Write) -> Result<(), CmdError> {
    let raw = api.get("/v1/limits".into())?;
    let l: LimitsView = parse_json!(raw)?;
    writeln!(out, "max upload:           {} bytes", l.max_upload_bytes)?;
    writeln!(out, "max JSON request:     {} bytes", l.max_json_bytes)?;
    writeln!(
        out,
        "max display name:     {} characters",
        l.max_display_name_chars
    )?;
    writeln!(
        out,
        "max description:      {} characters",
        l.max_description_chars
    )?;
    writeln!(out, "max file name:        {} bytes", l.max_file_name_bytes)?;
    writeln!(out, "verification chunk:   {} bytes", l.chunk_size)?;
    Ok(())
}

/// `image list`.
///
/// # Errors
///
/// [`CmdError`].
pub fn list<T: Transport>(api: &mut ApiClient<T>, out: &mut dyn Write) -> Result<(), CmdError> {
    let raw = api.get("/v1/images".into())?;
    let list: ImageList = parse_json!(raw)?;
    if list.images.is_empty() {
        writeln!(out, "no image files")?;
    }
    for v in &list.images {
        print_image(out, v, false)?;
    }
    Ok(())
}

/// GET one image with its entity tag.
fn get<T: Transport>(
    api: &mut ApiClient<T>,
    id: ContentId,
) -> Result<(ImageView, Option<String>), CmdError> {
    let raw = api.get(format!("/v1/images/{id}"))?;
    let v: ImageView = parse_json!(raw)?;
    if v.id != id {
        return Err(CmdError::Client(crate::client::ClientError::BadResponse(
            "the server returned a different image",
        )));
    }
    Ok((v, raw.etag))
}

/// `image view ID`.
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
    print_image(out, &v, true)
}

/// The values of `image declare`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declare {
    /// Edition index (1-based).
    pub index: u64,
    /// Release text.
    pub release: String,
    /// Edition text.
    pub edition: String,
    /// Architecture text.
    pub architecture: String,
}

/// `image declare ID --index N --release R --edition E --arch A`
/// (decision 0013).
///
/// # Errors
///
/// [`CmdError::Invalid`] for a value outside the closed sets (nothing is
/// sent), or the server's refusal.
pub fn declare<T: Transport>(
    api: &mut ApiClient<T>,
    id: ContentId,
    d: &Declare,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    let index = EditionIndex::new(d.index)
        .map_err(|_| CmdError::Invalid("--index must be at least 1".into()))?;
    let req = EditionDeclarationRequest {
        release: d.release.clone(),
        edition: d.edition.clone(),
        architecture: d.architecture.clone(),
    };
    let decl = req.validate().map_err(|e| CmdError::Invalid(e.message))?;
    let body = EditionDeclarationRequest::from(&decl);
    let raw = api.call(
        Method::Put,
        format!("/v1/images/{id}/editions/{}/declaration", index.get()),
        None,
        json_body!(&body)?,
    )?;
    let e: EditionView = parse_json!(raw)?;
    writeln!(out, "declared image {id} edition {}", e.index.get())?;
    print_edition(out, &e)?;
    Ok(())
}

/// `image delete ID [--yes]`: reads the image, warns, asks for
/// confirmation unless `yes`, then deletes with `If-Match`.
///
/// # Errors
///
/// [`CmdError`]; [`CmdError::NotConfirmed`] if the operator does not
/// answer `yes`.
pub fn delete<T: Transport>(
    api: &mut ApiClient<T>,
    id: ContentId,
    yes: bool,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CmdError> {
    let (v, etag) = get(api, id)?;
    let tag = etag.or_else(|| v.sha256.as_ref().map(content_etag)).ok_or(
        crate::client::ClientError::BadResponse("the server sent no ETag for the image"),
    )?;
    if !yes {
        confirm(
            &format!(
                "This permanently deletes image {id} ({}, {} editions).",
                esc(v.display_name.as_str()),
                v.editions.len()
            ),
            input,
            err,
        )?;
    }
    api.delete(format!("/v1/images/{id}"), Some(tag))?;
    writeln!(out, "deleted image {id}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::fake::{FakeTransport, Scripted};
    use crate::cmd_content::tests::{ID, id};
    use usgp_proto::api::SupportView;
    use usgp_proto::facts::{Architecture, Edition, Release, SupportState};
    use usgp_proto::ids::{OperatorId, UnixMicros};
    use usgp_proto::names::{DisplayName, FileName, WimText};
    use usgp_proto::status::ContentState;

    pub(crate) fn edition(name: &str) -> EditionView {
        EditionView {
            index: EditionIndex::new(1).unwrap(),
            name: WimText::new(name).unwrap(),
            description: WimText::new("desc\u{202e}x").unwrap(),
            total_bytes: Some(9),
            facts: Some(EditionFacts {
                release: Fact::declared(Release::Windows11),
                edition: Fact::declared(Edition::Enterprise),
                architecture: Fact::declared(Architecture::X64),
            }),
            declared_by: Some(OperatorId::parse("2c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516").unwrap()),
            declared_at: Some(UnixMicros::new(0).unwrap()),
            support: SupportView {
                status: SupportState::Supported,
                reason: None,
            },
        }
    }

    fn image() -> ImageView {
        ImageView {
            id: id(),
            display_name: DisplayName::new("Win 11").unwrap(),
            file_name: FileName::new("install image.wim").unwrap(),
            size: 3,
            sha256: Some(usgp_crypto::sha256(b"abc")),
            state: ContentState::Ready,
            reason: None,
            created_by: OperatorId::parse("2c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516").unwrap(),
            created_at: UnixMicros::new(0).unwrap(),
            updated_at: UnixMicros::new(0).unwrap(),
            compression: None,
            image_count: Some(1),
            boot_index: Some(0),
            editions: vec![edition("Ent\x1b]0;owned\x07 erprise")],
        }
    }

    #[test]
    fn view_escapes_wim_text_and_shows_sources() {
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Get,
            &format!("/v1/images/{ID}"),
            Scripted::bytes(200, serde_json::to_vec(&image()).unwrap()),
        ));
        let mut out = Vec::new();
        view(&mut api, id(), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains('\x1b') && !text.contains('\x07'), "{text}");
        assert!(!text.contains('\u{202e}'), "{text}");
        assert!(
            text.contains("Ent\\u{001b}]0;owned\\u{0007} erprise"),
            "{text}"
        );
        assert!(text.contains("release: windows-11 (declared)"), "{text}");
        assert!(text.contains("architecture: x64 (declared)"), "{text}");
        assert!(text.contains("support: supported"), "{text}");
    }

    #[test]
    fn declare_validates_then_puts() {
        let d = Declare {
            index: 3,
            release: "windows-11".into(),
            edition: "enterprise".into(),
            architecture: "x64".into(),
        };
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Put,
            &format!("/v1/images/{ID}/editions/3/declaration"),
            Scripted::bytes(200, serde_json::to_vec(&edition("E")).unwrap()),
        ));
        declare(&mut api, id(), &d, &mut Vec::new()).unwrap();
        let sent: EditionDeclarationRequest =
            serde_json::from_slice(&api.transport().seen.first().unwrap().body).unwrap();
        assert_eq!(sent.architecture, "x64");

        let mut api = ApiClient::new(FakeTransport::default());
        for bad in [
            Declare {
                index: 0,
                ..d.clone()
            },
            Declare {
                release: "windows-12".into(),
                ..d.clone()
            },
            Declare {
                edition: "Enterprise".into(),
                ..d.clone()
            },
            Declare {
                architecture: "amd64".into(),
                ..d.clone()
            },
        ] {
            assert!(matches!(
                declare(&mut api, id(), &bad, &mut Vec::new()),
                Err(CmdError::Invalid(_))
            ));
        }
        assert!(api.transport().seen.is_empty());
    }

    #[test]
    fn delete_uses_etag_and_confirms() {
        let script = || {
            FakeTransport::default()
                .expect(
                    Method::Get,
                    &format!("/v1/images/{ID}"),
                    Scripted::bytes(200, serde_json::to_vec(&image()).unwrap())
                        .with_etag("\"sha256:abc\""),
                )
                .expect(
                    Method::Delete,
                    &format!("/v1/images/{ID}"),
                    Scripted::bytes(204, Vec::new()),
                )
        };
        let mut api = ApiClient::new(script());
        let mut err = Vec::new();
        delete(
            &mut api,
            id(),
            false,
            &mut &b"yes\n"[..],
            &mut Vec::new(),
            &mut err,
        )
        .unwrap();
        let del = api.transport().seen.get(1).unwrap();
        assert_eq!(del.if_match.as_deref(), Some("\"sha256:abc\""));
        assert!(
            String::from_utf8(err)
                .unwrap()
                .contains("permanently deletes image")
        );

        let mut api = ApiClient::new(script());
        let e = delete(
            &mut api,
            id(),
            false,
            &mut &b"no\n"[..],
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(e, CmdError::NotConfirmed));
        assert_eq!(
            api.transport().seen.len(),
            1,
            "no DELETE without confirmation"
        );
    }
}
