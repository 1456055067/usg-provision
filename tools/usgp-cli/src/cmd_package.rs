//! `usgp-cli package ...`: create, list, view, edit, clone, delete and
//! fetch the signed manifest of deployment packages (plan WU-8, section
//! 3.2).
//!
//! - `edit` reads the package, replaces only the values given on the
//!   command line, and sends the full definition with `If-Match` set to
//!   the revision it read, so a concurrent change is refused (412) rather
//!   than overwritten (REQ-IMG-012).
//! - `delete` shows what will be deleted and asks for confirmation unless
//!   `--yes` is given (REQ-IMG-014).
//! - `manifest` verifies the package envelope against the pinned content
//!   public key before writing it (plan WU-8).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7(6) - the package manifest is verified with the
//   pinned key before it is written or shown.
// - NIST 800-53: SI-10 - names, descriptions, ids and the edition index
//   are validated before sending.
// - NIST 800-53: AU-10 basis - the signed manifest shows who declared the
//   facts and the audit sequence of the declaration.
// - SPEC: specs/os-images.md#REQ-IMG-010 (create), #REQ-IMG-011 (view),
//   #REQ-IMG-012 (edit, all or nothing), #REQ-IMG-013 (clone),
//   #REQ-IMG-014 (delete with warning and confirmation), #REQ-IMG-041
//   (one edition per package)
// - SPEC: specs/os-support.md#REQ-OS-005, #REQ-OS-009 (status and reason
//   shown); specs/preinstall-env.md#REQ-PE-007 (switch PE by edit)
// - RFC 9110 §13.1.1 (If-Match)

use std::fs::OpenOptions;
use std::io::{self, BufRead, Write};
use std::path::Path;

use usgp_proto::api::{
    ClonePackageRequest, PackageList, PackageRequest, PackageView, package_etag,
};
use usgp_proto::envelope::SignedEnvelopeV1;
use usgp_proto::ids::PackageId;
use usgp_proto::limits::MAX_ENVELOPE_BYTES;
use usgp_proto::names::DisplayName;
use usgp_proto::package_manifest::PackageManifestV1;

use crate::client::{ApiClient, ClientError, Method, Transport};
use crate::cmd_content::{CmdError, PinnedKey, confirm, manifest_error};
use crate::cmd_image::{print_facts, print_reason, print_support};
use crate::display::{esc, utc};

/// Parses a package identifier given on the command line.
///
/// # Errors
///
/// [`CmdError::Invalid`].
pub fn package_id(text: &str) -> Result<PackageId, CmdError> {
    PackageId::parse(text).map_err(|e| CmdError::Invalid(format!("ID {}: {e}", esc(text))))
}

/// Writes one package.
///
/// # Errors
///
/// [`CmdError::Output`].
pub fn print_package(out: &mut dyn Write, v: &PackageView) -> Result<(), CmdError> {
    writeln!(out, "package {}", v.id)?;
    writeln!(out, "  name:        {}", esc(v.name.as_str()))?;
    if let Some(d) = &v.description {
        writeln!(out, "  description: {}", esc(d.as_str()))?;
    }
    writeln!(out, "  revision:    {}", v.revision)?;
    writeln!(out, "  status:      {}", v.status)?;
    print_reason(out, "reason", v.status_reason.as_ref())?;
    let i = &v.image;
    writeln!(
        out,
        "  image:       {} ({}) edition {}: {}",
        i.image_id,
        esc(i.display_name.as_str()),
        i.edition_index.get(),
        esc(i.edition_name.as_str())
    )?;
    print_facts(out, "               ", i.facts.as_ref())?;
    print_support(out, "               ", &i.support)?;
    let p = &v.pe;
    writeln!(
        out,
        "  pe:          {} ({}) architecture {} ({}), kit {} ({})",
        p.pe_id,
        esc(p.display_name.as_str()),
        p.architecture.value,
        p.architecture.source,
        p.kit_version.value,
        p.kit_version.source
    )?;
    print_reason(out, "kit warning", p.kit_warning.as_ref())?;
    writeln!(
        out,
        "  created:     {} by operator {}",
        utc(v.created_at.as_micros()),
        v.created_by
    )?;
    writeln!(out, "  updated:     {}", utc(v.updated_at.as_micros()))?;
    Ok(())
}

/// Values for `package create` and `package edit`. For `edit`, `None`
/// keeps the current value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Definition {
    /// Name.
    pub name: Option<String>,
    /// Description.
    pub description: Option<String>,
    /// Image file id.
    pub image: Option<String>,
    /// Edition index.
    pub index: Option<u64>,
    /// PE kit id.
    pub pe: Option<String>,
}

/// Validates a wire request locally (the server applies the same rules).
fn checked(req: PackageRequest) -> Result<PackageRequest, CmdError> {
    let spec = req.validate().map_err(|e| CmdError::Invalid(e.message))?;
    Ok(PackageRequest::from(&spec))
}

fn send_view<T: Transport>(
    api: &mut ApiClient<T>,
    method: Method,
    path: String,
    if_match: Option<String>,
    body: crate::client::Body,
    out: &mut dyn Write,
    verb: &str,
) -> Result<(), CmdError> {
    let raw = api.call(method, path, if_match, body)?;
    let v: PackageView = parse_json!(raw)?;
    writeln!(out, "{verb} package {}", v.id)?;
    print_package(out, &v)
}

/// `package create --name N [--description D] --image ID --index N --pe ID`.
///
/// # Errors
///
/// [`CmdError`].
pub fn create<T: Transport>(
    api: &mut ApiClient<T>,
    d: &Definition,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    let need = |v: &Option<String>, flag: &str| {
        v.clone()
            .ok_or_else(|| CmdError::Invalid(format!("{flag} is required")))
    };
    let req = checked(PackageRequest {
        name: need(&d.name, "--name")?,
        description: d.description.clone(),
        image_id: need(&d.image, "--image")?,
        edition_index: d
            .index
            .ok_or_else(|| CmdError::Invalid("--index is required".into()))?,
        pe_id: need(&d.pe, "--pe")?,
    })?;
    send_view(
        api,
        Method::Post,
        "/v1/packages".into(),
        None,
        json_body!(&req)?,
        out,
        "created",
    )
}

/// `package list`.
///
/// # Errors
///
/// [`CmdError`].
pub fn list<T: Transport>(api: &mut ApiClient<T>, out: &mut dyn Write) -> Result<(), CmdError> {
    let raw = api.get("/v1/packages".into())?;
    let list: PackageList = parse_json!(raw)?;
    if list.packages.is_empty() {
        writeln!(out, "no packages")?;
    }
    for v in &list.packages {
        print_package(out, v)?;
    }
    Ok(())
}

/// GET one package; the `If-Match` value is its revision tag.
fn get<T: Transport>(
    api: &mut ApiClient<T>,
    id: PackageId,
) -> Result<(PackageView, String), CmdError> {
    let raw = api.get(format!("/v1/packages/{id}"))?;
    let v: PackageView = parse_json!(raw)?;
    if v.id != id {
        return Err(ClientError::BadResponse("the server returned a different package").into());
    }
    let tag = package_etag(v.revision);
    if raw.etag.as_ref().is_some_and(|e| *e != tag) {
        return Err(ClientError::BadResponse("ETag does not match the package revision").into());
    }
    Ok((v, tag))
}

/// `package view ID`.
///
/// # Errors
///
/// [`CmdError`].
pub fn view<T: Transport>(
    api: &mut ApiClient<T>,
    id: PackageId,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    let (v, _) = get(api, id)?;
    print_package(out, &v)
}

/// `package edit ID [--name N] [--description D] [--image ID] [--index N]
/// [--pe ID]`.
///
/// # Errors
///
/// [`CmdError`]; a concurrent change gives the server's 412.
pub fn edit<T: Transport>(
    api: &mut ApiClient<T>,
    id: PackageId,
    d: &Definition,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    if *d == Definition::default() {
        return Err(CmdError::Invalid(
            "nothing to change: give at least one of --name, --description, --image, --index, --pe"
                .into(),
        ));
    }
    let (v, tag) = get(api, id)?;
    let req = checked(PackageRequest {
        name: d.name.clone().unwrap_or_else(|| v.name.as_str().to_owned()),
        description: d
            .description
            .clone()
            .or_else(|| v.description.as_ref().map(|x| x.as_str().to_owned())),
        image_id: d
            .image
            .clone()
            .unwrap_or_else(|| v.image.image_id.to_string()),
        edition_index: d
            .index
            .unwrap_or_else(|| u64::from(v.image.edition_index.get())),
        pe_id: d.pe.clone().unwrap_or_else(|| v.pe.pe_id.to_string()),
    })?;
    send_view(
        api,
        Method::Put,
        format!("/v1/packages/{id}"),
        Some(tag),
        json_body!(&req)?,
        out,
        "edited",
    )
}

/// `package clone ID --name N`.
///
/// # Errors
///
/// [`CmdError`].
pub fn clone<T: Transport>(
    api: &mut ApiClient<T>,
    id: PackageId,
    name: &str,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    let name = DisplayName::new(name).map_err(|e| CmdError::Invalid(format!("--name {e}")))?;
    let req = ClonePackageRequest::from(&name);
    send_view(
        api,
        Method::Post,
        format!("/v1/packages/{id}/clone"),
        None,
        json_body!(&req)?,
        out,
        "cloned into",
    )
}

/// `package delete ID [--yes]`.
///
/// # Errors
///
/// [`CmdError`]; [`CmdError::NotConfirmed`].
pub fn delete<T: Transport>(
    api: &mut ApiClient<T>,
    id: PackageId,
    yes: bool,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), CmdError> {
    let (v, tag) = get(api, id)?;
    if !yes {
        confirm(
            &format!(
                "This permanently deletes package {id} ({}, revision {}, status {}).",
                esc(v.name.as_str()),
                v.revision,
                v.status
            ),
            input,
            err,
        )?;
    }
    api.delete(format!("/v1/packages/{id}"), Some(tag))?;
    writeln!(out, "deleted package {id}")?;
    Ok(())
}

/// `package manifest ID --out F`: fetches the signed package manifest,
/// verifies it with the pinned content key, checks it names this package,
/// writes the envelope exactly as received to a new file `out`, and
/// prints the signed facts.
///
/// # Errors
///
/// [`CmdError`]; nothing is written unless verification succeeds.
pub fn manifest<T: Transport>(
    api: &mut ApiClient<T>,
    id: PackageId,
    out_path: &Path,
    key: &PinnedKey,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    if std::fs::symlink_metadata(out_path).is_ok() {
        return Err(CmdError::OutputExists(out_path.to_path_buf()));
    }
    let max = u64::try_from(MAX_ENVELOPE_BYTES).unwrap_or(u64::MAX);
    let bytes = api.get_bytes(format!("/v1/packages/{id}/manifest"), max)?;
    let env = SignedEnvelopeV1::from_json(&bytes).map_err(|e| CmdError::Manifest(e.to_string()))?;
    let m = PackageManifestV1::open(&env, key).map_err(|e| manifest_error(&e))?;
    if m.package_id != id {
        return Err(CmdError::Manifest(format!(
            "the signed manifest describes package {}, not {id}",
            m.package_id
        )));
    }
    write_new(out_path, &bytes)?;
    writeln!(
        out,
        "verified package manifest for {id} written to {}",
        out_path.display()
    )?;
    writeln!(out, "  name:      {}", esc(m.name.as_str()))?;
    writeln!(out, "  revision:  {}", m.revision)?;
    writeln!(
        out,
        "  signed:    {} by key {}",
        utc(m.signed_at.as_micros()),
        m.key_id
    )?;
    writeln!(
        out,
        "  image:     sha256 {} edition {}: {}",
        m.image.content_sha256,
        m.image.edition_index.get(),
        esc(m.image.edition_name.as_str())
    )?;
    print_facts(out, "             ", Some(&m.image.facts))?;
    writeln!(
        out,
        "             declared by operator {} (audit record {})",
        m.image.declared_by, m.image.declared_audit_seq
    )?;
    writeln!(
        out,
        "  pe:        sha256 {} image {} architecture {} ({}), kit {} ({})",
        m.pe.content_sha256,
        m.pe.usable_index.get(),
        m.pe.architecture.value,
        m.pe.architecture.source,
        m.pe.kit_version.value,
        m.pe.kit_version.source
    )?;
    Ok(())
}

/// Writes `bytes` to a new file (never overwrites); removes it on error.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), CmdError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o644);
    }
    let mut f = opts.open(path).map_err(|e| match e.kind() {
        io::ErrorKind::AlreadyExists => CmdError::OutputExists(path.to_path_buf()),
        kind => CmdError::Local {
            path: path.to_path_buf(),
            kind,
        },
    })?;
    if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
        drop(f);
        let _ = std::fs::remove_file(path);
        return Err(CmdError::Local {
            path: path.to_path_buf(),
            kind: e.kind(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::fake::{FakeTransport, Scripted};
    use crate::cmd_content::tests::sign;
    use crate::config::tests::TempDir;
    use usgp_common::Sha256Digest;
    use usgp_crypto::SigningKey;
    use usgp_proto::api::{PackageImageView, PackagePeView, SupportView};
    use usgp_proto::envelope::PayloadType;
    use usgp_proto::facts::{
        Architecture, Edition, EditionFacts, Fact, KitVersion, Release, SupportState,
    };
    use usgp_proto::ids::{ContentId, OperatorId, UnixMicros};
    use usgp_proto::names::{EditionIndex, WimText};
    use usgp_proto::package_manifest::{PackageImageV1, PackagePeV1};
    use usgp_proto::status::PackageStatus;

    const PKG: &str = "1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516";
    const IMG: &str = "0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f";
    const PE: &str = "3a7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e70";
    const OTHER_PE: &str = "4a7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e71";

    fn pid() -> PackageId {
        PackageId::parse(PKG).unwrap()
    }

    fn facts() -> EditionFacts {
        EditionFacts {
            release: Fact::declared(Release::Windows11),
            edition: Fact::declared(Edition::Enterprise),
            architecture: Fact::declared(Architecture::X64),
        }
    }

    fn package(revision: u64) -> PackageView {
        PackageView {
            id: pid(),
            name: DisplayName::new("Laptops").unwrap(),
            description: Some(usgp_proto::names::Description::new("field").unwrap()),
            revision,
            status: PackageStatus::Ready,
            status_reason: None,
            image: PackageImageView {
                image_id: ContentId::parse(IMG).unwrap(),
                display_name: DisplayName::new("Win 11").unwrap(),
                edition_index: EditionIndex::new(2).unwrap(),
                edition_name: WimText::new("Ent\x1b[1m").unwrap(),
                facts: Some(facts()),
                support: SupportView {
                    status: SupportState::Supported,
                    reason: None,
                },
            },
            pe: PackagePeView {
                pe_id: ContentId::parse(PE).unwrap(),
                display_name: DisplayName::new("PE").unwrap(),
                architecture: Fact::declared(Architecture::X64),
                kit_version: Fact::declared(KitVersion::parse("10.1.26100.1").unwrap()),
                kit_warning: None,
            },
            created_by: OperatorId::parse("2c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516").unwrap(),
            created_at: UnixMicros::new(0).unwrap(),
            updated_at: UnixMicros::new(0).unwrap(),
        }
    }

    fn json(v: &PackageView) -> Vec<u8> {
        serde_json::to_vec(v).unwrap()
    }

    #[test]
    fn create_validates_and_posts() {
        let d = Definition {
            name: Some("Laptops".into()),
            description: None,
            image: Some(IMG.into()),
            index: Some(2),
            pe: Some(PE.into()),
        };
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Post,
            "/v1/packages",
            Scripted::bytes(201, json(&package(1))),
        ));
        let mut out = Vec::new();
        create(&mut api, &d, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Ent\\u{001b}[1m"), "{text}");
        assert!(!text.contains('\x1b'));
        let sent: PackageRequest =
            serde_json::from_slice(&api.transport().seen.first().unwrap().body).unwrap();
        assert_eq!(sent.edition_index, 2);

        let mut api = ApiClient::new(FakeTransport::default());
        for bad in [
            Definition {
                index: Some(0),
                ..d.clone()
            },
            Definition {
                image: Some("not-a-uuid".into()),
                ..d.clone()
            },
            Definition {
                name: Some(String::new()),
                ..d.clone()
            },
            Definition {
                pe: None,
                ..d.clone()
            },
        ] {
            assert!(matches!(
                create(&mut api, &bad, &mut Vec::new()),
                Err(CmdError::Invalid(_))
            ));
        }
        assert!(api.transport().seen.is_empty());
    }

    #[test]
    fn edit_merges_and_sends_if_match() {
        let mut edited = package(8);
        edited.pe.pe_id = ContentId::parse(OTHER_PE).unwrap();
        let mut api = ApiClient::new(
            FakeTransport::default()
                .expect(
                    Method::Get,
                    &format!("/v1/packages/{PKG}"),
                    Scripted::bytes(200, json(&package(7))).with_etag("\"r7\""),
                )
                .expect(
                    Method::Put,
                    &format!("/v1/packages/{PKG}"),
                    Scripted::bytes(200, json(&edited)),
                ),
        );
        let d = Definition {
            pe: Some(OTHER_PE.into()),
            ..Definition::default()
        };
        edit(&mut api, pid(), &d, &mut Vec::new()).unwrap();
        let put = api.transport().seen.get(1).unwrap();
        assert_eq!(put.if_match.as_deref(), Some("\"r7\""));
        let sent: PackageRequest = serde_json::from_slice(&put.body).unwrap();
        assert_eq!(sent.pe_id, OTHER_PE);
        assert_eq!(sent.image_id, IMG);
        assert_eq!(sent.edition_index, 2);
        assert_eq!(sent.name, "Laptops");
        assert_eq!(sent.description.as_deref(), Some("field"));

        // Nothing to change: no request.
        let mut api = ApiClient::new(FakeTransport::default());
        assert!(edit(&mut api, pid(), &Definition::default(), &mut Vec::new()).is_err());
        assert!(api.transport().seen.is_empty());
    }

    #[test]
    fn mismatched_etag_refused() {
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Get,
            &format!("/v1/packages/{PKG}"),
            Scripted::bytes(200, json(&package(7))).with_etag("\"r6\""),
        ));
        assert!(view(&mut api, pid(), &mut Vec::new()).is_err());
    }

    #[test]
    fn delete_prompts_unless_yes() {
        let script = || {
            FakeTransport::default()
                .expect(
                    Method::Get,
                    &format!("/v1/packages/{PKG}"),
                    Scripted::bytes(200, json(&package(3))),
                )
                .expect(
                    Method::Delete,
                    &format!("/v1/packages/{PKG}"),
                    Scripted::bytes(204, Vec::new()),
                )
        };
        // Declined: warned, nothing deleted.
        let mut api = ApiClient::new(script());
        let mut err = Vec::new();
        let e = delete(
            &mut api,
            pid(),
            false,
            &mut &b"n\n"[..],
            &mut Vec::new(),
            &mut err,
        )
        .unwrap_err();
        assert!(matches!(e, CmdError::NotConfirmed));
        let warning = String::from_utf8(err).unwrap();
        assert!(warning.contains("permanently deletes package"), "{warning}");
        assert!(warning.contains("Laptops"), "{warning}");
        assert_eq!(api.transport().seen.len(), 1);

        // Confirmed.
        let mut api = ApiClient::new(script());
        delete(
            &mut api,
            pid(),
            false,
            &mut &b"yes\n"[..],
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(
            api.transport().seen.get(1).unwrap().if_match.as_deref(),
            Some("\"r3\"")
        );

        // --yes: no prompt, nothing read.
        let mut api = ApiClient::new(script());
        let mut err = Vec::new();
        delete(
            &mut api,
            pid(),
            true,
            &mut &b""[..],
            &mut Vec::new(),
            &mut err,
        )
        .unwrap();
        assert!(err.is_empty());
        assert!(api.transport().done());
    }

    #[test]
    fn clone_posts_name() {
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Post,
            &format!("/v1/packages/{PKG}/clone"),
            Scripted::bytes(201, json(&package(1))),
        ));
        clone(&mut api, pid(), "Laptops 2", &mut Vec::new()).unwrap();
        let sent: ClonePackageRequest =
            serde_json::from_slice(&api.transport().seen.first().unwrap().body).unwrap();
        assert_eq!(sent.name, "Laptops 2");
    }

    fn signed_manifest(key: &SigningKey, id: PackageId) -> Vec<u8> {
        let m = PackageManifestV1 {
            schema: 1,
            package_id: id,
            revision: 3,
            name: DisplayName::new("Laptops").unwrap(),
            image: PackageImageV1 {
                content_sha256: Sha256Digest([0xaa; 32]),
                edition_index: EditionIndex::new(2).unwrap(),
                edition_name: WimText::new("Ent\x07").unwrap(),
                facts: facts(),
                declared_by: OperatorId::parse("2c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516").unwrap(),
                declared_audit_seq: 42,
            },
            pe: PackagePeV1 {
                content_sha256: Sha256Digest([0xbb; 32]),
                usable_index: EditionIndex::new(1).unwrap(),
                architecture: Fact::declared(Architecture::X64),
                kit_version: Fact::declared(KitVersion::parse("10.1.26100.1").unwrap()),
            },
            signed_at: UnixMicros::new(0).unwrap(),
            key_id: key.key_id().0,
        };
        sign(key, PayloadType::PackageManifestV1, m.to_payload().unwrap())
    }

    #[test]
    fn manifest_verified_then_written() {
        let key = SigningKey::generate().unwrap();
        let pinned = PinnedKey::new(key.verifying_key().clone());
        let env = signed_manifest(&key, pid());
        let t = TempDir::new("pm");
        let out_path = t.0.join("pkg.json");
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Get,
            &format!("/v1/packages/{PKG}/manifest"),
            Scripted::bytes(200, env.clone()),
        ));
        let mut out = Vec::new();
        manifest(&mut api, pid(), &out_path, &pinned, &mut out).unwrap();
        assert_eq!(std::fs::read(&out_path).unwrap(), env);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("release: windows-11 (declared)"), "{text}");
        assert!(text.contains("audit record 42"), "{text}");
        assert!(text.contains("Ent\\u{0007}"), "{text}");

        // Existing output is never overwritten.
        let mut api = ApiClient::new(FakeTransport::default());
        assert!(matches!(
            manifest(&mut api, pid(), &out_path, &pinned, &mut Vec::new()),
            Err(CmdError::OutputExists(_))
        ));
    }

    #[test]
    fn manifest_bad_signature_or_other_package_not_written() {
        let key = SigningKey::generate().unwrap();
        let other = SigningKey::generate().unwrap();
        let pinned = PinnedKey::new(key.verifying_key().clone());
        let t = TempDir::new("pmbad");
        let out_path = t.0.join("pkg.json");
        let other_pkg = PackageId::parse("9c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516").unwrap();
        for env in [
            signed_manifest(&other, pid()),
            signed_manifest(&key, other_pkg),
            b"{}".to_vec(),
        ] {
            let mut api = ApiClient::new(FakeTransport::default().expect(
                Method::Get,
                &format!("/v1/packages/{PKG}/manifest"),
                Scripted::bytes(200, env),
            ));
            let e = manifest(&mut api, pid(), &out_path, &pinned, &mut Vec::new()).unwrap_err();
            assert!(matches!(e, CmdError::Manifest(_)), "{e}");
            assert!(!out_path.exists());
        }
    }
}
