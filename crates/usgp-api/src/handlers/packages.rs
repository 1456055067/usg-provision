//! Deployment packages: list, view, create, edit, clone, delete, and the
//! signed package manifest (plan M2 section 3.2).
//!
//! A package names one image edition and one PE (REQ-IMG-001). Both must
//! be Ready when chosen (409 otherwise). An edition declared out of scope
//! is refused at selection with `os_scope` and nothing is created or
//! changed (REQ-OS-005); an undeclared edition makes a `not_usable`
//! package (`os_support_unknown`, REQ-OS-009). The status is computed in
//! the same transaction as the change, and a package that becomes Ready
//! gets a signed package manifest in that transaction. Edits and deletes
//! need `If-Match: "r<revision>"` (428 without, 412 on mismatch) and are
//! all-or-nothing (REQ-IMG-012).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - If-Match
//   precondition (optimistic concurrency) on every change; full
//   replacement; AU-12 - every change audited (supports CM-3 record
//   keeping).
// - NIST 800-53: SI-7(6) - Ready packages carry a signed manifest; content
//   manifests are verified before a package is signed over them.
// - NIST 800-53: AU-2, AU-12 - every change and refusal audited.
// - SPEC: specs/os-images.md#REQ-IMG-001, #REQ-IMG-010, #REQ-IMG-011,
//   #REQ-IMG-012, #REQ-IMG-013, #REQ-IMG-014, #REQ-IMG-020, #REQ-IMG-041
// - SPEC: specs/os-support.md#REQ-OS-005, #REQ-OS-009
// - SPEC: specs/preinstall-env.md#REQ-PE-007
// - RFC 9110 §13.1.1 (If-Match), §15.5.13 (412); RFC 6585 §3 (428)

use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use usgp_audit::{AuditRecord, Detail, Outcome};
use usgp_db::{Content, Edition, Package, RepoTx, Store, StoredManifest};
use usgp_image::os_support::{SupportStatus, evaluate};
use usgp_proto::PackageStatus;
use usgp_proto::api::{
    ClonePackageRequest, PackageList, PackageRequest, PackageSpec, if_match_revision, package_etag,
};
use usgp_proto::{
    ContentKind, ContentState, EditionIndex, PackageId, PackageImageV1, PackageManifestV1,
    PackagePeV1, PayloadType, UnixMicros, codes,
};

use super::content::verified_manifest;
use super::{
    code_of, field_error, if_match, json_response, package_id, package_view, parse_json, read_body,
    with_etag,
};
use crate::body::ApiBody;
use crate::context::{Api, RequestCtx};
use crate::error::ApiError;
use crate::manifest::{envelope, open_package};
use crate::package_status::{Computed, StatusInputs, compute};

/// The image, edition and PE a package refers to, checked.
struct Resolved {
    image: Content,
    edition: Edition,
    pe: Content,
}

fn invalid_ref(field: &'static str, what: &str) -> ApiError {
    ApiError::unprocessable(
        codes::INVALID_VALUE
            .with_param(field)
            .unwrap_or(codes::INVALID_VALUE),
        format!("{field}: no such {what}"),
    )
}

/// Resolves and checks a package definition (REQ-IMG-041, REQ-OS-005).
async fn resolve<S: Store + 'static>(
    api: &Api<S>,
    tx: &mut S::Tx,
    spec: &PackageSpec,
) -> Result<Resolved, ApiError> {
    let image = tx
        .lock_content(spec.image_id)
        .await?
        .filter(|c| c.kind == ContentKind::Image && c.state != ContentState::Deleted)
        .ok_or_else(|| invalid_ref("image_id", "image file"))?;
    let pe = tx
        .lock_content(spec.pe_id)
        .await?
        .filter(|c| c.kind == ContentKind::Pe && c.state != ContentState::Deleted)
        .ok_or_else(|| invalid_ref("pe_id", "preinstall environment"))?;
    for (c, which) in [(&image, "image file"), (&pe, "preinstall environment")] {
        if c.state != ContentState::Ready {
            return Err(ApiError::conflict(
                codes::NOT_READY_CONTENT,
                format!("the {which} is not ready"),
            )
            .detail(Detail::new().with("content_id", &c.id.to_string())));
        }
    }
    let count = image.wim.map_or(0, |w| w.image_count);
    let index = spec.edition_index.check(count).map_err(|e| {
        ApiError::unprocessable(
            codes::OUT_OF_RANGE
                .with_param("edition_index")
                .unwrap_or(codes::OUT_OF_RANGE),
            e.to_string(),
        )
    })?;
    let edition = tx
        .edition(image.id, index.get())
        .await?
        .ok_or_else(|| super::corrupt("edition"))?;
    // REQ-OS-005: an edition declared out of scope is refused here, naming
    // the facts at fault; nothing is created or changed.
    let facts = edition.declaration.as_ref().map(|d| d.facts.clone());
    if let SupportStatus::NotSupported { reasons } = evaluate(facts.as_ref()) {
        let names: Vec<&str> = reasons.iter().map(usgp_proto::ErrorCode::as_str).collect();
        let mut detail = Detail::new()
            .with("image_id", &image.id.to_string())
            .with("edition_index", &index.get())
            .with("reasons", &names.join(","));
        if let Some(f) = &facts {
            detail = detail
                .with("release", f.release.value.as_str())
                .with("edition", f.edition.value.as_str())
                .with("architecture", f.architecture.value.as_str());
        }
        return Err(ApiError::unprocessable(
            codes::OS_SCOPE,
            format!(
                "the chosen edition is outside the supported scope (Windows 11 Enterprise x64): {}",
                names.join(", ")
            ),
        )
        .event("os_support.refused")
        .detail(detail));
    }
    // Content is verified before it is relied on (decision 0011).
    for c in [&image, &pe] {
        if let Err(what) = verified_manifest(api, c) {
            return Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                codes::INTEGRITY_FAILED,
                "content referred to by the package failed its integrity check",
            )
            .internal(what));
        }
    }
    Ok(Resolved { image, edition, pe })
}

fn status_of(r: &Resolved) -> Result<Computed, ApiError> {
    let arch =
        r.pe.pe
            .as_ref()
            .ok_or_else(|| super::corrupt("pe declaration"))?
            .architecture
            .value;
    Ok(compute(&StatusInputs {
        image_state: r.image.state,
        edition_support: r.edition.support,
        edition_reason: r.edition.support_reason.as_deref().map(code_of),
        pe_state: r.pe.state,
        pe_architecture: arch,
    }))
}

/// Signs the package manifest for a Ready package.
fn sign_manifest<S: Store + 'static>(
    api: &Api<S>,
    id: PackageId,
    revision: u64,
    name: &usgp_proto::DisplayName,
    r: &Resolved,
    at: UnixMicros,
) -> Result<StoredManifest, ApiError> {
    let decl = r
        .edition
        .declaration
        .as_ref()
        .ok_or_else(|| super::corrupt("edition declaration"))?;
    let pe =
        r.pe.pe
            .as_ref()
            .ok_or_else(|| super::corrupt("pe declaration"))?;
    let usable =
        r.pe.usable_index
            .and_then(|i| EditionIndex::new(u64::from(i)).ok())
            .ok_or_else(|| super::corrupt("usable index"))?;
    let m = PackageManifestV1 {
        schema: usgp_proto::package_manifest::SCHEMA_V1,
        package_id: id,
        revision,
        name: name.clone(),
        image: PackageImageV1 {
            content_sha256: r.image.sha256,
            edition_index: EditionIndex::new(u64::from(r.edition.index))
                .map_err(|_| super::corrupt("edition index"))?,
            edition_name: r.edition.name.clone(),
            facts: decl.facts.clone(),
            declared_by: decl.declared_by,
            declared_audit_seq: decl.declared_audit_seq,
        },
        pe: PackagePeV1 {
            content_sha256: r.pe.sha256,
            usable_index: usable,
            architecture: pe.architecture.clone(),
            kit_version: pe.kit_version.clone(),
        },
        signed_at: at,
        key_id: api.keys().key_id().0,
    };
    let payload = m.to_payload().map_err(ApiError::internal_error)?;
    api.keys()
        .sign(PayloadType::PackageManifestV1, payload)
        .map_err(ApiError::internal_error)
}

/// The stored status, reason and manifest for `computed`.
fn stored_status<S: Store + 'static>(
    api: &Api<S>,
    computed: &Computed,
    id: PackageId,
    revision: u64,
    name: &usgp_proto::DisplayName,
    r: &Resolved,
    at: UnixMicros,
) -> Result<(PackageStatus, Option<String>, Option<StoredManifest>), ApiError> {
    Ok(match computed {
        Computed::Ready => (
            PackageStatus::Ready,
            None,
            Some(sign_manifest(api, id, revision, name, r, at)?),
        ),
        Computed::NotUsable(code) => (
            PackageStatus::NotUsable,
            Some(code.as_str().to_owned()),
            None,
        ),
    })
}

fn package_detail(p: &Package) -> Detail {
    let mut d = Detail::new()
        .with("name", p.name.as_str())
        .with("revision", &p.revision)
        .with("image_id", &p.image_id.to_string())
        .with("edition_index", &p.edition_index)
        .with("pe_id", &p.pe_id.to_string())
        .with("status", p.status.as_str());
    if let Some(r) = &p.status_reason {
        d = d.with("status_reason", r.as_str());
    }
    d
}

async fn signed_record<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    tx: &mut S::Tx,
    p: &Package,
    init: u64,
) -> Result<Option<AuditRecord>, ApiError> {
    let Some(m) = &p.manifest else {
        return Ok(None);
    };
    let d = ctx
        .ok("package.manifest.signed")
        .target("package", &p.id.to_string())
        .initiated_by(init)
        .detail(
            Detail::new()
                .with("revision", &p.revision)
                .with("key_id", &m.key_id),
        );
    Ok(Some(api.append(tx, &d).await?))
}

fn view_response(
    view: &usgp_proto::api::PackageView,
    status: StatusCode,
) -> Result<Response<ApiBody>, ApiError> {
    Ok(with_etag(
        json_response!(status, view)?,
        &package_etag(view.revision),
    ))
}

fn random_id() -> Result<PackageId, ApiError> {
    let mut b = [0u8; 16];
    usgp_crypto::fill_random(&mut b).map_err(ApiError::internal_error)?;
    Ok(PackageId::from_random_bytes(b))
}

pub(crate) async fn list<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let known_bad = &api.config().known_bad_kit_versions;
    let mut tx = api.store().begin().await?;
    let all = tx.list_packages().await?;
    let mut packages = Vec::with_capacity(all.len());
    for p in &all {
        packages.push(package_view(&mut tx, p, known_bad).await?);
    }
    let d = ctx
        .ok("package.list.read")
        .detail(Detail::new().with("count", &packages.len()));
    let rec = api.append(&mut tx, &d).await?;
    api.commit(tx, &[rec]).await?;
    json_response!(StatusCode::OK, &PackageList { packages })
}

pub(crate) async fn get<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let id = package_id(ctx)?;
    let mut tx = api.store().begin().await?;
    let p = tx
        .package(id)
        .await?
        .ok_or_else(|| ApiError::not_found("package"))?;
    let view = package_view(&mut tx, &p, &api.config().known_bad_kit_versions).await?;
    let d = ctx.ok("package.read").target("package", &id.to_string());
    let rec = api.append(&mut tx, &d).await?;
    api.commit(tx, &[rec]).await?;
    view_response(&view, StatusCode::OK)
}

async fn spec_from<S: Store + 'static>(
    api: &Api<S>,
    req: Request<Incoming>,
) -> Result<PackageSpec, ApiError> {
    let max_json = api.config().limits.max_json_bytes;
    let body = read_body(req, max_json).await?;
    let wire = parse_json!(PackageRequest, &body, max_json)?;
    wire.validate().map_err(|e| field_error(&e))
}

pub(crate) async fn create<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let spec = spec_from(api, req).await?;
    let mut tx = api.store().begin().await?;
    let r = resolve(api, &mut tx, &spec).await?;
    let id = random_id()?;
    let at = api.now()?;
    let computed = status_of(&r)?;
    let (status, status_reason, manifest) =
        stored_status(api, &computed, id, 1, &spec.name, &r, at)?;
    let p = Package {
        id,
        name: spec.name.clone(),
        description: spec.description.clone(),
        image_id: r.image.id,
        edition_index: r.edition.index,
        pe_id: r.pe.id,
        revision: 1,
        status,
        status_reason,
        manifest,
        created_by: ctx.principal.operator.id,
        created_at: at,
        updated_at: at,
    };
    tx.insert_package(&p).await?;
    let d = ctx
        .ok("package.created")
        .target("package", &id.to_string())
        .detail(package_detail(&p));
    let rec = api.append(&mut tx, &d).await?;
    let seq = rec.seq;
    let mut recs = vec![rec];
    if let Some(s) = signed_record(api, ctx, &mut tx, &p, seq).await? {
        recs.push(s);
    }
    let view = package_view(&mut tx, &p, &api.config().known_bad_kit_versions).await?;
    api.commit(tx, &recs).await?;
    let mut resp = view_response(&view, StatusCode::CREATED)?;
    if let Ok(v) = HeaderValue::from_str(&format!("/v1/packages/{id}")) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    Ok(resp)
}

/// The revision named by `If-Match` (428 without one; 412 if it is not a
/// single strong `"r<n>"` tag).
fn expected_revision<B>(req: &Request<B>) -> Result<u64, ApiError> {
    if_match_revision(if_match(req)?).ok_or_else(ApiError::precondition_failed)
}

pub(crate) async fn edit<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let id = package_id(ctx)?;
    let expected = expected_revision(&req)?;
    let spec = spec_from(api, req).await?;
    let mut tx = api.store().begin().await?;
    let cur = tx
        .lock_package(id)
        .await?
        .ok_or_else(|| ApiError::not_found("package"))?;
    if cur.revision != expected {
        return Err(ApiError::precondition_failed().detail(
            Detail::new()
                .with("expected", &expected)
                .with("current", &cur.revision),
        ));
    }
    let r = resolve(api, &mut tx, &spec).await?;
    let revision = expected
        .checked_add(1)
        .ok_or_else(|| ApiError::internal_error("revision overflow"))?;
    let at = api.now()?;
    let computed = status_of(&r)?;
    let (status, status_reason, manifest) =
        stored_status(api, &computed, id, revision, &spec.name, &r, at)?;
    let p = Package {
        id,
        name: spec.name.clone(),
        description: spec.description.clone(),
        image_id: r.image.id,
        edition_index: r.edition.index,
        pe_id: r.pe.id,
        revision,
        status,
        status_reason,
        manifest,
        created_by: cur.created_by,
        created_at: cur.created_at,
        updated_at: at,
    };
    match tx.update_package(&p, expected).await {
        Ok(()) => {}
        Err(e) if e.is_conflict() => return Err(ApiError::precondition_failed()),
        Err(e) => return Err(e.into()),
    }
    let d = ctx
        .ok("package.edited")
        .target("package", &id.to_string())
        .detail(
            package_detail(&p)
                .with("previous_revision", &cur.revision)
                .with("previous_image_id", &cur.image_id.to_string())
                .with("previous_edition_index", &cur.edition_index)
                .with("previous_pe_id", &cur.pe_id.to_string()),
        );
    let rec = api.append(&mut tx, &d).await?;
    let seq = rec.seq;
    let mut recs = vec![rec];
    if cur.status != p.status {
        let mut d = ctx
            .draft("package.status.changed", Outcome::Success)
            .target("package", &id.to_string())
            .initiated_by(seq)
            .detail(
                Detail::new()
                    .with("from", cur.status.as_str())
                    .with("to", p.status.as_str()),
            );
        if let Some(r) = &p.status_reason {
            d = d.reason(r);
        }
        recs.push(api.append(&mut tx, &d).await?);
    }
    if let Some(s) = signed_record(api, ctx, &mut tx, &p, seq).await? {
        recs.push(s);
    }
    let view = package_view(&mut tx, &p, &api.config().known_bad_kit_versions).await?;
    api.commit(tx, &recs).await?;
    view_response(&view, StatusCode::OK)
}

pub(crate) async fn clone<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let source = package_id(ctx)?;
    let max_json = api.config().limits.max_json_bytes;
    let body = read_body(req, max_json).await?;
    let wire = parse_json!(ClonePackageRequest, &body, max_json)?;
    let name = wire.validate().map_err(|e| field_error(&e))?;
    let mut tx = api.store().begin().await?;
    let orig = tx
        .lock_package(source)
        .await?
        .ok_or_else(|| ApiError::not_found("package"))?;
    let spec = PackageSpec {
        name: name.clone(),
        description: orig.description.clone(),
        image_id: orig.image_id,
        edition_index: EditionIndex::new(u64::from(orig.edition_index))
            .map_err(|_| super::corrupt("edition index"))?,
        pe_id: orig.pe_id,
    };
    // The clone is checked like a new package: same scope rules, its own
    // status and, if Ready, its own signed manifest.
    let r = resolve(api, &mut tx, &spec).await?;
    let id = random_id()?;
    let at = api.now()?;
    let computed = status_of(&r)?;
    let (status, status_reason, manifest) = stored_status(api, &computed, id, 1, &name, &r, at)?;
    let p = Package {
        id,
        name,
        description: orig.description.clone(),
        image_id: orig.image_id,
        edition_index: orig.edition_index,
        pe_id: orig.pe_id,
        revision: 1,
        status,
        status_reason,
        manifest,
        created_by: ctx.principal.operator.id,
        created_at: at,
        updated_at: at,
    };
    tx.insert_package(&p).await?;
    let d = ctx
        .ok("package.cloned")
        .target("package", &id.to_string())
        .detail(package_detail(&p).with("source_id", &source.to_string()));
    let rec = api.append(&mut tx, &d).await?;
    let seq = rec.seq;
    let mut recs = vec![rec];
    if let Some(s) = signed_record(api, ctx, &mut tx, &p, seq).await? {
        recs.push(s);
    }
    let view = package_view(&mut tx, &p, &api.config().known_bad_kit_versions).await?;
    api.commit(tx, &recs).await?;
    let mut resp = view_response(&view, StatusCode::CREATED)?;
    if let Ok(v) = HeaderValue::from_str(&format!("/v1/packages/{id}")) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    Ok(resp)
}

pub(crate) async fn delete<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: &Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let id = package_id(ctx)?;
    let expected = expected_revision(req)?;
    let mut tx = api.store().begin().await?;
    let cur = tx
        .lock_package(id)
        .await?
        .ok_or_else(|| ApiError::not_found("package"))?;
    if cur.revision != expected {
        return Err(ApiError::precondition_failed());
    }
    match tx.delete_package(id, expected).await {
        Ok(()) => {}
        Err(e) if e.is_conflict() => return Err(ApiError::precondition_failed()),
        Err(e) => return Err(e.into()),
    }
    let d = ctx
        .ok("package.deleted")
        .target("package", &id.to_string())
        .detail(package_detail(&cur));
    let rec = api.append(&mut tx, &d).await?;
    api.commit(tx, &[rec]).await?;
    let mut r = Response::new(ApiBody::empty());
    *r.status_mut() = StatusCode::NO_CONTENT;
    Ok(r)
}

pub(crate) async fn manifest<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let id = package_id(ctx)?;
    let mut tx = api.store().begin().await?;
    let p = tx
        .package(id)
        .await?
        .ok_or_else(|| ApiError::not_found("package"))?;
    let stored = match (&p.status, &p.manifest) {
        (PackageStatus::Ready, Some(m)) => m.clone(),
        _ => {
            return Err(ApiError::conflict(
                codes::PACKAGE_NOT_READY,
                "the package is not ready, so it has no signed manifest",
            ));
        }
    };
    // Verified before it is served (decision 0011).
    let ok = open_package(api.keys(), &stored)
        .is_ok_and(|m| m.package_id == p.id && m.revision == p.revision);
    if !ok {
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            codes::INTEGRITY_FAILED,
            "the package manifest failed verification and was not served",
        )
        .internal("package manifest signature, payload or identity invalid"));
    }
    let env =
        envelope(PayloadType::PackageManifestV1, &stored).map_err(ApiError::internal_error)?;
    let json = env.to_json().map_err(ApiError::internal_error)?;
    let d = ctx
        .ok("package.manifest.read")
        .target("package", &id.to_string())
        .detail(
            Detail::new()
                .with("revision", &p.revision)
                .with("key_id", &stored.key_id),
        );
    let rec = api.append(&mut tx, &d).await?;
    api.commit(tx, &[rec]).await?;
    let mut r = Response::new(ApiBody::full(json));
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(usgp_proto::api::JSON_MEDIA_TYPE),
    );
    Ok(with_etag(r, &package_etag(p.revision)))
}
