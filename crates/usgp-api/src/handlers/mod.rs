//! Route handlers and the helpers they share: bounded JSON bodies,
//! path-parameter parsing, `If-Match`, and conversion of stored rows to
//! API views.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - JSON bodies size
//   capped before parsing; strict parsing (usgp-proto); path IDs parsed as
//   UUIDs; stored values re-validated on the way out.
// - NIST 800-53: SI-11 (Error Handling) - stored reason codes that fail
//   validation are shown as `internal`, never raw.
// - SPEC: specs/os-images.md#REQ-IMG-020, #REQ-IMG-022, #REQ-IMG-040,
//   #REQ-IMG-043; specs/preinstall-env.md#REQ-PE-006, #REQ-PE-009;
//   specs/os-support.md#REQ-OS-009
// - RFC 9110 §8.8.3 (ETag), §13.1.1 (If-Match)

pub(crate) mod auth_codes;
pub(crate) mod boot_policy;
pub(crate) mod boot_services;
pub(crate) mod boot_stops;
pub(crate) mod content;
pub(crate) mod declarations;
pub(crate) mod images;
pub(crate) mod jobs;
pub(crate) mod limits;
pub(crate) mod packages;
pub(crate) mod pe;
pub(crate) mod sessions;
pub(crate) mod uploads;

use http_body_util::{BodyExt, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use usgp_db::{Content, Edition, RepoTx, Store};
use usgp_proto::api::{
    EditionView, ImageView, Message, PackageImageView, PackagePeView, PackageRef, PackageView,
    PeView, Reason, RequestError, SupportView,
};
use usgp_proto::{ContentId, EditionIndex, ErrorCode, KitVersion, PackageId, UploadId, codes};

use crate::body::ApiBody;
use crate::checker::kit_warning;
use crate::context::{Api, RequestCtx};
use crate::error::ApiError;
use crate::routes::RouteId;

/// A JSON response from a concrete serialisable value.
macro_rules! json_response {
    ($status:expr, $value:expr) => {
        $crate::handlers::json_bytes($status, ::serde_json::to_vec($value))
    };
}
pub(crate) use json_response;

/// Parses a JSON request body as a concrete wire type (400/413 on error).
macro_rules! parse_json {
    ($ty:ty, $bytes:expr, $max:expr) => {
        ::usgp_proto::api::parse_request::<$ty>($bytes, $max)
            .map_err($crate::handlers::request_error)
    };
}
pub(crate) use parse_json;

/// Runs the handler for the matched route.
pub(crate) async fn dispatch<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    match ctx.route.id {
        RouteId::Limits => limits::get(api, ctx).await,
        RouteId::UploadCreate => uploads::create(api, ctx, req).await,
        RouteId::UploadPut => uploads::put(api, ctx, req).await,
        RouteId::UploadCancel => uploads::cancel(api, ctx).await,
        RouteId::ImageList => images::list(api, ctx).await,
        RouteId::ImageGet => images::get(api, ctx).await,
        RouteId::ImageDeclare => declarations::put(api, ctx, req).await,
        RouteId::ImageDelete => images::delete(api, ctx, &req).await,
        RouteId::ImageManifest => content::manifest(api, ctx, usgp_proto::ContentKind::Image).await,
        RouteId::PeList => pe::list(api, ctx).await,
        RouteId::PeGet => pe::get(api, ctx).await,
        RouteId::PeDelete => pe::delete(api, ctx, &req).await,
        RouteId::PeManifest => content::manifest(api, ctx, usgp_proto::ContentKind::Pe).await,
        RouteId::ContentGet => content::download(api, ctx).await,
        RouteId::PackageList => packages::list(api, ctx).await,
        RouteId::PackageGet => packages::get(api, ctx).await,
        RouteId::PackageCreate => packages::create(api, ctx, req).await,
        RouteId::PackageEdit => packages::edit(api, ctx, req).await,
        RouteId::PackageClone => packages::clone(api, ctx, req).await,
        RouteId::PackageDelete => packages::delete(api, ctx, &req).await,
        RouteId::PackageManifest => packages::manifest(api, ctx).await,
        RouteId::AuthCodeIssue => auth_codes::issue(api, ctx, req).await,
        RouteId::AuthCodeList => auth_codes::list(api, ctx).await,
        RouteId::AuthCodeRevoke => auth_codes::revoke(api, ctx).await,
        RouteId::DeviceSessionList => sessions::list(api, ctx, &req).await,
        RouteId::DeviceSessionApprove => sessions::approve(api, ctx, req).await,
        RouteId::DeviceSessionRefuse => sessions::refuse(api, ctx, req).await,
        RouteId::JobList => jobs::list(api, ctx, &req).await,
        RouteId::JobGet => jobs::get(api, ctx).await,
        RouteId::JobAcknowledge => jobs::acknowledge(api, ctx).await,
        RouteId::BootServiceList => boot_services::list(api, ctx).await,
        RouteId::BootServiceGet => boot_services::get(api, ctx).await,
        RouteId::BootServicePackages => boot_services::set_packages(api, ctx, req).await,
        RouteId::BootStopList => boot_stops::list(api, ctx).await,
        RouteId::BootStopClear => boot_stops::clear(api, ctx).await,
        // Reached only through the boot-service branch of the router; an
        // operator never gets here (403 before dispatch).
        RouteId::RelayBootPolicy => Err(ApiError::forbidden()),
    }
}

/// A JSON response.
pub(crate) fn json_bytes(
    status: StatusCode,
    bytes: Result<Vec<u8>, serde_json::Error>,
) -> Result<Response<ApiBody>, ApiError> {
    let bytes = bytes.map_err(ApiError::internal_error)?;
    let mut r = Response::new(ApiBody::full(bytes));
    *r.status_mut() = status;
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(usgp_proto::api::JSON_MEDIA_TYPE),
    );
    Ok(r)
}

/// Adds an `ETag`.
pub(crate) fn with_etag(mut r: Response<ApiBody>, etag: &str) -> Response<ApiBody> {
    if let Ok(v) = HeaderValue::from_str(etag) {
        r.headers_mut().insert(header::ETAG, v);
    }
    r
}

/// Maps a body parse error.
pub(crate) fn request_error(e: RequestError) -> ApiError {
    let status = if e.code() == codes::BODY_TOO_LARGE {
        StatusCode::PAYLOAD_TOO_LARGE
    } else {
        StatusCode::BAD_REQUEST
    };
    let body = e.to_error_body();
    let mut err = ApiError::new(status, body.error.code.clone(), body.error.message.as_str());
    err.body = body;
    err
}

/// Maps a field validation error (422).
pub(crate) fn field_error(e: &usgp_proto::api::FieldError) -> ApiError {
    let body = e.to_error_body();
    let mut err = ApiError::unprocessable(body.error.code.clone(), body.error.message.as_str());
    err.body = body;
    err
}

/// Reads a JSON request body, refusing more than `max` bytes (413) before
/// buffering it.
pub(crate) async fn read_body(req: Request<Incoming>, max: usize) -> Result<Bytes, ApiError> {
    let max_u64 = u64::try_from(max).unwrap_or(u64::MAX);
    let too_large = || {
        ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            codes::BODY_TOO_LARGE,
            format!("the request body is over the limit of {max} bytes"),
        )
        .limit(max_u64)
    };
    if let Some(len) = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        && len > max_u64
    {
        return Err(too_large());
    }
    match Limited::new(req.into_body(), max).collect().await {
        Ok(c) => Ok(c.to_bytes()),
        Err(e) if e.is::<http_body_util::LengthLimitError>() => Err(too_large()),
        Err(_) => Err(ApiError::bad_request("the request body could not be read")),
    }
}

/// The `If-Match` value, or 428.
pub(crate) fn if_match<B>(req: &Request<B>) -> Result<&[u8], ApiError> {
    req.headers()
        .get(header::IF_MATCH)
        .map(HeaderValue::as_bytes)
        .ok_or_else(ApiError::precondition_required)
}

/// The `ETag` of an image file or PE: `"sha256:<hex>"` of its SHA-256
/// (declared at upload, equal to the verified digest once Ready).
///
/// Content is immutable and content-addressed (REQ-IMG-052), so the
/// digest is a strong validator of what the operator saw; declarations
/// and state are guarded separately (in-use refusal, state checks). The
/// same tag is sent by `GET /v1/content/{id}`, and the CLI falls back to
/// it (WU-8 note). See the WU-6 implementation notes.
#[must_use]
pub fn content_view_etag(c: &Content) -> String {
    usgp_proto::api::content_etag(&c.sha256)
}

pub(crate) fn content_id(ctx: &RequestCtx) -> Result<ContentId, ApiError> {
    ContentId::parse(ctx.params.get(0)).map_err(|_| ApiError::not_found("item"))
}

pub(crate) fn package_id(ctx: &RequestCtx) -> Result<PackageId, ApiError> {
    PackageId::parse(ctx.params.get(0)).map_err(|_| ApiError::not_found("package"))
}

pub(crate) fn upload_id(ctx: &RequestCtx) -> Result<UploadId, ApiError> {
    UploadId::parse(ctx.params.get(0)).map_err(|_| ApiError::not_found("upload"))
}

/// A stored value that no longer passes validation: 500, never shown.
pub(crate) fn corrupt(what: &'static str) -> ApiError {
    ApiError::internal_error(format!("stored value not representable: {what}"))
}

pub(crate) fn code_of(text: &str) -> ErrorCode {
    ErrorCode::new(text.to_owned()).unwrap_or(codes::INTERNAL)
}

pub(crate) fn reason_view(r: &usgp_db::Reason) -> Reason {
    Reason {
        code: code_of(&r.code),
        message: Message::truncated(r.text.clone()),
    }
}

pub(crate) fn package_refs(v: Vec<usgp_db::PackageRef>) -> Vec<PackageRef> {
    v.into_iter()
        .map(|p| PackageRef {
            id: p.id,
            name: p.name,
        })
        .collect()
}

/// Support status and reason; an undeclared edition (stored as
/// `unknown` with no reason) shows `os_support_unknown` (REQ-OS-009).
pub(crate) fn support_view(e: &Edition) -> SupportView {
    let reason = match (e.support, e.support_reason.as_deref()) {
        (usgp_proto::SupportState::Supported, _) => None,
        (_, Some(r)) => Some(code_of(r)),
        (usgp_proto::SupportState::Unknown, None) => Some(codes::OS_SUPPORT_UNKNOWN),
        (usgp_proto::SupportState::NotSupported, None) => Some(codes::OS_SCOPE),
    };
    SupportView {
        status: e.support,
        reason,
    }
}

pub(crate) fn edition_view(e: &Edition) -> Result<EditionView, ApiError> {
    let d = e.declaration.as_ref();
    Ok(EditionView {
        index: EditionIndex::new(u64::from(e.index)).map_err(|_| corrupt("edition index"))?,
        name: e.name.clone(),
        description: e.description.clone(),
        total_bytes: e.total_bytes,
        facts: d.map(|d| d.facts.clone()),
        declared_by: d.map(|d| d.declared_by),
        declared_at: d.map(|d| d.declared_at),
        support: support_view(e),
    })
}

pub(crate) fn image_view(c: &Content, editions: &[Edition]) -> Result<ImageView, ApiError> {
    let ready = c.state == usgp_proto::ContentState::Ready;
    Ok(ImageView {
        id: c.id,
        display_name: c.display_name.clone(),
        file_name: c.file_name.clone(),
        size: c.size,
        sha256: ready.then_some(c.sha256),
        state: c.state,
        reason: c.reason.as_ref().map(reason_view),
        created_by: c.created_by,
        created_at: c.created_at,
        updated_at: c.updated_at,
        compression: c.wim.map(|w| w.compression),
        image_count: c.wim.map(|w| w.image_count),
        boot_index: c.wim.map(|w| w.boot_index),
        editions: editions
            .iter()
            .map(edition_view)
            .collect::<Result<_, _>>()?,
    })
}

pub(crate) fn warning(v: &KitVersion, known_bad: &[KitVersion]) -> Option<Reason> {
    kit_warning(v, known_bad).map(|(code, text)| Reason {
        code,
        message: Message::truncated(text),
    })
}

pub(crate) fn pe_view(
    c: &Content,
    used_by: Vec<usgp_db::PackageRef>,
    known_bad: &[KitVersion],
) -> Result<PeView, ApiError> {
    let pe = c.pe.as_ref().ok_or_else(|| corrupt("pe declaration"))?;
    let ready = c.state == usgp_proto::ContentState::Ready;
    Ok(PeView {
        id: c.id,
        display_name: c.display_name.clone(),
        file_name: c.file_name.clone(),
        size: c.size,
        sha256: ready.then_some(c.sha256),
        state: c.state,
        reason: c.reason.as_ref().map(reason_view),
        imported_by: c.created_by,
        imported_at: c.created_at,
        updated_at: c.updated_at,
        usable_index: c
            .usable_index
            .map(|i| EditionIndex::new(u64::from(i)))
            .transpose()
            .map_err(|_| corrupt("usable index"))?,
        architecture: pe.architecture.clone(),
        kit_version: pe.kit_version.clone(),
        kit_warning: warning(&pe.kit_version.value, known_bad),
        used_by: package_refs(used_by),
    })
}

/// The view of a package, reading its image, edition and PE in `tx`.
pub(crate) async fn package_view<T: RepoTx>(
    tx: &mut T,
    p: &usgp_db::Package,
    known_bad: &[KitVersion],
) -> Result<PackageView, ApiError> {
    let image = tx
        .content(p.image_id)
        .await?
        .ok_or_else(|| corrupt("package image"))?;
    let edition = tx
        .edition(p.image_id, p.edition_index)
        .await?
        .ok_or_else(|| corrupt("package edition"))?;
    let pe = tx
        .content(p.pe_id)
        .await?
        .ok_or_else(|| corrupt("package pe"))?;
    let pe_decl = pe.pe.as_ref().ok_or_else(|| corrupt("pe declaration"))?;
    Ok(PackageView {
        id: p.id,
        name: p.name.clone(),
        description: p.description.clone(),
        revision: p.revision,
        status: p.status,
        status_reason: p.status_reason.as_deref().map(|r| Reason {
            code: code_of(r),
            message: Message::truncated(status_text(r)),
        }),
        image: PackageImageView {
            image_id: image.id,
            display_name: image.display_name.clone(),
            edition_index: EditionIndex::new(u64::from(p.edition_index))
                .map_err(|_| corrupt("edition index"))?,
            edition_name: edition.name.clone(),
            facts: edition.declaration.as_ref().map(|d| d.facts.clone()),
            support: support_view(&edition),
        },
        pe: PackagePeView {
            pe_id: pe.id,
            display_name: pe.display_name.clone(),
            architecture: pe_decl.architecture.clone(),
            kit_version: pe_decl.kit_version.clone(),
            kit_warning: warning(&pe_decl.kit_version.value, known_bad),
        },
        created_by: p.created_by,
        created_at: p.created_at,
        updated_at: p.updated_at,
    })
}

/// Operator text for a package status reason code.
pub(crate) fn status_text(code: &str) -> String {
    let c = code_of(code);
    match (c.base(), c.as_str().split_once(':').map(|(_, p)| p)) {
        ("not_ready_content", Some(which)) => {
            format!("the package's {which} is not ready")
        }
        ("os_support_unknown", _) => {
            "the edition's release, edition and architecture have not been declared".to_owned()
        }
        (
            "release_not_supported" | "edition_not_supported" | "architecture_not_supported",
            Some(v),
        ) => {
            format!(
                "the declared {} {v} is not supported in this release",
                fact_word(c.base())
            )
        }
        ("pe_architecture_not_supported", Some(v)) => {
            format!("preinstall environment architecture {v} is not supported; only x64 is")
        }
        _ => "the package is not usable".to_owned(),
    }
}

fn fact_word(base: &str) -> &'static str {
    match base {
        "release_not_supported" => "release",
        "edition_not_supported" => "edition",
        _ => "architecture",
    }
}
