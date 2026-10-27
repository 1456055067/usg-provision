//! Preinstall environments: list, view, delete (REQ-PE-006, REQ-PE-007,
//! REQ-PE-009).

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-12 - protected reads audited.
// - SPEC: specs/preinstall-env.md#REQ-PE-006 (name, architecture and
//   version with source, import time, status, digest, packages using it),
//   #REQ-PE-009 (kit warning shown)
// - SPEC: specs/os-images.md#REQ-IMG-015 (in-use delete refused)

use hyper::{Request, Response, StatusCode};
use usgp_audit::Detail;
use usgp_db::{RepoTx, Store};
use usgp_proto::ContentKind;
use usgp_proto::api::PeList;

use super::images::{VISIBLE, delete_content, visible};
use super::{content_id, content_view_etag, json_response, pe_view, with_etag};
use crate::body::ApiBody;
use crate::context::{Api, RequestCtx};
use crate::error::ApiError;

pub(crate) async fn list<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let known_bad = &api.config().known_bad_kit_versions;
    let mut tx = api.store().begin().await?;
    let items = tx.list_content(Some(ContentKind::Pe), &VISIBLE).await?;
    let mut pe = Vec::with_capacity(items.len());
    for c in &items {
        let used = tx.packages_using_content(c.id).await?;
        pe.push(pe_view(c, used, known_bad)?);
    }
    let d = ctx
        .ok("pe.list.read")
        .detail(Detail::new().with("count", &pe.len()));
    let rec = api.append(&mut tx, &d).await?;
    api.commit(tx, &[rec]).await?;
    json_response!(StatusCode::OK, &PeList { pe })
}

pub(crate) async fn get<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let id = content_id(ctx)?;
    let mut tx = api.store().begin().await?;
    let c = visible(&mut tx, id, ContentKind::Pe, false).await?;
    let used = tx.packages_using_content(c.id).await?;
    let view = pe_view(&c, used, &api.config().known_bad_kit_versions)?;
    let d = ctx.ok("pe.read").target("content", &id.to_string());
    let rec = api.append(&mut tx, &d).await?;
    api.commit(tx, &[rec]).await?;
    Ok(with_etag(
        json_response!(StatusCode::OK, &view)?,
        &content_view_etag(&c),
    ))
}

pub(crate) async fn delete<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: &Request<hyper::body::Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    delete_content(api, ctx, req, ContentKind::Pe).await
}
