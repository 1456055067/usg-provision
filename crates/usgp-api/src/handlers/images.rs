//! Image files: list, view, delete (plan M2 section 3.2), and the delete
//! logic shared with preinstall environments.

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-12 - protected reads audited (REQ-AUD-001).
// - NIST 800-53: SI-10 (Information Input Validation) - deletion needs an
//   If-Match precondition naming the viewed content; AU-12 - the delete
//   and its refusals are audited.
// - NIST 800-53: SI-7 - deletion refused while in use (decision 0015
//   item 2); objects unlinked only after commit.
// - SPEC: specs/os-images.md#REQ-IMG-015 (in-use delete refused naming
//   dependants), #REQ-IMG-020, #REQ-IMG-040, #REQ-IMG-042, #REQ-IMG-043
// - SPEC: specs/operator-access.md#REQ-AUD-001, #REQ-AUD-002
// - RFC 9110 §13.1.1 (If-Match), §15.5.13 (412), RFC 6585 §3 (428)

use hyper::{Request, Response, StatusCode};
use usgp_audit::Detail;
use usgp_db::{Content, RepoTx, Store};
use usgp_proto::api::{ImageList, content_etag};
use usgp_proto::{ContentKind, ContentState, codes};

use super::{
    content_id, content_view_etag, if_match, image_view, json_response, package_refs, with_etag,
};
use crate::body::ApiBody;
use crate::context::{Api, RequestCtx};
use crate::error::ApiError;

/// States listed and viewable (deleted items are gone).
pub(crate) const VISIBLE: [ContentState; 4] = [
    ContentState::Receiving,
    ContentState::Checking,
    ContentState::Ready,
    ContentState::Failed,
];

pub(crate) async fn list<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let mut tx = api.store().begin().await?;
    let items = tx.list_content(Some(ContentKind::Image), &VISIBLE).await?;
    let mut images = Vec::with_capacity(items.len());
    for c in &items {
        let eds = tx.editions(c.id).await?;
        images.push(image_view(c, &eds)?);
    }
    let d = ctx
        .ok("image.list.read")
        .detail(Detail::new().with("count", &images.len()));
    let rec = api.append(&mut tx, &d).await?;
    api.commit(tx, &[rec]).await?;
    json_response!(StatusCode::OK, &ImageList { images })
}

/// A visible item of `kind`, or 404.
pub(crate) async fn visible<T: RepoTx>(
    tx: &mut T,
    id: usgp_proto::ContentId,
    kind: ContentKind,
    lock: bool,
) -> Result<Content, ApiError> {
    let c = if lock {
        tx.lock_content(id).await?
    } else {
        tx.content(id).await?
    };
    c.filter(|c| c.kind == kind && c.state != ContentState::Deleted)
        .ok_or_else(|| ApiError::not_found(kind_word(kind)))
}

pub(crate) const fn kind_word(kind: ContentKind) -> &'static str {
    match kind {
        ContentKind::Image => "image file",
        ContentKind::Pe => "preinstall environment",
    }
}

pub(crate) async fn get<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let id = content_id(ctx)?;
    let mut tx = api.store().begin().await?;
    let c = visible(&mut tx, id, ContentKind::Image, false).await?;
    let eds = tx.editions(c.id).await?;
    let view = image_view(&c, &eds)?;
    let d = ctx.ok("image.read").target("content", &id.to_string());
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
    delete_content(api, ctx, req, ContentKind::Image).await
}

/// Deletes an image file or PE: `If-Match` required (428) and equal to
/// the item's ETag (412); refused while in progress (409 `not_ready`) or
/// in use (409 `in_use` naming the packages, decision 0015 item 2).
pub(crate) async fn delete_content<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: &Request<hyper::body::Incoming>,
    kind: ContentKind,
) -> Result<Response<ApiBody>, ApiError> {
    let id = content_id(ctx)?;
    let tag = if_match(req)?.to_vec();
    let mut tx = api.store().begin().await?;
    let c = visible(&mut tx, id, kind, true).await?;
    if tag != content_etag(&c.sha256).as_bytes() {
        return Err(ApiError::precondition_failed());
    }
    if c.state.is_in_progress() {
        return Err(ApiError::conflict(
            codes::NOT_READY,
            "the item is still being uploaded or checked; cancel the upload or wait",
        ));
    }
    let deps = tx.packages_using_content(id).await?;
    if !deps.is_empty() {
        let names: Vec<String> = deps
            .iter()
            .map(|p| format!("{} ({})", p.name.as_str(), p.id))
            .collect();
        return Err(ApiError::conflict(
            codes::IN_USE,
            format!(
                "the item is used by {} package(s); remove it from them first: {}",
                deps.len(),
                names.join(", ")
            ),
        )
        .detail(
            Detail::new()
                .with("dependants", &names.join(", "))
                .with("count", &deps.len()),
        )
        .dependants(package_refs(deps)));
    }
    let at = api.now()?;
    tx.set_content_state(
        id,
        &[ContentState::Ready, ContentState::Failed],
        ContentState::Deleted,
        None,
        at,
    )
    .await?;
    let event = match kind {
        ContentKind::Image => "image.deleted",
        ContentKind::Pe => "pe.deleted",
    };
    let mut d = ctx.ok(event).target("content", &id.to_string()).detail(
        Detail::new()
            .with("sha256", &c.sha256)
            .with("previous_state", c.state.as_str()),
    );
    if let Some(s) = c.initiating_audit_seq {
        d = d.initiated_by(s);
    }
    let rec = api.append(&mut tx, &d).await?;
    api.commit(tx, &[rec]).await?;
    if c.state == ContentState::Ready {
        // Unlink only after the commit, and only if no live item has the
        // same digest again (an orphan is reported at start-up otherwise).
        let mut tx = api.store().begin().await?;
        let live = tx.content_by_sha256(&c.sha256).await?;
        tx.rollback().await;
        if live.is_none() {
            let files = api.files().clone();
            let sha = c.sha256;
            let _ = tokio::task::spawn_blocking(move || files.remove_object(&sha)).await;
        }
    }
    let mut r = Response::new(ApiBody::empty());
    *r.status_mut() = StatusCode::NO_CONTENT;
    Ok(r)
}
