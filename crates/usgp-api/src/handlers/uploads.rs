//! Upload sessions: create (`POST /v1/uploads`), stream the body
//! (`PUT /v1/uploads/{id}`), cancel (`DELETE /v1/uploads/{id}`).
//!
//! A session is created with the declared size, file name and SHA-256
//! (and, for a PE, its declaration). Everything that can be refused
//! before the body is refused then: an empty file, a size over the stated
//! limit, an out-of-scope PE architecture, a duplicate, or too many open
//! uploads. The body then arrives in one `PUT` with `Content-Length`
//! equal to the declared size; it is written to a staging file and
//! hashed in one pass with bounded memory. A body that stops early, does
//! not match its digest, or cannot be stored leaves the content Failed
//! and the staging file removed. A complete, matching body moves the
//! content to Checking and starts the background check.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - declared size,
//   name and digest validated before any body; exact Content-Length;
//   chunked coding refused.
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   server-computed SHA-256 must equal the declared one.
// - NIST 800-53: SC-5 (Denial-of-Service Protection) - stated size limit
//   enforced before the body; open-upload caps (checked under a lock, so
//   concurrent creates cannot exceed them); bounded buffering;
//   progress-based idle timeout.
// - NIST 800-53: AU-2, AU-12 - every session state change audited in the
//   same transaction (decision 0015 item 1).
// - SPEC: specs/os-images.md#REQ-IMG-004, #REQ-IMG-020, #REQ-IMG-030,
//   #REQ-IMG-031, #REQ-IMG-032, #REQ-IMG-033, #REQ-IMG-035, #REQ-IMG-050,
//   #REQ-IMG-053
// - SPEC: specs/preinstall-env.md#REQ-PE-002, #REQ-PE-005
// - SPEC: specs/operator-access.md#REQ-AUD-001, #REQ-AUD-002
// - RFC 9110 §8.6 (Content-Length), §15.5.12 (411), §15.5.14 (413)

use std::time::Duration;

use http_body_util::BodyExt;
use hyper::body::{Bytes, Incoming};
use hyper::header;
use hyper::{Request, Response, StatusCode};
use tokio::sync::mpsc;
use usgp_audit::{AuditRecord, Detail, Outcome};
use usgp_db::{Content, DbError, NewContent, PeDeclaration, Reason, RepoTx, Store, Upload};
use usgp_image::chunks::ContentDigests;
use usgp_image::os_support::{SupportStatus, evaluate_pe};
use usgp_proto::api::{CreateUploadRequest, CreateUploadResponse, UploadAccepted};
use usgp_proto::{
    ContentId, ContentKind, ContentState, ErrorCode, Fact, UnixMicros, UploadId, UploadState, codes,
};

use super::{field_error, json_response, parse_json, read_body, upload_id};
use crate::body::ApiBody;
use crate::checker::CheckJob;
use crate::context::{Api, RequestCtx};
use crate::error::ApiError;
use crate::rbac::{Permission, allows};
use crate::store::staging_name;

fn kind_permission(kind: ContentKind) -> Permission {
    match kind {
        ContentKind::Image => Permission::ImageUpload,
        ContentKind::Pe => Permission::PeImport,
    }
}

/// 403 for the wrong kind or another operator's session (audited as
/// `authz.denied`).
fn denied(why: &'static str) -> ApiError {
    ApiError::forbidden()
        .event("authz.denied")
        .detail(Detail::new().with("why", why))
}

fn random_bytes() -> Result<[u8; 16], ApiError> {
    let mut b = [0u8; 16];
    usgp_crypto::fill_random(&mut b).map_err(ApiError::internal_error)?;
    Ok(b)
}

fn plus(t: UnixMicros, d: Duration) -> UnixMicros {
    let us = i64::try_from(d.as_micros()).unwrap_or(i64::MAX);
    UnixMicros::new(t.as_micros().saturating_add(us)).unwrap_or(t)
}

/// `POST /v1/uploads`.
pub(crate) async fn create<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let max_json = api.config().limits.max_json_bytes;
    let body = read_body(req, max_json).await?;
    let wire = parse_json!(CreateUploadRequest, &body, max_json)?;
    let u = wire.validate().map_err(|e| field_error(&e))?;
    if !allows(ctx.principal.operator.role, kind_permission(u.kind)) {
        return Err(denied("kind"));
    }
    // REQ-PE-005: a non-x64 PE is refused before any body.
    if let Some(decl) = &u.pe_declaration
        && let SupportStatus::NotSupported { reasons } = evaluate_pe(decl.architecture)
    {
        let code = reasons
            .first()
            .cloned()
            .unwrap_or(codes::PE_ARCHITECTURE_NOT_SUPPORTED);
        return Err(ApiError::unprocessable(
            code,
            format!(
                "preinstall environment architecture {} is not supported; only x64 is",
                decl.architecture.as_str()
            ),
        )
        .detail(Detail::new().with("architecture", decl.architecture.as_str())));
    }
    // REQ-IMG-031: over the stated limit, refused before any body.
    let max = api.config().content.max_upload_bytes;
    if u.size > max {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            codes::TOO_LARGE,
            format!(
                "the file is {} bytes; the server accepts at most {max} bytes",
                u.size
            ),
        )
        .limit(max)
        .detail(Detail::new().with("size", &u.size).with("limit", &max)));
    }

    let mut tx = api.store().begin().await?;
    let quota = &api.config().content;
    // SEC-009: the count and the insert below are one decision; the lock
    // is held until this transaction ends.
    tx.lock_upload_quota().await?;
    let all = tx.count_active_uploads(None).await?;
    let mine = tx
        .count_active_uploads(Some(ctx.principal.operator.id))
        .await?;
    if all >= quota.max_open_uploads || mine >= quota.max_open_uploads_per_operator {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            codes::QUOTA,
            "too many uploads are open; finish or cancel one first",
        )
        .detail(Detail::new().with("open", &all).with("open_by_you", &mine)));
    }
    if let Some(existing) = tx.content_by_sha256(&u.sha256).await? {
        return Err(duplicate(existing.id));
    }
    let upload_id = UploadId::from_random_bytes(random_bytes()?);
    let content_id = ContentId::from_random_bytes(random_bytes()?);
    let now = api.now()?;
    let expires_at = plus(now, quota.upload_session_ttl);
    let mut detail = Detail::new()
        .with("upload_id", &upload_id.to_string())
        .with("kind", u.kind.as_str())
        .with("display_name", u.display_name.as_str())
        .with("file_name", u.file_name.as_str())
        .with("size", &u.size)
        .with("sha256", &u.sha256);
    if let Some(d) = &u.pe_declaration {
        detail = detail
            .with("architecture", d.architecture.as_str())
            .with("kit_version", &d.kit_version.to_string())
            .with("source", "declared");
    }
    let draft = ctx
        .ok("content.upload.created")
        .target("content", &content_id.to_string())
        .detail(detail);
    let rec = api.append(&mut tx, &draft).await?;
    let nc = NewContent {
        id: content_id,
        kind: u.kind,
        display_name: u.display_name.clone(),
        file_name: u.file_name.clone(),
        size: u.size,
        sha256: u.sha256,
        created_by: ctx.principal.operator.id,
        initiating_audit_seq: Some(rec.seq),
        created_at: now,
        pe: u.pe_declaration.as_ref().map(|d| PeDeclaration {
            architecture: Fact::declared(d.architecture),
            kit_version: Fact::declared(d.kit_version.clone()),
        }),
    };
    let up = Upload {
        id: upload_id,
        content_id,
        operator_id: ctx.principal.operator.id,
        declared_size: u.size,
        declared_sha256: u.sha256,
        state: UploadState::Open,
        staging_name: staging_name(&upload_id),
        created_at: now,
        expires_at,
    };
    match tx.create_upload(&nc, &up).await {
        Ok(()) => {}
        Err(DbError::Conflict { .. }) => {
            // Lost a race with another upload of the same file.
            drop(tx);
            let mut tx = api.store().begin().await?;
            let existing = tx.content_by_sha256(&u.sha256).await?;
            tx.rollback().await;
            return Err(match existing {
                Some(c) => duplicate(c.id),
                None => ApiError::conflict(codes::DUPLICATE, "the content already exists"),
            });
        }
        Err(e) => return Err(e.into()),
    }
    api.commit(tx, &[rec]).await?;
    json_response!(
        StatusCode::CREATED,
        &CreateUploadResponse {
            upload_id,
            content_id,
            state: UploadState::Open,
            expires_at,
        }
    )
}

fn duplicate(existing: ContentId) -> ApiError {
    ApiError::conflict(
        codes::DUPLICATE,
        "content with this SHA-256 already exists; use the existing item",
    )
    .existing(existing)
    .detail(Detail::new().with("existing_id", &existing.to_string()))
}

/// The session and its content, locked, after the ownership and
/// permission checks.
async fn owned_session<S: Store + 'static>(
    tx: &mut S::Tx,
    ctx: &RequestCtx,
    id: UploadId,
) -> Result<(Upload, Content), ApiError> {
    let up = tx
        .lock_upload(id)
        .await?
        .ok_or_else(|| ApiError::not_found("upload"))?;
    if up.operator_id != ctx.principal.operator.id {
        return Err(denied("not_session_owner"));
    }
    let c = tx
        .lock_content(up.content_id)
        .await?
        .ok_or_else(|| super::corrupt("upload content"))?;
    if !allows(ctx.principal.operator.role, kind_permission(c.kind)) {
        return Err(denied("kind"));
    }
    Ok((up, c))
}

fn not_open() -> ApiError {
    ApiError::conflict(
        ErrorCode::new("upload_not_open").unwrap_or(codes::BAD_REQUEST),
        "this upload session is not open for a body",
    )
}

/// `PUT /v1/uploads/{id}`.
pub(crate) async fn put<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let id = upload_id(ctx)?;
    let mut tx = api.store().begin().await?;
    let (up, c) = owned_session::<S>(&mut tx, ctx, id).await?;
    if up.state != UploadState::Open {
        return Err(not_open());
    }
    let now = api.now()?;
    if now >= up.expires_at {
        return Err(ApiError::conflict(
            ErrorCode::new("upload_expired").unwrap_or(codes::BAD_REQUEST),
            "this upload session has expired; create a new one",
        ));
    }
    // RFC 9110 §8.6: the exact length is required; chunked coding is not
    // accepted (411), and the length must be the declared size.
    if req.headers().contains_key(header::TRANSFER_ENCODING) {
        return Err(length_required("chunked transfer coding is not accepted"));
    }
    let len = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .ok_or_else(|| length_required("Content-Length is required"))?
        .to_str()
        .ok()
        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| length_required("Content-Length is not a decimal length"))?;
    if len != up.declared_size {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            codes::SIZE_MISMATCH,
            format!(
                "Content-Length is {len}; the declared size is {}",
                up.declared_size
            ),
        )
        .detail(
            Detail::new()
                .with("content_length", &len)
                .with("declared_size", &up.declared_size),
        ));
    }
    tx.set_upload_state(id, &[UploadState::Open], UploadState::Streaming)
        .await?;
    let mut d = ctx
        .ok("content.upload.started")
        .target("upload", &id.to_string());
    if let Some(s) = c.initiating_audit_seq {
        d = d.initiated_by(s);
    }
    let started = api.append(&mut tx, &d).await?;
    api.commit(tx, &[started]).await?;

    match receive(api, &up, req.into_body()).await {
        Ok(digests) if digests.total == up.declared_sha256 && digests.size == up.declared_size => {
            accept(api, ctx, &up, &c, digests).await
        }
        Ok(_) => {
            fail(
                api,
                ctx,
                &up,
                &c,
                &codes::DIGEST_MISMATCH,
                "the received file does not match the declared SHA-256",
            )
            .await
        }
        Err(Received::Interrupted(why)) => fail(api, ctx, &up, &c, &codes::INTERRUPTED, why).await,
        Err(Received::Storage) => {
            fail(
                api,
                ctx,
                &up,
                &c,
                &codes::STORAGE_ERROR,
                "the file could not be stored",
            )
            .await
        }
    }
}

fn length_required(why: &str) -> ApiError {
    ApiError::new(StatusCode::LENGTH_REQUIRED, codes::LENGTH_REQUIRED, why)
}

enum Received {
    Interrupted(&'static str),
    Storage,
}

/// Frames buffered between the connection and the writer thread.
const WRITE_QUEUE: usize = 4;

/// Streams the body to the staging file on the blocking pool, hashing it
/// in the same pass. Memory is bounded by [`WRITE_QUEUE`] frames.
async fn receive<S: Store + 'static>(
    api: &Api<S>,
    up: &Upload,
    mut body: Incoming,
) -> Result<ContentDigests, Received> {
    let files = api.files().clone();
    let name = up.staging_name.clone();
    let (tx, mut rx) = mpsc::channel::<Bytes>(WRITE_QUEUE);
    let writer = tokio::task::spawn_blocking(move || {
        let file = files.create_staging(&name)?;
        let mut w = crate::store::StagingWriter::new(file);
        while let Some(b) = rx.blocking_recv() {
            w.write(&b)?;
        }
        w.finish()
    });
    let idle = api.config().content.upload_idle_timeout;
    let mut received: u64 = 0;
    let mut outcome: Result<(), Received> = Ok(());
    loop {
        match tokio::time::timeout(idle, body.frame()).await {
            Err(_) => {
                outcome = Err(Received::Interrupted("the upload stalled"));
                break;
            }
            Ok(None) => break,
            Ok(Some(Err(_))) => {
                outcome = Err(Received::Interrupted(
                    "the upload connection was interrupted",
                ));
                break;
            }
            Ok(Some(Ok(frame))) => {
                let Ok(data) = frame.into_data() else {
                    continue;
                };
                received = received.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
                if received > up.declared_size {
                    outcome = Err(Received::Interrupted("the body is longer than declared"));
                    break;
                }
                if tx.send(data).await.is_err() {
                    outcome = Err(Received::Storage);
                    break;
                }
            }
        }
    }
    drop(tx);
    let written = writer.await;
    outcome?;
    let digests = match written {
        Ok(Ok(d)) => d,
        _ => return Err(Received::Storage),
    };
    if received != up.declared_size || digests.size != up.declared_size {
        return Err(Received::Interrupted(
            "the body ended before the declared size",
        ));
    }
    Ok(digests)
}

/// The body arrived and matched: Streaming → Complete, Receiving →
/// Checking, then the check runs in the background.
async fn accept<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    up: &Upload,
    c: &Content,
    digests: ContentDigests,
) -> Result<Response<ApiBody>, ApiError> {
    let at = api.now()?;
    let result: Result<(u64, Vec<AuditRecord>, S::Tx), ApiError> = async {
        let mut tx = api.store().begin().await?;
        tx.set_upload_state(up.id, &[UploadState::Streaming], UploadState::Complete)
            .await?;
        tx.set_content_state(
            c.id,
            &[ContentState::Receiving],
            ContentState::Checking,
            None,
            at,
        )
        .await?;
        let init = c.initiating_audit_seq;
        let mut d = ctx
            .ok("content.upload.received")
            .target("content", &c.id.to_string())
            .detail(
                Detail::new()
                    .with("upload_id", &up.id.to_string())
                    .with("size", &digests.size)
                    .with("sha256", &digests.total),
            );
        let mut c_d = ctx
            .ok("content.check.started")
            .target("content", &c.id.to_string());
        if let Some(s) = init {
            d = d.initiated_by(s);
            c_d = c_d.initiated_by(s);
        }
        let r1 = api.append(&mut tx, &d).await?;
        let r2 = api.append(&mut tx, &c_d).await?;
        Ok((r1.seq, vec![r1, r2], tx))
    }
    .await;
    let (_, recs, tx) = match result {
        Ok(v) => v,
        Err(e) => {
            // The state change could not be recorded: the content must not
            // be checked. Remove the data and record the failure if possible.
            let files = api.files().clone();
            let name = up.staging_name.clone();
            let _ = tokio::task::spawn_blocking(move || files.remove_staging(&name)).await;
            let _ = mark_failed(
                api,
                ctx,
                up,
                c,
                &codes::AUDIT_UNAVAILABLE,
                "the upload could not be recorded",
            )
            .await;
            return Err(e.audited());
        }
    };
    api.commit(tx, &recs).await?;
    let job = CheckJob {
        content_id: c.id,
        staging_name: up.staging_name.clone(),
        digests,
        initiating_seq: c.initiating_audit_seq,
    };
    let bg = api.clone();
    tokio::spawn(async move { bg.run_check(job).await });
    let mut r = json_response!(
        StatusCode::ACCEPTED,
        &UploadAccepted {
            content_id: c.id,
            state: ContentState::Checking,
        }
    )?;
    if let Ok(v) = hyper::header::HeaderValue::from_str(&format!("/v1/content/{}", c.id)) {
        r.headers_mut().insert(header::CONTENT_LOCATION, v);
    }
    Ok(r)
}

/// Marks the session and content Failed with `code` (audited).
async fn mark_failed<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    up: &Upload,
    c: &Content,
    code: &ErrorCode,
    text: &str,
) -> Result<(), ApiError> {
    let mut tx = api.store().begin().await?;
    let at = api.now()?;
    tx.set_upload_state(
        up.id,
        &[UploadState::Open, UploadState::Streaming],
        UploadState::Failed,
    )
    .await?;
    tx.set_content_state(
        c.id,
        &[ContentState::Receiving],
        ContentState::Failed,
        Some(&Reason {
            code: code.as_str().to_owned(),
            text: text.to_owned(),
        }),
        at,
    )
    .await?;
    let mut d1 = ctx
        .draft("content.upload.failed", Outcome::Failure)
        .target("upload", &up.id.to_string())
        .reason(code.as_str())
        .detail(Detail::new().with("content_id", &c.id.to_string()));
    let mut d2 = ctx
        .draft("content.failed", Outcome::Failure)
        .target("content", &c.id.to_string())
        .reason(code.as_str());
    if let Some(s) = c.initiating_audit_seq {
        d1 = d1.initiated_by(s);
        d2 = d2.initiated_by(s);
    }
    let r1 = api.append(&mut tx, &d1).await?;
    let r2 = api.append(&mut tx, &d2).await?;
    api.commit(tx, &[r1, r2]).await
}

/// The body did not arrive whole or did not match: remove the partial
/// data (REQ-IMG-035) and mark everything Failed with `code`.
async fn fail<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    up: &Upload,
    c: &Content,
    code: &ErrorCode,
    text: &str,
) -> Result<Response<ApiBody>, ApiError> {
    let files = api.files().clone();
    let name = up.staging_name.clone();
    let removed = tokio::task::spawn_blocking(move || files.remove_staging(&name)).await;
    let marked = mark_failed(api, ctx, up, c, code, text).await;
    if let Err(e) = marked {
        // Left Streaming/Receiving; start-up recovery fails it later.
        return Err(e.audited());
    }
    if !matches!(removed, Ok(Ok(()))) {
        return Err(ApiError::internal_error("partial upload data could not be removed").audited());
    }
    let status = if *code == codes::DIGEST_MISMATCH {
        StatusCode::UNPROCESSABLE_ENTITY
    } else if *code == codes::STORAGE_ERROR {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    };
    Err(ApiError::new(status, code.clone(), text).audited())
}

/// `DELETE /v1/uploads/{id}`: cancels an open session (REQ-IMG-035).
pub(crate) async fn cancel<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let id = upload_id(ctx)?;
    let mut tx = api.store().begin().await?;
    let (up, c) = owned_session::<S>(&mut tx, ctx, id).await?;
    if up.state != UploadState::Open {
        return Err(not_open());
    }
    let at = api.now()?;
    tx.set_upload_state(id, &[UploadState::Open], UploadState::Cancelled)
        .await?;
    tx.set_content_state(
        c.id,
        &[ContentState::Receiving],
        ContentState::Failed,
        Some(&Reason {
            code: codes::CANCELLED.as_str().to_owned(),
            text: "the operator cancelled the upload".to_owned(),
        }),
        at,
    )
    .await?;
    let mut d1 = ctx
        .ok("content.upload.cancelled")
        .target("upload", &id.to_string())
        .detail(Detail::new().with("content_id", &c.id.to_string()));
    let mut d2 = ctx
        .draft("content.failed", Outcome::Failure)
        .target("content", &c.id.to_string())
        .reason(codes::CANCELLED.as_str());
    if let Some(s) = c.initiating_audit_seq {
        d1 = d1.initiated_by(s);
        d2 = d2.initiated_by(s);
    }
    let r1 = api.append(&mut tx, &d1).await?;
    let r2 = api.append(&mut tx, &d2).await?;
    api.commit(tx, &[r1, r2]).await?;
    let files = api.files().clone();
    let name = up.staging_name.clone();
    let _ = tokio::task::spawn_blocking(move || files.remove_staging(&name)).await;
    let mut r = Response::new(ApiBody::empty());
    *r.status_mut() = StatusCode::NO_CONTENT;
    Ok(r)
}
