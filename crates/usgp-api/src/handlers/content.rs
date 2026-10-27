//! Content download (`GET /v1/content/{id}`) and signed content manifests
//! (`GET /v1/images/{id}/manifest`, `GET /v1/pe/{id}/manifest`).
//!
//! Integrity on every use (decision 0011, plan section 5.7):
//!
//! 1. the stored content manifest's signature is verified with a trusted
//!    content key, and its id, kind, size and digest must equal the
//!    database row;
//! 2. the object's length must equal the signed size;
//! 3. each 8 MiB chunk is read, hashed and compared with its signed
//!    digest before any of its bytes are sent; the whole-file digest is
//!    checked at the end.
//!
//! A mismatch before the response head is a 500 `integrity_failed`;
//! after it, the connection is aborted. Either way the content becomes
//! Failed (`integrity_failed_on_use`), the failure is audited, and every
//! Ready package using it becomes `not_usable`.
//!
//! Only an integrity failure ([`VerifyError::is_integrity`]) fails the
//! content. An I/O error reading the object (for example a transient disk
//! error, or the object missing) is not evidence about the bytes: the
//! download is refused (503 `storage_error`) or aborted, audited as
//! `content.download.aborted` with the I/O error kind, and the content
//! stays Ready (finding SEC-008).
//!
//! A caller that lacks either view permission gets 403 both for an absent
//! item and for an item of the kind it may not view, so the answer never
//! depends on whether the item exists (finding SEC-010). Only a caller
//! holding both sees 404 for an absent item.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7, SI-7(1), SI-7(6) (Software, Firmware, and
//   Information Integrity; integrity checks; cryptographic protection) -
//   signed manifest and per-chunk verification on every use.
// - NIST 800-53: SC-5 - one chunk buffered per stream; idle timeout on a
//   stalled reader; a transient read error does not permanently fail
//   content.
// - NIST 800-53: AC-3 - no existence leak to a caller without view
//   permission (REQ-RBAC-003).
// - NIST 800-53: AU-2, AU-12 - download start, end and integrity failures
//   audited (REQ-AUD-001: reads of protected content).
// - SPEC: specs/os-images.md#REQ-IMG-033, #REQ-IMG-050
// - SPEC: specs/preinstall-env.md#REQ-PE-008
// - Decision 0011
// - RFC 9110 §8.6 (Content-Length), §8.8.3 (ETag)

use hyper::body::Bytes;
use hyper::header::{self, HeaderValue};
use hyper::{Response, StatusCode};
use tokio::sync::mpsc;
use usgp_audit::{Detail, Outcome};
use usgp_db::{Content, Reason, RepoTx, Store};
use usgp_proto::PackageStatus;
use usgp_proto::{ContentKind, ContentManifestV1, ContentState, PayloadType, codes};

use super::content_id;
use super::images::{kind_word, visible};
use crate::body::ApiBody;
use crate::context::{Api, RequestCtx};
use crate::error::ApiError;
use crate::manifest::{envelope, open_content};
use crate::rbac::{Permission, allows};
use crate::store::{VerifiedReader, VerifyError};

/// 500 `integrity_failed`; the failure was already audited by
/// [`Api::integrity_failed`].
fn integrity_error(what: &str) -> ApiError {
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        codes::INTEGRITY_FAILED,
        "the content failed its integrity check and was not served; it is now marked failed",
    )
    .internal(what)
    .event("content.integrity.failed")
    .audited()
}

/// 503 `storage_error`: the object could not be read (not an integrity
/// failure; the content stays Ready). Already audited as
/// `content.download.aborted`.
fn storage_error(kind: std::io::ErrorKind) -> ApiError {
    ApiError::new(
        StatusCode::SERVICE_UNAVAILABLE,
        codes::STORAGE_ERROR,
        "the content could not be read from storage and was not served; try again later",
    )
    .internal(format!("content object read failed: {kind}"))
    .event("content.download.aborted")
    .audited()
}

/// The error for an absent (or deleted) item (SEC-010): 404 only for a
/// caller that may view both kinds; otherwise the same 403 an item of the
/// other kind gets.
fn absent_item(views_all: bool) -> ApiError {
    if views_all {
        ApiError::not_found("item")
    } else {
        ApiError::forbidden().event("authz.denied")
    }
}

/// The I/O error kind of a verification error, if it is not an integrity
/// failure.
fn io_kind(e: &VerifyError) -> Option<std::io::ErrorKind> {
    match e {
        VerifyError::Io(io) if !e.is_integrity() => Some(io.kind()),
        _ => None,
    }
}

/// Verifies the stored manifest of Ready content `c` and checks it
/// against the row.
pub(crate) fn verified_manifest<S: Store + 'static>(
    api: &Api<S>,
    c: &Content,
) -> Result<ContentManifestV1, &'static str> {
    let stored = c.manifest.as_ref().ok_or("content manifest missing")?;
    let m = open_content(api.keys(), stored)
        .map_err(|_| "content manifest signature or payload invalid")?;
    if m.content_id != c.id || m.kind != c.kind || m.size != c.size || m.sha256 != c.sha256 {
        return Err("content manifest does not match the content record");
    }
    Ok(m)
}

impl<S: Store + 'static> Api<S> {
    /// Marks Ready content Failed after an integrity failure on use and
    /// makes its Ready packages `not_usable`, all audited in one
    /// transaction (plan section 5.7).
    pub(crate) async fn integrity_failed(
        &self,
        ctx: &RequestCtx,
        c: &Content,
        what: &str,
    ) -> Result<(), ApiError> {
        let mut tx = self.store().begin().await?;
        let at = self.now()?;
        let reason = Reason {
            code: codes::INTEGRITY_FAILED_ON_USE.as_str().to_owned(),
            text: "the content did not match its signed manifest when used".to_owned(),
        };
        let mut recs = Vec::new();
        let d = ctx
            .draft("content.integrity.failed", Outcome::Failure)
            .target("content", &c.id.to_string())
            .reason(codes::INTEGRITY_FAILED.as_str())
            .detail(Detail::new().with("what", what).with("sha256", &c.sha256));
        let first = self.append(&mut tx, &d).await?;
        let seq = first.seq;
        recs.push(first);
        let changed = tx
            .set_content_state(
                c.id,
                &[ContentState::Ready],
                ContentState::Failed,
                Some(&reason),
                at,
            )
            .await;
        match changed {
            Ok(()) => {
                let d = ctx
                    .draft("content.failed", Outcome::Failure)
                    .target("content", &c.id.to_string())
                    .reason(codes::INTEGRITY_FAILED_ON_USE.as_str())
                    .initiated_by(seq);
                recs.push(self.append(&mut tx, &d).await?);
            }
            // Already not Ready (another request got there first).
            Err(e) if e.is_conflict() => {}
            Err(e) => return Err(e.into()),
        }
        let which = match c.kind {
            ContentKind::Image => "image",
            ContentKind::Pe => "pe",
        };
        let code = codes::NOT_READY_CONTENT
            .with_param(which)
            .unwrap_or(codes::NOT_READY_CONTENT);
        for p in tx.packages_using_content(c.id).await? {
            let Some(pkg) = tx.lock_package(p.id).await? else {
                continue;
            };
            if pkg.status != PackageStatus::Ready {
                continue;
            }
            tx.set_package_status(
                p.id,
                PackageStatus::NotUsable,
                Some(code.as_str()),
                None,
                at,
            )
            .await?;
            let d = ctx
                .draft("package.status.changed", Outcome::Success)
                .target("package", &p.id.to_string())
                .reason(code.as_str())
                .initiated_by(seq)
                .detail(
                    Detail::new()
                        .with("from", PackageStatus::Ready.as_str())
                        .with("to", PackageStatus::NotUsable.as_str()),
                );
            recs.push(self.append(&mut tx, &d).await?);
        }
        self.commit(tx, &recs).await
    }
}

/// `GET /v1/{images|pe}/{id}/manifest`: the signed envelope, verified
/// before it is served.
pub(crate) async fn manifest<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    kind: ContentKind,
) -> Result<Response<ApiBody>, ApiError> {
    let id = content_id(ctx)?;
    let mut tx = api.store().begin().await?;
    let c = visible(&mut tx, id, kind, false).await?;
    if c.state != ContentState::Ready {
        return Err(ApiError::conflict(
            codes::NOT_READY,
            format!("the {} is not ready", kind_word(kind)),
        ));
    }
    let stored = match verified_manifest(api, &c) {
        Ok(_) => c
            .manifest
            .clone()
            .ok_or_else(|| ApiError::internal_error("manifest missing"))?,
        Err(what) => {
            drop(tx);
            let _ = api.integrity_failed(ctx, &c, what).await;
            return Err(integrity_error(what));
        }
    };
    let env =
        envelope(PayloadType::ContentManifestV1, &stored).map_err(ApiError::internal_error)?;
    let json = env.to_json().map_err(ApiError::internal_error)?;
    let d = ctx
        .ok("content.manifest.read")
        .target("content", &id.to_string())
        .detail(Detail::new().with("key_id", &stored.key_id));
    let rec = api.append(&mut tx, &d).await?;
    api.commit(tx, &[rec]).await?;
    let mut r = Response::new(ApiBody::full(json));
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(usgp_proto::api::JSON_MEDIA_TYPE),
    );
    Ok(r)
}

/// `GET /v1/content/{id}`: the verified bytes.
pub(crate) async fn download<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let role = ctx.principal.operator.role;
    // SEC-010: a caller that lacks either view permission gets the same
    // 403 for an absent item as for an item of the kind it may not view,
    // so the status never reveals whether an id exists.
    let views_all = allows(role, Permission::ImageView) && allows(role, Permission::PeView);
    let id = content_id(ctx)?;
    let mut tx = api.store().begin().await?;
    let c = tx
        .content(id)
        .await?
        .filter(|c| c.state != ContentState::Deleted);
    tx.rollback().await;
    let Some(c) = c else {
        return Err(absent_item(views_all));
    };
    let need = match c.kind {
        ContentKind::Image => Permission::ImageView,
        ContentKind::Pe => Permission::PeView,
    };
    if !allows(role, need) {
        return Err(ApiError::forbidden().event("authz.denied"));
    }
    if c.state != ContentState::Ready {
        return Err(ApiError::conflict(
            codes::NOT_READY,
            "the item is not ready",
        ));
    }
    let m = match verified_manifest(api, &c) {
        Ok(m) => m,
        Err(what) => {
            let _ = api.integrity_failed(ctx, &c, what).await;
            return Err(integrity_error(what));
        }
    };
    // Open the object and verify the first chunk before the response head
    // goes out.
    let files = api.files().clone();
    let m2 = m.clone();
    let opened = tokio::task::spawn_blocking(move || {
        let mut r = files.open_verified(&m2)?;
        let first = r.next_chunk()?;
        Ok::<_, VerifyError>((r, first))
    })
    .await
    .map_err(ApiError::internal_error)?;
    let (reader, first) = match opened {
        Ok(v) => v,
        // An object that cannot be read: not served, content unchanged
        // (SEC-008).
        Err(e) if !e.is_integrity() => {
            let kind = io_kind(&e).unwrap_or(std::io::ErrorKind::Other);
            let d = ctx
                .draft("content.download.aborted", Outcome::Failure)
                .target("content", &id.to_string())
                .reason(codes::STORAGE_ERROR.as_str())
                .detail(
                    Detail::new()
                        .with("io_kind", &kind.to_string())
                        .with("bytes_sent", &0u64)
                        .with("size", &c.size),
                );
            api.record_refusal(&d).await;
            return Err(storage_error(kind));
        }
        // A mismatch: not served, and the content is marked failed
        // (REQ-IMG-050).
        Err(e) => {
            let what = e.to_string();
            let _ = api.integrity_failed(ctx, &c, &what).await;
            return Err(integrity_error(&what));
        }
    };
    let d = ctx
        .ok("content.download")
        .target("content", &id.to_string())
        .detail(
            Detail::new()
                .with("size", &m.size)
                .with("sha256", &m.sha256)
                .with("kind", c.kind.as_str()),
        );
    let started = api.record(&d).await?;

    let (tx_body, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(1);
    let job = StreamJob {
        api: api.clone(),
        ctx: ctx.clone(),
        content: c.clone(),
        out: tx_body,
        idle: api.config().limits.idle_timeout,
        started: started.seq,
    };
    tokio::spawn(job.run(reader, first));

    let mut r = Response::new(ApiBody::Stream {
        rx,
        remaining: m.size,
    });
    let h = r.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(v) = HeaderValue::from_str(&usgp_proto::api::content_etag(&m.sha256)) {
        h.insert(header::ETAG, v);
    }
    Ok(r)
}

/// A running download.
struct StreamJob<S: Store> {
    api: Api<S>,
    ctx: RequestCtx,
    content: Content,
    out: mpsc::Sender<Result<Bytes, std::io::Error>>,
    idle: std::time::Duration,
    started: u64,
}

impl<S: Store + 'static> StreamJob<S> {
    /// Sends verified chunks until the end, a mismatch, or the client
    /// going away; then audits how the download ended.
    async fn run(self, mut reader: VerifiedReader, first: Option<Vec<u8>>) {
        let Self {
            api,
            ctx,
            content: c,
            out,
            idle,
            started,
        } = self;
        let mut sent: u64 = 0;
        let mut next = first;
        let mut io_failure: Option<std::io::ErrorKind> = None;
        let end: Result<(), String> = loop {
            let Some(chunk) = next.take() else {
                break Ok(());
            };
            let n = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
            match tokio::time::timeout(idle, out.send(Ok(Bytes::from(chunk)))).await {
                Ok(Ok(())) => sent = sent.saturating_add(n),
                Ok(Err(_)) => break Err("client went away".to_owned()),
                Err(_) => break Err("client stopped reading".to_owned()),
            }
            let joined = tokio::task::spawn_blocking(move || {
                let r = reader.next_chunk();
                (reader, r)
            })
            .await;
            let (r, res) = match joined {
                Ok(v) => v,
                Err(_) => break Err("reader task failed".to_owned()),
            };
            reader = r;
            match res {
                Ok(v) => next = v,
                Err(e) if !e.is_integrity() => {
                    // A read error: abort, but the content stays Ready
                    // (SEC-008).
                    let kind = io_kind(&e).unwrap_or(std::io::ErrorKind::Other);
                    io_failure = Some(kind);
                    let _ = out
                        .send(Err(std::io::Error::other("content read failed")))
                        .await;
                    break Err(codes::STORAGE_ERROR.as_str().to_owned());
                }
                Err(e) => {
                    let what = e.to_string();
                    // Abort the response: the client sees a cut stream.
                    let _ = out
                        .send(Err(std::io::Error::other("integrity check failed")))
                        .await;
                    let _ = api.integrity_failed(&ctx, &c, &what).await;
                    break Err(what);
                }
            }
        };
        let (event, outcome) = match &end {
            Ok(()) => ("content.download.completed", Outcome::Success),
            Err(_) => ("content.download.aborted", Outcome::Failure),
        };
        let mut detail = Detail::new()
            .with("bytes_sent", &sent)
            .with("size", &c.size);
        if let Some(kind) = io_failure {
            detail = detail.with("io_kind", &kind.to_string());
        }
        let mut d = ctx
            .draft(event, outcome)
            .target("content", &c.id.to_string())
            .initiated_by(started)
            .detail(detail);
        if let Err(why) = &end {
            d = d.reason(why);
        }
        api.record_refusal(&d).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_item_reveals_nothing_without_both_views() {
        assert_eq!(absent_item(true).status, StatusCode::NOT_FOUND);
        let e = absent_item(false);
        assert_eq!(e.status, StatusCode::FORBIDDEN);
        assert_eq!(e.status, ApiError::forbidden().status);
        assert_eq!(e.code(), ApiError::forbidden().code());
        assert_eq!(e.event, Some("authz.denied"));
    }

    #[test]
    fn io_errors_are_not_integrity_failures() {
        let io = VerifyError::Io(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(!io.is_integrity());
        assert_eq!(io_kind(&io), Some(std::io::ErrorKind::NotFound));
        assert!(VerifyError::NotRegularFile.is_integrity());
        assert_eq!(io_kind(&VerifyError::NotRegularFile), None);
        assert!(VerifyError::ChunkMismatch { index: 0 }.is_integrity());
        let e = storage_error(std::io::ErrorKind::Other);
        assert_eq!(e.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(e.code(), &codes::STORAGE_ERROR);
    }
}
