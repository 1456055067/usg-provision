//! `PUT /v1/images/{id}/editions/{index}/declaration`: the operator
//! declares an edition's release, edition and architecture (decision
//! 0013).
//!
//! Values come from closed sets (unknown → 422). Each is cross-checked
//! with what the file states through documented XML facts; a
//! contradiction is refused (422 `declaration_contradicts_file:<fact>`),
//! and a fact the file does not state is recorded as `declared`. An
//! out-of-scope declaration is recorded (the response shows the support
//! status); it is refused only when the edition is chosen for a package
//! (REQ-OS-005). A declaration on an edition a package uses is refused
//! (409 `in_use`, decision 0015).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - closed value sets;
//   cross-check with documented file facts.
// - NIST 800-53: AU-3, AU-10 basis - declarations bound to the operator,
//   with old and new values, in the audit record.
// - SPEC: specs/os-images.md#REQ-IMG-043 (decision 0013)
// - SPEC: specs/os-support.md#REQ-OS-001, #REQ-OS-002, #REQ-OS-004,
//   #REQ-OS-009
// - Decisions 0013, 0015

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use usgp_audit::Detail;
use usgp_db::{EditionDeclaration, RepoTx, Store};
use usgp_image::facts::{Declared, reconcile};
use usgp_image::os_support::evaluate;
use usgp_proto::api::EditionDeclarationRequest;
use usgp_proto::{ContentKind, ContentState, EditionIndex, codes};

use super::images::visible;
use super::{content_id, edition_view, field_error, json_response, parse_json, read_body};
use crate::body::ApiBody;
use crate::context::{Api, RequestCtx};
use crate::error::ApiError;

pub(crate) async fn put<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let id = content_id(ctx)?;
    let index = ctx
        .params
        .get(1)
        .parse::<u64>()
        .ok()
        .and_then(|i| EditionIndex::new(i).ok())
        .ok_or_else(|| ApiError::not_found("edition"))?;
    let max_json = api.config().limits.max_json_bytes;
    let body = read_body(req, max_json).await?;
    let wire = parse_json!(EditionDeclarationRequest, &body, max_json)?;
    let decl = wire.validate().map_err(|e| field_error(&e))?;

    let mut tx = api.store().begin().await?;
    let c = visible(&mut tx, id, ContentKind::Image, true).await?;
    if c.state != ContentState::Ready {
        return Err(ApiError::conflict(
            codes::NOT_READY,
            "editions can be declared only once the image file is ready",
        ));
    }
    let ed = tx
        .edition(id, index.get())
        .await?
        .ok_or_else(|| ApiError::not_found("edition"))?;
    let deps = tx.packages_using_edition(id, index.get()).await?;
    if !deps.is_empty() {
        let names: Vec<String> = deps
            .iter()
            .map(|p| format!("{} ({})", p.name.as_str(), p.id))
            .collect();
        return Err(ApiError::conflict(
            codes::IN_USE,
            format!(
                "the edition is used by {} package(s); its declaration cannot change: {}",
                deps.len(),
                names.join(", ")
            ),
        )
        .detail(Detail::new().with("dependants", &names.join(", ")))
        .dependants(super::package_refs(deps)));
    }
    // Decision 0013 item 2: cross-check with documented file facts.
    let checker = std::sync::Arc::clone(&api.inner.checker);
    let path = api.files().object_path(&c.sha256);
    let idx = index.get();
    let ff = tokio::task::spawn_blocking(move || checker.file_facts(&path, idx))
        .await
        .map_err(ApiError::internal_error)?
        .map_err(|e| ApiError::internal_error(e.reason_code()))?;
    let declared = Declared {
        release: decl.release,
        edition: decl.edition,
        architecture: decl.architecture,
    };
    let facts = reconcile(&declared, &ff).map_err(|k| {
        ApiError::unprocessable(k.reason_code(), k.operator_message()).detail(
            Detail::new()
                .with("index", &idx)
                .with("fact", k.fact.as_str())
                .with("declared", k.declared)
                .with("file", k.file),
        )
    })?;
    let support = evaluate(Some(&facts));
    let reason = support.reason().map(|r| r.as_str().to_owned());
    let mut detail = Detail::new()
        .with("index", &idx)
        .with("release", facts.release.value.as_str())
        .with("release_source", facts.release.source.as_str())
        .with("edition", facts.edition.value.as_str())
        .with("edition_source", facts.edition.source.as_str())
        .with("architecture", facts.architecture.value.as_str())
        .with("architecture_source", facts.architecture.source.as_str())
        .with("support", support.state().as_str());
    if let Some(r) = &reason {
        detail = detail.with("support_reason", r.as_str());
    }
    if let Some(old) = &ed.declaration {
        detail = detail
            .with("old_release", old.facts.release.value.as_str())
            .with("old_edition", old.facts.edition.value.as_str())
            .with("old_architecture", old.facts.architecture.value.as_str());
    }
    let d = ctx
        .ok("edition.declared")
        .target("content", &id.to_string())
        .detail(detail);
    let rec = api.append(&mut tx, &d).await?;
    let declared_at = api.now()?;
    let stored = EditionDeclaration {
        facts,
        declared_by: ctx.principal.operator.id,
        declared_at,
        declared_audit_seq: rec.seq,
    };
    tx.set_edition_declaration(id, idx, &stored, support.state(), reason.as_deref())
        .await?;
    let ed = tx
        .edition(id, idx)
        .await?
        .ok_or_else(|| ApiError::not_found("edition"))?;
    let view = edition_view(&ed)?;
    api.commit(tx, &[rec]).await?;
    json_response!(StatusCode::OK, &view)
}
