//! Agent-package signer keys (M4 plan sections 1.7 and 3.2; decision 0025
//! item 5): an administrator registers, lists and revokes the ECDSA P-384
//! keys whose detached signatures make an agent package acceptable.
//!
//! Revoking a signer (WU-6 follow-up U-3), in **one transaction**:
//!
//! 1. marks the signer revoked (`agent_signer.revoked`);
//! 2. refuses each of its ready agent packages with reason
//!    `signer_revoked`, one `agent_package.refused` record each;
//! 3. takes every ready package that names one of them out of ready, one
//!    `package.status.changed` record each.
//!
//! If any record cannot be written, nothing changes (AU-5). Jobs already
//! confirmed carry on: their plan is signed and their content pinned.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3, AC-6 - `agent_signer.manage`, held by the
//   administrator only.
// - NIST 800-53: AU-2, AU-3, AU-12 - every change and every consequence of
//   a revocation recorded in the same transaction.
// - NIST 800-53: SI-7 - a revoked signer's packages stop being usable.
// - NIST 800-53: SC-12, SC-13 - the key must be a P-384 SPKI the FIPS
//   module accepts; its id is its SHA-256.
// - NIST 800-53: SI-10 - strict body parsing.
// - SPEC: specs/agent-handoff.md#REQ-AGT-003, #REQ-AGT-004
// - Decisions 0024 item 2, 0025 item 5

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use usgp_audit::{Detail, Outcome};
use usgp_db::{
    AGENT_PACKAGE_REFUSED, AgentSigner, AgentSignerId, DbError, RepoTx, SIGNER_REVOKED, Store,
};
use usgp_proto::{DisplayName, OperatorId, P384Spki, PackageStatus, UnixMicros, codes};

use super::auth_codes::random;
use super::{json_response, parse_json, read_body};
use crate::body::ApiBody;
use crate::context::{Api, RequestCtx};
use crate::error::ApiError;

/// `POST /v1/agent-signers` body.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AddSigner {
    /// Operator-given name.
    name: DisplayName,
    /// The public key, P-384 SPKI DER, padded base64.
    spki_b64: P384Spki,
}

/// The view of a signer (public data only).
#[derive(Debug, serde::Serialize)]
pub(crate) struct SignerView {
    id: String,
    name: DisplayName,
    key_id: usgp_common::Sha256Digest,
    spki_b64: P384Spki,
    added_by: OperatorId,
    added_at: UnixMicros,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_by: Option<OperatorId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_at: Option<UnixMicros>,
}

fn view(s: &AgentSigner) -> SignerView {
    SignerView {
        id: s.id.to_string(),
        name: s.name.clone(),
        key_id: s.key_id,
        spki_b64: s.spki.clone(),
        added_by: s.added_by,
        added_at: s.added_at,
        revoked_by: s.revoked.map(|(by, _)| by),
        revoked_at: s.revoked.map(|(_, at)| at),
    }
}

#[derive(Debug, serde::Serialize)]
struct SignerList {
    signers: Vec<SignerView>,
}

fn signer_id(ctx: &RequestCtx) -> Result<AgentSignerId, ApiError> {
    AgentSignerId::parse(ctx.params.get(0)).ok_or_else(|| ApiError::not_found("agent signer"))
}

/// `POST /v1/agent-signers`.
pub(crate) async fn add<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let max = api.config().limits.max_json_bytes;
    let body = read_body(req, max).await?;
    let a = parse_json!(AddSigner, &body, max)?;
    // The FIPS module must accept the key as a P-384 verification key.
    usgp_crypto::VerifyingKey::from_spki_der(a.spki_b64.as_der()).map_err(|_| {
        ApiError::unprocessable(
            codes::INVALID_VALUE
                .with_param("spki_b64")
                .unwrap_or(codes::INVALID_VALUE),
            "spki_b64 is not a P-384 public key",
        )
    })?;
    let key_id = usgp_crypto::sha256(a.spki_b64.as_der());
    let at = api.now()?;
    let s = AgentSigner {
        id: AgentSignerId::from_random_bytes(random::<16>()?),
        spki: a.spki_b64,
        key_id,
        name: a.name,
        added_by: ctx.principal.operator.id,
        added_at: at,
        revoked: None,
    };
    let mut tx = api.store().begin().await?;
    match tx.insert_agent_signer(&s).await {
        Ok(()) => {}
        Err(DbError::Conflict { .. }) => {
            return Err(ApiError::conflict(
                codes::DUPLICATE,
                "this key is already registered as an agent-package signer",
            )
            .detail(Detail::new().with("key_id", &key_id)));
        }
        Err(e) => return Err(e.into()),
    }
    let d = ctx
        .ok("agent_signer.added")
        .target("agent_signer", &s.id.to_string())
        .detail(
            Detail::new()
                .with("name", s.name.as_str())
                .with("key_id", &key_id),
        );
    let r = api.append(&mut tx, &d).await?;
    api.commit(tx, &[r]).await?;
    json_response!(StatusCode::CREATED, &view(&s))
}

/// `GET /v1/agent-signers`.
pub(crate) async fn list<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let mut tx = api.store().begin().await?;
    let signers: Vec<SignerView> = tx.list_agent_signers().await?.iter().map(view).collect();
    let d = ctx
        .ok("agent_signer.list.read")
        .detail(Detail::new().with("count", &signers.len()));
    let r = api.append(&mut tx, &d).await?;
    api.commit(tx, &[r]).await?;
    json_response!(StatusCode::OK, &SignerList { signers })
}

/// `DELETE /v1/agent-signers/{id}`: revokes the signer and, in the same
/// transaction, refuses its agent packages and takes the packages that
/// use them out of ready, each with its own record (WU-6 follow-up U-3).
pub(crate) async fn revoke<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let id = signer_id(ctx)?;
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    let signer = tx
        .agent_signer(id)
        .await?
        .ok_or_else(|| ApiError::not_found("agent signer"))?;
    let out = match tx
        .revoke_agent_signer(id, ctx.principal.operator.id, at)
        .await
    {
        Ok(o) => o,
        Err(DbError::Conflict { .. }) => {
            return Err(ApiError::conflict(
                codes::WRONG_STATE,
                "the agent-package signer is already revoked",
            ));
        }
        Err(DbError::NotFound { .. }) => return Err(ApiError::not_found("agent signer")),
        Err(e) => return Err(e.into()),
    };
    let target = id.to_string();
    let d = ctx
        .ok("agent_signer.revoked")
        .target("agent_signer", &target)
        .detail(
            Detail::new()
                .with("key_id", &signer.key_id)
                .with("agent_packages_refused", &out.refused_agent_packages.len())
                .with("packages_not_ready", &out.packages_not_ready.len()),
        );
    let first = api.append(&mut tx, &d).await?;
    let seq = first.seq;
    let mut recs = vec![first];
    for ap in &out.refused_agent_packages {
        let d = ctx
            .draft("agent_package.refused", Outcome::Success)
            .target("agent_package", &ap.to_string())
            .reason(SIGNER_REVOKED)
            .initiated_by(seq)
            .detail(
                Detail::new()
                    .with("agent_signer_id", &target)
                    .with("key_id", &signer.key_id),
            );
        recs.push(api.append(&mut tx, &d).await?);
    }
    for p in &out.packages_not_ready {
        let d = ctx
            .draft("package.status.changed", Outcome::Success)
            .target("package", &p.to_string())
            .reason(AGENT_PACKAGE_REFUSED)
            .initiated_by(seq)
            .detail(
                Detail::new()
                    .with("from", PackageStatus::Ready.as_str())
                    .with("to", PackageStatus::NotUsable.as_str())
                    .with("agent_signer_id", &target),
            );
        recs.push(api.append(&mut tx, &d).await?);
    }
    let after = tx
        .agent_signer(id)
        .await?
        .ok_or_else(|| ApiError::internal_error("agent signer vanished"))?;
    api.commit(tx, &recs).await?;
    json_response!(StatusCode::OK, &view(&after))
}
