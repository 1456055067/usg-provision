//! Agent-package signers and agent packages (PostgreSQL; M4 plan sections
//! 1.7 and 3.5, migration 0005; decision 0025 item 5).
//!
//! A signer's key id is the SHA-256 of its SPKI DER, computed through
//! `usgp-crypto` on write and checked again on read. An agent package
//! becomes ready only when its content is Ready with a signed v2 manifest
//! of kind `agent_package` and its signer is registered and not revoked.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 - ready only with a verified signer (checked by the
//   caller) that is registered and unrevoked here, and Ready content.
// - NIST 800-53: SC-12 - signer keys registered, identified by digest,
//   revoked once (guard in 0005).
// - NIST 800-53: SI-10 - `agent.json` re-validated on read.
// - SPEC: specs/agent-handoff.md#REQ-AGT-001
// - Decisions 0024 item 2, 0025 item 5

use tokio_postgres::Row;
use usgp_common::Sha256Digest;
use usgp_proto::limits::MAX_AGENT_MANIFEST_BYTES;
use usgp_proto::{
    AgentPackageId, AgentPackageManifestV1, ContentId, ContentKindV2, ContentState, DisplayName,
    ErrorCode, OperatorId, P384Spki, UnixMicros,
};

use super::content::{archive_get, cas_miss};
use super::conv::{
    check_text, col, col_digest, col_enum, col_id, col_micros, col_opt_id, col_opt_micros,
    col_text, to_uuid,
};
use super::packages::ref_from_row;
use crate::error::DbError;
use crate::model::{
    AgentPackage, AgentPackageStatus, AgentSigner, AgentSignerId, NewAgentPackage, PackageRef,
};
use crate::pool::PgTx;

const SIGNER_COLUMNS: &str =
    "id, spki, key_id, name, added_by, added_at_us, revoked_at_us, revoked_by";

const PACKAGE_COLUMNS: &str = "id, content_id, signer_id, manifest::text AS manifest, status, \
     refusal, created_by, created_at_us, updated_at_us";

pub(crate) fn signer_id(bytes: [u8; 16]) -> Result<AgentSignerId, ()> {
    AgentSignerId::from_bytes(bytes).ok_or(())
}

/// Checks that `key_id` is the SHA-256 of the SPKI DER.
pub(crate) fn key_id_matches(spki: &P384Spki, key_id: &Sha256Digest) -> bool {
    usgp_crypto::sha256(spki.as_der()) == *key_id
}

fn signer_from_row(r: &Row) -> Result<AgentSigner, DbError> {
    let spki: &[u8] = col(r, "spki")?;
    let spki = P384Spki::from_der(spki).map_err(|_| DbError::Corrupt { what: "spki" })?;
    let key_id = col_digest(r, "key_id")?;
    if !key_id_matches(&spki, &key_id) {
        return Err(DbError::Corrupt { what: "key_id" });
    }
    let by = col_opt_id(r, "revoked_by", OperatorId::from_bytes)?;
    let at = col_opt_micros(r, "revoked_at_us")?;
    let revoked = match (by, at) {
        (Some(by), Some(at)) => Some((by, at)),
        (None, None) => None,
        _ => return Err(DbError::Corrupt { what: "revoked" }),
    };
    Ok(AgentSigner {
        id: col_id(r, "id", signer_id)?,
        spki,
        key_id,
        name: col_text(r, "name", DisplayName::new)?,
        added_by: col_id(r, "added_by", OperatorId::from_bytes)?,
        added_at: col_micros(r, "added_at_us")?,
        revoked,
    })
}

/// Parses a stored `agent.json`.
pub(crate) fn manifest_from_json(s: &str) -> Result<AgentPackageManifestV1, DbError> {
    if s.len() > MAX_AGENT_MANIFEST_BYTES {
        return Err(DbError::Corrupt { what: "manifest" });
    }
    AgentPackageManifestV1::from_json(s.as_bytes())
        .map_err(|_| DbError::Corrupt { what: "manifest" })
}

/// Renders `agent.json` for the `jsonb` column after validating it.
pub(crate) fn manifest_to_json(m: &AgentPackageManifestV1) -> Result<String, DbError> {
    m.validate()
        .map_err(|_| DbError::InvalidArgument { what: "manifest" })?;
    let s = serde_json::to_string(m).map_err(|_| DbError::InvalidArgument { what: "manifest" })?;
    if s.len() > MAX_AGENT_MANIFEST_BYTES {
        return Err(DbError::InvalidArgument { what: "manifest" });
    }
    Ok(s)
}

fn code(s: Option<String>) -> Result<Option<ErrorCode>, DbError> {
    s.map(|c| ErrorCode::new(c).map_err(|_| DbError::Corrupt { what: "refusal" }))
        .transpose()
}

fn package_from_row(r: &Row) -> Result<AgentPackage, DbError> {
    let manifest: Option<String> = col(r, "manifest")?;
    Ok(AgentPackage {
        id: col_id(r, "id", AgentPackageId::from_bytes)?,
        content_id: col_id(r, "content_id", ContentId::from_bytes)?,
        signer_id: col_opt_id(r, "signer_id", signer_id)?,
        manifest: manifest.as_deref().map(manifest_from_json).transpose()?,
        status: col_enum(r, "status", AgentPackageStatus::parse)?,
        refusal: code(col(r, "refusal")?)?,
        created_by: col_id(r, "created_by", OperatorId::from_bytes)?,
        created_at: col_micros(r, "created_at_us")?,
        updated_at: col_micros(r, "updated_at_us")?,
    })
}

// ------------------------------------------------------------- signers --

pub(crate) async fn insert_signer(tx: &mut PgTx, s: &AgentSigner) -> Result<(), DbError> {
    if s.revoked.is_some() || !key_id_matches(&s.spki, &s.key_id) {
        return Err(DbError::InvalidArgument {
            what: "agent signer",
        });
    }
    tx.execute(
        "insert agent_signer",
        "INSERT INTO agent_signer (id, spki, key_id, name, added_by, added_at_us) \
         VALUES ($1, $2, $3, $4, $5, $6)",
        &[
            &to_uuid(s.id.as_bytes()),
            &s.spki.as_der().as_slice(),
            &s.key_id.0.as_slice(),
            &check_text(s.name.as_str(), "name")?,
            &to_uuid(s.added_by.as_bytes()),
            &s.added_at.as_micros(),
        ],
    )
    .await?;
    Ok(())
}

pub(crate) async fn signer(
    tx: &mut PgTx,
    id: AgentSignerId,
) -> Result<Option<AgentSigner>, DbError> {
    let sql = format!("SELECT {SIGNER_COLUMNS} FROM agent_signer WHERE id = $1");
    let row = tx
        .query_opt("read agent_signer", &sql, &[&to_uuid(id.as_bytes())])
        .await?;
    row.map(|r| signer_from_row(&r)).transpose()
}

pub(crate) async fn signer_by_key_id(
    tx: &mut PgTx,
    key_id: &Sha256Digest,
) -> Result<Option<AgentSigner>, DbError> {
    let sql = format!("SELECT {SIGNER_COLUMNS} FROM agent_signer WHERE key_id = $1");
    let row = tx
        .query_opt("read agent_signer", &sql, &[&key_id.0.as_slice()])
        .await?;
    row.map(|r| signer_from_row(&r)).transpose()
}

pub(crate) async fn list_signers(tx: &mut PgTx) -> Result<Vec<AgentSigner>, DbError> {
    let sql = format!("SELECT {SIGNER_COLUMNS} FROM agent_signer ORDER BY added_at_us, id");
    let rows = tx.query("list agent_signer", &sql, &[]).await?;
    rows.iter().map(signer_from_row).collect()
}

pub(crate) async fn revoke_signer(
    tx: &mut PgTx,
    id: AgentSignerId,
    by: OperatorId,
    at: UnixMicros,
) -> Result<(), DbError> {
    let uid = to_uuid(id.as_bytes());
    let n = tx
        .execute(
            "update agent_signer revoked",
            "UPDATE agent_signer SET revoked_at_us = $2, revoked_by = $3 \
             WHERE id = $1 AND revoked_at_us IS NULL",
            &[&uid, &at.as_micros(), &to_uuid(by.as_bytes())],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "agent signer", &uid).await);
    }
    Ok(())
}

// ------------------------------------------------------------ packages --

pub(crate) async fn insert_package(tx: &mut PgTx, p: &NewAgentPackage) -> Result<(), DbError> {
    tx.execute(
        "insert agent_package",
        "INSERT INTO agent_package (id, content_id, status, created_by, created_at_us, \
         updated_at_us) VALUES ($1, $2, 'checking', $3, $4, $4)",
        &[
            &to_uuid(p.id.as_bytes()),
            &to_uuid(p.content_id.as_bytes()),
            &to_uuid(p.created_by.as_bytes()),
            &p.created_at.as_micros(),
        ],
    )
    .await?;
    Ok(())
}

pub(crate) async fn package(
    tx: &mut PgTx,
    id: AgentPackageId,
    lock: bool,
) -> Result<Option<AgentPackage>, DbError> {
    let sql = format!(
        "SELECT {PACKAGE_COLUMNS} FROM agent_package WHERE id = $1{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = tx
        .query_opt("read agent_package", &sql, &[&to_uuid(id.as_bytes())])
        .await?;
    row.map(|r| package_from_row(&r)).transpose()
}

pub(crate) async fn list_packages(
    tx: &mut PgTx,
    statuses: &[AgentPackageStatus],
) -> Result<Vec<AgentPackage>, DbError> {
    let st: Vec<&str> = statuses.iter().map(|s| s.as_str()).collect();
    let sql = format!(
        "SELECT {PACKAGE_COLUMNS} FROM agent_package \
         WHERE (cardinality($1::text[]) = 0 OR status = ANY($1)) ORDER BY created_at_us, id"
    );
    let rows = tx.query("list agent_package", &sql, &[&st]).await?;
    rows.iter().map(package_from_row).collect()
}

pub(crate) async fn set_package_ready(
    tx: &mut PgTx,
    id: AgentPackageId,
    signer: AgentSignerId,
    manifest: &AgentPackageManifestV1,
    at: UnixMicros,
) -> Result<(), DbError> {
    let json = manifest_to_json(manifest)?;
    let Some(cur) = package(tx, id, true).await? else {
        return Err(DbError::NotFound {
            what: "agent package",
        });
    };
    if cur.status != AgentPackageStatus::Checking {
        return Err(DbError::Conflict {
            what: "agent package",
        });
    }
    let content_ready = archive_get(tx, cur.content_id, false)
        .await?
        .is_some_and(|c| {
            c.state == ContentState::Ready
                && c.kind == ContentKindV2::AgentPackage
                && c.manifest.is_some()
        });
    if !content_ready {
        return Err(DbError::Conflict {
            what: "agent package content not ready",
        });
    }
    let uid = to_uuid(id.as_bytes());
    let sid = to_uuid(signer.as_bytes());
    // The signer must be registered and unrevoked; held until the
    // transaction ends so a concurrent revocation waits.
    let live = tx
        .query_opt(
            "lock agent_signer",
            "SELECT 1 FROM agent_signer WHERE id = $1 AND revoked_at_us IS NULL FOR SHARE",
            &[&sid],
        )
        .await?;
    if live.is_none() {
        return Err(DbError::Conflict {
            what: "agent signer",
        });
    }
    let n = tx
        .execute(
            "update agent_package ready",
            "UPDATE agent_package SET status = 'ready', signer_id = $2, \
             manifest = $3::text::jsonb, updated_at_us = $4 \
             WHERE id = $1 AND status = 'checking'",
            &[&uid, &sid, &json, &at.as_micros()],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "agent package", &uid).await);
    }
    Ok(())
}

pub(crate) async fn refuse_package(
    tx: &mut PgTx,
    id: AgentPackageId,
    reason: &ErrorCode,
    at: UnixMicros,
) -> Result<(), DbError> {
    let uid = to_uuid(id.as_bytes());
    let n = tx
        .execute(
            "update agent_package refused",
            "UPDATE agent_package SET status = 'refused', refusal = $2, updated_at_us = $3 \
             WHERE id = $1 AND status = 'checking'",
            &[&uid, &reason.as_str(), &at.as_micros()],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "agent package", &uid).await);
    }
    Ok(())
}

pub(crate) async fn using_package(
    tx: &mut PgTx,
    id: AgentPackageId,
) -> Result<Vec<PackageRef>, DbError> {
    let rows = tx
        .query(
            "list package dependants",
            "SELECT p.id, p.name FROM package p JOIN package_config c ON c.package_id = p.id \
             WHERE c.agent_package_id = $1 ORDER BY p.created_at_us, p.id",
            &[&to_uuid(id.as_bytes())],
        )
        .await?;
    rows.iter().map(ref_from_row).collect()
}
