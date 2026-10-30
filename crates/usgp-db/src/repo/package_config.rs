//! Package configuration (PostgreSQL; M4 plan sections 1.6 and 3.2,
//! migration 0005): the answer-file template, literal values, tags, the
//! agent package and the administrator-password mode. One row per
//! package, removed with the package.

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 (Configuration Settings) - stored per package,
//   changed only in an audited transaction.
// - NIST 800-53: SI-10 - value, tag and key bounds checked on write and
//   re-validated on read.
// - SPEC: specs/configuration.md#REQ-CFG-004, #REQ-CFG-008, #REQ-CFG-009
// - Decision 0024

use tokio_postgres::Row;
use usgp_proto::limits::MAX_TAGS;
use usgp_proto::{AgentPackageId, ContentId, OperatorId, PackageId, Tag};

use super::conv::{col, col_enum, col_id, col_micros, from_json, to_json, to_uuid};
use crate::error::DbError;
use crate::model::{AdminPasswordMode, PackageConfig, PackageValues};
use crate::pool::PgTx;

const COLUMNS: &str = "package_id, answer_content_id, config_values::text AS config_values, \
     tags, agent_package_id, admin_password_mode, updated_by, updated_at_us";

/// Validates a stored or given tag list (at most 64 tags).
pub(crate) fn tags_from(raw: Vec<String>, corrupt: bool) -> Result<Vec<Tag>, DbError> {
    let err = || {
        if corrupt {
            DbError::Corrupt { what: "tags" }
        } else {
            DbError::InvalidArgument { what: "tags" }
        }
    };
    if raw.len() > MAX_TAGS {
        return Err(err());
    }
    raw.into_iter()
        .map(|t| Tag::new(t).map_err(|_| err()))
        .collect()
}

/// Tags as a `text[]` parameter.
pub(crate) fn tag_params(tags: &[Tag]) -> Result<Vec<&str>, DbError> {
    if tags.len() > MAX_TAGS {
        return Err(DbError::InvalidArgument { what: "tags" });
    }
    Ok(tags.iter().map(Tag::as_str).collect())
}

fn from_row(r: &Row) -> Result<PackageConfig, DbError> {
    let values: String = col(r, "config_values")?;
    let values: PackageValues = from_json(&values, "config_values")?;
    if !values.valid() {
        return Err(DbError::Corrupt {
            what: "config_values",
        });
    }
    Ok(PackageConfig {
        package_id: col_id(r, "package_id", PackageId::from_bytes)?,
        answer_content_id: col_id(r, "answer_content_id", ContentId::from_bytes)?,
        values,
        tags: tags_from(col(r, "tags")?, true)?,
        agent_package_id: col_id(r, "agent_package_id", AgentPackageId::from_bytes)?,
        admin_password: col_enum(r, "admin_password_mode", AdminPasswordMode::parse)?,
        updated_by: col_id(r, "updated_by", OperatorId::from_bytes)?,
        updated_at: col_micros(r, "updated_at_us")?,
    })
}

pub(crate) async fn get(tx: &mut PgTx, id: PackageId) -> Result<Option<PackageConfig>, DbError> {
    let sql = format!("SELECT {COLUMNS} FROM package_config WHERE package_id = $1");
    let row = tx
        .query_opt("read package_config", &sql, &[&to_uuid(id.as_bytes())])
        .await?;
    row.map(|r| from_row(&r)).transpose()
}

pub(crate) async fn set(tx: &mut PgTx, c: &PackageConfig) -> Result<(), DbError> {
    if !c.values.valid() {
        return Err(DbError::InvalidArgument {
            what: "config values",
        });
    }
    let values = to_json(&c.values, "config values")?;
    tx.execute(
        "upsert package_config",
        "INSERT INTO package_config (package_id, answer_content_id, config_values, tags, \
         agent_package_id, admin_password_mode, updated_by, updated_at_us) \
         VALUES ($1, $2, $3::text::jsonb, $4, $5, $6, $7, $8) \
         ON CONFLICT (package_id) DO UPDATE SET answer_content_id = EXCLUDED.answer_content_id, \
         config_values = EXCLUDED.config_values, tags = EXCLUDED.tags, \
         agent_package_id = EXCLUDED.agent_package_id, \
         admin_password_mode = EXCLUDED.admin_password_mode, \
         updated_by = EXCLUDED.updated_by, updated_at_us = EXCLUDED.updated_at_us",
        &[
            &to_uuid(c.package_id.as_bytes()),
            &to_uuid(c.answer_content_id.as_bytes()),
            &values,
            &tag_params(&c.tags)?,
            &to_uuid(c.agent_package_id.as_bytes()),
            &c.admin_password.as_str(),
            &to_uuid(c.updated_by.as_bytes()),
            &c.updated_at.as_micros(),
        ],
    )
    .await?;
    Ok(())
}
