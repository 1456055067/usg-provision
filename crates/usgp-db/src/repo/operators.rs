//! Operator rows (PostgreSQL).

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-2, IA-5(2) - one certificate fingerprint maps to
//   exactly one operator (unique `cert_sha256`, decision 0007).
// - NIST 800-53: AC-2 (Account Management) - enrol and disable.

use tokio_postgres::Row;
use usgp_common::Sha256Digest;
use usgp_proto::{DisplayName, OperatorId};

use super::conv::{
    check_text, col, col_digest, col_enum, col_id, col_micros, col_opt_enum, col_text, to_uuid,
};
use crate::error::DbError;
use crate::model::{Operator, OperatorRole, OperatorStatus};
use crate::pool::PgTx;

const COLUMNS: &str = "id, display_name, cert_sha256, cert_subject, cert_issuer, cert_serial, \
     cert_not_after_us, role, status, created_at_us, created_by";

fn from_row(r: &Row) -> Result<Operator, DbError> {
    Ok(Operator {
        id: col_id(r, "id", OperatorId::from_bytes)?,
        display_name: col_text(r, "display_name", DisplayName::new)?,
        cert_sha256: col_digest(r, "cert_sha256")?,
        cert_subject: col(r, "cert_subject")?,
        cert_issuer: col(r, "cert_issuer")?,
        cert_serial: col(r, "cert_serial")?,
        cert_not_after: col_micros(r, "cert_not_after_us")?,
        role: col_opt_enum(r, "role", OperatorRole::parse)?,
        status: col_enum(r, "status", OperatorStatus::parse)?,
        created_at: col_micros(r, "created_at_us")?,
        created_by: col(r, "created_by")?,
    })
}

pub(crate) async fn get(tx: &mut PgTx, id: OperatorId) -> Result<Option<Operator>, DbError> {
    let sql = format!("SELECT {COLUMNS} FROM operator WHERE id = $1");
    let row = tx
        .query_opt("read operator", &sql, &[&to_uuid(id.as_bytes())])
        .await?;
    row.map(|r| from_row(&r)).transpose()
}

pub(crate) async fn by_cert(
    tx: &mut PgTx,
    sha: &Sha256Digest,
) -> Result<Option<Operator>, DbError> {
    let sql = format!("SELECT {COLUMNS} FROM operator WHERE cert_sha256 = $1");
    let row = tx
        .query_opt("read operator", &sql, &[&sha.0.as_slice()])
        .await?;
    row.map(|r| from_row(&r)).transpose()
}

pub(crate) async fn list(tx: &mut PgTx) -> Result<Vec<Operator>, DbError> {
    let sql = format!("SELECT {COLUMNS} FROM operator ORDER BY created_at_us, id");
    let rows = tx.query("list operator", &sql, &[]).await?;
    rows.iter().map(from_row).collect()
}

pub(crate) async fn insert(tx: &mut PgTx, op: &Operator) -> Result<(), DbError> {
    let sql = format!(
        "INSERT INTO operator ({COLUMNS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"
    );
    tx.execute(
        "insert operator",
        &sql,
        &[
            &to_uuid(op.id.as_bytes()),
            &op.display_name.as_str(),
            &op.cert_sha256.0.as_slice(),
            &check_text(&op.cert_subject, "cert_subject")?,
            &check_text(&op.cert_issuer, "cert_issuer")?,
            &check_text(&op.cert_serial, "cert_serial")?,
            &op.cert_not_after.as_micros(),
            &op.role.map(OperatorRole::as_str),
            &op.status.as_str(),
            &op.created_at.as_micros(),
            &check_text(&op.created_by, "created_by")?,
        ],
    )
    .await?;
    Ok(())
}

pub(crate) async fn set_status(
    tx: &mut PgTx,
    id: OperatorId,
    status: OperatorStatus,
) -> Result<(), DbError> {
    let n = tx
        .execute(
            "update operator",
            "UPDATE operator SET status = $2 WHERE id = $1",
            &[&to_uuid(id.as_bytes()), &status.as_str()],
        )
        .await?;
    if n == 0 {
        return Err(DbError::NotFound { what: "operator" });
    }
    Ok(())
}
