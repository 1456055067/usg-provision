//! Operator-issued authorisation codes (PostgreSQL). Only the HMAC of a
//! code is stored; the value never reaches the database.

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-5 (Authenticator Management) - stored only as keyed
//   HMAC; single use by an atomic conditional update; used and revoked
//   codes stay so (migration 0004 guard).
// - NIST 800-53: AC-7 - the same "no match" for wrong, expired, used and
//   revoked codes (no oracle).
// - SPEC: specs/targeting.md#REQ-TGT-013
// - Decisions 0018 item 1, 0020 item 3

use tokio_postgres::Row;
use usgp_crypto::HmacTag;
use usgp_proto::{AuthCodeId, Note, OperatorId, SessionId, UnixMicros};

use super::content::cas_miss;
use super::conv::{col, col_id, col_micros, col_opt_id, col_opt_micros, to_uuid};
use crate::error::DbError;
use crate::model::{AuthCodeRecord, NewAuthCode};
use crate::pool::PgTx;

const COLUMNS: &str = "id, issued_by, issued_at_us, expires_at_us, used_at_us, used_by_session, \
     revoked_at_us, revoked_by, note";

fn from_row(r: &Row) -> Result<AuthCodeRecord, DbError> {
    let note: Option<String> = col(r, "note")?;
    Ok(AuthCodeRecord {
        id: col_id(r, "id", AuthCodeId::from_bytes)?,
        issued_by: col_id(r, "issued_by", OperatorId::from_bytes)?,
        issued_at: col_micros(r, "issued_at_us")?,
        expires_at: col_micros(r, "expires_at_us")?,
        used_at: col_opt_micros(r, "used_at_us")?,
        used_by_session: col_opt_id(r, "used_by_session", SessionId::from_bytes)?,
        revoked_at: col_opt_micros(r, "revoked_at_us")?,
        revoked_by: col_opt_id(r, "revoked_by", OperatorId::from_bytes)?,
        note: note
            .map(|n| Note::new(n).map_err(|_| DbError::Corrupt { what: "note" }))
            .transpose()?,
    })
}

pub(crate) async fn insert(tx: &mut PgTx, c: &NewAuthCode) -> Result<(), DbError> {
    if c.expires_at <= c.issued_at {
        return Err(DbError::InvalidArgument {
            what: "code expiry must follow issue",
        });
    }
    tx.execute(
        "insert auth_code",
        "INSERT INTO auth_code (id, code_hmac, issued_by, issued_at_us, expires_at_us, note) \
         VALUES ($1, $2, $3, $4, $5, $6)",
        &[
            &to_uuid(c.id.as_bytes()),
            &c.code_hmac.as_bytes().as_slice(),
            &to_uuid(c.issued_by.as_bytes()),
            &c.issued_at.as_micros(),
            &c.expires_at.as_micros(),
            &c.note.as_ref().map(Note::as_str),
        ],
    )
    .await?;
    Ok(())
}

pub(crate) async fn get(tx: &mut PgTx, id: AuthCodeId) -> Result<Option<AuthCodeRecord>, DbError> {
    let sql = format!("SELECT {COLUMNS} FROM auth_code WHERE id = $1");
    let row = tx
        .query_opt("read auth_code", &sql, &[&to_uuid(id.as_bytes())])
        .await?;
    row.map(|r| from_row(&r)).transpose()
}

pub(crate) async fn list(tx: &mut PgTx) -> Result<Vec<AuthCodeRecord>, DbError> {
    let sql = format!("SELECT {COLUMNS} FROM auth_code ORDER BY issued_at_us, id");
    let rows = tx.query("list auth_code", &sql, &[]).await?;
    rows.iter().map(from_row).collect()
}

pub(crate) async fn consume(
    tx: &mut PgTx,
    code_hmac: &HmacTag,
    session: SessionId,
    at: UnixMicros,
) -> Result<Option<AuthCodeId>, DbError> {
    // Plan section 3.1: one atomic conditional update; a second use, a
    // revoked or an expired code matches no row.
    let rows = tx
        .query_write(
            "use auth_code",
            "UPDATE auth_code SET used_at_us = $3, used_by_session = $2 \
             WHERE code_hmac = $1 AND used_at_us IS NULL AND revoked_at_us IS NULL \
             AND expires_at_us > $3 RETURNING id",
            &[
                &code_hmac.as_bytes().as_slice(),
                &to_uuid(session.as_bytes()),
                &at.as_micros(),
            ],
        )
        .await?;
    match rows.as_slice() {
        [] => Ok(None),
        [r] => Ok(Some(col_id(r, "id", AuthCodeId::from_bytes)?)),
        _ => Err(DbError::Corrupt { what: "code_hmac" }),
    }
}

pub(crate) async fn revoke(
    tx: &mut PgTx,
    id: AuthCodeId,
    by: OperatorId,
    at: UnixMicros,
) -> Result<(), DbError> {
    let uid = to_uuid(id.as_bytes());
    let n = tx
        .execute(
            "revoke auth_code",
            "UPDATE auth_code SET revoked_at_us = $3, revoked_by = $2 \
             WHERE id = $1 AND used_at_us IS NULL AND revoked_at_us IS NULL",
            &[&uid, &to_uuid(by.as_bytes()), &at.as_micros()],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "auth code", &uid).await);
    }
    Ok(())
}
