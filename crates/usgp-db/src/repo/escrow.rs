//! Administrator-password escrow (PostgreSQL; M4 plan section 1.3,
//! migration 0005).
//!
//! Only the sealed form is stored (SC-28): the device's ephemeral public
//! key, the nonce and the AES-GCM ciphertext, sealed to the server's
//! escrow key. Nothing here can open it; decryption happens in the API
//! after the `escrow.revealed` record is durable. One escrow per job; the
//! sealed bytes never change (guard in 0005); the app role may update only
//! the state, the outcome time and the reveal count (column grant).

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-28, SC-28(1) (Protection of Information at Rest) -
//   ciphertext only; immutable once written.
// - NIST 800-53: AC-6 - column-level UPDATE grant; no DELETE.
// - NIST 800-53: AU-12 - every write here is a state change that cannot
//   commit without its audit record (`escrow.received`, `.applied`,
//   `.not_applied`, `.revealed`).
// - SPEC: specs/configuration.md#REQ-CFG-008
// - Decisions 0024, 0025 item 2

use tokio_postgres::Row;
use usgp_proto::escrow::{GCM_NONCE_LEN, P384_POINT_LEN};
use usgp_proto::{EscrowAccount, JobId};

use super::content::cas_miss;
use super::conv::{
    col, col_digest, col_enum, col_id, col_micros, col_opt_micros, col_u32, to_uuid,
};
use crate::error::DbError;
use crate::model::{EscrowRecord, EscrowState, NewEscrow, SealedPassword};
use crate::pool::PgTx;
use usgp_proto::UnixMicros;

const COLUMNS: &str = "job_id, account, key_id, state, received_at_us, applied_at_us, reveal_count";

fn from_row(r: &Row) -> Result<EscrowRecord, DbError> {
    let e = EscrowRecord {
        job_id: col_id(r, "job_id", JobId::from_bytes)?,
        account: col_enum(r, "account", EscrowAccount::parse)?,
        key_id: col_digest(r, "key_id")?,
        state: col_enum(r, "state", EscrowState::parse)?,
        received_at: col_micros(r, "received_at_us")?,
        applied_at: col_opt_micros(r, "applied_at_us")?,
        reveal_count: col_u32(r, "reveal_count")?,
    };
    if (e.state == EscrowState::Received) != e.applied_at.is_none() {
        return Err(DbError::Corrupt { what: "escrow" });
    }
    Ok(e)
}

pub(crate) async fn insert(tx: &mut PgTx, e: &NewEscrow) -> Result<(), DbError> {
    if !e.sealed.valid() {
        return Err(DbError::InvalidArgument {
            what: "sealed password",
        });
    }
    tx.execute(
        "insert admin_password_escrow",
        "INSERT INTO admin_password_escrow (job_id, account, key_id, eph_pub, nonce, ciphertext, \
         received_at_us, state) VALUES ($1, $2, $3, $4, $5, $6, $7, 'received')",
        &[
            &to_uuid(e.job_id.as_bytes()),
            &e.account.as_str(),
            &e.key_id.0.as_slice(),
            &e.sealed.eph_pub.as_slice(),
            &e.sealed.nonce.as_slice(),
            &e.sealed.ciphertext,
            &e.received_at.as_micros(),
        ],
    )
    .await?;
    Ok(())
}

pub(crate) async fn get(
    tx: &mut PgTx,
    job: JobId,
    lock: bool,
) -> Result<Option<EscrowRecord>, DbError> {
    let sql = format!(
        "SELECT {COLUMNS} FROM admin_password_escrow WHERE job_id = $1{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = tx
        .query_opt(
            "read admin_password_escrow",
            &sql,
            &[&to_uuid(job.as_bytes())],
        )
        .await?;
    row.map(|r| from_row(&r)).transpose()
}

pub(crate) async fn sealed(tx: &mut PgTx, job: JobId) -> Result<Option<SealedPassword>, DbError> {
    let row = tx
        .query_opt(
            "read admin_password_escrow sealed",
            "SELECT eph_pub, nonce, ciphertext FROM admin_password_escrow WHERE job_id = $1",
            &[&to_uuid(job.as_bytes())],
        )
        .await?;
    let Some(r) = row else {
        return Ok(None);
    };
    let eph: &[u8] = col(&r, "eph_pub")?;
    let nonce: &[u8] = col(&r, "nonce")?;
    let s = SealedPassword {
        eph_pub: <[u8; P384_POINT_LEN]>::try_from(eph)
            .map_err(|_| DbError::Corrupt { what: "eph_pub" })?,
        nonce: <[u8; GCM_NONCE_LEN]>::try_from(nonce)
            .map_err(|_| DbError::Corrupt { what: "nonce" })?,
        ciphertext: col(&r, "ciphertext")?,
    };
    if !s.valid() {
        return Err(DbError::Corrupt {
            what: "sealed password",
        });
    }
    Ok(Some(s))
}

pub(crate) async fn set_outcome(
    tx: &mut PgTx,
    job: JobId,
    applied: bool,
    at: UnixMicros,
) -> Result<(), DbError> {
    let to = if applied {
        EscrowState::Applied
    } else {
        EscrowState::NotApplied
    };
    let uid = to_uuid(job.as_bytes());
    let n = tx
        .execute(
            "update admin_password_escrow outcome",
            "UPDATE admin_password_escrow SET state = $2, applied_at_us = $3 \
             WHERE job_id = $1 AND state = 'received'",
            &[&uid, &to.as_str(), &at.as_micros()],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "escrow", &uid).await);
    }
    Ok(())
}

pub(crate) async fn record_reveal(tx: &mut PgTx, job: JobId) -> Result<u32, DbError> {
    let rows = tx
        .query_write(
            "update admin_password_escrow reveal",
            "UPDATE admin_password_escrow SET reveal_count = reveal_count + 1 \
             WHERE job_id = $1 RETURNING reveal_count",
            &[&to_uuid(job.as_bytes())],
        )
        .await?;
    match rows.first() {
        Some(r) => col_u32(r, "reveal_count"),
        None => Err(DbError::NotFound { what: "escrow" }),
    }
}
