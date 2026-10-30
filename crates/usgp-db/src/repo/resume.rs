//! Post-setup resume nonces and tokens (PostgreSQL; M4 plan section 3.1,
//! migration 0005).
//!
//! Both are stored only as SHA-256. Issuing a challenge nonce is
//! bookkeeping (the plan does not audit challenges; they are rate limited)
//! and runs through the closed [`Bookkeeping`] path: one fixed statement
//! that inserts only for a v2 job that is not finished, has step 6 done,
//! and holds fewer than the given number of live nonces. Using a nonce,
//! issuing a token and revoking tokens are audited state changes.

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-5, IA-5(1) - token and nonce stored only as SHA-256;
//   nonce single use; tokens scoped to one job, expiring, revocable.
// - NIST 800-53: AU-2, AU-12 - only the challenge nonce insert is
//   unaudited, by a closed statement that changes no state column.
// - NIST 800-53: SC-5 (Denial-of-Service Protection) - live nonces per job
//   bounded in the statement.
// - SPEC: specs/workflow.md#REQ-SEQ-002
// - Decision 0025 item 1

use usgp_common::Sha256Digest;
use usgp_proto::{JobId, UnixMicros};

use super::conv::{col_id, col_micros, col_opt_micros, col_u64, to_uuid};
use crate::error::DbError;
use crate::model::{NewResumeNonce, NewResumeToken, ResumeToken};
use crate::pool::{Bookkeeping, PgTx};

pub(crate) fn check_window(
    issued: UnixMicros,
    expires: UnixMicros,
    what: &'static str,
) -> Result<(), DbError> {
    if expires <= issued {
        return Err(DbError::InvalidArgument { what });
    }
    Ok(())
}

pub(crate) async fn insert_nonce(
    tx: &mut PgTx,
    n: &NewResumeNonce,
    max_live: u32,
) -> Result<bool, DbError> {
    check_window(n.issued_at, n.expires_at, "nonce expiry")?;
    let rows = tx
        .execute_bookkeeping(
            Bookkeeping::ResumeNonce,
            &[
                &n.nonce_hash.0.as_slice(),
                &to_uuid(n.job_id.as_bytes()),
                &n.issued_at.as_micros(),
                &n.expires_at.as_micros(),
                &i64::from(max_live),
            ],
        )
        .await?;
    Ok(rows == 1)
}

pub(crate) async fn consume_nonce(
    tx: &mut PgTx,
    job: JobId,
    nonce_hash: &Sha256Digest,
    at: UnixMicros,
) -> Result<bool, DbError> {
    let rows = tx
        .query_write(
            "update job_resume_nonce used",
            "UPDATE job_resume_nonce SET used_at_us = $3 \
             WHERE nonce_hash = $1 AND job_id = $2 AND used_at_us IS NULL AND expires_at_us > $3 \
             RETURNING job_id",
            &[
                &nonce_hash.0.as_slice(),
                &to_uuid(job.as_bytes()),
                &at.as_micros(),
            ],
        )
        .await?;
    Ok(!rows.is_empty())
}

pub(crate) async fn insert_token(tx: &mut PgTx, t: &NewResumeToken) -> Result<(), DbError> {
    check_window(t.issued_at, t.expires_at, "token expiry")?;
    tx.execute(
        "insert job_resume_token",
        "INSERT INTO job_resume_token (token_hash, job_id, issued_at_us, expires_at_us) \
         VALUES ($1, $2, $3, $4)",
        &[
            &t.token_hash.0.as_slice(),
            &to_uuid(t.job_id.as_bytes()),
            &t.issued_at.as_micros(),
            &t.expires_at.as_micros(),
        ],
    )
    .await?;
    Ok(())
}

pub(crate) async fn count_tokens(tx: &mut PgTx, job: JobId) -> Result<u64, DbError> {
    let row = tx
        .query_opt(
            "count job_resume_token",
            "SELECT count(*) AS n FROM job_resume_token WHERE job_id = $1",
            &[&to_uuid(job.as_bytes())],
        )
        .await?;
    match row {
        Some(r) => col_u64(&r, "n"),
        None => Err(DbError::Corrupt { what: "count" }),
    }
}

pub(crate) async fn token(
    tx: &mut PgTx,
    hash: &Sha256Digest,
) -> Result<Option<ResumeToken>, DbError> {
    let row = tx
        .query_opt(
            "read job_resume_token",
            "SELECT job_id, issued_at_us, expires_at_us, revoked_at_us FROM job_resume_token \
             WHERE token_hash = $1",
            &[&hash.0.as_slice()],
        )
        .await?;
    row.map(|r| {
        Ok(ResumeToken {
            job_id: col_id(&r, "job_id", JobId::from_bytes)?,
            issued_at: col_micros(&r, "issued_at_us")?,
            expires_at: col_micros(&r, "expires_at_us")?,
            revoked_at: col_opt_micros(&r, "revoked_at_us")?,
        })
    })
    .transpose()
}

pub(crate) async fn revoke_tokens(
    tx: &mut PgTx,
    job: JobId,
    at: UnixMicros,
) -> Result<u64, DbError> {
    let rows = tx
        .query_write(
            "update job_resume_token revoked",
            "UPDATE job_resume_token SET revoked_at_us = $2 \
             WHERE job_id = $1 AND revoked_at_us IS NULL RETURNING job_id",
            &[&to_uuid(job.as_bytes()), &at.as_micros()],
        )
        .await?;
    u64::try_from(rows.len()).map_err(|_| DbError::Corrupt { what: "count" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_must_be_positive() {
        let t = |v| UnixMicros::new(v).unwrap();
        assert!(check_window(t(10), t(10), "x").is_err());
        assert!(check_window(t(10), t(9), "x").is_err());
        assert!(check_window(t(10), t(11), "x").is_ok());
    }
}
