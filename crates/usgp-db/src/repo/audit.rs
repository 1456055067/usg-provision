//! [`AuditTx`] on a PostgreSQL transaction and [`AuditRead`] on the store
//! (plan section 5.6, `usgp_audit::store` mapping).
//!
//! - `lock_head`: `SELECT ... FROM audit_head WHERE id = 1 FOR UPDATE`;
//!   the row always exists (0001), `seq = 0` means an empty chain. The lock
//!   serialises appends until the transaction ends.
//! - `insert_record`: `INSERT audit_record` then `UPDATE audit_head`, in
//!   the caller's transaction. Database triggers also refuse a record that
//!   does not extend the head, and a head that does not advance by one.

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-9 (Protection of Audit Information) - insert-only
//   access; the application role cannot UPDATE or DELETE records (0002).
// - NIST 800-53: AU-5 - written in the caller's transaction.
// - SPEC: specs/operator-access.md#REQ-AUD-005, #REQ-AUD-006

use tokio_postgres::Row;
use usgp_audit::{
    AuditRead, AuditRecord, AuditTx, ChainHead, Checkpoint, StoreError, StoreErrorKind,
};
use usgp_common::Sha256Digest;
use usgp_crypto::KeyId;

use super::conv::{bytes32, col, col_digest, col_opt_u64, col_u64, to_i64};
use crate::error::DbError;
use crate::pool::{PgStore, PgTx};

const RECORD_COLUMNS: &str = "seq, ts_us, event, outcome, actor_kind, actor_id, actor_label, \
     interface, node, source, target_kind, target_id, reason, detail, initiating_seq, \
     prev_hash, record_hash";

fn store_err(ctx: &'static str) -> impl FnOnce(DbError) -> StoreError {
    move |e| e.into_store(ctx)
}

fn head_from_row(r: &Row) -> Result<Option<ChainHead>, DbError> {
    let seq = col_u64(r, "seq")?;
    if seq == 0 {
        return Ok(None);
    }
    Ok(Some(ChainHead {
        seq,
        record_hash: col_digest(r, "record_hash")?,
    }))
}

pub(crate) fn record_from_row(r: &Row) -> Result<AuditRecord, DbError> {
    Ok(AuditRecord {
        seq: col_u64(r, "seq")?,
        ts_us: col(r, "ts_us")?,
        event: col(r, "event")?,
        outcome: col(r, "outcome")?,
        actor_kind: col(r, "actor_kind")?,
        actor_id: col(r, "actor_id")?,
        actor_label: col(r, "actor_label")?,
        interface: col(r, "interface")?,
        node: col(r, "node")?,
        source: col(r, "source")?,
        target_kind: col(r, "target_kind")?,
        target_id: col(r, "target_id")?,
        reason: col(r, "reason")?,
        detail: col(r, "detail")?,
        initiating_seq: col_opt_u64(r, "initiating_seq")?,
        prev_hash: col_digest(r, "prev_hash")?,
        record_hash: col_digest(r, "record_hash")?,
    })
}

fn checkpoint_from_row(r: &Row) -> Result<Checkpoint, DbError> {
    let key: &[u8] = col(r, "key_id")?;
    Ok(Checkpoint {
        seq: col_u64(r, "seq")?,
        record_hash: col_digest(r, "record_hash")?,
        signed_at_us: col(r, "signed_at_us")?,
        key_id: KeyId(Sha256Digest(bytes32(key, "key_id")?)),
        signature: col(r, "signature")?,
    })
}

impl AuditTx for PgTx {
    async fn lock_head(&mut self) -> Result<Option<ChainHead>, StoreError> {
        let row = self
            .query_opt(
                "lock audit_head",
                "SELECT seq, record_hash FROM audit_head WHERE id = 1 FOR UPDATE",
                &[],
            )
            .await
            .map_err(store_err("lock audit_head"))?;
        match row {
            Some(r) => head_from_row(&r).map_err(store_err("read audit_head")),
            None => Err(StoreError::new(
                StoreErrorKind::Corrupt,
                "audit_head row missing",
            )),
        }
    }

    async fn insert_record(&mut self, rec: &AuditRecord) -> Result<(), StoreError> {
        let ctx = "insert audit_record";
        let seq = to_i64(rec.seq, "seq").map_err(store_err(ctx))?;
        let initiating = rec
            .initiating_seq
            .map(|s| to_i64(s, "initiating_seq"))
            .transpose()
            .map_err(store_err(ctx))?;
        let sql = format!(
            "INSERT INTO audit_record ({RECORD_COLUMNS}) VALUES \
             ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)"
        );
        let n = self
            .execute(
                ctx,
                &sql,
                &[
                    &seq,
                    &rec.ts_us,
                    &rec.event,
                    &rec.outcome,
                    &rec.actor_kind,
                    &rec.actor_id,
                    &rec.actor_label,
                    &rec.interface,
                    &rec.node,
                    &rec.source,
                    &rec.target_kind,
                    &rec.target_id,
                    &rec.reason,
                    &rec.detail,
                    &initiating,
                    &rec.prev_hash.0.as_slice(),
                    &rec.record_hash.0.as_slice(),
                ],
            )
            .await
            .map_err(store_err(ctx))?;
        if n != 1 {
            self.poison();
            return Err(StoreError::new(StoreErrorKind::Unavailable, ctx));
        }
        let n = self
            .execute(
                "update audit_head",
                "UPDATE audit_head SET seq = $1, record_hash = $2 WHERE id = 1",
                &[&seq, &rec.record_hash.0.as_slice()],
            )
            .await
            .map_err(store_err("update audit_head"))?;
        if n != 1 {
            self.poison();
            return Err(StoreError::new(
                StoreErrorKind::Corrupt,
                "audit_head row missing",
            ));
        }
        self.audited = true;
        Ok(())
    }

    async fn insert_checkpoint(&mut self, cp: &Checkpoint) -> Result<(), StoreError> {
        let ctx = "insert audit_checkpoint";
        let seq = to_i64(cp.seq, "seq").map_err(store_err(ctx))?;
        self.execute(
            ctx,
            "INSERT INTO audit_checkpoint (seq, record_hash, signed_at_us, key_id, signature) \
             VALUES ($1, $2, $3, $4, $5)",
            &[
                &seq,
                &cp.record_hash.0.as_slice(),
                &cp.signed_at_us,
                &cp.key_id.0.0.as_slice(),
                &cp.signature,
            ],
        )
        .await
        .map_err(store_err(ctx))?;
        Ok(())
    }

    async fn last_checkpoint(&mut self) -> Result<Option<Checkpoint>, StoreError> {
        let ctx = "read audit_checkpoint";
        let row = self
            .query_opt(
                ctx,
                "SELECT seq, record_hash, signed_at_us, key_id, signature \
                 FROM audit_checkpoint ORDER BY seq DESC LIMIT 1",
                &[],
            )
            .await
            .map_err(store_err(ctx))?;
        row.map(|r| checkpoint_from_row(&r))
            .transpose()
            .map_err(store_err(ctx))
    }
}

impl AuditRead for PgStore {
    async fn head(&self) -> Result<Option<ChainHead>, StoreError> {
        let ctx = "read audit_head";
        let obj = self.get().await.map_err(store_err(ctx))?;
        let row = obj
            .query_opt("SELECT seq, record_hash FROM audit_head WHERE id = 1", &[])
            .await
            .map_err(|e| DbError::from_pg(ctx, e).into_store(ctx))?;
        match row {
            Some(r) => head_from_row(&r).map_err(store_err(ctx)),
            None => Ok(None),
        }
    }

    async fn records_after(
        &self,
        after_seq: u64,
        limit: usize,
    ) -> Result<Vec<AuditRecord>, StoreError> {
        let ctx = "read audit_record";
        let after = to_i64(after_seq, "after_seq").map_err(store_err(ctx))?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let obj = self.get().await.map_err(store_err(ctx))?;
        let sql = format!(
            "SELECT {RECORD_COLUMNS} FROM audit_record WHERE seq > $1 ORDER BY seq LIMIT $2"
        );
        let rows = obj
            .query(&sql, &[&after, &limit])
            .await
            .map_err(|e| DbError::from_pg(ctx, e).into_store(ctx))?;
        rows.iter()
            .map(record_from_row)
            .collect::<Result<_, _>>()
            .map_err(store_err(ctx))
    }

    async fn checkpoints(&self) -> Result<Vec<Checkpoint>, StoreError> {
        let ctx = "read audit_checkpoint";
        let obj = self.get().await.map_err(store_err(ctx))?;
        let rows = obj
            .query(
                "SELECT seq, record_hash, signed_at_us, key_id, signature \
                 FROM audit_checkpoint ORDER BY seq",
                &[],
            )
            .await
            .map_err(|e| DbError::from_pg(ctx, e).into_store(ctx))?;
        rows.iter()
            .map(checkpoint_from_row)
            .collect::<Result<_, _>>()
            .map_err(store_err(ctx))
    }
}
