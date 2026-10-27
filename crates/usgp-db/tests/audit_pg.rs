//! The audit chain on PostgreSQL (feature `pg-integration`; CI). Without
//! the `USGP_TEST_PG_*` environment every test fails (never skips).
//!
//! - records and checkpoints persist and verify (REQ-AUD-005);
//! - the application role cannot UPDATE, DELETE or TRUNCATE audit records
//!   or checkpoints, nor insert or delete the head; the head only advances
//!   by one onto a stored record; a record must extend the head;
//! - triggers refuse UPDATE/DELETE/TRUNCATE even for the owner;
//! - an owner who disables the triggers and modifies, deletes or reorders
//!   records is caught by the verifier at the right seq;
//! - a failed audit write rolls back the change it records (REQ-AUD-006);
//! - concurrent appends stay one contiguous chain.

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-9, AU-9(3), AU-5, AU-12
// - SPEC: specs/operator-access.md#REQ-AUD-005, #REQ-AUD-006
// - Decision 0015 item 1

#![cfg(feature = "pg-integration")]

#[cfg(test)]
pub mod common;

// Helpers and tests in one `cfg(test)` module so the workspace's
// test-only clippy allowances apply (same convention as usgp-audit).
#[cfg(test)]
mod t {
    use super::common;

    use common::pg::{TestDb, assert_sqlstate};
    use common::{
        Audit, append, draft, flow_atomic_with_audit, flow_chain_verifies, init_audit, operator,
    };
    use tokio_postgres::error::SqlState;
    use usgp_audit::{AuditRead, AuditTx, Violation, verify_store};
    use usgp_db::{DbError, PgStore, RepoTx, Store};

    /// A migrated database with a genesis record and `n` more records, then a
    /// checkpoint.
    async fn chain_with(n: usize) -> (TestDb, Audit) {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        for i in 0..n {
            let mut tx = db.app.begin().await.unwrap();
            append(&a, &mut tx, "api.limits.read", "limits", &i.to_string()).await;
            tx.commit().await.unwrap();
        }
        flow_chain_verifies(&db.app, &a).await;
        (db, a)
    }

    async fn first_finding(store: &PgStore, a: &Audit) -> (u64, Violation) {
        let report = verify_store(store, std::slice::from_ref(&a.public), 50)
            .await
            .unwrap();
        assert!(!report.is_intact());
        let f = report.first_finding().unwrap();
        (f.seq, f.violation)
    }

    #[tokio::test]
    async fn records_and_checkpoints_persist_and_verify() {
        let (db, a) = chain_with(5).await;
        // Operators are written by the admin role (decision 0016); both
        // roles append to the same chain.
        flow_atomic_with_audit(&db.admin, &a).await;
        flow_chain_verifies(&db.app, &a).await;
        let head = db.app.head().await.unwrap().unwrap();
        let all = db.app.records_after(0, 1000).await.unwrap();
        assert_eq!(u64::try_from(all.len()).unwrap(), head.seq);
        assert_eq!(all.last().unwrap().record_hash, head.record_hash);
        assert!(db.app.checkpoints().await.unwrap().len() >= 2);
        db.finish().await;
    }

    #[tokio::test]
    async fn application_role_cannot_rewrite_audit() {
        let (db, _a) = chain_with(2).await;
        let app = db.raw_app().await;
        for (sql, what) in [
            (
                "UPDATE audit_record SET detail = '{}' WHERE seq = 2",
                "update record",
            ),
            ("DELETE FROM audit_record WHERE seq = 2", "delete record"),
            ("TRUNCATE audit_record", "truncate records"),
            (
                "UPDATE audit_checkpoint SET signed_at_us = 0",
                "update checkpoint",
            ),
            ("DELETE FROM audit_checkpoint", "delete checkpoint"),
            ("TRUNCATE audit_checkpoint", "truncate checkpoints"),
            ("DELETE FROM audit_head", "delete head"),
            (
                "INSERT INTO audit_head (id, seq, record_hash) VALUES (2, 0, decode(repeat('00', 32), 'hex'))",
                "insert head",
            ),
        ] {
            assert_sqlstate(
                app.batch_execute(sql).await,
                &SqlState::INSUFFICIENT_PRIVILEGE,
                what,
            );
        }
        // UPDATE on the head is granted, but the guard allows only +1 onto a
        // stored record.
        assert_sqlstate(
            app.batch_execute("UPDATE audit_head SET seq = seq + 5")
                .await,
            &SqlState::INTEGRITY_CONSTRAINT_VIOLATION,
            "head jump",
        );
        assert_sqlstate(
        app.batch_execute(
            "UPDATE audit_head SET seq = seq + 1, record_hash = decode(repeat('ee', 32), 'hex')",
        )
        .await,
        &SqlState::INTEGRITY_CONSTRAINT_VIOLATION,
        "head onto a missing record",
    );
        db.finish().await;
    }

    #[tokio::test]
    async fn triggers_refuse_the_owner_too() {
        let (db, _a) = chain_with(2).await;
        let owner = db.raw_owner().await;
        for (sql, what) in [
            (
                "UPDATE audit_record SET detail = '{}' WHERE seq = 2",
                "update record",
            ),
            ("DELETE FROM audit_record WHERE seq = 2", "delete record"),
            ("TRUNCATE audit_record CASCADE", "truncate records"),
            (
                "UPDATE audit_checkpoint SET signed_at_us = 0",
                "update checkpoint",
            ),
            ("DELETE FROM audit_head", "delete head"),
        ] {
            assert_sqlstate(
                owner.batch_execute(sql).await,
                &SqlState::INSUFFICIENT_PRIVILEGE,
                what,
            );
        }
        db.finish().await;
    }

    #[tokio::test]
    async fn record_must_extend_the_head() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        let mut tx = db.app.begin().await.unwrap();
        let mut rec = a
            .chain
            .append(&mut tx, &draft("api.limits.read", "limits", "1"))
            .await
            .unwrap();
        // Re-inserting a record that does not extend the (moved) head.
        rec.seq += 5;
        assert!(tx.insert_record(&rec).await.is_err());
        assert!(matches!(tx.commit().await, Err(DbError::TxFailed)));
        db.finish().await;
    }

    /// REQ-AUD-006 / decision 0015 item 1 on PostgreSQL: the audit write fails,
    /// so the change it would record is rolled back with it.
    #[tokio::test]
    async fn failed_audit_write_rolls_back_the_change() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        let head = db.app.head().await.unwrap();
        let op = operator("not recorded");
        let mut tx = db.admin.begin().await.unwrap();
        tx.insert_operator(&op).await.unwrap();
        let mut rec = a
            .chain
            .append(&mut tx, &draft("operator.enrolled", "operator", "x"))
            .await
            .unwrap();
        // A second record that does not extend the head: the database
        // refuses it, as any audit write failure.
        rec.seq += 7;
        assert!(tx.insert_record(&rec).await.is_err());
        assert!(matches!(tx.commit().await, Err(DbError::TxFailed)));
        assert_eq!(db.app.head().await.unwrap(), head);
        let mut tx = db.app.begin().await.unwrap();
        assert!(tx.operator(op.id).await.unwrap().is_none());
        tx.rollback().await;
        db.finish().await;
    }

    async fn tamper(db: &TestDb, sql: &str) {
        // Three separate statements, not one batch: a batch is one implicit
        // transaction, and a DELETE queues the deferred foreign-key checks
        // on audit_record, so re-enabling triggers in the same transaction
        // fails with 55006 (pending trigger events).
        let owner = db.raw_owner().await;
        for stmt in [
            "ALTER TABLE audit_record DISABLE TRIGGER USER",
            sql,
            "ALTER TABLE audit_record ENABLE TRIGGER USER",
        ] {
            owner.batch_execute(stmt).await.unwrap();
        }
    }

    #[tokio::test]
    async fn modified_record_detected() {
        let (db, a) = chain_with(5).await;
        tamper(
            &db,
            "UPDATE audit_record SET detail = '{\"test\":\"2\"}' WHERE seq = 3",
        )
        .await;
        let (seq, v) = first_finding(&db.app, &a).await;
        assert_eq!(seq, 3);
        assert_eq!(v, Violation::RecordHashMismatch);
        db.finish().await;
    }

    #[tokio::test]
    async fn deleted_record_detected() {
        let (db, a) = chain_with(5).await;
        tamper(&db, "DELETE FROM audit_record WHERE seq = 3").await;
        let (seq, _v) = first_finding(&db.app, &a).await;
        assert!(seq == 3 || seq == 4, "first finding at {seq}");
        db.finish().await;
    }

    #[tokio::test]
    async fn reordered_records_detected() {
        let (db, a) = chain_with(5).await;
        // Swap the contents of records 3 and 4.
        tamper(
            &db,
            "UPDATE audit_record r SET target_id = s.target_id, ts_us = s.ts_us, \
         prev_hash = s.prev_hash, record_hash = s.record_hash \
         FROM (SELECT seq, target_id, ts_us, prev_hash, record_hash FROM audit_record \
               WHERE seq IN (3, 4)) s \
         WHERE r.seq IN (3, 4) AND s.seq = 7 - r.seq",
        )
        .await;
        let (seq, _v) = first_finding(&db.app, &a).await;
        assert_eq!(seq, 3);
        db.finish().await;
    }

    #[tokio::test]
    async fn concurrent_appends_stay_contiguous() {
        let db = TestDb::migrated().await;
        let a = std::sync::Arc::new(init_audit(&db.app).await);
        let mut tasks = Vec::new();
        for t in 0..3 {
            let store = db.app.clone();
            let a = std::sync::Arc::clone(&a);
            tasks.push(tokio::spawn(async move {
                for i in 0..10 {
                    let mut tx = store.begin().await.unwrap();
                    append(
                        &a,
                        &mut tx,
                        "api.limits.read",
                        "limits",
                        &format!("{t}-{i}"),
                    )
                    .await;
                    tx.commit().await.unwrap();
                }
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        let head = db.app.head().await.unwrap().unwrap();
        assert_eq!(head.seq, 31);
        flow_chain_verifies(&db.app, &a).await;
        db.finish().await;
    }
}
