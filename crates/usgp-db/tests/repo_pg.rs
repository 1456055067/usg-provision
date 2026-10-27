//! Repository rules against PostgreSQL as the application role (feature
//! `pg-integration`; CI). The same scenarios run on the memory store in
//! `memory_repo.rs`. Without the `USGP_TEST_PG_*` environment every test
//! fails (never skips).
//!
//! PostgreSQL-only checks: declaration all-or-nothing and closed value
//! sets as CHECK constraints, least privilege of the application role, and
//! re-validation of stored rows on read.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-6 (application role), SI-10, AU-12
// - SPEC: specs/os-images.md#REQ-IMG-020, #REQ-IMG-043
// - Decisions 0013, 0015

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
        enrol, flow_atomic_with_audit, flow_chain_verifies, flow_content_lifecycle,
        flow_operator_rules, flow_package_lifecycle, flow_unaudited_change_refused, init_audit,
        make_ready,
    };
    use tokio_postgres::error::SqlState;
    use usgp_db::{DbError, RepoTx, Store};
    use usgp_proto::ContentKind;

    #[tokio::test]
    async fn unaudited_change_refused() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        flow_unaudited_change_refused(&db.admin, &a).await;
        db.finish().await;
    }

    #[tokio::test]
    async fn change_and_record_are_atomic() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        flow_atomic_with_audit(&db.admin, &a).await;
        db.finish().await;
    }

    #[tokio::test]
    async fn operator_rules() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        flow_operator_rules(&db.admin, &a).await;
        db.finish().await;
    }

    #[tokio::test]
    async fn content_lifecycle() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        flow_content_lifecycle(&db.admin, &db.app, &a).await;
        db.finish().await;
    }

    #[tokio::test]
    async fn package_lifecycle() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        flow_package_lifecycle(&db.admin, &db.app, &a).await;
        flow_chain_verifies(&db.app, &a).await;
        db.finish().await;
    }

    #[tokio::test]
    async fn declaration_and_value_constraints() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        let op = enrol(&db.admin, &a, "declarer").await;
        let image = make_ready(&db.app, &a, op.id, ContentKind::Image, 2).await;
        let app = db.raw_app().await;
        let id = uuid::Uuid::from_bytes(*image.id.as_bytes());
        // Partial declaration (decision 0013: all or nothing).
        assert_sqlstate(
            app.execute(
                "UPDATE edition SET decl_release = 'windows-11' WHERE content_id = $1 AND idx = 1",
                &[&id],
            )
            .await,
            &SqlState::CHECK_VIOLATION,
            "partial declaration",
        );
        // Values outside the closed sets.
        assert_sqlstate(
            app.execute("UPDATE content SET state = 'bogus' WHERE id = $1", &[&id])
                .await,
            &SqlState::CHECK_VIOLATION,
            "unknown state",
        );
        assert_sqlstate(
            app.execute(
                "UPDATE edition SET support_status = 'supported' WHERE content_id = $1 AND idx = 1",
                &[&id],
            )
            .await,
            &SqlState::CHECK_VIOLATION,
            "supported without declaration",
        );
        // Ready without a manifest.
        assert_sqlstate(
        app.execute("UPDATE content SET manifest = NULL, manifest_sig = NULL, manifest_key_id = NULL WHERE id = $1", &[&id])
            .await,
        &SqlState::CHECK_VIOLATION,
        "ready without manifest",
    );
        db.finish().await;
    }

    #[tokio::test]
    async fn application_role_least_privilege() {
        let db = TestDb::migrated().await;
        let app = db.raw_app().await;
        for (sql, what) in [
            ("DELETE FROM content", "delete content"),
            ("DELETE FROM edition", "delete edition"),
            ("DELETE FROM upload", "delete upload"),
            ("DELETE FROM operator", "delete operator"),
            ("TRUNCATE package", "truncate package"),
            ("CREATE TABLE intruder (i integer)", "create table"),
            ("DROP TABLE package", "drop table"),
            (
                "ALTER TABLE audit_record DISABLE TRIGGER USER",
                "disable audit triggers",
            ),
            ("DELETE FROM schema_migrations", "delete schema_migrations"),
            // Decision 0016: operators are written only by the admin role.
            (
                "INSERT INTO operator (id) VALUES (gen_random_uuid())",
                "insert operator",
            ),
            ("UPDATE operator SET status = 'active'", "update operator"),
        ] {
            assert_sqlstate(
                app.batch_execute(sql).await,
                &SqlState::INSUFFICIENT_PRIVILEGE,
                what,
            );
        }
        // Reading operators (authentication) still works.
        app.batch_execute("SELECT count(*) FROM operator")
            .await
            .unwrap();
        db.finish().await;
    }

    /// Decision 0016: the administrative role writes operators and the
    /// audit chain, and nothing else.
    #[tokio::test]
    async fn admin_role_least_privilege() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.admin).await;
        // Enrol and disable work through the admin role.
        let op = enrol(&db.admin, &a, "enrolled by admin").await;
        flow_operator_rules(&db.admin, &a).await;
        assert_eq!(
            db.admin.check_schema().await.unwrap(),
            usgp_db::SCHEMA_VERSION
        );
        let admin = db.raw_admin().await;
        let id = uuid::Uuid::from_bytes(*op.id.as_bytes());
        for (sql, what) in [
            ("SELECT count(*) FROM content", "read content"),
            ("SELECT count(*) FROM package", "read package"),
            ("SELECT count(*) FROM upload", "read upload"),
            ("SELECT count(*) FROM edition", "read edition"),
            ("DELETE FROM package", "delete package"),
            ("DELETE FROM operator", "delete operator"),
            (
                "UPDATE audit_record SET detail = '{}'",
                "update audit record",
            ),
            ("DELETE FROM audit_checkpoint", "delete checkpoint"),
            ("TRUNCATE operator", "truncate operator"),
            ("CREATE TABLE intruder (i integer)", "create table"),
            ("DELETE FROM schema_migrations", "delete schema_migrations"),
        ] {
            assert_sqlstate(
                admin.batch_execute(sql).await,
                &SqlState::INSUFFICIENT_PRIVILEGE,
                what,
            );
        }
        let mut tx = db.app.begin().await.unwrap();
        assert_eq!(tx.operator(op.id).await.unwrap().unwrap().id, op.id);
        tx.rollback().await;
        let _ = id;
        db.finish().await;
    }

    #[tokio::test]
    async fn tampered_row_is_corrupt_on_read() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        let op = enrol(&db.admin, &a, "victim").await;
        let owner = db.raw_owner().await;
        let id = uuid::Uuid::from_bytes(*op.id.as_bytes());
        owner
            .execute(
                "UPDATE operator SET display_name = E'bad\\x01name' WHERE id = $1",
                &[&id],
            )
            .await
            .unwrap();
        let mut tx = db.app.begin().await.unwrap();
        let err = tx.operator(op.id).await.unwrap_err();
        assert!(
            matches!(
                err,
                DbError::Corrupt {
                    what: "display_name"
                }
            ),
            "{err:?}"
        );
        tx.rollback().await;
        db.finish().await;
    }
}
