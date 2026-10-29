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

    use common::m3;
    use common::pg::{TestDb, assert_sqlstate};
    use common::{
        enrol, flow_atomic_with_audit, flow_chain_verifies, flow_content_lifecycle,
        flow_operator_rules, flow_package_lifecycle, flow_unaudited_change_refused, init_audit,
        make_ready,
    };
    use tokio_postgres::error::SqlState;
    use usgp_db::{DbError, RepoTx, Store};
    use usgp_proto::device::SessionState;
    use usgp_proto::{ContentKind, JobState, Step, StepState};

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

    // ------------------------------------------------- M3 (migration 0004)

    #[tokio::test]
    async fn m3_boot_services() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        m3::flow_boot_services(&db.admin, &db.app, &a).await;
        db.finish().await;
    }

    #[tokio::test]
    async fn m3_codes() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        m3::flow_codes(&db.admin, &db.app, &a).await;
        db.finish().await;
    }

    #[tokio::test]
    async fn m3_sessions() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        m3::flow_sessions(&db.admin, &db.app, &a).await;
        m3::flow_expiry_is_audited(&db.app, &a).await;
        db.finish().await;
    }

    #[tokio::test]
    async fn m3_job_success() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        m3::flow_job_success(&db.admin, &db.app, &a).await;
        flow_chain_verifies(&db.app, &a).await;
        db.finish().await;
    }

    #[tokio::test]
    async fn m3_job_failure() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        m3::flow_job_failure(&db.admin, &db.app, &a).await;
        db.finish().await;
    }

    /// The deferred wipe guard on PostgreSQL (REQ-DISK-006).
    #[tokio::test]
    async fn m3_wipe_guard() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        m3::flow_wipe_guard(&db.admin, &db.app, &a).await;
        flow_chain_verifies(&db.app, &a).await;
        db.finish().await;
    }

    /// Acceptance 3 on PostgreSQL (REQ-DISK-006, decision 0018 item 7;
    /// QA-005): when the `disk.wipe.authorised` record cannot be written,
    /// the confirmation transaction commits nothing: no job row, the
    /// session unchanged (still authorised, same row), and the chain still
    /// verifies. The failure is injected by a trigger, owned by the owner
    /// role in this test's own database, that refuses only that event;
    /// the trigger is then dropped and the same confirmation succeeds, so
    /// the refusal was the injected one.
    #[tokio::test]
    async fn m3_wipe_record_failure_creates_no_job() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        let op = common::enrol(&db.admin, &a, "wipe fault operator").await;
        let bs = m3::enrol_boot_service(&db.admin, &a, "relay wipe fault").await;
        let p = m3::ready_package(&db.app, &a, &op).await;
        let s = m3::ready_session(&db.app, &a, &op, bs.id, &p, m3::macs(1)).await;
        let session_before = {
            let mut tx = db.app.begin().await.unwrap();
            let v = tx.device_session(s.id).await.unwrap().unwrap();
            tx.rollback().await;
            v
        };
        assert_eq!(session_before.state, SessionState::Authorised);
        let head_before = usgp_audit::AuditRead::head(&db.app).await.unwrap();

        let owner = db.raw_owner().await;
        owner
            .batch_execute(
                "CREATE FUNCTION usgp_test_refuse_wipe_record() RETURNS trigger \
                 LANGUAGE plpgsql AS $$ BEGIN \
                 IF NEW.event = 'disk.wipe.authorised' THEN \
                 RAISE EXCEPTION 'test: wipe record refused' \
                 USING ERRCODE = 'insufficient_privilege'; END IF; \
                 RETURN NEW; END; $$; \
                 CREATE TRIGGER usgp_test_refuse_wipe_record \
                 BEFORE INSERT ON audit_record FOR EACH ROW \
                 EXECUTE FUNCTION usgp_test_refuse_wipe_record();",
            )
            .await
            .unwrap();

        let r = m3::confirm(&db.app, &a, &s, bs.id, &p).await;
        assert!(r.is_err(), "confirmation must fail without its wipe record");

        let mut tx = db.app.begin().await.unwrap();
        assert!(tx.job_by_session(s.id).await.unwrap().is_none());
        assert!(tx.list_jobs(&[]).await.unwrap().is_empty());
        assert_eq!(
            tx.device_session(s.id).await.unwrap().unwrap(),
            session_before
        );
        tx.rollback().await;
        // Nothing of the failed transaction reached the chain (not even
        // its `job.created` record).
        assert_eq!(
            usgp_audit::AuditRead::head(&db.app).await.unwrap(),
            head_before
        );
        let raw = db.raw_app().await;
        let jobs: i64 = raw
            .query_one("SELECT count(*) FROM job", &[])
            .await
            .unwrap()
            .get(0);
        assert_eq!(jobs, 0);
        let wipes: i64 = raw
            .query_one(
                "SELECT count(*) FROM audit_record WHERE event = 'disk.wipe.authorised'",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(wipes, 0);

        // Restore: drop the injected trigger; the same confirmation now
        // succeeds.
        owner
            .batch_execute(
                "DROP TRIGGER usgp_test_refuse_wipe_record ON audit_record; \
                 DROP FUNCTION usgp_test_refuse_wipe_record();",
            )
            .await
            .unwrap();
        let job = m3::confirm(&db.app, &a, &s, bs.id, &p).await.unwrap();
        let mut tx = db.app.begin().await.unwrap();
        assert_eq!(tx.job_by_session(s.id).await.unwrap().unwrap().id, job);
        tx.rollback().await;
        flow_chain_verifies(&db.app, &a).await;
        db.finish().await;
    }

    /// Plan section 3.8: the application role reads every new table,
    /// never writes boot services, deletes only assignments, and changes
    /// nothing else by DELETE or TRUNCATE.
    #[tokio::test]
    async fn m3_application_role_least_privilege() {
        let db = TestDb::migrated().await;
        let app = db.raw_app().await;
        for t in [
            "boot_service",
            "boot_service_package",
            "auth_code",
            "device_session",
            "job",
            "job_step",
            "boot_stop",
            "boot_policy_generation",
        ] {
            app.batch_execute(&format!("SELECT count(*) FROM {t}"))
                .await
                .unwrap();
        }
        for (sql, what) in [
            (
                "INSERT INTO boot_service (id) VALUES (gen_random_uuid())",
                "insert boot_service",
            ),
            (
                "UPDATE boot_service SET status = 'active'",
                "update boot_service",
            ),
            ("DELETE FROM boot_service", "delete boot_service"),
            ("SELECT 1 FROM boot_service FOR UPDATE", "lock boot_service"),
            (
                "UPDATE boot_service_package SET added_at_us = 0",
                "update boot_service_package",
            ),
            ("DELETE FROM auth_code", "delete auth_code"),
            ("DELETE FROM device_session", "delete device_session"),
            ("DELETE FROM job", "delete job"),
            ("DELETE FROM job_step", "delete job_step"),
            ("DELETE FROM boot_stop", "delete boot_stop"),
            (
                "DELETE FROM boot_policy_generation",
                "delete boot_policy_generation",
            ),
            ("TRUNCATE job", "truncate job"),
            ("TRUNCATE auth_code", "truncate auth_code"),
            ("ALTER TABLE job DISABLE TRIGGER USER", "disable job guards"),
            (
                "ALTER TABLE auth_code DISABLE TRIGGER USER",
                "disable code guards",
            ),
            ("DROP TRIGGER job_guard ON job", "drop job guard"),
        ] {
            assert_sqlstate(
                app.batch_execute(sql).await,
                &SqlState::INSUFFICIENT_PRIVILEGE,
                what,
            );
        }
        db.finish().await;
    }

    /// Decisions 0016 and 0021: the administrative role enrols and
    /// disables boot services, and touches nothing else of 0004.
    #[tokio::test]
    async fn m3_admin_role_least_privilege() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.admin).await;
        let bs = m3::enrol_boot_service(&db.admin, &a, "admin relay").await;
        let admin = db.raw_admin().await;
        admin
            .batch_execute("SELECT count(*) FROM boot_service")
            .await
            .unwrap();
        for (sql, what) in [
            ("SELECT count(*) FROM auth_code", "read auth_code"),
            ("SELECT count(*) FROM device_session", "read device_session"),
            ("SELECT count(*) FROM job", "read job"),
            (
                "SELECT count(*) FROM boot_service_package",
                "read boot_service_package",
            ),
            ("SELECT count(*) FROM boot_stop", "read boot_stop"),
            (
                "INSERT INTO boot_policy_generation VALUES (gen_random_uuid(), 1)",
                "insert boot_policy_generation",
            ),
            ("DELETE FROM boot_service", "delete boot_service"),
            ("TRUNCATE boot_service", "truncate boot_service"),
        ] {
            assert_sqlstate(
                admin.batch_execute(sql).await,
                &SqlState::INSUFFICIENT_PRIVILEGE,
                what,
            );
        }
        let mut tx = db.app.begin().await.unwrap();
        assert_eq!(tx.boot_service(bs.id).await.unwrap().unwrap().id, bs.id);
        tx.rollback().await;
        db.finish().await;
    }

    /// Migration 0004 guards against the application role writing rows
    /// directly: a used or revoked code stays so and its HMAC never
    /// changes; a finished job never changes; the wipe reference never
    /// changes; the generation only increases; a cleared stop stays
    /// cleared.
    #[tokio::test]
    async fn m3_guards_refuse_direct_changes() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        let op = enrol(&db.admin, &a, "guarded").await;
        let bs = m3::enrol_boot_service(&db.admin, &a, "relay guards").await;
        let p = m3::ready_package(&db.app, &a, &op).await;

        // A used code and a revoked code.
        let used = m3::issue_code(&db.app, &a, &op, "USED000001", 900).await;
        let revoked = m3::issue_code(&db.app, &a, &op, "REV0KED001", 900).await;
        let s = m3::open_session(&db.app, &a, None, m3::macs(1)).await;
        let mut tx = db.app.begin().await.unwrap();
        assert_eq!(
            tx.consume_auth_code(&m3::code_hmac("USED000001"), s.id, common::now())
                .await
                .unwrap(),
            Some(used)
        );
        tx.revoke_auth_code(revoked, op.id, common::now())
            .await
            .unwrap();
        common::append(&a, &mut tx, "auth_code.used", "auth_code", "x").await;
        tx.commit().await.unwrap();

        // A failed job and a running one.
        let s1 = m3::ready_session(&db.app, &a, &op, bs.id, &p, m3::macs(1)).await;
        let failed = m3::confirm(&db.app, &a, &s1, bs.id, &p).await.unwrap();
        let mut tx = db.app.begin().await.unwrap();
        tx.set_job_step(
            failed,
            Step::VERIFY_CONTENT,
            StepState::Failed,
            common::now(),
        )
        .await
        .unwrap();
        tx.fail_job(
            failed,
            &[JobState::Running],
            &m3::failure(Step::VERIFY_CONTENT),
            common::now(),
        )
        .await
        .unwrap();
        tx.bump_boot_policy_generation(bs.id).await.unwrap();
        common::append(&a, &mut tx, "job.failed", "job", &failed.to_string()).await;
        tx.commit().await.unwrap();
        let s2 = m3::ready_session(&db.app, &a, &op, bs.id, &p, m3::macs(1)).await;
        let running = m3::confirm(&db.app, &a, &s2, bs.id, &p).await.unwrap();

        let app = db.raw_app().await;
        let uid = |b: &[u8; 16]| uuid::Uuid::from_bytes(*b);
        let (u, r) = (uid(used.as_bytes()), uid(revoked.as_bytes()));
        let (f, run) = (uid(failed.as_bytes()), uid(running.as_bytes()));
        let b = uid(bs.id.as_bytes());
        let refused: [(&str, &[&(dyn tokio_postgres::types::ToSql + Sync)], &str); 11] = [
            (
                "UPDATE auth_code SET used_at_us = NULL, used_by_session = NULL WHERE id = $1",
                &[&u],
                "un-use a code",
            ),
            (
                "UPDATE auth_code SET code_hmac = decode(repeat('11', 32), 'hex') WHERE id = $1",
                &[&u],
                "change a code HMAC",
            ),
            (
                "UPDATE auth_code SET expires_at_us = expires_at_us + 1 WHERE id = $1",
                &[&r],
                "extend a code",
            ),
            (
                "UPDATE auth_code SET revoked_at_us = NULL, revoked_by = NULL WHERE id = $1",
                &[&r],
                "un-revoke a code",
            ),
            (
                "UPDATE job SET state = 'running', finished_at_us = NULL, failure_step = NULL, \
                 failure_category = NULL, failure_detail = NULL WHERE id = $1",
                &[&f],
                "reopen a failed job",
            ),
            (
                "UPDATE job SET bytes_done = 1 WHERE id = $1",
                &[&f],
                "change a failed job",
            ),
            (
                "UPDATE job SET wipe_audit_seq = wipe_audit_seq + 1 WHERE id = $1",
                &[&run],
                "move the wipe reference",
            ),
            (
                "UPDATE job SET plan_sha256 = decode(repeat('22', 32), 'hex') WHERE id = $1",
                &[&run],
                "change the plan digest",
            ),
            (
                "UPDATE job_step SET state = 'running', finished_at_us = NULL \
                 WHERE job_id = $1 AND step = 1",
                &[&f],
                "reopen a failed step",
            ),
            (
                "UPDATE boot_policy_generation SET generation = generation - 1 \
                 WHERE boot_service_id = $1",
                &[&b],
                "roll back the generation",
            ),
            (
                "UPDATE device_session SET state = 'authorised' WHERE id = $1",
                &[&uid(s1.id.as_bytes())],
                "reopen a confirmed session",
            ),
        ];
        for (sql, params, what) in refused {
            let r = app.execute(sql, params).await;
            assert_sqlstate(r, &SqlState::INTEGRITY_CONSTRAINT_VIOLATION, what);
        }
        // Progress cannot go backwards on a running job.
        app.execute("UPDATE job SET last_seq = 5 WHERE id = $1", &[&run])
            .await
            .unwrap();
        assert_sqlstate(
            app.execute("UPDATE job SET last_seq = 4 WHERE id = $1", &[&run])
                .await,
            &SqlState::INTEGRITY_CONSTRAINT_VIOLATION,
            "seq backwards",
        );
        // The guards bind the owner too (only disabling them would not).
        let owner = db.raw_owner().await;
        assert_sqlstate(
            owner
                .execute("UPDATE job SET state = 'succeeded' WHERE id = $1", &[&f])
                .await,
            &SqlState::INTEGRITY_CONSTRAINT_VIOLATION,
            "owner changes a failed job",
        );
        // A stored session state outside the set is refused (CHECK).
        assert_sqlstate(
            app.execute(
                "UPDATE device_session SET state = 'bogus' WHERE id = $1",
                &[&uid(s.id.as_bytes())],
            )
            .await,
            &SqlState::CHECK_VIOLATION,
            "unknown session state",
        );
        let mut tx = db.app.begin().await.unwrap();
        assert_eq!(
            tx.device_session(s1.id).await.unwrap().unwrap().state,
            SessionState::Confirmed
        );
        tx.rollback().await;
        db.finish().await;
    }

    /// Stored session rows are re-validated on read.
    #[tokio::test]
    async fn m3_tampered_session_is_corrupt_on_read() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        let s = m3::open_session(&db.app, &a, None, m3::macs(1)).await;
        let owner = db.raw_owner().await;
        let id = uuid::Uuid::from_bytes(*s.id.as_bytes());
        // Identity columns are guarded even against the owner; an attacker
        // with owner rights disables the guard first (column checks stay).
        owner
            .batch_execute("ALTER TABLE device_session DISABLE TRIGGER device_session_guard")
            .await
            .unwrap();
        // Seven characters (passes the column check) but `U` is outside
        // the base32 alphabet even after look-alike normalisation.
        owner
            .execute(
                "UPDATE device_session SET display_code = 'UUU-UUU' WHERE id = $1",
                &[&id],
            )
            .await
            .unwrap();
        let mut tx = db.app.begin().await.unwrap();
        let err = tx.device_session(s.id).await.unwrap_err();
        assert!(
            matches!(
                err,
                DbError::Corrupt {
                    what: "display_code"
                }
            ),
            "{err:?}"
        );
        tx.rollback().await;
        // A multicast MAC (6 bytes, so the column check passes).
        owner
            .execute(
                "UPDATE device_session SET display_code = 'ABC-DEF', \
                 macs = ARRAY[decode('010000000001', 'hex')] WHERE id = $1",
                &[&id],
            )
            .await
            .unwrap();
        let mut tx = db.app.begin().await.unwrap();
        let err = tx.device_session(s.id).await.unwrap_err();
        assert!(matches!(err, DbError::Corrupt { what: "macs" }), "{err:?}");
        tx.rollback().await;
        // A MAC of the wrong length is refused by the column check.
        assert_sqlstate(
            owner
                .execute(
                    "UPDATE device_session SET macs = ARRAY[decode('0200000001', 'hex')] \
                     WHERE id = $1",
                    &[&id],
                )
                .await,
            &SqlState::CHECK_VIOLATION,
            "five-byte MAC",
        );
        db.finish().await;
    }
}
