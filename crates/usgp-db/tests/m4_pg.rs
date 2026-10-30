//! M4 repository rules against PostgreSQL (migration 0005; feature
//! `pg-integration`; CI). The same scenarios run on the memory store in
//! `memory_repo.rs`. Without the `USGP_TEST_PG_*` environment every test
//! fails (never skips).
//!
//! PostgreSQL-only checks: least privilege on the new tables (column
//! UPDATE grant on the escrow, no DELETE), and the 0005 guards against
//! direct changes, including by the owner role.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-6, SC-28, IA-5, SI-10, AU-12
// - SPEC: specs/drivers.md#REQ-DRV-003; specs/configuration.md#REQ-CFG-008;
//   specs/workflow.md#REQ-SEQ-002, #REQ-SEQ-006
// - Decisions 0024, 0025

#![cfg(feature = "pg-integration")]

#[cfg(test)]
pub mod common;

#[cfg(test)]
mod t {
    use super::common;

    use common::pg::{TestDb, assert_sqlstate};
    use common::{enrol, flow_chain_verifies, init_audit, m3, m4};
    use tokio_postgres::error::SqlState;
    use tokio_postgres::types::ToSql;
    use usgp_db::{NewEscrow, NewResumeToken, RepoTx, Store};
    use usgp_proto::{EscrowAccount, StepState, StepV2};

    #[tokio::test]
    async fn m4_archive_content() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        m4::flow_archive_content(&db.app, &a).await;
        flow_chain_verifies(&db.app, &a).await;
        db.finish().await;
    }

    #[tokio::test]
    async fn m4_driver_archives() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        m4::flow_driver_archives(&db.app, &a).await;
        db.finish().await;
    }

    #[tokio::test]
    async fn m4_agent_packages_and_config() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        m4::flow_agent_packages_and_config(&db.app, &a).await;
        db.finish().await;
    }

    #[tokio::test]
    async fn m4_device_values() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        m4::flow_device_values(&db.app, &a).await;
        db.finish().await;
    }

    #[tokio::test]
    async fn m4_job_v2() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        m4::flow_job_v2(&db.admin, &db.app, &a).await;
        flow_chain_verifies(&db.app, &a).await;
        db.finish().await;
    }

    #[tokio::test]
    async fn m4_job_v2_failure() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        m4::flow_job_v2_failure(&db.admin, &db.app, &a).await;
        db.finish().await;
    }

    #[tokio::test]
    async fn m4_job_v2_guards() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        m4::flow_job_v2_guards(&db.admin, &db.app, &a).await;
        db.finish().await;
    }

    /// M4 plan section 3.5: the application role cannot delete escrow,
    /// resume, archive or signer rows, cannot change the sealed password
    /// (column grant), and cannot disable the guards.
    #[tokio::test]
    async fn m4_application_role_least_privilege() {
        let db = TestDb::migrated().await;
        let app = db.raw_app().await;
        for t in [
            "driver_archive",
            "package_driver",
            "agent_signer",
            "agent_package",
            "package_config",
            "device_value",
            "job_resume_nonce",
            "job_resume_token",
            "admin_password_escrow",
        ] {
            app.batch_execute(&format!("SELECT count(*) FROM {t}"))
                .await
                .unwrap();
        }
        for (sql, what) in [
            ("DELETE FROM admin_password_escrow", "delete escrow"),
            (
                "UPDATE admin_password_escrow SET ciphertext = ciphertext",
                "update escrow ciphertext",
            ),
            (
                "UPDATE admin_password_escrow SET key_id = key_id",
                "update escrow key id",
            ),
            ("TRUNCATE admin_password_escrow", "truncate escrow"),
            ("DELETE FROM job_resume_nonce", "delete nonce"),
            ("DELETE FROM job_resume_token", "delete token"),
            ("DELETE FROM driver_archive", "delete driver_archive"),
            ("DELETE FROM agent_signer", "delete agent_signer"),
            ("DELETE FROM agent_package", "delete agent_package"),
            ("DELETE FROM package_config", "delete package_config"),
            (
                "ALTER TABLE admin_password_escrow DISABLE TRIGGER USER",
                "disable escrow guard",
            ),
            (
                "DROP TRIGGER admin_password_escrow_guard ON admin_password_escrow",
                "drop escrow guard",
            ),
        ] {
            assert_sqlstate(
                app.batch_execute(sql).await,
                &SqlState::INSUFFICIENT_PRIVILEGE,
                what,
            );
        }
        db.finish().await;
    }

    /// The 0005 guards refuse direct changes, by the owner too.
    #[tokio::test]
    async fn m4_guards_refuse_direct_changes() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        let op = enrol(&db.admin, &a, "m4 guarded").await;
        let bs = m3::enrol_boot_service(&db.admin, &a, "m4 relay guards").await;
        let p = m3::ready_package(&db.app, &a, &op).await;
        let s = m3::ready_session(&db.app, &a, &op, bs.id, &p, m3::macs(1)).await;
        let job = m4::confirm_v2(&db.app, &a, &s, bs.id, &p).await;
        let s1 = m3::ready_session(&db.app, &a, &op, bs.id, &p, m3::macs(1)).await;
        let v1 = m3::confirm(&db.app, &a, &s1, bs.id, &p).await.unwrap();
        let signer = m4::register_signer(&db.app, &a, &op).await;

        let token = common::digest();
        let mut tx = db.app.begin().await.unwrap();
        tx.insert_escrow(&NewEscrow {
            job_id: job,
            account: EscrowAccount::Administrator,
            key_id: common::digest(),
            sealed: m4::sealed(40),
            received_at: common::now(),
        })
        .await
        .unwrap();
        tx.set_escrow_outcome(job, true, common::now())
            .await
            .unwrap();
        tx.record_escrow_reveal(job).await.unwrap();
        let t0 = common::now();
        tx.insert_resume_token(&NewResumeToken {
            token_hash: token,
            job_id: job,
            issued_at: t0,
            expires_at: m3::later(t0, 60),
        })
        .await
        .unwrap();
        tx.revoke_resume_tokens(job, t0).await.unwrap();
        tx.revoke_agent_signer(signer.id, op.id, t0).await.unwrap();
        common::append(&a, &mut tx, "escrow.applied", "job", &job.to_string()).await;
        tx.commit().await.unwrap();

        let uid = |b: &[u8; 16]| uuid::Uuid::from_bytes(*b);
        let (j, j1) = (uid(job.as_bytes()), uid(v1.as_bytes()));
        let sid = uid(signer.id.as_bytes());
        let th = token.0.to_vec();
        let owner = db.raw_owner().await;
        let refused: [(&str, &[&(dyn ToSql + Sync)], &str); 11] = [
            (
                "UPDATE admin_password_escrow SET ciphertext = decode(repeat('00', 40), 'hex') \
                 WHERE job_id = $1",
                &[&j],
                "replace the ciphertext",
            ),
            (
                "UPDATE admin_password_escrow SET state = 'received', applied_at_us = NULL \
                 WHERE job_id = $1",
                &[&j],
                "reopen an escrow outcome",
            ),
            (
                "UPDATE admin_password_escrow SET reveal_count = 0 WHERE job_id = $1",
                &[&j],
                "lower the reveal count",
            ),
            (
                "UPDATE job_resume_token SET revoked_at_us = NULL WHERE token_hash = $1",
                &[&th],
                "un-revoke a token",
            ),
            (
                "UPDATE agent_signer SET revoked_at_us = NULL, revoked_by = NULL WHERE id = $1",
                &[&sid],
                "un-revoke a signer",
            ),
            (
                "UPDATE agent_signer SET name = 'other' WHERE id = $1",
                &[&sid],
                "rename a signer",
            ),
            (
                "UPDATE job SET job_key_id = decode(repeat('33', 32), 'hex') WHERE id = $1",
                &[&j],
                "change the job key",
            ),
            (
                "UPDATE job SET tags = ARRAY['x'] WHERE id = $1",
                &[&j],
                "change the tags",
            ),
            (
                "UPDATE job SET plan_schema = 1 WHERE id = $1",
                &[&j],
                "change the plan schema",
            ),
            (
                "INSERT INTO job_step (job_id, step, state) VALUES ($1, 6, 'pending')",
                &[&j1],
                "a sixth step on a v1 job",
            ),
            (
                "INSERT INTO admin_password_escrow (job_id, account, key_id, eph_pub, nonce, \
                 ciphertext, received_at_us, state, applied_at_us) \
                 SELECT $1, 'administrator', key_id, eph_pub, nonce, ciphertext, 0, 'applied', 1 \
                 FROM admin_password_escrow LIMIT 1",
                &[&j1],
                "an escrow that starts applied",
            ),
        ];
        for (sql, params, what) in refused {
            let r = owner.execute(sql, params).await;
            assert!(r.is_err(), "{what}: {r:?}");
            let code = r.unwrap_err().code().cloned();
            assert!(
                code == Some(SqlState::INTEGRITY_CONSTRAINT_VIOLATION)
                    || code == Some(SqlState::FOREIGN_KEY_VIOLATION),
                "{what}: {code:?}"
            );
        }
        // A step 7 move on a v1 job is refused by the repository.
        let mut tx = db.app.begin().await.unwrap();
        assert!(
            tx.set_job_step_v2(v1, StepV2::WINDOWS_SETUP, StepState::Running, common::now())
                .await
                .is_err()
        );
        tx.rollback().await;
        // A v1 job cannot hold v2 columns (CHECK).
        assert_sqlstate(
            owner
                .execute(
                    "UPDATE job SET restart_pending = true WHERE id = $1",
                    &[&j1],
                )
                .await,
            &SqlState::CHECK_VIOLATION,
            "restart pending on a v1 job",
        );
        db.finish().await;
    }

    /// U-2: the operator role check takes `escrow_officer` (the Rust
    /// variant comes with WU-8); U-4: superseded content stays so.
    #[tokio::test]
    async fn m4_role_values_and_superseded_guard() {
        let db = TestDb::migrated().await;
        let a = init_audit(&db.app).await;
        let op = enrol(&db.admin, &a, "m4 roles").await;
        let owner = db.raw_owner().await;
        let id = uuid::Uuid::from_bytes(*op.id.as_bytes());
        owner
            .execute(
                "UPDATE operator SET role = 'escrow_officer' WHERE id = $1",
                &[&id],
            )
            .await
            .unwrap();
        assert_sqlstate(
            owner
                .execute("UPDATE operator SET role = 'bogus' WHERE id = $1", &[&id])
                .await,
            &SqlState::CHECK_VIOLATION,
            "unknown role",
        );
        let c = m4::ready_archive(
            &db.app,
            &a,
            op.id,
            usgp_proto::ContentKindV2::DriverArchive,
            &["a.inf"],
        )
        .await;
        let cid = uuid::Uuid::from_bytes(*c.id.as_bytes());
        owner
            .execute(
                "UPDATE content SET superseded_at_us = 1 WHERE id = $1",
                &[&cid],
            )
            .await
            .unwrap();
        assert_sqlstate(
            owner
                .execute(
                    "UPDATE content SET superseded_at_us = NULL WHERE id = $1",
                    &[&cid],
                )
                .await,
            &SqlState::INTEGRITY_CONSTRAINT_VIOLATION,
            "un-supersede",
        );
        db.finish().await;
    }
}
