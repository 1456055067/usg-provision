//! Migrations and connection rules against PostgreSQL (feature
//! `pg-integration`; CI job `pg-integration`). Without the
//! `USGP_TEST_PG_*` environment every test fails (never skips).
//!
//! - migrations apply in order, are idempotent, and the app role sees the
//!   current schema;
//! - an unmigrated, altered or newer schema is refused;
//! - certificate-only login: a server asking for a password is refused
//!   (`auth_method_refused`, decision 0012); a wrong certificate for the
//!   role is refused; an untrusted server is refused;
//! - the session is TLS, as the explicitly configured user.

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-3, SI-7 (migration checksums), IA-5(2), SC-8, SC-8(1)
// - Decisions 0008, 0012

#![cfg(feature = "pg-integration")]

#[cfg(test)]
pub mod common;

// Helpers and tests in one `cfg(test)` module so the workspace's
// test-only clippy allowances apply (same convention as usgp-audit).
#[cfg(test)]
mod t {
    use super::common;

    use common::pg::{TestDb, env, raw};
    use usgp_crypto::test_pki::TestPki;
    use usgp_crypto::tls::TlsFailureClass;
    use usgp_db::{ConnectFailure, DbError, MigrationError, PgStore, SCHEMA_VERSION};

    #[tokio::test]
    async fn migrations_apply_in_order_and_are_idempotent() {
        let db = TestDb::create().await;
        let r = db.owner.migrate().await.unwrap();
        assert_eq!(r.applied, vec![1, 2, 3]);
        assert_eq!(r.version, SCHEMA_VERSION);
        let again = db.owner.migrate().await.unwrap();
        assert!(again.applied.is_empty());
        assert_eq!(again.version, SCHEMA_VERSION);
        // The application role can check the schema (plan 3.4: serve refuses
        // otherwise).
        assert_eq!(db.app.check_schema().await.unwrap(), SCHEMA_VERSION);
        // So can the administrative role (decision 0016).
        assert_eq!(db.admin.check_schema().await.unwrap(), SCHEMA_VERSION);
        db.finish().await;
    }

    #[tokio::test]
    async fn unmigrated_database_refused() {
        let db = TestDb::create().await;
        let err = db.app.check_schema().await.unwrap_err();
        assert!(
            matches!(err, DbError::Migration(MigrationError::SchemaMissing)),
            "{err:?}"
        );
        db.finish().await;
    }

    #[tokio::test]
    async fn altered_applied_migration_refused() {
        let db = TestDb::migrated().await;
        let owner = db.raw_owner().await;
        owner
        .batch_execute(
            "UPDATE schema_migrations SET sha256 = decode(repeat('ab', 32), 'hex') WHERE version = 1",
        )
        .await
        .unwrap();
        for err in [
            db.owner.migrate().await.unwrap_err(),
            db.app.check_schema().await.unwrap_err(),
        ] {
            assert!(
                matches!(
                    err,
                    DbError::Migration(MigrationError::ChecksumMismatch { version: 1 })
                ),
                "{err:?}"
            );
        }
        db.finish().await;
    }

    #[tokio::test]
    async fn newer_schema_refused() {
        let db = TestDb::migrated().await;
        let owner = db.raw_owner().await;
        // One past the newest migration this build knows.
        let future = SCHEMA_VERSION + 1;
        owner
            .batch_execute(&format!(
                "INSERT INTO schema_migrations (version, name, sha256) \
             VALUES ({future}, 'future', decode(repeat('00', 32), 'hex'))"
            ))
            .await
            .unwrap();
        let err = db.app.check_schema().await.unwrap_err();
        assert!(
            matches!(
                err,
                DbError::Migration(MigrationError::UnknownApplied { version })
                    if version == future
            ),
            "{err:?}"
        );
        db.finish().await;
    }

    /// Decision 0012 / plan 5.5: pg_hba asks this role for SCRAM; no password
    /// exists, so the driver refuses before computing anything.
    #[tokio::test]
    async fn password_auth_requested_is_refused() {
        let env = env();
        let s = env.settings_as(&env.pwprobe_user, &env.app, &env.admin_db);
        let store = PgStore::connect(&s).unwrap();
        let err = store.ping().await.unwrap_err();
        assert!(
            matches!(
                err,
                DbError::Connect {
                    class: ConnectFailure::AuthMethodRefused,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn certificate_of_another_role_refused() {
        let env = env();
        let s = env.settings_as(&env.app.user, &env.owner, &env.admin_db);
        let store = PgStore::connect(&s).unwrap();
        let err = store.ping().await.unwrap_err();
        assert!(
            matches!(
                err,
                DbError::Connect {
                    class: ConnectFailure::Rejected,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn untrusted_server_refused() {
        let env = env();
        let mut s = env.app(&env.admin_db);
        s.server_ca_pem = TestPki::generate()
            .unwrap()
            .root
            .cert_pem()
            .unwrap()
            .into_bytes();
        let store = PgStore::connect(&s).unwrap();
        let err = store.ping().await.unwrap_err();
        assert!(
            matches!(
                err,
                DbError::Connect {
                    class: ConnectFailure::Tls(TlsFailureClass::Untrusted),
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn wrong_server_name_refused() {
        let env = env();
        let mut s = env.app(&env.admin_db);
        s.server_name = Some("db.invalid.example".into());
        let store = PgStore::connect(&s).unwrap();
        let err = store.ping().await.unwrap_err();
        assert!(
            matches!(
                err,
                DbError::Connect {
                    class: ConnectFailure::Tls(TlsFailureClass::BadCertificate),
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn session_is_tls_as_the_configured_user() {
        let env = env();
        let c = raw(&env.app(&env.admin_db)).await;
        let row = c
        .query_one(
            "SELECT current_user::text AS u, s.ssl, s.version, current_setting('search_path') AS sp \
             FROM pg_stat_ssl s WHERE s.pid = pg_backend_pid()",
            &[],
        )
        .await
        .unwrap();
        let user: String = row.get("u");
        let ssl: bool = row.get("ssl");
        let version: Option<String> = row.get("version");
        let sp: String = row.get("sp");
        assert_eq!(user, env.app.user);
        assert!(ssl);
        assert!(
            matches!(version.as_deref(), Some("TLSv1.2" | "TLSv1.3")),
            "{version:?}"
        );
        assert_eq!(sp, "public");
    }
}
