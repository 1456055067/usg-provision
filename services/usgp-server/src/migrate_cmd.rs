//! `migrate`: applies the embedded database migrations as the owner role
//! (plan M2 section 3.4; WU-3a: the migration runner takes an advisory
//! lock, runs each pending migration in its own transaction and refuses a
//! changed checksum).
//!
//! The owner role's certificate and key are given on the command line,
//! never in `server.toml`, so the running service never holds owner
//! credentials (AC-6). They are read under the trusted-file rules and the
//! connection is certificate-only (decision 0012).
//!
//! The run is recorded as `server.migrate`. Before the first `serve` the
//! chain has no genesis record and cannot take records yet; the record is
//! then mirrored to stdout as unpersisted.

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-3 (Configuration Change Control) - ordered, checksummed
//   migrations, recorded.
// - NIST 800-53: AC-6 (Least Privilege) - owner credentials only for this
//   command; the service uses the application role.
// - NIST 800-53: IA-5(2) - certificate-only login (decision 0012).
// - SPEC: plan section 3.4; decisions 0008, 0012

use usgp_audit::{AuditChain, Detail, Outcome};
use usgp_db::{DbError, MigrateReport, PgStore};

use crate::events::{self, LocalUser};

/// Applies pending migrations and records the run.
///
/// # Errors
///
/// [`DbError`]; the failure is recorded (best effort) too.
pub async fn migrate(
    store: &PgStore,
    chain: &AuditChain,
    who: &LocalUser,
) -> Result<MigrateReport, DbError> {
    let result = store.migrate().await;
    let draft = match &result {
        Ok(r) => {
            let applied = r
                .applied
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            who.draft(events::DB_MIGRATE, Outcome::Success).detail(
                Detail::new()
                    .with("applied", &applied)
                    .with("schema_version", &r.version),
            )
        }
        Err(e) => who
            .draft(events::DB_MIGRATE, Outcome::Failure)
            .reason("migration_failed")
            .detail(Detail::new().with("error", &e.to_string())),
    };
    let _ = events::record(store, chain, &draft).await;
    result
}
