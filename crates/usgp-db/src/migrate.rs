//! Embedded, ordered, checksummed migrations (decision 0008; plan 3.4).
//!
//! - Migrations are compiled in ([`MIGRATIONS`]), numbered from 1 with no
//!   gaps, each with a SHA-256 of its exact SQL text (through
//!   `usgp-crypto`).
//! - The runner takes a session advisory lock, creates `schema_migrations`
//!   if absent, refuses if any applied migration is unknown to this build
//!   or its checksum differs, and applies each pending migration in its
//!   own transaction together with its `schema_migrations` row.
//! - [`check_schema`] (server start) refuses unless the applied version is
//!   exactly [`SCHEMA_VERSION`] and every checksum matches.

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-3 (Configuration Change Control) - ordered, recorded
//   schema changes; an altered applied migration is refused.
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   checksums of applied migrations verified at every start.
// - Decision 0008

use tokio_postgres::Client;
use tokio_postgres::error::SqlState;
use usgp_common::Sha256Digest;

use crate::error::DbError;
use crate::repo::conv::bytes32;

/// One migration.
#[derive(Debug, Clone, Copy)]
pub struct Migration {
    /// Version, from 1, contiguous.
    pub version: u32,
    /// Short name.
    pub name: &'static str,
    /// SQL text (no transaction control).
    pub sql: &'static str,
}

impl Migration {
    /// SHA-256 of the SQL text.
    #[must_use]
    pub fn checksum(&self) -> Sha256Digest {
        usgp_crypto::sha256(self.sql.as_bytes())
    }
}

/// The migrations this build knows, in order.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "init",
        sql: include_str!("../migrations/0001_init.sql"),
    },
    Migration {
        version: 2,
        name: "roles_and_guards",
        sql: include_str!("../migrations/0002_roles_and_guards.sql"),
    },
    Migration {
        version: 3,
        name: "admin_role",
        sql: include_str!("../migrations/0003_admin_role.sql"),
    },
];

/// The schema version this build requires.
pub const SCHEMA_VERSION: u32 = 3;

/// Advisory-lock key serialising migration runs ("usgpmigr" as ASCII).
pub const MIGRATION_LOCK_KEY: i64 = 0x7573_6770_6d69_6772;

const CREATE_TABLE: &str = "CREATE TABLE IF NOT EXISTS schema_migrations (
    version     integer     PRIMARY KEY CHECK (version >= 1),
    name        text        NOT NULL,
    sha256      bytea       NOT NULL CHECK (length(sha256) = 32),
    applied_at  timestamptz NOT NULL DEFAULT now()
)";

/// Why the schema is refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MigrationError {
    /// No `schema_migrations` table: the database was never migrated.
    #[error("schema not initialised; run the migrate command")]
    SchemaMissing,
    /// An applied migration's SQL differs from this build's.
    #[error("applied migration {version} does not match this build (checksum)")]
    ChecksumMismatch {
        /// Version.
        version: u32,
    },
    /// An applied migration is unknown to this build (database newer).
    #[error("applied migration {version} is unknown to this build")]
    UnknownApplied {
        /// Version.
        version: u32,
    },
    /// Applied versions are not 1..=n.
    #[error("applied migrations are not contiguous at {version}")]
    NotContiguous {
        /// First unexpected version.
        version: u32,
    },
    /// The schema is older than this build requires.
    #[error("schema version {applied} is older than required {expected}; run the migrate command")]
    SchemaBehind {
        /// Applied version.
        applied: u32,
        /// Required version.
        expected: u32,
    },
    /// Applying a migration failed; it was rolled back.
    #[error("migration {version} failed and was rolled back")]
    Failed {
        /// Version.
        version: u32,
        /// The driver error.
        #[source]
        source: tokio_postgres::Error,
    },
}

/// Result of a migration run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrateReport {
    /// Versions applied by this run, in order.
    pub applied: Vec<u32>,
    /// Schema version afterwards.
    pub version: u32,
}

/// Checks the applied list against `known` and returns what is pending.
///
/// # Errors
///
/// [`MigrationError`] for a gap, an unknown version or a checksum
/// mismatch.
pub fn pending<'a>(
    applied: &[(u32, Sha256Digest)],
    known: &'a [Migration],
) -> Result<Vec<&'a Migration>, MigrationError> {
    let mut sorted = applied.to_vec();
    sorted.sort_by_key(|(v, _)| *v);
    let mut expect = 1u32;
    for (version, sum) in &sorted {
        if *version != expect {
            return Err(MigrationError::NotContiguous { version: *version });
        }
        let Some(m) = known.iter().find(|m| m.version == *version) else {
            return Err(MigrationError::UnknownApplied { version: *version });
        };
        if m.checksum() != *sum {
            return Err(MigrationError::ChecksumMismatch { version: *version });
        }
        expect = expect.saturating_add(1);
    }
    let last = sorted.last().map_or(0, |(v, _)| *v);
    Ok(known.iter().filter(|m| m.version > last).collect())
}

async fn read_applied(client: &Client) -> Result<Vec<(u32, Sha256Digest)>, DbError> {
    let rows = client
        .query(
            "SELECT version, sha256 FROM schema_migrations ORDER BY version",
            &[],
        )
        .await
        .map_err(|e| {
            if e.code() == Some(&SqlState::UNDEFINED_TABLE) {
                DbError::Migration(MigrationError::SchemaMissing)
            } else {
                DbError::from_pg("read schema_migrations", e)
            }
        })?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let v = crate::repo::conv::col_u32(r, "version")?;
        let sum: &[u8] = crate::repo::conv::col(r, "sha256")?;
        out.push((v, Sha256Digest(bytes32(sum, "sha256")?)));
    }
    Ok(out)
}

/// Verifies the schema version and checksums (server start; app role).
///
/// # Errors
///
/// [`DbError::Migration`].
pub async fn check_schema(client: &Client) -> Result<u32, DbError> {
    let applied = read_applied(client).await?;
    let todo = pending(&applied, MIGRATIONS)?;
    let version = applied.iter().map(|(v, _)| *v).max().unwrap_or(0);
    if !todo.is_empty() || version != SCHEMA_VERSION {
        return Err(MigrationError::SchemaBehind {
            applied: version,
            expected: SCHEMA_VERSION,
        }
        .into());
    }
    Ok(version)
}

/// Applies pending migrations (owner role). The caller passes a
/// connection it will close afterwards; on error the session (and its
/// advisory lock) should be dropped.
///
/// # Errors
///
/// [`DbError::Migration`] or a database error.
pub async fn run(client: &Client) -> Result<MigrateReport, DbError> {
    client
        .execute("SELECT pg_advisory_lock($1)", &[&MIGRATION_LOCK_KEY])
        .await
        .map_err(|e| DbError::from_pg("migration lock", e))?;
    client
        .batch_execute(CREATE_TABLE)
        .await
        .map_err(|e| DbError::from_pg("create schema_migrations", e))?;
    let applied = read_applied(client).await?;
    let todo = pending(&applied, MIGRATIONS)?;
    let mut done = Vec::with_capacity(todo.len());
    for m in todo {
        apply(client, m).await?;
        done.push(m.version);
    }
    client
        .execute("SELECT pg_advisory_unlock($1)", &[&MIGRATION_LOCK_KEY])
        .await
        .map_err(|e| DbError::from_pg("migration unlock", e))?;
    let version = check_schema(client).await?;
    Ok(MigrateReport {
        applied: done,
        version,
    })
}

async fn apply(client: &Client, m: &Migration) -> Result<(), DbError> {
    let fail = |source| {
        DbError::Migration(MigrationError::Failed {
            version: m.version,
            source,
        })
    };
    client.batch_execute("BEGIN").await.map_err(fail)?;
    let version = i32::try_from(m.version).map_err(|_| DbError::InvalidArgument {
        what: "migration version",
    })?;
    let sum = m.checksum();
    let result = async {
        client.batch_execute(m.sql).await?;
        client
            .execute(
                "INSERT INTO schema_migrations (version, name, sha256) VALUES ($1, $2, $3)",
                &[&version, &m.name, &sum.0.as_slice()],
            )
            .await?;
        client.batch_execute("COMMIT").await
    }
    .await;
    if let Err(e) = result {
        // Best effort; the caller drops the connection on error anyway.
        let _rolled_back = client.batch_execute("ROLLBACK").await;
        return Err(fail(e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use usgp_proto::{
        Architecture, ContentKind, ContentState, Edition, FactSource, PackageStatus, Release,
        SupportState, UploadState, WimCompression,
    };

    use super::*;
    use crate::model::{OperatorRole, OperatorStatus};

    fn mig(i: usize) -> &'static Migration {
        MIGRATIONS.get(i).unwrap()
    }

    fn applied(n: usize) -> Vec<(u32, Sha256Digest)> {
        MIGRATIONS
            .iter()
            .take(n)
            .map(|m| (m.version, m.checksum()))
            .collect()
    }

    #[test]
    fn versions_contiguous_and_current() {
        for (i, m) in MIGRATIONS.iter().enumerate() {
            assert_eq!(usize::try_from(m.version).unwrap(), i + 1);
        }
        assert_eq!(MIGRATIONS.last().unwrap().version, SCHEMA_VERSION);
    }

    #[test]
    fn fresh_database_applies_everything_in_order() {
        let p = pending(&[], MIGRATIONS).unwrap();
        let v: Vec<_> = p.iter().map(|m| m.version).collect();
        assert_eq!(v, [1, 2, 3]);
    }

    #[test]
    fn up_to_date_has_nothing_pending() {
        assert!(pending(&applied(3), MIGRATIONS).unwrap().is_empty());
        let p = pending(&applied(2), MIGRATIONS).unwrap();
        assert_eq!(p.len(), 1);
        let p = pending(&applied(1), MIGRATIONS).unwrap();
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn checksum_mismatch_refused() {
        let mut a = applied(2);
        a.get_mut(1).unwrap().1 = Sha256Digest([7; 32]);
        assert!(matches!(
            pending(&a, MIGRATIONS),
            Err(MigrationError::ChecksumMismatch { version: 2 })
        ));
    }

    #[test]
    fn unknown_and_gap_refused() {
        let mut a = applied(3);
        a.push((4, Sha256Digest([0; 32])));
        assert!(matches!(
            pending(&a, MIGRATIONS),
            Err(MigrationError::UnknownApplied { version: 4 })
        ));
        let a = vec![(2, mig(1).checksum())];
        assert!(matches!(
            pending(&a, MIGRATIONS),
            Err(MigrationError::NotContiguous { version: 2 })
        ));
    }

    #[test]
    fn no_transaction_control_in_migrations() {
        for m in MIGRATIONS {
            let upper = m.sql.to_ascii_uppercase();
            for word in ["BEGIN;", "COMMIT", "ROLLBACK", "START TRANSACTION"] {
                assert!(!upper.contains(word), "{} contains {word}", m.name);
            }
        }
    }

    /// WU-3b contract: roles are created outside; 0002 and 0003 never
    /// create or alter a role, only grant and revoke.
    fn assert_only_grants_and_revokes(m: &Migration) {
        let sql = m.sql.to_ascii_uppercase();
        for line in sql.lines() {
            let t = line.trim_start();
            if t.starts_with("--") || t.is_empty() {
                continue;
            }
            for word in [
                "CREATE ROLE",
                "ALTER ROLE",
                "CREATE USER",
                "PASSWORD",
                "DROP ",
            ] {
                assert!(!t.contains(word), "{} contains {word}", m.name);
            }
            assert!(
                [
                    "GRANT",
                    "REVOKE",
                    "DO $$",
                    "BEGIN",
                    "EXECUTE FORMAT",
                    "END;",
                    "$$;",
                    "USGP_AUDIT_HEAD_GUARD"
                ]
                .iter()
                .any(|p| t.starts_with(p)),
                "unexpected statement in {}: {t}",
                m.name
            );
        }
    }

    #[test]
    fn migration_0002_only_grants_and_revokes() {
        assert_only_grants_and_revokes(mig(1));
    }

    /// Decision 0016: 0003 only grants and revokes, takes operator writes
    /// from the application role and gives them to the admin role.
    #[test]
    fn migration_0003_moves_operator_writes_to_admin_role() {
        let m = mig(2);
        assert_only_grants_and_revokes(m);
        let sql = m.sql.to_ascii_uppercase();
        assert!(sql.contains("REVOKE INSERT, UPDATE, DELETE ON OPERATOR FROM USGP_APP;"));
        assert!(sql.contains("GRANT SELECT, INSERT, UPDATE ON OPERATOR TO USGP_ADMIN;"));
        // The admin role never gets content, package or upload rights.
        for table in ["CONTENT", "EDITION", "UPLOAD", "PACKAGE"] {
            assert!(
                !sql.lines().any(|l| l.trim_start().starts_with("GRANT")
                    && l.contains(&format!(" {table}"))
                    && l.contains("USGP_ADMIN")),
                "0003 grants {table} to usgp_admin"
            );
        }
        assert!(!sql.contains("ON OPERATOR TO USGP_APP"));
    }

    fn in_list<T: Copy>(col: &str, all: &[T], s: impl Fn(T) -> &'static str) -> String {
        let vals: Vec<String> = all.iter().map(|v| format!("'{}'", s(*v))).collect();
        format!("{col} IN ({})", vals.join(", "))
    }

    #[test]
    fn check_constraints_match_proto_value_sets() {
        let sql = mig(0).sql;
        let expect = [
            in_list("kind", ContentKind::ALL, ContentKind::as_str),
            in_list("state", ContentState::ALL, ContentState::as_str),
            in_list("compression", WimCompression::ALL, WimCompression::as_str),
            in_list("pe_arch", Architecture::ALL, Architecture::as_str),
            in_list("pe_arch_source", FactSource::ALL, FactSource::as_str),
            in_list("pe_kit_version_source", FactSource::ALL, FactSource::as_str),
            in_list("decl_release", Release::ALL, Release::as_str),
            in_list("decl_edition", Edition::ALL, Edition::as_str),
            in_list("decl_arch", Architecture::ALL, Architecture::as_str),
            in_list("release_source", FactSource::ALL, FactSource::as_str),
            in_list("edition_source", FactSource::ALL, FactSource::as_str),
            in_list("arch_source", FactSource::ALL, FactSource::as_str),
            in_list("support_status", SupportState::ALL, SupportState::as_str),
            in_list("state", UploadState::ALL, UploadState::as_str),
            in_list("status", PackageStatus::ALL, PackageStatus::as_str),
            in_list("role", OperatorRole::ALL, OperatorRole::as_str),
            in_list("status", OperatorStatus::ALL, OperatorStatus::as_str),
        ];
        for e in expect {
            assert!(sql.contains(&e), "0001 lacks `{e}`");
        }
    }

    #[test]
    fn checksum_is_sha256_of_text() {
        let m = *mig(0);
        assert_eq!(m.checksum(), usgp_crypto::sha256(m.sql.as_bytes()));
        assert_ne!(m.checksum(), mig(1).checksum());
    }
}
