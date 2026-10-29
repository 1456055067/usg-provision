//! usgp-db: PostgreSQL persistence for the control plane (plan M2, WU-3a).
//!
//! - [`config`]: connection settings and the certificate-only rule
//!   ([`config::assert_certificate_only`], decision 0012).
//! - [`tls`]: the tokio-postgres TLS hook over `usgp-crypto`
//!   ([`tls::PgTls`]); no plaintext, no channel binding (no password).
//! - [`pool`]: [`PgStore`] (pool, `ping`, `migrate`, `check_schema`) and
//!   [`PgTx`].
//! - [`migrate`]: embedded, ordered, checksummed migrations
//!   ([`migrate::SCHEMA_VERSION`]).
//! - [`repo`]: the [`Store`] / [`RepoTx`] interface. A transaction carries
//!   the state change and its audit record ([`usgp_audit::AuditTx`]) and
//!   cannot commit a change without one ([`DbError::Unaudited`]).
//! - [`memory`]: an in-memory implementation with the same rules and audit
//!   fault injection, for `usgp-api` tests. Not durable; not for
//!   production.
//! - [`model`]: row types.
//!
//! M3 (plan WU-7, migration 0004): boot services and their package
//! assignments, operator codes (stored only as HMAC), device sessions,
//! jobs and job steps, boot stops and boot-policy generations. A job
//! commits only with the `disk.wipe.authorised` audit record it names
//! (the wipe guard, REQ-DISK-006); used codes and finished jobs cannot be
//! changed back (triggers).
//!
//! The audit tables are append-only for the application role: privileges
//! (migration 0002) and triggers (migration 0001) refuse UPDATE, DELETE
//! and TRUNCATE; the hash chain in `usgp-audit` detects what a privileged
//! attacker changes anyway.

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-9 (Protection of Audit Information), AU-5, AU-12
// - NIST 800-53: SC-8, SC-8(1), SC-13 (TLS through usgp-crypto), IA-5(2)
// - NIST 800-53: AC-6 (application role), CM-3 (migrations), SI-10
// - SPEC: specs/operator-access.md#REQ-AUD-005, #REQ-AUD-006;
//   specs/os-images.md#REQ-IMG-020
// - SPEC: specs/disk.md#REQ-DISK-006; specs/targeting.md#REQ-TGT-013,
//   #REQ-TGT-014; specs/progress.md#REQ-JOB-012;
//   specs/boot-network.md#REQ-BOOT-067
// - Decisions 0008, 0012, 0013, 0015, 0016, 0018, 0020, 0021

// POAM: `postgres-protocol` links SCRAM-SHA-256/MD5 password code built on
// non-FIPS RustCrypto primitives. It is unreachable because no password is
// ever configured (decision 0012; `config::assert_certificate_only`).

// Rows and connection inputs are untrusted: no panicking indexing.
#![deny(clippy::indexing_slicing)]

pub mod config;
pub mod error;
pub mod memory;
pub mod migrate;
pub mod model;
pub mod pool;
pub mod repo;
pub mod tls;

pub use config::{DbSettings, assert_certificate_only};
pub use error::{ConnectFailure, DbError};
pub use memory::{MemoryStore, MemoryTx};
pub use migrate::{MigrateReport, MigrationError, SCHEMA_VERSION};
pub use model::{
    AuthCodeRecord, BootService, BootServicePackage, BootStop, ChosenPackage, Content,
    DeviceSession, Edition, EditionDeclaration, Job, JobStep, JobTimeouts, NewAuthCode,
    NewBootStop, NewContent, NewDeviceSession, NewEdition, NewJob, Operator, OperatorRole,
    OperatorStatus, Package, PackageRef, PeDeclaration, ReadyContent, Reason, SessionAuth,
    SessionScope, StoredManifest, Upload, WimFacts, source_network,
};
pub use pool::{PgStore, PgTx};
pub use repo::{RepoTx, Store};
pub use tls::PgTls;
