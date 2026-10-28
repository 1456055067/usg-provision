//! usgp-server: the control plane (plan M2 WU-7).
//!
//! The binary (`main.rs`) checks FIPS mode first, parses the command line
//! ([`cli`]) and runs one command. The library is public so integration
//! tests can drive configuration loading ([`config`]), start-up
//! ([`serve::run`] on the in-memory store) and the local administrative
//! commands ([`operator`], [`audit_cmd`], [`boot_service_cmd`]) in-process.
//!
//! M3 (plan WU-10): `[device_api]`, `[codes]` and `[jobs]` map onto
//! `ApiConfig.device`; the plan, boot-policy and code HMAC keys are loaded
//! under the trusted-file rules and given to the API; the device listener
//! runs beside the operator listener when enabled; `keygen` writes the new
//! key types; `boot-service enrol|disable` are local administrative
//! commands under the `usgp_admin` role.
//!
//! Start-up order of `serve` (plan sections 3.4, 5.5; WU-3a notes):
//!
//! 1. FIPS self-check (`main`, before anything else);
//! 2. configuration: trusted file, `deny_unknown_fields`, every value
//!    range-checked ([`config::load`]);
//! 3. every referenced file read under the trusted-file rules, keys
//!    loaded, the TLS acceptor built ([`serve::prepare`]);
//! 4. database: [`usgp_db::assert_certificate_only`] (decision 0012),
//!    pool, `ping`, `check_schema` (must equal [`usgp_db::SCHEMA_VERSION`]);
//! 5. audit chain genesis ([`usgp_audit::AuditChain::ensure_genesis`]);
//! 6. API built, content root checked, restart recovery
//!    ([`usgp_api::Api::recover`]);
//! 7. listener bound (and the device listener, if enabled),
//!    `server.start` recorded, serving until SIGTERM or SIGINT, CRLs
//!    reloaded every `tls.crl_reload_s`, maintenance (session expiry,
//!    lost jobs, checkpoints) every minute;
//! 8. `server.stop` recorded and a final audit checkpoint signed.
//!
//! Any failure before serving refuses start-up and is recorded as
//! `server.start.refused` (persisted when the audit chain is reachable,
//! otherwise mirrored to stdout with `persisted=false`).

// Reads operator files and stored rows: indexing and slicing that can
// panic are denied (CLAUDE.md, Engineering Rules).
#![deny(clippy::indexing_slicing)]

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-13 - FIPS status is checked by main before anything
//   else (docs/decisions/0001).
// - NIST 800-53: CM-6 / CM-7 / CM-5 / SI-10 - strict configuration and
//   trusted files (config, material).
// - NIST 800-53: AU-2 / AU-3 / AU-12 - server lifecycle and every local
//   administrative command are audit events (events).
// - NIST 800-53: IA-5(2), SC-8 - certificate-only database login and TLS
//   (decision 0012).
// - SPEC: specs/operator-access.md#REQ-AUD-001, #REQ-AUD-005,
//   #REQ-AUD-007, #REQ-RBAC-005; specs/os-images.md#REQ-IMG-021
// - SPEC (M3): specs/targeting.md#REQ-TGT-012, #REQ-TGT-013;
//   specs/boot-network.md#REQ-BOOT-067
// - Decisions 0001, 0007, 0008, 0010, 0011, 0012, 0015, 0016, 0018, 0020,
//   0021

pub mod audit_cmd;
pub mod boot_service_cmd;
pub mod cli;
pub mod config;
pub mod events;
pub mod files;
pub mod keys;
pub mod material;
pub mod migrate_cmd;
pub mod operator;
pub mod serve;

/// Exit status: success.
pub const EXIT_OK: u8 = 0;
/// Exit status: FIPS inactive, database unreachable, bind or other runtime
/// failure; for `audit verify`, a broken chain (plan section 5.6).
pub const EXIT_FAILURE: u8 = 1;
/// Exit status: command-line usage error.
pub const EXIT_USAGE: u8 = 2;
/// Exit status (`audit verify` only): the chain could not be read, so it
/// was not verified (sysexits `EX_UNAVAILABLE`).
pub const EXIT_UNAVAILABLE: u8 = 69;
/// Exit status: a local administrative command was run by a user who is
/// neither root nor the `--admin-uid` (sysexits `EX_NOPERM`).
pub const EXIT_NOPERM: u8 = 77;
/// Exit status: configuration, trust or key error (sysexits `EX_CONFIG`),
/// as for the relay.
pub const EXIT_CONFIG: u8 = 78;
