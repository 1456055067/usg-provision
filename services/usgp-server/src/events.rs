//! Audit events of the server process and its local commands (plan M2
//! section 7), and the helper that writes one in its own transaction.
//!
//! Records go to the tamper-evident chain in the database and are then
//! mirrored to stdout (`usgp_audit::mirror`). If a record cannot be
//! stored, it is mirrored with `persisted=false` so it is not lost.

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-2, AU-3, AU-12 - lifecycle and local administrative
//   actions recorded with who (local uid or system), what, when, where
//   (node, interface `server-cli` or `system`), source and outcome.
// - NIST 800-53: AU-5 - a record that cannot be stored is mirrored as
//   unpersisted; state changes are refused (callers).
// - NIST 800-53: AC-6(1) (Authorize Access to Security Functions) - the
//   control on local administrative commands is possession of the
//   `usgp_admin` database client key, which deployment makes readable by
//   root only and which the commands refuse unless it is mode 0600/0400
//   (`files::KeyAccess::OwnerOnly`; decision 0016 item 3, finding
//   SEC-011). The uid check in [`local_admin`] is a guard against
//   mistakes only, not the access control: any local user can pass it
//   with a configuration file of their own (finding NIST-015).
// - SPEC: specs/operator-access.md#REQ-AUD-001; decisions 0010, 0015

use usgp_api::COMPONENT;
use usgp_audit::{Actor, AuditChain, AuditDraft, AuditError, AuditRecord, Interface, mirror};
use usgp_crypto::KeyId;
use usgp_db::{DbError, RepoTx, Store};

/// The server started serving.
pub const SERVER_START: &str = "server.start";
/// The server refused to start.
pub const SERVER_START_REFUSED: &str = "server.start.refused";
/// The server stopped.
pub const SERVER_STOP: &str = "server.stop";
/// The TLS acceptor was rebuilt with new CRLs (or the attempt failed).
pub const CRL_RELOADED: &str = "auth.tls.crl_reloaded";
/// An operator was enrolled.
pub const OPERATOR_ENROLLED: &str = "operator.enrolled";
/// An enrolment was refused.
pub const OPERATOR_ENROL_REFUSED: &str = "operator.enrol.refused";
/// An operator was disabled.
pub const OPERATOR_DISABLED: &str = "operator.disabled";
/// A disable was refused.
pub const OPERATOR_DISABLE_REFUSED: &str = "operator.disable.refused";
/// The audit chain was verified (result in the outcome and detail).
pub const AUDIT_VERIFY: &str = "audit.verify";
/// Database migrations ran.
pub const DB_MIGRATE: &str = "server.migrate";

/// Why a record could not be written.
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// The database refused or failed.
    #[error(transparent)]
    Db(#[from] DbError),
    /// The chain refused the record.
    #[error(transparent)]
    Audit(#[from] AuditError),
}

/// The local user running a server command: "who" for the
/// `server-cli` interface (plan section 7: the local uid, as claimed by
/// the operating system).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalUser {
    /// Effective uid.
    pub uid: u32,
}

impl LocalUser {
    /// The actor.
    #[must_use]
    pub fn actor(&self) -> Actor {
        Actor::local_user(self.uid, None)
    }

    /// The source text (`uid:<n>`).
    #[must_use]
    pub fn source(&self) -> String {
        format!("uid:{}", self.uid)
    }

    /// A `server-cli` draft for this user.
    #[must_use]
    pub fn draft(&self, event: &str, outcome: usgp_audit::Outcome) -> AuditDraft {
        AuditDraft::new(event, outcome, self.actor(), Interface::ServerCli).source(&self.source())
    }

    /// The text stored in `operator.created_by`.
    #[must_use]
    pub fn label(&self) -> String {
        self.source()
    }
}

/// Guard (not the access control) for local administrative commands
/// (decision 0016 item 3): root, or the owner of the configuration file
/// (`config_owner`, read by the caller from the file that was loaded),
/// provided that owner is also trusted by `policy` (root or
/// `--admin-uid`). A `--admin-uid` alone is not enough: it must name the
/// uid that actually owns the configuration. `euid` is the effective uid
/// as read by the caller.
///
/// The configuration path comes from the command line, so a local user
/// can pass this check with a configuration file of their own; it only
/// stops mistakes (for example running as the service account). The
/// access control is the administrative database role's client key
/// (`[database.admin]`), readable only by its owner (root), without
/// which the command cannot log in (AC-6(1); finding NIST-015).
///
/// # Errors
///
/// A short reason: `not_local_admin` or `uid_unknown`.
pub fn local_admin(
    policy: &usgp_common::config::TrustPolicy,
    config_owner: Option<u32>,
    euid: std::io::Result<u32>,
) -> Result<LocalUser, &'static str> {
    match euid {
        Ok(0) => Ok(LocalUser { uid: 0 }),
        Ok(uid) if config_owner == Some(uid) && policy.is_trusted_owner(uid) => {
            Ok(LocalUser { uid })
        }
        Ok(_) => Err("not_local_admin"),
        Err(_) => Err("uid_unknown"),
    }
}

/// The owner uid of `path` (the configuration file), if it can be read.
#[must_use]
pub fn file_owner(path: &std::path::Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path).ok().map(|m| m.uid())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// A `system` draft (server-initiated).
#[must_use]
pub fn system_draft(event: &str, outcome: usgp_audit::Outcome) -> AuditDraft {
    AuditDraft::new(event, outcome, Actor::system(), Interface::System)
}

/// Writes `draft` in a transaction of its own, then mirrors it. On
/// failure the draft is mirrored as unpersisted.
///
/// # Errors
///
/// [`RecordError`].
pub async fn record<S: Store>(
    store: &S,
    chain: &AuditChain,
    draft: &AuditDraft,
) -> Result<AuditRecord, RecordError> {
    let result = async {
        let mut tx = store.begin().await?;
        let rec = chain.append(&mut tx, draft).await?;
        tx.commit().await?;
        Ok::<_, RecordError>(rec)
    }
    .await;
    match result {
        Ok(rec) => {
            mirror::emit_json(COMPONENT, &rec, true);
            Ok(rec)
        }
        Err(e) => {
            mirror::emit_unpersisted(COMPONENT, chain, draft);
            Err(e)
        }
    }
}

/// Writes the genesis record if the chain is empty (its own transaction).
///
/// # Errors
///
/// [`RecordError`].
pub async fn ensure_genesis<S: Store>(
    store: &S,
    chain: &AuditChain,
    audit_key_id: &KeyId,
) -> Result<(), RecordError> {
    let mut tx = store.begin().await?;
    let rec = chain.ensure_genesis(&mut tx, audit_key_id).await?;
    tx.commit().await?;
    if let Some(r) = rec {
        mirror::emit_json(COMPONENT, &r, true);
    }
    Ok(())
}

/// Mirrors `draft` as unpersisted (no database reachable). `node` is the
/// AU-3 "where"; `unknown-node` if none is known.
pub fn unpersisted(node: Option<&str>, draft: &AuditDraft) {
    let node = node.filter(|n| !n.is_empty()).unwrap_or("unknown-node");
    if let Ok(chain) = AuditChain::new(node) {
        mirror::emit_unpersisted(COMPONENT, &chain, draft);
    }
}
