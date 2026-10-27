//! `operator enrol` and `operator disable`: local, audited administrative
//! commands (plan M2 sections 1.1 and 7; decision 0007).
//!
//! One certificate binds to exactly one operator by the SHA-256 of its
//! DER; enrolling a certificate that is already bound is refused. Each
//! change and its `operator.enrolled` / `operator.disabled` record commit
//! in one transaction (decision 0015 item 1); a refusal is recorded in a
//! transaction of its own. The actor is the local uid (plan section 7:
//! "who = local uid, claimed").
//!
//! The certificate's path is not validated here; the TLS handshake
//! validates it on every connection (RFC 5280 path, CRLs). One rule is
//! checked at enrolment too, so a certificate that can never log in is
//! refused (recorded) instead of enrolled: it must carry an
//! extendedKeyUsage extension listing id-kp-clientAuth (finding SEC-006).
//!
//! These commands log in to PostgreSQL as the administrative role
//! (`[database.admin]`, decision 0016); the API's role cannot write
//! operator records.

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-2, IA-4 (Identifier Management) - one certificate,
//   one operator, by fingerprint; disabled operators get 401.
// - NIST 800-53: AC-2 (Account Management) - enrolment and disabling are
//   local administrative actions, audited; AC-6(1) - through the
//   administrative database role only (decision 0016).
// - NIST 800-53: IA-5(2) - a certificate without the TLS client purpose
//   is refused at enrolment (RFC 5280 §4.2.1.12).
// - NIST 800-53: AU-2, AU-3, AU-12; AU-5 (change refused if its record
//   cannot be written).
// - SPEC: specs/operator-access.md#REQ-RBAC-004, #REQ-RBAC-005,
//   #REQ-AUD-001; decisions 0007, 0010, 0015

use std::time::UNIX_EPOCH;

use usgp_api::COMPONENT;
use usgp_audit::{AuditChain, AuditRecord, Detail, Outcome, mirror};
use usgp_crypto::PeerCertificate;
use usgp_db::{DbError, Operator, OperatorRole, OperatorStatus, RepoTx, Store};
use usgp_proto::{DisplayName, OperatorId, UnixMicros};

use crate::events::{self, LocalUser, RecordError};

/// Why an operator command failed.
#[derive(Debug, thiserror::Error)]
pub enum OperatorCmdError {
    /// Refused (recorded), with a reason code.
    #[error("refused: {0}")]
    Refused(&'static str),
    /// The database or the audit chain failed; nothing changed.
    #[error(transparent)]
    Record(#[from] RecordError),
    /// A value could not be represented.
    #[error("{0}")]
    Invalid(&'static str),
}

impl From<DbError> for OperatorCmdError {
    fn from(e: DbError) -> Self {
        Self::Record(RecordError::Db(e))
    }
}

impl From<usgp_audit::AuditError> for OperatorCmdError {
    fn from(e: usgp_audit::AuditError) -> Self {
        Self::Record(RecordError::Audit(e))
    }
}

/// An enrolment request.
#[derive(Debug, Clone)]
pub struct Enrolment {
    /// The operator's certificate.
    pub cert: PeerCertificate,
    /// Display name.
    pub name: DisplayName,
    /// Role, or none (every route then answers 403).
    pub role: Option<OperatorRole>,
}

fn micros(t: std::time::SystemTime) -> Result<UnixMicros, OperatorCmdError> {
    let d = t
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OperatorCmdError::Invalid("certificate notAfter is before 1970"))?;
    let us = i64::try_from(d.as_micros())
        .map_err(|_| OperatorCmdError::Invalid("certificate notAfter is out of range"))?;
    UnixMicros::new(us).map_err(|_| OperatorCmdError::Invalid("certificate notAfter is negative"))
}

fn now(chain: &AuditChain) -> Result<UnixMicros, OperatorCmdError> {
    let us = chain.now_us()?;
    UnixMicros::new(us).map_err(|_| OperatorCmdError::Invalid("clock before 1970"))
}

fn new_id() -> Result<OperatorId, OperatorCmdError> {
    let mut b = [0u8; 16];
    usgp_crypto::fill_random(&mut b)
        .map_err(|_| OperatorCmdError::Invalid("the random bit generator failed"))?;
    Ok(OperatorId::from_random_bytes(b))
}

fn commit_mirror(recs: &[AuditRecord]) {
    for r in recs {
        mirror::emit_json(COMPONENT, r, true);
    }
}

/// Enrols an operator. Refused (and recorded) if the certificate is
/// already bound to an operator.
///
/// # Errors
///
/// [`OperatorCmdError`].
pub async fn enrol<S: Store>(
    store: &S,
    chain: &AuditChain,
    who: &LocalUser,
    req: &Enrolment,
) -> Result<Operator, OperatorCmdError> {
    let op = Operator {
        id: new_id()?,
        display_name: req.name.clone(),
        cert_sha256: req.cert.sha256,
        cert_subject: req.cert.subject.clone(),
        cert_issuer: req.cert.issuer.clone(),
        cert_serial: req.cert.serial.clone(),
        cert_not_after: micros(req.cert.not_after)?,
        role: req.role,
        status: OperatorStatus::Active,
        created_at: now(chain)?,
        created_by: who.label(),
    };
    let role_text = req.role.map_or("none", OperatorRole::as_str);
    if req.cert.require_client_auth_eku().is_err() {
        let d = who
            .draft(events::OPERATOR_ENROL_REFUSED, Outcome::Refused)
            .reason("certificate_eku")
            .detail(
                Detail::new()
                    .with("cert_sha256", &req.cert.sha256)
                    .with("cert_subject", &req.cert.subject),
            );
        events::record(store, chain, &d).await?;
        return Err(OperatorCmdError::Refused("certificate_eku"));
    }
    let mut tx = store.begin().await?;
    if let Some(existing) = tx.operator_by_cert(&req.cert.sha256).await? {
        tx.rollback().await;
        let d = who
            .draft(events::OPERATOR_ENROL_REFUSED, Outcome::Refused)
            .target("operator", &existing.id.to_string())
            .reason("certificate_already_enrolled")
            .detail(Detail::new().with("cert_sha256", &req.cert.sha256));
        events::record(store, chain, &d).await?;
        return Err(OperatorCmdError::Refused("certificate_already_enrolled"));
    }
    match tx.insert_operator(&op).await {
        Ok(()) => {}
        Err(e) if e.is_conflict() => {
            // Enrolled concurrently since the check above.
            tx.rollback().await;
            let d = who
                .draft(events::OPERATOR_ENROL_REFUSED, Outcome::Refused)
                .reason("certificate_already_enrolled")
                .detail(Detail::new().with("cert_sha256", &req.cert.sha256));
            events::record(store, chain, &d).await?;
            return Err(OperatorCmdError::Refused("certificate_already_enrolled"));
        }
        Err(e) => return Err(e.into()),
    }
    let d = who
        .draft(events::OPERATOR_ENROLLED, Outcome::Success)
        .target("operator", &op.id.to_string())
        .detail(
            Detail::new()
                .with("display_name", op.display_name.as_str())
                .with("role", role_text)
                .with("cert_sha256", &op.cert_sha256)
                .with("cert_subject", &op.cert_subject)
                .with("cert_issuer", &op.cert_issuer)
                .with("cert_serial", &op.cert_serial)
                .with("cert_not_after_us", &op.cert_not_after.as_micros()),
        );
    let rec = match chain.append(&mut tx, &d).await {
        Ok(r) => r,
        Err(e) => {
            mirror::emit_unpersisted(COMPONENT, chain, &d);
            return Err(e.into());
        }
    };
    if let Err(e) = tx.commit().await {
        mirror::emit_json(COMPONENT, &rec, false);
        return Err(e.into());
    }
    commit_mirror(&[rec]);
    Ok(op)
}

/// What `disable` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disabled {
    /// The operator was active and is now disabled.
    Changed,
    /// The operator was already disabled (recorded, nothing changed).
    AlreadyDisabled,
}

/// Disables an operator: its certificate then gets 401 on every request.
///
/// # Errors
///
/// [`OperatorCmdError::Refused`] (`operator_not_found`, recorded), or a
/// database/audit failure.
pub async fn disable<S: Store>(
    store: &S,
    chain: &AuditChain,
    who: &LocalUser,
    id: OperatorId,
) -> Result<Disabled, OperatorCmdError> {
    let mut tx = store.begin().await?;
    let Some(op) = tx.operator(id).await? else {
        tx.rollback().await;
        let d = who
            .draft(events::OPERATOR_DISABLE_REFUSED, Outcome::Refused)
            .target("operator", &id.to_string())
            .reason("operator_not_found");
        events::record(store, chain, &d).await?;
        return Err(OperatorCmdError::Refused("operator_not_found"));
    };
    let changed = op.status == OperatorStatus::Active;
    if changed {
        tx.set_operator_status(id, OperatorStatus::Disabled).await?;
    }
    let d = who
        .draft(events::OPERATOR_DISABLED, Outcome::Success)
        .target("operator", &id.to_string())
        .detail(
            Detail::new()
                .with("previous_status", op.status.as_str())
                .with("changed", &changed)
                .with("cert_sha256", &op.cert_sha256),
        );
    let rec = match chain.append(&mut tx, &d).await {
        Ok(r) => r,
        Err(e) => {
            mirror::emit_unpersisted(COMPONENT, chain, &d);
            return Err(e.into());
        }
    };
    if let Err(e) = tx.commit().await {
        mirror::emit_json(COMPONENT, &rec, false);
        return Err(e.into());
    }
    commit_mirror(&[rec]);
    Ok(if changed {
        Disabled::Changed
    } else {
        Disabled::AlreadyDisabled
    })
}
