//! `boot-service enrol` and `boot-service disable`: local, audited
//! administrative commands (plan M3 sections 0 item 6,
//! 3.6 and 7; decisions 0016 and 0021).
//!
//! - **Enrol** binds one relay client certificate (by the SHA-256 of its
//!   DER) to a new boot-service record and the subnets it serves. Refused
//!   (and recorded) if the certificate lacks the TLS client purpose (it
//!   could never authenticate), is already bound to an operator (the API
//!   refuses a certificate bound to both, so the relay would be locked
//!   out and the operator too), or is already bound to a boot service;
//!   and if the name is in use.
//! - **Disable** sets the record to `disabled`: the relay's certificate
//!   then gets 401 and its devices are offered nothing.
//!
//! A boot stop is reversed only through the operator API
//! (`POST /v1/boot-stops/{id}/clear`, permission `device.boot_reenable`;
//! decision 0021 item 3), not by a local command.
//!
//! Each change and its record commit in one transaction (decision 0015
//! item 1); a refusal is recorded in a transaction of its own. The actor
//! is the local uid (claimed), interface `server-cli`. These commands log
//! in as the administrative role (`[database.admin]`, decision 0016),
//! which alone may write boot-service records (migration 0004).

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-3 (Device Identification and Authentication) - one
//   relay certificate, one boot service, by fingerprint; a certificate
//   bound to an operator is refused (no ambiguous identity).
// - NIST 800-53: IA-5(2) - a certificate without id-kp-clientAuth is
//   refused at enrolment (RFC 5280 §4.2.1.12).
// - NIST 800-53: AC-2, AC-6(1) - enrolment and disabling are local administrative actions through the administrative database
//   role only (decision 0016).
// - NIST 800-53: CM-5 - the certificate is read under the trusted-file
//   rules (caller).
// - NIST 800-53: AU-2, AU-3, AU-12; AU-5 - every change and refusal is
//   recorded; a change whose record cannot be written is not made.
// - SPEC: specs/targeting.md#REQ-TGT-001; decisions 0016, 0021 item 1

use std::time::UNIX_EPOCH;

use usgp_api::COMPONENT;
use usgp_audit::{AuditChain, AuditRecord, Detail, Outcome, mirror};
use usgp_crypto::PeerCertificate;
use usgp_db::{BootService, DbError, RepoTx, Store};
use usgp_proto::ops::{BootServiceStatus, IpCidr, SubnetList};
use usgp_proto::{BootServiceId, DisplayName, UnixMicros};

use crate::events::{self, LocalUser, RecordError};

/// A boot service was enrolled.
pub const BOOT_SERVICE_ENROLLED: &str = "boot_service.enrolled";
/// An enrolment was refused.
pub const BOOT_SERVICE_ENROL_REFUSED: &str = "boot_service.enrol.refused";
/// A boot service was disabled.
pub const BOOT_SERVICE_DISABLED: &str = "boot_service.disabled";
/// A disable was refused.
pub const BOOT_SERVICE_DISABLE_REFUSED: &str = "boot_service.disable.refused";

/// Why a boot-service command failed.
#[derive(Debug, thiserror::Error)]
pub enum BootServiceCmdError {
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

impl From<DbError> for BootServiceCmdError {
    fn from(e: DbError) -> Self {
        Self::Record(RecordError::Db(e))
    }
}

impl From<usgp_audit::AuditError> for BootServiceCmdError {
    fn from(e: usgp_audit::AuditError) -> Self {
        Self::Record(RecordError::Audit(e))
    }
}

/// An enrolment request.
#[derive(Debug, Clone)]
pub struct BootServiceEnrolment {
    /// The relay's client certificate.
    pub cert: PeerCertificate,
    /// Unique name.
    pub name: DisplayName,
    /// The subnets it serves (REQ-TGT-001).
    pub subnets: SubnetList,
}

/// Parses `--subnet` values into a subnet list: each a CIDR prefix with
/// no host bits set, 1 to 64, none repeated.
///
/// # Errors
///
/// A static reason naming the rule.
pub fn parse_subnets(texts: &[String]) -> Result<SubnetList, &'static str> {
    let mut v = Vec::with_capacity(texts.len());
    for t in texts {
        v.push(
            IpCidr::parse(t)
                .map_err(|_| "--subnet must be an address/prefix with no host bits set")?,
        );
    }
    SubnetList::new(v).map_err(|_| "--subnet: 1 to 64 subnets, each once")
}

fn micros(t: std::time::SystemTime) -> Result<UnixMicros, BootServiceCmdError> {
    let d = t
        .duration_since(UNIX_EPOCH)
        .map_err(|_| BootServiceCmdError::Invalid("certificate notAfter is before 1970"))?;
    let us = i64::try_from(d.as_micros())
        .map_err(|_| BootServiceCmdError::Invalid("certificate notAfter is out of range"))?;
    UnixMicros::new(us)
        .map_err(|_| BootServiceCmdError::Invalid("certificate notAfter is negative"))
}

fn now(chain: &AuditChain) -> Result<UnixMicros, BootServiceCmdError> {
    let us = chain.now_us()?;
    UnixMicros::new(us).map_err(|_| BootServiceCmdError::Invalid("clock before 1970"))
}

fn new_id() -> Result<BootServiceId, BootServiceCmdError> {
    let mut b = [0u8; 16];
    usgp_crypto::fill_random(&mut b)
        .map_err(|_| BootServiceCmdError::Invalid("the random bit generator failed"))?;
    Ok(BootServiceId::from_random_bytes(b))
}

fn subnets_text(s: &SubnetList) -> String {
    s.as_slice()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// Appends `draft` in `tx` and commits; mirrors the record (or the draft,
/// unpersisted, if it could not be written).
async fn append_commit<T: RepoTx>(
    chain: &AuditChain,
    mut tx: T,
    draft: &usgp_audit::AuditDraft,
) -> Result<AuditRecord, BootServiceCmdError> {
    let rec = match chain.append(&mut tx, draft).await {
        Ok(r) => r,
        Err(e) => {
            tx.rollback().await;
            mirror::emit_unpersisted(COMPONENT, chain, draft);
            return Err(e.into());
        }
    };
    if let Err(e) = tx.commit().await {
        mirror::emit_json(COMPONENT, &rec, false);
        return Err(e.into());
    }
    mirror::emit_json(COMPONENT, &rec, true);
    Ok(rec)
}

/// Records a refusal in its own transaction and returns it as the error.
async fn refuse<S: Store>(
    store: &S,
    chain: &AuditChain,
    draft: usgp_audit::AuditDraft,
    reason: &'static str,
) -> BootServiceCmdError {
    match events::record(store, chain, &draft.reason(reason)).await {
        Ok(_) => BootServiceCmdError::Refused(reason),
        Err(e) => BootServiceCmdError::Record(e),
    }
}

/// Enrols a boot service (decision 0021 item 1).
///
/// # Errors
///
/// [`BootServiceCmdError::Refused`] (recorded): `certificate_eku`,
/// `certificate_bound_to_operator`, `certificate_already_enrolled`,
/// `name_in_use`; or a database/audit failure (nothing changed).
pub async fn enrol<S: Store>(
    store: &S,
    chain: &AuditChain,
    who: &LocalUser,
    req: &BootServiceEnrolment,
) -> Result<BootService, BootServiceCmdError> {
    let b = BootService {
        id: new_id()?,
        name: req.name.clone(),
        cert_sha256: req.cert.sha256,
        cert_not_after: micros(req.cert.not_after)?,
        served_subnets: req.subnets.clone(),
        status: BootServiceStatus::Active,
        created_at: now(chain)?,
        created_by: who.label(),
    };
    let refused = || {
        who.draft(BOOT_SERVICE_ENROL_REFUSED, Outcome::Refused)
            .detail(
                Detail::new()
                    .with("name", req.name.as_str())
                    .with("cert_sha256", &req.cert.sha256)
                    .with("cert_subject", &req.cert.subject),
            )
    };
    // The relay authenticates with this certificate over mTLS: without
    // the client purpose it could never log in.
    if req.cert.require_client_auth_eku().is_err() {
        return Err(refuse(store, chain, refused(), "certificate_eku").await);
    }
    let mut tx = store.begin().await?;
    if let Some(op) = tx.operator_by_cert(&req.cert.sha256).await? {
        tx.rollback().await;
        let d = refused().target("operator", &op.id.to_string());
        return Err(refuse(store, chain, d, "certificate_bound_to_operator").await);
    }
    if let Some(existing) = tx.boot_service_by_cert(&req.cert.sha256).await? {
        tx.rollback().await;
        let d = refused().target("boot_service", &existing.id.to_string());
        return Err(refuse(store, chain, d, "certificate_already_enrolled").await);
    }
    if tx
        .list_boot_services()
        .await?
        .iter()
        .any(|s| s.name == req.name)
    {
        tx.rollback().await;
        return Err(refuse(store, chain, refused(), "name_in_use").await);
    }
    match tx.insert_boot_service(&b).await {
        Ok(()) => {}
        Err(e) if e.is_conflict() => {
            // Enrolled concurrently since the checks above.
            tx.rollback().await;
            return Err(refuse(store, chain, refused(), "certificate_already_enrolled").await);
        }
        Err(e) => return Err(e.into()),
    }
    let d = who
        .draft(BOOT_SERVICE_ENROLLED, Outcome::Success)
        .target("boot_service", &b.id.to_string())
        .detail(
            Detail::new()
                .with("name", b.name.as_str())
                .with("subnets", &subnets_text(&b.served_subnets))
                .with("cert_sha256", &b.cert_sha256)
                .with("cert_subject", &req.cert.subject)
                .with("cert_issuer", &req.cert.issuer)
                .with("cert_serial", &req.cert.serial)
                .with("cert_not_after_us", &b.cert_not_after.as_micros()),
        );
    append_commit(chain, tx, &d).await?;
    Ok(b)
}

/// What `disable` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disabled {
    /// The boot service was active and is now disabled.
    Changed,
    /// It was already disabled (recorded, nothing changed).
    AlreadyDisabled,
}

/// Disables a boot service.
///
/// # Errors
///
/// [`BootServiceCmdError::Refused`] (`boot_service_not_found`,
/// recorded), or a database/audit failure.
pub async fn disable<S: Store>(
    store: &S,
    chain: &AuditChain,
    who: &LocalUser,
    id: BootServiceId,
) -> Result<Disabled, BootServiceCmdError> {
    let mut tx = store.begin().await?;
    let Some(b) = tx.boot_service(id).await? else {
        tx.rollback().await;
        let d = who
            .draft(BOOT_SERVICE_DISABLE_REFUSED, Outcome::Refused)
            .target("boot_service", &id.to_string());
        return Err(refuse(store, chain, d, "boot_service_not_found").await);
    };
    let changed = b.status == BootServiceStatus::Active;
    if changed {
        tx.set_boot_service_status(id, BootServiceStatus::Disabled)
            .await?;
    }
    let d = who
        .draft(BOOT_SERVICE_DISABLED, Outcome::Success)
        .target("boot_service", &id.to_string())
        .detail(
            Detail::new()
                .with("name", b.name.as_str())
                .with("previous_status", b.status.as_str())
                .with("changed", &changed)
                .with("cert_sha256", &b.cert_sha256),
        );
    append_commit(chain, tx, &d).await?;
    Ok(if changed {
        Disabled::Changed
    } else {
        Disabled::AlreadyDisabled
    })
}
