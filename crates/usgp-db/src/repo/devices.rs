//! Device sessions (PostgreSQL).

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 (Access Enforcement) - compare-and-set transitions:
//   no package or disk choice before authorisation, no confirmation
//   without both (constraints and guard in migration 0004).
// - NIST 800-53: IA-5 - only the SHA-256 of the bearer token is stored.
// - NIST 800-53: AC-7 - failed code attempts counted per session.
// - NIST 800-53: SC-5 - session counts for the per-IP and global caps,
//   serialised by an advisory lock.
// - SPEC: specs/targeting.md#REQ-TGT-010, #REQ-TGT-013, #REQ-TGT-014,
//   #REQ-TGT-016
// - Decisions 0018 items 1, 7 and 10; 0020

use std::net::IpAddr;

use tokio_postgres::Row;
use usgp_common::Sha256Digest;
use usgp_proto::device::{DeviceArch, FirmwareKind, SecureBootState, SessionState};
use usgp_proto::ops::AuthMethod;
use usgp_proto::{
    AgentVersion, AuthCodeId, BootServiceId, DiskDescriptorV1, DisplayCode, ErrorCode, OperatorId,
    PackageId, SessionId, UnixMicros,
};

use super::content::cas_miss;
use super::conv::{
    col, col_digest, col_enum, col_id, col_macs, col_micros, col_opt_enum, col_opt_id,
    col_opt_json, col_opt_micros, col_text, col_u64, mac_params, texts, to_i64, to_json, to_uuid,
};
use crate::error::DbError;
use crate::model::{ChosenPackage, DeviceSession, NewDeviceSession, SessionAuth};
use crate::pool::PgTx;

const COLUMNS: &str = "id, token_sha256, boot_service_id, source_ip, macs, firmware, arch, \
     secure_boot, memory_bytes, agent_version, display_code, state, auth_method, auth_code_id, \
     approved_by, failed_code_attempts, chosen_package_id, chosen_package_revision, chosen_disk, \
     created_at_us, last_seen_at_us, expires_at_us, ended_at_us, end_reason";

/// Advisory-lock key serialising session-cap decisions ("usgpsess").
pub(crate) const SESSION_QUOTA_LOCK_KEY: i64 = 0x7573_6770_7365_7373;

/// The end reason recorded by [`expire`].
pub(crate) const EXPIRED_REASON: &str = "expired";

fn from_row(r: &Row) -> Result<DeviceSession, DbError> {
    let method = col_opt_enum(r, "auth_method", AuthMethod::parse)?;
    let code = col_opt_id(r, "auth_code_id", AuthCodeId::from_bytes)?;
    let approver = col_opt_id(r, "approved_by", OperatorId::from_bytes)?;
    let auth = match (method, code, approver) {
        (None, None, None) => None,
        (Some(AuthMethod::Code), Some(c), None) => Some(SessionAuth::Code(c)),
        (Some(AuthMethod::Approval), None, Some(o)) => Some(SessionAuth::Approval(o)),
        _ => {
            return Err(DbError::Corrupt {
                what: "auth_method",
            });
        }
    };
    let pkg = col_opt_id(r, "chosen_package_id", PackageId::from_bytes)?;
    let rev: Option<i64> = col(r, "chosen_package_revision")?;
    let chosen_package = match (pkg, rev) {
        (None, None) => None,
        (Some(id), Some(rev)) => Some(ChosenPackage {
            id,
            revision: u64::try_from(rev).map_err(|_| DbError::Corrupt {
                what: "chosen_package_revision",
            })?,
        }),
        _ => {
            return Err(DbError::Corrupt {
                what: "chosen_package",
            });
        }
    };
    let attempts: i16 = col(r, "failed_code_attempts")?;
    let reason: Option<String> = col(r, "end_reason")?;
    Ok(DeviceSession {
        id: col_id(r, "id", SessionId::from_bytes)?,
        token_sha256: col_digest(r, "token_sha256")?,
        boot_service_id: col_opt_id(r, "boot_service_id", BootServiceId::from_bytes)?,
        source_ip: col(r, "source_ip")?,
        macs: col_macs(r, "macs")?,
        firmware: col_enum(r, "firmware", FirmwareKind::parse)?,
        arch: col_enum(r, "arch", DeviceArch::parse)?,
        secure_boot: col_enum(r, "secure_boot", SecureBootState::parse)?,
        memory_bytes: col_u64(r, "memory_bytes")?,
        agent_version: col_text(r, "agent_version", AgentVersion::new)?,
        display_code: col_text(r, "display_code", |s: String| DisplayCode::parse(&s))?,
        state: col_enum(r, "state", SessionState::parse)?,
        auth,
        failed_code_attempts: u32::try_from(attempts).map_err(|_| DbError::Corrupt {
            what: "failed_code_attempts",
        })?,
        chosen_package,
        chosen_disk: col_opt_json(r, "chosen_disk")?,
        created_at: col_micros(r, "created_at_us")?,
        last_seen_at: col_micros(r, "last_seen_at_us")?,
        expires_at: col_micros(r, "expires_at_us")?,
        ended_at: col_opt_micros(r, "ended_at_us")?,
        end_reason: reason
            .map(|s| ErrorCode::new(s).map_err(|_| DbError::Corrupt { what: "end_reason" }))
            .transpose()?,
    })
}

pub(crate) async fn insert(tx: &mut PgTx, s: &NewDeviceSession) -> Result<(), DbError> {
    if s.expires_at < s.created_at {
        return Err(DbError::InvalidArgument {
            what: "session expiry before creation",
        });
    }
    tx.execute(
        "insert device_session",
        "INSERT INTO device_session (id, token_sha256, boot_service_id, source_ip, macs, \
         firmware, arch, secure_boot, memory_bytes, agent_version, display_code, state, \
         created_at_us, last_seen_at_us, expires_at_us) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13, $14)",
        &[
            &to_uuid(s.id.as_bytes()),
            &s.token_sha256.0.as_slice(),
            &s.boot_service_id.map(|b| to_uuid(b.as_bytes())),
            &s.source_ip,
            &mac_params(&s.macs),
            &s.firmware.as_str(),
            &s.arch.as_str(),
            &s.secure_boot.as_str(),
            &to_i64(s.memory_bytes, "memory_bytes")?,
            &s.agent_version.as_str(),
            &s.display_code.as_str(),
            &SessionState::AwaitingAuthorisation.as_str(),
            &s.created_at.as_micros(),
            &s.expires_at.as_micros(),
        ],
    )
    .await?;
    Ok(())
}

pub(crate) async fn get(
    tx: &mut PgTx,
    id: SessionId,
    lock: bool,
) -> Result<Option<DeviceSession>, DbError> {
    let sql = format!(
        "SELECT {COLUMNS} FROM device_session WHERE id = $1{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = tx
        .query_opt("read device_session", &sql, &[&to_uuid(id.as_bytes())])
        .await?;
    row.map(|r| from_row(&r)).transpose()
}

pub(crate) async fn by_token(
    tx: &mut PgTx,
    token_sha256: &Sha256Digest,
) -> Result<Option<DeviceSession>, DbError> {
    let sql = format!("SELECT {COLUMNS} FROM device_session WHERE token_sha256 = $1");
    let row = tx
        .query_opt("read device_session", &sql, &[&token_sha256.0.as_slice()])
        .await?;
    row.map(|r| from_row(&r)).transpose()
}

pub(crate) async fn list(
    tx: &mut PgTx,
    states: &[SessionState],
) -> Result<Vec<DeviceSession>, DbError> {
    let st = texts(states, SessionState::as_str);
    let sql = format!(
        "SELECT {COLUMNS} FROM device_session \
         WHERE (cardinality($1::text[]) = 0 OR state = ANY($1)) ORDER BY created_at_us, id"
    );
    let rows = tx.query("list device_session", &sql, &[&st]).await?;
    rows.iter().map(from_row).collect()
}

pub(crate) async fn lock_quota(tx: &mut PgTx) -> Result<(), DbError> {
    // A transaction-scoped advisory lock changes no row; a query, not an
    // `execute` (no audit required), as the upload quota lock.
    tx.query_opt(
        "lock device_session quota",
        "SELECT pg_advisory_xact_lock($1)",
        &[&SESSION_QUOTA_LOCK_KEY],
    )
    .await?;
    Ok(())
}

pub(crate) async fn count(
    tx: &mut PgTx,
    states: &[SessionState],
    source_ip: Option<IpAddr>,
) -> Result<u64, DbError> {
    let st = texts(states, SessionState::as_str);
    let row = tx
        .query_opt(
            "count device_session",
            "SELECT count(*) AS n FROM device_session \
             WHERE (cardinality($1::text[]) = 0 OR state = ANY($1)) \
             AND ($2::inet IS NULL OR source_ip = $2)",
            &[&st, &source_ip],
        )
        .await?;
    match row {
        Some(r) => col_u64(&r, "n"),
        None => Err(DbError::Corrupt { what: "count" }),
    }
}

pub(crate) async fn touch(tx: &mut PgTx, id: SessionId, at: UnixMicros) -> Result<(), DbError> {
    let n = tx
        .execute_bookkeeping(
            "touch device_session",
            "UPDATE device_session SET last_seen_at_us = GREATEST(last_seen_at_us, $2) \
             WHERE id = $1",
            &[&to_uuid(id.as_bytes()), &at.as_micros()],
        )
        .await?;
    if n == 0 {
        return Err(DbError::NotFound {
            what: "device session",
        });
    }
    Ok(())
}

pub(crate) async fn authorise(
    tx: &mut PgTx,
    id: SessionId,
    auth: SessionAuth,
    at: UnixMicros,
) -> Result<(), DbError> {
    let (code, approver) = match auth {
        SessionAuth::Code(c) => (Some(to_uuid(c.as_bytes())), None),
        SessionAuth::Approval(o) => (None, Some(to_uuid(o.as_bytes()))),
    };
    let uid = to_uuid(id.as_bytes());
    let n = tx
        .execute(
            "authorise device_session",
            "UPDATE device_session SET state = 'authorised', auth_method = $2, \
             auth_code_id = $3, approved_by = $4, \
             last_seen_at_us = GREATEST(last_seen_at_us, $5) \
             WHERE id = $1 AND state = 'awaiting_authorisation' AND expires_at_us > $5",
            &[
                &uid,
                &auth.method().as_str(),
                &code,
                &approver,
                &at.as_micros(),
            ],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "device session", &uid).await);
    }
    Ok(())
}

pub(crate) async fn failed_code_attempt(tx: &mut PgTx, id: SessionId) -> Result<u32, DbError> {
    let uid = to_uuid(id.as_bytes());
    let rows = tx
        .query_write(
            "update device_session attempts",
            "UPDATE device_session SET failed_code_attempts = failed_code_attempts + 1 \
             WHERE id = $1 AND state = 'awaiting_authorisation' RETURNING failed_code_attempts",
            &[&uid],
        )
        .await?;
    match rows.first() {
        Some(r) => {
            let n: i16 = col(r, "failed_code_attempts")?;
            u32::try_from(n).map_err(|_| DbError::Corrupt {
                what: "failed_code_attempts",
            })
        }
        None => Err(cas_miss(tx, "device session", &uid).await),
    }
}

pub(crate) async fn choose_package(
    tx: &mut PgTx,
    id: SessionId,
    p: ChosenPackage,
) -> Result<(), DbError> {
    let uid = to_uuid(id.as_bytes());
    let n = tx
        .execute(
            "update device_session package",
            "UPDATE device_session SET chosen_package_id = $2, chosen_package_revision = $3, \
             chosen_disk = NULL WHERE id = $1 AND state = 'authorised'",
            &[
                &uid,
                &to_uuid(p.id.as_bytes()),
                &to_i64(p.revision, "package revision")?,
            ],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "device session", &uid).await);
    }
    Ok(())
}

pub(crate) async fn choose_disk(
    tx: &mut PgTx,
    id: SessionId,
    disk: &DiskDescriptorV1,
) -> Result<(), DbError> {
    let uid = to_uuid(id.as_bytes());
    let json = to_json(disk, "disk descriptor")?;
    let n = tx
        .execute(
            "update device_session disk",
            "UPDATE device_session SET chosen_disk = $2 \
             WHERE id = $1 AND state = 'authorised' AND chosen_package_id IS NOT NULL",
            &[&uid, &json],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "device session", &uid).await);
    }
    Ok(())
}

/// Session states that never change again (`SessionState::is_final`;
/// the 0004 guard lists the same set, checked by a unit test).
pub(crate) const FINAL_STATES: &[SessionState] = &[
    SessionState::Confirmed,
    SessionState::Refused,
    SessionState::Cancelled,
    SessionState::Expired,
    SessionState::Ended,
];

/// Checks a target state for [`set_state`].
pub(crate) fn check_target(to: SessionState) -> Result<(), DbError> {
    match to {
        SessionState::AwaitingAuthorisation | SessionState::Authorised => {
            Err(DbError::InvalidArgument {
                what: "use authorise_device_session",
            })
        }
        _ => Ok(()),
    }
}

pub(crate) async fn set_state(
    tx: &mut PgTx,
    id: SessionId,
    from: &[SessionState],
    to: SessionState,
    reason: Option<&ErrorCode>,
    at: UnixMicros,
) -> Result<(), DbError> {
    check_target(to)?;
    let uid = to_uuid(id.as_bytes());
    let st = texts(from, SessionState::as_str);
    let finals = texts(FINAL_STATES, SessionState::as_str);
    let ended = (to != SessionState::Confirmed).then(|| at.as_micros());
    let n = tx
        .execute(
            "update device_session state",
            "UPDATE device_session SET state = $2, ended_at_us = $3, end_reason = $4 \
             WHERE id = $1 AND state = ANY($5) AND NOT (state = ANY($6)) \
             AND ($2 <> 'confirmed' OR chosen_disk IS NOT NULL)",
            &[
                &uid,
                &to.as_str(),
                &ended,
                &reason.map(ErrorCode::as_str),
                &st,
                &finals,
            ],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "device session", &uid).await);
    }
    Ok(())
}

pub(crate) async fn expire(tx: &mut PgTx, at: UnixMicros) -> Result<Vec<SessionId>, DbError> {
    let rows = tx
        .query_write(
            "expire device_session",
            "UPDATE device_session SET state = 'expired', ended_at_us = $1, end_reason = $2 \
             WHERE state IN ('awaiting_authorisation', 'authorised') AND expires_at_us <= $1 \
             RETURNING id",
            &[&at.as_micros(), &EXPIRED_REASON],
        )
        .await?;
    let mut ids = rows
        .iter()
        .map(|r| col_id(r, "id", SessionId::from_bytes))
        .collect::<Result<Vec<_>, _>>()?;
    ids.sort();
    Ok(ids)
}
