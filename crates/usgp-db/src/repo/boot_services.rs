//! Boot services, their package assignments, boot stops and boot-policy
//! generations (PostgreSQL).

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-6 (Least Privilege) - boot services are written only
//   by the administrative role (migration 0004); the application role
//   reads them and replaces assignments.
// - NIST 800-53: CM-7 - a stopped device is no longer offered a boot
//   program; a stop is reversed only by an audited clear.
// - NIST 800-53: SI-10 - served subnets re-validated as CIDR on read.
// - SPEC: specs/targeting.md#REQ-TGT-001; specs/boot-network.md#REQ-BOOT-067
// - Decision 0021 items 1 to 3

use tokio_postgres::Row;
use usgp_common::Sha256Digest;
use usgp_proto::limits::MAX_BOOT_SERVICE_PACKAGES;
use usgp_proto::ops::{BootServiceStatus, IpCidr, SubnetList};
use usgp_proto::{
    BootServiceId, BootStopId, DisplayName, JobId, MacList, OperatorId, PackageId, UnixMicros,
};

use super::content::cas_miss;
use super::conv::{
    check_text, col, col_digest, col_enum, col_id, col_mac, col_micros, col_opt_id, col_opt_micros,
    col_text, col_u64, mac_params, to_i64, to_uuid,
};
use crate::error::DbError;
use crate::model::{BootService, BootServicePackage, BootStop, NewBootStop};
use crate::pool::PgTx;

const SERVICE_COLUMNS: &str =
    "id, name, cert_sha256, cert_not_after_us, served_subnets, status, created_at_us, created_by";

const STOP_COLUMNS: &str =
    "id, boot_service_id, mac, job_id, created_at_us, cleared_at_us, cleared_by";

/// First key of the two-key advisory locks on a boot service's
/// assignments ("usgp" as ASCII).
const ASSIGNMENT_LOCK_SPACE: i32 = 0x7573_6770;

fn service_from_row(r: &Row) -> Result<BootService, DbError> {
    let subnets: Vec<String> = col(r, "served_subnets")?;
    let subnets = subnets
        .iter()
        .map(|s| IpCidr::parse(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| DbError::Corrupt {
            what: "served_subnets",
        })?;
    Ok(BootService {
        id: col_id(r, "id", BootServiceId::from_bytes)?,
        name: col_text(r, "name", DisplayName::new)?,
        cert_sha256: col_digest(r, "cert_sha256")?,
        cert_not_after: col_micros(r, "cert_not_after_us")?,
        served_subnets: SubnetList::new(subnets).map_err(|_| DbError::Corrupt {
            what: "served_subnets",
        })?,
        status: col_enum(r, "status", BootServiceStatus::parse)?,
        created_at: col_micros(r, "created_at_us")?,
        created_by: col(r, "created_by")?,
    })
}

fn stop_from_row(r: &Row) -> Result<BootStop, DbError> {
    Ok(BootStop {
        id: col_id(r, "id", BootStopId::from_bytes)?,
        boot_service_id: col_id(r, "boot_service_id", BootServiceId::from_bytes)?,
        mac: col_mac(r, "mac")?,
        job_id: col_id(r, "job_id", JobId::from_bytes)?,
        created_at: col_micros(r, "created_at_us")?,
        cleared_at: col_opt_micros(r, "cleared_at_us")?,
        cleared_by: col_opt_id(r, "cleared_by", OperatorId::from_bytes)?,
    })
}

pub(crate) async fn get(tx: &mut PgTx, id: BootServiceId) -> Result<Option<BootService>, DbError> {
    let sql = format!("SELECT {SERVICE_COLUMNS} FROM boot_service WHERE id = $1");
    let row = tx
        .query_opt("read boot_service", &sql, &[&to_uuid(id.as_bytes())])
        .await?;
    row.map(|r| service_from_row(&r)).transpose()
}

pub(crate) async fn by_cert(
    tx: &mut PgTx,
    sha: &Sha256Digest,
) -> Result<Option<BootService>, DbError> {
    let sql = format!("SELECT {SERVICE_COLUMNS} FROM boot_service WHERE cert_sha256 = $1");
    let row = tx
        .query_opt("read boot_service", &sql, &[&sha.0.as_slice()])
        .await?;
    row.map(|r| service_from_row(&r)).transpose()
}

pub(crate) async fn list(tx: &mut PgTx) -> Result<Vec<BootService>, DbError> {
    let sql = format!("SELECT {SERVICE_COLUMNS} FROM boot_service ORDER BY created_at_us, id");
    let rows = tx.query("list boot_service", &sql, &[]).await?;
    rows.iter().map(service_from_row).collect()
}

pub(crate) async fn insert(tx: &mut PgTx, b: &BootService) -> Result<(), DbError> {
    let subnets: Vec<String> = b
        .served_subnets
        .as_slice()
        .iter()
        .map(ToString::to_string)
        .collect();
    let sql = format!(
        "INSERT INTO boot_service ({SERVICE_COLUMNS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
    );
    tx.execute(
        "insert boot_service",
        &sql,
        &[
            &to_uuid(b.id.as_bytes()),
            &b.name.as_str(),
            &b.cert_sha256.0.as_slice(),
            &b.cert_not_after.as_micros(),
            &subnets,
            &b.status.as_str(),
            &b.created_at.as_micros(),
            &check_text(&b.created_by, "created_by")?,
        ],
    )
    .await?;
    Ok(())
}

pub(crate) async fn set_status(
    tx: &mut PgTx,
    id: BootServiceId,
    status: BootServiceStatus,
) -> Result<(), DbError> {
    let n = tx
        .execute(
            "update boot_service",
            "UPDATE boot_service SET status = $2 WHERE id = $1",
            &[&to_uuid(id.as_bytes()), &status.as_str()],
        )
        .await?;
    if n == 0 {
        return Err(DbError::NotFound {
            what: "boot service",
        });
    }
    Ok(())
}

fn assignment_from_row(r: &Row) -> Result<BootServicePackage, DbError> {
    Ok(BootServicePackage {
        boot_service_id: col_id(r, "boot_service_id", BootServiceId::from_bytes)?,
        package_id: col_id(r, "package_id", PackageId::from_bytes)?,
        added_by: col_id(r, "added_by", OperatorId::from_bytes)?,
        added_at: col_micros(r, "added_at_us")?,
    })
}

pub(crate) async fn packages(
    tx: &mut PgTx,
    id: BootServiceId,
) -> Result<Vec<BootServicePackage>, DbError> {
    let rows = tx
        .query(
            "list boot_service_package",
            "SELECT boot_service_id, package_id, added_by, added_at_us FROM boot_service_package \
             WHERE boot_service_id = $1 ORDER BY added_at_us, package_id",
            &[&to_uuid(id.as_bytes())],
        )
        .await?;
    rows.iter().map(assignment_from_row).collect()
}

/// The second advisory-lock key for a boot service (any 32 bits of the
/// random id; a collision only serialises two services).
fn assignment_lock_key(id: BootServiceId) -> i32 {
    let b = id.as_bytes();
    let mut k = [0u8; 4];
    for (o, i) in k.iter_mut().zip(b.iter().skip(12)) {
        *o = *i;
    }
    i32::from_be_bytes(k)
}

pub(crate) async fn set_packages(
    tx: &mut PgTx,
    id: BootServiceId,
    package_ids: &[PackageId],
    by: OperatorId,
    at: UnixMicros,
) -> Result<(), DbError> {
    let mut wanted: Vec<PackageId> = package_ids.to_vec();
    wanted.sort();
    wanted.dedup();
    if wanted.len() != package_ids.len() || wanted.len() > MAX_BOOT_SERVICE_PACKAGES {
        return Err(DbError::InvalidArgument {
            what: "package ids (distinct, at most 256)",
        });
    }
    // Serialise replacements of one service's list (the application role
    // cannot lock boot_service rows: it has no UPDATE there).
    tx.query_opt(
        "lock boot_service_package",
        "SELECT pg_advisory_xact_lock($1, $2)",
        &[&ASSIGNMENT_LOCK_SPACE, &assignment_lock_key(id)],
    )
    .await?;
    let bs = to_uuid(id.as_bytes());
    if tx
        .query_opt(
            "read boot_service",
            "SELECT 1 FROM boot_service WHERE id = $1",
            &[&bs],
        )
        .await?
        .is_none()
    {
        return Err(DbError::NotFound {
            what: "boot service",
        });
    }
    let ids: Vec<uuid::Uuid> = wanted.iter().map(|p| to_uuid(p.as_bytes())).collect();
    tx.execute(
        "delete boot_service_package",
        "DELETE FROM boot_service_package WHERE boot_service_id = $1 AND NOT (package_id = ANY($2))",
        &[&bs, &ids],
    )
    .await?;
    let by = to_uuid(by.as_bytes());
    let at = at.as_micros();
    for p in &ids {
        tx.execute(
            "insert boot_service_package",
            "INSERT INTO boot_service_package (boot_service_id, package_id, added_by, added_at_us) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (boot_service_id, package_id) DO NOTHING",
            &[&bs, p, &by, &at],
        )
        .await?;
    }
    Ok(())
}

pub(crate) async fn using_package(
    tx: &mut PgTx,
    id: PackageId,
) -> Result<Vec<BootServiceId>, DbError> {
    let rows = tx
        .query(
            "list boot_service_package",
            "SELECT boot_service_id FROM boot_service_package WHERE package_id = $1 \
             ORDER BY boot_service_id",
            &[&to_uuid(id.as_bytes())],
        )
        .await?;
    rows.iter()
        .map(|r| col_id(r, "boot_service_id", BootServiceId::from_bytes))
        .collect()
}

pub(crate) async fn stop(tx: &mut PgTx, id: BootStopId) -> Result<Option<BootStop>, DbError> {
    let sql = format!("SELECT {STOP_COLUMNS} FROM boot_stop WHERE id = $1");
    let row = tx
        .query_opt("read boot_stop", &sql, &[&to_uuid(id.as_bytes())])
        .await?;
    row.map(|r| stop_from_row(&r)).transpose()
}

pub(crate) async fn stops(
    tx: &mut PgTx,
    boot_service: Option<BootServiceId>,
    active_only: bool,
) -> Result<Vec<BootStop>, DbError> {
    let bs = boot_service.map(|b| to_uuid(b.as_bytes()));
    let sql = format!(
        "SELECT {STOP_COLUMNS} FROM boot_stop \
         WHERE ($1::uuid IS NULL OR boot_service_id = $1) AND (NOT $2 OR cleared_at_us IS NULL) \
         ORDER BY created_at_us, id"
    );
    let rows = tx
        .query("list boot_stop", &sql, &[&bs, &active_only])
        .await?;
    rows.iter().map(stop_from_row).collect()
}

pub(crate) async fn active_stops_for_macs(
    tx: &mut PgTx,
    macs: &MacList,
) -> Result<Vec<BootStop>, DbError> {
    let sql = format!(
        "SELECT {STOP_COLUMNS} FROM boot_stop \
         WHERE cleared_at_us IS NULL AND mac = ANY($1::bytea[]) ORDER BY created_at_us, id"
    );
    let rows = tx
        .query("list boot_stop by mac", &sql, &[&mac_params(macs)])
        .await?;
    rows.iter().map(stop_from_row).collect()
}

pub(crate) async fn add_stop(tx: &mut PgTx, s: &NewBootStop) -> Result<bool, DbError> {
    let n = tx
        .execute(
            "insert boot_stop",
            "INSERT INTO boot_stop (id, boot_service_id, mac, job_id, created_at_us) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (boot_service_id, mac) WHERE cleared_at_us IS NULL DO NOTHING",
            &[
                &to_uuid(s.id.as_bytes()),
                &to_uuid(s.boot_service_id.as_bytes()),
                &s.mac.octets().as_slice(),
                &to_uuid(s.job_id.as_bytes()),
                &s.created_at.as_micros(),
            ],
        )
        .await?;
    Ok(n == 1)
}

pub(crate) async fn clear_stop(
    tx: &mut PgTx,
    id: BootStopId,
    by: OperatorId,
    at: UnixMicros,
) -> Result<(), DbError> {
    let uid = to_uuid(id.as_bytes());
    let n = tx
        .execute(
            "update boot_stop",
            "UPDATE boot_stop SET cleared_at_us = $3, cleared_by = $2 \
             WHERE id = $1 AND cleared_at_us IS NULL",
            &[&uid, &to_uuid(by.as_bytes()), &at.as_micros()],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "boot stop", &uid).await);
    }
    Ok(())
}

pub(crate) async fn generation(tx: &mut PgTx, id: BootServiceId) -> Result<u64, DbError> {
    let row = tx
        .query_opt(
            "read boot_policy_generation",
            "SELECT generation FROM boot_policy_generation WHERE boot_service_id = $1",
            &[&to_uuid(id.as_bytes())],
        )
        .await?;
    row.map_or(Ok(0), |r| col_u64(&r, "generation"))
}

pub(crate) async fn bump_generation(tx: &mut PgTx, id: BootServiceId) -> Result<u64, DbError> {
    let rows = tx
        .query_write(
            "update boot_policy_generation",
            "INSERT INTO boot_policy_generation (boot_service_id, generation) VALUES ($1, 1) \
             ON CONFLICT (boot_service_id) \
             DO UPDATE SET generation = boot_policy_generation.generation + 1 \
             RETURNING generation",
            &[&to_uuid(id.as_bytes())],
        )
        .await?;
    match rows.first() {
        Some(r) => col_u64(r, "generation"),
        None => Err(DbError::Corrupt { what: "generation" }),
    }
}

pub(crate) async fn raise_generation(
    tx: &mut PgTx,
    id: BootServiceId,
    to: u64,
) -> Result<(), DbError> {
    if to == 0 {
        return Err(DbError::InvalidArgument {
            what: "generation 0",
        });
    }
    let to = to_i64(to, "generation")?;
    // Raises only: an equal or lower target changes nothing (and the
    // 0004 guard would refuse it anyway).
    let rows = tx
        .query_write(
            "raise boot_policy_generation",
            "INSERT INTO boot_policy_generation (boot_service_id, generation) VALUES ($1, $2) \
             ON CONFLICT (boot_service_id) DO UPDATE SET generation = $2 \
             WHERE boot_policy_generation.generation < $2 \
             RETURNING generation",
            &[&to_uuid(id.as_bytes()), &to],
        )
        .await?;
    if rows.is_empty() {
        return Err(DbError::Conflict {
            what: "boot_policy_generation",
        });
    }
    Ok(())
}
