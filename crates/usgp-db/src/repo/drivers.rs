//! Driver archive records and package driver lists (PostgreSQL; M4 plan
//! section 3.5, migration 0005).
//!
//! A driver archive record names its current archive content. It becomes
//! ready only when that content is Ready with a signed v2 manifest of kind
//! `driver_archive`; the format, INF list and expanded size are copied
//! from that manifest, never from the caller. A replacement keeps the id
//! (REQ-DRV-003) and restarts the check.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 - ready only from a Ready, signed v2 manifest; the
//   INF list the plan carries comes from it.
// - NIST 800-53: SI-10 - compare-and-set status moves; at most 64 distinct
//   archives per package; stored INF paths re-validated on read.
// - SPEC: specs/drivers.md#REQ-DRV-003, #REQ-DRV-006
// - Decision 0025 item 4

use tokio_postgres::Row;
use usgp_proto::limits::{MAX_ARCHIVE_INFS, MAX_PLAN_DRIVERS};
use usgp_proto::{
    ArchiveFormat, ContentId, ContentKindV2, ContentManifestV2, ContentState, DisplayName,
    DriverArchiveId, ErrorCode, OperatorId, PackageId, RelPath, UnixMicros,
};

use super::content::{archive_get, cas_miss, mark_superseded};
use super::conv::{
    check_text, col, col_enum, col_id, col_micros, col_opt_enum, col_opt_micros, col_opt_u64,
    col_text, to_i64, to_uuid,
};
use super::packages::ref_from_row;
use crate::error::DbError;
use crate::model::{DriverArchive, DriverArchiveStatus, NewDriverArchive, PackageRef};
use crate::pool::PgTx;

const COLUMNS: &str = "id, content_id, name, kind, status, refusal, inf_list::text AS inf_list, \
     expanded_bytes, created_by, created_at_us, updated_at_us, replaced_at_us";

/// Longest stored INF list text: 4096 paths of at most 1024 bytes, JSON
/// quoted and escaped.
const MAX_INF_LIST_TEXT: usize = 4096 * (2 * 1024 + 4);

/// Parses a stored INF list (JSON array of relative paths).
pub(crate) fn infs_from_json(s: &str) -> Result<Vec<RelPath>, DbError> {
    if s.len() > MAX_INF_LIST_TEXT {
        return Err(DbError::Corrupt { what: "inf_list" });
    }
    let raw: Vec<String> =
        serde_json::from_str(s).map_err(|_| DbError::Corrupt { what: "inf_list" })?;
    if raw.len() > MAX_ARCHIVE_INFS {
        return Err(DbError::Corrupt { what: "inf_list" });
    }
    raw.into_iter()
        .map(|p| RelPath::new(p).map_err(|_| DbError::Corrupt { what: "inf_list" }))
        .collect()
}

/// Renders an INF list for the `jsonb` column.
pub(crate) fn infs_to_json(infs: &[RelPath]) -> Result<String, DbError> {
    let raw: Vec<&str> = infs.iter().map(RelPath::as_str).collect();
    serde_json::to_string(&raw).map_err(|_| DbError::InvalidArgument { what: "inf_list" })
}

fn code(s: Option<String>) -> Result<Option<ErrorCode>, DbError> {
    s.map(|c| ErrorCode::new(c).map_err(|_| DbError::Corrupt { what: "refusal" }))
        .transpose()
}

fn from_row(r: &Row) -> Result<DriverArchive, DbError> {
    let infs: String = col(r, "inf_list")?;
    Ok(DriverArchive {
        id: col_id(r, "id", DriverArchiveId::from_bytes)?,
        content_id: col_id(r, "content_id", ContentId::from_bytes)?,
        name: col_text(r, "name", DisplayName::new)?,
        format: col_opt_enum(r, "kind", ArchiveFormat::parse)?,
        status: col_enum(r, "status", DriverArchiveStatus::parse)?,
        refusal: code(col(r, "refusal")?)?,
        infs: infs_from_json(&infs)?,
        expanded_bytes: col_opt_u64(r, "expanded_bytes")?,
        created_by: col_id(r, "created_by", OperatorId::from_bytes)?,
        created_at: col_micros(r, "created_at_us")?,
        updated_at: col_micros(r, "updated_at_us")?,
        replaced_at: col_opt_micros(r, "replaced_at_us")?,
    })
}

/// The `driver_archive` record facts of a Ready archive item, from its
/// signed v2 manifest: format, INF list, expanded bytes. `None` unless the
/// item is Ready, of kind `driver_archive`, with a manifest.
pub(crate) fn ready_facts(
    c: &crate::model::ArchiveContent,
) -> Option<(ArchiveFormat, Vec<RelPath>, u64)> {
    if c.state != ContentState::Ready || c.kind != ContentKindV2::DriverArchive {
        return None;
    }
    let m = ContentManifestV2::from_payload(&c.manifest.as_ref()?.payload).ok()?;
    Some((m.archive.format, m.archive.infs, m.archive.expanded_bytes))
}

pub(crate) async fn insert(tx: &mut PgTx, a: &NewDriverArchive) -> Result<(), DbError> {
    tx.execute(
        "insert driver_archive",
        "INSERT INTO driver_archive (id, content_id, name, status, created_by, created_at_us, \
         updated_at_us) VALUES ($1, $2, $3, 'checking', $4, $5, $5)",
        &[
            &to_uuid(a.id.as_bytes()),
            &to_uuid(a.content_id.as_bytes()),
            &check_text(a.name.as_str(), "name")?,
            &to_uuid(a.created_by.as_bytes()),
            &a.created_at.as_micros(),
        ],
    )
    .await?;
    Ok(())
}

pub(crate) async fn get(
    tx: &mut PgTx,
    id: DriverArchiveId,
    lock: bool,
) -> Result<Option<DriverArchive>, DbError> {
    let sql = format!(
        "SELECT {COLUMNS} FROM driver_archive WHERE id = $1{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = tx
        .query_opt("read driver_archive", &sql, &[&to_uuid(id.as_bytes())])
        .await?;
    row.map(|r| from_row(&r)).transpose()
}

pub(crate) async fn list(
    tx: &mut PgTx,
    statuses: &[DriverArchiveStatus],
) -> Result<Vec<DriverArchive>, DbError> {
    let st: Vec<&str> = statuses.iter().map(|s| s.as_str()).collect();
    let sql = format!(
        "SELECT {COLUMNS} FROM driver_archive \
         WHERE (cardinality($1::text[]) = 0 OR status = ANY($1)) ORDER BY created_at_us, id"
    );
    let rows = tx.query("list driver_archive", &sql, &[&st]).await?;
    rows.iter().map(from_row).collect()
}

pub(crate) async fn set_ready(
    tx: &mut PgTx,
    id: DriverArchiveId,
    at: UnixMicros,
) -> Result<(), DbError> {
    let Some(cur) = get(tx, id, true).await? else {
        return Err(DbError::NotFound {
            what: "driver archive",
        });
    };
    if cur.status != DriverArchiveStatus::Checking {
        return Err(DbError::Conflict {
            what: "driver archive",
        });
    }
    let content = archive_get(tx, cur.content_id, false).await?;
    let (format, infs, expanded) =
        content
            .as_ref()
            .and_then(ready_facts)
            .ok_or(DbError::Conflict {
                what: "driver archive content not ready",
            })?;
    let uid = to_uuid(id.as_bytes());
    let n = tx
        .execute(
            "update driver_archive ready",
            "UPDATE driver_archive SET status = 'ready', kind = $2, inf_list = $3::text::jsonb, \
             expanded_bytes = $4, updated_at_us = $5 \
             WHERE id = $1 AND status = 'checking' AND content_id = $6",
            &[
                &uid,
                &format.as_str(),
                &infs_to_json(&infs)?,
                &to_i64(expanded, "expanded_bytes")?,
                &at.as_micros(),
                &to_uuid(cur.content_id.as_bytes()),
            ],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "driver archive", &uid).await);
    }
    Ok(())
}

pub(crate) async fn refuse(
    tx: &mut PgTx,
    id: DriverArchiveId,
    reason: &ErrorCode,
    at: UnixMicros,
) -> Result<(), DbError> {
    let uid = to_uuid(id.as_bytes());
    let n = tx
        .execute(
            "update driver_archive refused",
            "UPDATE driver_archive SET status = 'refused', refusal = $2, updated_at_us = $3 \
             WHERE id = $1 AND status = 'checking'",
            &[&uid, &reason.as_str(), &at.as_micros()],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "driver archive", &uid).await);
    }
    Ok(())
}

pub(crate) async fn replace(
    tx: &mut PgTx,
    id: DriverArchiveId,
    content_id: ContentId,
    at: UnixMicros,
) -> Result<(), DbError> {
    let Some(cur) = get(tx, id, true).await? else {
        return Err(DbError::NotFound {
            what: "driver archive",
        });
    };
    let uid = to_uuid(id.as_bytes());
    let n = tx
        .execute(
            "update driver_archive replaced",
            "UPDATE driver_archive SET status = 'checking', content_id = $2, kind = NULL, \
             inf_list = '[]'::jsonb, expanded_bytes = NULL, refusal = NULL, updated_at_us = $3, \
             replaced_at_us = $3 \
             WHERE id = $1 AND status IN ('ready', 'refused') AND content_id <> $2",
            &[&uid, &to_uuid(content_id.as_bytes()), &at.as_micros()],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "driver archive", &uid).await);
    }
    // The old file is superseded (U-4): still served to packages that pin
    // it, never attached again.
    mark_superseded(tx, cur.content_id, at).await
}

pub(crate) async fn delete(
    tx: &mut PgTx,
    id: DriverArchiveId,
    at: UnixMicros,
) -> Result<(), DbError> {
    let uid = to_uuid(id.as_bytes());
    // An archive a package lists cannot be deleted (decision 0015 item 2:
    // name the dependants with `using_archive` first).
    let n = tx
        .execute(
            "update driver_archive deleted",
            "UPDATE driver_archive SET status = 'deleted', updated_at_us = $2 \
             WHERE id = $1 AND status <> 'deleted' \
             AND NOT EXISTS (SELECT 1 FROM package_driver d WHERE d.archive_id = $1)",
            &[&uid, &at.as_micros()],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "driver archive", &uid).await);
    }
    Ok(())
}

pub(crate) async fn using_archive(
    tx: &mut PgTx,
    id: DriverArchiveId,
) -> Result<Vec<PackageRef>, DbError> {
    let rows = tx
        .query(
            "list package dependants",
            "SELECT p.id, p.name FROM package p JOIN package_driver d ON d.package_id = p.id \
             WHERE d.archive_id = $1 ORDER BY p.created_at_us, p.id",
            &[&to_uuid(id.as_bytes())],
        )
        .await?;
    rows.iter().map(ref_from_row).collect()
}

pub(crate) async fn package_drivers(
    tx: &mut PgTx,
    package: PackageId,
) -> Result<Vec<DriverArchiveId>, DbError> {
    let rows = tx
        .query(
            "list package_driver",
            "SELECT archive_id FROM package_driver WHERE package_id = $1 ORDER BY ord",
            &[&to_uuid(package.as_bytes())],
        )
        .await?;
    rows.iter()
        .map(|r| col_id(r, "archive_id", DriverArchiveId::from_bytes))
        .collect()
}

/// Checks a package's driver list: at most 64, distinct.
pub(crate) fn check_driver_list(ids: &[DriverArchiveId]) -> Result<(), DbError> {
    let mut seen = ids.to_vec();
    seen.sort();
    seen.dedup();
    if ids.len() > MAX_PLAN_DRIVERS || seen.len() != ids.len() {
        return Err(DbError::InvalidArgument {
            what: "driver archives (at most 64, distinct)",
        });
    }
    Ok(())
}

pub(crate) async fn set_package_drivers(
    tx: &mut PgTx,
    package: PackageId,
    ids: &[DriverArchiveId],
) -> Result<(), DbError> {
    check_driver_list(ids)?;
    let pid = to_uuid(package.as_bytes());
    // Serialise per package (and require it to exist).
    let row = tx
        .query_opt(
            "lock package",
            "SELECT 1 FROM package WHERE id = $1 FOR UPDATE",
            &[&pid],
        )
        .await?;
    if row.is_none() {
        return Err(DbError::NotFound { what: "package" });
    }
    let aids: Vec<uuid::Uuid> = ids.iter().map(|a| to_uuid(a.as_bytes())).collect();
    // Every archive exists and is not deleted; held against deletion
    // until the transaction ends.
    let live = tx
        .query(
            "lock driver_archive",
            "SELECT id FROM driver_archive WHERE id = ANY($1) AND status <> 'deleted' FOR SHARE",
            &[&aids],
        )
        .await?;
    if live.len() != ids.len() {
        tx.poison();
        return Err(DbError::Constraint {
            what: "package driver archive",
        });
    }
    tx.execute(
        "delete package_driver",
        "DELETE FROM package_driver WHERE package_id = $1",
        &[&pid],
    )
    .await?;
    for (i, a) in aids.iter().enumerate() {
        let ord = i16::try_from(i + 1).map_err(|_| DbError::InvalidArgument { what: "ord" })?;
        tx.execute(
            "insert package_driver",
            "INSERT INTO package_driver (package_id, archive_id, ord) VALUES ($1, $2, $3)",
            &[&pid, a, &ord],
        )
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inf_list_round_trip_and_rejects() {
        let infs = vec![
            RelPath::new("net/e1d.inf").unwrap(),
            RelPath::new("x.inf").unwrap(),
        ];
        let j = infs_to_json(&infs).unwrap();
        assert_eq!(infs_from_json(&j).unwrap(), infs);
        assert!(infs_from_json("[\"../x.inf\"]").is_err());
        assert!(infs_from_json("{}").is_err());
        assert!(infs_from_json("[1]").is_err());
    }

    #[test]
    fn driver_list_bounds() {
        let id = |b: u8| DriverArchiveId::from_bytes([b; 16]).unwrap();
        assert!(check_driver_list(&[]).is_ok());
        assert!(check_driver_list(&[id(1), id(2)]).is_ok());
        assert!(check_driver_list(&[id(1), id(1)]).is_err());
        let many: Vec<_> = (1..=65).map(id).collect();
        assert!(check_driver_list(&many).is_err());
        assert!(check_driver_list(many.get(..64).unwrap()).is_ok());
    }
}
