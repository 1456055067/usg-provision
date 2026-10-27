//! Package rows (PostgreSQL).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 - revision compare-and-set (If-Match, 412);
//   foreign keys force image = image with that edition, PE = PE.
// - SPEC: specs/os-images.md#REQ-IMG-010, #REQ-IMG-012, #REQ-IMG-014
// - Decision 0015 item 2 (dependants named on in-use delete)

use tokio_postgres::Row;
use usgp_proto::{
    ContentId, Description, DisplayName, OperatorId, PackageId, PackageStatus, UnixMicros,
};

use super::content::{cas_miss, stored_manifest};
use super::conv::{
    check_text, col, col_enum, col_id, col_micros, col_opt_key_id, col_text, col_u32, col_u64,
    to_i32, to_i64, to_uuid,
};
use crate::error::DbError;
use crate::model::{Package, PackageRef, StoredManifest};
use crate::pool::PgTx;

const COLUMNS: &str = "id, name, description, image_id, edition_index, pe_id, revision, status, \
     status_reason, manifest, manifest_sig, manifest_key_id, created_by, created_at_us, \
     updated_at_us";

fn from_row(r: &Row) -> Result<Package, DbError> {
    let description: Option<String> = col(r, "description")?;
    let description = description
        .map(|d| {
            Description::new(d).map_err(|_| DbError::Corrupt {
                what: "description",
            })
        })
        .transpose()?;
    let payload: Option<Vec<u8>> = col(r, "manifest")?;
    let sig: Option<Vec<u8>> = col(r, "manifest_sig")?;
    let key = col_opt_key_id(r, "manifest_key_id")?;
    Ok(Package {
        id: col_id(r, "id", PackageId::from_bytes)?,
        name: col_text(r, "name", DisplayName::new)?,
        description,
        image_id: col_id(r, "image_id", ContentId::from_bytes)?,
        edition_index: col_u32(r, "edition_index")?,
        pe_id: col_id(r, "pe_id", ContentId::from_bytes)?,
        revision: col_u64(r, "revision")?,
        status: col_enum(r, "status", PackageStatus::parse)?,
        status_reason: col(r, "status_reason")?,
        manifest: stored_manifest(payload, sig, key)?,
        created_by: col_id(r, "created_by", OperatorId::from_bytes)?,
        created_at: col_micros(r, "created_at_us")?,
        updated_at: col_micros(r, "updated_at_us")?,
    })
}

fn ref_from_row(r: &Row) -> Result<PackageRef, DbError> {
    Ok(PackageRef {
        id: col_id(r, "id", PackageId::from_bytes)?,
        name: col_text(r, "name", DisplayName::new)?,
    })
}

pub(crate) async fn get(
    tx: &mut PgTx,
    id: PackageId,
    lock: bool,
) -> Result<Option<Package>, DbError> {
    let sql = format!(
        "SELECT {COLUMNS} FROM package WHERE id = $1{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = tx
        .query_opt("read package", &sql, &[&to_uuid(id.as_bytes())])
        .await?;
    row.map(|r| from_row(&r)).transpose()
}

pub(crate) async fn list(tx: &mut PgTx) -> Result<Vec<Package>, DbError> {
    let sql = format!("SELECT {COLUMNS} FROM package ORDER BY created_at_us, id");
    let rows = tx.query("list package", &sql, &[]).await?;
    rows.iter().map(from_row).collect()
}

pub(crate) async fn using_content(
    tx: &mut PgTx,
    id: ContentId,
) -> Result<Vec<PackageRef>, DbError> {
    let rows = tx
        .query(
            "list package dependants",
            "SELECT id, name FROM package WHERE image_id = $1 OR pe_id = $1 ORDER BY created_at_us, id",
            &[&to_uuid(id.as_bytes())],
        )
        .await?;
    rows.iter().map(ref_from_row).collect()
}

pub(crate) async fn using_edition(
    tx: &mut PgTx,
    id: ContentId,
    index: u32,
) -> Result<Vec<PackageRef>, DbError> {
    let rows = tx
        .query(
            "list package dependants",
            "SELECT id, name FROM package WHERE image_id = $1 AND edition_index = $2 \
             ORDER BY created_at_us, id",
            &[&to_uuid(id.as_bytes()), &to_i32(index, "edition index")?],
        )
        .await?;
    rows.iter().map(ref_from_row).collect()
}

/// Payload, signature and key id parameters.
type ManifestParams<'a> = (Option<&'a [u8]>, Option<&'a [u8]>, Option<&'a [u8]>);

fn manifest_params(m: Option<&StoredManifest>) -> ManifestParams<'_> {
    match m {
        Some(m) => (
            Some(m.payload.as_slice()),
            Some(m.signature.as_slice()),
            Some(m.key_id.0.0.as_slice()),
        ),
        None => (None, None, None),
    }
}

pub(crate) async fn insert(tx: &mut PgTx, p: &Package) -> Result<(), DbError> {
    if p.revision != 1 {
        return Err(DbError::InvalidArgument {
            what: "new package revision must be 1",
        });
    }
    let (m, s, k) = manifest_params(p.manifest.as_ref());
    let reason = p
        .status_reason
        .as_deref()
        .map(|r| check_text(r, "status_reason"))
        .transpose()?;
    tx.execute(
        "insert package",
        &format!(
            "INSERT INTO package ({COLUMNS}) VALUES \
             ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)"
        ),
        &[
            &to_uuid(p.id.as_bytes()),
            &p.name.as_str(),
            &p.description.as_ref().map(Description::as_str),
            &to_uuid(p.image_id.as_bytes()),
            &to_i32(p.edition_index, "edition index")?,
            &to_uuid(p.pe_id.as_bytes()),
            &to_i64(p.revision, "revision")?,
            &p.status.as_str(),
            &reason,
            &m,
            &s,
            &k,
            &to_uuid(p.created_by.as_bytes()),
            &p.created_at.as_micros(),
            &p.updated_at.as_micros(),
        ],
    )
    .await?;
    Ok(())
}

pub(crate) async fn update(tx: &mut PgTx, p: &Package, expected: u64) -> Result<(), DbError> {
    if Some(p.revision) != expected.checked_add(1) {
        return Err(DbError::InvalidArgument {
            what: "revision must be expected + 1",
        });
    }
    let (m, s, k) = manifest_params(p.manifest.as_ref());
    let reason = p
        .status_reason
        .as_deref()
        .map(|r| check_text(r, "status_reason"))
        .transpose()?;
    let uid = to_uuid(p.id.as_bytes());
    let n = tx
        .execute(
            "update package",
            "UPDATE package SET name = $2, description = $3, image_id = $4, edition_index = $5, \
             pe_id = $6, revision = $7, status = $8, status_reason = $9, manifest = $10, \
             manifest_sig = $11, manifest_key_id = $12, updated_at_us = $13 \
             WHERE id = $1 AND revision = $14",
            &[
                &uid,
                &p.name.as_str(),
                &p.description.as_ref().map(Description::as_str),
                &to_uuid(p.image_id.as_bytes()),
                &to_i32(p.edition_index, "edition index")?,
                &to_uuid(p.pe_id.as_bytes()),
                &to_i64(p.revision, "revision")?,
                &p.status.as_str(),
                &reason,
                &m,
                &s,
                &k,
                &p.updated_at.as_micros(),
                &to_i64(expected, "revision")?,
            ],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "package", &uid).await);
    }
    Ok(())
}

pub(crate) async fn set_status(
    tx: &mut PgTx,
    id: PackageId,
    status: PackageStatus,
    reason: Option<&str>,
    manifest: Option<&StoredManifest>,
    at: UnixMicros,
) -> Result<(), DbError> {
    let (m, s, k) = manifest_params(manifest);
    let reason = reason.map(|r| check_text(r, "status_reason")).transpose()?;
    let n = tx
        .execute(
            "update package status",
            "UPDATE package SET status = $2, status_reason = $3, manifest = $4, \
             manifest_sig = $5, manifest_key_id = $6, updated_at_us = $7 WHERE id = $1",
            &[
                &to_uuid(id.as_bytes()),
                &status.as_str(),
                &reason,
                &m,
                &s,
                &k,
                &at.as_micros(),
            ],
        )
        .await?;
    if n == 0 {
        return Err(DbError::NotFound { what: "package" });
    }
    Ok(())
}

pub(crate) async fn delete(tx: &mut PgTx, id: PackageId, expected: u64) -> Result<(), DbError> {
    let uid = to_uuid(id.as_bytes());
    let n = tx
        .execute(
            "delete package",
            "DELETE FROM package WHERE id = $1 AND revision = $2",
            &[&uid, &to_i64(expected, "revision")?],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "package", &uid).await);
    }
    Ok(())
}
