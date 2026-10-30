//! Content, edition and upload rows (PostgreSQL). Images and PEs carry
//! v1 manifests; driver archives and agent packages (M4, migration 0005)
//! carry v2 manifests and are read through the `archive_*` functions.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 - content becomes Ready only with its signed
//   manifest (constraint in 0001; archive kinds: 0005, and the v2 manifest
//   must describe the row it is stored with, checked on write and read).
// - NIST 800-53: SI-10 - compare-and-set state transitions; values
//   re-validated on read.
// - SPEC: specs/os-images.md#REQ-IMG-020, #REQ-IMG-040, #REQ-IMG-043;
//   specs/preinstall-env.md#REQ-PE-005
// - Decision 0013 (declared facts with their source)

use tokio_postgres::Row;
use usgp_common::Sha256Digest;
use usgp_proto::{
    Architecture, ArchiveFormat, ContentId, ContentKind, ContentKindV2, ContentManifestV2,
    ContentState, DisplayName, Edition, EditionFacts, Fact, FactSource, FileName, KitVersion,
    OperatorId, Release, SupportState, UnixMicros, UploadId, UploadState, WimCompression, WimText,
};

use super::conv::{
    check_text, col, col_digest, col_enum, col_id, col_micros, col_opt_enum, col_opt_id,
    col_opt_key_id, col_opt_micros, col_opt_u32, col_opt_u64, col_text, col_u32, col_u64, texts,
    to_i32, to_i64, to_uuid,
};
use crate::error::DbError;
use crate::model::Edition as EditionRow;
use crate::model::{ArchiveContent, ArchiveFacts, NewArchiveContent, ReadyArchiveContent};
use crate::model::{
    Content, EditionDeclaration, NewContent, PeDeclaration, ReadyContent, Reason, StoredManifest,
    Upload, WimFacts,
};
use crate::pool::PgTx;

const CONTENT_COLUMNS: &str = "id, kind, display_name, file_name, size, sha256, state, \
     reason_code, reason_text, created_by, initiating_audit_seq, created_at_us, updated_at_us, \
     ready_at_us, compression, image_count, boot_index, usable_index, pe_arch, pe_arch_source, \
     pe_kit_version, pe_kit_version_source, manifest, manifest_sig, manifest_key_id";

/// The M2 readers see only image and PE rows; archive kinds (M4) are
/// read through the `archive_*` functions below.
const WIM_KINDS: &str = "kind IN ('image', 'pe')";

const EDITION_COLUMNS: &str = "content_id, idx, name, description, total_bytes, decl_release, \
     decl_edition, decl_arch, release_source, edition_source, arch_source, declared_by, \
     declared_at_us, declared_audit_seq, support_status, support_reason";

const UPLOAD_COLUMNS: &str = "id, content_id, operator_id, declared_size, declared_sha256, \
     state, staging_name, created_at_us, expires_at_us";

fn fact<T>(value: T, source: FactSource) -> Fact<T> {
    Fact { value, source }
}

fn kit_version(s: &str) -> Option<KitVersion> {
    KitVersion::parse(s).ok()
}

fn content_from_row(r: &Row) -> Result<Content, DbError> {
    let reason_code: Option<String> = col(r, "reason_code")?;
    let reason_text: Option<String> = col(r, "reason_text")?;
    let reason = reason_code.map(|code| Reason {
        code,
        text: reason_text.unwrap_or_default(),
    });
    let compression = col_opt_enum(r, "compression", WimCompression::parse)?;
    let image_count = col_opt_u32(r, "image_count")?;
    let boot_index = col_opt_u32(r, "boot_index")?;
    let wim = match (compression, image_count, boot_index) {
        (Some(compression), Some(image_count), Some(boot_index)) => Some(WimFacts {
            compression,
            image_count,
            boot_index,
        }),
        (None, None, None) => None,
        _ => return Err(DbError::Corrupt { what: "wim facts" }),
    };
    let pe_arch = col_opt_enum(r, "pe_arch", Architecture::parse)?;
    let pe_arch_source = col_opt_enum(r, "pe_arch_source", FactSource::parse)?;
    let pe_kit = col_opt_enum(r, "pe_kit_version", kit_version)?;
    let pe_kit_source = col_opt_enum(r, "pe_kit_version_source", FactSource::parse)?;
    let pe = match (pe_arch, pe_arch_source, pe_kit, pe_kit_source) {
        (Some(a), Some(asrc), Some(k), Some(ksrc)) => Some(PeDeclaration {
            architecture: fact(a, asrc),
            kit_version: fact(k, ksrc),
        }),
        (None, None, None, None) => None,
        _ => {
            return Err(DbError::Corrupt {
                what: "pe declaration",
            });
        }
    };
    let payload: Option<Vec<u8>> = col(r, "manifest")?;
    let sig: Option<Vec<u8>> = col(r, "manifest_sig")?;
    let key = col_opt_key_id(r, "manifest_key_id")?;
    let manifest = stored_manifest(payload, sig, key)?;
    Ok(Content {
        id: col_id(r, "id", ContentId::from_bytes)?,
        kind: col_enum(r, "kind", ContentKind::parse)?,
        display_name: col_text(r, "display_name", DisplayName::new)?,
        file_name: col_text(r, "file_name", FileName::new)?,
        size: col_u64(r, "size")?,
        sha256: col_digest(r, "sha256")?,
        state: col_enum(r, "state", ContentState::parse)?,
        reason,
        created_by: col_id(r, "created_by", OperatorId::from_bytes)?,
        initiating_audit_seq: col_opt_u64(r, "initiating_audit_seq")?,
        created_at: col_micros(r, "created_at_us")?,
        updated_at: col_micros(r, "updated_at_us")?,
        ready_at: col_opt_micros(r, "ready_at_us")?,
        wim,
        usable_index: col_opt_u32(r, "usable_index")?,
        pe,
        manifest,
    })
}

pub(crate) fn stored_manifest(
    payload: Option<Vec<u8>>,
    signature: Option<Vec<u8>>,
    key_id: Option<usgp_crypto::KeyId>,
) -> Result<Option<StoredManifest>, DbError> {
    match (payload, signature, key_id) {
        (Some(payload), Some(signature), Some(key_id)) => Ok(Some(StoredManifest {
            payload,
            signature,
            key_id,
        })),
        (None, None, None) => Ok(None),
        _ => Err(DbError::Corrupt { what: "manifest" }),
    }
}

fn edition_from_row(r: &Row) -> Result<EditionRow, DbError> {
    let release = col_opt_enum(r, "decl_release", Release::parse)?;
    let edition = col_opt_enum(r, "decl_edition", Edition::parse)?;
    let arch = col_opt_enum(r, "decl_arch", Architecture::parse)?;
    let rs = col_opt_enum(r, "release_source", FactSource::parse)?;
    let es = col_opt_enum(r, "edition_source", FactSource::parse)?;
    let a_s = col_opt_enum(r, "arch_source", FactSource::parse)?;
    let by = col_opt_id(r, "declared_by", OperatorId::from_bytes)?;
    let at = col_opt_micros(r, "declared_at_us")?;
    let seq = col_opt_u64(r, "declared_audit_seq")?;
    let declaration = match (release, edition, arch, rs, es, a_s, by, at, seq) {
        (
            Some(rel),
            Some(ed),
            Some(ar),
            Some(rs),
            Some(es),
            Some(a_s),
            Some(by),
            Some(at),
            Some(seq),
        ) => Some(EditionDeclaration {
            facts: EditionFacts {
                release: fact(rel, rs),
                edition: fact(ed, es),
                architecture: fact(ar, a_s),
            },
            declared_by: by,
            declared_at: at,
            declared_audit_seq: seq,
        }),
        (None, None, None, None, None, None, None, None, None) => None,
        _ => {
            return Err(DbError::Corrupt {
                what: "edition declaration",
            });
        }
    };
    Ok(EditionRow {
        content_id: col_id(r, "content_id", ContentId::from_bytes)?,
        index: col_u32(r, "idx")?,
        name: col_text(r, "name", WimText::new)?,
        description: col_text(r, "description", WimText::new)?,
        total_bytes: col_opt_u64(r, "total_bytes")?,
        declaration,
        support: col_enum(r, "support_status", SupportState::parse)?,
        support_reason: col(r, "support_reason")?,
    })
}

fn upload_from_row(r: &Row) -> Result<Upload, DbError> {
    Ok(Upload {
        id: col_id(r, "id", UploadId::from_bytes)?,
        content_id: col_id(r, "content_id", ContentId::from_bytes)?,
        operator_id: col_id(r, "operator_id", OperatorId::from_bytes)?,
        declared_size: col_u64(r, "declared_size")?,
        declared_sha256: col_digest(r, "declared_sha256")?,
        state: col_enum(r, "state", UploadState::parse)?,
        staging_name: col(r, "staging_name")?,
        created_at: col_micros(r, "created_at_us")?,
        expires_at: col_micros(r, "expires_at_us")?,
    })
}

// ------------------------------------------------------------- content --

pub(crate) async fn get(
    tx: &mut PgTx,
    id: ContentId,
    lock: bool,
) -> Result<Option<Content>, DbError> {
    let sql = format!(
        "SELECT {CONTENT_COLUMNS} FROM content WHERE id = $1 AND {WIM_KINDS}{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = tx
        .query_opt("read content", &sql, &[&to_uuid(id.as_bytes())])
        .await?;
    row.map(|r| content_from_row(&r)).transpose()
}

pub(crate) async fn by_sha256(
    tx: &mut PgTx,
    sha: &Sha256Digest,
) -> Result<Option<Content>, DbError> {
    let sql = format!(
        "SELECT {CONTENT_COLUMNS} FROM content \
         WHERE sha256 = $1 AND state IN ('receiving', 'checking', 'ready') AND {WIM_KINDS}"
    );
    let row = tx
        .query_opt("read content", &sql, &[&sha.0.as_slice()])
        .await?;
    row.map(|r| content_from_row(&r)).transpose()
}

pub(crate) async fn list(
    tx: &mut PgTx,
    kind: Option<ContentKind>,
    states: &[ContentState],
) -> Result<Vec<Content>, DbError> {
    let states = if states.is_empty() {
        ContentState::ALL
    } else {
        states
    };
    let st = texts(states, ContentState::as_str);
    let kind = kind.map(ContentKind::as_str);
    let sql = format!(
        "SELECT {CONTENT_COLUMNS} FROM content \
         WHERE ($1::text IS NULL OR kind = $1) AND state = ANY($2) AND {WIM_KINDS} \
         ORDER BY created_at_us, id"
    );
    let rows = tx.query("list content", &sql, &[&kind, &st]).await?;
    rows.iter().map(content_from_row).collect()
}

pub(crate) async fn create_upload(
    tx: &mut PgTx,
    c: &NewContent,
    u: &Upload,
) -> Result<(), DbError> {
    if (c.kind == ContentKind::Pe) != c.pe.is_some() {
        return Err(DbError::InvalidArgument {
            what: "pe declaration",
        });
    }
    if u.content_id != c.id || u.declared_size != c.size || u.declared_sha256 != c.sha256 {
        return Err(DbError::InvalidArgument {
            what: "upload does not match content",
        });
    }
    let initiating = c
        .initiating_audit_seq
        .map(|s| to_i64(s, "initiating_audit_seq"))
        .transpose()?;
    let pe_arch = c.pe.as_ref().map(|p| p.architecture.value.as_str());
    let pe_arch_src = c.pe.as_ref().map(|p| p.architecture.source.as_str());
    let pe_kit = c.pe.as_ref().map(|p| p.kit_version.value.to_string());
    let pe_kit_src = c.pe.as_ref().map(|p| p.kit_version.source.as_str());
    let size = to_i64(c.size, "size")?;
    tx.execute(
        "insert content",
        "INSERT INTO content (id, kind, display_name, file_name, size, sha256, state, \
         created_by, initiating_audit_seq, created_at_us, updated_at_us, pe_arch, \
         pe_arch_source, pe_kit_version, pe_kit_version_source) \
         VALUES ($1, $2, $3, $4, $5, $6, 'receiving', $7, $8, $9, $9, $10, $11, $12, $13)",
        &[
            &to_uuid(c.id.as_bytes()),
            &c.kind.as_str(),
            &c.display_name.as_str(),
            &c.file_name.as_str(),
            &size,
            &c.sha256.0.as_slice(),
            &to_uuid(c.created_by.as_bytes()),
            &initiating,
            &c.created_at.as_micros(),
            &pe_arch,
            &pe_arch_src,
            &pe_kit,
            &pe_kit_src,
        ],
    )
    .await?;
    insert_upload(tx, u).await
}

/// After a compare-and-set update that touched no row: tell "missing"
/// from "wrong state".
pub(crate) async fn cas_miss(tx: &mut PgTx, table: &'static str, id: &uuid::Uuid) -> DbError {
    let sql = match table {
        "upload" => "SELECT 1 FROM upload WHERE id = $1",
        "package" => "SELECT 1 FROM package WHERE id = $1",
        "auth code" => "SELECT 1 FROM auth_code WHERE id = $1",
        "device session" => "SELECT 1 FROM device_session WHERE id = $1",
        "job" => "SELECT 1 FROM job WHERE id = $1",
        "boot stop" => "SELECT 1 FROM boot_stop WHERE id = $1",
        "boot service" => "SELECT 1 FROM boot_service WHERE id = $1",
        "driver archive" => "SELECT 1 FROM driver_archive WHERE id = $1",
        "agent signer" => "SELECT 1 FROM agent_signer WHERE id = $1",
        "agent package" => "SELECT 1 FROM agent_package WHERE id = $1",
        "escrow" => "SELECT 1 FROM admin_password_escrow WHERE job_id = $1",
        _ => "SELECT 1 FROM content WHERE id = $1",
    };
    match tx.query_opt("compare-and-set check", sql, &[id]).await {
        Ok(Some(_)) => DbError::Conflict { what: table },
        Ok(None) => DbError::NotFound { what: table },
        Err(e) => e,
    }
}

pub(crate) async fn set_state(
    tx: &mut PgTx,
    id: ContentId,
    from: &[ContentState],
    to: ContentState,
    reason: Option<&Reason>,
    at: UnixMicros,
) -> Result<(), DbError> {
    if to == ContentState::Ready {
        return Err(DbError::InvalidArgument {
            what: "use set_content_ready",
        });
    }
    if to == ContentState::Failed && reason.is_none() {
        return Err(DbError::InvalidArgument {
            what: "reason required for failed",
        });
    }
    let from = texts(from, ContentState::as_str);
    let code = reason
        .map(|r| check_text(&r.code, "reason_code"))
        .transpose()?;
    let text = reason
        .map(|r| check_text(&r.text, "reason_text"))
        .transpose()?;
    let uid = to_uuid(id.as_bytes());
    let n = tx
        .execute(
            "update content state",
            "UPDATE content SET state = $2, reason_code = COALESCE($3, reason_code), \
             reason_text = COALESCE($4, reason_text), updated_at_us = $5 \
             WHERE id = $1 AND state = ANY($6)",
            &[&uid, &to.as_str(), &code, &text, &at.as_micros(), &from],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "content", &uid).await);
    }
    Ok(())
}

pub(crate) async fn set_ready(
    tx: &mut PgTx,
    id: ContentId,
    r: &ReadyContent,
) -> Result<(), DbError> {
    let count = usize::try_from(r.wim.image_count).map_err(|_| DbError::InvalidArgument {
        what: "image_count",
    })?;
    if r.editions.len() != count
        || r.editions
            .iter()
            .enumerate()
            .any(|(i, e)| usize::try_from(e.index).ok() != Some(i + 1))
    {
        return Err(DbError::InvalidArgument {
            what: "editions must be 1..=image_count",
        });
    }
    let uid = to_uuid(id.as_bytes());
    let pe_arch = r.pe.as_ref().map(|p| p.architecture.value.as_str());
    let pe_arch_src = r.pe.as_ref().map(|p| p.architecture.source.as_str());
    let pe_kit = r.pe.as_ref().map(|p| p.kit_version.value.to_string());
    let pe_kit_src = r.pe.as_ref().map(|p| p.kit_version.source.as_str());
    let usable = r
        .usable_index
        .map(|v| to_i32(v, "usable_index"))
        .transpose()?;
    let n = tx
        .execute(
            "update content ready",
            "UPDATE content SET state = 'ready', reason_code = NULL, reason_text = NULL, \
             updated_at_us = $2, ready_at_us = $2, compression = $3, image_count = $4, \
             boot_index = $5, usable_index = $6, manifest = $7, manifest_sig = $8, \
             manifest_key_id = $9, \
             pe_arch = COALESCE($10, pe_arch), pe_arch_source = COALESCE($11, pe_arch_source), \
             pe_kit_version = COALESCE($12, pe_kit_version), \
             pe_kit_version_source = COALESCE($13, pe_kit_version_source) \
             WHERE id = $1 AND state = 'checking' AND kind IN ('image', 'pe')",
            &[
                &uid,
                &r.at.as_micros(),
                &r.wim.compression.as_str(),
                &to_i32(r.wim.image_count, "image_count")?,
                &to_i32(r.wim.boot_index, "boot_index")?,
                &usable,
                &r.manifest.payload,
                &r.manifest.signature,
                &r.manifest.key_id.0.0.as_slice(),
                &pe_arch,
                &pe_arch_src,
                &pe_kit,
                &pe_kit_src,
            ],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "content", &uid).await);
    }
    for e in &r.editions {
        let total = e
            .total_bytes
            .map(|v| to_i64(v, "total_bytes"))
            .transpose()?;
        tx.execute(
            "insert edition",
            "INSERT INTO edition (content_id, idx, name, description, total_bytes, support_status) \
             VALUES ($1, $2, $3, $4, $5, 'unknown')",
            &[
                &uid,
                &to_i32(e.index, "edition index")?,
                &check_text(e.name.as_str(), "edition name")?,
                &check_text(e.description.as_str(), "edition description")?,
                &total,
            ],
        )
        .await?;
    }
    Ok(())
}

// ------------------------------------------------------------ editions --

pub(crate) async fn editions(tx: &mut PgTx, id: ContentId) -> Result<Vec<EditionRow>, DbError> {
    let sql = format!("SELECT {EDITION_COLUMNS} FROM edition WHERE content_id = $1 ORDER BY idx");
    let rows = tx
        .query("list edition", &sql, &[&to_uuid(id.as_bytes())])
        .await?;
    rows.iter().map(edition_from_row).collect()
}

pub(crate) async fn edition(
    tx: &mut PgTx,
    id: ContentId,
    index: u32,
) -> Result<Option<EditionRow>, DbError> {
    let sql = format!("SELECT {EDITION_COLUMNS} FROM edition WHERE content_id = $1 AND idx = $2");
    let idx = to_i32(index, "edition index")?;
    let row = tx
        .query_opt("read edition", &sql, &[&to_uuid(id.as_bytes()), &idx])
        .await?;
    row.map(|r| edition_from_row(&r)).transpose()
}

pub(crate) async fn set_declaration(
    tx: &mut PgTx,
    id: ContentId,
    index: u32,
    d: &EditionDeclaration,
    support: SupportState,
    reason: Option<&str>,
) -> Result<(), DbError> {
    let reason = reason
        .map(|r| check_text(r, "support_reason"))
        .transpose()?;
    let n = tx
        .execute(
            "update edition declaration",
            "UPDATE edition SET decl_release = $3, decl_edition = $4, decl_arch = $5, \
             release_source = $6, edition_source = $7, arch_source = $8, declared_by = $9, \
             declared_at_us = $10, declared_audit_seq = $11, support_status = $12, \
             support_reason = $13 WHERE content_id = $1 AND idx = $2",
            &[
                &to_uuid(id.as_bytes()),
                &to_i32(index, "edition index")?,
                &d.facts.release.value.as_str(),
                &d.facts.edition.value.as_str(),
                &d.facts.architecture.value.as_str(),
                &d.facts.release.source.as_str(),
                &d.facts.edition.source.as_str(),
                &d.facts.architecture.source.as_str(),
                &to_uuid(d.declared_by.as_bytes()),
                &d.declared_at.as_micros(),
                &to_i64(d.declared_audit_seq, "declared_audit_seq")?,
                &support.as_str(),
                &reason,
            ],
        )
        .await?;
    if n == 0 {
        return Err(DbError::NotFound { what: "edition" });
    }
    Ok(())
}

// ------------------------------------------------------------- uploads --

pub(crate) async fn upload(
    tx: &mut PgTx,
    id: UploadId,
    lock: bool,
) -> Result<Option<Upload>, DbError> {
    let sql = format!(
        "SELECT {UPLOAD_COLUMNS} FROM upload WHERE id = $1{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = tx
        .query_opt("read upload", &sql, &[&to_uuid(id.as_bytes())])
        .await?;
    row.map(|r| upload_from_row(&r)).transpose()
}

pub(crate) async fn list_uploads(
    tx: &mut PgTx,
    states: &[UploadState],
) -> Result<Vec<Upload>, DbError> {
    let states = if states.is_empty() {
        UploadState::ALL
    } else {
        states
    };
    let st = texts(states, UploadState::as_str);
    let sql = format!(
        "SELECT {UPLOAD_COLUMNS} FROM upload WHERE state = ANY($1) ORDER BY created_at_us, id"
    );
    let rows = tx.query("list upload", &sql, &[&st]).await?;
    rows.iter().map(upload_from_row).collect()
}

/// Advisory-lock key for upload-quota decisions (an arbitrary constant
/// owned by this schema: ASCII "usgpuplq").
pub(crate) const UPLOAD_QUOTA_LOCK_KEY: i64 = 0x7573_6770_7570_6c71;

pub(crate) async fn lock_upload_quota(tx: &mut PgTx) -> Result<(), DbError> {
    // Transaction-scoped: released at COMMIT or ROLLBACK. Not a state
    // change, so it is a query, not an `execute` (no audit required).
    tx.query_opt(
        "lock upload quota",
        "SELECT pg_advisory_xact_lock($1)",
        &[&UPLOAD_QUOTA_LOCK_KEY],
    )
    .await?;
    Ok(())
}

pub(crate) async fn count_active(
    tx: &mut PgTx,
    operator: Option<OperatorId>,
) -> Result<u64, DbError> {
    let op = operator.map(|o| to_uuid(o.as_bytes()));
    let row = tx
        .query_opt(
            "count upload",
            "SELECT count(*) AS n FROM upload WHERE state IN ('open', 'streaming') \
             AND ($1::uuid IS NULL OR operator_id = $1)",
            &[&op],
        )
        .await?;
    match row {
        Some(r) => col_u64(&r, "n"),
        None => Ok(0),
    }
}

pub(crate) async fn set_upload_state(
    tx: &mut PgTx,
    id: UploadId,
    from: &[UploadState],
    to: UploadState,
) -> Result<(), DbError> {
    let from = texts(from, UploadState::as_str);
    let uid = to_uuid(id.as_bytes());
    let n = tx
        .execute(
            "update upload state",
            "UPDATE upload SET state = $2 WHERE id = $1 AND state = ANY($3)",
            &[&uid, &to.as_str(), &from],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "upload", &uid).await);
    }
    Ok(())
}

// ----------------------------------------------- archive content (M4) --

const ARCHIVE_COLUMNS: &str = "id, kind, display_name, file_name, size, sha256, state, \
     reason_code, reason_text, created_by, initiating_audit_seq, created_at_us, updated_at_us, \
     ready_at_us, manifest_schema, archive_format, archive_entries, archive_expanded_bytes, \
     manifest, manifest_sig, manifest_key_id";

/// The archive kinds (migration 0005).
const ARCHIVE_KINDS: &str = "kind IN ('driver_archive', 'agent_package')";

/// Checks a v2 manifest payload against the row it is (or will be)
/// stored with, and returns the archive facts it states.
pub(crate) fn archive_facts_of(
    payload: &[u8],
    id: ContentId,
    kind: ContentKindV2,
    size: u64,
    sha256: &Sha256Digest,
    ready_at: UnixMicros,
) -> Option<ArchiveFacts> {
    let m = ContentManifestV2::from_payload(payload).ok()?;
    (m.content_id == id
        && m.kind == kind
        && m.size == size
        && m.sha256 == *sha256
        && m.ready_at == ready_at)
        .then_some(ArchiveFacts {
            format: m.archive.format,
            entries: m.archive.entries,
            expanded_bytes: m.archive.expanded_bytes,
        })
}

fn archive_from_row(r: &Row) -> Result<ArchiveContent, DbError> {
    let schema: i16 = col(r, "manifest_schema")?;
    if schema != 2 {
        return Err(DbError::Corrupt {
            what: "manifest_schema",
        });
    }
    let reason_code: Option<String> = col(r, "reason_code")?;
    let reason_text: Option<String> = col(r, "reason_text")?;
    let reason = reason_code.map(|code| Reason {
        code,
        text: reason_text.unwrap_or_default(),
    });
    let format = col_opt_enum(r, "archive_format", ArchiveFormat::parse)?;
    let entries = col_opt_u32(r, "archive_entries")?;
    let expanded = col_opt_u64(r, "archive_expanded_bytes")?;
    let archive = match (format, entries, expanded) {
        (Some(format), Some(entries), Some(expanded_bytes)) => Some(ArchiveFacts {
            format,
            entries,
            expanded_bytes,
        }),
        (None, None, None) => None,
        _ => {
            return Err(DbError::Corrupt {
                what: "archive facts",
            });
        }
    };
    let payload: Option<Vec<u8>> = col(r, "manifest")?;
    let sig: Option<Vec<u8>> = col(r, "manifest_sig")?;
    let key = col_opt_key_id(r, "manifest_key_id")?;
    let c = ArchiveContent {
        id: col_id(r, "id", ContentId::from_bytes)?,
        kind: col_enum(r, "kind", ContentKindV2::parse)?,
        display_name: col_text(r, "display_name", DisplayName::new)?,
        file_name: col_text(r, "file_name", FileName::new)?,
        size: col_u64(r, "size")?,
        sha256: col_digest(r, "sha256")?,
        state: col_enum(r, "state", ContentState::parse)?,
        reason,
        created_by: col_id(r, "created_by", OperatorId::from_bytes)?,
        initiating_audit_seq: col_opt_u64(r, "initiating_audit_seq")?,
        created_at: col_micros(r, "created_at_us")?,
        updated_at: col_micros(r, "updated_at_us")?,
        ready_at: col_opt_micros(r, "ready_at_us")?,
        archive,
        manifest: stored_manifest(payload, sig, key)?,
    };
    check_archive(&c)?;
    Ok(c)
}

/// Re-validates a stored archive item: a stored manifest must parse as a
/// v2 manifest of this item and state the stored facts (SI-7, SI-10).
pub(crate) fn check_archive(c: &ArchiveContent) -> Result<(), DbError> {
    match (&c.manifest, c.ready_at) {
        (Some(m), Some(at)) => {
            let facts = archive_facts_of(&m.payload, c.id, c.kind, c.size, &c.sha256, at);
            if facts.is_none() || facts != c.archive {
                return Err(DbError::Corrupt {
                    what: "archive manifest",
                });
            }
        }
        (None, _) if c.archive.is_none() && c.state != ContentState::Ready => {}
        _ => {
            return Err(DbError::Corrupt {
                what: "archive manifest",
            });
        }
    }
    Ok(())
}

pub(crate) async fn archive_get(
    tx: &mut PgTx,
    id: ContentId,
    lock: bool,
) -> Result<Option<ArchiveContent>, DbError> {
    let sql = format!(
        "SELECT {ARCHIVE_COLUMNS} FROM content WHERE id = $1 AND {ARCHIVE_KINDS}{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = tx
        .query_opt("read archive content", &sql, &[&to_uuid(id.as_bytes())])
        .await?;
    row.map(|r| archive_from_row(&r)).transpose()
}

pub(crate) async fn archive_by_sha256(
    tx: &mut PgTx,
    sha: &Sha256Digest,
) -> Result<Option<ArchiveContent>, DbError> {
    let sql = format!(
        "SELECT {ARCHIVE_COLUMNS} FROM content \
         WHERE sha256 = $1 AND state IN ('receiving', 'checking', 'ready') AND {ARCHIVE_KINDS}"
    );
    let row = tx
        .query_opt("read archive content", &sql, &[&sha.0.as_slice()])
        .await?;
    row.map(|r| archive_from_row(&r)).transpose()
}

pub(crate) async fn archive_list(
    tx: &mut PgTx,
    kind: Option<ContentKindV2>,
    states: &[ContentState],
) -> Result<Vec<ArchiveContent>, DbError> {
    let states = if states.is_empty() {
        ContentState::ALL
    } else {
        states
    };
    let st = texts(states, ContentState::as_str);
    let kind = kind.map(ContentKindV2::as_str);
    let sql = format!(
        "SELECT {ARCHIVE_COLUMNS} FROM content \
         WHERE ($1::text IS NULL OR kind = $1) AND state = ANY($2) AND {ARCHIVE_KINDS} \
         ORDER BY created_at_us, id"
    );
    let rows = tx
        .query("list archive content", &sql, &[&kind, &st])
        .await?;
    rows.iter().map(archive_from_row).collect()
}

pub(crate) async fn archive_create_upload(
    tx: &mut PgTx,
    c: &NewArchiveContent,
    u: &Upload,
) -> Result<(), DbError> {
    if u.content_id != c.id || u.declared_size != c.size || u.declared_sha256 != c.sha256 {
        return Err(DbError::InvalidArgument {
            what: "upload does not match content",
        });
    }
    let initiating = c
        .initiating_audit_seq
        .map(|s| to_i64(s, "initiating_audit_seq"))
        .transpose()?;
    tx.execute(
        "insert archive content",
        "INSERT INTO content (id, kind, display_name, file_name, size, sha256, state, \
         created_by, initiating_audit_seq, created_at_us, updated_at_us, manifest_schema) \
         VALUES ($1, $2, $3, $4, $5, $6, 'receiving', $7, $8, $9, $9, 2)",
        &[
            &to_uuid(c.id.as_bytes()),
            &c.kind.as_str(),
            &c.display_name.as_str(),
            &c.file_name.as_str(),
            &to_i64(c.size, "size")?,
            &c.sha256.0.as_slice(),
            &to_uuid(c.created_by.as_bytes()),
            &initiating,
            &c.created_at.as_micros(),
        ],
    )
    .await?;
    insert_upload(tx, u).await
}

async fn insert_upload(tx: &mut PgTx, u: &Upload) -> Result<(), DbError> {
    tx.execute(
        "insert upload",
        &format!(
            "INSERT INTO upload ({UPLOAD_COLUMNS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
        ),
        &[
            &to_uuid(u.id.as_bytes()),
            &to_uuid(u.content_id.as_bytes()),
            &to_uuid(u.operator_id.as_bytes()),
            &to_i64(u.declared_size, "declared_size")?,
            &u.declared_sha256.0.as_slice(),
            &u.state.as_str(),
            &check_text(&u.staging_name, "staging_name")?,
            &u.created_at.as_micros(),
            &u.expires_at.as_micros(),
        ],
    )
    .await?;
    Ok(())
}

pub(crate) async fn archive_set_ready(
    tx: &mut PgTx,
    id: ContentId,
    r: &ReadyArchiveContent,
) -> Result<(), DbError> {
    let Some(cur) = archive_get(tx, id, true).await? else {
        return Err(DbError::NotFound { what: "content" });
    };
    if cur.state != ContentState::Checking {
        return Err(DbError::Conflict { what: "content" });
    }
    let facts = archive_facts_of(
        &r.manifest.payload,
        cur.id,
        cur.kind,
        cur.size,
        &cur.sha256,
        r.at,
    )
    .ok_or(DbError::InvalidArgument {
        what: "manifest does not describe this content",
    })?;
    let uid = to_uuid(id.as_bytes());
    let n = tx
        .execute(
            "update archive content ready",
            "UPDATE content SET state = 'ready', reason_code = NULL, reason_text = NULL, \
             updated_at_us = $2, ready_at_us = $2, archive_format = $3, archive_entries = $4, \
             archive_expanded_bytes = $5, manifest = $6, manifest_sig = $7, manifest_key_id = $8 \
             WHERE id = $1 AND state = 'checking' AND kind IN ('driver_archive', 'agent_package')",
            &[
                &uid,
                &r.at.as_micros(),
                &facts.format.as_str(),
                &to_i32(facts.entries, "archive entries")?,
                &to_i64(facts.expanded_bytes, "archive expanded bytes")?,
                &r.manifest.payload,
                &r.manifest.signature,
                &r.manifest.key_id.0.0.as_slice(),
            ],
        )
        .await?;
    if n == 0 {
        return Err(cas_miss(tx, "content", &uid).await);
    }
    Ok(())
}
