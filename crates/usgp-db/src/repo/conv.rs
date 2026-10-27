//! Column conversions. Writes check ranges (`u64` → `bigint`, `u32` →
//! `integer`) and refuse with [`DbError::InvalidArgument`]; reads
//! re-validate every value and refuse with [`DbError::Corrupt`]. No
//! unchecked `as` casts, no panicking `Row::get`.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - stored rows are
//   untrusted input on read.

use tokio_postgres::Row;
use tokio_postgres::types::FromSql;
use usgp_common::Sha256Digest;
use usgp_crypto::KeyId;
use usgp_proto::UnixMicros;

use crate::error::DbError;

/// `u64` to a `bigint` parameter.
pub(crate) fn to_i64(v: u64, what: &'static str) -> Result<i64, DbError> {
    i64::try_from(v).map_err(|_| DbError::InvalidArgument { what })
}

/// `u32` to an `integer` parameter.
pub(crate) fn to_i32(v: u32, what: &'static str) -> Result<i32, DbError> {
    i32::try_from(v).map_err(|_| DbError::InvalidArgument { what })
}

/// 16 id bytes as a `uuid` parameter.
pub(crate) fn to_uuid(bytes: &[u8; 16]) -> uuid::Uuid {
    uuid::Uuid::from_bytes(*bytes)
}

/// Text for a `text` column: PostgreSQL cannot store U+0000.
pub(crate) fn check_text<'a>(s: &'a str, what: &'static str) -> Result<&'a str, DbError> {
    if s.contains('\0') {
        return Err(DbError::InvalidArgument { what });
    }
    Ok(s)
}

/// A column value of type `T`.
pub(crate) fn col<'a, T: FromSql<'a>>(row: &'a Row, name: &'static str) -> Result<T, DbError> {
    row.try_get::<_, T>(name)
        .map_err(|_| DbError::Corrupt { what: name })
}

/// A non-negative `bigint` as `u64`.
pub(crate) fn col_u64(row: &Row, name: &'static str) -> Result<u64, DbError> {
    let v: i64 = col(row, name)?;
    u64::try_from(v).map_err(|_| DbError::Corrupt { what: name })
}

/// A nullable non-negative `bigint` as `u64`.
pub(crate) fn col_opt_u64(row: &Row, name: &'static str) -> Result<Option<u64>, DbError> {
    let v: Option<i64> = col(row, name)?;
    v.map(|v| u64::try_from(v).map_err(|_| DbError::Corrupt { what: name }))
        .transpose()
}

/// A non-negative `integer` as `u32`.
pub(crate) fn col_u32(row: &Row, name: &'static str) -> Result<u32, DbError> {
    let v: i32 = col(row, name)?;
    u32::try_from(v).map_err(|_| DbError::Corrupt { what: name })
}

/// A nullable non-negative `integer` as `u32`.
pub(crate) fn col_opt_u32(row: &Row, name: &'static str) -> Result<Option<u32>, DbError> {
    let v: Option<i32> = col(row, name)?;
    v.map(|v| u32::try_from(v).map_err(|_| DbError::Corrupt { what: name }))
        .transpose()
}

/// A `bigint` microsecond timestamp.
pub(crate) fn col_micros(row: &Row, name: &'static str) -> Result<UnixMicros, DbError> {
    let v: i64 = col(row, name)?;
    UnixMicros::new(v).map_err(|_| DbError::Corrupt { what: name })
}

/// A nullable `bigint` microsecond timestamp.
pub(crate) fn col_opt_micros(row: &Row, name: &'static str) -> Result<Option<UnixMicros>, DbError> {
    let v: Option<i64> = col(row, name)?;
    v.map(|v| UnixMicros::new(v).map_err(|_| DbError::Corrupt { what: name }))
        .transpose()
}

/// 32 bytes from a `bytea`.
pub(crate) fn bytes32(v: &[u8], name: &'static str) -> Result<[u8; 32], DbError> {
    <[u8; 32]>::try_from(v).map_err(|_| DbError::Corrupt { what: name })
}

/// A SHA-256 `bytea` column.
pub(crate) fn col_digest(row: &Row, name: &'static str) -> Result<Sha256Digest, DbError> {
    let v: &[u8] = col(row, name)?;
    Ok(Sha256Digest(bytes32(v, name)?))
}

/// A nullable key-id `bytea` column.
pub(crate) fn col_opt_key_id(row: &Row, name: &'static str) -> Result<Option<KeyId>, DbError> {
    let v: Option<&[u8]> = col(row, name)?;
    v.map(|b| Ok(KeyId(Sha256Digest(bytes32(b, name)?))))
        .transpose()
}

/// A `uuid` column as one of the proto id types.
pub(crate) fn col_id<T, E>(
    row: &Row,
    name: &'static str,
    from: impl Fn([u8; 16]) -> Result<T, E>,
) -> Result<T, DbError> {
    let u: uuid::Uuid = col(row, name)?;
    from(*u.as_bytes()).map_err(|_| DbError::Corrupt { what: name })
}

/// A nullable `uuid` column as one of the proto id types.
pub(crate) fn col_opt_id<T, E>(
    row: &Row,
    name: &'static str,
    from: impl Fn([u8; 16]) -> Result<T, E>,
) -> Result<Option<T>, DbError> {
    let u: Option<uuid::Uuid> = col(row, name)?;
    u.map(|u| from(*u.as_bytes()).map_err(|_| DbError::Corrupt { what: name }))
        .transpose()
}

/// A `text` column parsed into a closed value set.
pub(crate) fn col_enum<T>(
    row: &Row,
    name: &'static str,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<T, DbError> {
    let s: &str = col(row, name)?;
    parse(s).ok_or(DbError::Corrupt { what: name })
}

/// A nullable `text` column parsed into a closed value set.
pub(crate) fn col_opt_enum<T>(
    row: &Row,
    name: &'static str,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<Option<T>, DbError> {
    let s: Option<&str> = col(row, name)?;
    s.map(|s| parse(s).ok_or(DbError::Corrupt { what: name }))
        .transpose()
}

/// A `text` column through a validating constructor.
pub(crate) fn col_text<T, E>(
    row: &Row,
    name: &'static str,
    new: impl Fn(String) -> Result<T, E>,
) -> Result<T, DbError> {
    let s: String = col(row, name)?;
    new(s).map_err(|_| DbError::Corrupt { what: name })
}

/// Lists of state texts for `= ANY($n)` parameters.
pub(crate) fn texts<T: Copy>(
    values: &[T],
    as_str: impl Fn(T) -> &'static str,
) -> Vec<&'static str> {
    values.iter().map(|v| as_str(*v)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_checks() {
        assert!(to_i64(u64::MAX, "size").is_err());
        assert_eq!(to_i64(5, "size").unwrap(), 5);
        assert!(to_i32(u32::MAX, "idx").is_err());
        assert!(check_text("a\0b", "name").is_err());
        assert!(bytes32(&[0; 31], "d").is_err());
        assert!(bytes32(&[0; 32], "d").is_ok());
    }
}
