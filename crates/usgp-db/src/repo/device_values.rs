//! Per-device values keyed by MAC (PostgreSQL; M4 plan section 3.2,
//! migration 0005), the `device.<key>` references of the answer-file
//! template.

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 - operator-set values, changed only in an audited
//   transaction.
// - NIST 800-53: SI-10 - key syntax, value bounds and count checked on
//   write and re-validated on read.
// - SPEC: specs/configuration.md#REQ-CFG-004

use std::collections::BTreeMap;

use tokio_postgres::Row;
use usgp_proto::{MacAddress, OperatorId};

use super::conv::{col, col_id, col_mac, col_micros, to_uuid};
use crate::error::DbError;
use crate::model::DeviceValues;
use crate::pool::PgTx;

/// Longest stored values document (the 0005 column bound).
const MAX_DEVICE_VALUES_TEXT: usize = 524_288;

fn from_row(r: &Row) -> Result<DeviceValues, DbError> {
    let text: String = col(r, "device_values")?;
    if text.len() > MAX_DEVICE_VALUES_TEXT {
        return Err(DbError::Corrupt {
            what: "device_values",
        });
    }
    let values: BTreeMap<String, String> =
        serde_json::from_str(&text).map_err(|_| DbError::Corrupt {
            what: "device_values",
        })?;
    let v = DeviceValues {
        mac: col_mac(r, "mac")?,
        values,
        updated_by: col_id(r, "updated_by", OperatorId::from_bytes)?,
        updated_at: col_micros(r, "updated_at_us")?,
    };
    if !v.valid() {
        return Err(DbError::Corrupt {
            what: "device_values",
        });
    }
    Ok(v)
}

/// Renders the values document after checking the bounds.
pub(crate) fn values_json(v: &DeviceValues) -> Result<String, DbError> {
    if !v.valid() {
        return Err(DbError::InvalidArgument {
            what: "device values",
        });
    }
    let s = serde_json::to_string(&v.values).map_err(|_| DbError::InvalidArgument {
        what: "device values",
    })?;
    if s.len() > MAX_DEVICE_VALUES_TEXT {
        return Err(DbError::InvalidArgument {
            what: "device values",
        });
    }
    Ok(s)
}

pub(crate) async fn get(tx: &mut PgTx, mac: MacAddress) -> Result<Option<DeviceValues>, DbError> {
    let row = tx
        .query_opt(
            "read device_value",
            "SELECT mac, device_values::text AS device_values, updated_by, updated_at_us \
             FROM device_value WHERE mac = $1",
            &[&mac.octets().as_slice()],
        )
        .await?;
    row.map(|r| from_row(&r)).transpose()
}

pub(crate) async fn set(tx: &mut PgTx, v: &DeviceValues) -> Result<(), DbError> {
    let json = values_json(v)?;
    tx.execute(
        "upsert device_value",
        "INSERT INTO device_value (mac, device_values, updated_by, updated_at_us) \
         VALUES ($1, $2::text::jsonb, $3, $4) \
         ON CONFLICT (mac) DO UPDATE SET device_values = EXCLUDED.device_values, \
         updated_by = EXCLUDED.updated_by, updated_at_us = EXCLUDED.updated_at_us",
        &[
            &v.mac.octets().as_slice(),
            &json,
            &to_uuid(v.updated_by.as_bytes()),
            &v.updated_at.as_micros(),
        ],
    )
    .await?;
    Ok(())
}

pub(crate) async fn delete(tx: &mut PgTx, mac: MacAddress) -> Result<(), DbError> {
    let n = tx
        .execute(
            "delete device_value",
            "DELETE FROM device_value WHERE mac = $1",
            &[&mac.octets().as_slice()],
        )
        .await?;
    if n == 0 {
        return Err(DbError::NotFound {
            what: "device values",
        });
    }
    Ok(())
}
