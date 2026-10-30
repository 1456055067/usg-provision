//! Administrator password escrow bodies (M4 plan sections 1.3 and 3.1).
//!
//! | Route | Body | Response |
//! |---|---|---|
//! | `POST /v1/device/jobs/{id}/escrow` | [`EscrowSubmitV1`] | `201` |
//! | `POST /v1/device/jobs/{id}/escrow/confirm` | [`EscrowConfirmV1`] | `200` |
//!
//! The device seals the password to the server's escrow key with
//! `usgp_crypto` (ECDH P-384 one-pass, HKDF-SHA-384, AES-256-GCM) before
//! anything here is built; these bodies carry only the sealed form, never
//! the password. `Debug` shows lengths only, so neither the ciphertext nor
//! the ephemeral key reaches a log through `{:?}`.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-28, SC-28(1) (Protection of Information at Rest;
//   Cryptographic Protection) - only ciphertext is carried and stored.
// - NIST 800-53: IA-5(1) (Authenticator Management, basis) - the device
//   generates the password; the server never sends one.
// - NIST 800-53: SI-10 - exact lengths for the nonce and point, bounded
//   ciphertext, closed account set, strict parse.
// - SPEC: specs/configuration.md (administrator password escrow)
// - DECISION: docs/decisions/0024, 0025 item 2 (RID 500 account)
// - SP 800-56A Rev 3 C(1e,1s), SP 800-38D (GCM 96-bit nonce, 128-bit
//   tag), RFC 5480 §2.2 (uncompressed point)

use usgp_common::Sha256Digest;

use crate::b64::B64Bytes;
use crate::error_code::ErrorCode;
use crate::job_plan::EscrowAccount;
use crate::limits::MAX_ESCROW_CT_BYTES;

/// Length of an uncompressed P-384 point (`0x04 || X || Y`, RFC 5480
/// §2.2; SEC 1 §2.3.3).
pub const P384_POINT_LEN: usize = 97;

/// Length of an AES-GCM nonce (SP 800-38D §8.2, 96 bits).
pub const GCM_NONCE_LEN: usize = 12;

/// Smallest ciphertext: 1 byte of plaintext plus the 16-byte GCM tag.
pub const MIN_ESCROW_CT_BYTES: usize = 17;

/// Why an escrow body was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EscrowDataError {
    /// The ephemeral key is not an uncompressed point.
    #[error("eph_pub_b64 must be an uncompressed P-384 point")]
    NotUncompressedPoint,
    /// `set` is false without a code, or true with one.
    #[error("code is required when set is false and not allowed when set is true")]
    CodeMismatch,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EscrowSubmitWire {
    key_id: Sha256Digest,
    eph_pub_b64: B64Bytes<P384_POINT_LEN, P384_POINT_LEN>,
    nonce_b64: B64Bytes<GCM_NONCE_LEN, GCM_NONCE_LEN>,
    ct_b64: B64Bytes<MIN_ESCROW_CT_BYTES, MAX_ESCROW_CT_BYTES>,
    account: EscrowAccount,
}

/// `POST /v1/device/jobs/{id}/escrow` body (resume token). The server
/// requires `key_id` to equal the plan's escrow key id and refuses a
/// second submission for the job (409).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "EscrowSubmitWire")]
pub struct EscrowSubmitV1 {
    /// Escrow key id the password was sealed to.
    pub key_id: Sha256Digest,
    /// Ephemeral ECDH public key, uncompressed point (97 bytes).
    pub eph_pub_b64: B64Bytes<P384_POINT_LEN, P384_POINT_LEN>,
    /// AES-GCM nonce (12 bytes).
    pub nonce_b64: B64Bytes<GCM_NONCE_LEN, GCM_NONCE_LEN>,
    /// Ciphertext with the tag (17 to 512 bytes).
    pub ct_b64: B64Bytes<MIN_ESCROW_CT_BYTES, MAX_ESCROW_CT_BYTES>,
    /// The account.
    pub account: EscrowAccount,
}

impl TryFrom<EscrowSubmitWire> for EscrowSubmitV1 {
    type Error = EscrowDataError;

    fn try_from(w: EscrowSubmitWire) -> Result<Self, Self::Error> {
        let s = Self {
            key_id: w.key_id,
            eph_pub_b64: w.eph_pub_b64,
            nonce_b64: w.nonce_b64,
            ct_b64: w.ct_b64,
            account: w.account,
        };
        s.validate()?;
        Ok(s)
    }
}

impl EscrowSubmitV1 {
    /// Checks the point form (the point itself is checked by
    /// `usgp-crypto` when the server opens the escrow).
    ///
    /// # Errors
    ///
    /// [`EscrowDataError::NotUncompressedPoint`].
    pub fn validate(&self) -> Result<(), EscrowDataError> {
        if self.eph_pub_b64.as_bytes().first() != Some(&0x04) {
            return Err(EscrowDataError::NotUncompressedPoint);
        }
        Ok(())
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EscrowConfirmWire {
    set: bool,
    #[serde(default)]
    code: Option<ErrorCode>,
}

/// `POST /v1/device/jobs/{id}/escrow/confirm` body (resume token): whether
/// the password was set on the account; when not, why
/// (`admin_password_set_failed:<win32>`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "EscrowConfirmWire")]
pub struct EscrowConfirmV1 {
    /// `true` once the password is set and the account enabled.
    pub set: bool,
    /// The reason, on and only on `set: false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<ErrorCode>,
}

impl TryFrom<EscrowConfirmWire> for EscrowConfirmV1 {
    type Error = EscrowDataError;

    fn try_from(w: EscrowConfirmWire) -> Result<Self, Self::Error> {
        let c = Self {
            set: w.set,
            code: w.code,
        };
        c.validate()?;
        Ok(c)
    }
}

impl EscrowConfirmV1 {
    /// Checks that a code comes with, and only with, `set: false`.
    ///
    /// # Errors
    ///
    /// [`EscrowDataError::CodeMismatch`].
    pub fn validate(&self) -> Result<(), EscrowDataError> {
        if self.set == self.code.is_some() {
            return Err(EscrowDataError::CodeMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding};

    use super::*;

    fn submit_json(point_head: u8, nonce_len: usize, ct_len: usize, account: &str) -> String {
        let mut point = vec![point_head];
        point.extend_from_slice(&[0x11; P384_POINT_LEN - 1]);
        format!(
            r#"{{"key_id":"{}","eph_pub_b64":"{}","nonce_b64":"{}","ct_b64":"{}","account":"{account}"}}"#,
            "ab".repeat(32),
            Base64::encode_string(&point),
            Base64::encode_string(&vec![1; nonce_len]),
            Base64::encode_string(&vec![2; ct_len]),
        )
    }

    #[test]
    fn submit_rules() {
        let ok: EscrowSubmitV1 =
            serde_json::from_str(&submit_json(4, 12, 40, "administrator")).unwrap();
        let back = serde_json::to_string(&ok).unwrap();
        assert_eq!(serde_json::from_str::<EscrowSubmitV1>(&back).unwrap(), ok);
        let dbg = format!("{ok:?}");
        assert!(dbg.contains("<40 bytes>") && !dbg.contains("AgIC"), "{dbg}");

        for bad in [
            submit_json(2, 12, 40, "administrator"),
            submit_json(4, 11, 40, "administrator"),
            submit_json(4, 12, 16, "administrator"),
            submit_json(4, 12, 513, "administrator"),
            submit_json(4, 12, 40, "Administrator"),
            submit_json(4, 12, 40, "guest"),
        ] {
            assert!(
                serde_json::from_str::<EscrowSubmitV1>(&bad).is_err(),
                "{bad}"
            );
        }
        let extra = submit_json(4, 12, 40, "administrator").replace('}', r#","pt":"x"}"#);
        assert!(serde_json::from_str::<EscrowSubmitV1>(&extra).is_err());
    }

    #[test]
    fn confirm_rules() {
        let p = |s: &str| serde_json::from_str::<EscrowConfirmV1>(s);
        assert!(p(r#"{"set":true}"#).is_ok());
        assert!(p(r#"{"set":false,"code":"admin_password_set_failed:5"}"#).is_ok());
        assert!(p(r#"{"set":false}"#).is_err());
        assert!(p(r#"{"set":true,"code":"x"}"#).is_err());
        assert!(p(r#"{"set":false,"code":"Bad Code"}"#).is_err());
        assert_eq!(
            serde_json::to_string(&p(r#"{"set":true}"#).unwrap()).unwrap(),
            r#"{"set":true}"#
        );
    }
}
