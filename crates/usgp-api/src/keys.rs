//! The M3 server keys: the job-plan signing key, the boot-policy signing
//! key and the operator-code HMAC key (plan M3 section 5).
//!
//! One key, one purpose: the plan and boot-policy keys must differ from
//! each other and from the content key ([`crate::ApiBuilder::build`]
//! refuses otherwise). The keys come from trusted files read by
//! `usgp-server` (WU-10); this crate never reads key files. `Debug` shows
//! key ids only.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-12 (Cryptographic Key Establishment and Management) -
//   separate keys per purpose; secret keys never printed.
// - NIST 800-53: SC-13 (Cryptographic Protection) - ECDSA P-384/SHA-384
//   and HMAC-SHA-256 in the FIPS module via usgp-crypto.
// - NIST 800-53: IA-5 (Authenticator Management) - codes stored only as
//   their HMAC; the value is never kept.
// - NIST 800-53: SI-7(6) - plans and boot-policy lists are signed.
// - SPEC: specs/targeting.md#REQ-TGT-013 (single-use code);
//   specs/boot-network.md#REQ-BOOT-067 (signed stop list)
// - Decisions 0001, 0018 item 1, 0021 item 2

use usgp_crypto::{CryptoError, HmacKey, HmacTag, KeyId, SigningKey, sign_typed};
use usgp_db::StoredManifest;
use usgp_proto::{AuthCode, PayloadType};

use crate::error::ApiInitError;

/// The plan, boot-policy and code keys.
pub struct ProvisioningKeys {
    plan: SigningKey,
    boot_policy: SigningKey,
    code_hmac: HmacKey,
}

impl std::fmt::Debug for ProvisioningKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvisioningKeys")
            .field("plan_key_id", &self.plan.key_id())
            .field("boot_policy_key_id", &self.boot_policy.key_id())
            .field("code_hmac", &"<redacted>")
            .finish()
    }
}

impl ProvisioningKeys {
    /// The three keys.
    ///
    /// # Errors
    ///
    /// [`ApiInitError::KeyReuse`] if the plan and boot-policy keys are the
    /// same key.
    pub fn new(
        plan: SigningKey,
        boot_policy: SigningKey,
        code_hmac: HmacKey,
    ) -> Result<Self, ApiInitError> {
        if plan.key_id() == boot_policy.key_id() {
            return Err(ApiInitError::KeyReuse);
        }
        Ok(Self {
            plan,
            boot_policy,
            code_hmac,
        })
    }

    /// The plan key id (`server.start`, job records).
    #[must_use]
    pub fn plan_key_id(&self) -> KeyId {
        self.plan.key_id()
    }

    /// The boot-policy key id.
    #[must_use]
    pub fn boot_policy_key_id(&self) -> KeyId {
        self.boot_policy.key_id()
    }

    /// Signs a job-plan payload.
    pub(crate) fn sign_plan(&self, payload: Vec<u8>) -> Result<StoredManifest, CryptoError> {
        sign(&self.plan, PayloadType::JobPlanV1, payload)
    }

    /// Signs a boot-policy payload.
    pub(crate) fn sign_boot_policy(&self, payload: Vec<u8>) -> Result<StoredManifest, CryptoError> {
        sign(&self.boot_policy, PayloadType::BootPolicyV1, payload)
    }

    /// The stored form of a code: HMAC-SHA-256 of its 10 canonical
    /// symbols under the code key (plan section 5).
    pub(crate) fn code_tag(&self, code: &AuthCode) -> HmacTag {
        self.code_hmac.sign(code.normalized().as_bytes())
    }
}

fn sign(
    key: &SigningKey,
    ty: PayloadType,
    payload: Vec<u8>,
) -> Result<StoredManifest, CryptoError> {
    let signature = sign_typed(key, ty.as_str(), &payload)?;
    Ok(StoredManifest {
        payload,
        signature,
        key_id: key.key_id(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_key_one_purpose_and_redacted() {
        let k = SigningKey::generate().unwrap();
        let same = SigningKey::from_pkcs8_der(&k.to_pkcs8_der().unwrap()).unwrap();
        let hmac = HmacKey::from_bytes(&[7; 32]).unwrap();
        assert!(matches!(
            ProvisioningKeys::new(k, same, hmac),
            Err(ApiInitError::KeyReuse)
        ));
        let keys = ProvisioningKeys::new(
            SigningKey::generate().unwrap(),
            SigningKey::generate().unwrap(),
            HmacKey::from_bytes(&[7; 32]).unwrap(),
        )
        .unwrap();
        let d = format!("{keys:?}");
        assert!(d.contains("<redacted>") && !d.contains("PRIVATE"));
        // Case and separators do not change the stored tag.
        let a = AuthCode::parse("ABCDE-FGHJK").unwrap();
        let b = AuthCode::parse("abcdefghjk").unwrap();
        assert_eq!(keys.code_tag(&a), keys.code_tag(&b));
    }
}
