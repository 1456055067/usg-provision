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

use usgp_crypto::{CryptoError, EscrowKey, HmacKey, HmacTag, KeyId, SigningKey, sign_typed};
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

    /// Signs a v2 job-plan payload (M4).
    pub(crate) fn sign_plan_v2(&self, payload: Vec<u8>) -> Result<StoredManifest, CryptoError> {
        sign(&self.plan, PayloadType::JobPlanV2, payload)
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

/// Most retired escrow keys kept for opening only (M4 plan section 1.3).
pub const MAX_RETIRED_ESCROW_KEYS: usize = 8;

/// The escrow keys (M4 plan section 1.3): the current ECDH P-384 key, whose
/// public half goes into every v2 plan, and up to
/// [`MAX_RETIRED_ESCROW_KEYS`] retired keys used only to open escrows
/// sealed to them. One purpose only. `Debug` shows key ids.
// COMPLIANCE MAPPING:
// - NIST 800-53: SC-12 - one key per purpose; rotation keeps retired keys
//   for decryption only; SC-28 - only the server can open an escrow.
// - Decision 0024 item 1
pub struct EscrowKeys {
    current: EscrowKey,
    retired: Vec<EscrowKey>,
}

impl std::fmt::Debug for EscrowKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EscrowKeys")
            .field("current_key_id", &self.current.key_id())
            .field(
                "retired_key_ids",
                &self
                    .retired
                    .iter()
                    .map(EscrowKey::key_id)
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl EscrowKeys {
    /// The current key and the retired ones.
    ///
    /// # Errors
    ///
    /// [`ApiInitError::KeyReuse`] if a key appears twice, or
    /// [`ApiInitError::TooManyRetiredKeys`] above
    /// [`MAX_RETIRED_ESCROW_KEYS`].
    pub fn new(current: EscrowKey, retired: Vec<EscrowKey>) -> Result<Self, ApiInitError> {
        if retired.len() > MAX_RETIRED_ESCROW_KEYS {
            return Err(ApiInitError::TooManyRetiredKeys);
        }
        let mut ids = vec![current.key_id()];
        for k in &retired {
            let id = k.key_id();
            if ids.contains(&id) {
                return Err(ApiInitError::KeyReuse);
            }
            ids.push(id);
        }
        Ok(Self { current, retired })
    }

    /// The key new plans name.
    #[must_use]
    pub fn current(&self) -> &EscrowKey {
        &self.current
    }

    /// The key (current or retired) with this id.
    #[must_use]
    pub fn by_id(&self, id: &KeyId) -> Option<&EscrowKey> {
        std::iter::once(&self.current)
            .chain(&self.retired)
            .find(|k| k.key_id() == *id)
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

    #[test]
    fn escrow_keys_distinct_bounded_and_redacted() {
        let k = EscrowKey::generate().unwrap();
        let same = EscrowKey::from_pkcs8_der(&k.to_pkcs8_der().unwrap()).unwrap();
        assert!(matches!(
            EscrowKeys::new(k, vec![same]),
            Err(ApiInitError::KeyReuse)
        ));
        let many = (0..=MAX_RETIRED_ESCROW_KEYS)
            .map(|_| EscrowKey::generate().unwrap())
            .collect();
        assert!(matches!(
            EscrowKeys::new(EscrowKey::generate().unwrap(), many),
            Err(ApiInitError::TooManyRetiredKeys)
        ));
        let old = EscrowKey::generate().unwrap();
        let old_id = old.key_id();
        let keys = EscrowKeys::new(EscrowKey::generate().unwrap(), vec![old]).unwrap();
        assert!(keys.by_id(&old_id).is_some());
        assert!(keys.by_id(&keys.current().key_id()).is_some());
        let d = format!("{keys:?}");
        assert!(d.contains("current_key_id") && !d.contains("PRIVATE"));
    }
}
