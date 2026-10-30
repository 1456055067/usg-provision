//! Verifying the signed job plan and its content manifest on the device
//! (plan section 3.2), with keys pinned in the agent's configuration.
//!
//! [`verify_plan`] runs the six checks of section 3.2 in order through
//! [`VerifiedJobPlan::verify`]: the plan signature (before any parse), the
//! payload type and schema, the nonce, the session, job and package, the
//! disk, and the content manifest (signature first, then the SHA-256 of its
//! exact payload, then its facts). Signatures are checked with
//! `usgp-crypto` (ECDSA P-384, FIPS 186-5) and digests with the
//! [`CryptoProvider`] (decision 0001). There is no expiry check against the
//! device clock; freshness comes from the nonce.
//!
//! Only a [`VerifiedJobPlan`] can start the engine, and the wipe
//! authorisation is built only from one (engine step 2).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7(6) (Cryptographic Protection) - plan and content
//   manifest signatures verified with pinned keys before use.
// - NIST 800-53: SC-13 (Cryptographic Protection) - ECDSA and SHA-256
//   through usgp-crypto's FIPS module.
// - NIST 800-53: SC-23 (Session Authenticity) - nonce, session, job and
//   disk binding.
// - SPEC: specs/preinstall-env.md#REQ-PE-016; specs/disk.md#REQ-DISK-006
// - SPEC: specs/targeting.md#REQ-TGT-015 (no secrets in the plan)
// - DECISION: docs/decisions/0001, 0011, 0020

use std::fmt;

use usgp_common::Sha256Digest;
use usgp_crypto::{CryptoProvider, VerifyingKey, verify_signing_input};
use usgp_proto::envelope::{SignatureAlg, SignatureVerifier, SignedEnvelopeV1};
use usgp_proto::job_plan::{
    PlanContentV2, PlanError, PlanExpectation, PlanExpectationV2, VerifiedJobPlan,
    VerifiedJobPlanV2,
};

/// One pinned ECDSA P-384 public key. Verifies only signatures that name
/// its own key id, with the one algorithm we use.
#[derive(Clone)]
pub struct PinnedKey {
    key: VerifyingKey,
    id: Sha256Digest,
}

impl PinnedKey {
    /// Pins `key`.
    #[must_use]
    pub fn new(key: VerifyingKey) -> Self {
        let id = key.key_id().0;
        Self { key, id }
    }

    /// The key id (SHA-256 of the SubjectPublicKeyInfo).
    #[must_use]
    pub fn key_id(&self) -> Sha256Digest {
        self.id
    }
}

impl fmt::Debug for PinnedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedKey").field("id", &self.id).finish()
    }
}

impl SignatureVerifier for PinnedKey {
    fn verify(
        &self,
        key_id: &Sha256Digest,
        alg: SignatureAlg,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        alg == SignatureAlg::EcdsaP384Sha384
            && *key_id == self.id
            && verify_signing_input(&self.key, message, signature).is_ok()
    }
}

/// The two keys the device trusts: the plan key and the content key
/// (from `agent.toml`; plan section 0 item 1). They are kept apart, so a
/// content-key signature never verifies a plan and the reverse.
#[derive(Debug, Clone)]
pub struct PlanKeys {
    /// Verifies job plans.
    pub plan: PinnedKey,
    /// Verifies content manifests.
    pub content: PinnedKey,
}

/// Runs the plan section 3.2 checks, in order, and stops at the first
/// failure. Nothing is written by the caller unless this succeeds.
///
/// # Errors
///
/// [`PlanError`] naming the check that failed (always an integrity
/// failure, REQ-JOB-005 item 3).
pub fn verify_plan(
    plan: &SignedEnvelopeV1,
    content: &SignedEnvelopeV1,
    keys: &PlanKeys,
    expect: &PlanExpectation<'_>,
    crypto: &dyn CryptoProvider,
) -> Result<VerifiedJobPlan, PlanError> {
    let sha256 = |b: &[u8]| crypto.sha256(b);
    VerifiedJobPlan::verify(plan, &keys.plan, content, &keys.content, &sha256, expect)
}

/// The v2 checks (`VerifiedJobPlanV2::verify`: the v1 checks, the job key,
/// the escrow key id, the answer file and every driver and agent
/// manifest), in order, stopping at the first failure. Nothing is written
/// by the caller unless this succeeds (M4 WU-10).
///
/// # Errors
///
/// [`PlanError`] naming the check that failed.
pub fn verify_plan_v2(
    plan: &SignedEnvelopeV1,
    content: &PlanContentV2<'_>,
    keys: &PlanKeys,
    expect: &PlanExpectationV2<'_>,
    crypto: &dyn CryptoProvider,
) -> Result<VerifiedJobPlanV2, PlanError> {
    let sha256 = |b: &[u8]| crypto.sha256(b);
    VerifiedJobPlanV2::verify(plan, &keys.plan, content, &keys.content, &sha256, expect)
}
