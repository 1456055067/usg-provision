//! Canonical record bytes and the record hash (plan section 5.6).
//!
//! Version 1:
//!
//! ```text
//! canonical   = 0x01 || seq (u64 BE) || ts_us (i64 BE) ||
//!               field(event) || field(outcome) || field(actor_kind) ||
//!               field(actor_id) || field(actor_label) || field(interface) ||
//!               field(node) || field(source) || field(target_kind) ||
//!               field(target_id) || field(reason) || field(detail) ||
//!               field(initiating_seq as decimal text)
//! field(x)    = len(x) (u32 BE) || UTF-8 bytes of x;  absent = 0xFFFFFFFF
//! record_hash = SHA-256("usgp-audit-v1" || prev_hash || canonical)
//! ```
//!
//! Every field is length-prefixed, so no two different records have the
//! same canonical bytes, and an absent field differs from an empty one.

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-9 (Protection of Audit Information) - each record is
//   bound to its predecessor by a SHA-256 hash chain.
// - NIST 800-53: SC-13 (Cryptographic Protection) - SHA-256 (FIPS 180-4)
//   through the usgp-crypto provider.
// - SPEC: specs/operator-access.md#REQ-AUD-005

use usgp_common::Sha256Digest;
use usgp_crypto::CryptoProvider;

use crate::error::AuditError;
use crate::record::AuditRecord;

/// Canonical encoding version byte.
pub const CANONICAL_VERSION: u8 = 1;
/// Domain tag hashed before every record.
pub const HASH_DOMAIN: &[u8] = b"usgp-audit-v1";
/// `prev_hash` of record 1.
pub const GENESIS_PREV_HASH: Sha256Digest = Sha256Digest([0; 32]);
/// Length marker of an absent field.
pub const ABSENT: u32 = u32::MAX;

/// The canonical bytes of `record` (its `prev_hash` and `record_hash` are
/// not part of them).
///
/// # Errors
///
/// [`AuditError::Encoding`] if a field is `u32::MAX` bytes or longer.
pub fn encode(record: &AuditRecord) -> Result<Vec<u8>, AuditError> {
    let initiating = record.initiating_seq.map(|s| s.to_string());
    let fields: [(&'static str, Option<&str>); 13] = [
        ("event", Some(record.event.as_str())),
        ("outcome", Some(record.outcome.as_str())),
        ("actor_kind", Some(record.actor_kind.as_str())),
        ("actor_id", record.actor_id.as_deref()),
        ("actor_label", record.actor_label.as_deref()),
        ("interface", Some(record.interface.as_str())),
        ("node", Some(record.node.as_str())),
        ("source", record.source.as_deref()),
        ("target_kind", record.target_kind.as_deref()),
        ("target_id", record.target_id.as_deref()),
        ("reason", record.reason.as_deref()),
        ("detail", Some(record.detail.as_str())),
        ("initiating_seq", initiating.as_deref()),
    ];
    let body: usize = fields
        .iter()
        .map(|(_, v)| 4_usize.saturating_add(v.map_or(0, str::len)))
        .fold(0, usize::saturating_add);
    let mut out = Vec::with_capacity(17_usize.saturating_add(body));
    out.push(CANONICAL_VERSION);
    out.extend_from_slice(&record.seq.to_be_bytes());
    out.extend_from_slice(&record.ts_us.to_be_bytes());
    for (name, value) in fields {
        match value {
            None => out.extend_from_slice(&ABSENT.to_be_bytes()),
            Some(v) => {
                let len = u32::try_from(v.len())
                    .ok()
                    .filter(|l| *l != ABSENT)
                    .ok_or(AuditError::Encoding { field: name })?;
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(v.as_bytes());
            }
        }
    }
    Ok(out)
}

/// `SHA-256(HASH_DOMAIN || prev_hash || canonical)`.
#[must_use]
pub fn hash_canonical(prev_hash: &Sha256Digest, canonical: &[u8]) -> Sha256Digest {
    let mut h = usgp_crypto::provider().sha256_hasher();
    h.update(HASH_DOMAIN);
    h.update(prev_hash.as_bytes());
    h.update(canonical);
    h.finish()
}

/// Recomputes the hash `record` should carry, from its own `prev_hash`
/// and fields.
///
/// # Errors
///
/// [`AuditError::Encoding`] as for [`encode`].
pub fn compute_record_hash(record: &AuditRecord) -> Result<Sha256Digest, AuditError> {
    Ok(hash_canonical(&record.prev_hash, &encode(record)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec() -> AuditRecord {
        AuditRecord {
            seq: 1,
            ts_us: 2,
            event: "e".into(),
            outcome: "success".into(),
            actor_kind: "system".into(),
            actor_id: None,
            actor_label: Some(String::new()),
            interface: "system".into(),
            node: "n".into(),
            source: None,
            target_kind: None,
            target_id: None,
            reason: None,
            detail: "{}".into(),
            initiating_seq: Some(7),
            prev_hash: GENESIS_PREV_HASH,
            record_hash: GENESIS_PREV_HASH,
        }
    }

    #[test]
    fn layout_is_exact() {
        let b = encode(&rec()).unwrap();
        let mut want = vec![1u8];
        want.extend_from_slice(&1u64.to_be_bytes());
        want.extend_from_slice(&2i64.to_be_bytes());
        let field = |w: &mut Vec<u8>, s: Option<&str>| match s {
            None => w.extend_from_slice(&[0xff; 4]),
            Some(s) => {
                w.extend_from_slice(&u32::try_from(s.len()).unwrap().to_be_bytes());
                w.extend_from_slice(s.as_bytes());
            }
        };
        for f in [
            Some("e"),
            Some("success"),
            Some("system"),
            None,
            Some(""),
            Some("system"),
            Some("n"),
            None,
            None,
            None,
            None,
            Some("{}"),
            Some("7"),
        ] {
            field(&mut want, f);
        }
        assert_eq!(b, want);
    }

    #[test]
    fn absent_differs_from_empty() {
        let a = rec();
        let mut b = rec();
        b.actor_label = None;
        assert_ne!(encode(&a).unwrap(), encode(&b).unwrap());
    }

    #[test]
    fn hash_binds_prev_and_domain() {
        let r = rec();
        let c = encode(&r).unwrap();
        let h1 = hash_canonical(&GENESIS_PREV_HASH, &c);
        let h2 = hash_canonical(&Sha256Digest([1; 32]), &c);
        assert_ne!(h1, h2);
        let mut direct = HASH_DOMAIN.to_vec();
        direct.extend_from_slice(&[0; 32]);
        direct.extend_from_slice(&c);
        assert_eq!(h1, usgp_crypto::sha256(&direct));
        assert_eq!(compute_record_hash(&r).unwrap(), h1);
    }
}
