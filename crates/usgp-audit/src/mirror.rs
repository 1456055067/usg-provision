//! Stdout mirror of audit records (plan sections 1.1 and 5.6).
//!
//! Each record is also emitted as one JSON line through
//! `usgp_common::event::emit`, in the M1 shape, with every stored field
//! added to `detail` (`seq`, `record_hash`, `prev_hash`, ...). A party
//! holding the forwarded lines (journald, SIEM) can therefore recompute
//! the chain and verify each `audit.checkpoint` line without the
//! database: the external anchor.
//!
//! Call [`emit_json`] after the transaction commits (`persisted = true`),
//! or with `persisted = false` when the record was sealed but its
//! transaction failed. A refusal whose record could not be sealed or
//! stored is mirrored with [`emit_unpersisted`].

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-9(2) (Store on Separate Physical Systems) - partial:
//   records and signed checkpoints leave the host via stdout forwarding.
// - NIST 800-53: AU-6(4) (Central Review and Analysis) - basis: one JSON
//   shape for SIEM ingestion, shared with M1.
// - NIST 800-53: AU-3 (Content of Audit Records) - every stored field is
//   on the line.
// - SPEC: specs/operator-access.md#REQ-AUD-005, #REQ-AUD-006

use usgp_common::event::{AuditEvent, Outcome, emit};

use crate::canonical::GENESIS_PREV_HASH;
use crate::chain::AuditChain;
use crate::record::{AuditDraft, AuditRecord, parse_outcome};

/// The `detail` pairs of a mirrored record.
#[must_use]
pub fn mirror_fields(record: &AuditRecord, persisted: bool) -> Vec<(&'static str, String)> {
    let mut f = vec![
        ("seq", record.seq.to_string()),
        ("ts_us", record.ts_us.to_string()),
        ("record_hash", record.record_hash.to_hex()),
        ("prev_hash", record.prev_hash.to_hex()),
    ];
    push_record_fields(&mut f, record);
    f.push(("persisted", persisted.to_string()));
    f
}

fn push_record_fields(f: &mut Vec<(&'static str, String)>, record: &AuditRecord) {
    f.push(("actor_kind", record.actor_kind.clone()));
    let optional = [
        ("actor_id", &record.actor_id),
        ("actor_label", &record.actor_label),
    ];
    for (k, v) in optional {
        if let Some(v) = v {
            f.push((k, v.clone()));
        }
    }
    f.push(("node", record.node.clone()));
    let optional = [
        ("source", &record.source),
        ("target_kind", &record.target_kind),
        ("target_id", &record.target_id),
        ("reason", &record.reason),
    ];
    for (k, v) in optional {
        if let Some(v) = v {
            f.push((k, v.clone()));
        }
    }
    if let Some(s) = record.initiating_seq {
        f.push(("initiating_seq", s.to_string()));
    }
    f.push(("record_detail", record.detail.clone()));
    if parse_outcome(&record.outcome).is_none() {
        f.push(("outcome_text", record.outcome.clone()));
    }
}

fn emit_fields(component: &str, record: &AuditRecord, fields: &[(&str, String)]) {
    let e = AuditEvent {
        interface: Some(&record.interface),
        detail: fields,
        ..AuditEvent::new(
            &record.event,
            parse_outcome(&record.outcome).unwrap_or(Outcome::Failure),
            component,
        )
    };
    emit(&e);
}

/// Mirrors a sealed record on stdout. `component` is the emitting
/// service (`usgp-server`).
pub fn emit_json(component: &str, record: &AuditRecord, persisted: bool) {
    emit_fields(component, record, &mirror_fields(record, persisted));
}

/// The `detail` pairs for a draft that has no stored record.
#[must_use]
pub fn unpersisted_fields(chain: &AuditChain, draft: &AuditDraft) -> Vec<(&'static str, String)> {
    let ts_us = chain.now_us().unwrap_or(0);
    let mut f = vec![("ts_us", ts_us.to_string())];
    match draft.to_record(0, ts_us, chain.node(), GENESIS_PREV_HASH) {
        Ok(r) => push_record_fields(&mut f, &r),
        Err(_) => f.push(("draft_invalid", "true".to_owned())),
    }
    f.push(("persisted", "false".to_owned()));
    f
}

/// Mirrors a draft whose record could not be sealed or stored
/// (`persisted=false`, no seq or hashes). The refusal it describes still
/// stands (REQ-AUD-006).
pub fn emit_unpersisted(component: &str, chain: &AuditChain, draft: &AuditDraft) {
    let fields = unpersisted_fields(chain, draft);
    let interface = draft.interface().as_str();
    let e = AuditEvent {
        interface: Some(interface),
        detail: &fields,
        ..AuditEvent::new(draft.event(), draft.outcome(), component)
    };
    emit(&e);
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use usgp_common::Sha256Digest;
    use usgp_common::event::Outcome;

    use super::*;
    use crate::chain::seal;
    use crate::memory::ManualClock;
    use crate::record::{Actor, ChainHead, Detail, Interface};

    fn chain() -> AuditChain {
        AuditChain::with_clock("ctl-01", Arc::new(ManualClock::new(5))).unwrap()
    }

    fn draft() -> AuditDraft {
        AuditDraft::new(
            "authz.denied",
            Outcome::Refused,
            Actor::operator("op-1", "Alice"),
            Interface::Api,
        )
        .source("192.0.2.1:4000")
        .target("package", "p-1")
        .reason("forbidden")
        .detail(Detail::new().with("route", "DELETE /v1/packages/{id}"))
        .initiated_by(3)
    }

    #[test]
    fn mirrored_fields_carry_every_stored_field() {
        let head = ChainHead {
            seq: 4,
            record_hash: Sha256Digest([2; 32]),
        };
        let r = seal(Some(&head), &draft(), 9, "ctl-01").unwrap();
        let f = mirror_fields(&r, true);
        let get = |k: &str| f.iter().find(|(n, _)| *n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("seq"), Some("5"));
        assert_eq!(get("ts_us"), Some("9"));
        assert_eq!(get("record_hash"), Some(r.record_hash.to_hex().as_str()));
        assert_eq!(get("prev_hash"), Some(head.record_hash.to_hex().as_str()));
        assert_eq!(get("actor_kind"), Some("operator"));
        assert_eq!(get("actor_id"), Some("op-1"));
        assert_eq!(get("source"), Some("192.0.2.1:4000"));
        assert_eq!(get("target_kind"), Some("package"));
        assert_eq!(get("reason"), Some("forbidden"));
        assert_eq!(get("initiating_seq"), Some("3"));
        assert_eq!(
            get("record_detail"),
            Some(r#"{"route":"DELETE /v1/packages/{id}"}"#)
        );
        assert_eq!(get("persisted"), Some("true"));
        assert_eq!(get("outcome_text"), None);
        // Emitting must not panic without a subscriber.
        emit_json("usgp-server", &r, true);
    }

    #[test]
    fn unpersisted_has_no_seq() {
        let c = chain();
        let f = unpersisted_fields(&c, &draft());
        assert!(f.iter().all(|(k, _)| *k != "seq" && *k != "record_hash"));
        assert!(f.contains(&("persisted", "false".to_owned())));
        assert!(f.contains(&("node", "ctl-01".to_owned())));
        assert!(f.contains(&("ts_us", "5".to_owned())));
        emit_unpersisted("usgp-server", &c, &draft());
    }
}
