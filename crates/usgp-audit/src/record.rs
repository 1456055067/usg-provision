//! The audit record model: what callers build ([`AuditDraft`]) and what
//! the chain stores ([`AuditRecord`]).
//!
//! A draft is typed: the actor kind, interface and outcome come from
//! closed sets, event names and detail keys are developer-chosen static
//! text, and free text (labels, ids, reasons) is cleaned and bounded.
//! A record is the stored row exactly as hashed: every text column is a
//! plain `String`, so a verifier hashes what is stored and a tampered
//! value shows up as a hash mismatch, never as a load error.
//!
//! Fields (plan section 7, AU-3):
//!
//! | AU-3 element | Field(s) |
//! |---|---|
//! | who | `actor_kind`, `actor_id`, `actor_label` |
//! | what | `event`, `target_kind`, `target_id` |
//! | when | `ts_us` (UTC microseconds since 1970) |
//! | where | `interface`, `node` |
//! | source | `source` (peer `ip:port`, or `uid:<n>` for the server CLI) |
//! | outcome | `outcome`, plus `reason` when not success |
//! | related action | `initiating_seq` (REQ-AUD-002) |

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-3 (Content of Audit Records) - who/what/when/where/
//   source/outcome on every record; a non-success outcome needs a reason.
// - NIST 800-53: AU-3(1) (Additional Audit Information) - target, detail
//   and initiating_seq.
// - NIST 800-53: AU-8 (Time Stamps) - UTC, microsecond resolution.
// - NIST 800-53: SI-10 (Information Input Validation) - bounded, cleaned
//   text; closed value sets.
// - SPEC: specs/operator-access.md#REQ-AUD-001, #REQ-AUD-002, #REQ-AUD-003
// - SPEC: specs/progress.md#REQ-JOB-012 and specs/targeting.md#REQ-TGT-016
//   (device sessions and boot services as named actors; plan M3 section 7)

use std::collections::BTreeSet;

use usgp_common::Sha256Digest;
use usgp_common::event::{Outcome, render_detail};
use usgp_crypto::KeyId;

use crate::error::AuditError;

/// Longest event name, in bytes.
pub const MAX_EVENT_LEN: usize = 64;
/// Longest free-text field (actor id/label, node, source, target id,
/// reason), in bytes. Longer text is truncated with [`TRUNCATION_MARK`].
pub const MAX_TEXT_LEN: usize = 1024;
/// Longest target kind, in bytes.
pub const MAX_TARGET_KIND_LEN: usize = 32;
/// Most detail pairs on one record.
pub const MAX_DETAIL_PAIRS: usize = 32;
/// Longest detail key, in bytes.
pub const MAX_DETAIL_KEY_LEN: usize = 64;
/// Longest detail value, in bytes, before JSON escaping. Longer values
/// are truncated with [`TRUNCATION_MARK`].
pub const MAX_DETAIL_VALUE_LEN: usize = 2048;
/// Longest rendered detail JSON text, in bytes.
pub const MAX_DETAIL_LEN: usize = 16 * 1024;
/// Appended to text cut at a limit.
pub const TRUNCATION_MARK: &str = "[truncated]";

/// Event of the first record of every chain.
pub const EVENT_GENESIS: &str = "audit.chain.genesis";
/// Event of the record written with each checkpoint.
pub const EVENT_CHECKPOINT: &str = "audit.checkpoint";

/// Who acted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ActorKind {
    /// An authenticated operator (mTLS certificate bound to an operator).
    Operator,
    /// A requester the product could not authenticate.
    Unauthenticated,
    /// The server itself (start-up, checks, checkpoints).
    System,
    /// A local user running a server command (`server-cli`). The uid is
    /// reported by the OS and recorded as claimed.
    LocalUser,
    /// A pre-boot device session on the device listener (plan M3 section
    /// 7): the id is the session id; the label names the MACs and source
    /// address the device claimed. The device holds no credential
    /// (decision 0020); the session is authorised by code or approval.
    DeviceSession,
    /// A relay authenticated by its client certificate bound to a
    /// boot-service record (decision 0021): the id is the boot-service id;
    /// the label names the boot service and its certificate SHA-256.
    BootService,
}

impl ActorKind {
    /// Stored text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Unauthenticated => "unauthenticated",
            Self::System => "system",
            Self::LocalUser => "local_user",
            Self::DeviceSession => "device_session",
            Self::BootService => "boot_service",
        }
    }
}

/// Which interface the action came through (AU-3 "where").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Interface {
    /// The operator REST API.
    Api,
    /// A local `usgp-server` subcommand.
    ServerCli,
    /// Internal server activity.
    System,
    /// The device listener (pre-boot agent sessions, plan M3 section 3.1).
    DeviceApi,
    /// The relay's boot-policy feed (plan M3 section 3.6).
    RelayFeed,
}

impl Interface {
    /// Stored text.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Api => "api",
            Self::ServerCli => "server-cli",
            Self::System => "system",
            Self::DeviceApi => "device_api",
            Self::RelayFeed => "relay_feed",
        }
    }
}

/// Parses stored outcome text.
#[must_use]
pub fn parse_outcome(text: &str) -> Option<Outcome> {
    match text {
        "success" => Some(Outcome::Success),
        "failure" => Some(Outcome::Failure),
        "refused" => Some(Outcome::Refused),
        "dropped" => Some(Outcome::Dropped),
        _ => None,
    }
}

/// The actor of a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    kind: ActorKind,
    id: Option<String>,
    label: Option<String>,
}

impl Actor {
    /// An authenticated operator: `id` is the operator id, `label` the
    /// display name and certificate SHA-256.
    #[must_use]
    pub fn operator(id: &str, label: &str) -> Self {
        Self {
            kind: ActorKind::Operator,
            id: Some(clean_text(id, MAX_TEXT_LEN)),
            label: Some(clean_text(label, MAX_TEXT_LEN)),
        }
    }

    /// An unauthenticated requester. `presented` is what the product could
    /// learn (for example a presented certificate's fingerprint), if any.
    #[must_use]
    pub fn unauthenticated(presented: Option<&str>) -> Self {
        Self {
            kind: ActorKind::Unauthenticated,
            id: None,
            label: Some(presented.map_or_else(
                || "unauthenticated".to_owned(),
                |p| clean_text(&format!("unauthenticated; presented {p}"), MAX_TEXT_LEN),
            )),
        }
    }

    /// The server itself.
    #[must_use]
    pub const fn system() -> Self {
        Self {
            kind: ActorKind::System,
            id: None,
            label: None,
        }
    }

    /// A local user running a server command; the uid is as the OS
    /// reports it (claimed, not authenticated by the product).
    #[must_use]
    pub fn local_user(uid: u32, name: Option<&str>) -> Self {
        Self {
            kind: ActorKind::LocalUser,
            id: Some(format!("uid:{uid}")),
            label: name.map(|n| clean_text(n, MAX_TEXT_LEN)),
        }
    }

    /// A pre-boot device session: `session_id` is the session id,
    /// `claimed` what the device stated about itself (MACs, source
    /// address), which the caller marks as claimed.
    #[must_use]
    pub fn device_session(session_id: &str, claimed: &str) -> Self {
        Self {
            kind: ActorKind::DeviceSession,
            id: Some(clean_text(session_id, MAX_TEXT_LEN)),
            label: Some(clean_text(claimed, MAX_TEXT_LEN)),
        }
    }

    /// A relay acting as a boot service: `boot_service_id` is the
    /// boot-service id, `label` its name and certificate SHA-256.
    #[must_use]
    pub fn boot_service(boot_service_id: &str, label: &str) -> Self {
        Self {
            kind: ActorKind::BootService,
            id: Some(clean_text(boot_service_id, MAX_TEXT_LEN)),
            label: Some(clean_text(label, MAX_TEXT_LEN)),
        }
    }

    /// The actor kind.
    #[must_use]
    pub const fn kind(&self) -> ActorKind {
        self.kind
    }
}

/// A value allowed in a record's `detail` object.
///
/// Implemented only for plain, non-secret value types. Secret-holding
/// types (`SigningKey`, `Zeroizing<_>`, TLS key settings) do not
/// implement it, so they cannot be passed to [`Detail::with`]
/// (REQ-AUD-003):
///
/// ```compile_fail,E0277
/// let key = usgp_crypto::SigningKey::generate().unwrap();
/// let _ = usgp_audit::Detail::new().with("key", &key);
/// ```
pub trait DetailValue {
    /// The text written in the detail object.
    fn detail_text(&self) -> String;
}

impl DetailValue for str {
    fn detail_text(&self) -> String {
        self.to_owned()
    }
}

impl DetailValue for String {
    fn detail_text(&self) -> String {
        self.clone()
    }
}

impl DetailValue for bool {
    fn detail_text(&self) -> String {
        if *self { "true" } else { "false" }.to_owned()
    }
}

macro_rules! detail_value_display {
    ($($t:ty),*) => {
        $(impl DetailValue for $t {
            fn detail_text(&self) -> String {
                self.to_string()
            }
        })*
    };
}

detail_value_display!(
    u8,
    u16,
    u32,
    u64,
    usize,
    i32,
    i64,
    Sha256Digest,
    KeyId,
    Outcome
);

/// The `detail` key/value pairs of a record, rendered as one JSON object
/// in insertion order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Detail {
    pairs: Vec<(&'static str, String)>,
}

impl Detail {
    /// An empty detail object.
    #[must_use]
    pub const fn new() -> Self {
        Self { pairs: Vec::new() }
    }

    /// Adds `key: value`. Keys are developer-chosen static names
    /// (`[a-z][a-z0-9_]*`, at most 64 bytes, unique), checked when the
    /// draft is sealed. Values longer than [`MAX_DETAIL_VALUE_LEN`] are
    /// truncated.
    #[must_use]
    pub fn with<V: DetailValue + ?Sized>(mut self, key: &'static str, value: &V) -> Self {
        self.pairs
            .push((key, truncate(value.detail_text(), MAX_DETAIL_VALUE_LEN)));
        self
    }

    /// Number of pairs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pairs.len()
    }

    /// True if there are no pairs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// Checks the keys and renders the JSON object text that is stored and
    /// hashed.
    ///
    /// # Errors
    ///
    /// [`AuditError::InvalidDraft`] for a bad or duplicate key, too many
    /// pairs, or a rendered text above [`MAX_DETAIL_LEN`].
    pub fn render(&self) -> Result<String, AuditError> {
        if self.pairs.len() > MAX_DETAIL_PAIRS {
            return Err(invalid("detail", "too many pairs"));
        }
        let mut seen = BTreeSet::new();
        for (k, _) in &self.pairs {
            if !is_identifier(k, MAX_DETAIL_KEY_LEN) {
                return Err(invalid("detail", "key is not a lowercase identifier"));
            }
            if !seen.insert(*k) {
                return Err(invalid("detail", "duplicate key"));
            }
        }
        let text = render_detail(&self.pairs);
        if text.len() > MAX_DETAIL_LEN {
            return Err(invalid("detail", "rendered text too long"));
        }
        Ok(text)
    }
}

/// What a caller builds to record one action: required fields in
/// [`AuditDraft::new`], optional ones through the builder methods
/// (`source`, `target`, `reason`, `detail`, `initiated_by`). See
/// `tests/audit/append.rs` for complete examples. (No runnable doc
/// example: on macOS the FIPS module is a dynamic library that rustdoc's
/// test binaries cannot load, POAM-2.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditDraft {
    event: String,
    outcome: Outcome,
    actor: Actor,
    interface: Interface,
    source: Option<String>,
    target: Option<(String, String)>,
    reason: Option<String>,
    detail: Detail,
    initiating_seq: Option<u64>,
    internal: bool,
}

impl AuditDraft {
    /// A draft with the required fields. `event` is a dotted lowercase
    /// name (plan section 7), checked by [`AuditDraft::validate`]. The
    /// names [`EVENT_GENESIS`] and [`EVENT_CHECKPOINT`] are reserved for
    /// this crate.
    #[must_use]
    pub fn new(event: &str, outcome: Outcome, actor: Actor, interface: Interface) -> Self {
        Self {
            event: event.to_owned(),
            outcome,
            actor,
            interface,
            source: None,
            target: None,
            reason: None,
            detail: Detail::new(),
            initiating_seq: None,
            internal: false,
        }
    }

    /// A draft for a reserved event, built only inside this crate.
    pub(crate) fn internal(event: &'static str, detail: Detail, target_id: String) -> Self {
        Self {
            target: Some(("audit_chain".to_owned(), target_id)),
            detail,
            internal: true,
            ..Self::new(event, Outcome::Success, Actor::system(), Interface::System)
        }
    }

    /// Sets the network origin (`ip:port`) or local origin (`uid:<n>`).
    #[must_use]
    pub fn source(mut self, source: &str) -> Self {
        self.source = Some(clean_text(source, MAX_TEXT_LEN));
        self
    }

    /// Sets the item acted on. `kind` is a lowercase identifier such as
    /// `content` or `package`; `id` is free text.
    #[must_use]
    pub fn target(mut self, kind: &str, id: &str) -> Self {
        self.target = Some((kind.to_owned(), clean_text(id, MAX_TEXT_LEN)));
        self
    }

    /// Sets the reason (required when the outcome is not success).
    #[must_use]
    pub fn reason(mut self, reason: &str) -> Self {
        self.reason = Some(clean_text(reason, MAX_TEXT_LEN));
        self
    }

    /// Sets the detail object.
    #[must_use]
    pub fn detail(mut self, detail: Detail) -> Self {
        self.detail = detail;
        self
    }

    /// Names the record of the operator action that started this later
    /// state change (REQ-AUD-002).
    #[must_use]
    pub const fn initiated_by(mut self, seq: u64) -> Self {
        self.initiating_seq = Some(seq);
        self
    }

    /// The event name.
    #[must_use]
    pub fn event(&self) -> &str {
        &self.event
    }

    /// The outcome.
    #[must_use]
    pub const fn outcome(&self) -> Outcome {
        self.outcome
    }

    /// The interface.
    #[must_use]
    pub const fn interface(&self) -> Interface {
        self.interface
    }

    /// Checks the draft. [`crate::chain::AuditChain::append`] calls this;
    /// callers may call it earlier.
    ///
    /// # Errors
    ///
    /// [`AuditError::InvalidDraft`] naming the field.
    pub fn validate(&self) -> Result<(), AuditError> {
        self.validated_detail().map(|_| ())
    }

    pub(crate) fn validated_detail(&self) -> Result<String, AuditError> {
        if !is_event_name(&self.event) {
            return Err(invalid("event", "not a dotted lowercase name"));
        }
        let reserved = self.event == EVENT_GENESIS || self.event == EVENT_CHECKPOINT;
        if reserved != self.internal {
            return Err(invalid("event", "reserved for the audit chain"));
        }
        if let Some((kind, _)) = &self.target
            && !is_identifier(kind, MAX_TARGET_KIND_LEN)
        {
            return Err(invalid("target_kind", "not a lowercase identifier"));
        }
        if self.outcome != Outcome::Success && self.reason.is_none() {
            return Err(invalid(
                "reason",
                "required when the outcome is not success",
            ));
        }
        if self.initiating_seq == Some(0) {
            return Err(invalid("initiating_seq", "sequence numbers start at 1"));
        }
        self.detail.render()
    }

    /// Builds the stored record for `seq` after `prev_hash`, without its
    /// hash (`record_hash` is filled by [`crate::chain::seal`]).
    pub(crate) fn to_record(
        &self,
        seq: u64,
        ts_us: i64,
        node: &str,
        prev_hash: Sha256Digest,
    ) -> Result<AuditRecord, AuditError> {
        let detail = self.validated_detail()?;
        let (target_kind, target_id) = match &self.target {
            Some((k, i)) => (Some(k.clone()), Some(i.clone())),
            None => (None, None),
        };
        Ok(AuditRecord {
            seq,
            ts_us,
            event: self.event.clone(),
            outcome: self.outcome.as_str().to_owned(),
            actor_kind: self.actor.kind.as_str().to_owned(),
            actor_id: self.actor.id.clone(),
            actor_label: self.actor.label.clone(),
            interface: self.interface.as_str().to_owned(),
            node: node.to_owned(),
            source: self.source.clone(),
            target_kind,
            target_id,
            reason: self.reason.clone(),
            detail,
            initiating_seq: self.initiating_seq,
            prev_hash,
            record_hash: Sha256Digest([0; 32]),
        })
    }
}

/// One stored audit record, exactly as hashed.
///
/// Storage maps each field to one column (plan section 3.4,
/// `audit_record`). `seq` and `initiating_seq` must fit `bigint`
/// (`i64::try_from`); a stored negative value is
/// [`crate::error::StoreErrorKind::Corrupt`]. `detail` is stored as
/// `text`, never `jsonb`, so its bytes hash the same after a round trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// Position in the chain, from 1, contiguous.
    pub seq: u64,
    /// UTC microseconds since 1970-01-01.
    pub ts_us: i64,
    /// Event name.
    pub event: String,
    /// Outcome text (`success`, `failure`, `refused`, `dropped`).
    pub outcome: String,
    /// Actor kind text.
    pub actor_kind: String,
    /// Operator id, `uid:<n>`, device-session id, boot-service id, or
    /// none.
    pub actor_id: Option<String>,
    /// Display label of the actor.
    pub actor_label: Option<String>,
    /// Interface text.
    pub interface: String,
    /// Node name of the server.
    pub node: String,
    /// Network or local origin.
    pub source: Option<String>,
    /// Kind of the item acted on.
    pub target_kind: Option<String>,
    /// Id of the item acted on.
    pub target_id: Option<String>,
    /// Reason for a non-success outcome.
    pub reason: Option<String>,
    /// Detail JSON object text.
    pub detail: String,
    /// The record of the action that started this one (REQ-AUD-002).
    pub initiating_seq: Option<u64>,
    /// `record_hash` of record `seq - 1`; 32 zero bytes for record 1.
    pub prev_hash: Sha256Digest,
    /// SHA-256 over the domain tag, `prev_hash` and the canonical bytes.
    pub record_hash: Sha256Digest,
}

/// The chain head: the last record's seq and hash (`audit_head`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainHead {
    /// Seq of the last record.
    pub seq: u64,
    /// `record_hash` of the last record.
    pub record_hash: Sha256Digest,
}

impl From<&AuditRecord> for ChainHead {
    fn from(r: &AuditRecord) -> Self {
        Self {
            seq: r.seq,
            record_hash: r.record_hash,
        }
    }
}

pub(crate) const fn invalid(field: &'static str, reason: &'static str) -> AuditError {
    AuditError::InvalidDraft { field, reason }
}

/// `[a-z][a-z0-9_]*`, 1..=`max` bytes.
pub(crate) fn is_identifier(s: &str, max: usize) -> bool {
    let mut bytes = s.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_lowercase() => {}
        _ => return false,
    }
    s.len() <= max && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Dot-separated identifiers, at most [`MAX_EVENT_LEN`] bytes.
pub(crate) fn is_event_name(s: &str) -> bool {
    s.len() <= MAX_EVENT_LEN && s.split('.').all(|seg| is_identifier(seg, MAX_EVENT_LEN))
}

/// Replaces control characters with U+FFFD (they could forge log lines,
/// and PostgreSQL `text` cannot hold U+0000) and bounds the length.
pub(crate) fn clean_text(s: &str, max: usize) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect();
    truncate(cleaned, max)
}

/// Cuts `s` to at most `max` bytes on a character boundary, ending in
/// [`TRUNCATION_MARK`] when cut.
pub(crate) fn truncate(mut s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let keep = max.saturating_sub(TRUNCATION_MARK.len());
    let mut cut = keep;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s.truncate(cut);
    s.push_str(TRUNCATION_MARK);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op() -> Actor {
        Actor::operator("id-1", "Alice")
    }

    #[test]
    fn event_names() {
        assert!(is_event_name("content.upload.refused"));
        assert!(is_event_name("auth.tls.crl_stale"));
        assert!(!is_event_name(""));
        assert!(!is_event_name("Content.x"));
        assert!(!is_event_name("a..b"));
        assert!(!is_event_name(".a"));
        assert!(!is_event_name("a.1b"));
        assert!(!is_event_name(&"a".repeat(MAX_EVENT_LEN + 1)));
    }

    #[test]
    fn reserved_events_refused_from_callers() {
        for e in [EVENT_GENESIS, EVENT_CHECKPOINT] {
            let d = AuditDraft::new(e, Outcome::Success, Actor::system(), Interface::System);
            assert!(matches!(
                d.validate(),
                Err(AuditError::InvalidDraft { field: "event", .. })
            ));
        }
        let d = AuditDraft::internal(EVENT_GENESIS, Detail::new(), "1".into());
        assert!(d.validate().is_ok());
    }

    #[test]
    fn non_success_needs_reason() {
        let d = AuditDraft::new("authz.denied", Outcome::Refused, op(), Interface::Api);
        assert!(matches!(
            d.validate(),
            Err(AuditError::InvalidDraft {
                field: "reason",
                ..
            })
        ));
        assert!(d.reason("forbidden").validate().is_ok());
    }

    #[test]
    fn detail_keys_checked() {
        let base = AuditDraft::new("x.y", Outcome::Success, op(), Interface::Api);
        let dup = Detail::new().with("a", "1").with("a", "2");
        assert!(base.clone().detail(dup).validate().is_err());
        let bad = Detail::new().with("Bad", "1");
        assert!(base.clone().detail(bad).validate().is_err());
        let mut many = Detail::new();
        for k in KEYS {
            many = many.with(k, "v");
        }
        assert!(base.clone().detail(many).validate().is_err());
        let ok = Detail::new().with("size", &5_u64).with("ok", &true);
        assert_eq!(ok.render().unwrap(), r#"{"size":"5","ok":"true"}"#);
    }

    const KEYS: [&str; 33] = [
        "k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7", "k8", "k9", "k10", "k11", "k12", "k13",
        "k14", "k15", "k16", "k17", "k18", "k19", "k20", "k21", "k22", "k23", "k24", "k25", "k26",
        "k27", "k28", "k29", "k30", "k31", "k32",
    ];

    #[test]
    fn text_cleaned_and_truncated() {
        assert_eq!(clean_text("a\nb\0c", 100), "a\u{FFFD}b\u{FFFD}c");
        let long = "é".repeat(1000); // 2000 bytes
        let t = clean_text(&long, MAX_TEXT_LEN);
        assert!(t.len() <= MAX_TEXT_LEN);
        assert!(t.ends_with(TRUNCATION_MARK));
        let v = Detail::new().with("v", &"x".repeat(5000));
        let text = v.render().unwrap();
        assert!(text.len() < MAX_DETAIL_VALUE_LEN + 16);
    }

    #[test]
    fn target_kind_checked() {
        let d = AuditDraft::new("x.y", Outcome::Success, op(), Interface::Api).target("Pkg", "1");
        assert!(d.validate().is_err());
    }

    #[test]
    fn actors() {
        assert_eq!(Actor::system().kind(), ActorKind::System);
        let u = Actor::unauthenticated(Some("sha256 ab\ncd"));
        assert_eq!(
            u.label.as_deref(),
            Some("unauthenticated; presented sha256 ab\u{FFFD}cd")
        );
        let l = Actor::local_user(1000, None);
        assert_eq!(l.id.as_deref(), Some("uid:1000"));
        let d = Actor::device_session("s-1", "macs 02:00:00:00:00:01 (claimed)\n");
        assert_eq!(d.kind().as_str(), "device_session");
        assert_eq!(d.id.as_deref(), Some("s-1"));
        assert_eq!(
            d.label.as_deref(),
            Some("macs 02:00:00:00:00:01 (claimed)\u{FFFD}")
        );
        let b = Actor::boot_service("b-1", "relay-a; cert sha256 ab");
        assert_eq!(b.kind().as_str(), "boot_service");
        assert_eq!(b.id.as_deref(), Some("b-1"));
    }

    #[test]
    fn closed_sets_text() {
        let kinds = [
            ActorKind::Operator,
            ActorKind::Unauthenticated,
            ActorKind::System,
            ActorKind::LocalUser,
            ActorKind::DeviceSession,
            ActorKind::BootService,
        ];
        let texts: BTreeSet<_> = kinds.iter().map(|k| k.as_str()).collect();
        assert_eq!(texts.len(), kinds.len());
        let ifaces = [
            Interface::Api,
            Interface::ServerCli,
            Interface::System,
            Interface::DeviceApi,
            Interface::RelayFeed,
        ];
        let texts: BTreeSet<_> = ifaces.iter().map(|i| i.as_str()).collect();
        assert_eq!(texts.len(), ifaces.len());
        assert!(texts.contains("device_api") && texts.contains("relay_feed"));
    }

    #[test]
    fn outcome_round_trip() {
        for o in [
            Outcome::Success,
            Outcome::Failure,
            Outcome::Refused,
            Outcome::Dropped,
        ] {
            assert_eq!(parse_outcome(o.as_str()), Some(o));
        }
        assert_eq!(parse_outcome("ok"), None);
    }
}
