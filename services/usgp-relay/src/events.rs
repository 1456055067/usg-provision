//! Audit event names and the relay's emit helper (plan section 7).
//!
//! Every relay event goes through [`emit`], which fills in the component
//! name, so the "who" field is always the service identity.

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-2 (Event Logging) - one named event per auditable action.
// - NIST 800-53: AU-3 (Content of Audit Records) - fixed fields via
//   usgp_common::event.
// - NIST 800-53: AU-12 (Audit Record Generation)
// - SPEC: specs/boot-network.md#REQ-BOOT-052 (state and missing content
//   reported through events in M1; owner answer Q-4), #REQ-BOOT-067 (boot
//   policy applied, refused, unreachable; stopped devices)

use usgp_common::event::{AuditEvent, emit as emit_event};

pub use usgp_common::event::Outcome;

/// The `component` field of every relay event.
pub const COMPONENT: &str = "usgp-relay";

/// Process start (after configuration, content check and socket binding).
pub const RELAY_START: &str = "relay.start";
/// Process stop (signal received).
pub const RELAY_STOP: &str = "relay.stop";
/// Configuration refused at start-up.
pub const CONFIG_REJECTED: &str = "relay.config.rejected";
/// Service state changed (Running / RunningMissingContent).
pub const STATE_CHANGED: &str = "relay.state.changed";
/// Boot manifest loaded and validated.
pub const MANIFEST_LOADED: &str = "boot.manifest.loaded";
/// A published file matched its manifest entry.
pub const FILE_VERIFIED: &str = "boot.file.verified";
/// A published file did not match its manifest entry.
pub const FILE_INTEGRITY_FAILED: &str = "boot.file.integrity_failed";
/// A published file was not found in the boot root.
pub const FILE_MISSING: &str = "boot.file.missing";
/// Suppression list (re)loaded.
pub const SUPPRESSION_LOADED: &str = "suppression.loaded";
/// Suppression file refused; the previous list is kept.
pub const SUPPRESSION_REJECTED: &str = "suppression.rejected";
/// ProxyDHCP OFFER sent.
pub const DHCP_OFFER_SENT: &str = "dhcp.offer.sent";
/// ProxyDHCP ACK sent.
pub const DHCP_ACK_SENT: &str = "dhcp.ack.sent";
/// A suppressed device was seen (throttled per device).
pub const DHCP_SUPPRESSED: &str = "dhcp.suppressed";
/// Periodic count of dropped DHCP messages per reason.
pub const DHCP_DROP_SUMMARY: &str = "dhcp.drop.summary";
/// Periodic count of dropped TFTP datagrams per reason (not in the plan's
/// event table; added so TFTP floods are summarised like DHCP ones).
pub const TFTP_DROP_SUMMARY: &str = "tftp.drop.summary";
/// Periodic count of requests shed by a rate limit or cap.
pub const LIMITS_SHED: &str = "limits.shed";
/// TFTP read transfer started.
pub const TFTP_STARTED: &str = "tftp.transfer.started";
/// TFTP read transfer completed.
pub const TFTP_COMPLETED: &str = "tftp.transfer.completed";
/// TFTP read transfer abandoned by the server.
pub const TFTP_FAILED: &str = "tftp.transfer.failed";
/// TFTP read transfer ended by the client.
pub const TFTP_ABORTED_BY_CLIENT: &str = "tftp.transfer.aborted_by_client";
/// TFTP request refused with an ERROR packet.
pub const TFTP_REQUEST_REFUSED: &str = "tftp.request.refused";
/// The boot manifest's `[pe_kit]` is incomplete or does not match: no
/// boot program is offered (M3 plan section 7; REQ-PE-012).
pub const KIT_INCOMPLETE: &str = "boot.kit.incomplete";
/// A signed boot-policy list was verified and applied (M3 plan section 7;
/// REQ-BOOT-067, decision 0021).
pub const BOOT_POLICY_APPLIED: &str = "boot_policy.applied";
/// A boot-policy list was refused (signature, boot service, rollback,
/// shape); the last good list is kept.
pub const BOOT_POLICY_REJECTED: &str = "boot_policy.rejected";
/// The boot-policy list could not be fetched; the last good list is kept.
pub const BOOT_POLICY_FETCH_FAILED: &str = "boot_policy.fetch_failed";
/// A device on the boot-policy stop list was seen and got no reply
/// (throttled per device, like `dhcp.suppressed`).
pub const BOOT_DEVICE_STOPPED: &str = "boot.device.stopped";

/// Emits a relay event: `base` with the component filled in.
///
/// `base` is usually built as
/// `AuditEvent { interface: .., ..AuditEvent::new(name, outcome, COMPONENT) }`;
/// the component is overwritten here so it cannot be forgotten.
pub fn emit(mut base: AuditEvent<'_>) {
    base.component = COMPONENT;
    emit_event(&base);
}

/// Emits an event that carries only a name, an outcome and detail pairs.
pub fn emit_simple(event: &str, outcome: Outcome, detail: &[(&str, String)]) {
    emit(AuditEvent {
        detail,
        ..AuditEvent::new(event, outcome, COMPONENT)
    });
}
