//! Parse errors for incoming DHCP/PXE messages.
//!
//! Every variant carries only small numeric facts about the message (lengths,
//! codes), never message bytes, so an error can be counted or logged without
//! echoing attacker-chosen content.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - each rejection rule
//   has its own variant so drop counters show why traffic was discarded.
// - SPEC: specs/boot-network.md#REQ-BOOT-006

use thiserror::Error;

/// Why an incoming message was rejected as malformed or not handled.
///
/// A rejected message is always dropped silently (REQ-BOOT-006): it never
/// produces an error reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ParseError {
    /// Shorter than the 236-octet fixed BOOTP header.
    #[error("message too short ({len} octets)")]
    TooShort {
        /// Received length.
        len: usize,
    },
    /// Header and cookie present, but shorter than the 300-octet minimum
    /// BOOTP message (specs/standards/pxe-dhcp.md §3.2; RFC 1542 §2.1).
    #[error("message shorter than the BOOTP minimum ({len} octets)")]
    ShortMessage {
        /// Received length.
        len: usize,
    },
    /// Longer than the accepted maximum (1472 octets).
    #[error("message too long ({len} octets)")]
    TooLong {
        /// Received length.
        len: usize,
    },
    /// Header present but the 4-octet magic cookie is missing.
    #[error("magic cookie missing")]
    MissingCookie,
    /// The magic cookie is not 99.130.83.99.
    #[error("bad magic cookie")]
    BadCookie,
    /// `op` is not 1 (BOOTREQUEST); replies from other servers land here.
    #[error("not a BOOTREQUEST (op {op})")]
    NotBootRequest {
        /// Received `op`.
        op: u8,
    },
    /// `htype` is not 1 (Ethernet).
    #[error("unsupported hardware type {htype}")]
    BadHardwareType {
        /// Received `htype`.
        htype: u8,
    },
    /// `hlen` is not 6.
    #[error("unsupported hardware address length {hlen}")]
    BadHardwareLength {
        /// Received `hlen`.
        hlen: u8,
    },
    /// `chaddr` is multicast or all zero.
    #[error("client hardware address is multicast or zero")]
    BadChaddr,
    /// `ciaddr` is non-zero but not a usable unicast address.
    #[error("client address is not unicast")]
    BadCiaddr,
    /// An option code had no length octet, or its length ran past the area.
    #[error("option {code} truncated")]
    OptionTruncated {
        /// Option code.
        code: u8,
    },
    /// The options field has no End option.
    #[error("options field has no End option")]
    MissingEnd,
    /// Option 52 carried a value other than 1, 2 or 3.
    #[error("bad option overload value {value}")]
    BadOverload {
        /// Received value.
        value: u8,
    },
    /// An option's length breaks the rule for that option.
    #[error("option {code} has invalid length {len}")]
    BadOptionLength {
        /// Option code.
        code: u8,
        /// Received length.
        len: usize,
    },
    /// An option occurred more than once where repeats are not allowed.
    /// Incoming requests never produce this: repeated options are
    /// reassembled (RFC 3396). Only [`crate::reply::inspect_reply`] uses
    /// it, because this crate's own replies never split an option.
    #[error("option {code} repeated")]
    DuplicateOption {
        /// Option code.
        code: u8,
    },
    /// No option 53: a plain BOOTP request, which this service does not
    /// answer.
    #[error("no DHCP message type")]
    MissingMessageType,
    /// Option 53 is not DISCOVER (1) or REQUEST (3).
    #[error("message type {value} not handled")]
    UnhandledMessageType {
        /// Received option 53 value.
        value: u8,
    },
    /// Option 97 type octet is not 0.
    #[error("client machine identifier type {kind} not supported")]
    BadMachineIdType {
        /// Received type octet.
        kind: u8,
    },
    /// The `Arch:` field of option 60 is not five decimal digits.
    #[error("vendor class Arch field malformed")]
    BadVendorClassArch,
    /// The `Arch:` field of option 60 is not in the option 93 list.
    #[error("vendor class Arch field disagrees with option 93")]
    VendorClassArchMismatch,
    /// A PXE sub-option inside option 43 overran or repeated.
    #[error("PXE vendor sub-option {tag} malformed")]
    BadVendorSubOption {
        /// Sub-option tag.
        tag: u8,
    },
    /// The received message is a well-formed BOOTREQUEST but a BOOTREPLY was
    /// expected (used only by [`crate::reply::inspect_reply`]).
    #[error("not a BOOTREPLY (op {op})")]
    NotBootReply {
        /// Received `op`.
        op: u8,
    },
}

impl ParseError {
    /// Stable, low-cardinality label for drop counters and audit summaries.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::TooShort { .. } => "too_short",
            Self::ShortMessage { .. } => "short_message",
            Self::TooLong { .. } => "too_long",
            Self::MissingCookie => "missing_cookie",
            Self::BadCookie => "bad_cookie",
            Self::NotBootRequest { .. } => "not_boot_request",
            Self::BadHardwareType { .. } => "bad_htype",
            Self::BadHardwareLength { .. } => "bad_hlen",
            Self::BadChaddr => "bad_chaddr",
            Self::BadCiaddr => "bad_ciaddr",
            Self::OptionTruncated { .. } => "option_truncated",
            Self::MissingEnd => "missing_end",
            Self::BadOverload { .. } => "bad_overload",
            Self::BadOptionLength { .. } => "bad_option_length",
            Self::DuplicateOption { .. } => "duplicate_option",
            Self::MissingMessageType => "missing_message_type",
            Self::UnhandledMessageType { .. } => "unhandled_message_type",
            Self::BadMachineIdType { .. } => "bad_machine_id_type",
            Self::BadVendorClassArch => "bad_vendor_class_arch",
            Self::VendorClassArchMismatch => "vendor_class_arch_mismatch",
            Self::BadVendorSubOption { .. } => "bad_vendor_sub_option",
            Self::NotBootReply { .. } => "not_boot_reply",
        }
    }
}
