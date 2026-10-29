//! Device session protocol (M3 plan section 3.1): the request and response
//! bodies between the pre-boot agent and the server's device listener
//! (`https://<server>:8444`, JSON over HTTP/1.1, server-authenticated TLS).
//!
//! | Route | Request | Response |
//! |---|---|---|
//! | `POST /v1/device/sessions` | [`DeviceHelloV1`] | [`SessionOpenedV1`] |
//! | `GET /v1/device/session` | | [`SessionStatusV1`] |
//! | `POST /v1/device/session/code` | [`CodeSubmitV1`] | [`SessionStatusV1`] |
//! | `GET /v1/device/session/packages` | | [`DevicePackageListV1`] |
//! | `POST /v1/device/session/package` | [`ChoosePackageV1`] | |
//! | `POST /v1/device/session/disk` | [`ChooseDiskV1`] | |
//! | `POST /v1/device/session/confirm` | [`ConfirmV1`] | [`ConfirmedV1`] |
//! | `POST /v1/device/session/cancel` | [`CancelV1`] | |
//! | `POST /v1/device/session/end` | [`EndSessionV1`] | |
//!
//! Every body refuses unknown and duplicate fields, and every value is
//! checked as it is parsed. Request bodies are parsed with
//! [`crate::api::parse_request`] and [`MAX_DEVICE_JSON_BYTES`]; the confirm
//! response with [`ConfirmedV1::from_json`].
//!
//! **Secrets.** The session token ([`SessionToken`]) and the
//! operator-issued code ([`AuthCode`]) are held in `Zeroizing` buffers,
//! have redacted `Debug`, no `Display`, and are serialised only into the
//! TLS body (`to_json_zeroizing`). The display code ([`DisplayCode`]) and
//! the agent nonce ([`AgentNonce`]) are not secrets.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - strict JSON;
//   closed value sets; bounded lists and text; MAC, token, code and nonce
//   syntax checked; errors never echo values.
// - NIST 800-53: IA-5(1)/IA-5 (Authenticator Management) - single-use
//   codes and session tokens drawn from the DRBG by the caller, zeroized,
//   never displayed or logged by this crate.
// - NIST 800-53: SC-28, SC-8 - secrets travel only in the TLS body; the
//   types offer zeroizing serialisation.
// - NIST 800-53: AC-3 - the bearer token names the session on every route.
// - SPEC: specs/targeting.md#REQ-TGT-004, #REQ-TGT-005, #REQ-TGT-006
//   (package, disk, separate wipe confirmation), #REQ-TGT-008, #REQ-TGT-009
//   (nothing to offer, no usable disk), #REQ-TGT-010, #REQ-TGT-011
//   (cancel), #REQ-TGT-012 (session over TLS), #REQ-TGT-013 (code, case
//   and hyphens ignored), #REQ-TGT-014 (display code for approval),
//   #REQ-TGT-016 (device identity recorded)
// - SPEC: specs/disk.md#REQ-DISK-003 (refused disks reported),
//   #REQ-DISK-006 (wipe confirmation is a distinct, explicit value)
// - SPEC: specs/preinstall-env.md#REQ-PE-020 (firmware and architecture
//   reported)
// - RFC 6750 §2.1 (Bearer), RFC 4648 §4 and §5 (base64, base64url),
//   IEEE 802 (unicast bit of a MAC address); Crockford's public base32
//   symbol set

use std::collections::HashSet;
use std::fmt;

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use zeroize::Zeroizing;

use crate::disk::{Bus, DiskDescriptorV1, DiskToken};
use crate::envelope::{EnvelopeError, SignedEnvelopeV1};
use crate::error_code::ErrorCode;
use crate::facts::{Architecture, Edition, EditionFacts, FactSource, Release};
use crate::ids::{JobId, PackageId, SessionId, UnixMicros};
use crate::limits::{
    MAX_AUTH_CODE_INPUT_BYTES, MAX_CONFIRM_RESPONSE_BYTES, MAX_MACS, MAX_OFFERED_PACKAGES,
    MAX_REFUSED_DISKS,
};
use crate::names::{AgentVersion, Description, DisplayName};

pub use crate::limits::MAX_DEVICE_JSON_BYTES;

/// The only device protocol schema version.
pub const SCHEMA_V1: u32 = 1;

/// Why a device protocol value was refused. Values are never echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DeviceDataError {
    /// `schema` is not 1.
    #[error("schema {0} is not supported (expected 1)")]
    UnsupportedSchema(u32),
    /// A MAC address is not `aa:bb:cc:dd:ee:ff`, or is zero or multicast.
    #[error("MAC address must be six hex pairs separated by ':', unicast and not zero")]
    BadMac,
    /// The MAC list is empty, too long, or repeats an address.
    #[error("macs must list 1 to 16 distinct addresses")]
    BadMacList,
    /// The session token is not 43 base64url characters of 32 bytes.
    #[error("session token is malformed")]
    BadToken,
    /// The code is not 10 base32 symbols (case and hyphens ignored).
    #[error("code must be 10 base32 symbols")]
    BadCode,
    /// The display code is not `XXX-XXX` in base32 symbols.
    #[error("display code must be three base32 symbols, '-', three base32 symbols")]
    BadDisplayCode,
    /// The nonce is not padded base64 of 32 bytes.
    #[error("agent_nonce must be padded base64 of 32 bytes")]
    BadNonce,
    /// A revision is 0.
    #[error("revision must be at least 1")]
    BadRevision,
    /// A list is longer than its limit or repeats an item.
    #[error("{field} has too many entries or repeats one")]
    BadList {
        /// The field.
        field: &'static str,
    },
}

// ---------------------------------------------------------------------------
// Device identity
// ---------------------------------------------------------------------------

/// A unicast, non-zero IEEE 802 MAC address. Wire text is
/// `aa:bb:cc:dd:ee:ff`; either case is accepted and lowercase is written.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MacAddress([u8; 6]);

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

impl MacAddress {
    /// An address from six octets.
    ///
    /// # Errors
    ///
    /// [`DeviceDataError::BadMac`] for all zeros or a multicast (group)
    /// address (the least significant bit of the first octet set).
    pub fn new(octets: [u8; 6]) -> Result<Self, DeviceDataError> {
        if octets == [0; 6] || octets.first().is_some_and(|b| b & 1 == 1) {
            return Err(DeviceDataError::BadMac);
        }
        Ok(Self(octets))
    }

    /// Parses `aa:bb:cc:dd:ee:ff` (17 characters, either case).
    ///
    /// # Errors
    ///
    /// [`DeviceDataError::BadMac`].
    pub fn parse(text: &str) -> Result<Self, DeviceDataError> {
        let b = text.as_bytes();
        if b.len() != 17 {
            return Err(DeviceDataError::BadMac);
        }
        let mut out = [0u8; 6];
        for (i, o) in out.iter_mut().enumerate() {
            let at = i * 3;
            let hi = b.get(at).copied().and_then(hex_nibble);
            let lo = b.get(at + 1).copied().and_then(hex_nibble);
            let sep_ok = i == 5 || b.get(at + 2) == Some(&b':');
            match (hi, lo, sep_ok) {
                (Some(hi), Some(lo), true) => *o = (hi << 4) | lo,
                _ => return Err(DeviceDataError::BadMac),
            }
        }
        Self::new(out)
    }

    /// The six octets (for database columns and the relay's stop set).
    #[must_use]
    pub const fn octets(&self) -> &[u8; 6] {
        &self.0
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddress({self})")
    }
}

impl serde::Serialize for MacAddress {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for MacAddress {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;

        impl serde::de::Visitor<'_> for V {
            type Value = MacAddress;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a MAC address aa:bb:cc:dd:ee:ff")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<MacAddress, E> {
                MacAddress::parse(v).map_err(E::custom)
            }
        }

        d.deserialize_str(V)
    }
}

/// A device's MAC addresses: 1 to [`MAX_MACS`], all distinct, in the
/// order the device reported them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "Vec<MacAddress>", into = "Vec<MacAddress>")]
pub struct MacList(Vec<MacAddress>);

impl MacList {
    /// Checks and wraps a list.
    ///
    /// # Errors
    ///
    /// [`DeviceDataError::BadMacList`] if it is empty, too long, or repeats
    /// an address.
    pub fn new(macs: Vec<MacAddress>) -> Result<Self, DeviceDataError> {
        if macs.is_empty() || macs.len() > MAX_MACS {
            return Err(DeviceDataError::BadMacList);
        }
        let mut seen = HashSet::with_capacity(macs.len());
        if !macs.iter().all(|m| seen.insert(*m)) {
            return Err(DeviceDataError::BadMacList);
        }
        Ok(Self(macs))
    }

    /// The addresses.
    #[must_use]
    pub fn as_slice(&self) -> &[MacAddress] {
        &self.0
    }

    /// `true` if any address is in both lists (the REQ-JOB-009 link to an
    /// earlier job of the same device).
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.0.iter().any(|m| other.0.contains(m))
    }
}

impl TryFrom<Vec<MacAddress>> for MacList {
    type Error = DeviceDataError;

    fn try_from(v: Vec<MacAddress>) -> Result<Self, Self::Error> {
        Self::new(v)
    }
}

impl From<MacList> for Vec<MacAddress> {
    fn from(m: MacList) -> Self {
        m.0
    }
}

closed_enum!(
    /// Firmware the running environment booted from (REQ-PE-020).
    FirmwareKind, "firmware" {
        /// UEFI.
        Uefi => "uefi",
        /// Legacy BIOS (refused, REQ-DISK-011).
        Bios => "bios",
        /// Not determined.
        Unknown => "unknown",
    }
);

closed_enum!(
    /// Processor architecture of the running environment (REQ-PE-020).
    DeviceArch, "architecture" {
        /// x64.
        X64 => "x64",
        /// x86.
        X86 => "x86",
        /// Arm64.
        Arm64 => "arm64",
        /// Not determined.
        Unknown => "unknown",
    }
);

closed_enum!(
    /// Secure Boot state as the environment reports it.
    SecureBootState, "secure boot state" {
        /// Enabled.
        On => "on",
        /// Disabled.
        Off => "off",
        /// Not determined.
        Unknown => "unknown",
    }
);

closed_enum!(
    /// State of a device session (plan section 3.8).
    SessionState, "session state" {
        /// Opened; waiting for a code or an operator's approval.
        AwaitingAuthorisation => "awaiting_authorisation",
        /// Authorised; packages can be listed and chosen.
        Authorised => "authorised",
        /// The wipe was confirmed and a job created.
        Confirmed => "confirmed",
        /// Refused (attempts exhausted or an operator refused it).
        Refused => "refused",
        /// Cancelled at the device before confirmation (REQ-TGT-010).
        Cancelled => "cancelled",
        /// Expired while pending.
        Expired => "expired",
        /// Ended by the device (nothing to offer, no disk, and so on).
        Ended => "ended",
    }
);

impl SessionState {
    /// `true` for states that never change again.
    #[must_use]
    pub const fn is_final(self) -> bool {
        matches!(
            self,
            Self::Confirmed | Self::Refused | Self::Cancelled | Self::Expired | Self::Ended
        )
    }
}

// ---------------------------------------------------------------------------
// Base32 symbols (codes and display codes)
// ---------------------------------------------------------------------------

/// Crockford's base32 symbols, upper case (no I, L, O or U).
const BASE32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn base32_symbol(v: u64) -> char {
    // `v & 31` is below 32, so the lookup always succeeds.
    usize::try_from(v & 31)
        .ok()
        .and_then(|i| BASE32.get(i))
        .map_or('0', |&b| char::from(b))
}

/// Crockford's decode normalisation of one typed byte: case-insensitive,
/// `I` and `L` read as `1`, `O` as `0`. Returns the canonical upper-case
/// symbol, or `None` for anything outside the alphabet (including `U`).
/// Every alias maps to a symbol that is not itself an alias, and canonical
/// symbols map to themselves, so two distinct canonical codes never
/// normalise to the same value.
fn normalize_symbol(c: u8) -> Option<u8> {
    let up = match c.to_ascii_uppercase() {
        b'I' | b'L' => b'1',
        b'O' => b'0',
        other => other,
    };
    BASE32.contains(&up).then_some(up)
}

/// `true` for the separators typed input may contain between groups.
const fn is_separator(c: u8) -> bool {
    matches!(c, b'-' | b' ')
}

/// Longest raw display-code input (`XXX-XXX` plus some separators).
const MAX_DISPLAY_CODE_INPUT_BYTES: usize = 16;

// ---------------------------------------------------------------------------
// Session token (secret)
// ---------------------------------------------------------------------------

/// Length of a session token's text (32 bytes, base64url, no padding).
pub const SESSION_TOKEN_TEXT_LEN: usize = 43;

/// The bearer token of a device session: 32 DRBG bytes, base64url without
/// padding (RFC 4648 §5). The server stores only its SHA-256.
///
/// Held in a zeroizing buffer; `Debug` is redacted; there is no `Display`
/// and no `PartialEq` (compare digests, not tokens).
pub struct SessionToken(Zeroizing<String>);

impl SessionToken {
    /// A token from 32 bytes the caller drew from the `usgp-crypto` DRBG.
    #[must_use]
    pub fn from_random_bytes(bytes: &[u8; 32]) -> Self {
        Self(Zeroizing::new(Base64UrlUnpadded::encode_string(bytes)))
    }

    /// Parses the 43-character text form.
    ///
    /// # Errors
    ///
    /// [`DeviceDataError::BadToken`].
    pub fn parse(text: &str) -> Result<Self, DeviceDataError> {
        if text.len() != SESSION_TOKEN_TEXT_LEN {
            return Err(DeviceDataError::BadToken);
        }
        let mut buf = Zeroizing::new([0u8; 32]);
        let n = Base64UrlUnpadded::decode(text, &mut buf[..])
            .map_err(|_| DeviceDataError::BadToken)?
            .len();
        if n != 32 {
            return Err(DeviceDataError::BadToken);
        }
        Ok(Self(Zeroizing::new(text.to_owned())))
    }

    /// The token from an `Authorization` header value: `Bearer <token>`
    /// (RFC 6750 §2.1; the scheme is matched case-insensitively, RFC 9110
    /// §11.1). Anything else is `None`.
    #[must_use]
    pub fn from_authorization(value: &[u8]) -> Option<Self> {
        let (scheme, rest) = value.split_at_checked(7)?;
        if !scheme.eq_ignore_ascii_case(b"Bearer ") {
            return None;
        }
        Self::parse(std::str::from_utf8(rest).ok()?).ok()
    }

    /// The `Authorization` header value, in a zeroizing buffer.
    #[must_use]
    pub fn authorization_value(&self) -> Zeroizing<String> {
        let mut v = Zeroizing::new(String::with_capacity(7 + SESSION_TOKEN_TEXT_LEN));
        v.push_str("Bearer ");
        v.push_str(&self.0);
        v
    }

    /// The token text, for hashing (server) or the request header (agent).
    /// Never log, display or audit it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken(<redacted>)")
    }
}

impl serde::Serialize for SessionToken {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for SessionToken {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;

        impl serde::de::Visitor<'_> for V {
            type Value = SessionToken;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a session token")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<SessionToken, E> {
                SessionToken::parse(v).map_err(E::custom)
            }
        }

        d.deserialize_str(V)
    }
}

// ---------------------------------------------------------------------------
// Operator-issued code (secret)
// ---------------------------------------------------------------------------

/// Number of base32 symbols in an operator-issued code (50 bits).
pub const AUTH_CODE_SYMBOLS: usize = 10;

/// An operator-issued, single-use authorisation code (REQ-TGT-013): 10
/// symbols of Crockford's base32 alphabet (50 bits from the DRBG).
///
/// Input ignores case and hyphens; anything else outside the symbol set
/// (including the letters I, L, O and U) is refused. The normalised form
/// (10 upper-case symbols, no hyphen) is what the server keys its HMAC
/// with. The display form is `XXXXX-XXXXX`.
///
/// Held in a zeroizing buffer; `Debug` is redacted; there is no `Display`
/// and no `PartialEq`.
pub struct AuthCode(Zeroizing<String>);

impl AuthCode {
    /// A code from 8 bytes the caller drew from the `usgp-crypto` DRBG;
    /// the low 50 bits of the big-endian value are used.
    #[must_use]
    pub fn from_random_bytes(bytes: &[u8; 8]) -> Self {
        let v = Zeroizing::new(u64::from_be_bytes(*bytes) & ((1u64 << 50) - 1));
        let mut s = Zeroizing::new(String::with_capacity(AUTH_CODE_SYMBOLS));
        for i in (0..AUTH_CODE_SYMBOLS).rev() {
            // i < 10, so the shift is below 50.
            let shift = u32::try_from(i * 5).unwrap_or(0);
            s.push(base32_symbol(*v >> shift));
        }
        Self(s)
    }

    /// Parses typed or wire text with Crockford's normalisation: case is
    /// ignored, `I` and `L` read as `1`, `O` as `0`, and hyphens or spaces
    /// are ignored; `U` and anything else outside the alphabet is refused.
    /// The rest must be exactly 10 symbols. Input over
    /// [`MAX_AUTH_CODE_INPUT_BYTES`] bytes is refused.
    ///
    /// # Errors
    ///
    /// [`DeviceDataError::BadCode`]. The text is never echoed.
    pub fn parse(text: &str) -> Result<Self, DeviceDataError> {
        if text.len() > MAX_AUTH_CODE_INPUT_BYTES {
            return Err(DeviceDataError::BadCode);
        }
        let mut s = Zeroizing::new(String::with_capacity(AUTH_CODE_SYMBOLS));
        for b in text.bytes().filter(|&b| !is_separator(b)) {
            let sym = normalize_symbol(b).ok_or(DeviceDataError::BadCode)?;
            if s.len() >= AUTH_CODE_SYMBOLS {
                return Err(DeviceDataError::BadCode);
            }
            s.push(char::from(sym));
        }
        if s.len() != AUTH_CODE_SYMBOLS {
            return Err(DeviceDataError::BadCode);
        }
        Ok(Self(s))
    }

    /// The normalised code (10 upper-case symbols), the HMAC input. Never
    /// log, display or audit it.
    #[must_use]
    pub fn normalized(&self) -> &str {
        &self.0
    }

    /// `XXXXX-XXXXX`, for showing once to the issuing operator.
    #[must_use]
    pub fn grouped(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(AUTH_CODE_SYMBOLS + 1));
        for (i, c) in self.0.chars().enumerate() {
            if i == AUTH_CODE_SYMBOLS / 2 {
                out.push('-');
            }
            out.push(c);
        }
        out
    }
}

impl fmt::Debug for AuthCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthCode(<redacted>)")
    }
}

impl serde::Serialize for AuthCode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.grouped())
    }
}

impl<'de> serde::Deserialize<'de> for AuthCode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;

        impl serde::de::Visitor<'_> for V {
            type Value = AuthCode;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a 10-symbol code")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<AuthCode, E> {
                AuthCode::parse(v).map_err(E::custom)
            }
        }

        d.deserialize_str(V)
    }
}

// ---------------------------------------------------------------------------
// Display code and nonce (not secret)
// ---------------------------------------------------------------------------

/// The code shown on the device's screen, `XXX-XXX` in base32 symbols
/// (30 bits). The operator types it to approve that device
/// (REQ-TGT-014); it is not a secret. Input is case-insensitive; upper
/// case is written.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DisplayCode([u8; 7]);

impl DisplayCode {
    /// A display code from 4 bytes the caller drew from the DRBG (the low
    /// 30 bits of the big-endian value are used).
    #[must_use]
    pub fn from_random_bytes(bytes: [u8; 4]) -> Self {
        let v = u64::from(u32::from_be_bytes(bytes));
        let mut out = [b'-'; 7];
        for (slot, i) in [0usize, 1, 2, 4, 5, 6].into_iter().zip((0u32..6).rev()) {
            if let Some(o) = out.get_mut(slot) {
                // base32_symbol gives an ASCII symbol.
                *o = u8::try_from(base32_symbol(v >> (i * 5))).unwrap_or(b'0');
            }
        }
        Self(out)
    }

    /// Parses typed or wire text with Crockford's normalisation (as
    /// [`AuthCode::parse`]): case ignored, `I`/`L` → `1`, `O` → `0`,
    /// hyphens and spaces ignored, `U` refused. Exactly 6 symbols must
    /// remain; the canonical form `XXX-XXX` is kept.
    ///
    /// # Errors
    ///
    /// [`DeviceDataError::BadDisplayCode`].
    pub fn parse(text: &str) -> Result<Self, DeviceDataError> {
        if text.len() > MAX_DISPLAY_CODE_INPUT_BYTES {
            return Err(DeviceDataError::BadDisplayCode);
        }
        let mut out = [b'-'; 7];
        let mut slots = [0usize, 1, 2, 4, 5, 6].into_iter();
        for b in text.bytes().filter(|&b| !is_separator(b)) {
            let sym = normalize_symbol(b).ok_or(DeviceDataError::BadDisplayCode)?;
            let o = slots
                .next()
                .and_then(|i| out.get_mut(i))
                .ok_or(DeviceDataError::BadDisplayCode)?;
            *o = sym;
        }
        if slots.next().is_some() {
            return Err(DeviceDataError::BadDisplayCode);
        }
        Ok(Self(out))
    }

    /// The text, `XXX-XXX`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Only ASCII is ever stored.
        std::str::from_utf8(&self.0).unwrap_or("???-???")
    }
}

impl fmt::Display for DisplayCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for DisplayCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DisplayCode({})", self.as_str())
    }
}

impl serde::Serialize for DisplayCode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for DisplayCode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;

        impl serde::de::Visitor<'_> for V {
            type Value = DisplayCode;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a display code XXX-XXX")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<DisplayCode, E> {
                DisplayCode::parse(v).map_err(E::custom)
            }
        }

        d.deserialize_str(V)
    }
}

/// A fresh 32-byte nonce the agent sends with the confirmation; the signed
/// plan must carry it back (plan section 3.2, freshness without a trusted
/// clock). Wire form: padded base64 (RFC 4648 §4), 44 characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AgentNonce([u8; 32]);

impl AgentNonce {
    /// A nonce from 32 bytes the caller drew from the DRBG.
    #[must_use]
    pub const fn from_random_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parses 44 characters of padded base64.
    ///
    /// # Errors
    ///
    /// [`DeviceDataError::BadNonce`].
    pub fn parse(text: &str) -> Result<Self, DeviceDataError> {
        if text.len() != 44 {
            return Err(DeviceDataError::BadNonce);
        }
        let mut out = [0u8; 32];
        let n = Base64::decode(text, &mut out)
            .map_err(|_| DeviceDataError::BadNonce)?
            .len();
        if n != 32 {
            return Err(DeviceDataError::BadNonce);
        }
        Ok(Self(out))
    }
}

impl fmt::Display for AgentNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&Base64::encode_string(&self.0))
    }
}

impl fmt::Debug for AgentNonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AgentNonce({self})")
    }
}

impl serde::Serialize for AgentNonce {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for AgentNonce {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;

        impl serde::de::Visitor<'_> for V {
            type Value = AgentNonce;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("32 bytes of padded base64")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<AgentNonce, E> {
                AgentNonce::parse(v).map_err(E::custom)
            }
        }

        d.deserialize_str(V)
    }
}

// POAM: serde_json may copy a token or code into scratch buffers it does
// not zeroize (string unescaping on parse; the output buffer before it is
// wrapped). Callers keep request and response buffers in `Zeroizing`; the
// residual copies are short-lived heap memory inside the process.
/// Serialises a body that holds a secret into a zeroizing buffer.
fn to_json_zeroizing<T: serde::Serialize>(v: &T) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
    serde_json::to_vec(v).map(Zeroizing::new)
}

fn revision(r: u64) -> Result<u64, DeviceDataError> {
    if r == 0 {
        Err(DeviceDataError::BadRevision)
    } else {
        Ok(r)
    }
}

// ---------------------------------------------------------------------------
// Open and status
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceHelloWire {
    schema: u32,
    agent_version: AgentVersion,
    firmware: FirmwareKind,
    arch: DeviceArch,
    secure_boot: SecureBootState,
    memory_bytes: u64,
    macs: MacList,
}

/// `POST /v1/device/sessions` body: what the device says about itself.
/// Every value is a claim (recorded as `claimed` in audit, plan section 7).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "DeviceHelloWire")]
pub struct DeviceHelloV1 {
    /// Always [`SCHEMA_V1`].
    pub schema: u32,
    /// Agent version.
    pub agent_version: AgentVersion,
    /// Firmware mode.
    pub firmware: FirmwareKind,
    /// Processor architecture.
    pub arch: DeviceArch,
    /// Secure Boot state.
    pub secure_boot: SecureBootState,
    /// Physical memory in bytes.
    pub memory_bytes: u64,
    /// MAC addresses.
    pub macs: MacList,
}

impl TryFrom<DeviceHelloWire> for DeviceHelloV1 {
    type Error = DeviceDataError;

    fn try_from(w: DeviceHelloWire) -> Result<Self, Self::Error> {
        if w.schema != SCHEMA_V1 {
            return Err(DeviceDataError::UnsupportedSchema(w.schema));
        }
        Ok(Self {
            schema: w.schema,
            agent_version: w.agent_version,
            firmware: w.firmware,
            arch: w.arch,
            secure_boot: w.secure_boot,
            memory_bytes: w.memory_bytes,
            macs: w.macs,
        })
    }
}

/// `201` response to [`DeviceHelloV1`]. The token is sent once.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionOpenedV1 {
    /// Session id.
    pub session_id: SessionId,
    /// Bearer token for every later route (secret).
    pub token: SessionToken,
    /// Code to show on the device's screen.
    pub display_code: DisplayCode,
    /// Always `awaiting_authorisation` on open.
    pub state: SessionState,
    /// Suggested poll interval in milliseconds.
    pub poll_ms: u32,
    /// When a pending session expires.
    pub expires_at: UnixMicros,
}

impl SessionOpenedV1 {
    /// The response body, in a zeroizing buffer (it holds the token).
    ///
    /// # Errors
    ///
    /// Serialization errors (not expected for this type).
    pub fn to_json_zeroizing(&self) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
        to_json_zeroizing(self)
    }
}

/// `GET /v1/device/session` response (also the response to a code).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionStatusV1 {
    /// State.
    pub state: SessionState,
    /// Display code.
    pub display_code: DisplayCode,
    /// Code attempts left before the session is refused.
    pub code_attempts_left: u32,
    /// When a pending session expires.
    pub expires_at: UnixMicros,
    /// The boot service the device was resolved to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_service_name: Option<DisplayName>,
    /// Reason for a refused, expired or ended session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<ErrorCode>,
}

/// `POST /v1/device/session/code` body.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeSubmitV1 {
    /// The code the technician typed (secret).
    pub code: AuthCode,
}

impl CodeSubmitV1 {
    /// The request body, in a zeroizing buffer (it holds the code).
    ///
    /// # Errors
    ///
    /// Serialization errors (not expected for this type).
    pub fn to_json_zeroizing(&self) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
        to_json_zeroizing(self)
    }
}

// ---------------------------------------------------------------------------
// Packages
// ---------------------------------------------------------------------------

/// What a package installs, for the device's list (REQ-TGT-004).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceOsV1 {
    /// Windows release.
    pub release: Release,
    /// Edition.
    pub edition: Edition,
    /// Architecture.
    pub architecture: Architecture,
    /// `verified` only if all three facts are verified; otherwise
    /// `declared` (see [`DeviceOsV1::from_facts`]).
    pub source: FactSource,
}

impl DeviceOsV1 {
    /// The device view of a package's facts. The single `source` is the
    /// weaker of the three: `verified` only when every fact is verified.
    #[must_use]
    pub fn from_facts(f: &EditionFacts) -> Self {
        let all_verified = [f.release.source, f.edition.source, f.architecture.source]
            .iter()
            .all(|s| *s == FactSource::Verified);
        Self {
            release: f.release.value,
            edition: f.edition.value,
            architecture: f.architecture.value,
            source: if all_verified {
                FactSource::Verified
            } else {
                FactSource::Declared
            },
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DevicePackageWire {
    package_id: PackageId,
    revision: u64,
    name: DisplayName,
    #[serde(default)]
    description: Option<Description>,
    os: DeviceOsV1,
    image_bytes: u64,
    required_disk_bytes: u64,
}

/// One package offered to the device.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "DevicePackageWire")]
pub struct DevicePackageV1 {
    /// Package id.
    pub package_id: PackageId,
    /// Revision (at least 1).
    pub revision: u64,
    /// Name.
    pub name: DisplayName,
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
    /// OS facts.
    pub os: DeviceOsV1,
    /// Size of the image file.
    pub image_bytes: u64,
    /// Smallest disk the package can be installed on (REQ-DISK-004).
    pub required_disk_bytes: u64,
}

impl TryFrom<DevicePackageWire> for DevicePackageV1 {
    type Error = DeviceDataError;

    fn try_from(w: DevicePackageWire) -> Result<Self, Self::Error> {
        Ok(Self {
            package_id: w.package_id,
            revision: revision(w.revision)?,
            name: w.name,
            description: w.description,
            os: w.os,
            image_bytes: w.image_bytes,
            required_disk_bytes: w.required_disk_bytes,
        })
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DevicePackageListWire {
    packages: Vec<DevicePackageV1>,
}

/// `GET /v1/device/session/packages` response. An empty list means
/// nothing to offer (REQ-TGT-008).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "DevicePackageListWire")]
pub struct DevicePackageListV1 {
    packages: Vec<DevicePackageV1>,
}

impl TryFrom<DevicePackageListWire> for DevicePackageListV1 {
    type Error = DeviceDataError;

    fn try_from(w: DevicePackageListWire) -> Result<Self, Self::Error> {
        Self::new(w.packages)
    }
}

impl DevicePackageListV1 {
    /// Checks and wraps a list: at most [`MAX_OFFERED_PACKAGES`], no
    /// package twice.
    ///
    /// # Errors
    ///
    /// [`DeviceDataError::BadList`].
    pub fn new(packages: Vec<DevicePackageV1>) -> Result<Self, DeviceDataError> {
        let mut seen = HashSet::with_capacity(packages.len());
        if packages.len() > MAX_OFFERED_PACKAGES
            || !packages.iter().all(|p| seen.insert(p.package_id))
        {
            return Err(DeviceDataError::BadList { field: "packages" });
        }
        Ok(Self { packages })
    }

    /// The packages offered.
    #[must_use]
    pub fn packages(&self) -> &[DevicePackageV1] {
        &self.packages
    }

    /// The offered package with this id and revision, if any.
    #[must_use]
    pub fn find(&self, id: PackageId, revision: u64) -> Option<&DevicePackageV1> {
        self.packages
            .iter()
            .find(|p| p.package_id == id && p.revision == revision)
    }
}

// ---------------------------------------------------------------------------
// Choices, confirmation, cancel, end
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ChoosePackageWire {
    package_id: PackageId,
    revision: u64,
}

/// `POST /v1/device/session/package` body (REQ-TGT-004).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "ChoosePackageWire")]
pub struct ChoosePackageV1 {
    /// Package id.
    pub package_id: PackageId,
    /// Revision (at least 1).
    pub revision: u64,
}

impl TryFrom<ChoosePackageWire> for ChoosePackageV1 {
    type Error = DeviceDataError;

    fn try_from(w: ChoosePackageWire) -> Result<Self, Self::Error> {
        Ok(Self {
            package_id: w.package_id,
            revision: revision(w.revision)?,
        })
    }
}

/// `POST /v1/device/session/disk` body (REQ-TGT-005).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChooseDiskV1 {
    /// The chosen disk.
    pub disk: DiskDescriptorV1,
}

closed_enum!(
    /// The explicit wipe confirmation (REQ-DISK-006, decision 0018 item
    /// 7). There is no other value, so no request can skip it.
    WipeConfirmation, "confirmation" {
        /// The technician confirmed that the disk will be wiped.
        WipeDisk => "wipe-disk",
    }
);

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmWire {
    package_id: PackageId,
    revision: u64,
    disk_token: DiskToken,
    confirm: WipeConfirmation,
    agent_nonce: AgentNonce,
}

/// `POST /v1/device/session/confirm` body: the separate wipe confirmation
/// (REQ-TGT-006, REQ-DISK-006). It must repeat the chosen package and disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "ConfirmWire")]
pub struct ConfirmV1 {
    /// Chosen package.
    pub package_id: PackageId,
    /// Its revision.
    pub revision: u64,
    /// Chosen disk.
    pub disk_token: DiskToken,
    /// Always `wipe-disk`.
    pub confirm: WipeConfirmation,
    /// Fresh nonce the plan must carry back.
    pub agent_nonce: AgentNonce,
}

impl TryFrom<ConfirmWire> for ConfirmV1 {
    type Error = DeviceDataError;

    fn try_from(w: ConfirmWire) -> Result<Self, Self::Error> {
        Ok(Self {
            package_id: w.package_id,
            revision: revision(w.revision)?,
            disk_token: w.disk_token,
            confirm: w.confirm,
            agent_nonce: w.agent_nonce,
        })
    }
}

/// Errors from parsing a [`ConfirmedV1`] response.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfirmedError {
    /// Over [`MAX_CONFIRM_RESPONSE_BYTES`].
    #[error("confirm response is {len} bytes; the limit is {MAX_CONFIRM_RESPONSE_BYTES}")]
    TooLarge {
        /// Length in bytes.
        len: usize,
    },
    /// Not JSON of the expected shape (envelope limits included).
    #[error("confirm response is not valid JSON of the expected shape")]
    Json(#[source] serde_json::Error),
    /// An envelope failed its own checks.
    #[error(transparent)]
    Envelope(#[from] EnvelopeError),
}

/// `201` response to [`ConfirmV1`]: the job and its signed plan and
/// content manifest. Holding it says nothing about the signatures; see
/// [`crate::job_plan::VerifiedJobPlan::verify`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfirmedV1 {
    /// The new job.
    pub job_id: JobId,
    /// Signed [`crate::job_plan::JobPlanV1`].
    pub plan: SignedEnvelopeV1,
    /// Signed [`crate::ContentManifestV1`] of the image.
    pub content_manifest: SignedEnvelopeV1,
}

impl ConfirmedV1 {
    /// Parses the response after checking its size.
    ///
    /// # Errors
    ///
    /// [`ConfirmedError`].
    pub fn from_json(bytes: &[u8]) -> Result<Self, ConfirmedError> {
        if bytes.len() > MAX_CONFIRM_RESPONSE_BYTES {
            return Err(ConfirmedError::TooLarge { len: bytes.len() });
        }
        serde_json::from_slice(bytes).map_err(ConfirmedError::Json)
    }
}

/// `POST /v1/device/session/cancel` body: exactly `{}` (REQ-TGT-010).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub struct CancelV1 {}

impl<'de> serde::Deserialize<'de> for CancelV1 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;

        impl<'de> serde::de::Visitor<'de> for V {
            type Value = CancelV1;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an empty object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut m: A,
            ) -> Result<CancelV1, A::Error> {
                match m.next_key::<serde::de::IgnoredAny>()? {
                    None => Ok(CancelV1 {}),
                    Some(_) => Err(serde::de::Error::custom("cancel takes no fields")),
                }
            }
        }

        d.deserialize_map(V)
    }
}

closed_enum!(
    /// Why the device ended its session (plan section 3.1).
    EndReason, "end reason" {
        /// No package was offered (REQ-TGT-008).
        NothingToOffer => "nothing_to_offer",
        /// No eligible disk (REQ-TGT-009, REQ-DISK-003).
        NoDisk => "no_disk",
        /// Not UEFI or not x64 (REQ-PE-020, REQ-DISK-011).
        FirmwareUnsupported => "firmware_unsupported",
        /// The agent hit an error before confirmation.
        AgentError => "agent_error",
    }
);

closed_enum!(
    /// Why a disk was not eligible (`usgp-disk` eligibility; plan section
    /// 3.7).
    DiskRefusal, "disk refusal" {
        /// Removable media (REQ-DISK-005).
        Removable => "removable",
        /// A USB disk, even one that reports itself fixed (OPEN-DISK-4,
        /// refused until decided).
        UsbDisk => "usb_disk",
        /// A bus the product does not install to.
        UnsupportedBus => "unsupported_bus",
        /// The disk the environment booted from (REQ-DISK-005).
        BootMedia => "boot_media",
        /// Below the minimum size (REQ-DISK-004).
        TooSmall => "too_small",
        /// Read-only.
        ReadOnly => "read_only",
        /// A sector size other than 512 or 4096.
        UnsupportedSectorSize => "unsupported_sector_size",
        /// Agent only: the volumes on the disk could not all be identified,
        /// so the disk cannot be shown not to hold the running boot
        /// environment (REQ-DISK-005; fail closed).
        VolumesUndetermined => "volumes_undetermined",
        /// Agent only: the disk's partition table could not be described
        /// for the operator (REQ-DISK-006 needs the partitions shown).
        PartitionTableUndescribable => "partition_table_undescribable",
        /// Agent only: another otherwise eligible disk has the same model,
        /// bus, size and sector sizes and neither reports a serial number,
        /// so the person could not tell which disk would be erased
        /// (REQ-DISK-006; SEC-003, fix round 1).
        IndistinguishableDisks => "indistinguishable_disks",
    }
);

/// A disk the device refused, reported when the session ends with
/// `no_disk` (REQ-DISK-003). Only the bus, size and reason; no identity
/// and no content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefusedDiskV1 {
    /// Bus.
    pub bus: Bus,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Reason.
    pub reason: DiskRefusal,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EndSessionWire {
    reason: EndReason,
    #[serde(default)]
    refused_disks: Vec<RefusedDiskV1>,
}

/// `POST /v1/device/session/end` body.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "EndSessionWire")]
pub struct EndSessionV1 {
    /// Why.
    pub reason: EndReason,
    /// Refused disks (at most [`MAX_REFUSED_DISKS`]).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub refused_disks: Vec<RefusedDiskV1>,
}

impl TryFrom<EndSessionWire> for EndSessionV1 {
    type Error = DeviceDataError;

    fn try_from(w: EndSessionWire) -> Result<Self, Self::Error> {
        if w.refused_disks.len() > MAX_REFUSED_DISKS {
            return Err(DeviceDataError::BadList {
                field: "refused_disks",
            });
        }
        Ok(Self {
            reason: w.reason,
            refused_disks: w.refused_disks,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_rules() {
        let m = MacAddress::parse("A8:bb:0C:dd:ee:ff").unwrap();
        assert_eq!(m.to_string(), "a8:bb:0c:dd:ee:ff");
        assert_eq!(m.octets(), &[0xa8, 0xbb, 0x0c, 0xdd, 0xee, 0xff]);
        // 0xa9 has the group (multicast) bit set.
        assert_eq!(
            MacAddress::parse("a9:bb:0c:dd:ee:ff"),
            Err(DeviceDataError::BadMac)
        );
        for bad in [
            "00:00:00:00:00:00",
            "01:00:5e:00:00:01",
            "ff:ff:ff:ff:ff:ff",
            "a8-bb-0c-dd-ee-ff",
            "a8:bb:0c:dd:ee:f",
            "a8:bb:0c:dd:ee:ff:",
            "a8:bb:0c:dd:ee:fg",
            "a8bb0cddeeff",
            "",
        ] {
            assert_eq!(
                MacAddress::parse(bad),
                Err(DeviceDataError::BadMac),
                "{bad}"
            );
        }
    }

    #[test]
    fn mac_list_rules() {
        let a = MacAddress::new([2, 0, 0, 0, 0, 1]).unwrap();
        let b = MacAddress::new([2, 0, 0, 0, 0, 2]).unwrap();
        assert!(MacList::new(vec![a, b]).is_ok());
        assert_eq!(MacList::new(vec![]), Err(DeviceDataError::BadMacList));
        assert_eq!(MacList::new(vec![a, a]), Err(DeviceDataError::BadMacList));
        let many: Vec<_> = (1..=17u8)
            .map(|i| MacAddress::new([2, 0, 0, 0, 0, i]).unwrap())
            .collect();
        assert_eq!(MacList::new(many), Err(DeviceDataError::BadMacList));
        let x = MacList::new(vec![a]).unwrap();
        let y = MacList::new(vec![b, a]).unwrap();
        let z = MacList::new(vec![b]).unwrap();
        assert!(x.overlaps(&y));
        assert!(!x.overlaps(&z));
    }

    #[test]
    fn auth_code_normalisation() {
        let c = AuthCode::parse("abcde-fghjk").unwrap();
        assert_eq!(c.normalized(), "ABCDEFGHJK");
        assert_eq!(c.grouped().as_str(), "ABCDE-FGHJK");
        assert_eq!(
            AuthCode::parse("A-B-C-D-E-F-G-H-J-K").unwrap().normalized(),
            "ABCDEFGHJK"
        );
        assert_eq!(
            AuthCode::parse("abcde fghjk").unwrap().normalized(),
            "ABCDEFGHJK"
        );
        for bad in [
            "ABCDEFGHJ",
            "ABCDEFGHJKM",
            "ABCDEFGHJU",
            "ABCDEFGHJu",
            "ABCDE_FGHJK",
            "ABCDE\tFGHJK",
            "ABCDEFGHJ\u{e9}",
            "",
        ] {
            assert!(AuthCode::parse(bad).is_err(), "{bad}");
        }
        let long = format!("{}ABCDEFGHJK", "-".repeat(30));
        assert!(AuthCode::parse(&long).is_err());
        assert!(AuthCode::parse(&format!("{}ABCDEFGHJK", "-".repeat(22))).is_ok());
    }

    #[test]
    fn crockford_aliases() {
        // I and L read as 1, O as 0, either case; U is refused.
        for (typed, want) in [
            ("IIIIIIIIII", "1111111111"),
            ("iiiiiiiiii", "1111111111"),
            ("LLLLLLLLLL", "1111111111"),
            ("llllllllll", "1111111111"),
            ("OOOOOOOOOO", "0000000000"),
            ("oooooooooo", "0000000000"),
            ("Il0Oi-LoAzZ", "1100110AZZ"),
            ("Il0Oi LoAzZ", "1100110AZZ"),
        ] {
            assert_eq!(
                AuthCode::parse(typed).unwrap().normalized(),
                want,
                "{typed}"
            );
        }
        assert!(AuthCode::parse("UUUUUUUUUU").is_err());
        assert!(AuthCode::parse("uuuuuuuuuu").is_err());
    }

    #[test]
    fn normalisation_never_collides_canonical_codes() {
        // Per symbol: every canonical symbol (either case) maps to itself,
        // and the map is injective on the canonical alphabet. Aliases are
        // never canonical and map only onto canonical symbols, so two
        // distinct canonical codes cannot normalise to the same value.
        let mut seen = std::collections::HashSet::new();
        for &c in BASE32 {
            assert_eq!(normalize_symbol(c), Some(c));
            assert_eq!(normalize_symbol(c.to_ascii_lowercase()), Some(c));
            assert!(seen.insert(normalize_symbol(c)));
        }
        assert_eq!(seen.len(), 32);
        for alias in *b"ILOilo" {
            assert!(!BASE32.contains(&alias.to_ascii_uppercase()));
            assert!(BASE32.contains(&normalize_symbol(alias).unwrap()));
        }
        // Canonical codes round-trip unchanged, and distinct canonical
        // codes stay distinct after parsing.
        let mut outputs = std::collections::HashSet::new();
        for i in 0u64..4096 {
            let v = i.wrapping_mul(0x9e37_79b9_7f4a_7c15);
            let c = AuthCode::from_random_bytes(&v.to_be_bytes());
            let again = AuthCode::parse(&c.grouped()).unwrap();
            assert_eq!(again.normalized(), c.normalized());
            outputs.insert((c.normalized().to_owned(), again.normalized().to_owned()));
            let d =
                DisplayCode::from_random_bytes(u32::try_from(v >> 32).unwrap_or(0).to_be_bytes());
            assert_eq!(DisplayCode::parse(d.as_str()).unwrap(), d);
        }
        let canon: std::collections::HashSet<_> = outputs.iter().map(|(a, _)| a).collect();
        let parsed: std::collections::HashSet<_> = outputs.iter().map(|(_, b)| b).collect();
        assert_eq!(canon.len(), parsed.len());
    }

    #[test]
    fn auth_code_from_random() {
        let zero = AuthCode::from_random_bytes(&[0; 8]);
        assert_eq!(zero.normalized(), "0000000000");
        let max = AuthCode::from_random_bytes(&[0xff; 8]);
        assert_eq!(max.normalized(), "ZZZZZZZZZZ");
        let one = AuthCode::from_random_bytes(&[0, 0, 0, 0, 0, 0, 0, 33]);
        assert_eq!(one.normalized(), "0000000011");
        // Every generated code parses back to itself.
        let c = AuthCode::from_random_bytes(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            AuthCode::parse(&c.grouped()).unwrap().normalized(),
            c.normalized()
        );
    }

    #[test]
    fn secrets_are_redacted_in_debug() {
        let c = AuthCode::parse("ABCDEFGHJK").unwrap();
        assert_eq!(format!("{c:?}"), "AuthCode(<redacted>)");
        let t = SessionToken::from_random_bytes(&[7; 32]);
        assert_eq!(format!("{t:?}"), "SessionToken(<redacted>)");
        let submit = CodeSubmitV1 { code: c };
        assert!(!format!("{submit:?}").contains("ABCDE"));
    }

    #[test]
    fn token_text_and_bearer() {
        let t = SessionToken::from_random_bytes(&[0xfb; 32]);
        assert_eq!(t.expose().len(), SESSION_TOKEN_TEXT_LEN);
        assert!(t.expose().contains('-') || t.expose().contains('_'));
        let back = SessionToken::parse(t.expose()).unwrap();
        assert_eq!(back.expose(), t.expose());
        let header = t.authorization_value();
        let got = SessionToken::from_authorization(header.as_bytes()).unwrap();
        assert_eq!(got.expose(), t.expose());
        let lower = format!("bearer {}", t.expose());
        assert!(SessionToken::from_authorization(lower.as_bytes()).is_some());
        for bad in [
            format!("Bearer  {}", t.expose()),
            format!("Basic {}", t.expose()),
            format!("Bearer {}=", t.expose()),
            format!("Bearer {} ", t.expose()),
            "Bearer".to_owned(),
            String::new(),
        ] {
            assert!(
                SessionToken::from_authorization(bad.as_bytes()).is_none(),
                "{bad}"
            );
        }
        // Standard base64 symbols are not base64url.
        let std_alpha = t.expose().replace('-', "+").replace('_', "/");
        assert!(SessionToken::parse(&std_alpha).is_err());
        assert!(SessionToken::parse(&"A".repeat(44)).is_err());
    }

    #[test]
    fn display_code_text() {
        let d = DisplayCode::from_random_bytes([0xff; 4]);
        assert_eq!(d.as_str(), "ZZZ-ZZZ");
        let z = DisplayCode::from_random_bytes([0; 4]);
        assert_eq!(z.as_str(), "000-000");
        assert_eq!(DisplayCode::parse("ab1-x9z").unwrap().as_str(), "AB1-X9Z");
        for ok in ["AB1X9Z", "ab1 x9z", "-AB1X9Z", "AB1-X9Z-", "ab1 - x9z"] {
            assert_eq!(DisplayCode::parse(ok).unwrap().as_str(), "AB1-X9Z", "{ok}");
        }
        assert_eq!(DisplayCode::parse("il0-oLi").unwrap().as_str(), "110-011");
        for bad in [
            "AB1-X9",
            "AB1-X9ZZ",
            "AB1_X9Z",
            "AU1-X9Z",
            "AB1-X9\u{e9}",
            "AB1                    X9Z",
            "",
        ] {
            assert!(DisplayCode::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn nonce_text() {
        let n = AgentNonce::from_random_bytes([9; 32]);
        let s = n.to_string();
        assert_eq!(s.len(), 44);
        assert_eq!(AgentNonce::parse(&s).unwrap(), n);
        assert!(AgentNonce::parse(&s.replacen('=', "", 1)).is_err());
        assert!(AgentNonce::parse(&Base64::encode_string(&[1; 31])).is_err());
        assert!(AgentNonce::parse(&Base64::encode_string(&[1; 33])).is_err());
    }

    #[test]
    fn os_source_is_the_weakest() {
        use crate::facts::Fact;
        let mut f = EditionFacts {
            release: Fact::verified(Release::Windows11),
            edition: Fact::verified(Edition::Enterprise),
            architecture: Fact::verified(Architecture::X64),
        };
        assert_eq!(DeviceOsV1::from_facts(&f).source, FactSource::Verified);
        f.edition = Fact::declared(Edition::Enterprise);
        assert_eq!(DeviceOsV1::from_facts(&f).source, FactSource::Declared);
    }

    #[test]
    fn session_state_finality() {
        assert!(!SessionState::AwaitingAuthorisation.is_final());
        assert!(!SessionState::Authorised.is_final());
        for s in [
            SessionState::Confirmed,
            SessionState::Refused,
            SessionState::Cancelled,
            SessionState::Expired,
            SessionState::Ended,
        ] {
            assert!(s.is_final());
        }
    }
}
