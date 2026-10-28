//! Operator API additions for M3 (plan section 3.5): authorisation codes,
//! device sessions, jobs, boot services and boot stops.
//!
//! The M2 conventions of [`crate::api`] apply. Requests have a wire form
//! with plain JSON types (shape errors are 400 `invalid_json`) and a
//! `validate()` that gives strong types or a [`FieldError`] naming the
//! field (422). Responses use strong types and refuse unknown fields.
//!
//! The only secret here is the code value in [`AuthCodeIssuedV1`], shown
//! once to the issuing operator. No view carries a code value or a session
//! token (REQ-TGT-013, REQ-JOB-014).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - strict JSON;
//   bounded notes, lists and identifiers; CIDR syntax.
// - NIST 800-53: IA-5 (Authenticator Management) - a code value appears
//   only in the issue response, zeroized, redacted in Debug.
// - NIST 800-53: AC-3 (Access Enforcement) - path ids parse only as UUIDs;
//   approval bound to the device's display code.
// - NIST 800-53: AU-3 (Content of Audit Records, basis) - the views carry
//   the identity the audit records name (REQ-TGT-016).
// - SPEC: specs/targeting.md#REQ-TGT-001 (packages per boot service),
//   #REQ-TGT-008 (warning when nothing is usable), #REQ-TGT-013 (codes:
//   issue, list, revoke; no values), #REQ-TGT-014 (approval with display
//   code), #REQ-TGT-016 (device identity)
// - SPEC: specs/progress.md#REQ-JOB-001 (job record), #REQ-JOB-002 (steps),
//   #REQ-JOB-003 (overall percentage), #REQ-JOB-006 (failure detail,
//   attempts, persistence until acknowledged), #REQ-JOB-009 (previous job),
//   #REQ-JOB-014 (no secrets)
// - SPEC: specs/disk.md#REQ-DISK-014 (disk and layout reported)
// - SPEC: specs/boot-network.md#REQ-BOOT-067 (boot stops, minimal clear)
// - RFC 4632 §3.1 (IPv4 prefix notation), RFC 4291 §2.3 (IPv6 prefixes)

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;

use zeroize::Zeroizing;

use crate::api::{FieldError, PackageRef, Reason};
use crate::device::{
    AuthCode, DeviceArch, DisplayCode, FirmwareKind, MacAddress, MacList, SecureBootState,
    SessionState,
};
use crate::disk::{DiskDescriptorV1, LayoutReportV1};
use crate::error_code::codes;
use crate::ids::{
    AuthCodeId, BootServiceId, BootStopId, JobId, OperatorId, PackageId, SessionId, UnixMicros,
};
use crate::limits::{MAX_BOOT_SERVICE_PACKAGES, MAX_SERVED_SUBNETS};
use crate::names::{AgentVersion, DisplayName, EditionIndex, Note};
use crate::progress::{FailureV1, JobState, Step, StepKind, StepState};

/// Longest code lifetime a request may ask for, in seconds (1 day). The
/// server applies its own `codes.max_ttl_s`, which must not exceed it.
pub const MAX_CODE_TTL_S: u64 = 86_400;

// ---------------------------------------------------------------------------
// Authorisation codes
// ---------------------------------------------------------------------------

/// Wire body of `POST /v1/auth-codes`.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssueAuthCodeRequest {
    /// Lifetime in seconds; the server default if absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_s: Option<u64>,
    /// Operator note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// A validated code request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssueAuthCode {
    /// Lifetime in seconds (1 to [`MAX_CODE_TTL_S`]).
    pub ttl_s: Option<u32>,
    /// Note.
    pub note: Option<Note>,
}

impl IssueAuthCodeRequest {
    /// Validates every field.
    ///
    /// # Errors
    ///
    /// `out_of_range:ttl_s`, or a name rule on `note`.
    pub fn validate(&self) -> Result<IssueAuthCode, FieldError> {
        let ttl_s = self
            .ttl_s
            .map(|t| {
                u32::try_from(t)
                    .ok()
                    .filter(|&t| t >= 1 && u64::from(t) <= MAX_CODE_TTL_S)
                    .ok_or_else(|| {
                        FieldError::new(
                            "ttl_s",
                            &codes::OUT_OF_RANGE,
                            format!("ttl_s must be 1 to {MAX_CODE_TTL_S} seconds"),
                        )
                    })
            })
            .transpose()?;
        let note = self
            .note
            .as_deref()
            .map(Note::new)
            .transpose()
            .map_err(|e| FieldError::name("note", e))?;
        Ok(IssueAuthCode { ttl_s, note })
    }
}

impl From<&IssueAuthCode> for IssueAuthCodeRequest {
    fn from(v: &IssueAuthCode) -> Self {
        Self {
            ttl_s: v.ttl_s.map(u64::from),
            note: v.note.as_ref().map(|n| n.as_str().to_owned()),
        }
    }
}

/// `201` response to `POST /v1/auth-codes`: the code, shown once (sent
/// with `Cache-Control: no-store`, never logged or audited).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthCodeIssuedV1 {
    /// Record id (used to revoke).
    pub id: AuthCodeId,
    /// The code (secret), `XXXXX-XXXXX`.
    pub code: AuthCode,
    /// When it expires.
    pub expires_at: UnixMicros,
}

impl AuthCodeIssuedV1 {
    /// The response body, in a zeroizing buffer (it holds the code).
    ///
    /// # Errors
    ///
    /// Serialization errors (not expected for this type).
    pub fn to_json_zeroizing(&self) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
        serde_json::to_vec(self).map(Zeroizing::new)
    }
}

closed_enum!(
    /// State of an issued code, derived from its record.
    AuthCodeState, "code state" {
        /// Usable.
        Active => "active",
        /// Used by a session.
        Used => "used",
        /// Past its lifetime.
        Expired => "expired",
        /// Revoked by an operator.
        Revoked => "revoked",
    }
);

/// An issued code's record (`GET /v1/auth-codes`). No code value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthCodeView {
    /// Record id.
    pub id: AuthCodeId,
    /// State.
    pub state: AuthCodeState,
    /// Issuing operator.
    pub issued_by: OperatorId,
    /// When issued.
    pub issued_at: UnixMicros,
    /// When it expires.
    pub expires_at: UnixMicros,
    /// When used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_at: Option<UnixMicros>,
    /// The session that used it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_by_session: Option<SessionId>,
    /// When revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<UnixMicros>,
    /// Who revoked it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<OperatorId>,
    /// Note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<Note>,
}

/// Response of `GET /v1/auth-codes`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthCodeList {
    /// Codes.
    pub codes: Vec<AuthCodeView>,
}

// ---------------------------------------------------------------------------
// Device sessions
// ---------------------------------------------------------------------------

closed_enum!(
    /// How a session was authorised.
    AuthMethod, "authorisation method" {
        /// An operator-issued code (REQ-TGT-013).
        Code => "code",
        /// Operator approval (REQ-TGT-014).
        Approval => "approval",
    }
);

/// A device session (`GET /v1/device-sessions`): the identity the operator
/// needs to decide on approval (MACs, source IP, firmware, architecture,
/// Secure Boot, memory, boot service, display code, waiting since).
/// Device-reported values are claims.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSessionView {
    /// Session id.
    pub id: SessionId,
    /// State.
    pub state: SessionState,
    /// MAC addresses (claimed).
    pub macs: MacList,
    /// Source IP the server saw.
    pub source_ip: IpAddr,
    /// Firmware (claimed).
    pub firmware: FirmwareKind,
    /// Architecture (claimed).
    pub arch: DeviceArch,
    /// Secure Boot (claimed).
    pub secure_boot: SecureBootState,
    /// Memory (claimed).
    pub memory_bytes: u64,
    /// Agent version (claimed).
    pub agent_version: AgentVersion,
    /// Boot service resolved from the source IP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_service_id: Option<BootServiceId>,
    /// Its name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_service_name: Option<DisplayName>,
    /// Display code on the device's screen.
    pub display_code: DisplayCode,
    /// How it was authorised, once it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_method: Option<AuthMethod>,
    /// Failed code attempts.
    pub failed_code_attempts: u32,
    /// Opened (waiting since).
    pub created_at: UnixMicros,
    /// Last poll.
    pub last_seen_at: UnixMicros,
    /// When it expires if still pending.
    pub expires_at: UnixMicros,
    /// Chosen package.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chosen_package_id: Option<PackageId>,
    /// Its revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chosen_package_revision: Option<u64>,
    /// Chosen disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chosen_disk: Option<DiskDescriptorV1>,
}

/// Response of `GET /v1/device-sessions`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSessionList {
    /// Sessions.
    pub sessions: Vec<DeviceSessionView>,
}

/// Wire body of `POST /v1/device-sessions/{id}/approve`. The display code
/// the operator reads off the device's screen binds the approval to that
/// device.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveSessionRequest {
    /// Display code, `XXX-XXX` (either case).
    pub display_code: String,
}

impl ApproveSessionRequest {
    /// Validates the display code's syntax. Whether it is the session's is
    /// the server's check (`display_code_mismatch`).
    ///
    /// # Errors
    ///
    /// `invalid_value:display_code`.
    pub fn validate(&self) -> Result<DisplayCode, FieldError> {
        DisplayCode::parse(&self.display_code).map_err(|e| FieldError::invalid("display_code", e))
    }
}

impl From<&DisplayCode> for ApproveSessionRequest {
    fn from(d: &DisplayCode) -> Self {
        Self {
            display_code: d.as_str().to_owned(),
        }
    }
}

/// Wire body of `POST /v1/device-sessions/{id}/refuse`.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefuseSessionRequest {
    /// Operator note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl RefuseSessionRequest {
    /// Validates the note.
    ///
    /// # Errors
    ///
    /// A name rule on `note`.
    pub fn validate(&self) -> Result<Option<Note>, FieldError> {
        self.note
            .as_deref()
            .map(Note::new)
            .transpose()
            .map_err(|e| FieldError::name("note", e))
    }
}

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

/// One step of a job (REQ-JOB-002).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobStepView {
    /// Step.
    pub step: Step,
    /// What it does.
    pub kind: StepKind,
    /// State.
    pub state: StepState,
    /// When it started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<UnixMicros>,
    /// When it finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<UnixMicros>,
}

/// A job (`GET /v1/jobs/{id}`; REQ-JOB-001, REQ-JOB-006).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobView {
    /// Job id.
    pub id: JobId,
    /// Session that confirmed it.
    pub session_id: SessionId,
    /// Boot service.
    pub boot_service_id: BootServiceId,
    /// Package.
    pub package_id: PackageId,
    /// Package revision.
    pub package_revision: u64,
    /// Edition applied.
    pub edition_index: EditionIndex,
    /// Device MAC addresses.
    pub macs: MacList,
    /// Disk chosen (REQ-DISK-014).
    pub disk: DiskDescriptorV1,
    /// Layout written, once reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout: Option<LayoutReportV1>,
    /// State (REQ-JOB-012).
    pub state: JobState,
    /// Current step.
    pub current_step: Step,
    /// The five steps and their states.
    pub steps: Vec<JobStepView>,
    /// Bytes done in the current step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_done: Option<u64>,
    /// Bytes the current step handles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_total: Option<u64>,
    /// Overall percentage of the current step ([`percent`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub percent: Option<u8>,
    /// Failure detail when failed (REQ-JOB-006).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<FailureV1>,
    /// When it failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_at: Option<UnixMicros>,
    /// Attempts made in the failing or current step.
    pub attempts: u32,
    /// The earlier failed or lost job of the same device (REQ-JOB-009).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_job_id: Option<JobId>,
    /// Whether an operator acknowledged the failure.
    pub acknowledged: bool,
    /// When the job started (the wipe confirmation).
    pub started_at: UnixMicros,
    /// Last report from the device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_report_at: Option<UnixMicros>,
    /// When it succeeded or failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<UnixMicros>,
}

/// Response of `GET /v1/jobs`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobList {
    /// Jobs.
    pub jobs: Vec<JobView>,
}

/// Whole percent of `done` out of `total`, 0 to 100 (REQ-JOB-003), or
/// `None` when `total` is 0 or `done` exceeds it.
#[must_use]
pub fn percent(done: u64, total: u64) -> Option<u8> {
    if total == 0 || done > total {
        return None;
    }
    let p = u128::from(done) * 100 / u128::from(total);
    u8::try_from(p).ok()
}

// ---------------------------------------------------------------------------
// Boot services
// ---------------------------------------------------------------------------

closed_enum!(
    /// Enrolment status of a boot service.
    BootServiceStatus, "boot service status" {
        /// Enrolled and serving.
        Active => "active",
        /// Disabled by an administrator.
        Disabled => "disabled",
    }
);

/// An IP prefix in CIDR notation with no host bits set, for example
/// `10.20.0.0/16` (RFC 4632 §3.1) or `2001:db8::/32` (RFC 4291 §2.3).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpCidr {
    addr: IpAddr,
    prefix: u8,
}

/// A CIDR prefix that is malformed or has host bits set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("must be an address/prefix with no host bits set")]
pub struct BadCidr;

/// Longest CIDR text accepted (an IPv6 address plus `/128`).
const MAX_CIDR_TEXT: usize = 49;

impl IpCidr {
    /// Parses `address/prefix`.
    ///
    /// # Errors
    ///
    /// [`BadCidr`].
    pub fn parse(text: &str) -> Result<Self, BadCidr> {
        if text.len() > MAX_CIDR_TEXT {
            return Err(BadCidr);
        }
        let (a, p) = text.split_once('/').ok_or(BadCidr)?;
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return Err(BadCidr);
        }
        if p.len() > 1 && p.starts_with('0') {
            return Err(BadCidr);
        }
        let prefix: u8 = p.parse().map_err(|_| BadCidr)?;
        let addr: IpAddr = a.parse().map_err(|_| BadCidr)?;
        let ok = match addr {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4);
                prefix <= 32
                    && (prefix == 32 || bits.checked_shl(u32::from(prefix)).unwrap_or(0) == 0)
            }
            IpAddr::V6(v6) => {
                let bits = u128::from(v6);
                prefix <= 128
                    && (prefix == 128 || bits.checked_shl(u32::from(prefix)).unwrap_or(0) == 0)
            }
        };
        if !ok {
            return Err(BadCidr);
        }
        Ok(Self { addr, prefix })
    }

    /// The network address.
    #[must_use]
    pub const fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length.
    #[must_use]
    pub const fn prefix(&self) -> u8 {
        self.prefix
    }

    /// `true` if `ip` is inside the prefix (same address family only).
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(ip) & mask == u32::from(net)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(ip) & mask == u128::from(net)
            }
            _ => false,
        }
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl fmt::Debug for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IpCidr({self})")
    }
}

impl serde::Serialize for IpCidr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for IpCidr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;

        impl serde::de::Visitor<'_> for V {
            type Value = IpCidr;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an address/prefix")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<IpCidr, E> {
                IpCidr::parse(v).map_err(E::custom)
            }
        }

        d.deserialize_str(V)
    }
}

/// A boot service's served subnets: 1 to [`MAX_SERVED_SUBNETS`] prefixes,
/// each once (plan section 3.8).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "Vec<IpCidr>", into = "Vec<IpCidr>")]
pub struct SubnetList(Vec<IpCidr>);

/// A subnet list that is empty, too long, or repeats a prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("served subnets must list 1 to 64 distinct prefixes")]
pub struct BadSubnetList;

impl SubnetList {
    /// Checks and wraps a list.
    ///
    /// # Errors
    ///
    /// [`BadSubnetList`].
    pub fn new(subnets: Vec<IpCidr>) -> Result<Self, BadSubnetList> {
        let mut seen = HashSet::with_capacity(subnets.len());
        if subnets.is_empty()
            || subnets.len() > MAX_SERVED_SUBNETS
            || !subnets.iter().all(|c| seen.insert(*c))
        {
            return Err(BadSubnetList);
        }
        Ok(Self(subnets))
    }

    /// The prefixes.
    #[must_use]
    pub fn as_slice(&self) -> &[IpCidr] {
        &self.0
    }

    /// `true` if any prefix contains `ip` (REQ-TGT-001: the boot service
    /// is resolved from the device's source address).
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|c| c.contains(ip))
    }
}

impl TryFrom<Vec<IpCidr>> for SubnetList {
    type Error = BadSubnetList;

    fn try_from(v: Vec<IpCidr>) -> Result<Self, Self::Error> {
        Self::new(v)
    }
}

impl From<SubnetList> for Vec<IpCidr> {
    fn from(s: SubnetList) -> Self {
        s.0
    }
}

/// A boot service (`GET /v1/boot-services/{id}`; REQ-TGT-001,
/// REQ-TGT-008).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootServiceView {
    /// Id.
    pub id: BootServiceId,
    /// Name.
    pub name: DisplayName,
    /// Served subnets.
    pub served_subnets: SubnetList,
    /// Status.
    pub status: BootServiceStatus,
    /// Assigned packages.
    pub packages: Vec<PackageRef>,
    /// How many of them a device could be offered now.
    pub usable_count: u32,
    /// Warning when none is usable (REQ-TGT-008).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<Reason>,
}

/// Response of `GET /v1/boot-services`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootServiceList {
    /// Boot services.
    pub boot_services: Vec<BootServiceView>,
}

/// Wire body of `PUT /v1/boot-services/{id}/packages` (with `If-Match`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetBootServicePackagesRequest {
    /// Package ids (at most [`MAX_BOOT_SERVICE_PACKAGES`], each once).
    pub package_ids: Vec<String>,
}

impl SetBootServicePackagesRequest {
    /// Validates the list.
    ///
    /// # Errors
    ///
    /// `too_long:package_ids`, `invalid_value:package_ids` (bad id) or
    /// `invalid_value:package_ids` (repeated id).
    pub fn validate(&self) -> Result<Vec<PackageId>, FieldError> {
        if self.package_ids.len() > MAX_BOOT_SERVICE_PACKAGES {
            return Err(FieldError::new(
                "package_ids",
                &codes::TOO_LONG,
                format!("package_ids lists at most {MAX_BOOT_SERVICE_PACKAGES} packages"),
            ));
        }
        let mut seen = HashSet::with_capacity(self.package_ids.len());
        let mut out = Vec::with_capacity(self.package_ids.len());
        for text in &self.package_ids {
            let id = PackageId::parse(text).map_err(|e| FieldError::invalid("package_ids", e))?;
            if !seen.insert(id) {
                return Err(FieldError::invalid(
                    "package_ids",
                    "a package is listed twice",
                ));
            }
            out.push(id);
        }
        Ok(out)
    }
}

impl From<&[PackageId]> for SetBootServicePackagesRequest {
    fn from(ids: &[PackageId]) -> Self {
        Self {
            package_ids: ids.iter().map(ToString::to_string).collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Boot stops
// ---------------------------------------------------------------------------

/// A boot stop (`GET /v1/boot-stops`; REQ-BOOT-067).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootStopView {
    /// Id.
    pub id: BootStopId,
    /// Boot service.
    pub boot_service_id: BootServiceId,
    /// Stopped device.
    pub mac: MacAddress,
    /// The job that succeeded.
    pub job_id: JobId,
    /// When the stop was added.
    pub created_at: UnixMicros,
    /// When cleared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleared_at: Option<UnixMicros>,
    /// Who cleared it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleared_by: Option<OperatorId>,
}

/// Response of `GET /v1/boot-stops`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootStopList {
    /// Stops.
    pub stops: Vec<BootStopView>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr() {
        let c = IpCidr::parse("10.20.0.0/16").unwrap();
        assert_eq!(c.to_string(), "10.20.0.0/16");
        assert!(c.contains("10.20.255.1".parse().unwrap()));
        assert!(!c.contains("10.21.0.1".parse().unwrap()));
        assert!(!c.contains("::1".parse().unwrap()));
        let all = IpCidr::parse("0.0.0.0/0").unwrap();
        assert!(all.contains("192.0.2.1".parse().unwrap()));
        let host = IpCidr::parse("192.0.2.7/32").unwrap();
        assert!(host.contains("192.0.2.7".parse().unwrap()));
        assert!(!host.contains("192.0.2.8".parse().unwrap()));
        let v6 = IpCidr::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8:1::5".parse().unwrap()));
        assert!(IpCidr::parse("::/0").is_ok());
        for bad in [
            "10.20.0.1/16",
            "10.20.0.0/33",
            "10.20.0.0/016",
            "10.20.0.0/",
            "10.20.0.0",
            "/16",
            "10.20.0.0/+16",
            "10.20.0.0/16 ",
            "2001:db8::1/32",
            "2001:db8::/129",
            "10.020.0.0/16",
        ] {
            assert_eq!(IpCidr::parse(bad), Err(BadCidr), "{bad}");
        }
        assert_eq!(IpCidr::parse(&"1".repeat(100)), Err(BadCidr));
    }

    #[test]
    fn subnet_list() {
        let a = IpCidr::parse("10.0.0.0/8").unwrap();
        let b = IpCidr::parse("192.0.2.0/24").unwrap();
        let l = SubnetList::new(vec![a, b]).unwrap();
        assert!(l.contains("192.0.2.9".parse().unwrap()));
        assert!(!l.contains("198.51.100.1".parse().unwrap()));
        assert_eq!(SubnetList::new(vec![]), Err(BadSubnetList));
        assert_eq!(SubnetList::new(vec![a, a]), Err(BadSubnetList));
        let many: Vec<_> = (0..=64u8)
            .map(|i| IpCidr::parse(&format!("10.{i}.0.0/16")).unwrap())
            .collect();
        assert_eq!(SubnetList::new(many), Err(BadSubnetList));
        assert!(serde_json::from_str::<SubnetList>("[]").is_err());
        assert!(serde_json::from_str::<SubnetList>("[\"10.0.0.1/8\"]").is_err());
    }

    #[test]
    fn percent_math() {
        assert_eq!(percent(0, 10), Some(0));
        assert_eq!(percent(5, 10), Some(50));
        assert_eq!(percent(10, 10), Some(100));
        assert_eq!(percent(u64::MAX, u64::MAX), Some(100));
        assert_eq!(percent(1, 0), None);
        assert_eq!(percent(11, 10), None);
    }

    #[test]
    fn ttl_and_note() {
        let ok = IssueAuthCodeRequest {
            ttl_s: Some(900),
            note: Some("bench 4".into()),
        }
        .validate()
        .unwrap();
        assert_eq!(ok.ttl_s, Some(900));
        for ttl in [0, MAX_CODE_TTL_S + 1, u64::MAX] {
            let e = IssueAuthCodeRequest {
                ttl_s: Some(ttl),
                note: None,
            }
            .validate()
            .unwrap_err();
            assert_eq!(e.code.as_str(), "out_of_range:ttl_s");
        }
        let e = IssueAuthCodeRequest {
            ttl_s: None,
            note: Some("x".repeat(201)),
        }
        .validate()
        .unwrap_err();
        assert_eq!(e.code.as_str(), "too_long:note");
        assert!(IssueAuthCodeRequest::default().validate().is_ok());
    }

    #[test]
    fn package_id_list() {
        let a = "1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516".to_owned();
        let ok = SetBootServicePackagesRequest {
            package_ids: vec![a.clone()],
        };
        assert_eq!(ok.validate().unwrap().len(), 1);
        let dup = SetBootServicePackagesRequest {
            package_ids: vec![a.clone(), a.to_uppercase()],
        };
        assert_eq!(
            dup.validate().unwrap_err().code.as_str(),
            "invalid_value:package_ids"
        );
        let bad = SetBootServicePackagesRequest {
            package_ids: vec!["nope".into()],
        };
        assert_eq!(
            bad.validate().unwrap_err().code.as_str(),
            "invalid_value:package_ids"
        );
        let many = SetBootServicePackagesRequest {
            package_ids: vec![a; MAX_BOOT_SERVICE_PACKAGES + 1],
        };
        assert_eq!(
            many.validate().unwrap_err().code.as_str(),
            "too_long:package_ids"
        );
    }

    #[test]
    fn approve_display_code() {
        let r = ApproveSessionRequest {
            display_code: "ab1-x9z".into(),
        };
        assert_eq!(r.validate().unwrap().as_str(), "AB1-X9Z");
        let bad = ApproveSessionRequest {
            display_code: "AB1-X9".into(),
        };
        assert_eq!(
            bad.validate().unwrap_err().code.as_str(),
            "invalid_value:display_code"
        );
    }
}
