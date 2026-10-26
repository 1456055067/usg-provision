//! Device suppression list and its polling reloader (REQ-BOOT-050/051).
//!
//! A suppressed device gets no reply at all, so its firmware falls through
//! to the next boot option. Suppression matches on **claimed** identity
//! (hardware address or machine GUID) and is a convenience, not an access
//! control (REQ-BOOT-045).
//!
//! The file is polled every `suppression.reload_interval_secs`. A file
//! that cannot be read, breaks a trusted-file rule
//! (`usgp_common::config::read_trusted`), or fails validation keeps the
//! previous list and emits `suppression.rejected` once per distinct file
//! content or error. At start-up there is no previous list, so a bad file
//! refuses start-up (fail closed; exit 78).

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 (Configuration Settings) - strict validation, the
//   previous list is kept on error.
// - NIST 800-53: SI-10 (Information Input Validation) - size and entry
//   limits, exactly one identifier per entry, multicast/zero MACs and the
//   nil GUID refused.
// - NIST 800-53: IA-3 - NOT MET on TB-1: PXE devices are unauthenticated
//   by the standard; MAC and GUID here are claimed labels, never
//   authenticators, and suppression is not access control (REQ-BOOT-045).
//   See docs/compliance/POAM.md (IA-3 on TB-1).
// - NIST 800-53: CM-5 / SI-7 - the file is read under the trusted-file
//   rules on every load.
// - NIST 800-53: AU-2 / AU-12 - every load and rejection is an event.
// - SPEC: specs/boot-network.md#REQ-BOOT-007 (MAC or GUID), #REQ-BOOT-045,
//   #REQ-BOOT-050 (no restart), #REQ-BOOT-051 (no reply)

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use usgp_common::Sha256Digest;
use usgp_common::config::{ConfigError, TrustPolicy, read_trusted};
use usgp_dhcp::{Guid, MacAddr};

use crate::events::{self, Outcome};
use crate::{lock, read_lock, write_lock};

/// Largest suppression file.
pub const MAX_SUPPRESSION_BYTES: u64 = 1024 * 1024;
/// Largest number of `[[device]]` entries.
pub const MAX_ENTRIES: usize = 10_000;
/// Longest `note`, in characters.
pub const MAX_NOTE_CHARS: usize = 200;
/// The only supported `schema_version`.
pub const SCHEMA_VERSION: i64 = 1;

/// The suppression file as written.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuppressionFileDocument {
    /// `schema_version` (required, must be 1).
    pub schema_version: Option<i64>,
    /// `[[device]]` entries.
    #[serde(default)]
    pub device: Vec<DeviceDocument>,
}

/// One `[[device]]` entry: exactly one of `mac` or `guid`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceDocument {
    /// Hardware address, `aa:bb:cc:dd:ee:ff`.
    pub mac: Option<String>,
    /// Machine GUID in the 8-4-4-4-12 text form.
    pub guid: Option<String>,
    /// Free text for the operator (at most 200 characters).
    pub note: Option<String>,
}

/// A suppression file rule violation. Never echoes the value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid suppression file: {field}: {reason}")]
pub struct SuppressionInvalid {
    /// The key, with the entry index.
    pub field: String,
    /// The rule that failed.
    pub reason: &'static str,
}

/// Why a suppression file could not be used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SuppressionError {
    /// The file could not be read, or is world-writable.
    #[error(transparent)]
    File(#[from] ConfigError),
    /// A rule failed.
    #[error(transparent)]
    Invalid(#[from] SuppressionInvalid),
}

/// The set of suppressed devices.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SuppressionList {
    macs: HashSet<MacAddr>,
    guids: HashSet<Guid>,
}

fn bad(field: String, reason: &'static str) -> SuppressionInvalid {
    SuppressionInvalid { field, reason }
}

impl SuppressionList {
    /// The empty list.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Builds a list from identifiers (programmatic use and tests). The
    /// nil GUID is refused because it would match every device that sends
    /// nil.
    ///
    /// # Errors
    ///
    /// [`SuppressionInvalid`] for the nil GUID.
    pub fn from_ids(macs: &[MacAddr], guids: &[Guid]) -> Result<Self, SuppressionInvalid> {
        if guids.iter().any(is_nil) {
            return Err(bad("guid".to_owned(), "the nil GUID is not allowed"));
        }
        Ok(Self {
            macs: macs.iter().copied().collect(),
            guids: guids.iter().copied().collect(),
        })
    }

    /// Validates a parsed suppression file.
    ///
    /// # Errors
    ///
    /// [`SuppressionInvalid`] naming the first failing entry.
    pub fn from_document(doc: &SuppressionFileDocument) -> Result<Self, SuppressionInvalid> {
        match doc.schema_version {
            Some(SCHEMA_VERSION) => {}
            Some(_) => return Err(bad("schema_version".to_owned(), "must be 1")),
            None => return Err(bad("schema_version".to_owned(), "is required")),
        }
        if doc.device.len() > MAX_ENTRIES {
            return Err(bad("device".to_owned(), "more than 10000 entries"));
        }
        let mut list = Self::default();
        for (i, d) in doc.device.iter().enumerate() {
            if let Some(n) = &d.note
                && n.chars().count() > MAX_NOTE_CHARS
            {
                return Err(bad(
                    format!("device[{i}].note"),
                    "longer than 200 characters",
                ));
            }
            match (&d.mac, &d.guid) {
                (Some(m), None) => {
                    let mac = MacAddr::from_str(m).map_err(|_| {
                        bad(
                            format!("device[{i}].mac"),
                            "must be a unicast, non-zero aa:bb:cc:dd:ee:ff address",
                        )
                    })?;
                    list.macs.insert(mac);
                }
                (None, Some(g)) => {
                    let guid = Guid::from_str(g).map_err(|_| {
                        bad(
                            format!("device[{i}].guid"),
                            "must be a GUID in 8-4-4-4-12 hex form",
                        )
                    })?;
                    if is_nil(&guid) {
                        return Err(bad(
                            format!("device[{i}].guid"),
                            "the nil GUID is not allowed",
                        ));
                    }
                    list.guids.insert(guid);
                }
                (Some(_), Some(_)) => {
                    return Err(bad(format!("device[{i}]"), "has both mac and guid"));
                }
                (None, None) => {
                    return Err(bad(format!("device[{i}]"), "needs mac or guid"));
                }
            }
        }
        Ok(list)
    }

    /// Whether the device (by claimed MAC, or claimed GUID if sent) is
    /// suppressed.
    #[must_use]
    pub fn contains(&self, mac: MacAddr, guid: Option<Guid>) -> bool {
        self.macs.contains(&mac) || guid.is_some_and(|g| self.guids.contains(&g))
    }

    /// Number of distinct identifiers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.macs.len() + self.guids.len()
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn is_nil(g: &Guid) -> bool {
    g.wire_octets() == [0u8; 16]
}

/// Turns suppression TOML text into a document. Unknown keys are refused.
///
/// # Errors
///
/// [`SuppressionError::File`] with [`ConfigError::Parse`].
pub fn parse_document(text: &str) -> Result<SuppressionFileDocument, SuppressionError> {
    usgp_common::config::parse_toml(text).map_err(SuppressionError::File)
}

/// Reads and validates the suppression file at `path` under the
/// trusted-file rules of `trust`. Returns the list and the SHA-256 of the
/// file bytes.
///
/// # Errors
///
/// [`SuppressionError`].
pub fn read_file(
    path: &Path,
    trust: &TrustPolicy,
) -> Result<(SuppressionList, Sha256Digest), SuppressionError> {
    let text = read_trusted(path, MAX_SUPPRESSION_BYTES, trust)?;
    let digest = usgp_crypto::sha256(text.as_bytes());
    let doc = parse_document(&text)?;
    Ok((SuppressionList::from_document(&doc)?, digest))
}

/// What the last reload attempt saw, so an unchanged file (good or bad)
/// does not repeat its event every poll.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Content(Sha256Digest),
    Error(String),
}

/// Result of [`Suppression::reload`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReloadOutcome {
    /// No file configured, or nothing changed since the last attempt.
    Unchanged,
    /// A new list is in effect.
    Loaded,
    /// The file was refused; the previous list is kept.
    Rejected,
}

/// The live suppression list, shared by every DHCP socket task.
#[derive(Debug)]
pub struct Suppression {
    path: Option<PathBuf>,
    trust: TrustPolicy,
    current: RwLock<Arc<SuppressionList>>,
    seen: Mutex<Option<Seen>>,
}

impl Suppression {
    /// No suppression file: the list is always empty.
    #[must_use]
    pub fn disabled() -> Self {
        Self::with_list(None, SuppressionList::empty())
    }

    /// A handle holding `list` (programmatic use and tests); `path`, if
    /// given, is polled by [`Self::reload`] under a root-only trust policy
    /// (see [`Self::with_trust`]).
    #[must_use]
    pub fn with_list(path: Option<PathBuf>, list: SuppressionList) -> Self {
        Self {
            path,
            trust: TrustPolicy::root_only(),
            current: RwLock::new(Arc::new(list)),
            seen: Mutex::new(None),
        }
    }

    /// The same handle, reloading under `trust`.
    #[must_use]
    pub fn with_trust(mut self, trust: TrustPolicy) -> Self {
        self.trust = trust;
        self
    }

    /// Loads the configured file at start-up (trusted-file rules under
    /// `trust`, kept for every reload) and emits `suppression.loaded`.
    ///
    /// # Errors
    ///
    /// [`SuppressionError`]: there is no previous list to keep, so the
    /// caller refuses to start.
    pub fn load_initial(path: &Path, trust: TrustPolicy) -> Result<Self, SuppressionError> {
        let (list, digest) = read_file(path, &trust)?;
        emit_loaded(&list, &digest, "startup");
        let s = Self::with_list(Some(path.to_path_buf()), list).with_trust(trust);
        *lock(&s.seen) = Some(Seen::Content(digest));
        Ok(s)
    }

    /// The list in effect now.
    #[must_use]
    pub fn current(&self) -> Arc<SuppressionList> {
        Arc::clone(&read_lock(&self.current))
    }

    /// Replaces the list in effect.
    pub fn set(&self, list: SuppressionList) {
        *write_lock(&self.current) = Arc::new(list);
    }

    /// Re-reads the configured file. A valid, changed file replaces the
    /// list (`suppression.loaded`); an invalid or unreadable one keeps the
    /// previous list (`suppression.rejected`, once per distinct content or
    /// error).
    pub fn reload(&self) -> ReloadOutcome {
        let Some(path) = &self.path else {
            return ReloadOutcome::Unchanged;
        };
        let attempt = read_file(path, &self.trust);
        let seen = match &attempt {
            Ok((_, d)) => Seen::Content(*d),
            Err(e) => Seen::Error(e.to_string()),
        };
        {
            let mut last = lock(&self.seen);
            if last.as_ref() == Some(&seen) {
                return ReloadOutcome::Unchanged;
            }
            *last = Some(seen);
        }
        match attempt {
            Ok((list, digest)) => {
                emit_loaded(&list, &digest, "reload");
                self.set(list);
                ReloadOutcome::Loaded
            }
            Err(e) => {
                let detail = [
                    ("error", e.to_string()),
                    ("action", "previous list kept".to_owned()),
                    ("entries_in_effect", self.current().len().to_string()),
                ];
                events::emit_simple(events::SUPPRESSION_REJECTED, Outcome::Refused, &detail);
                ReloadOutcome::Rejected
            }
        }
    }
}

fn emit_loaded(list: &SuppressionList, digest: &Sha256Digest, cause: &str) {
    let detail = [
        ("entries", list.len().to_string()),
        ("file_sha256", digest.to_hex()),
        ("cause", cause.to_owned()),
    ];
    events::emit_simple(events::SUPPRESSION_LOADED, Outcome::Success, &detail);
}

/// Polls the suppression file every `interval`, forever (the caller
/// aborts the task at shutdown).
pub async fn reload_loop(handle: Arc<Suppression>, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick completes at once; the start-up load already ran.
    tick.tick().await;
    loop {
        tick.tick().await;
        let h = Arc::clone(&handle);
        // File reads block; keep them off the async worker threads.
        let _ = tokio::task::spawn_blocking(move || h.reload()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GUID: &str = "00112233-4455-6677-8899-aabbccddeeff";

    fn mac(s: &str) -> MacAddr {
        s.parse().unwrap()
    }

    /// The test's own uid as the administrator uid, so the trusted-file
    /// rules pass for files this (non-root) test creates.
    fn me() -> TrustPolicy {
        TrustPolicy::with_admin(usgp_common::process::effective_uid().unwrap())
    }

    fn entry(mac: Option<&str>, guid: Option<&str>) -> DeviceDocument {
        DeviceDocument {
            mac: mac.map(str::to_owned),
            guid: guid.map(str::to_owned),
            note: None,
        }
    }

    fn doc(devices: Vec<DeviceDocument>) -> SuppressionFileDocument {
        SuppressionFileDocument {
            schema_version: Some(1),
            device: devices,
        }
    }

    #[test]
    fn mac_and_guid_entries_match() {
        let l = SuppressionList::from_document(&doc(vec![
            entry(Some("52:54:00:12:34:56"), None),
            entry(None, Some(GUID)),
        ]))
        .unwrap();
        assert_eq!(l.len(), 2);
        assert!(l.contains(mac("52:54:00:12:34:56"), None));
        let g: Guid = GUID.parse().unwrap();
        assert!(l.contains(mac("52:54:00:00:00:01"), Some(g)));
        assert!(!l.contains(mac("52:54:00:00:00:01"), None));
    }

    #[test]
    fn schema_version_rules() {
        let mut d = doc(vec![]);
        d.schema_version = None;
        assert!(SuppressionList::from_document(&d).is_err());
        d.schema_version = Some(2);
        assert!(SuppressionList::from_document(&d).is_err());
        d.schema_version = Some(1);
        assert!(SuppressionList::from_document(&d).unwrap().is_empty());
    }

    #[test]
    fn entry_rules() {
        let cases = [
            entry(None, None),
            entry(Some("52:54:00:12:34:56"), Some(GUID)),
            entry(Some("01:00:5e:00:00:01"), None), // multicast
            entry(Some("00:00:00:00:00:00"), None), // zero
            entry(Some("52-54-00-12-34-56"), None),
            entry(None, Some("00000000-0000-0000-0000-000000000000")), // nil
            entry(None, Some("not-a-guid")),
        ];
        for (i, c) in cases.into_iter().enumerate() {
            let r = SuppressionList::from_document(&doc(vec![c]));
            assert!(r.is_err(), "case {i}");
        }
    }

    #[test]
    fn note_limit() {
        let mut e = entry(Some("52:54:00:12:34:56"), None);
        e.note = Some("x".repeat(200));
        assert!(SuppressionList::from_document(&doc(vec![e.clone()])).is_ok());
        e.note = Some("x".repeat(201));
        assert!(SuppressionList::from_document(&doc(vec![e])).is_err());
    }

    #[test]
    fn entry_limit() {
        let one = entry(Some("52:54:00:12:34:56"), None);
        assert!(SuppressionList::from_document(&doc(vec![one.clone(); MAX_ENTRIES])).is_ok());
        assert!(SuppressionList::from_document(&doc(vec![one; MAX_ENTRIES + 1])).is_err());
    }

    #[test]
    fn errors_do_not_echo_values() {
        let e =
            SuppressionList::from_document(&doc(vec![entry(Some("zz:secret"), None)])).unwrap_err();
        assert!(!e.to_string().contains("secret"), "{e}");
    }

    #[test]
    fn from_ids_refuses_nil_guid() {
        let nil = Guid::from_wire([0; 16]);
        assert!(SuppressionList::from_ids(&[], &[nil]).is_err());
    }

    #[test]
    fn reload_without_path_is_unchanged() {
        assert_eq!(Suppression::disabled().reload(), ReloadOutcome::Unchanged);
    }

    #[test]
    fn parse_document_golden_and_strict() {
        let d = parse_document(
            "schema_version = 1\n\
             [[device]]\nmac = \"52:54:00:12:34:56\"\nnote = \"provisioned 2026-10-26\"\n\
             [[device]]\nguid = \"00112233-4455-6677-8899-aabbccddeeff\"\n",
        )
        .unwrap();
        assert_eq!(d.device.len(), 2);
        assert_eq!(SuppressionList::from_document(&d).unwrap().len(), 2);
        // No devices at all is an empty list.
        let empty = parse_document("schema_version = 1\n").unwrap();
        assert!(SuppressionList::from_document(&empty).unwrap().is_empty());
        for bad in [
            "schema_version = 1\nextra = 1\n",
            "schema_version = 1\n[[device]]\nmac = \"52:54:00:12:34:56\"\nhostname = \"x\"\n",
            "schema_version = 1\ndevice = \"52:54:00:12:34:56\"\n",
            "schema_version = 1\n[[device]]\nmac = 5\n",
        ] {
            assert!(parse_document(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn reload_applies_without_restart() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("usgp-relay-supp-reload-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("suppress.toml");
        let write = |text: &str| {
            std::fs::write(&path, text).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        };
        let m = mac("52:54:00:12:34:56");
        write("schema_version = 1\n");
        let s = Suppression::load_initial(&path, me()).unwrap();
        assert!(!s.current().contains(m, None));
        // Suppress: applies on the next poll, same handle (no restart).
        write("schema_version = 1\n[[device]]\nmac = \"52:54:00:12:34:56\"\n");
        assert_eq!(s.reload(), ReloadOutcome::Loaded);
        assert!(s.current().contains(m, None));
        assert_eq!(s.reload(), ReloadOutcome::Unchanged);
        // A broken edit keeps the list in effect.
        write("schema_version = 1\n[[device]]\nmac = \"01:00:5e:00:00:01\"\n");
        assert_eq!(s.reload(), ReloadOutcome::Rejected);
        assert!(s.current().contains(m, None));
        // World-writable is refused too, previous list kept.
        write("schema_version = 1\n");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(s.reload(), ReloadOutcome::Rejected);
        assert!(s.current().contains(m, None));
        // Group-writable is refused as well.
        write("schema_version = 1\n");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert_eq!(s.reload(), ReloadOutcome::Rejected);
        assert!(s.current().contains(m, None));
        // Lift: back to an empty list.
        write("schema_version = 1\n");
        assert_eq!(s.reload(), ReloadOutcome::Loaded);
        assert!(!s.current().contains(m, None));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_initial_refuses_bad_file() {
        let dir = std::env::temp_dir().join(format!("usgp-relay-supp-init-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("suppress.toml");
        std::fs::write(&path, "schema_version = 1\nbogus = true\n").unwrap();
        assert!(Suppression::load_initial(&path, me()).is_err());
        assert!(Suppression::load_initial(&dir.join("absent.toml"), me()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn broken_file_keeps_previous_and_reports_once() {
        let dir = std::env::temp_dir().join(format!("usgp-relay-supp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("missing.toml");
        let list = SuppressionList::from_ids(&[mac("52:54:00:12:34:56")], &[]).unwrap();
        let s = Suppression::with_list(Some(path.clone()), list.clone()).with_trust(me());
        assert_eq!(s.reload(), ReloadOutcome::Rejected);
        assert_eq!(*s.current(), list);
        // Same error again: no repeated event.
        assert_eq!(s.reload(), ReloadOutcome::Unchanged);
        // A file that exists but is invalid: a new rejection.
        std::fs::write(&path, "schema_version = 2\n").unwrap();
        assert_eq!(s.reload(), ReloadOutcome::Rejected);
        assert_eq!(*s.current(), list);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
