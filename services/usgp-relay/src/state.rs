//! Service state: Running or Running with missing content (REQ-BOOT-052).
//!
//! The state is derived from the status of every file in the boot
//! manifest. M1 serves one architecture (UEFI x86-64, DEC-0004), so every
//! published file is treated as needed by it: offers for that architecture
//! are made only while every published file is verified. This is project
//! design: the specs do not say which files an architecture needs.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   content that fails verification stops offers.
// - NIST 800-53: AU-2 / AU-12 - every state transition emits an event.
// - SPEC: specs/boot-network.md#REQ-BOOT-052 (status, missing content, no
//   offer that cannot be delivered); "States and transitions" (Running,
//   Running with missing content)

// POAM: REQ-BOOT-052 operator view - in M1 the state and the per-file
// status are visible only through audit events (`relay.state.changed`,
// `boot.file.*`) and `--check-config`; there is no live status query.
// The operator view arrives with the M2 control plane (owner answer Q-4).

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::events::{self, Outcome};
use crate::lock;

/// Boot service state as the operator sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// Before the first content check finished.
    Starting,
    /// Answers eligible devices.
    Running,
    /// Running, but at least one published file is missing or failed
    /// verification, so no boot program is offered.
    RunningMissingContent,
}

impl ServiceState {
    /// Stable label for events and `--check-config` output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::RunningMissingContent => "running_missing_content",
        }
    }
}

/// Last known status of one published file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileStatus {
    /// Not checked yet.
    Unchecked,
    /// Size and SHA-256 matched the manifest at the last read.
    Verified,
    /// Not present in the boot root at the last read.
    Missing,
    /// Present but not matching the manifest (or not a regular file).
    IntegrityFailed,
}

impl FileStatus {
    /// Stable label for events and `--check-config` output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unchecked => "unchecked",
            Self::Verified => "verified",
            Self::Missing => "missing",
            Self::IntegrityFailed => "integrity_failed",
        }
    }
}

#[derive(Debug)]
struct Inner {
    /// Status of each file and the sequence number of the check that set
    /// it.
    files: BTreeMap<String, (FileStatus, u64)>,
    state: ServiceState,
}

/// Shared service state.
#[derive(Debug)]
pub struct RelayState {
    inner: Mutex<Inner>,
    /// Fast path for the DHCP responder: true only in `Running`.
    available: AtomicBool,
    /// Source of check sequence numbers ([`Self::begin_check`]).
    next_check: AtomicU64,
}

impl RelayState {
    /// A state tracking `names` (the manifest entries), all unchecked.
    pub fn new<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let files = names
            .into_iter()
            .map(|n| (n.into(), (FileStatus::Unchecked, 0)))
            .collect();
        Self {
            inner: Mutex::new(Inner {
                files,
                state: ServiceState::Starting,
            }),
            available: AtomicBool::new(false),
            next_check: AtomicU64::new(1),
        }
    }

    /// A sequence number for a file check, taken when the read starts.
    /// Pass it to [`Self::record_check`] with the result.
    pub fn begin_check(&self) -> u64 {
        self.next_check.fetch_add(1, Ordering::Relaxed)
    }

    /// Records the status of `name` after a read and recomputes the
    /// service state, as one check that starts and ends now. See
    /// [`Self::record_check`].
    pub fn record(&self, name: &str, status: FileStatus, cause: &str) -> ServiceState {
        let seq = self.begin_check();
        self.record_check(name, status, cause, seq)
            .unwrap_or_else(|| self.current())
    }

    /// Records the result of the check numbered `seq` (from
    /// [`Self::begin_check`]) and recomputes the service state. A state
    /// change emits `relay.state.changed` with the cause (`cause` names the
    /// check: `startup`, `recheck` or `rrq`). Unknown names are ignored.
    ///
    /// Concurrent checks of one file can finish out of order. A result
    /// from a check that started before the one already recorded for that
    /// file is stale and is ignored (returns `None`), so a slow read of old
    /// bytes cannot undo a newer failure, or the other way round (SI-7).
    /// Otherwise returns the new state.
    pub fn record_check(
        &self,
        name: &str,
        status: FileStatus,
        cause: &str,
        seq: u64,
    ) -> Option<ServiceState> {
        let mut inner = lock(&self.inner);
        if let Some(slot) = inner.files.get_mut(name) {
            if seq < slot.1 {
                return None;
            }
            *slot = (status, seq);
        }
        let all_verified = inner
            .files
            .values()
            .all(|(s, _)| *s == FileStatus::Verified);
        // While starting, wait until every file has been looked at once.
        let any_unchecked = inner
            .files
            .values()
            .any(|(s, _)| *s == FileStatus::Unchecked);
        let next = if all_verified {
            ServiceState::Running
        } else if inner.state == ServiceState::Starting && any_unchecked {
            ServiceState::Starting
        } else {
            ServiceState::RunningMissingContent
        };
        let previous = inner.state;
        inner.state = next;
        self.available
            .store(next == ServiceState::Running, Ordering::Release);
        if previous != next {
            let detail = transition_detail(&inner, previous, next, name, cause);
            drop(inner);
            let outcome = if next == ServiceState::Running {
                Outcome::Success
            } else {
                Outcome::Failure
            };
            events::emit_simple(events::STATE_CHANGED, outcome, &detail);
        }
        Some(next)
    }

    /// Current state.
    #[must_use]
    pub fn current(&self) -> ServiceState {
        lock(&self.inner).state
    }

    /// Whether a boot program can be offered (state is `Running`).
    #[must_use]
    pub fn content_available(&self) -> bool {
        self.available.load(Ordering::Acquire)
    }

    /// Status of every tracked file, in name order.
    #[must_use]
    pub fn files(&self) -> Vec<(String, FileStatus)> {
        lock(&self.inner)
            .files
            .iter()
            .map(|(n, (s, _))| (n.clone(), *s))
            .collect()
    }
}

fn transition_detail(
    inner: &Inner,
    previous: ServiceState,
    next: ServiceState,
    name: &str,
    cause: &str,
) -> Vec<(&'static str, String)> {
    let not_ok: Vec<&str> = inner
        .files
        .iter()
        .filter(|(_, (s, _))| *s != FileStatus::Verified)
        .map(|(n, _)| n.as_str())
        .collect();
    let arch_status = if next == ServiceState::Running {
        "available"
    } else {
        "missing_content"
    };
    vec![
        ("from", previous.as_str().to_owned()),
        ("to", next.as_str().to_owned()),
        ("uefi_x64", arch_status.to_owned()),
        ("cause", cause.to_owned()),
        ("file", name.to_owned()),
        ("files_not_verified", not_ok.join(",")),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_unavailable_until_all_verified() {
        let s = RelayState::new(["a", "b"]);
        assert_eq!(s.current(), ServiceState::Starting);
        assert!(!s.content_available());
        assert_eq!(
            s.record("a", FileStatus::Verified, "startup"),
            ServiceState::Starting
        );
        assert!(!s.content_available());
        assert_eq!(
            s.record("b", FileStatus::Verified, "startup"),
            ServiceState::Running
        );
        assert!(s.content_available());
    }

    #[test]
    fn one_bad_file_means_missing_content_and_recovery() {
        let s = RelayState::new(["a", "b"]);
        s.record("a", FileStatus::Verified, "startup");
        s.record("b", FileStatus::Verified, "startup");
        assert_eq!(
            s.record("b", FileStatus::IntegrityFailed, "rrq"),
            ServiceState::RunningMissingContent
        );
        assert!(!s.content_available());
        assert_eq!(
            s.record("b", FileStatus::Verified, "recheck"),
            ServiceState::Running
        );
        assert!(s.content_available());
    }

    #[test]
    fn startup_with_missing_file_leaves_starting() {
        let s = RelayState::new(["a", "b"]);
        s.record("a", FileStatus::Missing, "startup");
        assert_eq!(s.current(), ServiceState::Starting);
        s.record("b", FileStatus::Verified, "startup");
        assert_eq!(s.current(), ServiceState::RunningMissingContent);
    }

    /// A check that started earlier but finished later does not
    /// overwrite a newer result.
    #[test]
    fn stale_result_ignored() {
        let s = RelayState::new(["a"]);
        s.record("a", FileStatus::Verified, "startup");
        assert_eq!(s.current(), ServiceState::Running);
        let old = s.begin_check();
        let new = s.begin_check();
        assert_eq!(
            s.record_check("a", FileStatus::IntegrityFailed, "rrq", new),
            Some(ServiceState::RunningMissingContent)
        );
        // The older read (of the old, matching bytes) ends late.
        assert_eq!(s.record_check("a", FileStatus::Verified, "rrq", old), None);
        assert_eq!(s.current(), ServiceState::RunningMissingContent);
        assert!(!s.content_available());
        // A newer successful check still recovers.
        let newer = s.begin_check();
        assert_eq!(
            s.record_check("a", FileStatus::Verified, "recheck", newer),
            Some(ServiceState::Running)
        );
        // And a stale failure cannot undo that recovery.
        assert_eq!(s.record_check("a", FileStatus::Missing, "rrq", new), None);
        assert_eq!(s.current(), ServiceState::Running);
    }

    #[test]
    fn unknown_name_ignored() {
        let s = RelayState::new(["a"]);
        s.record("zzz", FileStatus::Verified, "rrq");
        assert_eq!(s.current(), ServiceState::Starting);
        assert_eq!(s.files(), vec![("a".to_owned(), FileStatus::Unchecked)]);
    }
}
