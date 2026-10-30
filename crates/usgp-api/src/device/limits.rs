//! Device listener settings (`[device_api]`, `[codes]`, `[jobs]`, plan M3
//! section 3.9) and the per-source rate limits of the device routes.
//!
//! `usgp-server` (WU-10) maps `server.toml` onto [`DeviceConfig`];
//! [`DeviceConfig::validate`] runs inside [`crate::ApiConfig::validate`],
//! so an out-of-range value refuses start-up.

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 (Configuration Settings) - secure defaults (listener
//   off); every value range-checked.
// - NIST 800-53: AC-7 (Unsuccessful Logon Attempts) - code attempts capped
//   per session and per source address.
// - NIST 800-53: SC-5 (Denial-of-Service Protection) - session opens per
//   source per minute and in total, pending sessions per source network,
//   per boot service and in total, connection caps, body and header
//   limits (finding SEC-001).
// - NIST 800-53: AC-12 (Session Termination) - pending sessions expire;
//   unauthorised sessions expire sooner when idle.
// - SPEC: specs/targeting.md#REQ-TGT-013 (code attempts limited),
//   #REQ-TGT-014 (pending sessions expire; OPEN-TGT-1 fail-closed default)
// - SPEC: specs/progress.md#REQ-JOB-007 (retry), #REQ-JOB-011 (timeouts)

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use usgp_proto::limits::{
    MAX_DEVICE_JSON_BYTES, MAX_REPORT_INTERVAL_S, MAX_RETRY_ATTEMPTS, MAX_RETRY_DELAY_MS,
    MAX_STEP_TIMEOUT_S,
};
use usgp_proto::ops::MAX_CODE_TTL_S;

use usgp_proto::BootServiceId;

use crate::authn::{MAX_TRACKED_SOURCES, source_key};
use crate::limits::ConfigError;

/// Job timing and retry values written into every signed plan
/// (`[jobs]`; OPEN-JOB-4 values, clean-side defaults).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobSettings {
    /// A running job not heard from for this long becomes `lost` (900 s).
    pub lost_after: Duration,
    /// Retry attempts for transient failures (5).
    pub retry_attempts: u32,
    /// First retry delay, ms (2000).
    pub retry_base_ms: u32,
    /// Largest retry delay, ms (60000).
    pub retry_max_ms: u32,
    /// Seconds without progress before a step is stalled (1800).
    pub stall_timeout_s: u32,
    /// Step 1 timeout, s (21600).
    pub timeout_verify_s: u32,
    /// Step 2 timeout, s (1800).
    pub timeout_disk_s: u32,
    /// Step 3 timeout, s (21600).
    pub timeout_apply_s: u32,
    /// Step 4 timeout, s (1800).
    pub timeout_boot_s: u32,
    /// Step 5 timeout, s (600).
    pub timeout_report_s: u32,
    /// Seconds between progress reports (30; plan section 3.2).
    pub report_interval_s: u32,
}

impl Default for JobSettings {
    fn default() -> Self {
        Self {
            lost_after: Duration::from_secs(900),
            retry_attempts: 5,
            retry_base_ms: 2000,
            retry_max_ms: 60_000,
            stall_timeout_s: 1800,
            timeout_verify_s: 21_600,
            timeout_disk_s: 1800,
            timeout_apply_s: 21_600,
            timeout_boot_s: 1800,
            timeout_report_s: 600,
            report_interval_s: 30,
        }
    }
}

/// Device listener, operator code and job settings (plan section 3.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceConfig {
    /// The device listener is off unless configured (`device_api.enabled`).
    pub enabled: bool,
    /// Concurrent device connections (256).
    pub max_connections: usize,
    /// Concurrent connections from one source (IPv4 address or IPv6 /64)
    /// (16; our choice, the plan names only the total).
    pub max_connections_per_source: usize,
    /// Concurrent TLS handshakes from one source (8).
    pub max_handshakes_per_source: usize,
    /// TLS handshake timeout (10 s).
    pub handshake_timeout: Duration,
    /// Request head timeout (10 s).
    pub header_timeout: Duration,
    /// Idle read or write timeout (120 s).
    pub idle_timeout: Duration,
    /// Largest JSON request body (64 KiB).
    pub max_json_bytes: usize,
    /// Request header fields (64).
    pub max_headers: usize,
    /// Request head size (16 KiB).
    pub max_header_bytes: usize,
    /// Lifetime of a session before its wipe confirmation (3600 s;
    /// OPEN-TGT-1, fail-closed default).
    pub pending_session_ttl: Duration,
    /// Pending sessions in total (64).
    pub max_pending_sessions: u64,
    /// Pending sessions per source (an IPv4 address or an IPv6 /64) (4).
    pub max_pending_sessions_per_ip: u64,
    /// Pending sessions per boot service (32; finding SEC-001, our
    /// choice: one subnet cannot hold every slot of the server).
    pub max_pending_sessions_per_boot_service: u64,
    /// A session never authorised and not heard from for this long
    /// expires before its TTL (120 s; finding SEC-001; the agent polls
    /// every `poll_ms`).
    pub unauthorised_idle_timeout: Duration,
    /// Session opens per source per minute (10).
    pub session_opens_per_ip_per_min: u32,
    /// Session opens per minute from all sources together (600; findings
    /// SEC-001, SEC-011: above the per-boot-service ceiling, so one
    /// network cannot use it up).
    pub session_opens_per_min: u32,
    /// Session opens per minute per boot service (60; finding SEC-011).
    pub session_opens_per_boot_service_per_min: u32,
    /// Concurrent connections from the sources one boot service serves
    /// (64; finding SEC-001: a connection is admitted only from a source
    /// an active boot service serves).
    pub max_connections_per_boot_service: usize,
    /// How often the accept loop reloads the served-subnet table from the
    /// store (30 s; finding SEC-001).
    pub boot_service_refresh: Duration,
    /// Failed code attempts before the session is refused (5).
    pub code_attempts_per_session: u32,
    /// Code attempts per source per minute (10).
    pub code_attempts_per_ip_per_min: u32,
    /// Poll interval suggested to the agent, ms (2000).
    pub poll_ms: u32,
    /// `progress` reports are recorded at most this often per job (2 s);
    /// the excess is dropped.
    pub progress_min_interval: Duration,
    /// Concurrent chunk requests per job (2; plan section 6).
    pub max_chunk_requests_per_job: usize,
    /// Code lifetime when the request names none (`codes.default_ttl_s`,
    /// 900 s).
    pub code_default_ttl: Duration,
    /// Longest code lifetime (`codes.max_ttl_s`, 3600 s).
    pub code_max_ttl: Duration,
    /// Job timings.
    pub jobs: JobSettings,
    /// M4 settings: nine-step timeouts and resume (M4 plan section 3.6).
    pub m4: M4Settings,
}

/// M4 device settings (M4 plan section 3.6; CM-6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M4Settings {
    /// `steps.timeout_s.*` for steps 1 to 9 of a v2 plan (OPEN-SEQ-1
    /// defaults: 21600, 1800, 21600, 7200, 1800, 3600, 14400, 10800,
    /// 1800).
    pub step_timeouts_s: [u32; 9],
    /// `resume.token_ttl_s` (86400): a resume token's lifetime, capped by
    /// the job's end.
    pub resume_token_ttl: Duration,
    /// `resume.max_per_job` (10).
    pub resume_max_per_job: u64,
    /// Resume challenges per source per minute (10; our choice, the plan
    /// names "rate limited per IP").
    pub resume_challenges_per_ip_per_min: u32,
}

impl Default for M4Settings {
    fn default() -> Self {
        Self {
            step_timeouts_s: [21_600, 1800, 21_600, 7200, 1800, 3600, 14_400, 10_800, 1800],
            resume_token_ttl: Duration::from_secs(86_400),
            resume_max_per_job: 10,
            resume_challenges_per_ip_per_min: 10,
        }
    }
}

impl M4Settings {
    /// Checks every value against its allowed range.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming the first bad setting.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let checks: [(bool, &'static str, &'static str); 4] = [
            (
                self.step_timeouts_s
                    .iter()
                    .all(|s| (1..=MAX_STEP_TIMEOUT_S).contains(s)),
                "steps.timeout_s",
                "every step timeout 1 to 604800",
            ),
            (
                (60..=86_400).contains(&self.resume_token_ttl.as_secs()),
                "resume.token_ttl_s",
                "60 to 86400",
            ),
            (
                (1..=100).contains(&self.resume_max_per_job),
                "resume.max_per_job",
                "1 to 100",
            ),
            (
                (1..=1000).contains(&self.resume_challenges_per_ip_per_min),
                "resume.challenges_per_ip_per_min",
                "1 to 1000",
            ),
        ];
        for (ok, setting, range) in checks {
            if !ok {
                return Err(ConfigError { setting, range });
            }
        }
        Ok(())
    }
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_connections: 256,
            max_connections_per_source: 16,
            max_handshakes_per_source: 8,
            handshake_timeout: Duration::from_secs(10),
            header_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(120),
            max_json_bytes: MAX_DEVICE_JSON_BYTES,
            max_headers: 64,
            max_header_bytes: 16 * 1024,
            pending_session_ttl: Duration::from_secs(3600),
            max_pending_sessions: 64,
            max_pending_sessions_per_ip: 4,
            max_pending_sessions_per_boot_service: 32,
            unauthorised_idle_timeout: Duration::from_secs(120),
            session_opens_per_ip_per_min: 10,
            session_opens_per_min: 600,
            session_opens_per_boot_service_per_min: 60,
            max_connections_per_boot_service: 64,
            boot_service_refresh: Duration::from_secs(30),
            code_attempts_per_session: 5,
            code_attempts_per_ip_per_min: 10,
            poll_ms: 2000,
            progress_min_interval: Duration::from_millis(2000),
            max_chunk_requests_per_job: 2,
            code_default_ttl: Duration::from_secs(900),
            code_max_ttl: Duration::from_secs(3600),
            jobs: JobSettings::default(),
            m4: M4Settings::default(),
        }
    }
}

impl DeviceConfig {
    /// Checks every value against its allowed range.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming the first bad setting.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let secs = |d: Duration, lo: u64, hi: u64| (lo..=hi).contains(&d.as_secs());
        let step = |s: u32| (1..=MAX_STEP_TIMEOUT_S).contains(&s);
        let j = &self.jobs;
        let checks: [(bool, &'static str, &'static str); 28] = [
            (
                (1..=4096).contains(&self.max_connections),
                "device_api.max_connections",
                "1 to 4096",
            ),
            (
                (1..=self.max_connections).contains(&self.max_connections_per_source),
                "device_api.max_connections_per_source",
                "1 to device_api.max_connections",
            ),
            (
                (1..=self.max_connections_per_source).contains(&self.max_handshakes_per_source),
                "device_api.max_handshakes_per_source",
                "1 to device_api.max_connections_per_source",
            ),
            (
                secs(self.handshake_timeout, 1, 300),
                "device_api.handshake_timeout_s",
                "1 to 300",
            ),
            (
                secs(self.header_timeout, 1, 300),
                "device_api.header_timeout_s",
                "1 to 300",
            ),
            (
                secs(self.idle_timeout, 1, 3600),
                "device_api.idle_timeout_s",
                "1 to 3600",
            ),
            (
                (1024..=MAX_DEVICE_JSON_BYTES).contains(&self.max_json_bytes),
                "device_api.max_json_bytes",
                "1024 to 65536",
            ),
            (
                (8..=256).contains(&self.max_headers)
                    && (8192..=1024 * 1024).contains(&self.max_header_bytes),
                "device_api.max_headers",
                "8 to 256 headers and 8192 to 1048576 header bytes",
            ),
            (
                secs(self.pending_session_ttl, 60, 86_400),
                "device_api.pending_session_ttl_s",
                "60 to 86400",
            ),
            (
                (1..=100_000).contains(&self.max_pending_sessions)
                    && (1..=self.max_pending_sessions).contains(&self.max_pending_sessions_per_ip),
                "device_api.max_pending_sessions",
                "1 to 100000, and per source 1 to the total",
            ),
            (
                (1..=self.max_pending_sessions)
                    .contains(&self.max_pending_sessions_per_boot_service),
                "device_api.max_pending_sessions_per_boot_service",
                "1 to device_api.max_pending_sessions",
            ),
            (
                secs(
                    self.unauthorised_idle_timeout,
                    30,
                    self.pending_session_ttl.as_secs(),
                ) && self.unauthorised_idle_timeout.as_millis()
                    >= u128::from(self.poll_ms).saturating_mul(5),
                "device_api.unauthorised_idle_timeout_s",
                "30 to device_api.pending_session_ttl_s, and at least 5 poll intervals",
            ),
            (
                (1..=1000).contains(&self.session_opens_per_ip_per_min),
                "device_api.session_opens_per_ip_per_min",
                "1 to 1000",
            ),
            (
                (1..=100_000).contains(&self.session_opens_per_min),
                "device_api.session_opens_per_min",
                "1 to 100000",
            ),
            (
                (1..=100_000).contains(&self.session_opens_per_boot_service_per_min),
                "device_api.session_opens_per_boot_service_per_min",
                "1 to 100000",
            ),
            (
                (1..=self.max_connections).contains(&self.max_connections_per_boot_service),
                "device_api.max_connections_per_boot_service",
                "1 to device_api.max_connections",
            ),
            (
                secs(self.boot_service_refresh, 1, 600),
                "device_api.boot_service_refresh_s",
                "1 to 600",
            ),
            (
                (1..=20).contains(&self.code_attempts_per_session),
                "device_api.code_attempts_per_session",
                "1 to 20",
            ),
            (
                (1..=1000).contains(&self.code_attempts_per_ip_per_min),
                "device_api.code_attempts_per_ip_per_min",
                "1 to 1000",
            ),
            (
                (500..=60_000).contains(&self.poll_ms),
                "device_api.poll_ms",
                "500 to 60000",
            ),
            (
                (100..=60_000).contains(&self.progress_min_interval.as_millis()),
                "device_api.progress_min_interval_ms",
                "100 to 60000",
            ),
            (
                (1..=16).contains(&self.max_chunk_requests_per_job),
                "device_api.max_chunk_requests_per_job",
                "1 to 16",
            ),
            (
                secs(self.code_max_ttl, 60, MAX_CODE_TTL_S)
                    && secs(self.code_default_ttl, 60, self.code_max_ttl.as_secs()),
                "codes.default_ttl_s",
                "60 to codes.max_ttl_s, and codes.max_ttl_s 60 to 86400",
            ),
            (
                secs(j.lost_after, 60, 86_400),
                "jobs.lost_after_s",
                "60 to 86400",
            ),
            (
                (1..=MAX_RETRY_ATTEMPTS).contains(&j.retry_attempts),
                "jobs.retry_attempts",
                "1 to 100",
            ),
            (
                j.retry_base_ms >= 1
                    && j.retry_base_ms <= j.retry_max_ms
                    && j.retry_max_ms <= MAX_RETRY_DELAY_MS,
                "jobs.retry_base_ms",
                "1 <= retry_base_ms <= retry_max_ms <= 3600000",
            ),
            (
                step(j.stall_timeout_s)
                    && step(j.timeout_verify_s)
                    && step(j.timeout_disk_s)
                    && step(j.timeout_apply_s)
                    && step(j.timeout_boot_s)
                    && step(j.timeout_report_s),
                "jobs.timeout_s",
                "every step and stall timeout 1 to 604800",
            ),
            (
                (1..=MAX_REPORT_INTERVAL_S).contains(&j.report_interval_s),
                "jobs.report_interval_s",
                "1 to 3600",
            ),
        ];
        for (ok, setting, range) in checks {
            if !ok {
                return Err(ConfigError { setting, range });
            }
        }
        self.m4.validate()
    }
}

/// The per-minute window of [`PerSourceRate`].
const WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy)]
struct Window {
    start: Instant,
    count: u32,
}

#[derive(Debug, Default)]
struct RateState {
    sources: HashMap<IpAddr, Window>,
    overflow: Option<Window>,
}

/// Events per minute from every source together (finding SEC-001: a
/// ceiling on session opens however many sources send them).
#[derive(Debug)]
pub struct GlobalRate {
    per_min: u32,
    window: Mutex<Option<Window>>,
}

impl GlobalRate {
    /// A limiter allowing `per_min` events per minute in total.
    #[must_use]
    pub fn new(per_min: u32) -> Self {
        Self {
            per_min,
            window: Mutex::new(None),
        }
    }

    /// True (and counted) if one more event fits now.
    pub fn admit(&self, now: Instant) -> bool {
        let mut g = self.window.lock().unwrap_or_else(PoisonError::into_inner);
        let w = g.get_or_insert(Window {
            start: now,
            count: 0,
        });
        if now.saturating_duration_since(w.start) >= WINDOW {
            *w = Window {
                start: now,
                count: 0,
            };
        }
        if w.count < self.per_min {
            w.count = w.count.saturating_add(1);
            true
        } else {
            false
        }
    }
}

/// Most boot services [`PerServiceRate`] tracks; beyond it the windows
/// are reset (at worst a fresh minute for every service).
const MAX_TRACKED_SERVICES: usize = 4096;

/// Events per boot service per minute (finding SEC-011).
#[derive(Debug)]
pub struct PerServiceRate {
    per_min: u32,
    state: Mutex<HashMap<BootServiceId, Window>>,
}

impl PerServiceRate {
    /// A limiter allowing `per_min` events per boot service per minute.
    #[must_use]
    pub fn new(per_min: u32) -> Self {
        Self {
            per_min,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// True (and counted) if one more event for `service` fits now.
    pub fn admit(&self, service: BootServiceId, now: Instant) -> bool {
        let mut m = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if !m.contains_key(&service) && m.len() >= MAX_TRACKED_SERVICES {
            m.retain(|_, w| now.saturating_duration_since(w.start) < WINDOW);
            if m.len() >= MAX_TRACKED_SERVICES {
                m.clear();
            }
        }
        let w = m.entry(service).or_insert(Window {
            start: now,
            count: 0,
        });
        if now.saturating_duration_since(w.start) >= WINDOW {
            *w = Window {
                start: now,
                count: 0,
            };
        }
        if w.count < self.per_min {
            w.count = w.count.saturating_add(1);
            true
        } else {
            false
        }
    }
}

/// Events per source (IPv4 address or IPv6 /64) per minute. Memory is
/// bounded: beyond [`MAX_TRACKED_SOURCES`] sources, new ones share one
/// overflow window (so a spoofed-address flood limits itself).
#[derive(Debug)]
pub struct PerSourceRate {
    per_min: u32,
    state: Mutex<RateState>,
}

impl PerSourceRate {
    /// A limiter allowing `per_min` events per source per minute.
    #[must_use]
    pub fn new(per_min: u32) -> Self {
        Self {
            per_min,
            state: Mutex::new(RateState::default()),
        }
    }

    /// True (and counted) if one more event from `ip` fits now.
    pub fn admit(&self, ip: IpAddr, now: Instant) -> bool {
        let key = source_key(ip);
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if !s.sources.contains_key(&key) && s.sources.len() >= MAX_TRACKED_SOURCES {
            s.sources
                .retain(|_, w| now.saturating_duration_since(w.start) < WINDOW);
        }
        let tracked = s.sources.contains_key(&key) || s.sources.len() < MAX_TRACKED_SOURCES;
        let fresh = Window {
            start: now,
            count: 0,
        };
        let w = if tracked {
            s.sources.entry(key).or_insert(fresh)
        } else {
            s.overflow.get_or_insert(fresh)
        };
        if now.saturating_duration_since(w.start) >= WINDOW {
            *w = fresh;
        }
        if w.count < self.per_min {
            w.count = w.count.saturating_add(1);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn defaults_valid_and_off() {
        let c = DeviceConfig::default();
        c.validate().unwrap();
        assert!(!c.enabled);
        assert_eq!(c.max_json_bytes, 65_536);
        assert_eq!(c.code_attempts_per_session, 5);
        assert_eq!(c.pending_session_ttl, Duration::from_secs(3600));
    }

    #[test]
    fn out_of_range_refused() {
        let base = DeviceConfig::default();
        let c = DeviceConfig {
            code_default_ttl: Duration::from_secs(7200),
            ..base.clone()
        };
        assert_eq!(c.validate().unwrap_err().setting, "codes.default_ttl_s");
        let c = DeviceConfig {
            max_json_bytes: 65_537,
            ..base.clone()
        };
        assert_eq!(
            c.validate().unwrap_err().setting,
            "device_api.max_json_bytes"
        );
        let mut c = base.clone();
        c.jobs.retry_base_ms = 70_000;
        assert_eq!(c.validate().unwrap_err().setting, "jobs.retry_base_ms");
        let c = DeviceConfig {
            max_pending_sessions_per_ip: 65,
            ..base
        };
        assert!(c.validate().is_err());
    }

    /// Finding SEC-001: the new caps are range-checked.
    #[test]
    fn sec001_settings_checked() {
        let base = DeviceConfig::default();
        assert_eq!(base.max_pending_sessions_per_boot_service, 32);
        assert_eq!(base.unauthorised_idle_timeout, Duration::from_secs(120));
        assert_eq!(base.session_opens_per_min, 600);
        assert_eq!(base.session_opens_per_boot_service_per_min, 60);
        assert_eq!(base.max_connections_per_boot_service, 64);
        assert_eq!(base.boot_service_refresh, Duration::from_secs(30));
        for (c, setting) in [
            (
                DeviceConfig {
                    max_pending_sessions_per_boot_service: 65,
                    ..base.clone()
                },
                "device_api.max_pending_sessions_per_boot_service",
            ),
            (
                DeviceConfig {
                    unauthorised_idle_timeout: Duration::from_secs(5),
                    ..base.clone()
                },
                "device_api.unauthorised_idle_timeout_s",
            ),
            (
                DeviceConfig {
                    unauthorised_idle_timeout: Duration::from_secs(30),
                    poll_ms: 10_000,
                    ..base.clone()
                },
                "device_api.unauthorised_idle_timeout_s",
            ),
            (
                DeviceConfig {
                    session_opens_per_min: 0,
                    ..base.clone()
                },
                "device_api.session_opens_per_min",
            ),
            (
                DeviceConfig {
                    session_opens_per_boot_service_per_min: 0,
                    ..base.clone()
                },
                "device_api.session_opens_per_boot_service_per_min",
            ),
            (
                DeviceConfig {
                    max_connections_per_boot_service: 257,
                    ..base.clone()
                },
                "device_api.max_connections_per_boot_service",
            ),
            (
                DeviceConfig {
                    boot_service_refresh: Duration::from_secs(0),
                    ..base.clone()
                },
                "device_api.boot_service_refresh_s",
            ),
        ] {
            assert_eq!(c.validate().unwrap_err().setting, setting);
        }
    }

    #[test]
    fn per_service_rate() {
        let r = PerServiceRate::new(2);
        let t = Instant::now();
        let a = BootServiceId::from_random_bytes([1; 16]);
        let b = BootServiceId::from_random_bytes([2; 16]);
        assert!(r.admit(a, t) && r.admit(a, t));
        assert!(!r.admit(a, t));
        assert!(r.admit(b, t));
        assert!(r.admit(a, t + WINDOW));
    }

    #[test]
    fn global_rate() {
        let r = GlobalRate::new(2);
        let t = Instant::now();
        assert!(r.admit(t) && r.admit(t));
        assert!(!r.admit(t));
        assert!(r.admit(t + WINDOW));
    }

    #[test]
    fn per_source_rate() {
        let r = PerSourceRate::new(2);
        let t = Instant::now();
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(r.admit(a, t) && r.admit(a, t));
        assert!(!r.admit(a, t));
        assert!(r.admit(b, t));
        assert!(r.admit(a, t + WINDOW));
    }
}
