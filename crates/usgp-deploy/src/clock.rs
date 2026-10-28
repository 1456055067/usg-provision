//! Monotonic time for step timeouts, stall detection, retry delays and the
//! report interval (REQ-JOB-007, REQ-JOB-011).
//!
//! The engine never reads the wall clock: the device's RTC is not trusted
//! (plan section 3.2), and timeouts need only elapsed time.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-5 (Denial of Service Protection) - bounded steps,
//   bounded retries.
// - SPEC: specs/progress.md#REQ-JOB-007, #REQ-JOB-011

use std::time::{Duration, Instant};

/// Elapsed time and sleeping. Tests use a fake whose `sleep` advances
/// time without waiting.
pub trait Clock {
    /// Time since an arbitrary fixed point; never goes backwards.
    fn now(&self) -> Duration;
    /// Waits for `d`.
    fn sleep(&self, d: Duration);
}

/// The process's monotonic clock.
#[derive(Debug, Clone, Copy)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// A clock whose zero is now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// Which time limit a step hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimeLimit {
    /// The step's own timeout (plan `steps[].timeout_s`).
    Step,
    /// No progress for `stall_timeout_s`.
    Stall,
}

/// The time limits of one running step. Interior mutability, because the
/// chunk source and the apply progress hook both mark progress while the
/// engine holds them separately.
pub(crate) struct Watch<'a> {
    clock: &'a dyn Clock,
    deadline: Duration,
    stall: Duration,
    last_progress: std::cell::Cell<Duration>,
    tripped: std::cell::Cell<Option<TimeLimit>>,
}

impl<'a> Watch<'a> {
    /// Starts the limits of a step now.
    pub(crate) fn start(clock: &'a dyn Clock, timeout: Duration, stall: Duration) -> Self {
        let now = clock.now();
        Self {
            clock,
            deadline: now.saturating_add(timeout),
            stall,
            last_progress: std::cell::Cell::new(now),
            tripped: std::cell::Cell::new(None),
        }
    }

    /// Records progress (bytes moved).
    pub(crate) fn progress(&self) {
        self.last_progress.set(self.clock.now());
    }

    /// `Err` with the limit hit, if any. Once hit, a limit stays hit.
    pub(crate) fn check(&self) -> Result<(), TimeLimit> {
        if let Some(t) = self.tripped.get() {
            return Err(t);
        }
        let now = self.clock.now();
        let hit = if now >= self.deadline {
            Some(TimeLimit::Step)
        } else if now.saturating_sub(self.last_progress.get()) >= self.stall {
            Some(TimeLimit::Stall)
        } else {
            None
        };
        match hit {
            Some(t) => {
                self.tripped.set(Some(t));
                Err(t)
            }
            None => Ok(()),
        }
    }

    /// `Err` if waiting `d` from now would pass a limit: the step deadline,
    /// or the stall limit counted from the last progress.
    pub(crate) fn check_wait(&self, d: Duration) -> Result<(), TimeLimit> {
        self.check()?;
        let after = self.clock.now().saturating_add(d);
        let hit = if after >= self.deadline {
            Some(TimeLimit::Step)
        } else if after.saturating_sub(self.last_progress.get()) >= self.stall {
            Some(TimeLimit::Stall)
        } else {
            None
        };
        match hit {
            Some(t) => {
                self.tripped.set(Some(t));
                Err(t)
            }
            None => Ok(()),
        }
    }

    /// The limit hit so far, if any (without reading the clock).
    pub(crate) fn tripped(&self) -> Option<TimeLimit> {
        self.tripped.get()
    }
}

/// Delay before retry `attempt` (1-based count of failures so far):
/// `base * 2^(attempt-1)`, capped at `max` (REQ-JOB-007; values from the
/// signed plan, OPEN-JOB-4).
pub(crate) fn backoff(base_ms: u32, max_ms: u32, attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(31);
    let ms = u64::from(base_ms)
        .checked_shl(shift)
        .unwrap_or(u64::MAX)
        .min(u64::from(max_ms));
    Duration::from_millis(ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct Fake(Cell<Duration>);
    impl Clock for Fake {
        fn now(&self) -> Duration {
            self.0.get()
        }
        fn sleep(&self, d: Duration) {
            self.0.set(self.0.get() + d);
        }
    }

    #[test]
    fn backoff_doubles_and_caps() {
        assert_eq!(backoff(2000, 60_000, 1), Duration::from_millis(2000));
        assert_eq!(backoff(2000, 60_000, 2), Duration::from_millis(4000));
        assert_eq!(backoff(2000, 60_000, 5), Duration::from_millis(32_000));
        assert_eq!(backoff(2000, 60_000, 6), Duration::from_millis(60_000));
        assert_eq!(backoff(2000, 60_000, 100), Duration::from_millis(60_000));
        assert_eq!(backoff(1, u32::MAX, 0), Duration::from_millis(1));
    }

    #[test]
    fn watch_trips_step_then_stays() {
        let c = Fake(Cell::new(Duration::ZERO));
        let w = Watch::start(&c, Duration::from_secs(10), Duration::from_secs(100));
        assert!(w.check().is_ok());
        c.sleep(Duration::from_secs(10));
        assert_eq!(w.check(), Err(TimeLimit::Step));
        assert_eq!(w.tripped(), Some(TimeLimit::Step));
    }

    #[test]
    fn watch_trips_stall_and_progress_resets() {
        let c = Fake(Cell::new(Duration::ZERO));
        let w = Watch::start(&c, Duration::from_secs(1000), Duration::from_secs(10));
        c.sleep(Duration::from_secs(9));
        w.progress();
        c.sleep(Duration::from_secs(9));
        assert!(w.check().is_ok());
        assert_eq!(w.check_wait(Duration::from_secs(1)), Err(TimeLimit::Stall));
    }
}
