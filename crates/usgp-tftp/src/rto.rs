//! Adaptive retransmission timeout in the style of RFC 6298: smoothed RTT
//! and RTT variance, Karn's rule (the caller skips samples for
//! retransmitted packets), and doubling backoff on each timeout.
//!
//! RFC 1123 §4.2.3.2 requires an adaptive TFTP timeout that at least backs
//! off exponentially, using TCP's methods as a model.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-5 (Denial-of-Service Protection) - bounded, backing-off
//   retransmission.
// - SPEC: specs/boot-network.md#REQ-BOOT-032
// - RFC 1123 §4.2.3.2 - adaptive timeout

use core::time::Duration;

/// Retransmission timer state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rto {
    srtt: Option<Duration>,
    rttvar: Duration,
    rto: Duration,
    min: Duration,
    max: Duration,
}

impl Rto {
    /// Starts at `initial`, kept within `min..=max` (if `min > max`, `max`
    /// is raised to `min`).
    #[must_use]
    pub fn new(initial: Duration, min: Duration, max: Duration) -> Self {
        let max = max.max(min);
        Self {
            srtt: None,
            rttvar: Duration::ZERO,
            rto: initial.clamp(min, max),
            min,
            max,
        }
    }

    /// The current timeout.
    #[must_use]
    pub fn current(&self) -> Duration {
        self.rto
    }

    /// Smoothed RTT, once a sample exists.
    #[must_use]
    pub fn srtt(&self) -> Option<Duration> {
        self.srtt
    }

    /// Feeds one RTT measurement from a packet that was sent only once
    /// (Karn's rule is the caller's job).
    ///
    /// First sample: SRTT = R, RTTVAR = R/2. Later: RTTVAR = 3/4 RTTVAR +
    /// 1/4 |SRTT - R|, SRTT = 7/8 SRTT + 1/8 R. RTO = SRTT + 4 RTTVAR,
    /// clamped to `min..=max`.
    pub fn sample(&mut self, r: Duration) {
        let (srtt, rttvar) = match self.srtt {
            None => (r, r / 2),
            Some(srtt) => {
                let diff = srtt.abs_diff(r);
                let rttvar = (self.rttvar.saturating_mul(3) / 4).saturating_add(diff / 4);
                let srtt = (srtt.saturating_mul(7) / 8).saturating_add(r / 8);
                (srtt, rttvar)
            }
        };
        self.srtt = Some(srtt);
        self.rttvar = rttvar;
        self.rto = srtt
            .saturating_add(rttvar.saturating_mul(4))
            .clamp(self.min, self.max);
    }

    /// Doubles the timeout after a retransmission, up to `max`.
    pub fn backoff(&mut self) {
        self.rto = self.rto.saturating_mul(2).min(self.max);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    #[test]
    fn rto_backoff_doubles() {
        let mut r = Rto::new(ms(1000), ms(250), ms(8000));
        assert_eq!(r.current(), ms(1000));
        r.backoff();
        assert_eq!(r.current(), ms(2000));
        r.backoff();
        assert_eq!(r.current(), ms(4000));
        r.backoff();
        assert_eq!(r.current(), ms(8000));
        r.backoff();
        assert_eq!(r.current(), ms(8000), "capped at max");
    }

    #[test]
    fn rto_adapts_from_samples() {
        let mut r = Rto::new(ms(1000), ms(250), ms(8000));
        r.sample(ms(100));
        // SRTT 100, RTTVAR 50 -> 300.
        assert_eq!(r.srtt(), Some(ms(100)));
        assert_eq!(r.current(), ms(300));
        for _ in 0..50 {
            r.sample(ms(20));
        }
        // Converges toward the floor.
        assert_eq!(r.current(), ms(250));
        r.sample(ms(3000));
        assert!(r.current() > ms(250));
    }

    #[test]
    fn rto_clamped_to_bounds() {
        let r = Rto::new(ms(10), ms(250), ms(8000));
        assert_eq!(r.current(), ms(250));
        let r = Rto::new(ms(60_000), ms(250), ms(8000));
        assert_eq!(r.current(), ms(8000));
        let r = Rto::new(ms(1000), ms(5000), ms(100));
        assert_eq!(r.current(), ms(5000));
        let mut r = Rto::new(ms(1000), ms(250), ms(8000));
        r.sample(Duration::MAX);
        assert_eq!(r.current(), ms(8000));
    }
}
