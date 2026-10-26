//! Load-shedding primitives: token buckets, bounded bucket tables and
//! aggregated counters (REQ-BOOT-044).
//!
//! All arithmetic is integer and saturating, and time is passed in, so the
//! behaviour is deterministic in tests. Shedding always means a silent drop
//! (plan section 1.1).

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-5 (Denial-of-Service Protection) - per-key and global
//   budgets; bounded tables evict the stalest key first, so memory stays
//   bounded however many keys arrive.
// - SPEC: specs/boot-network.md#REQ-BOOT-044 (numeric limits are project
//   design, OPEN-BOOT-L1)

use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;
use std::time::{Duration, Instant};

/// A token bucket holding up to `burst` tokens, refilled by one token per
/// `per_token`.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    tokens: u32,
    burst: u32,
    per_token: Duration,
    /// Time up to which refill has been credited.
    credited: Instant,
}

impl TokenBucket {
    /// A full bucket. `burst` is at least 1 and `per_token` at least 1 ns.
    #[must_use]
    pub fn new(burst: u32, per_token: Duration, now: Instant) -> Self {
        Self {
            tokens: burst.max(1),
            burst: burst.max(1),
            per_token: per_token.max(Duration::from_nanos(1)),
            credited: now,
        }
    }

    /// A bucket refilled at `per_sec` tokens per second, holding at most
    /// `burst`.
    #[must_use]
    pub fn per_second(burst: u32, per_sec: u32, now: Instant) -> Self {
        let per_sec = u64::from(per_sec.max(1));
        Self::new(burst, Duration::from_nanos(1_000_000_000 / per_sec), now)
    }

    fn refill(&mut self, now: Instant) {
        if self.tokens >= self.burst {
            self.credited = now.max(self.credited);
            return;
        }
        let elapsed = now.saturating_duration_since(self.credited);
        let step = self.per_token.as_nanos().max(1);
        let earned = elapsed.as_nanos() / step;
        if earned == 0 {
            return;
        }
        let room = u128::from(self.burst - self.tokens);
        if earned >= room {
            self.tokens = self.burst;
            self.credited = now;
        } else {
            // earned < room <= u32::MAX, so both conversions are exact.
            let earned32 = u32::try_from(earned).unwrap_or(u32::MAX);
            self.tokens = self.tokens.saturating_add(earned32);
            let credit = self.per_token.saturating_mul(earned32);
            self.credited = self.credited.checked_add(credit).unwrap_or(now);
        }
    }

    /// Takes one token if available.
    pub fn try_take(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens == 0 {
            return false;
        }
        self.tokens -= 1;
        true
    }

    /// Tokens currently available (after refill to `now`).
    pub fn available(&mut self, now: Instant) -> u32 {
        self.refill(now);
        self.tokens
    }
}

/// Parameters for the buckets created by a [`BucketTable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketSpec {
    /// Bucket size.
    pub burst: u32,
    /// Refill interval per token.
    pub per_token: Duration,
}

#[derive(Debug)]
struct Slot {
    bucket: TokenBucket,
    stamp: u64,
}

/// One token bucket per key, at most `capacity` keys. When full, the key
/// used least recently is evicted first. Every operation is O(log n).
#[derive(Debug)]
pub struct BucketTable<K> {
    spec: BucketSpec,
    capacity: usize,
    slots: HashMap<K, Slot>,
    order: BTreeMap<u64, K>,
    next_stamp: u64,
    evictions: u64,
}

impl<K: Eq + Hash + Clone> BucketTable<K> {
    /// An empty table. `capacity` is at least 1.
    #[must_use]
    pub fn new(spec: BucketSpec, capacity: usize) -> Self {
        Self {
            spec,
            capacity: capacity.max(1),
            slots: HashMap::new(),
            order: BTreeMap::new(),
            next_stamp: 0,
            evictions: 0,
        }
    }

    /// Takes one token from `key`'s bucket, creating a full bucket for a
    /// new key (evicting the stalest key if the table is full).
    pub fn try_take(&mut self, key: &K, now: Instant) -> bool {
        let stamp = self.next_stamp;
        self.next_stamp = self.next_stamp.wrapping_add(1);
        if let Some(slot) = self.slots.get_mut(key) {
            self.order.remove(&slot.stamp);
            slot.stamp = stamp;
            self.order.insert(stamp, key.clone());
            return slot.bucket.try_take(now);
        }
        while self.slots.len() >= self.capacity {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            self.slots.remove(&oldest);
            self.evictions = self.evictions.saturating_add(1);
        }
        let mut bucket = TokenBucket::new(self.spec.burst, self.spec.per_token, now);
        let ok = bucket.try_take(now);
        self.slots.insert(key.clone(), Slot { bucket, stamp });
        self.order.insert(stamp, key.clone());
        ok
    }

    /// Number of keys tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether no key is tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Whether `key` is tracked.
    #[must_use]
    pub fn contains(&self, key: &K) -> bool {
        self.slots.contains_key(key)
    }

    /// Keys evicted so far.
    #[must_use]
    pub fn evictions(&self) -> u64 {
        self.evictions
    }
}

/// Counts per static label, drained by a periodic summary event so that a
/// flood produces one log line per interval, not one per packet.
#[derive(Debug, Default)]
pub struct Counters {
    counts: BTreeMap<&'static str, u64>,
}

impl Counters {
    /// Adds one to `label`.
    pub fn bump(&mut self, label: &'static str) {
        let c = self.counts.entry(label).or_insert(0);
        *c = c.saturating_add(1);
    }

    /// Current count for `label`.
    #[must_use]
    pub fn get(&self, label: &str) -> u64 {
        self.counts.get(label).copied().unwrap_or(0)
    }

    /// Returns and clears every non-zero count, in label order.
    pub fn drain(&mut self) -> Vec<(&'static str, u64)> {
        std::mem::take(&mut self.counts).into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn bucket_burst_then_refill() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(3, ms(100), t0);
        assert!(b.try_take(t0));
        assert!(b.try_take(t0));
        assert!(b.try_take(t0));
        assert!(!b.try_take(t0));
        assert!(!b.try_take(t0 + ms(99)));
        assert!(b.try_take(t0 + ms(100)));
        assert!(!b.try_take(t0 + ms(150)));
        assert!(b.try_take(t0 + ms(200)));
    }

    #[test]
    fn bucket_never_exceeds_burst() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(2, ms(10), t0);
        assert_eq!(b.available(t0 + Duration::from_secs(3600)), 2);
    }

    #[test]
    fn bucket_partial_refill_keeps_remainder() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(5, ms(100), t0);
        for _ in 0..5 {
            assert!(b.try_take(t0));
        }
        // 250 ms earns 2 tokens and keeps 50 ms of credit.
        assert_eq!(b.available(t0 + ms(250)), 2);
        assert_eq!(b.available(t0 + ms(300)), 3);
    }

    #[test]
    fn per_second_rate() {
        let t0 = Instant::now();
        let mut b = TokenBucket::per_second(1, 10, t0);
        assert!(b.try_take(t0));
        assert!(!b.try_take(t0 + ms(99)));
        assert!(b.try_take(t0 + ms(100)));
    }

    #[test]
    fn zero_parameters_are_clamped() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(0, Duration::ZERO, t0);
        assert!(b.try_take(t0));
        let mut p = TokenBucket::per_second(0, 0, t0);
        assert!(p.try_take(t0));
    }

    #[test]
    fn table_is_bounded_and_evicts_stalest() {
        let t0 = Instant::now();
        let spec = BucketSpec {
            burst: 1,
            per_token: Duration::from_secs(60),
        };
        let mut t = BucketTable::new(spec, 3);
        assert!(t.try_take(&1u32, t0));
        assert!(t.try_take(&2u32, t0));
        assert!(t.try_take(&3u32, t0));
        // Touch 1 so that 2 is the stalest.
        assert!(!t.try_take(&1u32, t0));
        assert!(t.try_take(&4u32, t0));
        assert_eq!(t.len(), 3);
        assert!(t.contains(&1));
        assert!(!t.contains(&2));
        assert!(t.contains(&3));
        assert!(t.contains(&4));
        assert_eq!(t.evictions(), 1);
    }

    #[test]
    fn table_many_keys_stays_bounded() {
        let t0 = Instant::now();
        let spec = BucketSpec {
            burst: 2,
            per_token: ms(1),
        };
        let mut t = BucketTable::new(spec, 64);
        for k in 0u32..10_000 {
            assert!(t.try_take(&k, t0));
        }
        assert_eq!(t.len(), 64);
        assert_eq!(t.evictions(), 10_000 - 64);
    }

    #[test]
    fn counters_drain() {
        let mut c = Counters::default();
        c.bump("b");
        c.bump("a");
        c.bump("a");
        assert_eq!(c.get("a"), 2);
        assert_eq!(c.drain(), vec![("a", 2), ("b", 1)]);
        assert!(c.drain().is_empty());
    }
}
