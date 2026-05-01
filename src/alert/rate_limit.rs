//! Shared token-bucket rate limiter for outbound sinks.
//!
//! Why a token bucket and not a simple "max N per window"?
//! - Bursts: real outages emit 50 errors in two seconds. Capping at
//!   `5/minute` would lose all but the first five even though the rest
//!   are genuinely informative; a token-bucket smooths the burst over
//!   the cap interval.
//! - Steady-state idle refill keeps long-running daemons from
//!   accumulating credit forever and pager-storming on the next event.
//!
//! Why per-key dedup *on top of* the bucket?
//! - The classifier already cools down per (rule, key). The sink-level
//!   dedup is the second guard: even if classifier rules are tweaked
//!   loosely, sinks can't flood the user. Defense in depth per AVP-2.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Allows at most `capacity` events per `refill_interval`, with linear
/// refill. Thread-safe via the surrounding `Mutex` in the sink.
#[derive(Debug)]
pub struct TokenBucket {
    capacity: u32,
    refill_interval: Duration,
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(capacity: u32, refill_interval: Duration) -> Self {
        Self {
            capacity,
            refill_interval,
            tokens: capacity as f64,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume one token. Returns true on success, false if the
    /// bucket is empty (caller should drop the alert and log).
    pub fn try_take(&mut self) -> bool {
        self.try_take_at(Instant::now())
    }

    pub fn try_take_at(&mut self, now: Instant) -> bool {
        // Refill: add `capacity` tokens per `refill_interval` elapsed.
        let elapsed = now.saturating_duration_since(self.last_refill);
        let interval_secs = self.refill_interval.as_secs_f64();
        if interval_secs > 0.0 {
            let added = (elapsed.as_secs_f64() / interval_secs) * self.capacity as f64;
            if added > 0.0 {
                self.tokens = (self.tokens + added).min(self.capacity as f64);
                self.last_refill = now;
            }
        }

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Per-key dedup: returns true on the first call for each key, then
/// suppresses subsequent calls for the configured cooldown duration.
/// Used to prevent the email sink from re-paging on a repeating alert.
#[derive(Debug, Default)]
pub struct DedupCache {
    cooldown: Duration,
    seen: HashMap<String, Instant>,
}

impl DedupCache {
    pub fn new(cooldown: Duration) -> Self {
        Self {
            cooldown,
            seen: HashMap::new(),
        }
    }

    pub fn should_emit(&mut self, key: &str) -> bool {
        self.should_emit_at(key, Instant::now())
    }

    pub fn should_emit_at(&mut self, key: &str, now: Instant) -> bool {
        match self.seen.get(key) {
            Some(last) if now.saturating_duration_since(*last) < self.cooldown => false,
            _ => {
                self.seen.insert(key.to_string(), now);
                // Opportunistic GC: drop entries past cooldown so the
                // map doesn't grow unbounded across long runs.
                let cooldown = self.cooldown;
                self.seen
                    .retain(|_, t| now.saturating_duration_since(*t) < cooldown);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_allows_capacity_then_blocks() {
        let mut b = TokenBucket::new(3, Duration::from_secs(60));
        assert!(b.try_take());
        assert!(b.try_take());
        assert!(b.try_take());
        assert!(!b.try_take(), "fourth take must be blocked");
    }

    #[test]
    fn bucket_refills_over_time() {
        let mut b = TokenBucket::new(2, Duration::from_secs(10));
        let t0 = Instant::now();
        assert!(b.try_take_at(t0));
        assert!(b.try_take_at(t0));
        assert!(!b.try_take_at(t0));
        // Half the refill interval = 1 token added.
        let t1 = t0 + Duration::from_secs(5);
        assert!(b.try_take_at(t1));
        assert!(!b.try_take_at(t1));
        // Full interval = 2 more tokens, but cap at capacity (2).
        let t2 = t1 + Duration::from_secs(20);
        assert!(b.try_take_at(t2));
        assert!(b.try_take_at(t2));
        assert!(!b.try_take_at(t2));
    }

    #[test]
    fn dedup_first_call_emits_subsequent_suppressed() {
        let mut d = DedupCache::new(Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(d.should_emit_at("k", t0));
        assert!(!d.should_emit_at("k", t0));
        assert!(!d.should_emit_at("k", t0 + Duration::from_secs(30)));
    }

    #[test]
    fn dedup_emits_again_after_cooldown() {
        let mut d = DedupCache::new(Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(d.should_emit_at("k", t0));
        assert!(d.should_emit_at("k", t0 + Duration::from_secs(61)));
    }

    #[test]
    fn dedup_distinct_keys_are_independent() {
        let mut d = DedupCache::new(Duration::from_secs(60));
        let t0 = Instant::now();
        assert!(d.should_emit_at("a", t0));
        assert!(d.should_emit_at("b", t0));
        assert!(!d.should_emit_at("a", t0));
    }
}
