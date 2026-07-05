//! Runtime resource bounds: concurrent-session caps and per-IP accept rate limits. Counters stay
//! process-local; nothing crosses process boundaries unless a caller explicitly re-registers an
//! adopted session.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

use crate::config::LimitsConfig;

/// Returned to the caller on `try_acquire_session`. On `Ok`, the caller *must* release the slot
/// when the session ends. This is easiest via `Drop` of the guard.
#[must_use = "drop releases the in-flight slot"]
pub struct SessionGuard {
    counter: Arc<AtomicU64>,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Cap on concurrent sessions in this process. `try_acquire` is the only way to bump the counter;
/// the returned guard releases on drop.
#[derive(Clone)]
pub struct SessionCap {
    in_flight: Arc<AtomicU64>,
    cap: u64,
}

impl SessionCap {
    pub fn new(cap: u64) -> Self {
        Self {
            in_flight: Arc::new(AtomicU64::new(0)),
            cap,
        }
    }

    pub fn try_acquire(&self) -> Option<SessionGuard> {
        if self.cap == 0 {
            // 0 disables the cap; still track in_flight so current() stays accurate
            self.in_flight.fetch_add(1, Ordering::SeqCst);
            return Some(SessionGuard {
                counter: self.in_flight.clone(),
            });
        }
        // Optimistic CAS: read, check, increment if under cap
        loop {
            let cur = self.in_flight.load(Ordering::SeqCst);
            if cur >= self.cap {
                return None;
            }
            if self
                .in_flight
                .compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Some(SessionGuard {
                    counter: self.in_flight.clone(),
                });
            }
        }
    }

    pub fn current(&self) -> u64 {
        self.in_flight.load(Ordering::Relaxed)
    }
}

// Token bucket for per-IP accept rate

struct Bucket {
    tokens: f64,
    last_refill: Instant,
    last_touch: Instant,
}

/// Per-IP token-bucket rate limit with bounded memory. The `try_take(ip)` call returns true when a
/// token was available and consumed, or false when the bucket is empty or the limiter is at
/// capacity with all buckets throttled.
///
/// When `max_tracked_ips` is non-zero, the limiter maintains an LRU + TTL eviction policy: buckets
/// past `idle_ttl` are opportunistically dropped, and when inserting at the cap, the LRU or a full
/// bucket is evicted. If all buckets are throttled at cap, the new IP is refused (returns false).
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<LimiterInner>>,
    capacity: f64,
    refill_per_sec: f64,
    idle_ttl: Duration,
    max_tracked: usize,
}

struct LimiterInner {
    buckets: HashMap<IpAddr, Bucket>,
    /// Eviction stats: (`idle_evictions`, `lru_evictions`, `cap_refused`)
    stats: (u64, u64, u64),
}

impl RateLimiter {
    /// Test-only convenience constructor: unbounded tracking, 300s idle TTL. Production code goes
    /// through [`AcceptorLimits::from_config`], which always calls [`RateLimiter::with_limits`]
    /// with explicit bounds.
    #[cfg(test)]
    pub fn new(refill_per_sec: u32, burst: u32) -> Self {
        Self::with_limits(refill_per_sec, burst, 0, 300)
    }

    /// Create a limiter with explicit bounds. `max_tracked=0` means unbounded.
    pub fn with_limits(
        refill_per_sec: u32,
        burst: u32,
        max_tracked: usize,
        idle_ttl_secs: u64,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(LimiterInner {
                buckets: HashMap::new(),
                stats: (0, 0, 0),
            })),
            capacity: f64::from(burst.max(1)),
            refill_per_sec: f64::from(refill_per_sec),
            idle_ttl: Duration::from_secs(idle_ttl_secs),
            max_tracked,
        }
    }

    /// 0 refill rate disables the limiter; everyone passes.
    fn enabled(&self) -> bool {
        self.refill_per_sec > 0.0
    }

    pub fn try_take(&self, ip: IpAddr) -> bool {
        if !self.enabled() {
            return true;
        }
        let now = Instant::now();
        self.inner.lock().unwrap().try_take_at(
            now,
            ip,
            self.capacity,
            self.refill_per_sec,
            self.idle_ttl,
            self.max_tracked,
        )
    }

    /// Return (`tracked_ips`, `idle_evictions`, `lru_evictions`, `cap_refused`)
    pub fn stats(&self) -> (usize, u64, u64, u64) {
        let inner = self.inner.lock().unwrap();
        (
            inner.buckets.len(),
            inner.stats.0,
            inner.stats.1,
            inner.stats.2,
        )
    }
}

impl LimiterInner {
    fn try_take_at(
        &mut self,
        now: Instant,
        ip: IpAddr,
        capacity: f64,
        refill_per_sec: f64,
        idle_ttl: Duration,
        max_tracked: usize,
    ) -> bool {
        // Evict idle buckets (first pass).
        self.evict_idle_buckets(now, idle_ttl);

        // Handle insert-at-cap eviction. If we're at the tracked-IP cap with a new IP and every
        // bucket is throttled, `evict_at_cap` makes no room. Refuse the new IP.
        if max_tracked > 0
            && self.buckets.len() >= max_tracked
            && !self.buckets.contains_key(&ip)
            && !self.evict_at_cap(now, capacity, max_tracked)
        {
            self.stats.2 += 1;
            return false;
        }

        let bucket = self.buckets.entry(ip).or_insert_with(|| Bucket {
            tokens: capacity,
            last_refill: now,
            last_touch: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * refill_per_sec).min(capacity);
        bucket.last_refill = now;
        bucket.last_touch = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn evict_idle_buckets(&mut self, now: Instant, idle_ttl: Duration) {
        let before = self.buckets.len();
        self.buckets
            .retain(|_, b| now.duration_since(b.last_touch) < idle_ttl);
        let after = self.buckets.len();
        self.stats.0 += u64::try_from(before - after).unwrap_or(u64::MAX);
    }

    /// Evict one bucket at cap to make room. Returns false if all buckets are throttled (should
    /// refuse the new IP), or true if an eviction succeeded.
    fn evict_at_cap(&mut self, _now: Instant, _capacity: f64, _max_tracked: usize) -> bool {
        let mut best_candidate: Option<(IpAddr, f64, Instant)> = None;
        let mut all_throttled = true;

        for (&ip, bucket) in &self.buckets {
            let tokens = bucket.tokens;
            let last_touch = bucket.last_touch;

            // Check if this bucket is not throttled.
            if tokens >= 1.0 {
                all_throttled = false;
            }

            // Prefer bucket with most tokens (closest to full, least throttled). Break ties by
            // oldest last_touch (LRU).
            if let Some((_, best_tokens, best_touch)) = best_candidate {
                if tokens > best_tokens
                    || (tokens.total_cmp(&best_tokens).is_eq() && last_touch < best_touch)
                {
                    best_candidate = Some((ip, tokens, last_touch));
                }
            } else {
                best_candidate = Some((ip, tokens, last_touch));
            }
        }

        if all_throttled {
            // All buckets are throttled (tokens < 1.0); refuse the new IP
            return false;
        }

        if let Some((ip, _, _)) = best_candidate {
            // Evict the bucket with most tokens (closest to full, least throttled)
            self.buckets.remove(&ip);
            self.stats.1 += 1;
            true
        } else {
            false
        }
    }
}

/// Bundle the acceptor's runtime limits in one struct so we only pass one arg around.
#[derive(Clone)]
pub struct AcceptorLimits {
    pub sessions: SessionCap,
    pub rate: RateLimiter,
}

impl AcceptorLimits {
    pub fn from_config(cfg: &LimitsConfig) -> Self {
        Self {
            sessions: SessionCap::new(cfg.max_in_flight_per_role),
            rate: RateLimiter::with_limits(
                cfg.accept_rate_per_ip,
                cfg.accept_rate_burst,
                cfg.rate_limit_max_tracked_ips,
                cfg.rate_limit_bucket_idle_ttl_secs,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, thread, time::Duration};

    use super::*;

    #[test]
    fn session_cap_zero_is_unbounded() {
        let cap = SessionCap::new(0);
        let mut guards = Vec::new();
        for _ in 0..10_000 {
            guards.push(cap.try_acquire().expect("0 = unbounded"));
        }
    }

    #[test]
    fn session_cap_zero_current_tracks_in_flight() {
        let cap = SessionCap::new(0);
        let g1 = cap.try_acquire().unwrap();
        assert_eq!(cap.current(), 1);
        let g2 = cap.try_acquire().unwrap();
        assert_eq!(cap.current(), 2);
        drop(g1);
        assert_eq!(cap.current(), 1);
        drop(g2);
        assert_eq!(cap.current(), 0);
    }

    #[test]
    fn session_cap_blocks_over_limit() {
        let cap = SessionCap::new(2);
        let g1 = cap.try_acquire().unwrap();
        let g2 = cap.try_acquire().unwrap();
        assert!(cap.try_acquire().is_none(), "3rd over cap=2 should fail");
        assert_eq!(cap.current(), 2);
        drop(g1);
        assert_eq!(cap.current(), 1);
        let g3 = cap.try_acquire().expect("slot freed");
        assert_eq!(cap.current(), 2);
        drop(g2);
        drop(g3);
        assert_eq!(cap.current(), 0);
    }

    #[test]
    fn rate_limiter_zero_disabled() {
        let rl = RateLimiter::new(0, 1);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for _ in 0..1000 {
            assert!(rl.try_take(ip), "refill=0 disables limiter");
        }
    }

    #[test]
    fn rate_limiter_burst_then_throttle() {
        // 10 tokens/sec, burst of 3
        let rl = RateLimiter::new(10, 3);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        // First 3 succeed immediately (burst)
        assert!(rl.try_take(ip));
        assert!(rl.try_take(ip));
        assert!(rl.try_take(ip));
        // 4th drained — must fail (no time has passed for refill)
        assert!(!rl.try_take(ip));
    }

    #[test]
    fn rate_limiter_refills_over_time() {
        let rl = RateLimiter::new(100, 1);
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(rl.try_take(ip));
        assert!(!rl.try_take(ip), "burst=1 empties immediately");
        thread::sleep(Duration::from_millis(50));
        assert!(
            rl.try_take(ip),
            "after 50ms at 100/s there should be tokens"
        );
    }

    #[test]
    fn rate_limiter_isolates_ips() {
        let rl = RateLimiter::new(1, 1);
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11));
        assert!(rl.try_take(a));
        assert!(!rl.try_take(a));
        // Different IP has its own bucket
        assert!(rl.try_take(b));
    }

    #[test]
    fn unbounded_when_cap_zero() {
        // max_tracked=0 means unbounded (legacy behavior)
        let rl = RateLimiter::with_limits(10, 100, 0, 300);
        for i in 0..1000 {
            let ip = IpAddr::V4(Ipv4Addr::new(
                10,
                0,
                u8::try_from(i / 256).unwrap(),
                u8::try_from(i % 256).unwrap(),
            ));
            assert!(rl.try_take(ip), "should never be refused at cap=0");
        }
        let (tracked, _, _, refused) = rl.stats();
        assert_eq!(tracked, 1000, "should track all 1000 IPs");
        assert_eq!(refused, 0, "should never refuse when unbounded");
    }

    #[test]
    fn evicts_full_bucket_when_at_cap() {
        // Fill to cap with non-empty buckets, then insert new IP
        // Should evict the one with most tokens (least throttled)
        let rl = RateLimiter::with_limits(10, 2, 3, 300);

        // Create 3 buckets with different token levels
        // A: takes 1 token immediately (1 token left)
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(rl.try_take(a));

        // B: takes 2 tokens immediately, empty (0 tokens left)
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(rl.try_take(b));
        assert!(rl.try_take(b));

        // C: takes 1 token immediately (1 token left)
        let c = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        assert!(rl.try_take(c));

        let (tracked, _, _, refused_before) = rl.stats();
        assert_eq!(tracked, 3);
        assert_eq!(refused_before, 0);

        // Now insert a 4th IP while at cap:
        // B has 0 tokens, A and C have 1 each
        // We should evict one of them (doesn't matter which since all have at least 1 token)
        let new_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99));
        assert!(
            rl.try_take(new_ip),
            "should succeed by evicting one of the full/partial buckets"
        );

        let (tracked, _, lru_evictions, refused_after) = rl.stats();
        assert_eq!(tracked, 3, "should stay at cap");
        assert_eq!(lru_evictions, 1, "should have 1 LRU eviction");
        assert_eq!(refused_after, 0, "should not refuse");
    }

    #[test]
    fn refuses_new_ip_when_all_throttled_at_cap() {
        // Fill to cap with all throttled (empty) buckets, then refuse new IP
        let rl = RateLimiter::with_limits(10, 1, 2, 300);

        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        // Drain both buckets (1 token each, burst=1)
        assert!(rl.try_take(a), "a drains");
        assert!(rl.try_take(b), "b drains");

        // Both are now empty (throttled); can't refill yet (no time passed)
        assert!(!rl.try_take(a), "a throttled");
        assert!(!rl.try_take(b), "b throttled");

        // Now try to insert a 3rd IP; should be refused (cap=2, all throttled)
        let c = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        assert!(
            !rl.try_take(c),
            "new IP should be refused when all throttled at cap"
        );

        let (tracked, _, _, refused) = rl.stats();
        assert_eq!(tracked, 2, "should still be at cap");
        assert_eq!(refused, 1, "should have 1 cap_refused");
    }

    #[test]
    fn evicts_idle_buckets_past_ttl() {
        // Create limiter, insert IP, then wait past TTL and insert another
        let rl = RateLimiter::with_limits(1, 1, 100, 1); // TTL = 1 second

        let old_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let new_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        assert!(rl.try_take(old_ip), "insert old_ip");
        let (tracked, _, _, _) = rl.stats();
        assert_eq!(tracked, 1);

        // Sleep past the TTL
        thread::sleep(Duration::from_millis(1100));

        // Insert new IP; should trigger idle eviction of old_ip
        assert!(rl.try_take(new_ip), "insert new_ip");

        let (tracked, idle_evictions, _, _) = rl.stats();
        assert_eq!(tracked, 1, "old_ip should be evicted");
        assert_eq!(idle_evictions, 1, "should have 1 idle eviction");
    }

    #[test]
    fn lru_keeps_recently_touched() {
        // Fill to cap with non-empty buckets, touch A recently, then insert E:
        // should evict B (oldest last_touch), not A (most recent)
        let rl = RateLimiter::with_limits(100, 2, 4, 300);

        let newest_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let oldest_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let middle_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let other_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
        let inserted_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));

        // Create B, C, D with 1 token each
        assert!(rl.try_take(oldest_ip));
        thread::sleep(Duration::from_millis(1));
        assert!(rl.try_take(middle_ip));
        thread::sleep(Duration::from_millis(1));
        assert!(rl.try_take(other_ip));
        thread::sleep(Duration::from_millis(1));

        // Create A much later (most recently touched)
        assert!(rl.try_take(newest_ip));

        // Now A has most tokens (it hasn't been touched before), but B is oldest
        // When we insert E, eviction should prefer: most tokens first, then oldest LRU
        // All have 1 token, so evict oldest: B
        assert!(rl.try_take(inserted_ip), "E should be inserted");

        let inner = rl.inner.lock().unwrap();
        let has_a = inner.buckets.contains_key(&newest_ip);
        let has_b = inner.buckets.contains_key(&oldest_ip);
        let has_e = inner.buckets.contains_key(&inserted_ip);
        drop(inner);
        assert!(has_a, "A should be kept (most recently touched)");
        assert!(
            !has_b,
            "B should be evicted (oldest last_touch among same token count)"
        );
        assert!(has_e, "E should be inserted");
    }
}
