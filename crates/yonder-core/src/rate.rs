use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use std::num::NonZeroU32;

/// A validated GCRA rate and burst configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    per_second: NonZeroU32,
    burst: NonZeroU32,
}

impl RateLimit {
    /// Creates a rate whose values cannot be zero.
    #[must_use]
    pub const fn new(per_second: NonZeroU32, burst: NonZeroU32) -> Self {
        Self { per_second, burst }
    }

    /// The target authentication-start limit: 1/s with a burst of 4.
    #[must_use]
    pub const fn authentication() -> Self {
        Self::new(nonzero(1), nonzero(4))
    }

    #[must_use]
    pub const fn per_second(self) -> NonZeroU32 {
        self.per_second
    }

    #[must_use]
    pub const fn burst(self) -> NonZeroU32 {
        self.burst
    }

    fn quota(self) -> Quota {
        Quota::per_second(self.per_second).allow_burst(self.burst)
    }
}

const fn nonzero(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).expect("frozen rate limits are nonzero")
}

/// A direct, non-waiting governor limiter owned by one actor.
#[derive(Debug)]
pub struct DirectRateLimiter {
    inner: DefaultDirectRateLimiter,
}

impl DirectRateLimiter {
    #[must_use]
    pub fn new(limit: RateLimit) -> Self {
        Self {
            inner: RateLimiter::direct(limit.quota()),
        }
    }

    /// Consumes one cell if the request is currently permitted.
    #[must_use]
    pub fn check(&self) -> bool {
        self.inner.check().is_ok()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{DirectRateLimiter, RateLimit};
    use governor::RateLimiter;
    use governor::clock::FakeRelativeClock;
    use std::time::Duration;

    #[test]
    fn frozen_authentication_limit_has_exact_values() {
        let authentication = RateLimit::authentication();
        assert_eq!(authentication.per_second().get(), 1);
        assert_eq!(authentication.burst().get(), 4);
    }

    #[test]
    fn direct_limiter_never_waits_and_enforces_its_burst() {
        let limit = RateLimit::authentication();
        let limiter = DirectRateLimiter::new(limit);
        for _ in 0..limit.burst().get() {
            assert!(limiter.check());
        }
        assert!(!limiter.check());
    }

    #[test]
    fn governor_enforces_burst_and_recovery_with_a_fake_clock() {
        let clock = FakeRelativeClock::default();
        let limiter =
            RateLimiter::direct_with_clock(RateLimit::authentication().quota(), clock.clone());
        for _ in 0..4 {
            assert!(limiter.check().is_ok());
        }
        assert!(limiter.check().is_err());
        clock.advance(Duration::from_secs(1));
        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_err());
    }
}
