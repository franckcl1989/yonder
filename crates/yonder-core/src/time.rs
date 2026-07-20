use std::time::{Duration, Instant};

/// A process-local monotonic timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonotonicTime(Duration);

impl MonotonicTime {
    /// Creates a timestamp from elapsed process-local time.
    #[must_use]
    pub const fn from_elapsed(elapsed: Duration) -> Self {
        Self(elapsed)
    }

    /// Returns the underlying elapsed duration.
    #[must_use]
    pub const fn elapsed(self) -> Duration {
        self.0
    }

    /// Adds a duration, returning `None` on overflow.
    #[must_use]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        self.0.checked_add(duration).map(Self)
    }

    /// Returns the duration since an earlier timestamp.
    #[must_use]
    pub fn duration_since(self, earlier: Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0)
    }
}

/// A replaceable source of monotonic process-local time.
pub trait MonotonicClock {
    /// Reads the current monotonic timestamp.
    fn now(&self) -> MonotonicTime;
}

/// Production monotonic clock backed by [`Instant`].
#[derive(Debug, Clone)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// Creates a clock whose epoch is the current instant.
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

impl MonotonicClock for SystemClock {
    fn now(&self) -> MonotonicTime {
        MonotonicTime(self.origin.elapsed())
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{MonotonicClock, MonotonicTime, SystemClock};
    use std::time::Duration;

    #[test]
    fn arithmetic_is_checked() {
        let start = MonotonicTime::from_elapsed(Duration::from_secs(2));
        let end = start.checked_add(Duration::from_secs(3)).unwrap();
        assert_eq!(end.elapsed(), Duration::from_secs(5));
        assert_eq!(end.duration_since(start), Some(Duration::from_secs(3)));
        assert_eq!(start.duration_since(end), None);
        assert_eq!(
            MonotonicTime::from_elapsed(Duration::MAX).checked_add(Duration::from_nanos(1)),
            None
        );
    }

    #[test]
    fn system_clock_is_monotonic() {
        let clock = SystemClock::default();
        let first = clock.now();
        let second = clock.now();
        assert!(second >= first);
    }
}
