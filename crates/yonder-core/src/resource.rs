use crate::{RateLimit, RetryAfter};
use std::num::NonZeroU32;
use std::time::Duration;
use thiserror::Error;

/// Relay resource fields reported by validation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayResourceField {
    RegistrationCapacity,
    SourceRegistrationCapacity,
    ResolveConcurrency,
    ResolveRate,
    ResolveBurst,
    SourceLimiterCapacity,
    SourceLimiterIdleSeconds,
    ReservationDurationSeconds,
    CircuitCapacity,
    CircuitDurationSeconds,
    CircuitBytes,
}

/// Failures returned while constructing a relay resource policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RelayResourceError {
    #[error("relay resource field {field:?} must be between {minimum} and {maximum}")]
    OutOfRange {
        field: RelayResourceField,
        minimum: u64,
        maximum: u64,
    },
    #[error("source registration capacity cannot exceed registration capacity")]
    SourceRegistrationExceedsTotal,
    #[error("source resolve rate and burst cannot exceed their global limits")]
    SourceResolveExceedsGlobal,
    #[error("source limiter capacity is smaller than the bounded global admission window")]
    SourceLimiterCapacityTooSmall,
    #[error("the bounded global admission window overflowed")]
    SourceLimiterWindowOverflow,
}

macro_rules! capacity_type {
    ($name:ident, $field:ident, $maximum:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(usize);

        impl $name {
            pub const MIN: usize = 1;
            pub const MAX: usize = $maximum;

            pub const fn new(value: usize) -> Result<Self, RelayResourceError> {
                if value >= Self::MIN && value <= Self::MAX {
                    Ok(Self(value))
                } else {
                    Err(RelayResourceError::OutOfRange {
                        field: RelayResourceField::$field,
                        minimum: Self::MIN as u64,
                        maximum: Self::MAX as u64,
                    })
                }
            }

            #[must_use]
            pub const fn get(self) -> usize {
                self.0
            }
        }
    };
}

capacity_type!(RegistrationCapacity, RegistrationCapacity, 320);
capacity_type!(SourceRegistrationCapacity, SourceRegistrationCapacity, 320);
capacity_type!(ResolveConcurrency, ResolveConcurrency, 320);
capacity_type!(SourceLimiterCapacity, SourceLimiterCapacity, 65_536);
capacity_type!(CircuitCapacity, CircuitCapacity, 320);

macro_rules! seconds_type {
    ($name:ident, $field:ident, $minimum:expr, $maximum:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        impl $name {
            pub const MIN_SECONDS: u64 = $minimum;
            pub const MAX_SECONDS: u64 = $maximum;

            pub const fn from_seconds(seconds: u64) -> Result<Self, RelayResourceError> {
                if seconds >= Self::MIN_SECONDS && seconds <= Self::MAX_SECONDS {
                    Ok(Self(seconds))
                } else {
                    Err(RelayResourceError::OutOfRange {
                        field: RelayResourceField::$field,
                        minimum: Self::MIN_SECONDS,
                        maximum: Self::MAX_SECONDS,
                    })
                }
            }

            #[must_use]
            pub const fn seconds(self) -> u64 {
                self.0
            }

            #[must_use]
            pub const fn duration(self) -> Duration {
                Duration::from_secs(self.0)
            }
        }
    };
}

seconds_type!(SourceLimiterIdle, SourceLimiterIdleSeconds, 1, 86_400);
seconds_type!(ReservationDuration, ReservationDurationSeconds, 60, 86_400);
seconds_type!(CircuitDuration, CircuitDurationSeconds, 60, 604_800);

/// A bounded GCRA rate used by relay resolve admission control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolveRate {
    per_second: NonZeroU32,
    burst: NonZeroU32,
}

impl ResolveRate {
    pub const MAX_PER_SECOND: u32 = 10_000;
    pub const MAX_BURST: u32 = 65_536;

    pub const fn new(per_second: u32, burst: u32) -> Result<Self, RelayResourceError> {
        let Some(per_second) = NonZeroU32::new(per_second) else {
            return Err(rate_range_error());
        };
        if per_second.get() > Self::MAX_PER_SECOND {
            return Err(rate_range_error());
        }
        let Some(burst) = NonZeroU32::new(burst) else {
            return Err(burst_range_error());
        };
        if burst.get() > Self::MAX_BURST {
            return Err(burst_range_error());
        }
        Ok(Self { per_second, burst })
    }

    #[must_use]
    pub const fn per_second(self) -> NonZeroU32 {
        self.per_second
    }

    #[must_use]
    pub const fn burst(self) -> NonZeroU32 {
        self.burst
    }

    #[must_use]
    pub const fn rate_limit(self) -> RateLimit {
        RateLimit::new(self.per_second, self.burst)
    }
}

const fn rate_range_error() -> RelayResourceError {
    RelayResourceError::OutOfRange {
        field: RelayResourceField::ResolveRate,
        minimum: 1,
        maximum: ResolveRate::MAX_PER_SECOND as u64,
    }
}

const fn burst_range_error() -> RelayResourceError {
    RelayResourceError::OutOfRange {
        field: RelayResourceField::ResolveBurst,
        minimum: 1,
        maximum: ResolveRate::MAX_BURST as u64,
    }
}

/// A bounded per-circuit byte budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CircuitBytes(u64);

impl CircuitBytes {
    pub const MIN: u64 = 1024 * 1024;
    pub const MAX: u64 = 1024 * 1024 * 1024 * 1024;

    pub const fn new(bytes: u64) -> Result<Self, RelayResourceError> {
        if bytes >= Self::MIN && bytes <= Self::MAX {
            Ok(Self(bytes))
        } else {
            Err(RelayResourceError::OutOfRange {
                field: RelayResourceField::CircuitBytes,
                minimum: Self::MIN,
                maximum: Self::MAX,
            })
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Registration-table and reservation limits sharing one authoritative capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistrationLimits {
    capacity: RegistrationCapacity,
    per_source: SourceRegistrationCapacity,
    reservation_duration: ReservationDuration,
}

impl RegistrationLimits {
    pub const fn new(
        capacity: RegistrationCapacity,
        per_source: SourceRegistrationCapacity,
        reservation_duration: ReservationDuration,
    ) -> Result<Self, RelayResourceError> {
        if per_source.get() > capacity.get() {
            return Err(RelayResourceError::SourceRegistrationExceedsTotal);
        }
        Ok(Self {
            capacity,
            per_source,
            reservation_duration,
        })
    }

    #[must_use]
    pub const fn capacity(self) -> RegistrationCapacity {
        self.capacity
    }

    #[must_use]
    pub const fn per_source(self) -> SourceRegistrationCapacity {
        self.per_source
    }

    #[must_use]
    pub const fn reservation_duration(self) -> ReservationDuration {
        self.reservation_duration
    }
}

/// Resolve concurrency, rates and bounded source-state policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolveLimits {
    concurrency: ResolveConcurrency,
    global: ResolveRate,
    source: ResolveRate,
    source_limiter_capacity: SourceLimiterCapacity,
    source_limiter_idle: SourceLimiterIdle,
    retry_after: RetryAfter,
}

impl ResolveLimits {
    pub const fn new(
        concurrency: ResolveConcurrency,
        global: ResolveRate,
        source: ResolveRate,
        source_limiter_capacity: SourceLimiterCapacity,
        source_limiter_idle: SourceLimiterIdle,
        retry_after: RetryAfter,
    ) -> Result<Self, RelayResourceError> {
        if source.per_second().get() > global.per_second().get()
            || source.burst().get() > global.burst().get()
        {
            return Err(RelayResourceError::SourceResolveExceedsGlobal);
        }
        let Some(sustained) =
            (global.per_second().get() as u64).checked_mul(source_limiter_idle.seconds())
        else {
            return Err(RelayResourceError::SourceLimiterWindowOverflow);
        };
        let Some(required) = sustained.checked_add(global.burst().get() as u64) else {
            return Err(RelayResourceError::SourceLimiterWindowOverflow);
        };
        if required > source_limiter_capacity.get() as u64 {
            return Err(RelayResourceError::SourceLimiterCapacityTooSmall);
        }
        Ok(Self {
            concurrency,
            global,
            source,
            source_limiter_capacity,
            source_limiter_idle,
            retry_after,
        })
    }

    #[must_use]
    pub const fn concurrency(self) -> ResolveConcurrency {
        self.concurrency
    }

    #[must_use]
    pub const fn global(self) -> ResolveRate {
        self.global
    }

    #[must_use]
    pub const fn source(self) -> ResolveRate {
        self.source
    }

    #[must_use]
    pub const fn source_limiter_capacity(self) -> SourceLimiterCapacity {
        self.source_limiter_capacity
    }

    #[must_use]
    pub const fn source_limiter_idle(self) -> SourceLimiterIdle {
        self.source_limiter_idle
    }

    #[must_use]
    pub const fn retry_after(self) -> RetryAfter {
        self.retry_after
    }
}

/// Circuit Relay v2 circuit budgets. Per-peer limits remain fixed at one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircuitRelayLimits {
    capacity: CircuitCapacity,
    duration: CircuitDuration,
    bytes: CircuitBytes,
}

impl CircuitRelayLimits {
    #[must_use]
    pub const fn new(
        capacity: CircuitCapacity,
        duration: CircuitDuration,
        bytes: CircuitBytes,
    ) -> Self {
        Self {
            capacity,
            duration,
            bytes,
        }
    }

    #[must_use]
    pub const fn capacity(self) -> CircuitCapacity {
        self.capacity
    }

    #[must_use]
    pub const fn duration(self) -> CircuitDuration {
        self.duration
    }

    #[must_use]
    pub const fn bytes(self) -> CircuitBytes {
        self.bytes
    }
}

/// Complete, validated relay resource configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayResourceConfig {
    registration: RegistrationLimits,
    resolve: ResolveLimits,
    circuit: CircuitRelayLimits,
}

impl RelayResourceConfig {
    #[must_use]
    pub const fn new(
        registration: RegistrationLimits,
        resolve: ResolveLimits,
        circuit: CircuitRelayLimits,
    ) -> Self {
        Self {
            registration,
            resolve,
            circuit,
        }
    }

    #[must_use]
    pub const fn registration(self) -> RegistrationLimits {
        self.registration
    }

    #[must_use]
    pub const fn resolve(self) -> ResolveLimits {
        self.resolve
    }

    #[must_use]
    pub const fn circuit(self) -> CircuitRelayLimits {
        self.circuit
    }
}

impl Default for RelayResourceConfig {
    fn default() -> Self {
        let registration = RegistrationLimits {
            capacity: RegistrationCapacity(128),
            per_source: SourceRegistrationCapacity(32),
            reservation_duration: ReservationDuration(60 * 60),
        };
        let resolve = ResolveLimits {
            concurrency: ResolveConcurrency(64),
            global: ResolveRate {
                per_second: NonZeroU32::new(4).expect("default resolve rate is nonzero"),
                burst: NonZeroU32::new(128).expect("default resolve burst is nonzero"),
            },
            source: ResolveRate {
                per_second: NonZeroU32::new(1).expect("default source rate is nonzero"),
                burst: NonZeroU32::new(32).expect("default source burst is nonzero"),
            },
            source_limiter_capacity: SourceLimiterCapacity(4_096),
            source_limiter_idle: SourceLimiterIdle(10 * 60),
            retry_after: RetryAfter::from_millis(250).expect("default retry delay is valid"),
        };
        let circuit = CircuitRelayLimits {
            capacity: CircuitCapacity(128),
            duration: CircuitDuration(24 * 60 * 60),
            bytes: CircuitBytes(8 * 1024 * 1024 * 1024),
        };
        Self::new(registration, resolve, circuit)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        CircuitBytes, CircuitCapacity, CircuitDuration, CircuitRelayLimits, RegistrationCapacity,
        RegistrationLimits, RelayResourceConfig, RelayResourceError, RelayResourceField,
        ReservationDuration, ResolveConcurrency, ResolveLimits, ResolveRate, SourceLimiterCapacity,
        SourceLimiterIdle, SourceRegistrationCapacity,
    };
    use crate::RetryAfter;
    use proptest::prelude::*;
    use std::num::NonZeroU32;

    #[test]
    fn defaults_match_the_approved_resource_policy() {
        let config = RelayResourceConfig::default();
        assert_eq!(config.registration().capacity().get(), 128);
        assert_eq!(config.registration().per_source().get(), 32);
        assert_eq!(
            config.registration().reservation_duration().seconds(),
            3_600
        );
        assert_eq!(config.resolve().concurrency().get(), 64);
        assert_eq!(config.resolve().global().per_second().get(), 4);
        assert_eq!(config.resolve().global().burst().get(), 128);
        assert_eq!(config.resolve().source().per_second().get(), 1);
        assert_eq!(config.resolve().source().burst().get(), 32);
        assert_eq!(config.resolve().source_limiter_capacity().get(), 4_096);
        assert_eq!(config.resolve().source_limiter_idle().seconds(), 600);
        assert_eq!(config.resolve().retry_after().millis(), 250);
        assert_eq!(config.circuit().capacity().get(), 128);
        assert_eq!(config.circuit().duration().seconds(), 86_400);
        assert_eq!(config.circuit().bytes().get(), 8 * 1024 * 1024 * 1024);
    }

    #[test]
    fn every_scalar_bound_is_enforced() {
        assert_range(
            RegistrationCapacity::new(0),
            RelayResourceField::RegistrationCapacity,
        );
        assert_range(
            RegistrationCapacity::new(321),
            RelayResourceField::RegistrationCapacity,
        );
        assert_range(
            SourceRegistrationCapacity::new(0),
            RelayResourceField::SourceRegistrationCapacity,
        );
        assert_range(
            ResolveConcurrency::new(321),
            RelayResourceField::ResolveConcurrency,
        );
        assert_range(
            SourceLimiterCapacity::new(65_537),
            RelayResourceField::SourceLimiterCapacity,
        );
        assert_range(CircuitCapacity::new(0), RelayResourceField::CircuitCapacity);
        assert_range(
            SourceLimiterIdle::from_seconds(0),
            RelayResourceField::SourceLimiterIdleSeconds,
        );
        assert_range(
            ReservationDuration::from_seconds(59),
            RelayResourceField::ReservationDurationSeconds,
        );
        assert_range(
            CircuitDuration::from_seconds(604_801),
            RelayResourceField::CircuitDurationSeconds,
        );
        assert_range(ResolveRate::new(0, 1), RelayResourceField::ResolveRate);
        assert_range(ResolveRate::new(10_001, 1), RelayResourceField::ResolveRate);
        assert_range(ResolveRate::new(1, 0), RelayResourceField::ResolveBurst);
        assert_range(
            ResolveRate::new(1, 65_537),
            RelayResourceField::ResolveBurst,
        );
        assert_range(
            CircuitBytes::new(CircuitBytes::MIN - 1),
            RelayResourceField::CircuitBytes,
        );
        assert_range(
            CircuitBytes::new(CircuitBytes::MAX + 1),
            RelayResourceField::CircuitBytes,
        );

        assert_eq!(RegistrationCapacity::new(1).unwrap().get(), 1);
        assert_eq!(RegistrationCapacity::new(320).unwrap().get(), 320);
        assert_eq!(
            SourceLimiterIdle::from_seconds(1)
                .unwrap()
                .duration()
                .as_secs(),
            1
        );
        assert_eq!(
            CircuitBytes::new(CircuitBytes::MAX).unwrap().get(),
            CircuitBytes::MAX
        );
    }

    #[test]
    fn combination_rules_reject_inconsistent_policies() {
        assert_eq!(
            RegistrationLimits::new(
                RegistrationCapacity::new(1).unwrap(),
                SourceRegistrationCapacity::new(2).unwrap(),
                ReservationDuration::from_seconds(60).unwrap(),
            ),
            Err(RelayResourceError::SourceRegistrationExceedsTotal)
        );
        assert_eq!(
            resolve_limits(
                ResolveRate::new(1, 1).unwrap(),
                ResolveRate::new(2, 1).unwrap(),
                2,
                1,
            ),
            Err(RelayResourceError::SourceResolveExceedsGlobal)
        );
        assert_eq!(
            resolve_limits(
                ResolveRate::new(2, 1).unwrap(),
                ResolveRate::new(1, 2).unwrap(),
                3,
                1,
            ),
            Err(RelayResourceError::SourceResolveExceedsGlobal)
        );
        assert_eq!(
            resolve_limits(
                ResolveRate::new(1, 2).unwrap(),
                ResolveRate::new(1, 2).unwrap(),
                2,
                1,
            ),
            Err(RelayResourceError::SourceLimiterCapacityTooSmall)
        );

        let enormous_rate = ResolveRate {
            per_second: NonZeroU32::MAX,
            burst: NonZeroU32::MIN,
        };
        let enormous_idle = SourceLimiterIdle(u64::MAX);
        assert_eq!(
            ResolveLimits::new(
                ResolveConcurrency::new(1).unwrap(),
                enormous_rate,
                ResolveRate::new(1, 1).unwrap(),
                SourceLimiterCapacity::new(1).unwrap(),
                enormous_idle,
                RetryAfter::from_millis(100).unwrap(),
            ),
            Err(RelayResourceError::SourceLimiterWindowOverflow)
        );
        let additive_overflow_rate = ResolveRate {
            per_second: NonZeroU32::MIN,
            burst: NonZeroU32::MIN,
        };
        assert_eq!(
            ResolveLimits::new(
                ResolveConcurrency::new(1).unwrap(),
                additive_overflow_rate,
                ResolveRate::new(1, 1).unwrap(),
                SourceLimiterCapacity::new(1).unwrap(),
                enormous_idle,
                RetryAfter::from_millis(100).unwrap(),
            ),
            Err(RelayResourceError::SourceLimiterWindowOverflow)
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn valid_registration_combinations_round_trip(total in 1_usize..=320, source in 1_usize..=320) {
            let result = RegistrationLimits::new(
                RegistrationCapacity::new(total).unwrap(),
                SourceRegistrationCapacity::new(source).unwrap(),
                ReservationDuration::from_seconds(60).unwrap(),
            );
            prop_assert_eq!(result.is_ok(), source <= total);
        }

        #[test]
        fn source_window_formula_is_applied(rate in 1_u32..=64, burst in 1_u32..=256, idle in 1_u64..=60) {
            let required = u64::from(rate) * idle + u64::from(burst);
            let capacity = usize::try_from(required.min(65_536)).unwrap();
            let result = resolve_limits(
                ResolveRate::new(rate, burst).unwrap(),
                ResolveRate::new(1, 1).unwrap(),
                capacity,
                idle,
            );
            prop_assert_eq!(result.is_ok(), required <= 65_536);
        }
    }

    fn resolve_limits(
        global: ResolveRate,
        source: ResolveRate,
        capacity: usize,
        idle: u64,
    ) -> Result<ResolveLimits, RelayResourceError> {
        ResolveLimits::new(
            ResolveConcurrency::new(1).unwrap(),
            global,
            source,
            SourceLimiterCapacity::new(capacity).unwrap(),
            SourceLimiterIdle::from_seconds(idle).unwrap(),
            RetryAfter::from_millis(100).unwrap(),
        )
    }

    fn assert_range<T>(result: Result<T, RelayResourceError>, expected_field: RelayResourceField) {
        assert!(matches!(
            result,
            Err(RelayResourceError::OutOfRange { field, .. }) if field == expected_field
        ));
    }

    #[test]
    fn circuit_group_preserves_validated_values() {
        let limits = CircuitRelayLimits::new(
            CircuitCapacity::new(1).unwrap(),
            CircuitDuration::from_seconds(60).unwrap(),
            CircuitBytes::new(CircuitBytes::MIN).unwrap(),
        );
        assert_eq!(limits.capacity().get(), 1);
        assert_eq!(limits.duration().seconds(), 60);
        assert_eq!(limits.bytes().get(), CircuitBytes::MIN);
    }
}
