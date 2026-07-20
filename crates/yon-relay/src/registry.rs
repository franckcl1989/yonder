use std::collections::{HashMap, HashSet};
use std::time::Duration;
use thiserror::Error;
use yonder_core::wire::registry::RegistryResponse;
use yonder_core::wire::resolve::ResolveResponse;
use yonder_core::{
    DirectRateLimiter, Locator, MonotonicClock, MonotonicTime, PeerIdBytes, RandomError,
    RegistrationCapacity, RegistrationLimits, RelayResourceConfig, ResolveLimits, RetryAfter,
    SecureRandom,
};
use yonder_net::{PeerId, SourcePrefix};

const SUSPEND_GRACE: Duration = Duration::from_secs(120);

/// Registry operations that cannot be represented as a peer response.
#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("secure locator allocation failed")]
    Random(#[source] RandomError),
    #[error("a libp2p PeerId exceeded the frozen wire bound")]
    PeerIdTooLong,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MappingState {
    Active,
    Suspended { since: MonotonicTime },
}

#[derive(Debug, Clone, Copy)]
struct Mapping {
    owner: PeerId,
    source: SourcePrefix,
    state: MappingState,
}

/// Single-owner, process-local rendezvous registry.
#[derive(Debug)]
pub struct Registry<C> {
    clock: C,
    limits: RegistrationLimits,
    retry_after: RetryAfter,
    by_locator: HashMap<Locator, Mapping>,
    by_owner: HashMap<PeerId, Locator>,
    by_source: HashMap<SourcePrefix, usize>,
    reservations: HashSet<PeerId>,
    connections: HashSet<PeerId>,
}

impl<C: MonotonicClock> Registry<C> {
    #[must_use]
    pub fn new(clock: C) -> Self {
        let resources = RelayResourceConfig::default();
        Self::with_limits(
            clock,
            resources.registration(),
            resources.resolve().retry_after(),
        )
    }

    /// Constructs a registry with validated capacities and retry semantics.
    #[must_use]
    pub fn with_limits(clock: C, limits: RegistrationLimits, retry_after: RetryAfter) -> Self {
        let capacity = limits.capacity().get();
        Self {
            clock,
            limits,
            retry_after,
            by_locator: HashMap::with_capacity(capacity),
            by_owner: HashMap::with_capacity(capacity),
            by_source: HashMap::with_capacity(capacity),
            reservations: HashSet::with_capacity(capacity),
            connections: HashSet::with_capacity(capacity),
        }
    }

    /// Updates the relay reservation half of the Active invariant.
    pub fn set_reservation(&mut self, peer: PeerId, available: bool) {
        set_membership(&mut self.reservations, peer, available);
        self.refresh(peer);
    }

    /// Updates the physical relay connection half of the Active invariant.
    pub fn set_connection(&mut self, peer: PeerId, available: bool) {
        set_membership(&mut self.connections, peer, available);
        self.refresh(peer);
    }

    /// Allocates or idempotently returns this peer's locator.
    pub fn allocate(
        &mut self,
        owner: PeerId,
        source: SourcePrefix,
        random: &mut impl SecureRandom,
    ) -> Result<RegistryResponse, RegistryError> {
        self.prune();
        if !self.is_available(&owner) {
            return Ok(RegistryResponse::ReservationRequired);
        }
        if let Some(locator) = self.by_owner.get(&owner).copied() {
            return Ok(RegistryResponse::Acquired(locator));
        }
        if !self.has_capacity(source) {
            return Ok(RegistryResponse::Capacity);
        }
        let mut candidate = Locator::random(random).map_err(RegistryError::Random)?;
        loop {
            if !self.by_locator.contains_key(&candidate) {
                self.insert(candidate, owner, source);
                return Ok(RegistryResponse::Acquired(candidate));
            }
            candidate = candidate.wrapping_next();
        }
    }

    /// Reclaims the same locator after a short relay reconnect.
    pub fn reclaim(
        &mut self,
        owner: PeerId,
        source: SourcePrefix,
        locator: Locator,
    ) -> RegistryResponse {
        self.prune();
        if !self.is_available(&owner) {
            return RegistryResponse::ReservationRequired;
        }
        if let Some(existing) = self.by_owner.get(&owner).copied() {
            return if existing == locator {
                RegistryResponse::Acquired(locator)
            } else {
                RegistryResponse::Conflict
            };
        }
        if self.by_locator.contains_key(&locator) {
            return RegistryResponse::Conflict;
        }
        if !self.has_capacity(source) {
            return RegistryResponse::Capacity;
        }
        self.insert(locator, owner, source);
        RegistryResponse::Acquired(locator)
    }

    /// Idempotently releases only the caller's matching mapping.
    pub fn release(&mut self, owner: PeerId, locator: Locator) -> RegistryResponse {
        self.prune();
        if self.by_owner.get(&owner) == Some(&locator) {
            self.remove(locator);
        }
        RegistryResponse::Released
    }

    /// Resolves only currently Active mappings without mutating them.
    pub fn resolve(&mut self, locator: Locator) -> Result<ResolveResponse, RegistryError> {
        self.prune();
        let Some(mapping) = self.by_locator.get(&locator) else {
            return Ok(ResolveResponse::Unavailable);
        };
        match mapping.state {
            MappingState::Active => {
                let peer = bounded_peer_id(&mapping.owner.to_bytes())?;
                Ok(ResolveResponse::Resolved(peer))
            }
            MappingState::Suspended { .. } => Ok(ResolveResponse::Retry(self.retry_after)),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_locator.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_locator.is_empty()
    }

    #[must_use]
    pub const fn retry_after(&self) -> RetryAfter {
        self.retry_after
    }

    fn insert(&mut self, locator: Locator, owner: PeerId, source: SourcePrefix) {
        let mapping = Mapping {
            owner,
            source,
            state: MappingState::Active,
        };
        self.by_locator.insert(locator, mapping);
        self.by_owner.insert(owner, locator);
        *self.by_source.entry(source).or_insert(0) += 1;
    }

    fn remove(&mut self, locator: Locator) {
        let Some(mapping) = self.by_locator.remove(&locator) else {
            return;
        };
        self.by_owner.remove(&mapping.owner);
        let Some(count) = self.by_source.get_mut(&mapping.source) else {
            return;
        };
        *count -= 1;
        if *count == 0 {
            self.by_source.remove(&mapping.source);
        }
    }

    fn refresh(&mut self, peer: PeerId) {
        self.prune();
        let Some(locator) = self.by_owner.get(&peer).copied() else {
            return;
        };
        let available = self.is_available(&peer);
        let now = self.clock.now();
        let mapping = self
            .by_locator
            .get_mut(&locator)
            .expect("owner and locator indexes are updated atomically");
        mapping.state = match (available, mapping.state) {
            (true, _) => MappingState::Active,
            (false, MappingState::Active) => MappingState::Suspended { since: now },
            (false, suspended @ MappingState::Suspended { .. }) => suspended,
        };
    }

    fn is_available(&self, peer: &PeerId) -> bool {
        self.reservations.contains(peer) && self.connections.contains(peer)
    }

    fn has_capacity(&self, source: SourcePrefix) -> bool {
        self.by_locator.len() < self.limits.capacity().get()
            && self.by_source.get(&source).copied().unwrap_or(0) < self.limits.per_source().get()
    }

    fn prune(&mut self) {
        let now = self.clock.now();
        let mut expired = [None; RegistrationCapacity::MAX];
        let mut len = 0;
        for (locator, mapping) in &self.by_locator {
            let MappingState::Suspended { since } = mapping.state else {
                continue;
            };
            if now
                .duration_since(since)
                .is_some_and(|age| age >= SUSPEND_GRACE)
            {
                expired[len] = Some(*locator);
                len += 1;
            }
        }
        for locator in expired.into_iter().take(len).flatten() {
            self.remove(locator);
        }
    }
}

fn bounded_peer_id(source: &[u8]) -> Result<PeerIdBytes, RegistryError> {
    PeerIdBytes::new(source).map_err(|_| RegistryError::PeerIdTooLong)
}

fn set_membership(set: &mut HashSet<PeerId>, peer: PeerId, available: bool) {
    if available {
        set.insert(peer);
    } else {
        set.remove(&peer);
    }
}

#[derive(Debug)]
struct SourceLimiter {
    limiter: DirectRateLimiter,
    last_seen: MonotonicTime,
}

/// Global and per-source non-waiting resolve admission control.
#[derive(Debug)]
pub struct ResolveLimiters {
    global: DirectRateLimiter,
    sources: HashMap<SourcePrefix, SourceLimiter>,
    limits: ResolveLimits,
}

impl ResolveLimiters {
    #[must_use]
    pub fn new() -> Self {
        Self::with_limits(RelayResourceConfig::default().resolve())
    }

    /// Constructs resolve admission control from one validated policy.
    #[must_use]
    pub fn with_limits(limits: ResolveLimits) -> Self {
        Self {
            global: DirectRateLimiter::new(limits.global().rate_limit()),
            sources: HashMap::with_capacity(limits.source_limiter_capacity().get()),
            limits,
        }
    }

    /// Checks global first, then the bounded source-prefix table.
    pub fn check(&mut self, source: SourcePrefix, now: MonotonicTime) -> bool {
        if !self.check_global() {
            return false;
        }
        self.check_source(source, now)
    }

    pub(crate) fn check_global(&self) -> bool {
        self.global.check()
    }

    pub(crate) fn check_source(&mut self, source: SourcePrefix, now: MonotonicTime) -> bool {
        self.prune(now);
        if let Some(entry) = self.sources.get_mut(&source) {
            entry.last_seen = now;
            return entry.limiter.check();
        }
        if self.sources.len() == self.limits.source_limiter_capacity().get() {
            return false;
        }
        let limiter = DirectRateLimiter::new(self.limits.source().rate_limit());
        let allowed = limiter.check();
        self.sources.insert(
            source,
            SourceLimiter {
                limiter,
                last_seen: now,
            },
        );
        allowed
    }

    fn prune(&mut self, now: MonotonicTime) {
        let idle = self.limits.source_limiter_idle().duration();
        self.sources.retain(|_, entry| {
            now.duration_since(entry.last_seen)
                .is_none_or(|age| age < idle)
        });
    }

    #[must_use]
    pub const fn retry_after(&self) -> RetryAfter {
        self.limits.retry_after()
    }
}

impl Default for ResolveLimiters {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        Mapping, MappingState, Registry, RegistryError, RegistryResponse, ResolveLimiters,
        ResolveResponse, SourcePrefix, bounded_peer_id,
    };
    use std::cell::Cell;
    use std::net::Ipv4Addr;
    use std::time::Duration;
    use yonder_core::{
        Locator, MonotonicClock, MonotonicTime, RandomError, RegistrationCapacity,
        RegistrationLimits, ReservationDuration, ResolveConcurrency, ResolveLimits, ResolveRate,
        RetryAfter, SecureRandom, SourceLimiterCapacity, SourceLimiterIdle,
        SourceRegistrationCapacity,
    };
    use yonder_net::Keypair;

    #[derive(Debug, Default)]
    struct FakeClock(Cell<Duration>);

    impl FakeClock {
        fn advance(&self, duration: Duration) {
            self.0.set(self.0.get() + duration);
        }
    }

    impl MonotonicClock for FakeClock {
        fn now(&self) -> MonotonicTime {
            MonotonicTime::from_elapsed(self.0.get())
        }
    }

    struct ZeroRandom;

    impl SecureRandom for ZeroRandom {
        fn try_fill(&mut self, destination: &mut [u8]) -> Result<(), RandomError> {
            destination.fill(0);
            Ok(())
        }
    }

    struct FailingRandom;

    impl SecureRandom for FailingRandom {
        fn try_fill(&mut self, _destination: &mut [u8]) -> Result<(), RandomError> {
            Err(RandomError)
        }
    }

    #[test]
    fn mapping_requires_both_signals_and_survives_short_suspend() {
        let clock = FakeClock::default();
        let mut registry = Registry::new(clock);
        let peer = peer();
        let source = source();
        assert_eq!(
            registry.allocate(peer, source, &mut ZeroRandom).unwrap(),
            RegistryResponse::ReservationRequired
        );
        registry.set_connection(peer, true);
        registry.set_reservation(peer, true);
        let RegistryResponse::Acquired(locator) =
            registry.allocate(peer, source, &mut ZeroRandom).unwrap()
        else {
            panic!("expected locator");
        };
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.allocate(peer, source, &mut ZeroRandom).unwrap(),
            RegistryResponse::Acquired(locator)
        );
        assert_eq!(
            registry.reclaim(peer, source, locator),
            RegistryResponse::Acquired(locator)
        );
        assert_eq!(
            registry.reclaim(peer, source, Locator::new(9).unwrap()),
            RegistryResponse::Conflict
        );
        assert!(matches!(
            registry.resolve(locator).unwrap(),
            ResolveResponse::Resolved(_)
        ));

        registry.set_reservation(peer, false);
        assert!(matches!(
            registry.resolve(locator).unwrap(),
            ResolveResponse::Retry(_)
        ));
        registry.clock.advance(Duration::from_secs(119));
        registry.set_reservation(peer, true);
        assert!(matches!(
            registry.resolve(locator).unwrap(),
            ResolveResponse::Resolved(_)
        ));
    }

    #[test]
    fn suspend_expiry_removes_all_indexes_and_allows_reuse() {
        let mut registry = Registry::new(FakeClock::default());
        let first = peer();
        registry.set_connection(first, true);
        registry.set_reservation(first, true);
        let RegistryResponse::Acquired(locator) =
            registry.allocate(first, source(), &mut ZeroRandom).unwrap()
        else {
            panic!("expected locator");
        };
        registry.set_connection(first, false);
        registry.clock.advance(Duration::from_secs(120));
        registry.set_connection(first, true);
        assert_eq!(
            registry.resolve(locator).unwrap(),
            ResolveResponse::Unavailable
        );
        assert!(registry.is_empty());

        let second = peer();
        registry.set_connection(second, true);
        registry.set_reservation(second, true);
        assert_eq!(
            registry.reclaim(second, source(), locator),
            RegistryResponse::Acquired(locator)
        );
    }

    #[test]
    fn source_quota_and_ring_scan_are_bounded() {
        let mut registry = Registry::new(FakeClock::default());
        let source = source();
        for expected in 0..32 {
            let peer = peer();
            registry.set_connection(peer, true);
            registry.set_reservation(peer, true);
            assert_eq!(
                registry.allocate(peer, source, &mut ZeroRandom).unwrap(),
                RegistryResponse::Acquired(Locator::new(expected).unwrap())
            );
        }
        let blocked = peer();
        registry.set_connection(blocked, true);
        registry.set_reservation(blocked, true);
        assert_eq!(
            registry.allocate(blocked, source, &mut ZeroRandom).unwrap(),
            RegistryResponse::Capacity
        );
    }

    #[test]
    fn configured_registration_capacity_quota_and_retry_are_authoritative() {
        let limits = RegistrationLimits::new(
            RegistrationCapacity::new(2).unwrap(),
            SourceRegistrationCapacity::new(1).unwrap(),
            ReservationDuration::from_seconds(60).unwrap(),
        )
        .unwrap();
        let retry = RetryAfter::from_millis(100).unwrap();
        let mut registry = Registry::with_limits(FakeClock::default(), limits, retry);
        let shared_source = source();
        let first = peer();
        make_available(&mut registry, first);
        let RegistryResponse::Acquired(locator) = registry
            .allocate(first, shared_source, &mut ZeroRandom)
            .unwrap()
        else {
            panic!("first registration must fit");
        };
        let source_blocked = peer();
        make_available(&mut registry, source_blocked);
        assert_eq!(
            registry
                .allocate(source_blocked, shared_source, &mut ZeroRandom)
                .unwrap(),
            RegistryResponse::Capacity
        );
        let second = peer();
        make_available(&mut registry, second);
        assert!(matches!(
            registry
                .allocate(
                    second,
                    SourcePrefix::Ipv4("198.51.100.1".parse().unwrap()),
                    &mut ZeroRandom,
                )
                .unwrap(),
            RegistryResponse::Acquired(_)
        ));
        let total_blocked = peer();
        make_available(&mut registry, total_blocked);
        assert_eq!(
            registry
                .allocate(
                    total_blocked,
                    SourcePrefix::Ipv4("203.0.113.1".parse().unwrap()),
                    &mut ZeroRandom,
                )
                .unwrap(),
            RegistryResponse::Capacity
        );
        registry.set_connection(first, false);
        assert_eq!(
            registry.resolve(locator).unwrap(),
            ResolveResponse::Retry(retry)
        );
        assert_eq!(registry.retry_after(), retry);
    }

    #[test]
    fn reclaim_release_random_and_global_capacity_paths_are_explicit() {
        let mut registry = Registry::new(FakeClock::default());
        registry.remove(Locator::new(0).unwrap());
        let unavailable = peer();
        assert_eq!(
            registry.reclaim(unavailable, source(), Locator::new(7).unwrap()),
            RegistryResponse::ReservationRequired
        );

        let first = peer();
        make_available(&mut registry, first);
        assert!(matches!(
            registry.allocate(first, source(), &mut FailingRandom),
            Err(RegistryError::Random(_))
        ));
        let locator = Locator::new(7).unwrap();
        assert_eq!(
            registry.reclaim(first, source(), locator),
            RegistryResponse::Acquired(locator)
        );
        let other = peer();
        make_available(&mut registry, other);
        assert_eq!(
            registry.reclaim(other, source(), locator),
            RegistryResponse::Conflict
        );
        assert_eq!(registry.release(other, locator), RegistryResponse::Released);
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.release(first, locator), RegistryResponse::Released);
        assert!(registry.is_empty());
        assert_eq!(registry.release(first, locator), RegistryResponse::Released);

        for value in 0..128_u8 {
            let owner = peer();
            make_available(&mut registry, owner);
            let source = SourcePrefix::Ipv4(Ipv4Addr::new(198, 51, value, 1));
            assert!(matches!(
                registry.allocate(owner, source, &mut ZeroRandom).unwrap(),
                RegistryResponse::Acquired(_)
            ));
        }
        let blocked = peer();
        make_available(&mut registry, blocked);
        assert_eq!(
            registry
                .allocate(blocked, source(), &mut ZeroRandom)
                .unwrap(),
            RegistryResponse::Capacity
        );

        let mut reclaim_capacity = Registry::new(FakeClock::default());
        for value in 0..32 {
            let owner = peer();
            make_available(&mut reclaim_capacity, owner);
            assert_eq!(
                reclaim_capacity.reclaim(
                    owner,
                    source(),
                    Locator::new(value).expect("test locator is valid")
                ),
                RegistryResponse::Acquired(Locator::new(value).unwrap())
            );
        }
        let blocked = peer();
        make_available(&mut reclaim_capacity, blocked);
        assert_eq!(
            reclaim_capacity.reclaim(blocked, source(), Locator::new(100).unwrap()),
            RegistryResponse::Capacity
        );

        let mut inconsistent = Registry::new(FakeClock::default());
        let owner = peer();
        let locator = Locator::new(5).unwrap();
        inconsistent.by_locator.insert(
            locator,
            Mapping {
                owner,
                source: source(),
                state: MappingState::Active,
            },
        );
        inconsistent.by_owner.insert(owner, locator);
        assert_eq!(
            inconsistent.release(owner, locator),
            RegistryResponse::Released
        );
        assert!(inconsistent.is_empty());

        assert!(matches!(
            bounded_peer_id(&[0_u8; 65]),
            Err(RegistryError::PeerIdTooLong)
        ));
    }

    #[test]
    fn resolve_limiters_enforce_bursts_capacity_and_idle_pruning() {
        let source = source();
        let now = MonotonicTime::from_elapsed(Duration::ZERO);
        let mut limiters = ResolveLimiters::default();
        for _ in 0..32 {
            assert!(limiters.check(source, now));
        }
        assert!(!limiters.check(source, now));

        let limits = tiny_resolve_limits();
        let mut full = ResolveLimiters::with_limits(limits);
        assert!(full.check_source(source, now));
        assert!(full.check_source(SourcePrefix::Ipv6([1; 8]), now));
        let third = SourcePrefix::Ipv6([2; 8]);
        assert!(!full.check_source(third, now));
        assert!(full.check_source(third, MonotonicTime::from_elapsed(Duration::from_secs(1))));
        assert_eq!(full.sources.len(), 1);
        assert_eq!(full.retry_after().millis(), 100);

        let mut global = ResolveLimiters::new();
        for _ in 0..128 {
            assert!(global.check_global());
        }
        assert!(!global.check(source, now));
    }

    fn tiny_resolve_limits() -> ResolveLimits {
        ResolveLimits::new(
            ResolveConcurrency::new(1).unwrap(),
            ResolveRate::new(1, 1).unwrap(),
            ResolveRate::new(1, 1).unwrap(),
            SourceLimiterCapacity::new(2).unwrap(),
            SourceLimiterIdle::from_seconds(1).unwrap(),
            RetryAfter::from_millis(100).unwrap(),
        )
        .unwrap()
    }

    fn make_available(registry: &mut Registry<FakeClock>, peer: yonder_net::PeerId) {
        registry.set_connection(peer, true);
        registry.set_reservation(peer, true);
    }

    fn peer() -> yonder_net::PeerId {
        Keypair::generate_ed25519().public().to_peer_id()
    }

    fn source() -> SourcePrefix {
        SourcePrefix::Ipv4("192.0.2.1".parse().unwrap())
    }
}
