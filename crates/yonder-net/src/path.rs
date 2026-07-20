use crate::TransportKind;
use std::cmp::Ordering;
use std::time::Duration;

/// An opaque identifier used to map a ranked candidate back to a libp2p connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CandidateId(u64);

impl CandidateId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A unique order assigned when a candidate connection becomes established.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EstablishedOrder(u64);

impl EstablishedOrder {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// Whether an end-to-end candidate bypasses the circuit relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CandidatePath {
    Direct,
    Relayed,
}

/// Up to the first three successful selection-window ping samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingSamples {
    values: [Duration; 3],
    len: u8,
}

impl PingSamples {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            values: [Duration::ZERO; 3],
            len: 0,
        }
    }

    /// Records a successful sample and ignores results beyond the frozen first three.
    pub fn push(&mut self, sample: Duration) -> bool {
        if self.len == 3 {
            return false;
        }
        self.values[usize::from(self.len)] = sample;
        self.len += 1;
        true
    }

    #[must_use]
    pub const fn len(self) -> u8 {
        self.len
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub const fn is_usable(self) -> bool {
        self.len >= 1
    }

    fn statistics(self) -> Option<(u8, Duration, Duration)> {
        if !self.is_usable() {
            return None;
        }
        let mut nanos = [0_u64; 3];
        for (destination, source) in nanos
            .iter_mut()
            .zip(self.values.iter())
            .take(usize::from(self.len))
        {
            *destination = source.as_nanos().try_into().ok()?;
        }
        nanos[..usize::from(self.len)].sort_unstable();
        let median = match self.len {
            1 => Duration::from_nanos(nanos[0]),
            2 => Duration::from_nanos(nanos[0] + (nanos[1] - nanos[0]) / 2),
            _ => Duration::from_nanos(nanos[1]),
        };
        let range = Duration::from_nanos(nanos[usize::from(self.len) - 1] - nanos[0]);
        Some((self.len, median, range))
    }
}

impl Default for PingSamples {
    fn default() -> Self {
        Self::new()
    }
}

/// One established path candidate with bounded quality evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathCandidate {
    id: CandidateId,
    samples: PingSamples,
    path: CandidatePath,
    pub(crate) transport: TransportKind,
    established: EstablishedOrder,
}

impl PathCandidate {
    #[must_use]
    pub const fn new(
        id: CandidateId,
        samples: PingSamples,
        path: CandidatePath,
        transport: TransportKind,
        established: EstablishedOrder,
    ) -> Self {
        Self {
            id,
            samples,
            path,
            transport,
            established,
        }
    }

    #[must_use]
    pub const fn id(self) -> CandidateId {
        self.id
    }

    pub(crate) const fn is_usable(self) -> bool {
        self.samples.is_usable()
    }

    pub(crate) fn samples_mut(&mut self) -> &mut PingSamples {
        &mut self.samples
    }
}

/// Selects one winner from an already bounded candidate slice.
pub trait PathPolicy {
    fn select<'a>(&self, candidates: &'a [PathCandidate]) -> Option<&'a PathCandidate>;
}

/// The frozen connectivity, stability, latency, path and transport ordering.
#[derive(Debug, Default, Clone, Copy)]
pub struct FrozenPathPolicy;

impl PathPolicy for FrozenPathPolicy {
    fn select<'a>(&self, candidates: &'a [PathCandidate]) -> Option<&'a PathCandidate> {
        candidates
            .iter()
            .filter(|candidate| candidate.samples.is_usable())
            .min_by(|left, right| compare(left, right))
    }
}

pub(crate) fn compare(left: &PathCandidate, right: &PathCandidate) -> Ordering {
    let left_stats = left
        .samples
        .statistics()
        .expect("only usable candidates are ranked");
    let right_stats = right
        .samples
        .statistics()
        .expect("only usable candidates are ranked");
    right_stats
        .0
        .cmp(&left_stats.0)
        .then_with(|| left_stats.1.cmp(&right_stats.1))
        .then_with(|| left_stats.2.cmp(&right_stats.2))
        .then_with(|| left.path.cmp(&right.path))
        .then_with(|| left.transport.cmp(&right.transport))
        .then_with(|| left.established.cmp(&right.established))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        CandidateId, CandidatePath, EstablishedOrder, FrozenPathPolicy, PathCandidate, PathPolicy,
        PingSamples,
    };
    use crate::TransportKind;
    use proptest::prelude::*;
    use std::time::Duration;

    #[test]
    fn one_success_is_usable_and_zero_successes_are_not() {
        let mut samples = PingSamples::default();
        assert!(samples.is_empty());
        assert_eq!(samples.len(), 0);
        assert_eq!(samples.statistics(), None);
        let empty = candidate(0, samples, CandidatePath::Direct, TransportKind::Quic, 0);
        assert!(!empty.is_usable());
        assert_eq!(FrozenPathPolicy.select(&[empty]), None);
        assert!(samples.push(Duration::from_millis(1)));
        assert_eq!(samples.len(), 1);
        assert_eq!(
            samples.statistics(),
            Some((1, Duration::from_millis(1), Duration::ZERO))
        );
        let mut checked = candidate(0, samples, CandidatePath::Direct, TransportKind::Quic, 0);
        assert!(checked.is_usable());
        assert!(checked.samples_mut().push(Duration::from_millis(2)));
        assert!(checked.is_usable());
        assert_eq!(checked.id().get(), 0);
        assert!(checked.samples_mut().push(Duration::from_millis(3)));
        assert!(!checked.samples_mut().push(Duration::from_millis(4)));
        let candidate = candidate(0, samples, CandidatePath::Direct, TransportKind::Quic, 0);
        assert_eq!(
            FrozenPathPolicy
                .select(&[candidate])
                .map(|value| value.id()),
            Some(CandidateId::new(0))
        );
    }

    #[test]
    fn samples_reject_durations_that_do_not_fit_the_frozen_wire_statistic() {
        let mut values = PingSamples::new();
        values.push(Duration::MAX);
        values.push(Duration::MAX);
        assert_eq!(values.statistics(), None);
    }

    #[test]
    fn ranking_uses_every_frozen_tie_break() {
        let stable = samples(&[20, 20, 20]);
        let jitter = samples(&[10, 20, 30]);
        let fewer = samples(&[1, 1]);
        let candidates = [
            candidate(1, fewer, CandidatePath::Direct, TransportKind::Quic, 0),
            candidate(2, jitter, CandidatePath::Direct, TransportKind::Quic, 0),
            candidate(3, stable, CandidatePath::Relayed, TransportKind::Quic, 0),
            candidate(4, stable, CandidatePath::Direct, TransportKind::Tcp, 0),
            candidate(5, stable, CandidatePath::Direct, TransportKind::Quic, 1),
            candidate(6, stable, CandidatePath::Direct, TransportKind::Quic, 0),
        ];
        assert_eq!(
            FrozenPathPolicy.select(&candidates).map(|value| value.id()),
            Some(CandidateId::new(6))
        );
    }

    proptest! {
        #[test]
        fn selection_is_permutation_independent(keys in any::<[u8; 4]>()) {
            let mut order = [0_usize, 1, 2, 3];
            order.sort_by_key(|index| (keys[*index], *index));
            let source = [
                candidate(1, samples(&[10, 10]), CandidatePath::Direct, TransportKind::Quic, 0),
                candidate(2, samples(&[9, 10, 11]), CandidatePath::Direct, TransportKind::Tcp, 1),
                candidate(3, samples(&[9, 10, 11]), CandidatePath::Direct, TransportKind::Quic, 2),
                candidate(4, samples(&[9, 10, 11]), CandidatePath::Relayed, TransportKind::Quic, 3),
            ];
            let permuted: Vec<_> = order.into_iter().map(|index| source[index]).collect();
            prop_assert_eq!(FrozenPathPolicy.select(&permuted).map(|value| value.id()), Some(CandidateId::new(3)));
        }
    }

    fn samples(milliseconds: &[u64]) -> PingSamples {
        let mut samples = PingSamples::new();
        for value in milliseconds {
            samples.push(Duration::from_millis(*value));
        }
        samples
    }

    fn candidate(
        id: u64,
        samples: PingSamples,
        path: CandidatePath,
        transport: TransportKind,
        established: u64,
    ) -> PathCandidate {
        PathCandidate::new(
            CandidateId::new(id),
            samples,
            path,
            transport,
            EstablishedOrder::new(established),
        )
    }
}
