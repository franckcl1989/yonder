use crate::path::{CandidateId, CandidatePath, EstablishedOrder, PathCandidate, PingSamples};
use crate::{TransportKind, path};
use libp2p::PeerId;
use libp2p::core::ConnectedPoint;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::ConnectionId;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use thiserror::Error;
use yonder_core::{ConnectionRoster, RosterError};

const PER_PEER_CAPACITY: usize = 8;
const PER_TRANSPORT_CAPACITY: usize = 2;

/// The immutable source quota prefix derived from one authenticated connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourcePrefix {
    Ipv4(Ipv4Addr),
    Ipv6([u8; 8]),
}

impl SourcePrefix {
    /// Extracts IPv4 /32 or IPv6 /64 from a connected point.
    #[must_use]
    pub fn from_endpoint(endpoint: &ConnectedPoint) -> Option<Self> {
        endpoint
            .get_remote_address()
            .iter()
            .find_map(|protocol| match protocol {
                Protocol::Ip4(address) => Some(Self::Ipv4(address)),
                Protocol::Ip6(address) => Some(Self::Ipv6(ipv6_prefix(address))),
                _ => None,
            })
    }
}

fn ipv6_prefix(address: Ipv6Addr) -> [u8; 8] {
    let octets = address.octets();
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&octets[..8]);
    prefix
}

/// The sole physical connection and its locally observed endpoint.
#[derive(Debug, Clone)]
pub struct UniqueConnection<'a> {
    id: ConnectionId,
    endpoint: &'a ConnectedPoint,
}

impl UniqueConnection<'_> {
    #[must_use]
    pub const fn id(&self) -> ConnectionId {
        self.id
    }

    #[must_use]
    pub const fn endpoint(&self) -> &ConnectedPoint {
        self.endpoint
    }

    #[must_use]
    pub fn source_prefix(&self) -> Option<SourcePrefix> {
        SourcePrefix::from_endpoint(self.endpoint)
    }
}

/// Errors while maintaining the bounded local connection roster.
#[derive(Debug, Error)]
pub enum ConnectionBookError {
    #[error("a peer exceeded its bounded physical connection roster")]
    PeerRosterFull(#[source] RosterError),
}

/// Single-owner connection state used by unique-connection security checks.
#[derive(Debug, Default)]
pub struct ConnectionBook {
    rosters: HashMap<PeerId, ConnectionRoster<ConnectionId, PER_PEER_CAPACITY>>,
    endpoints: HashMap<ConnectionId, ConnectedPoint>,
}

impl ConnectionBook {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies a Swarm establishment event. Duplicate events are idempotent.
    pub fn established(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
        endpoint: ConnectedPoint,
    ) -> Result<bool, ConnectionBookError> {
        let inserted = self
            .rosters
            .entry(peer)
            .or_default()
            .insert(connection)
            .map_err(ConnectionBookError::PeerRosterFull)?;
        if inserted {
            self.endpoints.insert(connection, endpoint);
        }
        Ok(inserted)
    }

    /// Applies a close event and removes empty peer state.
    pub fn closed(&mut self, peer: &PeerId, connection: &ConnectionId) -> bool {
        let Some(roster) = self.rosters.get_mut(peer) else {
            return false;
        };
        if !roster.remove(connection) {
            return false;
        }
        self.endpoints.remove(connection);
        if roster.is_empty() {
            self.rosters.remove(peer);
        }
        true
    }

    /// Returns a connection only after the roster has converged to one entry.
    #[must_use]
    pub fn unique(&self, peer: &PeerId) -> Option<UniqueConnection<'_>> {
        let id = *self.rosters.get(peer)?.unique()?;
        let endpoint = self.endpoints.get(&id)?;
        Some(UniqueConnection { id, endpoint })
    }

    #[must_use]
    pub fn count(&self, peer: &PeerId) -> usize {
        self.rosters.get(peer).map_or(0, ConnectionRoster::len)
    }

    /// Iterates the connection IDs that must be closed to enforce the barrier.
    pub fn connections(&self, peer: &PeerId) -> impl Iterator<Item = ConnectionId> + '_ {
        self.rosters
            .get(peer)
            .into_iter()
            .flat_map(ConnectionRoster::iter)
            .copied()
    }
}

/// Failures while collecting the fixed maximum of eight candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SelectionError {
    #[error("the path candidate set is full")]
    Full,
    #[error("a transport exceeded its bounded path candidate set")]
    TransportFull,
    #[error("the path candidate is unknown")]
    UnknownCandidate,
}

#[derive(Debug, Clone)]
struct TrackedCandidate {
    connection: ConnectionId,
    ranked: PathCandidate,
}

/// Bounded quality evidence for one endpoint-to-endpoint selection window.
#[derive(Debug, Default)]
pub struct ConnectionSelection {
    candidates: Vec<TrackedCandidate>,
    next_id: u64,
    next_order: u64,
}

impl ConnectionSelection {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reports whether an exact physical connection has entered this selection window.
    #[must_use]
    pub fn contains(&self, connection: ConnectionId) -> bool {
        self.candidates
            .iter()
            .any(|candidate| candidate.connection == connection)
    }

    /// Adds an established candidate and assigns unique deterministic ordering.
    pub fn established(
        &mut self,
        connection: ConnectionId,
        endpoint: &ConnectedPoint,
    ) -> Result<(), SelectionError> {
        if self
            .candidates
            .iter()
            .any(|candidate| candidate.connection == connection)
        {
            return Ok(());
        }
        if self.candidates.len() == PER_PEER_CAPACITY {
            return Err(SelectionError::Full);
        }
        let transport = classify_transport(endpoint.get_remote_address());
        if self
            .candidates
            .iter()
            .filter(|candidate| candidate.ranked.transport == transport)
            .count()
            == PER_TRANSPORT_CAPACITY
        {
            return Err(SelectionError::TransportFull);
        }
        let path = if endpoint.is_relayed() {
            CandidatePath::Relayed
        } else {
            CandidatePath::Direct
        };
        let ranked = PathCandidate::new(
            CandidateId::new(self.next_id),
            PingSamples::new(),
            path,
            transport,
            EstablishedOrder::new(self.next_order),
        );
        self.next_id = self.next_id.wrapping_add(1);
        self.next_order = self.next_order.wrapping_add(1);
        self.candidates
            .push(TrackedCandidate { connection, ranked });
        Ok(())
    }

    /// Records one successful ping for the exact physical connection.
    pub fn ping(
        &mut self,
        connection: ConnectionId,
        round_trip: Duration,
    ) -> Result<bool, SelectionError> {
        let candidate = self
            .candidates
            .iter_mut()
            .find(|candidate| candidate.connection == connection)
            .ok_or(SelectionError::UnknownCandidate)?;
        Ok(candidate.ranked.samples_mut().push(round_trip))
    }

    /// Removes a failed candidate during the collection window.
    pub fn closed(&mut self, connection: ConnectionId) -> bool {
        let Some(index) = self
            .candidates
            .iter()
            .position(|candidate| candidate.connection == connection)
        else {
            return false;
        };
        self.candidates.swap_remove(index);
        true
    }

    /// Selects the winner and returns all established losers for explicit closing.
    #[must_use]
    pub fn finish(&self) -> Option<(ConnectionId, Vec<ConnectionId>)> {
        let tracked = self
            .candidates
            .iter()
            .filter(|candidate| candidate.ranked.is_usable())
            .min_by(|left, right| path::compare(&left.ranked, &right.ranked))?;
        let losers = self
            .candidates
            .iter()
            .filter(|candidate| candidate.connection != tracked.connection)
            .map(|candidate| candidate.connection)
            .collect();
        Some((tracked.connection, losers))
    }
}

fn classify_transport(address: &libp2p::Multiaddr) -> TransportKind {
    let protocols: Vec<_> = address.iter().collect();
    if protocols
        .windows(2)
        .any(|window| matches!(window, [Protocol::Udp(_), Protocol::QuicV1]))
    {
        TransportKind::Quic
    } else if protocols
        .windows(3)
        .any(|window| matches!(window, [Protocol::Tcp(_), Protocol::Tls, Protocol::Ws(_)]))
    {
        TransportKind::SecureWebSocket
    } else if protocols
        .windows(2)
        .any(|window| matches!(window, [Protocol::Tcp(_), Protocol::Ws(_)]))
    {
        TransportKind::WebSocket
    } else {
        TransportKind::Tcp
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{ConnectionBook, ConnectionSelection, SelectionError, SourcePrefix};
    use libp2p::core::{ConnectedPoint, Endpoint, transport::PortUse};
    use libp2p::identity::Keypair;
    use libp2p::swarm::ConnectionId;
    use std::time::Duration;

    #[test]
    fn book_only_exposes_a_unique_connection_and_source_prefix() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let first = ConnectionId::new_unchecked(1);
        let second = ConnectionId::new_unchecked(2);
        let endpoint = dialer("/ip4/192.0.2.4/tcp/1");
        let mut book = ConnectionBook::new();
        assert_eq!(book.count(&peer), 0);
        assert!(!book.closed(&peer, &first));
        assert!(book.established(peer, first, endpoint).unwrap());
        assert!(
            !book
                .established(peer, first, dialer("/ip4/192.0.2.5/tcp/2"))
                .unwrap()
        );
        let unique = book.unique(&peer).unwrap();
        assert_eq!(unique.id(), first);
        assert_eq!(
            unique.endpoint().get_remote_address().to_string(),
            "/ip4/192.0.2.4/tcp/1"
        );
        assert_eq!(book.count(&peer), 1);
        assert_eq!(book.connections(&peer).collect::<Vec<_>>(), vec![first]);
        assert!(!book.closed(&peer, &second));
        assert_eq!(
            book.unique(&peer).unwrap().source_prefix(),
            Some(SourcePrefix::Ipv4("192.0.2.4".parse().unwrap()))
        );
        book.established(peer, second, dialer("/ip6/2001:db8:1:2::1/tcp/1"))
            .unwrap();
        assert!(book.unique(&peer).is_none());
        assert!(book.closed(&peer, &first));
        assert_eq!(
            book.unique(&peer).unwrap().source_prefix(),
            Some(SourcePrefix::Ipv6([0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2]))
        );
        assert!(book.closed(&peer, &second));
        assert!(book.unique(&peer).is_none());
        assert!(!book.closed(&peer, &second));
        assert_eq!(
            SourcePrefix::from_endpoint(&dialer("/dns4/example.test/tcp/1")),
            None
        );
    }

    #[test]
    fn connection_book_enforces_the_per_peer_capacity() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let mut book = ConnectionBook::new();
        for value in 0..8 {
            book.established(
                peer,
                ConnectionId::new_unchecked(value),
                dialer("/ip4/127.0.0.1/tcp/1"),
            )
            .unwrap();
        }
        assert!(
            book.established(
                peer,
                ConnectionId::new_unchecked(9),
                dialer("/ip4/127.0.0.1/tcp/1"),
            )
            .is_err()
        );
    }

    #[test]
    fn selection_tracks_exact_connections_and_losers() {
        let fast = ConnectionId::new_unchecked(1);
        let slow = ConnectionId::new_unchecked(2);
        let mut selection = ConnectionSelection::new();
        selection
            .established(fast, &dialer("/ip4/127.0.0.1/udp/1/quic-v1"))
            .unwrap();
        assert!(selection.contains(fast));
        assert!(!selection.contains(slow));
        selection
            .established(slow, &dialer("/ip4/127.0.0.1/tcp/1"))
            .unwrap();
        assert!(selection.contains(slow));
        for value in [10, 10, 10] {
            selection.ping(fast, Duration::from_millis(value)).unwrap();
        }
        for value in [20, 20, 20] {
            selection.ping(slow, Duration::from_millis(value)).unwrap();
        }
        assert_eq!(selection.finish(), Some((fast, vec![slow])));
    }

    #[test]
    fn selection_is_bounded_idempotent_and_rejects_unknown_candidates() {
        let first = ConnectionId::new_unchecked(1);
        let mut selection = ConnectionSelection::new();
        assert_eq!(selection.finish(), None);
        assert_eq!(
            selection.ping(first, Duration::ZERO),
            Err(SelectionError::UnknownCandidate)
        );
        assert!(!selection.closed(first));

        let addresses = [
            "/ip4/127.0.0.1/tcp/1",
            "/ip4/127.0.0.1/tcp/2",
            "/ip4/127.0.0.1/udp/1/quic-v1",
            "/ip4/127.0.0.1/udp/2/quic-v1",
            "/ip4/127.0.0.1/tcp/3/ws",
            "/ip4/127.0.0.1/tcp/4/ws",
            "/ip4/127.0.0.1/tcp/5/tls/ws",
            "/ip4/127.0.0.1/tcp/6/tls/ws",
        ];
        for (index, address) in addresses.into_iter().enumerate() {
            let value = index + 1;
            let connection = ConnectionId::new_unchecked(value);
            selection.established(connection, &dialer(address)).unwrap();
        }
        assert_eq!(
            selection.established(first, &dialer("/ip4/127.0.0.1/tcp/1")),
            Ok(())
        );
        assert_eq!(
            selection.established(
                ConnectionId::new_unchecked(9),
                &dialer("/ip4/127.0.0.1/tcp/1")
            ),
            Err(SelectionError::Full)
        );
        for _ in 0..3 {
            assert!(selection.ping(first, Duration::from_millis(1)).unwrap());
        }
        assert!(!selection.ping(first, Duration::from_millis(1)).unwrap());
        assert!(selection.closed(first));
        assert!(!selection.closed(first));

        let mut per_transport = ConnectionSelection::new();
        per_transport
            .established(first, &dialer("/ip4/127.0.0.1/tcp/1"))
            .unwrap();
        per_transport
            .established(
                ConnectionId::new_unchecked(2),
                &dialer("/ip4/127.0.0.1/tcp/2"),
            )
            .unwrap();
        assert_eq!(
            per_transport.established(
                ConnectionId::new_unchecked(3),
                &dialer("/ip4/127.0.0.1/tcp/3")
            ),
            Err(SelectionError::TransportFull)
        );
    }

    fn dialer(address: &str) -> ConnectedPoint {
        ConnectedPoint::Dialer {
            address: address.parse().unwrap(),
            role_override: Endpoint::Dialer,
            port_use: PortUse::Reuse,
        }
    }
}
