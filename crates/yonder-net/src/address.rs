use crate::error::AddressError;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use std::fmt;
use std::str::FromStr;

const MAX_TEXT_LEN: usize = 512;
const MAX_RELAY_ADDRESSES: usize = 8;

/// A transport category used by address validation and path ranking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TransportKind {
    Quic,
    Tcp,
    WebSocket,
    SecureWebSocket,
}

/// The pinned identity of the one configured self-hosted relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelayPeerId(PeerId);

impl RelayPeerId {
    #[must_use]
    pub const fn new(peer_id: PeerId) -> Self {
        Self(peer_id)
    }

    #[must_use]
    pub const fn get(self) -> PeerId {
        self.0
    }
}

impl fmt::Display for RelayPeerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// A validated endpoint-to-relay dial address ending in the pinned PeerId.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRelayAddress {
    address: Multiaddr,
    relay: RelayPeerId,
    transport: TransportKind,
}

impl EndpointRelayAddress {
    #[must_use]
    pub const fn relay(&self) -> RelayPeerId {
        self.relay
    }

    #[must_use]
    pub const fn transport(&self) -> TransportKind {
        self.transport
    }

    #[must_use]
    pub const fn as_multiaddr(&self) -> &Multiaddr {
        &self.address
    }

    #[must_use]
    pub fn into_multiaddr(self) -> Multiaddr {
        self.address
    }

    /// Builds the canonical circuit address for one resolved endpoint peer.
    #[must_use]
    pub fn circuit_to(&self, target: PeerId) -> Multiaddr {
        self.address
            .clone()
            .with(Protocol::P2pCircuit)
            .with(Protocol::P2p(target))
    }
}

impl FromStr for EndpointRelayAddress {
    type Err = AddressError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let address = parse_bounded(input)?;
        Self::try_from(address)
    }
}

impl TryFrom<Multiaddr> for EndpointRelayAddress {
    type Error = AddressError;

    fn try_from(address: Multiaddr) -> Result<Self, Self::Error> {
        let protocols: Vec<_> = address.iter().collect();
        let Some(Protocol::P2p(peer_id)) = protocols.last() else {
            return Err(AddressError::MissingRelayPeerId);
        };
        let peer_id = *peer_id;
        if protocols[..protocols.len() - 1]
            .iter()
            .any(|protocol| matches!(protocol, Protocol::P2p(_)))
        {
            return Err(AddressError::MissingRelayPeerId);
        }
        let transport = validate_transport(&protocols[..protocols.len() - 1], HostRule::IpOrDns)?;
        drop(protocols);
        Ok(Self {
            address,
            relay: RelayPeerId::new(peer_id),
            transport,
        })
    }
}

/// One to eight entry addresses that all pin the same relay identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointRelaySet {
    addresses: Vec<EndpointRelayAddress>,
    relay: RelayPeerId,
}

impl EndpointRelaySet {
    /// Validates address count and relay identity consistency.
    pub fn new(addresses: Vec<EndpointRelayAddress>) -> Result<Self, AddressError> {
        if addresses.is_empty() || addresses.len() > MAX_RELAY_ADDRESSES {
            return Err(AddressError::InvalidRelayAddressCount);
        }
        let relay = addresses[0].relay();
        if addresses.iter().any(|address| address.relay() != relay) {
            return Err(AddressError::MixedRelayPeerIds);
        }
        Ok(Self { addresses, relay })
    }

    #[must_use]
    pub const fn relay(&self) -> RelayPeerId {
        self.relay
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &EndpointRelayAddress> {
        self.addresses.iter()
    }
}

/// A validated bindable relay listener address without a PeerId.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayListenAddress {
    address: Multiaddr,
    transport: TransportKind,
}

impl RelayListenAddress {
    #[must_use]
    pub const fn transport(&self) -> TransportKind {
        self.transport
    }

    #[must_use]
    pub const fn as_multiaddr(&self) -> &Multiaddr {
        &self.address
    }
}

impl FromStr for RelayListenAddress {
    type Err = AddressError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let address = parse_bounded(input)?;
        let protocols: Vec<_> = address.iter().collect();
        reject_peer_id(&protocols)?;
        let transport = validate_transport(&protocols, HostRule::IpOnly)?;
        Ok(Self { address, transport })
    }
}

/// A validated advertised relay address without a PeerId.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayExternalAddress {
    address: Multiaddr,
    transport: TransportKind,
}

impl RelayExternalAddress {
    #[must_use]
    pub const fn transport(&self) -> TransportKind {
        self.transport
    }

    #[must_use]
    pub const fn as_multiaddr(&self) -> &Multiaddr {
        &self.address
    }

    #[must_use]
    pub fn with_peer_id(&self, relay: RelayPeerId) -> Multiaddr {
        self.address.clone().with(Protocol::P2p(relay.get()))
    }
}

impl FromStr for RelayExternalAddress {
    type Err = AddressError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let address = parse_bounded(input)?;
        let protocols: Vec<_> = address.iter().collect();
        reject_peer_id(&protocols)?;
        let transport = validate_transport(&protocols, HostRule::IpOrDns)?;
        Ok(Self { address, transport })
    }
}

#[derive(Clone, Copy)]
enum HostRule {
    IpOnly,
    IpOrDns,
}

fn parse_bounded(input: &str) -> Result<Multiaddr, AddressError> {
    if input.len() > MAX_TEXT_LEN {
        return Err(AddressError::TooLong);
    }
    input.parse().map_err(|_| AddressError::InvalidSyntax)
}

fn reject_peer_id(protocols: &[Protocol<'_>]) -> Result<(), AddressError> {
    if protocols
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2p(_)))
    {
        Err(AddressError::UnexpectedPeerId)
    } else {
        Ok(())
    }
}

fn validate_transport(
    protocols: &[Protocol<'_>],
    host_rule: HostRule,
) -> Result<TransportKind, AddressError> {
    let Some((host, transport)) = protocols.split_first() else {
        return Err(AddressError::UnsupportedHost);
    };
    let host_valid = match host_rule {
        HostRule::IpOnly => matches!(host, Protocol::Ip4(_) | Protocol::Ip6(_)),
        HostRule::IpOrDns => matches!(
            host,
            Protocol::Ip4(_) | Protocol::Ip6(_) | Protocol::Dns4(_) | Protocol::Dns6(_)
        ),
    };
    if !host_valid {
        return Err(match host_rule {
            HostRule::IpOnly => AddressError::ListenRequiresIp,
            HostRule::IpOrDns => AddressError::UnsupportedHost,
        });
    }

    if matches!(host_rule, HostRule::IpOrDns)
        && match host {
            Protocol::Ip4(address) => address.is_unspecified(),
            Protocol::Ip6(address) => address.is_unspecified(),
            _ => false,
        }
    {
        return Err(AddressError::UnspecifiedDialHost);
    }

    let (kind, port) = match transport {
        [Protocol::Udp(port), Protocol::QuicV1] => (TransportKind::Quic, *port),
        [Protocol::Tcp(port)] => (TransportKind::Tcp, *port),
        [Protocol::Tcp(port), Protocol::Ws(path)] if path.as_ref() == "/" => {
            (TransportKind::WebSocket, *port)
        }
        [Protocol::Tcp(port), Protocol::Tls, Protocol::Ws(path)] if path.as_ref() == "/" => {
            (TransportKind::SecureWebSocket, *port)
        }
        _ => return Err(AddressError::UnsupportedTransport),
    };
    if matches!(host_rule, HostRule::IpOrDns) && port == 0 {
        return Err(AddressError::ZeroDialPort);
    }
    Ok(kind)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        EndpointRelayAddress, EndpointRelaySet, RelayExternalAddress, RelayListenAddress,
        TransportKind,
    };
    use crate::error::AddressError;
    use libp2p::identity::Keypair;

    fn peer() -> String {
        Keypair::generate_ed25519()
            .public()
            .to_peer_id()
            .to_string()
    }

    #[test]
    fn endpoint_addresses_accept_exact_frozen_transports() {
        let peer = peer();
        for (suffix, expected) in [
            ("udp/443/quic-v1", TransportKind::Quic),
            ("tcp/443", TransportKind::Tcp),
            ("tcp/80/ws", TransportKind::WebSocket),
            ("tcp/443/tls/ws", TransportKind::SecureWebSocket),
        ] {
            let address: EndpointRelayAddress = format!("/dns4/relay.example/{suffix}/p2p/{peer}")
                .parse()
                .unwrap();
            assert_eq!(address.transport(), expected);
            assert_eq!(address.relay().to_string(), peer);
            assert_eq!(address.relay().get(), address.relay().get());
            let target = address.relay().get();
            assert_eq!(
                address.circuit_to(target),
                address
                    .as_multiaddr()
                    .clone()
                    .with(libp2p::multiaddr::Protocol::P2pCircuit)
                    .with(libp2p::multiaddr::Protocol::P2p(target))
            );
            assert_eq!(address.clone().into_multiaddr(), *address.as_multiaddr());
        }
    }

    #[test]
    fn unsupported_hosts_transports_and_peer_layouts_fail() {
        let peer = peer();
        assert_eq!(
            format!("/dnsaddr/relay.example/tcp/443/p2p/{peer}").parse::<EndpointRelayAddress>(),
            Err(AddressError::UnsupportedHost)
        );
        assert_eq!(
            format!("/ip4/127.0.0.1/udp/1/quic/p2p/{peer}").parse::<EndpointRelayAddress>(),
            Err(AddressError::UnsupportedTransport)
        );
        assert_eq!(
            "/ip4/127.0.0.1/tcp/1".parse::<EndpointRelayAddress>(),
            Err(AddressError::MissingRelayPeerId)
        );
        assert_eq!(
            "not-a-multiaddr".parse::<EndpointRelayAddress>(),
            Err(AddressError::InvalidSyntax)
        );
        assert_eq!(
            format!("/ip4/127.0.0.1/tcp/1/p2p/{peer}/p2p/{peer}").parse::<EndpointRelayAddress>(),
            Err(AddressError::MissingRelayPeerId)
        );
        assert_eq!(
            format!("/p2p/{peer}").parse::<EndpointRelayAddress>(),
            Err(AddressError::UnsupportedHost)
        );
        assert_eq!(
            format!("/ip4/0.0.0.0/tcp/1/p2p/{peer}").parse::<EndpointRelayAddress>(),
            Err(AddressError::UnspecifiedDialHost)
        );
        assert_eq!(
            format!("/ip6/::/udp/1/quic-v1/p2p/{peer}").parse::<EndpointRelayAddress>(),
            Err(AddressError::UnspecifiedDialHost)
        );
        assert_eq!(
            format!("/ip4/127.0.0.1/tcp/0/p2p/{peer}").parse::<EndpointRelayAddress>(),
            Err(AddressError::ZeroDialPort)
        );
        assert_eq!(
            format!("/ip4/127.0.0.1/tcp/1/p2p/{peer}")
                .repeat(513)
                .parse::<EndpointRelayAddress>(),
            Err(AddressError::TooLong)
        );
    }

    #[test]
    fn relay_sets_require_one_identity_and_bounded_count() {
        let first: EndpointRelayAddress = format!("/ip4/127.0.0.1/tcp/1/p2p/{}", peer())
            .parse()
            .unwrap();
        let second: EndpointRelayAddress = format!("/ip4/127.0.0.1/tcp/2/p2p/{}", peer())
            .parse()
            .unwrap();
        assert_eq!(
            EndpointRelaySet::new(Vec::new()),
            Err(AddressError::InvalidRelayAddressCount)
        );
        assert_eq!(
            EndpointRelaySet::new(vec![first, second]),
            Err(AddressError::MixedRelayPeerIds)
        );

        let first: EndpointRelayAddress = format!("/ip4/127.0.0.1/tcp/1/p2p/{}", peer())
            .parse()
            .unwrap();
        let relay = first.relay();
        let set = EndpointRelaySet::new(vec![first.clone(); 8]).unwrap();
        assert_eq!(set.relay(), relay);
        assert_eq!(set.iter().len(), 8);
        assert_eq!(
            EndpointRelaySet::new(vec![first; 9]),
            Err(AddressError::InvalidRelayAddressCount)
        );
    }

    #[test]
    fn listen_and_external_rules_are_distinct() {
        let ephemeral = "/ip4/0.0.0.0/tcp/0".parse::<RelayListenAddress>().unwrap();
        assert_eq!(ephemeral.transport(), TransportKind::Tcp);
        let listener = "/ip6/::/tcp/443/tls/ws"
            .parse::<RelayListenAddress>()
            .unwrap();
        assert_eq!(listener.transport(), TransportKind::SecureWebSocket);
        assert_eq!(
            listener.as_multiaddr().to_string(),
            "/ip6/::/tcp/443/tls/ws"
        );
        assert_eq!(
            "/dns4/relay.example/tcp/443".parse::<RelayListenAddress>(),
            Err(AddressError::ListenRequiresIp)
        );
        assert_eq!(
            "not-a-multiaddr".parse::<RelayListenAddress>(),
            Err(AddressError::InvalidSyntax)
        );
        assert_eq!(
            "/ip4/127.0.0.1/tcp/1"
                .repeat(513)
                .parse::<RelayListenAddress>(),
            Err(AddressError::TooLong)
        );
        let external = "/dns6/relay.example/udp/443/quic-v1"
            .parse::<RelayExternalAddress>()
            .unwrap();
        assert_eq!(external.transport(), TransportKind::Quic);
        assert!(
            "/ip4/127.0.0.1/tcp/1"
                .parse::<RelayExternalAddress>()
                .is_ok()
        );
        assert_eq!(
            "/ip4/0.0.0.0/tcp/1".parse::<RelayExternalAddress>(),
            Err(AddressError::UnspecifiedDialHost)
        );
        assert_eq!(
            "/ip6/::/udp/1/quic-v1".parse::<RelayExternalAddress>(),
            Err(AddressError::UnspecifiedDialHost)
        );
        assert_eq!(
            "/dns4/relay.example/tcp/0".parse::<RelayExternalAddress>(),
            Err(AddressError::ZeroDialPort)
        );
        let relay = super::RelayPeerId::new(peer().parse().unwrap());
        assert_eq!(
            external.with_peer_id(relay),
            external
                .as_multiaddr()
                .clone()
                .with(libp2p::multiaddr::Protocol::P2p(relay.get()))
        );
        let peer = peer();
        assert_eq!(
            format!("/ip4/127.0.0.1/tcp/1/p2p/{peer}").parse::<RelayListenAddress>(),
            Err(AddressError::UnexpectedPeerId)
        );
        assert_eq!(
            format!("/ip4/127.0.0.1/tcp/1/p2p/{peer}").parse::<RelayExternalAddress>(),
            Err(AddressError::UnexpectedPeerId)
        );
    }
}
