use crate::behaviour::{
    DirectUpgradePolicy, EndpointBehaviour, EndpointBehaviourEvent, RelayBehaviour,
    RelayBehaviourEvent,
};
use crate::streams::Libp2pApplicationStreams;
use crate::transport::{WssTransportConfig, build_endpoint_transport, build_relay_transport};
use crate::{EndpointRelayAddress, NetworkBuildError, RelayExternalAddress, RelayListenAddress};
use libp2p::core::transport::{ListenerId, TransportError};
use libp2p::identity::Keypair;
use libp2p::swarm::ConnectionId;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{Config, DialError, Swarm, SwarmEvent};
use libp2p::{Multiaddr, PeerId};
use thiserror::Error;
use yonder_core::{CircuitRelayLimits, RegistrationLimits, RelayResourceConfig};

/// Runtime errors from an already constructed network node.
#[derive(Debug, Error)]
pub enum NetworkNodeError {
    #[error("failed to listen on the configured address")]
    Listen(#[source] TransportError<std::io::Error>),
    #[error("failed to dial the configured address")]
    Dial(#[source] DialError),
}

/// An endpoint Swarm and its isolated application-stream control.
pub struct EndpointNode {
    peer_id: PeerId,
    swarm: Swarm<EndpointBehaviour>,
    streams: Libp2pApplicationStreams,
}

impl EndpointNode {
    /// Constructs the endpoint stack without starting network activity.
    pub fn new(identity: Keypair, wss: WssTransportConfig) -> Result<Self, NetworkBuildError> {
        Self::with_direct_upgrade(identity, wss, DirectUpgradePolicy::Enabled)
    }

    /// Constructs an endpoint with an explicit, immutable DCUtR policy.
    pub fn with_direct_upgrade(
        identity: Keypair,
        wss: WssTransportConfig,
        direct_upgrade: DirectUpgradePolicy,
    ) -> Result<Self, NetworkBuildError> {
        let peer_id = identity.public().to_peer_id();
        let (transport, relay_client) = build_endpoint_transport(&identity, wss)?;
        let behaviour =
            EndpointBehaviour::with_direct_upgrade(&identity, relay_client, direct_upgrade);
        let streams = Libp2pApplicationStreams::new(behaviour.stream_control());
        let swarm = Swarm::new(transport, behaviour, peer_id, Config::with_tokio_executor());
        Ok(Self {
            peer_id,
            swarm,
            streams,
        })
    }

    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn streams(&mut self) -> &mut Libp2pApplicationStreams {
        &mut self.streams
    }

    /// Starts the six ephemeral direct listeners frozen for endpoints.
    pub fn listen_on_defaults(&mut self) -> Result<(), NetworkNodeError> {
        for address in default_endpoint_listeners() {
            self.swarm
                .listen_on(address)
                .map_err(NetworkNodeError::Listen)?;
        }
        Ok(())
    }

    /// Starts a relay reservation listener through the already pinned relay address.
    pub fn reserve(
        &mut self,
        relay: &EndpointRelayAddress,
    ) -> Result<ListenerId, NetworkNodeError> {
        let address = relay
            .as_multiaddr()
            .clone()
            .with(libp2p::multiaddr::Protocol::P2pCircuit);
        self.swarm
            .listen_on(address)
            .map_err(NetworkNodeError::Listen)
    }

    pub fn dial_relay(
        &mut self,
        relay: &EndpointRelayAddress,
    ) -> Result<ConnectionId, NetworkNodeError> {
        let options = DialOpts::from(relay.as_multiaddr().clone());
        let connection = options.connection_id();
        self.swarm.dial(options).map_err(NetworkNodeError::Dial)?;
        Ok(connection)
    }

    /// Dials a fully validated or internally constructed address.
    pub fn dial(&mut self, address: Multiaddr) -> Result<(), NetworkNodeError> {
        self.swarm.dial(address).map_err(NetworkNodeError::Dial)
    }

    pub async fn next_event(&mut self) -> SwarmEvent<EndpointBehaviourEvent> {
        self.swarm.select_next_some().await
    }

    pub fn swarm(&self) -> &Swarm<EndpointBehaviour> {
        &self.swarm
    }

    pub fn swarm_mut(&mut self) -> &mut Swarm<EndpointBehaviour> {
        &mut self.swarm
    }
}

/// A relay-server Swarm and its isolated registry/resolve stream control.
pub struct RelayNode {
    peer_id: PeerId,
    swarm: Swarm<RelayBehaviour>,
    streams: Libp2pApplicationStreams,
}

impl RelayNode {
    /// Constructs the relay stack without binding any implicit listener.
    pub fn new(identity: Keypair, wss: WssTransportConfig) -> Result<Self, NetworkBuildError> {
        let resources = RelayResourceConfig::default();
        Self::with_limits(identity, wss, resources.registration(), resources.circuit())
    }

    /// Constructs the relay stack with validated reservation and circuit limits.
    pub fn with_limits(
        identity: Keypair,
        wss: WssTransportConfig,
        registration: RegistrationLimits,
        circuit: CircuitRelayLimits,
    ) -> Result<Self, NetworkBuildError> {
        let peer_id = identity.public().to_peer_id();
        let transport = build_relay_transport(&identity, wss)?;
        let behaviour = RelayBehaviour::with_limits(&identity, registration, circuit);
        let streams = Libp2pApplicationStreams::new(behaviour.stream_control());
        let swarm = Swarm::new(transport, behaviour, peer_id, Config::with_tokio_executor());
        Ok(Self {
            peer_id,
            swarm,
            streams,
        })
    }

    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn streams(&mut self) -> &mut Libp2pApplicationStreams {
        &mut self.streams
    }

    pub fn listen(&mut self, address: &RelayListenAddress) -> Result<ListenerId, NetworkNodeError> {
        self.swarm
            .listen_on(address.as_multiaddr().clone())
            .map_err(NetworkNodeError::Listen)
    }

    pub fn add_external_address(&mut self, address: &RelayExternalAddress) {
        self.swarm
            .add_external_address(address.as_multiaddr().clone());
    }

    pub async fn next_event(&mut self) -> SwarmEvent<RelayBehaviourEvent> {
        self.swarm.select_next_some().await
    }

    pub fn swarm(&self) -> &Swarm<RelayBehaviour> {
        &self.swarm
    }

    pub fn swarm_mut(&mut self) -> &mut Swarm<RelayBehaviour> {
        &mut self.swarm
    }
}

fn default_endpoint_listeners() -> [Multiaddr; 6] {
    [
        "/ip4/0.0.0.0/udp/0/quic-v1"
            .parse()
            .expect("frozen listener is valid"),
        "/ip6/::/udp/0/quic-v1"
            .parse()
            .expect("frozen listener is valid"),
        "/ip4/0.0.0.0/tcp/0"
            .parse()
            .expect("frozen listener is valid"),
        "/ip6/::/tcp/0".parse().expect("frozen listener is valid"),
        "/ip4/0.0.0.0/tcp/0/ws"
            .parse()
            .expect("frozen listener is valid"),
        "/ip6/::/tcp/0/ws"
            .parse()
            .expect("frozen listener is valid"),
    ]
}

use futures::StreamExt as _;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{EndpointNode, RelayNode};
    use crate::{
        DirectUpgradePolicy, EndpointRelayAddress, RelayExternalAddress, RelayListenAddress,
        WssTransportConfig,
    };
    use libp2p::Multiaddr;
    use libp2p::identity::Keypair;
    use std::time::Duration;

    #[tokio::test(flavor = "current_thread")]
    async fn endpoint_and_relay_nodes_expose_the_frozen_runtime_operations() {
        let endpoint_identity = Keypair::generate_ed25519();
        let endpoint_peer = endpoint_identity.public().to_peer_id();
        let mut endpoint =
            EndpointNode::new(endpoint_identity, WssTransportConfig::client(None)).unwrap();
        assert_eq!(endpoint.peer_id(), endpoint_peer);
        let _ = endpoint.streams();
        assert_eq!(*endpoint.swarm().local_peer_id(), endpoint_peer);
        assert_eq!(*endpoint.swarm_mut().local_peer_id(), endpoint_peer);
        let fallback_identity = Keypair::generate_ed25519();
        let fallback_peer = fallback_identity.public().to_peer_id();
        let fallback = EndpointNode::with_direct_upgrade(
            fallback_identity,
            WssTransportConfig::client(None),
            DirectUpgradePolicy::Disabled,
        )
        .unwrap();
        assert_eq!(fallback.peer_id(), fallback_peer);
        endpoint.listen_on_defaults().unwrap();
        tokio::time::timeout(Duration::from_secs(1), endpoint.next_event())
            .await
            .unwrap();
        endpoint.dial(Multiaddr::empty()).unwrap();

        let relay_identity = Keypair::generate_ed25519();
        let relay_peer = relay_identity.public().to_peer_id();
        let relay_address: EndpointRelayAddress = format!("/ip4/127.0.0.1/tcp/1/p2p/{relay_peer}")
            .parse()
            .unwrap();
        endpoint.dial_relay(&relay_address).unwrap();
        endpoint.reserve(&relay_address).unwrap();

        let mut relay = RelayNode::new(relay_identity, WssTransportConfig::client(None)).unwrap();
        assert_eq!(relay.peer_id(), relay_peer);
        let _ = relay.streams();
        assert_eq!(*relay.swarm().local_peer_id(), relay_peer);
        assert_eq!(*relay.swarm_mut().local_peer_id(), relay_peer);
        let listen: RelayListenAddress = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        relay.listen(&listen).unwrap();
        let external: RelayExternalAddress = "/ip4/127.0.0.1/tcp/1".parse().unwrap();
        relay.add_external_address(&external);
        tokio::time::timeout(Duration::from_secs(1), relay.next_event())
            .await
            .unwrap();
    }
}
