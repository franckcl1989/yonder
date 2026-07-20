use libp2p::identity::Keypair;
use libp2p::{
    autonat, connection_limits, dcutr, identify, memory_connection_limits, ping, relay,
    swarm::{NetworkBehaviour, behaviour::toggle::Toggle},
    upnp,
};
use std::time::Duration;
use yonder_core::{CircuitRelayLimits, RegistrationLimits, RelayResourceConfig};

const IDENTIFY_PROTOCOL: &str = "/yonder/id/1.0.0";
const ENDPOINT_PING_INTERVAL: Duration = Duration::from_secs(1);
const RELAY_PING_INTERVAL: Duration = Duration::from_secs(15);
const PING_TIMEOUT: Duration = Duration::from_millis(750);
#[cfg(not(yonder_sanitizer))]
const ENDPOINT_MEMORY_LIMIT_BYTES: usize = 96 * 1024 * 1024;
#[cfg(not(yonder_sanitizer))]
const RELAY_MEMORY_LIMIT_BYTES: usize = 64 * 1024 * 1024;

// Sanitizer instrumentation raises the idle process RSS above the production limits.
#[cfg(yonder_sanitizer)]
const ENDPOINT_MEMORY_LIMIT_BYTES: usize = 512 * 1024 * 1024;
#[cfg(yonder_sanitizer)]
const RELAY_MEMORY_LIMIT_BYTES: usize = 512 * 1024 * 1024;

/// The endpoint role's composition of official libp2p behaviours.
#[derive(NetworkBehaviour)]
pub struct EndpointBehaviour {
    relay: relay::client::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    dcutr: Toggle<dcutr::Behaviour>,
    upnp: upnp::tokio::Behaviour,
    streams: libp2p_stream::Behaviour,
    connection_limits: connection_limits::Behaviour,
    memory_limits: memory_connection_limits::Behaviour,
}

/// Whether one endpoint Swarm may initiate or accept DCUtR hole punching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectUpgradePolicy {
    Enabled,
    Disabled,
}

impl DirectUpgradePolicy {
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

impl EndpointBehaviour {
    #[must_use]
    pub fn new(identity: &Keypair, relay: relay::client::Behaviour) -> Self {
        Self::with_direct_upgrade(identity, relay, DirectUpgradePolicy::Enabled)
    }

    #[must_use]
    pub fn with_direct_upgrade(
        identity: &Keypair,
        relay: relay::client::Behaviour,
        direct_upgrade: DirectUpgradePolicy,
    ) -> Self {
        let peer_id = identity.public().to_peer_id();
        Self {
            relay,
            identify: identify_behaviour(identity),
            ping: endpoint_ping_behaviour(),
            dcutr: direct_upgrade
                .is_enabled()
                .then(|| dcutr::Behaviour::new(peer_id))
                .into(),
            upnp: upnp::tokio::Behaviour::default(),
            streams: libp2p_stream::Behaviour::new(),
            connection_limits: connection_limits::Behaviour::new(endpoint_connection_limits()),
            memory_limits: memory_connection_limits::Behaviour::with_max_bytes(
                ENDPOINT_MEMORY_LIMIT_BYTES,
            ),
        }
    }

    pub(crate) fn stream_control(&self) -> libp2p_stream::Control {
        self.streams.new_control()
    }
}

/// The server role's composition of the same base stack and relay-specific behaviours.
#[derive(NetworkBehaviour)]
pub struct RelayBehaviour {
    relay: relay::Behaviour,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    autonat: autonat::v2::server::Behaviour,
    streams: libp2p_stream::Behaviour,
    connection_limits: connection_limits::Behaviour,
    memory_limits: memory_connection_limits::Behaviour,
}

impl RelayBehaviour {
    #[must_use]
    pub fn new(identity: &Keypair) -> Self {
        let resources = RelayResourceConfig::default();
        Self::with_limits(identity, resources.registration(), resources.circuit())
    }

    /// Constructs the relay behaviour with a validated resource policy.
    #[must_use]
    pub fn with_limits(
        identity: &Keypair,
        registration: RegistrationLimits,
        circuit: CircuitRelayLimits,
    ) -> Self {
        let peer_id = identity.public().to_peer_id();
        Self {
            relay: relay::Behaviour::new(peer_id, relay_config(registration, circuit)),
            identify: identify_behaviour(identity),
            ping: relay_ping_behaviour(),
            autonat: autonat::v2::server::Behaviour::default(),
            streams: libp2p_stream::Behaviour::new(),
            connection_limits: connection_limits::Behaviour::new(relay_connection_limits()),
            memory_limits: memory_connection_limits::Behaviour::with_max_bytes(
                RELAY_MEMORY_LIMIT_BYTES,
            ),
        }
    }

    pub(crate) fn stream_control(&self) -> libp2p_stream::Control {
        self.streams.new_control()
    }
}

fn identify_behaviour(identity: &Keypair) -> identify::Behaviour {
    let config =
        identify::Config::new_with_signed_peer_record(IDENTIFY_PROTOCOL.to_owned(), identity)
            .with_agent_version(format!("yonder/{}", env!("CARGO_PKG_VERSION")))
            .with_push_listen_addr_updates(true)
            .with_cache_size(128);
    identify::Behaviour::new(config)
}

fn endpoint_ping_behaviour() -> ping::Behaviour {
    ping::Behaviour::new(
        ping::Config::new()
            .with_interval(ENDPOINT_PING_INTERVAL)
            .with_timeout(PING_TIMEOUT),
    )
}

fn relay_ping_behaviour() -> ping::Behaviour {
    ping::Behaviour::new(
        ping::Config::new()
            .with_interval(RELAY_PING_INTERVAL)
            .with_timeout(PING_TIMEOUT),
    )
}

fn endpoint_connection_limits() -> connection_limits::ConnectionLimits {
    connection_limits::ConnectionLimits::default()
        .with_max_pending_incoming(Some(16))
        .with_max_pending_outgoing(Some(16))
        .with_max_established_incoming(Some(16))
        .with_max_established_outgoing(Some(16))
        .with_max_established(Some(24))
        .with_max_established_per_peer(Some(8))
}

fn relay_connection_limits() -> connection_limits::ConnectionLimits {
    connection_limits::ConnectionLimits::default()
        .with_max_pending_incoming(Some(128))
        .with_max_pending_outgoing(Some(64))
        .with_max_established_incoming(Some(320))
        .with_max_established_outgoing(Some(64))
        .with_max_established(Some(320))
        .with_max_established_per_peer(Some(8))
}

fn relay_config(registration: RegistrationLimits, circuit: CircuitRelayLimits) -> relay::Config {
    relay::Config {
        max_reservations: registration.capacity().get(),
        max_reservations_per_peer: 1,
        reservation_duration: registration.reservation_duration().duration(),
        max_circuits: circuit.capacity().get(),
        max_circuits_per_peer: 1,
        max_circuit_duration: circuit.duration().duration(),
        max_circuit_bytes: circuit.bytes().get(),
        ..relay::Config::default()
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        DirectUpgradePolicy, ENDPOINT_MEMORY_LIMIT_BYTES, EndpointBehaviour,
        RELAY_MEMORY_LIMIT_BYTES, RelayBehaviour, relay_config,
    };
    use libp2p::{PeerId, identity::Keypair, relay};
    use yonder_core::{
        CircuitBytes, CircuitCapacity, CircuitDuration, CircuitRelayLimits, RegistrationCapacity,
        RegistrationLimits, ReservationDuration, SourceRegistrationCapacity,
    };

    #[tokio::test(flavor = "current_thread")]
    async fn all_role_behaviours_construct() {
        let identity = Keypair::generate_ed25519();
        let (_, relay_client) = relay::client::new(PeerId::from(identity.public()));
        let _endpoint = EndpointBehaviour::new(&identity, relay_client);
        let (_, relay_client) = relay::client::new(PeerId::from(identity.public()));
        let _relay_only = EndpointBehaviour::with_direct_upgrade(
            &identity,
            relay_client,
            DirectUpgradePolicy::Disabled,
        );
        assert!(DirectUpgradePolicy::Enabled.is_enabled());
        assert!(!DirectUpgradePolicy::Disabled.is_enabled());
        let _relay = RelayBehaviour::new(&identity);
        let registration = RegistrationLimits::new(
            RegistrationCapacity::new(1).unwrap(),
            SourceRegistrationCapacity::new(1).unwrap(),
            ReservationDuration::from_seconds(60).unwrap(),
        )
        .unwrap();
        let circuit = CircuitRelayLimits::new(
            CircuitCapacity::new(1).unwrap(),
            CircuitDuration::from_seconds(60).unwrap(),
            CircuitBytes::new(CircuitBytes::MIN).unwrap(),
        );
        let _configured = RelayBehaviour::with_limits(&identity, registration, circuit);
        let configured = relay_config(registration, circuit);
        assert_eq!(configured.max_reservations, 1);
        assert_eq!(configured.max_reservations_per_peer, 1);
        assert_eq!(
            configured.reservation_duration,
            std::time::Duration::from_secs(60)
        );
        assert_eq!(configured.max_circuits, 1);
        assert_eq!(configured.max_circuits_per_peer, 1);
        assert_eq!(
            configured.max_circuit_duration,
            std::time::Duration::from_secs(60)
        );
        assert_eq!(configured.max_circuit_bytes, CircuitBytes::MIN);
    }

    #[test]
    fn memory_limits_match_the_build_purpose() {
        #[cfg(not(yonder_sanitizer))]
        {
            assert_eq!(ENDPOINT_MEMORY_LIMIT_BYTES, 96 * 1024 * 1024);
            assert_eq!(RELAY_MEMORY_LIMIT_BYTES, 64 * 1024 * 1024);
        }
        #[cfg(yonder_sanitizer)]
        {
            assert_eq!(ENDPOINT_MEMORY_LIMIT_BYTES, 512 * 1024 * 1024);
            assert_eq!(RELAY_MEMORY_LIMIT_BYTES, 512 * 1024 * 1024);
        }
    }
}
