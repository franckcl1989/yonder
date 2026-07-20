#![forbid(unsafe_code)]

use yonder_net::swarm::NetworkBehaviour as _;
use yonder_net::{EndpointBehaviour, Keypair, Multiaddr, PeerId, RelayBehaviour, relay};

use libp2p::core::Endpoint;
use libp2p::core::transport::PortUse;
use libp2p::swarm::ConnectionId;

#[tokio::test(flavor = "current_thread")]
async fn composed_behaviours_accept_connection_lifecycle_callbacks() {
    let identity = Keypair::generate_ed25519();
    let peer = Keypair::generate_ed25519().public().to_peer_id();
    let local: Multiaddr = "/ip4/127.0.0.1/tcp/1".parse().unwrap();
    let remote: Multiaddr = "/ip4/127.0.0.1/tcp/2".parse().unwrap();
    let addresses = [remote.clone()];

    let (_, relay_client) = relay::client::new(PeerId::from(identity.public()));
    let mut endpoint = EndpointBehaviour::new(&identity, relay_client);
    assert!(
        endpoint
            .handle_pending_inbound_connection(ConnectionId::new_unchecked(1), &local, &remote)
            .is_ok()
    );
    assert!(
        endpoint
            .handle_pending_outbound_connection(
                ConnectionId::new_unchecked(2),
                Some(peer),
                &addresses,
                Endpoint::Dialer,
            )
            .is_ok()
    );
    assert!(
        endpoint
            .handle_established_inbound_connection(
                ConnectionId::new_unchecked(1),
                peer,
                &local,
                &remote,
            )
            .is_ok()
    );
    assert!(
        endpoint
            .handle_established_outbound_connection(
                ConnectionId::new_unchecked(2),
                peer,
                &remote,
                Endpoint::Dialer,
                PortUse::New,
            )
            .is_ok()
    );

    let mut relay = RelayBehaviour::new(&identity);
    assert!(
        relay
            .handle_pending_inbound_connection(ConnectionId::new_unchecked(3), &local, &remote)
            .is_ok()
    );
    assert!(
        relay
            .handle_pending_outbound_connection(
                ConnectionId::new_unchecked(4),
                Some(peer),
                &addresses,
                Endpoint::Dialer,
            )
            .is_ok()
    );
    assert!(
        relay
            .handle_established_inbound_connection(
                ConnectionId::new_unchecked(3),
                peer,
                &local,
                &remote,
            )
            .is_ok()
    );
    assert!(
        relay
            .handle_established_outbound_connection(
                ConnectionId::new_unchecked(4),
                peer,
                &remote,
                Endpoint::Dialer,
                PortUse::New,
            )
            .is_ok()
    );
}
