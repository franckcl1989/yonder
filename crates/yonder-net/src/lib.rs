#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Shared libp2p networking used by every Yonder role.

pub mod address;
pub mod behaviour;
pub mod connection;
pub mod error;
pub mod identity;
pub mod node;
pub mod path;
pub mod streams;
pub mod tasks;
pub mod transport;

pub use address::{
    EndpointRelayAddress, EndpointRelaySet, RelayExternalAddress, RelayListenAddress, RelayPeerId,
    TransportKind,
};
pub use behaviour::{DirectUpgradePolicy, EndpointBehaviour, RelayBehaviour};
pub use connection::{ConnectionBook, ConnectionSelection, SourcePrefix, UniqueConnection};
pub use error::{AddressError, NetworkBuildError};
pub use identity::{decode_identity, encode_identity, peer_id_bytes};
pub use libp2p::core::ConnectedPoint;
pub use libp2p::core::transport::ListenerId;
pub use libp2p::swarm::ConnectionId;
pub use libp2p::{Multiaddr, PeerId, identity::Keypair, multiaddr, ping, relay, swarm};
pub use node::{EndpointNode, NetworkNodeError, RelayNode};
pub use path::{
    CandidateId, CandidatePath, EstablishedOrder, FrozenPathPolicy, PathCandidate, PathPolicy,
    PingSamples,
};
pub use streams::{
    ApplicationStream, ApplicationStreamError, ApplicationStreams, IncomingApplicationStreams,
    Libp2pApplicationStreams,
};
pub use tasks::{CancellationHandle, TaskFailure, TaskGroup, TaskShutdown};
pub use transport::{
    WssTransportConfig, build_endpoint_transport, build_relay_transport, generate_identity,
};
