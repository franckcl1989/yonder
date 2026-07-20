use thiserror::Error;

/// Errors returned while validating operator-provided network addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AddressError {
    #[error("a multiaddress cannot exceed 512 bytes")]
    TooLong,
    #[error("the multiaddress syntax is invalid")]
    InvalidSyntax,
    #[error("the multiaddress uses an unsupported host protocol")]
    UnsupportedHost,
    #[error("the multiaddress uses an unsupported transport sequence")]
    UnsupportedTransport,
    #[error("a dial address cannot use an unspecified IP host")]
    UnspecifiedDialHost,
    #[error("a dial address cannot use port zero")]
    ZeroDialPort,
    #[error("the relay address must end in exactly one PeerId")]
    MissingRelayPeerId,
    #[error("a listen or external address cannot contain a PeerId")]
    UnexpectedPeerId,
    #[error("a relay listen address must use an IP host")]
    ListenRequiresIp,
    #[error("all relay entry addresses must identify the same relay")]
    MixedRelayPeerIds,
    #[error("between one and eight relay entry addresses are required")]
    InvalidRelayAddressCount,
}

/// Failures while constructing a shared libp2p stack.
#[derive(Debug, Error)]
pub enum NetworkBuildError {
    #[error("failed to obtain operating system secure randomness")]
    Random(#[source] yonder_core::RandomError),
    #[error("failed to import the generated Ed25519 identity")]
    Identity(#[source] libp2p::identity::DecodingError),
    #[error("failed to configure the libp2p security upgrade")]
    Security(#[source] libp2p::noise::Error),
    #[error("failed to create the system DNS transport")]
    Dns(#[source] std::io::Error),
    #[error("the WSS certificate or private key is invalid")]
    InvalidTlsMaterial,
}
