use libp2p::PeerId;
use libp2p::identity::{DecodingError, Keypair};
use yonder_core::{DomainError, PeerIdBytes, SecretDocument};

/// Encodes an identity for an atomic secret-file write.
pub fn encode_identity(identity: &Keypair) -> Result<SecretDocument, DecodingError> {
    identity.to_protobuf_encoding().map(SecretDocument::new)
}

/// Decodes a bounded identity document.
pub fn decode_identity(document: &[u8]) -> Result<Keypair, DecodingError> {
    Keypair::from_protobuf_encoding(document)
}

/// Converts libp2p's authenticated identity into the bounded wire representation.
pub fn peer_id_bytes(peer: PeerId) -> Result<PeerIdBytes, DomainError> {
    PeerIdBytes::new(&peer.to_bytes())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{decode_identity, encode_identity, peer_id_bytes};
    use libp2p::identity::Keypair;

    #[test]
    fn identity_document_round_trips() {
        let identity = Keypair::generate_ed25519();
        let expected = identity.public().to_peer_id();
        let encoded = encode_identity(&identity).unwrap();
        let decoded = decode_identity(encoded.as_bytes()).unwrap();
        assert_eq!(decoded.public().to_peer_id(), expected);
    }

    #[test]
    fn peer_ids_fit_the_wire_identity_bound() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        assert_eq!(peer_id_bytes(peer).unwrap().as_bytes(), peer.to_bytes());
    }
}
