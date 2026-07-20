use super::WireBytes;
use crate::error::{ProtocolError, ProtocolField};
use crate::{Locator, PeerIdBytes, RetryAfter};

pub const REQUEST_LEN: usize = 3;
pub const MAX_RESPONSE_LEN: usize = 66;

/// A one-shot target lookup request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolveRequest(Locator);

impl ResolveRequest {
    #[must_use]
    pub const fn new(locator: Locator) -> Self {
        Self(locator)
    }

    #[must_use]
    pub const fn locator(self) -> Locator {
        self.0
    }

    #[must_use]
    pub const fn encode(self) -> [u8; REQUEST_LEN] {
        self.0.to_wire()
    }

    /// Decodes one complete resolve request.
    pub fn decode(message: &[u8]) -> Result<Self, ProtocolError> {
        let bytes: [u8; REQUEST_LEN] =
            message
                .try_into()
                .map_err(|_| ProtocolError::InvalidLength {
                    expected: REQUEST_LEN,
                    actual: message.len(),
                })?;
        Locator::from_wire(bytes)
            .map(Self)
            .map_err(|_| ProtocolError::InvalidField(ProtocolField::Locator))
    }
}

/// A one-shot target lookup response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveResponse {
    Resolved(PeerIdBytes),
    Retry(RetryAfter),
    Unavailable,
}

impl ResolveResponse {
    #[must_use]
    pub fn encode(&self) -> WireBytes<MAX_RESPONSE_LEN> {
        let mut bytes = [0_u8; MAX_RESPONSE_LEN];
        let len = match self {
            Self::Resolved(peer) => {
                bytes[0] = 0x80;
                bytes[1] = peer.as_bytes().len() as u8;
                bytes[2..2 + peer.as_bytes().len()].copy_from_slice(peer.as_bytes());
                2 + peer.as_bytes().len()
            }
            Self::Retry(retry) => {
                bytes[0] = 0x81;
                bytes[1..5].copy_from_slice(&retry.millis().to_be_bytes());
                5
            }
            Self::Unavailable => {
                bytes[0] = 0x82;
                1
            }
        };
        WireBytes::new(bytes, len)
    }

    /// Decodes one complete resolve response.
    pub fn decode(message: &[u8]) -> Result<Self, ProtocolError> {
        let Some((&tag, payload)) = message.split_first() else {
            return Err(ProtocolError::InvalidLength {
                expected: 1,
                actual: 0,
            });
        };
        match tag {
            0x80 => decode_resolved(payload),
            0x81 => decode_retry(payload),
            0x82 if payload.is_empty() => Ok(Self::Unavailable),
            0x82 => Err(ProtocolError::TrailingBytes),
            other => Err(ProtocolError::UnknownTag(other)),
        }
    }
}

fn decode_resolved(payload: &[u8]) -> Result<ResolveResponse, ProtocolError> {
    let Some((&length, peer)) = payload.split_first() else {
        return Err(ProtocolError::InvalidField(ProtocolField::PeerId));
    };
    let length = usize::from(length);
    if peer.len() != length {
        return Err(ProtocolError::InvalidLength {
            expected: length + 2,
            actual: peer.len() + 2,
        });
    }
    PeerIdBytes::new(peer)
        .map(ResolveResponse::Resolved)
        .map_err(|_| ProtocolError::InvalidField(ProtocolField::PeerId))
}

fn decode_retry(payload: &[u8]) -> Result<ResolveResponse, ProtocolError> {
    let bytes: [u8; 4] = payload
        .try_into()
        .map_err(|_| ProtocolError::InvalidLength {
            expected: 5,
            actual: payload.len() + 1,
        })?;
    RetryAfter::from_millis(u32::from_be_bytes(bytes))
        .map(ResolveResponse::Retry)
        .map_err(|_| ProtocolError::InvalidField(ProtocolField::RetryAfter))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{ResolveRequest, ResolveResponse};
    use crate::error::{ProtocolError, ProtocolField};
    use crate::{Locator, PeerIdBytes, RetryAfter};

    #[test]
    fn requests_and_responses_round_trip() {
        let request = ResolveRequest::new(Locator::new(0xABCDE).unwrap());
        assert_eq!(request.locator(), Locator::new(0xABCDE).unwrap());
        assert_eq!(ResolveRequest::decode(&request.encode()), Ok(request));

        for response in [
            ResolveResponse::Resolved(PeerIdBytes::new(&[1, 2, 3]).unwrap()),
            ResolveResponse::Retry(RetryAfter::from_millis(5_000).unwrap()),
            ResolveResponse::Unavailable,
        ] {
            assert_eq!(
                ResolveResponse::decode(response.encode().as_slice()),
                Ok(response)
            );
        }
    }

    #[test]
    fn malformed_responses_fail_closed() {
        assert!(matches!(
            ResolveRequest::decode(&[]),
            Err(ProtocolError::InvalidLength { .. })
        ));
        assert_eq!(
            ResolveRequest::decode(&[0x10, 0, 0]),
            Err(ProtocolError::InvalidField(ProtocolField::Locator))
        );
        assert!(matches!(
            ResolveResponse::decode(&[]),
            Err(ProtocolError::InvalidLength { .. })
        ));
        assert_eq!(
            ResolveResponse::decode(&[0x80, 0]),
            Err(ProtocolError::InvalidField(ProtocolField::PeerId))
        );
        assert_eq!(
            ResolveResponse::decode(&[0x80]),
            Err(ProtocolError::InvalidField(ProtocolField::PeerId))
        );
        assert!(matches!(
            ResolveResponse::decode(&[0x80, 2, 1]),
            Err(ProtocolError::InvalidLength { .. })
        ));
        assert_eq!(
            ResolveResponse::decode(&[0x82, 0]),
            Err(ProtocolError::TrailingBytes)
        );
        assert_eq!(
            ResolveResponse::decode(&[0xFF]),
            Err(ProtocolError::UnknownTag(0xFF))
        );
        assert!(matches!(
            ResolveResponse::decode(&[0x81]),
            Err(ProtocolError::InvalidLength { .. })
        ));
        assert_eq!(
            ResolveResponse::decode(&[0x81, 0, 0, 0, 1]),
            Err(ProtocolError::InvalidField(ProtocolField::RetryAfter))
        );
        let oversized = [0_u8; PeerIdBytes::MAX_LEN + 3];
        let mut response = oversized;
        response[0] = 0x80;
        response[1] = (PeerIdBytes::MAX_LEN + 1) as u8;
        assert_eq!(
            ResolveResponse::decode(&response),
            Err(ProtocolError::InvalidField(ProtocolField::PeerId))
        );
    }
}
