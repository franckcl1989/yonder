use super::WireBytes;
use crate::enterprise::{EnterpriseProvider, EnterpriseProviders};
use crate::error::{ProtocolError, ProtocolField};
use crate::{Locator, PeerIdBytes, RetryAfter};

/// Fixed length of a client start request: tag plus the 20-bit locator.
pub const START_LEN: usize = 4;
/// Fixed length of a client provider selection: tag plus the provider tag.
pub const SELECT_LEN: usize = 2;
/// Bounded length of an OAuth authorization URL carried to the client.
pub const MAX_AUTHORIZATION_URL_LEN: usize = 2048;
/// Largest encoded relay response: tag, u16 length, and the URL payload.
pub const MAX_RESPONSE_LEN: usize = 3 + MAX_AUTHORIZATION_URL_LEN;

/// The client-to-relay start request: opens one enterprise session for a locator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnterpriseStart(Locator);

impl EnterpriseStart {
    #[must_use]
    pub const fn new(locator: Locator) -> Self {
        Self(locator)
    }

    #[must_use]
    pub const fn locator(self) -> Locator {
        self.0
    }

    #[must_use]
    pub fn encode(self) -> [u8; START_LEN] {
        let mut bytes = [0_u8; START_LEN];
        bytes[0] = 0x01;
        bytes[1..].copy_from_slice(&self.0.to_wire());
        bytes
    }

    /// Decodes one complete start request.
    pub fn decode(message: &[u8]) -> Result<Self, ProtocolError> {
        let bytes: [u8; START_LEN] =
            message
                .try_into()
                .map_err(|_| ProtocolError::InvalidLength {
                    expected: START_LEN,
                    actual: message.len(),
                })?;
        if bytes[0] != 0x01 {
            return Err(ProtocolError::UnknownTag(bytes[0]));
        }
        Locator::from_wire(bytes[1..].try_into().expect("fixed four-byte slice"))
            .map(Self)
            .map_err(|_| ProtocolError::InvalidField(ProtocolField::Locator))
    }
}

/// The client-to-relay provider selection; the chosen provider cannot change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnterpriseSelect(EnterpriseProvider);

impl EnterpriseSelect {
    #[must_use]
    pub const fn new(provider: EnterpriseProvider) -> Self {
        Self(provider)
    }

    #[must_use]
    pub const fn provider(self) -> EnterpriseProvider {
        self.0
    }

    #[must_use]
    pub const fn encode(self) -> [u8; SELECT_LEN] {
        [0x02, self.0.wire_tag()]
    }

    /// Decodes one complete provider selection.
    pub fn decode(message: &[u8]) -> Result<Self, ProtocolError> {
        let bytes: [u8; SELECT_LEN] =
            message
                .try_into()
                .map_err(|_| ProtocolError::InvalidLength {
                    expected: SELECT_LEN,
                    actual: message.len(),
                })?;
        if bytes[0] != 0x02 {
            return Err(ProtocolError::UnknownTag(bytes[0]));
        }
        EnterpriseProvider::from_wire_tag(bytes[1])
            .map(Self)
            .ok_or(ProtocolError::InvalidField(
                ProtocolField::EnterpriseProvider,
            ))
    }
}

/// A bounded OAuth authorization URL sent to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationUrl {
    bytes: [u8; MAX_AUTHORIZATION_URL_LEN],
    len: u16,
}

impl AuthorizationUrl {
    /// Validates and bounds an authorization URL.
    pub fn new(value: &str) -> Result<Self, ProtocolError> {
        let source = value.as_bytes();
        if source.is_empty() || source.len() > MAX_AUTHORIZATION_URL_LEN {
            return Err(ProtocolError::InvalidLength {
                expected: MAX_AUTHORIZATION_URL_LEN,
                actual: source.len(),
            });
        }
        let mut bytes = [0_u8; MAX_AUTHORIZATION_URL_LEN];
        bytes[..source.len()].copy_from_slice(source);
        Ok(Self {
            bytes,
            len: source.len() as u16,
        })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        // The constructor only accepts UTF-8 input, so this never fails.
        std::str::from_utf8(&self.bytes[..usize::from(self.len)])
            .expect("authorization URL bytes are validated UTF-8")
    }
}

/// One relay response on the enterprise resolve substream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnterpriseResolveResponse {
    /// The available authentication platforms, in deterministic order.
    Providers(EnterpriseProviders),
    /// The session was deferred by rate or capacity limits.
    Retry(RetryAfter),
    /// The client must open this URL in the user's browser.
    Authenticate(Box<AuthorizationUrl>),
    /// The target locator resolved after successful authentication.
    Resolved(PeerIdBytes),
    /// The session was cancelled.
    Cancelled,
    /// The session expired before completing.
    Expired,
    /// Authentication failed or the member was rejected.
    Failed,
    /// The target locator is not available.
    Unavailable,
}

impl EnterpriseResolveResponse {
    #[must_use]
    pub fn encode(&self) -> WireBytes<MAX_RESPONSE_LEN> {
        let mut bytes = [0_u8; MAX_RESPONSE_LEN];
        let len = match self {
            Self::Providers(providers) => {
                bytes[0] = 0x10;
                bytes[1] = providers.wire_mask();
                2
            }
            Self::Retry(retry) => {
                bytes[0] = 0x11;
                bytes[1..5].copy_from_slice(&retry.millis().to_be_bytes());
                5
            }
            Self::Authenticate(url) => {
                bytes[0] = 0x12;
                let url_bytes = url.as_str().as_bytes();
                bytes[1..3].copy_from_slice(&(url_bytes.len() as u16).to_be_bytes());
                bytes[3..3 + url_bytes.len()].copy_from_slice(url_bytes);
                3 + url_bytes.len()
            }
            Self::Resolved(peer) => {
                bytes[0] = 0x13;
                bytes[1] = peer.as_bytes().len() as u8;
                bytes[2..2 + peer.as_bytes().len()].copy_from_slice(peer.as_bytes());
                2 + peer.as_bytes().len()
            }
            Self::Cancelled => {
                bytes[0] = 0x14;
                1
            }
            Self::Expired => {
                bytes[0] = 0x15;
                1
            }
            Self::Failed => {
                bytes[0] = 0x16;
                1
            }
            Self::Unavailable => {
                bytes[0] = 0x17;
                1
            }
        };
        WireBytes::new(bytes, len)
    }

    /// Decodes one complete relay response.
    pub fn decode(message: &[u8]) -> Result<Self, ProtocolError> {
        let Some((&tag, payload)) = message.split_first() else {
            return Err(ProtocolError::InvalidLength {
                expected: 1,
                actual: 0,
            });
        };
        match tag {
            0x10 => decode_providers(payload),
            0x11 => decode_retry(payload),
            0x12 => decode_authenticate(payload),
            0x13 => decode_resolved(payload),
            0x14 if payload.is_empty() => Ok(Self::Cancelled),
            0x15 if payload.is_empty() => Ok(Self::Expired),
            0x16 if payload.is_empty() => Ok(Self::Failed),
            0x17 if payload.is_empty() => Ok(Self::Unavailable),
            0x14..=0x17 => Err(ProtocolError::TrailingBytes),
            other => Err(ProtocolError::UnknownTag(other)),
        }
    }
}

fn decode_providers(payload: &[u8]) -> Result<EnterpriseResolveResponse, ProtocolError> {
    let [mask] = payload else {
        return Err(ProtocolError::InvalidLength {
            expected: 2,
            actual: payload.len() + 1,
        });
    };
    EnterpriseProviders::from_wire_mask(*mask)
        .map(EnterpriseResolveResponse::Providers)
        .ok_or(ProtocolError::InvalidField(
            ProtocolField::EnterpriseProviders,
        ))
}

fn decode_retry(payload: &[u8]) -> Result<EnterpriseResolveResponse, ProtocolError> {
    let bytes: [u8; 4] = payload
        .try_into()
        .map_err(|_| ProtocolError::InvalidLength {
            expected: 5,
            actual: payload.len() + 1,
        })?;
    RetryAfter::from_millis(u32::from_be_bytes(bytes))
        .map(EnterpriseResolveResponse::Retry)
        .map_err(|_| ProtocolError::InvalidField(ProtocolField::RetryAfter))
}

fn decode_authenticate(payload: &[u8]) -> Result<EnterpriseResolveResponse, ProtocolError> {
    let Some((&hi, rest)) = payload.split_first() else {
        return Err(ProtocolError::InvalidField(ProtocolField::AuthorizationUrl));
    };
    let Some((&lo, url_bytes)) = rest.split_first() else {
        return Err(ProtocolError::InvalidField(ProtocolField::AuthorizationUrl));
    };
    let length = usize::from(u16::from_be_bytes([hi, lo]));
    if url_bytes.len() != length {
        return Err(ProtocolError::InvalidLength {
            expected: 3 + length,
            actual: payload.len() + 1,
        });
    }
    let value = std::str::from_utf8(url_bytes)
        .map_err(|_| ProtocolError::InvalidField(ProtocolField::AuthorizationUrl))?;
    AuthorizationUrl::new(value)
        .map(Box::new)
        .map(EnterpriseResolveResponse::Authenticate)
        .map_err(|_| ProtocolError::InvalidField(ProtocolField::AuthorizationUrl))
}

fn decode_resolved(payload: &[u8]) -> Result<EnterpriseResolveResponse, ProtocolError> {
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
        .map(EnterpriseResolveResponse::Resolved)
        .map_err(|_| ProtocolError::InvalidField(ProtocolField::PeerId))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        AuthorizationUrl, EnterpriseResolveResponse, EnterpriseSelect, EnterpriseStart,
        MAX_AUTHORIZATION_URL_LEN, MAX_RESPONSE_LEN,
    };
    use crate::enterprise::{EnterpriseProvider, EnterpriseProviders};
    use crate::error::{ProtocolError, ProtocolField};
    use crate::{Locator, PeerIdBytes, RetryAfter};

    const LOCATOR: Locator = match Locator::new(0xABCDE) {
        Ok(locator) => locator,
        Err(_) => panic!("test locator"),
    };

    #[test]
    fn start_requests_round_trip() {
        let request = EnterpriseStart::new(LOCATOR);
        assert_eq!(request.locator(), LOCATOR);
        assert_eq!(EnterpriseStart::decode(&request.encode()), Ok(request));
    }

    #[test]
    fn start_requests_fail_closed() {
        assert!(matches!(
            EnterpriseStart::decode(&[]),
            Err(ProtocolError::InvalidLength { .. })
        ));
        assert!(matches!(
            EnterpriseStart::decode(&[0x02, 0, 0, 0]),
            Err(ProtocolError::UnknownTag(0x02))
        ));
        // Every 20-bit value is a legal locator, including zero.
        assert!(EnterpriseStart::decode(&[0x01, 0, 0, 0]).is_ok());
        assert!(matches!(
            EnterpriseStart::decode(&[0x01, 0, 0]),
            Err(ProtocolError::InvalidLength { .. })
        ));
    }

    #[test]
    fn provider_selections_round_trip() {
        for provider in EnterpriseProvider::ALL {
            let select = EnterpriseSelect::new(provider);
            assert_eq!(select.provider(), provider);
            assert_eq!(EnterpriseSelect::decode(&select.encode()), Ok(select));
        }
    }

    #[test]
    fn provider_selections_fail_closed() {
        assert!(matches!(
            EnterpriseSelect::decode(&[0x02, 0x00]),
            Err(ProtocolError::InvalidField(
                ProtocolField::EnterpriseProvider
            ))
        ));
        assert!(matches!(
            EnterpriseSelect::decode(&[0x03, 0x01]),
            Err(ProtocolError::UnknownTag(0x03))
        ));
        assert!(matches!(
            EnterpriseSelect::decode(&[0x02]),
            Err(ProtocolError::InvalidLength { .. })
        ));
    }

    #[test]
    fn authorization_urls_are_bounded_and_utf8() {
        let url = AuthorizationUrl::new("https://provider.example/auth?state=abc").unwrap();
        assert_eq!(url.as_str(), "https://provider.example/auth?state=abc");

        assert!(matches!(
            AuthorizationUrl::new(""),
            Err(ProtocolError::InvalidLength { .. })
        ));
        let oversized = "x".repeat(MAX_AUTHORIZATION_URL_LEN + 1);
        assert!(matches!(
            AuthorizationUrl::new(&oversized),
            Err(ProtocolError::InvalidLength { .. })
        ));
    }

    #[test]
    fn responses_round_trip() {
        let responses = [
            EnterpriseResolveResponse::Providers(EnterpriseProviders::new(true, true).unwrap()),
            EnterpriseResolveResponse::Retry(RetryAfter::from_millis(5_000).unwrap()),
            EnterpriseResolveResponse::Authenticate(Box::new(
                AuthorizationUrl::new("https://provider.example/auth").unwrap(),
            )),
            EnterpriseResolveResponse::Resolved(PeerIdBytes::new(&[1, 2, 3]).unwrap()),
            EnterpriseResolveResponse::Cancelled,
            EnterpriseResolveResponse::Expired,
            EnterpriseResolveResponse::Failed,
            EnterpriseResolveResponse::Unavailable,
        ];
        for response in responses {
            assert_eq!(
                EnterpriseResolveResponse::decode(response.encode().as_slice()),
                Ok(response.clone())
            );
        }
    }

    #[test]
    fn authenticate_responses_carry_the_full_url_and_bounds() {
        let url = "https://provider.example/auth?response_type=code&state=0123456789".to_owned();
        let response =
            EnterpriseResolveResponse::Authenticate(Box::new(AuthorizationUrl::new(&url).unwrap()));
        let encoded = response.encode();
        assert_eq!(encoded.as_slice().len(), 3 + url.len());
        assert_eq!(
            EnterpriseResolveResponse::decode(encoded.as_slice()),
            Ok(response)
        );

        let largest = EnterpriseResolveResponse::Authenticate(Box::new(
            AuthorizationUrl::new(&"x".repeat(MAX_AUTHORIZATION_URL_LEN)).unwrap(),
        ));
        assert_eq!(largest.encode().as_slice().len(), MAX_RESPONSE_LEN);
    }

    #[test]
    fn malformed_responses_fail_closed() {
        assert!(matches!(
            EnterpriseResolveResponse::decode(&[]),
            Err(ProtocolError::InvalidLength { .. })
        ));
        assert_eq!(
            EnterpriseResolveResponse::decode(&[0x10, 0x00]),
            Err(ProtocolError::InvalidField(
                ProtocolField::EnterpriseProviders
            ))
        );
        assert!(matches!(
            EnterpriseResolveResponse::decode(&[0x10]),
            Err(ProtocolError::InvalidLength { .. })
        ));
        assert_eq!(
            EnterpriseResolveResponse::decode(&[0x11, 0, 0, 0, 1]),
            Err(ProtocolError::InvalidField(ProtocolField::RetryAfter))
        );
        assert!(matches!(
            EnterpriseResolveResponse::decode(&[0x12]),
            Err(ProtocolError::InvalidField(ProtocolField::AuthorizationUrl))
        ));
        // A single-character URL is legal; a declared length with no
        // payload or a truncated payload is not.
        assert_eq!(
            EnterpriseResolveResponse::decode(&[0x12, 0, 1, b'a']),
            Ok(EnterpriseResolveResponse::Authenticate(Box::new(
                AuthorizationUrl::new("a").unwrap()
            )))
        );
        assert!(matches!(
            EnterpriseResolveResponse::decode(&[0x12, 0, 1]),
            Err(ProtocolError::InvalidLength { .. })
        ));
        assert!(matches!(
            EnterpriseResolveResponse::decode(&[0x12, 0]),
            Err(ProtocolError::InvalidField(ProtocolField::AuthorizationUrl))
        ));
        assert_eq!(
            EnterpriseResolveResponse::decode(&[0x12, 0, 1, 0xff]),
            Err(ProtocolError::InvalidField(ProtocolField::AuthorizationUrl))
        );
        assert_eq!(
            EnterpriseResolveResponse::decode(&[0x13, 0]),
            Err(ProtocolError::InvalidField(ProtocolField::PeerId))
        );
        assert_eq!(
            EnterpriseResolveResponse::decode(&[0x14, 0]),
            Err(ProtocolError::TrailingBytes)
        );
        assert_eq!(
            EnterpriseResolveResponse::decode(&[0xFF]),
            Err(ProtocolError::UnknownTag(0xFF))
        );
        let oversized = [0_u8; PeerIdBytes::MAX_LEN + 3];
        let mut response = oversized;
        response[0] = 0x13;
        response[1] = (PeerIdBytes::MAX_LEN + 1) as u8;
        assert_eq!(
            EnterpriseResolveResponse::decode(&response),
            Err(ProtocolError::InvalidField(ProtocolField::PeerId))
        );
    }
}
