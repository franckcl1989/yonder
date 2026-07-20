use crate::error::{ProtocolError, ProtocolField};
use crate::{Locator, RetryAfter};

pub const REQUEST_LEN: usize = 4;
pub const RESPONSE_LEN: usize = 5;

/// A one-shot relay registration request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryRequest {
    Allocate,
    Reclaim(Locator),
    Release(Locator),
}

impl RegistryRequest {
    #[must_use]
    pub const fn encode(self) -> [u8; REQUEST_LEN] {
        match self {
            Self::Allocate => [0x01, 0, 0, 0],
            Self::Reclaim(locator) => with_locator(0x02, locator),
            Self::Release(locator) => with_locator(0x03, locator),
        }
    }

    /// Decodes one complete registry request.
    pub fn decode(message: &[u8]) -> Result<Self, ProtocolError> {
        let bytes: [u8; REQUEST_LEN] =
            message
                .try_into()
                .map_err(|_| ProtocolError::InvalidLength {
                    expected: REQUEST_LEN,
                    actual: message.len(),
                })?;
        match bytes[0] {
            0x01 if bytes[1..] == [0, 0, 0] => Ok(Self::Allocate),
            0x01 => Err(ProtocolError::InvalidField(ProtocolField::Reserved)),
            0x02 => decode_locator(bytes).map(Self::Reclaim),
            0x03 => decode_locator(bytes).map(Self::Release),
            tag => Err(ProtocolError::UnknownTag(tag)),
        }
    }
}

/// A one-shot relay registration response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryResponse {
    Acquired(Locator),
    Released,
    Retry(RetryAfter),
    Conflict,
    Capacity,
    ReservationRequired,
}

impl RegistryResponse {
    #[must_use]
    pub const fn encode(self) -> [u8; RESPONSE_LEN] {
        let (tag, value) = match self {
            Self::Acquired(locator) => (0x80, locator.get()),
            Self::Released => (0x81, 0),
            Self::Retry(retry) => (0x82, retry.millis()),
            Self::Conflict => (0x83, 0),
            Self::Capacity => (0x84, 0),
            Self::ReservationRequired => (0x85, 0),
        };
        let value = value.to_be_bytes();
        [tag, value[0], value[1], value[2], value[3]]
    }

    /// Decodes one complete registry response.
    pub fn decode(message: &[u8]) -> Result<Self, ProtocolError> {
        let bytes: [u8; RESPONSE_LEN] =
            message
                .try_into()
                .map_err(|_| ProtocolError::InvalidLength {
                    expected: RESPONSE_LEN,
                    actual: message.len(),
                })?;
        let value = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        match bytes[0] {
            0x80 => Locator::new(value)
                .map(Self::Acquired)
                .map_err(|_| ProtocolError::InvalidField(ProtocolField::Locator)),
            0x81 => zero_value(value, Self::Released),
            0x82 => RetryAfter::from_millis(value)
                .map(Self::Retry)
                .map_err(|_| ProtocolError::InvalidField(ProtocolField::RetryAfter)),
            0x83 => zero_value(value, Self::Conflict),
            0x84 => zero_value(value, Self::Capacity),
            0x85 => zero_value(value, Self::ReservationRequired),
            tag => Err(ProtocolError::UnknownTag(tag)),
        }
    }
}

const fn with_locator(tag: u8, locator: Locator) -> [u8; REQUEST_LEN] {
    let locator = locator.to_wire();
    [tag, locator[0], locator[1], locator[2]]
}

fn decode_locator(bytes: [u8; REQUEST_LEN]) -> Result<Locator, ProtocolError> {
    Locator::from_wire([bytes[1], bytes[2], bytes[3]])
        .map_err(|_| ProtocolError::InvalidField(ProtocolField::Locator))
}

fn zero_value(value: u32, response: RegistryResponse) -> Result<RegistryResponse, ProtocolError> {
    if value == 0 {
        Ok(response)
    } else {
        Err(ProtocolError::InvalidField(ProtocolField::Reserved))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{RegistryRequest, RegistryResponse};
    use crate::error::{ProtocolError, ProtocolField};
    use crate::{Locator, RetryAfter};

    #[test]
    fn requests_round_trip() {
        for request in [
            RegistryRequest::Allocate,
            RegistryRequest::Reclaim(Locator::new(0xABCDE).unwrap()),
            RegistryRequest::Release(Locator::new(0xFFFFF).unwrap()),
        ] {
            assert_eq!(RegistryRequest::decode(&request.encode()), Ok(request));
        }
    }

    #[test]
    fn responses_round_trip() {
        for response in [
            RegistryResponse::Acquired(Locator::new(7).unwrap()),
            RegistryResponse::Released,
            RegistryResponse::Retry(RetryAfter::from_millis(100).unwrap()),
            RegistryResponse::Conflict,
            RegistryResponse::Capacity,
            RegistryResponse::ReservationRequired,
        ] {
            assert_eq!(RegistryResponse::decode(&response.encode()), Ok(response));
        }
    }

    #[test]
    fn invalid_lengths_tags_and_reserved_fields_fail() {
        assert!(matches!(
            RegistryRequest::decode(&[]),
            Err(ProtocolError::InvalidLength { .. })
        ));
        assert_eq!(
            RegistryRequest::decode(&[0x01, 0, 0, 1]),
            Err(ProtocolError::InvalidField(ProtocolField::Reserved))
        );
        assert_eq!(
            RegistryRequest::decode(&[0xFF, 0, 0, 0]),
            Err(ProtocolError::UnknownTag(0xFF))
        );
        assert_eq!(
            RegistryResponse::decode(&[0x81, 0, 0, 0, 1]),
            Err(ProtocolError::InvalidField(ProtocolField::Reserved))
        );
        assert!(matches!(
            RegistryResponse::decode(&[]),
            Err(ProtocolError::InvalidLength { .. })
        ));
        assert_eq!(
            RegistryRequest::decode(&[0x02, 0x10, 0, 0]),
            Err(ProtocolError::InvalidField(ProtocolField::Locator))
        );
        assert_eq!(
            RegistryResponse::decode(&[0x80, 0x10, 0, 0, 0]),
            Err(ProtocolError::InvalidField(ProtocolField::Locator))
        );
        assert_eq!(
            RegistryResponse::decode(&[0x82, 0, 0, 0, 1]),
            Err(ProtocolError::InvalidField(ProtocolField::RetryAfter))
        );
        for tag in [0x83, 0x84, 0x85] {
            assert_eq!(
                RegistryResponse::decode(&[tag, 0, 0, 0, 1]),
                Err(ProtocolError::InvalidField(ProtocolField::Reserved))
            );
        }
        assert_eq!(
            RegistryResponse::decode(&[0xFF, 0, 0, 0, 0]),
            Err(ProtocolError::UnknownTag(0xFF))
        );
    }
}
