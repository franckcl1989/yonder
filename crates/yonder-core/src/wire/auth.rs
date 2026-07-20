use super::{AUTH_PROTOCOL, WireBytes};
use crate::error::{ProtocolError, ProtocolField};
use crate::{Locator, PeerIdBytes, RetryAfter};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const NONCE_LEN: usize = 32;
pub const KE1_LEN: usize = 96;
pub const KE2_LEN: usize = 320;
pub const KE3_LEN: usize = 64;
pub const CLIENT_HELLO_LEN: usize = NONCE_LEN + KE1_LEN;
pub const PROCEED_LEN: usize = 1 + NONCE_LEN + KE2_LEN;
pub const RETRY_LEN: usize = 5;
pub const MAX_CONTEXT_LEN: usize = 256;

/// The context that binds OPAQUE to the selected authenticated peer identities.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PakeContext {
    bytes: [u8; MAX_CONTEXT_LEN],
    len: u8,
}

impl PakeContext {
    /// Builds the exact versioned context without heap allocation.
    pub fn new(
        locator: Locator,
        controller: &PeerIdBytes,
        target: &PeerIdBytes,
        controller_nonce: &[u8; NONCE_LEN],
        target_nonce: &[u8; NONCE_LEN],
    ) -> Self {
        let mut bytes = [0_u8; MAX_CONTEXT_LEN];
        let mut cursor = 0;
        append(&mut bytes, &mut cursor, AUTH_PROTOCOL.as_bytes());
        append(&mut bytes, &mut cursor, &locator.to_wire());
        append(
            &mut bytes,
            &mut cursor,
            &[controller.as_bytes().len() as u8],
        );
        append(&mut bytes, &mut cursor, controller.as_bytes());
        append(&mut bytes, &mut cursor, &[target.as_bytes().len() as u8]);
        append(&mut bytes, &mut cursor, target.as_bytes());
        append(&mut bytes, &mut cursor, controller_nonce);
        append(&mut bytes, &mut cursor, target_nonce);
        Self {
            bytes,
            len: cursor as u8,
        }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

fn append(destination: &mut [u8; MAX_CONTEXT_LEN], cursor: &mut usize, source: &[u8]) {
    let end = *cursor + source.len();
    destination[*cursor..end].copy_from_slice(source);
    *cursor = end;
}

/// The controller's first authentication message.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AuthClientHello {
    nonce: [u8; NONCE_LEN],
    ke1: [u8; KE1_LEN],
}

impl AuthClientHello {
    #[must_use]
    pub const fn new(nonce: [u8; NONCE_LEN], ke1: [u8; KE1_LEN]) -> Self {
        Self { nonce, ke1 }
    }

    #[must_use]
    pub const fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    #[must_use]
    pub const fn ke1(&self) -> &[u8; KE1_LEN] {
        &self.ke1
    }

    #[must_use]
    pub fn encode(&self) -> [u8; CLIENT_HELLO_LEN] {
        let mut bytes = [0_u8; CLIENT_HELLO_LEN];
        bytes[..NONCE_LEN].copy_from_slice(&self.nonce);
        bytes[NONCE_LEN..].copy_from_slice(&self.ke1);
        bytes
    }

    /// Decodes the exact fixed-size client hello.
    pub fn decode(message: &[u8]) -> Result<Self, ProtocolError> {
        let bytes: [u8; CLIENT_HELLO_LEN] =
            message
                .try_into()
                .map_err(|_| ProtocolError::InvalidLength {
                    expected: CLIENT_HELLO_LEN,
                    actual: message.len(),
                })?;
        let mut nonce = [0_u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[..NONCE_LEN]);
        let mut ke1 = [0_u8; KE1_LEN];
        ke1.copy_from_slice(&bytes[NONCE_LEN..]);
        Ok(Self::new(nonce, ke1))
    }
}

/// The target's response to a structurally valid client hello.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AuthServerResponse {
    #[zeroize(skip)]
    kind: AuthServerResponseKind,
    nonce: [u8; NONCE_LEN],
    ke2: [u8; KE2_LEN],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthServerResponseKind {
    Proceed,
    Retry(RetryAfter),
}

impl AuthServerResponse {
    #[must_use]
    pub const fn proceed(nonce: [u8; NONCE_LEN], ke2: [u8; KE2_LEN]) -> Self {
        Self {
            kind: AuthServerResponseKind::Proceed,
            nonce,
            ke2,
        }
    }

    #[must_use]
    pub const fn retry(after: RetryAfter) -> Self {
        Self {
            kind: AuthServerResponseKind::Retry(after),
            nonce: [0; NONCE_LEN],
            ke2: [0; KE2_LEN],
        }
    }

    #[must_use]
    pub const fn proceed_parts(&self) -> Option<(&[u8; NONCE_LEN], &[u8; KE2_LEN])> {
        match self.kind {
            AuthServerResponseKind::Proceed => Some((&self.nonce, &self.ke2)),
            AuthServerResponseKind::Retry(_) => None,
        }
    }

    #[must_use]
    pub const fn retry_after(&self) -> Option<RetryAfter> {
        match self.kind {
            AuthServerResponseKind::Proceed => None,
            AuthServerResponseKind::Retry(after) => Some(after),
        }
    }

    #[must_use]
    pub fn encode(&self) -> WireBytes<PROCEED_LEN> {
        let mut bytes = [0_u8; PROCEED_LEN];
        let len = match self.kind {
            AuthServerResponseKind::Proceed => {
                bytes[0] = 0x01;
                bytes[1..1 + NONCE_LEN].copy_from_slice(&self.nonce);
                bytes[1 + NONCE_LEN..].copy_from_slice(&self.ke2);
                PROCEED_LEN
            }
            AuthServerResponseKind::Retry(after) => {
                bytes[0] = 0x02;
                bytes[1..RETRY_LEN].copy_from_slice(&after.millis().to_be_bytes());
                RETRY_LEN
            }
        };
        WireBytes::new(bytes, len)
    }

    /// Decodes a complete proceed or retry response.
    pub fn decode(message: &[u8]) -> Result<Self, ProtocolError> {
        let Some(&tag) = message.first() else {
            return Err(ProtocolError::InvalidLength {
                expected: 1,
                actual: 0,
            });
        };
        match tag {
            0x01 => {
                if message.len() != PROCEED_LEN {
                    return Err(ProtocolError::InvalidLength {
                        expected: PROCEED_LEN,
                        actual: message.len(),
                    });
                }
                let mut nonce = [0_u8; NONCE_LEN];
                nonce.copy_from_slice(&message[1..1 + NONCE_LEN]);
                let mut ke2 = [0_u8; KE2_LEN];
                ke2.copy_from_slice(&message[1 + NONCE_LEN..]);
                Ok(Self::proceed(nonce, ke2))
            }
            0x02 => {
                let bytes: [u8; 4] = message
                    .get(1..)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or(ProtocolError::InvalidLength {
                        expected: RETRY_LEN,
                        actual: message.len(),
                    })?;
                let after = RetryAfter::from_millis(u32::from_be_bytes(bytes))
                    .map_err(|_| ProtocolError::InvalidField(ProtocolField::RetryAfter))?;
                Ok(Self::retry(after))
            }
            other => Err(ProtocolError::UnknownTag(other)),
        }
    }
}

impl std::fmt::Debug for AuthServerResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            AuthServerResponseKind::Proceed => {
                formatter.write_str("AuthServerResponse::Proceed([REDACTED])")
            }
            AuthServerResponseKind::Retry(after) => formatter
                .debug_tuple("AuthServerResponse::Retry")
                .field(&after)
                .finish(),
        }
    }
}

/// The controller's fixed-size KE3 message.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AuthClientFinish([u8; KE3_LEN]);

impl AuthClientFinish {
    #[must_use]
    pub const fn new(ke3: [u8; KE3_LEN]) -> Self {
        Self(ke3)
    }

    #[must_use]
    pub const fn ke3(&self) -> &[u8; KE3_LEN] {
        &self.0
    }

    /// Decodes the exact fixed-size client finish.
    pub fn decode(message: &[u8]) -> Result<Self, ProtocolError> {
        let bytes = message
            .try_into()
            .map_err(|_| ProtocolError::InvalidLength {
                expected: KE3_LEN,
                actual: message.len(),
            })?;
        Ok(Self(bytes))
    }
}

/// Authentication succeeded and the unique connection is authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authenticated;

impl Authenticated {
    pub const ENCODED: [u8; 1] = [0x03];

    /// Decodes the final one-byte acknowledgement.
    pub fn decode(message: &[u8]) -> Result<Self, ProtocolError> {
        match message {
            [0x03] => Ok(Self),
            [tag] => Err(ProtocolError::UnknownTag(*tag)),
            _ => Err(ProtocolError::InvalidLength {
                expected: 1,
                actual: message.len(),
            }),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        AuthClientFinish, AuthClientHello, AuthServerResponse, Authenticated, PakeContext,
    };
    use crate::error::{ProtocolError, ProtocolField};
    use crate::{Locator, PeerIdBytes, RetryAfter};

    #[test]
    fn auth_messages_round_trip_at_frozen_lengths() {
        let hello = AuthClientHello::new([1; 32], [2; 96]);
        let decoded = AuthClientHello::decode(&hello.encode()).unwrap();
        assert_eq!(decoded.nonce(), &[1; 32]);
        assert_eq!(decoded.ke1(), &[2; 96]);

        for response in [
            AuthServerResponse::proceed([3; 32], [4; 320]),
            AuthServerResponse::retry(RetryAfter::from_millis(100).unwrap()),
        ] {
            let encoded = response.encode();
            let decoded = AuthServerResponse::decode(encoded.as_slice()).unwrap();
            assert_eq!(decoded.encode().as_slice(), encoded.as_slice());
        }

        let proceed = AuthServerResponse::proceed([3; 32], [4; 320]);
        assert_eq!(proceed.proceed_parts(), Some((&[3; 32], &[4; 320])));
        assert_eq!(proceed.retry_after(), None);
        assert_eq!(
            format!("{proceed:?}"),
            "AuthServerResponse::Proceed([REDACTED])"
        );
        let retry = AuthServerResponse::retry(RetryAfter::from_millis(100).unwrap());
        assert_eq!(retry.proceed_parts(), None);
        assert_eq!(retry.retry_after().unwrap().millis(), 100);
        assert!(format!("{retry:?}").contains("RetryAfter"));

        assert_eq!(AuthClientFinish::new([5; 64]).ke3(), &[5; 64]);
        assert_eq!(AuthClientFinish::decode(&[6; 64]).unwrap().ke3(), &[6; 64]);
        assert_eq!(Authenticated::decode(&[0x03]), Ok(Authenticated));
    }

    #[test]
    fn context_has_the_exact_frozen_layout() {
        let controller = PeerIdBytes::new(&[1, 2]).unwrap();
        let target = PeerIdBytes::new(&[3, 4, 5]).unwrap();
        let context = PakeContext::new(
            Locator::new(0xABCDE).unwrap(),
            &controller,
            &target,
            &[6; 32],
            &[7; 32],
        );
        let mut expected = Vec::new();
        expected.extend_from_slice(b"/yonder/auth/1.0.0");
        expected.extend_from_slice(&[0x0A, 0xBC, 0xDE]);
        expected.extend_from_slice(&[2, 1, 2, 3, 3, 4, 5]);
        expected.extend_from_slice(&[6; 32]);
        expected.extend_from_slice(&[7; 32]);
        assert_eq!(context.as_bytes(), expected);
    }

    #[test]
    fn malformed_auth_messages_fail() {
        assert!(matches!(
            AuthClientHello::decode(&[]),
            Err(ProtocolError::InvalidLength { .. })
        ));
        assert!(matches!(
            AuthServerResponse::decode(&[0x02, 0, 0, 0, 1]),
            Err(ProtocolError::InvalidField(ProtocolField::RetryAfter))
        ));
        for malformed in [&[][..], &[0x01][..], &[0x02][..]] {
            assert!(matches!(
                AuthServerResponse::decode(malformed),
                Err(ProtocolError::InvalidLength { .. })
            ));
        }
        assert!(matches!(
            AuthServerResponse::decode(&[0xFF]),
            Err(ProtocolError::UnknownTag(0xFF))
        ));
        assert!(matches!(
            AuthClientFinish::decode(&[]),
            Err(ProtocolError::InvalidLength { .. })
        ));
        assert_eq!(
            Authenticated::decode(&[0x99]),
            Err(ProtocolError::UnknownTag(0x99))
        );
        for malformed in [&[][..], &[0x03, 0][..]] {
            assert!(matches!(
                Authenticated::decode(malformed),
                Err(ProtocolError::InvalidLength { .. })
            ));
        }
    }
}
