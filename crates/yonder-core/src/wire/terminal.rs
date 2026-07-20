use super::WireBytes;
use crate::error::{ProtocolError, ProtocolField};
use crate::{TerminalSize, TerminalValue};

pub const MAX_HELLO_LEN: usize = 135;
pub const CONTROL_LEN: usize = 5;

/// The controller's initial terminal metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalHello {
    size: TerminalSize,
    term: TerminalValue,
    color_term: TerminalValue,
}

impl TerminalHello {
    #[must_use]
    pub const fn new(size: TerminalSize, term: TerminalValue, color_term: TerminalValue) -> Self {
        Self {
            size,
            term,
            color_term,
        }
    }

    #[must_use]
    pub const fn size(&self) -> TerminalSize {
        self.size
    }

    #[must_use]
    pub const fn term(&self) -> &TerminalValue {
        &self.term
    }

    #[must_use]
    pub const fn color_term(&self) -> &TerminalValue {
        &self.color_term
    }

    #[must_use]
    pub fn encode(&self) -> WireBytes<MAX_HELLO_LEN> {
        let mut bytes = [0_u8; MAX_HELLO_LEN];
        bytes[0] = 0x01;
        bytes[1..3].copy_from_slice(&self.size.columns().to_be_bytes());
        bytes[3..5].copy_from_slice(&self.size.rows().to_be_bytes());
        bytes[5] = self.term.as_bytes().len() as u8;
        let term_end = 6 + self.term.as_bytes().len();
        bytes[6..term_end].copy_from_slice(self.term.as_bytes());
        bytes[term_end] = self.color_term.as_bytes().len() as u8;
        let end = term_end + 1 + self.color_term.as_bytes().len();
        bytes[term_end + 1..end].copy_from_slice(self.color_term.as_bytes());
        WireBytes::new(bytes, end)
    }

    /// Decodes one complete initial terminal hello.
    pub fn decode(message: &[u8]) -> Result<Self, ProtocolError> {
        if message.len() < 7 {
            return Err(ProtocolError::InvalidLength {
                expected: 7,
                actual: message.len(),
            });
        }
        if message[0] != 0x01 {
            return Err(ProtocolError::UnknownTag(message[0]));
        }
        let size = TerminalSize::new(
            u16::from_be_bytes([message[1], message[2]]),
            u16::from_be_bytes([message[3], message[4]]),
        )
        .map_err(|_| ProtocolError::InvalidField(ProtocolField::TerminalDimension))?;
        let term_len = usize::from(message[5]);
        if term_len > TerminalValue::MAX_LEN || message.len() < 7 + term_len {
            return Err(ProtocolError::InvalidField(ProtocolField::TerminalValue));
        }
        let term_end = 6 + term_len;
        let color_len = usize::from(message[term_end]);
        if color_len > TerminalValue::MAX_LEN {
            return Err(ProtocolError::InvalidField(ProtocolField::TerminalValue));
        }
        let expected = term_end + 1 + color_len;
        if message.len() != expected {
            return Err(if message.len() > expected {
                ProtocolError::TrailingBytes
            } else {
                ProtocolError::InvalidLength {
                    expected,
                    actual: message.len(),
                }
            });
        }
        let term = decode_terminal_value(&message[6..term_end])?;
        let color_term = decode_terminal_value(&message[term_end + 1..])?;
        Ok(Self::new(size, term, color_term))
    }
}

/// A controller-to-target resize message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalResize(TerminalSize);

impl TerminalResize {
    #[must_use]
    pub const fn new(size: TerminalSize) -> Self {
        Self(size)
    }

    #[must_use]
    pub const fn size(self) -> TerminalSize {
        self.0
    }

    #[must_use]
    pub const fn encode(self) -> [u8; CONTROL_LEN] {
        let columns = self.0.columns().to_be_bytes();
        let rows = self.0.rows().to_be_bytes();
        [0x02, columns[0], columns[1], rows[0], rows[1]]
    }

    /// Decodes one complete resize message.
    pub fn decode(message: &[u8]) -> Result<Self, ProtocolError> {
        decode_sized_control(message, 0x02).map(Self)
    }
}

/// A target-to-controller portable shell exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalExit(u32);

impl TerminalExit {
    #[must_use]
    pub const fn new(code: u32) -> Self {
        Self(code)
    }

    #[must_use]
    pub const fn code(self) -> u32 {
        self.0
    }

    #[must_use]
    pub const fn encode(self) -> [u8; CONTROL_LEN] {
        let code = self.0.to_be_bytes();
        [0x80, code[0], code[1], code[2], code[3]]
    }

    /// Decodes one complete exit message.
    pub fn decode(message: &[u8]) -> Result<Self, ProtocolError> {
        let bytes: [u8; CONTROL_LEN] = exact_control(message)?;
        if bytes[0] != 0x80 {
            return Err(ProtocolError::UnknownTag(bytes[0]));
        }
        Ok(Self(u32::from_be_bytes([
            bytes[1], bytes[2], bytes[3], bytes[4],
        ])))
    }
}

/// The target has created its PTY and committed the one-time code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalReady;

impl TerminalReady {
    pub const ENCODED: [u8; 1] = [0x01];

    /// Decodes the one-byte ready marker.
    pub fn decode(message: &[u8]) -> Result<Self, ProtocolError> {
        match message {
            [0x01] => Ok(Self),
            [tag] => Err(ProtocolError::UnknownTag(*tag)),
            _ => Err(ProtocolError::InvalidLength {
                expected: 1,
                actual: message.len(),
            }),
        }
    }
}

fn decode_terminal_value(bytes: &[u8]) -> Result<TerminalValue, ProtocolError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ProtocolError::InvalidField(ProtocolField::TerminalValue))?;
    TerminalValue::new(text).map_err(|_| ProtocolError::InvalidField(ProtocolField::TerminalValue))
}

fn decode_sized_control(message: &[u8], tag: u8) -> Result<TerminalSize, ProtocolError> {
    let bytes = exact_control(message)?;
    if bytes[0] != tag {
        return Err(ProtocolError::UnknownTag(bytes[0]));
    }
    TerminalSize::new(
        u16::from_be_bytes([bytes[1], bytes[2]]),
        u16::from_be_bytes([bytes[3], bytes[4]]),
    )
    .map_err(|_| ProtocolError::InvalidField(ProtocolField::TerminalDimension))
}

fn exact_control(message: &[u8]) -> Result<[u8; CONTROL_LEN], ProtocolError> {
    message
        .try_into()
        .map_err(|_| ProtocolError::InvalidLength {
            expected: CONTROL_LEN,
            actual: message.len(),
        })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{TerminalExit, TerminalHello, TerminalReady, TerminalResize};
    use crate::error::{ProtocolError, ProtocolField};
    use crate::{TerminalSize, TerminalValue};

    #[test]
    fn terminal_messages_round_trip() {
        let hello = TerminalHello::new(
            TerminalSize::new(80, 24).unwrap(),
            TerminalValue::new("xterm-256color").unwrap(),
            TerminalValue::new("truecolor").unwrap(),
        );
        assert_eq!(hello.size(), TerminalSize::new(80, 24).unwrap());
        assert_eq!(hello.term().as_str(), "xterm-256color");
        assert_eq!(hello.color_term().as_str(), "truecolor");
        assert_eq!(TerminalHello::decode(hello.encode().as_slice()), Ok(hello));

        let resize = TerminalResize::new(TerminalSize::new(120, 40).unwrap());
        assert_eq!(TerminalResize::decode(&resize.encode()), Ok(resize));
        assert_eq!(resize.size(), TerminalSize::new(120, 40).unwrap());
        let exit = TerminalExit::new(255);
        assert_eq!(TerminalExit::decode(&exit.encode()), Ok(exit));
        assert_eq!(exit.code(), 255);
        assert_eq!(TerminalReady::decode(&[1]), Ok(TerminalReady));
    }

    #[test]
    fn malformed_terminal_messages_fail() {
        assert!(matches!(
            TerminalHello::decode(&[]),
            Err(ProtocolError::InvalidLength { .. })
        ));
        assert_eq!(
            TerminalHello::decode(&[0xFF, 0, 1, 0, 1, 0, 0]),
            Err(ProtocolError::UnknownTag(0xFF))
        );
        assert_eq!(
            TerminalHello::decode(&[0x01, 0, 0, 0, 1, 0, 0]),
            Err(ProtocolError::InvalidField(
                ProtocolField::TerminalDimension
            ))
        );
        let mut oversized_term = [0_u8; 7];
        oversized_term[0] = 0x01;
        oversized_term[2] = 1;
        oversized_term[4] = 1;
        oversized_term[5] = (TerminalValue::MAX_LEN + 1) as u8;
        assert_eq!(
            TerminalHello::decode(&oversized_term),
            Err(ProtocolError::InvalidField(ProtocolField::TerminalValue))
        );
        let mut oversized_color = [0_u8; 7];
        oversized_color[0] = 0x01;
        oversized_color[2] = 1;
        oversized_color[4] = 1;
        oversized_color[6] = (TerminalValue::MAX_LEN + 1) as u8;
        assert_eq!(
            TerminalHello::decode(&oversized_color),
            Err(ProtocolError::InvalidField(ProtocolField::TerminalValue))
        );
        assert!(matches!(
            TerminalHello::decode(&[0x01, 0, 1, 0, 1, 0, 1]),
            Err(ProtocolError::InvalidLength { .. })
        ));
        assert_eq!(
            TerminalHello::decode(&[0x01, 0, 1, 0, 1, 1, 0xFF, 0]),
            Err(ProtocolError::InvalidField(ProtocolField::TerminalValue))
        );
        assert_eq!(
            TerminalHello::decode(&[0x01, 0, 1, 0, 1, 1, b' ', 0]),
            Err(ProtocolError::InvalidField(ProtocolField::TerminalValue))
        );
        assert_eq!(
            TerminalHello::decode(&[0x01, 0, 1, 0, 1, 0, 1, 0xFF]),
            Err(ProtocolError::InvalidField(ProtocolField::TerminalValue))
        );
        assert_eq!(
            TerminalResize::decode(&[0x02, 0, 0, 0, 1]),
            Err(ProtocolError::InvalidField(
                ProtocolField::TerminalDimension
            ))
        );
        let hello = TerminalHello::new(
            TerminalSize::new(1, 1).unwrap(),
            TerminalValue::new("").unwrap(),
            TerminalValue::new("").unwrap(),
        );
        let mut bytes = hello.encode().as_slice().to_vec();
        bytes.push(0);
        assert_eq!(
            TerminalHello::decode(&bytes),
            Err(ProtocolError::TrailingBytes)
        );
        assert_eq!(
            TerminalExit::decode(&[0x02, 0, 0, 0, 0]),
            Err(ProtocolError::UnknownTag(2))
        );
        assert!(matches!(
            TerminalExit::decode(&[]),
            Err(ProtocolError::InvalidLength { .. })
        ));
        assert_eq!(
            TerminalResize::decode(&[0x03, 0, 1, 0, 1]),
            Err(ProtocolError::UnknownTag(3))
        );
        assert!(matches!(
            TerminalResize::decode(&[]),
            Err(ProtocolError::InvalidLength { .. })
        ));
        assert_eq!(
            TerminalReady::decode(&[0x02]),
            Err(ProtocolError::UnknownTag(0x02))
        );
        assert!(matches!(
            TerminalReady::decode(&[]),
            Err(ProtocolError::InvalidLength { .. })
        ));
    }
}
