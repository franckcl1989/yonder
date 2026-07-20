use crate::error::DomainError;
use std::num::NonZeroU16;

/// A bounded retry hint carried on the wire.
///
/// Raw integers cannot bypass [`RetryAfter::from_millis`].
///
/// ```compile_fail
/// use yonder_core::RetryAfter;
///
/// let retry = RetryAfter(99);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RetryAfter(u32);

impl RetryAfter {
    pub const MIN_MILLIS: u32 = 100;
    pub const MAX_MILLIS: u32 = 5_000;

    /// Creates a retry hint in the protocol's accepted range.
    pub const fn from_millis(milliseconds: u32) -> Result<Self, DomainError> {
        if milliseconds >= Self::MIN_MILLIS && milliseconds <= Self::MAX_MILLIS {
            Ok(Self(milliseconds))
        } else {
            Err(DomainError::RetryAfterOutOfRange)
        }
    }

    /// Returns the retry delay in milliseconds.
    #[must_use]
    pub const fn millis(self) -> u32 {
        self.0
    }
}

/// A validated terminal size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TerminalSize {
    columns: NonZeroU16,
    rows: NonZeroU16,
}

impl TerminalSize {
    /// Creates a size whose dimensions are both nonzero.
    pub const fn new(columns: u16, rows: u16) -> Result<Self, DomainError> {
        let Some(columns) = NonZeroU16::new(columns) else {
            return Err(DomainError::ZeroTerminalDimension);
        };
        let Some(rows) = NonZeroU16::new(rows) else {
            return Err(DomainError::ZeroTerminalDimension);
        };
        Ok(Self { columns, rows })
    }

    #[must_use]
    pub const fn columns(self) -> u16 {
        self.columns.get()
    }

    #[must_use]
    pub const fn rows(self) -> u16 {
        self.rows.get()
    }
}

/// A bounded, validated `TERM` or `COLORTERM` value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TerminalValue {
    bytes: [u8; Self::MAX_LEN],
    len: u8,
}

impl TerminalValue {
    pub const MAX_LEN: usize = 64;

    /// Validates the protocol's restricted ASCII terminal-value grammar.
    pub fn new(value: &str) -> Result<Self, DomainError> {
        let source = value.as_bytes();
        if source.len() > Self::MAX_LEN {
            return Err(DomainError::TerminalValueTooLong);
        }
        if !source.iter().copied().all(is_allowed_terminal_byte) {
            return Err(DomainError::InvalidTerminalValue);
        }
        let mut bytes = [0_u8; Self::MAX_LEN];
        bytes[..source.len()].copy_from_slice(source);
        Ok(Self {
            bytes,
            len: source.len() as u8,
        })
    }

    /// Returns the validated ASCII string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(self.as_bytes()).expect("TerminalValue only accepts ASCII")
    }

    /// Returns the validated bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// Returns whether the value requests no environment override.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

fn is_allowed_terminal_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-')
}

/// A bounded serialized libp2p PeerId that keeps the core crate network-agnostic.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerIdBytes {
    bytes: [u8; Self::MAX_LEN],
    len: u8,
}

impl PeerIdBytes {
    pub const MAX_LEN: usize = 64;

    /// Copies a serialized PeerId after checking its protocol bound.
    pub fn new(source: &[u8]) -> Result<Self, DomainError> {
        if source.is_empty() || source.len() > Self::MAX_LEN {
            return Err(DomainError::InvalidPeerIdLength);
        }
        let mut bytes = [0_u8; Self::MAX_LEN];
        bytes[..source.len()].copy_from_slice(source);
        Ok(Self {
            bytes,
            len: source.len() as u8,
        })
    }

    /// Returns the serialized PeerId.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{PeerIdBytes, RetryAfter, TerminalSize, TerminalValue};
    use crate::error::DomainError;

    #[test]
    fn retry_bounds_are_enforced() {
        assert_eq!(
            RetryAfter::from_millis(99),
            Err(DomainError::RetryAfterOutOfRange)
        );
        assert_eq!(RetryAfter::from_millis(100).unwrap().millis(), 100);
        assert_eq!(RetryAfter::from_millis(5_000).unwrap().millis(), 5_000);
        assert_eq!(
            RetryAfter::from_millis(5_001),
            Err(DomainError::RetryAfterOutOfRange)
        );
    }

    #[test]
    fn terminal_values_and_sizes_are_validated() {
        let size = TerminalSize::new(80, 24).unwrap();
        assert_eq!((size.columns(), size.rows()), (80, 24));
        assert_eq!(
            TerminalSize::new(0, 1),
            Err(DomainError::ZeroTerminalDimension)
        );
        assert_eq!(
            TerminalSize::new(1, 0),
            Err(DomainError::ZeroTerminalDimension)
        );
        assert_eq!(
            TerminalValue::new("xterm-256color").unwrap().as_str(),
            "xterm-256color"
        );
        assert!(TerminalValue::new("").unwrap().is_empty());
        assert!(!TerminalValue::new("xterm").unwrap().is_empty());
        assert_eq!(
            TerminalValue::new("bad value"),
            Err(DomainError::InvalidTerminalValue)
        );
        assert_eq!(
            TerminalValue::new(&"x".repeat(65)),
            Err(DomainError::TerminalValueTooLong)
        );
    }

    #[test]
    fn peer_ids_are_bounded() {
        assert_eq!(PeerIdBytes::new(&[]), Err(DomainError::InvalidPeerIdLength));
        assert_eq!(
            PeerIdBytes::new(&[1; 65]),
            Err(DomainError::InvalidPeerIdLength)
        );
        assert_eq!(PeerIdBytes::new(&[1, 2]).unwrap().as_bytes(), &[1, 2]);
    }
}
