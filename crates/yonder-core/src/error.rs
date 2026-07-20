use thiserror::Error;

/// Errors returned while parsing a connection code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CodeError {
    #[error("the connection code has an invalid length")]
    InvalidLength,
    #[error("the connection code has invalid grouping")]
    InvalidGrouping,
    #[error("the connection code contains an invalid character")]
    InvalidCharacter,
    #[error("the connection code could not be decoded")]
    InvalidEncoding,
}

/// Domain-value construction failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DomainError {
    #[error("the locator exceeds 20 bits")]
    LocatorOutOfRange,
    #[error("the PAKE secret exceeds 60 bits")]
    PakeSecretOutOfRange,
    #[error("retry delay must be between 100 and 5000 milliseconds")]
    RetryAfterOutOfRange,
    #[error("a terminal dimension cannot be zero")]
    ZeroTerminalDimension,
    #[error("the terminal value is longer than 64 bytes")]
    TerminalValueTooLong,
    #[error("the terminal value contains a disallowed byte")]
    InvalidTerminalValue,
    #[error("a serialized PeerId must contain between 1 and 64 bytes")]
    InvalidPeerIdLength,
}

/// Fixed fields used by the versioned application protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolField {
    Locator,
    PeerId,
    RetryAfter,
    Reserved,
    TerminalDimension,
    TerminalValue,
}

/// Errors returned by bounded wire decoders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProtocolError {
    #[error("protocol message length is invalid: expected {expected}, received {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("protocol message tag 0x{0:02X} is unknown")]
    UnknownTag(u8),
    #[error("protocol field {0:?} is invalid")]
    InvalidField(ProtocolField),
    #[error("protocol message contains trailing bytes")]
    TrailingBytes,
}
