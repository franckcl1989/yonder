//! Bounded wire messages for Yonder application protocols.

pub mod auth;
pub mod registry;
pub mod resolve;
pub mod terminal;

pub const REGISTRY_PROTOCOL: &str = "/yonder/registry/1.0.0";
pub const RESOLVE_PROTOCOL: &str = "/yonder/resolve/1.0.0";
pub const AUTH_PROTOCOL: &str = "/yonder/auth/1.0.0";
pub const TERMINAL_DATA_PROTOCOL: &str = "/yonder/terminal/1.0.0";
pub const TERMINAL_CONTROL_PROTOCOL: &str = "/yonder/terminal-control/1.0.0";

/// A stack-backed encoded message with a validated used length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireBytes<const CAPACITY: usize> {
    bytes: [u8; CAPACITY],
    len: usize,
}

impl<const CAPACITY: usize> WireBytes<CAPACITY> {
    pub(crate) const fn new(bytes: [u8; CAPACITY], len: usize) -> Self {
        debug_assert!(len <= CAPACITY);
        Self { bytes, len }
    }

    /// Returns exactly the bytes belonging to the message.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
