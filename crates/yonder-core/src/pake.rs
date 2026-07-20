use crate::{PakeSecret, PeerIdBytes};

/// A complete opaque PAKE implementation hidden behind fixed Yonder wire sizes.
pub trait Pake {
    type Error;
    type Registration;
    type ClientState;
    type ServerState;
    type SessionKey: AsRef<[u8]>;

    /// Creates an in-memory one-time server registration.
    fn register(
        &mut self,
        server: &PeerIdBytes,
        secret: &PakeSecret,
    ) -> Result<Self::Registration, Self::Error>;

    /// Starts a client login and emits a fixed KE1 message.
    fn client_start(
        &mut self,
        server: &PeerIdBytes,
        secret: &PakeSecret,
    ) -> Result<(Self::ClientState, [u8; 96]), Self::Error>;

    /// Completes a client login and emits KE3 plus the confirmed session key.
    fn client_finish(
        &mut self,
        state: Self::ClientState,
        response: &[u8; 320],
        context: &[u8],
    ) -> Result<([u8; 64], Self::SessionKey), Self::Error>;

    /// Starts the server side and emits a fixed KE2 message.
    fn server_start(
        &mut self,
        registration: &Self::Registration,
        request: &[u8; 96],
        context: &[u8],
    ) -> Result<(Self::ServerState, [u8; 320]), Self::Error>;

    /// Verifies KE3 and returns the same confirmed session key.
    fn server_finish(
        &mut self,
        state: Self::ServerState,
        finish: &[u8; 64],
    ) -> Result<Self::SessionKey, Self::Error>;
}
