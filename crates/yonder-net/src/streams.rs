use futures::io::{AsyncRead, AsyncWrite};
use futures::{StreamExt, future::Future};
use libp2p::swarm::StreamProtocol;
use libp2p::{PeerId, swarm};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use thiserror::Error;
use tokio_util::compat::FuturesAsyncReadCompatExt as _;

/// An application substream without exposing the alpha adapter's concrete types.
pub struct ApplicationStream {
    inner: swarm::Stream,
}

impl ApplicationStream {
    fn new(inner: swarm::Stream) -> Self {
        Self { inner }
    }

    /// Adapts the libp2p futures I/O stream to Tokio without a handwritten bridge.
    pub fn into_tokio(self) -> impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {
        self.compat()
    }
}

impl AsyncRead for ApplicationStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for ApplicationStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_close(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(context)
    }
}

/// A continuously polled inbound protocol registration.
pub struct IncomingApplicationStreams {
    inner: libp2p_stream::IncomingStreams,
}

impl IncomingApplicationStreams {
    /// Waits for the next authenticated peer and negotiated stream.
    pub async fn next(&mut self) -> Option<(PeerId, ApplicationStream)> {
        self.inner
            .next()
            .await
            .map(|(peer, stream)| (peer, ApplicationStream::new(stream)))
    }
}

/// Errors at the versioned application-substream boundary.
#[derive(Debug, Error)]
pub enum ApplicationStreamError {
    #[error("the application protocol is already registered")]
    AlreadyRegistered,
    #[error("the remote peer does not support the application protocol")]
    UnsupportedProtocol,
    #[error("application stream I/O failed")]
    Io(#[source] io::Error),
    #[error("the application stream adapter rejected the operation")]
    Adapter,
}

/// Minimal replaceable operations required from an application-stream adapter.
pub trait ApplicationStreams {
    /// Registers one static, versioned protocol.
    fn accept(
        &mut self,
        protocol: &'static str,
    ) -> Result<IncomingApplicationStreams, ApplicationStreamError>;

    /// Opens one negotiated stream to an already authenticated peer.
    fn open(
        &mut self,
        peer: PeerId,
        protocol: &'static str,
    ) -> impl Future<Output = Result<ApplicationStream, ApplicationStreamError>> + Send;
}

/// The only module allowed to depend on `libp2p-stream`'s alpha API.
#[derive(Clone)]
pub struct Libp2pApplicationStreams {
    control: libp2p_stream::Control,
}

impl Libp2pApplicationStreams {
    pub(crate) fn new(control: libp2p_stream::Control) -> Self {
        Self { control }
    }
}

impl ApplicationStreams for Libp2pApplicationStreams {
    fn accept(
        &mut self,
        protocol: &'static str,
    ) -> Result<IncomingApplicationStreams, ApplicationStreamError> {
        self.control
            .accept(StreamProtocol::new(protocol))
            .map(|inner| IncomingApplicationStreams { inner })
            .map_err(|_| ApplicationStreamError::AlreadyRegistered)
    }

    async fn open(
        &mut self,
        peer: PeerId,
        protocol: &'static str,
    ) -> Result<ApplicationStream, ApplicationStreamError> {
        self.control
            .open_stream(peer, StreamProtocol::new(protocol))
            .await
            .map(ApplicationStream::new)
            .map_err(|error| match error {
                libp2p_stream::OpenStreamError::UnsupportedProtocol(_) => {
                    ApplicationStreamError::UnsupportedProtocol
                }
                libp2p_stream::OpenStreamError::Io(error) => ApplicationStreamError::Io(error),
                _ => ApplicationStreamError::Adapter,
            })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{ApplicationStreamError, ApplicationStreams, Libp2pApplicationStreams};
    use futures::StreamExt as _;
    use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
    use libp2p::swarm::{ConnectionId, Swarm, SwarmEvent};
    use libp2p::{Multiaddr, PeerId};
    use libp2p_swarm_test::SwarmExt as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const TEST_PROTOCOL: &str = "/yonder/test/stream-binding/1.0.0";

    type TestSwarm = Swarm<libp2p_stream::Behaviour>;

    #[tokio::test(flavor = "current_thread")]
    async fn application_stream_uses_the_single_surviving_physical_connection() {
        let mut dialer = TestSwarm::new_ephemeral_tokio(|_| libp2p_stream::Behaviour::new());
        let mut listener = TestSwarm::new_ephemeral_tokio(|_| libp2p_stream::Behaviour::new());
        let listener_peer = *listener.local_peer_id();
        let (listener_address, _) = listener.listen().with_memory_addr_external().await;

        let mut dialer_streams = Libp2pApplicationStreams::new(dialer.behaviour().new_control());
        let mut listener_streams =
            Libp2pApplicationStreams::new(listener.behaviour().new_control());
        let mut incoming = listener_streams.accept(TEST_PROTOCOL).unwrap();

        let first =
            connect_physical(&mut dialer, &mut listener, listener_peer, &listener_address).await;
        let survivor =
            connect_physical(&mut dialer, &mut listener, listener_peer, &listener_address).await;
        assert_ne!(first.0, survivor.0);
        assert_ne!(first.1, survivor.1);
        assert_eq!(established_connections(&dialer), 2);
        assert_eq!(established_connections(&listener), 2);

        assert!(dialer.close_connection(first.0));
        observe_closed_pair(&mut dialer, &mut listener, first).await;
        assert_eq!(established_connections(&dialer), 1);
        assert_eq!(established_connections(&listener), 1);

        let (outbound, inbound) = {
            let open = dialer_streams.open(listener_peer, TEST_PROTOCOL);
            let accept = incoming.next();
            tokio::pin!(open);
            tokio::pin!(accept);
            let mut outbound = None;
            let mut inbound = None;
            while outbound.is_none() || inbound.is_none() {
                tokio::select! {
                    result = &mut open, if outbound.is_none() => {
                        outbound = Some(result.unwrap());
                    }
                    result = &mut accept, if inbound.is_none() => {
                        let (peer, stream) = result.expect("registered protocol remains active");
                        assert_eq!(peer, *dialer.local_peer_id());
                        inbound = Some(stream);
                    }
                    _ = dialer.select_next_some() => {}
                    _ = listener.select_next_some() => {}
                }
            }
            (
                outbound.expect("outbound stream was opened"),
                inbound.expect("inbound stream was accepted"),
            )
        };

        let mut outbound = outbound.into_tokio();
        let mut inbound = inbound.into_tokio();
        let transfer = async {
            outbound.write_all(b"yon").await.unwrap();
            outbound.flush().await.unwrap();
            let mut request = [0_u8; 3];
            inbound.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"yon");

            inbound.write_all(b"der").await.unwrap();
            inbound.flush().await.unwrap();
            let mut response = [0_u8; 3];
            outbound.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"der");

            outbound.shutdown().await.unwrap();
            assert_eq!(inbound.read(&mut [0_u8; 1]).await.unwrap(), 0);
            inbound.shutdown().await.unwrap();
        };
        drive_transfer(&mut dialer, &mut listener, transfer).await;

        let error = {
            let unsupported = dialer_streams.open(listener_peer, "/yonder/test/missing/1.0.0");
            tokio::pin!(unsupported);
            loop {
                tokio::select! {
                    result = &mut unsupported => match result {
                        Ok(_) => panic!("unsupported protocol unexpectedly opened"),
                        Err(error) => break error,
                    },
                    _ = dialer.select_next_some() => {}
                    _ = listener.select_next_some() => {}
                }
            }
        };
        assert!(matches!(error, ApplicationStreamError::UnsupportedProtocol));

        let absent_peer = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let unavailable = dialer_streams.open(absent_peer, TEST_PROTOCOL);
        tokio::pin!(unavailable);
        let error = loop {
            tokio::select! {
                result = &mut unavailable => match result {
                    Ok(_) => panic!("stream unexpectedly opened without a connection"),
                    Err(error) => break error,
                },
                _ = dialer.select_next_some() => {}
                _ = listener.select_next_some() => {}
            }
        };
        assert!(
            matches!(
                error,
                ApplicationStreamError::Io(ref source)
                    if source.kind() == std::io::ErrorKind::NotConnected
            ),
            "unexpected missing-connection error: {error:?}"
        );

        assert_eq!(established_connections(&dialer), 1);
        assert_eq!(established_connections(&listener), 1);
        assert!(dialer.is_connected(&listener_peer));
        assert!(listener.is_connected(dialer.local_peer_id()));
    }

    async fn connect_physical(
        dialer: &mut TestSwarm,
        listener: &mut TestSwarm,
        listener_peer: PeerId,
        listener_address: &Multiaddr,
    ) -> (ConnectionId, ConnectionId) {
        let options = DialOpts::peer_id(listener_peer)
            .addresses(vec![listener_address.clone()])
            .condition(PeerCondition::Always)
            .build();
        dialer.dial(options).unwrap();

        let mut dialer_connection = None;
        let mut listener_connection = None;
        while dialer_connection.is_none() || listener_connection.is_none() {
            tokio::select! {
                event = dialer.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished {
                        peer_id,
                        connection_id,
                        ..
                    } = event
                        && peer_id == listener_peer
                    {
                        dialer_connection = Some(connection_id);
                    }
                }
                event = listener.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished {
                        peer_id,
                        connection_id,
                        ..
                    } = event
                        && peer_id == *dialer.local_peer_id()
                    {
                        listener_connection = Some(connection_id);
                    }
                }
            }
        }
        (
            dialer_connection.expect("dialer observed establishment"),
            listener_connection.expect("listener observed establishment"),
        )
    }

    async fn observe_closed_pair(
        dialer: &mut TestSwarm,
        listener: &mut TestSwarm,
        closed: (ConnectionId, ConnectionId),
    ) {
        let mut dialer_closed = false;
        let mut listener_closed = false;
        while !dialer_closed || !listener_closed {
            tokio::select! {
                event = dialer.select_next_some(), if !dialer_closed => {
                    if let SwarmEvent::ConnectionClosed { connection_id, .. } = event
                        && connection_id == closed.0
                    {
                        dialer_closed = true;
                    }
                }
                event = listener.select_next_some(), if !listener_closed => {
                    if let SwarmEvent::ConnectionClosed { connection_id, .. } = event
                        && connection_id == closed.1
                    {
                        listener_closed = true;
                    }
                }
            }
        }
    }

    async fn drive_transfer<F>(dialer: &mut TestSwarm, listener: &mut TestSwarm, transfer: F)
    where
        F: Future<Output = ()>,
    {
        tokio::pin!(transfer);
        loop {
            tokio::select! {
                () = &mut transfer => return,
                _ = dialer.select_next_some() => {}
                _ = listener.select_next_some() => {}
            }
        }
    }

    fn established_connections(swarm: &TestSwarm) -> u32 {
        swarm.network_info().connection_counters().num_established()
    }

    use std::future::Future;
}
