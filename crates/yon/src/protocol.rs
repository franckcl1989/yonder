use crate::network::{
    ConnectionBinding, EndpointDriver, EndpointError, RelayConnection, drive, drive_bound,
    reconverge_relay,
};
use backon::{BackoffBuilder as _, ConstantBuilder};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use yonder_core::wire::registry::{RegistryRequest, RegistryResponse};
use yonder_core::wire::resolve::{MAX_RESPONSE_LEN, ResolveRequest, ResolveResponse};
use yonder_core::wire::{REGISTRY_PROTOCOL, RESOLVE_PROTOCOL};
use yonder_core::{Locator, ProtocolError, RetryAfter};
use yonder_net::{ApplicationStreams, Libp2pApplicationStreams, PeerId};

const PROTOCOL_TIMEOUT: Duration = Duration::from_secs(10);
const RETRY_LIMIT: usize = 20;
const CONTROLLER_RESOLVE_TIMEOUT: Duration = Duration::from_secs(30);

/// The absolute controller discovery budget, shared across every relay retry.
#[derive(Debug, Clone, Copy)]
pub struct ResolveDeadline(tokio::time::Instant);

impl ResolveDeadline {
    #[must_use]
    pub fn controller() -> Self {
        Self(tokio::time::Instant::now() + CONTROLLER_RESOLVE_TIMEOUT)
    }

    #[cfg(test)]
    fn instant(self) -> tokio::time::Instant {
        self.0
    }
}

/// Failures from a bounded relay registry or resolve exchange.
#[derive(Debug, Error)]
pub enum RelayProtocolError {
    #[error(transparent)]
    Endpoint(#[from] EndpointError),
    #[error("the relay protocol exchange timed out")]
    Timeout,
    #[error("relay protocol I/O failed")]
    Io(#[from] std::io::Error),
    #[error("the relay returned an invalid protocol message")]
    Protocol(#[from] ProtocolError),
    #[error("the relay registration is at capacity")]
    Capacity,
    #[error("the relay requires an active reservation")]
    ReservationRequired,
    #[error("the requested locator conflicts with another endpoint")]
    Conflict,
    #[error("the relay acknowledged a different locator than the one requested")]
    LocatorMismatch,
    #[error("the target is not currently available")]
    Unavailable,
    #[error("the relay response contained an invalid PeerId")]
    InvalidPeerId,
    #[error("the bounded relay retry budget was exhausted")]
    RetryExhausted,
    #[error("the relay returned a response that is invalid for this request")]
    UnexpectedResponse,
}

/// Allocates a locator, honoring the relay's retry hints within a fixed budget.
pub async fn allocate_locator(
    driver: &mut EndpointDriver,
    streams: &mut Libp2pApplicationStreams,
    relay: &RelayConnection,
) -> Result<Locator, RelayProtocolError> {
    let mut backoff = ConstantBuilder::default()
        .with_delay(Duration::from_millis(250))
        .with_max_times(RETRY_LIMIT)
        .build();
    loop {
        reconverge_relay(driver, relay).await?;
        match allocation_response(
            registry_call(driver, streams, relay.peer(), RegistryRequest::Allocate).await?,
        )? {
            AllocationResponse::Acquired(locator) => return Ok(locator),
            AllocationResponse::Retry(after) => {
                retry(driver, relay.binding(), &mut backoff, after).await?;
            }
        }
    }
}

/// Reclaims one existing locator on the same endpoint identity after relay recovery.
pub async fn reclaim_locator(
    driver: &mut EndpointDriver,
    streams: &mut Libp2pApplicationStreams,
    relay: &RelayConnection,
    locator: Locator,
) -> Result<ReclaimResponse, RelayProtocolError> {
    let mut backoff = ConstantBuilder::default()
        .with_delay(Duration::from_millis(250))
        .with_max_times(RETRY_LIMIT)
        .build();
    loop {
        reconverge_relay(driver, relay).await?;
        match reclaim_response(
            registry_call(
                driver,
                streams,
                relay.peer(),
                RegistryRequest::Reclaim(locator),
            )
            .await?,
            locator,
        )? {
            ReclaimStep::Reclaimed => return Ok(ReclaimResponse::Reclaimed),
            ReclaimStep::Conflict => return Ok(ReclaimResponse::Conflict),
            ReclaimStep::Retry(after) => {
                retry(driver, relay.binding(), &mut backoff, after).await?;
            }
        }
    }
}

/// The only two terminal outcomes of a valid Reclaim exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclaimResponse {
    Reclaimed,
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReclaimStep {
    Reclaimed,
    Conflict,
    Retry(RetryAfter),
}

fn reclaim_response(
    response: RegistryResponse,
    requested: Locator,
) -> Result<ReclaimStep, RelayProtocolError> {
    match response {
        RegistryResponse::Acquired(locator) if locator == requested => Ok(ReclaimStep::Reclaimed),
        RegistryResponse::Acquired(_) => Err(RelayProtocolError::LocatorMismatch),
        RegistryResponse::Conflict => Ok(ReclaimStep::Conflict),
        RegistryResponse::Retry(after) => Ok(ReclaimStep::Retry(after)),
        RegistryResponse::Capacity => Err(RelayProtocolError::Capacity),
        RegistryResponse::ReservationRequired => Err(RelayProtocolError::ReservationRequired),
        RegistryResponse::Released => Err(RelayProtocolError::UnexpectedResponse),
    }
}

enum AllocationResponse {
    Acquired(Locator),
    Retry(RetryAfter),
}

fn allocation_response(
    response: RegistryResponse,
) -> Result<AllocationResponse, RelayProtocolError> {
    match response {
        RegistryResponse::Acquired(locator) => Ok(AllocationResponse::Acquired(locator)),
        RegistryResponse::Retry(after) => Ok(AllocationResponse::Retry(after)),
        RegistryResponse::Capacity => Err(RelayProtocolError::Capacity),
        RegistryResponse::ReservationRequired => Err(RelayProtocolError::ReservationRequired),
        RegistryResponse::Conflict | RegistryResponse::Released => {
            Err(RelayProtocolError::UnexpectedResponse)
        }
    }
}

/// Best-effort explicit release used during orderly host shutdown.
pub async fn release_locator(
    driver: &mut EndpointDriver,
    streams: &mut Libp2pApplicationStreams,
    relay: PeerId,
    locator: Locator,
) -> Result<(), RelayProtocolError> {
    release_response(
        registry_call(driver, streams, relay, RegistryRequest::Release(locator)).await?,
    )
}

/// Releases a committed locator while preserving the endpoint-to-endpoint connection binding.
pub async fn release_locator_bound(
    driver: &mut EndpointDriver,
    streams: &mut Libp2pApplicationStreams,
    binding: ConnectionBinding,
    relay: PeerId,
    locator: Locator,
) -> Result<(), RelayProtocolError> {
    release_response(
        registry_call_bound(
            driver,
            streams,
            binding,
            relay,
            RegistryRequest::Release(locator),
        )
        .await?,
    )
}

fn release_response(response: RegistryResponse) -> Result<(), RelayProtocolError> {
    match response {
        RegistryResponse::Released => Ok(()),
        RegistryResponse::Conflict => Err(RelayProtocolError::Conflict),
        RegistryResponse::ReservationRequired => Err(RelayProtocolError::ReservationRequired),
        RegistryResponse::Capacity | RegistryResponse::Acquired(_) | RegistryResponse::Retry(_) => {
            Err(RelayProtocolError::UnexpectedResponse)
        }
    }
}

async fn registry_call_bound(
    driver: &mut EndpointDriver,
    streams: &mut Libp2pApplicationStreams,
    binding: ConnectionBinding,
    relay: PeerId,
    request: RegistryRequest,
) -> Result<RegistryResponse, RelayProtocolError> {
    let stream =
        open_stream_timed_bound(driver, streams, binding, relay, REGISTRY_PROTOCOL).await?;
    let response = drive_bound(
        driver,
        binding,
        exact_exchange::<5>(stream, &request.encode()),
    )
    .await??;
    RegistryResponse::decode(&response).map_err(RelayProtocolError::from)
}

/// Resolves the public 20-bit locator without ever sending the PAKE secret.
pub async fn resolve_peer(
    driver: &mut EndpointDriver,
    streams: &mut Libp2pApplicationStreams,
    relay: &RelayConnection,
    locator: Locator,
    deadline: ResolveDeadline,
) -> Result<PeerId, RelayProtocolError> {
    tokio::time::timeout_at(deadline.0, async {
        let mut backoff = std::iter::repeat(Duration::from_millis(250));
        loop {
            reconverge_relay(driver, relay).await?;
            match resolve_response(
                resolve_call(driver, streams, relay.peer(), ResolveRequest::new(locator)).await?,
            )? {
                ResolvedResponse::Resolved(peer) => return Ok(peer),
                ResolvedResponse::Retry(after) => {
                    retry(driver, relay.binding(), &mut backoff, after).await?;
                }
            }
        }
    })
    .await
    .map_err(|_| RelayProtocolError::Timeout)?
}

enum ResolvedResponse {
    Resolved(PeerId),
    Retry(RetryAfter),
}

fn resolve_response(response: ResolveResponse) -> Result<ResolvedResponse, RelayProtocolError> {
    match response {
        ResolveResponse::Resolved(peer) => PeerId::from_bytes(peer.as_bytes())
            .map(ResolvedResponse::Resolved)
            .map_err(|_| RelayProtocolError::InvalidPeerId),
        ResolveResponse::Retry(after) => Ok(ResolvedResponse::Retry(after)),
        ResolveResponse::Unavailable => Err(RelayProtocolError::Unavailable),
    }
}

async fn retry(
    driver: &mut EndpointDriver,
    binding: ConnectionBinding,
    backoff: &mut impl Iterator<Item = Duration>,
    requested: RetryAfter,
) -> Result<(), RelayProtocolError> {
    let delay = retry_delay(backoff, requested)?;
    drive_bound(driver, binding, tokio::time::sleep(delay)).await?;
    Ok(())
}

fn retry_delay(
    backoff: &mut impl Iterator<Item = Duration>,
    requested: RetryAfter,
) -> Result<Duration, RelayProtocolError> {
    let generated = backoff.next().ok_or(RelayProtocolError::RetryExhausted)?;
    Ok(generated.max(Duration::from_millis(u64::from(requested.millis()))))
}

async fn registry_call(
    driver: &mut EndpointDriver,
    streams: &mut Libp2pApplicationStreams,
    relay: PeerId,
    request: RegistryRequest,
) -> Result<RegistryResponse, RelayProtocolError> {
    let stream = open_stream_timed(driver, streams, relay, REGISTRY_PROTOCOL).await?;
    let response = drive(driver, exact_exchange::<5>(stream, &request.encode())).await?;
    RegistryResponse::decode(&response).map_err(RelayProtocolError::from)
}

async fn resolve_call(
    driver: &mut EndpointDriver,
    streams: &mut Libp2pApplicationStreams,
    relay: PeerId,
    request: ResolveRequest,
) -> Result<ResolveResponse, RelayProtocolError> {
    let stream = open_stream_timed(driver, streams, relay, RESOLVE_PROTOCOL).await?;
    let response = drive(
        driver,
        bounded_exchange::<MAX_RESPONSE_LEN>(stream, &request.encode()),
    )
    .await?;
    ResolveResponse::decode(response.as_slice()).map_err(RelayProtocolError::from)
}

async fn open_stream_timed(
    driver: &mut EndpointDriver,
    streams: &mut Libp2pApplicationStreams,
    peer: PeerId,
    protocol: &'static str,
) -> Result<yonder_net::ApplicationStream, RelayProtocolError> {
    drive(
        driver,
        tokio::time::timeout(PROTOCOL_TIMEOUT, streams.open(peer, protocol)),
    )
    .await
    .map_err(|_| RelayProtocolError::Timeout)?
    .map_err(EndpointError::from)
    .map_err(RelayProtocolError::from)
}

async fn open_stream_timed_bound(
    driver: &mut EndpointDriver,
    streams: &mut Libp2pApplicationStreams,
    binding: ConnectionBinding,
    peer: PeerId,
    protocol: &'static str,
) -> Result<yonder_net::ApplicationStream, RelayProtocolError> {
    tokio::time::timeout(
        PROTOCOL_TIMEOUT,
        drive_bound(driver, binding, streams.open(peer, protocol)),
    )
    .await
    .map_err(|_| RelayProtocolError::Timeout)??
    .map_err(EndpointError::from)
    .map_err(RelayProtocolError::from)
}

async fn exact_exchange<const RESPONSE: usize>(
    stream: yonder_net::ApplicationStream,
    request: &[u8],
) -> Result<[u8; RESPONSE], RelayProtocolError> {
    exact_exchange_io(stream.into_tokio(), request, PROTOCOL_TIMEOUT).await
}

async fn exact_exchange_io<const RESPONSE: usize>(
    mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    request: &[u8],
    timeout: Duration,
) -> Result<[u8; RESPONSE], RelayProtocolError> {
    tokio::time::timeout(timeout, async move {
        stream.write_all(request).await?;
        stream.flush().await?;
        stream.shutdown().await?;
        let mut response = [0_u8; RESPONSE];
        stream.read_exact(&mut response).await?;
        let mut trailing = [0_u8; 1];
        if stream.read(&mut trailing).await? != 0 {
            return Err(RelayProtocolError::Protocol(ProtocolError::TrailingBytes));
        }
        Ok(response)
    })
    .await
    .map_err(|_| RelayProtocolError::Timeout)?
}

struct BoundedResponse<const CAPACITY: usize> {
    bytes: [u8; CAPACITY],
    len: usize,
}

impl<const CAPACITY: usize> BoundedResponse<CAPACITY> {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

async fn bounded_exchange<const CAPACITY: usize>(
    stream: yonder_net::ApplicationStream,
    request: &[u8],
) -> Result<BoundedResponse<CAPACITY>, RelayProtocolError> {
    bounded_exchange_io(stream.into_tokio(), request, PROTOCOL_TIMEOUT).await
}

async fn bounded_exchange_io<const CAPACITY: usize>(
    mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    request: &[u8],
    timeout: Duration,
) -> Result<BoundedResponse<CAPACITY>, RelayProtocolError> {
    tokio::time::timeout(timeout, async move {
        stream.write_all(request).await?;
        stream.flush().await?;
        stream.shutdown().await?;
        let mut response = BoundedResponse {
            bytes: [0; CAPACITY],
            len: 0,
        };
        while response.len < CAPACITY {
            let read = stream.read(&mut response.bytes[response.len..]).await?;
            if read == 0 {
                return Ok(response);
            }
            response.len += read;
        }
        let mut trailing = [0_u8; 1];
        if stream.read(&mut trailing).await? != 0 {
            return Err(RelayProtocolError::Protocol(ProtocolError::TrailingBytes));
        }
        Ok(response)
    })
    .await
    .map_err(|_| RelayProtocolError::Timeout)?
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        AllocationResponse, BoundedResponse, CONTROLLER_RESOLVE_TIMEOUT, RETRY_LIMIT, ReclaimStep,
        RelayProtocolError, ResolveDeadline, ResolvedResponse, RetryAfter, allocation_response,
        bounded_exchange_io, exact_exchange_io, reclaim_response, release_response,
        resolve_response, retry_delay,
    };
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
    use yonder_core::wire::registry::RegistryResponse;
    use yonder_core::wire::resolve::ResolveResponse;
    use yonder_core::{Locator, PeerIdBytes};
    use yonder_net::Keypair;

    #[test]
    fn retry_budget_and_wire_hint_are_bounded() {
        assert_eq!(RETRY_LIMIT, 20);
        assert_eq!(RetryAfter::from_millis(250).unwrap().millis(), 250);
    }

    #[test]
    fn controller_resolve_uses_one_absolute_thirty_second_budget() {
        let now = tokio::time::Instant::now();
        let deadline = ResolveDeadline::controller().instant();
        assert!(deadline >= now + CONTROLLER_RESOLVE_TIMEOUT);
        assert!(deadline <= tokio::time::Instant::now() + CONTROLLER_RESOLVE_TIMEOUT);
    }

    #[test]
    fn retry_obeys_the_iterator_budget() {
        let mut available = [Duration::ZERO].into_iter();
        assert_eq!(
            retry_delay(&mut available, RetryAfter::from_millis(100).unwrap()).unwrap(),
            Duration::from_millis(100)
        );
        assert!(matches!(
            retry_delay(&mut available, RetryAfter::from_millis(100).unwrap()),
            Err(RelayProtocolError::RetryExhausted)
        ));

        let response = BoundedResponse::<3> {
            bytes: [1, 2, 0],
            len: 2,
        };
        assert_eq!(response.as_slice(), &[1, 2]);
        assert_eq!(
            RelayProtocolError::Capacity.to_string(),
            "the relay registration is at capacity"
        );
    }

    #[test]
    fn registry_responses_are_exhaustively_classified() {
        let locator = Locator::new(7).unwrap();
        assert!(matches!(
            allocation_response(RegistryResponse::Acquired(locator)).unwrap(),
            AllocationResponse::Acquired(value) if value == locator
        ));
        assert!(matches!(
            allocation_response(RegistryResponse::Retry(RetryAfter::from_millis(100).unwrap()))
                .unwrap(),
            AllocationResponse::Retry(after) if after.millis() == 100
        ));
        assert!(matches!(
            allocation_response(RegistryResponse::Capacity),
            Err(RelayProtocolError::Capacity)
        ));
        assert!(matches!(
            allocation_response(RegistryResponse::ReservationRequired),
            Err(RelayProtocolError::ReservationRequired)
        ));
        for response in [RegistryResponse::Conflict, RegistryResponse::Released] {
            assert!(matches!(
                allocation_response(response),
                Err(RelayProtocolError::UnexpectedResponse)
            ));
        }

        assert!(release_response(RegistryResponse::Released).is_ok());
        assert!(matches!(
            release_response(RegistryResponse::Conflict),
            Err(RelayProtocolError::Conflict)
        ));
        assert!(matches!(
            release_response(RegistryResponse::ReservationRequired),
            Err(RelayProtocolError::ReservationRequired)
        ));
        for response in [
            RegistryResponse::Capacity,
            RegistryResponse::Acquired(locator),
            RegistryResponse::Retry(RetryAfter::from_millis(100).unwrap()),
        ] {
            assert!(matches!(
                release_response(response),
                Err(RelayProtocolError::UnexpectedResponse)
            ));
        }

        assert_eq!(
            reclaim_response(RegistryResponse::Acquired(locator), locator).unwrap(),
            ReclaimStep::Reclaimed
        );
        assert_eq!(
            reclaim_response(RegistryResponse::Conflict, locator).unwrap(),
            ReclaimStep::Conflict
        );
        assert!(matches!(
            reclaim_response(
                RegistryResponse::Acquired(Locator::new(8).unwrap()),
                locator
            ),
            Err(RelayProtocolError::LocatorMismatch)
        ));
        assert!(matches!(
            reclaim_response(RegistryResponse::Retry(RetryAfter::from_millis(100).unwrap()), locator)
                .unwrap(),
            ReclaimStep::Retry(after) if after.millis() == 100
        ));
        assert!(matches!(
            reclaim_response(RegistryResponse::Capacity, locator),
            Err(RelayProtocolError::Capacity)
        ));
        assert!(matches!(
            reclaim_response(RegistryResponse::ReservationRequired, locator),
            Err(RelayProtocolError::ReservationRequired)
        ));
        assert!(matches!(
            reclaim_response(RegistryResponse::Released, locator),
            Err(RelayProtocolError::UnexpectedResponse)
        ));
    }

    #[test]
    fn resolve_responses_validate_peer_identity_and_status() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let wire_peer = PeerIdBytes::new(&peer.to_bytes()).unwrap();
        assert!(matches!(
            resolve_response(ResolveResponse::Resolved(wire_peer)).unwrap(),
            ResolvedResponse::Resolved(resolved) if resolved == peer
        ));
        assert!(matches!(
            resolve_response(ResolveResponse::Retry(RetryAfter::from_millis(250).unwrap())).unwrap(),
            ResolvedResponse::Retry(after) if after.millis() == 250
        ));
        assert!(matches!(
            resolve_response(ResolveResponse::Unavailable),
            Err(RelayProtocolError::Unavailable)
        ));
        assert!(matches!(
            resolve_response(ResolveResponse::Resolved(
                PeerIdBytes::new(&[0xff]).unwrap()
            )),
            Err(RelayProtocolError::InvalidPeerId)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exact_exchange_rejects_truncation_trailing_data_and_timeout() {
        let response = exact_response(b"hello").await.unwrap();
        assert_eq!(response, *b"hello");

        assert!(matches!(
            exact_response(b"hell").await,
            Err(RelayProtocolError::Io(_))
        ));
        assert!(matches!(
            exact_response(b"hello!").await,
            Err(RelayProtocolError::Protocol(
                yonder_core::ProtocolError::TrailingBytes
            ))
        ));

        let (client, _server) = tokio::io::duplex(8);
        assert!(matches!(
            exact_exchange_io::<1>(client, b"request", Duration::ZERO).await,
            Err(RelayProtocolError::Timeout)
        ));
        let (client, _server) = tokio::io::duplex(8);
        assert!(matches!(
            bounded_exchange_io::<1>(client, b"request", Duration::ZERO).await,
            Err(RelayProtocolError::Timeout)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bounded_exchange_accepts_short_and_exact_responses_but_rejects_trailing_data() {
        assert_eq!(bounded_response::<5>(b"yon").await.unwrap(), b"yon");
        assert!(matches!(
            bounded_response::<5>(b"yonder").await,
            Err(RelayProtocolError::Protocol(
                yonder_core::ProtocolError::TrailingBytes
            ))
        ));
        assert_eq!(bounded_response::<5>(b"12345").await.unwrap(), b"12345");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn exchange_io_propagates_every_transport_operation_failure() {
        for stage in [
            FailureStage::Write,
            FailureStage::Flush,
            FailureStage::Shutdown,
            FailureStage::Read,
        ] {
            assert!(matches!(
                exact_exchange_io::<1>(FailingIo(stage), b"request", Duration::from_secs(1)).await,
                Err(RelayProtocolError::Io(_))
            ));
            assert!(matches!(
                bounded_exchange_io::<1>(FailingIo(stage), b"request", Duration::from_secs(1))
                    .await,
                Err(RelayProtocolError::Io(_))
            ));
        }

        assert!(matches!(
            exact_exchange_io::<1>(
                TrailingReadFailureIo::new(),
                b"request",
                Duration::from_secs(1)
            )
            .await,
            Err(RelayProtocolError::Io(_))
        ));
        assert!(matches!(
            bounded_exchange_io::<1>(
                TrailingReadFailureIo::new(),
                b"request",
                Duration::from_secs(1)
            )
            .await,
            Err(RelayProtocolError::Io(_))
        ));
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum FailureStage {
        Write,
        Flush,
        Shutdown,
        Read,
    }

    struct FailingIo(FailureStage);

    struct TrailingReadFailureIo {
        served_response: bool,
    }

    impl TrailingReadFailureIo {
        const fn new() -> Self {
            Self {
                served_response: false,
            }
        }
    }

    impl AsyncRead for FailingIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.0 == FailureStage::Read {
                Poll::Ready(Err(io::Error::other("scripted read failure")))
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }

    impl AsyncWrite for FailingIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.0 == FailureStage::Write {
                Poll::Ready(Err(io::Error::other("scripted write failure")))
            } else {
                Poll::Ready(Ok(buffer.len()))
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.0 == FailureStage::Flush {
                Poll::Ready(Err(io::Error::other("scripted flush failure")))
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.0 == FailureStage::Shutdown {
                Poll::Ready(Err(io::Error::other("scripted shutdown failure")))
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }

    impl AsyncRead for TrailingReadFailureIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.served_response {
                Poll::Ready(Err(io::Error::other("scripted trailing read failure")))
            } else {
                self.served_response = true;
                buffer.put_slice(&[0]);
                Poll::Ready(Ok(()))
            }
        }
    }

    impl AsyncWrite for TrailingReadFailureIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    async fn exact_response(response: &'static [u8]) -> Result<[u8; 5], RelayProtocolError> {
        let (client, mut server) = tokio::io::duplex(32);
        let peer = tokio::spawn(async move {
            let mut request = [0_u8; 3];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"req");
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });
        let result = exact_exchange_io(client, b"req", Duration::from_secs(1)).await;
        peer.await.unwrap();
        result
    }

    async fn bounded_response<const CAPACITY: usize>(
        response: &'static [u8],
    ) -> Result<Vec<u8>, RelayProtocolError> {
        let (client, mut server) = tokio::io::duplex(32);
        let peer = tokio::spawn(async move {
            let mut request = [0_u8; 3];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"req");
            server.write_all(response).await.unwrap();
            server.shutdown().await.unwrap();
        });
        let result = bounded_exchange_io::<CAPACITY>(client, b"req", Duration::from_secs(1))
            .await
            .map(|response| response.as_slice().to_vec());
        peer.await.unwrap();
        result
    }
}
