use crate::registry::{Registry, RegistryError, ResolveLimiters};
use std::collections::HashSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{Semaphore, mpsc, oneshot};
use yonder_core::wire::registry::{RegistryRequest, RegistryResponse};
use yonder_core::wire::resolve::{ResolveRequest, ResolveResponse};
use yonder_core::wire::{REGISTRY_PROTOCOL, RESOLVE_PROTOCOL};
use yonder_core::{OsSecureRandom, ProtocolError, RelayResourceConfig, RetryAfter, SystemClock};
use yonder_net::behaviour::RelayBehaviourEvent;
use yonder_net::swarm::SwarmEvent;
use yonder_net::{
    ApplicationStream, ApplicationStreamError, ApplicationStreams, ConnectionBook, Keypair,
    ListenerId, Multiaddr, NetworkBuildError, NetworkNodeError, PeerId, RelayExternalAddress,
    RelayListenAddress, RelayNode, TaskFailure, TaskGroup, TransportKind, WssTransportConfig,
};

const MESSAGE_TIMEOUT: Duration = Duration::from_secs(10);
const TASK_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const REGISTRY_READERS: usize = 16;

/// Fully validated inputs required to run a relay process.
pub struct RelayServeConfig {
    identity: Keypair,
    listen: Vec<RelayListenAddress>,
    external: Vec<RelayExternalAddress>,
    wss: WssTransportConfig,
    resources: RelayResourceConfig,
}

impl RelayServeConfig {
    /// Validates address counts and the WSS certificate requirement.
    pub fn new(
        identity: Keypair,
        listen: Vec<RelayListenAddress>,
        external: Vec<RelayExternalAddress>,
        wss: WssTransportConfig,
        has_wss_server: bool,
    ) -> Result<Self, RelayServiceError> {
        Self::with_resources(
            identity,
            listen,
            external,
            wss,
            has_wss_server,
            RelayResourceConfig::default(),
        )
    }

    /// Validates address inputs and attaches an already validated resource policy.
    pub fn with_resources(
        identity: Keypair,
        listen: Vec<RelayListenAddress>,
        external: Vec<RelayExternalAddress>,
        wss: WssTransportConfig,
        has_wss_server: bool,
        resources: RelayResourceConfig,
    ) -> Result<Self, RelayServiceError> {
        if listen.is_empty() || listen.len() > 8 || external.is_empty() || external.len() > 8 {
            return Err(RelayServiceError::InvalidConfiguration);
        }
        if listen
            .iter()
            .any(|address| address.transport() == TransportKind::SecureWebSocket)
            && !has_wss_server
        {
            return Err(RelayServiceError::MissingWssCertificate);
        }
        Ok(Self {
            identity,
            listen,
            external,
            wss,
            resources,
        })
    }
}

/// Root failures that prevent the relay from continuing safely.
#[derive(Debug, Error)]
pub enum RelayServiceError {
    #[error("relay configuration is invalid")]
    InvalidConfiguration,
    #[error("a TLS WebSocket listener requires both certificate and private key")]
    MissingWssCertificate,
    #[error("failed to construct the relay network")]
    NetworkBuild(#[from] NetworkBuildError),
    #[error("failed to start a relay listener")]
    NetworkNode(#[from] NetworkNodeError),
    #[error("failed to register a relay application protocol")]
    ApplicationStreams(#[from] ApplicationStreamError),
    #[error("a required relay application stream registration ended")]
    ProtocolRegistrationEnded,
    #[error(transparent)]
    ProtocolTask(#[from] TaskFailure),
    #[error(transparent)]
    Registry(#[from] RegistryError),
    #[error("failed to install the process signal handler")]
    Signal(#[source] std::io::Error),
    #[error("required relay listener {listener_id:?} reported an error")]
    RequiredListenerError {
        listener_id: ListenerId,
        #[source]
        source: std::io::Error,
    },
    #[error("required relay listener {listener_id:?} closed")]
    RequiredListenerClosed {
        listener_id: ListenerId,
        #[source]
        source: Option<std::io::Error>,
    },
    #[error("failed to report the relay's public addresses")]
    Output(#[source] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ListenerProgress {
    Ignored,
    Pending,
    BecameReady,
    Additional,
}

#[derive(Debug)]
struct RequiredListeners {
    required: HashSet<ListenerId>,
    pending: HashSet<ListenerId>,
    ready_addresses: Vec<Multiaddr>,
    ready_reported: bool,
}

impl RequiredListeners {
    fn new(listener_ids: impl IntoIterator<Item = ListenerId>) -> Self {
        let required: HashSet<_> = listener_ids.into_iter().collect();
        Self {
            pending: required.clone(),
            ready_addresses: Vec::with_capacity(required.len()),
            required,
            ready_reported: false,
        }
    }

    fn observe(&mut self, listener_id: ListenerId, address: &Multiaddr) -> ListenerProgress {
        if !self.required.contains(&listener_id) {
            return ListenerProgress::Ignored;
        }
        if self.ready_reported {
            return ListenerProgress::Additional;
        }
        if self.pending.remove(&listener_id) {
            self.ready_addresses.push(address.clone());
        }
        if self.pending.is_empty() {
            self.ready_reported = true;
            ListenerProgress::BecameReady
        } else {
            ListenerProgress::Pending
        }
    }

    fn is_required(&self, listener_id: &ListenerId) -> bool {
        self.required.contains(listener_id)
    }
}

#[derive(Debug)]
struct RegistryCall {
    peer: PeerId,
    request: RegistryRequest,
    response: oneshot::Sender<Result<RegistryResponse, RegistryError>>,
}

#[derive(Debug)]
struct ResolveCall {
    peer: PeerId,
    request: [u8; 3],
    response: oneshot::Sender<Result<ResolveResponse, ProtocolTaskError>>,
}

#[derive(Debug, Error)]
enum ProtocolTaskError {
    #[error("protocol exchange timed out")]
    Timeout,
    #[error("protocol stream I/O failed")]
    Io(#[from] std::io::Error),
    #[error("protocol message was rejected")]
    Protocol(#[from] ProtocolError),
    #[error("the relay state owner stopped")]
    OwnerStopped,
    #[error("the relay state owner rejected the request")]
    Registry(#[from] RegistryError),
}

/// Runs until Ctrl+C or a root service failure.
pub async fn run_relay(config: RelayServeConfig) -> Result<(), RelayServiceError> {
    run_relay_until(config, tokio::signal::ctrl_c()).await
}

/// Runs the relay until an injected shutdown signal completes.
pub async fn run_relay_until(
    config: RelayServeConfig,
    shutdown: impl Future<Output = Result<(), std::io::Error>>,
) -> Result<(), RelayServiceError> {
    let RelayServeConfig {
        identity,
        listen,
        external,
        wss,
        resources,
    } = config;
    let mut node =
        RelayNode::with_limits(identity, wss, resources.registration(), resources.circuit())?;
    let mut listener_ids = Vec::with_capacity(listen.len());
    for address in &listen {
        listener_ids.push(node.listen(address)?);
    }
    for address in &external {
        node.add_external_address(address);
    }
    let mut listeners = RequiredListeners::new(listener_ids);

    let mut registry_incoming = node.streams().accept(REGISTRY_PROTOCOL)?;
    let mut resolve_incoming = node.streams().accept(RESOLVE_PROTOCOL)?;

    let resolve_concurrency = resources.resolve().concurrency().get();
    let retry_after = resources.resolve().retry_after();
    let (registry_calls_tx, mut registry_calls_rx) = mpsc::channel(REGISTRY_READERS);
    let (resolve_calls_tx, mut resolve_calls_rx) = mpsc::channel(resolve_concurrency);
    let (registry_done_tx, mut registry_done_rx) = mpsc::channel(REGISTRY_READERS);
    let (resolve_done_tx, mut resolve_done_rx) = mpsc::channel(resolve_concurrency);
    let registry_permits = Arc::new(Semaphore::new(REGISTRY_READERS));
    let resolve_permits = Arc::new(Semaphore::new(resolve_concurrency));
    let mut registry_active = HashSet::with_capacity(REGISTRY_READERS);
    let mut resolve_active = HashSet::with_capacity(resolve_concurrency);
    let mut tasks = TaskGroup::new();

    let clock = SystemClock::new();
    let mut registry = Registry::with_limits(
        clock.clone(),
        resources.registration(),
        resources.resolve().retry_after(),
    );
    let mut limiters = ResolveLimiters::with_limits(resources.resolve());
    let mut connections = ConnectionBook::new();
    let mut random = OsSecureRandom;
    tokio::pin!(shutdown);

    let root_result = loop {
        tokio::select! {
            signal = &mut shutdown => {
                break signal.map_err(RelayServiceError::Signal);
            }
            event = node.next_event() => {
                if let Err(error) = handle_swarm_event(
                    event,
                    &mut node,
                    &mut connections,
                    &mut registry,
                    &mut listeners,
                    &external,
                ) {
                    break Err(error);
                }
            }
            incoming = registry_incoming.next() => {
                let Some((peer, stream)) = incoming else {
                    break Err(RelayServiceError::ProtocolRegistrationEnded);
                };
                let Ok(permit) = Arc::clone(&registry_permits).try_acquire_owned() else {
                    continue;
                };
                if registry_active.contains(&peer) || connections.unique(&peer).is_none() {
                    let cancellation = tasks.cancellation();
                    tasks.spawn(async move {
                        let exchange = registry_immediate_retry(stream, retry_after);
                        tokio::select! {
                            result = exchange => log_protocol_result(peer, result),
                            () = cancellation.cancelled() => {}
                        }
                        drop(permit);
                    });
                    continue;
                }
                registry_active.insert(peer);
                let calls = registry_calls_tx.clone();
                let done = registry_done_tx.clone();
                let cancellation = tasks.cancellation();
                tasks.spawn(async move {
                    let exchange = registry_exchange(peer, stream, calls);
                    tokio::select! {
                        result = exchange => log_protocol_result(peer, result),
                        () = cancellation.cancelled() => {}
                    }
                    let _ = done.send(peer).await;
                    drop(permit);
                });
            }
            incoming = resolve_incoming.next() => {
                let Some((peer, stream)) = incoming else {
                    break Err(RelayServiceError::ProtocolRegistrationEnded);
                };
                let Ok(permit) = Arc::clone(&resolve_permits).try_acquire_owned() else {
                    continue;
                };
                if resolve_active.contains(&peer) || connections.unique(&peer).is_none() {
                    let cancellation = tasks.cancellation();
                    tasks.spawn(async move {
                        let exchange = resolve_immediate_retry(stream, retry_after);
                        tokio::select! {
                            result = exchange => log_protocol_result(peer, result),
                            () = cancellation.cancelled() => {}
                        }
                        drop(permit);
                    });
                    continue;
                }
                resolve_active.insert(peer);
                let calls = resolve_calls_tx.clone();
                let done = resolve_done_tx.clone();
                let cancellation = tasks.cancellation();
                tasks.spawn(async move {
                    let exchange = resolve_exchange(peer, stream, calls);
                    tokio::select! {
                        result = exchange => log_protocol_result(peer, result),
                        () = cancellation.cancelled() => {}
                    }
                    let _ = done.send(peer).await;
                    drop(permit);
                });
            }
            Some(call) = registry_calls_rx.recv() => {
                let response = match handle_registry_call(
                    &call,
                    &connections,
                    &mut registry,
                    &mut random,
                ) {
                    Ok(response) => response,
                    Err(error) => break Err(RelayServiceError::Registry(error)),
                };
                let _ = call.response.send(Ok(response));
            }
            Some(call) = resolve_calls_rx.recv() => {
                let response = match handle_resolve_call(
                    &call,
                    &connections,
                    &clock,
                    &mut registry,
                    &mut limiters,
                ) {
                    Ok(response) => Ok(response),
                    Err(ProtocolTaskError::Registry(error)) => {
                        break Err(RelayServiceError::Registry(error));
                    }
                    Err(error) => Err(error),
                };
                let _ = call.response.send(response);
            }
            Some(peer) = registry_done_rx.recv() => {
                registry_active.remove(&peer);
            }
            Some(peer) = resolve_done_rx.recv() => {
                resolve_active.remove(&peer);
            }
            completed = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = completed_task_result(completed) {
                    break Err(error);
                }
            }
        }
    };

    finish_relay_run(root_result, tasks).await
}

fn completed_task_result(
    completed: Option<Result<(), TaskFailure>>,
) -> Result<(), RelayServiceError> {
    match completed {
        Some(Err(failure)) => Err(RelayServiceError::ProtocolTask(failure)),
        Some(Ok(())) | None => Ok(()),
    }
}

async fn finish_relay_run(
    root_result: Result<(), RelayServiceError>,
    tasks: TaskGroup,
) -> Result<(), RelayServiceError> {
    finish_relay_run_with_timeout(root_result, tasks, TASK_SHUTDOWN_TIMEOUT).await
}

async fn finish_relay_run_with_timeout(
    root_result: Result<(), RelayServiceError>,
    tasks: TaskGroup,
    timeout: Duration,
) -> Result<(), RelayServiceError> {
    let shutdown = tasks.shutdown(timeout).await;
    if !shutdown.was_cooperative() {
        tracing::warn!("relay protocol tasks exceeded the shutdown deadline");
    }
    match (root_result, shutdown.failure()) {
        (Err(root), Some(failure)) => {
            tracing::warn!(%failure, "relay protocol task also failed during root shutdown");
            Err(root)
        }
        (Err(root), None) => Err(root),
        (Ok(()), Some(failure)) => Err(RelayServiceError::ProtocolTask(failure)),
        (Ok(()), None) => Ok(()),
    }
}

fn handle_swarm_event<C: yonder_core::MonotonicClock>(
    event: SwarmEvent<RelayBehaviourEvent>,
    node: &mut RelayNode,
    connections: &mut ConnectionBook,
    registry: &mut Registry<C>,
    listeners: &mut RequiredListeners,
    external: &[RelayExternalAddress],
) -> Result<(), RelayServiceError> {
    match event {
        SwarmEvent::ConnectionEstablished {
            peer_id,
            connection_id,
            endpoint,
            ..
        } => {
            if let Err(error) = connections.established(peer_id, connection_id, endpoint) {
                tracing::warn!(%peer_id, %connection_id, %error, "closing connection beyond roster bound");
                node.swarm_mut().close_connection(connection_id);
            }
            registry.set_connection(peer_id, connections.count(&peer_id) > 0);
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            connection_id,
            ..
        } => {
            connections.closed(&peer_id, &connection_id);
            registry.set_connection(peer_id, connections.count(&peer_id) > 0);
        }
        SwarmEvent::NewListenAddr {
            listener_id,
            address,
        } => match listeners.observe(listener_id, &address) {
            ListenerProgress::BecameReady => report_ready(node.peer_id(), listeners, external)?,
            ListenerProgress::Additional => report_listen_address(node.peer_id(), address),
            ListenerProgress::Ignored | ListenerProgress::Pending => {}
        },
        SwarmEvent::ListenerError { listener_id, error } if listeners.is_required(&listener_id) => {
            return Err(RelayServiceError::RequiredListenerError {
                listener_id,
                source: error,
            });
        }
        SwarmEvent::ListenerClosed {
            listener_id,
            reason,
            ..
        } if listeners.is_required(&listener_id) => {
            return Err(RelayServiceError::RequiredListenerClosed {
                listener_id,
                source: reason.err(),
            });
        }
        SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(event)) => match event {
            yonder_net::relay::Event::ReservationReqAccepted { src_peer_id, .. } => {
                registry.set_reservation(src_peer_id, true);
            }
            yonder_net::relay::Event::ReservationClosed { src_peer_id }
            | yonder_net::relay::Event::ReservationTimedOut { src_peer_id } => {
                registry.set_reservation(src_peer_id, false);
            }
            _ => {}
        },
        _ => {}
    }
    Ok(())
}

fn report_ready(
    peer_id: PeerId,
    listeners: &RequiredListeners,
    external: &[RelayExternalAddress],
) -> Result<(), RelayServiceError> {
    for address in &listeners.ready_addresses {
        report_listen_address(peer_id, address.clone());
    }
    let stdout = std::io::stdout();
    report_ready_to(&mut stdout.lock(), peer_id, external).map_err(RelayServiceError::Output)
}

fn report_ready_to(
    output: &mut impl std::io::Write,
    peer_id: PeerId,
    external: &[RelayExternalAddress],
) -> std::io::Result<()> {
    for address in external {
        writeln!(
            output,
            "{}",
            address.with_peer_id(yonder_net::RelayPeerId::new(peer_id))
        )?;
    }
    writeln!(output, "Relay PeerId: {peer_id}")?;
    output.flush()
}

fn report_listen_address(peer_id: PeerId, address: Multiaddr) {
    tracing::debug!(%peer_id, %address, "relay listener is active");
}

fn handle_registry_call<C: yonder_core::MonotonicClock>(
    call: &RegistryCall,
    connections: &ConnectionBook,
    registry: &mut Registry<C>,
    random: &mut OsSecureRandom,
) -> Result<RegistryResponse, RegistryError> {
    let Some(connection) = connections.unique(&call.peer) else {
        return Ok(RegistryResponse::Retry(registry.retry_after()));
    };
    let reclaim = match call.request {
        RegistryRequest::Release(locator) => return Ok(registry.release(call.peer, locator)),
        RegistryRequest::Allocate => None,
        RegistryRequest::Reclaim(locator) => Some(locator),
    };
    let Some(source) = connection.source_prefix() else {
        return Ok(RegistryResponse::Retry(registry.retry_after()));
    };
    match reclaim {
        None => registry.allocate(call.peer, source, random),
        Some(locator) => Ok(registry.reclaim(call.peer, source, locator)),
    }
}

fn handle_resolve_call<C: yonder_core::MonotonicClock>(
    call: &ResolveCall,
    connections: &ConnectionBook,
    clock: &C,
    registry: &mut Registry<C>,
    limiters: &mut ResolveLimiters,
) -> Result<ResolveResponse, ProtocolTaskError> {
    if !limiters.check_global() {
        return Ok(ResolveResponse::Retry(limiters.retry_after()));
    }
    let request = ResolveRequest::decode(&call.request).map_err(ProtocolTaskError::from)?;
    let Some(source) = connections
        .unique(&call.peer)
        .and_then(|connection| connection.source_prefix())
    else {
        return Ok(ResolveResponse::Retry(limiters.retry_after()));
    };
    if !limiters.check_source(source, clock.now()) {
        return Ok(ResolveResponse::Retry(limiters.retry_after()));
    }
    registry
        .resolve(request.locator())
        .map_err(ProtocolTaskError::from)
}

trait ProtocolIo {
    fn into_protocol_io(self) -> impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin;
}

impl ProtocolIo for ApplicationStream {
    fn into_protocol_io(self) -> impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {
        self.into_tokio()
    }
}

async fn registry_exchange<S: ProtocolIo>(
    peer: PeerId,
    stream: S,
    calls: mpsc::Sender<RegistryCall>,
) -> Result<(), ProtocolTaskError> {
    with_timeout(async move {
        let mut stream = stream.into_protocol_io();
        let request = RegistryRequest::decode(&read_exact_eof::<4>(&mut stream).await?)?;
        let (response_tx, response_rx) = oneshot::channel();
        calls
            .send(RegistryCall {
                peer,
                request,
                response: response_tx,
            })
            .await
            .map_err(|_| ProtocolTaskError::OwnerStopped)?;
        let response = response_rx
            .await
            .map_err(|_| ProtocolTaskError::OwnerStopped)??;
        write_close(&mut stream, &response.encode()).await
    })
    .await
}

async fn resolve_exchange<S: ProtocolIo>(
    peer: PeerId,
    stream: S,
    calls: mpsc::Sender<ResolveCall>,
) -> Result<(), ProtocolTaskError> {
    with_timeout(async move {
        let mut stream = stream.into_protocol_io();
        let request = read_exact_eof::<3>(&mut stream).await?;
        let (response_tx, response_rx) = oneshot::channel();
        calls
            .send(ResolveCall {
                peer,
                request,
                response: response_tx,
            })
            .await
            .map_err(|_| ProtocolTaskError::OwnerStopped)?;
        let response = response_rx
            .await
            .map_err(|_| ProtocolTaskError::OwnerStopped)??;
        write_close(&mut stream, response.encode().as_slice()).await
    })
    .await
}

async fn registry_immediate_retry<S: ProtocolIo>(
    stream: S,
    retry_after: RetryAfter,
) -> Result<(), ProtocolTaskError> {
    with_timeout(async move {
        let mut stream = stream.into_protocol_io();
        RegistryRequest::decode(&read_exact_eof::<4>(&mut stream).await?)?;
        write_close(&mut stream, &RegistryResponse::Retry(retry_after).encode()).await
    })
    .await
}

async fn resolve_immediate_retry<S: ProtocolIo>(
    stream: S,
    retry_after: RetryAfter,
) -> Result<(), ProtocolTaskError> {
    with_timeout(async move {
        let mut stream = stream.into_protocol_io();
        read_exact_eof::<3>(&mut stream).await?;
        let response = ResolveResponse::Retry(retry_after).encode();
        write_close(&mut stream, response.as_slice()).await
    })
    .await
}

async fn with_timeout(
    exchange: impl Future<Output = Result<(), ProtocolTaskError>>,
) -> Result<(), ProtocolTaskError> {
    tokio::time::timeout(MESSAGE_TIMEOUT, exchange)
        .await
        .map_err(|_| ProtocolTaskError::Timeout)?
}

async fn read_exact_eof<const LENGTH: usize>(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<[u8; LENGTH], ProtocolTaskError> {
    let mut message = [0_u8; LENGTH];
    stream.read_exact(&mut message).await?;
    let mut trailing = [0_u8; 1];
    if stream.read(&mut trailing).await? != 0 {
        return Err(ProtocolTaskError::Protocol(ProtocolError::TrailingBytes));
    }
    Ok(message)
}

async fn write_close(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    response: &[u8],
) -> Result<(), ProtocolTaskError> {
    stream.write_all(response).await?;
    stream.flush().await?;
    stream.shutdown().await?;
    Ok(())
}

fn log_protocol_result(peer: PeerId, result: Result<(), ProtocolTaskError>) {
    if let Err(error) = result {
        tracing::debug!(%peer, %error, "relay application protocol stream closed");
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        ProtocolIo, ProtocolTaskError, REGISTRY_READERS, RegistryCall, RelayServeConfig,
        RelayServiceError, RequiredListeners, ResolveCall, completed_task_result, finish_relay_run,
        finish_relay_run_with_timeout, handle_registry_call, handle_resolve_call,
        handle_swarm_event as handle_swarm_event_inner, log_protocol_result, read_exact_eof,
        registry_exchange, registry_immediate_retry, report_ready_to, resolve_exchange,
        resolve_immediate_retry, run_relay, run_relay_until, with_timeout, write_close,
    };
    use crate::registry::{Registry, ResolveLimiters};
    use std::io;
    use std::num::NonZeroU32;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::{mpsc, oneshot};
    use yonder_core::{
        Locator, MonotonicClock, OsSecureRandom, ProtocolError, RelayResourceConfig,
        ResolveConcurrency, ResolveLimits, RetryAfter, SystemClock,
        wire::registry::{RegistryRequest, RegistryResponse},
        wire::resolve::{ResolveRequest, ResolveResponse},
    };
    use yonder_net::behaviour::RelayBehaviourEvent;
    use yonder_net::swarm::SwarmEvent;
    use yonder_net::{
        ApplicationStream, ApplicationStreams, ConnectedPoint, ConnectionBook, ConnectionId,
        EndpointNode, Keypair, Libp2pApplicationStreams, PeerId, RelayExternalAddress,
        RelayListenAddress, RelayNode, TaskGroup, WssTransportConfig,
    };

    impl ProtocolIo for tokio::io::DuplexStream {
        fn into_protocol_io(self) -> impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin {
            self
        }
    }

    struct FailingOutput;

    impl io::Write for FailingOutput {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed output"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed output"))
        }
    }

    #[test]
    fn ready_output_contains_only_public_addresses_and_propagates_failures() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let external: RelayExternalAddress = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        let mut output = Vec::new();
        report_ready_to(&mut output, peer, std::slice::from_ref(&external)).unwrap();
        let text = String::from_utf8(output).unwrap();
        let lines = text.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            external
                .with_peer_id(yonder_net::RelayPeerId::new(peer))
                .to_string()
        );
        assert_eq!(lines[1], format!("Relay PeerId: {peer}"));

        let error = report_ready_to(&mut FailingOutput, peer, &[external]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn relay_configuration_enforces_every_bounded_input() {
        let identity = Keypair::generate_ed25519();
        assert!(matches!(
            RelayServeConfig::new(
                identity.clone(),
                Vec::new(),
                Vec::new(),
                WssTransportConfig::client(None),
                false,
            ),
            Err(RelayServiceError::InvalidConfiguration)
        ));
        let listener: RelayListenAddress = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        let external: RelayExternalAddress = "/ip4/127.0.0.1/tcp/1".parse().unwrap();
        assert!(matches!(
            RelayServeConfig::new(
                identity.clone(),
                vec![listener.clone()],
                Vec::new(),
                WssTransportConfig::client(None),
                false,
            ),
            Err(RelayServiceError::InvalidConfiguration)
        ));
        assert!(matches!(
            RelayServeConfig::new(
                identity.clone(),
                vec![listener.clone(); 9],
                vec![external.clone()],
                WssTransportConfig::client(None),
                false,
            ),
            Err(RelayServiceError::InvalidConfiguration)
        ));
        assert!(matches!(
            RelayServeConfig::new(
                identity.clone(),
                vec![listener],
                vec![external.clone(); 9],
                WssTransportConfig::client(None),
                false,
            ),
            Err(RelayServiceError::InvalidConfiguration)
        ));
        let resources = resources_with_resolve_concurrency(2);
        let configured = RelayServeConfig::with_resources(
            identity.clone(),
            vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            vec![external.clone()],
            WssTransportConfig::client(None),
            false,
            resources,
        )
        .unwrap();
        assert_eq!(configured.resources, resources);
        let secure: RelayListenAddress = "/ip4/127.0.0.1/tcp/0/tls/ws".parse().unwrap();
        assert!(matches!(
            RelayServeConfig::new(
                identity,
                vec![secure],
                vec![external],
                WssTransportConfig::client(None),
                false,
            ),
            Err(RelayServiceError::MissingWssCertificate)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_starts_and_obeys_injected_shutdown_results() {
        let relay_config = config();
        run_relay_until(relay_config, async { Ok(()) })
            .await
            .unwrap();

        let error = run_relay_until(config(), async { Err(io::Error::other("signal")) })
            .await
            .unwrap_err();
        assert!(matches!(error, RelayServiceError::Signal(_)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn live_relay_bounds_registry_and_resolve_stream_readers() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let port = available_tcp_port();
            let relay_identity = Keypair::generate_ed25519();
            let relay_peer = relay_identity.public().to_peer_id();
            let listen: RelayListenAddress = format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap();
            let external: RelayExternalAddress =
                format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap();
            let resources = resources_with_resolve_concurrency(2);
            let resolve_readers = resources.resolve().concurrency().get();
            let relay_config = RelayServeConfig::with_resources(
                relay_identity,
                vec![listen],
                vec![external],
                WssTransportConfig::client(None),
                false,
                resources,
            )
            .unwrap();
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let relay = tokio::spawn(run_relay_until(relay_config, async move {
                let _ = shutdown_rx.await;
                Ok(())
            }));

            tokio::task::yield_now().await;
            let mut endpoint = EndpointNode::new(
                Keypair::generate_ed25519(),
                WssTransportConfig::client(None),
            )
            .unwrap();
            let relay_address = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{relay_peer}")
                .parse()
                .unwrap();
            endpoint.dial(relay_address).unwrap();
            wait_for_connection(&mut endpoint, relay_peer).await;
            let mut streams = endpoint.streams().clone();

            let registry = open_stream(
                &mut endpoint,
                &mut streams,
                relay_peer,
                yonder_core::wire::REGISTRY_PROTOCOL,
            )
            .await;
            let registry_response =
                exchange_stream(&mut endpoint, registry, &RegistryRequest::Allocate.encode()).await;
            assert!(matches!(
                RegistryResponse::decode(&registry_response).unwrap(),
                RegistryResponse::ReservationRequired
            ));
            tokio::task::yield_now().await;

            let resolve = open_stream(
                &mut endpoint,
                &mut streams,
                relay_peer,
                yonder_core::wire::RESOLVE_PROTOCOL,
            )
            .await;
            let resolve_response = exchange_stream(
                &mut endpoint,
                resolve,
                &ResolveRequest::new(Locator::new(7).unwrap()).encode(),
            )
            .await;
            assert_eq!(
                ResolveResponse::decode(&resolve_response).unwrap(),
                ResolveResponse::Unavailable
            );
            tokio::task::yield_now().await;

            let mut registry_streams = Vec::with_capacity(REGISTRY_READERS);
            for _ in 0..REGISTRY_READERS {
                registry_streams.push(
                    open_stream(
                        &mut endpoint,
                        &mut streams,
                        relay_peer,
                        yonder_core::wire::REGISTRY_PROTOCOL,
                    )
                    .await,
                );
            }
            tokio::task::yield_now().await;
            let registry_overflow = open_stream(
                &mut endpoint,
                &mut streams,
                relay_peer,
                yonder_core::wire::REGISTRY_PROTOCOL,
            )
            .await;
            assert_stream_closed(&mut endpoint, registry_overflow).await;

            let mut resolve_streams = Vec::with_capacity(resolve_readers);
            for _ in 0..resolve_readers {
                resolve_streams.push(
                    open_stream(
                        &mut endpoint,
                        &mut streams,
                        relay_peer,
                        yonder_core::wire::RESOLVE_PROTOCOL,
                    )
                    .await,
                );
            }
            tokio::task::yield_now().await;
            let resolve_overflow = open_stream(
                &mut endpoint,
                &mut streams,
                relay_peer,
                yonder_core::wire::RESOLVE_PROTOCOL,
            )
            .await;
            assert_stream_closed(&mut endpoint, resolve_overflow).await;

            drop((registry_streams, resolve_streams));
            shutdown_tx.send(()).unwrap();
            relay.await.unwrap().unwrap();
        })
        .await
        .expect("the bounded live relay scenario must finish");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn public_relay_entry_reports_an_unusable_secure_listener() {
        let secure: RelayListenAddress = "/ip4/127.0.0.1/tcp/0/tls/ws".parse().unwrap();
        let config = RelayServeConfig::new(
            Keypair::generate_ed25519(),
            vec![secure],
            vec!["/ip4/127.0.0.1/tcp/1/tls/ws".parse().unwrap()],
            WssTransportConfig::client(None),
            true,
        )
        .unwrap();

        assert!(matches!(
            run_relay(config).await,
            Err(RelayServiceError::NetworkNode(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn root_failure_still_cancels_and_joins_active_protocol_tasks() {
        let mut tasks = TaskGroup::new();
        let cancellation = tasks.cancellation();
        let (cancelled_tx, cancelled_rx) = oneshot::channel();
        tasks.spawn(async move {
            cancellation.cancelled().await;
            let _ = cancelled_tx.send(());
        });

        let error = finish_relay_run(
            Err(RelayServiceError::Signal(io::Error::other("signal"))),
            tasks,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, RelayServiceError::Signal(_)));
        tokio::time::timeout(Duration::from_millis(50), cancelled_rx)
            .await
            .expect("the active task must receive cancellation")
            .expect("the active task reports cancellation before exit");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_shutdown_reports_and_aborts_uncooperative_protocol_tasks() {
        let mut tasks = TaskGroup::new();
        tasks.spawn(std::future::pending());
        assert!(
            finish_relay_run_with_timeout(Ok(()), tasks, Duration::from_millis(1))
                .await
                .is_ok()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn relay_shutdown_propagates_protocol_task_panics() {
        let mut tasks = TaskGroup::new();
        tasks.spawn(async { panic!("protocol task panic") });
        tokio::task::yield_now().await;

        assert!(matches!(
            finish_relay_run(Ok(()), tasks).await,
            Err(RelayServiceError::ProtocolTask(
                yonder_net::TaskFailure::Panicked
            ))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn root_failure_remains_authoritative_when_a_protocol_task_also_fails() {
        let mut tasks = TaskGroup::new();
        tasks.spawn(async { panic!("protocol task panic during root shutdown") });
        tokio::task::yield_now().await;

        assert!(matches!(
            finish_relay_run(
                Err(RelayServiceError::Signal(io::Error::other("signal"))),
                tasks,
            )
            .await,
            Err(RelayServiceError::Signal(_))
        ));
    }

    #[test]
    fn protocol_task_completion_only_escalates_abnormal_outcomes() {
        assert!(completed_task_result(None).is_ok());
        assert!(completed_task_result(Some(Ok(()))).is_ok());
        for failure in [
            yonder_net::TaskFailure::Panicked,
            yonder_net::TaskFailure::Cancelled,
        ] {
            assert!(matches!(
                completed_task_result(Some(Err(failure))),
                Err(RelayServiceError::ProtocolTask(observed)) if observed == failure
            ));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn bounded_protocol_io_accepts_exact_messages_and_closes_writes() {
        let (mut writer, mut reader) = tokio::io::duplex(16);
        let send = async move {
            writer.write_all(&[1, 2, 3]).await.unwrap();
            writer.shutdown().await.unwrap();
        };
        let receive = async move { read_exact_eof::<3>(&mut reader).await.unwrap() };
        let (_, message) = tokio::join!(send, receive);
        assert_eq!(message, [1, 2, 3]);

        let (mut writer, mut reader) = tokio::io::duplex(16);
        writer.write_all(&[1, 2, 3, 4]).await.unwrap();
        writer.shutdown().await.unwrap();
        assert!(matches!(
            read_exact_eof::<3>(&mut reader).await,
            Err(ProtocolTaskError::Protocol(ProtocolError::TrailingBytes))
        ));

        let (mut writer, mut reader) = tokio::io::duplex(16);
        writer.write_all(&[1, 2]).await.unwrap();
        writer.shutdown().await.unwrap();
        assert!(matches!(
            read_exact_eof::<3>(&mut reader).await,
            Err(ProtocolTaskError::Io(_))
        ));

        let (mut writer, mut reader) = tokio::io::duplex(16);
        let send = async move { write_close(&mut writer, &[4, 5, 6]).await.unwrap() };
        let receive = async move {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await.unwrap();
            bytes
        };
        let (_, bytes) = tokio::join!(send, receive);
        assert_eq!(bytes, [4, 5, 6]);

        let (mut writer, reader) = tokio::io::duplex(1);
        drop(reader);
        assert!(matches!(
            write_close(&mut writer, &[1]).await,
            Err(ProtocolTaskError::Io(_))
        ));

        let mut trailing_failure = ExactThenError::new([1, 2, 3]);
        assert!(matches!(
            read_exact_eof::<3>(&mut trailing_failure).await,
            Err(ProtocolTaskError::Io(_))
        ));

        let mut flush_failure = FailingWrite::new(WriteFailure::Flush);
        assert!(matches!(
            write_close(&mut flush_failure, &[1]).await,
            Err(ProtocolTaskError::Io(_))
        ));
        let mut shutdown_failure = FailingWrite::new(WriteFailure::Shutdown);
        assert!(matches!(
            write_close(&mut shutdown_failure, &[1]).await,
            Err(ProtocolTaskError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn protocol_timeout_and_logging_paths_are_observable() {
        assert!(with_timeout(async { Ok(()) }).await.is_ok());
        assert!(matches!(
            with_timeout(async { Err(ProtocolTaskError::OwnerStopped) }).await,
            Err(ProtocolTaskError::OwnerStopped)
        ));
        assert!(matches!(
            with_timeout(std::future::pending()).await,
            Err(ProtocolTaskError::Timeout)
        ));

        let peer = Keypair::generate_ed25519().public().to_peer_id();
        log_protocol_result(peer, Ok(()));
        log_protocol_result(peer, Err(ProtocolTaskError::OwnerStopped));
        assert_eq!(retry_after().millis(), 250);
        assert_eq!(RegistryResponse::Retry(retry_after()).encode()[0], 0x82);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn actor_protocol_exchanges_and_immediate_retries_use_exact_wire_messages() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let locator = Locator::new(7).unwrap();

        let (registry_client, registry_server) = tokio::io::duplex(32);
        let (registry_tx, mut registry_rx) = mpsc::channel::<RegistryCall>(1);
        let registry_owner = async {
            let call = registry_rx
                .recv()
                .await
                .expect("registry call is delivered");
            assert_eq!(call.peer, peer);
            assert_eq!(call.request, RegistryRequest::Reclaim(locator));
            call.response
                .send(Ok(RegistryResponse::Acquired(locator)))
                .expect("exchange still waits for the actor");
        };
        let registry_request = RegistryRequest::Reclaim(locator).encode();
        let (exchange, response, ()) = tokio::join!(
            registry_exchange(peer, registry_server, registry_tx),
            request_response(registry_client, &registry_request),
            registry_owner,
        );
        exchange.unwrap();
        assert_eq!(response, RegistryResponse::Acquired(locator).encode());

        let (resolve_client, resolve_server) = tokio::io::duplex(96);
        let (resolve_tx, mut resolve_rx) = mpsc::channel::<ResolveCall>(1);
        let resolved_peer = Keypair::generate_ed25519().public().to_peer_id();
        let resolved = yonder_net::peer_id_bytes(resolved_peer).unwrap();
        let resolve_owner = async {
            let call = resolve_rx.recv().await.expect("resolve call is delivered");
            assert_eq!(call.peer, peer);
            assert_eq!(call.request, ResolveRequest::new(locator).encode());
            call.response
                .send(Ok(ResolveResponse::Resolved(resolved.clone())))
                .expect("exchange still waits for the actor");
        };
        let resolve_request = ResolveRequest::new(locator).encode();
        let (exchange, response, ()) = tokio::join!(
            resolve_exchange(peer, resolve_server, resolve_tx),
            request_response(resolve_client, &resolve_request),
            resolve_owner,
        );
        exchange.unwrap();
        assert_eq!(
            ResolveResponse::decode(&response).unwrap(),
            ResolveResponse::Resolved(resolved)
        );

        let (client, server) = tokio::io::duplex(32);
        let allocate_request = RegistryRequest::Allocate.encode();
        let configured_retry = RetryAfter::from_millis(100).unwrap();
        let (result, response) = tokio::join!(
            registry_immediate_retry(server, configured_retry),
            request_response(client, &allocate_request)
        );
        result.unwrap();
        assert_eq!(
            RegistryResponse::decode(&response).unwrap(),
            RegistryResponse::Retry(configured_retry)
        );

        let (client, server) = tokio::io::duplex(32);
        let resolve_request = ResolveRequest::new(locator).encode();
        let (result, response) = tokio::join!(
            resolve_immediate_retry(server, configured_retry),
            request_response(client, &resolve_request)
        );
        result.unwrap();
        assert_eq!(
            ResolveResponse::decode(&response).unwrap(),
            ResolveResponse::Retry(configured_retry)
        );

        let (mut client, server) = tokio::io::duplex(32);
        let (calls, owner) = mpsc::channel(1);
        drop(owner);
        let send = async move {
            client
                .write_all(&RegistryRequest::Allocate.encode())
                .await
                .unwrap();
            client.shutdown().await.unwrap();
        };
        let (result, ()) = tokio::join!(registry_exchange(peer, server, calls), send);
        assert!(matches!(result, Err(ProtocolTaskError::OwnerStopped)));

        let (client, server) = tokio::io::duplex(32);
        let (calls, mut owner) = mpsc::channel::<RegistryCall>(1);
        let drop_response = async move {
            drop(owner.recv().await.expect("registry call is delivered"));
        };
        let allocate = RegistryRequest::Allocate.encode();
        let (result, _response, ()) = tokio::join!(
            registry_exchange(peer, server, calls),
            request_response(client, &allocate),
            drop_response,
        );
        assert!(matches!(result, Err(ProtocolTaskError::OwnerStopped)));

        let (client, server) = tokio::io::duplex(32);
        let (calls, owner) = mpsc::channel(1);
        drop(owner);
        let (result, _response) = tokio::join!(
            resolve_exchange(peer, server, calls),
            request_response(client, &resolve_request),
        );
        assert!(matches!(result, Err(ProtocolTaskError::OwnerStopped)));

        let (client, server) = tokio::io::duplex(32);
        let (calls, mut owner) = mpsc::channel::<ResolveCall>(1);
        let drop_response = async move {
            drop(owner.recv().await.expect("resolve call is delivered"));
        };
        let (result, _response, ()) = tokio::join!(
            resolve_exchange(peer, server, calls),
            request_response(client, &resolve_request),
            drop_response,
        );
        assert!(matches!(result, Err(ProtocolTaskError::OwnerStopped)));

        let (client, server) = tokio::io::duplex(32);
        let (calls, mut owner) = mpsc::channel::<RegistryCall>(1);
        let reject = async move {
            let call = owner.recv().await.expect("registry call is delivered");
            call.response
                .send(Err(crate::registry::RegistryError::Random(
                    yonder_core::RandomError,
                )))
                .expect("exchange still waits for the actor");
        };
        let (result, _response, ()) = tokio::join!(
            registry_exchange(peer, server, calls),
            request_response(client, &allocate),
            reject,
        );
        assert!(matches!(result, Err(ProtocolTaskError::Registry(_))));

        let (client, server) = tokio::io::duplex(32);
        let (calls, mut owner) = mpsc::channel::<ResolveCall>(1);
        let reject = async move {
            let call = owner.recv().await.expect("resolve call is delivered");
            call.response
                .send(Err(ProtocolTaskError::OwnerStopped))
                .expect("exchange still waits for the actor");
        };
        let (result, _response, ()) = tokio::join!(
            resolve_exchange(peer, server, calls),
            request_response(client, &resolve_request),
            reject,
        );
        assert!(matches!(result, Err(ProtocolTaskError::OwnerStopped)));

        let (client, server) = tokio::io::duplex(32);
        let invalid_registry = [0xff, 0, 0, 0];
        let (result, response) = tokio::join!(
            registry_exchange(peer, server, mpsc::channel(1).0),
            request_response(client, &invalid_registry),
        );
        assert!(matches!(result, Err(ProtocolTaskError::Protocol(_))));
        assert!(response.is_empty());

        let (client, server) = tokio::io::duplex(32);
        let (result, response) = tokio::join!(
            registry_immediate_retry(server, retry_after()),
            request_response(client, &invalid_registry),
        );
        assert!(matches!(result, Err(ProtocolTaskError::Protocol(_))));
        assert!(response.is_empty());

        let (client, server) = tokio::io::duplex(32);
        let (result, response) = tokio::join!(
            resolve_exchange(peer, server, mpsc::channel(1).0),
            request_response(client, &[0, 0]),
        );
        assert!(matches!(result, Err(ProtocolTaskError::Io(_))));
        assert!(response.is_empty());

        let (client, server) = tokio::io::duplex(32);
        let (result, response) = tokio::join!(
            resolve_immediate_retry(server, retry_after()),
            request_response(client, &[0, 0]),
        );
        assert!(matches!(result, Err(ProtocolTaskError::Io(_))));
        assert!(response.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resolve_immediate_retry_does_not_decode_a_complete_request() {
        let (client, server) = tokio::io::duplex(32);
        let invalid_locator = [0x10, 0, 0];
        let (result, response) = tokio::join!(
            resolve_immediate_retry(server, retry_after()),
            request_response(client, &invalid_locator)
        );

        result.unwrap();
        assert!(matches!(
            ResolveResponse::decode(&response).unwrap(),
            ResolveResponse::Retry(_)
        ));
    }

    #[test]
    fn registry_release_rechecks_the_unique_connection_barrier() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let mut connections = ConnectionBook::new();
        connections
            .established(peer, ConnectionId::new_unchecked(1), endpoint())
            .unwrap();
        let clock = SystemClock::new();
        let mut registry = Registry::new(clock);
        registry.set_connection(peer, true);
        registry.set_reservation(peer, true);
        let mut random = OsSecureRandom;

        let RegistryResponse::Acquired(locator) = handle_registry_call(
            &registry_call(peer, RegistryRequest::Allocate),
            &connections,
            &mut registry,
            &mut random,
        )
        .unwrap() else {
            panic!("available peer receives a locator");
        };
        connections
            .established(peer, ConnectionId::new_unchecked(2), endpoint())
            .unwrap();

        assert!(matches!(
            handle_registry_call(
                &registry_call(peer, RegistryRequest::Release(locator)),
                &connections,
                &mut registry,
                &mut random,
            )
            .unwrap(),
            RegistryResponse::Retry(_)
        ));
        assert!(matches!(
            registry.resolve(locator).unwrap(),
            ResolveResponse::Resolved(_)
        ));
    }

    #[test]
    fn registry_and_resolve_handlers_cover_every_admission_result() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let mut connections = ConnectionBook::new();
        connections
            .established(peer, ConnectionId::new_unchecked(1), endpoint())
            .unwrap();
        let clock = SystemClock::new();
        let mut registry = Registry::new(clock.clone());
        registry.set_connection(peer, true);
        registry.set_reservation(peer, true);
        let mut random = OsSecureRandom;

        let response = handle_registry_call(
            &registry_call(peer, RegistryRequest::Allocate),
            &connections,
            &mut registry,
            &mut random,
        )
        .unwrap();
        let RegistryResponse::Acquired(locator) = response else {
            panic!("available peer receives a locator");
        };
        assert_eq!(
            handle_registry_call(
                &registry_call(peer, RegistryRequest::Reclaim(locator)),
                &connections,
                &mut registry,
                &mut random,
            )
            .unwrap(),
            RegistryResponse::Acquired(locator)
        );
        assert_eq!(
            handle_registry_call(
                &registry_call(peer, RegistryRequest::Release(locator)),
                &connections,
                &mut registry,
                &mut random,
            )
            .unwrap(),
            RegistryResponse::Released
        );
        let other = Keypair::generate_ed25519().public().to_peer_id();
        assert!(matches!(
            handle_registry_call(
                &registry_call(other, RegistryRequest::Allocate),
                &connections,
                &mut registry,
                &mut random,
            )
            .unwrap(),
            RegistryResponse::Retry(_)
        ));

        let no_source = Keypair::generate_ed25519().public().to_peer_id();
        connections
            .established(
                no_source,
                ConnectionId::new_unchecked(2),
                ConnectedPoint::Listener {
                    local_addr: "/memory/1".parse().unwrap(),
                    send_back_addr: "/memory/2".parse().unwrap(),
                },
            )
            .unwrap();
        assert!(matches!(
            handle_registry_call(
                &registry_call(no_source, RegistryRequest::Allocate),
                &connections,
                &mut registry,
                &mut random,
            )
            .unwrap(),
            RegistryResponse::Retry(_)
        ));

        let valid = resolve_call(peer, locator);
        let mut exhausted_global = ResolveLimiters::new();
        for _ in 0..128 {
            assert!(exhausted_global.check_global());
        }
        assert!(matches!(
            handle_resolve_call(
                &valid,
                &connections,
                &clock,
                &mut registry,
                &mut exhausted_global,
            )
            .unwrap(),
            ResolveResponse::Retry(_)
        ));

        let mut fresh = ResolveLimiters::new();
        assert!(matches!(
            handle_resolve_call(
                &resolve_call(other, locator),
                &connections,
                &clock,
                &mut registry,
                &mut fresh,
            )
            .unwrap(),
            ResolveResponse::Retry(_)
        ));

        let source = connections.unique(&peer).unwrap().source_prefix().unwrap();
        let mut exhausted_source = ResolveLimiters::new();
        for _ in 0..32 {
            assert!(exhausted_source.check_source(source, clock.now()));
        }
        assert!(matches!(
            handle_resolve_call(
                &valid,
                &connections,
                &clock,
                &mut registry,
                &mut exhausted_source,
            )
            .unwrap(),
            ResolveResponse::Retry(_)
        ));

        assert_eq!(
            handle_resolve_call(
                &valid,
                &connections,
                &clock,
                &mut registry,
                &mut ResolveLimiters::new(),
            )
            .unwrap(),
            ResolveResponse::Unavailable
        );
        registry.reclaim(peer, source, locator);
        assert!(matches!(
            handle_resolve_call(
                &valid,
                &connections,
                &clock,
                &mut registry,
                &mut ResolveLimiters::new(),
            )
            .unwrap(),
            ResolveResponse::Resolved(_)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn swarm_events_drive_connection_and_reservation_state() {
        let identity = Keypair::generate_ed25519();
        let mut node = RelayNode::new(identity, WssTransportConfig::client(None)).unwrap();
        let listen: RelayListenAddress = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        let listener_id = node.listen(&listen).unwrap();
        let clock = SystemClock::new();
        let mut registry = Registry::new(clock);
        let mut connections = ConnectionBook::new();
        let peer = Keypair::generate_ed25519().public().to_peer_id();

        handle_swarm_event(
            SwarmEvent::NewListenAddr {
                listener_id,
                address: "/ip4/127.0.0.1/tcp/4001".parse().unwrap(),
            },
            &mut node,
            &mut connections,
            &mut registry,
        );
        handle_swarm_event(
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(
                yonder_net::relay::Event::ReservationReqAccepted {
                    src_peer_id: peer,
                    renewed: false,
                },
            )),
            &mut node,
            &mut connections,
            &mut registry,
        );
        handle_swarm_event(
            established_event(peer, ConnectionId::new_unchecked(1), 1),
            &mut node,
            &mut connections,
            &mut registry,
        );
        let RegistryResponse::Acquired(locator) = registry
            .allocate(peer, source(), &mut OsSecureRandom)
            .unwrap()
        else {
            panic!("reservation and connection activate the registry");
        };

        handle_swarm_event(
            SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(
                yonder_net::relay::Event::CircuitReqAccepted {
                    src_peer_id: peer,
                    dst_peer_id: Keypair::generate_ed25519().public().to_peer_id(),
                },
            )),
            &mut node,
            &mut connections,
            &mut registry,
        );
        handle_swarm_event(
            SwarmEvent::Dialing {
                peer_id: Some(peer),
                connection_id: ConnectionId::new_unchecked(99),
            },
            &mut node,
            &mut connections,
            &mut registry,
        );
        handle_swarm_event(
            closed_event(peer, ConnectionId::new_unchecked(1), 0),
            &mut node,
            &mut connections,
            &mut registry,
        );
        assert!(matches!(
            registry.resolve(locator).unwrap(),
            ResolveResponse::Retry(_)
        ));

        handle_swarm_event(
            established_event(peer, ConnectionId::new_unchecked(2), 1),
            &mut node,
            &mut connections,
            &mut registry,
        );
        assert!(matches!(
            registry.resolve(locator).unwrap(),
            ResolveResponse::Resolved(_)
        ));
        for event in [
            yonder_net::relay::Event::ReservationClosed { src_peer_id: peer },
            yonder_net::relay::Event::ReservationTimedOut { src_peer_id: peer },
        ] {
            handle_swarm_event(
                SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(event)),
                &mut node,
                &mut connections,
                &mut registry,
            );
        }
        assert!(matches!(
            registry.resolve(locator).unwrap(),
            ResolveResponse::Retry(_)
        ));

        let overflow = Keypair::generate_ed25519().public().to_peer_id();
        for value in 1..=9 {
            handle_swarm_event(
                established_event(
                    overflow,
                    ConnectionId::new_unchecked(value),
                    u32::try_from(value).unwrap(),
                ),
                &mut node,
                &mut connections,
                &mut registry,
            );
        }
        assert_eq!(connections.count(&overflow), 8);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn required_listener_readiness_and_failures_are_authoritative() {
        let identity = Keypair::generate_ed25519();
        let mut node = RelayNode::new(identity, WssTransportConfig::client(None)).unwrap();
        let first = node
            .listen(&"/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let second = node
            .listen(&"/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();
        let untracked = node
            .listen(&"/ip4/127.0.0.1/tcp/0/ws".parse().unwrap())
            .unwrap();
        let mut listeners = RequiredListeners::new([first, second]);
        let mut connections = ConnectionBook::new();
        let mut registry = Registry::new(SystemClock::new());
        let first_address: yonder_net::Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        let second_address: yonder_net::Multiaddr =
            "/ip4/127.0.0.1/udp/4002/quic-v1".parse().unwrap();

        handle_swarm_event_inner(
            SwarmEvent::NewListenAddr {
                listener_id: first,
                address: first_address.clone(),
            },
            &mut node,
            &mut connections,
            &mut registry,
            &mut listeners,
            &[],
        )
        .unwrap();
        assert_eq!(listeners.pending.len(), 1);
        assert!(!listeners.ready_reported);
        handle_swarm_event_inner(
            SwarmEvent::NewListenAddr {
                listener_id: first,
                address: first_address,
            },
            &mut node,
            &mut connections,
            &mut registry,
            &mut listeners,
            &[],
        )
        .unwrap();
        assert_eq!(listeners.ready_addresses.len(), 1);
        handle_swarm_event_inner(
            SwarmEvent::NewListenAddr {
                listener_id: second,
                address: second_address.clone(),
            },
            &mut node,
            &mut connections,
            &mut registry,
            &mut listeners,
            &[],
        )
        .unwrap();
        assert!(listeners.ready_reported);
        assert_eq!(listeners.ready_addresses.len(), 2);
        handle_swarm_event_inner(
            SwarmEvent::NewListenAddr {
                listener_id: second,
                address: second_address,
            },
            &mut node,
            &mut connections,
            &mut registry,
            &mut listeners,
            &[],
        )
        .unwrap();

        handle_swarm_event_inner(
            SwarmEvent::ListenerError {
                listener_id: untracked,
                error: io::Error::other("ignored"),
            },
            &mut node,
            &mut connections,
            &mut registry,
            &mut listeners,
            &[],
        )
        .unwrap();
        handle_swarm_event_inner(
            SwarmEvent::ListenerClosed {
                listener_id: untracked,
                addresses: Vec::new(),
                reason: Ok(()),
            },
            &mut node,
            &mut connections,
            &mut registry,
            &mut listeners,
            &[],
        )
        .unwrap();
        assert!(matches!(
            handle_swarm_event_inner(
                SwarmEvent::ListenerError {
                    listener_id: first,
                    error: io::Error::other("listener failed"),
                },
                &mut node,
                &mut connections,
                &mut registry,
                &mut listeners,
                &[],
            ),
            Err(RelayServiceError::RequiredListenerError { listener_id, .. })
                if listener_id == first
        ));
        assert!(matches!(
            handle_swarm_event_inner(
                SwarmEvent::ListenerClosed {
                    listener_id: second,
                    addresses: Vec::new(),
                    reason: Ok(()),
                },
                &mut node,
                &mut connections,
                &mut registry,
                &mut listeners,
                &[],
            ),
            Err(RelayServiceError::RequiredListenerClosed {
                listener_id,
                source: None,
            }) if listener_id == second
        ));
        assert!(matches!(
            handle_swarm_event_inner(
                SwarmEvent::ListenerClosed {
                    listener_id: first,
                    addresses: Vec::new(),
                    reason: Err(io::Error::other("listener closed")),
                },
                &mut node,
                &mut connections,
                &mut registry,
                &mut listeners,
                &[],
            ),
            Err(RelayServiceError::RequiredListenerClosed {
                listener_id,
                source: Some(_),
            }) if listener_id == first
        ));
    }

    #[test]
    fn complete_invalid_resolve_messages_consume_global_capacity_before_decode() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let (response, _receiver) = oneshot::channel();
        let call = ResolveCall {
            peer,
            request: [0x10, 0, 0],
            response,
        };
        let mut connections = ConnectionBook::new();
        let connection = ConnectionId::new_unchecked(1);
        connections
            .established(
                peer,
                connection,
                ConnectedPoint::Listener {
                    local_addr: "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
                    send_back_addr: "/ip4/192.0.2.1/tcp/1".parse().unwrap(),
                },
            )
            .unwrap();
        let source = connections
            .unique(&peer)
            .and_then(|entry| entry.source_prefix())
            .unwrap();
        let clock = SystemClock::new();
        let mut registry = Registry::new(clock.clone());
        let mut limiters = ResolveLimiters::new();

        assert!(matches!(
            handle_resolve_call(&call, &connections, &clock, &mut registry, &mut limiters,),
            Err(ProtocolTaskError::Protocol(_))
        ));
        for _ in 0..127 {
            assert!(limiters.check_global());
        }
        assert!(!limiters.check_global());
        for _ in 0..32 {
            assert!(limiters.check_source(source, clock.now()));
        }
        assert!(!limiters.check_source(source, clock.now()));
    }

    async fn request_response(mut stream: tokio::io::DuplexStream, request: &[u8]) -> Vec<u8> {
        stream.write_all(request).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        response
    }

    fn available_tcp_port() -> u16 {
        std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    async fn wait_for_connection(endpoint: &mut EndpointNode, relay: PeerId) {
        loop {
            match endpoint.next_event().await {
                SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == relay => return,
                SwarmEvent::OutgoingConnectionError { error, .. } => {
                    panic!("relay connection failed: {error}")
                }
                _ => {}
            }
        }
    }

    async fn open_stream(
        endpoint: &mut EndpointNode,
        streams: &mut Libp2pApplicationStreams,
        relay: PeerId,
        protocol: &'static str,
    ) -> ApplicationStream {
        let open = streams.open(relay, protocol);
        tokio::pin!(open);
        loop {
            tokio::select! {
                result = &mut open => return result.unwrap(),
                _ = endpoint.next_event() => {}
            }
        }
    }

    async fn assert_stream_closed(endpoint: &mut EndpointNode, stream: ApplicationStream) {
        let mut stream = stream.into_tokio();
        let mut byte = [0_u8; 1];
        let read = stream.read(&mut byte);
        tokio::pin!(read);
        loop {
            tokio::select! {
                result = &mut read => {
                    match result {
                        Ok(0) => return,
                        Err(error) if matches!(
                            error.kind(),
                            io::ErrorKind::BrokenPipe
                                | io::ErrorKind::ConnectionAborted
                                | io::ErrorKind::ConnectionReset
                        ) => return,
                        other => panic!("overflow stream was not closed: {other:?}"),
                    }
                }
                _ = endpoint.next_event() => {}
            }
        }
    }

    async fn exchange_stream(
        endpoint: &mut EndpointNode,
        stream: ApplicationStream,
        request: &[u8],
    ) -> Vec<u8> {
        let mut stream = stream.into_tokio();
        let exchange = async move {
            stream.write_all(request).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            response
        };
        tokio::pin!(exchange);
        loop {
            tokio::select! {
                response = &mut exchange => return response,
                _ = endpoint.next_event() => {}
            }
        }
    }

    struct ExactThenError<const LENGTH: usize> {
        bytes: [u8; LENGTH],
        emitted: bool,
    }

    impl<const LENGTH: usize> ExactThenError<LENGTH> {
        const fn new(bytes: [u8; LENGTH]) -> Self {
            Self {
                bytes,
                emitted: false,
            }
        }
    }

    impl<const LENGTH: usize> tokio::io::AsyncRead for ExactThenError<LENGTH> {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.emitted {
                return Poll::Ready(Err(io::Error::other("trailing read failed")));
            }
            buffer.put_slice(&this.bytes);
            this.emitted = true;
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Clone, Copy)]
    enum WriteFailure {
        Flush,
        Shutdown,
    }

    struct FailingWrite(WriteFailure);

    impl FailingWrite {
        const fn new(failure: WriteFailure) -> Self {
            Self(failure)
        }
    }

    impl tokio::io::AsyncWrite for FailingWrite {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.0 {
                WriteFailure::Flush => Poll::Ready(Err(io::Error::other("flush failed"))),
                WriteFailure::Shutdown => Poll::Ready(Ok(())),
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.0 {
                WriteFailure::Flush => Poll::Ready(Ok(())),
                WriteFailure::Shutdown => Poll::Ready(Err(io::Error::other("shutdown failed"))),
            }
        }
    }

    fn retry_after() -> RetryAfter {
        RelayResourceConfig::default().resolve().retry_after()
    }

    fn resources_with_resolve_concurrency(concurrency: usize) -> RelayResourceConfig {
        let defaults = RelayResourceConfig::default();
        let resolve = defaults.resolve();
        let configured = ResolveLimits::new(
            ResolveConcurrency::new(concurrency).unwrap(),
            resolve.global(),
            resolve.source(),
            resolve.source_limiter_capacity(),
            resolve.source_limiter_idle(),
            resolve.retry_after(),
        )
        .unwrap();
        RelayResourceConfig::new(defaults.registration(), configured, defaults.circuit())
    }

    fn handle_swarm_event<C: MonotonicClock>(
        event: SwarmEvent<RelayBehaviourEvent>,
        node: &mut RelayNode,
        connections: &mut ConnectionBook,
        registry: &mut Registry<C>,
    ) {
        let mut listeners = RequiredListeners::new([]);
        handle_swarm_event_inner(event, node, connections, registry, &mut listeners, &[]).unwrap();
    }

    fn registry_call(peer: yonder_net::PeerId, request: RegistryRequest) -> RegistryCall {
        let (response, _receiver) = oneshot::channel();
        RegistryCall {
            peer,
            request,
            response,
        }
    }

    fn resolve_call(peer: yonder_net::PeerId, locator: Locator) -> ResolveCall {
        let (response, _receiver) = oneshot::channel();
        ResolveCall {
            peer,
            request: ResolveRequest::new(locator).encode(),
            response,
        }
    }

    fn endpoint() -> ConnectedPoint {
        ConnectedPoint::Listener {
            local_addr: "/ip4/127.0.0.1/tcp/1".parse().unwrap(),
            send_back_addr: "/ip4/192.0.2.1/tcp/1".parse().unwrap(),
        }
    }

    fn source() -> yonder_net::SourcePrefix {
        yonder_net::SourcePrefix::Ipv4("192.0.2.1".parse().unwrap())
    }

    fn established_event(
        peer_id: yonder_net::PeerId,
        connection_id: ConnectionId,
        num_established: u32,
    ) -> SwarmEvent<RelayBehaviourEvent> {
        SwarmEvent::ConnectionEstablished {
            peer_id,
            connection_id,
            endpoint: endpoint(),
            num_established: NonZeroU32::new(num_established).unwrap(),
            concurrent_dial_errors: None,
            established_in: Duration::ZERO,
        }
    }

    fn closed_event(
        peer_id: yonder_net::PeerId,
        connection_id: ConnectionId,
        num_established: u32,
    ) -> SwarmEvent<RelayBehaviourEvent> {
        SwarmEvent::ConnectionClosed {
            peer_id,
            connection_id,
            endpoint: endpoint(),
            num_established,
            cause: None,
        }
    }

    fn config() -> RelayServeConfig {
        RelayServeConfig::new(
            Keypair::generate_ed25519(),
            vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            vec!["/ip4/127.0.0.1/tcp/1".parse().unwrap()],
            WssTransportConfig::client(None),
            false,
        )
        .unwrap()
    }
}
