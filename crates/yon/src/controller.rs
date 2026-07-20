use crate::network::{
    ConnectionBinding, EndpointDriver, EndpointError, EndpointEvent, connect_relay,
    connect_relay_with_policy, connect_target, connect_target_via_relay, drive_bound,
};
use crate::pake::{OpaquePake, OpaquePakeError};
use crate::protocol::{RelayProtocolError, resolve_peer};
use crate::terminal::TerminalChunk;
use backon::{BackoffBuilder as _, ConstantBuilder};
use std::io::IsTerminal as _;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use yonder_core::wire::auth::{
    AuthClientFinish, AuthClientHello, AuthServerResponse, Authenticated, PROCEED_LEN, PakeContext,
    RETRY_LEN,
};
use yonder_core::wire::terminal::{
    CONTROL_LEN, TerminalExit, TerminalHello, TerminalReady, TerminalResize,
};
use yonder_core::wire::{AUTH_PROTOCOL, TERMINAL_CONTROL_PROTOCOL, TERMINAL_DATA_PROTOCOL};
use yonder_core::{
    ConnectionCode, DomainError, OsSecureRandom, Pake, ProtocolError, RandomError, RetryAfter,
    SecureRandom, TerminalSize, TerminalValue,
};
use yonder_net::{
    ApplicationStream, ApplicationStreams, DirectUpgradePolicy, EndpointRelaySet, Keypair,
    Libp2pApplicationStreams, PeerId, WssTransportConfig, generate_identity, peer_id_bytes,
};

const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
const RETRY_LIMIT: usize = 20;
const SIZE_POLL_INTERVAL: Duration = Duration::from_millis(250);
const REMOTE_COMPLETION_TIMEOUT: Duration = Duration::from_secs(2);

trait TerminalFrontend {
    type Input: tokio::io::AsyncRead + Unpin;
    type Output: tokio::io::AsyncWrite + Unpin;
    type RawModeGuard;

    fn is_interactive(&self) -> bool;
    fn output_is_terminal(&self) -> bool;
    fn size(&self) -> Result<(u16, u16), std::io::Error>;
    fn enter_raw_mode(&self) -> Result<Option<Self::RawModeGuard>, std::io::Error>;
    fn input(&mut self) -> Self::Input;
    fn output(&mut self) -> Self::Output;
}

#[derive(Debug, Clone, Copy, Default)]
struct CrosstermFrontend;

impl TerminalFrontend for CrosstermFrontend {
    type Input = tokio::io::Stdin;
    type Output = tokio::io::Stdout;
    type RawModeGuard = RawModeGuard;

    fn is_interactive(&self) -> bool {
        std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
    }

    fn output_is_terminal(&self) -> bool {
        std::io::stdout().is_terminal()
    }

    fn size(&self) -> Result<(u16, u16), std::io::Error> {
        crossterm::terminal::size()
    }

    fn enter_raw_mode(&self) -> Result<Option<Self::RawModeGuard>, std::io::Error> {
        if !self.is_interactive() {
            return Ok(None);
        }
        crossterm::terminal::enable_raw_mode()?;
        Ok(Some(RawModeGuard))
    }

    fn input(&mut self) -> Self::Input {
        tokio::io::stdin()
    }

    fn output(&mut self) -> Self::Output {
        tokio::io::stdout()
    }
}

/// Complete input required to connect to one advertised remote terminal.
pub struct ControllerConfig {
    identity: Keypair,
    relays: EndpointRelaySet,
    wss: WssTransportConfig,
    code: ConnectionCode,
    terminal: TerminalHello,
}

impl ControllerConfig {
    #[must_use]
    pub const fn new(
        identity: Keypair,
        relays: EndpointRelaySet,
        wss: WssTransportConfig,
        code: ConnectionCode,
        terminal: TerminalHello,
    ) -> Self {
        Self {
            identity,
            relays,
            wss,
            code,
            terminal,
        }
    }
}

/// Controller-side failures with secret-independent authentication reporting.
#[derive(Debug, Error)]
pub enum ControllerError {
    #[error(transparent)]
    Endpoint(#[from] EndpointError),
    #[error(transparent)]
    Relay(#[from] RelayProtocolError),
    #[error("secure random generation failed")]
    Random(#[from] RandomError),
    #[error("OPAQUE authentication failed")]
    Pake(#[from] OpaquePakeError),
    #[error("an endpoint identity could not be represented on the wire")]
    PeerIdentity,
    #[error("the controller requires a client TLS transport configuration")]
    InvalidTransportRole,
    #[error("an authentication or terminal exchange timed out")]
    Timeout,
    #[error("endpoint protocol I/O failed")]
    Io(#[from] std::io::Error),
    #[error("an endpoint sent an invalid protocol message")]
    Protocol(#[from] ProtocolError),
    #[error("the authentication retry budget was exhausted")]
    RetryExhausted,
    #[error("the local terminal environment is invalid")]
    TerminalEnvironment,
    #[error("the local terminal dimensions or environment are invalid")]
    TerminalDomain(#[from] DomainError),
    #[error("the controller connection was lost")]
    ConnectionLost,
    #[error("failed to install the local interrupt handler")]
    Signal(#[source] std::io::Error),
    #[error("the controller was interrupted locally")]
    Interrupted,
    #[error("the remote terminal did not finish within the shutdown deadline")]
    RemoteCompletionTimeout,
}

/// Connects, authenticates, and returns the remote shell exit code.
pub async fn run_controller(config: ControllerConfig) -> Result<u32, ControllerError> {
    run_until_interrupted(
        run_controller_session(config, CrosstermFrontend),
        tokio::signal::ctrl_c(),
    )
    .await
}

async fn run_until_interrupted<T>(
    session: impl std::future::Future<Output = Result<T, ControllerError>>,
    signal: impl std::future::Future<Output = Result<(), std::io::Error>>,
) -> Result<T, ControllerError> {
    tokio::select! {
        biased;
        signal = signal => {
            signal.map_err(ControllerError::Signal)?;
            Err(ControllerError::Interrupted)
        }
        result = session => result,
    }
}

async fn run_controller_session<F: TerminalFrontend>(
    config: ControllerConfig,
    frontend: F,
) -> Result<u32, ControllerError> {
    let ControllerConfig {
        identity,
        relays,
        wss,
        code,
        terminal,
    } = config;
    let fallback_wss = fallback_transport(&wss)?;
    let (mut driver, mut streams, relay) = connect_relay(identity, &relays, wss).await?;
    #[cfg(yonder_e2e_rebuild)]
    let initial_peer_id = driver.peer_id();
    let target = resolve_peer(&mut driver, &mut streams, &relay, code.locator()).await?;
    let (mut driver, mut streams, binding) =
        match connect_target(&mut driver, relay.address(), target).await {
            Ok(binding) => (driver, streams, binding),
            Err(error) if direct_fallback_required(&error) => {
                tracing::debug!(%error, "rebuilding the endpoint for strict relay-only fallback");
                drop((driver, streams));
                let mut random = OsSecureRandom;
                let identity = generate_identity(&mut random).map_err(EndpointError::from)?;
                let (mut fallback_driver, mut fallback_streams, fallback_relay) =
                    connect_relay_with_policy(
                        identity,
                        &relays,
                        fallback_wss,
                        DirectUpgradePolicy::Disabled,
                    )
                    .await?;
                let target = resolve_peer(
                    &mut fallback_driver,
                    &mut fallback_streams,
                    &fallback_relay,
                    code.locator(),
                )
                .await?;
                let binding = connect_target_via_relay(
                    &mut fallback_driver,
                    fallback_relay.address(),
                    target,
                )
                .await?;
                #[cfg(yonder_e2e_rebuild)]
                {
                    let fallback_peer_id = fallback_driver.peer_id();
                    let relayed = fallback_driver.binding_is_relayed(binding)?;
                    tracing::debug!(
                        %initial_peer_id,
                        %fallback_peer_id,
                        relayed,
                        "strict relay-only fallback established"
                    );
                }
                (fallback_driver, fallback_streams, binding)
            }
            Err(error) => return Err(error.into()),
        };
    authenticate_controller(&mut driver, &mut streams, binding, &code).await?;
    drop(code);

    let terminal_stream_deadline = tokio::time::Instant::now() + EXCHANGE_TIMEOUT;
    let control = open_until(
        &mut driver,
        &mut streams,
        binding,
        TERMINAL_CONTROL_PROTOCOL,
        terminal_stream_deadline,
    )
    .await?;
    let data = open_until(
        &mut driver,
        &mut streams,
        binding,
        TERMINAL_DATA_PROTOCOL,
        terminal_stream_deadline,
    )
    .await?;
    run_terminal(&mut driver, binding, data, control, terminal, frontend).await
}

fn direct_fallback_required(error: &EndpointError) -> bool {
    matches!(
        error,
        EndpointError::DirectUpgradeFailed | EndpointError::TargetUpgradeDidNotSettle
    )
}

fn fallback_transport(wss: &WssTransportConfig) -> Result<WssTransportConfig, ControllerError> {
    wss.clone_client()
        .ok_or(ControllerError::InvalidTransportRole)
}

/// Captures validated local terminal metadata before network activity begins.
pub fn local_terminal_hello() -> Result<TerminalHello, ControllerError> {
    local_terminal_hello_with(&CrosstermFrontend)
}

fn local_terminal_hello_with(
    frontend: &impl TerminalFrontend,
) -> Result<TerminalHello, ControllerError> {
    let (columns, rows) = if frontend.output_is_terminal() {
        frontend.size()?
    } else {
        (80, 24)
    };
    Ok(TerminalHello::new(
        TerminalSize::new(columns, rows)?,
        terminal_environment("TERM")?,
        terminal_environment("COLORTERM")?,
    ))
}

fn terminal_environment(name: &str) -> Result<TerminalValue, ControllerError> {
    terminal_environment_from(std::env::var(name))
}

fn terminal_environment_from(
    value: Result<String, std::env::VarError>,
) -> Result<TerminalValue, ControllerError> {
    match value {
        Ok(value) => TerminalValue::new(&value).map_err(ControllerError::from),
        Err(std::env::VarError::NotPresent) => {
            TerminalValue::new("").map_err(ControllerError::from)
        }
        Err(std::env::VarError::NotUnicode(_)) => Err(ControllerError::TerminalEnvironment),
    }
}

async fn authenticate_controller(
    driver: &mut EndpointDriver,
    streams: &mut Libp2pApplicationStreams,
    binding: ConnectionBinding,
    code: &ConnectionCode,
) -> Result<(), ControllerError> {
    let mut backoff = ConstantBuilder::default()
        .with_delay(Duration::from_millis(250))
        .with_max_times(RETRY_LIMIT)
        .build();
    loop {
        let stream = open_timed(driver, streams, binding, AUTH_PROTOCOL).await?;
        match drive_bound(
            driver,
            binding,
            authentication_attempt(stream, driver.peer_id(), binding.peer(), code),
        )
        .await??
        {
            AuthenticationOutcome::Authenticated => return Ok(()),
            AuthenticationOutcome::Retry(after) => {
                drive_bound(
                    driver,
                    binding,
                    tokio::time::sleep(next_retry_delay(&mut backoff, after)?),
                )
                .await?;
            }
        }
    }
}

fn next_retry_delay(
    backoff: &mut impl Iterator<Item = Duration>,
    requested: RetryAfter,
) -> Result<Duration, ControllerError> {
    let generated = backoff.next().ok_or(ControllerError::RetryExhausted)?;
    Ok(generated.max(Duration::from_millis(u64::from(requested.millis()))))
}

enum AuthenticationOutcome {
    Authenticated,
    Retry(RetryAfter),
}

async fn authentication_attempt(
    stream: ApplicationStream,
    controller: PeerId,
    target: PeerId,
    code: &ConnectionCode,
) -> Result<AuthenticationOutcome, ControllerError> {
    tokio::time::timeout(EXCHANGE_TIMEOUT, async move {
        let mut stream = stream.into_tokio();
        let mut pake = OpaquePake;
        let target_identity = peer_id_bytes(target).map_err(|_| ControllerError::PeerIdentity)?;
        let (state, ke1) = pake.client_start(&target_identity, code.secret())?;
        let mut controller_nonce = [0_u8; 32];
        OsSecureRandom.try_fill(&mut controller_nonce)?;
        let hello = AuthClientHello::new(controller_nonce, ke1).encode();
        stream.write_all(&hello).await?;
        stream.flush().await?;

        let response = read_auth_response(&mut stream).await?;
        let Some((target_nonce, ke2)) = response.proceed_parts() else {
            return Ok(AuthenticationOutcome::Retry(
                response
                    .retry_after()
                    .expect("a non-proceed response is retry"),
            ));
        };
        let controller = peer_id_bytes(controller).map_err(|_| ControllerError::PeerIdentity)?;
        let context = PakeContext::new(
            code.locator(),
            &controller,
            &target_identity,
            &controller_nonce,
            target_nonce,
        );
        let (ke3, session_key) = pake.client_finish(state, ke2, context.as_bytes())?;
        stream
            .write_all(&AuthClientFinish::new(ke3).ke3()[..])
            .await?;
        stream.flush().await?;
        let mut acknowledged = [0_u8; 1];
        stream.read_exact(&mut acknowledged).await?;
        Authenticated::decode(&acknowledged)?;
        drop(session_key);
        Ok(AuthenticationOutcome::Authenticated)
    })
    .await
    .map_err(|_| ControllerError::Timeout)?
}

async fn read_auth_response(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<AuthServerResponse, ControllerError> {
    let mut tag = [0_u8; 1];
    stream.read_exact(&mut tag).await?;
    match tag[0] {
        0x01 => {
            let mut response = [0_u8; PROCEED_LEN];
            response[0] = tag[0];
            stream.read_exact(&mut response[1..]).await?;
            AuthServerResponse::decode(&response).map_err(ControllerError::from)
        }
        0x02 => {
            let mut response = [0_u8; RETRY_LEN];
            response[0] = tag[0];
            stream.read_exact(&mut response[1..]).await?;
            AuthServerResponse::decode(&response).map_err(ControllerError::from)
        }
        other => Err(ProtocolError::UnknownTag(other).into()),
    }
}

async fn open_timed(
    driver: &mut EndpointDriver,
    streams: &mut Libp2pApplicationStreams,
    binding: ConnectionBinding,
    protocol: &'static str,
) -> Result<ApplicationStream, ControllerError> {
    open_until(
        driver,
        streams,
        binding,
        protocol,
        tokio::time::Instant::now() + EXCHANGE_TIMEOUT,
    )
    .await
}

async fn open_until(
    driver: &mut EndpointDriver,
    streams: &mut Libp2pApplicationStreams,
    binding: ConnectionBinding,
    protocol: &'static str,
    deadline: tokio::time::Instant,
) -> Result<ApplicationStream, ControllerError> {
    await_until(
        deadline,
        drive_bound(driver, binding, streams.open(binding.peer(), protocol)),
    )
    .await??
    .map_err(EndpointError::from)
    .map_err(ControllerError::from)
}

async fn await_until<T>(
    deadline: tokio::time::Instant,
    future: impl std::future::Future<Output = T>,
) -> Result<T, ControllerError> {
    tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| ControllerError::Timeout)
}

async fn run_terminal(
    driver: &mut EndpointDriver,
    binding: ConnectionBinding,
    data: ApplicationStream,
    control: ApplicationStream,
    hello: TerminalHello,
    mut frontend: impl TerminalFrontend,
) -> Result<u32, ControllerError> {
    let (mut data_read, mut data_write) = tokio::io::split(data.into_tokio());
    let (mut control_read, mut control_write) = tokio::io::split(control.into_tokio());
    let handshake = async {
        drive_bound(
            driver,
            binding,
            exchange_terminal_ready_timed(
                &mut data_read,
                &mut control_write,
                &hello,
                EXCHANGE_TIMEOUT,
            ),
        )
        .await??;
        Ok(())
    };
    let (_raw_mode, ()) = enter_raw_mode_before(&frontend, handshake).await?;

    let interactive = frontend.is_interactive();
    let mut input = frontend.input();
    let mut output = frontend.output();
    let mut input_open = true;
    let mut remote = RemoteCompletion::new();
    let mut last_size = hello.size();
    let mut size_poll = tokio::time::interval(SIZE_POLL_INTERVAL);
    size_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        let mut remote_output = TerminalChunk::new();
        let mut exit = [0_u8; 5];
        let completion_deadline = remote.deadline();
        tokio::select! {
            biased;
            () = wait_for_remote_completion_deadline(completion_deadline) => {
                return Err(ControllerError::RemoteCompletionTimeout);
            }
            event = driver.next() => match event {
                EndpointEvent::Established { peer, .. } | EndpointEvent::Closed { peer, .. }
                    if peer == binding.peer() => driver.enforce_binding(binding)?,
                _ => {}
            },
            read = read_local_input(&mut input), if input_open => {
                let Some(local_input) = read? else {
                    drive_terminal_io(
                        driver,
                        binding,
                        completion_deadline,
                        data_write.shutdown(),
                    )
                    .await?;
                    input_open = false;
                    continue;
                };
                tracing::debug!(length = local_input.as_slice().len(), "local terminal input read completed");
                drive_terminal_io(
                    driver,
                    binding,
                    completion_deadline,
                    data_write.write_all(local_input.as_slice()),
                )
                .await?;
                drive_terminal_io(
                    driver,
                    binding,
                    completion_deadline,
                    data_write.flush(),
                )
                .await?;
            }
            read = data_read.read(remote_output.writable()), if remote.output_open() => {
                let length = read?;
                if length == 0 {
                    if let Some(code) = complete_after_output_eof(
                        &mut remote,
                        &mut output,
                        tokio::time::Instant::now(),
                    )
                    .await?
                    {
                        return Ok(code);
                    }
                    continue;
                }
                remote_output.set_len(length).map_err(|_| ControllerError::ConnectionLost)?;
                await_remote_completion(
                    completion_deadline,
                    output.write_all(remote_output.as_slice()),
                )
                .await??;
                await_remote_completion(completion_deadline, output.flush()).await??;
            }
            read = control_read.read_exact(&mut exit), if remote.exit_pending() => {
                read?;
                let code = decode_terminal_exit(&exit)?;
                if let Some(code) = remote.observe_exit(code, tokio::time::Instant::now()) {
                    await_remote_completion(remote.deadline(), output.flush()).await??;
                    return Ok(code);
                }
            }
            _ = size_poll.tick(), if interactive => {
                if let Some((size, resize)) = changed_terminal_size(&frontend, last_size)? {
                    drive_terminal_io(
                        driver,
                        binding,
                        completion_deadline,
                        control_write.write_all(&resize),
                    )
                    .await?;
                    drive_terminal_io(
                        driver,
                        binding,
                        completion_deadline,
                        control_write.flush(),
                    )
                    .await?;
                    last_size = size;
                }
            }
        }
    }
}

async fn enter_raw_mode_before<F: TerminalFrontend, T>(
    frontend: &F,
    operation: impl std::future::Future<Output = Result<T, ControllerError>>,
) -> Result<(Option<F::RawModeGuard>, T), ControllerError> {
    let guard = frontend.enter_raw_mode()?;
    let output = operation.await?;
    Ok((guard, output))
}

fn changed_terminal_size(
    frontend: &impl TerminalFrontend,
    current: TerminalSize,
) -> Result<Option<(TerminalSize, [u8; CONTROL_LEN])>, ControllerError> {
    let (columns, rows) = frontend.size()?;
    let observed = TerminalSize::new(columns, rows)?;
    Ok((observed != current).then_some((observed, TerminalResize::new(observed).encode())))
}

async fn complete_after_output_eof(
    remote: &mut RemoteCompletion,
    output: &mut (impl tokio::io::AsyncWrite + Unpin),
    now: tokio::time::Instant,
) -> Result<Option<u32>, ControllerError> {
    let Some(code) = remote.observe_output_eof(now) else {
        return Ok(None);
    };
    await_remote_completion(remote.deadline(), output.flush()).await??;
    Ok(Some(code))
}

async fn read_local_input(
    input: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<Option<TerminalChunk>, ControllerError> {
    let mut chunk = TerminalChunk::new();
    let length = input.read(chunk.writable()).await?;
    if length == 0 {
        return Ok(None);
    }
    chunk
        .set_len(length)
        .map_err(|_| ControllerError::ConnectionLost)?;
    Ok(Some(chunk))
}

async fn wait_for_remote_completion_deadline(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

async fn await_remote_completion<T>(
    deadline: Option<tokio::time::Instant>,
    future: impl std::future::Future<Output = T>,
) -> Result<T, ControllerError> {
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline, future)
            .await
            .map_err(|_| ControllerError::RemoteCompletionTimeout),
        None => Ok(future.await),
    }
}

async fn drive_terminal_io(
    driver: &mut EndpointDriver,
    binding: ConnectionBinding,
    deadline: Option<tokio::time::Instant>,
    operation: impl std::future::Future<Output = Result<(), std::io::Error>>,
) -> Result<(), ControllerError> {
    let result = await_remote_completion(deadline, drive_bound(driver, binding, operation)).await?;
    result??;
    Ok(())
}

async fn exchange_terminal_ready(
    data: &mut (impl tokio::io::AsyncRead + Unpin),
    control: &mut (impl tokio::io::AsyncWrite + Unpin),
    hello: &TerminalHello,
) -> Result<(), ControllerError> {
    control.write_all(hello.encode().as_slice()).await?;
    control.flush().await?;
    let mut ready = [0_u8; 1];
    data.read_exact(&mut ready).await?;
    TerminalReady::decode(&ready)
        .map(|_| ())
        .map_err(ControllerError::from)
}

async fn exchange_terminal_ready_timed(
    data: &mut (impl tokio::io::AsyncRead + Unpin),
    control: &mut (impl tokio::io::AsyncWrite + Unpin),
    hello: &TerminalHello,
    timeout: Duration,
) -> Result<(), ControllerError> {
    tokio::time::timeout(timeout, exchange_terminal_ready(data, control, hello))
        .await
        .map_err(|_| ControllerError::Timeout)?
}

fn decode_terminal_exit(message: &[u8]) -> Result<u32, ControllerError> {
    TerminalExit::decode(message)
        .map(TerminalExit::code)
        .map_err(ControllerError::from)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum RemoteCompletion {
    #[default]
    AwaitingBoth,
    AwaitingExit {
        deadline: tokio::time::Instant,
    },
    AwaitingOutput {
        code: u32,
        deadline: tokio::time::Instant,
    },
    Complete {
        code: u32,
        deadline: tokio::time::Instant,
    },
}

impl RemoteCompletion {
    const fn new() -> Self {
        Self::AwaitingBoth
    }

    const fn output_open(self) -> bool {
        matches!(self, Self::AwaitingBoth | Self::AwaitingOutput { .. })
    }

    const fn exit_pending(self) -> bool {
        matches!(self, Self::AwaitingBoth | Self::AwaitingExit { .. })
    }

    const fn deadline(self) -> Option<tokio::time::Instant> {
        match self {
            Self::AwaitingExit { deadline }
            | Self::AwaitingOutput { deadline, .. }
            | Self::Complete { deadline, .. } => Some(deadline),
            Self::AwaitingBoth => None,
        }
    }

    fn observe_output_eof(&mut self, now: tokio::time::Instant) -> Option<u32> {
        match *self {
            Self::AwaitingBoth => {
                *self = Self::AwaitingExit {
                    deadline: now + REMOTE_COMPLETION_TIMEOUT,
                };
                None
            }
            Self::AwaitingOutput { code, deadline } => {
                *self = Self::Complete { code, deadline };
                Some(code)
            }
            Self::AwaitingExit { .. } | Self::Complete { .. } => None,
        }
    }

    fn observe_exit(&mut self, code: u32, now: tokio::time::Instant) -> Option<u32> {
        match *self {
            Self::AwaitingBoth => {
                *self = Self::AwaitingOutput {
                    code,
                    deadline: now + REMOTE_COMPLETION_TIMEOUT,
                };
                None
            }
            Self::AwaitingExit { deadline } => {
                *self = Self::Complete { code, deadline };
                Some(code)
            }
            Self::AwaitingOutput { .. } | Self::Complete { .. } => None,
        }
    }
}

struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if let Err(error) = crossterm::terminal::disable_raw_mode() {
            tracing::warn!(%error, "failed to restore local terminal mode");
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        ControllerConfig, ControllerError, CrosstermFrontend, EndpointError,
        REMOTE_COMPLETION_TIMEOUT, RawModeGuard, RemoteCompletion, TerminalFrontend,
        await_remote_completion, await_until, changed_terminal_size, complete_after_output_eof,
        decode_terminal_exit, direct_fallback_required, enter_raw_mode_before,
        exchange_terminal_ready, exchange_terminal_ready_timed, fallback_transport,
        local_terminal_hello, local_terminal_hello_with, next_retry_delay, read_auth_response,
        read_local_input, run_controller, run_until_interrupted, terminal_environment,
        terminal_environment_from, wait_for_remote_completion_deadline,
    };
    use std::cell::Cell;
    use std::io;
    use std::pin::Pin;
    use std::rc::Rc;
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
    use tokio::sync::oneshot;
    use yonder_core::wire::auth::AuthServerResponse;
    use yonder_core::wire::terminal::{TerminalHello, TerminalReady};
    use yonder_core::{
        ConnectionCode, Locator, PakeSecret, RetryAfter, SecretDocument, TerminalSize,
        TerminalValue,
    };
    use yonder_net::{
        EndpointRelayAddress, EndpointRelaySet, Keypair, NetworkBuildError, WssTransportConfig,
    };

    #[test]
    fn relay_only_fallback_is_narrowly_classified_and_requires_client_tls() {
        assert!(direct_fallback_required(
            &EndpointError::DirectUpgradeFailed
        ));
        assert!(direct_fallback_required(
            &EndpointError::TargetUpgradeDidNotSettle
        ));
        for error in [
            EndpointError::RelayUnavailable,
            EndpointError::AdditionalBoundConnection,
            EndpointError::BoundConnectionLost,
        ] {
            assert!(!direct_fallback_required(&error));
        }

        assert!(fallback_transport(&WssTransportConfig::client(None)).is_ok());
        assert!(matches!(
            fallback_transport(&WssTransportConfig::server(
                vec![1],
                SecretDocument::new(vec![2]),
            )),
            Err(ControllerError::InvalidTransportRole)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalid_wss_ca_is_rejected_before_controller_network_activity() {
        let relay_identity = Keypair::generate_ed25519();
        let relay: EndpointRelayAddress = format!(
            "/dns4/localhost/tcp/443/tls/ws/p2p/{}",
            relay_identity.public().to_peer_id()
        )
        .parse()
        .unwrap();
        let config = ControllerConfig::new(
            Keypair::generate_ed25519(),
            EndpointRelaySet::new(vec![relay]).unwrap(),
            WssTransportConfig::client(Some(vec![1])),
            ConnectionCode::new(Locator::new(0).unwrap(), PakeSecret::from_u64(0).unwrap()),
            TerminalHello::new(
                TerminalSize::new(80, 24).unwrap(),
                TerminalValue::new("xterm").unwrap(),
                TerminalValue::new("truecolor").unwrap(),
            ),
        );

        assert!(matches!(
            run_controller(config).await,
            Err(ControllerError::Endpoint(EndpointError::Build(
                NetworkBuildError::InvalidTlsMaterial
            )))
        ));
    }

    #[test]
    fn missing_terminal_environment_is_represented_as_empty() {
        let name = "YONDER_TEST_MISSING_TERMINAL_VALUE";
        assert!(std::env::var_os(name).is_none());
        assert!(terminal_environment(name).unwrap().is_empty());
    }

    #[test]
    fn terminal_environment_boundary_validates_all_platform_results() {
        assert_eq!(
            terminal_environment_from(Ok("xterm-256color".to_owned()))
                .unwrap()
                .as_str(),
            "xterm-256color"
        );
        assert!(
            terminal_environment_from(Err(std::env::VarError::NotPresent))
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            terminal_environment_from(Err(std::env::VarError::NotUnicode(
                std::ffi::OsString::from("invalid")
            ))),
            Err(ControllerError::TerminalEnvironment)
        ));
        assert!(matches!(
            terminal_environment_from(Ok("bad value".to_owned())),
            Err(ControllerError::TerminalDomain(_))
        ));
    }

    #[test]
    fn crossterm_boundary_is_callable_without_an_interactive_terminal() {
        let frontend = CrosstermFrontend;
        let _ = frontend.size();
        if !frontend.is_interactive() {
            assert!(frontend.enter_raw_mode().unwrap().is_none());
            drop(RawModeGuard);
        }
    }

    #[test]
    fn non_interactive_terminal_metadata_uses_safe_defaults() {
        let hello = local_terminal_hello().unwrap();
        assert_eq!(hello.size(), TerminalSize::new(80, 24).unwrap());
    }

    #[test]
    fn terminal_frontend_is_statically_replaceable_and_owns_raw_cleanup() {
        let restored = Rc::new(Cell::new(false));
        let mut frontend = FakeFrontend {
            restored: Rc::clone(&restored),
            size: Ok((132, 43)),
            raw_error: None,
        };
        let hello = local_terminal_hello_with(&frontend).unwrap();
        assert_eq!(hello.size(), TerminalSize::new(132, 43).unwrap());
        assert!(frontend.is_interactive());

        let guard = frontend.enter_raw_mode().unwrap().unwrap();
        let _input = frontend.input();
        let _output = frontend.output();
        assert!(!restored.get());
        drop(guard);
        assert!(restored.get());
    }

    #[test]
    fn terminal_frontend_size_failures_remain_structured() {
        let restored = Rc::new(Cell::new(false));
        let size_error = FakeFrontend {
            restored: Rc::clone(&restored),
            size: Err(io::ErrorKind::Other),
            raw_error: None,
        };
        assert!(matches!(
            local_terminal_hello_with(&size_error),
            Err(ControllerError::Io(_))
        ));

        let invalid_size = FakeFrontend {
            restored,
            size: Ok((0, 43)),
            raw_error: None,
        };
        assert!(matches!(
            local_terminal_hello_with(&invalid_size),
            Err(ControllerError::TerminalDomain(_))
        ));
    }

    #[test]
    fn terminal_resize_polling_validates_and_reports_only_changes() {
        let restored = Rc::new(Cell::new(false));
        let current = TerminalSize::new(80, 24).unwrap();

        let changed = FakeFrontend {
            restored: Rc::clone(&restored),
            size: Ok((132, 43)),
            raw_error: None,
        };
        assert_eq!(
            changed_terminal_size(&changed, current).unwrap(),
            Some((TerminalSize::new(132, 43).unwrap(), [0x02, 0, 132, 0, 43]))
        );

        let unchanged = FakeFrontend {
            restored: Rc::clone(&restored),
            size: Ok((80, 24)),
            raw_error: None,
        };
        assert_eq!(changed_terminal_size(&unchanged, current).unwrap(), None);

        let size_error = FakeFrontend {
            restored: Rc::clone(&restored),
            size: Err(io::ErrorKind::Other),
            raw_error: None,
        };
        assert!(matches!(
            changed_terminal_size(&size_error, current),
            Err(ControllerError::Io(_))
        ));

        let invalid = FakeFrontend {
            restored,
            size: Ok((0, 24)),
            raw_error: None,
        };
        assert!(matches!(
            changed_terminal_size(&invalid, current),
            Err(ControllerError::TerminalDomain(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn raw_mode_is_ready_before_the_terminal_commit_exchange() {
        let restored = Rc::new(Cell::new(false));
        let operation_polled = Rc::new(Cell::new(false));
        let failed = FakeFrontend {
            restored: Rc::clone(&restored),
            size: Ok((80, 24)),
            raw_error: Some(io::ErrorKind::PermissionDenied),
        };
        let polled = Rc::clone(&operation_polled);
        let operation = async move {
            polled.set(true);
            Ok::<_, ControllerError>(())
        };
        assert!(matches!(
            enter_raw_mode_before(&failed, operation).await,
            Err(ControllerError::Io(_))
        ));
        assert!(!operation_polled.get());
        assert!(!restored.get());

        let ready = FakeFrontend {
            restored: Rc::clone(&restored),
            size: Ok((80, 24)),
            raw_error: None,
        };
        let (guard, value) = enter_raw_mode_before(&ready, async { Ok(23) })
            .await
            .unwrap();
        assert_eq!(value, 23);
        assert!(!restored.get());
        drop(guard);
        assert!(restored.get());

        let restored_after_handshake_failure = Rc::new(Cell::new(false));
        let ready = FakeFrontend {
            restored: Rc::clone(&restored_after_handshake_failure),
            size: Ok((80, 24)),
            raw_error: None,
        };
        assert!(matches!(
            enter_raw_mode_before(&ready, async {
                Err::<(), _>(ControllerError::ConnectionLost)
            })
            .await,
            Err(ControllerError::ConnectionLost)
        ));
        assert!(restored_after_handshake_failure.get());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn output_eof_completes_an_exit_first_session_after_flushing() {
        let now = tokio::time::Instant::now();
        let mut awaiting_both = RemoteCompletion::new();
        assert_eq!(
            complete_after_output_eof(&mut awaiting_both, &mut tokio::io::sink(), now)
                .await
                .unwrap(),
            None
        );

        let mut exit_first = RemoteCompletion::new();
        assert_eq!(exit_first.observe_exit(27, now), None);
        assert_eq!(
            complete_after_output_eof(&mut exit_first, &mut tokio::io::sink(), now)
                .await
                .unwrap(),
            Some(27)
        );

        let mut failed_flush = RemoteCompletion::new();
        assert_eq!(failed_flush.observe_exit(31, now), None);
        assert!(matches!(
            complete_after_output_eof(&mut failed_flush, &mut FailingFlush, now).await,
            Err(ControllerError::Io(_))
        ));
    }

    #[test]
    fn retry_delay_honors_both_server_hint_and_local_budget() {
        let mut local_dominates = [Duration::from_millis(250)].into_iter();
        assert_eq!(
            next_retry_delay(&mut local_dominates, RetryAfter::from_millis(100).unwrap()).unwrap(),
            Duration::from_millis(250)
        );

        let mut server_dominates = [Duration::from_millis(250)].into_iter();
        assert_eq!(
            next_retry_delay(&mut server_dominates, RetryAfter::from_millis(500).unwrap()).unwrap(),
            Duration::from_millis(500)
        );

        let mut exhausted = std::iter::empty();
        assert!(matches!(
            next_retry_delay(&mut exhausted, RetryAfter::from_millis(100).unwrap()),
            Err(ControllerError::RetryExhausted)
        ));
    }

    #[test]
    fn remote_completion_requires_both_exit_and_output_eof_in_either_order() {
        let now = tokio::time::Instant::now();
        let mut exit_first = RemoteCompletion::new();
        assert_eq!(exit_first.observe_exit(7, now), None);
        assert_eq!(exit_first.deadline(), Some(now + REMOTE_COMPLETION_TIMEOUT));
        assert_eq!(exit_first.observe_output_eof(now), Some(7));
        assert_eq!(exit_first.deadline(), Some(now + REMOTE_COMPLETION_TIMEOUT));
        assert!(!exit_first.output_open());
        assert!(!exit_first.exit_pending());

        let mut eof_first = RemoteCompletion::new();
        assert_eq!(eof_first.observe_output_eof(now), None);
        assert_eq!(eof_first.deadline(), Some(now + REMOTE_COMPLETION_TIMEOUT));
        assert_eq!(eof_first.observe_exit(9, now), Some(9));
        assert_eq!(eof_first.deadline(), Some(now + REMOTE_COMPLETION_TIMEOUT));

        let mut only_exit = RemoteCompletion::new();
        assert_eq!(only_exit.observe_exit(11, now), None);
        assert!(!only_exit.exit_pending());
        assert!(only_exit.output_open());
        let mut only_eof = RemoteCompletion::new();
        assert_eq!(only_eof.observe_output_eof(now), None);
        assert!(only_eof.exit_pending());
        assert!(!only_eof.output_open());

        assert_eq!(exit_first.observe_exit(99, now), None);
        assert_eq!(exit_first.observe_output_eof(now), None);
        assert_eq!(only_exit.observe_exit(99, now), None);
        assert_eq!(only_eof.observe_output_eof(now), None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn os_interrupt_cancels_the_session_and_drops_its_raw_guard() {
        let restored = Rc::new(Cell::new(false));
        let session_restored = Rc::clone(&restored);
        let (started_tx, started_rx) = oneshot::channel();
        let session = async move {
            let _guard = FakeRawGuard(session_restored);
            started_tx.send(()).unwrap();
            std::future::pending::<Result<u32, ControllerError>>().await
        };
        let signal = async move {
            started_rx.await.unwrap();
            Ok(())
        };

        assert!(matches!(
            run_until_interrupted(session, signal).await,
            Err(ControllerError::Interrupted)
        ));
        assert!(restored.get());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn controller_session_and_signal_failures_remain_distinct() {
        assert_eq!(
            run_until_interrupted(
                async { Ok::<_, ControllerError>(23) },
                std::future::pending(),
            )
            .await
            .unwrap(),
            23
        );
        assert!(matches!(
            run_until_interrupted(
                std::future::pending::<Result<u32, ControllerError>>(),
                async { Err(io::Error::other("signal")) },
            )
            .await,
            Err(ControllerError::Signal(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn completion_deadline_future_is_absolute_and_optional() {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(5);
        tokio::time::timeout(
            Duration::from_millis(50),
            wait_for_remote_completion_deadline(Some(deadline)),
        )
        .await
        .expect("the absolute deadline expires");
        assert!(
            tokio::time::timeout(
                Duration::from_millis(1),
                wait_for_remote_completion_deadline(None),
            )
            .await
            .is_err()
        );

        assert_eq!(
            await_remote_completion(None, async { 41 }).await.unwrap(),
            41
        );
        assert!(matches!(
            await_remote_completion(
                Some(tokio::time::Instant::now() + Duration::from_millis(5)),
                std::future::pending::<()>(),
            )
            .await,
            Err(ControllerError::RemoteCompletionTimeout)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn raw_ctrl_c_byte_remains_uninterpreted_terminal_input() {
        let mut input = [0x03_u8].as_slice();
        let chunk = read_local_input(&mut input)
            .await
            .unwrap()
            .expect("one raw input byte");
        assert_eq!(chunk.as_slice(), [0x03]);

        let mut eof = tokio::io::empty();
        assert!(read_local_input(&mut eof).await.unwrap().is_none());

        assert!(matches!(
            read_local_input(&mut FailingRead).await,
            Err(ControllerError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_handshake_uses_control_for_hello_and_data_for_ready() {
        let hello = TerminalHello::new(
            TerminalSize::new(80, 24).unwrap(),
            TerminalValue::new("xterm").unwrap(),
            TerminalValue::new("truecolor").unwrap(),
        );
        let encoded = hello.encode();
        let (mut controller_data, mut host_data) = tokio::io::duplex(1);
        let length = encoded.as_slice().len();
        let (mut controller_control, mut host_control) = tokio::io::duplex(length);
        let host = async {
            let mut received = vec![0_u8; length];
            host_control.read_exact(&mut received).await.unwrap();
            assert_eq!(received, encoded.as_slice());
            host_data.write_all(&TerminalReady::ENCODED).await.unwrap();
            host_data.flush().await.unwrap();
        };
        let controller =
            exchange_terminal_ready(&mut controller_data, &mut controller_control, &hello);
        let (result, ()) = tokio::join!(controller, host);
        result.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authentication_response_reader_accepts_both_shapes_and_rejects_bad_wire() {
        let proceed = AuthServerResponse::proceed([2; 32], [3; 320]).encode();
        let mut proceed_input = proceed.as_slice();
        let decoded = read_auth_response(&mut proceed_input).await.unwrap();
        assert!(decoded.proceed_parts().is_some());

        let retry = AuthServerResponse::retry(RetryAfter::from_millis(750).unwrap()).encode();
        let mut retry_input = retry.as_slice();
        assert_eq!(
            read_auth_response(&mut retry_input)
                .await
                .unwrap()
                .retry_after()
                .unwrap()
                .millis(),
            750
        );

        let mut unknown = [0xff_u8].as_slice();
        assert!(matches!(
            read_auth_response(&mut unknown).await,
            Err(ControllerError::Protocol(_))
        ));

        let mut invalid_retry = [0x02_u8, 0, 0, 0, 0].as_slice();
        assert!(matches!(
            read_auth_response(&mut invalid_retry).await,
            Err(ControllerError::Protocol(_))
        ));

        let mut truncated = [0x02_u8].as_slice();
        assert!(matches!(
            read_auth_response(&mut truncated).await,
            Err(ControllerError::Io(_))
        ));

        let mut truncated_proceed = [0x01_u8].as_slice();
        assert!(matches!(
            read_auth_response(&mut truncated_proceed).await,
            Err(ControllerError::Io(_))
        ));

        let mut empty = tokio::io::empty();
        assert!(matches!(
            read_auth_response(&mut empty).await,
            Err(ControllerError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_handshake_reports_invalid_ready_and_io_failures() {
        let hello = TerminalHello::new(
            TerminalSize::new(80, 24).unwrap(),
            TerminalValue::new("xterm").unwrap(),
            TerminalValue::new("").unwrap(),
        );

        let mut invalid_ready = [0xff_u8].as_slice();
        let mut control = tokio::io::sink();
        assert!(matches!(
            exchange_terminal_ready(&mut invalid_ready, &mut control, &hello).await,
            Err(ControllerError::Protocol(_))
        ));

        let mut missing_ready = tokio::io::empty();
        assert!(matches!(
            exchange_terminal_ready(&mut missing_ready, &mut control, &hello).await,
            Err(ControllerError::Io(_))
        ));

        let mut valid_ready = TerminalReady::ENCODED.as_slice();
        let (mut rejected_control, peer) = tokio::io::duplex(1);
        drop(peer);
        assert!(matches!(
            exchange_terminal_ready(&mut valid_ready, &mut rejected_control, &hello).await,
            Err(ControllerError::Io(_))
        ));

        let mut valid_ready = TerminalReady::ENCODED.as_slice();
        assert!(matches!(
            exchange_terminal_ready(&mut valid_ready, &mut FailingFlush, &hello).await,
            Err(ControllerError::Io(_))
        ));

        let (_host_data, mut pending_ready) = tokio::io::duplex(1);
        assert!(matches!(
            exchange_terminal_ready_timed(
                &mut pending_ready,
                &mut tokio::io::sink(),
                &hello,
                Duration::from_millis(1),
            )
            .await,
            Err(ControllerError::Timeout)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sequential_operations_share_one_absolute_exchange_deadline() {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
        await_until(
            deadline,
            tokio::time::sleep_until(deadline - Duration::from_millis(100)),
        )
        .await
        .unwrap();

        let second = tokio::time::timeout(
            Duration::from_millis(150),
            await_until(deadline, std::future::pending::<()>()),
        )
        .await
        .expect("the remaining shared budget must expire before a fresh full budget");
        assert!(matches!(second, Err(ControllerError::Timeout)));
    }

    #[test]
    fn terminal_exit_decoder_preserves_code_and_rejects_wrong_direction() {
        assert_eq!(
            decode_terminal_exit(&yonder_core::wire::terminal::TerminalExit::new(23).encode())
                .unwrap(),
            23
        );
        assert!(matches!(
            decode_terminal_exit(&[0x02, 0, 80, 0, 24]),
            Err(ControllerError::Protocol(_))
        ));
    }

    struct FakeFrontend {
        restored: Rc<Cell<bool>>,
        size: Result<(u16, u16), io::ErrorKind>,
        raw_error: Option<io::ErrorKind>,
    }

    impl TerminalFrontend for FakeFrontend {
        type Input = tokio::io::Empty;
        type Output = tokio::io::Sink;
        type RawModeGuard = FakeRawGuard;

        fn is_interactive(&self) -> bool {
            true
        }

        fn output_is_terminal(&self) -> bool {
            true
        }

        fn size(&self) -> Result<(u16, u16), io::Error> {
            self.size.map_err(io::Error::from)
        }

        fn enter_raw_mode(&self) -> Result<Option<Self::RawModeGuard>, io::Error> {
            if let Some(error) = self.raw_error {
                return Err(error.into());
            }
            Ok(Some(FakeRawGuard(Rc::clone(&self.restored))))
        }

        fn input(&mut self) -> Self::Input {
            tokio::io::empty()
        }

        fn output(&mut self) -> Self::Output {
            tokio::io::sink()
        }
    }

    struct FakeRawGuard(Rc<Cell<bool>>);

    impl Drop for FakeRawGuard {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    struct FailingRead;

    impl AsyncRead for FailingRead {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("read failed")))
        }
    }

    struct FailingFlush;

    impl AsyncWrite for FailingFlush {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buffer.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("flush failed")))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}
