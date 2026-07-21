use crate::network::{
    ConnectionBinding, EndpointDriver, EndpointError, EndpointEvent, connect_relay,
    connect_relay_with_policy, connect_target, connect_target_via_relay, drive_bound,
};
use crate::pake::{OpaquePake, OpaquePakeError};
use crate::progress::{NoopProgress, OperationProgress, wait_with_progress};
use crate::protocol::{RelayProtocolError, ResolveDeadline, resolve_peer};
use crate::terminal::TerminalChunk;
use backon::{BackoffBuilder as _, ConstantBuilder};
use std::convert::Infallible;
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
    ApplicationStream, ApplicationStreams, DirectUpgradePolicy, EndpointRelayAddress,
    EndpointRelaySet, Keypair, Libp2pApplicationStreams, PeerId, WssTransportConfig,
    generate_identity, peer_id_bytes,
};

const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
const RETRY_LIMIT: usize = 20;
const SIZE_POLL_INTERVAL: Duration = Duration::from_millis(250);
const REMOTE_COMPLETION_TIMEOUT: Duration = Duration::from_secs(2);
const LOCAL_ESCAPE: u8 = 0x1d;
const UTF8_SEQUENCE_CAPACITY: usize = 4;
const UTF8_OUTPUT_BATCH_CAPACITY: usize = 4 * 1024;
const UTF8_REPLACEMENT: &[u8] = "\u{fffd}".as_bytes();

trait TerminalFrontend {
    type Input: tokio::io::AsyncRead + Unpin;
    type Output: tokio::io::AsyncWrite + Unpin;
    type RawModeGuard;

    fn is_interactive(&self) -> bool;
    fn output_is_terminal(&self) -> bool;
    fn size(&self) -> Result<(u16, u16), std::io::Error>;
    fn enter_raw_mode(&self) -> Result<Option<Self::RawModeGuard>, std::io::Error>;
    fn restore_raw_mode(&self, guard: Option<Self::RawModeGuard>) -> Result<(), std::io::Error> {
        drop(guard);
        Ok(())
    }
    fn restore_display(&self) -> Result<(), std::io::Error> {
        Ok(())
    }
    fn input(&mut self) -> Self::Input;
    fn output(&mut self) -> Self::Output;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteTerminalOutputMode {
    Bytes,
    WindowsConsoleUtf8,
}

impl RemoteTerminalOutputMode {
    const fn native(output_is_terminal: bool) -> Self {
        if cfg!(windows) && output_is_terminal {
            Self::WindowsConsoleUtf8
        } else {
            Self::Bytes
        }
    }
}

struct RemoteTerminalOutput {
    mode: RemoteTerminalOutputMode,
    pending: [u8; UTF8_SEQUENCE_CAPACITY],
    pending_len: usize,
}

struct Utf8OutputBatch {
    bytes: [u8; UTF8_OUTPUT_BATCH_CAPACITY],
    len: usize,
}

impl Utf8OutputBatch {
    const fn new() -> Self {
        Self {
            bytes: [0; UTF8_OUTPUT_BATCH_CAPACITY],
            len: 0,
        }
    }

    async fn append(
        &mut self,
        output: &mut (impl tokio::io::AsyncWrite + Unpin),
        bytes: &[u8],
    ) -> Result<(), std::io::Error> {
        debug_assert!(std::str::from_utf8(bytes).is_ok());
        if bytes.len() > self.bytes.len() {
            self.flush(output).await?;
            return output.write_all(bytes).await;
        }
        if bytes.len() > self.bytes.len() - self.len {
            self.flush(output).await?;
        }
        self.bytes[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }

    async fn flush(
        &mut self,
        output: &mut (impl tokio::io::AsyncWrite + Unpin),
    ) -> Result<(), std::io::Error> {
        if self.len != 0 {
            output.write_all(&self.bytes[..self.len]).await?;
            self.len = 0;
        }
        Ok(())
    }
}

impl RemoteTerminalOutput {
    const fn new(mode: RemoteTerminalOutputMode) -> Self {
        Self {
            mode,
            pending: [0; UTF8_SEQUENCE_CAPACITY],
            pending_len: 0,
        }
    }

    async fn write(
        &mut self,
        output: &mut (impl tokio::io::AsyncWrite + Unpin),
        bytes: &[u8],
    ) -> Result<(), std::io::Error> {
        match self.mode {
            RemoteTerminalOutputMode::Bytes => output.write_all(bytes).await,
            RemoteTerminalOutputMode::WindowsConsoleUtf8 => {
                self.write_windows_console_utf8(output, bytes).await
            }
        }
    }

    async fn write_windows_console_utf8(
        &mut self,
        output: &mut (impl tokio::io::AsyncWrite + Unpin),
        mut bytes: &[u8],
    ) -> Result<(), std::io::Error> {
        let mut batch = Utf8OutputBatch::new();
        while self.pending_len != 0 {
            let Some((&next, remaining)) = bytes.split_first() else {
                return batch.flush(output).await;
            };
            let candidate_len = self.pending_len + 1;
            self.pending[self.pending_len] = next;
            match std::str::from_utf8(&self.pending[..candidate_len]) {
                Ok(_) => {
                    batch.append(output, &self.pending[..candidate_len]).await?;
                    self.pending_len = 0;
                    bytes = remaining;
                }
                Err(error) if error.error_len().is_none() => {
                    self.pending_len = candidate_len;
                    bytes = remaining;
                }
                Err(_) => {
                    batch.append(output, UTF8_REPLACEMENT).await?;
                    self.pending_len = 0;
                }
            }
        }

        while !bytes.is_empty() {
            match std::str::from_utf8(bytes) {
                Ok(_) => {
                    batch.append(output, bytes).await?;
                    return batch.flush(output).await;
                }
                Err(error) => {
                    let valid_len = error.valid_up_to();
                    if valid_len != 0 {
                        batch.append(output, &bytes[..valid_len]).await?;
                        bytes = &bytes[valid_len..];
                    }
                    if let Some(invalid_len) = error.error_len() {
                        batch.append(output, UTF8_REPLACEMENT).await?;
                        bytes = &bytes[invalid_len..];
                    } else {
                        debug_assert!(bytes.len() < UTF8_SEQUENCE_CAPACITY);
                        self.pending[..bytes.len()].copy_from_slice(bytes);
                        self.pending_len = bytes.len();
                        return batch.flush(output).await;
                    }
                }
            }
        }
        batch.flush(output).await
    }

    async fn finish(
        &mut self,
        output: &mut (impl tokio::io::AsyncWrite + Unpin),
    ) -> Result<(), std::io::Error> {
        if self.mode == RemoteTerminalOutputMode::WindowsConsoleUtf8 && self.pending_len != 0 {
            output.write_all(UTF8_REPLACEMENT).await?;
            self.pending_len = 0;
        }
        output.flush().await
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct CrosstermFrontend;

impl TerminalFrontend for CrosstermFrontend {
    type Input = tokio::io::Stdin;
    type Output = tokio::io::Stdout;
    type RawModeGuard = RawModeGuard;

    fn is_interactive(&self) -> bool {
        std::io::stdin().is_terminal()
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
        RawModeGuard::enter().map(Some)
    }

    fn restore_raw_mode(&self, guard: Option<Self::RawModeGuard>) -> Result<(), std::io::Error> {
        guard.map_or(Ok(()), RawModeGuard::restore)
    }

    fn restore_display(&self) -> Result<(), std::io::Error> {
        restore_native_display()
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
    #[error("failed to configure the local terminal")]
    TerminalSetup(#[source] std::io::Error),
    #[error("the controller connection was lost")]
    ConnectionLost,
    #[error("failed to install the local interrupt handler")]
    Signal(#[source] std::io::Error),
    #[error("the controller was interrupted locally")]
    Interrupted,
    #[error("the remote terminal did not finish within the shutdown deadline")]
    RemoteCompletionTimeout,
    #[error("failed to restore the local terminal mode")]
    TerminalRestore(#[source] std::io::Error),
    #[error("failed to finish writing remote terminal output")]
    TerminalOutput(#[source] std::io::Error),
    #[error("the session failed and remote terminal output could not be finished: {output}")]
    SessionAndTerminalOutput {
        #[source]
        session: Box<ControllerError>,
        output: std::io::Error,
    },
    #[error("the session failed and the local terminal mode could not be restored: {restore}")]
    SessionAndTerminalRestore {
        #[source]
        session: Box<ControllerError>,
        restore: std::io::Error,
    },
}

/// User-visible milestones emitted while a controller session is being prepared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerStage {
    ConnectingRelay,
    ResolvingHost,
    EstablishingPath,
    RelayFallback,
    Authenticating,
    StartingTerminal,
}

/// Connects, authenticates, and returns the remote shell exit code.
pub async fn run_controller(config: ControllerConfig) -> Result<u32, ControllerError> {
    let display_mode = DisplayModeGuard::enter(native_display_available())
        .map_err(ControllerError::TerminalSetup)?;
    let mut progress = NoopProgress;
    let cancellation = tokio_util::sync::CancellationToken::new();
    let session = Box::pin(run_controller_session(
        config,
        CrosstermFrontend,
        &mut progress,
        cancellation.clone(),
    ));
    let result = run_until_interrupted(
        session,
        crate::shutdown::endpoint_shutdown_signal(),
        cancellation,
    )
    .await;
    finish_terminal(result, DisplayModeGuard::restore_optional(display_mode))
}

/// Connects while reporting bounded, non-secret controller preparation milestones.
pub async fn run_controller_with_progress(
    config: ControllerConfig,
    progress: &mut impl OperationProgress<ControllerStage>,
) -> Result<u32, ControllerError> {
    let display_mode = DisplayModeGuard::enter(native_display_available())
        .map_err(ControllerError::TerminalSetup)?;
    let cancellation = tokio_util::sync::CancellationToken::new();
    let session = Box::pin(run_controller_session(
        config,
        CrosstermFrontend,
        progress,
        cancellation.clone(),
    ));
    let result = run_until_interrupted(
        session,
        crate::shutdown::endpoint_shutdown_signal(),
        cancellation,
    )
    .await;
    finish_terminal(result, DisplayModeGuard::restore_optional(display_mode))
}

fn native_display_available() -> bool {
    std::io::stdout().is_terminal() || std::io::stderr().is_terminal()
}

async fn run_until_interrupted<T>(
    session: impl std::future::Future<Output = Result<T, ControllerError>>,
    signal: impl std::future::Future<Output = Result<(), std::io::Error>>,
    cancellation: tokio_util::sync::CancellationToken,
) -> Result<T, ControllerError> {
    tokio::pin!(session);
    tokio::select! {
        biased;
        signal = signal => {
            let signal = signal.map_err(ControllerError::Signal);
            cancellation.cancel();
            let cleanup = session.await;
            match signal {
                Ok(()) => cleanup,
                Err(error) => {
                    let _ = cleanup;
                    Err(error)
                }
            }
        }
        result = &mut session => result,
    }
}

async fn run_controller_session<F: TerminalFrontend>(
    config: ControllerConfig,
    frontend: F,
    progress: &mut impl OperationProgress<ControllerStage>,
    cancellation: tokio_util::sync::CancellationToken,
) -> Result<u32, ControllerError> {
    let (prepared, terminal) = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Err(ControllerError::Interrupted),
        result = prepare_controller_session(config, progress) => result?,
    };
    run_terminal(prepared, terminal, frontend, progress, &cancellation).await
}

async fn prepare_controller_session(
    config: ControllerConfig,
    progress: &mut impl OperationProgress<ControllerStage>,
) -> Result<(PreparedController, TerminalHello), ControllerError> {
    let ControllerConfig {
        identity,
        relays,
        wss,
        code,
        terminal,
    } = config;
    let fallback_wss = fallback_transport(&wss)?;
    let (mut driver, mut streams, relay) = wait_with_progress(
        progress,
        ControllerStage::ConnectingRelay,
        connect_relay(identity, &relays, wss),
    )
    .await?;
    #[cfg(yonder_e2e_rebuild)]
    let initial_peer_id = driver.peer_id();
    let target = wait_with_progress(
        progress,
        ControllerStage::ResolvingHost,
        resolve_peer(
            &mut driver,
            &mut streams,
            &relay,
            code.locator(),
            ResolveDeadline::controller(),
        ),
    )
    .await?;
    let initial = Box::pin(prepare_controller(
        driver,
        streams,
        relay.address(),
        target,
        &code,
        DirectUpgradePolicy::Enabled,
        progress,
    ))
    .await;
    let prepared = match initial {
        Ok(prepared) => prepared,
        Err(error) if controller_fallback_required(&error) => {
            tracing::debug!(%error, "rebuilding the endpoint for strict relay-only fallback");
            let mut random = OsSecureRandom;
            let identity = generate_identity(&mut random).map_err(EndpointError::from)?;
            let (mut fallback_driver, mut fallback_streams, fallback_relay) = wait_with_progress(
                progress,
                ControllerStage::RelayFallback,
                connect_relay_with_policy(
                    identity,
                    &relays,
                    fallback_wss,
                    DirectUpgradePolicy::Disabled,
                ),
            )
            .await?;
            let target = wait_with_progress(
                progress,
                ControllerStage::ResolvingHost,
                resolve_peer(
                    &mut fallback_driver,
                    &mut fallback_streams,
                    &fallback_relay,
                    code.locator(),
                    ResolveDeadline::controller(),
                ),
            )
            .await?;
            let prepared = Box::pin(prepare_controller(
                fallback_driver,
                fallback_streams,
                fallback_relay.address(),
                target,
                &code,
                DirectUpgradePolicy::Disabled,
                progress,
            ))
            .await?;
            #[cfg(yonder_e2e_rebuild)]
            {
                let fallback_peer_id = prepared.driver.peer_id();
                let relayed = prepared.driver.binding_is_relayed(prepared.binding)?;
                tracing::debug!(
                    %initial_peer_id,
                    %fallback_peer_id,
                    relayed,
                    "strict relay-only fallback established"
                );
            }
            prepared
        }
        Err(error) => return Err(error),
    };
    drop(code);
    Ok((prepared, terminal))
}

struct PreparedController {
    driver: EndpointDriver,
    _streams: Libp2pApplicationStreams,
    binding: ConnectionBinding,
    control: ApplicationStream,
    data: ApplicationStream,
}

async fn prepare_controller(
    mut driver: EndpointDriver,
    mut streams: Libp2pApplicationStreams,
    relay: &EndpointRelayAddress,
    target: PeerId,
    code: &ConnectionCode,
    direct_upgrade: DirectUpgradePolicy,
    progress: &mut impl OperationProgress<ControllerStage>,
) -> Result<PreparedController, ControllerError> {
    let selected = wait_with_progress(progress, ControllerStage::EstablishingPath, async {
        match direct_upgrade {
            DirectUpgradePolicy::Enabled => connect_target(&mut driver, relay, target).await,
            DirectUpgradePolicy::Disabled => {
                connect_target_via_relay(&mut driver, relay, target).await
            }
        }
    })
    .await?;
    let path = selected.path();
    tracing::debug!(
        route = ?path.route(),
        transport = ?path.transport(),
        "endpoint path selected"
    );
    let binding = selected.binding();
    wait_with_progress(
        progress,
        ControllerStage::Authenticating,
        authenticate_controller(&mut driver, &mut streams, binding, code),
    )
    .await?;

    let (control, data) = wait_with_progress(progress, ControllerStage::StartingTerminal, async {
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
        Ok::<_, ControllerError>((control, data))
    })
    .await?;
    Ok(PreparedController {
        driver,
        _streams: streams,
        binding,
        control,
        data,
    })
}

fn controller_fallback_required(error: &ControllerError) -> bool {
    matches!(error, ControllerError::Endpoint(error) if direct_fallback_required(error))
}

fn direct_fallback_required(error: &EndpointError) -> bool {
    matches!(
        error,
        EndpointError::DirectUpgradeFailed
            | EndpointError::TargetUpgradeDidNotSettle
            | EndpointError::AdditionalBoundConnection
            | EndpointError::BoundConnectionLost
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
    let (columns, rows) = if frontend.output_is_terminal() || frontend.is_interactive() {
        frontend.size()?
    } else {
        (80, 24)
    };
    let mut term = terminal_environment("TERM")?;
    if term.is_empty() {
        term = TerminalValue::new(
            if frontend.output_is_terminal() || frontend.is_interactive() {
                "xterm-256color"
            } else {
                "dumb"
            },
        )?;
    }
    Ok(TerminalHello::new(
        TerminalSize::new(columns, rows)?,
        term,
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
    prepared: PreparedController,
    hello: TerminalHello,
    mut frontend: impl TerminalFrontend,
    progress: &mut impl OperationProgress<ControllerStage>,
    cancellation: &tokio_util::sync::CancellationToken,
) -> Result<u32, ControllerError> {
    let PreparedController {
        mut driver,
        _streams,
        binding,
        control,
        data,
    } = prepared;
    let driver = &mut driver;
    let (mut data_read, mut data_write) = tokio::io::split(data.into_tokio());
    let (mut control_read, mut control_write) = tokio::io::split(control.into_tokio());
    let handshake = async {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(ControllerError::Interrupted),
            result = drive_bound(
                driver,
                binding,
                exchange_terminal_ready_timed(
                    &mut data_read,
                    &mut control_write,
                    &hello,
                    EXCHANGE_TIMEOUT,
                ),
            ) => {
                result??;
                Ok(())
            }
        }
    };
    let (raw_mode, ()) = wait_with_progress(
        progress,
        ControllerStage::StartingTerminal,
        enter_raw_mode_before(&frontend, handshake),
    )
    .await?;
    progress.clear();

    let interactive = frontend.is_interactive();
    let output_mode = RemoteTerminalOutputMode::native(frontend.output_is_terminal());
    let mut input = frontend.input();
    let mut output = frontend.output();
    let mut terminal_output = RemoteTerminalOutput::new(output_mode);
    let mut local_escape = LocalInputEscape::new(interactive);
    let mut remote = RemoteCompletion::new();
    let session = {
        let local_input = copy_local_input(&mut input, &mut data_write, &mut local_escape);
        let remote_output = copy_remote_output(&mut data_read, &mut output, &mut terminal_output);
        let remote_exit = read_remote_exit(&mut control_read);
        let terminal_resizes =
            copy_terminal_resizes(&frontend, &mut control_write, hello.size(), interactive);
        tokio::pin!(local_input);
        tokio::pin!(remote_output);
        tokio::pin!(remote_exit);
        tokio::pin!(terminal_resizes);
        loop {
            let completion_deadline = remote.deadline();
            tokio::select! {
                biased;
                () = wait_for_remote_completion_deadline(completion_deadline) => {
                    break Err(ControllerError::RemoteCompletionTimeout);
                }
                event = async {
                    tokio::select! {
                        () = cancellation.cancelled() => TerminalPumpEvent::Cancelled,
                        event = driver.next() => TerminalPumpEvent::Driver(event),
                        result = &mut local_input => TerminalPumpEvent::LocalInput(result),
                        result = &mut remote_output, if remote.output_open() => {
                            TerminalPumpEvent::RemoteOutput(result)
                        }
                        result = &mut remote_exit, if remote.exit_pending() => {
                            TerminalPumpEvent::RemoteExit(result)
                        }
                        result = &mut terminal_resizes => TerminalPumpEvent::Resize(result),
                    }
                } => match event {
                    TerminalPumpEvent::Cancelled => break Err(ControllerError::Interrupted),
                    TerminalPumpEvent::Driver(event) => match event {
                        EndpointEvent::Established { peer, .. } | EndpointEvent::Closed { peer, .. }
                            if peer == binding.peer() => {
                                if let Err(error) = driver.enforce_binding(binding) {
                                    break Err(error.into());
                                }
                            }
                        _ => {}
                    },
                    TerminalPumpEvent::LocalInput(result) => match result {
                        Ok(never) => match never {},
                        Err(error) => break Err(error),
                    },
                    TerminalPumpEvent::RemoteOutput(result) => {
                        if let Err(error) = result {
                            break Err(error);
                        }
                        if let Some(code) = remote.observe_output_eof(tokio::time::Instant::now()) {
                            break Ok(code);
                        }
                    }
                    TerminalPumpEvent::RemoteExit(result) => {
                        let code = match result {
                            Ok(code) => code,
                            Err(error) => break Err(error),
                        };
                        if let Some(code) = remote.observe_exit(code, tokio::time::Instant::now()) {
                            break Ok(code);
                        }
                    }
                    TerminalPumpEvent::Resize(result) => match result {
                        Ok(never) => match never {},
                        Err(error) => break Err(error),
                    }
                }
            }
        }
    };
    let output_deadline = remote
        .deadline()
        .unwrap_or_else(|| tokio::time::Instant::now() + REMOTE_COMPLETION_TIMEOUT);
    let output_finish =
        tokio::time::timeout_at(output_deadline, terminal_output.finish(&mut output))
            .await
            .map_err(|_| ControllerError::RemoteCompletionTimeout)
            .and_then(|result| result.map_err(ControllerError::TerminalOutput));
    let session = finish_terminal_output(session, output_finish);
    let display_restore = if session.is_err() {
        frontend.restore_display()
    } else {
        Ok(())
    };
    let session = finish_terminal(session, display_restore);
    finish_terminal(session, frontend.restore_raw_mode(raw_mode))
}

enum TerminalPumpEvent {
    Cancelled,
    Driver(EndpointEvent),
    LocalInput(Result<Infallible, ControllerError>),
    RemoteOutput(Result<(), ControllerError>),
    RemoteExit(Result<u32, ControllerError>),
    Resize(Result<Infallible, ControllerError>),
}

fn restore_native_display() -> Result<(), std::io::Error> {
    use crossterm::Command as _;
    use std::io::Write as _;

    if !native_display_available() {
        return Ok(());
    }
    let mut commands = String::with_capacity(128);
    crossterm::event::DisableBracketedPaste
        .write_ansi(&mut commands)
        .map_err(std::io::Error::other)?;
    crossterm::event::DisableFocusChange
        .write_ansi(&mut commands)
        .map_err(std::io::Error::other)?;
    crossterm::event::DisableMouseCapture
        .write_ansi(&mut commands)
        .map_err(std::io::Error::other)?;
    crossterm::event::PopKeyboardEnhancementFlags
        .write_ansi(&mut commands)
        .map_err(std::io::Error::other)?;
    crossterm::terminal::LeaveAlternateScreen
        .write_ansi(&mut commands)
        .map_err(std::io::Error::other)?;
    crossterm::cursor::Show
        .write_ansi(&mut commands)
        .map_err(std::io::Error::other)?;
    crossterm::style::SetAttribute(crossterm::style::Attribute::Reset)
        .write_ansi(&mut commands)
        .map_err(std::io::Error::other)?;

    if std::io::stdout().is_terminal() {
        let mut output = std::io::stdout().lock();
        output.write_all(commands.as_bytes())?;
        output.flush()
    } else {
        let mut output = std::io::stderr().lock();
        output.write_all(commands.as_bytes())?;
        output.flush()
    }
}

async fn copy_local_input(
    input: &mut (impl tokio::io::AsyncRead + Unpin),
    data_write: &mut (impl tokio::io::AsyncWrite + Unpin),
    local_escape: &mut LocalInputEscape,
) -> Result<Infallible, ControllerError> {
    loop {
        let Some(local_input) = read_local_input(input, local_escape.read_reserve()).await? else {
            if let Some(pending_escape) = local_escape.finish()? {
                write_local_input_io(data_write, &pending_escape).await?;
            }
            data_write.shutdown().await?;
            return std::future::pending().await;
        };
        tracing::debug!(
            length = local_input.as_slice().len(),
            "local terminal input read completed"
        );
        let filtered = local_escape.filter(local_input)?;
        if !filtered.chunk.as_slice().is_empty() {
            write_local_input_io(data_write, &filtered.chunk).await?;
        }
        if filtered.detach {
            return Err(ControllerError::Interrupted);
        }
        tokio::task::yield_now().await;
    }
}

async fn write_local_input_io(
    data_write: &mut (impl tokio::io::AsyncWrite + Unpin),
    input: &TerminalChunk,
) -> Result<(), ControllerError> {
    data_write.write_all(input.as_slice()).await?;
    data_write.flush().await?;
    Ok(())
}

async fn copy_remote_output(
    data_read: &mut (impl tokio::io::AsyncRead + Unpin),
    output: &mut (impl tokio::io::AsyncWrite + Unpin),
    terminal_output: &mut RemoteTerminalOutput,
) -> Result<(), ControllerError> {
    loop {
        let mut chunk = TerminalChunk::new();
        let length = data_read.read(chunk.writable()).await?;
        if length == 0 {
            return Ok(());
        }
        chunk
            .set_len(length)
            .map_err(|_| ControllerError::ConnectionLost)?;
        terminal_output.write(output, chunk.as_slice()).await?;
        output.flush().await?;
        tokio::task::yield_now().await;
    }
}

async fn read_remote_exit(
    control_read: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<u32, ControllerError> {
    let mut exit = [0_u8; 5];
    control_read.read_exact(&mut exit).await?;
    decode_terminal_exit(&exit)
}

async fn copy_terminal_resizes(
    frontend: &impl TerminalFrontend,
    control_write: &mut (impl tokio::io::AsyncWrite + Unpin),
    mut last_size: TerminalSize,
    enabled: bool,
) -> Result<Infallible, ControllerError> {
    if !enabled {
        return std::future::pending().await;
    }
    let mut poll = tokio::time::interval(SIZE_POLL_INTERVAL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        poll.tick().await;
        let Ok(changed) = changed_terminal_size(frontend, last_size) else {
            continue;
        };
        if let Some((size, resize)) = changed {
            control_write.write_all(&resize).await?;
            control_write.flush().await?;
            last_size = size;
        }
        tokio::task::yield_now().await;
    }
}

struct FilteredLocalInput {
    chunk: TerminalChunk,
    detach: bool,
}

#[derive(Debug, Clone, Copy)]
struct LocalInputEscape {
    enabled: bool,
    pending: bool,
}

impl LocalInputEscape {
    const fn new(enabled: bool) -> Self {
        Self {
            enabled,
            pending: false,
        }
    }

    const fn read_reserve(self) -> usize {
        if self.enabled && self.pending { 1 } else { 0 }
    }

    fn filter(&mut self, input: TerminalChunk) -> Result<FilteredLocalInput, ControllerError> {
        if !self.enabled {
            return Ok(FilteredLocalInput {
                chunk: input,
                detach: false,
            });
        }

        let mut output = TerminalChunk::new();
        let mut length = 0;
        let mut detach = false;
        for &byte in input.as_slice() {
            if self.pending {
                self.pending = false;
                match byte {
                    b'.' => {
                        detach = true;
                        break;
                    }
                    LOCAL_ESCAPE => {
                        push_local_byte(&mut output, &mut length, LOCAL_ESCAPE)?;
                        continue;
                    }
                    _ => {
                        push_local_byte(&mut output, &mut length, LOCAL_ESCAPE)?;
                    }
                }
            }

            if byte == LOCAL_ESCAPE {
                self.pending = true;
            } else {
                push_local_byte(&mut output, &mut length, byte)?;
            }
        }
        output
            .set_len(length)
            .map_err(|_| ControllerError::ConnectionLost)?;
        Ok(FilteredLocalInput {
            chunk: output,
            detach,
        })
    }

    fn finish(&mut self) -> Result<Option<TerminalChunk>, ControllerError> {
        if !self.enabled || !self.pending {
            return Ok(None);
        }
        self.pending = false;
        let mut output = TerminalChunk::new();
        output.writable()[0] = LOCAL_ESCAPE;
        output
            .set_len(1)
            .map_err(|_| ControllerError::ConnectionLost)?;
        Ok(Some(output))
    }
}

fn push_local_byte(
    output: &mut TerminalChunk,
    length: &mut usize,
    byte: u8,
) -> Result<(), ControllerError> {
    let slot = output
        .writable()
        .get_mut(*length)
        .ok_or(ControllerError::ConnectionLost)?;
    *slot = byte;
    *length += 1;
    Ok(())
}

fn finish_terminal<T>(
    session: Result<T, ControllerError>,
    restore: Result<(), std::io::Error>,
) -> Result<T, ControllerError> {
    match (session, restore) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(ControllerError::TerminalRestore(error)),
        (Err(session), Err(restore)) => Err(ControllerError::SessionAndTerminalRestore {
            session: Box::new(session),
            restore,
        }),
    }
}

fn finish_terminal_output<T>(
    session: Result<T, ControllerError>,
    output: Result<(), ControllerError>,
) -> Result<T, ControllerError> {
    match (session, output) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(session), Err(ControllerError::TerminalOutput(output))) => {
            Err(ControllerError::SessionAndTerminalOutput {
                session: Box::new(session),
                output,
            })
        }
        (Err(session), Err(_)) => Err(session),
    }
}

async fn enter_raw_mode_before<F: TerminalFrontend, T>(
    frontend: &F,
    operation: impl std::future::Future<Output = Result<T, ControllerError>>,
) -> Result<(Option<F::RawModeGuard>, T), ControllerError> {
    let guard = frontend
        .enter_raw_mode()
        .map_err(ControllerError::TerminalSetup)?;
    match operation.await {
        Ok(output) => Ok((guard, output)),
        Err(error) => match frontend.restore_raw_mode(guard) {
            Ok(()) => Err(error),
            Err(restore) => Err(ControllerError::SessionAndTerminalRestore {
                session: Box::new(error),
                restore,
            }),
        },
    }
}

fn changed_terminal_size(
    frontend: &impl TerminalFrontend,
    current: TerminalSize,
) -> Result<Option<(TerminalSize, [u8; CONTROL_LEN])>, ControllerError> {
    let (columns, rows) = frontend.size()?;
    let observed = TerminalSize::new(columns, rows)?;
    Ok((observed != current).then_some((observed, TerminalResize::new(observed).encode())))
}

#[cfg(test)]
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
    reserve: usize,
) -> Result<Option<TerminalChunk>, ControllerError> {
    let mut chunk = TerminalChunk::new();
    let capacity = chunk.writable().len().saturating_sub(reserve);
    let length = input.read(&mut chunk.writable()[..capacity]).await?;
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

#[cfg(test)]
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

struct RawModeGuard {
    #[cfg(windows)]
    mode: crossterm_winapi::ConsoleMode,
    #[cfg(windows)]
    original: u32,
    armed: bool,
}

impl RawModeGuard {
    #[cfg(windows)]
    fn enter() -> Result<Self, std::io::Error> {
        const ENABLE_LINE_INPUT: u32 = 0x0002;
        const ENABLE_ECHO_INPUT: u32 = 0x0004;
        const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
        const ENABLE_VIRTUAL_TERMINAL_INPUT: u32 = 0x0200;
        const NOT_RAW: u32 = ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT;

        let mode =
            crossterm_winapi::ConsoleMode::from(crossterm_winapi::Handle::current_in_handle()?);
        let original = mode.mode()?;
        mode.set_mode((original & !NOT_RAW) | ENABLE_VIRTUAL_TERMINAL_INPUT)?;
        Ok(Self {
            mode,
            original,
            armed: true,
        })
    }

    #[cfg(not(windows))]
    fn enter() -> Result<Self, std::io::Error> {
        crossterm::terminal::enable_raw_mode()?;
        Ok(Self { armed: true })
    }

    fn restore(mut self) -> Result<(), std::io::Error> {
        let result = self.restore_inner();
        if result.is_ok() {
            self.armed = false;
        }
        result
    }

    #[cfg(windows)]
    fn restore_inner(&self) -> Result<(), std::io::Error> {
        self.mode.set_mode(self.original)
    }

    #[cfg(not(windows))]
    fn restore_inner(&self) -> Result<(), std::io::Error> {
        crossterm::terminal::disable_raw_mode()
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.restore_inner();
        }
    }
}

struct DisplayModeGuard {
    #[cfg(windows)]
    mode: crossterm_winapi::ConsoleMode,
    #[cfg(windows)]
    original: u32,
    armed: bool,
}

impl DisplayModeGuard {
    #[cfg(windows)]
    fn enter(enabled: bool) -> Result<Option<Self>, std::io::Error> {
        const ENABLE_PROCESSED_OUTPUT: u32 = 0x0001;
        const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;

        if !enabled {
            return Ok(None);
        }
        let mode =
            crossterm_winapi::ConsoleMode::from(crossterm_winapi::Handle::current_out_handle()?);
        let original = mode.mode()?;
        mode.set_mode(original | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING)?;
        Ok(Some(Self {
            mode,
            original,
            armed: true,
        }))
    }

    #[cfg(not(windows))]
    const fn enter(enabled: bool) -> Result<Option<Self>, std::io::Error> {
        if enabled {
            Ok(Some(Self { armed: true }))
        } else {
            Ok(None)
        }
    }

    fn restore_optional(guard: Option<Self>) -> Result<(), std::io::Error> {
        guard.map_or(Ok(()), Self::restore)
    }

    fn restore(mut self) -> Result<(), std::io::Error> {
        let result = self.restore_inner();
        if result.is_ok() {
            self.armed = false;
        }
        result
    }

    #[cfg(windows)]
    fn restore_inner(&self) -> Result<(), std::io::Error> {
        self.mode.set_mode(self.original)
    }

    #[cfg(not(windows))]
    const fn restore_inner(&self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

impl Drop for DisplayModeGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.restore_inner();
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    #[cfg(not(windows))]
    use super::RawModeGuard;
    use super::{
        ControllerConfig, ControllerError, CrosstermFrontend, EndpointError, LOCAL_ESCAPE,
        LocalInputEscape, REMOTE_COMPLETION_TIMEOUT, RemoteCompletion, RemoteTerminalOutput,
        RemoteTerminalOutputMode, TerminalFrontend, await_remote_completion, await_until,
        changed_terminal_size, complete_after_output_eof, controller_fallback_required,
        copy_local_input, copy_remote_output, decode_terminal_exit, direct_fallback_required,
        enter_raw_mode_before, exchange_terminal_ready, exchange_terminal_ready_timed,
        fallback_transport, finish_terminal, local_terminal_hello, local_terminal_hello_with,
        next_retry_delay, read_auth_response, read_local_input, run_controller,
        run_controller_session, run_until_interrupted, terminal_environment,
        terminal_environment_from, wait_for_remote_completion_deadline,
    };
    use crate::progress::NoopProgress;
    use crate::terminal::TerminalChunk;
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

    const CONTROLLER_SESSION_HEAP_LIMIT: usize = 128 * 1024;

    fn invalid_wss_controller_config() -> ControllerConfig {
        let relay_identity = Keypair::generate_ed25519();
        let relay: EndpointRelayAddress = format!(
            "/dns4/localhost/tcp/443/tls/ws/p2p/{}",
            relay_identity.public().to_peer_id()
        )
        .parse()
        .unwrap();
        ControllerConfig::new(
            Keypair::generate_ed25519(),
            EndpointRelaySet::new(vec![relay]).unwrap(),
            WssTransportConfig::client(Some(vec![1])),
            ConnectionCode::new(Locator::new(0).unwrap(), PakeSecret::from_u64(0).unwrap()),
            TerminalHello::new(
                TerminalSize::new(80, 24).unwrap(),
                TerminalValue::new("xterm").unwrap(),
                TerminalValue::new("truecolor").unwrap(),
            ),
        )
    }

    #[test]
    fn relay_only_fallback_is_narrowly_classified_and_requires_client_tls() {
        assert!(direct_fallback_required(
            &EndpointError::DirectUpgradeFailed
        ));
        assert!(direct_fallback_required(
            &EndpointError::TargetUpgradeDidNotSettle
        ));
        assert!(controller_fallback_required(&ControllerError::Endpoint(
            EndpointError::AdditionalBoundConnection
        )));
        assert!(controller_fallback_required(&ControllerError::Endpoint(
            EndpointError::BoundConnectionLost
        )));
        for error in [
            EndpointError::RelayUnavailable,
            EndpointError::SelectedConnectionLost,
            EndpointError::ConnectionCloseDidNotConverge,
        ] {
            assert!(!direct_fallback_required(&error));
            assert!(!controller_fallback_required(&ControllerError::Endpoint(
                error
            )));
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
        assert!(matches!(
            run_controller(invalid_wss_controller_config()).await,
            Err(ControllerError::Endpoint(EndpointError::Build(
                NetworkBuildError::WssTls(_)
            )))
        ));
    }

    #[test]
    fn controller_session_heap_state_has_a_fixed_upper_bound() {
        let mut progress = NoopProgress;
        let session = run_controller_session(
            invalid_wss_controller_config(),
            CrosstermFrontend,
            &mut progress,
            tokio_util::sync::CancellationToken::new(),
        );
        let size = std::mem::size_of_val(&session);
        assert!(
            size <= CONTROLLER_SESSION_HEAP_LIMIT,
            "session size: {size}"
        );
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
            #[cfg(not(windows))]
            drop(RawModeGuard { armed: false });
        }
    }

    #[test]
    fn terminal_restore_failures_are_never_hidden() {
        assert_eq!(finish_terminal(Ok(7), Ok(())).unwrap(), 7);
        assert!(matches!(
            finish_terminal::<()>(Err(ControllerError::ConnectionLost), Ok(())),
            Err(ControllerError::ConnectionLost)
        ));
        assert!(matches!(
            finish_terminal(Ok(()), Err(io::Error::other("restore failed"))),
            Err(ControllerError::TerminalRestore(_))
        ));
        assert!(matches!(
            finish_terminal::<()>(
                Err(ControllerError::ConnectionLost),
                Err(io::Error::other("restore failed"))
            ),
            Err(ControllerError::SessionAndTerminalRestore { .. })
        ));
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
        frontend.restore_raw_mode(Some(guard)).unwrap();
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
            Err(ControllerError::TerminalSetup(_))
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
        let cancellation = tokio_util::sync::CancellationToken::new();
        let session_cancellation = cancellation.clone();
        let session = async move {
            let _guard = FakeRawGuard(session_restored);
            started_tx.send(()).unwrap();
            session_cancellation.cancelled().await;
            Err::<u32, _>(ControllerError::Interrupted)
        };
        let signal = async move {
            started_rx.await.unwrap();
            Ok(())
        };

        assert!(matches!(
            run_until_interrupted(session, signal, cancellation).await,
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
                tokio_util::sync::CancellationToken::new(),
            )
            .await
            .unwrap(),
            23
        );
        assert!(matches!(
            {
                let cancellation = tokio_util::sync::CancellationToken::new();
                let session_cancellation = cancellation.clone();
                run_until_interrupted(
                    async move {
                        session_cancellation.cancelled().await;
                        Err::<u32, _>(ControllerError::Interrupted)
                    },
                    async { Err(io::Error::other("signal")) },
                    cancellation,
                )
            }
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
        let chunk = read_local_input(&mut input, 0)
            .await
            .unwrap()
            .expect("one raw input byte");
        assert_eq!(chunk.as_slice(), [0x03]);

        let mut eof = tokio::io::empty();
        assert!(read_local_input(&mut eof, 0).await.unwrap().is_none());

        assert!(matches!(
            read_local_input(&mut FailingRead, 0).await,
            Err(ControllerError::Io(_))
        ));
    }

    async fn render_remote_output(mode: RemoteTerminalOutputMode, chunks: &[&[u8]]) -> Vec<u8> {
        let (mut output, mut captured) = tokio::io::duplex(128);
        let writer = async {
            let mut terminal_output = RemoteTerminalOutput::new(mode);
            for chunk in chunks {
                terminal_output.write(&mut output, chunk).await.unwrap();
                output.flush().await.unwrap();
            }
            terminal_output.finish(&mut output).await.unwrap();
            output.shutdown().await.unwrap();
        };
        let reader = async {
            let mut bytes = Vec::new();
            captured.read_to_end(&mut bytes).await.unwrap();
            bytes
        };
        let ((), bytes) = tokio::join!(writer, reader);
        bytes
    }

    #[derive(Default)]
    struct CountingWriter {
        bytes: Vec<u8>,
        writes: usize,
    }

    impl AsyncWrite for CountingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            self.writes += 1;
            self.bytes.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn native_remote_output_mode_is_platform_and_destination_specific() {
        assert_eq!(
            RemoteTerminalOutputMode::native(false),
            RemoteTerminalOutputMode::Bytes
        );
        #[cfg(windows)]
        assert_eq!(
            RemoteTerminalOutputMode::native(true),
            RemoteTerminalOutputMode::WindowsConsoleUtf8
        );
        #[cfg(not(windows))]
        assert_eq!(
            RemoteTerminalOutputMode::native(true),
            RemoteTerminalOutputMode::Bytes
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn windows_console_output_preserves_ansi_and_split_utf8() {
        let chunks: &[&[u8]] = &[b"\x1b[Htop \xe4", b"\xb8", b"\xad\xe6\x96", b"\x87\r\n"];
        let rendered =
            render_remote_output(RemoteTerminalOutputMode::WindowsConsoleUtf8, chunks).await;
        assert_eq!(rendered, "\x1b[Htop \u{4e2d}\u{6587}\r\n".as_bytes());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn windows_console_output_replaces_invalid_and_incomplete_utf8_without_stopping() {
        let chunks: &[&[u8]] = &[b"ok\xff", b"\xe4\xb8", b"A", b"\xf0\x90", b""];
        let rendered =
            render_remote_output(RemoteTerminalOutputMode::WindowsConsoleUtf8, chunks).await;
        assert_eq!(rendered, "ok\u{fffd}\u{fffd}A\u{fffd}".as_bytes());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn windows_console_invalid_block_uses_bounded_batched_writes() {
        let invalid = [0xff; 16 * 1024];
        let mut output = CountingWriter::default();
        let mut terminal_output =
            RemoteTerminalOutput::new(RemoteTerminalOutputMode::WindowsConsoleUtf8);
        terminal_output.write(&mut output, &invalid).await.unwrap();
        terminal_output.finish(&mut output).await.unwrap();
        assert_eq!(output.bytes, String::from_utf8_lossy(&invalid).as_bytes());
        assert!(output.writes <= 16, "write count: {}", output.writes);
    }

    #[test]
    fn windows_console_streaming_matches_lossy_utf8_for_arbitrary_chunking() {
        use proptest::prelude::*;
        use proptest::test_runner::TestRunner;

        let strategy = (
            proptest::collection::vec(any::<u8>(), 0..2_048),
            proptest::collection::vec(any::<usize>(), 0..64),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let mut runner = TestRunner::default();
        runner
            .run(&strategy, |(bytes, cuts)| {
                let mut boundaries: Vec<usize> = cuts
                    .into_iter()
                    .map(|cut| cut % (bytes.len() + 1))
                    .collect();
                boundaries.extend([0, bytes.len()]);
                boundaries.sort_unstable();
                boundaries.dedup();
                let chunks: Vec<&[u8]> = boundaries
                    .windows(2)
                    .map(|pair| &bytes[pair[0]..pair[1]])
                    .collect();
                let rendered = runtime.block_on(render_remote_output(
                    RemoteTerminalOutputMode::WindowsConsoleUtf8,
                    &chunks,
                ));
                let expected = String::from_utf8_lossy(&bytes);
                prop_assert_eq!(rendered, expected.as_bytes());
                Ok(())
            })
            .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn non_console_output_remains_byte_transparent() {
        let chunks: &[&[u8]] = &[b"\xff\xe4", b"\xb8\x00\x1b[H"];
        let rendered = render_remote_output(RemoteTerminalOutputMode::Bytes, chunks).await;
        assert_eq!(rendered, b"\xff\xe4\xb8\x00\x1b[H");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_pumps_make_bidirectional_progress_under_tiny_backpressure() {
        let local_payload = vec![0x5a; 128 * 1024];
        let remote_payload = vec![0xa5; 128 * 1024];
        let (controller, peer) = tokio::io::duplex(31);
        let (mut controller_read, mut controller_write) = tokio::io::split(controller);
        let (mut peer_read, mut peer_write) = tokio::io::split(peer);
        let mut local_input = local_payload.as_slice();
        let mut local_output = Vec::new();
        let mut escape = LocalInputEscape::new(false);
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);

        let input_pump = copy_local_input(&mut local_input, &mut controller_write, &mut escape);
        let output_pump = copy_remote_output(
            &mut controller_read,
            &mut local_output,
            &mut terminal_output,
        );
        let peer_exchange = async {
            peer_write.write_all(&remote_payload).await.unwrap();
            peer_write.shutdown().await.unwrap();
            let mut received = vec![0; local_payload.len()];
            peer_read.read_exact(&mut received).await.unwrap();
            received
        };

        let completed = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::pin!(input_pump);
            tokio::pin!(output_pump);
            tokio::pin!(peer_exchange);
            let mut output_complete = false;
            let mut received = None;
            loop {
                tokio::select! {
                    result = &mut input_pump => match result {
                        Ok(never) => match never {},
                        Err(error) => panic!("input pump failed: {error}"),
                    },
                    result = &mut output_pump, if !output_complete => {
                        result.unwrap();
                        output_complete = true;
                    }
                    result = &mut peer_exchange, if received.is_none() => {
                        received = Some(result);
                    }
                }
                if output_complete && let Some(received) = received.take() {
                    break received;
                }
            }
        })
        .await
        .expect("both bounded terminal directions must continue making progress");

        assert_eq!(completed, local_payload);
        assert_eq!(local_output, remote_payload);
    }

    fn terminal_chunk(bytes: &[u8]) -> TerminalChunk {
        let mut chunk = TerminalChunk::new();
        chunk.writable()[..bytes.len()].copy_from_slice(bytes);
        chunk.set_len(bytes.len()).unwrap();
        chunk
    }

    #[test]
    fn interactive_detach_escape_is_chunk_boundary_independent() {
        let mut escape = LocalInputEscape::new(true);
        let first = escape.filter(terminal_chunk(b"typed\x1d")).unwrap();
        assert_eq!(first.chunk.as_slice(), b"typed");
        assert!(!first.detach);
        assert_eq!(escape.read_reserve(), 1);

        let second = escape.filter(terminal_chunk(b".")).unwrap();
        assert!(second.chunk.as_slice().is_empty());
        assert!(second.detach);
    }

    #[test]
    fn interactive_escape_preserves_literal_and_non_command_sequences() {
        let mut escape = LocalInputEscape::new(true);
        let terminal_escape = escape.filter(terminal_chunk(b"\x1b")).unwrap();
        assert_eq!(terminal_escape.chunk.as_slice(), b"\x1b");
        assert!(!terminal_escape.detach);

        let literal = escape
            .filter(terminal_chunk(&[LOCAL_ESCAPE, LOCAL_ESCAPE]))
            .unwrap();
        assert_eq!(literal.chunk.as_slice(), [LOCAL_ESCAPE]);
        assert!(!literal.detach);

        let ordinary = escape
            .filter(terminal_chunk(&[LOCAL_ESCAPE, b'x']))
            .unwrap();
        assert_eq!(ordinary.chunk.as_slice(), [LOCAL_ESCAPE, b'x']);
        assert!(!ordinary.detach);

        let before_detach = escape
            .filter(terminal_chunk(b"abc\x1d.trailing bytes"))
            .unwrap();
        assert_eq!(before_detach.chunk.as_slice(), b"abc");
        assert!(before_detach.detach);
    }

    #[test]
    fn isolated_escape_is_forwarded_when_local_input_reaches_eof() {
        let mut escape = LocalInputEscape::new(true);
        let pending = escape.filter(terminal_chunk(&[LOCAL_ESCAPE])).unwrap();
        assert!(pending.chunk.as_slice().is_empty());
        assert!(!pending.detach);
        assert_eq!(escape.finish().unwrap().unwrap().as_slice(), [LOCAL_ESCAPE]);
        assert!(escape.finish().unwrap().is_none());
    }

    #[test]
    fn pending_escape_reserve_keeps_filter_output_within_fixed_chunk() {
        let mut escape = LocalInputEscape::new(true);
        escape.filter(terminal_chunk(&[LOCAL_ESCAPE])).unwrap();
        assert_eq!(escape.read_reserve(), 1);
        let input = vec![b'x'; 16 * 1024 - escape.read_reserve()];
        let output = escape.filter(terminal_chunk(&input)).unwrap();
        assert_eq!(output.chunk.as_slice().len(), 16 * 1024);
        assert_eq!(output.chunk.as_slice()[0], LOCAL_ESCAPE);
        assert!(
            output.chunk.as_slice()[1..]
                .iter()
                .all(|byte| *byte == b'x')
        );
    }

    #[test]
    fn non_interactive_input_remains_byte_transparent() {
        let mut escape = LocalInputEscape::new(false);
        let bytes = [b'a', LOCAL_ESCAPE, b'.', LOCAL_ESCAPE, LOCAL_ESCAPE];
        let filtered = escape.filter(terminal_chunk(&bytes)).unwrap();
        assert_eq!(filtered.chunk.as_slice(), bytes);
        assert!(!filtered.detach);
        assert_eq!(escape.read_reserve(), 0);
        assert!(escape.finish().unwrap().is_none());
    }

    fn assert_native_input_adapter_uses_byte_escape_semantics() {
        let mut escape = LocalInputEscape::new(true);
        let filtered = escape
            .filter(terminal_chunk(&[LOCAL_ESCAPE, LOCAL_ESCAPE]))
            .unwrap();
        assert_eq!(filtered.chunk.as_slice(), [LOCAL_ESCAPE]);
    }

    #[cfg(windows)]
    #[test]
    fn windows_terminal_input_adapter_uses_byte_escape_semantics() {
        assert_native_input_adapter_uses_byte_escape_semantics();
    }

    #[cfg(unix)]
    #[test]
    fn unix_terminal_input_adapter_uses_byte_escape_semantics() {
        assert_native_input_adapter_uses_byte_escape_semantics();
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
