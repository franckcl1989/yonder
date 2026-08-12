use crate::audit::observer::{
    AUDIT_CHECKPOINT_POLL, AUDIT_ESTABLISH_TIMEOUT, AuditObserver, CloseNoticeHandling, FrameEvent,
};
use crate::audit::session::{
    AuditError, DIRECTION_CTRL_TO_HOST, KEY_ACTION_DETACH, KEY_ACTION_DOWNLOAD, KEY_ACTION_HELP,
    KEY_ACTION_INTERRUPT, KEY_ACTION_UPLOAD, LIFECYCLE_KIND_ACTIVE_DETACH,
    LIFECYCLE_KIND_LOCAL_INTERRUPT,
};
use crate::file_semantics::{BaseDirectory, SourceFile};
use crate::local_control::{LocalAction, LocalControlInput, LocalInputChunk, ProcessedInput};
use crate::network::{
    ConnectionBinding, EndpointDriver, EndpointError, EndpointEvent, RelayAccessMode,
    connect_relay, connect_relay_with_policy, connect_target, connect_target_via_relay,
    drive_bound,
};
use crate::pake::{OpaquePake, OpaquePakeError};
use crate::progress::{NoopProgress, OperationProgress, wait_with_progress};
use crate::protocol::{
    EnterpriseResolveUi, RelayProtocolError, ResolveDeadline, ResolvedTarget, resolve_peer_auto,
};
use crate::terminal::TerminalChunk;
use crate::transfer::{TransferConfig, TransferOutcome, run_download_audited, run_upload_audited};
use crate::transfer_prompt::{
    AppendOutcome, DELAYED_OUTPUT_CAP, DelayedOutputBuffer, PROMPT_PATH_LIMIT, PathPrompt,
    PromptResult,
};
use backon::{BackoffBuilder as _, ConstantBuilder};
use sha2::{Digest as _, Sha256};
use std::convert::Infallible;
use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{
    AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _,
};
use yonder_core::EnterpriseProvider;
use yonder_core::wire::audit::{
    AUDIT_PROTOCOL, AuditCloseReason, AuditRole, Digest32, ManifestEnding,
};
use yonder_core::wire::auth::{
    AuthClientFinish, AuthClientHello, AuthServerResponse, Authenticated, PROCEED_LEN, PakeContext,
    RETRY_LEN,
};
use yonder_core::wire::file_transfer::{FILE_TRANSFER_PROTOCOL, TransferDirection};
use yonder_core::wire::terminal::{
    CONTROL_LEN, TerminalComplete, TerminalExit, TerminalHello, TerminalReady, TerminalResize,
};
use yonder_core::wire::{AUTH_PROTOCOL, TERMINAL_CONTROL_PROTOCOL, TERMINAL_DATA_PROTOCOL};
use yonder_core::{
    ConnectionCode, DomainError, OsSecureRandom, Pake, ProtocolError, RandomError, RetryAfter,
    SecureRandom, TerminalSize, TerminalValue,
};
use yonder_net::{
    ApplicationStream, ApplicationStreamError, ApplicationStreams, ConnectionId,
    DirectUpgradePolicy, EndpointRelayAddress, EndpointRelaySet, Keypair, Libp2pApplicationStreams,
    PeerId, WssTransportConfig, generate_identity, peer_id_bytes,
};

/// The erased audit substream I/O; the opaque `into_tokio` type cannot be
/// named, so the handshake boxes it (one bounded allocation per session).
trait AuditStreamIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> AuditStreamIo for T {}

const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
const RETRY_LIMIT: usize = 20;
const SIZE_POLL_INTERVAL: Duration = Duration::from_millis(250);
const REMOTE_COMPLETION_TIMEOUT: Duration = Duration::from_secs(2);
const UTF8_SEQUENCE_CAPACITY: usize = 4;
#[cfg(test)]
const UTF8_OUTPUT_BATCH_CAPACITY: usize = 4 * 1024;
const UTF8_REPLACEMENT: &[u8] = "\u{fffd}".as_bytes();

// Fixed controller-local texts of the 0.2.0 file-transfer UI. The prompt
// labels, the "already active" line (design §15.3) and the paused-input
// phrase (design §7.5) are frozen; the remaining texts are fixed
// implementation strings (the design requires fixed errors, §7.1/§9.3).
const PROMPT_BANNER_UPLOAD: &str = "[yonder upload]";
const PROMPT_BANNER_DOWNLOAD: &str = "[yonder download]";
const PROMPT_UPLOAD_SOURCE: &str = "local source:";
const PROMPT_UPLOAD_DESTINATION: &str = "remote destination [remote session start directory]:";
const PROMPT_DOWNLOAD_SOURCE: &str = "remote source:";
const PROMPT_DOWNLOAD_DESTINATION: &str = "local destination [local connect start directory]:";
const FILE_TRANSFER_ALREADY_ACTIVE: &str = "file transfer already active";
const FILE_TRANSFER_UNAVAILABLE: &str = "file transfer is unavailable in this session";
const FILE_TRANSFER_UNSUPPORTED: &str = "file transfer is not supported by the remote peer";
const FILE_TRANSFER_PROBE_FAILED: &str = "file transfer capability check failed";
const FILE_TRANSFER_OPEN_FAILED: &str = "the file transfer substream could not be opened";
const TRANSFER_STATUS_PAUSED: &str = "terminal input paused during transfer; Ctrl+C cancels";
const LOCAL_CONTROL_HELP: &str = "Ctrl+] .      end the session\r\n\
    Ctrl+] Ctrl+] send a literal Ctrl+]\r\n\
    Ctrl+] u      upload a file\r\n\
    Ctrl+] d      download a file\r\n\
    Ctrl+] ?      show this help";

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

impl RemoteTerminalOutput {
    const fn new(mode: RemoteTerminalOutputMode) -> Self {
        Self {
            mode,
            pending: [0; UTF8_SEQUENCE_CAPACITY],
            pending_len: 0,
        }
    }

    /// The platform output adapter (design section 18.4): transforms one
    /// raw chunk into the display bytes that will be handed to the display
    /// write path. Pure — no I/O — so the caller can record the display
    /// bytes through the audit observer before the write effect. The
    /// pending UTF-8 state carries across chunks.
    fn prepare(&mut self, bytes: &[u8]) -> Vec<u8> {
        match self.mode {
            RemoteTerminalOutputMode::Bytes => bytes.to_vec(),
            RemoteTerminalOutputMode::WindowsConsoleUtf8 => {
                self.prepare_windows_console_utf8(bytes)
            }
        }
    }

    fn prepare_windows_console_utf8(&mut self, mut bytes: &[u8]) -> Vec<u8> {
        let mut display = Vec::with_capacity(bytes.len());
        while self.pending_len != 0 {
            let Some((&next, remaining)) = bytes.split_first() else {
                return display;
            };
            let candidate_len = self.pending_len + 1;
            self.pending[self.pending_len] = next;
            match std::str::from_utf8(&self.pending[..candidate_len]) {
                Ok(_) => {
                    display.extend_from_slice(&self.pending[..candidate_len]);
                    self.pending_len = 0;
                    bytes = remaining;
                }
                Err(error) if error.error_len().is_none() => {
                    self.pending_len = candidate_len;
                    bytes = remaining;
                }
                Err(_) => {
                    display.extend_from_slice(UTF8_REPLACEMENT);
                    self.pending_len = 0;
                }
            }
        }

        while !bytes.is_empty() {
            match std::str::from_utf8(bytes) {
                Ok(_) => {
                    display.extend_from_slice(bytes);
                    return display;
                }
                Err(error) => {
                    let valid_len = error.valid_up_to();
                    if valid_len != 0 {
                        display.extend_from_slice(&bytes[..valid_len]);
                        bytes = &bytes[valid_len..];
                    }
                    if let Some(invalid_len) = error.error_len() {
                        display.extend_from_slice(UTF8_REPLACEMENT);
                        bytes = &bytes[invalid_len..];
                    } else {
                        debug_assert!(bytes.len() < UTF8_SEQUENCE_CAPACITY);
                        self.pending[..bytes.len()].copy_from_slice(bytes);
                        self.pending_len = bytes.len();
                        return display;
                    }
                }
            }
        }
        display
    }

    /// Writes one prepared display chunk to the display write path.
    async fn write(
        &mut self,
        output: &mut (impl tokio::io::AsyncWrite + Unpin),
        display: &[u8],
    ) -> Result<(), std::io::Error> {
        output.write_all(display).await
    }

    /// Flushes the trailing incomplete UTF-8 sequence (Windows console
    /// mode) and returns the bytes that were written, so the audit
    /// observer can record the display tail (design section 18.4).
    async fn finish(
        &mut self,
        output: &mut (impl tokio::io::AsyncWrite + Unpin),
    ) -> Result<Vec<u8>, std::io::Error> {
        let mut tail = Vec::new();
        if self.mode == RemoteTerminalOutputMode::WindowsConsoleUtf8 && self.pending_len != 0 {
            output.write_all(UTF8_REPLACEMENT).await?;
            tail.extend_from_slice(UTF8_REPLACEMENT);
            self.pending_len = 0;
        }
        output.flush().await?;
        Ok(tail)
    }
}

/// The bounded display write batch of the removed streaming adapter,
/// retained for the byte-exact regression tests of the Windows console
/// transformation.
#[cfg(test)]
struct Utf8OutputBatch {
    bytes: [u8; UTF8_OUTPUT_BATCH_CAPACITY],
    len: usize,
}

#[cfg(test)]
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

/// Interactive enterprise authentication prompts during the connect flow.
///
/// The methods run inside the endpoint drive loop, so the relay
/// connection stays alive while the user reads the prompt or opens the
/// browser. The URL is always printed; the platform browser opener is
/// best effort and its failure never aborts the flow.
pub struct EnterpriseControllerUi<I: AsyncRead + Unpin, O: AsyncWrite + Unpin> {
    input: I,
    output: O,
    opener: Box<dyn Fn(&str) -> bool + Send + Sync>,
}

impl EnterpriseControllerUi<tokio::io::BufReader<tokio::io::Stdin>, tokio::io::Stdout> {
    /// The production UI over the terminal and the platform browser.
    #[must_use]
    pub fn new() -> Self {
        Self {
            input: tokio::io::BufReader::new(tokio::io::stdin()),
            output: tokio::io::stdout(),
            opener: Box::new(platform_open),
        }
    }
}

impl Default for EnterpriseControllerUi<tokio::io::BufReader<tokio::io::Stdin>, tokio::io::Stdout> {
    fn default() -> Self {
        Self::new()
    }
}

impl<I: tokio::io::AsyncBufRead + Unpin + Send, O: AsyncWrite + Unpin + Send> EnterpriseResolveUi
    for EnterpriseControllerUi<I, O>
{
    fn select_provider(
        &mut self,
        providers: yonder_core::EnterpriseProviders,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<EnterpriseProvider, RelayProtocolError>> + Send + '_>,
    > {
        // A single configured platform is chosen without prompting.
        let mut offered = providers.iter();
        let first = offered.next().expect("the provider set is never empty");
        if offered.next().is_none() {
            let provider = first;
            return Box::pin(async move { Ok(provider) });
        }
        let input = &mut self.input;
        let output = &mut self.output;
        Box::pin(async move {
            output
                .write_all("请选择企业认证平台（输入序号后回车）:\n1) 企业微信 (WeCom)\n2) 飞书 (Feishu)\n> ".as_bytes())
                .await
                .map_err(RelayProtocolError::Io)?;
            output.flush().await.map_err(RelayProtocolError::Io)?;
            let mut line = String::new();
            input
                .read_line(&mut line)
                .await
                .map_err(RelayProtocolError::Io)?;
            match line.trim() {
                "1" => Ok(EnterpriseProvider::WeCom),
                "2" => Ok(EnterpriseProvider::Feishu),
                _ => Err(RelayProtocolError::EnterpriseRejected),
            }
        })
    }

    fn open_authorization(
        &mut self,
        url: &str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), RelayProtocolError>> + Send + '_>> {
        let url = url.to_owned();
        let opener = &self.opener;
        let output = &mut self.output;
        Box::pin(async move {
            output
                .write_all(format!("\n请在浏览器中完成企业认证:\n{url}\n").as_bytes())
                .await
                .map_err(RelayProtocolError::Io)?;
            if !opener(&url) {
                output
                    .write_all("无法自动打开浏览器，请手动打开上面的链接。\n".as_bytes())
                    .await
                    .map_err(RelayProtocolError::Io)?;
            }
            output.flush().await.map_err(RelayProtocolError::Io)?;
            Ok(())
        })
    }
}

/// Opens the URL with the platform default browser, best effort.
fn platform_open(url: &str) -> bool {
    open::that(url).is_ok()
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
    #[error("the relay access policy changed while rebuilding the connection")]
    RelayAccessChanged,
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
    #[error(transparent)]
    Audit(#[from] AuditError),
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
    let resolved = wait_with_progress(
        progress,
        ControllerStage::ResolvingHost,
        resolve_peer_auto(
            &mut driver,
            &mut streams,
            &relay,
            code.locator(),
            ResolveDeadline::controller(),
            &mut EnterpriseControllerUi::new(),
        ),
    )
    .await?;
    let initial = Box::pin(prepare_controller(
        driver,
        streams,
        relay.address(),
        resolved,
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
            let fallback_resolved = wait_with_progress(
                progress,
                ControllerStage::ResolvingHost,
                resolve_peer_auto(
                    &mut fallback_driver,
                    &mut fallback_streams,
                    &fallback_relay,
                    code.locator(),
                    ResolveDeadline::controller(),
                    &mut EnterpriseControllerUi::new(),
                ),
            )
            .await?;
            if fallback_resolved.access() != resolved.access() {
                return Err(ControllerError::RelayAccessChanged);
            }
            let prepared = Box::pin(prepare_controller(
                fallback_driver,
                fallback_streams,
                fallback_relay.address(),
                fallback_resolved,
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
    streams: Libp2pApplicationStreams,
    binding: ConnectionBinding,
    control: ApplicationStream,
    data: ApplicationStream,
    audit: Option<ApplicationStream>,
    /// Test and embedding seam for isolating audit artifacts. Production
    /// sessions leave this unset and use the platform audit directory.
    audit_root_override: Option<PathBuf>,
}

async fn prepare_controller(
    mut driver: EndpointDriver,
    mut streams: Libp2pApplicationStreams,
    relay: &EndpointRelayAddress,
    target: ResolvedTarget,
    code: &ConnectionCode,
    direct_upgrade: DirectUpgradePolicy,
    progress: &mut impl OperationProgress<ControllerStage>,
) -> Result<PreparedController, ControllerError> {
    let selected = wait_with_progress(progress, ControllerStage::EstablishingPath, async {
        match direct_upgrade {
            DirectUpgradePolicy::Enabled => connect_target(&mut driver, relay, target.peer()).await,
            DirectUpgradePolicy::Disabled => {
                connect_target_via_relay(&mut driver, relay, target.peer()).await
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

    let (control, data, audit) =
        wait_with_progress(progress, ControllerStage::StartingTerminal, async {
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
            let audit = match target.access() {
                RelayAccessMode::Standard => None,
                RelayAccessMode::Enterprise => {
                    match open_until(
                        &mut driver,
                        &mut streams,
                        binding,
                        AUDIT_PROTOCOL,
                        terminal_stream_deadline,
                    )
                    .await
                    {
                        Ok(stream) => Some(stream),
                        Err(ControllerError::Endpoint(EndpointError::Application(
                            ApplicationStreamError::UnsupportedProtocol,
                        ))) => return Err(audit_open_error()),
                        Err(error) => return Err(error),
                    }
                }
            };
            Ok::<_, ControllerError>((control, data, audit))
        })
        .await?;
    Ok(PreparedController {
        driver,
        streams,
        binding,
        control,
        data,
        audit,
        audit_root_override: None,
    })
}

/// The fixed peer-unsupported audit error of design section 14.
fn audit_open_error() -> ControllerError {
    ControllerError::Audit(AuditError::peer_unsupported())
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
        term = default_terminal_value(frontend.output_is_terminal() || frontend.is_interactive())?;
    }
    Ok(TerminalHello::new(
        TerminalSize::new(columns, rows)?,
        term,
        terminal_environment("COLORTERM")?,
    ))
}

fn default_terminal_value(interactive: bool) -> Result<TerminalValue, ControllerError> {
    TerminalValue::new(if interactive {
        "xterm-256color"
    } else {
        "dumb"
    })
    .map_err(ControllerError::from)
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
        mut streams,
        binding,
        control,
        data,
        audit: audit_stream,
        audit_root_override,
    } = prepared;
    let driver = &mut driver;
    let self_peer = driver.peer_id();
    let (mut data_read, mut data_write) = tokio::io::split(data.into_tokio());
    let (mut control_read, mut control_write) = tokio::io::split(control.into_tokio());
    let handshake = async {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => Err(ControllerError::Interrupted),
            result = drive_bound(
                driver,
                binding,
                establish_audit_and_terminal(
                    audit_stream,
                    &mut data_read,
                    &mut control_write,
                    &hello,
                    binding,
                    self_peer,
                    audit_root_override.as_deref(),
                ),
            ) => result?,
        }
    };
    let (raw_mode, audit) = wait_with_progress(
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
    // The local base directory is captured once per session (design §8.7);
    // relative local paths resolve against it for the whole session.
    let base = match BaseDirectory::capture() {
        Ok(base) => Some(base),
        Err(error) => {
            tracing::debug!(%error, "file transfer base directory unavailable");
            None
        }
    };
    let transfer_cancel = AtomicBool::new(false);
    // The running transfer is a pump branch (design §7.5, §15.2): terminal
    // output, control, resizes and cancellation keep flowing while the file
    // substream is active. The future owns the substream, the opened source
    // and the transfer parameters; it is one fixed-size allocation.
    let mut transfer: Option<Pin<Box<dyn Future<Output = TransferOutcome> + '_>>> = None;
    let mut session_ui = TransferUi::new(
        interactive,
        frontend.output_is_terminal(),
        frontend.output_is_terminal() || std::io::stderr().is_terminal(),
    );
    let mut remote = RemoteCompletion::new();
    // Whether the `Ctrl+] .` detach ended the pump (the shutdown signal
    // produces the same Interrupted error; the close reason differs).
    let mut detached = false;
    let session = {
        // The remote-exit reader and the resize poller keep state across
        // pump iterations and are pinned once; the local-input and
        // remote-output steps are re-armed per iteration (their state lives
        // in `session_ui`), so the modal flows can borrow the same streams
        // between events. The audit frame reader is a select branch that is
        // re-armed after every frame (design section 20).
        let remote_exit = read_remote_exit(&mut control_read);
        let terminal_resizes = copy_terminal_resizes(
            &frontend,
            &mut control_write,
            hello.size(),
            interactive,
            audit.as_ref(),
        );
        let mut audit_frames = Box::pin(wait_for_audit_frame(audit.as_ref()));
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
                        biased;
                        () = cancellation.cancelled() => TerminalPumpEvent::Cancelled,
                        event = driver.next() => TerminalPumpEvent::Driver(event),
                        result = tokio::time::timeout(AUDIT_CHECKPOINT_POLL, &mut audit_frames),
                            if audit.is_some() => {
                            TerminalPumpEvent::Audit(result)
                        }
                        result = process_local_input_chunk(
                            &mut input,
                            &mut data_write,
                            &mut session_ui.control,
                            &mut session_ui.pending_input,
                            audit.as_ref(),
                        ), if !session_ui.local_ended => TerminalPumpEvent::LocalInput(result),
                        result = copy_remote_output(
                            &mut data_read,
                            &mut output,
                            &mut terminal_output,
                            &mut session_ui.delayed,
                            &mut session_ui.delayed_overflow,
                            &session_ui.flow,
                            audit.as_ref(),
                        ), if remote.output_open() => {
                            TerminalPumpEvent::RemoteOutput(result)
                        }
                        result = &mut remote_exit, if remote.exit_pending() => {
                            TerminalPumpEvent::RemoteExit(result)
                        }
                        result = &mut terminal_resizes => TerminalPumpEvent::Resize(result),
                        result = poll_inflight_transfer(&mut transfer),
                            if session_ui.direction.is_some() => {
                            TerminalPumpEvent::Transfer(result)
                        }
                    }
                } => {
                    let completion = match event {
                        TerminalPumpEvent::Cancelled => break Err(ControllerError::Interrupted),
                        TerminalPumpEvent::Driver(event) => {
                            match active_terminal_connection_event(
                                &event,
                                binding.peer(),
                                binding.connection(),
                            ) {
                                ActiveTerminalConnectionEvent::EnforceBinding => {
                                    if let Err(error) = driver.enforce_binding(binding) {
                                        break Err(error.into());
                                    }
                                }
                                ActiveTerminalConnectionEvent::DrainSelectedStreams => {
                                    tracing::debug!(
                                        peer = %binding.peer(),
                                        "selected connection closed; draining terminal streams"
                                    );
                                    remote.observe_transport_close(tokio::time::Instant::now());
                                }
                                ActiveTerminalConnectionEvent::Ignore => {}
                            }
                            None
                        }
                        TerminalPumpEvent::LocalInput(result) => match result {
                            Ok(LocalInputSignal::ChunkPending) => {
                                let processed = session_ui.pending_input.take().expect(
                                    "the pump stores one processed chunk before signalling",
                                );
                                match handle_processed_input(
                                    processed,
                                    &mut output,
                                    &mut terminal_output,
                                    &mut session_ui,
                                    &transfer_cancel,
                                    audit.as_ref(),
                                )
                                .await
                                {
                                    Ok(LocalInputHandling::Done) => None,
                                    Ok(LocalInputHandling::StartModal(direction)) => {
                                        match begin_file_transfer_modal(
                                            direction,
                                            driver,
                                            &mut streams,
                                            binding,
                                            &mut output,
                                            &mut session_ui,
                                            &base,
                                            cancellation,
                                        )
                                        .await
                                        {
                                            Ok(()) => None,
                                            Err(error) => break Err(error),
                                        }
                                    }
                                    Ok(LocalInputHandling::RunTransfer {
                                        direction,
                                        first,
                                        second,
                                    }) => {
                                        match begin_transfer(
                                            direction,
                                            first,
                                            second,
                                            driver,
                                            &mut streams,
                                            binding,
                                            &mut output,
                                            &mut session_ui,
                                            cancellation,
                                            &base,
                                            &transfer_cancel,
                                            &mut transfer,
                                            audit.as_ref(),
                                        )
                                        .await
                                        {
                                            Ok(()) => None,
                                            Err(error) => break Err(error),
                                        }
                                    }
                                    Err(error) => {
                                        detached = matches!(error, ControllerError::Interrupted);
                                        break Err(error);
                                    }
                                }
                            }
                            Ok(LocalInputSignal::Eof) => {
                                match finish_local_input_eof(
                                    &mut data_write,
                                    &mut output,
                                    &mut terminal_output,
                                    &mut session_ui,
                                    audit.as_ref(),
                                )
                                .await
                                {
                                    Ok(()) => None,
                                    Err(error) => break Err(error),
                                }
                            }
                            Err(error) => break Err(error),
                        },
                        TerminalPumpEvent::RemoteOutput(result) => {
                            if let Err(error) = result {
                                break Err(error);
                            }
                            remote.observe_output_eof(tokio::time::Instant::now())
                        }
                        TerminalPumpEvent::RemoteExit(result) => {
                            let code = match result {
                                Ok(code) => code,
                                Err(error) => break Err(error),
                            };
                            // Design section 15.2: the shared TerminalExit
                            // event, matching the host's record.
                            if let Some(audit) = audit.as_ref()
                                && let Err(error) = audit.record_terminal_exit(code as u8).await
                            {
                                break Err(error.into());
                            }
                            remote.observe_exit(code, tokio::time::Instant::now())
                        }
                        TerminalPumpEvent::Resize(result) => {
                            match result {
                                Ok(never) => match never {},
                                Err(error) => break Err(error),
                            }
                        }
                        TerminalPumpEvent::Transfer(outcome) => {
                            // A transfer outcome is only shown after its
                            // audit events were recorded (design section
                            // 18.6); a recording failure already failed the
                            // session closed inside the transfer.
                            if let Some(audit) = audit.as_ref()
                                && audit.has_failed().await
                            {
                                break Err(ControllerError::Audit(AuditError::FailedClosed));
                            }
                            match handle_transfer_event(
                                outcome,
                                &mut output,
                                &mut session_ui,
                                &transfer_cancel,
                                &mut transfer,
                            )
                            .await
                            {
                                Ok(completion) => completion,
                                Err(error) => break Err(error),
                            }
                        }
                        TerminalPumpEvent::Audit(result) => {
                            let audit = audit
                                .as_ref()
                                .expect("the audit branch is enabled only for enterprise sessions");
                            match result {
                                // The periodic poll: send a due checkpoint
                                // (design sections 20.1 and 27.4). The
                                // substream send is driven with the swarm so
                                // a full muxer queue cannot stall the pump.
                                Err(_elapsed) => {
                                    match drive_bound(
                                        driver,
                                        binding,
                                        audit.send_due_checkpoint(),
                                    )
                                    .await
                                    {
                                        Ok(Ok(())) => None,
                                        Ok(Err(error)) => break Err(error.into()),
                                        Err(endpoint) => break Err(endpoint.into()),
                                    }
                                }
                                Ok(Ok(Some(frame))) => {
                                    let handled = match drive_bound(
                                        driver,
                                        binding,
                                        audit.handle_frame(&frame),
                                    )
                                    .await
                                    {
                                        Ok(Ok(event)) => event,
                                        Ok(Err(error)) => break Err(error.into()),
                                        Err(endpoint) => break Err(endpoint.into()),
                                    };
                                    match handled {
                                        FrameEvent::None => {}
                                        // The controller never initiates a
                                        // close from the peer's notice; the
                                        // host only conveys its own audit
                                        // failure, so the session fails
                                        // closed (design section 18.7).
                                        FrameEvent::Close(_) => {
                                            drive_bound(
                                                driver,
                                                binding,
                                                audit.fail_closed(
                                                    None,
                                                    AuditCloseReason::AuditFailure,
                                                ),
                                            )
                                            .await
                                            .ok();
                                            break Err(ControllerError::Audit(
                                                AuditError::FailedClosed,
                                            ));
                                        }
                                        FrameEvent::PeerAuditError(code) => {
                                            drive_bound(
                                                driver,
                                                binding,
                                                audit.fail_closed(
                                                    Some(code),
                                                    AuditCloseReason::AuditFailure,
                                                ),
                                            )
                                            .await
                                            .ok();
                                            break Err(ControllerError::Audit(
                                                AuditError::FailedClosed,
                                            ));
                                        }
                                    };
                                    // The completed read is re-armed so the
                                    // substream keeps being drained; without
                                    // this the peer's checkpoints and close
                                    // notice would sit unread and the peer's
                                    // writes would stall on the muxer window.
                                    audit_frames = Box::pin(wait_for_audit_frame(Some(audit)));
                                    None
                                }
                                // The audit substream ended: the connection
                                // is gone, the session fails closed.
                                Ok(Ok(None)) => {
                                    break Err(ControllerError::Audit(AuditError::FailedClosed));
                                }
                                Ok(Err(error)) => break Err(error.into()),
                            }
                        }
                    };
                    // §7.4.5: a delayed-buffer overflow cancels the
                    // not-yet-started operation and flushes the buffer
                    // immediately; the remote terminal stays open.
                    if session_ui.take_delayed_overflow() {
                        match abort_prompt_for_overflow(
                            &mut session_ui,
                            &mut output,
                            &mut terminal_output,
                            audit.as_ref(),
                        )
                        .await
                        {
                            Ok(()) => {}
                            Err(error) => break Err(error),
                        }
                    }
                    if let Some(code) = completion {
                        // The session is ending; write any still-delayed
                        // remote output so the remote's final lines appear
                        // in order (§7.4.4).
                        match flush_delayed_output(
                            &mut session_ui,
                            &mut output,
                            &mut terminal_output,
                            audit.as_ref(),
                        )
                        .await
                        {
                            Ok(()) => {}
                            Err(error) => break Err(error),
                        }
                        break Ok(code);
                    }
                }
            }
        }
    };
    let output_deadline = remote
        .deadline()
        .unwrap_or_else(|| tokio::time::Instant::now() + REMOTE_COMPLETION_TIMEOUT);
    let output_finish = tokio::time::timeout_at(output_deadline, async {
        let tail = terminal_output
            .finish(&mut output)
            .await
            .map_err(ControllerError::TerminalOutput)?;
        // The display tail written by the finish (design section 18.4).
        if !tail.is_empty()
            && let Some(audit) = audit.as_ref()
        {
            audit.record_display_bytes(&tail).await?;
        }
        Ok::<(), ControllerError>(())
    })
    .await
    .map_err(|_| ControllerError::RemoteCompletionTimeout)?;
    let session = finish_terminal_output(session, output_finish);
    let session = match session {
        Ok(code) => complete_terminal_control(
            driver,
            binding,
            &mut control_read,
            &mut control_write,
            cancellation,
            audit.as_ref(),
        )
        .await
        .map(|()| code),
        Err(error) => Err(error),
    };
    // The audit close and finalization (design sections 21 and 22).
    let session = audit_close_controller(driver, binding, session, audit.as_ref(), detached).await;
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
    LocalInput(Result<LocalInputSignal, ControllerError>),
    RemoteOutput(Result<(), ControllerError>),
    RemoteExit(Result<u32, ControllerError>),
    Resize(Result<Infallible, ControllerError>),
    Transfer(TransferOutcome),
    Audit(Result<Result<Option<Vec<u8>>, AuditError>, tokio::time::error::Elapsed>),
}

async fn wait_for_audit_frame(
    audit: Option<&AuditObserver>,
) -> Result<Option<Vec<u8>>, AuditError> {
    match audit {
        Some(audit) => audit.wait_for_frame().await,
        None => std::future::pending().await,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveTerminalConnectionEvent {
    EnforceBinding,
    DrainSelectedStreams,
    Ignore,
}

fn active_terminal_connection_event(
    event: &EndpointEvent,
    bound_peer: PeerId,
    bound_connection: ConnectionId,
) -> ActiveTerminalConnectionEvent {
    match event {
        EndpointEvent::Closed { peer, connection }
            if *peer == bound_peer && *connection == bound_connection =>
        {
            ActiveTerminalConnectionEvent::DrainSelectedStreams
        }
        EndpointEvent::Established { peer, .. } | EndpointEvent::Closed { peer, .. }
            if *peer == bound_peer =>
        {
            ActiveTerminalConnectionEvent::EnforceBinding
        }
        _ => ActiveTerminalConnectionEvent::Ignore,
    }
}

fn restore_native_display() -> Result<(), std::io::Error> {
    if !native_display_available() {
        return Ok(());
    }
    let commands = native_display_restore_commands()?;
    if std::io::stdout().is_terminal() {
        let mut output = std::io::stdout().lock();
        write_native_display_restore(&mut output, &commands)
    } else {
        let mut output = std::io::stderr().lock();
        write_native_display_restore(&mut output, &commands)
    }
}

fn write_native_display_restore(
    output: &mut impl std::io::Write,
    commands: &str,
) -> Result<(), std::io::Error> {
    output.write_all(commands.as_bytes())?;
    output.flush()
}

fn native_display_restore_commands() -> Result<String, std::io::Error> {
    use crossterm::Command as _;

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
    Ok(commands)
}

/// The outcome of one local input pump step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalInputSignal {
    /// A processed chunk is waiting in the session state.
    ChunkPending,
    /// Local input reached EOF.
    Eof,
}

/// Reads one local input chunk and processes it through the local control
/// machine, forwarding the chunk's remote bytes to the terminal-data
/// stream and storing the processed chunk for the pump loop. The machine
/// keeps its state across calls and the chunk never exceeds the fixed
/// input capacity (design §6, §15.1).
///
/// The pump borrows only disjoint parts of the session state, so the
/// pump-loop branches can run at the same time, and the chunk data stays
/// in the session state instead of a large pump event.
async fn process_local_input_chunk(
    input: &mut (impl tokio::io::AsyncRead + Unpin),
    data_write: &mut (impl tokio::io::AsyncWrite + Unpin),
    control: &mut LocalControlInput,
    pending_input: &mut Option<ProcessedInput>,
    audit: Option<&AuditObserver>,
) -> Result<LocalInputSignal, ControllerError> {
    let reserve = if control.enabled() && control.pending_prefix() {
        1
    } else {
        0
    };
    let Some(chunk) = read_local_input(input, reserve).await? else {
        return Ok(LocalInputSignal::Eof);
    };
    tracing::debug!(
        length = chunk.as_slice().len(),
        "local terminal input read completed"
    );
    let processed = control.process(chunk);
    if !processed.remote_bytes.is_empty() {
        // Design sections 18.1: the input commitment is appended before the
        // bytes are sent, and the send outcome after the send.
        if let Some(audit) = audit {
            audit
                .record_input(processed.remote_bytes.as_slice())
                .await?;
        }
        let length = processed.remote_bytes.as_slice().len() as u64;
        let send = async {
            data_write
                .write_all(processed.remote_bytes.as_slice())
                .await?;
            data_write.flush().await
        }
        .await;
        if let Err(error) = send {
            if let Some(audit) = audit {
                let _ = audit
                    .record_send_outcome(DIRECTION_CTRL_TO_HOST, false, length)
                    .await;
            }
            return Err(error.into());
        }
        if let Some(audit) = audit {
            audit
                .record_send_outcome(DIRECTION_CTRL_TO_HOST, true, length)
                .await?;
        }
    }
    *pending_input = Some(processed);
    tokio::task::yield_now().await;
    Ok(LocalInputSignal::ChunkPending)
}

/// Handles local input EOF (the session is ending): the machine flushes an
/// orphaned prefix, the active file operation is dropped together with its
/// unconsumed remainder — which is never replayed to the remote (§6.2,
/// §16.4) — and the remote data stream shuts down.
async fn finish_local_input_eof(
    data_write: &mut (impl tokio::io::AsyncWrite + Unpin),
    output: &mut (impl tokio::io::AsyncWrite + Unpin),
    terminal_output: &mut RemoteTerminalOutput,
    session_ui: &mut TransferUi,
    audit: Option<&AuditObserver>,
) -> Result<(), ControllerError> {
    session_ui.local_ended = true;
    let finished = session_ui.control.finish();
    if !finished.remote_bytes.is_empty() {
        if let Some(audit) = audit {
            audit.record_input(finished.remote_bytes.as_slice()).await?;
        }
        let length = finished.remote_bytes.as_slice().len() as u64;
        let send = async {
            data_write
                .write_all(finished.remote_bytes.as_slice())
                .await?;
            data_write.flush().await
        }
        .await;
        if let Err(error) = send {
            if let Some(audit) = audit {
                let _ = audit
                    .record_send_outcome(DIRECTION_CTRL_TO_HOST, false, length)
                    .await;
            }
            return Err(error.into());
        }
        if let Some(audit) = audit {
            audit
                .record_send_outcome(DIRECTION_CTRL_TO_HOST, true, length)
                .await?;
        }
    }
    if finished.action == LocalAction::Bell {
        write_local_ui(output, session_ui.ui_to_display, b"\x07").await?;
    }
    if session_ui.flow.is_some() {
        end_transfer_modal(session_ui, output).await?;
        flush_delayed_output(session_ui, output, terminal_output, audit).await?;
    }
    data_write.shutdown().await?;
    Ok(())
}

async fn copy_remote_output(
    data_read: &mut (impl tokio::io::AsyncRead + Unpin),
    output: &mut (impl tokio::io::AsyncWrite + Unpin),
    terminal_output: &mut RemoteTerminalOutput,
    delayed: &mut DelayedOutputBuffer,
    delayed_overflow: &mut bool,
    prompt_active: &Option<PathPromptFlow>,
    audit: Option<&AuditObserver>,
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
        // Design section 18.3: the raw network output is recorded before
        // any display handling; the shared output chain always compares the
        // raw terminal bytes.
        if let Some(audit) = audit {
            audit.record_raw_output(chunk.as_slice()).await?;
        }
        if prompt_active.is_some() {
            // §7.4: while a path prompt is active the display is paused but
            // the remote output keeps being read into the bounded delayed
            // buffer, so the remote PTY never blocks. The display record is
            // appended when the delayed bytes are flushed.
            if delayed.append(chunk.as_slice()) == AppendOutcome::Overflow {
                *delayed_overflow = true;
            }
        } else {
            // Design section 18.4: the display bytes (after the platform
            // output adapter) are recorded before the display write.
            let display = terminal_output.prepare(chunk.as_slice());
            if let Some(audit) = audit {
                audit.record_display_bytes(&display).await?;
            }
            if let Err(error) = async {
                terminal_output.write(output, &display).await?;
                output.flush().await
            }
            .await
            {
                if let Some(audit) = audit {
                    let _ = audit
                        .record_display_write_outcome(false, display.len() as u64)
                        .await;
                }
                return Err(error.into());
            }
            if let Some(audit) = audit {
                audit
                    .record_display_write_outcome(true, display.len() as u64)
                    .await?;
            }
        }
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

async fn complete_terminal_control(
    driver: &mut EndpointDriver,
    binding: ConnectionBinding,
    control_read: &mut (impl tokio::io::AsyncRead + Unpin),
    control_write: &mut (impl tokio::io::AsyncWrite + Unpin),
    cancellation: &tokio_util::sync::CancellationToken,
    audit: Option<&AuditObserver>,
) -> Result<(), ControllerError> {
    // Design section 15.2: the shared TerminalComplete event is recorded
    // before it is conveyed.
    if let Some(audit) = audit {
        audit.record_terminal_complete().await?;
    }
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(ControllerError::Interrupted),
        result = tokio::time::timeout(
            REMOTE_COMPLETION_TIMEOUT,
            drive_bound(
                driver,
                binding,
                complete_terminal_control_io(control_read, control_write),
            ),
        ) => {
            let result = result.map_err(|_| ControllerError::RemoteCompletionTimeout)?;
            result.map_err(ControllerError::from)??;
            Ok(())
        }
    }
}

async fn complete_terminal_control_io(
    control_read: &mut (impl tokio::io::AsyncRead + Unpin),
    control_write: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> Result<(), ControllerError> {
    let acknowledge = async {
        control_write.write_all(&TerminalComplete::ENCODED).await?;
        control_write.flush().await?;
        control_write.shutdown().await?;
        Ok::<_, ControllerError>(())
    };
    let host_close = async {
        let mut trailing = [0_u8; 1];
        if control_read.read(&mut trailing).await? == 0 {
            Ok(())
        } else {
            Err(ProtocolError::TrailingBytes.into())
        }
    };
    tokio::pin!(acknowledge);
    tokio::pin!(host_close);
    tokio::select! {
        biased;
        result = &mut host_close => result,
        result = &mut acknowledge => {
            result?;
            host_close.await
        }
    }
}

async fn copy_terminal_resizes(
    frontend: &impl TerminalFrontend,
    control_write: &mut (impl tokio::io::AsyncWrite + Unpin),
    mut last_size: TerminalSize,
    enabled: bool,
    audit: Option<&AuditObserver>,
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
            // Design section 18.5: the resize is recorded before it is
            // sent, with the sender's direction.
            if let Some(audit) = audit {
                audit
                    .record_resize(DIRECTION_CTRL_TO_HOST, size.columns(), size.rows())
                    .await?;
            }
            control_write.write_all(&resize).await?;
            control_write.flush().await?;
            last_size = size;
        }
        tokio::task::yield_now().await;
    }
}

/// The three-state file-transfer capability cache of the active connection
/// (design §9.3). Session-local; a rebuilt connection ends the session in
/// the current architecture, so the cache always restarts at `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum CapabilityCache {
    #[default]
    Unknown,
    Supported,
    Unsupported,
}

/// Why the file-transfer modal cannot start (design §7.1, §9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferNotReady {
    /// No terminal output for the local UI, or no session base directory.
    Unavailable,
    /// The peer does not support the protocol; the result is cached and
    /// never re-probed (§9.3).
    Unsupported,
    /// The capability is unknown; the caller must probe first (§9.3).
    Probe,
}

/// The pre-prompt decision of one file operation: the local availability
/// check and the three-state capability cache (design §7.1, §9.3).
fn file_transfer_ready(
    session_ui: &TransferUi,
    base: Option<&BaseDirectory>,
) -> Result<CapabilityCache, TransferNotReady> {
    if !session_ui.ui_terminal || base.is_none() {
        return Err(TransferNotReady::Unavailable);
    }
    match session_ui.capability {
        CapabilityCache::Unknown => Err(TransferNotReady::Probe),
        CapabilityCache::Supported => Ok(CapabilityCache::Supported),
        CapabilityCache::Unsupported => Err(TransferNotReady::Unsupported),
    }
}

/// Runs one capability probe (design §9.3): the file-transfer protocol
/// substream is opened and closed immediately without any message on
/// success (the peer treats a pre-frame EOF as a side-effect-free probe).
/// Only an explicit unsupported-protocol result is cached; timeouts,
/// connection errors and transient I/O failures propagate and are never
/// cached, so the user may retry.
async fn probe_file_transfer_capability<S>(
    open: impl Future<Output = Result<S, ControllerError>>,
) -> Result<CapabilityCache, ControllerError> {
    match open.await {
        Ok(stream) => {
            // §9.3: close the probe substream without any message.
            drop(stream);
            Ok(CapabilityCache::Supported)
        }
        Err(ControllerError::Endpoint(EndpointError::Application(
            ApplicationStreamError::UnsupportedProtocol,
        ))) => Ok(CapabilityCache::Unsupported),
        Err(error) => Err(error),
    }
}

/// The progress of one [`PathPromptFlow::feed`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PromptProgress {
    /// The active field continues; `bell` reports rejected bytes.
    Active { bell: bool },
    /// The active field was reset (invalid input); the caller must reprint
    /// its label.
    Reprompt,
    /// The required field completed; the caller must print the destination
    /// label.
    NextField,
    /// Both fields completed.
    Completed {
        first: String,
        second: Option<String>,
    },
    /// `Ctrl+C` cancelled the operation (design §16.1).
    Cancelled,
}

/// The two-field path prompt of one upload or download (design §7.2, §7.3).
///
/// Pure controller-local UI state: it never parses or normalizes a path,
/// never performs remote I/O and never logs. The `echoed` field tracks the
/// line already rendered on the local display, so the raw-mode controller
/// can render the delta as the user types.
struct PathPromptFlow {
    direction: TransferDirection,
    /// The submitted required field (local source / remote source).
    first: Option<String>,
    /// The editor of the active field.
    prompt: PathPrompt,
    /// 0 = required field, 1 = defaultable destination field.
    field: usize,
    /// Whether the next feed is the selector-chunk remainder (§6.2).
    initial: bool,
    /// The line currently echoed on the local display.
    echoed: String,
}

impl PathPromptFlow {
    fn new(direction: TransferDirection) -> Self {
        Self {
            direction,
            first: None,
            prompt: PathPrompt::required(PROMPT_PATH_LIMIT),
            field: 0,
            initial: true,
            echoed: String::new(),
        }
    }

    const fn banner(&self) -> &'static str {
        match self.direction {
            TransferDirection::Upload => PROMPT_BANNER_UPLOAD,
            TransferDirection::Download => PROMPT_BANNER_DOWNLOAD,
        }
    }

    const fn label(&self) -> &'static str {
        match (self.direction, self.field) {
            (TransferDirection::Upload, 0) => PROMPT_UPLOAD_SOURCE,
            (TransferDirection::Upload, 1) => PROMPT_UPLOAD_DESTINATION,
            (TransferDirection::Download, 0) => PROMPT_DOWNLOAD_SOURCE,
            (TransferDirection::Download, 1) => PROMPT_DOWNLOAD_DESTINATION,
            // The field index is 0 or 1 by construction; a defensive arm
            // keeps the match total without a panic.
            (_, _) => PROMPT_UPLOAD_SOURCE,
        }
    }

    fn current_line(&self) -> &str {
        self.prompt.current_line()
    }

    /// Feeds one processed input chunk.
    ///
    /// The first call consumes the selector-chunk remainder via
    /// `feed_initial` (§6.2) — that remainder is only non-empty when the
    /// selector and the first path bytes share one read block. Interactive
    /// typing delivers the path in later chunks as `path_bytes`, so every
    /// call additionally feeds the modal path bytes unless the remainder
    /// already produced a terminal outcome (trailing bytes of a terminal
    /// outcome belong to the dead input of the finished operation, §6.2).
    fn feed(&mut self, processed: &ProcessedInput) -> PromptProgress {
        let mut result = PromptResult::Continue;
        if self.initial {
            self.initial = false;
            result = self.prompt.feed_initial(processed.remainder.as_slice());
        }
        if matches!(result, PromptResult::Continue | PromptResult::Bell)
            && !processed.path_bytes.is_empty()
        {
            result = self.prompt.feed(processed.path_bytes.as_slice());
        }
        self.advance(result)
    }

    fn advance(&mut self, result: PromptResult) -> PromptProgress {
        match result {
            PromptResult::Submitted(path) => {
                if self.field == 0 {
                    self.first = Some(path.into());
                    self.prompt = PathPrompt::with_default(PROMPT_PATH_LIMIT);
                    self.field = 1;
                    self.echoed.clear();
                    PromptProgress::NextField
                } else {
                    self.echoed.clear();
                    PromptProgress::Completed {
                        first: self
                            .first
                            .take()
                            .expect("the required field completed before the destination"),
                        second: Some(path.into()),
                    }
                }
            }
            PromptResult::Empty => {
                // Only the defaultable destination field can submit empty.
                self.echoed.clear();
                PromptProgress::Completed {
                    first: self
                        .first
                        .take()
                        .expect("the required field completed before the destination"),
                    second: None,
                }
            }
            PromptResult::Cancelled => {
                self.echoed.clear();
                PromptProgress::Cancelled
            }
            PromptResult::Reprompt => {
                self.echoed.clear();
                PromptProgress::Reprompt
            }
            PromptResult::Bell => PromptProgress::Active { bell: true },
            PromptResult::Continue => PromptProgress::Active { bell: false },
        }
    }

    /// Renders the echo delta of the active field: the controller is in raw
    /// mode, so the prompt line is rendered locally — accepted characters
    /// echo as they arrive, backspace erases one column, and the caller
    /// rings the bell for rejected bytes (the exact rendering is an
    /// implementation decision; the frozen design fixes only the labels).
    async fn echo_delta(
        &mut self,
        output: &mut (impl tokio::io::AsyncWrite + Unpin),
    ) -> Result<(), ControllerError> {
        let line = self.prompt.current_line();
        let common = self
            .echoed
            .as_bytes()
            .iter()
            .zip(line.as_bytes())
            .take_while(|(left, right)| left == right)
            .count();
        for _ in self.echoed[common..].chars() {
            output.write_all(b"\x08 \x08").await?;
        }
        let added = &line[common..];
        if !added.is_empty() {
            output.write_all(added.as_bytes()).await?;
        }
        output.flush().await?;
        self.echoed.clear();
        self.echoed.push_str(line);
        Ok(())
    }
}

/// Session-local controller state of the 0.2.0 file-transfer interaction
/// (design §6–§9, §15, §16).
struct TransferUi {
    /// The local control input machine (disabled for non-interactive
    /// stdin: full byte transparency, §6.4).
    control: LocalControlInput,
    /// The active two-field path prompt, when one is open.
    flow: Option<PathPromptFlow>,
    /// The direction of the active file operation.
    direction: Option<TransferDirection>,
    /// Delayed remote terminal output while a prompt is active (§7.4).
    delayed: DelayedOutputBuffer,
    /// The three-state capability cache of the active connection (§9.3).
    capability: CapabilityCache,
    /// Whether the local UI has a terminal to write to (design §7.1).
    ui_terminal: bool,
    /// Whether the local UI shares the remote display (stdout terminal);
    /// otherwise it writes to stderr (design §7.1).
    ui_to_display: bool,
    /// Delayed-buffer overflow pending the pump's abort (§7.4.5).
    delayed_overflow: bool,
    /// Local input EOF was observed; the read branch stays disabled.
    local_ended: bool,
    /// The processed chunk the pump stored for the loop body, so the pump
    /// event stays small while the chunk data never leaves the session
    /// state (design §15.1: the fixed 4096-byte input bound).
    pending_input: Option<ProcessedInput>,
}

impl TransferUi {
    fn new(interactive: bool, ui_to_display: bool, ui_terminal: bool) -> Self {
        Self {
            control: LocalControlInput::new(interactive, false),
            flow: None,
            direction: None,
            delayed: DelayedOutputBuffer::new(DELAYED_OUTPUT_CAP),
            capability: CapabilityCache::Unknown,
            ui_terminal,
            ui_to_display,
            delayed_overflow: false,
            local_ended: false,
            pending_input: None,
        }
    }

    fn take_delayed_overflow(&mut self) -> bool {
        std::mem::take(&mut self.delayed_overflow)
    }

    /// Ends the active file operation and returns the machine to
    /// pass-through; the returned action reports an abandoned `Ctrl+]`
    /// prefix that the caller must render as a bell (§6.3).
    fn leave_modal(&mut self) -> LocalAction {
        self.flow = None;
        self.direction = None;
        self.delayed_overflow = false;
        self.control.leave_modal()
    }
}

/// What the pump loop must do after one processed local input chunk.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LocalInputHandling {
    /// Nothing further.
    Done,
    /// A new file operation must start (pass-through `u`/`d`).
    StartModal(TransferDirection),
    /// The prompt completed; the transfer substream must be opened.
    RunTransfer {
        direction: TransferDirection,
        first: String,
        second: Option<String>,
    },
}

/// Writes one local UI message: to the remote display when stdout is a
/// terminal, else to stderr (design §7.1). Local UI never enters
/// terminal-data and never logs.
async fn write_local_ui(
    output: &mut (impl tokio::io::AsyncWrite + Unpin),
    to_display: bool,
    bytes: &[u8],
) -> Result<(), ControllerError> {
    if to_display {
        output.write_all(bytes).await?;
        output.flush().await?;
    } else {
        tokio::io::stderr().write_all(bytes).await?;
        tokio::io::stderr().flush().await?;
    }
    Ok(())
}

/// Writes the delayed remote output in original order (design §7.4.4):
/// the prompt has ended, the terminal is in its session mode, and the
/// buffered bytes now stream to the local display.
async fn flush_delayed_output(
    session_ui: &mut TransferUi,
    output: &mut (impl tokio::io::AsyncWrite + Unpin),
    terminal_output: &mut RemoteTerminalOutput,
    audit: Option<&AuditObserver>,
) -> Result<(), ControllerError> {
    if session_ui.delayed.is_empty() {
        return Ok(());
    }
    let bytes = session_ui.delayed.take_all();
    // Design section 18.4: the delayed bytes were already recorded as raw
    // network output; the display record is appended before the display
    // write.
    let display = terminal_output.prepare(&bytes);
    if let Some(audit) = audit {
        audit.record_display_bytes(&display).await?;
    }
    let displayed = async {
        terminal_output.write(output, &display).await?;
        output.flush().await
    }
    .await;
    if let Err(error) = displayed {
        if let Some(audit) = audit {
            let _ = audit
                .record_display_write_outcome(false, display.len() as u64)
                .await;
        }
        return Err(error.into());
    }
    if let Some(audit) = audit {
        audit
            .record_display_write_outcome(true, display.len() as u64)
            .await?;
    }
    Ok(())
}

/// Ends the active file operation, returning the machine to pass-through,
/// and rings the bell when the machine reports an abandoned prefix (§6.3).
async fn end_transfer_modal(
    session_ui: &mut TransferUi,
    output: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> Result<(), ControllerError> {
    if session_ui.leave_modal() == LocalAction::Bell {
        write_local_ui(output, session_ui.ui_to_display, b"\x07").await?;
    }
    Ok(())
}

/// Aborts the active prompt because the delayed output buffer reached its
/// capacity (design §7.4.5): the not-yet-started file operation is
/// cancelled, the terminal stays in its session mode, and the buffered
/// remote output is written out immediately. The remote terminal stays
/// open.
async fn abort_prompt_for_overflow(
    session_ui: &mut TransferUi,
    output: &mut (impl tokio::io::AsyncWrite + Unpin),
    terminal_output: &mut RemoteTerminalOutput,
    audit: Option<&AuditObserver>,
) -> Result<(), ControllerError> {
    end_transfer_modal(session_ui, output).await?;
    flush_delayed_output(session_ui, output, terminal_output, audit).await
}

/// Handles one processed local input chunk: the active prompt consumes its
/// path bytes, and the chunk's local action is applied with modal rules
/// (design §6.3, §7.4, §16).
async fn handle_processed_input(
    processed: ProcessedInput,
    output: &mut (impl tokio::io::AsyncWrite + Unpin),
    terminal_output: &mut RemoteTerminalOutput,
    session_ui: &mut TransferUi,
    cancel: &AtomicBool,
    audit: Option<&AuditObserver>,
) -> Result<LocalInputHandling, ControllerError> {
    let mut run_transfer = None;
    if let Some(flow) = session_ui.flow.as_mut() {
        match flow.feed(&processed) {
            PromptProgress::Active { bell } => {
                flow.echo_delta(output).await?;
                if bell {
                    write_local_ui(output, session_ui.ui_to_display, b"\x07").await?;
                }
            }
            PromptProgress::Reprompt => {
                // §7.2/§7.3: an empty required field, an over-long line or
                // an invalid encoding re-prompts the same field.
                write_local_ui(output, session_ui.ui_to_display, b"\r\n").await?;
                write_local_ui(output, session_ui.ui_to_display, flow.label().as_bytes()).await?;
            }
            PromptProgress::NextField => {
                write_local_ui(output, session_ui.ui_to_display, b"\r\n").await?;
                write_local_ui(output, session_ui.ui_to_display, flow.label().as_bytes()).await?;
            }
            PromptProgress::Completed { first, second } => {
                write_local_ui(output, session_ui.ui_to_display, b"\r\n").await?;
                session_ui.flow = None;
                // §7.4.4: the delayed remote output is flushed in order
                // once the prompt has ended.
                flush_delayed_output(session_ui, output, terminal_output, audit).await?;
                run_transfer = Some((
                    session_ui
                        .direction
                        .expect("an active prompt keeps its direction"),
                    first,
                    second,
                ));
            }
            PromptProgress::Cancelled => {
                write_local_ui(output, session_ui.ui_to_display, b"\r\n").await?;
                // §16.1: no file substream is opened and nothing is sent to
                // the remote PTY.
                end_transfer_modal(session_ui, output).await?;
                flush_delayed_output(session_ui, output, terminal_output, audit).await?;
            }
        }
    }
    // The chunk's local action, interpreted with modal rules (§6.3).
    match processed.action {
        LocalAction::None => {}
        LocalAction::Detach => {
            // §6.2/§16.3: end the whole session; an active operation is
            // cancelled by dropping it (its substream closes, the peer
            // cleans up best-effort). The local key action is recorded
            // before the session ends (design section 15.3).
            if let Some(audit) = audit {
                audit.record_key_action(KEY_ACTION_DETACH).await?;
            }
            return Err(ControllerError::Interrupted);
        }
        LocalAction::ShowHelp => {
            if let Some(audit) = audit {
                audit.record_key_action(KEY_ACTION_HELP).await?;
            }
            if session_ui.ui_terminal {
                write_local_ui(output, session_ui.ui_to_display, b"\r\n").await?;
                write_local_ui(
                    output,
                    session_ui.ui_to_display,
                    LOCAL_CONTROL_HELP.as_bytes(),
                )
                .await?;
                if let Some(flow) = session_ui.flow.as_ref() {
                    // §6.3: the prompt continues after the help.
                    write_local_ui(output, session_ui.ui_to_display, b"\r\n").await?;
                    write_local_ui(output, session_ui.ui_to_display, flow.label().as_bytes())
                        .await?;
                    write_local_ui(
                        output,
                        session_ui.ui_to_display,
                        flow.current_line().as_bytes(),
                    )
                    .await?;
                }
            } else {
                // §7.1: without a terminal output the fixed unavailable
                // error is shown for `u`, `d` and `?`.
                write_local_ui(output, session_ui.ui_to_display, b"\r\n").await?;
                write_local_ui(
                    output,
                    session_ui.ui_to_display,
                    FILE_TRANSFER_UNAVAILABLE.as_bytes(),
                )
                .await?;
            }
        }
        LocalAction::AlreadyActive => {
            // §15.3: a second operation is never started.
            write_local_ui(output, session_ui.ui_to_display, b"\r\n").await?;
            write_local_ui(
                output,
                session_ui.ui_to_display,
                FILE_TRANSFER_ALREADY_ACTIVE.as_bytes(),
            )
            .await?;
        }
        LocalAction::Bell => {
            write_local_ui(output, session_ui.ui_to_display, b"\x07").await?;
        }
        LocalAction::CancelOp => {
            if let Some(audit) = audit {
                audit.record_key_action(KEY_ACTION_INTERRUPT).await?;
            }
            if session_ui.flow.is_some() {
                // §16.1: Ctrl+C cancels the path prompt; the terminal is
                // restored and the delayed remote output is written out.
                write_local_ui(output, session_ui.ui_to_display, b"\r\n").await?;
                end_transfer_modal(session_ui, output).await?;
                flush_delayed_output(session_ui, output, terminal_output, audit).await?;
            } else {
                // §16.2: Ctrl+C cancels the running transfer; the flag is
                // observed by the transfer between bounded blocks.
                cancel.store(true, Ordering::Relaxed);
            }
        }
        LocalAction::StartUpload | LocalAction::StartDownload => {
            // Pass-through only: the machine never starts an operation
            // while modal; the pump loop runs the modal entry. The local
            // key action is recorded before the modal starts (design
            // section 15.3).
            if let Some(audit) = audit {
                let action = if processed.action == LocalAction::StartUpload {
                    KEY_ACTION_UPLOAD
                } else {
                    KEY_ACTION_DOWNLOAD
                };
                audit.record_key_action(action).await?;
            }
            let direction = if processed.action == LocalAction::StartUpload {
                TransferDirection::Upload
            } else {
                TransferDirection::Download
            };
            return Ok(LocalInputHandling::StartModal(direction));
        }
    }
    if let Some((direction, first, second)) = run_transfer {
        return Ok(LocalInputHandling::RunTransfer {
            direction,
            first,
            second,
        });
    }
    Ok(LocalInputHandling::Done)
}

/// Enters the file-transfer modal for one direction (design §7.1, §9.3):
/// local availability, capability probing, then the two-field path prompt.
#[allow(clippy::too_many_arguments)]
async fn begin_file_transfer_modal(
    direction: TransferDirection,
    driver: &mut EndpointDriver,
    streams: &mut Libp2pApplicationStreams,
    binding: ConnectionBinding,
    output: &mut (impl tokio::io::AsyncWrite + Unpin),
    session_ui: &mut TransferUi,
    base: &Option<BaseDirectory>,
    cancellation: &tokio_util::sync::CancellationToken,
) -> Result<(), ControllerError> {
    let capability = match file_transfer_ready(session_ui, base.as_ref()) {
        Ok(capability) => capability,
        Err(TransferNotReady::Unavailable) => {
            write_local_ui(output, session_ui.ui_to_display, b"\r\n").await?;
            write_local_ui(
                output,
                session_ui.ui_to_display,
                FILE_TRANSFER_UNAVAILABLE.as_bytes(),
            )
            .await?;
            end_transfer_modal(session_ui, output).await?;
            return Ok(());
        }
        Err(TransferNotReady::Unsupported) => {
            // §9.3: cached unsupported — the fixed error is shown and no
            // path prompt is entered; later shortcuts do not re-probe.
            write_local_ui(output, session_ui.ui_to_display, b"\r\n").await?;
            write_local_ui(
                output,
                session_ui.ui_to_display,
                FILE_TRANSFER_UNSUPPORTED.as_bytes(),
            )
            .await?;
            end_transfer_modal(session_ui, output).await?;
            return Ok(());
        }
        Err(TransferNotReady::Probe) => {
            // §9.3: first trigger probes the protocol on a dedicated
            // substream that is closed without a message on success.
            let probe = tokio::select! {
                biased;
                () = cancellation.cancelled() => return Err(ControllerError::Interrupted),
                result = async {
                    probe_file_transfer_capability(open_until(
                        driver,
                        streams,
                        binding,
                        FILE_TRANSFER_PROTOCOL,
                        tokio::time::Instant::now() + EXCHANGE_TIMEOUT,
                    ))
                    .await
                } => result,
            };
            match probe {
                Ok(capability) => {
                    session_ui.capability = capability;
                    capability
                }
                Err(_) => {
                    // §9.3: timeouts, connection errors and transient I/O
                    // failures are not cached; the user may retry.
                    tracing::debug!("file transfer capability probe failed");
                    write_local_ui(output, session_ui.ui_to_display, b"\r\n").await?;
                    write_local_ui(
                        output,
                        session_ui.ui_to_display,
                        FILE_TRANSFER_PROBE_FAILED.as_bytes(),
                    )
                    .await?;
                    end_transfer_modal(session_ui, output).await?;
                    return Ok(());
                }
            }
        }
    };
    debug_assert_eq!(capability, CapabilityCache::Supported);
    // §7.1: the local UI starts on a fresh line, away from the remote
    // application's current line.
    let flow = PathPromptFlow::new(direction);
    write_local_ui(output, session_ui.ui_to_display, b"\r\n").await?;
    write_local_ui(output, session_ui.ui_to_display, flow.banner().as_bytes()).await?;
    write_local_ui(output, session_ui.ui_to_display, b"\r\n").await?;
    write_local_ui(output, session_ui.ui_to_display, flow.label().as_bytes()).await?;
    session_ui.direction = Some(direction);
    session_ui.flow = Some(flow);
    Ok(())
}

/// Reports a local initialization failure of the transfer and returns to
/// pass-through (design §17.2: ordinary file errors never end the session).
async fn fail_transfer_startup(
    direction: TransferDirection,
    reason: &str,
    output: &mut (impl tokio::io::AsyncWrite + Unpin),
    session_ui: &mut TransferUi,
) -> Result<(), ControllerError> {
    let summary = format!("{} failed: {reason}", transfer_direction_verb(direction));
    write_local_ui(output, session_ui.ui_to_display, b"\r\n").await?;
    write_local_ui(output, session_ui.ui_to_display, summary.as_bytes()).await?;
    end_transfer_modal(session_ui, output).await
}

/// Starts the real transfer after both prompt fields completed (design
/// §7.4.7, §7.5, §9.3): the transfer substream is opened only now, the
/// local source is opened for uploads, one status line is written, and the
/// transfer future is armed as a pump branch (§15.2). The future owns the
/// substream, the opened source and the (Copy) transfer parameters; it
/// borrows only the shared session base directory and cancel flag, so the
/// pump loop can re-arm it across iterations.
#[allow(clippy::too_many_arguments)]
async fn begin_transfer<'a>(
    direction: TransferDirection,
    first: String,
    second: Option<String>,
    driver: &mut EndpointDriver,
    streams: &mut Libp2pApplicationStreams,
    binding: ConnectionBinding,
    output: &mut (impl tokio::io::AsyncWrite + Unpin),
    session_ui: &mut TransferUi,
    cancellation: &tokio_util::sync::CancellationToken,
    base: &'a Option<BaseDirectory>,
    cancel: &'a AtomicBool,
    transfer: &mut Option<Pin<Box<dyn Future<Output = TransferOutcome> + 'a>>>,
    audit: Option<&'a AuditObserver>,
) -> Result<(), ControllerError> {
    let Some(base) = base.as_ref() else {
        // The base directory became unavailable after the session started:
        // the operation fails locally and the session continues (§17.2).
        write_local_ui(output, session_ui.ui_to_display, b"\r\n").await?;
        write_local_ui(
            output,
            session_ui.ui_to_display,
            FILE_TRANSFER_UNAVAILABLE.as_bytes(),
        )
        .await?;
        end_transfer_modal(session_ui, output).await?;
        return Ok(());
    };
    // §7.5: the machine pauses ordinary input for the transfer phase.
    session_ui
        .control
        .enter_transfer()
        .expect("a completed prompt implies an active prompt phase");
    // §7.4.7: the real substream opens only after all prompts completed.
    let deadline = tokio::time::Instant::now() + EXCHANGE_TIMEOUT;
    let stream = tokio::select! {
        biased;
        () = cancellation.cancelled() => return Err(ControllerError::Interrupted),
        result = open_until(driver, streams, binding, FILE_TRANSFER_PROTOCOL, deadline) => match result {
            Ok(stream) => stream,
            // §15.4: a bounded open failure cancels the operation and
            // returns to the terminal; the session stays alive (§17.2).
            Err(_) => {
                return fail_transfer_startup(
                    direction,
                    FILE_TRANSFER_OPEN_FAILED,
                    output,
                    session_ui,
                )
                .await;
            }
        },
    };
    if cancel.load(Ordering::Relaxed) {
        // The user cancelled before the transfer began (§16.2): nothing was
        // sent on the substream.
        drop(stream);
        let summary = format!("{} cancelled", transfer_direction_verb(direction));
        write_local_ui(output, session_ui.ui_to_display, b"\r\n").await?;
        write_local_ui(output, session_ui.ui_to_display, summary.as_bytes()).await?;
        end_transfer_modal(session_ui, output).await?;
        return Ok(());
    }
    if direction == TransferDirection::Upload {
        // §8.2: the local source is opened and judged through its handle.
        let path = match base.resolve(&first) {
            Ok(path) => path,
            Err(error) => {
                return fail_transfer_startup(direction, &error.to_string(), output, session_ui)
                    .await;
            }
        };
        let mut source = match SourceFile::open(&path) {
            Ok(source) => source,
            Err(error) => {
                return fail_transfer_startup(direction, &error.to_string(), output, session_ui)
                    .await;
            }
        };
        let file_name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let destination = second.unwrap_or_default();
        // §7.5: one status line at the start.
        let status = format!(
            "{}: {TRANSFER_STATUS_PAUSED}",
            transfer_direction_verb(direction)
        );
        write_local_ui(output, session_ui.ui_to_display, b"\r\n").await?;
        write_local_ui(output, session_ui.ui_to_display, status.as_bytes()).await?;
        *transfer = Some(Box::pin(async move {
            let mut stream = stream.into_tokio();
            run_upload_audited(
                &mut stream,
                &TransferConfig::defaults(),
                &mut source,
                &destination,
                &file_name,
                cancel,
                audit,
            )
            .await
        }));
    } else {
        // §7.5: one status line at the start.
        let status = format!(
            "{}: {TRANSFER_STATUS_PAUSED}",
            transfer_direction_verb(direction)
        );
        write_local_ui(output, session_ui.ui_to_display, b"\r\n").await?;
        write_local_ui(output, session_ui.ui_to_display, status.as_bytes()).await?;
        *transfer = Some(Box::pin(async move {
            let local_target = second.as_deref();
            let mut stream = stream.into_tokio();
            run_download_audited(
                &mut stream,
                &TransferConfig::defaults(),
                base,
                &first,
                local_target,
                cancel,
                audit,
            )
            .await
        }));
    }
    Ok(())
}

/// Polls the running transfer as one pump branch (design §7.5, §15.2).
async fn poll_inflight_transfer(
    transfer: &mut Option<Pin<Box<dyn Future<Output = TransferOutcome> + '_>>>,
) -> TransferOutcome {
    match transfer.as_mut() {
        Some(future) => future.await,
        // Unreachable: the pump gates the branch on `transfer.is_some()`.
        None => std::future::pending().await,
    }
}

/// Handles the completion of the running transfer (design §7.5): one
/// completion summary is written and the session returns to pass-through
/// (§17.2 — ordinary file errors never end the remote shell).
async fn handle_transfer_event(
    outcome: TransferOutcome,
    output: &mut (impl tokio::io::AsyncWrite + Unpin),
    session_ui: &mut TransferUi,
    cancel: &AtomicBool,
    transfer: &mut Option<Pin<Box<dyn Future<Output = TransferOutcome> + '_>>>,
) -> Result<Option<u32>, ControllerError> {
    let direction = session_ui
        .direction
        .expect("a running transfer keeps its direction");
    let summary = transfer_summary_line(direction, outcome);
    write_local_ui(output, session_ui.ui_to_display, b"\r\n").await?;
    write_local_ui(output, session_ui.ui_to_display, summary.as_bytes()).await?;
    end_transfer_modal(session_ui, output).await?;
    *transfer = None;
    cancel.store(false, Ordering::Relaxed);
    Ok(None)
}

/// The direction verb of the local UI texts.
const fn transfer_direction_verb(direction: TransferDirection) -> &'static str {
    match direction {
        TransferDirection::Upload => "upload",
        TransferDirection::Download => "download",
    }
}

/// The single completion summary of one transfer (design §7.5).
fn transfer_summary_line(direction: TransferDirection, outcome: TransferOutcome) -> String {
    let verb = transfer_direction_verb(direction);
    match outcome {
        TransferOutcome::Committed { bytes } => format!("{verb} complete: {bytes} bytes"),
        TransferOutcome::Cancelled => format!("{verb} cancelled"),
        TransferOutcome::Failed(code) => format!("{verb} failed: {code:?}"),
    }
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
) -> Result<Option<LocalInputChunk>, ControllerError> {
    let mut chunk = LocalInputChunk::new();
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

#[cfg(test)]
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

#[cfg(test)]
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

/// The Terminal Active gate (design sections 13.2 and 14): the terminal
/// hello is conveyed first, an enterprise session completes its mandatory
/// audit handshake, and then `TerminalReady` is awaited. Standard sessions
/// pass `None` and never resolve audit storage or construct an observer.
#[allow(clippy::too_many_arguments)]
async fn establish_audit_and_terminal(
    audit_stream: Option<ApplicationStream>,
    data_read: &mut (impl tokio::io::AsyncRead + Unpin),
    control_write: &mut (impl tokio::io::AsyncWrite + Unpin),
    hello: &TerminalHello,
    binding: ConnectionBinding,
    self_peer: PeerId,
    audit_root_override: Option<&Path>,
) -> Result<Option<AuditObserver>, ControllerError> {
    control_write.write_all(hello.encode().as_slice()).await?;
    control_write.flush().await?;
    let digest = Digest32::new(Sha256::digest(hello.encode().as_slice()).into());
    let audit = if let Some(audit_stream) = audit_stream {
        let audit_root = match audit_root_override {
            Some(root) => root.to_path_buf(),
            None => crate::audit::observer::platform_audit_root()?,
        };
        // The opaque tokio stream is boxed before the handshake so the
        // handshake future never holds the stream's inline buffers.
        let audit_stream: Box<dyn AuditStreamIo> = Box::new(audit_stream.into_tokio());
        let audit = tokio::time::timeout(
            AUDIT_ESTABLISH_TIMEOUT,
            AuditObserver::establish(
                audit_stream,
                AuditRole::Controller,
                self_peer,
                binding.peer(),
                crate::audit::observer::utc_start_seconds(),
                digest,
                &audit_root,
                &mut OsSecureRandom,
            ),
        )
        .await
        .map_err(|_| ControllerError::Timeout)?
        .map_err(ControllerError::from)?;
        audit.record_terminal_hello(digest).await?;
        Some(audit)
    } else {
        None
    };
    let mut ready = [0_u8; 1];
    tokio::time::timeout(EXCHANGE_TIMEOUT, data_read.read_exact(&mut ready))
        .await
        .map_err(|_| ControllerError::Timeout)??;
    TerminalReady::decode(&ready).map_err(ControllerError::from)?;
    if let Some(audit) = audit.as_ref() {
        audit.record_terminal_ready().await?;
    }
    Ok(audit)
}

/// The controller-side audit close (design sections 21 and 22). On a
/// normal exit the finalization runs to completion; on an interrupted
/// session the close reason is conveyed and the finalization is attempted;
/// on connection loss the local tail is completed without a manifest; on
/// an audit failure the observer already failed closed. A finalization
/// failure is never hidden behind the remote exit code (design
/// section 22.1).
///
/// The finalization exchange reads and writes the audit substream, so the
/// endpoint driver is polled throughout (`drive_bound`); the connection
/// would otherwise never deliver the peer's finalization frames.
async fn audit_close_controller(
    driver: &mut EndpointDriver,
    binding: ConnectionBinding,
    session: Result<u32, ControllerError>,
    audit: Option<&AuditObserver>,
    detached: bool,
) -> Result<u32, ControllerError> {
    let Some(audit) = audit else {
        return session;
    };
    match session {
        Ok(code) => {
            let finalized = drive_bound(
                driver,
                binding,
                audit.close_and_finalize(
                    ManifestEnding::ShellExit(code as u8),
                    true,
                    CloseNoticeHandling::Sender(AuditCloseReason::NormalShellExit),
                ),
            )
            .await;
            match finalized {
                Ok(Ok(())) => Ok(code),
                Ok(Err(error)) => {
                    audit
                        .fail_closed(None, AuditCloseReason::AuditFailure)
                        .await;
                    Err(ControllerError::Audit(error))
                }
                Err(endpoint) => {
                    audit
                        .fail_closed(None, AuditCloseReason::AuditFailure)
                        .await;
                    Err(endpoint.into())
                }
            }
        }
        Err(error) => match error {
            ControllerError::Interrupted => {
                let reason = if detached {
                    AuditCloseReason::ControllerDetach
                } else {
                    AuditCloseReason::LocalInterrupt
                };
                let lifecycle = if detached {
                    LIFECYCLE_KIND_ACTIVE_DETACH
                } else {
                    LIFECYCLE_KIND_LOCAL_INTERRUPT
                };
                let _ = audit.record_lifecycle(lifecycle).await;
                match drive_bound(
                    driver,
                    binding,
                    audit.close_and_finalize(
                        ManifestEnding::CloseReason(reason),
                        false,
                        CloseNoticeHandling::Sender(reason),
                    ),
                )
                .await
                {
                    Ok(Ok(())) => Err(error),
                    Ok(Err(audit_error)) => {
                        audit
                            .fail_closed(None, AuditCloseReason::AuditFailure)
                            .await;
                        Err(ControllerError::Audit(audit_error))
                    }
                    Err(endpoint) => {
                        audit
                            .fail_closed(None, AuditCloseReason::AuditFailure)
                            .await;
                        Err(endpoint.into())
                    }
                }
            }
            ControllerError::Audit(_) => {
                // The observer already failed closed and conveyed the
                // notice; keep the original error.
                Err(error)
            }
            _ => {
                // Connection loss or any other failure: the local tail is
                // completed without a manifest (design section 22.4).
                audit
                    .close_interrupted(AuditCloseReason::ConnectionLost)
                    .await;
                Err(error)
            }
        },
    }
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
    DrainingBoth {
        deadline: tokio::time::Instant,
    },
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
        matches!(
            self,
            Self::AwaitingBoth | Self::DrainingBoth { .. } | Self::AwaitingOutput { .. }
        )
    }

    const fn exit_pending(self) -> bool {
        matches!(
            self,
            Self::AwaitingBoth | Self::DrainingBoth { .. } | Self::AwaitingExit { .. }
        )
    }

    const fn deadline(self) -> Option<tokio::time::Instant> {
        match self {
            Self::DrainingBoth { deadline }
            | Self::AwaitingExit { deadline }
            | Self::AwaitingOutput { deadline, .. }
            | Self::Complete { deadline, .. } => Some(deadline),
            Self::AwaitingBoth => None,
        }
    }

    fn observe_transport_close(&mut self, now: tokio::time::Instant) {
        if matches!(self, Self::AwaitingBoth) {
            *self = Self::DrainingBoth {
                deadline: now + REMOTE_COMPLETION_TIMEOUT,
            };
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
            Self::DrainingBoth { deadline } => {
                *self = Self::AwaitingExit { deadline };
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
            Self::DrainingBoth { deadline } => {
                *self = Self::AwaitingOutput { code, deadline };
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
        ActiveTerminalConnectionEvent, CapabilityCache, ControllerConfig, ControllerError,
        ControllerStage, CrosstermFrontend, DELAYED_OUTPUT_CAP, DisplayModeGuard, EndpointError,
        EndpointEvent, EnterpriseControllerUi, FILE_TRANSFER_ALREADY_ACTIVE,
        FILE_TRANSFER_UNAVAILABLE, FILE_TRANSFER_UNSUPPORTED, LOCAL_CONTROL_HELP,
        LocalInputHandling, LocalInputSignal, PROMPT_BANNER_DOWNLOAD, PROMPT_BANNER_UPLOAD,
        PROMPT_DOWNLOAD_SOURCE, PROMPT_UPLOAD_SOURCE, PathPromptFlow, PromptProgress,
        REMOTE_COMPLETION_TIMEOUT, RemoteCompletion, RemoteTerminalOutput,
        RemoteTerminalOutputMode, TerminalFrontend, TransferNotReady, TransferUi,
        UTF8_OUTPUT_BATCH_CAPACITY, Utf8OutputBatch, abort_prompt_for_overflow,
        active_terminal_connection_event, await_remote_completion, await_until,
        begin_file_transfer_modal, begin_transfer, changed_terminal_size,
        complete_after_output_eof, complete_terminal_control_io, controller_fallback_required,
        copy_remote_output, copy_terminal_resizes, decode_terminal_exit, default_terminal_value,
        direct_fallback_required, end_transfer_modal, enter_raw_mode_before,
        exchange_terminal_ready, exchange_terminal_ready_timed, fail_transfer_startup,
        fallback_transport, file_transfer_ready, finish_local_input_eof, finish_terminal,
        finish_terminal_output, flush_delayed_output, handle_processed_input,
        handle_transfer_event, local_terminal_hello, local_terminal_hello_with,
        native_display_restore_commands, next_retry_delay, platform_open, prepare_controller,
        prepare_controller_session, probe_file_transfer_capability, process_local_input_chunk,
        read_auth_response, read_local_input, read_remote_exit, restore_native_display,
        run_controller, run_controller_session, run_controller_with_progress, run_terminal,
        run_until_interrupted, terminal_environment, terminal_environment_from,
        transfer_summary_line, wait_for_audit_frame, wait_for_remote_completion_deadline,
        write_local_ui, write_native_display_restore,
    };
    use crate::audit::observer::{AuditObserver, CloseNoticeHandling, FrameEvent};
    use crate::audit::session::{
        AuditError, KEY_ACTION_DOWNLOAD, KEY_ACTION_HELP, KEY_ACTION_INTERRUPT, KEY_ACTION_UPLOAD,
        OUTCOME_FAILED, OUTCOME_OK,
    };
    use crate::audit::verify::{StreamAction, stream_frames};
    use crate::file_semantics::BaseDirectory;
    use crate::local_control::{LocalAction, LocalControlInput, LocalInputChunk, ModalPhase};
    use crate::network::{
        ConnectionBinding, EndpointDriver, RelayAccessMode, RelayConnection, build_endpoint,
        connect_configured_relay, wait_for_reservation,
    };
    use crate::pake::{OpaquePake, OpaqueRegistration};
    use crate::progress::NoopProgress;
    use crate::progress::OperationProgress;
    use crate::protocol::EnterpriseResolveUi as _;
    use crate::protocol::{ResolveDeadline, ResolvedTarget, allocate_locator, resolve_peer};
    use crate::transfer::TransferOutcome;
    use crate::transfer_prompt::{AppendOutcome, DelayedOutputBuffer};
    use sha2::{Digest as _, Sha256};
    use std::cell::Cell;
    use std::fs;
    use std::future::Future;
    use std::io;
    use std::io::Write as _;
    use std::path::Path;
    use std::pin::Pin;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::io::DuplexStream;
    use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};
    use tokio::sync::oneshot;
    use yon_relay::{RelayServeConfig, RelayServiceError, run_relay_until};
    use yonder_core::wire::audit::{
        AUDIT_PROTOCOL, AuditCloseReason, AuditErrorCode, AuditRole, Digest32, ManifestEnding,
    };
    use yonder_core::wire::audit_container::RecordType;
    use yonder_core::wire::auth::AuthServerResponse;
    use yonder_core::wire::auth::{
        AuthClientFinish, AuthClientHello, Authenticated, CLIENT_HELLO_LEN, KE3_LEN, PakeContext,
    };
    use yonder_core::wire::file_transfer::{
        FRAME_HEADER_LEN, FileTransferMessage, MAX_DATA_LEN, Sha256Digest, TransferTag,
        decode_frame_header, encode_frame_header,
    };
    use yonder_core::wire::file_transfer::{FileTransferErrorCode, TransferDirection};
    use yonder_core::wire::terminal::{CONTROL_LEN, MAX_HELLO_LEN, TerminalResize};
    use yonder_core::wire::terminal::{
        TerminalComplete, TerminalExit, TerminalHello, TerminalReady,
    };
    use yonder_core::wire::{
        AUTH_PROTOCOL, FILE_TRANSFER_PROTOCOL, TERMINAL_CONTROL_PROTOCOL, TERMINAL_DATA_PROTOCOL,
    };
    use yonder_core::{
        ConnectionCode, EnterpriseProvider, EnterpriseProviders, Locator, PakeSecret,
        ProtocolError, RetryAfter, SecretDocument, TerminalSize, TerminalValue,
    };
    use yonder_core::{OsSecureRandom, Pake, PeerIdBytes, SecureRandom};
    use yonder_net::{
        ApplicationStream, ApplicationStreamError, ApplicationStreams, ConnectedPoint,
        ConnectionId, DirectUpgradePolicy, EndpointRelayAddress, EndpointRelaySet,
        IncomingApplicationStreams, Keypair, Libp2pApplicationStreams, NetworkBuildError, PeerId,
        WssTransportConfig, peer_id_bytes,
    };

    // The fixed session state with the 0.2.0 audit observer: the
    // handshake futures carry the session state machine (the two 16 KiB
    // canonical normalizers) and the observer is alive across the pump.
    // The bound is still fixed-size — never proportional to input.
    const CONTROLLER_SESSION_HEAP_LIMIT: usize = 2 * 1024 * 1024;

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

    #[test]
    fn invalid_wss_ca_is_rejected_before_controller_network_activity() {
        // The controller future (with the 0.2.0 audit observer state)
        // exceeds the default test-thread stack, so the scenario runs on a
        // dedicated thread with a large stack.
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    assert!(matches!(
                        run_controller(invalid_wss_controller_config()).await,
                        Err(ControllerError::Endpoint(EndpointError::Build(
                            NetworkBuildError::WssTls(_)
                        )))
                    ));
                });
            })
            .unwrap()
            .join()
            .unwrap();
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
            frontend.restore_display().unwrap();
            #[cfg(not(windows))]
            drop(RawModeGuard { armed: false });
        }
    }

    #[test]
    fn display_restore_covers_every_terminal_mode_enabled_by_remote_apps() {
        let commands = native_display_restore_commands().unwrap();
        assert!(commands.starts_with("\u{1b}[?2004l"));
        assert!(commands.contains("\u{1b}[?1004l"));
        assert!(commands.contains("\u{1b}[?1006l"));
        assert!(commands.contains("\u{1b}[?1049l"));
        assert!(commands.contains("\u{1b}[?25h"));
        assert!(commands.ends_with("\u{1b}[0m"));
        assert!(commands.len() <= 128);

        assert!(DisplayModeGuard::enter(false).unwrap().is_none());
        DisplayModeGuard::restore_optional(None).unwrap();

        let mut output = Vec::new();
        write_native_display_restore(&mut output, &commands).unwrap();
        assert_eq!(output, commands.as_bytes());
        assert!(write_native_display_restore(&mut FailingDisplayOutput, &commands).is_err());
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

        assert!(matches!(
            finish_terminal_output::<()>(Err(ControllerError::ConnectionLost), Ok(())),
            Err(ControllerError::ConnectionLost)
        ));
        assert!(matches!(
            finish_terminal_output(Ok(()), Err(ControllerError::Timeout)),
            Err(ControllerError::Timeout)
        ));
        assert!(matches!(
            finish_terminal_output::<()>(
                Err(ControllerError::ConnectionLost),
                Err(ControllerError::TerminalOutput(io::Error::other(
                    "output failed"
                ))),
            ),
            Err(ControllerError::SessionAndTerminalOutput { .. })
        ));
        assert!(matches!(
            finish_terminal_output::<()>(
                Err(ControllerError::ConnectionLost),
                Err(ControllerError::Timeout),
            ),
            Err(ControllerError::ConnectionLost)
        ));
    }

    #[test]
    fn non_interactive_terminal_metadata_uses_safe_defaults() {
        let hello = local_terminal_hello().unwrap();
        assert_eq!(hello.size(), TerminalSize::new(80, 24).unwrap());
        assert_eq!(default_terminal_value(false).unwrap().as_str(), "dumb");
        assert_eq!(
            default_terminal_value(true).unwrap().as_str(),
            "xterm-256color"
        );
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
        frontend.restore_display().unwrap();
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
    async fn terminal_resize_pump_sends_each_observed_size_once() {
        let frontend = FakeFrontend {
            restored: Rc::new(Cell::new(false)),
            size: Ok((132, 43)),
            raw_error: None,
        };
        let (mut controller, mut host) = tokio::io::duplex(5);
        let pump = copy_terminal_resizes(
            &frontend,
            &mut controller,
            TerminalSize::new(80, 24).unwrap(),
            true,
            None,
        );
        let receive = async {
            let mut resize = [0_u8; 5];
            host.read_exact(&mut resize).await.unwrap();
            resize
        };
        tokio::pin!(pump);
        let resize = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                result = &mut pump => match result {
                    Ok(never) => match never {},
                    Err(error) => panic!("resize pump failed: {error}"),
                },
                resize = receive => resize,
            }
        })
        .await
        .expect("the changed terminal size was not sent");
        assert_eq!(resize, [0x02, 0, 132, 0, 43]);
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

        assert!(matches!(
            enter_raw_mode_before(&RestoreFailingFrontend, async {
                Err::<(), _>(ControllerError::ConnectionLost)
            })
            .await,
            Err(ControllerError::SessionAndTerminalRestore { .. })
        ));
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

        let mut closed_exit_first = RemoteCompletion::new();
        closed_exit_first.observe_transport_close(now);
        assert_eq!(
            closed_exit_first.deadline(),
            Some(now + REMOTE_COMPLETION_TIMEOUT)
        );
        assert_eq!(closed_exit_first.observe_exit(13, now), None);
        assert_eq!(closed_exit_first.observe_output_eof(now), Some(13));

        let mut closed_eof_first = RemoteCompletion::new();
        closed_eof_first.observe_transport_close(now);
        closed_eof_first.observe_transport_close(now + Duration::from_secs(1));
        assert_eq!(closed_eof_first.observe_output_eof(now), None);
        assert_eq!(closed_eof_first.observe_exit(17, now), Some(17));
        assert_eq!(
            closed_eof_first.deadline(),
            Some(now + REMOTE_COMPLETION_TIMEOUT)
        );

        assert_eq!(exit_first.observe_exit(99, now), None);
        assert_eq!(exit_first.observe_output_eof(now), None);
        assert_eq!(only_exit.observe_exit(99, now), None);
        assert_eq!(only_eof.observe_output_eof(now), None);
    }

    #[test]
    fn selected_connection_close_drains_terminal_protocol_before_failing() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let other = Keypair::generate_ed25519().public().to_peer_id();
        let selected = ConnectionId::new_unchecked(17);
        assert_eq!(
            active_terminal_connection_event(
                &EndpointEvent::Established {
                    peer,
                    connection: ConnectionId::new_unchecked(18),
                    endpoint: ConnectedPoint::Listener {
                        local_addr: "/memory/1".parse().unwrap(),
                        send_back_addr: "/memory/2".parse().unwrap(),
                    },
                },
                peer,
                selected,
            ),
            ActiveTerminalConnectionEvent::EnforceBinding
        );
        assert_eq!(
            active_terminal_connection_event(
                &EndpointEvent::Closed {
                    peer,
                    connection: selected,
                },
                peer,
                selected,
            ),
            ActiveTerminalConnectionEvent::DrainSelectedStreams
        );
        assert_eq!(
            active_terminal_connection_event(
                &EndpointEvent::Closed {
                    peer,
                    connection: ConnectionId::new_unchecked(18),
                },
                peer,
                selected,
            ),
            ActiveTerminalConnectionEvent::EnforceBinding
        );
        assert_eq!(
            active_terminal_connection_event(
                &EndpointEvent::Closed {
                    peer: other,
                    connection: selected,
                },
                peer,
                selected,
            ),
            ActiveTerminalConnectionEvent::Ignore
        );
        assert_eq!(
            active_terminal_connection_event(
                &EndpointEvent::Established {
                    peer: other,
                    connection: selected,
                    endpoint: ConnectedPoint::Listener {
                        local_addr: "/memory/1".parse().unwrap(),
                        send_back_addr: "/memory/2".parse().unwrap(),
                    },
                },
                peer,
                selected,
            ),
            ActiveTerminalConnectionEvent::Ignore
        );
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

    async fn write_prepared(
        terminal_output: &mut RemoteTerminalOutput,
        output: &mut (impl tokio::io::AsyncWrite + Unpin),
        raw: &[u8],
    ) {
        let display = terminal_output.prepare(raw);
        terminal_output.write(output, &display).await.unwrap();
    }

    async fn render_remote_output(mode: RemoteTerminalOutputMode, chunks: &[&[u8]]) -> Vec<u8> {
        let (mut output, mut captured) = tokio::io::duplex(128);
        let writer = async {
            let mut terminal_output = RemoteTerminalOutput::new(mode);
            for chunk in chunks {
                write_prepared(&mut terminal_output, &mut output, chunk).await;
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
        fail_on_write: Option<usize>,
        fail_flush: bool,
    }

    impl CountingWriter {
        fn failing_first_write() -> Self {
            Self {
                fail_on_write: Some(1),
                ..Self::default()
            }
        }

        fn failing_flush() -> Self {
            Self {
                fail_flush: true,
                ..Self::default()
            }
        }
    }

    impl AsyncWrite for CountingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            self.writes += 1;
            if self.fail_on_write == Some(self.writes) {
                return Poll::Ready(Err(io::Error::other("injected write failure")));
            }
            self.bytes.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            if self.fail_flush {
                Poll::Ready(Err(io::Error::other("injected flush failure")))
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    fn assert_injected_io(error: io::Error) {
        assert_eq!(error.kind(), io::ErrorKind::Other);
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
        let display = terminal_output.prepare(&invalid);
        terminal_output.write(&mut output, &display).await.unwrap();
        terminal_output.finish(&mut output).await.unwrap();
        assert_eq!(output.bytes, String::from_utf8_lossy(&invalid).as_bytes());
        assert!(output.writes <= 16, "write count: {}", output.writes);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn utf8_output_batch_propagates_every_write_failure() {
        let oversized = vec![b'a'; UTF8_OUTPUT_BATCH_CAPACITY + 1];

        let mut output = CountingWriter::failing_first_write();
        let mut batch = Utf8OutputBatch::new();
        assert_injected_io(batch.append(&mut output, &oversized).await.unwrap_err());

        let mut output = CountingWriter::failing_first_write();
        let mut batch = Utf8OutputBatch::new();
        batch.append(&mut output, b"buffered").await.unwrap();
        assert_injected_io(batch.append(&mut output, &oversized).await.unwrap_err());

        let mut output = CountingWriter::failing_first_write();
        let mut batch = Utf8OutputBatch::new();
        let full = vec![b'a'; UTF8_OUTPUT_BATCH_CAPACITY];
        batch.append(&mut output, &full).await.unwrap();
        assert_injected_io(batch.append(&mut output, b"overflow").await.unwrap_err());

        let mut output = CountingWriter::failing_first_write();
        let mut batch = Utf8OutputBatch::new();
        batch.append(&mut output, b"buffered").await.unwrap();
        assert_injected_io(batch.flush(&mut output).await.unwrap_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn remote_output_adapter_propagates_write_and_flush_failures() {
        let mut output = CountingWriter::failing_first_write();
        let mut bytes = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        let display = bytes.prepare(b"bytes");
        assert_injected_io(bytes.write(&mut output, &display).await.unwrap_err());

        let mut output = CountingWriter::failing_first_write();
        let mut terminal_output =
            RemoteTerminalOutput::new(RemoteTerminalOutputMode::WindowsConsoleUtf8);
        let oversized = vec![b'a'; UTF8_OUTPUT_BATCH_CAPACITY + 1];
        let display = terminal_output.prepare(&oversized);
        assert_injected_io(
            terminal_output
                .write(&mut output, &display)
                .await
                .unwrap_err(),
        );

        let mut output = CountingWriter::failing_first_write();
        let mut terminal_output =
            RemoteTerminalOutput::new(RemoteTerminalOutputMode::WindowsConsoleUtf8);
        let mut valid_then_invalid = vec![b'a'; UTF8_OUTPUT_BATCH_CAPACITY + 1];
        valid_then_invalid.push(0xff);
        let display = terminal_output.prepare(&valid_then_invalid);
        assert_injected_io(
            terminal_output
                .write(&mut output, &display)
                .await
                .unwrap_err(),
        );

        let mut output = CountingWriter::failing_first_write();
        let mut terminal_output =
            RemoteTerminalOutput::new(RemoteTerminalOutputMode::WindowsConsoleUtf8);
        let invalid = vec![0xff; UTF8_OUTPUT_BATCH_CAPACITY];
        let display = terminal_output.prepare(&invalid);
        assert_injected_io(
            terminal_output
                .write(&mut output, &display)
                .await
                .unwrap_err(),
        );

        let mut output = CountingWriter::failing_first_write();
        let mut terminal_output =
            RemoteTerminalOutput::new(RemoteTerminalOutputMode::WindowsConsoleUtf8);
        let display = terminal_output.prepare(b"\xf0");
        terminal_output.write(&mut output, &display).await.unwrap();
        assert_injected_io(terminal_output.finish(&mut output).await.unwrap_err());

        let mut output = CountingWriter::failing_flush();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        assert_injected_io(terminal_output.finish(&mut output).await.unwrap_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn remote_output_adapter_handles_every_streaming_utf8_boundary() {
        let mut output = CountingWriter::default();
        let mut bytes = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        write_prepared(&mut bytes, &mut output, b"\xff").await;
        bytes.finish(&mut output).await.unwrap();
        assert_eq!(output.bytes, b"\xff");

        let mut output = CountingWriter::default();
        let mut terminal_output =
            RemoteTerminalOutput::new(RemoteTerminalOutputMode::WindowsConsoleUtf8);
        write_prepared(&mut terminal_output, &mut output, b"valid").await;
        write_prepared(&mut terminal_output, &mut output, b"\xe4").await;
        write_prepared(&mut terminal_output, &mut output, b"").await;
        write_prepared(&mut terminal_output, &mut output, b"\xb8").await;
        write_prepared(&mut terminal_output, &mut output, b"\xad").await;
        write_prepared(&mut terminal_output, &mut output, b"\xe4").await;
        write_prepared(&mut terminal_output, &mut output, b"A").await;
        write_prepared(&mut terminal_output, &mut output, b"ok\xff\xf0\x90").await;
        terminal_output.finish(&mut output).await.unwrap();

        assert_eq!(
            output.bytes,
            "valid\u{4e2d}\u{fffd}Aok\u{fffd}\u{fffd}".as_bytes()
        );
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
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        // Non-interactive input: the pump is fully transparent (§6.4).
        let mut session_ui = TransferUi::new(false, false, false);
        let input_pump = async {
            loop {
                match process_local_input_chunk(
                    &mut local_input,
                    &mut controller_write,
                    &mut session_ui.control,
                    &mut session_ui.pending_input,
                    None,
                )
                .await
                {
                    Ok(LocalInputSignal::ChunkPending) => {
                        let _ = session_ui.pending_input.take();
                    }
                    Ok(LocalInputSignal::Eof) => {
                        controller_write.shutdown().await.unwrap();
                        break;
                    }
                    Err(error) => panic!("input pump failed: {error}"),
                }
            }
        };
        let output_pump = copy_remote_output(
            &mut controller_read,
            &mut local_output,
            &mut terminal_output,
            &mut session_ui.delayed,
            &mut session_ui.delayed_overflow,
            &session_ui.flow,
            None,
        );
        let peer_exchange = async {
            peer_write.write_all(&remote_payload).await.unwrap();
            peer_write.shutdown().await.unwrap();
            let mut received = vec![0; local_payload.len()];
            peer_read.read_exact(&mut received).await.unwrap();
            received
        };

        let completed = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::pin!(input_pump);
            tokio::pin!(output_pump);
            tokio::pin!(peer_exchange);
            let mut input_complete = false;
            let mut output_complete = false;
            let mut received = None;
            loop {
                tokio::select! {
                    _ = &mut input_pump, if !input_complete => {
                        input_complete = true;
                    }
                    result = &mut output_pump, if !output_complete => {
                        result.unwrap();
                        output_complete = true;
                    }
                    result = &mut peer_exchange, if received.is_none() => {
                        received = Some(result);
                    }
                }
                if input_complete
                    && output_complete
                    && let Some(received) = received.take()
                {
                    break received;
                }
            }
        })
        .await
        .expect("both bounded terminal directions must continue making progress");

        assert_eq!(completed, local_payload);
        assert_eq!(local_output, remote_payload);
    }

    async fn establish_audit_pair() -> (
        Arc<AuditObserver>,
        Arc<AuditObserver>,
        tempfile::TempDir,
        tempfile::TempDir,
    ) {
        let controller = Keypair::generate_ed25519().public().to_peer_id();
        let host = Keypair::generate_ed25519().public().to_peer_id();
        let (host_half, controller_half) = tokio::io::duplex(256 * 1024);
        let digest = Digest32::new([0xCE; 32]);
        let controller_dir = tempdir().unwrap();
        let host_dir = tempdir().unwrap();
        let controller_root = controller_dir.path().join("audit");
        let host_root = host_dir.path().join("audit");
        let mut controller_random = OsSecureRandom;
        let mut host_random = OsSecureRandom;
        let (controller_result, host_result) = tokio::join!(
            Box::pin(AuditObserver::establish(
                controller_half,
                AuditRole::Controller,
                controller,
                host,
                crate::audit::observer::utc_start_seconds(),
                digest,
                &controller_root,
                &mut controller_random,
            )),
            Box::pin(AuditObserver::establish(
                host_half,
                AuditRole::Host,
                controller,
                host,
                crate::audit::observer::utc_start_seconds(),
                digest,
                &host_root,
                &mut host_random,
            )),
        );
        (
            Arc::new(controller_result.unwrap()),
            Arc::new(host_result.unwrap()),
            controller_dir,
            host_dir,
        )
    }

    #[test]
    fn audit_failure_stops_further_remote_output_from_reaching_the_display() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let (controller_audit, _host_audit, _controller_dir, _host_dir) =
                        establish_audit_pair().await;
                    let pump_audit = Arc::clone(&controller_audit);
                    let (host_half, controller_half) = tokio::io::duplex(64 * 1024);
                    let (mut controller_read, _controller_write) =
                        tokio::io::split(controller_half);
                    let (_peer_read, mut peer_write) = tokio::io::split(host_half);
                    let (mut output_write, mut output_read) = tokio::io::duplex(64 * 1024);

                    let pump = tokio::task::spawn(async move {
                        copy_remote_output(
                            &mut controller_read,
                            &mut output_write,
                            &mut RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes),
                            &mut DelayedOutputBuffer::new(DELAYED_OUTPUT_CAP),
                            &mut false,
                            &None,
                            Some(&pump_audit),
                        )
                        .await
                    });

                    let first = b"remote-output-first";
                    peer_write.write_all(first).await.unwrap();
                    let mut shown = vec![0_u8; first.len()];
                    output_read.read_exact(&mut shown).await.unwrap();
                    assert_eq!(shown, first);

                    controller_audit
                        .fail_closed(None, AuditCloseReason::AuditFailure)
                        .await;
                    assert!(controller_audit.has_failed().await);

                    peer_write.write_all(b"remote-output-second").await.unwrap();
                    let result = tokio::time::timeout(Duration::from_secs(10), pump)
                        .await
                        .expect("the output pump must stop after audit failure")
                        .expect("the output pump must not panic");
                    assert!(matches!(result, Err(ControllerError::Audit(_))));
                    let mut trailing = Vec::new();
                    output_read.read_to_end(&mut trailing).await.unwrap();
                    assert!(trailing.is_empty());
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }

    fn local_chunk(bytes: &[u8]) -> LocalInputChunk {
        let mut chunk = LocalInputChunk::new();
        chunk.writable()[..bytes.len()].copy_from_slice(bytes);
        chunk.set_len(bytes.len()).unwrap();
        chunk
    }

    fn flow_line(session_ui: &TransferUi) -> String {
        session_ui
            .flow
            .as_ref()
            .expect("an active prompt")
            .current_line()
            .to_owned()
    }

    #[test]
    fn interactive_detach_escape_is_chunk_boundary_independent() {
        let mut machine = LocalControlInput::new(true, false);
        let first = machine.process(local_chunk(b"typed\x1d"));
        assert_eq!(first.remote_bytes.as_slice(), b"typed");
        assert_eq!(first.action, LocalAction::None);
        assert!(machine.pending_prefix());

        let second = machine.process(local_chunk(b"."));
        assert_eq!(second.action, LocalAction::Detach);
        assert!(second.remote_bytes.is_empty());
        assert!(machine.ended());
    }

    #[test]
    fn interactive_escape_preserves_literal_and_non_command_sequences() {
        let mut machine = LocalControlInput::new(true, false);
        let terminal_escape = machine.process(local_chunk(b"\x1b"));
        assert_eq!(terminal_escape.remote_bytes.as_slice(), b"\x1b");
        assert_eq!(terminal_escape.action, LocalAction::None);

        let literal = machine.process(local_chunk(b"\x1d\x1d"));
        assert_eq!(literal.remote_bytes.as_slice(), b"\x1d");
        assert_eq!(literal.action, LocalAction::None);

        let ordinary = machine.process(local_chunk(b"\x1dx"));
        assert_eq!(ordinary.remote_bytes.as_slice(), b"\x1dx");
        assert_eq!(ordinary.action, LocalAction::None);

        let before_detach = machine.process(local_chunk(b"abc\x1d.trailing bytes"));
        assert_eq!(before_detach.remote_bytes.as_slice(), b"abc");
        assert_eq!(before_detach.action, LocalAction::Detach);
    }

    #[test]
    fn isolated_escape_is_forwarded_when_local_input_reaches_eof() {
        let mut machine = LocalControlInput::new(true, false);
        let pending = machine.process(local_chunk(b"\x1d"));
        assert!(pending.remote_bytes.is_empty());
        assert!(!pending.remote_bytes.is_empty() || machine.pending_prefix());
        assert!(machine.pending_prefix());
        let eof = machine.finish();
        assert_eq!(eof.remote_bytes.as_slice(), b"\x1d");
        assert_eq!(eof.action, LocalAction::None);
        assert!(machine.finish().remote_bytes.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pending_escape_reserve_keeps_processing_within_fixed_chunks() {
        let mut machine = LocalControlInput::new(true, false);
        let _ = machine.process(local_chunk(b"\x1d"));
        assert!(machine.pending_prefix());
        // A full-capacity read reserves one byte for the pending selector.
        let input = vec![b'x'; 16 * 1024];
        let mut consumed = input.as_slice();
        let mut controller_write = tokio::io::sink();
        let mut pending_input = None;
        let signal = process_local_input_chunk(
            &mut consumed,
            &mut controller_write,
            &mut machine,
            &mut pending_input,
            None,
        )
        .await
        .unwrap();
        assert_eq!(signal, LocalInputSignal::ChunkPending);
        let processed = pending_input.take().expect("one chunk");
        // The pending prefix resolves inside the chunk; the rest forwards,
        // and the output stays within the fixed remote capacity (§15.1).
        assert_eq!(processed.remote_bytes.as_slice()[0], b'\x1d');
        assert_eq!(processed.remote_bytes.as_slice()[1], b'x');
        assert_eq!(processed.remote_bytes.len(), 4096);
        assert_eq!(consumed.len(), 16 * 1024 - 4095);
        assert!(!machine.pending_prefix());
    }

    #[test]
    fn non_interactive_input_remains_byte_transparent() {
        let mut machine = LocalControlInput::new(false, false);
        let bytes = *b"a\x1d.\x1d\x1d";
        let processed = machine.process(local_chunk(&bytes));
        assert_eq!(processed.remote_bytes.as_slice(), bytes);
        assert_eq!(processed.action, LocalAction::None);
        assert!(!machine.pending_prefix());
        assert!(machine.finish().remote_bytes.is_empty());
    }

    fn assert_native_input_adapter_uses_byte_escape_semantics() {
        let mut machine = LocalControlInput::new(true, false);
        let processed = machine.process(local_chunk(b"\x1d\x1d"));
        assert_eq!(processed.remote_bytes.as_slice(), b"\x1d");
        assert_eq!(processed.action, LocalAction::None);
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

    // ---- 0.2.0 native file transfer: capability, prompts, transfers ----

    struct TrackedProbeStream(Rc<Cell<bool>>);

    impl Drop for TrackedProbeStream {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn capability_probe_closes_a_successful_stream_without_a_message() {
        let dropped = Rc::new(Cell::new(false));
        let probe_stream = dropped.clone();
        let result = probe_file_transfer_capability(async move {
            Ok::<_, ControllerError>(TrackedProbeStream(probe_stream))
        })
        .await;
        assert_eq!(result.unwrap(), CapabilityCache::Supported);
        assert!(
            dropped.get(),
            "the probe substream closes without a message"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn capability_probe_caches_only_explicit_unsupported() {
        let unsupported = ControllerError::Endpoint(EndpointError::Application(
            ApplicationStreamError::UnsupportedProtocol,
        ));
        let result =
            probe_file_transfer_capability::<TrackedProbeStream>(async { Err(unsupported) }).await;
        assert_eq!(result.unwrap(), CapabilityCache::Unsupported);

        // Timeouts, connection errors and transient I/O failures are never
        // cached: the error propagates and the user may retry (§9.3).
        let transient = ControllerError::Io(io::Error::other("transient"));
        let result =
            probe_file_transfer_capability::<TrackedProbeStream>(async { Err(transient) }).await;
        assert!(matches!(result, Err(ControllerError::Io(_))));
    }

    #[test]
    fn file_transfer_readiness_covers_availability_and_the_three_state_cache() {
        let base = BaseDirectory::capture().unwrap();
        let mut ui = TransferUi::new(true, true, true);
        assert_eq!(
            file_transfer_ready(&ui, Some(&base)),
            Err(TransferNotReady::Probe)
        );
        ui.capability = CapabilityCache::Supported;
        assert_eq!(
            file_transfer_ready(&ui, Some(&base)),
            Ok(CapabilityCache::Supported)
        );
        ui.capability = CapabilityCache::Unsupported;
        assert_eq!(
            file_transfer_ready(&ui, Some(&base)),
            Err(TransferNotReady::Unsupported)
        );

        let no_terminal = TransferUi::new(true, true, false);
        assert_eq!(
            file_transfer_ready(&no_terminal, Some(&base)),
            Err(TransferNotReady::Unavailable)
        );
        let no_base = TransferUi::new(true, true, true);
        assert_eq!(
            file_transfer_ready(&no_base, None),
            Err(TransferNotReady::Unavailable)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn file_transfer_modal_preflight_preserves_ui_and_substream_boundaries() {
        let _permit = crate::IN_PROCESS_NETWORK_GUARD.acquire().await;
        let (mut driver, mut streams) = build_endpoint(
            Keypair::generate_ed25519(),
            WssTransportConfig::client(None),
        )
        .unwrap();
        let binding =
            ConnectionBinding::for_test(driver.peer_id(), ConnectionId::new_unchecked(0xF11E));
        let cancellation = tokio_util::sync::CancellationToken::new();
        let base = Some(BaseDirectory::capture().unwrap());

        let mut unavailable = TransferUi::new(true, true, true);
        let _ = unavailable.control.process(local_chunk(b"\x1du"));
        let mut output = CountingWriter::default();
        begin_file_transfer_modal(
            TransferDirection::Upload,
            &mut driver,
            &mut streams,
            binding,
            &mut output,
            &mut unavailable,
            &None,
            &cancellation,
        )
        .await
        .unwrap();
        assert!(
            output
                .bytes
                .windows(FILE_TRANSFER_UNAVAILABLE.len())
                .any(|window| window == FILE_TRANSFER_UNAVAILABLE.as_bytes())
        );
        assert_eq!(unavailable.control.modal_phase(), None);

        let mut unsupported = TransferUi::new(true, true, true);
        let _ = unsupported.control.process(local_chunk(b"\x1dd"));
        unsupported.capability = CapabilityCache::Unsupported;
        output.bytes.clear();
        begin_file_transfer_modal(
            TransferDirection::Download,
            &mut driver,
            &mut streams,
            binding,
            &mut output,
            &mut unsupported,
            &base,
            &cancellation,
        )
        .await
        .unwrap();
        assert!(
            output
                .bytes
                .windows(FILE_TRANSFER_UNSUPPORTED.len())
                .any(|window| window == FILE_TRANSFER_UNSUPPORTED.as_bytes())
        );
        assert_eq!(unsupported.control.modal_phase(), None);

        let mut supported = TransferUi::new(true, true, true);
        let _ = supported.control.process(local_chunk(b"\x1du"));
        supported.capability = CapabilityCache::Supported;
        output.bytes.clear();
        begin_file_transfer_modal(
            TransferDirection::Upload,
            &mut driver,
            &mut streams,
            binding,
            &mut output,
            &mut supported,
            &base,
            &cancellation,
        )
        .await
        .unwrap();
        assert_eq!(supported.direction, Some(TransferDirection::Upload));
        assert!(supported.flow.is_some());
        assert!(
            output
                .bytes
                .windows(PROMPT_BANNER_UPLOAD.len())
                .any(|window| window == PROMPT_BANNER_UPLOAD.as_bytes())
        );

        let mut disappeared = TransferUi::new(true, true, true);
        let _ = disappeared.control.process(local_chunk(b"\x1du"));
        output.bytes.clear();
        let missing_base = None;
        let cancel = AtomicBool::new(false);
        let mut transfer: Option<Pin<Box<dyn Future<Output = TransferOutcome>>>> = None;
        begin_transfer(
            TransferDirection::Upload,
            "source.bin".to_owned(),
            None,
            &mut driver,
            &mut streams,
            binding,
            &mut output,
            &mut disappeared,
            &cancellation,
            &missing_base,
            &cancel,
            &mut transfer,
            None,
        )
        .await
        .unwrap();
        assert!(transfer.is_none());
        assert_eq!(disappeared.control.modal_phase(), None);
        assert!(
            output
                .bytes
                .windows(FILE_TRANSFER_UNAVAILABLE.len())
                .any(|window| window == FILE_TRANSFER_UNAVAILABLE.as_bytes())
        );
    }

    #[test]
    fn prompt_flow_uses_the_selector_remainder_as_initial_input() {
        let mut flow = PathPromptFlow::new(TransferDirection::Upload);
        let mut machine = LocalControlInput::new(true, false);
        let processed = machine.process(local_chunk(b"\x1dusrc/file"));
        assert_eq!(processed.action, LocalAction::StartUpload);
        assert_eq!(processed.remainder.as_slice(), b"src/file");
        match flow.feed(&processed) {
            PromptProgress::Active { bell: false } => {}
            other => panic!("expected Active, got {other:?}"),
        }
        assert_eq!(flow.current_line(), "src/file");
        // The rest of the line completes and submits the required field.
        let processed = machine.process(local_chunk(b".txt\r\n"));
        match flow.feed(&processed) {
            PromptProgress::NextField => {}
            other => panic!("expected NextField, got {other:?}"),
        }
        assert_eq!(
            flow.label(),
            "remote destination [remote session start directory]:"
        );
    }

    #[test]
    fn prompt_flow_feeds_path_bytes_when_the_selector_chunk_carries_no_remainder() {
        // Interactive typing delivers the selector and the path in separate
        // read chunks: the selector chunk has an empty remainder and the
        // path arrives later as modal path_bytes. The first feed must not
        // consume the initial flag on the empty remainder alone, or the
        // first path chunk would be silently dropped.
        let mut flow = PathPromptFlow::new(TransferDirection::Upload);
        let mut machine = LocalControlInput::new(true, false);
        let started = machine.process(local_chunk(b"\x1du"));
        assert_eq!(started.action, LocalAction::StartUpload);
        assert!(started.remainder.is_empty());
        match flow.feed(&started) {
            PromptProgress::Active { bell: false } => {}
            other => panic!("expected Active, got {other:?}"),
        }
        let processed = machine.process(local_chunk(b"payload.bin\r"));
        assert!(processed.remainder.is_empty());
        // The modal machine routes editor bytes too; the prompt submits on
        // the trailing carriage return.
        assert_eq!(processed.path_bytes.as_slice(), b"payload.bin\r");
        match flow.feed(&processed) {
            PromptProgress::NextField => {}
            other => panic!("expected NextField, got {other:?}"),
        }
        assert_eq!(
            flow.label(),
            "remote destination [remote session start directory]:"
        );
    }

    #[test]
    fn prompt_flow_collects_upload_source_and_defaultable_destination() {
        let mut flow = PathPromptFlow::new(TransferDirection::Upload);
        assert_eq!(flow.label(), "local source:");
        let mut machine = LocalControlInput::new(true, false);
        let started = machine.process(local_chunk(b"\x1du"));
        assert!(matches!(
            flow.feed(&started),
            PromptProgress::Active { bell: false }
        ));
        let processed = machine.process(local_chunk(b"src"));
        assert!(matches!(
            flow.feed(&processed),
            PromptProgress::Active { bell: false }
        ));
        let processed = machine.process(local_chunk(b"\n"));
        assert!(matches!(flow.feed(&processed), PromptProgress::NextField));
        let processed = machine.process(local_chunk(b"\r\n"));
        assert_eq!(
            flow.feed(&processed),
            PromptProgress::Completed {
                first: "src".to_owned(),
                second: None,
            }
        );
    }

    #[test]
    fn prompt_flow_collects_download_source_and_local_destination() {
        let mut flow = PathPromptFlow::new(TransferDirection::Download);
        assert_eq!(flow.label(), "remote source:");
        let mut machine = LocalControlInput::new(true, false);
        let started = machine.process(local_chunk(b"\x1dd"));
        assert!(matches!(
            flow.feed(&started),
            PromptProgress::Active { bell: false }
        ));
        let processed = machine.process(local_chunk(b"/remote/file\n"));
        assert!(matches!(flow.feed(&processed), PromptProgress::NextField));
        assert_eq!(
            flow.label(),
            "local destination [local connect start directory]:"
        );
        let processed = machine.process(local_chunk(b"dest\r\n"));
        assert_eq!(
            flow.feed(&processed),
            PromptProgress::Completed {
                first: "/remote/file".to_owned(),
                second: Some("dest".to_owned()),
            }
        );
    }

    #[test]
    fn prompt_flow_rejects_empty_required_fields_and_reprompts() {
        let mut flow = PathPromptFlow::new(TransferDirection::Upload);
        let mut machine = LocalControlInput::new(true, false);
        let started = machine.process(local_chunk(b"\x1du"));
        flow.feed(&started);
        let processed = machine.process(local_chunk(b"\n"));
        assert_eq!(flow.feed(&processed), PromptProgress::Reprompt);
        assert_eq!(flow.current_line(), "");
        let processed = machine.process(local_chunk(b"ok\r\n"));
        assert!(matches!(flow.feed(&processed), PromptProgress::NextField));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn prompt_echo_renders_additions_and_backspace_erasure() {
        let mut machine = LocalControlInput::new(true, false);
        let started = machine.process(local_chunk(b"\x1du"));
        let mut flow = PathPromptFlow::new(TransferDirection::Upload);
        let mut output = CountingWriter::default();
        flow.feed(&started);
        let processed = machine.process(local_chunk(b"abc"));
        assert!(matches!(
            flow.feed(&processed),
            PromptProgress::Active { bell: false }
        ));
        flow.echo_delta(&mut output).await.unwrap();
        assert_eq!(output.bytes, b"abc");
        let processed = machine.process(local_chunk(b"\x08"));
        flow.feed(&processed);
        flow.echo_delta(&mut output).await.unwrap();
        assert_eq!(output.bytes, b"abc\x08 \x08");
        let processed = machine.process(local_chunk(b"d"));
        flow.feed(&processed);
        flow.echo_delta(&mut output).await.unwrap();
        assert_eq!(output.bytes, b"abc\x08 \x08d");
        assert_eq!(flow.current_line(), "abd");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn prompt_ctrl_c_cancels_without_opening_a_substream() {
        let mut session_ui = TransferUi::new(true, true, true);
        let started = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        assert!(matches!(
            session_ui.flow.as_mut().unwrap().feed(&started),
            PromptProgress::Active { bell: false }
        ));
        assert_eq!(
            session_ui.delayed.append(b"remote bytes"),
            AppendOutcome::Ok
        );
        let processed = session_ui.control.process(local_chunk(b"abc\x03"));
        assert_eq!(processed.action, LocalAction::CancelOp);
        assert_eq!(processed.path_bytes.as_slice(), b"abc");
        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        let cancel = AtomicBool::new(false);
        let handling = handle_processed_input(
            processed,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(handling, LocalInputHandling::Done);
        assert!(session_ui.flow.is_none());
        assert_eq!(session_ui.control.modal_phase(), None);
        assert!(!cancel.load(Ordering::Relaxed));
        // §16.1: nothing is sent to the remote; the typed line stays on
        // the display and the delayed output is flushed in order once the
        // prompt is gone.
        assert_eq!(output.bytes, b"abc\r\nremote bytes");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delayed_overflow_aborts_the_prompt_and_flushes_in_order() {
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        assert_eq!(session_ui.delayed.append(b"first"), AppendOutcome::Ok);
        assert_eq!(session_ui.delayed.append(b"second"), AppendOutcome::Ok);
        session_ui.delayed_overflow = true;
        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        abort_prompt_for_overflow(&mut session_ui, &mut output, &mut terminal_output, None)
            .await
            .unwrap();
        assert!(session_ui.flow.is_none());
        assert_eq!(session_ui.control.modal_phase(), None);
        assert!(session_ui.delayed.is_empty());
        assert_eq!(output.bytes, b"firstsecond");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transfer_cancellation_writes_one_summary_and_restores_the_terminal() {
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.control.enter_transfer().unwrap();
        session_ui.direction = Some(TransferDirection::Upload);
        let cancel = AtomicBool::new(false);
        let mut transfer: Option<Pin<Box<dyn Future<Output = TransferOutcome>>>> =
            Some(Box::pin(async { TransferOutcome::Cancelled }));
        let mut output = CountingWriter::default();
        let completion = handle_transfer_event(
            TransferOutcome::Cancelled,
            &mut output,
            &mut session_ui,
            &cancel,
            &mut transfer,
        )
        .await
        .unwrap();
        assert_eq!(completion, None);
        assert!(transfer.is_none());
        assert_eq!(session_ui.control.modal_phase(), None);
        assert!(!cancel.load(Ordering::Relaxed));
        assert_eq!(output.bytes, b"\r\nupload cancelled");
    }

    #[test]
    fn transfer_summaries_cover_success_cancellation_and_failure() {
        assert_eq!(
            transfer_summary_line(
                TransferDirection::Upload,
                TransferOutcome::Committed { bytes: 42 }
            ),
            "upload complete: 42 bytes"
        );
        assert_eq!(
            transfer_summary_line(TransferDirection::Download, TransferOutcome::Cancelled),
            "download cancelled"
        );
        assert_eq!(
            transfer_summary_line(
                TransferDirection::Upload,
                TransferOutcome::Failed(FileTransferErrorCode::SourceNotFound)
            ),
            "upload failed: SourceNotFound"
        );
    }

    #[test]
    fn fixed_local_ui_texts_cover_the_frozen_interaction() {
        assert_eq!(FILE_TRANSFER_ALREADY_ACTIVE, "file transfer already active");
        for shortcut in [
            "Ctrl+] .",
            "Ctrl+] Ctrl+]",
            "Ctrl+] u",
            "Ctrl+] d",
            "Ctrl+] ?",
        ] {
            assert!(LOCAL_CONTROL_HELP.contains(shortcut), "missing {shortcut}");
        }
        assert!(LOCAL_CONTROL_HELP.contains("end the session"));
        assert!(LOCAL_CONTROL_HELP.contains("upload a file"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn second_operation_while_modal_reports_already_active() {
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        let processed = session_ui.control.process(local_chunk(b"\x1du"));
        assert_eq!(processed.action, LocalAction::AlreadyActive);
        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        let cancel = AtomicBool::new(false);
        let handling = handle_processed_input(
            processed,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(handling, LocalInputHandling::Done);
        assert_eq!(output.bytes, b"\r\nfile transfer already active");
        // The active operation keeps its phase (§15.3).
        assert_eq!(
            session_ui.control.modal_phase(),
            Some(ModalPhase::UploadPrompt)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pass_through_help_is_local_ui_only() {
        let mut session_ui = TransferUi::new(true, true, true);
        let processed = session_ui.control.process(local_chunk(b"\x1d?xy"));
        assert_eq!(processed.action, LocalAction::ShowHelp);
        assert_eq!(processed.remote_bytes.as_slice(), b"xy");
        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        let cancel = AtomicBool::new(false);
        let handling = handle_processed_input(
            processed,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(handling, LocalInputHandling::Done);
        let text = String::from_utf8_lossy(&output.bytes);
        assert!(text.contains("Ctrl+] u"));
        assert_eq!(session_ui.control.modal_phase(), None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pass_through_u_signals_the_modal_start_without_writing_ui() {
        let mut session_ui = TransferUi::new(true, true, true);
        let processed = session_ui.control.process(local_chunk(b"\x1du"));
        assert_eq!(processed.action, LocalAction::StartUpload);
        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        let cancel = AtomicBool::new(false);
        let handling = handle_processed_input(
            processed,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            handling,
            LocalInputHandling::StartModal(TransferDirection::Upload)
        );
        assert!(output.bytes.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pass_through_detach_ends_the_session() {
        let mut session_ui = TransferUi::new(true, true, true);
        let processed = session_ui.control.process(local_chunk(b"abc\x1d."));
        assert_eq!(processed.action, LocalAction::Detach);
        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        let cancel = AtomicBool::new(false);
        assert!(matches!(
            handle_processed_input(
                processed,
                &mut output,
                &mut terminal_output,
                &mut session_ui,
                &cancel,
                None,
            )
            .await,
            Err(ControllerError::Interrupted)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn non_interactive_chunks_are_forwarded_byte_transparent() {
        let mut session_ui = TransferUi::new(false, false, false);
        let bytes = [
            b'a', b'\x1d', b'u', b'b', b'\x1d', b'.', b'\x1d', b'\x1d', 0x03,
        ];
        let mut input = bytes.as_slice();
        let (mut controller_write, mut peer_read) = tokio::io::duplex(16);
        let signal = process_local_input_chunk(
            &mut input,
            &mut controller_write,
            &mut session_ui.control,
            &mut session_ui.pending_input,
            None,
        )
        .await
        .unwrap();
        assert_eq!(signal, LocalInputSignal::ChunkPending);
        let processed = session_ui.pending_input.take().expect("one chunk");
        assert_eq!(processed.remote_bytes.as_slice(), bytes);
        assert_eq!(processed.action, LocalAction::None);
        let mut received = [0_u8; 9];
        peer_read.read_exact(&mut received).await.unwrap();
        assert_eq!(received, bytes);
        // EOF is reported to the pump loop without side effects.
        let mut eof_input = tokio::io::empty();
        assert_eq!(
            process_local_input_chunk(
                &mut eof_input,
                &mut controller_write,
                &mut session_ui.control,
                &mut session_ui.pending_input,
                None,
            )
            .await
            .unwrap(),
            LocalInputSignal::Eof
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn selector_at_a_chunk_boundary_keeps_the_remainder_in_bounds() {
        let mut session_ui = TransferUi::new(true, true, true);
        let mut block = b"ab\x1du".to_vec();
        block.extend(std::iter::repeat_n(b'x', 4096 - 4));
        assert_eq!(block.len(), 4096);
        let mut input = block.as_slice();
        let (mut controller_write, mut peer_read) = tokio::io::duplex(16);
        let signal = process_local_input_chunk(
            &mut input,
            &mut controller_write,
            &mut session_ui.control,
            &mut session_ui.pending_input,
            None,
        )
        .await
        .unwrap();
        assert_eq!(signal, LocalInputSignal::ChunkPending);
        let processed = session_ui.pending_input.take().expect("one chunk");
        assert_eq!(processed.action, LocalAction::StartUpload);
        assert_eq!(processed.remote_bytes.as_slice(), b"ab");
        assert_eq!(processed.remainder.len(), 4092);
        assert!(processed.drop_remainder);
        assert_eq!(
            session_ui.control.modal_phase(),
            Some(ModalPhase::UploadPrompt)
        );
        // Only the forwarded prefix reaches the remote (§17.3).
        let mut received = [0_u8; 2];
        peer_read.read_exact(&mut received).await.unwrap();
        assert_eq!(received, *b"ab");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn finish_local_input_eof_flushes_orphaned_escape_and_shuts_down() {
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"ab\x1d"));
        assert!(session_ui.control.pending_prefix());
        let (mut controller_write, mut peer_read) = tokio::io::duplex(16);
        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        finish_local_input_eof(
            &mut controller_write,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            None,
        )
        .await
        .unwrap();
        assert!(session_ui.local_ended);
        let mut received = Vec::new();
        peer_read.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"\x1d");
    }

    #[test]
    fn audited_local_input_flush_failures_record_failed_send_outcomes() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        let (controller_audit, host_audit, controller_dir, host_dir) =
                            establish_audit_pair().await;

                        let mut session_ui = TransferUi::new(true, true, true);
                        let mut input = &b"input"[..];
                        let mut data_write = CountingWriter::failing_flush();
                        assert!(matches!(
                            process_local_input_chunk(
                                &mut input,
                                &mut data_write,
                                &mut session_ui.control,
                                &mut session_ui.pending_input,
                                Some(&controller_audit),
                            )
                            .await,
                            Err(ControllerError::Io(_))
                        ));

                        let mut session_ui = TransferUi::new(true, true, true);
                        let _ = session_ui.control.process(local_chunk(b"\x1d"));
                        let mut data_write = CountingWriter::failing_flush();
                        let mut output = CountingWriter::default();
                        let mut terminal_output =
                            RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
                        assert!(matches!(
                            finish_local_input_eof(
                                &mut data_write,
                                &mut output,
                                &mut terminal_output,
                                &mut session_ui,
                                Some(&controller_audit),
                            )
                            .await,
                            Err(ControllerError::Io(_))
                        ));

                        controller_audit
                            .close_interrupted(AuditCloseReason::ConnectionLost)
                            .await;
                        drop(controller_audit);
                        drop(host_audit);

                        let record =
                            fs::read_dir(controller_dir.path().join("audit").join("records"))
                                .unwrap()
                                .next()
                                .unwrap()
                                .unwrap()
                                .path();
                        let mut failures = 0_u8;
                        stream_frames(&record, &mut |record_type, payload| {
                            let local = payload.get(40..).unwrap_or_default();
                            if record_type == RecordType::LocalSendOutcome
                                && local.get(1) == Some(&OUTCOME_FAILED)
                            {
                                failures += 1;
                            }
                            Ok(StreamAction::Continue)
                        })
                        .unwrap();
                        assert_eq!(failures, 2, "both flush failures must be recorded");
                        drop(host_dir);
                    });
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn local_input_eof_drops_an_active_prompt_and_flushes_delayed_output() {
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        assert_eq!(session_ui.delayed.append(b"tail"), AppendOutcome::Ok);
        let (mut controller_write, mut peer_read) = tokio::io::duplex(16);
        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        finish_local_input_eof(
            &mut controller_write,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            None,
        )
        .await
        .unwrap();
        assert!(session_ui.flow.is_none());
        assert_eq!(session_ui.control.modal_phase(), None);
        assert_eq!(output.bytes, b"tail");
        let mut received = Vec::new();
        peer_read.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty());
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
    async fn terminal_completion_ack_waits_for_host_control_close() {
        let (controller_control, host_control) = tokio::io::duplex(1);
        let (mut controller_read, mut controller_write) = tokio::io::split(controller_control);
        let (mut host_read, mut host_write) = tokio::io::split(host_control);
        let controller = complete_terminal_control_io(&mut controller_read, &mut controller_write);
        let host = async {
            let mut complete = [0_u8; 1];
            host_read.read_exact(&mut complete).await.unwrap();
            assert_eq!(TerminalComplete::decode(&complete), Ok(TerminalComplete));
            host_write.shutdown().await.unwrap();
        };

        let (result, ()) = tokio::join!(controller, host);
        result.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_completion_accepts_legacy_host_close_and_rejects_trailing_bytes() {
        let (controller_control, host_control) = tokio::io::duplex(1);
        let (mut controller_read, mut controller_write) = tokio::io::split(controller_control);
        drop(host_control);
        complete_terminal_control_io(&mut controller_read, &mut controller_write)
            .await
            .unwrap();

        let (controller_control, mut host_control) = tokio::io::duplex(1);
        let (mut controller_read, mut controller_write) = tokio::io::split(controller_control);
        host_control.write_all(&[0xff]).await.unwrap();
        assert!(matches!(
            complete_terminal_control_io(&mut controller_read, &mut controller_write).await,
            Err(ControllerError::Protocol(ProtocolError::TrailingBytes))
        ));
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

    struct RestoreFailingFrontend;

    impl TerminalFrontend for RestoreFailingFrontend {
        type Input = tokio::io::Empty;
        type Output = tokio::io::Sink;
        type RawModeGuard = ();

        fn is_interactive(&self) -> bool {
            true
        }

        fn output_is_terminal(&self) -> bool {
            true
        }

        fn size(&self) -> Result<(u16, u16), io::Error> {
            Ok((80, 24))
        }

        fn enter_raw_mode(&self) -> Result<Option<Self::RawModeGuard>, io::Error> {
            Ok(Some(()))
        }

        fn restore_raw_mode(&self, _guard: Option<Self::RawModeGuard>) -> Result<(), io::Error> {
            Err(io::Error::other("restore failed"))
        }

        fn input(&mut self) -> Self::Input {
            tokio::io::empty()
        }

        fn output(&mut self) -> Self::Output {
            tokio::io::sink()
        }
    }

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

    struct FailingDisplayOutput;

    impl io::Write for FailingDisplayOutput {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("flush failed"))
        }
    }

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

    // ---- enterprise controller UI ----

    fn test_ui() -> EnterpriseControllerUi<
        tokio::io::BufReader<tokio::io::DuplexStream>,
        tokio::io::DuplexStream,
    > {
        EnterpriseControllerUi {
            input: tokio::io::BufReader::new(tokio::io::duplex(16).0),
            output: tokio::io::duplex(256).1,
            opener: Box::new(|_| false),
        }
    }

    /// Reads whatever the UI writes, with a short window.
    async fn read_ui_output(mut output: tokio::io::DuplexStream) -> String {
        let mut text = Vec::new();
        for _ in 0..4 {
            let mut buffer = [0_u8; 256];
            match tokio::time::timeout(Duration::from_millis(200), output.read(&mut buffer)).await {
                Ok(Ok(0)) => break,
                Ok(Ok(read)) => text.extend_from_slice(&buffer[..read]),
                _ => break,
            }
        }
        String::from_utf8_lossy(&text).into_owned()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_ui_auto_picks_the_only_platform_without_prompting() {
        let mut ui = test_ui();
        let provider = ui
            .select_provider(EnterpriseProviders::new(true, false).unwrap())
            .await
            .unwrap();
        assert_eq!(provider, EnterpriseProvider::WeCom);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_ui_prompts_and_reads_the_platform_choice() {
        let (mut client_input, input) = tokio::io::duplex(16);
        let (client_output, output) = tokio::io::duplex(256);
        let mut ui = EnterpriseControllerUi {
            input: tokio::io::BufReader::new(input),
            output,
            opener: Box::new(|_| false),
        };
        let selection = ui.select_provider(EnterpriseProviders::new(true, true).unwrap());
        let (chosen, prompt) = tokio::join!(async { selection.await.unwrap() }, async {
            let prompt = read_ui_output(client_output).await;
            client_input.write_all(b"2\n").await.unwrap();
            prompt
        },);
        assert_eq!(chosen, EnterpriseProvider::Feishu);
        assert!(prompt.contains("企业微信 (WeCom)"));
        assert!(prompt.contains("飞书 (Feishu)"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_ui_rejects_an_invalid_platform_choice() {
        let (mut client_input, input) = tokio::io::duplex(16);
        let (client_output, output) = tokio::io::duplex(256);
        let mut ui = EnterpriseControllerUi {
            input: tokio::io::BufReader::new(input),
            output,
            opener: Box::new(|_| false),
        };
        let selection = ui.select_provider(EnterpriseProviders::new(true, true).unwrap());
        let (chosen, _) = tokio::join!(selection, async {
            let _ = read_ui_output(client_output).await;
            client_input.write_all(b"9\n").await.unwrap();
        },);
        assert!(matches!(
            chosen,
            Err(crate::protocol::RelayProtocolError::EnterpriseRejected)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_ui_prints_the_authorization_url_and_calls_the_opener() {
        let (input, _) = tokio::io::duplex(16);
        let (client_output, output) = tokio::io::duplex(512);
        let opened = std::sync::Arc::new(std::sync::Mutex::new(None));
        let opened_clone = std::sync::Arc::clone(&opened);
        let mut ui = EnterpriseControllerUi {
            input: tokio::io::BufReader::new(input),
            output,
            opener: Box::new(move |url| {
                *opened_clone.lock().unwrap() = Some(url.to_owned());
                false
            }),
        };
        let (result, printed) = tokio::join!(
            ui.open_authorization(
                "https://relay.example.test/yonder/callback/wecom?code=x&state=y"
            ),
            read_ui_output(client_output),
        );
        result.unwrap();
        assert!(
            printed.contains("https://relay.example.test/yonder/callback/wecom?code=x&state=y")
        );
        assert_eq!(
            opened.lock().unwrap().as_deref(),
            Some("https://relay.example.test/yonder/callback/wecom?code=x&state=y")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_ui_new_and_default_pick_the_only_platform_without_prompting() {
        // Both constructors wrap the terminal; a single configured platform
        // is chosen without any terminal I/O.
        let providers = EnterpriseProviders::new(true, false).unwrap();
        let picked = {
            let mut from_new = EnterpriseControllerUi::new();
            let mut from_default = EnterpriseControllerUi::default();
            (
                from_new.select_provider(providers).await.unwrap(),
                from_default.select_provider(providers).await.unwrap(),
            )
        };
        assert_eq!(
            picked,
            (EnterpriseProvider::WeCom, EnterpriseProvider::WeCom)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_ui_prompt_accepts_the_first_platform_by_number() {
        let (mut client_input, input) = tokio::io::duplex(16);
        let (client_output, output) = tokio::io::duplex(256);
        let mut ui = EnterpriseControllerUi {
            input: tokio::io::BufReader::new(input),
            output,
            opener: Box::new(|_| false),
        };
        let selection = ui.select_provider(EnterpriseProviders::new(true, true).unwrap());
        let (chosen, prompt) = tokio::join!(async { selection.await.unwrap() }, async {
            let prompt = read_ui_output(client_output).await;
            client_input.write_all(b"1\n").await.unwrap();
            prompt
        },);
        assert_eq!(chosen, EnterpriseProvider::WeCom);
        assert!(prompt.contains("企业微信 (WeCom)"));
        assert!(prompt.contains("飞书 (Feishu)"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_ui_authorization_prints_the_manual_url_message_only_on_opener_failure() {
        let url = "https://relay.example.test/yonder/callback/feishu";

        // A failing opener: the manual-URL message follows the URL.
        let (input, _) = tokio::io::duplex(16);
        let (client_output, output) = tokio::io::duplex(512);
        let mut failing = EnterpriseControllerUi {
            input: tokio::io::BufReader::new(input),
            output,
            opener: Box::new(|_| false),
        };
        let (result, printed) = tokio::join!(
            failing.open_authorization(url),
            read_ui_output(client_output),
        );
        result.unwrap();
        assert!(printed.contains(url));
        assert!(
            printed.contains("无法自动打开浏览器，请手动打开上面的链接。"),
            "printed: {printed}"
        );

        // A succeeding opener: the manual-URL message is absent.
        let (input, _) = tokio::io::duplex(16);
        let (client_output, output) = tokio::io::duplex(512);
        let mut succeeding = EnterpriseControllerUi {
            input: tokio::io::BufReader::new(input),
            output,
            opener: Box::new(|_| true),
        };
        let (result, printed) = tokio::join!(
            succeeding.open_authorization(url),
            read_ui_output(client_output),
        );
        result.unwrap();
        assert!(printed.contains(url));
        assert!(!printed.contains("无法自动打开浏览器"));
    }

    #[test]
    fn platform_open_rejects_a_malformed_url_fast() {
        // A NUL byte can never name a path or URL, so the platform opener
        // fails without launching anything.
        assert!(!platform_open("\0"));
        assert!(!platform_open("not a url://["));
    }

    #[test]
    fn run_controller_with_progress_rejects_invalid_wss_before_network_activity() {
        // The controller future (with the 0.2.0 audit observer state)
        // exceeds the default test-thread stack, so the scenario runs on a
        // dedicated thread with a large stack.
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let mut progress = NoopProgress;
                    assert!(matches!(
                        run_controller_with_progress(
                            invalid_wss_controller_config(),
                            &mut progress
                        )
                        .await,
                        Err(ControllerError::Endpoint(EndpointError::Build(
                            NetworkBuildError::WssTls(_)
                        )))
                    ));
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn pre_cancelled_token_stops_the_session_before_any_network_activity() {
        // The controller session future (with the 0.2.0 audit observer
        // state) exceeds the default test-thread stack, so the scenario
        // runs on a dedicated thread with a large stack.
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let cancellation = tokio_util::sync::CancellationToken::new();
                    cancellation.cancel();
                    let mut progress = NoopProgress;
                    assert!(matches!(
                        run_controller_session(
                            invalid_wss_controller_config(),
                            CrosstermFrontend,
                            &mut progress,
                            cancellation,
                        )
                        .await,
                        Err(ControllerError::Interrupted)
                    ));
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_until_interrupted_with_a_pre_cancelled_token_returns_the_session_error() {
        let cancellation = tokio_util::sync::CancellationToken::new();
        cancellation.cancel();
        let session_cancellation = cancellation.clone();
        let session = async move {
            session_cancellation.cancelled().await;
            Err::<u32, _>(ControllerError::Interrupted)
        };
        assert!(matches!(
            run_until_interrupted(session, std::future::pending(), cancellation).await,
            Err(ControllerError::Interrupted)
        ));
    }

    #[test]
    fn display_mode_guard_enters_and_restores_when_enabled() {
        // On Windows the enabled enter attaches the real console (CONOUT$);
        // a detached process reports the environment error and the guard is
        // never created. On non-Windows the enabled enter is unconditional.
        let Ok(Some(guard)) = DisplayModeGuard::enter(true) else {
            #[cfg(not(windows))]
            panic!("non-Windows enter(true) cannot fail");
            #[cfg(windows)]
            return;
        };
        DisplayModeGuard::restore_optional(Some(guard)).unwrap();
    }

    #[test]
    fn raw_mode_guard_enters_and_restores_through_the_real_console_when_available() {
        let frontend = CrosstermFrontend;
        let Ok(Some(guard)) = frontend.enter_raw_mode() else {
            // Non-interactive stdin creates no raw guard (covered by
            // crossterm_boundary_is_callable_without_an_interactive_terminal).
            return;
        };
        frontend.restore_raw_mode(Some(guard)).unwrap();
    }

    #[cfg(not(windows))]
    #[test]
    fn raw_mode_guard_restore_without_enter_is_a_no_op() {
        // restore() on a guard that was never armed must succeed without
        // touching the terminal: crossterm only rewrites the mode when a
        // raw mode was previously enabled, so this is deterministic even
        // without a controlling terminal.
        RawModeGuard { armed: false }.restore().unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resize_pump_survives_terminal_size_query_failures() {
        let frontend = FakeFrontend {
            restored: Rc::new(Cell::new(false)),
            size: Err(io::ErrorKind::Other),
            raw_error: None,
        };
        // Every size query fails; the pump must keep polling instead of
        // erroring out, so the session's resize branch never dies.
        let result = tokio::time::timeout(
            Duration::from_millis(300),
            copy_terminal_resizes(
                &frontend,
                &mut tokio::io::sink(),
                TerminalSize::new(80, 24).unwrap(),
                true,
                None,
            ),
        )
        .await;
        assert!(
            result.is_err(),
            "the resize pump must keep polling after a failed size query: {result:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn utf8_writer_oversized_valid_chunk_passes_through_the_batch() {
        let mut output = CountingWriter::default();
        let mut terminal_output =
            RemoteTerminalOutput::new(RemoteTerminalOutputMode::WindowsConsoleUtf8);
        let chunk = vec![b'a'; UTF8_OUTPUT_BATCH_CAPACITY + 1];
        terminal_output.write(&mut output, &chunk).await.unwrap();
        terminal_output.finish(&mut output).await.unwrap();
        // An over-capacity valid chunk is flushed through the batch and
        // written directly, never truncated or duplicated.
        assert_eq!(output.bytes, chunk);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn local_input_pump_logs_the_chunk_length_at_debug_level() {
        // Enable a debug-level subscriber so the pump's length tracing
        // evaluates its field expressions instead of being filtered out.
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(std::io::sink)
            .finish();
        let _subscriber = tracing::subscriber::set_default(subscriber);
        let mut session_ui = TransferUi::new(true, true, true);
        let mut input = [b'a'; 7].as_slice();
        let (mut controller_write, _peer) = tokio::io::duplex(16);
        let signal = process_local_input_chunk(
            &mut input,
            &mut controller_write,
            &mut session_ui.control,
            &mut session_ui.pending_input,
            None,
        )
        .await
        .unwrap();
        assert_eq!(signal, LocalInputSignal::ChunkPending);
        assert!(session_ui.pending_input.is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_local_ui_uses_stderr_without_a_display() {
        let mut output = CountingWriter::default();
        // §7.1: without a display the message goes to the real stderr and
        // never reaches the session output.
        write_local_ui(&mut output, false, b"stderr ui line")
            .await
            .unwrap();
        assert!(output.bytes.is_empty());
        write_local_ui(&mut output, true, b"display ui line")
            .await
            .unwrap();
        assert_eq!(output.bytes, b"display ui line");
    }

    #[test]
    fn prompt_flow_banners_and_labels_cover_both_directions_and_the_defensive_field() {
        let mut upload = PathPromptFlow::new(TransferDirection::Upload);
        assert_eq!(upload.banner(), PROMPT_BANNER_UPLOAD);
        assert_eq!(upload.label(), PROMPT_UPLOAD_SOURCE);
        let download = PathPromptFlow::new(TransferDirection::Download);
        assert_eq!(download.banner(), PROMPT_BANNER_DOWNLOAD);
        assert_eq!(download.label(), PROMPT_DOWNLOAD_SOURCE);
        // The defensive label arm is unreachable by construction (the field
        // index is 0 or 1); pin its fallback text.
        upload.field = 2;
        assert_eq!(upload.label(), PROMPT_UPLOAD_SOURCE);
    }

    #[test]
    fn prompt_flow_cancels_on_ctrl_c_within_the_selector_remainder() {
        // §6.2: Ctrl+C typed in the same block as the selector reaches the
        // path editor through the remainder and cancels the operation.
        let mut flow = PathPromptFlow::new(TransferDirection::Upload);
        let mut machine = LocalControlInput::new(true, false);
        let processed = machine.process(local_chunk(b"\x1duabc\x03"));
        assert_eq!(processed.action, LocalAction::StartUpload);
        assert_eq!(processed.remainder.as_slice(), b"abc\x03");
        assert_eq!(flow.feed(&processed), PromptProgress::Cancelled);
        assert_eq!(flow.current_line(), "");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn prompt_bell_path_echoes_valid_characters_and_rings_the_bell() {
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        let processed = session_ui.control.process(local_chunk(b"a\x01b"));
        assert_eq!(processed.path_bytes.as_slice(), b"a\x01b");
        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        let cancel = AtomicBool::new(false);
        let handling = handle_processed_input(
            processed,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(handling, LocalInputHandling::Done);
        // The valid characters echo, the rejected control byte rings the
        // bell and never enters the field.
        assert_eq!(output.bytes, b"ab\x07");
        assert_eq!(flow_line(&session_ui), "ab");
        assert_eq!(
            session_ui.control.modal_phase(),
            Some(ModalPhase::UploadPrompt)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn modal_unknown_selector_rings_the_bell_without_echoing() {
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        let processed = session_ui.control.process(local_chunk(b"\x1dX"));
        assert_eq!(processed.action, LocalAction::Bell);
        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        let cancel = AtomicBool::new(false);
        let handling = handle_processed_input(
            processed,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(handling, LocalInputHandling::Done);
        // §6.3: the unknown selector is BEL-ignored, never forwarded.
        assert_eq!(output.bytes, b"\x07");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn empty_required_field_reprompts_with_the_label() {
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        let processed = session_ui.control.process(local_chunk(b"\n"));
        assert_eq!(processed.path_bytes.as_slice(), b"\n");
        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        let cancel = AtomicBool::new(false);
        let handling = handle_processed_input(
            processed,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(handling, LocalInputHandling::Done);
        // §7.2: an empty required field re-prompts the same field.
        assert_eq!(output.bytes, b"\r\nlocal source:");
        assert_eq!(flow_line(&session_ui), "");
        assert_eq!(
            session_ui.control.modal_phase(),
            Some(ModalPhase::UploadPrompt)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn completed_prompt_runs_the_transfer_with_delayed_output_flushed() {
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        assert_eq!(
            session_ui.delayed.append(b"delayed-tail"),
            AppendOutcome::Ok
        );

        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        let cancel = AtomicBool::new(false);

        let source = session_ui.control.process(local_chunk(b"src\n"));
        let handling = handle_processed_input(
            source,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(handling, LocalInputHandling::Done);
        assert_eq!(
            output.bytes,
            b"\r\nremote destination [remote session start directory]:"
        );
        assert!(session_ui.flow.is_some());

        let destination = session_ui.control.process(local_chunk(b"dest\r\n"));
        let handling = handle_processed_input(
            destination,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            handling,
            LocalInputHandling::RunTransfer {
                direction: TransferDirection::Upload,
                first: "src".to_owned(),
                second: Some("dest".to_owned()),
            }
        );
        assert!(session_ui.flow.is_none());
        // §7.4.4: the delayed remote output is flushed in order once the
        // prompt has ended.
        assert_eq!(
            output.bytes,
            b"\r\nremote destination [remote session start directory]:\r\ndelayed-tail"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pass_through_d_signals_the_download_modal_start() {
        let mut session_ui = TransferUi::new(true, true, true);
        let processed = session_ui.control.process(local_chunk(b"\x1dd"));
        assert_eq!(processed.action, LocalAction::StartDownload);
        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        let cancel = AtomicBool::new(false);
        let handling = handle_processed_input(
            processed,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            handling,
            LocalInputHandling::StartModal(TransferDirection::Download)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn help_during_a_prompt_restores_the_prompt_label_and_line() {
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        let processed = session_ui.control.process(local_chunk(b"\x1d?xy"));
        assert_eq!(processed.action, LocalAction::ShowHelp);
        assert_eq!(processed.path_bytes.as_slice(), b"xy");
        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        let cancel = AtomicBool::new(false);
        let handling = handle_processed_input(
            processed,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(handling, LocalInputHandling::Done);
        let text = String::from_utf8_lossy(&output.bytes);
        assert!(text.contains("Ctrl+] u"));
        // §6.3: the prompt continues after the help with its label and line.
        assert!(text.ends_with("local source:xy"), "text: {text}");
        assert_eq!(flow_line(&session_ui), "xy");
        assert_eq!(
            session_ui.control.modal_phase(),
            Some(ModalPhase::UploadPrompt)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn help_without_a_terminal_reports_file_transfer_unavailable() {
        let mut session_ui = TransferUi::new(true, true, false);
        let processed = session_ui.control.process(local_chunk(b"\x1d?"));
        assert_eq!(processed.action, LocalAction::ShowHelp);
        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        let cancel = AtomicBool::new(false);
        let handling = handle_processed_input(
            processed,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(handling, LocalInputHandling::Done);
        // §7.1: without a terminal output the fixed unavailable error is
        // shown instead of the help.
        let mut expected = b"\r\n".to_vec();
        expected.extend_from_slice(FILE_TRANSFER_UNAVAILABLE.as_bytes());
        assert_eq!(output.bytes, expected);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancel_during_the_transfer_phase_sets_the_cancel_flag() {
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.control.enter_transfer().unwrap();
        session_ui.direction = Some(TransferDirection::Upload);
        let processed = session_ui.control.process(local_chunk(b"\x03"));
        assert_eq!(processed.action, LocalAction::CancelOp);
        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        let cancel = AtomicBool::new(false);
        let handling = handle_processed_input(
            processed,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(handling, LocalInputHandling::Done);
        // §16.2: the running transfer observes the flag between blocks.
        assert!(cancel.load(Ordering::Relaxed));
        assert!(output.bytes.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transfer_completion_bells_an_abandoned_prefix_before_ending() {
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.control.enter_transfer().unwrap();
        session_ui.direction = Some(TransferDirection::Upload);
        // The user typed Ctrl+] right before the transfer completed.
        let pending = session_ui.control.process(local_chunk(b"\x1d"));
        assert_eq!(pending.action, LocalAction::None);
        assert!(session_ui.control.pending_prefix());
        let mut transfer: Option<Pin<Box<dyn Future<Output = TransferOutcome>>>> =
            Some(Box::pin(async { TransferOutcome::Cancelled }));
        let mut output = CountingWriter::default();
        let cancel = AtomicBool::new(false);
        let completion = handle_transfer_event(
            TransferOutcome::Cancelled,
            &mut output,
            &mut session_ui,
            &cancel,
            &mut transfer,
        )
        .await
        .unwrap();
        assert_eq!(completion, None);
        assert!(transfer.is_none());
        // §6.3: the abandoned prefix rings the bell and is cleared, so it
        // can never detach the session after the operation ends.
        assert_eq!(output.bytes, b"\r\nupload cancelled\x07");
        assert_eq!(session_ui.control.modal_phase(), None);
        let after = session_ui.control.process(local_chunk(b"."));
        assert_eq!(after.action, LocalAction::None);
        assert_eq!(after.remote_bytes.as_slice(), b".");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn local_input_eof_bells_an_orphaned_modal_prefix_and_drops_the_prompt() {
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        let _ = session_ui.control.process(local_chunk(b"\x1d"));
        assert!(session_ui.control.pending_prefix());
        let (mut controller_write, mut peer_read) = tokio::io::duplex(16);
        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        finish_local_input_eof(
            &mut controller_write,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            None,
        )
        .await
        .unwrap();
        assert!(session_ui.local_ended);
        assert!(session_ui.flow.is_none());
        // §6.3: an orphaned modal prefix rings the bell and is never
        // forwarded to the remote.
        assert_eq!(output.bytes, b"\x07");
        let mut received = Vec::new();
        peer_read.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fail_transfer_startup_writes_the_fixed_summary_and_returns_to_pass_through() {
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        let mut output = CountingWriter::default();
        fail_transfer_startup(
            TransferDirection::Upload,
            "boom",
            &mut output,
            &mut session_ui,
        )
        .await
        .unwrap();
        assert_eq!(output.bytes, b"\r\nupload failed: boom");
        assert!(session_ui.flow.is_none());
        assert_eq!(session_ui.control.modal_phase(), None);
        // §17.2: ordinary local failures never end the terminal session.
        let next = session_ui.control.process(local_chunk(b"ok"));
        assert_eq!(next.remote_bytes.as_slice(), b"ok");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn delayed_overflow_while_a_prompt_is_active_is_reported_and_bounded() {
        let (mut controller, mut host) = tokio::io::duplex(8192);
        let mut session_ui = TransferUi::new(true, true, true);
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        let mut sink = tokio::io::sink();
        let payload = vec![0x55_u8; DELAYED_OUTPUT_CAP + 16 * 1024];
        let (result, ()) = tokio::join!(
            copy_remote_output(
                &mut controller,
                &mut sink,
                &mut terminal_output,
                &mut session_ui.delayed,
                &mut session_ui.delayed_overflow,
                &session_ui.flow,
                None,
            ),
            async {
                host.write_all(&payload).await.unwrap();
                host.shutdown().await.unwrap();
            },
        );
        result.unwrap();
        // §7.4.5: the overflow is reported, nothing is dropped, and the
        // buffer never grows past its hard per-session bound.
        assert!(session_ui.delayed_overflow);
        assert_eq!(session_ui.delayed.used(), DELAYED_OUTPUT_CAP);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn windows_console_utf8_completes_a_pending_prefix_and_replaces_invalid_bytes() {
        let mut output = CountingWriter::default();
        let mut terminal_output =
            RemoteTerminalOutput::new(RemoteTerminalOutputMode::WindowsConsoleUtf8);

        // An incomplete prefix parks in the adapter without writing...
        write_prepared(&mut terminal_output, &mut output, b"\xe4").await;
        assert!(output.bytes.is_empty());

        // ...and completes into a valid sequence once the continuation
        // bytes arrive in a later call.
        write_prepared(&mut terminal_output, &mut output, b"\xb8\xad").await;
        assert_eq!(output.bytes, "\u{4e2d}".as_bytes());

        // A fresh prefix completed by an invalid byte is replaced; the
        // byte itself is replaced again, matching lossy UTF-8 conversion.
        write_prepared(&mut terminal_output, &mut output, b"\xe4").await;
        write_prepared(&mut terminal_output, &mut output, b"\xff").await;
        assert_eq!(output.bytes, "\u{4e2d}\u{fffd}\u{fffd}".as_bytes());

        // An incomplete prefix at the end is replaced by finish().
        write_prepared(&mut terminal_output, &mut output, b"\xf0\x90").await;
        terminal_output.finish(&mut output).await.unwrap();
        assert_eq!(output.bytes, "\u{4e2d}\u{fffd}\u{fffd}\u{fffd}".as_bytes());
    }

    #[test]
    fn local_terminal_hello_defaults_an_empty_term_and_reads_colorterm() {
        // The workspace forbids the `unsafe_code` lint category (edition
        // 2024 marks `std::env::set_var` as an `unsafe_fn`), so the process
        // environment is only reachable through a child process with
        // controlled variables. The inner test is `#[ignore]`d and re-run
        // here with `--ignored`.
        let exe = std::env::current_exe().unwrap();
        for (name, term, colorterm) in [
            (
                "an empty TERM falls back to the interactive default",
                "",
                "truecolor",
            ),
            (
                "a set TERM passes through with an absent COLORTERM",
                "xterm",
                "",
            ),
        ] {
            let output = std::process::Command::new(&exe)
                .args([
                    "--ignored",
                    "local_terminal_hello_metadata_matches_the_process_environment",
                ])
                .env("TERM", term)
                .env("COLORTERM", colorterm)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    #[ignore = "spawned by local_terminal_hello_defaults_an_empty_term_and_reads_colorterm"]
    fn local_terminal_hello_metadata_matches_the_process_environment() {
        let term = std::env::var("TERM").unwrap_or_default();
        let colorterm = std::env::var("COLORTERM").unwrap_or_default();
        let frontend = FakeFrontend {
            restored: Rc::new(Cell::new(false)),
            size: Ok((132, 43)),
            raw_error: None,
        };
        let hello = local_terminal_hello_with(&frontend).unwrap();
        assert_eq!(hello.size(), TerminalSize::new(132, 43).unwrap());
        if term.is_empty() {
            // An empty TERM falls back to the interactive default.
            assert_eq!(hello.term().as_str(), "xterm-256color");
        } else {
            assert_eq!(hello.term().as_str(), term);
        }
        assert_eq!(hello.color_term().as_str(), colorterm);
    }

    #[test]
    fn restore_native_display_writes_the_restore_commands_without_error() {
        // The real stdout/stderr path; in an environment without a display
        // the availability check returns early, otherwise the restore
        // command string is written and flushed to the detected output.
        restore_native_display().unwrap();

        // Direct in-memory invocation: the restore command string is
        // written in full and flushed to the caller's output.
        let commands = native_display_restore_commands().unwrap();
        let mut output = Vec::new();
        write_native_display_restore(&mut output, &commands).unwrap();
        assert_eq!(output, commands.as_bytes());
        assert!(output.starts_with(b"\x1b[?2004l"));
        assert!(output.ends_with(b"\x1b[0m"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn process_local_input_chunk_reports_eof_for_an_empty_input() {
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        let _ = session_ui.control.process(local_chunk(b"\x1d"));
        assert!(session_ui.control.enabled());
        assert!(session_ui.control.pending_prefix());
        let (mut controller_write, mut peer_read) = tokio::io::duplex(16);
        let mut empty = tokio::io::empty();
        assert_eq!(
            process_local_input_chunk(
                &mut empty,
                &mut controller_write,
                &mut session_ui.control,
                &mut session_ui.pending_input,
                None,
            )
            .await
            .unwrap(),
            LocalInputSignal::Eof
        );
        // EOF never stores a pending chunk and never writes to the remote
        // data stream.
        assert!(session_ui.pending_input.is_none());
        drop(controller_write);
        let mut received = Vec::new();
        peer_read.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn finish_local_input_eof_combines_orphaned_prefix_bell_with_an_active_flow() {
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        let _ = session_ui.control.process(local_chunk(b"\x1d"));
        assert!(session_ui.control.pending_prefix());
        assert_eq!(session_ui.delayed.append(b"tail"), AppendOutcome::Ok);
        let (mut controller_write, mut peer_read) = tokio::io::duplex(16);
        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        finish_local_input_eof(
            &mut controller_write,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            None,
        )
        .await
        .unwrap();
        assert!(session_ui.local_ended);
        assert!(session_ui.flow.is_none());
        assert_eq!(session_ui.control.modal_phase(), None);
        assert!(session_ui.delayed.is_empty());
        // §6.3/§7.4.4: the orphaned prefix rings the bell and the delayed
        // remote output flushes in order; the prefix is never forwarded.
        assert_eq!(output.bytes, b"\x07tail");
        let mut received = Vec::new();
        peer_read.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn read_remote_exit_decodes_a_five_byte_exit_frame() {
        let (mut controller_read, mut host_write) = tokio::io::duplex(8);
        host_write
            .write_all(TerminalExit::new(23).encode().as_slice())
            .await
            .unwrap();
        host_write.flush().await.unwrap();
        assert_eq!(read_remote_exit(&mut controller_read).await.unwrap(), 23);

        // An empty control stream is reported as an IO failure.
        let (mut controller_read, host_write) = tokio::io::duplex(8);
        drop(host_write);
        assert!(matches!(
            read_remote_exit(&mut controller_read).await,
            Err(ControllerError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_completion_ack_finishes_before_the_host_control_close() {
        let (controller_control, host_control) = tokio::io::duplex(8);
        let (mut controller_read, mut controller_write) = tokio::io::split(controller_control);
        let (mut host_read, mut host_write) = tokio::io::split(host_control);
        let controller = complete_terminal_control_io(&mut controller_read, &mut controller_write);
        let host = async {
            let mut complete = [0_u8; 1];
            host_read.read_exact(&mut complete).await.unwrap();
            assert_eq!(TerminalComplete::decode(&complete), Ok(TerminalComplete));
            // The host keeps its write half open for a moment, so the ack
            // branch must finish first and then wait for this close.
            tokio::time::sleep(Duration::from_millis(50)).await;
            host_write.shutdown().await.unwrap();
        };

        let (result, ()) = tokio::join!(controller, host);
        result.unwrap();
    }

    struct ResizeCellFrontend {
        restored: Rc<Cell<bool>>,
        size: Rc<Cell<(u16, u16)>>,
    }

    impl TerminalFrontend for ResizeCellFrontend {
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
            Ok(self.size.get())
        }

        fn enter_raw_mode(&self) -> Result<Option<Self::RawModeGuard>, io::Error> {
            Ok(Some(FakeRawGuard(Rc::clone(&self.restored))))
        }

        fn input(&mut self) -> Self::Input {
            tokio::io::empty()
        }

        fn output(&mut self) -> Self::Output {
            tokio::io::sink()
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_resize_pump_reports_each_observed_size_change() {
        let frontend = ResizeCellFrontend {
            restored: Rc::new(Cell::new(false)),
            size: Rc::new(Cell::new((132, 43))),
        };
        let size = Rc::clone(&frontend.size);
        let (mut controller, mut host) = tokio::io::duplex(5);
        let pump = copy_terminal_resizes(
            &frontend,
            &mut controller,
            TerminalSize::new(80, 24).unwrap(),
            true,
            None,
        );
        tokio::pin!(pump);
        let receive = async {
            let mut resize = [0_u8; 5];
            host.read_exact(&mut resize).await.unwrap();
            resize
        };
        let resize = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                result = &mut pump => match result {
                    Ok(never) => match never {},
                    Err(error) => panic!("resize pump failed: {error}"),
                },
                resize = receive => resize,
            }
        })
        .await
        .expect("the first changed size was not sent");
        assert_eq!(resize, [0x02, 0, 132, 0, 43]);

        // The frontend reports a second change; the pump observes it on a
        // later poll and writes the new resize frame.
        size.set((140, 50));
        let receive = async {
            let mut resize = [0_u8; 5];
            host.read_exact(&mut resize).await.unwrap();
            resize
        };
        let resize = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                result = &mut pump => match result {
                    Ok(never) => match never {},
                    Err(error) => panic!("resize pump failed: {error}"),
                },
                resize = receive => resize,
            }
        })
        .await
        .expect("the second changed size was not sent");
        assert_eq!(resize, [0x02, 0, 140, 0, 50]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn echo_delta_erases_multiple_characters_and_rewrites_the_added_tail() {
        let mut machine = LocalControlInput::new(true, false);
        let started = machine.process(local_chunk(b"\x1du"));
        let mut flow = PathPromptFlow::new(TransferDirection::Upload);
        let mut output = CountingWriter::default();
        flow.feed(&started);
        let processed = machine.process(local_chunk(b"abcde"));
        assert!(matches!(
            flow.feed(&processed),
            PromptProgress::Active { bell: false }
        ));
        flow.echo_delta(&mut output).await.unwrap();
        assert_eq!(output.bytes, b"abcde");

        // Two backspaces erase two columns in one delta.
        let processed = machine.process(local_chunk(b"\x08\x08"));
        flow.feed(&processed);
        flow.echo_delta(&mut output).await.unwrap();
        assert_eq!(output.bytes, b"abcde\x08 \x08\x08 \x08");
        assert_eq!(flow.current_line(), "abc");

        // The typed tail is appended after the erasure.
        let processed = machine.process(local_chunk(b"xy"));
        flow.feed(&processed);
        flow.echo_delta(&mut output).await.unwrap();
        assert_eq!(output.bytes, b"abcde\x08 \x08\x08 \x08xy");
        assert_eq!(flow.current_line(), "abcxy");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_local_ui_display_path_writes_and_propagates_flush_failures() {
        let mut output = CountingWriter::default();
        write_local_ui(&mut output, true, b"display line")
            .await
            .unwrap();
        assert_eq!(output.bytes, b"display line");

        let mut output = FailingFlush;
        assert!(matches!(
            write_local_ui(&mut output, true, b"display line").await,
            Err(ControllerError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn flush_delayed_output_writes_buffered_remote_bytes_in_order() {
        let mut session_ui = TransferUi::new(true, true, true);
        assert_eq!(session_ui.delayed.append(b"abc"), AppendOutcome::Ok);
        assert_eq!(session_ui.delayed.append(b"def"), AppendOutcome::Ok);
        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        flush_delayed_output(&mut session_ui, &mut output, &mut terminal_output, None)
            .await
            .unwrap();
        assert_eq!(output.bytes, b"abcdef");
        assert!(session_ui.delayed.is_empty());

        // An empty delayed buffer writes nothing.
        flush_delayed_output(&mut session_ui, &mut output, &mut terminal_output, None)
            .await
            .unwrap();
        assert_eq!(output.bytes, b"abcdef");

        // A flush failure propagates as a controller IO error.
        let mut session_ui = TransferUi::new(true, true, true);
        assert_eq!(session_ui.delayed.append(b"tail"), AppendOutcome::Ok);
        let mut output = FailingFlush;
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        assert!(matches!(
            flush_delayed_output(&mut session_ui, &mut output, &mut terminal_output, None).await,
            Err(ControllerError::Io(_))
        ));
    }

    #[test]
    fn audited_delayed_display_records_flush_success_and_failure() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        let (controller_audit, host_audit, controller_dir, host_dir) =
                            establish_audit_pair().await;

                        let mut session_ui = TransferUi::new(true, true, true);
                        assert_eq!(session_ui.delayed.append(b"visible"), AppendOutcome::Ok);
                        let mut output = CountingWriter::default();
                        let mut terminal_output =
                            RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
                        flush_delayed_output(
                            &mut session_ui,
                            &mut output,
                            &mut terminal_output,
                            Some(&controller_audit),
                        )
                        .await
                        .unwrap();

                        assert_eq!(session_ui.delayed.append(b"failure"), AppendOutcome::Ok);
                        let mut output = CountingWriter::failing_flush();
                        assert!(matches!(
                            flush_delayed_output(
                                &mut session_ui,
                                &mut output,
                                &mut terminal_output,
                                Some(&controller_audit),
                            )
                            .await,
                            Err(ControllerError::Io(_))
                        ));

                        controller_audit
                            .close_interrupted(AuditCloseReason::ConnectionLost)
                            .await;
                        drop(controller_audit);
                        drop(host_audit);

                        let record =
                            fs::read_dir(controller_dir.path().join("audit").join("records"))
                                .unwrap()
                                .next()
                                .unwrap()
                                .unwrap()
                                .path();
                        let mut outcomes = Vec::new();
                        stream_frames(&record, &mut |record_type, payload| {
                            if record_type == RecordType::LocalDisplayWriteOutcome
                                && let Some(outcome) = payload.get(40)
                            {
                                outcomes.push(*outcome);
                            }
                            Ok(StreamAction::Continue)
                        })
                        .unwrap();
                        assert_eq!(outcomes, [OUTCOME_OK, OUTCOME_FAILED]);
                        drop(host_dir);
                    });
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn enterprise_local_shortcuts_are_all_persisted_in_the_audit_record() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        let (controller_audit, host_audit, controller_dir, host_dir) =
                            establish_audit_pair().await;
                        let mut output = CountingWriter::default();
                        let mut terminal_output =
                            RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
                        let cancel = AtomicBool::new(false);

                        let mut help_ui = TransferUi::new(true, true, true);
                        let help = help_ui.control.process(local_chunk(b"\x1d?"));
                        assert_eq!(help.action, LocalAction::ShowHelp);
                        assert_eq!(
                            handle_processed_input(
                                help,
                                &mut output,
                                &mut terminal_output,
                                &mut help_ui,
                                &cancel,
                                Some(&controller_audit),
                            )
                            .await
                            .unwrap(),
                            LocalInputHandling::Done
                        );

                        let mut interrupt_ui = TransferUi::new(true, true, true);
                        let _ = interrupt_ui.control.process(local_chunk(b"\x1du"));
                        interrupt_ui.control.enter_transfer().unwrap();
                        let interrupt = interrupt_ui.control.process(local_chunk(b"\x03"));
                        assert_eq!(interrupt.action, LocalAction::CancelOp);
                        handle_processed_input(
                            interrupt,
                            &mut output,
                            &mut terminal_output,
                            &mut interrupt_ui,
                            &cancel,
                            Some(&controller_audit),
                        )
                        .await
                        .unwrap();

                        for (selector, direction) in [
                            (b"\x1du".as_slice(), TransferDirection::Upload),
                            (b"\x1dd".as_slice(), TransferDirection::Download),
                        ] {
                            let mut session_ui = TransferUi::new(true, true, true);
                            let processed = session_ui.control.process(local_chunk(selector));
                            assert_eq!(
                                handle_processed_input(
                                    processed,
                                    &mut output,
                                    &mut terminal_output,
                                    &mut session_ui,
                                    &cancel,
                                    Some(&controller_audit),
                                )
                                .await
                                .unwrap(),
                                LocalInputHandling::StartModal(direction)
                            );
                        }

                        controller_audit
                            .close_interrupted(AuditCloseReason::ConnectionLost)
                            .await;
                        drop(controller_audit);
                        drop(host_audit);

                        let record =
                            fs::read_dir(controller_dir.path().join("audit").join("records"))
                                .unwrap()
                                .next()
                                .unwrap()
                                .unwrap()
                                .path();
                        let mut actions = Vec::new();
                        stream_frames(&record, &mut |record_type, payload| {
                            if record_type == RecordType::LocalKeyAction
                                && let Some(action) = payload.get(40)
                            {
                                actions.push(*action);
                            }
                            Ok(StreamAction::Continue)
                        })
                        .unwrap();
                        assert_eq!(
                            actions,
                            [
                                KEY_ACTION_HELP,
                                KEY_ACTION_INTERRUPT,
                                KEY_ACTION_UPLOAD,
                                KEY_ACTION_DOWNLOAD,
                            ]
                        );
                        drop(host_dir);
                    });
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn end_transfer_modal_bells_an_abandoned_prefix_and_stays_quiet_otherwise() {
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        let _ = session_ui.control.process(local_chunk(b"\x1d"));
        assert!(session_ui.control.pending_prefix());
        let mut output = CountingWriter::default();
        end_transfer_modal(&mut session_ui, &mut output)
            .await
            .unwrap();
        assert_eq!(output.bytes, b"\x07");
        assert_eq!(session_ui.control.modal_phase(), None);
        // A second end is a no-op: the bell is written exactly once.
        end_transfer_modal(&mut session_ui, &mut output)
            .await
            .unwrap();
        assert_eq!(output.bytes, b"\x07");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn handle_processed_input_reprompts_advances_and_cancels_with_ui_writes() {
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        let cancel = AtomicBool::new(false);

        // §7.2: an empty required field re-prompts with the field label.
        let processed = session_ui.control.process(local_chunk(b"\n"));
        let handling = handle_processed_input(
            processed,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(handling, LocalInputHandling::Done);
        assert_eq!(output.bytes, b"\r\nlocal source:");

        // §7.2: a submitted required field prints the destination label.
        let processed = session_ui.control.process(local_chunk(b"src\n"));
        let handling = handle_processed_input(
            processed,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(handling, LocalInputHandling::Done);
        assert_eq!(
            output.bytes,
            b"\r\nlocal source:\r\nremote destination [remote session start directory]:"
        );

        // §16.1: Ctrl+C cancels; the prompt is dropped, the bell never
        // rings (no abandoned prefix) and the delayed output flushes.
        assert_eq!(session_ui.delayed.append(b"tail"), AppendOutcome::Ok);
        let processed = session_ui.control.process(local_chunk(b"x\x03"));
        assert_eq!(processed.action, LocalAction::CancelOp);
        let handling = handle_processed_input(
            processed,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(handling, LocalInputHandling::Done);
        assert!(session_ui.flow.is_none());
        assert_eq!(session_ui.control.modal_phase(), None);
        assert!(!cancel.load(Ordering::Relaxed));
        assert_eq!(
            output.bytes,
            b"\r\nlocal source:\r\nremote destination [remote session start directory]:x\r\ntail"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn help_and_cancel_with_an_active_prompt_write_the_prompt_ui() {
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        let mut output = CountingWriter::default();
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        let cancel = AtomicBool::new(false);

        // §6.3: help during a prompt restores the label and the typed line.
        let processed = session_ui.control.process(local_chunk(b"\x1d?xy"));
        assert_eq!(processed.action, LocalAction::ShowHelp);
        let handling = handle_processed_input(
            processed,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(handling, LocalInputHandling::Done);
        let text = String::from_utf8_lossy(&output.bytes).into_owned();
        assert!(text.contains("Ctrl+] u"));
        assert!(text.ends_with("local source:xy"), "text: {text}");
        assert_eq!(flow_line(&session_ui), "xy");

        // §16.1: Ctrl+C with the prompt still active cancels it; the
        // delayed remote output flushes in order and the cancel flag stays
        // clear (no transfer is running).
        assert_eq!(session_ui.delayed.append(b"delayed"), AppendOutcome::Ok);
        let processed = session_ui.control.process(local_chunk(b"\x03"));
        assert_eq!(processed.action, LocalAction::CancelOp);
        let handling = handle_processed_input(
            processed,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(handling, LocalInputHandling::Done);
        assert!(session_ui.flow.is_none());
        assert_eq!(session_ui.control.modal_phase(), None);
        assert!(!cancel.load(Ordering::Relaxed));
        let text = String::from_utf8_lossy(&output.bytes).into_owned();
        assert!(text.ends_with("\r\ndelayed"), "text: {text}");

        // §7.1: without a terminal output the help shows the fixed
        // unavailable error instead.
        let mut no_terminal = TransferUi::new(true, true, false);
        let processed = no_terminal.control.process(local_chunk(b"\x1d?"));
        assert_eq!(processed.action, LocalAction::ShowHelp);
        let mut output = CountingWriter::default();
        let handling = handle_processed_input(
            processed,
            &mut output,
            &mut terminal_output,
            &mut no_terminal,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(handling, LocalInputHandling::Done);
        let mut expected = b"\r\n".to_vec();
        expected.extend_from_slice(FILE_TRANSFER_UNAVAILABLE.as_bytes());
        assert_eq!(output.bytes, expected);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transfer_completion_writes_committed_and_failed_summaries() {
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.control.enter_transfer().unwrap();
        session_ui.direction = Some(TransferDirection::Upload);
        let cancel = AtomicBool::new(true);
        let mut transfer: Option<Pin<Box<dyn Future<Output = TransferOutcome>>>> =
            Some(Box::pin(async { TransferOutcome::Committed { bytes: 0 } }));
        let mut output = CountingWriter::default();
        let completion = handle_transfer_event(
            TransferOutcome::Committed { bytes: 42 },
            &mut output,
            &mut session_ui,
            &cancel,
            &mut transfer,
        )
        .await
        .unwrap();
        assert_eq!(completion, None);
        assert!(transfer.is_none());
        assert_eq!(session_ui.control.modal_phase(), None);
        assert!(!cancel.load(Ordering::Relaxed));
        assert_eq!(output.bytes, b"\r\nupload complete: 42 bytes");

        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1dd"));
        session_ui.control.enter_transfer().unwrap();
        session_ui.direction = Some(TransferDirection::Download);
        let cancel = AtomicBool::new(false);
        let mut transfer: Option<Pin<Box<dyn Future<Output = TransferOutcome>>>> =
            Some(Box::pin(async { TransferOutcome::Cancelled }));
        let mut output = CountingWriter::default();
        let completion = handle_transfer_event(
            TransferOutcome::Failed(FileTransferErrorCode::SourceNotFound),
            &mut output,
            &mut session_ui,
            &cancel,
            &mut transfer,
        )
        .await
        .unwrap();
        assert_eq!(completion, None);
        assert!(transfer.is_none());
        assert_eq!(session_ui.control.modal_phase(), None);
        assert_eq!(output.bytes, b"\r\ndownload failed: SourceNotFound");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn complete_after_output_eof_returns_the_exit_code_of_a_prior_exit_frame() {
        let now = tokio::time::Instant::now();
        // The exit frame arrives first; the EOF observation then completes
        // with that code after the pending output has been flushed.
        let mut exit_first = RemoteCompletion::new();
        assert_eq!(exit_first.observe_exit(42, now), None);
        let (mut output, mut peer) = tokio::io::duplex(1);
        let code = complete_after_output_eof(&mut exit_first, &mut output, now)
            .await
            .unwrap();
        assert_eq!(code, Some(42));
        // The completion is consumed: a later EOF observation is a no-op.
        assert_eq!(
            complete_after_output_eof(&mut exit_first, &mut output, now)
                .await
                .unwrap(),
            None
        );
        peer.shutdown().await.unwrap();

        // EOF first leaves the completion open until the exit frame lands,
        // which then completes it directly.
        let mut eof_first = RemoteCompletion::new();
        assert_eq!(
            complete_after_output_eof(&mut eof_first, &mut tokio::io::sink(), now)
                .await
                .unwrap(),
            None
        );
        assert_eq!(eof_first.observe_exit(7, now), Some(7));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn prepare_controller_session_rejects_a_server_role_wss_transport() {
        let mut config = invalid_wss_controller_config();
        config.wss = WssTransportConfig::server(vec![1], SecretDocument::new(vec![2]));
        // §transport: only a client TLS role can build the relay-only
        // fallback, so the session is rejected before any network activity.
        assert!(matches!(
            prepare_controller_session(config, &mut NoopProgress).await,
            Err(ControllerError::InvalidTransportRole)
        ));
    }

    // ---- focused error-path coverage for the remaining controller lines ----

    /// An input whose `read_line` fails immediately, for the enterprise UI
    /// prompt error path.
    struct FailingBufRead;

    impl AsyncRead for FailingBufRead {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("read failed")))
        }
    }

    impl tokio::io::AsyncBufRead for FailingBufRead {
        fn poll_fill_buf(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<io::Result<&[u8]>> {
            Poll::Ready(Err(io::Error::other("read failed")))
        }

        fn consume(self: Pin<&mut Self>, _amount: usize) {}
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_ui_new_binds_the_real_terminal_and_platform_opener() {
        // §16.x: `new` wires the production terminal and the platform
        // browser opener; a single configured platform is picked without
        // any terminal I/O.
        let mut ui = EnterpriseControllerUi::<
            tokio::io::BufReader<tokio::io::Stdin>,
            tokio::io::Stdout,
        >::new();
        let picked = ui
            .select_provider(EnterpriseProviders::new(true, false).unwrap())
            .await
            .unwrap();
        assert_eq!(picked, EnterpriseProvider::WeCom);
    }

    // The controller session future is large enough that its inline state
    // overflows the default test stack; the session runs on a 64 MiB stack
    // thread like the other in-process harnesses.
    #[test]
    fn controller_config_const_constructor_builds_a_stoppable_session() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    // §16.3: the const constructor initializes every field; a config
                    // built from it starts a session that stops on a pre-cancelled
                    // token before any network activity.
                    let identity = Keypair::generate_ed25519();
                    let relay: EndpointRelayAddress = format!(
                        "/dns4/localhost/tcp/443/tls/ws/p2p/{}",
                        identity.public().to_peer_id()
                    )
                    .parse()
                    .unwrap();
                    let config = ControllerConfig::new(
                        identity,
                        EndpointRelaySet::new(vec![relay]).unwrap(),
                        WssTransportConfig::client(Some(vec![1])),
                        ConnectionCode::new(
                            Locator::new(0).unwrap(),
                            PakeSecret::from_u64(0).unwrap(),
                        ),
                        TerminalHello::new(
                            TerminalSize::new(80, 24).unwrap(),
                            TerminalValue::new("xterm").unwrap(),
                            TerminalValue::new("truecolor").unwrap(),
                        ),
                    );
                    let cancellation = tokio_util::sync::CancellationToken::new();
                    cancellation.cancel();
                    let mut progress = NoopProgress;
                    assert!(matches!(
                        run_controller_session(
                            config,
                            CrosstermFrontend,
                            &mut progress,
                            cancellation
                        )
                        .await,
                        Err(ControllerError::Interrupted)
                    ));
                })
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_ui_provider_prompt_propagates_output_write_failures() {
        let mut ui = EnterpriseControllerUi {
            input: tokio::io::BufReader::new(tokio::io::empty()),
            output: CountingWriter::failing_first_write(),
            opener: Box::new(|_| false),
        };
        assert!(matches!(
            ui.select_provider(EnterpriseProviders::new(true, true).unwrap())
                .await,
            Err(crate::protocol::RelayProtocolError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_ui_provider_prompt_propagates_input_read_failures() {
        let mut ui = EnterpriseControllerUi {
            input: FailingBufRead,
            output: tokio::io::sink(),
            opener: Box::new(|_| false),
        };
        assert!(matches!(
            ui.select_provider(EnterpriseProviders::new(true, true).unwrap())
                .await,
            Err(crate::protocol::RelayProtocolError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_ui_authorization_propagates_the_url_write_failure() {
        let mut ui = EnterpriseControllerUi {
            input: tokio::io::BufReader::new(tokio::io::empty()),
            output: CountingWriter::failing_first_write(),
            opener: Box::new(|_| false),
        };
        assert!(matches!(
            ui.open_authorization("https://relay.example.test/yonder/callback/wecom")
                .await,
            Err(crate::protocol::RelayProtocolError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn enterprise_ui_authorization_propagates_the_manual_url_write_failure() {
        // §16.x: when the opener fails, the manual-URL message is still
        // error-checked; its write failure propagates as an IO error.
        let mut ui = EnterpriseControllerUi {
            input: tokio::io::BufReader::new(tokio::io::empty()),
            output: CountingWriter {
                fail_on_write: Some(2),
                ..CountingWriter::default()
            },
            opener: Box::new(|_| false),
        };
        assert!(matches!(
            ui.open_authorization("https://relay.example.test/yonder/callback/feishu")
                .await,
            Err(crate::protocol::RelayProtocolError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn completed_prompt_propagates_each_ui_write_failure() {
        let cancel = AtomicBool::new(false);
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);

        // The CRLF that precedes the transfer start fails (the first write
        // of the completed branch, §7.4.4).
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        let mut output = CountingWriter::default();
        let source = session_ui.control.process(local_chunk(b"src\n"));
        handle_processed_input(
            source,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            output.bytes,
            b"\r\nremote destination [remote session start directory]:"
        );
        let destination = session_ui.control.process(local_chunk(b"dest\r\n"));
        let mut failing = CountingWriter::failing_first_write();
        assert!(matches!(
            handle_processed_input(
                destination,
                &mut failing,
                &mut terminal_output,
                &mut session_ui,
                &cancel,
                None,
            )
            .await,
            Err(ControllerError::Io(_))
        ));

        // The delayed remote output flush after the prompt ends fails on
        // its own write (§7.4.4).
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        let mut output = CountingWriter::default();
        let source = session_ui.control.process(local_chunk(b"src\n"));
        handle_processed_input(
            source,
            &mut output,
            &mut terminal_output,
            &mut session_ui,
            &cancel,
            None,
        )
        .await
        .unwrap();
        assert_eq!(session_ui.delayed.append(b"tail"), AppendOutcome::Ok);
        let destination = session_ui.control.process(local_chunk(b"dest\r\n"));
        let mut failing = CountingWriter {
            fail_on_write: Some(2),
            ..CountingWriter::default()
        };
        assert!(matches!(
            handle_processed_input(
                destination,
                &mut failing,
                &mut terminal_output,
                &mut session_ui,
                &cancel,
                None,
            )
            .await,
            Err(ControllerError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_prompt_propagates_crlf_and_flush_failures() {
        let cancel = AtomicBool::new(false);
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);

        // §16.1: the CRLF of the cancelled prompt fails (the selector chunk
        // carries the Ctrl+C in its remainder, §6.2).
        let mut session_ui = TransferUi::new(true, true, true);
        let processed = session_ui.control.process(local_chunk(b"\x1duabc\x03"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        assert_eq!(processed.action, LocalAction::StartUpload);
        let mut output = CountingWriter::failing_first_write();
        assert!(matches!(
            handle_processed_input(
                processed,
                &mut output,
                &mut terminal_output,
                &mut session_ui,
                &cancel,
                None,
            )
            .await,
            Err(ControllerError::Io(_))
        ));

        // §7.4.4: the delayed output flush after the cancel fails on its
        // own write.
        let mut session_ui = TransferUi::new(true, true, true);
        let processed = session_ui.control.process(local_chunk(b"\x1duabc\x03"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        assert_eq!(session_ui.delayed.append(b"tail"), AppendOutcome::Ok);
        let mut output = CountingWriter {
            fail_on_write: Some(2),
            ..CountingWriter::default()
        };
        assert!(matches!(
            handle_processed_input(
                processed,
                &mut output,
                &mut terminal_output,
                &mut session_ui,
                &cancel,
                None,
            )
            .await,
            Err(ControllerError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn help_ui_write_failures_propagate_through_each_message() {
        let cancel = AtomicBool::new(false);
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);

        for fail_on in [2, 4, 5] {
            // §6.3: help during a prompt writes the help text, then the
            // prompt label and line; each write is error-checked. The typed
            // path bytes are fed into the flow so the restored current line
            // is non-empty and its write is observable.
            let mut session_ui = TransferUi::new(true, true, true);
            let _ = session_ui.control.process(local_chunk(b"\x1du"));
            session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
            session_ui.direction = Some(TransferDirection::Upload);
            let typed = session_ui.control.process(local_chunk(b"ab"));
            session_ui.flow.as_mut().unwrap().feed(&typed);
            let processed = session_ui.control.process(local_chunk(b"\x1d?"));
            assert_eq!(processed.action, LocalAction::ShowHelp);
            let mut output = CountingWriter {
                fail_on_write: Some(fail_on),
                ..CountingWriter::default()
            };
            assert!(
                matches!(
                    handle_processed_input(
                        processed,
                        &mut output,
                        &mut terminal_output,
                        &mut session_ui,
                        &cancel,
                        None,
                    )
                    .await,
                    Err(ControllerError::Io(_))
                ),
                "write position {fail_on} must propagate"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn help_without_terminal_propagates_the_unavailable_message_write_failure() {
        // §7.1: without a terminal output the fixed unavailable error is
        // shown; its write failure propagates.
        let mut session_ui = TransferUi::new(true, true, false);
        let processed = session_ui.control.process(local_chunk(b"\x1d?"));
        assert_eq!(processed.action, LocalAction::ShowHelp);
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        let cancel = AtomicBool::new(false);
        let mut output = CountingWriter {
            fail_on_write: Some(2),
            ..CountingWriter::default()
        };
        assert!(matches!(
            handle_processed_input(
                processed,
                &mut output,
                &mut terminal_output,
                &mut session_ui,
                &cancel,
                None,
            )
            .await,
            Err(ControllerError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn already_active_propagates_the_fixed_message_write_failure() {
        // §15.3: a second operation while modal writes the fixed message;
        // its write failure propagates.
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        let processed = session_ui.control.process(local_chunk(b"\x1du"));
        assert_eq!(processed.action, LocalAction::AlreadyActive);
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);
        let cancel = AtomicBool::new(false);
        let mut output = CountingWriter {
            fail_on_write: Some(2),
            ..CountingWriter::default()
        };
        assert!(matches!(
            handle_processed_input(
                processed,
                &mut output,
                &mut terminal_output,
                &mut session_ui,
                &cancel,
                None,
            )
            .await,
            Err(ControllerError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancel_op_with_an_active_prompt_propagates_ui_write_failures() {
        let cancel = AtomicBool::new(false);
        let mut terminal_output = RemoteTerminalOutput::new(RemoteTerminalOutputMode::Bytes);

        // §16.1: Ctrl+C with the prompt active writes the CRLF, then the
        // delayed remote output flushes in order; each write is
        // error-checked (the echoed character is the first write).
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        let processed = session_ui.control.process(local_chunk(b"x\x03"));
        assert_eq!(processed.action, LocalAction::CancelOp);
        let mut output = CountingWriter {
            fail_on_write: Some(2),
            ..CountingWriter::default()
        };
        assert!(matches!(
            handle_processed_input(
                processed,
                &mut output,
                &mut terminal_output,
                &mut session_ui,
                &cancel,
                None,
            )
            .await,
            Err(ControllerError::Io(_))
        ));

        // The delayed output flush fails on its own write.
        let mut session_ui = TransferUi::new(true, true, true);
        let _ = session_ui.control.process(local_chunk(b"\x1du"));
        session_ui.flow = Some(PathPromptFlow::new(TransferDirection::Upload));
        session_ui.direction = Some(TransferDirection::Upload);
        assert_eq!(session_ui.delayed.append(b"tail"), AppendOutcome::Ok);
        let processed = session_ui.control.process(local_chunk(b"x\x03"));
        let mut output = CountingWriter {
            fail_on_write: Some(3),
            ..CountingWriter::default()
        };
        assert!(matches!(
            handle_processed_input(
                processed,
                &mut output,
                &mut terminal_output,
                &mut session_ui,
                &cancel,
                None,
            )
            .await,
            Err(ControllerError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn windows_console_pending_buffer_accepts_a_second_incomplete_prefix_byte() {
        // Two consecutive incomplete UTF-8 prefixes keep growing the
        // pending buffer: the first write parks `\xe4`, and a continuation
        // byte that still does not complete the 3-byte sequence extends the
        // pending state instead of writing. Nothing is written until
        // finish() replaces the incomplete sequence.
        let mut output = CountingWriter::default();
        let mut terminal_output =
            RemoteTerminalOutput::new(RemoteTerminalOutputMode::WindowsConsoleUtf8);
        write_prepared(&mut terminal_output, &mut output, b"\xe4").await;
        write_prepared(&mut terminal_output, &mut output, b"\x80").await;
        assert!(output.bytes.is_empty());
        terminal_output.finish(&mut output).await.unwrap();
        assert_eq!(output.bytes, "\u{fffd}".as_bytes());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn await_until_with_an_expired_deadline_returns_timeout_immediately() {
        // §16.x: an absolute deadline in the past times out on the first
        // poll instead of waiting for the underlying future.
        let expired = tokio::time::Instant::now() - Duration::from_secs(1);
        let started = tokio::time::Instant::now();
        assert!(matches!(
            await_until(expired, std::future::pending::<()>()).await,
            Err(ControllerError::Timeout)
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn finish_terminal_output_ok_ok_preserves_the_session_value() {
        // The one combination not exercised by the existing helper tests:
        // a finished session value passes through when the output finish
        // also succeeded.
        assert_eq!(finish_terminal_output(Ok(7), Ok(())).unwrap(), 7);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn remote_completion_deadline_some_arm_waits_until_the_absolute_instant() {
        // The Some arm sleeps until the absolute deadline instead of
        // pending forever.
        let deadline = tokio::time::Instant::now() + Duration::from_millis(2);
        let started = tokio::time::Instant::now();
        wait_for_remote_completion_deadline(Some(deadline)).await;
        assert!(started.elapsed() >= Duration::from_millis(2));
    }

    // ------------------------------------------------------------------
    // In-process controller-session harness: a real relay service, a real
    // controller session (`run_controller_session` with a scripted
    // frontend) and a scripted host endpoint all live in the test runtime,
    // so the controller-side session state machine (relay connect ->
    // locator resolve -> path selection -> OPAQUE auth -> terminal
    // handshake -> pump -> file transfers -> completion) runs over the
    // real libp2p loopback stack without spawning any binaries. The host
    // registers a real locator with a code the test itself created and
    // serves every controller-facing wire role (auth server, terminal
    // peer, file-transfer peer) from a script.
    //
    // The session futures contain `Pin<Box<dyn Future>>` and are not Send,
    // so every scenario runs on a LocalSet (the relay service stays a
    // regular Send spawn), exactly like the host-side harness.
    // ------------------------------------------------------------------

    fn available_tcp_port() -> u16 {
        crate::available_test_tcp_port()
    }

    /// A real relay service running inside the test runtime on a pinned port.
    struct InProcessRelay {
        task: Option<tokio::task::JoinHandle<Result<(), RelayServiceError>>>,
        shutdown: Option<oneshot::Sender<()>>,
    }

    impl InProcessRelay {
        fn start(identity: Keypair, port: u16) -> Self {
            let listen: yonder_net::RelayListenAddress =
                format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap();
            let external: yonder_net::RelayExternalAddress =
                format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap();
            let config = RelayServeConfig::new(
                identity,
                vec![listen],
                vec![external],
                WssTransportConfig::client(None),
            )
            .unwrap();
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let task = tokio::spawn(run_relay_until(config, async move {
                let _ = shutdown_rx.await;
                Ok(())
            }));
            Self {
                task: Some(task),
                shutdown: Some(shutdown_tx),
            }
        }

        async fn stop(mut self) {
            if let Some(shutdown) = self.shutdown.take() {
                let _ = shutdown.send(());
            }
            if let Some(task) = self.task.take() {
                let _ = task.await;
            }
        }
    }

    impl Drop for InProcessRelay {
        fn drop(&mut self) {
            if let Some(shutdown) = self.shutdown.take() {
                let _ = shutdown.send(());
            }
            if let Some(task) = self.task.take() {
                task.abort();
            }
        }
    }

    /// Connects to the in-process relay with bounded retries: the relay's
    /// listener is up before its swarm is fully ready, so under parallel
    /// test load the first dial may transiently fail.
    async fn connect_relay_with_retry(
        driver: &mut EndpointDriver,
        relays: &EndpointRelaySet,
    ) -> RelayConnection {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            match connect_configured_relay(driver, relays).await {
                Ok(connection) => return connection,
                Err(_) => {
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "the relay connection did not stabilize"
                    );
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }
        }
    }

    /// Records every controller preparation milestone so the tests can
    /// assert that the full connect flow ran.
    #[derive(Default)]
    struct RecordingProgress {
        stages: Arc<Mutex<Vec<ControllerStage>>>,
    }

    impl OperationProgress<ControllerStage> for RecordingProgress {
        fn update(&mut self, stage: ControllerStage) {
            self.stages.lock().unwrap().push(stage);
        }

        fn clear(&mut self) {}
    }

    /// A frontend with real duplex streams: the test script writes the
    /// local keystrokes into one half and reads the rendered output from
    /// the other. `size` is shared so the script can resize the terminal
    /// mid-session (the pump then emits a resize frame); `restored` is set
    /// when the raw-mode guard is dropped.
    struct SessionFrontend {
        input: DuplexStream,
        output: DuplexStream,
        size: Rc<Cell<(u16, u16)>>,
        restored: Rc<Cell<bool>>,
    }

    impl TerminalFrontend for SessionFrontend {
        type Input = DuplexStream;
        type Output = DuplexStream;
        type RawModeGuard = FakeRawGuard;

        fn is_interactive(&self) -> bool {
            true
        }

        fn output_is_terminal(&self) -> bool {
            true
        }

        fn size(&self) -> Result<(u16, u16), io::Error> {
            Ok(self.size.get())
        }

        fn enter_raw_mode(&self) -> Result<Option<Self::RawModeGuard>, io::Error> {
            Ok(Some(FakeRawGuard(Rc::clone(&self.restored))))
        }

        fn input(&mut self) -> Self::Input {
            std::mem::replace(&mut self.input, tokio::io::duplex(0).0)
        }

        fn output(&mut self) -> Self::Output {
            std::mem::replace(&mut self.output, tokio::io::duplex(0).1)
        }
    }

    fn pattern_byte(index: u64) -> u8 {
        ((index * 31) + (index / 251) + (index >> 3)) as u8
    }

    fn write_pattern_file(path: &Path, size: u64) {
        let mut file = fs::File::create(path).unwrap();
        let mut buffer = [0_u8; 4096];
        let mut remaining = size;
        let mut offset = 0_u64;
        while remaining > 0 {
            let n = remaining.min(4096) as usize;
            for (i, byte) in buffer[..n].iter_mut().enumerate() {
                *byte = pattern_byte(offset + i as u64);
            }
            file.write_all(&buffer[..n]).unwrap();
            remaining -= n as u64;
            offset += n as u64;
        }
        file.sync_all().unwrap();
    }

    fn sha256_bytes(bytes: &[u8]) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Sha256Digest::new(hasher.finalize().into())
    }

    /// Polls `future` while draining endpoint events, so the scripted
    /// host's swarm keeps making progress during every wire exchange.
    async fn drive_drained<T>(driver: &mut EndpointDriver, future: impl Future<Output = T>) -> T {
        tokio::pin!(future);
        loop {
            tokio::select! {
                biased;
                _ = driver.next() => {}
                result = &mut future => return result,
            }
        }
    }

    /// The scripted host's terminal-peer behaviour. Every field is data the
    /// host verifies against the wire or records for the test.
    struct HostScript {
        exit_code: u32,
        /// Written to terminal-data once after TerminalReady.
        output: Vec<u8>,
        upload_destination: String,
        upload_file_name: String,
        upload_bytes: Vec<u8>,
        download_source: String,
        download_file_name: String,
        download_bytes: Vec<u8>,
        /// Controller terminal-data input, recorded in order.
        recorded_input: Arc<Mutex<Vec<u8>>>,
        /// The last TerminalResize received on terminal-control.
        resize: Arc<Mutex<Option<TerminalSize>>>,
        /// Answer the first authentication start with Retry, then proceed.
        retry_auth_once: bool,
    }

    /// How the scripted host ends its terminal side.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HostEnding {
        /// On data EOF: TerminalExit, data close, TerminalComplete, control close.
        Complete,
        /// Keep the Active session alive through a periodic checkpoint,
        /// then complete the same full terminal flow.
        CheckpointThenComplete,
        /// Close data right after Ready and never send TerminalExit.
        CloseDataSilently,
        /// Read the terminal hello but never send TerminalReady.
        StallHandshake,
        /// Keep everything open after Ready.
        Stall,
        /// Finalize after the controller's local detach escape.
        ControllerDetach,
        /// Finalize after the controller's cancellation token fires.
        ControllerInterrupt,
        /// Close the controller's local display before the first host output.
        ControllerDisplayFailure,
        /// Fail the mandatory enterprise audit after TerminalReady.
        AuditFailure,
        /// Drop the mandatory enterprise audit stream without a close notice.
        AuditStreamEnd,
        /// Drop the audit stream after terminal completion but before finalization.
        AuditFinalizeStreamEnd,
    }

    /// Reads the controller's rendered output until `needle` appears.
    /// Returns the bytes read in this call (the caller accumulates).
    async fn read_output_until(output: &mut DuplexStream, needle: &[u8]) -> Vec<u8> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let mut text = Vec::new();
        let mut buffer = [0_u8; 8192];
        while !text.windows(needle.len()).any(|window| window == needle) {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the controller output never contained {needle:?}; so far: {}",
                String::from_utf8_lossy(&text)
            );
            let read =
                match tokio::time::timeout(Duration::from_millis(500), output.read(&mut buffer))
                    .await
                {
                    Ok(Ok(0)) => panic!("the frontend output closed before {needle:?} appeared"),
                    Ok(Ok(n)) => n,
                    Ok(Err(error)) => panic!("frontend output read failed: {error}"),
                    Err(_) => continue,
                };
            text.extend_from_slice(&buffer[..read]);
        }
        text
    }

    /// Drains the controller's rendered output until the frontend is
    /// dropped (the session completed).
    async fn drain_output_until_closed(output: &mut DuplexStream) -> Vec<u8> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let mut text = Vec::new();
        let mut buffer = [0_u8; 8192];
        loop {
            match tokio::time::timeout(Duration::from_millis(500), output.read(&mut buffer)).await {
                Ok(Ok(0)) => return text,
                Ok(Ok(n)) => text.extend_from_slice(&buffer[..n]),
                Ok(Err(error)) => panic!("frontend output read failed: {error}"),
                Err(_) => assert!(
                    tokio::time::Instant::now() < deadline,
                    "the frontend output never closed"
                ),
            }
        }
    }

    /// The server side of one OPAQUE exchange: reads the client hello,
    /// answers with a fresh nonce and KE2, verifies KE3 and sends the
    /// one-byte `Authenticated` acknowledgement.
    async fn serve_auth_exchange(
        driver: &mut EndpointDriver,
        stream: &mut (impl tokio::io::AsyncRead + AsyncWrite + Unpin),
        locator: Locator,
        registration: &OpaqueRegistration,
        controller: PeerId,
        target: &PeerIdBytes,
        pake: &mut OpaquePake,
    ) {
        drive_drained(driver, async {
            let mut hello = [0_u8; CLIENT_HELLO_LEN];
            stream.read_exact(&mut hello).await.unwrap();
            let hello = AuthClientHello::decode(&hello).unwrap();
            let controller_bytes = peer_id_bytes(controller).unwrap();
            let mut target_nonce = [0_u8; 32];
            OsSecureRandom.try_fill(&mut target_nonce).unwrap();
            let context = PakeContext::new(
                locator,
                &controller_bytes,
                target,
                hello.nonce(),
                &target_nonce,
            );
            let (state, ke2) = pake
                .server_start(registration, hello.ke1(), context.as_bytes())
                .unwrap();
            let response = AuthServerResponse::proceed(target_nonce, ke2).encode();
            stream.write_all(response.as_slice()).await.unwrap();
            stream.flush().await.unwrap();
            let mut finish = [0_u8; KE3_LEN];
            stream.read_exact(&mut finish).await.unwrap();
            let finish = AuthClientFinish::decode(&finish).unwrap();
            let session_key = pake.server_finish(state, finish.ke3()).unwrap();
            drop(session_key);
            stream.write_all(&Authenticated::ENCODED).await.unwrap();
            stream.flush().await.unwrap();
        })
        .await;
    }

    async fn read_terminal_hello(
        stream: &mut (impl tokio::io::AsyncRead + Unpin),
    ) -> TerminalHello {
        let mut bytes = [0_u8; MAX_HELLO_LEN];
        stream.read_exact(&mut bytes[..6]).await.unwrap();
        let term_end = 6 + usize::from(bytes[5]);
        stream.read_exact(&mut bytes[6..=term_end]).await.unwrap();
        let end = term_end + 1 + usize::from(bytes[term_end]);
        stream
            .read_exact(&mut bytes[term_end + 1..end])
            .await
            .unwrap();
        TerminalHello::decode(&bytes[..end]).unwrap()
    }

    /// Reads one complete file-transfer frame. `None` means EOF at a frame
    /// boundary: the capability probe of design §9.3.
    async fn read_file_frame<S: tokio::io::AsyncRead + Unpin>(
        driver: &mut EndpointDriver,
        stream: &mut S,
    ) -> Option<Vec<u8>> {
        let mut header = [0_u8; FRAME_HEADER_LEN];
        let mut read = 0;
        while read < FRAME_HEADER_LEN {
            let n = drive_drained(driver, stream.read(&mut header[read..]))
                .await
                .unwrap();
            if n == 0 {
                if read == 0 {
                    return None;
                }
                panic!("truncated file frame header");
            }
            read += n;
        }
        let (_, payload_len) = decode_frame_header(&header).unwrap();
        let mut payload = vec![0_u8; payload_len as usize];
        drive_drained(driver, stream.read_exact(&mut payload))
            .await
            .unwrap();
        let mut frame = header.to_vec();
        frame.extend_from_slice(&payload);
        Some(frame)
    }

    async fn write_file_frame<S: tokio::io::AsyncWrite + Unpin>(
        driver: &mut EndpointDriver,
        stream: &mut S,
        message: &FileTransferMessage<'_>,
    ) {
        drive_drained(driver, async {
            stream
                .write_all(message.encode().unwrap().as_slice())
                .await
                .unwrap();
            stream.flush().await.unwrap();
        })
        .await;
    }

    /// Serves the controller side of an upload: Ready, the Data blocks, and
    /// a verified Finish before Committed (design 11).
    async fn serve_upload<S: tokio::io::AsyncRead + AsyncWrite + Unpin>(
        driver: &mut EndpointDriver,
        stream: &mut S,
        destination: &str,
        file_name: &str,
        declared_size: u64,
        script: &HostScript,
    ) {
        assert_eq!(destination, script.upload_destination);
        assert_eq!(file_name, script.upload_file_name);
        write_file_frame(driver, stream, &FileTransferMessage::Ready).await;
        let mut received = Vec::new();
        loop {
            let Some(frame) = read_file_frame(driver, stream).await else {
                panic!("the upload ended before Finish");
            };
            match FileTransferMessage::decode_frame(&frame).unwrap() {
                FileTransferMessage::Data { bytes } => received.extend_from_slice(bytes),
                FileTransferMessage::Finish {
                    actual_size,
                    digest,
                } => {
                    assert_eq!(received.len() as u64, declared_size);
                    assert_eq!(actual_size, declared_size);
                    assert_eq!(digest, sha256_bytes(&received));
                    assert_eq!(received, script.upload_bytes);
                    write_file_frame(driver, stream, &FileTransferMessage::Committed).await;
                    return;
                }
                other => panic!("unexpected upload frame: {other:?}"),
            }
        }
    }

    /// Serves the controller side of a download: DownloadOffer, then the
    /// scripted Data blocks and Finish, then Committed (design 12).
    async fn serve_download<S: tokio::io::AsyncRead + AsyncWrite + Unpin>(
        driver: &mut EndpointDriver,
        stream: &mut S,
        source: &str,
        script: &HostScript,
    ) {
        assert_eq!(source, script.download_source);
        let file_name = script.download_file_name.clone();
        let declared_size = script.download_bytes.len() as u64;
        let offer = FileTransferMessage::DownloadOffer {
            file_name: &file_name,
            declared_size,
        };
        write_file_frame(driver, stream, &offer).await;
        let Some(frame) = read_file_frame(driver, stream).await else {
            panic!("the download ended before Ready");
        };
        assert_eq!(
            FileTransferMessage::decode_frame(&frame).unwrap(),
            FileTransferMessage::Ready
        );
        for chunk in script.download_bytes.chunks(MAX_DATA_LEN) {
            let header = encode_frame_header(TransferTag::Data.code(), chunk.len() as u32);
            drive_drained(driver, async {
                stream.write_all(&header).await.unwrap();
                stream.write_all(chunk).await.unwrap();
                stream.flush().await.unwrap();
            })
            .await;
        }
        let finish = FileTransferMessage::Finish {
            actual_size: script.download_bytes.len() as u64,
            digest: sha256_bytes(&script.download_bytes),
        };
        write_file_frame(driver, stream, &finish).await;
        let Some(frame) = read_file_frame(driver, stream).await else {
            panic!("the download ended before Committed");
        };
        assert_eq!(
            FileTransferMessage::decode_frame(&frame).unwrap(),
            FileTransferMessage::Committed
        );
    }

    /// Handles one incoming file substream: a pre-frame EOF is the
    /// side-effect-free capability probe; a frame is a real transfer.
    async fn serve_file_stream(
        driver: &mut EndpointDriver,
        stream: ApplicationStream,
        script: &HostScript,
    ) {
        let mut stream = stream.into_tokio();
        let mut header = [0_u8; FRAME_HEADER_LEN];
        let mut read = 0;
        while read < FRAME_HEADER_LEN {
            let n = drive_drained(driver, stream.read(&mut header[read..]))
                .await
                .unwrap();
            if n == 0 {
                if read == 0 {
                    // Capability probe (§9.3): closed without a message.
                    return;
                }
                panic!("truncated file frame header");
            }
            read += n;
        }
        let (_, payload_len) = decode_frame_header(&header).unwrap();
        let mut payload = vec![0_u8; payload_len as usize];
        drive_drained(driver, stream.read_exact(&mut payload))
            .await
            .unwrap();
        let mut frame = header.to_vec();
        frame.extend_from_slice(&payload);
        match FileTransferMessage::decode_frame(&frame).unwrap() {
            FileTransferMessage::UploadOpen {
                destination,
                file_name,
                declared_size,
            } => {
                serve_upload(
                    driver,
                    &mut stream,
                    destination,
                    file_name,
                    declared_size,
                    script,
                )
                .await
            }
            FileTransferMessage::DownloadOpen { source } => {
                serve_download(driver, &mut stream, source, script).await
            }
            other => panic!("unexpected first file frame: {other:?}"),
        }
    }

    /// Waits for the optional delayed-output dump trigger.
    async fn fire_dump_trigger(trigger: &mut Option<oneshot::Receiver<()>>) {
        match trigger.as_mut() {
            Some(receiver) => {
                let _ = receiver.await;
            }
            None => std::future::pending().await,
        }
    }

    /// Runs the scripted host through one full controller session: auth
    /// (with an optional Retry answer), the two terminal streams, the
    /// hello/Ready handshake, the terminal-data/control loop, the file
    /// substreams, and the scripted completion.
    #[allow(clippy::too_many_arguments)]
    async fn serve_scripted_host(
        driver: &mut EndpointDriver,
        auth_incoming: &mut IncomingApplicationStreams,
        data_incoming: &mut IncomingApplicationStreams,
        control_incoming: &mut IncomingApplicationStreams,
        file_incoming: &mut IncomingApplicationStreams,
        audit_incoming: Option<&mut IncomingApplicationStreams>,
        audit_root: Option<&Path>,
        locator: Locator,
        registration: &OpaqueRegistration,
        target: &PeerIdBytes,
        pake: &mut OpaquePake,
        script: &HostScript,
        ending: HostEnding,
        dump: Option<(Vec<u8>, oneshot::Receiver<()>)>,
    ) {
        // -- authentication: one Retry answer, then a full proceed
        // exchange; the controller reopens the substream for the retry.
        let (controller, auth) = drive_drained(driver, auth_incoming.next())
            .await
            .expect("the auth protocol registration ended");
        let mut auth = auth.into_tokio();
        if script.retry_auth_once {
            let retry = AuthServerResponse::retry(
                RetryAfter::from_millis(1_000).expect("frozen retry is valid"),
            )
            .encode();
            drive_drained(driver, async {
                auth.write_all(retry.as_slice()).await.unwrap();
                auth.flush().await.unwrap();
            })
            .await;
            drop(auth);
            let (_, second) = drive_drained(driver, auth_incoming.next())
                .await
                .expect("the second auth stream never arrived");
            let mut auth = second.into_tokio();
            serve_auth_exchange(
                driver,
                &mut auth,
                locator,
                registration,
                controller,
                target,
                pake,
            )
            .await;
        } else {
            serve_auth_exchange(
                driver,
                &mut auth,
                locator,
                registration,
                controller,
                target,
                pake,
            )
            .await;
        }

        // -- the two terminal streams and the hello/Ready handshake.
        let data = drive_drained(driver, data_incoming.next())
            .await
            .expect("the data protocol registration ended");
        let control = drive_drained(driver, control_incoming.next())
            .await
            .expect("the control protocol registration ended");
        let mut control = control.1.into_tokio();
        let hello = drive_drained(driver, read_terminal_hello(&mut control)).await;
        assert_eq!(hello.size(), TerminalSize::new(80, 24).unwrap());
        if ending == HostEnding::StallHandshake {
            tokio::time::sleep(Duration::from_secs(12)).await;
            return;
        }
        let mut audit = match audit_incoming {
            Some(incoming) => {
                let (audit_peer, audit_stream) = drive_drained(driver, incoming.next())
                    .await
                    .expect("the audit protocol registration ended");
                assert_eq!(audit_peer, controller);
                let digest = Digest32::new(Sha256::digest(hello.encode().as_slice()).into());
                let host_peer = driver.peer_id();
                let observer = drive_drained(
                    driver,
                    AuditObserver::establish(
                        audit_stream.into_tokio(),
                        AuditRole::Host,
                        controller,
                        host_peer,
                        crate::audit::observer::utc_start_seconds(),
                        digest,
                        audit_root.expect("enterprise host audit needs an isolated root"),
                        &mut OsSecureRandom,
                    ),
                )
                .await
                .unwrap();
                drive_drained(driver, observer.record_terminal_hello(digest))
                    .await
                    .unwrap();
                Some(observer)
            }
            None => None,
        };
        let data = data.1.into_tokio();
        let (mut data_read, mut data_write) = tokio::io::split(data);
        let (mut control_read, mut control_write) = tokio::io::split(control);
        drive_drained(driver, async {
            data_write.write_all(&TerminalReady::ENCODED).await.unwrap();
            data_write.flush().await.unwrap();
        })
        .await;
        if let Some(audit) = audit.as_ref() {
            drive_drained(driver, audit.record_terminal_ready())
                .await
                .unwrap();
            drive_drained(driver, audit.record_raw_output(script.output.as_slice()))
                .await
                .unwrap();
        }
        data_write
            .write_all(script.output.as_slice())
            .await
            .unwrap();
        data_write.flush().await.unwrap();
        if let Some(audit) = audit.as_ref() {
            drive_drained(
                driver,
                audit.record_send_outcome(
                    crate::audit::session::DIRECTION_HOST_TO_CTRL,
                    true,
                    script.output.len() as u64,
                ),
            )
            .await
            .unwrap();
        }
        if ending == HostEnding::AuditFailure {
            let audit = audit
                .as_ref()
                .expect("the audit-failure scenario requires enterprise audit");
            drive_drained(
                driver,
                audit.fail_closed(
                    Some(AuditErrorCode::AuditRecordWriteFailed),
                    AuditCloseReason::AuditFailure,
                ),
            )
            .await;
        }
        if ending == HostEnding::AuditStreamEnd {
            drop(audit.take());
        }
        if matches!(
            ending,
            HostEnding::AuditFailure | HostEnding::AuditStreamEnd
        ) {
            let mut buffer = [0_u8; 4096];
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    match drive_drained(driver, data_read.read(&mut buffer)).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            })
            .await
            .expect("the controller must close terminal data after audit failure");
            return;
        }
        match ending {
            HostEnding::CloseDataSilently => {
                let _ = data_write.shutdown().await;
                tokio::time::sleep(Duration::from_secs(6)).await;
                return;
            }
            // The stall keeps the session Active while the scenario drives
            // the controller.
            HostEnding::Stall => {}
            HostEnding::Complete
            | HostEnding::CheckpointThenComplete
            | HostEnding::ControllerDetach
            | HostEnding::ControllerInterrupt
            | HostEnding::ControllerDisplayFailure
            | HostEnding::StallHandshake
            | HostEnding::AuditFailure
            | HostEnding::AuditStreamEnd
            | HostEnding::AuditFinalizeStreamEnd => {}
        }

        // -- the terminal session loop: echo controller data input, record
        // resizes, serve file substreams, and (optionally) dump delayed
        // output bytes once the test triggers it.
        let (dump, mut dump_trigger) = match dump {
            Some((bytes, trigger)) => (Some(bytes), Some(trigger)),
            None => (None, None),
        };
        let mut dump_fired = false;
        let mut dump_sent = false;
        let mut pending_file: Option<(PeerId, ApplicationStream)> = None;
        let mut control_pending = Vec::new();
        let mut audit_frames = Box::pin(wait_for_audit_frame(audit.as_ref()));
        let mut data_buffer = [0_u8; 4096];
        let mut control_buffer = [0_u8; 16];
        let mut data_open = true;
        let mut control_open = true;
        loop {
            tokio::select! {
                _ = driver.next() => {}
                result = data_read.read(&mut data_buffer), if data_open => {
                    let read = match result {
                        Ok(read) => read,
                        Err(_) if matches!(ending, HostEnding::Stall) => return,
                        Err(error) => panic!("scripted terminal data read failed: {error}"),
                    };
                    if read == 0 {
                        if ending == HostEnding::ControllerDisplayFailure {
                            audit
                                .as_ref()
                                .unwrap()
                                .close_interrupted(AuditCloseReason::ConnectionLost)
                                .await;
                            return;
                        }
                        if matches!(ending, HostEnding::Stall) {
                            return;
                        }
                        if matches!(ending, HostEnding::ControllerDetach | HostEnding::ControllerInterrupt) {
                            data_open = false;
                            continue;
                        }
                        break;
                    }
                    script.recorded_input.lock().unwrap().extend_from_slice(&data_buffer[..read]);
                    if let Some(audit) = audit.as_ref() {
                        drive_drained(driver, audit.record_input(&data_buffer[..read])).await.unwrap();
                        drive_drained(driver, audit.record_pty_write_outcome(true, read as u64)).await.unwrap();
                        drive_drained(driver, audit.record_raw_output(&data_buffer[..read])).await.unwrap();
                    }
                    // The scripted host echoes the typed bytes back without
                    // a PTY.
                    data_write.write_all(&data_buffer[..read]).await.unwrap();
                    data_write.flush().await.unwrap();
                    if let Some(audit) = audit.as_ref() {
                        drive_drained(
                            driver,
                            audit.record_send_outcome(
                                crate::audit::session::DIRECTION_HOST_TO_CTRL,
                                true,
                                read as u64,
                            ),
                        ).await.unwrap();
                    }
                }
                result = control_read.read(&mut control_buffer), if control_open => {
                    let read = match result {
                        Ok(read) => read,
                        Err(_) if matches!(ending, HostEnding::Stall) => return,
                        Err(error) => panic!("scripted terminal control read failed: {error}"),
                    };
                    if read == 0 {
                        if ending == HostEnding::ControllerDisplayFailure {
                            audit
                                .as_ref()
                                .unwrap()
                                .close_interrupted(AuditCloseReason::ConnectionLost)
                                .await;
                            return;
                        }
                        if matches!(ending, HostEnding::Stall) {
                            return;
                        }
                        if matches!(ending, HostEnding::ControllerDetach | HostEnding::ControllerInterrupt) {
                            control_open = false;
                            continue;
                        }
                        break;
                    }
                    control_pending.extend_from_slice(&control_buffer[..read]);
                    while control_pending.len() >= CONTROL_LEN {
                        let frame: [u8; CONTROL_LEN] = control_pending
                            .drain(..CONTROL_LEN)
                            .collect::<Vec<_>>()
                            .try_into()
                            .unwrap();
                        let resize = TerminalResize::decode(&frame).unwrap();
                        if let Some(audit) = audit.as_ref() {
                            drive_drained(
                                driver,
                                audit.record_resize(
                                    crate::audit::session::DIRECTION_CTRL_TO_HOST,
                                    resize.size().columns(),
                                    resize.size().rows(),
                                ),
                            ).await.unwrap();
                        }
                        *script.resize.lock().unwrap() = Some(resize.size());
                    }
                }
                result = &mut audit_frames, if audit.is_some() => {
                    let audit = audit.as_ref().unwrap();
                    let Some(frame) = result.unwrap() else {
                        assert_eq!(ending, HostEnding::ControllerDisplayFailure);
                        audit.close_interrupted(AuditCloseReason::ConnectionLost).await;
                        return;
                    };
                    let event = drive_drained(driver, audit.handle_frame(&frame)).await.unwrap();
                    if let FrameEvent::Close(reason) = event {
                        if ending == HostEnding::ControllerDisplayFailure {
                            assert_eq!(reason, AuditCloseReason::ConnectionLost);
                            drive_drained(driver, audit.close_interrupted(reason)).await;
                        } else {
                            let expected = if ending == HostEnding::ControllerDetach {
                                AuditCloseReason::ControllerDetach
                            } else {
                                AuditCloseReason::LocalInterrupt
                            };
                            assert_eq!(reason, expected);
                            drive_drained(
                                driver,
                                audit.close_and_finalize(
                                    ManifestEnding::CloseReason(reason),
                                    false,
                                    CloseNoticeHandling::AlreadyReceived(reason),
                                ),
                            )
                            .await
                            .unwrap();
                        }
                        return;
                    }
                    audit_frames = Box::pin(wait_for_audit_frame(Some(audit)));
                }
                stream = file_incoming.next() => {
                    pending_file = Some(stream.expect("the file transfer registration ended"));
                }
                _ = fire_dump_trigger(&mut dump_trigger), if !dump_fired => {
                    dump_fired = true;
                }
            }
            if dump_fired && !dump_sent {
                dump_sent = true;
                let bytes = dump.as_ref().expect("a fired dump holds bytes");
                data_write.write_all(bytes).await.unwrap();
                data_write.flush().await.unwrap();
            }
            if let Some((_peer, stream)) = pending_file.take() {
                serve_file_stream(driver, stream, script).await;
            }
        }
        drop(audit_frames);

        // -- completion: exit code, data EOF, TerminalComplete, control
        // close; the controller returns the exit code.
        if let Some(audit) = audit.as_ref() {
            drive_drained(driver, audit.record_terminal_exit(script.exit_code as u8))
                .await
                .unwrap();
        }
        drive_drained(driver, async {
            control_write
                .write_all(&TerminalExit::new(script.exit_code).encode())
                .await
                .unwrap();
            control_write.flush().await.unwrap();
        })
        .await;
        let _ = data_write.shutdown().await;
        let mut complete = [0_u8; 1];
        drive_drained(driver, control_read.read_exact(&mut complete))
            .await
            .unwrap();
        assert_eq!(complete, TerminalComplete::ENCODED);
        if let Some(audit) = audit.as_ref() {
            drive_drained(driver, audit.record_terminal_complete())
                .await
                .unwrap();
        }
        let _ = control_write.shutdown().await;
        if ending == HostEnding::AuditFinalizeStreamEnd {
            drop(audit.take());
            return;
        }
        if let Some(audit) = audit.as_ref() {
            drive_drained(
                driver,
                audit.close_and_finalize(
                    ManifestEnding::ShellExit(script.exit_code as u8),
                    true,
                    CloseNoticeHandling::Receiver,
                ),
            )
            .await
            .unwrap();
        }
    }

    /// Registers the scripted host on the in-process relay: a real
    /// reservation, a real locator and an advertisement the controller's
    /// `ConnectionCode` can authenticate against.
    async fn register_scripted_host(
        relays: &EndpointRelaySet,
    ) -> (
        EndpointDriver,
        Libp2pApplicationStreams,
        Locator,
        OpaqueRegistration,
        PeerIdBytes,
        OpaquePake,
        ConnectionCode,
    ) {
        let (mut driver, mut streams) = build_endpoint(
            Keypair::generate_ed25519(),
            WssTransportConfig::client(None),
        )
        .unwrap();
        let relay_connection = connect_relay_with_retry(&mut driver, relays).await;
        let listener = driver.reserve(relay_connection.address()).unwrap();
        let lease = wait_for_reservation(&mut driver, relay_connection, listener)
            .await
            .unwrap();
        let locator = allocate_locator(&mut driver, &mut streams, lease.relay())
            .await
            .unwrap();
        let target = peer_id_bytes(driver.peer_id()).unwrap();
        let mut pake = OpaquePake;
        let code = ConnectionCode::generate(locator, &mut OsSecureRandom).unwrap();
        let registration = pake.register(&target, code.secret()).unwrap();
        (driver, streams, locator, registration, target, pake, code)
    }

    /// The controller-side configuration of one scenario: real identity,
    /// the in-process relay set, the host's generated code and a fixed
    /// terminal hello.
    fn controller_config(relays: &EndpointRelaySet, code: ConnectionCode) -> ControllerConfig {
        ControllerConfig::new(
            Keypair::generate_ed25519(),
            relays.clone(),
            WssTransportConfig::client(None),
            code,
            TerminalHello::new(
                TerminalSize::new(80, 24).unwrap(),
                TerminalValue::new("xterm").unwrap(),
                TerminalValue::new("truecolor").unwrap(),
            ),
        )
    }

    #[test]
    fn in_process_controller_session_authenticates_and_completes_with_file_transfers() {
        let _test_guard = crate::in_process_test_guard();
        // The combined controller, audit and transfer futures exceed the
        // default test-thread stack; the project pattern runs the scenario
        // on a 64 MiB stack thread.
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let local = tokio::task::LocalSet::new();
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let _permit = crate::IN_PROCESS_NETWORK_GUARD.acquire().await;
                    tokio::time::timeout(
                        Duration::from_secs(180),
                        local.run_until(async {
                            const EXIT_CODE: u32 = 23;
                            const SCRIPTED_OUTPUT: &[u8] = b"scripted-host-prompt> ";
                            const TYPED_ECHO: &[u8] = b"hello from the controller\n";

                            let port = available_tcp_port();
                            let relay_identity = Keypair::generate_ed25519();
                            let relay_address: EndpointRelayAddress = format!(
                                "/ip4/127.0.0.1/tcp/{port}/p2p/{}",
                                relay_identity.public().to_peer_id()
                            )
                            .parse()
                            .unwrap();
                            let relays =
                                EndpointRelaySet::new(vec![relay_address.clone()]).unwrap();
                            let relay = InProcessRelay::start(relay_identity, port);

                            let directory = tempdir().unwrap();
                            let upload_source = directory.path().join("upload-source.bin");
                            write_pattern_file(&upload_source, 96 * 1024);
                            let upload_bytes = fs::read(&upload_source).unwrap();
                            let upload_source_text = upload_source.to_str().unwrap().to_owned();
                            let upload_destination = "remote/upload/final.bin".to_owned();
                            let download_source = directory.path().join("download-source.bin");
                            write_pattern_file(&download_source, 64 * 1024);
                            let download_bytes = fs::read(&download_source).unwrap();
                            let download_target = directory.path().join("download-target");
                            fs::create_dir(&download_target).unwrap();
                            let download_target_text = download_target.to_str().unwrap().to_owned();
                            let download_remote_source = "remote/download/source.bin".to_owned();

                            let (
                                mut driver,
                                mut streams,
                                locator,
                                registration,
                                target,
                                mut pake,
                                code,
                            ) = register_scripted_host(&relays).await;
                            let mut auth_incoming = streams.accept(AUTH_PROTOCOL).unwrap();
                            let mut data_incoming = streams.accept(TERMINAL_DATA_PROTOCOL).unwrap();
                            let mut control_incoming =
                                streams.accept(TERMINAL_CONTROL_PROTOCOL).unwrap();
                            let mut file_incoming = streams.accept(FILE_TRANSFER_PROTOCOL).unwrap();

                            let recorded_input = Arc::new(Mutex::new(Vec::new()));
                            let resize = Arc::new(Mutex::new(None));
                            let host_script = HostScript {
                                exit_code: EXIT_CODE,
                                output: SCRIPTED_OUTPUT.to_vec(),
                                upload_destination: upload_destination.clone(),
                                upload_file_name: "upload-source.bin".to_owned(),
                                upload_bytes: upload_bytes.clone(),
                                download_source: download_remote_source.clone(),
                                download_file_name: "download-source.bin".to_owned(),
                                download_bytes: download_bytes.clone(),
                                recorded_input: Arc::clone(&recorded_input),
                                resize: Arc::clone(&resize),
                                retry_auth_once: true,
                            };

                            let mut controller_progress = RecordingProgress::default();
                            let config = controller_config(&relays, code);
                            let (mut script_input, frontend_input) = tokio::io::duplex(64 * 1024);
                            let (frontend_output, mut script_output) = tokio::io::duplex(64 * 1024);
                            let size = Rc::new(Cell::new((80_u16, 24_u16)));
                            let restored = Rc::new(Cell::new(false));
                            let frontend = SessionFrontend {
                                input: frontend_input,
                                output: frontend_output,
                                size: Rc::clone(&size),
                                restored: Rc::clone(&restored),
                            };
                            let cancellation = tokio_util::sync::CancellationToken::new();

                            let session = run_controller_session(
                                config,
                                frontend,
                                &mut controller_progress,
                                cancellation.clone(),
                            );
                            let host = serve_scripted_host(
                                &mut driver,
                                &mut auth_incoming,
                                &mut data_incoming,
                                &mut control_incoming,
                                &mut file_incoming,
                                None,
                                None,
                                locator,
                                &registration,
                                &target,
                                &mut pake,
                                &host_script,
                                HostEnding::Complete,
                                None,
                            );
                            let driver_script = async {
                                let mut seen =
                                    read_output_until(&mut script_output, SCRIPTED_OUTPUT).await;
                                // The scripted resize reaches the host on
                                // terminal-control. Set it here, while the session is in
                                // pass-through, so the pump detects it before any modal
                                // work can delay the resize arm.
                                size.set((100, 30));
                                tokio::time::timeout(Duration::from_secs(2), async {
                                    loop {
                                        if resize.lock().unwrap().is_some() {
                                            break;
                                        }
                                        tokio::time::sleep(Duration::from_millis(10)).await;
                                    }
                                })
                                .await
                                .expect("the resize pump must observe the new size");
                                script_input.write_all(&[0x1d, b'u']).await.unwrap();
                                script_input.flush().await.unwrap();
                                seen.extend(
                                    read_output_until(&mut script_output, b"local source:").await,
                                );
                                script_input
                                    .write_all(format!("{upload_source_text}\n").as_bytes())
                                    .await
                                    .unwrap();
                                script_input.flush().await.unwrap();
                                seen.extend(
                                    read_output_until(&mut script_output, b"remote destination")
                                        .await,
                                );
                                script_input
                                    .write_all(format!("{upload_destination}\n").as_bytes())
                                    .await
                                    .unwrap();
                                script_input.flush().await.unwrap();
                                seen.extend(
                                    read_output_until(&mut script_output, b"upload:").await,
                                );
                                seen.extend(
                                    read_output_until(&mut script_output, b"upload complete:")
                                        .await,
                                );

                                script_input.write_all(&[0x1d, b'd']).await.unwrap();
                                script_input.flush().await.unwrap();
                                seen.extend(
                                    read_output_until(&mut script_output, b"remote source:").await,
                                );
                                script_input
                                    .write_all(format!("{download_remote_source}\n").as_bytes())
                                    .await
                                    .unwrap();
                                script_input.flush().await.unwrap();
                                seen.extend(
                                    read_output_until(&mut script_output, b"local destination")
                                        .await,
                                );
                                script_input
                                    .write_all(format!("{download_target_text}\n").as_bytes())
                                    .await
                                    .unwrap();
                                script_input.flush().await.unwrap();
                                seen.extend(
                                    read_output_until(&mut script_output, b"download:").await,
                                );
                                seen.extend(
                                    read_output_until(&mut script_output, b"download complete:")
                                        .await,
                                );

                                script_input.write_all(TYPED_ECHO).await.unwrap();
                                script_input.flush().await.unwrap();
                                seen.extend(
                                    read_output_until(&mut script_output, TYPED_ECHO).await,
                                );

                                drop(script_input);
                                seen.extend(drain_output_until_closed(&mut script_output).await);
                                seen
                            };

                            let (session_result, (), seen) = tokio::join!(
                                Box::pin(session),
                                Box::pin(host),
                                Box::pin(driver_script)
                            );

                            assert_eq!(
                                session_result.unwrap(),
                                EXIT_CODE,
                                "the remote shell exit code must reach the controller"
                            );
                            assert!(restored.get(), "the raw-mode guard must be restored");
                            assert_eq!(
                                *resize.lock().unwrap(),
                                Some(TerminalSize::new(100, 30).unwrap()),
                                "the scripted resize must reach the host"
                            );
                            assert_eq!(
                                *recorded_input.lock().unwrap(),
                                TYPED_ECHO,
                                "only pass-through input must reach the remote terminal"
                            );
                            {
                                let stages = controller_progress.stages.lock().unwrap();
                                for stage in [
                                    ControllerStage::ConnectingRelay,
                                    ControllerStage::ResolvingHost,
                                    ControllerStage::EstablishingPath,
                                    ControllerStage::Authenticating,
                                    ControllerStage::StartingTerminal,
                                ] {
                                    assert!(
                                        stages.contains(&stage),
                                        "the session never reported {stage:?}: {stages:?}"
                                    );
                                }
                            }
                            let rendered = String::from_utf8_lossy(&seen);
                            assert!(rendered.contains("upload complete"), "{rendered:?}");
                            assert!(rendered.contains("download complete"), "{rendered:?}");
                            assert!(rendered.contains("scripted-host-prompt> "), "{rendered:?}");
                            let downloaded =
                                fs::read(download_target.join("download-source.bin")).unwrap();
                            assert_eq!(downloaded, download_bytes);

                            relay.stop().await;
                        }),
                    )
                    .await
                    .expect("the in-process controller session must finish");
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }

    fn run_enterprise_controller_case(ending: HostEnding) {
        let _test_guard = crate::in_process_test_guard();
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let _permit = crate::IN_PROCESS_NETWORK_GUARD.acquire().await;
                    let local = tokio::task::LocalSet::new();
                    tokio::time::timeout(
                        Duration::from_secs(120),
                        local.run_until(async {
                            const EXIT_CODE: u32 = 31;
                            const OUTPUT: &[u8] = b"enterprise-host-output> ";
                            const INPUT: &[u8] = b"enterprise controller input\n";

                            let port = available_tcp_port();
                            let relay_identity = Keypair::generate_ed25519();
                            let relay_address: EndpointRelayAddress = format!(
                                "/ip4/127.0.0.1/tcp/{port}/p2p/{}",
                                relay_identity.public().to_peer_id()
                            )
                            .parse()
                            .unwrap();
                            let relays =
                                EndpointRelaySet::new(vec![relay_address.clone()]).unwrap();
                            let relay = InProcessRelay::start(relay_identity, port);

                            let (
                                mut host_driver,
                                mut host_streams,
                                locator,
                                registration,
                                target,
                                mut host_pake,
                                code,
                            ) = register_scripted_host(&relays).await;
                            let mut auth_incoming = host_streams.accept(AUTH_PROTOCOL).unwrap();
                            let mut data_incoming =
                                host_streams.accept(TERMINAL_DATA_PROTOCOL).unwrap();
                            let mut control_incoming =
                                host_streams.accept(TERMINAL_CONTROL_PROTOCOL).unwrap();
                            let mut file_incoming =
                                host_streams.accept(FILE_TRANSFER_PROTOCOL).unwrap();
                            let mut audit_incoming = host_streams.accept(AUDIT_PROTOCOL).unwrap();
                            let host_audit_dir = tempdir().unwrap();
                            let host_audit_root = host_audit_dir.path().join("audit");

                            let recorded_input = Arc::new(Mutex::new(Vec::new()));
                            let resize = Arc::new(Mutex::new(None));
                            let host_script = HostScript {
                                exit_code: EXIT_CODE,
                                output: OUTPUT.to_vec(),
                                upload_destination: String::new(),
                                upload_file_name: String::new(),
                                upload_bytes: Vec::new(),
                                download_source: String::new(),
                                download_file_name: String::new(),
                                download_bytes: Vec::new(),
                                recorded_input: Arc::clone(&recorded_input),
                                resize,
                                retry_auth_once: false,
                            };

                            let (mut script_input, frontend_input) = tokio::io::duplex(64 * 1024);
                            let (frontend_output, mut script_output) = tokio::io::duplex(64 * 1024);
                            let restored = Rc::new(Cell::new(false));
                            let frontend = SessionFrontend {
                                input: frontend_input,
                                output: frontend_output,
                                size: Rc::new(Cell::new((80, 24))),
                                restored: Rc::clone(&restored),
                            };
                            let cancellation = tokio_util::sync::CancellationToken::new();
                            let controller_audit_dir = tempdir().unwrap();
                            let controller_done = Arc::new(tokio::sync::Notify::new());
                            let controller_done_signal = Arc::clone(&controller_done);

                            let controller = async {
                                let (mut driver, mut streams) = build_endpoint(
                                    Keypair::generate_ed25519(),
                                    WssTransportConfig::client(None),
                                )
                                .unwrap();
                                let relay_connection =
                                    connect_relay_with_retry(&mut driver, &relays).await;
                                let host = resolve_peer(
                                    &mut driver,
                                    &mut streams,
                                    &relay_connection,
                                    code.locator(),
                                    ResolveDeadline::controller(),
                                )
                                .await
                                .unwrap();
                                let mut progress = NoopProgress;
                                let mut prepared = prepare_controller(
                                    driver,
                                    streams,
                                    relay_connection.address(),
                                    ResolvedTarget::new(host, RelayAccessMode::Enterprise),
                                    &code,
                                    DirectUpgradePolicy::Disabled,
                                    &mut progress,
                                )
                                .await
                                .unwrap();
                                prepared.audit_root_override =
                                    Some(controller_audit_dir.path().join("audit"));
                                let hello = TerminalHello::new(
                                    TerminalSize::new(80, 24).unwrap(),
                                    TerminalValue::new("xterm").unwrap(),
                                    TerminalValue::new("truecolor").unwrap(),
                                );
                                let result = tokio::time::timeout(
                                    Duration::from_secs(60),
                                    run_terminal(
                                        prepared,
                                        hello,
                                        frontend,
                                        &mut progress,
                                        &cancellation,
                                    ),
                                )
                                .await
                                .expect("the controller terminal stage must finish");
                                controller_done_signal.notify_one();
                                result
                            };
                            let host = serve_scripted_host(
                                &mut host_driver,
                                &mut auth_incoming,
                                &mut data_incoming,
                                &mut control_incoming,
                                &mut file_incoming,
                                Some(&mut audit_incoming),
                                Some(&host_audit_root),
                                locator,
                                &registration,
                                &target,
                                &mut host_pake,
                                &host_script,
                                ending,
                                None,
                            );
                            let interaction = async {
                                if ending == HostEnding::ControllerDisplayFailure {
                                    drop(script_output);
                                    controller_done.notified().await;
                                    drop(script_input);
                                    return Vec::new();
                                }
                                let mut seen = if matches!(
                                    ending,
                                    HostEnding::AuditFailure | HostEnding::AuditStreamEnd
                                ) {
                                    Vec::new()
                                } else {
                                    read_output_until(&mut script_output, OUTPUT).await
                                };
                                if matches!(
                                    ending,
                                    HostEnding::Complete | HostEnding::CheckpointThenComplete
                                ) {
                                    if ending == HostEnding::CheckpointThenComplete {
                                        tokio::time::sleep(Duration::from_millis(1_500)).await;
                                    }
                                    script_input.write_all(INPUT).await.unwrap();
                                    script_input.flush().await.unwrap();
                                    seen.extend(read_output_until(&mut script_output, INPUT).await);
                                } else if ending == HostEnding::AuditFinalizeStreamEnd {
                                    script_input.write_all(INPUT).await.unwrap();
                                    script_input.flush().await.unwrap();
                                    seen.extend(read_output_until(&mut script_output, INPUT).await);
                                } else if ending == HostEnding::ControllerDetach {
                                    script_input.write_all(b"\x1d.").await.unwrap();
                                    script_input.flush().await.unwrap();
                                } else if ending == HostEnding::ControllerInterrupt {
                                    cancellation.cancel();
                                }
                                drop(script_input);
                                seen.extend(drain_output_until_closed(&mut script_output).await);
                                seen
                            };

                            let (controller_result, (), seen) = tokio::join!(
                                Box::pin(controller),
                                Box::pin(host),
                                Box::pin(interaction),
                            );
                            match ending {
                                HostEnding::Complete | HostEnding::CheckpointThenComplete => {
                                    assert_eq!(controller_result.unwrap(), EXIT_CODE);
                                }
                                HostEnding::AuditFailure | HostEnding::AuditStreamEnd => {
                                    assert!(
                                        matches!(
                                            &controller_result,
                                            Err(ControllerError::Audit(AuditError::FailedClosed))
                                        ),
                                        "unexpected controller result: {controller_result:?}"
                                    );
                                }
                                HostEnding::ControllerDetach => {
                                    assert!(matches!(
                                        controller_result,
                                        Err(ControllerError::Interrupted)
                                    ));
                                }
                                HostEnding::ControllerInterrupt => {
                                    assert!(matches!(
                                        controller_result,
                                        Err(ControllerError::Interrupted)
                                    ));
                                }
                                HostEnding::ControllerDisplayFailure => {
                                    assert!(matches!(
                                        controller_result,
                                        Err(ControllerError::SessionAndTerminalOutput { .. })
                                            | Err(ControllerError::Io(_))
                                    ));
                                }
                                HostEnding::AuditFinalizeStreamEnd => {
                                    assert!(
                                        matches!(
                                            &controller_result,
                                            Err(ControllerError::Audit(_))
                                        ),
                                        "unexpected controller result: {controller_result:?}"
                                    );
                                }
                                _ => unreachable!("unsupported enterprise controller case"),
                            }
                            assert!(restored.get(), "the display must be restored");
                            if matches!(
                                ending,
                                HostEnding::Complete
                                    | HostEnding::CheckpointThenComplete
                                    | HostEnding::AuditFinalizeStreamEnd
                            ) {
                                assert_eq!(*recorded_input.lock().unwrap(), INPUT);
                            } else {
                                assert!(recorded_input.lock().unwrap().is_empty());
                            }
                            if !matches!(
                                ending,
                                HostEnding::AuditFailure
                                    | HostEnding::AuditStreamEnd
                                    | HostEnding::ControllerDisplayFailure
                            ) {
                                assert!(seen.windows(OUTPUT.len()).any(|window| window == OUTPUT));
                            }
                            if matches!(
                                ending,
                                HostEnding::Complete
                                    | HostEnding::CheckpointThenComplete
                                    | HostEnding::AuditFinalizeStreamEnd
                            ) {
                                assert!(seen.windows(INPUT.len()).any(|window| window == INPUT));
                            }

                            relay.stop().await;
                        }),
                    )
                    .await
                    .expect("the enterprise controller session must finish");
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn in_process_enterprise_controller_runs_the_complete_audited_terminal() {
        run_enterprise_controller_case(HostEnding::Complete);
    }

    #[test]
    fn in_process_enterprise_controller_checkpoints_while_active() {
        run_enterprise_controller_case(HostEnding::CheckpointThenComplete);
    }

    #[test]
    fn in_process_enterprise_controller_detaches_and_finalizes_both_audits() {
        run_enterprise_controller_case(HostEnding::ControllerDetach);
    }

    #[test]
    fn in_process_enterprise_controller_interrupts_and_finalizes_both_audits() {
        run_enterprise_controller_case(HostEnding::ControllerInterrupt);
    }

    #[test]
    fn in_process_enterprise_controller_closes_after_local_display_failure() {
        run_enterprise_controller_case(HostEnding::ControllerDisplayFailure);
    }

    #[test]
    fn in_process_enterprise_controller_rejects_incomplete_audit_finalization() {
        run_enterprise_controller_case(HostEnding::AuditFinalizeStreamEnd);
    }

    #[test]
    fn in_process_enterprise_controller_fails_closed_with_the_peer_audit() {
        run_enterprise_controller_case(HostEnding::AuditFailure);
    }

    #[test]
    fn in_process_enterprise_controller_fails_closed_when_the_audit_stream_ends() {
        run_enterprise_controller_case(HostEnding::AuditStreamEnd);
    }

    #[test]
    fn in_process_controller_session_ends_cleanly_on_local_input_eof() {
        let _test_guard = crate::in_process_test_guard();
        // The combined controller and audit futures exceed the default test
        // thread stack; the project pattern runs the scenario on a 64 MiB
        // stack thread.
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let _permit = crate::IN_PROCESS_NETWORK_GUARD.acquire().await;
                    let local = tokio::task::LocalSet::new();
                    tokio::time::timeout(
                        Duration::from_secs(120),
                        local.run_until(async {
                            const EXIT_CODE: u32 = 7;
                            const SCRIPTED_OUTPUT: &[u8] = b"scripted-prompt> ";
                            const TYPED_ECHO: &[u8] = b"ls -la\n";

                            let port = available_tcp_port();
                            let relay_identity = Keypair::generate_ed25519();
                            let relay_address: EndpointRelayAddress = format!(
                                "/ip4/127.0.0.1/tcp/{port}/p2p/{}",
                                relay_identity.public().to_peer_id()
                            )
                            .parse()
                            .unwrap();
                            let relays =
                                EndpointRelaySet::new(vec![relay_address.clone()]).unwrap();
                            let relay = InProcessRelay::start(relay_identity, port);

                            let (
                                mut driver,
                                mut streams,
                                locator,
                                registration,
                                target,
                                mut pake,
                                code,
                            ) = register_scripted_host(&relays).await;
                            let mut auth_incoming = streams.accept(AUTH_PROTOCOL).unwrap();
                            let mut data_incoming = streams.accept(TERMINAL_DATA_PROTOCOL).unwrap();
                            let mut control_incoming =
                                streams.accept(TERMINAL_CONTROL_PROTOCOL).unwrap();
                            let mut file_incoming = streams.accept(FILE_TRANSFER_PROTOCOL).unwrap();

                            let recorded_input = Arc::new(Mutex::new(Vec::new()));
                            let resize = Arc::new(Mutex::new(None));
                            let host_script = HostScript {
                                exit_code: EXIT_CODE,
                                output: SCRIPTED_OUTPUT.to_vec(),
                                upload_destination: String::new(),
                                upload_file_name: String::new(),
                                upload_bytes: Vec::new(),
                                download_source: String::new(),
                                download_file_name: String::new(),
                                download_bytes: Vec::new(),
                                recorded_input: Arc::clone(&recorded_input),
                                resize: Arc::clone(&resize),
                                retry_auth_once: false,
                            };

                            let config = controller_config(&relays, code);
                            let (mut script_input, frontend_input) = tokio::io::duplex(64 * 1024);
                            let (frontend_output, mut script_output) = tokio::io::duplex(64 * 1024);
                            let size = Rc::new(Cell::new((80_u16, 24_u16)));
                            let restored = Rc::new(Cell::new(false));
                            let frontend = SessionFrontend {
                                input: frontend_input,
                                output: frontend_output,
                                size: Rc::clone(&size),
                                restored: Rc::clone(&restored),
                            };
                            let cancellation = tokio_util::sync::CancellationToken::new();

                            let mut progress = NoopProgress;
                            let session = run_controller_session(
                                config,
                                frontend,
                                &mut progress,
                                cancellation,
                            );
                            let host = serve_scripted_host(
                                &mut driver,
                                &mut auth_incoming,
                                &mut data_incoming,
                                &mut control_incoming,
                                &mut file_incoming,
                                None,
                                None,
                                locator,
                                &registration,
                                &target,
                                &mut pake,
                                &host_script,
                                HostEnding::Complete,
                                None,
                            );
                            // TEMPORARY DIAGNOSTIC driver: tolerant, prints what it saw.
                            let tolerant_driver = async {
                                let mut text = Vec::new();
                                let mut buffer = [0_u8; 8192];
                                let deadline =
                                    tokio::time::Instant::now() + Duration::from_secs(60);
                                loop {
                                    if !text
                                        .windows(SCRIPTED_OUTPUT.len())
                                        .any(|w| w == SCRIPTED_OUTPUT)
                                    {
                                        match tokio::time::timeout(
                                            Duration::from_millis(500),
                                            script_output.read(&mut buffer),
                                        )
                                        .await
                                        {
                                            Ok(Ok(0)) => break,
                                            Ok(Ok(n)) => text.extend_from_slice(&buffer[..n]),
                                            Ok(Err(_)) => break,
                                            Err(_) => {}
                                        }
                                    } else {
                                        script_input.write_all(TYPED_ECHO).await.unwrap();
                                        script_input.flush().await.unwrap();
                                        drop(script_input);
                                        if let Ok(more) = tokio::time::timeout(
                                            Duration::from_secs(5),
                                            drain_output_until_closed(&mut script_output),
                                        )
                                        .await
                                        {
                                            text.extend_from_slice(&more);
                                        }
                                        break;
                                    }
                                    assert!(
                                        tokio::time::Instant::now() < deadline,
                                        "the tolerant driver timed out: {}",
                                        String::from_utf8_lossy(&text)
                                    );
                                }
                                text
                            };

                            let (session_result, (), _) = tokio::join!(
                                Box::pin(session),
                                Box::pin(host),
                                Box::pin(tolerant_driver),
                            );
                            assert_eq!(session_result.unwrap(), EXIT_CODE);
                            assert!(restored.get(), "the raw-mode guard must be restored");
                            assert_eq!(
                                *recorded_input.lock().unwrap(),
                                TYPED_ECHO,
                                "the typed line must reach the remote terminal"
                            );

                            relay.stop().await;
                        }),
                    )
                    .await
                    .expect("the in-process EOF scenario must finish");
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn in_process_controller_session_times_out_when_the_remote_completion_is_silent() {
        let _test_guard = crate::in_process_test_guard();
        // The combined controller and scripted-host futures exceed the
        // default test-thread stack; the project pattern runs the scenario
        // on a 64 MiB stack thread.
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let local = tokio::task::LocalSet::new();
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let _permit = crate::IN_PROCESS_NETWORK_GUARD.acquire().await;
                    tokio::time::timeout(
                        Duration::from_secs(90),
                        local.run_until(async {
                            let port = available_tcp_port();
                            let relay_identity = Keypair::generate_ed25519();
                            let relay_address: EndpointRelayAddress = format!(
                                "/ip4/127.0.0.1/tcp/{port}/p2p/{}",
                                relay_identity.public().to_peer_id()
                            )
                            .parse()
                            .unwrap();
                            let relays =
                                EndpointRelaySet::new(vec![relay_address.clone()]).unwrap();
                            let relay = InProcessRelay::start(relay_identity, port);

                            let (
                                mut driver,
                                mut streams,
                                locator,
                                registration,
                                target,
                                mut pake,
                                code,
                            ) = register_scripted_host(&relays).await;
                            let mut auth_incoming = streams.accept(AUTH_PROTOCOL).unwrap();
                            let mut data_incoming = streams.accept(TERMINAL_DATA_PROTOCOL).unwrap();
                            let mut control_incoming =
                                streams.accept(TERMINAL_CONTROL_PROTOCOL).unwrap();
                            let mut file_incoming = streams.accept(FILE_TRANSFER_PROTOCOL).unwrap();

                            let recorded_input = Arc::new(Mutex::new(Vec::new()));
                            let resize = Arc::new(Mutex::new(None));
                            let host_script = HostScript {
                                exit_code: 0,
                                output: Vec::new(),
                                upload_destination: String::new(),
                                upload_file_name: String::new(),
                                upload_bytes: Vec::new(),
                                download_source: String::new(),
                                download_file_name: String::new(),
                                download_bytes: Vec::new(),
                                recorded_input: Arc::clone(&recorded_input),
                                resize: Arc::clone(&resize),
                                retry_auth_once: false,
                            };

                            let config = controller_config(&relays, code);
                            let (script_input, frontend_input) = tokio::io::duplex(64 * 1024);
                            let (frontend_output, script_output) = tokio::io::duplex(64 * 1024);
                            let size = Rc::new(Cell::new((80_u16, 24_u16)));
                            let restored = Rc::new(Cell::new(false));
                            let frontend = SessionFrontend {
                                input: frontend_input,
                                output: frontend_output,
                                size: Rc::clone(&size),
                                restored: Rc::clone(&restored),
                            };
                            let cancellation = tokio_util::sync::CancellationToken::new();

                            let mut progress = NoopProgress;
                            let session = run_controller_session(
                                config,
                                frontend,
                                &mut progress,
                                cancellation,
                            );
                            let host = serve_scripted_host(
                                &mut driver,
                                &mut auth_incoming,
                                &mut data_incoming,
                                &mut control_incoming,
                                &mut file_incoming,
                                None,
                                None,
                                locator,
                                &registration,
                                &target,
                                &mut pake,
                                &host_script,
                                HostEnding::CloseDataSilently,
                                None,
                            );
                            let driver_script = async {
                                // The local input stays open, so only the remote-completion
                                // deadline can end the session (§REMOTE_COMPLETION_TIMEOUT).
                                let _keep_input = script_input;
                                let _keep_output = script_output;
                                tokio::time::sleep(Duration::from_secs(8)).await;
                            };

                            let (session_result, (), _) = tokio::join!(
                                Box::pin(session),
                                Box::pin(host),
                                Box::pin(driver_script)
                            );
                            assert!(matches!(
                                session_result,
                                Err(ControllerError::RemoteCompletionTimeout)
                            ));

                            relay.stop().await;
                        }),
                    )
                    .await
                    .expect("the in-process silent-remote scenario must finish");
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }
    #[test]
    fn in_process_controller_session_times_out_when_terminal_ready_never_arrives() {
        let _test_guard = crate::in_process_test_guard();
        // The combined controller and audit futures exceed the default
        // test-thread stack; the project pattern runs the scenario on a
        // 64 MiB stack thread.
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let local = tokio::task::LocalSet::new();
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let _permit = crate::IN_PROCESS_NETWORK_GUARD.acquire().await;
                    tokio::time::timeout(
                        Duration::from_secs(90),
                        local.run_until(async {
                            let port = available_tcp_port();
                            let relay_identity = Keypair::generate_ed25519();
                            let relay_address: EndpointRelayAddress = format!(
                                "/ip4/127.0.0.1/tcp/{port}/p2p/{}",
                                relay_identity.public().to_peer_id()
                            )
                            .parse()
                            .unwrap();
                            let relays =
                                EndpointRelaySet::new(vec![relay_address.clone()]).unwrap();
                            let relay = InProcessRelay::start(relay_identity, port);

                            let (
                                mut driver,
                                mut streams,
                                locator,
                                registration,
                                target,
                                mut pake,
                                code,
                            ) = register_scripted_host(&relays).await;
                            let mut auth_incoming = streams.accept(AUTH_PROTOCOL).unwrap();
                            let mut data_incoming = streams.accept(TERMINAL_DATA_PROTOCOL).unwrap();
                            let mut control_incoming =
                                streams.accept(TERMINAL_CONTROL_PROTOCOL).unwrap();
                            let mut file_incoming = streams.accept(FILE_TRANSFER_PROTOCOL).unwrap();

                            let recorded_input = Arc::new(Mutex::new(Vec::new()));
                            let resize = Arc::new(Mutex::new(None));
                            let host_script = HostScript {
                                exit_code: 0,
                                output: Vec::new(),
                                upload_destination: String::new(),
                                upload_file_name: String::new(),
                                upload_bytes: Vec::new(),
                                download_source: String::new(),
                                download_file_name: String::new(),
                                download_bytes: Vec::new(),
                                recorded_input: Arc::clone(&recorded_input),
                                resize: Arc::clone(&resize),
                                retry_auth_once: false,
                            };

                            let config = controller_config(&relays, code);
                            let (script_input, frontend_input) = tokio::io::duplex(64 * 1024);
                            let (frontend_output, script_output) = tokio::io::duplex(64 * 1024);
                            let size = Rc::new(Cell::new((80_u16, 24_u16)));
                            let restored = Rc::new(Cell::new(false));
                            let frontend = SessionFrontend {
                                input: frontend_input,
                                output: frontend_output,
                                size: Rc::clone(&size),
                                restored: Rc::clone(&restored),
                            };
                            let cancellation = tokio_util::sync::CancellationToken::new();

                            let mut progress = NoopProgress;
                            let session = run_controller_session(
                                config,
                                frontend,
                                &mut progress,
                                cancellation,
                            );
                            let host = serve_scripted_host(
                                &mut driver,
                                &mut auth_incoming,
                                &mut data_incoming,
                                &mut control_incoming,
                                &mut file_incoming,
                                None,
                                None,
                                locator,
                                &registration,
                                &target,
                                &mut pake,
                                &host_script,
                                HostEnding::StallHandshake,
                                None,
                            );
                            let driver_script = async {
                                let _keep_input = script_input;
                                let _keep_output = script_output;
                                tokio::time::sleep(Duration::from_secs(11)).await;
                            };

                            let (session_result, (), _) = tokio::join!(
                                Box::pin(session),
                                Box::pin(host),
                                Box::pin(driver_script)
                            );
                            assert!(matches!(session_result, Err(ControllerError::Timeout)));

                            relay.stop().await;
                        }),
                    )
                    .await
                    .expect("the in-process handshake-timeout scenario must finish");
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }
    #[test]
    fn in_process_controller_session_stops_on_cancellation_mid_session() {
        let _test_guard = crate::in_process_test_guard();
        // This scenario's joined futures (the controller pump, the scripted
        // host and the driver script) exceed the default test-thread stack,
        // so it runs on a dedicated thread with a large stack. The
        // serialization permit is acquired inside the runtime so it is held
        // across the scenario's awaits.
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let local = tokio::task::LocalSet::new();
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let _permit = crate::IN_PROCESS_NETWORK_GUARD.acquire().await;
                    tokio::time::timeout(
                        Duration::from_secs(90),
                        local.run_until(async {
                            let port = available_tcp_port();
                            let relay_identity = Keypair::generate_ed25519();
                            let relay_address: EndpointRelayAddress = format!(
                                "/ip4/127.0.0.1/tcp/{port}/p2p/{}",
                                relay_identity.public().to_peer_id()
                            )
                            .parse()
                            .unwrap();
                            let relays =
                                EndpointRelaySet::new(vec![relay_address.clone()]).unwrap();
                            let relay = InProcessRelay::start(relay_identity, port);

                            let (
                                mut driver,
                                mut streams,
                                locator,
                                registration,
                                target,
                                mut pake,
                                code,
                            ) = register_scripted_host(&relays).await;
                            let mut auth_incoming = streams.accept(AUTH_PROTOCOL).unwrap();
                            let mut data_incoming = streams.accept(TERMINAL_DATA_PROTOCOL).unwrap();
                            let mut control_incoming =
                                streams.accept(TERMINAL_CONTROL_PROTOCOL).unwrap();
                            let mut file_incoming = streams.accept(FILE_TRANSFER_PROTOCOL).unwrap();

                            let recorded_input = Arc::new(Mutex::new(Vec::new()));
                            let resize = Arc::new(Mutex::new(None));
                            let host_script = HostScript {
                                exit_code: 0,
                                output: b"session-ready\n".to_vec(),
                                upload_destination: String::new(),
                                upload_file_name: String::new(),
                                upload_bytes: Vec::new(),
                                download_source: String::new(),
                                download_file_name: String::new(),
                                download_bytes: Vec::new(),
                                recorded_input: Arc::clone(&recorded_input),
                                resize: Arc::clone(&resize),
                                retry_auth_once: false,
                            };

                            let config = controller_config(&relays, code);
                            let (script_input, frontend_input) = tokio::io::duplex(64 * 1024);
                            let (frontend_output, mut script_output) = tokio::io::duplex(64 * 1024);
                            let size = Rc::new(Cell::new((80_u16, 24_u16)));
                            let restored = Rc::new(Cell::new(false));
                            let frontend = SessionFrontend {
                                input: frontend_input,
                                output: frontend_output,
                                size: Rc::clone(&size),
                                restored: Rc::clone(&restored),
                            };
                            let cancellation = tokio_util::sync::CancellationToken::new();

                            let mut progress = NoopProgress;
                            let session = run_controller_session(
                                config,
                                frontend,
                                &mut progress,
                                cancellation.clone(),
                            );
                            let host = serve_scripted_host(
                                &mut driver,
                                &mut auth_incoming,
                                &mut data_incoming,
                                &mut control_incoming,
                                &mut file_incoming,
                                None,
                                None,
                                locator,
                                &registration,
                                &target,
                                &mut pake,
                                &host_script,
                                HostEnding::Stall,
                                None,
                            );
                            let driver_script = async {
                                let _keep_input = script_input;
                                // Wait until the session is fully established
                                // (the host wrote its scripted output after
                                // TerminalReady), then cancel: the pump's
                                // cancellation branch ends the session.
                                let _ready =
                                    read_output_until(&mut script_output, b"session-ready").await;
                                tokio::time::sleep(Duration::from_millis(500)).await;
                                cancellation.cancel();
                                tokio::time::sleep(Duration::from_secs(5)).await;
                            };

                            let (session_result, (), _) = tokio::join!(
                                Box::pin(session),
                                Box::pin(host),
                                Box::pin(driver_script)
                            );
                            assert!(
                                matches!(session_result, Err(ControllerError::Interrupted)),
                                "unexpected session result: {session_result:?}"
                            );

                            relay.stop().await;
                        }),
                    )
                    .await
                    .expect("the in-process cancellation scenario must finish");
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn in_process_controller_prompt_overflow_aborts_the_modal_and_keeps_the_session() {
        let _test_guard = crate::in_process_test_guard();
        // This scenario's joined futures (the 300 KiB dump, the session, the
        // scripted host and the driver script) exceed the default test-thread
        // stack, so it runs on a dedicated thread with a large stack. The
        // serialization permit is acquired inside the runtime so it is held
        // across the scenario's awaits.
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let local = tokio::task::LocalSet::new();
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let _permit = crate::IN_PROCESS_NETWORK_GUARD.acquire().await;
                    tokio::time::timeout(
                        Duration::from_secs(120),
                        local.run_until(async {
                            const EXIT_CODE: u32 = 11;

                            let port = available_tcp_port();
                            let relay_identity = Keypair::generate_ed25519();
                            let relay_address: EndpointRelayAddress = format!(
                                "/ip4/127.0.0.1/tcp/{port}/p2p/{}",
                                relay_identity.public().to_peer_id()
                            )
                            .parse()
                            .unwrap();
                            let relays =
                                EndpointRelaySet::new(vec![relay_address.clone()]).unwrap();
                            let relay = InProcessRelay::start(relay_identity, port);

                            let (
                                mut driver,
                                mut streams,
                                locator,
                                registration,
                                target,
                                mut pake,
                                code,
                            ) = register_scripted_host(&relays).await;
                            let mut auth_incoming = streams.accept(AUTH_PROTOCOL).unwrap();
                            let mut data_incoming = streams.accept(TERMINAL_DATA_PROTOCOL).unwrap();
                            let mut control_incoming =
                                streams.accept(TERMINAL_CONTROL_PROTOCOL).unwrap();
                            let mut file_incoming = streams.accept(FILE_TRANSFER_PROTOCOL).unwrap();

                            let recorded_input = Arc::new(Mutex::new(Vec::new()));
                            let resize = Arc::new(Mutex::new(None));
                            let host_script = HostScript {
                                exit_code: EXIT_CODE,
                                output: b"session-ready\n".to_vec(),
                                upload_destination: String::new(),
                                upload_file_name: String::new(),
                                upload_bytes: Vec::new(),
                                download_source: String::new(),
                                download_file_name: String::new(),
                                download_bytes: Vec::new(),
                                recorded_input: Arc::clone(&recorded_input),
                                resize: Arc::clone(&resize),
                                retry_auth_once: false,
                            };

                            // More than the 256 KiB delayed-output cap (§7.4.5), triggered
                            // only while the upload prompt is active.
                            let mut dump = b"[DUMP-START]".to_vec();
                            let mut remaining = 300 * 1024 - dump.len();
                            let mut offset = 0_u64;
                            while remaining > 0 {
                                let n = remaining.min(4096);
                                for i in 0..n {
                                    dump.push(pattern_byte(offset + i as u64));
                                }
                                remaining -= n;
                                offset += n as u64;
                            }
                            let (dump_tx, dump_rx) = oneshot::channel();

                            let config = controller_config(&relays, code);
                            let (mut script_input, frontend_input) = tokio::io::duplex(64 * 1024);
                            let (frontend_output, mut script_output) = tokio::io::duplex(64 * 1024);
                            let size = Rc::new(Cell::new((80_u16, 24_u16)));
                            let restored = Rc::new(Cell::new(false));
                            let frontend = SessionFrontend {
                                input: frontend_input,
                                output: frontend_output,
                                size: Rc::clone(&size),
                                restored: Rc::clone(&restored),
                            };
                            let cancellation = tokio_util::sync::CancellationToken::new();

                            let mut progress = NoopProgress;
                            let session = run_controller_session(
                                config,
                                frontend,
                                &mut progress,
                                cancellation,
                            );
                            let host = serve_scripted_host(
                                &mut driver,
                                &mut auth_incoming,
                                &mut data_incoming,
                                &mut control_incoming,
                                &mut file_incoming,
                                None,
                                None,
                                locator,
                                &registration,
                                &target,
                                &mut pake,
                                &host_script,
                                HostEnding::Complete,
                                Some((dump, dump_rx)),
                            );
                            let driver_script = async {
                                let mut seen =
                                    read_output_until(&mut script_output, b"session-ready").await;
                                script_input.write_all(&[0x1d, b'u']).await.unwrap();
                                script_input.flush().await.unwrap();
                                seen.extend(
                                    read_output_until(&mut script_output, b"local source:").await,
                                );
                                // The prompt is active now; flood the delayed buffer.
                                let _ = dump_tx.send(());
                                seen.extend(
                                    read_output_until(&mut script_output, b"[DUMP-START]").await,
                                );
                                drop(script_input);
                                seen.extend(drain_output_until_closed(&mut script_output).await);
                                seen
                            };

                            let (session_result, (), seen) = tokio::join!(
                                Box::pin(session),
                                Box::pin(host),
                                Box::pin(driver_script)
                            );
                            assert_eq!(session_result.unwrap(), EXIT_CODE);
                            let rendered = String::from_utf8_lossy(&seen);
                            assert!(
                                rendered.contains("[DUMP-START]"),
                                "the overflow flush must reach the display"
                            );
                            assert!(
                                !rendered.contains("upload complete"),
                                "the overflow must abort the operation before any transfer"
                            );
                            assert!(
                                !rendered.contains("upload:"),
                                "the overflow must abort the operation before the status line"
                            );

                            relay.stop().await;
                        }),
                    )
                    .await
                    .expect("the in-process delayed-overflow scenario must finish");
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
