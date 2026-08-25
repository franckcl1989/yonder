#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use clap::{Parser, Subcommand, ValueEnum};
use serde::Deserialize;
use std::convert::Infallible;
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{IsTerminal as _, Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
use tracing_subscriber::filter::LevelFilter;
use yon::controller::{
    ControllerConfig, ControllerError, ControllerStage, local_terminal_hello,
    run_controller_with_progress,
};
use yon::host::{HostConfig, HostError, HostStage, run_host_with_progress};
use yon::network::RelayAccessMode;
use yon::progress::OperationProgress;
use yon::protocol::RelayProtocolError;
use yonder_config::{
    Application, ConfigLoader, ConfigurationError, ConfigurationKey, ConfigurationSchema,
    ConfigurationValues, LayeredConfigLoader,
};
use yonder_core::wire::audit::AuditRole;
use yonder_core::{CodeError, ConnectionCode, OsSecureRandom, write_error_report};
use yonder_net::{
    AddressError, EndpointRelayAddress, EndpointRelaySet, NetworkBuildError, WSS_CERTIFICATE_LIMIT,
    WssTransportConfig, WssTrustAnchors, generate_identity,
};
use zeroize::Zeroizing;

const MAX_CA_DOCUMENT: u64 = 1024 * 1024;
const MAX_CODE_TEXT: usize = 19;
const RUNTIME_STACK_SIZE: usize = 32 * 1024 * 1024;
const RUNTIME_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const RELAYS_KEY: ConfigurationKey = ConfigurationKey::new("relays");
const WSS_CA_KEY: ConfigurationKey = ConfigurationKey::new("wss_ca");
const WSS_CA_DER_KEY: ConfigurationKey = ConfigurationKey::new("wss_ca_der");
const ACCESS_MODE_KEY: ConfigurationKey = ConfigurationKey::new("access_mode");
const ENDPOINT_SCHEMA: ConfigurationSchema = ConfigurationSchema::new(
    Application::Yon,
    &[RELAYS_KEY, WSS_CA_KEY, WSS_CA_DER_KEY],
    &[ACCESS_MODE_KEY],
    &[WSS_CA_KEY, WSS_CA_DER_KEY],
);

#[derive(Debug, Parser)]
#[command(name = "yon", version, about)]
struct Cli {
    /// Diagnostic verbosity. Interactive diagnostics require --log-file or stderr redirection.
    #[arg(long, value_enum, default_value_t = LogLevel::Error, global = true)]
    log_level: LogLevel,
    /// Append detailed diagnostics to this file, keeping terminal interaction clean.
    #[arg(long, value_name = "PATH", global = true)]
    log_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Advertise this user's current shell as a single-use remote terminal.
    Host,
    /// Connect this terminal to an advertised host.
    ///
    /// In an interactive session, press Ctrl+] followed by `.` to disconnect locally.
    /// Press Ctrl+] twice to send one literal Ctrl+] to the remote shell.
    Connect {
        /// Single-use connection code. Omit it for a hidden prompt that avoids shell history.
        #[arg(value_name = "CODE")]
        code: Option<ConnectionCodeArgument>,
    },
    /// Inspect and validate endpoint configuration.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Verify or safely replay enterprise session audit files offline.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
}

impl Command {
    const fn uses_terminal_ui(&self) -> bool {
        matches!(
            self,
            Self::Host
                | Self::Connect { .. }
                | Self::Audit {
                    command: AuditCommand::Replay { .. }
                }
        )
    }
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Load and validate the effective endpoint configuration.
    Check,
    /// Show configuration sources in increasing precedence order.
    Sources,
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Verify one audit record or a bilateral record pair.
    Verify {
        #[arg(value_name = "LOCAL_FILE")]
        local_file: PathBuf,
        #[arg(value_name = "PEER_FILE")]
        peer_file: Option<PathBuf>,
    },
    /// Replay a controller display timeline through a safe virtual terminal.
    Replay {
        #[arg(value_name = "CONTROLLER_FILE")]
        controller_file: PathBuf,
        #[arg(value_name = "PEER_FILE")]
        peer_file: Option<PathBuf>,
    },
}

#[derive(Clone)]
struct ConnectionCodeArgument(Arc<Zeroizing<String>>);

impl ConnectionCodeArgument {
    fn into_code(self) -> Result<ConnectionCode, AppError> {
        Arc::try_unwrap(self.0)
            .map_err(|_| AppError::SharedConnectionCode)?
            .parse()
            .map_err(connection_code_input_error)
    }
}

impl FromStr for ConnectionCodeArgument {
    type Err = Infallible;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Ok(Self(Arc::new(Zeroizing::new(input.to_owned()))))
    }
}

impl std::fmt::Debug for ConnectionCodeArgument {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConnectionCodeArgument([REDACTED])")
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointSettings {
    relays: Vec<String>,
    wss_ca: Option<ConfigurationValues<PathBuf>>,
    wss_ca_der: Option<ConfigurationValues<PathBuf>>,
    #[serde(default)]
    access_mode: ConfiguredAccessMode,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ConfiguredAccessMode {
    #[default]
    Standard,
    Enterprise,
}

impl From<ConfiguredAccessMode> for RelayAccessMode {
    fn from(value: ConfiguredAccessMode) -> Self {
        match value {
            ConfiguredAccessMode::Standard => Self::Standard,
            ConfiguredAccessMode::Enterprise => Self::Enterprise,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    const fn filter(self) -> LevelFilter {
        match self {
            Self::Off => LevelFilter::OFF,
            Self::Error => LevelFilter::ERROR,
            Self::Warn => LevelFilter::WARN,
            Self::Info => LevelFilter::INFO,
            Self::Debug => LevelFilter::DEBUG,
            Self::Trace => LevelFilter::TRACE,
        }
    }

    const fn requires_redirect_for_terminal(self) -> bool {
        matches!(self, Self::Warn | Self::Info | Self::Debug | Self::Trace)
    }
}

#[derive(Debug, Error)]
enum AppError {
    #[error("failed to initialize diagnostics")]
    Diagnostics,
    #[error(
        "--log-level warn/info/debug/trace requires --log-file <PATH> or stderr redirection while terminal progress is active (for example: yon --log-level debug --log-file yon-debug.log connect)"
    )]
    InteractiveDiagnostics,
    #[error("failed to open diagnostic log file {path}: {source}")]
    LogFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("the relay address set is invalid: {0}")]
    RelaySet(#[from] AddressError),
    #[error("failed to load endpoint configuration: {0}")]
    Configuration(#[from] ConfigurationError),
    #[error("failed to report configuration status")]
    ConfigurationOutput(#[source] std::io::Error),
    #[error("failed to create an ephemeral endpoint identity: {0}")]
    Identity(#[from] NetworkBuildError),
    #[error("the WSS trust configuration is invalid: {0}")]
    WssConfiguration(#[source] NetworkBuildError),
    #[error("wss_ca and the legacy wss_ca_der setting cannot both be configured")]
    ConflictingWssCa,
    #[error("wss_ca must contain between 1 and {WSS_CERTIFICATE_LIMIT} document paths")]
    InvalidWssCaDocumentCount,
    #[error("failed to read the WSS CA document {path}: {source}")]
    CaRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("the WSS CA document exceeds the 1 MiB limit: {0}")]
    CaTooLarge(PathBuf),
    #[error("failed to construct the async runtime: {0}")]
    Runtime(#[source] std::io::Error),
    #[error("failed to start the endpoint runtime thread: {0}")]
    RuntimeThread(#[source] std::io::Error),
    #[error("the endpoint runtime thread panicked")]
    RuntimePanicked,
    #[error("the parsed connection code retained an unexpected shared owner")]
    SharedConnectionCode,
    #[error("failed to read the connection code")]
    CodeRead(#[source] std::io::Error),
    #[error("connection code is invalid or expired")]
    ConnectionCodeInput,
    #[error("connection code is invalid or expired")]
    ConnectionCodeUnavailable,
    #[error(transparent)]
    Host(#[from] HostError),
    #[error(transparent)]
    Controller(#[from] ControllerError),
    #[error(transparent)]
    AuditVerify(#[from] yon::audit::verify::VerifyError),
    #[error(transparent)]
    AuditReplay(#[from] yon::audit::replay::ReplayError),
    #[error("failed to report the audit result")]
    AuditOutput(#[source] std::io::Error),
}

fn main() -> ExitCode {
    process_result(run(Cli::parse()))
}

fn process_result(result: Result<u32, AppError>) -> ExitCode {
    match result {
        Ok(code) => process_exit(code),
        Err(
            AppError::Controller(ControllerError::Interrupted)
            | AppError::Host(HostError::Interrupted),
        ) => {
            begin_terminal_report_line();
            ExitCode::from(130)
        }
        Err(error) => {
            if matches!(&error, AppError::Controller(_) | AppError::Host(_)) {
                begin_terminal_report_line();
            }
            let _ = write_error_report(&mut std::io::stderr().lock(), &error);
            if matches!(error, AppError::ConnectionCodeInput) {
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn run(cli: Cli) -> Result<u32, AppError> {
    let stderr_is_terminal = std::io::stderr().is_terminal();
    let terminal_output = command_uses_terminal_ui(
        &cli.command,
        std::io::stdout().is_terminal(),
        stderr_is_terminal,
    );
    validate_diagnostic_output(cli.log_level, terminal_output, cli.log_file.is_some())?;
    let diagnostics_share_terminal = terminal_output && cli.log_file.is_none();
    match cli.log_file.as_deref() {
        Some(path) => initialize_diagnostics(
            cli.log_level,
            diagnostics_share_terminal,
            open_diagnostic_log(path)?,
            false,
        )?,
        None => initialize_diagnostics(
            cli.log_level,
            diagnostics_share_terminal,
            std::io::stderr,
            stderr_is_terminal,
        )?,
    }

    std::thread::Builder::new()
        .name("yon-runtime".to_owned())
        .stack_size(RUNTIME_STACK_SIZE)
        .spawn(move || run_command(cli.command))
        .map_err(AppError::RuntimeThread)?
        .join()
        .map_err(|_| AppError::RuntimePanicked)?
}

fn validate_diagnostic_output(
    level: LogLevel,
    terminal_output: bool,
    has_log_file: bool,
) -> Result<(), AppError> {
    if terminal_output && !has_log_file && level.requires_redirect_for_terminal() {
        return Err(AppError::InteractiveDiagnostics);
    }
    Ok(())
}

fn command_uses_terminal_ui(
    command: &Command,
    stdout_is_terminal: bool,
    stderr_is_terminal: bool,
) -> bool {
    command.uses_terminal_ui() && stdout_is_terminal && stderr_is_terminal
}

fn diagnostic_filter(level: LogLevel, terminal_output: bool) -> LevelFilter {
    if terminal_output {
        LevelFilter::OFF
    } else {
        level.filter()
    }
}

fn initialize_diagnostics<W>(
    level: LogLevel,
    diagnostics_share_terminal: bool,
    writer: W,
    ansi: bool,
) -> Result<(), AppError>
where
    W: for<'writer> tracing_subscriber::fmt::MakeWriter<'writer> + Send + Sync + 'static,
{
    tracing_subscriber::fmt()
        .with_max_level(diagnostic_filter(level, diagnostics_share_terminal))
        .with_target(false)
        .with_writer(writer)
        .with_ansi(ansi)
        .compact()
        .try_init()
        .map_err(|_| AppError::Diagnostics)
}

fn open_diagnostic_log(path: &Path) -> Result<File, AppError> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|source| AppError::LogFile {
            path: path.to_path_buf(),
            source,
        })
}

fn run_command(command: Command) -> Result<u32, AppError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(4)
        .build()
        .map_err(AppError::Runtime)?;
    let result = execute_command(&runtime, command);
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_TIMEOUT);
    result
}

fn execute_command(runtime: &tokio::runtime::Runtime, command: Command) -> Result<u32, AppError> {
    match command {
        Command::Host => {
            let (relays, wss, access) = endpoint_config()?;
            let identity = generate_identity(&mut OsSecureRandom)?;
            let terminal_output = std::io::stdout().is_terminal()
                && std::io::stderr().is_terminal()
                && terminal_supports_progress(std::env::var_os("TERM").as_deref());
            let mut progress = TerminalProgress::new(std::io::stderr(), terminal_output);
            runtime
                .block_on(run_host_with_progress(
                    HostConfig::new(identity, relays, wss, access),
                    &mut progress,
                ))
                .map_err(AppError::from)
        }
        Command::Connect { code } => {
            let (relays, wss, access) = endpoint_config()?;
            let code = code.map_or_else(read_connection_code, ConnectionCodeArgument::into_code)?;
            let terminal = local_terminal_hello()?;
            let identity = generate_identity(&mut OsSecureRandom)?;
            let terminal_output = std::io::stdout().is_terminal()
                && std::io::stderr().is_terminal()
                && terminal_supports_progress(std::env::var_os("TERM").as_deref());
            let mut progress = TerminalProgress::new(std::io::stderr(), terminal_output);
            runtime
                .block_on(run_controller_with_progress(
                    ControllerConfig::new(identity, relays, wss, code, terminal, access),
                    &mut progress,
                ))
                .map_err(map_controller_error)
        }
        Command::Config { command } => match command {
            ConfigCommand::Check => {
                endpoint_config()?;
                writeln!(std::io::stdout().lock(), "Configuration is valid.")
                    .map_err(AppError::ConfigurationOutput)?;
                Ok(0)
            }
            ConfigCommand::Sources => report_configuration_sources(),
        },
        Command::Audit { command } => match command {
            AuditCommand::Verify {
                local_file,
                peer_file,
            } => run_audit_verify(&local_file, peer_file.as_deref()),
            AuditCommand::Replay {
                controller_file,
                peer_file,
            } => run_audit_replay(&controller_file, peer_file.as_deref()),
        },
    }
}

fn run_audit_verify(local_file: &Path, peer_file: Option<&Path>) -> Result<u32, AppError> {
    let report = yon::audit::verify::verify_files(
        local_file,
        peer_file,
        &yon::audit::verify::PlatformAnchorLookup,
    )?;
    print_verification_report(&report)?;
    Ok(report.state.exit_code())
}

fn run_audit_replay(controller_file: &Path, peer_file: Option<&Path>) -> Result<u32, AppError> {
    let result = yon::audit::replay::replay_session(&yon::audit::replay::ReplayConfig {
        controller_path: controller_file.to_path_buf(),
        peer_path: peer_file.map(Path::to_path_buf),
    })?;
    match result {
        yon::audit::replay::ReplayResult::Replayed(report) => {
            print_replay_report(&report)?;
            Ok(if report.interrupted {
                130
            } else {
                report.state.exit_code()
            })
        }
        yon::audit::replay::ReplayResult::Refused { state, reason } => {
            writeln!(
                std::io::stderr().lock(),
                "audit replay refused: {} ({reason})",
                state.name()
            )
            .map_err(AppError::AuditOutput)?;
            Ok(state.exit_code())
        }
    }
}

fn print_verification_report(
    report: &yon::audit::verify::VerificationReport,
) -> Result<(), AppError> {
    let mut output = std::io::stdout().lock();
    write_verification_report(&mut output, report)
}

fn write_verification_report(
    output: &mut impl std::io::Write,
    report: &yon::audit::verify::VerificationReport,
) -> Result<(), AppError> {
    if let Some(session_id) = &report.session_id {
        writeln!(output, "session: {}", hex_digest(session_id.as_bytes()))
            .map_err(AppError::AuditOutput)?;
    }
    for file in [&report.controller, &report.host].into_iter().flatten() {
        let role = match file.role {
            AuditRole::Controller => "controller",
            AuditRole::Host => "host",
        };
        writeln!(
            output,
            "{role}: {} finalized={} shared-events=[{} {} {} {}] local-events={}",
            file.path.display(),
            file.finalized,
            file.shared_counts[0],
            file.shared_counts[1],
            file.shared_counts[2],
            file.shared_counts[3],
            file.local_event_count,
        )
        .map_err(AppError::AuditOutput)?;
        if file.truncated_tail {
            writeln!(output, "{role}: truncated tail; verified prefix retained")
                .map_err(AppError::AuditOutput)?;
        }
    }
    writeln!(output, "verification: {}", report.state.name()).map_err(AppError::AuditOutput)?;
    if let Some(reason) = report.reason {
        writeln!(output, "reason: {reason}").map_err(AppError::AuditOutput)?;
    }
    if report.anchor.identity_matched || report.anchor.ledger_continuous {
        writeln!(
            output,
            "anchor: identity-matched={} ledger-continuous={}",
            report.anchor.identity_matched, report.anchor.ledger_continuous
        )
        .map_err(AppError::AuditOutput)?;
    }
    Ok(())
}

fn print_replay_report(report: &yon::audit::replay::ReplayReport) -> Result<(), AppError> {
    let mut output = std::io::stdout().lock();
    write_replay_report(&mut output, report)
}

fn write_replay_report(
    output: &mut impl std::io::Write,
    report: &yon::audit::replay::ReplayReport,
) -> Result<(), AppError> {
    writeln!(output, "verification: {}", report.state.name()).map_err(AppError::AuditOutput)?;
    if report.unpaired {
        writeln!(
            output,
            "warning: no peer file was provided; bilateral consistency is not certified"
        )
        .map_err(AppError::AuditOutput)?;
    }
    writeln!(
        output,
        "display: {} records, {} bytes; final screen: {}x{}",
        report.display_records, report.display_bytes, report.final_screen.0, report.final_screen.1
    )
    .map_err(AppError::AuditOutput)?;
    if report.filtered.total() > 0 {
        writeln!(
            output,
            "filtered controls: title={} clipboard={} resize={} unhandled={}",
            report.filtered.title,
            report.filtered.clipboard,
            report.filtered.resize_request,
            report.filtered.unhandled
        )
        .map_err(AppError::AuditOutput)?;
    }
    if report.bells > 0 {
        writeln!(output, "suppressed bells: {}", report.bells).map_err(AppError::AuditOutput)?;
    }
    if report.interrupted {
        writeln!(output, "replay stopped by Ctrl+C").map_err(AppError::AuditOutput)?;
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn connection_code_input_error(error: CodeError) -> AppError {
    tracing::debug!(%error, "connection code input was rejected");
    AppError::ConnectionCodeInput
}

fn map_controller_error(error: ControllerError) -> AppError {
    if matches!(
        &error,
        ControllerError::Pake(_) | ControllerError::Relay(RelayProtocolError::Unavailable)
    ) {
        tracing::debug!(%error, "connection code was rejected by the remote endpoint");
        AppError::ConnectionCodeUnavailable
    } else {
        AppError::Controller(error)
    }
}

fn report_configuration_sources() -> Result<u32, AppError> {
    let loader = LayeredConfigLoader::system(ENDPOINT_SCHEMA);
    let locations = loader.locations()?;
    locations
        .inspect()?
        .write_to(&mut std::io::stdout().lock())
        .map_err(AppError::ConfigurationOutput)?;
    Ok(0)
}

enum TerminalColumns {
    System,
    #[cfg(test)]
    Fixed(usize),
    #[cfg(test)]
    Scripted(std::collections::VecDeque<Result<usize, std::io::ErrorKind>>),
}

impl TerminalColumns {
    fn read(&mut self) -> std::io::Result<usize> {
        match self {
            Self::System => crossterm::terminal::size().map(|(columns, _)| usize::from(columns)),
            #[cfg(test)]
            Self::Fixed(columns) => Ok(*columns),
            #[cfg(test)]
            Self::Scripted(results) => results
                .pop_front()
                .unwrap_or(Err(std::io::ErrorKind::Other))
                .map_err(std::io::Error::from),
        }
    }
}

struct TerminalProgress<W: std::io::Write> {
    writer: W,
    columns: TerminalColumns,
    enabled: bool,
    visible: bool,
    line_capacity: usize,
    frame: usize,
}

impl<W: std::io::Write> TerminalProgress<W> {
    const fn new(writer: W, enabled: bool) -> Self {
        Self {
            writer,
            columns: TerminalColumns::System,
            enabled,
            visible: false,
            line_capacity: 0,
            frame: 0,
        }
    }

    #[cfg(test)]
    const fn with_columns(writer: W, enabled: bool, columns: usize) -> Self {
        Self {
            writer,
            columns: TerminalColumns::Fixed(columns),
            enabled,
            visible: false,
            line_capacity: 0,
            frame: 0,
        }
    }

    #[cfg(test)]
    fn with_scripted_columns(
        writer: W,
        enabled: bool,
        results: impl IntoIterator<Item = Result<usize, std::io::ErrorKind>>,
    ) -> Self {
        Self {
            writer,
            columns: TerminalColumns::Scripted(results.into_iter().collect()),
            enabled,
            visible: false,
            line_capacity: 0,
            frame: 0,
        }
    }

    fn render(&mut self, message: &str) {
        if !self.enabled {
            return;
        }
        debug_assert!(message.is_ascii());
        let Ok(columns) = self.columns.read() else {
            if self.visible {
                let _ = self.writer.write_all(b"\r\n");
                let _ = self.writer.flush();
            }
            self.enabled = false;
            self.visible = false;
            return;
        };
        self.line_capacity = columns.saturating_sub(1);
        if self.line_capacity < 8 {
            self.clear_line();
            self.enabled = false;
            return;
        }
        let result = (|| {
            crossterm::queue!(
                &mut self.writer,
                crossterm::cursor::MoveToColumn(0),
                crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine)
            )?;
            const FRAMES: &[u8; 4] = b"|/-\\";
            write!(
                self.writer,
                "{} ",
                char::from(FRAMES[self.frame % FRAMES.len()])
            )?;
            let message_capacity = self.line_capacity.saturating_sub(2);
            self.writer
                .write_all(&message.as_bytes()[..message.len().min(message_capacity)])?;
            self.writer.flush()
        })();
        if result.is_ok() {
            self.visible = true;
            self.frame = self.frame.wrapping_add(1);
        } else {
            self.enabled = false;
            self.visible = false;
        }
    }

    fn clear_line(&mut self) {
        if !self.enabled || !self.visible {
            return;
        }
        let result = (|| {
            crossterm::queue!(
                &mut self.writer,
                crossterm::cursor::MoveToColumn(0),
                crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine)
            )?;
            self.writer.flush()
        })();
        self.visible = false;
        if result.is_err() {
            self.enabled = false;
        }
    }
}

impl<W: std::io::Write> OperationProgress<ControllerStage> for TerminalProgress<W> {
    fn update(&mut self, stage: ControllerStage) {
        let message = match stage {
            ControllerStage::ConnectingRelay => "Connecting to relay...",
            ControllerStage::ResolvingHost => "Finding remote host...",
            ControllerStage::WaitingForEnterpriseAuthorization => {
                "Waiting for enterprise authorization..."
            }
            ControllerStage::EstablishingPath => "Establishing the best available path...",
            ControllerStage::RelayFallback => "Direct path unavailable; switching to relay...",
            ControllerStage::Authenticating => "Authenticating remote host...",
            ControllerStage::StartingTerminal => "Starting remote terminal...",
        };
        self.render(message);
    }

    fn clear(&mut self) {
        self.clear_line();
    }
}

impl<W: std::io::Write> OperationProgress<HostStage> for TerminalProgress<W> {
    fn update(&mut self, stage: HostStage) {
        let message = match stage {
            HostStage::ConnectingRelay => "Connecting to relay...",
            HostStage::ReservingRelay => "Reserving relay capacity...",
            HostStage::RegisteringHost => "Registering remote host...",
            HostStage::WaitingForController => "Waiting for controller...",
            HostStage::ReconnectingRelay => "Relay unavailable; reconnecting...",
            HostStage::AuthenticatingController => "Authenticating controller...",
            HostStage::StartingTerminal => "Starting remote terminal...",
            HostStage::TerminalActive => "Remote terminal active.",
        };
        self.render(message);
    }

    fn clear(&mut self) {
        self.clear_line();
    }
}

impl<W: std::io::Write> Drop for TerminalProgress<W> {
    fn drop(&mut self) {
        self.clear_line();
    }
}

fn terminal_supports_progress(term: Option<&OsStr>) -> bool {
    term.and_then(OsStr::to_str)
        .is_none_or(|value| !value.eq_ignore_ascii_case("dumb"))
}

fn read_connection_code() -> Result<ConnectionCode, AppError> {
    if std::io::stdin().is_terminal() {
        let input = Zeroizing::new(
            rpassword::prompt_password("Connection code: ").map_err(AppError::CodeRead)?,
        );
        input.parse().map_err(connection_code_input_error)
    } else {
        read_connection_code_from(&mut std::io::stdin().lock())
    }
}

fn read_connection_code_from(reader: &mut impl Read) -> Result<ConnectionCode, AppError> {
    let mut text = Zeroizing::new([0_u8; MAX_CODE_TEXT + 2]);
    let mut len = 0;
    loop {
        if len == text.len() {
            return Err(AppError::ConnectionCodeInput);
        }
        if reader
            .read(&mut text[len..=len])
            .map_err(AppError::CodeRead)?
            == 0
            || text[len] == b'\n'
        {
            break;
        }
        len += 1;
    }
    if len > 0 && text[len - 1] == b'\r' {
        len -= 1;
    }
    if len > MAX_CODE_TEXT {
        return Err(AppError::ConnectionCodeInput);
    }
    let text = std::str::from_utf8(&text[..len]).map_err(|_| AppError::ConnectionCodeInput)?;
    text.parse().map_err(connection_code_input_error)
}

fn endpoint_config() -> Result<(EndpointRelaySet, WssTransportConfig, RelayAccessMode), AppError> {
    endpoint_config_with(&LayeredConfigLoader::system(ENDPOINT_SCHEMA))
}

fn endpoint_config_with(
    loader: &impl ConfigLoader<EndpointSettings>,
) -> Result<(EndpointRelaySet, WssTransportConfig, RelayAccessMode), AppError> {
    let loaded = loader.load()?;
    let ca_paths = match (&loaded.value().wss_ca, &loaded.value().wss_ca_der) {
        (Some(paths), Some(_))
            if loaded.compare_source_precedence(WSS_CA_KEY, WSS_CA_DER_KEY)
                == Some(std::cmp::Ordering::Greater) =>
        {
            Some((WSS_CA_KEY, paths.as_slice()))
        }
        (Some(_), Some(paths))
            if loaded.compare_source_precedence(WSS_CA_KEY, WSS_CA_DER_KEY)
                == Some(std::cmp::Ordering::Less) =>
        {
            Some((WSS_CA_DER_KEY, paths.as_slice()))
        }
        (Some(_), Some(_)) => return Err(AppError::ConflictingWssCa),
        (Some(paths), None) => Some((WSS_CA_KEY, paths.as_slice())),
        (None, Some(paths)) => Some((WSS_CA_DER_KEY, paths.as_slice())),
        (None, None) => None,
    };
    if ca_paths.is_some_and(|(_, paths)| !(1..=WSS_CERTIFICATE_LIMIT).contains(&paths.len())) {
        return Err(AppError::InvalidWssCaDocumentCount);
    }
    let relay_addresses = loaded
        .value()
        .relays
        .iter()
        .map(|address| address.parse::<EndpointRelayAddress>())
        .collect::<Result<Vec<_>, _>>()?;
    let relays = EndpointRelaySet::new(relay_addresses)?;
    let ca_documents = ca_paths
        .into_iter()
        .flat_map(|(key, paths)| paths.iter().map(move |path| (key, path)))
        .map(|(key, path)| {
            let path = loaded.resolve_path(key, path)?;
            read_ca(&path)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let trust =
        WssTrustAnchors::from_documents(ca_documents).map_err(AppError::WssConfiguration)?;
    let wss = WssTransportConfig::client_with_trust(trust);
    wss.validate_tls_material()
        .map_err(AppError::WssConfiguration)?;
    Ok((relays, wss, loaded.value().access_mode.into()))
}

fn read_ca(path: &Path) -> Result<Vec<u8>, AppError> {
    let file = File::open(path).map_err(|source| AppError::CaRead {
        path: path.to_path_buf(),
        source,
    })?;
    let reported_len = file
        .metadata()
        .map_err(|source| AppError::CaRead {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    read_ca_document(file, reported_len, path)
}

fn read_ca_document(
    reader: impl Read,
    reported_len: u64,
    path: &Path,
) -> Result<Vec<u8>, AppError> {
    if reported_len > MAX_CA_DOCUMENT {
        return Err(AppError::CaTooLarge(path.to_path_buf()));
    }
    let mut bytes = Vec::new();
    let mut bounded = reader.take(MAX_CA_DOCUMENT + 1);
    bounded
        .read_to_end(&mut bytes)
        .map_err(|source| AppError::CaRead {
            path: path.to_path_buf(),
            source,
        })?;
    if bytes.len() as u64 > MAX_CA_DOCUMENT {
        return Err(AppError::CaTooLarge(path.to_path_buf()));
    }
    Ok(bytes)
}

fn portable_process_exit(code: u32) -> Result<ExitCode, u32> {
    u8::try_from(code).map(ExitCode::from).map_err(|_| code)
}

fn process_exit(code: u32) -> ExitCode {
    match portable_process_exit(code) {
        Ok(exit) => exit,
        Err(remote_exit_code) => {
            begin_terminal_report_line();
            let _ = write_remote_exit_warning(&mut std::io::stderr().lock(), remote_exit_code);
            ExitCode::FAILURE
        }
    }
}

fn begin_terminal_report_line() {
    if std::io::stdout().is_terminal() && std::io::stderr().is_terminal() {
        let _ = write!(std::io::stderr().lock(), "\r\n");
    }
}

fn write_remote_exit_warning(output: &mut impl std::io::Write, code: u32) -> std::io::Result<()> {
    writeln!(
        output,
        "warning: remote exit code {code} exceeds the portable process range; returning 1"
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        AppError, AuditCommand, Cli, Command, ConfigCommand, ConnectionCodeArgument,
        ENDPOINT_SCHEMA, LevelFilter, LogLevel, RUNTIME_SHUTDOWN_TIMEOUT, TerminalProgress,
        command_uses_terminal_ui, diagnostic_filter, endpoint_config_with, execute_command,
        hex_digest, map_controller_error, open_diagnostic_log, portable_process_exit,
        process_result, read_ca, read_ca_document, read_connection_code_from, run,
        terminal_supports_progress, validate_diagnostic_output, write_remote_exit_warning,
        write_replay_report, write_verification_report,
    };
    use clap::Parser;
    use std::cell::Cell;
    use std::ffi::OsString;
    use std::fs;
    use std::io::{self, Cursor, Read, Write};
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use yon::controller::ControllerStage;
    use yon::host::HostStage;
    use yon::network::RelayAccessMode;
    use yon::progress::OperationProgress as _;
    use yonder_config::{ConfigurationLocationError, ConfigurationSources, LayeredConfigLoader};
    use yonder_net::Keypair;

    const TEST_CA_DER: &[u8] = include_bytes!("../tests/fixtures/localhost-test-ca.der");

    #[test]
    fn configuration_driven_cli_shape_parses() {
        let host = Cli::try_parse_from(["yon", "host"]).unwrap();
        assert!(matches!(host.command, Command::Host));
        assert!(matches!(host.log_level, LogLevel::Error));
        assert!(host.log_file.is_none());

        let connect = Cli::try_parse_from(["yon", "connect", "0000-0000-0000-0000"]).unwrap();
        assert!(matches!(connect.command, Command::Connect { .. }));

        let prompted = Cli::try_parse_from(["yon", "connect"]).unwrap();
        assert!(matches!(prompted.command, Command::Connect { code: None }));
        let checked = Cli::try_parse_from(["yon", "config", "check"]).unwrap();
        assert!(matches!(
            checked.command,
            Command::Config {
                command: ConfigCommand::Check
            }
        ));
        let verified = Cli::try_parse_from(["yon", "audit", "verify", "local.yonaudit"]).unwrap();
        assert!(matches!(
            verified.command,
            Command::Audit {
                command: AuditCommand::Verify {
                    peer_file: None,
                    ..
                }
            }
        ));
        let replayed = Cli::try_parse_from([
            "yon",
            "audit",
            "replay",
            "controller.yonaudit",
            "host.yonaudit",
        ])
        .unwrap();
        assert!(matches!(
            replayed.command,
            Command::Audit {
                command: AuditCommand::Replay {
                    peer_file: Some(_),
                    ..
                }
            }
        ));
        let logged = Cli::try_parse_from([
            "yon",
            "--log-level",
            "debug",
            "--log-file",
            "diagnostics.log",
            "host",
        ])
        .unwrap();
        assert!(matches!(logged.log_level, LogLevel::Debug));
        assert_eq!(logged.log_file, Some(PathBuf::from("diagnostics.log")));
        assert!(Cli::try_parse_from(["yon", "host", "--relay", "ignored"]).is_err());
    }

    #[test]
    fn cli_help_snapshots_expose_the_complete_user_workflow() {
        let top = Cli::try_parse_from(["yon", "--help"])
            .unwrap_err()
            .to_string();
        assert_eq!(
            top,
            concat!(
                "Peer-to-peer remote terminal client and host\n\n",
                "Usage: yon [OPTIONS] <COMMAND>\n\n",
                "Commands:\n",
                "  host     Advertise this user's current shell as a single-use remote terminal\n",
                "  connect  Connect this terminal to an advertised host\n",
                "  config   Inspect and validate endpoint configuration\n",
                "  audit    Verify or safely replay enterprise session audit files offline\n",
                "  help     Print this message or the help of the given subcommand(s)\n\n",
                "Options:\n",
                "      --log-level <LOG_LEVEL>  Diagnostic verbosity. Interactive diagnostics require --log-file or stderr redirection [default: error] [possible values: off, error, warn, info, debug, trace]\n",
                "      --log-file <PATH>        Append detailed diagnostics to this file, keeping terminal interaction clean\n",
                "  -h, --help                   Print help\n",
                "  -V, --version                Print version\n",
            )
        );

        let connect = Cli::try_parse_from(["yon", "connect", "--help"])
            .unwrap_err()
            .to_string();
        assert_eq!(
            connect,
            concat!(
                "Connect this terminal to an advertised host.\n\n",
                "In an interactive session, press Ctrl+] followed by `.` to disconnect locally. Press Ctrl+] twice to send one literal Ctrl+] to the remote shell.\n\n",
                "Usage: yon connect [OPTIONS] [CODE]\n\n",
                "Arguments:\n",
                "  [CODE]\n",
                "          Single-use connection code. Omit it for a hidden prompt that avoids shell history\n\n",
                "Options:\n",
                "      --log-level <LOG_LEVEL>\n",
                "          Diagnostic verbosity. Interactive diagnostics require --log-file or stderr redirection\n",
                "          \n",
                "          [default: error]\n",
                "          [possible values: off, error, warn, info, debug, trace]\n\n",
                "      --log-file <PATH>\n",
                "          Append detailed diagnostics to this file, keeping terminal interaction clean\n\n",
                "  -h, --help\n",
                "          Print help (see a summary with '-h')\n",
            )
        );
    }

    #[test]
    fn terminal_connect_diagnostics_require_explicit_stderr_redirection() {
        for level in [
            LogLevel::Warn,
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Trace,
        ] {
            assert!(matches!(
                validate_diagnostic_output(level, true, false),
                Err(AppError::InteractiveDiagnostics)
            ));
            assert!(validate_diagnostic_output(level, false, false).is_ok());
            assert!(validate_diagnostic_output(level, true, true).is_ok());
        }
        for level in [LogLevel::Off, LogLevel::Error] {
            assert!(validate_diagnostic_output(level, true, false).is_ok());
        }
        assert_eq!(diagnostic_filter(LogLevel::Error, true), LevelFilter::OFF);
        assert_eq!(
            diagnostic_filter(LogLevel::Debug, false),
            LevelFilter::DEBUG
        );

        let connect = Command::Connect { code: None };
        assert!(command_uses_terminal_ui(&connect, true, true));
        assert!(!command_uses_terminal_ui(&connect, false, true));
        assert!(!command_uses_terminal_ui(&connect, true, false));
        assert!(command_uses_terminal_ui(&Command::Host, true, true));
        assert!(!command_uses_terminal_ui(
            &Command::Config {
                command: ConfigCommand::Check
            },
            true,
            true
        ));
        assert!(command_uses_terminal_ui(
            &Command::Audit {
                command: AuditCommand::Replay {
                    controller_file: PathBuf::from("controller.yonaudit"),
                    peer_file: None,
                }
            },
            true,
            true
        ));
        assert!(!command_uses_terminal_ui(
            &Command::Audit {
                command: AuditCommand::Verify {
                    local_file: PathBuf::from("local.yonaudit"),
                    peer_file: None,
                }
            },
            true,
            true
        ));
    }

    #[test]
    fn controller_progress_reuses_and_clears_one_terminal_line() {
        let mut progress = TerminalProgress::with_columns(Vec::new(), true, 80);
        for (stage, expected) in [
            (ControllerStage::ConnectingRelay, "Connecting to relay..."),
            (ControllerStage::ResolvingHost, "Finding remote host..."),
            (
                ControllerStage::WaitingForEnterpriseAuthorization,
                "Waiting for enterprise authorization...",
            ),
            (
                ControllerStage::EstablishingPath,
                "Establishing the best available path...",
            ),
            (
                ControllerStage::RelayFallback,
                "Direct path unavailable; switching to relay...",
            ),
            (
                ControllerStage::Authenticating,
                "Authenticating remote host...",
            ),
            (
                ControllerStage::StartingTerminal,
                "Starting remote terminal...",
            ),
        ] {
            progress.update(stage);
            assert!(String::from_utf8_lossy(&progress.writer).contains(expected));
            assert!(progress.visible);
        }
        progress.clear_line();
        assert!(!progress.visible);

        let mut disabled = TerminalProgress::with_columns(Vec::new(), false, 80);
        disabled.update(ControllerStage::ConnectingRelay);
        disabled.clear_line();
        assert!(disabled.writer.is_empty());

        let mut failing = TerminalProgress::with_columns(FailingWriter, true, 80);
        failing.update(ControllerStage::ConnectingRelay);
        assert!(!failing.enabled);
        assert!(!failing.visible);

        let mut narrow = TerminalProgress::with_columns(Vec::new(), true, 12);
        narrow.update(ControllerStage::ConnectingRelay);
        assert!(narrow.writer.ends_with(b"| Connectin"));
        assert!(!String::from_utf8_lossy(&narrow.writer).contains("Connecting to relay..."));
    }

    #[test]
    fn host_progress_and_terminal_capabilities_are_explicit() {
        let mut progress = TerminalProgress::with_columns(Vec::new(), true, 80);
        for stage in [
            HostStage::ConnectingRelay,
            HostStage::ReservingRelay,
            HostStage::RegisteringHost,
            HostStage::WaitingForController,
            HostStage::ReconnectingRelay,
            HostStage::AuthenticatingController,
            HostStage::StartingTerminal,
            HostStage::TerminalActive,
        ] {
            progress.update(stage);
        }
        let rendered = String::from_utf8(progress.writer.clone()).unwrap();
        assert!(rendered.contains("Connecting to relay..."));
        assert!(rendered.contains("Waiting for controller..."));
        assert!(rendered.contains("Relay unavailable; reconnecting..."));
        assert!(rendered.contains("Remote terminal active."));

        assert!(terminal_supports_progress(None));
        assert!(terminal_supports_progress(Some(std::ffi::OsStr::new(
            "xterm-256color"
        ))));
        assert!(!terminal_supports_progress(Some(std::ffi::OsStr::new(
            "dumb"
        ))));
        assert!(!terminal_supports_progress(Some(std::ffi::OsStr::new(
            "DUMB"
        ))));
    }

    #[test]
    fn progress_remeasures_width_and_disables_controls_after_query_failure() {
        let mut progress = TerminalProgress::with_scripted_columns(
            Vec::new(),
            true,
            [Ok(80), Ok(12), Err(io::ErrorKind::Unsupported), Ok(80)],
        );
        progress.update(ControllerStage::ConnectingRelay);
        progress.update(ControllerStage::ResolvingHost);
        let rendered = String::from_utf8_lossy(&progress.writer);
        assert!(rendered.contains("Connecting to relay..."));
        assert!(!rendered.contains("Finding remote host..."));
        drop(rendered);

        let before_failure = progress.writer.len();
        progress.update(ControllerStage::Authenticating);
        assert!(!progress.enabled);
        assert!(!progress.visible);
        assert_eq!(&progress.writer[before_failure..], b"\r\n");
        let after_failure = progress.writer.len();
        progress.update(ControllerStage::StartingTerminal);
        assert_eq!(progress.writer.len(), after_failure);

        let mut too_narrow =
            TerminalProgress::with_scripted_columns(Vec::new(), true, [Ok(80), Ok(7)]);
        too_narrow.update(ControllerStage::ConnectingRelay);
        too_narrow.update(ControllerStage::ResolvingHost);
        assert!(!too_narrow.enabled);
        assert!(!too_narrow.visible);

        let fail_writes = Rc::new(Cell::new(false));
        let mut failed_clear = TerminalProgress::with_columns(
            ToggleWriter {
                fail: Rc::clone(&fail_writes),
            },
            true,
            80,
        );
        failed_clear.update(ControllerStage::ConnectingRelay);
        assert!(failed_clear.visible);
        fail_writes.set(true);
        failed_clear.clear_line();
        assert!(!failed_clear.enabled);
        assert!(!failed_clear.visible);
    }

    #[test]
    fn progress_disables_itself_after_every_reachable_output_failure() {
        let mut successful = TerminalProgress::with_columns(CallFailingWriter::never(), true, 80);
        successful.update(ControllerStage::ConnectingRelay);
        assert!(successful.visible);
        let calls = successful.writer.calls;
        assert!(calls > 1);

        for fail_at in 0..calls {
            let mut progress =
                TerminalProgress::with_columns(CallFailingWriter::at(fail_at), true, 80);
            progress.update(ControllerStage::ConnectingRelay);
            assert!(
                !progress.enabled,
                "write call {fail_at} did not disable progress"
            );
            assert!(!progress.visible);
        }

        let mut unavailable_columns = TerminalProgress::with_scripted_columns(
            CallFailingWriter::never(),
            true,
            [Err(io::ErrorKind::Unsupported)],
        );
        unavailable_columns.update(ControllerStage::ConnectingRelay);
        assert!(!unavailable_columns.enabled);
        assert_eq!(unavailable_columns.writer.calls, 0);
    }

    #[test]
    fn successful_runs_map_to_the_reporting_exit_code() {
        assert_eq!(process_result(Ok(0)), ExitCode::SUCCESS);
        assert_eq!(process_result(Ok(42)), ExitCode::from(42));
    }

    #[test]
    fn terminal_progress_new_is_disabled_until_configured() {
        let mut progress = TerminalProgress::new(Vec::new(), false);
        assert!(!progress.enabled);
        assert!(!progress.visible);
        progress.update(ControllerStage::ConnectingRelay);
        progress.clear_line();
        assert!(progress.writer.is_empty());
    }

    #[test]
    fn config_check_validates_and_reports_the_effective_configuration() {
        // The system loader depends on the machine's real config files, so
        // the check is driven against a deterministic test directory: a
        // valid relay set passes, and an empty config fails the schema.
        let directory = test_directory("config-check");
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        fs::write(
            directory.join("yon.toml"),
            format!("relays = ['/ip4/127.0.0.1/tcp/1/p2p/{peer}']\n"),
        )
        .unwrap();
        let loader = test_loader(directory.clone());
        assert!(
            endpoint_config_with(&loader).is_ok(),
            "a valid relay set must pass the check"
        );

        fs::write(directory.join("yon.toml"), "").unwrap();
        assert!(
            matches!(
                endpoint_config_with(&loader),
                Err(AppError::Configuration(_))
            ),
            "an empty config must fail the schema"
        );
    }

    #[test]
    fn portable_process_exit_preserves_out_of_range_remote_values() {
        assert_eq!(portable_process_exit(0), Ok(ExitCode::SUCCESS));
        assert_eq!(portable_process_exit(255), Ok(ExitCode::from(255)));
        assert_eq!(portable_process_exit(256), Err(256));
        assert_eq!(process_result(Ok(256)), ExitCode::FAILURE);
        let mut warning = Vec::new();
        write_remote_exit_warning(&mut warning, 256).unwrap();
        assert_eq!(
            String::from_utf8(warning).unwrap(),
            "warning: remote exit code 256 exceeds the portable process range; returning 1\n"
        );
    }

    #[test]
    fn local_interrupts_map_to_130_and_runtime_shutdown_is_bounded() {
        assert_eq!(
            process_result(Err(AppError::Controller(
                yon::controller::ControllerError::Interrupted,
            ))),
            ExitCode::from(130)
        );
        assert_eq!(
            process_result(Err(AppError::Host(yon::host::HostError::Interrupted))),
            ExitCode::from(130)
        );
        assert_eq!(
            process_result(Err(AppError::Controller(
                yon::controller::ControllerError::Timeout,
            ))),
            ExitCode::FAILURE
        );
        assert_eq!(RUNTIME_SHUTDOWN_TIMEOUT, std::time::Duration::from_secs(1));
    }

    #[test]
    fn diagnostics_initialization_has_one_process_owner() {
        let invalid = || Cli {
            log_level: LogLevel::Off,
            log_file: None,
            command: Command::Config {
                command: ConfigCommand::Sources,
            },
        };
        assert!(run(invalid()).is_ok());
        assert!(matches!(run(invalid()), Err(AppError::Diagnostics)));
    }

    #[test]
    fn connection_code_input_errors_preserve_usage_exit_without_echoing_values() {
        assert_eq!(
            process_result(Err(AppError::ConnectionCodeInput)),
            ExitCode::from(2)
        );
        assert_eq!(
            process_result(Err(AppError::ConnectionCodeUnavailable)),
            ExitCode::FAILURE
        );
        assert_eq!(
            process_result(Err(AppError::Diagnostics)),
            ExitCode::FAILURE
        );
        assert_eq!(
            process_result(Err(AppError::SharedConnectionCode)),
            ExitCode::FAILURE
        );

        for error in [
            AppError::CaTooLarge(PathBuf::from("ca.der")),
            AppError::InteractiveDiagnostics,
            AppError::RuntimePanicked,
            AppError::CodeRead(io::Error::other("connection code read failed")),
            AppError::CaRead {
                path: PathBuf::from("ca.der"),
                source: io::Error::other("CA read failed"),
            },
            AppError::Runtime(io::Error::other("runtime construction failed")),
            AppError::RuntimeThread(io::Error::other("runtime thread failed")),
        ] {
            assert_eq!(process_result(Err(error)), ExitCode::FAILURE);
        }

        for error in [
            AppError::ConnectionCodeInput,
            AppError::ConnectionCodeUnavailable,
        ] {
            let mut report = Vec::new();
            yonder_core::write_error_report(&mut report, &error).unwrap();
            let report = String::from_utf8(report).unwrap();
            assert_eq!(report, "error: connection code is invalid or expired\n");
            for forbidden in ["OPAQUE", "PeerId", "locator", "0000-0000-0000-0000"] {
                assert!(
                    !report.contains(forbidden),
                    "public error leaked {forbidden}"
                );
            }
        }
    }

    #[test]
    fn remote_code_rejections_use_the_same_public_error_boundary() {
        for error in [
            yon::controller::ControllerError::Pake(yon::pake::OpaquePakeError::Rejected),
            yon::controller::ControllerError::Relay(yon::protocol::RelayProtocolError::Unavailable),
        ] {
            assert!(matches!(
                map_controller_error(error),
                AppError::ConnectionCodeUnavailable
            ));
        }
        assert!(matches!(
            map_controller_error(yon::controller::ControllerError::Timeout),
            AppError::Controller(yon::controller::ControllerError::Timeout)
        ));
    }

    #[test]
    fn piped_connection_code_is_bounded_and_accepts_platform_lines() {
        for input in [
            b"0000-0000-0000-0000\n".as_slice(),
            b"0000-0000-0000-0000\r\n".as_slice(),
            b"0000000000000000\r\n".as_slice(),
        ] {
            let code = read_connection_code_from(&mut Cursor::new(input)).unwrap();
            assert_eq!(code.expose().to_string(), "0000-0000-0000-0000");
        }
        assert!(matches!(
            read_connection_code_from(&mut Cursor::new(b"0000-0000-0000-00000\n")),
            Err(AppError::ConnectionCodeInput)
        ));
        assert!(matches!(
            read_connection_code_from(&mut Cursor::new(b"000000000000000000000")),
            Err(AppError::ConnectionCodeInput)
        ));
        assert!(matches!(
            read_connection_code_from(&mut Cursor::new([0xFF, b'\n'])),
            Err(AppError::ConnectionCodeInput)
        ));
        assert!(matches!(
            read_connection_code_from(&mut Cursor::new(b"invalid\n")),
            Err(AppError::ConnectionCodeInput)
        ));
        assert!(matches!(
            read_connection_code_from(&mut FailingReader),
            Err(AppError::CodeRead(_))
        ));

        let mut input = Cursor::new(b"0000000000000000\necho next\n".as_slice());
        read_connection_code_from(&mut input).unwrap();
        let mut remaining = Vec::new();
        input.read_to_end(&mut remaining).unwrap();
        assert_eq!(remaining, b"echo next\n");
    }

    #[test]
    fn connection_code_arguments_are_redacted_and_validated_after_cli_parsing() {
        let argument: ConnectionCodeArgument = "0000-0000-0000-0000".parse().unwrap();
        assert_eq!(
            format!("{argument:?}"),
            "ConnectionCodeArgument([REDACTED])"
        );
        assert_eq!(
            argument.into_code().unwrap().expose().to_string(),
            "0000-0000-0000-0000"
        );
        let shared: ConnectionCodeArgument = "0000-0000-0000-0000".parse().unwrap();
        let retained = shared.clone();
        assert!(matches!(
            shared.into_code(),
            Err(AppError::SharedConnectionCode)
        ));
        assert!(retained.into_code().is_ok());
        let invalid: ConnectionCodeArgument = "0000-0000-0000-000U".parse().unwrap();
        assert!(matches!(
            invalid.into_code(),
            Err(AppError::ConnectionCodeInput)
        ));

        for (level, expected) in [
            (LogLevel::Off, tracing_subscriber::filter::LevelFilter::OFF),
            (
                LogLevel::Error,
                tracing_subscriber::filter::LevelFilter::ERROR,
            ),
            (
                LogLevel::Warn,
                tracing_subscriber::filter::LevelFilter::WARN,
            ),
            (
                LogLevel::Info,
                tracing_subscriber::filter::LevelFilter::INFO,
            ),
            (
                LogLevel::Debug,
                tracing_subscriber::filter::LevelFilter::DEBUG,
            ),
            (
                LogLevel::Trace,
                tracing_subscriber::filter::LevelFilter::TRACE,
            ),
        ] {
            assert_eq!(level.filter(), expected);
        }
    }

    #[test]
    fn configuration_source_report_is_ordered_and_hides_values() {
        let directory = test_directory("configuration-report");
        fs::create_dir_all(directory.join("system")).unwrap();
        fs::write(directory.join("system").join("yon.toml"), "relays = []\n").unwrap();
        let locations = test_loader(directory.clone()).locations().unwrap();
        let mut output = Vec::new();
        locations.inspect().unwrap().write_to(&mut output).unwrap();
        let report = String::from_utf8(output).unwrap();
        let system = directory.join("system").join("yon.toml");
        let working = directory.join("yon.toml");
        assert!(report.starts_with("Configuration precedence (lowest to highest):\n"));
        assert!(
            report.contains(&format!("1. System file: {} (present)", system.display())),
            "{report}"
        );
        assert!(report.contains(&format!(
            "2. Working-directory file: {} (missing)",
            working.display()
        )));
        assert!(report.ends_with("3. Environment variables: YON_* (values hidden)\n"));
        assert!(!report.contains("relays ="));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn user_facing_reports_propagate_each_output_failure() {
        let directory = test_directory("configuration-report-failure");
        let locations = test_loader(directory.clone()).locations().unwrap();
        let report = locations.inspect().unwrap();
        for completed_reports in 0..4 {
            assert!(
                report
                    .write_to(&mut FailAfterReports::new(completed_reports))
                    .is_err()
            );
        }
        assert!(write_remote_exit_warning(&mut FailAfterReports::new(0), 256).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn audit_reports_render_every_optional_fact_without_raw_session_content() {
        use yon::audit::replay::{FilteredControls, ReplayReport};
        use yon::audit::verify::{AnchorReport, FileReport, VerificationReport, VerificationState};
        use yonder_core::wire::audit::{AuditRole, IdentityFingerprint, ManifestEnding, SessionId};

        let controller = FileReport {
            path: PathBuf::from("controller.yonaudit"),
            role: AuditRole::Controller,
            fingerprint: IdentityFingerprint::new([1; 32]),
            utc_start_seconds: 1,
            shared_counts: [2, 3, 4, 5],
            local_event_count: 6,
            finalized: true,
            truncated_tail: true,
            last_confirmed_sent_checkpoint: Some((7, [2; 32])),
            last_confirmed_received_checkpoint: Some((6, [3; 32])),
            ending: Some(ManifestEnding::ShellExit(0)),
            ended_normally: true,
        };
        let host = FileReport {
            role: AuditRole::Host,
            path: PathBuf::from("host.yonaudit"),
            truncated_tail: false,
            ..controller.clone()
        };
        let verification = VerificationReport {
            state: VerificationState::Mismatch,
            session_id: Some(SessionId::new([0xAB; 32])),
            controller: Some(controller),
            host: Some(host),
            anchor: AnchorReport {
                identity_matched: true,
                ledger_continuous: true,
            },
            reason: Some("the records differ"),
        };
        let mut output = Vec::new();
        write_verification_report(&mut output, &verification).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains(&format!("session: {}", hex_digest(&[0xAB; 32]))));
        assert!(output.contains("controller: controller.yonaudit finalized=true"));
        assert!(output.contains("host: host.yonaudit finalized=true"));
        assert!(output.contains("controller: truncated tail; verified prefix retained"));
        assert!(output.contains("verification: MISMATCH"));
        assert!(output.contains("reason: the records differ"));
        assert!(output.contains("anchor: identity-matched=true ledger-continuous=true"));

        let replay = ReplayReport {
            state: VerificationState::IntactUnpaired,
            unpaired: true,
            interrupted: true,
            filtered: FilteredControls {
                title: 1,
                clipboard: 2,
                resize_request: 3,
                unhandled: 4,
            },
            bells: 5,
            display_records: 6,
            display_bytes: 7,
            final_screen: (24, 80),
            final_text: "must not be printed".to_owned(),
        };
        let mut output = Vec::new();
        write_replay_report(&mut output, &replay).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("verification: INTACT_UNPAIRED"));
        assert!(output.contains("warning: no peer file was provided"));
        assert!(output.contains("display: 6 records, 7 bytes; final screen: 24x80"));
        assert!(output.contains("filtered controls: title=1 clipboard=2 resize=3 unhandled=4"));
        assert!(output.contains("suppressed bells: 5"));
        assert!(output.contains("replay stopped by Ctrl+C"));
        assert!(!output.contains("must not be printed"));

        assert!(matches!(
            write_verification_report(&mut FailingWriter, &verification),
            Err(AppError::AuditOutput(_))
        ));
        assert!(matches!(
            write_replay_report(&mut FailingWriter, &replay),
            Err(AppError::AuditOutput(_))
        ));
    }

    #[test]
    fn audit_commands_fail_closed_through_the_real_command_dispatch() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let missing = test_directory("missing-audit-record").join("missing.yonaudit");

        assert!(matches!(
            execute_command(
                &runtime,
                Command::Audit {
                    command: AuditCommand::Verify {
                        local_file: missing.clone(),
                        peer_file: None,
                    },
                },
            ),
            Err(AppError::AuditVerify(_))
        ));
        assert!(matches!(
            execute_command(
                &runtime,
                Command::Audit {
                    command: AuditCommand::Replay {
                        controller_file: missing,
                        peer_file: None,
                    },
                },
            ),
            Err(AppError::AuditReplay(_))
        ));
    }

    #[test]
    fn finalized_bilateral_audit_runs_through_verify_and_replay_commands() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    use yon::audit::observer::{
                        AuditObserver, CloseNoticeHandling, utc_start_seconds,
                    };
                    use yonder_core::OsSecureRandom;
                    use yonder_core::wire::audit::{
                        AuditCloseReason, AuditRole, Digest32, ManifestEnding,
                    };

                    let controller_dir = tempfile::tempdir().unwrap();
                    let host_dir = tempfile::tempdir().unwrap();
                    let controller_root = controller_dir.path().join("audit");
                    let host_root = host_dir.path().join("audit");
                    let controller_peer = Keypair::generate_ed25519().public().to_peer_id();
                    let host_peer = Keypair::generate_ed25519().public().to_peer_id();
                    let digest = Digest32::new([0xA5; 32]);
                    let (controller_half, host_half) = tokio::io::duplex(256 * 1024);
                    let mut controller_random = OsSecureRandom;
                    let mut host_random = OsSecureRandom;
                    let (controller, host) = tokio::join!(
                        Box::pin(AuditObserver::establish(
                            controller_half,
                            AuditRole::Controller,
                            controller_peer,
                            host_peer,
                            utc_start_seconds(),
                            digest,
                            &controller_root,
                            &mut controller_random,
                        )),
                        Box::pin(AuditObserver::establish(
                            host_half,
                            AuditRole::Host,
                            controller_peer,
                            host_peer,
                            utc_start_seconds(),
                            digest,
                            &host_root,
                            &mut host_random,
                        )),
                    );
                    let controller = controller.unwrap();
                    let host = host.unwrap();
                    controller.record_terminal_hello(digest).await.unwrap();
                    host.record_terminal_hello(digest).await.unwrap();
                    host.record_terminal_ready().await.unwrap();
                    controller.record_terminal_ready().await.unwrap();
                    host.record_raw_output(b"verified replay output\r\n")
                        .await
                        .unwrap();
                    controller
                        .record_raw_output(b"verified replay output\r\n")
                        .await
                        .unwrap();
                    controller
                        .record_display_bytes(b"verified replay output\r\n")
                        .await
                        .unwrap();
                    host.record_terminal_exit(0).await.unwrap();
                    controller.record_terminal_exit(0).await.unwrap();
                    controller.record_terminal_complete().await.unwrap();
                    host.record_terminal_complete().await.unwrap();
                    let (controller_result, host_result) = tokio::join!(
                        Box::pin(controller.close_and_finalize(
                            ManifestEnding::ShellExit(0),
                            true,
                            CloseNoticeHandling::Sender(AuditCloseReason::NormalShellExit),
                        )),
                        Box::pin(host.close_and_finalize(
                            ManifestEnding::ShellExit(0),
                            true,
                            CloseNoticeHandling::Receiver,
                        )),
                    );
                    controller_result.unwrap();
                    host_result.unwrap();

                    let controller_file = fs::read_dir(controller_root.join("records"))
                        .unwrap()
                        .next()
                        .unwrap()
                        .unwrap()
                        .path();
                    let host_file = fs::read_dir(host_root.join("records"))
                        .unwrap()
                        .next()
                        .unwrap()
                        .unwrap()
                        .path();
                    let expected =
                        yon::audit::verify::VerificationState::ConsistentCompleteUnanchored
                            .exit_code();
                    assert_eq!(
                        execute_command(
                            &runtime,
                            Command::Audit {
                                command: AuditCommand::Verify {
                                    local_file: controller_file.clone(),
                                    peer_file: Some(host_file.clone()),
                                },
                            },
                        )
                        .unwrap(),
                        expected
                    );
                    assert_eq!(
                        execute_command(
                            &runtime,
                            Command::Audit {
                                command: AuditCommand::Replay {
                                    controller_file: controller_file.clone(),
                                    peer_file: Some(host_file.clone()),
                                },
                            },
                        )
                        .unwrap(),
                        expected
                    );

                    let mut tampered = fs::read(&host_file).unwrap();
                    let mutation = tampered.len() / 2;
                    tampered[mutation] ^= 0x80;
                    fs::write(&host_file, tampered).unwrap();
                    assert_eq!(
                        execute_command(
                            &runtime,
                            Command::Audit {
                                command: AuditCommand::Replay {
                                    controller_file,
                                    peer_file: Some(host_file),
                                },
                            },
                        )
                        .unwrap(),
                        yon::audit::verify::VerificationState::Tampered.exit_code()
                    );
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn configuration_status_and_diagnostic_log_failures_are_structured() {
        let directory = test_directory("configuration-status");
        assert!(matches!(
            open_diagnostic_log(&directory),
            Err(AppError::LogFile { .. })
        ));
        let log = directory.join("yon.log");
        drop(open_diagnostic_log(&log).unwrap());
        drop(open_diagnostic_log(&log).unwrap());
        assert!(log.is_file());
    }

    #[test]
    fn endpoint_ca_files_are_bounded_and_relay_sets_are_validated() {
        let directory = test_directory("endpoint-config");
        let path = directory.join("ca.der");
        fs::write(&path, [1, 2, 3]).unwrap();
        assert_eq!(read_ca(&path).unwrap(), [1, 2, 3]);

        let peer = Keypair::generate_ed25519().public().to_peer_id();
        fs::write(
            directory.join("yon.toml"),
            format!("relays = ['/ip4/127.0.0.1/tcp/1/p2p/{peer}']\nwss_ca_der = 'ca.der'\n"),
        )
        .unwrap();
        let loader = test_loader(directory.clone());
        assert!(matches!(
            endpoint_config_with(&loader),
            Err(AppError::WssConfiguration(_))
        ));
        fs::write(&path, TEST_CA_DER).unwrap();
        let (_, wss, _) = endpoint_config_with(&loader).unwrap();
        assert!(format!("{wss:?}").contains("additional_trust_count: 1"));

        fs::write(
            directory.join("yon.toml"),
            format!(
                "relays = ['/ip4/127.0.0.1/tcp/1/p2p/{peer}']\nwss_ca = ['ca.der', 'ca.der']\n"
            ),
        )
        .unwrap();
        let (_, wss, _) = endpoint_config_with(&loader).unwrap();
        assert!(format!("{wss:?}").contains("additional_trust_count: 2"));

        fs::create_dir(directory.join("system")).unwrap();
        fs::write(
            directory.join("system").join("yon.toml"),
            "wss_ca_der = 'legacy-invalid.der'\n",
        )
        .unwrap();
        let (_, wss, _) = endpoint_config_with(&loader).unwrap();
        assert!(format!("{wss:?}").contains("additional_trust_count: 2"));

        fs::write(
            directory.join("yon.toml"),
            format!(
                "relays = ['/ip4/127.0.0.1/tcp/1/p2p/{peer}']\nwss_ca = 'ca.der'\nwss_ca_der = 'ca.der'\n"
            ),
        )
        .unwrap();
        assert!(matches!(
            endpoint_config_with(&loader),
            Err(AppError::ConflictingWssCa)
        ));

        fs::write(
            directory.join("system").join("yon.toml"),
            "wss_ca = 'legacy-invalid.der'\n",
        )
        .unwrap();
        fs::write(
            directory.join("yon.toml"),
            format!("relays = ['/ip4/127.0.0.1/tcp/1/p2p/{peer}']\nwss_ca_der = 'ca.der'\n"),
        )
        .unwrap();
        let (_, wss, _) = endpoint_config_with(&loader).unwrap();
        assert!(format!("{wss:?}").contains("additional_trust_count: 1"));
        fs::remove_file(directory.join("system").join("yon.toml")).unwrap();

        fs::write(
            directory.join("yon.toml"),
            format!("relays = ['/ip4/127.0.0.1/tcp/1/p2p/{peer}']\n"),
        )
        .unwrap();
        let (_, wss, _) = endpoint_config_with(&loader).unwrap();
        assert!(format!("{wss:?}").contains("additional_trust_count: 0"));

        for paths in [
            "[]",
            "['ca.der','ca.der','ca.der','ca.der','ca.der','ca.der','ca.der','ca.der','ca.der']",
        ] {
            fs::write(
                directory.join("yon.toml"),
                format!("relays = ['/ip4/127.0.0.1/tcp/1/p2p/{peer}']\nwss_ca = {paths}\n"),
            )
            .unwrap();
            assert!(matches!(
                endpoint_config_with(&loader),
                Err(AppError::InvalidWssCaDocumentCount)
            ));
        }

        fs::write(
            directory.join("yon.toml"),
            format!("relays = ['/ip4/127.0.0.1/tcp/1/p2p/{peer}']\nwss_ca_der = ''\n"),
        )
        .unwrap();
        assert!(matches!(
            endpoint_config_with(&loader),
            Err(AppError::Configuration(_))
        ));

        fs::write(directory.join("yon.toml"), "relays = ['invalid']\n").unwrap();
        assert!(matches!(
            endpoint_config_with(&loader),
            Err(AppError::RelaySet(_))
        ));

        fs::write(
            directory.join("yon.toml"),
            format!("relays = ['/ip4/127.0.0.1/tcp/1/p2p/{peer}']\nwss_ca_der = 'missing.der'\n"),
        )
        .unwrap();
        assert!(matches!(
            endpoint_config_with(&loader),
            Err(AppError::CaRead { .. })
        ));

        fs::write(directory.join("yon.toml"), "relays = 1\n").unwrap();
        assert!(matches!(
            endpoint_config_with(&loader),
            Err(AppError::Configuration(_))
        ));

        fs::write(&path, vec![0; 1024 * 1024 + 1]).unwrap();
        assert!(matches!(read_ca(&path), Err(AppError::CaTooLarge(_))));
        let fixture_path = std::path::Path::new("ca.der");
        assert!(matches!(
            read_ca_document(Cursor::new(vec![0; 1024 * 1024 + 1]), 0, fixture_path),
            Err(AppError::CaTooLarge(_))
        ));
        assert!(matches!(
            read_ca_document(Cursor::new([]), 1024 * 1024 + 1, fixture_path),
            Err(AppError::CaTooLarge(_))
        ));
        assert!(matches!(
            read_ca_document(FailingReader, 0, fixture_path),
            Err(AppError::CaRead { .. })
        ));
        fs::remove_file(&path).unwrap();
        assert!(matches!(read_ca(&path), Err(AppError::CaRead { .. })));

        let first = Keypair::generate_ed25519().public().to_peer_id();
        let second = Keypair::generate_ed25519().public().to_peer_id();
        fs::write(
            directory.join("yon.toml"),
            format!(
                "relays = ['/ip4/127.0.0.1/tcp/1/p2p/{first}', '/ip4/127.0.0.1/tcp/2/p2p/{second}']\n"
            ),
        )
        .unwrap();
        let result = endpoint_config_with(&loader);
        assert!(matches!(result, Err(AppError::RelaySet(_))));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn endpoint_access_mode_is_explicit_typed_and_environment_overridable() {
        let directory = test_directory("endpoint-access-mode");
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let config = directory.join("yon.toml");

        fs::write(
            &config,
            format!("relays = ['/ip4/127.0.0.1/tcp/1/p2p/{peer}']\n"),
        )
        .unwrap();
        let (_, _, access) = endpoint_config_with(&test_loader(directory.clone())).unwrap();
        assert_eq!(access, RelayAccessMode::Standard);

        fs::write(
            &config,
            format!("relays = ['/ip4/127.0.0.1/tcp/1/p2p/{peer}']\naccess_mode = 'enterprise'\n"),
        )
        .unwrap();
        let (_, _, access) = endpoint_config_with(&test_loader(directory.clone())).unwrap();
        assert_eq!(access, RelayAccessMode::Enterprise);

        fs::write(
            &config,
            format!("relays = ['/ip4/127.0.0.1/tcp/1/p2p/{peer}']\naccess_mode = 'standard'\n"),
        )
        .unwrap();
        let loader = test_loader_with_environment(
            directory.clone(),
            vec![
                ("YON_ACCESS_MODE".into(), "enterprise".into()),
                ("YON_RELAY_MODE".into(), "standard".into()),
            ],
        );
        let (_, _, access) = endpoint_config_with(&loader).unwrap();
        assert_eq!(access, RelayAccessMode::Enterprise);

        fs::write(
            &config,
            format!("relays = ['/ip4/127.0.0.1/tcp/1/p2p/{peer}']\naccess_mode = 'automatic'\n"),
        )
        .unwrap();
        assert!(matches!(
            endpoint_config_with(&test_loader(directory.clone())),
            Err(AppError::Configuration(_))
        ));

        fs::write(
            &config,
            format!("relays = ['/ip4/127.0.0.1/tcp/1/p2p/{peer}']\nrelay_mode = 'enterprise'\n"),
        )
        .unwrap();
        assert!(matches!(
            endpoint_config_with(&test_loader(directory.clone())),
            Err(AppError::Configuration(_))
        ));
        fs::remove_dir_all(directory).unwrap();
    }

    #[derive(Debug)]
    struct TestSources {
        cwd: PathBuf,
        environment: Vec<(OsString, OsString)>,
    }

    impl ConfigurationSources for TestSources {
        fn current_directory(&self) -> Result<PathBuf, io::Error> {
            Ok(self.cwd.clone())
        }

        fn system_directory(&self) -> Result<PathBuf, ConfigurationLocationError> {
            Ok(self.cwd.join("system"))
        }

        fn environment(&self) -> Vec<(OsString, OsString)> {
            self.environment.clone()
        }
    }

    fn test_loader(directory: PathBuf) -> LayeredConfigLoader<TestSources> {
        test_loader_with_environment(directory, Vec::new())
    }

    fn test_loader_with_environment(
        directory: PathBuf,
        environment: Vec<(OsString, OsString)>,
    ) -> LayeredConfigLoader<TestSources> {
        LayeredConfigLoader::new(
            TestSources {
                cwd: directory,
                environment,
            },
            ENDPOINT_SCHEMA,
        )
    }

    fn test_directory(label: &str) -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "yonder-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("read failed"))
        }
    }

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("write failed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::other("flush failed"))
        }
    }

    struct FailAfterReports {
        remaining: usize,
    }

    impl FailAfterReports {
        const fn new(remaining: usize) -> Self {
            Self { remaining }
        }
    }

    impl Write for FailAfterReports {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                Err(io::Error::other("output closed"))
            } else {
                self.remaining -= 1;
                Ok(buffer.len())
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn write_fmt(&mut self, _arguments: std::fmt::Arguments<'_>) -> io::Result<()> {
            if self.remaining == 0 {
                Err(io::Error::other("output closed"))
            } else {
                self.remaining -= 1;
                Ok(())
            }
        }
    }

    struct CallFailingWriter {
        calls: usize,
        fail_at: Option<usize>,
    }

    impl CallFailingWriter {
        const fn never() -> Self {
            Self {
                calls: 0,
                fail_at: None,
            }
        }

        const fn at(fail_at: usize) -> Self {
            Self {
                calls: 0,
                fail_at: Some(fail_at),
            }
        }

        fn next(&mut self) -> io::Result<()> {
            let current = self.calls;
            self.calls += 1;
            if self.fail_at == Some(current) {
                Err(io::Error::other("output closed"))
            } else {
                Ok(())
            }
        }
    }

    impl Write for CallFailingWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.next()?;
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.next()
        }
    }

    struct ToggleWriter {
        fail: Rc<Cell<bool>>,
    }

    impl Write for ToggleWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if self.fail.get() {
                Err(io::Error::other("write failed"))
            } else {
                Ok(buffer.len())
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            if self.fail.get() {
                Err(io::Error::other("flush failed"))
            } else {
                Ok(())
            }
        }
    }
}
