#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use clap::{Parser, Subcommand, ValueEnum};
use serde::Deserialize;
use std::convert::Infallible;
use std::ffi::OsStr;
use std::fs::File;
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
use yon::progress::OperationProgress;
use yonder_config::{
    Application, ConfigLoader, ConfigurationError, ConfigurationKey, ConfigurationSchema,
    LayeredConfigLoader,
};
use yonder_core::{CodeError, ConnectionCode, OsSecureRandom, write_error_report};
use yonder_net::{
    AddressError, EndpointRelayAddress, EndpointRelaySet, NetworkBuildError, WssTransportConfig,
    generate_identity,
};
use zeroize::Zeroizing;

const MAX_CA_DOCUMENT: u64 = 1024 * 1024;
const MAX_CODE_TEXT: usize = 19;
const RUNTIME_STACK_SIZE: usize = 8 * 1024 * 1024;
const RUNTIME_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const RELAYS_KEY: ConfigurationKey = ConfigurationKey::new("relays");
const WSS_CA_DER_KEY: ConfigurationKey = ConfigurationKey::new("wss_ca_der");
const ENDPOINT_SCHEMA: ConfigurationSchema =
    ConfigurationSchema::new(Application::Yon, &[RELAYS_KEY], &[WSS_CA_DER_KEY]);

#[derive(Debug, Parser)]
#[command(name = "yon", version, about)]
struct Cli {
    #[arg(long, value_enum, default_value_t = LogLevel::Error, global = true)]
    log_level: LogLevel,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Advertise one single-use remote terminal.
    Host,
    /// Connect the current terminal to an advertised host.
    Connect {
        code: Option<ConnectionCodeArgument>,
    },
}

impl Command {
    const fn is_connect(&self) -> bool {
        matches!(self, Self::Connect { .. })
    }
}

#[derive(Clone)]
struct ConnectionCodeArgument(Arc<Zeroizing<String>>);

impl ConnectionCodeArgument {
    fn into_code(self) -> Result<ConnectionCode, AppError> {
        Arc::try_unwrap(self.0)
            .map_err(|_| AppError::SharedConnectionCode)?
            .parse()
            .map_err(AppError::Code)
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
    wss_ca_der: Option<PathBuf>,
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
        "--log-level warn/info/debug/trace requires stderr redirection when connect writes to a terminal (for example: yon --log-level debug connect 2> yon-debug.log)"
    )]
    InteractiveDiagnostics,
    #[error("the relay address set is invalid: {0}")]
    RelaySet(#[from] AddressError),
    #[error("failed to load endpoint configuration: {0}")]
    Configuration(#[from] ConfigurationError),
    #[error("failed to create an ephemeral endpoint identity: {0}")]
    Identity(#[from] NetworkBuildError),
    #[error("failed to read the WSS CA document: {0}")]
    CaRead(#[source] std::io::Error),
    #[error("the WSS CA document exceeds the 1 MiB limit")]
    CaTooLarge,
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
    #[error("the connection code input exceeds 19 bytes")]
    CodeTooLong,
    #[error("the connection code input is not UTF-8")]
    CodeEncoding,
    #[error("the connection code is invalid")]
    Code(#[source] CodeError),
    #[error(transparent)]
    Host(#[from] HostError),
    #[error(transparent)]
    Controller(#[from] ControllerError),
}

fn main() -> ExitCode {
    process_result(run(Cli::parse()))
}

fn process_result(result: Result<u32, AppError>) -> ExitCode {
    match result {
        Ok(code) => process_exit(code),
        Err(AppError::Controller(ControllerError::Interrupted)) => {
            begin_terminal_report_line();
            ExitCode::from(130)
        }
        Err(error) => {
            if matches!(&error, AppError::Controller(_) | AppError::Host(_)) {
                begin_terminal_report_line();
            }
            let _ = write_error_report(&mut std::io::stderr().lock(), &error);
            if matches!(
                error,
                AppError::Code(_) | AppError::CodeTooLong | AppError::CodeEncoding
            ) {
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn run(cli: Cli) -> Result<u32, AppError> {
    let stderr_is_terminal = std::io::stderr().is_terminal();
    let terminal_output = controller_uses_terminal(
        &cli.command,
        std::io::stdout().is_terminal(),
        stderr_is_terminal,
    );
    validate_diagnostic_output(cli.log_level, terminal_output)?;
    tracing_subscriber::fmt()
        .with_max_level(diagnostic_filter(cli.log_level, terminal_output))
        .with_target(false)
        .with_writer(std::io::stderr)
        .with_ansi(stderr_is_terminal)
        .compact()
        .try_init()
        .map_err(|_| AppError::Diagnostics)?;

    std::thread::Builder::new()
        .name("yon-runtime".to_owned())
        .stack_size(RUNTIME_STACK_SIZE)
        .spawn(move || run_command(cli.command))
        .map_err(AppError::RuntimeThread)?
        .join()
        .map_err(|_| AppError::RuntimePanicked)?
}

fn validate_diagnostic_output(level: LogLevel, terminal_output: bool) -> Result<(), AppError> {
    if terminal_output && level.requires_redirect_for_terminal() {
        return Err(AppError::InteractiveDiagnostics);
    }
    Ok(())
}

fn controller_uses_terminal(
    command: &Command,
    stdout_is_terminal: bool,
    stderr_is_terminal: bool,
) -> bool {
    command.is_connect() && stdout_is_terminal && stderr_is_terminal
}

fn diagnostic_filter(level: LogLevel, terminal_output: bool) -> LevelFilter {
    if terminal_output {
        LevelFilter::OFF
    } else {
        level.filter()
    }
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
            let (relays, wss) = endpoint_config()?;
            let identity = generate_identity(&mut OsSecureRandom)?;
            let terminal_output = std::io::stdout().is_terminal()
                && std::io::stderr().is_terminal()
                && terminal_supports_progress(std::env::var_os("TERM").as_deref());
            let mut progress = TerminalProgress::new(std::io::stderr(), terminal_output);
            runtime
                .block_on(run_host_with_progress(
                    HostConfig::new(identity, relays, wss),
                    &mut progress,
                ))
                .map_err(AppError::from)
        }
        Command::Connect { code } => {
            let code = code.map_or_else(read_connection_code, ConnectionCodeArgument::into_code)?;
            let terminal = local_terminal_hello()?;
            let (relays, wss) = endpoint_config()?;
            let identity = generate_identity(&mut OsSecureRandom)?;
            let terminal_output = std::io::stdout().is_terminal()
                && std::io::stderr().is_terminal()
                && terminal_supports_progress(std::env::var_os("TERM").as_deref());
            let mut progress = TerminalProgress::new(std::io::stderr(), terminal_output);
            runtime
                .block_on(run_controller_with_progress(
                    ControllerConfig::new(identity, relays, wss, code, terminal),
                    &mut progress,
                ))
                .map_err(AppError::from)
        }
    }
}

struct TerminalProgress<W: std::io::Write> {
    writer: W,
    enabled: bool,
    visible: bool,
    line_capacity: usize,
    frame: usize,
}

impl<W: std::io::Write> TerminalProgress<W> {
    fn new(writer: W, enabled: bool) -> Self {
        let columns = enabled
            .then(crossterm::terminal::size)
            .and_then(Result::ok)
            .map_or(0, |(columns, _)| usize::from(columns));
        Self::with_columns(writer, enabled, columns)
    }

    const fn with_columns(writer: W, enabled: bool, columns: usize) -> Self {
        let line_capacity = columns.saturating_sub(1);
        Self {
            writer,
            enabled: enabled && line_capacity >= 8,
            visible: false,
            line_capacity,
            frame: 0,
        }
    }

    fn render(&mut self, message: &str) {
        if !self.enabled {
            return;
        }
        debug_assert!(message.is_ascii());
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
        input.parse().map_err(AppError::Code)
    } else {
        read_connection_code_from(&mut std::io::stdin().lock())
    }
}

fn read_connection_code_from(reader: &mut impl Read) -> Result<ConnectionCode, AppError> {
    let mut text = Zeroizing::new([0_u8; MAX_CODE_TEXT + 2]);
    let mut len = 0;
    loop {
        if len == text.len() {
            return Err(AppError::CodeTooLong);
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
        return Err(AppError::CodeTooLong);
    }
    let text = std::str::from_utf8(&text[..len]).map_err(|_| AppError::CodeEncoding)?;
    text.parse().map_err(AppError::Code)
}

fn endpoint_config() -> Result<(EndpointRelaySet, WssTransportConfig), AppError> {
    endpoint_config_with(&LayeredConfigLoader::system(ENDPOINT_SCHEMA))
}

fn endpoint_config_with(
    loader: &impl ConfigLoader<EndpointSettings>,
) -> Result<(EndpointRelaySet, WssTransportConfig), AppError> {
    let loaded = loader.load()?;
    let ca_path = loaded
        .value()
        .wss_ca_der
        .as_deref()
        .map(|path| loaded.resolve_path(WSS_CA_DER_KEY, path))
        .transpose()?;
    let relay_addresses = loaded
        .value()
        .relays
        .iter()
        .map(|address| address.parse::<EndpointRelayAddress>())
        .collect::<Result<Vec<_>, _>>()?;
    let relays = EndpointRelaySet::new(relay_addresses)?;
    let ca = ca_path.as_deref().map(read_ca).transpose()?;
    Ok((relays, WssTransportConfig::client(ca)))
}

fn read_ca(path: &Path) -> Result<Vec<u8>, AppError> {
    let file = File::open(path).map_err(AppError::CaRead)?;
    let reported_len = file.metadata().map_err(AppError::CaRead)?.len();
    read_ca_document(file, reported_len)
}

fn read_ca_document(reader: impl Read, reported_len: u64) -> Result<Vec<u8>, AppError> {
    if reported_len > MAX_CA_DOCUMENT {
        return Err(AppError::CaTooLarge);
    }
    let mut bytes = Vec::new();
    let mut bounded = reader.take(MAX_CA_DOCUMENT + 1);
    bounded.read_to_end(&mut bytes).map_err(AppError::CaRead)?;
    if bytes.len() as u64 > MAX_CA_DOCUMENT {
        return Err(AppError::CaTooLarge);
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
        AppError, Cli, Command, ConnectionCodeArgument, ENDPOINT_SCHEMA, LevelFilter, LogLevel,
        RUNTIME_SHUTDOWN_TIMEOUT, TerminalProgress, controller_uses_terminal, diagnostic_filter,
        endpoint_config_with, portable_process_exit, process_result, read_ca, read_ca_document,
        read_connection_code_from, run, run_command, terminal_supports_progress,
        validate_diagnostic_output, write_remote_exit_warning,
    };
    use clap::Parser;
    use std::ffi::OsString;
    use std::fs;
    use std::io::{self, Cursor, Read, Write};
    use std::path::PathBuf;
    use std::process::ExitCode;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use yon::controller::ControllerStage;
    use yon::host::HostStage;
    use yon::progress::OperationProgress as _;
    use yonder_config::{ConfigurationLocationError, ConfigurationSources, LayeredConfigLoader};
    use yonder_net::Keypair;

    #[test]
    fn configuration_driven_cli_shape_parses() {
        let host = Cli::try_parse_from(["yon", "host"]).unwrap();
        assert!(matches!(host.command, Command::Host));
        assert!(matches!(host.log_level, LogLevel::Error));

        let connect = Cli::try_parse_from(["yon", "connect", "0000-0000-0000-0000"]).unwrap();
        assert!(matches!(connect.command, Command::Connect { .. }));

        let prompted = Cli::try_parse_from(["yon", "connect"]).unwrap();
        assert!(matches!(prompted.command, Command::Connect { code: None }));
        assert!(Cli::try_parse_from(["yon", "host", "--relay", "ignored"]).is_err());
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
                validate_diagnostic_output(level, true),
                Err(AppError::InteractiveDiagnostics)
            ));
            assert!(validate_diagnostic_output(level, false).is_ok());
        }
        for level in [LogLevel::Off, LogLevel::Error] {
            assert!(validate_diagnostic_output(level, true).is_ok());
        }
        assert_eq!(diagnostic_filter(LogLevel::Error, true), LevelFilter::OFF);
        assert_eq!(
            diagnostic_filter(LogLevel::Debug, false),
            LevelFilter::DEBUG
        );

        let connect = Command::Connect { code: None };
        assert!(controller_uses_terminal(&connect, true, true));
        assert!(!controller_uses_terminal(&connect, false, true));
        assert!(!controller_uses_terminal(&connect, true, false));
        assert!(!controller_uses_terminal(&Command::Host, true, true));
    }

    #[test]
    fn controller_progress_reuses_and_clears_one_terminal_line() {
        let mut progress = TerminalProgress::with_columns(Vec::new(), true, 80);
        for (stage, expected) in [
            (ControllerStage::ConnectingRelay, "Connecting to relay..."),
            (ControllerStage::ResolvingHost, "Finding remote host..."),
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
    fn controller_interrupt_maps_to_130_and_runtime_shutdown_is_bounded() {
        assert_eq!(
            process_result(Err(AppError::Controller(
                yon::controller::ControllerError::Interrupted,
            ))),
            ExitCode::from(130)
        );
        assert_eq!(RUNTIME_SHUTDOWN_TIMEOUT, std::time::Duration::from_secs(1));
    }

    #[test]
    fn diagnostics_initialization_has_one_process_owner() {
        let invalid = || Cli {
            log_level: LogLevel::Off,
            command: Command::Connect {
                code: Some("0000-0000-0000-000U".parse().unwrap()),
            },
        };
        assert!(matches!(run(invalid()), Err(AppError::Code(_))));
        assert!(matches!(run(invalid()), Err(AppError::Diagnostics)));
    }

    #[test]
    fn connection_code_input_errors_preserve_usage_exit_without_echoing_values() {
        let code_error = "invalid"
            .parse::<yonder_core::ConnectionCode>()
            .unwrap_err();
        assert_eq!(
            process_result(Err(AppError::Code(code_error))),
            ExitCode::from(2)
        );
        assert_eq!(
            process_result(Err(AppError::CodeTooLong)),
            ExitCode::from(2)
        );
        assert_eq!(
            process_result(Err(AppError::CodeEncoding)),
            ExitCode::from(2)
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
            AppError::CaTooLarge,
            AppError::InteractiveDiagnostics,
            AppError::RuntimePanicked,
            AppError::CodeRead(io::Error::other("connection code read failed")),
            AppError::CaRead(io::Error::other("CA read failed")),
            AppError::Runtime(io::Error::other("runtime construction failed")),
            AppError::RuntimeThread(io::Error::other("runtime thread failed")),
        ] {
            assert_eq!(process_result(Err(error)), ExitCode::FAILURE);
        }
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
            Err(AppError::CodeTooLong)
        ));
        assert!(matches!(
            read_connection_code_from(&mut Cursor::new(b"000000000000000000000")),
            Err(AppError::CodeTooLong)
        ));
        assert!(matches!(
            read_connection_code_from(&mut Cursor::new([0xFF, b'\n'])),
            Err(AppError::CodeEncoding)
        ));
        assert!(matches!(
            read_connection_code_from(&mut Cursor::new(b"invalid\n")),
            Err(AppError::Code(_))
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
        assert!(matches!(invalid.into_code(), Err(AppError::Code(_))));

        let invalid: ConnectionCodeArgument = "0000-0000-0000-000U".parse().unwrap();
        assert!(matches!(
            run_command(Command::Connect {
                code: Some(invalid)
            }),
            Err(AppError::Code(_))
        ));
        let shared: ConnectionCodeArgument = "0000-0000-0000-0000".parse().unwrap();
        let retained = shared.clone();
        assert!(matches!(
            run_command(Command::Connect { code: Some(shared) }),
            Err(AppError::SharedConnectionCode)
        ));
        assert!(retained.into_code().is_ok());

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
        let (_, wss) = endpoint_config_with(&loader).unwrap();
        assert!(format!("{wss:?}").contains("has_additional_ca: true"));

        fs::write(
            directory.join("yon.toml"),
            format!("relays = ['/ip4/127.0.0.1/tcp/1/p2p/{peer}']\n"),
        )
        .unwrap();
        let (_, wss) = endpoint_config_with(&loader).unwrap();
        assert!(format!("{wss:?}").contains("has_additional_ca: false"));

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
            Err(AppError::CaRead(_))
        ));

        fs::write(directory.join("yon.toml"), "relays = 1\n").unwrap();
        assert!(matches!(
            endpoint_config_with(&loader),
            Err(AppError::Configuration(_))
        ));

        fs::write(&path, vec![0; 1024 * 1024 + 1]).unwrap();
        assert!(matches!(read_ca(&path), Err(AppError::CaTooLarge)));
        assert!(matches!(
            read_ca_document(Cursor::new(vec![0; 1024 * 1024 + 1]), 0),
            Err(AppError::CaTooLarge)
        ));
        assert!(matches!(
            read_ca_document(Cursor::new([]), 1024 * 1024 + 1),
            Err(AppError::CaTooLarge)
        ));
        assert!(matches!(
            read_ca_document(FailingReader, 0),
            Err(AppError::CaRead(_))
        ));
        fs::remove_file(&path).unwrap();
        assert!(matches!(read_ca(&path), Err(AppError::CaRead(_))));

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

    #[derive(Debug)]
    struct TestSources {
        cwd: PathBuf,
    }

    impl ConfigurationSources for TestSources {
        fn current_directory(&self) -> Result<PathBuf, io::Error> {
            Ok(self.cwd.clone())
        }

        fn system_directory(&self) -> Result<PathBuf, ConfigurationLocationError> {
            Ok(self.cwd.join("system"))
        }

        fn environment(&self) -> Vec<(OsString, OsString)> {
            Vec::new()
        }
    }

    fn test_loader(directory: PathBuf) -> LayeredConfigLoader<TestSources> {
        LayeredConfigLoader::new(TestSources { cwd: directory }, ENDPOINT_SCHEMA)
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
}
