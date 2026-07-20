#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

use clap::{Parser, Subcommand, ValueEnum};
use serde::Deserialize;
use std::fmt;
use std::fs::File;
use std::io::{IsTerminal as _, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use thiserror::Error;
use tracing_subscriber::filter::LevelFilter;
use yon_relay::{
    FileIdentityStore, IdentityError, IdentityStore, RelayServeConfig, RelayServiceError, run_relay,
};
use yonder_config::{
    Application, ConfigLoader, ConfigurationError, ConfigurationKey, ConfigurationSchema,
    LayeredConfigLoader,
};
use yonder_core::{
    CircuitBytes, CircuitCapacity, CircuitDuration, CircuitRelayLimits, DomainError,
    OsSecureRandom, RegistrationCapacity, RegistrationLimits, RelayResourceConfig,
    RelayResourceError, ReservationDuration, ResolveConcurrency, ResolveLimits, ResolveRate,
    RetryAfter, SecretDocument, SecureRandom, SourceLimiterCapacity, SourceLimiterIdle,
    SourceRegistrationCapacity,
};
use yonder_net::{
    AddressError, NetworkBuildError, RelayExternalAddress, RelayListenAddress, WssTransportConfig,
    generate_identity,
};

const MAX_WSS_CERTIFICATE_DOCUMENT: u64 = 1024 * 1024;
const MAX_WSS_PRIVATE_KEY_DOCUMENT: u64 = 64 * 1024;
const IDENTITY_KEY: ConfigurationKey = ConfigurationKey::new("identity");
const LISTEN_KEY: ConfigurationKey = ConfigurationKey::new("listen");
const EXTERNAL_KEY: ConfigurationKey = ConfigurationKey::new("external");
const WSS_CERTIFICATE_KEY: ConfigurationKey = ConfigurationKey::new("wss_certificate_der");
const WSS_PRIVATE_KEY_KEY: ConfigurationKey = ConfigurationKey::new("wss_private_key_der");
const RELAY_SCHEMA: ConfigurationSchema = ConfigurationSchema::new(
    Application::Relay,
    &[LISTEN_KEY, EXTERNAL_KEY],
    &[IDENTITY_KEY, WSS_CERTIFICATE_KEY, WSS_PRIVATE_KEY_KEY],
);

#[derive(Debug, Parser)]
#[command(name = "yon-relay", version, about)]
struct Cli {
    #[arg(long, value_enum, default_value_t = LogLevel::Info, global = true)]
    log_level: LogLevel,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    Serve,
}

#[derive(Debug, Subcommand)]
enum IdentityCommand {
    Init {
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelaySettings {
    identity: PathBuf,
    listen: Vec<String>,
    external: Vec<String>,
    wss_certificate_der: Option<PathBuf>,
    wss_private_key_der: Option<PathBuf>,
    #[serde(default)]
    registry: RegistrySettings,
    #[serde(default)]
    resolve: ResolveSettings,
    #[serde(default)]
    circuit: CircuitSettings,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RegistrySettings {
    capacity: usize,
    per_source: usize,
    reservation_duration_seconds: u64,
}

impl Default for RegistrySettings {
    fn default() -> Self {
        Self {
            capacity: 128,
            per_source: 32,
            reservation_duration_seconds: 60 * 60,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ResolveSettings {
    concurrency: usize,
    global_rate_per_second: u32,
    global_burst: u32,
    source_rate_per_second: u32,
    source_burst: u32,
    source_limiter_capacity: usize,
    source_limiter_idle_seconds: u64,
    retry_milliseconds: u32,
}

impl Default for ResolveSettings {
    fn default() -> Self {
        Self {
            concurrency: 64,
            global_rate_per_second: 4,
            global_burst: 128,
            source_rate_per_second: 1,
            source_burst: 32,
            source_limiter_capacity: 4_096,
            source_limiter_idle_seconds: 10 * 60,
            retry_milliseconds: 250,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CircuitSettings {
    capacity: usize,
    duration_seconds: u64,
    bytes: u64,
}

impl Default for CircuitSettings {
    fn default() -> Self {
        Self {
            capacity: 128,
            duration_seconds: 24 * 60 * 60,
            bytes: 8 * 1024 * 1024 * 1024,
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
}

#[derive(Debug, Error)]
enum AppError {
    #[error("failed to initialize diagnostics")]
    Diagnostics,
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error(transparent)]
    Network(#[from] NetworkBuildError),
    #[error("relay network address configuration is invalid: {0}")]
    Address(#[from] AddressError),
    #[error(transparent)]
    Service(#[from] RelayServiceError),
    #[error("failed to load relay configuration: {0}")]
    Configuration(#[from] ConfigurationError),
    #[error("relay resource configuration is invalid: {0}")]
    Resource(#[from] RelayResourceError),
    #[error("relay retry configuration is invalid: {0}")]
    Retry(#[from] DomainError),
    #[error("failed to read TLS material: {0}")]
    TlsRead(#[source] std::io::Error),
    #[error("the TLS {0} document is too large")]
    TlsTooLarge(TlsDocumentKind),
    #[error("failed to construct the async runtime: {0}")]
    Runtime(#[source] std::io::Error),
    #[error("failed to report the relay identity")]
    Output(#[source] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsDocumentKind {
    Certificate,
    PrivateKey,
}

impl TlsDocumentKind {
    const fn limit(self) -> u64 {
        match self {
            Self::Certificate => MAX_WSS_CERTIFICATE_DOCUMENT,
            Self::PrivateKey => MAX_WSS_PRIVATE_KEY_DOCUMENT,
        }
    }
}

impl fmt::Display for TlsDocumentKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Certificate => formatter.write_str("certificate"),
            Self::PrivateKey => formatter.write_str("private key"),
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(std::io::stderr().lock(), "error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), AppError> {
    let ansi = std::io::stderr().is_terminal();
    tracing_subscriber::fmt()
        .with_max_level(cli.log_level.filter())
        .with_target(false)
        .with_writer(std::io::stderr)
        .with_ansi(ansi)
        .compact()
        .try_init()
        .map_err(|_| AppError::Diagnostics)?;

    execute_command(cli.command, serve_config, serve_relay)
}

fn execute_command(
    command: Command,
    configure: impl FnOnce() -> Result<RelayServeConfig, AppError>,
    serve: impl FnOnce(RelayServeConfig) -> Result<(), AppError>,
) -> Result<(), AppError> {
    match command {
        Command::Identity {
            command: IdentityCommand::Init { output },
        } => initialize_identity(&output),
        Command::Serve => {
            let config = configure()?;
            serve(config)
        }
    }
}

fn serve_relay(config: RelayServeConfig) -> Result<(), AppError> {
    relay_runtime()?
        .block_on(run_relay(config))
        .map_err(Into::into)
}

fn relay_runtime() -> Result<tokio::runtime::Runtime, AppError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(4)
        .build()
        .map_err(AppError::Runtime)
}

fn initialize_identity(output: &Path) -> Result<(), AppError> {
    initialize_identity_with(output, &mut OsSecureRandom)
}

fn initialize_identity_with(output: &Path, random: &mut impl SecureRandom) -> Result<(), AppError> {
    let identity = generate_identity(random)?;
    let peer = identity.public().to_peer_id();
    FileIdentityStore.create(output, &identity)?;
    let stdout = std::io::stdout();
    report_peer_id_to(&mut stdout.lock(), peer).map_err(AppError::Output)?;
    Ok(())
}

fn report_peer_id_to(
    output: &mut impl std::io::Write,
    peer: yonder_net::PeerId,
) -> std::io::Result<()> {
    writeln!(output, "Relay PeerId: {peer}")?;
    output.flush()
}

fn serve_config() -> Result<RelayServeConfig, AppError> {
    serve_config_with(&LayeredConfigLoader::system(RELAY_SCHEMA))
}

fn serve_config_with(
    loader: &impl ConfigLoader<RelaySettings>,
) -> Result<RelayServeConfig, AppError> {
    let loaded = loader.load()?;
    let identity_path = loaded.resolve_path(IDENTITY_KEY, &loaded.value().identity)?;
    let certificate_path = loaded
        .value()
        .wss_certificate_der
        .as_deref()
        .map(|path| loaded.resolve_path(WSS_CERTIFICATE_KEY, path))
        .transpose()?;
    let private_key_path = loaded
        .value()
        .wss_private_key_der
        .as_deref()
        .map(|path| loaded.resolve_path(WSS_PRIVATE_KEY_KEY, path))
        .transpose()?;
    let listen = loaded
        .value()
        .listen
        .iter()
        .map(|address| address.parse::<RelayListenAddress>())
        .collect::<Result<Vec<_>, _>>()?;
    let external = loaded
        .value()
        .external
        .iter()
        .map(|address| address.parse::<RelayExternalAddress>())
        .collect::<Result<Vec<_>, _>>()?;
    let resources = relay_resources(loaded.value())?;
    let identity = FileIdentityStore.read(&identity_path)?;
    let wss = match (certificate_path, private_key_path) {
        (Some(certificate), Some(private_key)) => {
            let certificate = read_tls_document(&certificate, TlsDocumentKind::Certificate)?;
            let private_key = read_tls_document(&private_key, TlsDocumentKind::PrivateKey)?;
            WssTransportConfig::server(certificate.into_upstream_bytes(), private_key)
        }
        (None, None) => WssTransportConfig::client(None),
        _ => return Err(RelayServiceError::MissingWssCertificate.into()),
    };
    RelayServeConfig::with_resources(identity, listen, external, wss, resources)
        .map_err(AppError::from)
}

fn relay_resources(settings: &RelaySettings) -> Result<RelayResourceConfig, AppError> {
    let registration = RegistrationLimits::new(
        RegistrationCapacity::new(settings.registry.capacity)?,
        SourceRegistrationCapacity::new(settings.registry.per_source)?,
        ReservationDuration::from_seconds(settings.registry.reservation_duration_seconds)?,
    )?;
    let resolve = ResolveLimits::new(
        ResolveConcurrency::new(settings.resolve.concurrency)?,
        ResolveRate::new(
            settings.resolve.global_rate_per_second,
            settings.resolve.global_burst,
        )?,
        ResolveRate::new(
            settings.resolve.source_rate_per_second,
            settings.resolve.source_burst,
        )?,
        SourceLimiterCapacity::new(settings.resolve.source_limiter_capacity)?,
        SourceLimiterIdle::from_seconds(settings.resolve.source_limiter_idle_seconds)?,
        RetryAfter::from_millis(settings.resolve.retry_milliseconds)?,
    )?;
    let circuit = CircuitRelayLimits::new(
        CircuitCapacity::new(settings.circuit.capacity)?,
        CircuitDuration::from_seconds(settings.circuit.duration_seconds)?,
        CircuitBytes::new(settings.circuit.bytes)?,
    );
    Ok(RelayResourceConfig::new(registration, resolve, circuit))
}

fn read_tls_document(path: &Path, kind: TlsDocumentKind) -> Result<SecretDocument, AppError> {
    let file = File::open(path).map_err(AppError::TlsRead)?;
    let reported_len = file.metadata().map_err(AppError::TlsRead)?.len();
    read_tls_document_from(file, reported_len, kind)
}

fn read_tls_document_from(
    reader: impl std::io::Read,
    reported_len: u64,
    kind: TlsDocumentKind,
) -> Result<SecretDocument, AppError> {
    let limit = kind.limit();
    if reported_len > limit {
        return Err(AppError::TlsTooLarge(kind));
    }
    let mut bytes = Vec::with_capacity(reported_len as usize);
    let read = reader.take(limit + 1).read_to_end(&mut bytes);
    let document = SecretDocument::new(bytes);
    read.map_err(AppError::TlsRead)?;
    if document.as_bytes().len() as u64 > limit {
        return Err(AppError::TlsTooLarge(kind));
    }
    Ok(document)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        AppError, Cli, Command, IdentityCommand, LogLevel, RELAY_SCHEMA, TlsDocumentKind,
        execute_command, initialize_identity, initialize_identity_with, read_tls_document,
        read_tls_document_from, relay_runtime, report_peer_id_to, run, serve_config_with,
        serve_relay,
    };
    use clap::Parser;
    use std::cell::Cell;
    use std::ffi::OsString;
    use std::fs;
    use std::io;
    use std::path::PathBuf;
    use tempfile::tempdir;
    use tracing_subscriber::filter::LevelFilter;
    use yonder_config::{ConfigurationLocationError, ConfigurationSources, LayeredConfigLoader};

    const TEST_WSS_CERTIFICATE_DER: &[u8] =
        include_bytes!("../../yon/tests/fixtures/localhost-test-cert.der");
    const TEST_WSS_PRIVATE_KEY_DER: &[u8] =
        include_bytes!("../../yon/tests/fixtures/localhost-test-key.der");
    const TEST_WSS_MISMATCHED_PRIVATE_KEY_DER: &[u8] =
        include_bytes!("../../yon/tests/fixtures/localhost-self-signed-key.der");

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
    fn identity_output_is_flushed_and_broken_pipes_are_recoverable() {
        let peer = yonder_net::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let mut output = Vec::new();
        report_peer_id_to(&mut output, peer).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            format!("Relay PeerId: {peer}\n")
        );
        assert_eq!(
            report_peer_id_to(&mut FailingOutput, peer)
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn configuration_driven_cli_shape_parses() {
        let identity =
            Cli::try_parse_from(["yon-relay", "identity", "init", "--output", "relay.key"])
                .unwrap();
        assert!(matches!(identity.command, Command::Identity { .. }));

        let serve = Cli::try_parse_from(["yon-relay", "--log-level", "debug", "serve"]).unwrap();
        assert!(matches!(serve.command, Command::Serve));
        assert!(matches!(serve.log_level, LogLevel::Debug));
        assert!(Cli::try_parse_from(["yon-relay", "serve", "--identity", "legacy.key",]).is_err());
    }

    #[test]
    fn log_filters_and_layered_serve_configuration_are_complete() {
        assert_eq!(TlsDocumentKind::Certificate.to_string(), "certificate");
        assert_eq!(TlsDocumentKind::PrivateKey.to_string(), "private key");
        for (level, expected) in [
            (LogLevel::Off, LevelFilter::OFF),
            (LogLevel::Error, LevelFilter::ERROR),
            (LogLevel::Warn, LevelFilter::WARN),
            (LogLevel::Info, LevelFilter::INFO),
            (LogLevel::Debug, LevelFilter::DEBUG),
            (LogLevel::Trace, LevelFilter::TRACE),
        ] {
            assert_eq!(level.filter(), expected);
        }

        let directory = tempdir().unwrap();
        let identity = directory.path().join("relay.identity");
        initialize_identity(&identity).unwrap();
        assert!(matches!(
            initialize_identity(&identity),
            Err(AppError::Identity(_))
        ));
        write_config(
            directory.path(),
            "identity='relay.identity'\nlisten=['/ip4/127.0.0.1/tcp/0']\n",
        );
        let loader = test_loader(directory.path().to_path_buf());
        assert!(matches!(
            serve_config_with(&loader),
            Err(AppError::Configuration(_))
        ));

        write_config(
            directory.path(),
            "identity='relay.identity'\nlisten=['/ip4/127.0.0.1/tcp/0']\nexternal=['/ip4/127.0.0.1/tcp/1']\n",
        );
        assert!(serve_config_with(&loader).is_ok());

        write_config(
            directory.path(),
            "identity='relay.identity'\nlisten=['/ip4/127.0.0.1/tcp/0']\nexternal=['/ip4/127.0.0.1/tcp/1']\nwss_certificate_der='missing.der'\n",
        );
        assert!(matches!(
            serve_config_with(&loader),
            Err(AppError::Service(_))
        ));

        write_config(
            directory.path(),
            "identity='relay.identity'\nlisten=['/ip4/127.0.0.1/tcp/0']\nexternal=['/ip4/127.0.0.1/tcp/1']\nwss_certificate_der='missing.der'\nwss_private_key_der='also-missing.der'\n",
        );
        assert!(matches!(
            serve_config_with(&loader),
            Err(AppError::TlsRead(_))
        ));

        let certificate = directory.path().join("certificate.der");
        let private_key = directory.path().join("private-key.der");
        fs::write(&certificate, [1, 2, 3]).unwrap();
        write_config(
            directory.path(),
            "identity='relay.identity'\nlisten=['/ip4/127.0.0.1/tcp/0']\nexternal=['/ip4/127.0.0.1/tcp/1']\nwss_certificate_der='certificate.der'\nwss_private_key_der='missing-private-key.der'\n",
        );
        assert!(matches!(
            serve_config_with(&loader),
            Err(AppError::TlsRead(_))
        ));
        fs::write(&private_key, [4, 5, 6]).unwrap();
        assert_eq!(
            read_tls_document(&certificate, TlsDocumentKind::Certificate)
                .unwrap()
                .as_bytes(),
            &[1, 2, 3]
        );
        write_config(
            directory.path(),
            "identity='relay.identity'\nlisten=['/ip4/127.0.0.1/tcp/0']\nexternal=['/ip4/127.0.0.1/tcp/1']\nwss_certificate_der='certificate.der'\nwss_private_key_der='private-key.der'\n",
        );
        assert!(matches!(
            serve_config_with(&loader),
            Err(AppError::Service(
                yon_relay::RelayServiceError::NetworkBuild(_)
            ))
        ));

        fs::write(&certificate, TEST_WSS_CERTIFICATE_DER).unwrap();
        fs::write(&private_key, TEST_WSS_PRIVATE_KEY_DER).unwrap();
        assert!(serve_config_with(&loader).is_ok());
    }

    #[test]
    fn relay_resource_sections_are_strict_and_compositionally_validated() {
        let directory = tempdir().unwrap();
        let identity = directory.path().join("relay.identity");
        initialize_identity(&identity).unwrap();
        let loader = test_loader(directory.path().to_path_buf());
        let prefix = "identity='relay.identity'\nlisten=['/ip4/127.0.0.1/tcp/0']\nexternal=['/ip4/127.0.0.1/tcp/1']\n";

        write_config(
            directory.path(),
            &format!("{prefix}[registry]\ncapacity=1\nper_source=2\n"),
        );
        assert!(matches!(
            serve_config_with(&loader),
            Err(AppError::Resource(_))
        ));

        write_config(
            directory.path(),
            &format!("{prefix}[resolve]\nretry_milliseconds=99\n"),
        );
        assert!(matches!(
            serve_config_with(&loader),
            Err(AppError::Retry(_))
        ));

        for resolve in [
            "global_rate_per_second=0\n",
            "source_rate_per_second=0\n",
            "global_rate_per_second=1\nglobal_burst=4\nsource_rate_per_second=2\nsource_burst=4\n",
        ] {
            write_config(directory.path(), &format!("{prefix}[resolve]\n{resolve}"));
            assert!(matches!(
                serve_config_with(&loader),
                Err(AppError::Resource(_))
            ));
        }

        for resources in [
            "[registry]\ncapacity=0\n",
            "[registry]\nper_source=0\n",
            "[registry]\nreservation_duration_seconds=59\n",
            "[resolve]\nconcurrency=0\n",
            "[resolve]\nsource_limiter_capacity=0\n",
            "[resolve]\nsource_limiter_idle_seconds=0\n",
            "[circuit]\ncapacity=0\n",
            "[circuit]\nduration_seconds=59\n",
            "[circuit]\nbytes=0\n",
        ] {
            write_config(directory.path(), &format!("{prefix}{resources}"));
            assert!(matches!(
                serve_config_with(&loader),
                Err(AppError::Resource(_))
            ));
        }

        write_config(directory.path(), &format!("{prefix}[circuit]\nunknown=1\n"));
        assert!(matches!(
            serve_config_with(&loader),
            Err(AppError::Configuration(_))
        ));

        write_config(
            directory.path(),
            &format!(
                "{prefix}[registry]\ncapacity=64\nper_source=8\nreservation_duration_seconds=120\n\
                 [resolve]\nconcurrency=16\nglobal_rate_per_second=8\nglobal_burst=64\n\
                 source_rate_per_second=1\nsource_burst=8\nsource_limiter_capacity=4096\n\
                 source_limiter_idle_seconds=60\nretry_milliseconds=500\n\
                 [circuit]\ncapacity=64\nduration_seconds=3600\nbytes=1073741824\n"
            ),
        );
        assert!(serve_config_with(&loader).is_ok());
    }

    #[test]
    fn tls_documents_are_bounded_before_and_during_reads() {
        use std::io::{self, Cursor, Read};

        assert_eq!(
            read_tls_document_from(
                Cursor::new(vec![0_u8; 64 * 1024]),
                64 * 1024,
                TlsDocumentKind::PrivateKey,
            )
            .unwrap()
            .as_bytes()
            .len(),
            64 * 1024
        );
        assert_eq!(
            read_tls_document_from(
                Cursor::new(vec![0_u8; 1024 * 1024]),
                1024 * 1024,
                TlsDocumentKind::Certificate,
            )
            .unwrap()
            .as_bytes()
            .len(),
            1024 * 1024
        );
        assert!(matches!(
            read_tls_document_from(
                Cursor::new(Vec::new()),
                64 * 1024 + 1,
                TlsDocumentKind::PrivateKey,
            ),
            Err(AppError::TlsTooLarge(TlsDocumentKind::PrivateKey))
        ));
        assert!(matches!(
            read_tls_document_from(
                Cursor::new(vec![0_u8; 64 * 1024 + 1]),
                64 * 1024,
                TlsDocumentKind::PrivateKey,
            ),
            Err(AppError::TlsTooLarge(TlsDocumentKind::PrivateKey))
        ));
        assert!(matches!(
            read_tls_document_from(FailingReader, 0, TlsDocumentKind::Certificate),
            Err(AppError::TlsRead(error)) if error.kind() == io::ErrorKind::Other
        ));

        struct FailingReader;

        impl Read for FailingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("read failed"))
            }
        }
    }

    #[test]
    fn serve_command_validates_configuration_before_invoking_the_runner() {
        let called = Cell::new(false);
        execute_command(
            Command::Serve,
            || {
                yon_relay::RelayServeConfig::new(
                    yonder_net::Keypair::generate_ed25519(),
                    vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
                    vec!["/ip4/127.0.0.1/tcp/1".parse().unwrap()],
                    yonder_net::WssTransportConfig::client(None),
                )
                .map_err(AppError::from)
            },
            |config| {
                called.set(true);
                drop(config);
                Ok(())
            },
        )
        .unwrap();
        assert!(called.get());

        let missing_called = Cell::new(false);
        assert!(matches!(
            execute_command(
                Command::Serve,
                || Err(yonder_core::RelayResourceError::SourceRegistrationExceedsTotal.into()),
                |config| {
                    missing_called.set(true);
                    drop(config);
                    Ok(())
                },
            ),
            Err(AppError::Resource(_))
        ));
        assert!(!missing_called.get());

        let directory = tempdir().unwrap();
        let configured = Cell::new(false);
        execute_command(
            Command::Identity {
                command: IdentityCommand::Init {
                    output: directory.path().join("identity"),
                },
            },
            || {
                configured.set(true);
                yon_relay::RelayServeConfig::new(
                    yonder_net::Keypair::generate_ed25519(),
                    vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
                    Vec::new(),
                    yonder_net::WssTransportConfig::client(None),
                )
                .map_err(AppError::from)
            },
            |_| Ok(()),
        )
        .unwrap();
        assert!(!configured.get());

        let runtime = relay_runtime().unwrap();
        assert_eq!(runtime.block_on(async { 7_u8 }), 7);
    }

    #[test]
    fn mismatched_wss_key_is_rejected_by_the_real_relay_transport() {
        let config = yon_relay::RelayServeConfig::new(
            yonder_net::Keypair::generate_ed25519(),
            vec!["/ip4/127.0.0.1/tcp/0/tls/ws".parse().unwrap()],
            vec!["/dns4/localhost/tcp/443/tls/ws".parse().unwrap()],
            yonder_net::WssTransportConfig::server(
                TEST_WSS_CERTIFICATE_DER.to_vec(),
                yonder_core::SecretDocument::new(TEST_WSS_MISMATCHED_PRIVATE_KEY_DER.to_vec()),
            ),
        )
        .unwrap();

        assert!(matches!(
            serve_relay(config),
            Err(AppError::Service(
                yon_relay::RelayServiceError::NetworkBuild(
                    yonder_net::NetworkBuildError::InvalidTlsMaterial
                )
            ))
        ));
    }

    #[test]
    fn invalid_address_configuration_fails_before_identity_loading() {
        let directory = tempdir().unwrap();
        let loader = test_loader(directory.path().to_path_buf());
        write_config(
            directory.path(),
            "identity='missing.identity'\nlisten=['/dns4/not-bindable/tcp/1']\nexternal=['/ip4/127.0.0.1/tcp/1']\n",
        );
        assert!(matches!(
            serve_config_with(&loader),
            Err(AppError::Address(_))
        ));

        write_config(
            directory.path(),
            "identity='missing.identity'\nlisten=['/ip4/127.0.0.1/tcp/0']\nexternal=['not-a-multiaddr']\n",
        );
        assert!(matches!(
            serve_config_with(&loader),
            Err(AppError::Address(_))
        ));

        for path in [
            "identity=''\n",
            "identity='missing.identity'\nwss_certificate_der=''\n",
            "identity='missing.identity'\nwss_private_key_der=''\n",
        ] {
            write_config(
                directory.path(),
                &format!(
                    "{path}listen=['/ip4/127.0.0.1/tcp/0']\nexternal=['/ip4/127.0.0.1/tcp/1']\n"
                ),
            );
            assert!(matches!(
                serve_config_with(&loader),
                Err(AppError::Configuration(_))
            ));
        }

        write_config(
            directory.path(),
            "identity='missing.identity'\nlisten=['/ip4/127.0.0.1/tcp/0']\nexternal=['/ip4/127.0.0.1/tcp/1']\n",
        );
        assert!(matches!(
            serve_config_with(&loader),
            Err(AppError::Identity(_))
        ));
    }

    fn relay_config() -> yon_relay::RelayServeConfig {
        yon_relay::RelayServeConfig::new(
            yonder_net::Keypair::generate_ed25519(),
            vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            vec!["/ip4/127.0.0.1/tcp/1".parse().unwrap()],
            yonder_net::WssTransportConfig::client(None),
        )
        .unwrap()
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
        LayeredConfigLoader::new(TestSources { cwd: directory }, RELAY_SCHEMA)
    }

    fn write_config(directory: &std::path::Path, contents: &str) {
        fs::write(directory.join("yon-relay.toml"), contents).unwrap();
    }

    #[test]
    fn relay_configuration_rejects_invalid_tls_before_startup() {
        assert!(matches!(
            yon_relay::RelayServeConfig::new(
                yonder_net::Keypair::generate_ed25519(),
                vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
                vec!["/ip4/127.0.0.1/tcp/1".parse().unwrap()],
                yonder_net::WssTransportConfig::server(
                    vec![1, 2, 3],
                    yonder_core::SecretDocument::new(vec![4, 5, 6]),
                ),
            ),
            Err(yon_relay::RelayServiceError::NetworkBuild(_))
        ));

        let directory = tempdir().unwrap();
        assert!(matches!(
            initialize_identity_with(
                &directory.path().join("failed.identity"),
                &mut FailingRandom,
            ),
            Err(AppError::Network(_))
        ));
        drop(relay_config());
    }

    #[test]
    fn diagnostics_initialization_is_single_owner() {
        let directory = tempdir().unwrap();
        let first = run(Cli {
            log_level: LogLevel::Off,
            command: Command::Identity {
                command: IdentityCommand::Init {
                    output: directory.path().join("first.identity"),
                },
            },
        });
        assert!(first.is_ok());
        assert!(matches!(
            run(Cli {
                log_level: LogLevel::Off,
                command: Command::Identity {
                    command: IdentityCommand::Init {
                        output: directory.path().join("second.identity"),
                    },
                },
            }),
            Err(AppError::Diagnostics)
        ));
    }

    struct FailingRandom;

    impl yonder_core::SecureRandom for FailingRandom {
        fn try_fill(&mut self, _destination: &mut [u8]) -> Result<(), yonder_core::RandomError> {
            Err(yonder_core::RandomError)
        }
    }
}
