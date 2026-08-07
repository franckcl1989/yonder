#![forbid(unsafe_code)]

#[cfg(any(unix, windows))]
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use yon::network::{
    EndpointDriver, EndpointError, ReservationLease, connect_relay, wait_for_reservation,
};
use yon::protocol::{
    ReclaimResponse, RelayProtocolError, ResolveDeadline, reclaim_locator, resolve_peer,
};
use yon_relay::{FileIdentityStore, IdentityStore, RelayServeConfig, run_relay_until};
use yonder_core::{ConnectionCode, Locator, OsSecureRandom, SecretDocument};
use yonder_net::{
    EndpointRelayAddress, EndpointRelaySet, Keypair, RelayExternalAddress, RelayListenAddress,
    WssCertificateChain, WssPrivateKey, WssTransportConfig, generate_identity,
};

const START_TIMEOUT: Duration = Duration::from_secs(45);
const SESSION_TIMEOUT: Duration = Duration::from_secs(60);
const CLAIM_STEP_TIMEOUT: Duration = Duration::from_secs(10);
const HOST_ENVIRONMENT_VALUE: &str = "inherited-by-remote-shell";
#[cfg(any(unix, windows))]
const CONTROLLER_LOG_SENTINEL: &[u8] = b"YON_E2E_LOG_SENTINEL\n";
#[cfg(any(unix, windows))]
const PERFORMANCE_PAYLOAD_BYTE: u8 = b'~';
#[cfg(any(unix, windows))]
const PERFORMANCE_PAYLOAD_LEN: usize = 8 * 1024 * 1024;
#[cfg(any(unix, windows))]
const PERFORMANCE_PAYLOAD_LINE_LEN: usize = 64;
#[cfg(any(unix, windows))]
const PERFORMANCE_PAYLOAD_BYTE_COUNT: usize =
    PERFORMANCE_PAYLOAD_LEN - (PERFORMANCE_PAYLOAD_LEN / PERFORMANCE_PAYLOAD_LINE_LEN);
#[cfg(any(unix, windows))]
const PERFORMANCE_PAYLOAD_BEGIN: &[u8] = b"YON_E2E_PERFORMANCE_BEGIN";
#[cfg(any(unix, windows))]
const PERFORMANCE_PAYLOAD_END: &[u8] = b"YON_E2E_PERFORMANCE_END";
const TEST_WSS_CA_DER: &[u8] = include_bytes!("fixtures/localhost-test-ca.der");
const TEST_WSS_CERT_DER: &[u8] = include_bytes!("fixtures/localhost-test-cert.der");
const TEST_WSS_KEY_DER: &[u8] = include_bytes!("fixtures/localhost-test-key.der");
const TEST_WSS_SELF_SIGNED_CERT_DER: &[u8] =
    include_bytes!("fixtures/localhost-self-signed-cert.der");
const TEST_WSS_SELF_SIGNED_KEY_DER: &[u8] =
    include_bytes!("fixtures/localhost-self-signed-key.der");
#[cfg(windows)]
const WINDOWS_PROBE_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(windows)]
const WINDOWS_ESCAPE_READY: &[u8] = b"YON_WAIT_ESCAPE";
#[cfg(windows)]
const WINDOWS_ARROW_READY: &[u8] = b"YON_WAIT_ARROW";
#[cfg(windows)]
const WINDOWS_ESCAPE_PROBE: &str = concat!(
    "powershell.exe -NoLogo -NoProfile -Command ",
    "\"[Console]::WriteLine(([char[]](89,79,78,95,87,65,73,84,95,69,83,67,65,80,69)-join '')); ",
    "$k=[Console]::ReadKey($true); ",
    "[Console]::WriteLine(('YON_KEY_ESCAPE={0}:{1}' -f $k.Key,[int]$k.KeyChar))\"\r",
);
#[cfg(windows)]
const WINDOWS_ARROW_PROBE: &str = concat!(
    "powershell.exe -NoLogo -NoProfile -Command ",
    "\"[Console]::WriteLine(([char[]](89,79,78,95,87,65,73,84,95,65,82,82,79,87)-join '')); ",
    "$a=[Console]::ReadKey($true); $b=[Console]::ReadKey($true); ",
    "$c=[Console]::ReadKey($true); ",
    "[Console]::WriteLine(('YON_KEY_ARROW={0},{1},{2}' -f ",
    "[int]$a.KeyChar,[int]$b.KeyChar,[int]$c.KeyChar))\"\r",
);

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct EndpointConfigDirectory {
    path: PathBuf,
}

impl EndpointConfigDirectory {
    fn new(relay: &str) -> Result<Self, std::io::Error> {
        Self::new_many(&[relay.to_owned()])
    }

    fn new_many(relays: &[String]) -> Result<Self, std::io::Error> {
        Self::new_many_with_ca(relays, None)
    }

    fn new_many_with_ca(relays: &[String], ca_der: Option<&[u8]>) -> Result<Self, std::io::Error> {
        let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("yonder-e2e-{}-{sequence}", std::process::id()));
        match std::fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        std::fs::create_dir(&path)?;
        let relays = relays
            .iter()
            .map(|relay| format!("\"{relay}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let ca_config = if let Some(ca_der) = ca_der {
            std::fs::write(path.join("wss-ca.der"), ca_der)?;
            "wss_ca = \"wss-ca.der\"\n"
        } else {
            ""
        };
        std::fs::write(
            path.join("yon.toml"),
            format!("relays = [{relays}]\n{ca_config}"),
        )?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for EndpointConfigDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[test]
fn three_process_terminal_session_executes_a_real_shell() -> Result<(), std::io::Error> {
    let port = available_port()?;
    let identity = generate_identity(&mut OsSecureRandom)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let peer = identity.public().to_peer_id();
    let relay_process = RelayProcess::start(identity, port)?;

    thread::sleep(Duration::from_millis(500));
    let relay = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}");
    let outcome = (|| {
        run_host_controller(&relay, CodeInput::Argument)?;
        run_host_controller(&relay, CodeInput::Stdin)
    })();
    let relay_result = relay_process.stop();

    outcome?;
    relay_result
}

#[cfg(any(unix, windows))]
#[test]
#[ignore = "release process performance gate"]
fn process_terminal_throughput_baseline_uses_the_real_product_path() -> Result<(), std::io::Error> {
    const SAMPLE_COUNT: usize = 10;
    const MIN_REMOTE_BYTES_PER_SECOND: f64 = 384.0 * 1024.0;
    const MIN_REMOTE_TO_LOCAL_PTY_RATIO: f64 = 0.70;
    let port = available_port()?;
    let relay_process = RelayBinaryProcess::start(port)?;
    let peer = relay_process.peer();
    let config = EndpointConfigDirectory::new(&format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}"))?;
    let payload = config.path().join("throughput.bin");
    let mut payload_bytes = vec![PERFORMANCE_PAYLOAD_BYTE; PERFORMANCE_PAYLOAD_LEN];
    for line_break in payload_bytes
        .iter_mut()
        .skip(PERFORMANCE_PAYLOAD_LINE_LEN - 1)
        .step_by(PERFORMANCE_PAYLOAD_LINE_LEN)
    {
        *line_break = b'\n';
    }
    std::fs::write(&payload, payload_bytes)?;
    let outcome = (|| {
        let mut samples = Vec::with_capacity(SAMPLE_COUNT);
        for sample_index in 1..=SAMPLE_COUNT {
            let direct = measure_direct_file_output(&payload)?;
            let local_pty = measure_local_pty_file_output(&payload)?;
            let host = HostProcess::start(&config)?;
            let session = (|| {
                let code = receive_code(&host.lines)?;
                run_controller_session_with_script(
                    &config,
                    &code,
                    CodeInput::Stdin,
                    throughput_command_script(),
                )
            })();
            let host_result = if session.is_ok() {
                host.finish()
            } else {
                host.terminate();
                Ok(())
            };
            let remote = session?;
            host_result?;

            let direct_payload_bytes = direct
                .bytes
                .iter()
                .filter(|byte| **byte == PERFORMANCE_PAYLOAD_BYTE)
                .count();
            let local_pty_payload_bytes = framed_performance_payload_bytes(&local_pty.bytes)
                .ok_or_else(|| std::io::Error::other("local PTY payload framing was missing"))?;
            let remote_payload_bytes = remote
                .payload_bytes
                .ok_or_else(|| std::io::Error::other("remote payload framing was missing"))?;
            if direct_payload_bytes != PERFORMANCE_PAYLOAD_BYTE_COUNT
                || local_pty_payload_bytes != PERFORMANCE_PAYLOAD_BYTE_COUNT
                || remote_payload_bytes != PERFORMANCE_PAYLOAD_BYTE_COUNT
            {
                return Err(std::io::Error::other(format!(
                    "throughput payload byte count differed from {PERFORMANCE_PAYLOAD_BYTE_COUNT}: direct={direct_payload_bytes} local_pty={local_pty_payload_bytes} remote={remote_payload_bytes}",
                )));
            }
            let sample = ThroughputSample {
                direct_bytes_per_second: throughput(PERFORMANCE_PAYLOAD_LEN, direct.active)?,
                local_pty_bytes_per_second: throughput(PERFORMANCE_PAYLOAD_LEN, local_pty.active)?,
                remote_bytes_per_second: throughput(
                    PERFORMANCE_PAYLOAD_LEN,
                    remote.transfer_duration,
                )?,
            };
            println!(
                "YONDER_PERFORMANCE_SAMPLE sample={sample_index}/{SAMPLE_COUNT} payload_bytes={PERFORMANCE_PAYLOAD_LEN} direct_active_ns={} local_pty_active_ns={} remote_active_ns={} direct_bytes_per_second={:.0} local_pty_bytes_per_second={:.0} remote_bytes_per_second={:.0} remote_to_local_pty_ratio={:.6}",
                direct.active.as_nanos(),
                local_pty.active.as_nanos(),
                remote.transfer_duration.as_nanos(),
                sample.direct_bytes_per_second,
                sample.local_pty_bytes_per_second,
                sample.remote_bytes_per_second,
                sample.remote_to_local_pty_ratio(),
            );
            samples.push(sample);
        }
        Ok::<_, std::io::Error>(samples)
    })();
    let relay_result = relay_process.stop();
    let samples = match (outcome, relay_result) {
        (Ok(samples), Ok(())) => samples,
        (Err(error), Ok(())) | (Ok(_), Err(error)) => return Err(error),
        (Err(error), Err(relay_error)) => {
            return Err(std::io::Error::other(format!(
                "{error}; relay process also failed: {relay_error}",
            )));
        }
    };
    let direct = median(samples.iter().map(|sample| sample.direct_bytes_per_second));
    let local_pty = median(
        samples
            .iter()
            .map(|sample| sample.local_pty_bytes_per_second),
    );
    let remote = median(samples.iter().map(|sample| sample.remote_bytes_per_second));
    let ratio = median(
        samples
            .iter()
            .map(ThroughputSample::remote_to_local_pty_ratio),
    );
    println!(
        "YONDER_PERFORMANCE_MEDIAN samples={SAMPLE_COUNT} payload_bytes={PERFORMANCE_PAYLOAD_LEN} direct_bytes_per_second={direct:.0} local_pty_bytes_per_second={local_pty:.0} remote_bytes_per_second={remote:.0} remote_to_local_pty_ratio={ratio:.6}",
    );
    if remote < MIN_REMOTE_BYTES_PER_SECOND || ratio < MIN_REMOTE_TO_LOCAL_PTY_RATIO {
        return Err(std::io::Error::other(format!(
            "terminal throughput gate failed: remote={remote:.0}B/s ratio={ratio:.6} minimum_remote={MIN_REMOTE_BYTES_PER_SECOND:.0}B/s minimum_ratio={MIN_REMOTE_TO_LOCAL_PTY_RATIO:.2}",
        )));
    }
    Ok(())
}

#[test]
fn pinned_relay_identity_rejects_an_impersonator_before_code_publication()
-> Result<(), std::io::Error> {
    let port = available_port()?;
    let impersonator = generate_identity(&mut OsSecureRandom)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let expected = generate_identity(&mut OsSecureRandom)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let relay_process = RelayProcess::start(impersonator, port)?;
    wait_for_tcp_listener(port)?;
    let relay = format!(
        "/ip4/127.0.0.1/tcp/{port}/p2p/{}",
        expected.public().to_peer_id()
    );
    let config = EndpointConfigDirectory::new(&relay)?;

    let outcome = run_rejected_host(&config);
    let relay_result = relay_process.stop();
    outcome?;
    relay_result
}

#[test]
fn tampering_transport_proxy_fails_closed_before_code_publication() -> Result<(), std::io::Error> {
    let relay_port = available_port()?;
    let identity = generate_identity(&mut OsSecureRandom)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let peer = identity.public().to_peer_id();
    let relay_process = RelayProcess::start(identity, relay_port)?;
    wait_for_tcp_listener(relay_port)?;
    let proxy = TamperingTcpProxy::start(relay_port)?;
    let relay = format!("/ip4/127.0.0.1/tcp/{}/p2p/{peer}", proxy.listen_port());
    let config = EndpointConfigDirectory::new(&relay)?;

    let outcome = run_rejected_host(&config);
    let proxy_result = proxy.stop();
    let relay_result = relay_process.stop();
    outcome?;
    proxy_result?;
    relay_result
}

#[cfg(yonder_e2e_rebuild)]
#[test]
fn strict_relay_only_fallback_rebuilds_the_controller_swarm() -> Result<(), std::io::Error> {
    let port = available_port()?;
    let identity = generate_identity(&mut OsSecureRandom)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let peer = identity.public().to_peer_id();
    let relay_process = RelayProcess::start(identity, port)?;
    thread::sleep(Duration::from_millis(500));
    let config = EndpointConfigDirectory::new(&format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}"))?;

    let outcome = run_host_controller_with_evidence(&config, CodeInput::Stdin);
    let relay_result = relay_process.stop();
    let evidence = outcome?;
    relay_result?;
    validate_required_controller_rebuild(&evidence.diagnostics)
}

#[test]
fn quic_and_websocket_relay_transports_run_real_terminal_sessions() -> Result<(), std::io::Error> {
    for transport in [RelayTransport::Quic, RelayTransport::WebSocket] {
        let port = transport.available_port()?;
        let identity = generate_identity(&mut OsSecureRandom)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let peer = identity.public().to_peer_id();
        let address = transport.address(port);
        let relay_process =
            RelayProcess::start_addresses(identity, vec![address.clone()], vec![address.clone()])?;
        thread::sleep(Duration::from_millis(500));
        let endpoint = format!("{address}/p2p/{peer}");
        let outcome = run_host_controller(&endpoint, CodeInput::Stdin);
        let relay_result = relay_process.stop();
        outcome?;
        relay_result?;
    }
    Ok(())
}

#[test]
fn secure_websocket_runs_a_real_tls_terminal_session() -> Result<(), std::io::Error> {
    run_secure_websocket_session(
        "dns4/localhost",
        TEST_WSS_CERT_DER,
        TEST_WSS_KEY_DER,
        TEST_WSS_CA_DER,
        Some(TEST_WSS_CA_DER),
    )
}

#[test]
fn secure_websocket_accepts_an_explicitly_trusted_self_signed_ip_certificate()
-> Result<(), std::io::Error> {
    run_secure_websocket_session(
        "ip4/127.0.0.1",
        TEST_WSS_SELF_SIGNED_CERT_DER,
        TEST_WSS_SELF_SIGNED_KEY_DER,
        TEST_WSS_SELF_SIGNED_CERT_DER,
        None,
    )
}

#[test]
fn enterprise_relay_serves_callback_https_and_rejects_malformed_callbacks()
-> Result<(), std::io::Error> {
    let port = available_port()?;
    let callback_port = available_port()?;
    let identity = generate_identity(&mut OsSecureRandom)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let relay_process = RelayProcess::start_enterprise(identity, port, callback_port)?;
    thread::sleep(Duration::from_millis(500));

    let status = enterprise_callback_request(
        callback_port,
        "GET / HTTP/1.1\r\nHost: relay.example.test\r\nConnection: close\r\n\r\n",
    )?;
    assert!(status.starts_with("HTTP/1.1 404"), "{status}");
    let status = enterprise_callback_request(
        callback_port,
        "GET /yonder/callback/wecom HTTP/1.1\r\nHost: relay.example.test\r\nConnection: close\r\n\r\n",
    )?;
    assert!(status.starts_with("HTTP/1.1 400"), "{status}");
    let status = enterprise_callback_request(
        callback_port,
        "GET /yonder/callback/wecom?code=a HTTP/1.1\r\nHost: relay.example.test\r\nConnection: close\r\n\r\n",
    )?;
    assert!(status.starts_with("HTTP/1.1 400"), "{status}");
    let status = enterprise_callback_request(
        callback_port,
        "POST /yonder/callback/wecom?code=a&state=b HTTP/1.1\r\nHost: relay.example.test\r\nConnection: close\r\n\r\n",
    )?;
    assert!(status.starts_with("HTTP/1.1 405"), "{status}");

    relay_process.stop()
}

#[test]
fn legacy_resolve_is_rejected_by_enterprise_relays() -> Result<(), std::io::Error> {
    let port = available_port()?;
    let callback_port = available_port()?;
    let identity = generate_identity(&mut OsSecureRandom)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let peer = identity.public().to_peer_id();
    let relay_process = RelayProcess::start_enterprise(identity, port, callback_port)?;
    thread::sleep(Duration::from_millis(500));

    let address: EndpointRelayAddress = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}")
        .parse()
        .map_err(|error: yonder_net::AddressError| std::io::Error::other(error.to_string()))?;
    let relays = EndpointRelaySet::new(vec![address])
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let client_identity = generate_identity(&mut OsSecureRandom)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let outcome = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| std::io::Error::other(error.to_string()))?
        .block_on(async {
            let (mut driver, mut streams, relay) =
                connect_relay(client_identity, &relays, WssTransportConfig::client(None))
                    .await
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
            resolve_peer(
                &mut driver,
                &mut streams,
                &relay,
                Locator::new(7).unwrap(),
                ResolveDeadline::controller(),
            )
            .await
        });
    let relay_result = relay_process.stop();
    assert!(matches!(
        outcome,
        Err(RelayProtocolError::Endpoint(EndpointError::Application(
            yonder_net::ApplicationStreamError::UnsupportedProtocol
        )))
    ));
    relay_result
}

#[test]
fn hosts_register_through_enterprise_relays() -> Result<(), std::io::Error> {
    let port = available_port()?;
    let callback_port = available_port()?;
    let identity = generate_identity(&mut OsSecureRandom)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let peer = identity.public().to_peer_id();
    let relay_process = RelayProcess::start_enterprise(identity, port, callback_port)?;
    thread::sleep(Duration::from_millis(500));
    let relay = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}");
    let config = EndpointConfigDirectory::new(&relay)?;

    let host = HostProcess::start(&config)?;
    let code = receive_code(&host.lines)
        .map_err(|error| std::io::Error::other(format!("host did not register: {error}")))?;
    assert!(!code.is_empty());
    host.terminate();

    relay_process.stop()
}

#[test]
fn unauthenticated_connects_are_rejected_by_enterprise_relays() -> Result<(), std::io::Error> {
    let port = available_port()?;
    let callback_port = available_port()?;
    let identity = generate_identity(&mut OsSecureRandom)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let peer = identity.public().to_peer_id();
    let relay_process = RelayProcess::start_enterprise(identity, port, callback_port)?;
    thread::sleep(Duration::from_millis(500));
    let relay = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}");
    let config = EndpointConfigDirectory::new(&relay)?;
    // A valid code still cannot connect: the enterprise relay requires a
    // completed browser authentication, and with no terminal input the
    // platform prompt ends, so the connect fails closed.
    let generated = ConnectionCode::generate(Locator::new(7).unwrap(), &mut OsSecureRandom)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let code = generated.expose().to_string();
    let mut controller = Command::new(env!("CARGO_BIN_EXE_yon"))
        .args(["connect", code.as_str()])
        .current_dir(config.path())
        .env_remove("YON_RELAYS")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = controller
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("controller stdout was not piped"))?;
    let stderr = controller
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("controller stderr was not piped"))?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        BufReader::new(stdout)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        BufReader::new(stderr)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let status = match wait_for_exit(&mut controller, SESSION_TIMEOUT) {
        Ok(status) => status,
        Err(error) => {
            let _ = controller.kill();
            let _ = controller.wait();
            relay_process.stop()?;
            return Err(error);
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| std::io::Error::other("controller stdout reader panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| std::io::Error::other("controller stderr reader panicked"))??;
    let relay_result = relay_process.stop();
    if status.success() {
        return Err(std::io::Error::other(
            "controller connected without completing enterprise authentication",
        ));
    }
    let stderr = String::from_utf8(stderr).map_err(std::io::Error::other)?;
    if !stderr.contains("enterprise authentication was not completed") {
        return Err(std::io::Error::other(format!(
            "an enterprise relay exposed an unexpected public error: {stderr:?}"
        )));
    }
    for forbidden in ["OPAQUE", "PeerId", "locator", &code.to_string()] {
        if stderr.contains(forbidden) {
            return Err(std::io::Error::other(format!(
                "an enterprise rejection leaked {forbidden:?} in its public error"
            )));
        }
    }
    if !stdout.is_empty() && !String::from_utf8_lossy(&stdout).contains("请选择企业认证平台")
    {
        return Err(std::io::Error::other(
            "an enterprise rejection wrote unexpected output to stdout",
        ));
    }
    relay_result
}

/// Executes one HTTPS request against the enterprise callback listener,
/// trusting the fixture CA, and returns the response status line.
fn enterprise_callback_request(
    callback_port: u16,
    request: &str,
) -> Result<String, std::io::Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    runtime.block_on(async {
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots
            .add(tokio_rustls::rustls::pki_types::CertificateDer::from(
                TEST_WSS_CA_DER.to_vec(),
            ))
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let client = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client));
        let server_name =
            tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", callback_port))
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let mut tls = connector
            .connect(server_name, stream)
            .await
            .map_err(|error| {
                std::io::Error::other(format!("callback TLS handshake failed: {error}"))
            })?;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        tls.write_all(request.as_bytes()).await?;
        let mut bytes = Vec::new();
        tls.read_to_end(&mut bytes).await?;
        let text = String::from_utf8_lossy(&bytes);
        Ok(text.lines().next().unwrap_or_default().to_owned())
    })
}

fn run_secure_websocket_session(
    external_host: &str,
    certificate_der: &[u8],
    private_key_der: &[u8],
    trust_anchor_der: &[u8],
    issuer_der: Option<&[u8]>,
) -> Result<(), std::io::Error> {
    let port = available_port()?;
    let identity = generate_identity(&mut OsSecureRandom)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let peer = identity.public().to_peer_id();
    let listen = format!("/ip4/127.0.0.1/tcp/{port}/tls/ws");
    let external = format!("/{external_host}/tcp/{port}/tls/ws");
    let certificate_chain = WssCertificateChain::from_documents(
        std::iter::once(certificate_der.to_vec()).chain(issuer_der.into_iter().map(<[u8]>::to_vec)),
    )
    .map_err(|error| std::io::Error::other(error.to_string()))?;
    let private_key = WssPrivateKey::from_document(SecretDocument::new(private_key_der.to_vec()))
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let relay_process = RelayProcess::start_addresses_with_wss(
        identity,
        vec![listen],
        vec![external.clone()],
        WssTransportConfig::server_with_chain(certificate_chain, private_key),
    )?;
    thread::sleep(Duration::from_millis(500));
    let config = EndpointConfigDirectory::new_many_with_ca(
        &[format!("{external}/p2p/{peer}")],
        Some(trust_anchor_der),
    )?;
    let outcome = run_host_controller_in_config(&config, CodeInput::Stdin);
    let relay_result = relay_process.stop();
    outcome?;
    relay_result
}

#[test]
fn blocked_udp_candidate_falls_back_to_tcp() -> Result<(), std::io::Error> {
    let tcp_port = available_port()?;
    let quic_port = available_udp_port()?;
    let identity = generate_identity(&mut OsSecureRandom)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let peer = identity.public().to_peer_id();
    let tcp = format!("/ip4/127.0.0.1/tcp/{tcp_port}");
    let quic = format!("/ip4/127.0.0.1/udp/{quic_port}/quic-v1");
    let relay_process = RelayProcess::start_addresses(
        identity,
        vec![tcp.clone(), quic.clone()],
        vec![tcp.clone(), quic.clone()],
    )?;
    thread::sleep(Duration::from_millis(500));

    let blocked_udp = UdpSocket::bind(("127.0.0.1", 0))?;
    let blocked_udp_address = format!(
        "/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{peer}",
        blocked_udp.local_addr()?.port()
    );
    run_host_controller_with_relays(
        &[blocked_udp_address, format!("{tcp}/p2p/{peer}")],
        CodeInput::Stdin,
    )?;
    drop(blocked_udp);
    relay_process.stop()
}

#[test]
fn blocked_tcp_candidate_falls_back_to_quic() -> Result<(), std::io::Error> {
    let tcp_port = available_port()?;
    let quic_port = available_udp_port()?;
    let identity = generate_identity(&mut OsSecureRandom)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let peer = identity.public().to_peer_id();
    let tcp = format!("/ip4/127.0.0.1/tcp/{tcp_port}");
    let quic = format!("/ip4/127.0.0.1/udp/{quic_port}/quic-v1");
    let relay_process = RelayProcess::start_addresses(
        identity,
        vec![tcp.clone(), quic.clone()],
        vec![tcp, quic.clone()],
    )?;
    thread::sleep(Duration::from_millis(500));
    let blocked_tcp = TcpListener::bind(("127.0.0.1", 0))?;
    let blocked_tcp_address = format!(
        "/ip4/127.0.0.1/tcp/{}/p2p/{peer}",
        blocked_tcp.local_addr()?.port()
    );
    run_host_controller_with_relays(
        &[blocked_tcp_address, format!("{quic}/p2p/{peer}")],
        CodeInput::Stdin,
    )?;
    drop(blocked_tcp);
    relay_process.stop()
}

#[derive(Clone, Copy)]
enum RelayTransport {
    Quic,
    WebSocket,
}

impl RelayTransport {
    fn available_port(self) -> Result<u16, std::io::Error> {
        match self {
            Self::Quic => available_udp_port(),
            Self::WebSocket => available_port(),
        }
    }

    fn address(self, port: u16) -> String {
        match self {
            Self::Quic => format!("/ip4/127.0.0.1/udp/{port}/quic-v1"),
            Self::WebSocket => format!("/ip4/127.0.0.1/tcp/{port}/ws"),
        }
    }
}

#[cfg(unix)]
#[test]
fn interactive_pty_preserves_bytes_resize_interrupt_environment_and_exit()
-> Result<(), std::io::Error> {
    run_interactive_pty(false)
}

#[cfg(unix)]
#[test]
fn interactive_pty_appends_diagnostics_without_contaminating_terminal() -> Result<(), std::io::Error>
{
    run_interactive_pty(true)
}

#[cfg(unix)]
fn run_interactive_pty(diagnostic_log: bool) -> Result<(), std::io::Error> {
    let port = available_port()?;
    let identity = generate_identity(&mut OsSecureRandom)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let peer = identity.public().to_peer_id();
    let relay_process = RelayProcess::start(identity, port)?;
    wait_for_tcp_listener(port)?;
    let relay = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}");
    let config = EndpointConfigDirectory::new(&relay)?;
    let mut host = HostProcess::start(&config)?;
    let code = receive_code(&host.lines)?;
    let controller_log = diagnostic_log.then(|| config.path().join("controller-debug.log"));
    if let Some(path) = &controller_log {
        std::fs::write(path, CONTROLLER_LOG_SENTINEL)?;
    }

    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 33,
            cols: 91,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(std::io::Error::other)?;
    let reader = pair
        .master
        .try_clone_reader()
        .map_err(std::io::Error::other)?;
    let mut writer = pair.master.take_writer().map_err(std::io::Error::other)?;
    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_yon"));
    if let Some(path) = &controller_log {
        command.args(["--log-level", "debug", "--log-file"]);
        command.arg(path.as_os_str());
    }
    command.args(["connect", &code.to_string()]);
    command.cwd(config.path());
    command.env("TERM", "xterm-256color");
    command.env("COLORTERM", "truecolor");
    command.env_remove("YON_RELAYS");
    command.env_remove("YON_WSS_CA");
    command.env_remove("YON_WSS_CA_DER");
    let mut controller = pair
        .slave
        .spawn_command(command)
        .map_err(std::io::Error::other)?;
    drop(pair.slave);

    let (output_tx, output_rx) = mpsc::channel();
    let mut output_reader = Some(thread::spawn(move || {
        let mut reader = reader;
        let mut chunk = [0_u8; 4096];
        loop {
            let length = reader.read(&mut chunk)?;
            if length == 0 {
                return Ok(());
            }
            if output_tx.send(chunk[..length].to_vec()).is_err() {
                return Ok(());
            }
        }
    }));
    let mut output = Vec::new();

    let outcome = (|| -> Result<u32, std::io::Error> {
        writer.write_all(b"printf 'YON_SHELL_%s\\n' READY\n")?;
        writer.flush()?;
        wait_for_bytes(&output_rx, &mut output, b"YON_SHELL_READY", SESSION_TIMEOUT)?;

        writer.write_all(
            b"old=$(stty -g); stty raw -echo; key=$(dd bs=1 count=1 2>/dev/null | od -An -tx1 | tr -d ' \\n'); stty \"$old\"; printf 'YON_KEY_ESCAPE=%s\\n' \"$key\"\n",
        )?;
        writer.flush()?;
        thread::sleep(Duration::from_millis(100));
        writer.write_all(b"\x1b")?;
        writer.flush()?;
        wait_for_bytes(
            &output_rx,
            &mut output,
            b"YON_KEY_ESCAPE=1b",
            Duration::from_secs(5),
        )?;

        writer.write_all(
            b"old=$(stty -g); stty raw -echo; key=$(dd bs=3 count=1 2>/dev/null | od -An -tx1 | tr -d ' \\n'); stty \"$old\"; printf 'YON_KEY_ARROW=%s\\n' \"$key\"\n",
        )?;
        writer.flush()?;
        thread::sleep(Duration::from_millis(100));
        writer.write_all(b"\x1b[A")?;
        writer.flush()?;
        wait_for_bytes(
            &output_rx,
            &mut output,
            b"YON_KEY_ARROW=1b5b41",
            Duration::from_secs(5),
        )?;

        writer.write_all(
            concat!(
                "printf '\\033[31mYON_ANSI\\033[0m\\n'\n",
                "printf 'YON_CWD=%s\\n' \"$PWD\"\n",
                "printf 'YON_ENV=%s\\n' \"$YONDER_E2E_ENV\"\n",
                "printf 'YON_TERM=%s/%s\\n' \"$TERM\" \"$COLORTERM\"\n",
                "stty size | sed 's/^/YON_SIZE_INITIAL=/'\n",
            )
            .as_bytes(),
        )?;
        writer.flush()?;
        wait_for_bytes(
            &output_rx,
            &mut output,
            b"YON_SIZE_INITIAL=33 91",
            SESSION_TIMEOUT,
        )?;

        pair.master
            .resize(PtySize {
                rows: 41,
                cols: 117,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(std::io::Error::other)?;
        thread::sleep(Duration::from_secs(1));
        writer.write_all(b"stty size | sed 's/^/YON_SIZE_RESIZED=/'\n")?;
        writer.flush()?;
        wait_for_bytes(
            &output_rx,
            &mut output,
            b"YON_SIZE_RESIZED=41 117",
            SESSION_TIMEOUT,
        )?;

        writer.write_all(b"sleep 30\n")?;
        writer.flush()?;
        thread::sleep(Duration::from_millis(500));
        writer.write_all(&[0x03])?;
        writer.write_all(b"printf 'YON_AFTER_INTERRUPT\\n'\n")?;
        writer.flush()?;
        wait_for_bytes(
            &output_rx,
            &mut output,
            b"YON_AFTER_INTERRUPT",
            Duration::from_secs(5),
        )?;

        writer.write_all(b"exit 23\n")?;
        writer.flush()?;
        wait_for_pty_exit(controller.as_mut(), SESSION_TIMEOUT)
    })();

    if outcome.is_err() {
        let _ = controller.kill();
        let _ = controller.wait();
    }
    drop(writer);
    finish_thread(&mut output_reader, START_TIMEOUT, "controller PTY output")??;
    output.extend(output_rx.try_iter().flatten());
    let controller_exit = outcome?;

    assert_eq!(
        controller_exit, 23,
        "controller did not preserve remote exit"
    );
    assert_bytes_contain(&output, b"\x1b[31mYON_ANSI\x1b[0m", "ANSI bytes")?;
    assert_bytes_contain(&output, b"YON_KEY_ESCAPE=1b", "Escape key bytes")?;
    assert_bytes_contain(&output, b"YON_KEY_ARROW=1b5b41", "arrow key bytes")?;
    let expected_working_directory = config.path().canonicalize()?;
    assert_bytes_contain(
        &output,
        format!("YON_CWD={}", expected_working_directory.display()).as_bytes(),
        "remote working directory",
    )?;
    assert_bytes_contain(
        &output,
        format!("YON_ENV={HOST_ENVIRONMENT_VALUE}").as_bytes(),
        "inherited environment",
    )?;
    assert_bytes_contain(
        &output,
        b"YON_TERM=xterm-256color/truecolor",
        "terminal environment",
    )?;
    assert_bytes_contain(&output, b"YON_SIZE_INITIAL=33 91", "initial PTY size")?;
    assert_bytes_contain(&output, b"YON_SIZE_RESIZED=41 117", "resized PTY size")?;
    assert_bytes_contain(&output, b"YON_AFTER_INTERRUPT", "Ctrl+C recovery")?;
    assert_progress_precedes_terminal_output(&output, b"\x1b[31mYON_ANSI\x1b[0m")?;
    if let Some(path) = &controller_log {
        assert_controller_log_is_appended_and_isolated(path, &output)?;
    }

    host.finish_with_exit(23)?;
    relay_process.stop()
}

#[cfg(any(unix, windows))]
fn assert_progress_precedes_terminal_output(
    output: &[u8],
    terminal_marker: &[u8],
) -> Result<(), std::io::Error> {
    const STAGES: [&[u8]; 6] = [
        b"Connecting to relay...",
        b"Finding remote host...",
        b"Establishing the best available path...",
        b"Direct path unavailable; switching to relay...",
        b"Authenticating remote host...",
        b"Starting remote terminal...",
    ];
    let terminal = output
        .windows(terminal_marker.len())
        .rposition(|window| window == terminal_marker)
        .ok_or_else(|| std::io::Error::other("remote terminal marker was absent"))?;
    let before_terminal = &output[..terminal];
    for stage in [
        b"Connecting to relay...".as_slice(),
        b"Establishing the best available path...".as_slice(),
    ] {
        if !before_terminal
            .windows(stage.len())
            .any(|window| window == stage)
        {
            return Err(std::io::Error::other(format!(
                "controller progress stage was absent: {}; output: {:?}",
                String::from_utf8_lossy(stage),
                String::from_utf8_lossy(output)
            )));
        }
    }
    if STAGES.iter().any(|stage| {
        output[terminal..]
            .windows(stage.len())
            .any(|window| window == *stage)
    }) {
        return Err(std::io::Error::other(
            "controller progress was written after terminal output began",
        ));
    }
    let last_progress = STAGES
        .iter()
        .filter_map(|stage| {
            before_terminal
                .windows(stage.len())
                .rposition(|window| window == *stage)
                .map(|position| position + stage.len())
        })
        .max()
        .ok_or_else(|| std::io::Error::other("controller progress was absent"))?;
    let after_progress = &before_terminal[last_progress..];
    let line_was_cleared = [
        b"\x1b[1G\x1b[2K".as_slice(),
        b"\x1b[H\x1b[K".as_slice(),
        b"\r\x1b[K".as_slice(),
        b"\x1b[K\r".as_slice(),
    ]
    .into_iter()
    .any(|sequence| {
        after_progress
            .windows(sequence.len())
            .any(|window| window == sequence)
    });
    if !line_was_cleared {
        return Err(std::io::Error::other(format!(
            "controller progress line was not cleared before terminal output: {:?}",
            String::from_utf8_lossy(output)
        )));
    }
    Ok(())
}

#[cfg(windows)]
#[test]
fn progress_accepts_conpty_native_clear_translation() {
    let output = concat!(
        "Connecting to relay...\r",
        "Establishing the best available path...\r",
        "Starting remote terminal...\x1b[K\r",
        "YON_REMOTE_BEGIN",
    );

    assert_progress_precedes_terminal_output(output.as_bytes(), b"YON_REMOTE_BEGIN").unwrap();
}

#[cfg(any(unix, windows))]
fn assert_controller_log_is_appended_and_isolated(
    path: &Path,
    terminal_output: &[u8],
) -> Result<(), std::io::Error> {
    let log = std::fs::read(path)?;
    if !log.starts_with(CONTROLLER_LOG_SENTINEL) {
        return Err(std::io::Error::other(
            "controller diagnostics did not append to the existing log file",
        ));
    }
    let log = String::from_utf8(log).map_err(std::io::Error::other)?;
    for marker in ["endpoint path selected", "route=", "transport="] {
        if !log.contains(marker) {
            return Err(std::io::Error::other(format!(
                "controller log did not record {marker:?}"
            )));
        }
        if terminal_output
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
        {
            return Err(std::io::Error::other(format!(
                "controller diagnostic {marker:?} contaminated the active terminal"
            )));
        }
    }
    Ok(())
}

#[cfg(windows)]
#[test]
fn windows_conpty_keeps_progress_separate_from_remote_output() -> Result<(), std::io::Error> {
    run_windows_conpty(false)
}

#[cfg(windows)]
#[test]
fn windows_conpty_appends_diagnostics_without_contaminating_terminal() -> Result<(), std::io::Error>
{
    run_windows_conpty(true)
}

#[cfg(windows)]
fn run_windows_conpty(diagnostic_log: bool) -> Result<(), std::io::Error> {
    const REMOTE_BEGIN_MARKER: &[u8] = b"YON_REMOTE_BEGIN";
    const OUTPUT_MARKER: &[u8] = b"YON_WINDOWS_CONPTY_OUTPUT";
    const UTF8_SCALAR: &[u8] = "\u{4e2d}".as_bytes();
    const UTF8_SCALAR_COUNT: usize = 6_000;
    let port = available_port()?;
    let identity = generate_identity(&mut OsSecureRandom)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let peer = identity.public().to_peer_id();
    let relay_process = RelayProcess::start(identity, port)?;
    wait_for_tcp_listener(port)?;
    let relay = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}");
    let config = EndpointConfigDirectory::new(&relay)?;
    let mut host = HostProcess::start(&config)?;
    let code = receive_code(&host.lines)?;
    let controller_log = diagnostic_log.then(|| config.path().join("controller-debug.log"));
    if let Some(path) = &controller_log {
        std::fs::write(path, CONTROLLER_LOG_SENTINEL)?;
    }

    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(std::io::Error::other)?;
    let reader = pair
        .master
        .try_clone_reader()
        .map_err(std::io::Error::other)?;
    let mut writer = pair.master.take_writer().map_err(std::io::Error::other)?;
    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_yon"));
    if let Some(path) = &controller_log {
        command.args(["--log-level", "debug", "--log-file"]);
        command.arg(path.as_os_str());
    }
    command.arg("connect");
    command.cwd(config.path());
    command.env_remove("YON_RELAYS");
    command.env_remove("YON_WSS_CA");
    command.env_remove("YON_WSS_CA_DER");
    let mut controller = pair
        .slave
        .spawn_command(command)
        .map_err(std::io::Error::other)?;
    drop(pair.slave);

    let (output_tx, output_rx) = mpsc::channel();
    let mut output_reader = Some(thread::spawn(move || {
        let mut reader = reader;
        let mut chunk = [0_u8; 4096];
        loop {
            let length = reader.read(&mut chunk)?;
            if length == 0 {
                return Ok(());
            }
            if output_tx.send(chunk[..length].to_vec()).is_err() {
                return Ok(());
            }
        }
    }));
    let mut output = Vec::new();
    let outcome = (|| -> Result<u32, std::io::Error> {
        writer.write_all(format!("{code}\r\x1b[1;1R\r").as_bytes())?;
        writer.write_all(b"echo YON_REMOTE_BEGIN\r")?;
        writer.flush()?;
        wait_for_bytes(
            &output_rx,
            &mut output,
            REMOTE_BEGIN_MARKER,
            Duration::from_secs(30),
        )
        .map_err(|error| windows_probe_error("remote terminal start", error, &output))?;

        writer.write_all(WINDOWS_ESCAPE_PROBE.as_bytes())?;
        writer.flush()?;
        wait_for_bytes(
            &output_rx,
            &mut output,
            WINDOWS_ESCAPE_READY,
            WINDOWS_PROBE_TIMEOUT,
        )
        .map_err(|error| windows_probe_error("Escape readiness", error, &output))?;
        writer.write_all(b"\x1b")?;
        writer.flush()?;
        wait_for_bytes(
            &output_rx,
            &mut output,
            b"YON_KEY_ESCAPE=Escape:27",
            WINDOWS_PROBE_TIMEOUT,
        )
        .map_err(|error| windows_probe_error("Escape result", error, &output))?;

        writer.write_all(WINDOWS_ARROW_PROBE.as_bytes())?;
        writer.flush()?;
        wait_for_bytes(
            &output_rx,
            &mut output,
            WINDOWS_ARROW_READY,
            WINDOWS_PROBE_TIMEOUT,
        )
        .map_err(|error| windows_probe_error("arrow readiness", error, &output))?;
        writer.write_all(b"\x1b[A")?;
        writer.flush()?;
        wait_for_bytes(
            &output_rx,
            &mut output,
            b"YON_KEY_ARROW=27,91,65",
            WINDOWS_PROBE_TIMEOUT,
        )
        .map_err(|error| windows_probe_error("arrow result", error, &output))?;

        writer.write_all(
            format!(
                concat!(
                    "powershell.exe -NoLogo -NoProfile -NonInteractive -Command ",
                    "\"[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); ",
                    "[Console]::Write(([char]0x4e2d).ToString()*{0}); ",
                    "[Console]::WriteLine('YON_UTF8_END')\"\r",
                    "echo YON_WINDOWS_CONPTY_OUTPUT\r",
                    "exit 23\r",
                ),
                UTF8_SCALAR_COUNT,
            )
            .as_bytes(),
        )?;
        writer.flush()?;
        if let Err(error) = wait_for_bytes(
            &output_rx,
            &mut output,
            OUTPUT_MARKER,
            Duration::from_secs(30),
        ) {
            output.extend(output_rx.try_iter().flatten());
            return Err(std::io::Error::other(format!(
                "{error}; controller ConPTY output: {:?}",
                String::from_utf8_lossy(&output)
            )));
        }
        wait_for_pty_exit(controller.as_mut(), SESSION_TIMEOUT)
    })();
    if outcome.is_err() {
        let _ = controller.kill();
        let _ = controller.wait();
    }
    drop(writer);
    drop(pair.master);
    finish_thread(
        &mut output_reader,
        START_TIMEOUT,
        "Windows controller PTY output",
    )??;
    output.extend(output_rx.try_iter().flatten());
    let controller_exit = outcome?;

    assert_eq!(controller_exit, 23);
    assert_bytes_contain(&output, b"Connection code:", "connection code prompt")?;
    if output
        .windows(code.len())
        .any(|window| window == code.as_bytes())
    {
        return Err(std::io::Error::other(
            "the hidden connection code was echoed by the Windows terminal",
        ));
    }
    assert_bytes_contain(&output, OUTPUT_MARKER, "Windows ConPTY output")?;
    assert_bytes_contain(&output, REMOTE_BEGIN_MARKER, "first remote output")?;
    assert_bytes_contain(
        &output,
        b"YON_KEY_ESCAPE=Escape:27",
        "Windows ConPTY Escape key",
    )?;
    assert_bytes_contain(
        &output,
        b"YON_KEY_ARROW=27,91,65",
        "Windows ConPTY arrow bytes",
    )?;
    assert_bytes_contain(&output, b"YON_UTF8_END", "Windows ConPTY UTF-8 output")?;
    let utf8_scalar_count = output
        .windows(UTF8_SCALAR.len())
        .filter(|window| *window == UTF8_SCALAR)
        .count();
    if utf8_scalar_count < UTF8_SCALAR_COUNT {
        return Err(std::io::Error::other(format!(
            "Windows ConPTY UTF-8 output count was {utf8_scalar_count}, expected at least {UTF8_SCALAR_COUNT}"
        )));
    }
    if output
        .windows("\u{fffd}".len())
        .any(|window| window == "\u{fffd}".as_bytes())
    {
        return Err(std::io::Error::other(
            "Windows ConPTY replaced valid split UTF-8 output",
        ));
    }
    assert_progress_precedes_terminal_output(&output, REMOTE_BEGIN_MARKER)?;
    if let Some(path) = &controller_log {
        assert_controller_log_is_appended_and_isolated(path, &output)?;
    }
    host.finish_with_exit(23)?;
    relay_process.stop()
}

#[cfg(windows)]
#[test]
fn windows_conpty_probe_echo_cannot_satisfy_readiness() {
    assert!(!contains_bytes(
        WINDOWS_ESCAPE_PROBE.as_bytes(),
        WINDOWS_ESCAPE_READY
    ));
    assert!(!contains_bytes(
        WINDOWS_ARROW_PROBE.as_bytes(),
        WINDOWS_ARROW_READY
    ));
}

#[test]
fn host_reclaims_the_same_code_after_relay_restart() -> Result<(), std::io::Error> {
    let port = available_port()?;
    let identity = generate_identity(&mut OsSecureRandom)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let relay = format!(
        "/ip4/127.0.0.1/tcp/{port}/p2p/{}",
        identity.public().to_peer_id()
    );
    let first_relay = RelayProcess::start(identity.clone(), port)?;
    thread::sleep(Duration::from_millis(500));
    let config = EndpointConfigDirectory::new(&relay)?;
    let host = HostProcess::start(&config)?;
    let code = match receive_code(&host.lines) {
        Ok(code) => code,
        Err(error) => {
            host.terminate();
            let _ = first_relay.stop();
            return Err(error);
        }
    };

    first_relay.stop()?;
    let second_relay = RelayProcess::start(identity, port)?;
    wait_for_tcp_listener(port)?;
    wait_for_resolved_locator(&relay, parse_locator(&code)?)?;
    let outcome = run_controller_session(&config, &code, CodeInput::Argument);
    let host_result = if outcome.is_ok() {
        host.finish()
    } else {
        host.terminate();
        Ok(())
    };
    let relay_result = second_relay.stop();

    outcome?;
    host_result?;
    relay_result
}

fn wait_for_resolved_locator(relay: &str, locator: Locator) -> Result<(), std::io::Error> {
    let address: EndpointRelayAddress = relay
        .parse()
        .map_err(|error: yonder_net::AddressError| std::io::Error::other(error.to_string()))?;
    let relays = EndpointRelaySet::new(vec![address])
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let identity = generate_identity(&mut OsSecureRandom)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async move {
            let (mut driver, mut streams, relay) =
                connect_relay(identity, &relays, WssTransportConfig::client(None))
                    .await
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
            let deadline = tokio::time::Instant::now() + START_TIMEOUT;
            loop {
                match resolve_peer(
                    &mut driver,
                    &mut streams,
                    &relay,
                    locator,
                    ResolveDeadline::controller(),
                )
                .await
                {
                    Ok(_) => return Ok(()),
                    Err(RelayProtocolError::Unavailable) => {}
                    Err(error) => return Err(std::io::Error::other(error.to_string())),
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "host locator did not become active after relay restart",
                    ));
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
}

#[test]
fn host_replaces_the_complete_code_after_reclaim_conflict() -> Result<(), std::io::Error> {
    let relay_port = available_port()?;
    let gate = PausableTcpGate::start(relay_port)?;
    let identity = generate_identity(&mut OsSecureRandom)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let peer = identity.public().to_peer_id();
    let routed_relay = format!("/ip4/127.0.0.1/tcp/{}/p2p/{peer}", gate.listen_port());
    let direct_relay = format!("/ip4/127.0.0.1/tcp/{relay_port}/p2p/{peer}");
    let first_relay = RelayProcess::start_routed(identity.clone(), relay_port, gate.listen_port())?;
    wait_for_tcp_listener(relay_port)?;
    let config = EndpointConfigDirectory::new(&routed_relay)?;
    let host = HostProcess::start(&config)?;
    let first_code = receive_code(&host.lines)
        .map_err(|error| std::io::Error::other(format!("initial code failed: {error}")))?;
    let first_locator = parse_locator(&first_code)?;

    gate.pause()?;
    first_relay.stop()?;
    let second_relay = RelayProcess::start_routed(identity, relay_port, gate.listen_port())?;
    wait_for_tcp_listener(relay_port)?;
    let claim = LocatorClaim::start(&direct_relay, first_locator)
        .map_err(|error| std::io::Error::other(format!("locator claimant failed: {error}")))?;
    gate.resume()
        .map_err(|error| std::io::Error::other(format!("TCP gate resume failed: {error}")))?;

    let second_code = receive_code(&host.lines)
        .map_err(|error| std::io::Error::other(format!("replacement code failed: {error}")))?;
    let second_locator = parse_locator(&second_code)?;
    if first_code == second_code {
        return Err(std::io::Error::other(
            "reclaim conflict preserved the complete connection code",
        ));
    }
    if first_locator == second_locator {
        return Err(std::io::Error::other(
            "reclaim conflict preserved the public locator",
        ));
    }

    std::fs::write(
        config.path().join("yon.toml"),
        format!("relays = [\"{direct_relay}\"]\n"),
    )?;
    let outcome = run_controller_session(&config, &second_code, CodeInput::Argument);
    let host_result = if outcome.is_ok() {
        host.finish()
    } else {
        host.terminate();
        Ok(())
    };
    let claim_result = claim.stop();
    let relay_result = second_relay.stop();
    let gate_result = gate.stop();

    outcome?;
    host_result?;
    claim_result?;
    relay_result?;
    gate_result
}

struct RelayProcess {
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<Result<(), std::io::Error>>>,
}

#[cfg(any(unix, windows))]
struct RelayBinaryProcess {
    child: Option<Child>,
    _directory: tempfile::TempDir,
    peer: yonder_net::PeerId,
}

#[cfg(any(unix, windows))]
impl RelayBinaryProcess {
    fn start(port: u16) -> Result<Self, std::io::Error> {
        let identity = generate_identity(&mut OsSecureRandom)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let peer = identity.public().to_peer_id();
        let directory = relay_test_directory()?;
        FileIdentityStore
            .create(&directory.path().join("relay.key"), &identity)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        std::fs::write(
            directory.path().join("yon-relay.toml"),
            format!(
                "identity = \"relay.key\"\nlisten = [\"/ip4/127.0.0.1/tcp/{port}\"]\nexternal = [\"/ip4/127.0.0.1/tcp/{port}\"]\n",
            ),
        )?;

        let mut command = Command::new(relay_binary_path()?);
        command
            .args(["--log-level", "error", "serve"])
            .current_dir(directory.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("YON_RELAY_") {
                command.env_remove(key);
            }
        }
        let child = command.spawn()?;
        let mut process = Self {
            child: Some(child),
            _directory: directory,
            peer,
        };
        process.wait_until_ready(port)?;
        Ok(process)
    }

    fn peer(&self) -> yonder_net::PeerId {
        self.peer
    }

    fn wait_until_ready(&mut self, port: u16) -> Result<(), std::io::Error> {
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Ok(());
            }
            if let Some(status) = self.child_mut()?.try_wait()? {
                let output = self.finish_child(false)?;
                return Err(std::io::Error::other(format!(
                    "relay exited during startup with {status}: {}",
                    String::from_utf8_lossy(&output.stderr),
                )));
            }
            if Instant::now() >= deadline {
                let output = self.finish_child(true)?;
                return Err(std::io::Error::other(format!(
                    "relay readiness timed out: {}",
                    String::from_utf8_lossy(&output.stderr),
                )));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn stop(mut self) -> Result<(), std::io::Error> {
        if let Some(status) = self.child_mut()?.try_wait()? {
            let output = self.finish_child(false)?;
            return Err(std::io::Error::other(format!(
                "relay exited before test cleanup with {status}: {}",
                String::from_utf8_lossy(&output.stderr),
            )));
        }
        let output = self.finish_child(true)?;
        if output.stderr.is_empty() {
            Ok(())
        } else {
            Err(std::io::Error::other(format!(
                "relay emitted error diagnostics: {}",
                String::from_utf8_lossy(&output.stderr),
            )))
        }
    }

    fn child_mut(&mut self) -> Result<&mut Child, std::io::Error> {
        self.child
            .as_mut()
            .ok_or_else(|| std::io::Error::other("relay process was already reaped"))
    }

    fn finish_child(&mut self, terminate: bool) -> Result<std::process::Output, std::io::Error> {
        let mut child = self
            .child
            .take()
            .ok_or_else(|| std::io::Error::other("relay process was already reaped"))?;
        if terminate {
            let _ = child.kill();
        }
        child.wait_with_output()
    }
}

#[cfg(any(unix, windows))]
impl Drop for RelayBinaryProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(any(unix, windows))]
fn relay_binary_path() -> Result<PathBuf, std::io::Error> {
    if let Some(path) = std::env::var_os("YONDER_E2E_YON_RELAY") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "YONDER_E2E_YON_RELAY does not name a file: {}",
                path.display(),
            ),
        ));
    }

    let mut path = std::env::current_exe()?;
    path.pop();
    if path.file_name().is_some_and(|name| name == "deps") {
        path.pop();
    }
    path.push(format!("yon-relay{}", std::env::consts::EXE_SUFFIX));
    if path.is_file() {
        Ok(path)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "optimized yon-relay binary was not found at {}; build it before running the ignored performance gate",
                path.display(),
            ),
        ))
    }
}

#[cfg(unix)]
fn relay_test_directory() -> Result<tempfile::TempDir, std::io::Error> {
    tempfile::tempdir()
}

#[cfg(windows)]
fn relay_test_directory() -> Result<tempfile::TempDir, std::io::Error> {
    let root = std::env::var_os("YONDER_E2E_RELAY_ROOT").ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "YONDER_E2E_RELAY_ROOT must identify a protected directory on Windows",
        )
    })?;
    tempfile::Builder::new()
        .prefix("yonder-e2e-relay-")
        .tempdir_in(PathBuf::from(root))
}

#[cfg(not(windows))]
fn secure_test_directory(_path: &Path) {}

/// Replaces the directory ACL with the trusted-only policy (owner plus
/// SYSTEM and Administrators with FullControl, no inheritance) so secret
/// files created inside it pass the Windows parent-directory check.
#[cfg(windows)]
fn secure_test_directory(path: &Path) {
    const SCRIPT: &str = r#"
$ErrorActionPreference='Stop'
$path=$env:YONDER_TEST_DIRECTORY
$current=[Security.Principal.WindowsIdentity]::GetCurrent().User
$system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$administrators=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetOwner($current)
$acl.SetAccessRuleProtection($true,$false)
$rights=[Security.AccessControl.FileSystemRights]::FullControl
$inherit=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
$propagate=[Security.AccessControl.PropagationFlags]::None
$allow=[Security.AccessControl.AccessControlType]::Allow
foreach($sid in @($current,$system,$administrators)){$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,$rights,$inherit,$propagate,$allow);[void]$acl.AddAccessRule($rule)}
[IO.Directory]::SetAccessControl($path,$acl)
exit 0
"#;
    let executable = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let status = Command::new(executable)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            SCRIPT,
        ])
        .env("YONDER_TEST_DIRECTORY", path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
}

impl RelayProcess {
    fn start(identity: Keypair, port: u16) -> Result<Self, std::io::Error> {
        Self::start_routed(identity, port, port)
    }

    fn start_routed(
        identity: Keypair,
        listen_port: u16,
        external_port: u16,
    ) -> Result<Self, std::io::Error> {
        Self::start_addresses(
            identity,
            vec![format!("/ip4/127.0.0.1/tcp/{listen_port}")],
            vec![format!("/ip4/127.0.0.1/tcp/{external_port}")],
        )
    }

    fn start_addresses(
        identity: Keypair,
        listen: Vec<String>,
        external: Vec<String>,
    ) -> Result<Self, std::io::Error> {
        Self::start_addresses_with_wss(identity, listen, external, WssTransportConfig::client(None))
    }

    fn start_addresses_with_wss(
        identity: Keypair,
        listen: Vec<String>,
        external: Vec<String>,
        wss: WssTransportConfig,
    ) -> Result<Self, std::io::Error> {
        let listen =
            listen
                .into_iter()
                .map(|address| {
                    address.parse::<RelayListenAddress>().map_err(
                        |error: yonder_net::AddressError| std::io::Error::other(error.to_string()),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
        let external = external
            .into_iter()
            .map(|address| {
                address.parse::<RelayExternalAddress>().map_err(
                    |error: yonder_net::AddressError| std::io::Error::other(error.to_string()),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let config = RelayServeConfig::new(identity, listen, external, wss)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        Self::start_with_config(config)
    }

    /// Starts an enterprise-mode relay with the callback TLS from the
    /// fixture certificate and a WeCom provider secret file.
    fn start_enterprise(
        identity: Keypair,
        port: u16,
        callback_port: u16,
    ) -> Result<Self, std::io::Error> {
        let listen = vec![format!("/ip4/127.0.0.1/tcp/{port}")];
        let external = vec![format!("/ip4/127.0.0.1/tcp/{port}")];
        let listen =
            listen
                .into_iter()
                .map(|address| {
                    address.parse::<RelayListenAddress>().map_err(
                        |error: yonder_net::AddressError| std::io::Error::other(error.to_string()),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
        let external = external
            .into_iter()
            .map(|address| {
                address.parse::<RelayExternalAddress>().map_err(
                    |error: yonder_net::AddressError| std::io::Error::other(error.to_string()),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let directory = relay_test_directory()?;
        secure_test_directory(directory.path());
        let wecom_secret = directory.path().join("wecom.secret");
        std::fs::write(
            &wecom_secret,
            "corp_id = \"ww1234567890abcdef\"\nagent_id = 1000002\napp_secret = \"s3cret\"\n",
        )?;
        let feishu_secret = directory.path().join("feishu.secret");
        std::fs::write(
            &feishu_secret,
            "app_id = \"cli_abc123\"\napp_secret = \"s3cret\"\n",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for secret in [&wecom_secret, &feishu_secret] {
                std::fs::set_permissions(secret, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        #[cfg(windows)]
        {
            use yon_relay::{SecretFilePolicy as _, SystemSecretFilePolicy};
            for secret in [&wecom_secret, &feishu_secret] {
                let file = std::fs::File::open(secret)?;
                SystemSecretFilePolicy
                    .protect_new(secret, &file)
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
            }
        }
        let providers = yonder_core::EnterpriseProviders::new(true, true)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let secrets =
            yon_relay::ProviderSecrets::new(providers, Some(wecom_secret), Some(feishu_secret))
                .map_err(|error| std::io::Error::other(error.to_string()))?;
        let config = yon_relay::EnterpriseAuthConfig::new(
            format!("127.0.0.1:{callback_port}").parse().map_err(
                |error: std::net::AddrParseError| std::io::Error::other(error.to_string()),
            )?,
            yon_relay::CallbackExternalUrl::new(
                "https://relay.example.test"
                    .parse()
                    .map_err(|error: url::ParseError| std::io::Error::other(error.to_string()))?,
            )
            .map_err(|error| std::io::Error::other(error.to_string()))?,
            vec![SecretDocument::new(TEST_WSS_CERT_DER.to_vec())],
            SecretDocument::new(TEST_WSS_KEY_DER.to_vec()),
            providers,
            secrets,
        )
        .map_err(|error| std::io::Error::other(error.to_string()))?;
        let credentials = yon_relay::ProviderCredentials::load(&config)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let context = yon_relay::EnterpriseContext::new(config, credentials);
        let config = RelayServeConfig::with_enterprise(
            identity,
            listen,
            external,
            WssTransportConfig::client(None),
            yonder_core::RelayResourceConfig::default(),
            Some(context),
        )
        .map_err(|error| std::io::Error::other(error.to_string()))?;
        Self::start_with_config(config)
    }

    fn start_with_config(config: RelayServeConfig) -> Result<Self, std::io::Error> {
        let (shutdown, shutdown_rx) = oneshot::channel();
        let thread = thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| std::io::Error::other(error.to_string()))?
                .block_on(run_relay_until(config, async move {
                    let _ = shutdown_rx.await;
                    Ok(())
                }))
                .map_err(|error| std::io::Error::other(error.to_string()))
        });
        Ok(Self {
            shutdown: Some(shutdown),
            thread: Some(thread),
        })
    }

    fn stop(mut self) -> Result<(), std::io::Error> {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> Result<(), std::io::Error> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        finish_thread(&mut self.thread, START_TIMEOUT, "relay")?
    }
}

impl Drop for RelayProcess {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

type GateAck = mpsc::SyncSender<Result<(), std::io::Error>>;

enum GateCommand {
    Pause(GateAck),
    Resume(GateAck),
    Shutdown(GateAck),
}

struct PausableTcpGate {
    port: u16,
    commands: mpsc::Sender<GateCommand>,
    thread: Option<JoinHandle<Result<(), std::io::Error>>>,
}

impl PausableTcpGate {
    fn start(target_port: u16) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let (commands, command_rx) = mpsc::channel();
        let thread = thread::spawn(move || run_tcp_gate(listener, target_port, command_rx));
        Ok(Self {
            port,
            commands,
            thread: Some(thread),
        })
    }

    const fn listen_port(&self) -> u16 {
        self.port
    }

    fn pause(&self) -> Result<(), std::io::Error> {
        self.control(GateCommand::Pause)
    }

    fn resume(&self) -> Result<(), std::io::Error> {
        self.control(GateCommand::Resume)
    }

    fn control(&self, command: impl FnOnce(GateAck) -> GateCommand) -> Result<(), std::io::Error> {
        let deadline = Instant::now() + START_TIMEOUT;
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        self.commands
            .send(command(ack_tx))
            .map_err(|_| std::io::Error::other("TCP gate command channel closed"))?;
        ack_rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|error| std::io::Error::other(error.to_string()))?
    }

    fn stop(mut self) -> Result<(), std::io::Error> {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> Result<(), std::io::Error> {
        let control = self.control(GateCommand::Shutdown);
        let thread = finish_thread(&mut self.thread, START_TIMEOUT, "TCP gate")?;
        control?;
        thread
    }
}

impl Drop for PausableTcpGate {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

struct GateConnection {
    client: TcpStream,
    upstream: TcpStream,
    thread: JoinHandle<()>,
}

#[derive(Clone, Copy)]
enum GateTraffic {
    PassThrough,
    CorruptFirstUploadByte,
}

impl GateConnection {
    fn start(
        client: TcpStream,
        target_port: u16,
        traffic: GateTraffic,
    ) -> Result<Self, std::io::Error> {
        client.set_nonblocking(false)?;
        client.set_nodelay(true)?;
        let upstream = TcpStream::connect(("127.0.0.1", target_port))?;
        upstream.set_nodelay(true)?;
        let mut client_read = client.try_clone()?;
        let mut client_write = client.try_clone()?;
        let mut upstream_read = upstream.try_clone()?;
        let mut upstream_write = upstream.try_clone()?;
        let thread = thread::spawn(move || {
            let upload = thread::spawn(move || {
                if matches!(traffic, GateTraffic::CorruptFirstUploadByte) {
                    let mut byte = [0_u8; 1];
                    if client_read.read_exact(&mut byte).is_ok() {
                        byte[0] ^= 1;
                        let _ = upstream_write.write_all(&byte);
                    }
                }
                let _ = std::io::copy(&mut client_read, &mut upstream_write);
                let _ = upstream_write.shutdown(Shutdown::Write);
            });
            let download = thread::spawn(move || {
                let _ = std::io::copy(&mut upstream_read, &mut client_write);
                let _ = client_write.shutdown(Shutdown::Write);
            });
            let _ = upload.join();
            let _ = download.join();
        });
        Ok(Self {
            client,
            upstream,
            thread,
        })
    }

    fn shutdown(&self) {
        let _ = self.client.shutdown(Shutdown::Both);
        let _ = self.upstream.shutdown(Shutdown::Both);
    }
}

fn run_tcp_gate(
    listener: TcpListener,
    target_port: u16,
    commands: mpsc::Receiver<GateCommand>,
) -> Result<(), std::io::Error> {
    let mut paused = false;
    let mut active = Vec::new();
    let mut resume_ack: Option<GateAck> = None;
    loop {
        match commands.recv_timeout(Duration::from_millis(5)) {
            Ok(GateCommand::Pause(ack)) => {
                if let Some(pending) = resume_ack.take() {
                    let _ = pending.send(Err(std::io::Error::other(
                        "TCP gate was paused before a resumed connection arrived",
                    )));
                }
                paused = true;
                let result = if active.is_empty() {
                    Err(std::io::Error::other(
                        "TCP gate had no active host connection to pause",
                    ))
                } else {
                    Ok(())
                };
                let _ = ack.send(result);
            }
            Ok(GateCommand::Resume(ack)) => {
                paused = false;
                resume_ack = Some(ack);
            }
            Ok(GateCommand::Shutdown(ack)) => {
                if let Some(pending) = resume_ack.take() {
                    let _ = pending.send(Err(std::io::Error::other(
                        "TCP gate stopped before a resumed connection arrived",
                    )));
                }
                let result = close_gate_connections(&mut active, Instant::now() + START_TIMEOUT);
                let failed = result.is_err();
                let _ = ack.send(result);
                return if failed {
                    Err(std::io::Error::other(
                        "TCP gate connections did not stop before shutdown",
                    ))
                } else {
                    Ok(())
                };
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return close_gate_connections(&mut active, Instant::now() + START_TIMEOUT);
            }
        }
        reap_gate_connections(&mut active);
        if paused {
            reject_pending_connections(&listener)?;
            continue;
        }
        loop {
            match listener.accept() {
                Ok((client, _)) => {
                    let connection =
                        GateConnection::start(client, target_port, GateTraffic::PassThrough)?;
                    active.push(connection);
                    if let Some(ack) = resume_ack.take() {
                        let _ = ack.send(Ok(()));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
    }
}

struct TamperingTcpProxy {
    port: u16,
    shutdown: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<Result<(), std::io::Error>>>,
}

impl TamperingTcpProxy {
    fn start(target_port: u16) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let thread = thread::spawn(move || run_tampering_proxy(listener, target_port, shutdown_rx));
        Ok(Self {
            port,
            shutdown: Some(shutdown_tx),
            thread: Some(thread),
        })
    }

    const fn listen_port(&self) -> u16 {
        self.port
    }

    fn stop(mut self) -> Result<(), std::io::Error> {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> Result<(), std::io::Error> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        finish_thread(&mut self.thread, START_TIMEOUT, "tampering TCP proxy")?
    }
}

impl Drop for TamperingTcpProxy {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

fn run_tampering_proxy(
    listener: TcpListener,
    target_port: u16,
    shutdown: mpsc::Receiver<()>,
) -> Result<(), std::io::Error> {
    let mut active = Vec::new();
    loop {
        match shutdown.recv_timeout(Duration::from_millis(5)) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                return close_gate_connections(&mut active, Instant::now() + START_TIMEOUT);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        reap_gate_connections(&mut active);
        loop {
            match listener.accept() {
                Ok((client, _)) => active.push(GateConnection::start(
                    client,
                    target_port,
                    GateTraffic::CorruptFirstUploadByte,
                )?),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
    }
}

fn reject_pending_connections(listener: &TcpListener) -> Result<(), std::io::Error> {
    loop {
        match listener.accept() {
            Ok((client, _)) => {
                let _ = client.shutdown(Shutdown::Both);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => return Err(error),
        }
    }
}

fn close_gate_connections(
    active: &mut Vec<GateConnection>,
    deadline: Instant,
) -> Result<(), std::io::Error> {
    for connection in active.iter() {
        connection.shutdown();
    }
    while !active.is_empty() {
        reap_gate_connections(active);
        if active.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::other(
                "TCP gate connection shutdown timed out",
            ));
        }
        thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

#[cfg(windows)]
fn windows_probe_error(stage: &str, source: std::io::Error, output: &[u8]) -> std::io::Error {
    std::io::Error::other(format!(
        "Windows ConPTY {stage} failed: {source}; output: {:?}",
        String::from_utf8_lossy(output)
    ))
}

fn reap_gate_connections(active: &mut Vec<GateConnection>) {
    let mut index = 0;
    while index < active.len() {
        if active[index].thread.is_finished() {
            let connection = active.swap_remove(index);
            let _ = connection.thread.join();
        } else {
            index += 1;
        }
    }
}

struct LocatorClaim {
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<Result<(), std::io::Error>>>,
}

impl LocatorClaim {
    fn start(relay: &str, locator: Locator) -> Result<Self, std::io::Error> {
        let relay = relay.to_owned();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (shutdown, shutdown_rx) = oneshot::channel();
        let thread = thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| std::io::Error::other(error.to_string()))?
                .block_on(run_locator_claim(relay, locator, ready_tx, shutdown_rx))
        });
        let mut claim = Self {
            shutdown: Some(shutdown),
            thread: Some(thread),
        };
        let deadline = Instant::now() + START_TIMEOUT;
        match ready_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(Ok(())) => Ok(claim),
            Ok(Err(message)) => {
                let _ = claim.stop_inner();
                Err(std::io::Error::other(message))
            }
            Err(error) => {
                let _ = claim.stop_inner();
                Err(std::io::Error::other(error.to_string()))
            }
        }
    }

    fn stop(mut self) -> Result<(), std::io::Error> {
        self.stop_inner()
    }

    fn stop_inner(&mut self) -> Result<(), std::io::Error> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        finish_thread(&mut self.thread, START_TIMEOUT, "locator claim")?
    }
}

impl Drop for LocatorClaim {
    fn drop(&mut self) {
        let _ = self.stop_inner();
    }
}

async fn run_locator_claim(
    relay: String,
    locator: Locator,
    ready: mpsc::SyncSender<Result<(), String>>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<(), std::io::Error> {
    let established = establish_locator_claim(&relay, locator).await;
    let (mut driver, lease) = match established {
        Ok(established) => established,
        Err(error) => {
            let _ = ready.send(Err(error.to_string()));
            return Err(error);
        }
    };
    if ready.send(Ok(())).is_err() {
        return Ok(());
    }
    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            _ = driver.next() => {
                if !lease.is_usable(&driver) {
                    return Err(std::io::Error::other("locator claim lost its relay reservation"));
                }
            }
        }
    }
}

async fn establish_locator_claim(
    relay: &str,
    locator: Locator,
) -> Result<(EndpointDriver, ReservationLease), std::io::Error> {
    let address: EndpointRelayAddress = relay
        .parse()
        .map_err(|error: yonder_net::AddressError| std::io::Error::other(error.to_string()))?;
    let relays = EndpointRelaySet::new(vec![address])
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let identity = generate_identity(&mut OsSecureRandom)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let (mut driver, mut streams, relay) =
        connect_relay(identity, &relays, WssTransportConfig::client(None))
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?;
    let listener = driver
        .reserve(relay.address())
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let lease = tokio::time::timeout(
        CLAIM_STEP_TIMEOUT,
        wait_for_reservation(&mut driver, relay, listener),
    )
    .await
    .map_err(|_| std::io::Error::other("competing reservation timed out"))?
    .map_err(|error| std::io::Error::other(error.to_string()))?;
    let response = tokio::time::timeout(
        CLAIM_STEP_TIMEOUT,
        reclaim_locator(&mut driver, &mut streams, lease.relay(), locator),
    )
    .await
    .map_err(|_| std::io::Error::other("competing reclaim timed out"))?
    .map_err(|error| std::io::Error::other(error.to_string()))?;
    if response != ReclaimResponse::Reclaimed {
        return Err(std::io::Error::other(
            "competing endpoint did not acquire the old locator",
        ));
    }
    Ok((driver, lease))
}

fn finish_thread(
    thread: &mut Option<JoinHandle<Result<(), std::io::Error>>>,
    timeout: Duration,
    name: &str,
) -> Result<Result<(), std::io::Error>, std::io::Error> {
    let Some(handle) = thread.as_ref() else {
        return Ok(Ok(()));
    };
    let deadline = Instant::now() + timeout;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return Err(std::io::Error::other(format!("{name} shutdown timed out")));
        }
        thread::sleep(Duration::from_millis(5));
    }
    thread
        .take()
        .expect("thread remains present until joined")
        .join()
        .map_err(|_| std::io::Error::other(format!("{name} thread panicked")))
}

fn wait_for_tcp_listener(port: u16) -> Result<(), std::io::Error> {
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => {
                let _ = stream.shutdown(Shutdown::Both);
                return Ok(());
            }
            Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
            Err(error) => return Err(error),
        }
    }
}

#[cfg(any(unix, windows))]
fn wait_for_bytes(
    chunks: &mpsc::Receiver<Vec<u8>>,
    output: &mut Vec<u8>,
    expected: &[u8],
    timeout: Duration,
) -> Result<(), std::io::Error> {
    let deadline = Instant::now() + timeout;
    while !contains_bytes(output, expected) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match chunks.recv_timeout(remaining) {
            Ok(chunk) => output.extend_from_slice(&chunk),
            Err(error) => {
                output.extend(chunks.try_iter().flatten());
                if contains_bytes(output, expected) {
                    return Ok(());
                }
                const DIAGNOSTIC_TAIL_LIMIT: usize = 4 * 1024;
                let tail_start = output.len().saturating_sub(DIAGNOSTIC_TAIL_LIMIT);
                return Err(std::io::Error::other(format!(
                    "timed out waiting for {:?}: {error}; terminal output tail: {:?}",
                    String::from_utf8_lossy(expected),
                    String::from_utf8_lossy(&output[tail_start..]),
                )));
            }
        }
    }
    Ok(())
}

#[cfg(any(unix, windows))]
fn wait_for_pty_exit(
    child: &mut dyn portable_pty::Child,
    timeout: Duration,
) -> Result<u32, std::io::Error> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status.exit_code());
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::other("controller PTY process timed out"));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(any(unix, windows))]
fn assert_bytes_contain(
    output: &[u8],
    expected: &[u8],
    description: &str,
) -> Result<(), std::io::Error> {
    if contains_bytes(output, expected) {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "terminal output did not contain {description}: {:?}",
            String::from_utf8_lossy(output)
        )))
    }
}

#[cfg(any(unix, windows))]
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn parse_locator(code: &str) -> Result<Locator, std::io::Error> {
    code.parse::<ConnectionCode>()
        .map(|code| code.locator())
        .map_err(|error| std::io::Error::other(error.to_string()))
}

#[derive(Clone, Copy)]
enum CodeInput {
    Argument,
    Stdin,
}

fn run_host_controller(relay: &str, code_input: CodeInput) -> Result<(), std::io::Error> {
    run_host_controller_with_relays(&[relay.to_owned()], code_input)
}

fn run_host_controller_with_relays(
    relays: &[String],
    code_input: CodeInput,
) -> Result<(), std::io::Error> {
    let config = EndpointConfigDirectory::new_many(relays)?;
    run_host_controller_in_config(&config, code_input)
}

fn run_host_controller_in_config(
    config: &EndpointConfigDirectory,
    code_input: CodeInput,
) -> Result<(), std::io::Error> {
    run_host_controller_with_evidence(config, code_input).map(drop)
}

fn run_host_controller_with_evidence(
    config: &EndpointConfigDirectory,
    code_input: CodeInput,
) -> Result<ControllerEvidence, std::io::Error> {
    let host = HostProcess::start(config)?;
    let outcome = (|| {
        let code = receive_code(&host.lines)?;
        if matches!(code_input, CodeInput::Argument) {
            run_rejected_controller(config, &code)?;
        }
        run_controller_session(config, &code, code_input)
    })();
    let host_result = if outcome.is_ok() {
        host.finish()
    } else {
        host.terminate();
        Ok(())
    };

    let evidence = outcome?;
    host_result?;
    Ok(evidence)
}

struct HostProcess {
    child: Child,
    lines: mpsc::Receiver<Result<String, std::io::Error>>,
    reader: Option<JoinHandle<()>>,
    diagnostic_reader: Option<JoinHandle<Result<Vec<u8>, std::io::Error>>>,
    reaped: bool,
}

impl HostProcess {
    fn start(config: &EndpointConfigDirectory) -> Result<Self, std::io::Error> {
        let mut child = Command::new(env!("CARGO_BIN_EXE_yon"))
            .args(["--log-level", "debug", "host"])
            .current_dir(config.path())
            .env("YONDER_E2E_ENV", HOST_ENVIRONMENT_VALUE)
            .env_remove("YON_RELAYS")
            .env_remove("YON_WSS_CA")
            .env_remove("YON_WSS_CA_DER")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("host stdout was not piped"))?;
        let (line_tx, lines) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if line_tx.send(line).is_err() {
                    break;
                }
            }
        });
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| std::io::Error::other("host stderr was not piped"))?;
        let diagnostic_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            BufReader::new(stderr)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        });
        Ok(Self {
            child,
            lines,
            reader: Some(reader),
            diagnostic_reader: Some(diagnostic_reader),
            reaped: false,
        })
    }

    fn finish(mut self) -> Result<(), std::io::Error> {
        self.finish_with_exit(0)
    }

    fn finish_with_exit(&mut self, expected: i32) -> Result<(), std::io::Error> {
        let status = wait_for_exit(&mut self.child, SESSION_TIMEOUT);
        if status.is_err() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.reaped = true;
        self.join_reader();
        let diagnostics = self.join_diagnostic_reader()?;
        let status = status?;
        if status.code() != Some(expected) {
            return Err(std::io::Error::other(format!(
                "host exited with {status}; expected {expected}"
            )));
        }
        if diagnostics.is_empty() {
            return Err(std::io::Error::other(
                "debug diagnostics were not emitted on host stderr",
            ));
        }
        for remaining in self.lines.try_iter() {
            validate_connection_code_line(&remaining?)?;
        }
        Ok(())
    }

    fn terminate(mut self) {
        self.terminate_inner();
    }

    fn terminate_inner(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.reaped = true;
        }
        self.join_reader();
        if let Ok(diagnostics) = self.join_diagnostic_reader()
            && !diagnostics.is_empty()
        {
            eprintln!(
                "host diagnostics during forced termination:\n{}",
                String::from_utf8_lossy(&diagnostics)
            );
        }
    }

    fn join_reader(&mut self) {
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }

    fn join_diagnostic_reader(&mut self) -> Result<Vec<u8>, std::io::Error> {
        match self.diagnostic_reader.take() {
            Some(reader) => reader
                .join()
                .map_err(|_| std::io::Error::other("host diagnostic reader panicked"))?,
            None => Ok(Vec::new()),
        }
    }
}

impl Drop for HostProcess {
    fn drop(&mut self) {
        self.terminate_inner();
    }
}

fn run_controller_session(
    config: &EndpointConfigDirectory,
    code: &str,
    code_input: CodeInput,
) -> Result<ControllerEvidence, std::io::Error> {
    run_controller_session_with_script(config, code, code_input, command_script())
}

fn run_controller_session_with_script(
    config: &EndpointConfigDirectory,
    code: &str,
    code_input: CodeInput,
    script: &[u8],
) -> Result<ControllerEvidence, std::io::Error> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_yon"));
    command
        .args(["--log-level", "debug", "connect"])
        .current_dir(config.path())
        .env_remove("YON_RELAYS")
        .env_remove("YON_WSS_CA")
        .env_remove("YON_WSS_CA_DER");
    if matches!(code_input, CodeInput::Argument) {
        command.arg(code);
    }
    let mut controller = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut input = Vec::with_capacity(code.len() + script.len() + 1);
    if matches!(code_input, CodeInput::Stdin) {
        input.extend_from_slice(code.as_bytes());
        input.push(b'\n');
    }
    input.extend_from_slice(script);
    let input_result = controller
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("controller stdin was not piped"))
        .and_then(|mut stdin| stdin.write_all(&input));
    if let Err(error) = input_result {
        let _ = controller.kill();
        let _ = controller.wait();
        return Err(error);
    }
    let stdout = controller
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("controller stdout was not piped"))?;
    let stderr = controller
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("controller stderr was not piped"))?;
    let output_reader = thread::spawn(move || read_to_end_timed(BufReader::new(stdout)));
    let diagnostic_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        BufReader::new(stderr)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let status = match wait_for_exit(&mut controller, SESSION_TIMEOUT) {
        Ok(status) => Ok(status),
        Err(error) => {
            let _ = controller.kill();
            let _ = controller.wait();
            Err(error)
        }
    };
    let timed_output = output_reader
        .join()
        .map_err(|_| std::io::Error::other("controller output reader panicked"));
    let diagnostics = diagnostic_reader
        .join()
        .map_err(|_| std::io::Error::other("controller diagnostic reader panicked"));
    let status = status?;
    let timed_output = timed_output??;
    let diagnostics = diagnostics??;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "controller exited unsuccessfully: {status}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&timed_output.bytes),
            String::from_utf8_lossy(&diagnostics),
        )));
    }
    let payload_bytes = framed_performance_payload_bytes(&timed_output.bytes);
    let output = String::from_utf8_lossy(&timed_output.bytes);
    if output.matches("YON_E2E").count() < 2 {
        return Err(std::io::Error::other(format!(
            "remote shell did not execute the marker command: {output:?}"
        )));
    }
    if diagnostics.is_empty() {
        return Err(std::io::Error::other(
            "debug diagnostics were not emitted on controller stderr",
        ));
    }
    for diagnostic in [
        b"local terminal input read completed".as_slice(),
        b"terminal output".as_slice(),
        b"libp2p".as_slice(),
    ] {
        if output
            .as_bytes()
            .windows(diagnostic.len())
            .any(|window| window == diagnostic)
        {
            return Err(std::io::Error::other(
                "controller diagnostics contaminated terminal stdout",
            ));
        }
    }
    Ok(ControllerEvidence {
        payload_bytes,
        transfer_duration: timed_output.active,
        #[cfg(yonder_e2e_rebuild)]
        diagnostics,
    })
}

fn run_rejected_host(config: &EndpointConfigDirectory) -> Result<(), std::io::Error> {
    let mut host = Command::new(env!("CARGO_BIN_EXE_yon"))
        .args(["--log-level", "debug", "host"])
        .current_dir(config.path())
        .env_remove("YON_RELAYS")
        .env_remove("YON_WSS_CA")
        .env_remove("YON_WSS_CA_DER")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = host
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("rejected host stdout was not piped"))?;
    let stderr = host
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("rejected host stderr was not piped"))?;
    let output_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        BufReader::new(stdout)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let diagnostic_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        BufReader::new(stderr)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    thread::sleep(Duration::from_secs(12));
    let mut status = host.try_wait()?;
    if status.is_none() {
        match host.kill() {
            Ok(()) => status = Some(host.wait()?),
            Err(error) => {
                status = host.try_wait()?;
                if status.is_none() {
                    return Err(error);
                }
            }
        }
    }
    let output = output_reader
        .join()
        .map_err(|_| std::io::Error::other("rejected host output reader panicked"))??;
    let diagnostics = diagnostic_reader
        .join()
        .map_err(|_| std::io::Error::other("rejected host diagnostic reader panicked"))??;
    if status.is_some_and(|status| status.success()) {
        return Err(std::io::Error::other(
            "host accepted an untrusted or tampered relay transport",
        ));
    }
    if !output.is_empty() {
        return Err(std::io::Error::other(
            "host published a connection code before relay authentication",
        ));
    }
    if diagnostics.is_empty() {
        return Err(std::io::Error::other(
            "rejected host did not emit safe diagnostics",
        ));
    }
    Ok(())
}

struct ControllerEvidence {
    payload_bytes: Option<usize>,
    transfer_duration: Duration,
    #[cfg(yonder_e2e_rebuild)]
    diagnostics: Vec<u8>,
}

struct TimedOutput {
    bytes: Vec<u8>,
    active: Duration,
}

struct ThroughputSample {
    direct_bytes_per_second: f64,
    local_pty_bytes_per_second: f64,
    remote_bytes_per_second: f64,
}

impl ThroughputSample {
    fn remote_to_local_pty_ratio(&self) -> f64 {
        self.remote_bytes_per_second / self.local_pty_bytes_per_second
    }
}

fn median(values: impl IntoIterator<Item = f64>) -> f64 {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort_unstable_by(f64::total_cmp);
    let midpoint = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[midpoint - 1] + values[midpoint]) / 2.0
    } else {
        values[midpoint]
    }
}

fn read_to_end_timed(mut reader: impl std::io::Read) -> Result<TimedOutput, std::io::Error> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    let mut first = None;
    let mut last = None;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let observed = Instant::now();
        first.get_or_insert(observed);
        last = Some(observed);
        bytes.extend_from_slice(&buffer[..read]);
    }
    let active = first
        .zip(last)
        .map_or(Duration::ZERO, |(first, last)| last.duration_since(first));
    Ok(TimedOutput { bytes, active })
}

fn throughput(bytes: usize, duration: Duration) -> Result<f64, std::io::Error> {
    if duration.is_zero() {
        return Err(std::io::Error::other(
            "throughput interval was below the monotonic clock resolution",
        ));
    }
    Ok(bytes as f64 / duration.as_secs_f64())
}

#[cfg(any(unix, windows))]
fn framed_performance_payload_bytes(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(PERFORMANCE_PAYLOAD_BEGIN.len())
        .enumerate()
        .filter_map(|(begin, window)| {
            if window != PERFORMANCE_PAYLOAD_BEGIN {
                return None;
            }
            let payload = &bytes[begin + PERFORMANCE_PAYLOAD_BEGIN.len()..];
            payload
                .windows(PERFORMANCE_PAYLOAD_END.len())
                .enumerate()
                .filter(|(_, candidate)| *candidate == PERFORMANCE_PAYLOAD_END)
                .map(|(end, _)| {
                    payload[..end]
                        .iter()
                        .filter(|byte| **byte == PERFORMANCE_PAYLOAD_BYTE)
                        .count()
                })
                .max()
        })
        .max()
}

#[cfg(any(unix, windows))]
#[test]
fn performance_payload_framing_ignores_a_later_empty_command_echo() {
    let output = b"YON_E2E_PERFORMANCE_BEGIN~~~YON_E2E_PERFORMANCE_END\
        YON_E2E_PERFORMANCE_BEGINYON_E2E_PERFORMANCE_END";
    let interleaved = b"YON_E2E_PERFORMANCE_BEGIN~~YON_E2E_PERFORMANCE_END\
        ~~~~YON_E2E_PERFORMANCE_END";

    assert_eq!(framed_performance_payload_bytes(output), Some(3));
    assert_eq!(framed_performance_payload_bytes(interleaved), Some(6));
}

fn measure_direct_file_output(path: &Path) -> Result<TimedOutput, std::io::Error> {
    #[cfg(windows)]
    let mut command = {
        let mut command = Command::new("cmd.exe");
        command.args(["/D", "/Q", "/C", "type throughput.bin"]);
        command
    };
    #[cfg(not(windows))]
    let mut command = {
        let mut command = Command::new("cat");
        command.arg("throughput.bin");
        command
    };
    let mut child = command
        .current_dir(
            path.parent()
                .ok_or_else(|| std::io::Error::other("throughput path has no parent"))?,
        )
        .stdout(Stdio::piped())
        .spawn()?;
    let output = read_to_end_timed(
        child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("direct stdout was not piped"))?,
    );
    let status = child.wait()?;
    let output = output?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "direct output command failed: {status}"
        )));
    }
    Ok(output)
}

#[cfg(any(unix, windows))]
fn measure_local_pty_file_output(path: &Path) -> Result<TimedOutput, std::io::Error> {
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(std::io::Error::other)?;
    let mut command = CommandBuilder::new_default_prog();
    command.cwd(
        path.parent()
            .ok_or_else(|| std::io::Error::other("throughput path has no parent"))?,
    );
    let reader = pair
        .master
        .try_clone_reader()
        .map_err(std::io::Error::other)?;
    let mut writer = pair.master.take_writer().map_err(std::io::Error::other)?;
    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(std::io::Error::other)?;
    drop(pair.slave);
    let reader = thread::spawn(move || read_to_end_timed(reader));
    let outcome = (|| {
        writer.write_all(local_pty_throughput_command_script())?;
        writer.flush()?;
        wait_for_pty_exit(child.as_mut(), SESSION_TIMEOUT)
    })();
    if outcome.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    drop(writer);
    drop(pair.master);
    let output = reader
        .join()
        .map_err(|_| std::io::Error::other("local PTY output reader panicked"));
    let exit_code = outcome?;
    let output = output??;
    if exit_code != 0 {
        return Err(std::io::Error::other(format!(
            "local PTY output command failed with exit code {exit_code}"
        )));
    }
    Ok(output)
}

#[cfg(yonder_e2e_rebuild)]
fn validate_required_controller_rebuild(diagnostics: &[u8]) -> Result<(), std::io::Error> {
    const FALLBACK_MARKER: &str = "strict relay-only fallback established";
    let diagnostics = std::str::from_utf8(diagnostics).map_err(std::io::Error::other)?;
    let mut markers = diagnostics
        .lines()
        .filter(|line| line.contains(FALLBACK_MARKER));
    let marker = markers.next().ok_or_else(|| {
        std::io::Error::other("strict relay-only fallback evidence was not emitted")
    })?;
    if markers.next().is_some() {
        return Err(std::io::Error::other(
            "strict relay-only fallback evidence was emitted more than once",
        ));
    }

    let initial = diagnostic_field(marker, "initial_peer_id")?
        .parse::<yonder_net::PeerId>()
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let fallback = diagnostic_field(marker, "fallback_peer_id")?
        .parse::<yonder_net::PeerId>()
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    if initial == fallback {
        return Err(std::io::Error::other(
            "strict relay-only fallback reused the initial controller PeerId",
        ));
    }
    if diagnostic_field(marker, "relayed")? != "true" {
        return Err(std::io::Error::other(
            "strict relay-only fallback did not bind a relay circuit",
        ));
    }
    Ok(())
}

#[cfg(yonder_e2e_rebuild)]
fn diagnostic_field<'a>(line: &'a str, name: &str) -> Result<&'a str, std::io::Error> {
    line.split_whitespace()
        .find_map(|field| field.strip_prefix(name)?.strip_prefix('='))
        .ok_or_else(|| std::io::Error::other(format!("missing fallback field {name}")))
}

fn run_rejected_controller(
    config: &EndpointConfigDirectory,
    code: &str,
) -> Result<(), std::io::Error> {
    let mut wrong = code.as_bytes().to_vec();
    let last = wrong
        .last_mut()
        .ok_or_else(|| std::io::Error::other("connection code was empty"))?;
    *last = if *last == b'0' { b'1' } else { b'0' };
    let wrong = String::from_utf8(wrong).map_err(std::io::Error::other)?;
    let mut controller = Command::new(env!("CARGO_BIN_EXE_yon"))
        .args(["connect", wrong.as_str()])
        .current_dir(config.path())
        .env_remove("YON_RELAYS")
        .env_remove("YON_WSS_CA")
        .env_remove("YON_WSS_CA_DER")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = controller
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("rejected controller stdout was not piped"))?;
    let stderr = controller
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("rejected controller stderr was not piped"))?;
    let stdout_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        BufReader::new(stdout)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        BufReader::new(stderr)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let status = match wait_for_exit(&mut controller, SESSION_TIMEOUT) {
        Ok(status) => status,
        Err(error) => {
            let _ = controller.kill();
            let _ = controller.wait();
            return Err(error);
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| std::io::Error::other("rejected controller stdout reader panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| std::io::Error::other("rejected controller stderr reader panicked"))??;
    if status.success() {
        return Err(std::io::Error::other(
            "controller accepted an incorrect connection code",
        ));
    }
    if !stdout.is_empty() {
        return Err(std::io::Error::other(
            "a rejected controller wrote diagnostics to stdout",
        ));
    }
    let stderr = String::from_utf8(stderr).map_err(std::io::Error::other)?;
    if stderr != "error: connection code is invalid or expired\n" {
        return Err(std::io::Error::other(format!(
            "a rejected controller exposed an unexpected public error: {stderr:?}"
        )));
    }
    for forbidden in ["OPAQUE", "PeerId", "locator", wrong.as_str(), code] {
        if stderr.contains(forbidden) {
            return Err(std::io::Error::other(format!(
                "a rejected controller leaked {forbidden:?} in its public error"
            )));
        }
    }
    Ok(())
}

fn receive_code(
    lines: &mpsc::Receiver<Result<String, std::io::Error>>,
) -> Result<String, std::io::Error> {
    let deadline = Instant::now() + START_TIMEOUT;
    let remaining = deadline.saturating_duration_since(Instant::now());
    let line = lines
        .recv_timeout(remaining)
        .map_err(|error| std::io::Error::other(error.to_string()))??;
    validate_connection_code_line(&line)
}

fn validate_connection_code_line(line: &str) -> Result<String, std::io::Error> {
    let code = line
        .strip_prefix("Connection code: ")
        .ok_or_else(|| std::io::Error::other("host stdout contained a non-product line"))?;
    code.parse::<ConnectionCode>()
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    Ok(code.to_owned())
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Result<ExitStatus, std::io::Error> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::other("child process timed out"));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn available_port() -> Result<u16, std::io::Error> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.local_addr().map(|address| address.port())
}

fn available_udp_port() -> Result<u16, std::io::Error> {
    let socket = UdpSocket::bind(("127.0.0.1", 0))?;
    socket.local_addr().map(|address| address.port())
}

#[cfg(windows)]
fn command_script() -> &'static [u8] {
    b"\x1b[1;1R\r\necho YON_E2E\r\nexit\r\n"
}

#[cfg(windows)]
fn throughput_command_script() -> &'static [u8] {
    b"\x1b[1;1R\r\ncmd.exe /D /Q /C \"(echo YON_E2E_PERFORMANCE_BEGIN&type throughput.bin&echo YON_E2E_PERFORMANCE_END)\"\r\nexit\r\n"
}

#[cfg(windows)]
fn local_pty_throughput_command_script() -> &'static [u8] {
    b"\x1b[1;1R\r\ncmd.exe /D /Q /C \"(echo YON_E2E_PERFORMANCE_BEGIN&type throughput.bin&echo YON_E2E_PERFORMANCE_END)\"\r\nexit\r\n"
}

#[cfg(not(windows))]
fn command_script() -> &'static [u8] {
    b"echo YON_E2E\nexit\n"
}

#[cfg(not(windows))]
fn throughput_command_script() -> &'static [u8] {
    b"sh -c 'printf YON_E2E_PERFORMANCE_BEGIN; cat throughput.bin; printf YON_E2E_PERFORMANCE_END'\nexit\n"
}

#[cfg(not(windows))]
fn local_pty_throughput_command_script() -> &'static [u8] {
    b"sh -c 'printf YON_E2E_PERFORMANCE_BEGIN; cat throughput.bin; printf YON_E2E_PERFORMANCE_END'\nexit\n"
}

// ---------------------------------------------------------------------
// 0.1.3 native file transfer: real-process end-to-end coverage.
// ---------------------------------------------------------------------
// These tests run the real product path of the file transfer modal
// (design 0.1.3 sections 7.2-7.5, 9-13, 17.2, 23.6): a real relay, a real
// host process whose working directory is the remote session start
// directory (design 21), and a real controller process under a PTY. A PTY
// stdin is required because the local control prefix and the transfer
// modal exist only on interactive input (design 6.2-6.4): a piped stdin
// is fully transparent. The asserted prompt labels are the frozen design
// texts of controller.rs (PROMPT_UPLOAD_SOURCE, PROMPT_UPLOAD_DESTINATION,
// PROMPT_DOWNLOAD_SOURCE, PROMPT_DOWNLOAD_DESTINATION); the completion
// summaries are the exact output of controller.rs `transfer_summary_line`
// ("{verb} complete: {bytes} bytes" / "{verb} failed: {code:?}"), and the
// failure codes are the fixed 1.0.0 wire error codes of
// yonder_core::wire::file_transfer.
//
// The tests are Unix-only by necessity, not by choice: portable_pty's
// ConPTY path on Windows cannot deliver the `Ctrl+]` (0x1D) prefix byte
// to the controller's local-control machine. Empirically on Windows 11
// (build 26200): the controller's stdin is a terminal (`is_terminal()`
// is true; the hidden code prompt works) and a raw ReadFile probe on the
// same ConPTY console delivers 0x1D intact in both legacy (0x1F0) and
// VT-input (0x3F0) console modes; but inside a real session the byte
// arrives mangled (the remote shell echoes `^]u` / `^]?` caret notation,
// the controller's own debug log records a 22-byte input write delivered
// as 23+6+1249+173-byte reads, and the marker echo executes twice). The
// controller's local-control machine never sees a usable 0x1D, so the
// modal cannot be entered and the detach cannot be driven. The Unix PTY
// input path is clean (the existing interactive_pty harness proves it),
// so the whole real-process file-transfer matrix runs there.
//
// The controller pump bug these tests exposed (the selector chunk and
// the first path chunk arriving in separate reads, with the modal path
// bytes silently dropped by `PathPromptFlow::feed`) was fixed in
// controller.rs with a split-chunk regression test; these tests run on
// Unix. The Windows ConPTY input path still mangles 0x1D, so the
// real-process file-transfer matrix stays `#[cfg(unix)]`; the Windows
// interactive path is a tracked post-release verification item.

#[cfg(unix)]
const TRANSFER_SHELL_READY: &[u8] = b"YON_E2E_FT_READY";
#[cfg(unix)]
const TRANSFER_TERMINAL_ALIVE: &[u8] = b"YON_E2E_AFTER";
/// One pattern payload above the 64 KiB transfer-size boundary.
#[cfg(unix)]
const TRANSFER_PATTERN_SIZE: usize = 128 * 1024;
#[cfg(unix)]
const TRANSFER_PROMPT_UPLOAD_SOURCE: &[u8] = b"local source:";
#[cfg(unix)]
const TRANSFER_PROMPT_UPLOAD_DESTINATION: &[u8] =
    b"remote destination [remote session start directory]:";
#[cfg(unix)]
const TRANSFER_PROMPT_DOWNLOAD_SOURCE: &[u8] = b"remote source:";
#[cfg(unix)]
const TRANSFER_PROMPT_DOWNLOAD_DESTINATION: &[u8] =
    b"local destination [local connect start directory]:";
/// `Ctrl+] .`, the local detach selector (design 6.2).
#[cfg(unix)]
const TRANSFER_DETACH: &[u8] = b"\x1d.";
/// The controller exit code after `Ctrl+] .`: main.rs `process_result`
/// maps `ControllerError::Interrupted` to the SIGINT convention 130.
#[cfg(unix)]
const TRANSFER_DETACH_EXIT_CODE: u32 = 130;

/// One real three-process file-transfer session: an in-process relay, a
/// real host binary whose working directory is the remote session start
/// directory, and an endpoint config directory shared by both endpoints.
#[cfg(unix)]
struct RealTransferSession {
    relay: RelayProcess,
    host: HostProcess,
    config: EndpointConfigDirectory,
    address: String,
}

#[cfg(unix)]
impl RealTransferSession {
    fn start() -> Result<Self, std::io::Error> {
        let port = available_port()?;
        let identity = generate_identity(&mut OsSecureRandom)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let peer = identity.public().to_peer_id();
        let address = format!("/ip4/127.0.0.1/tcp/{port}/p2p/{peer}");
        let relay = RelayProcess::start(identity, port)?;
        wait_for_tcp_listener(port)?;
        let config = EndpointConfigDirectory::new(&address)?;
        let host = HostProcess::start(&config)?;
        Ok(Self {
            relay,
            host,
            config,
            address,
        })
    }

    /// The remote session start directory: the host process working
    /// directory, captured once when the session shell starts (design 21).
    fn remote_base(&self) -> &Path {
        self.config.path()
    }

    /// The local connect directory: the controller process working
    /// directory and therefore the local file-transfer base (design 8.7).
    fn local_base(&self) -> PathBuf {
        self.config.path().join("controller-base")
    }

    /// Waits for the host connection code and spawns the PTY controller in
    /// the local connect directory.
    fn start_controller(&mut self) -> Result<PtyTransferSession, std::io::Error> {
        let code = receive_code(&self.host.lines)?;
        let local_base = self.local_base();
        std::fs::create_dir_all(&local_base)?;
        std::fs::write(
            local_base.join("yon.toml"),
            format!("relays = [\"{}\"]\n", self.address),
        )?;
        start_controller_pty(&code, &local_base, &local_base.join("controller-debug.log"))
    }
}

/// The PTY driving side of the controller process: the master writer for
/// scripted input, a reader thread for the accumulated output, and the
/// spawned controller child.
#[cfg(unix)]
struct PtyTransferSession {
    controller: Option<Box<dyn portable_pty::Child + Send + Sync>>,
    writer: Option<Box<dyn std::io::Write + Send>>,
    master: Option<Box<dyn portable_pty::MasterPty + Send>>,
    output_rx: mpsc::Receiver<Vec<u8>>,
    output_reader: Option<JoinHandle<Result<(), std::io::Error>>>,
    output: Vec<u8>,
}

#[cfg(unix)]
impl PtyTransferSession {
    fn send(&mut self, bytes: &[u8]) -> Result<(), std::io::Error> {
        let writer = self.writer.as_mut().expect("PTY writer is present");
        writer.write_all(bytes)?;
        writer.flush()
    }

    fn wait_for(&mut self, marker: &[u8], timeout: Duration) -> Result<(), std::io::Error> {
        wait_for_bytes(&self.output_rx, &mut self.output, marker, timeout)
    }

    /// Writes one scripted input segment and blocks until the expected
    /// marker appears in the accumulated terminal output: the script never
    /// proceeds on a guess, only on observed terminal state.
    fn send_and_wait(
        &mut self,
        bytes: &[u8],
        marker: &[u8],
        timeout: Duration,
    ) -> Result<(), std::io::Error> {
        self.send(bytes)?;
        self.wait_for(marker, timeout)
    }

    /// The remote shell is ready when the marker echo executes. The
    /// cursor-position report answer keeps the Windows ConPTY opening
    /// sequence identical to the existing Windows harness; on Unix it is a
    /// harmless empty command line before the marker echo.
    fn shell_ready(&mut self) -> Result<(), std::io::Error> {
        self.send_and_wait(
            b"echo YON_E2E_FT_READY\r",
            TRANSFER_SHELL_READY,
            START_TIMEOUT,
        )
    }

    /// Waits for the controller to exit, drains the PTY reader and returns
    /// the exit code plus the complete accumulated terminal output.
    fn wait_for_exit(mut self, timeout: Duration) -> Result<(u32, Vec<u8>), std::io::Error> {
        let mut controller = self.controller.take().expect("PTY controller is present");
        let exit = match wait_for_pty_exit(controller.as_mut(), timeout) {
            Ok(exit) => exit,
            Err(error) => {
                let _ = controller.kill();
                let _ = controller.wait();
                self.close_output()?;
                return Err(error);
            }
        };
        self.close_output()?;
        Ok((exit, std::mem::take(&mut self.output)))
    }

    fn close_output(&mut self) -> Result<(), std::io::Error> {
        self.writer = None;
        self.master = None;
        finish_thread(
            &mut self.output_reader,
            START_TIMEOUT,
            "controller PTY output",
        )??;
        self.output.extend(self.output_rx.try_iter().flatten());
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for PtyTransferSession {
    fn drop(&mut self) {
        if let Some(mut controller) = self.controller.take() {
            let _ = controller.kill();
            let _ = controller.wait();
        }
        self.writer = None;
        self.master = None;
        if let Some(reader) = self.output_reader.take() {
            let _ = reader.join();
        }
    }
}

/// Spawns the real controller binary under a PTY with the same arguments,
/// working directory and environment hygiene as the existing controller
/// harness (`run_controller_session_with_script`). The PTY makes stderr a
/// terminal, so the debug diagnostics go to `log_file` (the same
/// `--log-file` pattern as the existing PTY harnesses).
#[cfg(unix)]
fn start_controller_pty(
    code: &str,
    cwd: &Path,
    log_file: &Path,
) -> Result<PtyTransferSession, std::io::Error> {
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(std::io::Error::other)?;
    let reader = pair
        .master
        .try_clone_reader()
        .map_err(std::io::Error::other)?;
    let writer = pair.master.take_writer().map_err(std::io::Error::other)?;
    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_yon"));
    command.args(["--log-level", "debug", "--log-file"]);
    command.arg(log_file.as_os_str());
    command.args(["connect", code]);
    command.cwd(cwd);
    command.env_remove("YON_RELAYS");
    command.env_remove("YON_WSS_CA");
    command.env_remove("YON_WSS_CA_DER");
    let controller = pair
        .slave
        .spawn_command(command)
        .map_err(std::io::Error::other)?;
    drop(pair.slave);
    let (output_tx, output_rx) = mpsc::channel();
    let output_reader = thread::spawn(move || {
        let mut reader = reader;
        let mut chunk = [0_u8; 4096];
        loop {
            let length = reader.read(&mut chunk)?;
            if length == 0 {
                return Ok(());
            }
            if output_tx.send(chunk[..length].to_vec()).is_err() {
                return Ok(());
            }
        }
    });
    Ok(PtyTransferSession {
        controller: Some(controller),
        writer: Some(writer),
        master: Some(pair.master),
        output_rx,
        output_reader: Some(output_reader),
        output: Vec::new(),
    })
}

/// Drives one upload modal to the default remote destination: `Ctrl+] u`,
/// the local source, then an empty destination submit (default target = the
/// remote session start directory joined with the source file name). The
/// wait ends when the completion summary of the exact transferred size
/// appears.
#[cfg(unix)]
fn drive_upload_to_default(
    pty: &mut PtyTransferSession,
    file_name: &str,
    expected_size: usize,
) -> Result<(), std::io::Error> {
    pty.send_and_wait(b"\x1du", TRANSFER_PROMPT_UPLOAD_SOURCE, SESSION_TIMEOUT)?;
    let submit = transfer_path_submission(file_name);
    pty.send_and_wait(&submit, TRANSFER_PROMPT_UPLOAD_DESTINATION, SESSION_TIMEOUT)?;
    pty.send_and_wait(
        b"\r",
        transfer_summary("upload", expected_size).as_bytes(),
        SESSION_TIMEOUT,
    )
}

/// Drives one download modal to the default local destination: `Ctrl+] d`,
/// the remote source, then an empty destination submit (default target =
/// the local connect directory joined with the remote file name).
#[cfg(unix)]
fn drive_download_to_default(
    pty: &mut PtyTransferSession,
    file_name: &str,
    expected_size: usize,
) -> Result<(), std::io::Error> {
    pty.send_and_wait(b"\x1dd", TRANSFER_PROMPT_DOWNLOAD_SOURCE, SESSION_TIMEOUT)?;
    let submit = transfer_path_submission(file_name);
    pty.send_and_wait(
        &submit,
        TRANSFER_PROMPT_DOWNLOAD_DESTINATION,
        SESSION_TIMEOUT,
    )?;
    pty.send_and_wait(
        b"\r",
        transfer_summary("download", expected_size).as_bytes(),
        SESSION_TIMEOUT,
    )
}

/// Drives one upload modal with an explicit remote destination and waits
/// for the given expected marker (a completion or a failure summary).
#[cfg(unix)]
fn drive_upload_to(
    pty: &mut PtyTransferSession,
    file_name: &str,
    target: &str,
    expected_marker: &[u8],
) -> Result<(), std::io::Error> {
    pty.send_and_wait(b"\x1du", TRANSFER_PROMPT_UPLOAD_SOURCE, SESSION_TIMEOUT)?;
    let submit = transfer_path_submission(file_name);
    pty.send_and_wait(&submit, TRANSFER_PROMPT_UPLOAD_DESTINATION, SESSION_TIMEOUT)?;
    let target = transfer_path_submission(target);
    pty.send_and_wait(&target, expected_marker, SESSION_TIMEOUT)
}

/// One path prompt submission: the typed path plus the Enter byte.
#[cfg(unix)]
fn transfer_path_submission(path: &str) -> Vec<u8> {
    let mut submission = Vec::with_capacity(path.len() + 1);
    submission.extend_from_slice(path.as_bytes());
    submission.push(b'\r');
    submission
}

/// The exact completion summary of controller.rs `transfer_summary_line`:
/// "{verb} complete: {bytes} bytes".
#[cfg(unix)]
fn transfer_summary(direction: &str, size: usize) -> String {
    format!("{direction} complete: {size} bytes")
}

/// A deterministic pattern payload: every byte is a fixed function of its
/// index, so a byte-perfect comparison against the transferred file is
/// meaningful and reproducible.
#[cfg(unix)]
fn transfer_pattern_bytes(size: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(size);
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for _ in 0..size {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        bytes.push((state >> 33) as u8);
    }
    bytes
}

/// Sends the `Ctrl+] .` detach, waits for the controller exit and verifies
/// the interrupt-convention exit code; returns the full terminal output.
#[cfg(unix)]
fn detach_and_verify(mut pty: PtyTransferSession) -> Result<(u32, Vec<u8>), std::io::Error> {
    pty.send(TRANSFER_DETACH)?;
    let (exit_code, output) = pty.wait_for_exit(SESSION_TIMEOUT)?;
    if exit_code != TRANSFER_DETACH_EXIT_CODE {
        return Err(std::io::Error::other(format!(
            "controller exited with code {exit_code} after Ctrl+] . detach; expected {TRANSFER_DETACH_EXIT_CODE}; terminal output: {:?}",
            String::from_utf8_lossy(&output),
        )));
    }
    Ok((exit_code, output))
}

/// Waits for the host to exit on its own after the controller detached
/// (the closed session tears the host down), then finishes it the same way
/// `finish_with_exit` does but without constraining the exit code: the
/// detach ends the session before the remote shell exits, so the host
/// session ends abnormally by design.
#[cfg(unix)]
fn reap_detached_host(host: &mut HostProcess) -> Result<(), std::io::Error> {
    let status = wait_for_exit(&mut host.child, SESSION_TIMEOUT);
    if status.is_err() {
        let _ = host.child.kill();
        let _ = host.child.wait();
    }
    host.reaped = true;
    host.join_reader();
    host.join_diagnostic_reader()?;
    status.map(drop)
}

/// The try/finally teardown of one real transfer session, in the style of
/// the existing three-process harness: the host is reaped (it ends by
/// itself after the detach) and the relay is stopped, and the original
/// outcome is only returned after both cleanups ran.
#[cfg(unix)]
fn finish_real_transfer_session(
    mut session: RealTransferSession,
    outcome: Result<(), std::io::Error>,
) -> Result<(), std::io::Error> {
    let host_result = if outcome.is_ok() {
        reap_detached_host(&mut session.host)
    } else {
        session.host.terminate();
        Ok(())
    };
    let relay_result = session.relay.stop();
    outcome?;
    host_result?;
    relay_result
}

#[cfg(unix)]
#[test]
fn real_upload_transfers_a_pattern_file_between_processes() -> Result<(), std::io::Error> {
    const FILE_NAME: &str = "payload.bin";
    let mut session = RealTransferSession::start()?;
    let outcome = (|| -> Result<(), std::io::Error> {
        // The upload source is local to the controller: it lives in the
        // controller's connect directory, while the destination lands in
        // the remote session start directory (the host working directory).
        let payload = transfer_pattern_bytes(TRANSFER_PATTERN_SIZE);
        std::fs::write(session.local_base().join(FILE_NAME), &payload)?;
        let mut pty = session.start_controller()?;
        pty.shell_ready()?;
        drive_upload_to_default(&mut pty, FILE_NAME, TRANSFER_PATTERN_SIZE)?;
        let (_, output) = detach_and_verify(pty)?;
        assert_bytes_contain(
            &output,
            transfer_summary("upload", TRANSFER_PATTERN_SIZE).as_bytes(),
            "upload completion summary",
        )?;
        let received = std::fs::read(session.remote_base().join(FILE_NAME))?;
        if received != payload {
            return Err(std::io::Error::other(format!(
                "uploaded file differed from the source: {} source bytes, {} received bytes",
                payload.len(),
                received.len(),
            )));
        }
        Ok(())
    })();
    finish_real_transfer_session(session, outcome)
}

#[cfg(unix)]
#[test]
fn real_upload_transfers_an_empty_file_between_processes() -> Result<(), std::io::Error> {
    const FILE_NAME: &str = "empty.bin";
    let mut session = RealTransferSession::start()?;
    let outcome = (|| -> Result<(), std::io::Error> {
        std::fs::write(session.local_base().join(FILE_NAME), [])?;
        let mut pty = session.start_controller()?;
        pty.shell_ready()?;
        drive_upload_to_default(&mut pty, FILE_NAME, 0)?;
        let (_, output) = detach_and_verify(pty)?;
        assert_bytes_contain(
            &output,
            b"upload complete: 0 bytes",
            "empty upload completion summary",
        )?;
        let received = std::fs::read(session.remote_base().join(FILE_NAME))?;
        if !received.is_empty() {
            return Err(std::io::Error::other(format!(
                "uploaded empty file carried {} bytes",
                received.len(),
            )));
        }
        Ok(())
    })();
    finish_real_transfer_session(session, outcome)
}

#[cfg(unix)]
#[test]
fn real_download_transfers_a_pattern_file_between_processes() -> Result<(), std::io::Error> {
    const FILE_NAME: &str = "remote.bin";
    let mut session = RealTransferSession::start()?;
    let outcome = (|| -> Result<(), std::io::Error> {
        let payload = transfer_pattern_bytes(TRANSFER_PATTERN_SIZE);
        std::fs::write(session.remote_base().join(FILE_NAME), &payload)?;
        let mut pty = session.start_controller()?;
        pty.shell_ready()?;
        drive_download_to_default(&mut pty, FILE_NAME, TRANSFER_PATTERN_SIZE)?;
        let (_, output) = detach_and_verify(pty)?;
        assert_bytes_contain(
            &output,
            transfer_summary("download", TRANSFER_PATTERN_SIZE).as_bytes(),
            "download completion summary",
        )?;
        let received = std::fs::read(session.local_base().join(FILE_NAME))?;
        if received != payload {
            return Err(std::io::Error::other(format!(
                "downloaded file differed from the remote source: {} remote bytes, {} received bytes",
                payload.len(),
                received.len(),
            )));
        }
        Ok(())
    })();
    finish_real_transfer_session(session, outcome)
}

#[cfg(unix)]
#[test]
fn upload_to_an_explicit_remote_destination_rejects_a_missing_parent_and_recovers()
-> Result<(), std::io::Error> {
    const SOURCE_NAME: &str = "payload.bin";
    const TARGET: &str = "sub/out.bin";
    const FAILURE: &[u8] = b"upload failed: DestinationParentNotFound";
    let mut session = RealTransferSession::start()?;
    let outcome = (|| -> Result<(), std::io::Error> {
        let payload = transfer_pattern_bytes(TRANSFER_PATTERN_SIZE);
        std::fs::write(session.local_base().join(SOURCE_NAME), &payload)?;
        let mut pty = session.start_controller()?;
        pty.shell_ready()?;
        // The explicit destination's parent does not exist: the host
        // rejects the upload (§8.3: destination parents are never created
        // automatically).
        drive_upload_to(&mut pty, SOURCE_NAME, TARGET, FAILURE)?;
        // The failure is localized (§17.2): the terminal stays fully
        // usable, and a plain echo still executes.
        pty.send_and_wait(
            b"echo YON_E2E_AFTER\r",
            TRANSFER_TERMINAL_ALIVE,
            SESSION_TIMEOUT,
        )?;
        // The test then creates the missing parent on the remote side
        // directly (the remote session base is an ordinary directory of
        // this process) and the same upload succeeds.
        std::fs::create_dir(session.remote_base().join("sub"))?;
        drive_upload_to(
            &mut pty,
            SOURCE_NAME,
            TARGET,
            transfer_summary("upload", TRANSFER_PATTERN_SIZE).as_bytes(),
        )?;
        let (_, output) = detach_and_verify(pty)?;
        assert_bytes_contain(&output, FAILURE, "missing-parent failure summary")?;
        let received = std::fs::read(session.remote_base().join(TARGET))?;
        if received != payload {
            return Err(std::io::Error::other(format!(
                "explicit-destination upload differed from the source: {} source bytes, {} received bytes",
                payload.len(),
                received.len(),
            )));
        }
        Ok(())
    })();
    finish_real_transfer_session(session, outcome)
}

#[cfg(unix)]
#[test]
fn upload_to_an_existing_remote_destination_is_rejected_without_overwrite()
-> Result<(), std::io::Error> {
    const SOURCE_NAME: &str = "payload.bin";
    const TARGET: &str = "exists.bin";
    const EXISTING: &[u8] = b"YON_E2E_EXISTING_TARGET_CONTENT";
    const FAILURE: &[u8] = b"upload failed: DestinationExists";
    let mut session = RealTransferSession::start()?;
    let outcome = (|| -> Result<(), std::io::Error> {
        let payload = transfer_pattern_bytes(TRANSFER_PATTERN_SIZE);
        std::fs::write(session.local_base().join(SOURCE_NAME), &payload)?;
        std::fs::write(session.remote_base().join(TARGET), EXISTING)?;
        let mut pty = session.start_controller()?;
        pty.shell_ready()?;
        // §8.3: a final target that already exists is rejected before any
        // byte is written.
        drive_upload_to(&mut pty, SOURCE_NAME, TARGET, FAILURE)?;
        // The failure is localized (§17.2): the terminal stays usable.
        pty.send_and_wait(
            b"echo YON_E2E_AFTER\r",
            TRANSFER_TERMINAL_ALIVE,
            SESSION_TIMEOUT,
        )?;
        let (_, output) = detach_and_verify(pty)?;
        assert_bytes_contain(&output, FAILURE, "existing-target failure summary")?;
        // The existing target is never overwritten.
        let existing = std::fs::read(session.remote_base().join(TARGET))?;
        if existing != EXISTING {
            return Err(std::io::Error::other(format!(
                "rejected upload overwrote the existing target: {} bytes, expected {}",
                existing.len(),
                EXISTING.len(),
            )));
        }
        Ok(())
    })();
    finish_real_transfer_session(session, outcome)
}
