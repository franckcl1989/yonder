use crate::network::{
    ConnectionBinding, EndpointDriver, EndpointError, EndpointEvent, RelayConnection,
    ReservationLease, build_endpoint, connect_configured_relay, drive_bound, reconverge_relay,
    relay_backoff, wait_for_reservation,
};
use crate::pake::{OpaquePake, OpaquePakeError, OpaqueRegistration};
use crate::progress::{NoopProgress, OperationProgress, wait_with_progress};
use crate::protocol::{
    ReclaimResponse, RelayProtocolError, allocate_locator, reclaim_locator, release_locator,
    release_locator_bound,
};
use crate::terminal::{
    PortablePtyBackend, PtyEventKind, TerminalBackend, TerminalError, TerminalInput,
    TerminalSession,
};
use std::convert::Infallible;
use std::future::Future;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_util::compat::FuturesAsyncReadCompatExt as _;
use yonder_core::wire::auth::{
    AuthClientFinish, AuthClientHello, AuthServerResponse, Authenticated, CLIENT_HELLO_LEN,
    KE3_LEN, PakeContext,
};
use yonder_core::wire::terminal::{
    MAX_HELLO_LEN, TerminalExit, TerminalHello, TerminalReady, TerminalResize,
};
use yonder_core::wire::{AUTH_PROTOCOL, TERMINAL_CONTROL_PROTOCOL, TERMINAL_DATA_PROTOCOL};
use yonder_core::{
    ConnectionCode, DirectRateLimiter, OsSecureRandom, Pake, PeerIdBytes, ProtocolError,
    RandomError, RateLimit, SecureRandom, SessionEvent, TargetSession, TransitionError,
};
use yonder_net::{
    ApplicationStream, ApplicationStreamError, ApplicationStreams, EndpointRelaySet,
    IncomingApplicationStreams, Keypair, Libp2pApplicationStreams, PeerId, WssTransportConfig,
    peer_id_bytes,
};

const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
const PRE_AUTH_QUIESCENCE_TIMEOUT: Duration = Duration::from_secs(3);

/// Complete input required to advertise one remote terminal.
pub struct HostConfig {
    identity: Keypair,
    relays: EndpointRelaySet,
    wss: WssTransportConfig,
}

impl HostConfig {
    #[must_use]
    pub const fn new(identity: Keypair, relays: EndpointRelaySet, wss: WssTransportConfig) -> Self {
        Self {
            identity,
            relays,
            wss,
        }
    }
}

/// User-visible milestones emitted while a host advertises and serves one terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostStage {
    ConnectingRelay,
    ReservingRelay,
    RegisteringHost,
    WaitingForController,
    ReconnectingRelay,
    AuthenticatingController,
    StartingTerminal,
    TerminalActive,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{
        EXCHANGE_TIMEOUT, HostConfig, HostError, PRE_AUTH_QUIESCENCE_TIMEOUT, PendingPair,
        binding_event, copy_controller_input, copy_terminal_output, host_error_event,
        read_auth_hello_io, read_terminal_hello_io, report_connection_code_to,
        report_replacement_notice_to, retryable_relay_error, run_host, run_host_with,
        run_host_with_progress, send_auth_retry_io, start_terminal_io, write_authenticated_io,
        write_terminal_ready_io,
    };
    use crate::network::EndpointError;
    use crate::progress::NoopProgress;
    use crate::protocol::RelayProtocolError;
    use crate::terminal::{
        PtyEvent, TerminalBackend, TerminalChunk, TerminalError, TerminalInput, TerminalSession,
    };
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
    use yonder_core::wire::auth::{AuthClientHello, AuthServerResponse, CLIENT_HELLO_LEN};
    use yonder_core::wire::terminal::{MAX_HELLO_LEN, TerminalExit, TerminalHello, TerminalResize};
    use yonder_core::{
        ConnectionCode, Locator, PakeSecret, SessionEvent, TerminalSize, TerminalValue,
    };
    use yonder_net::{
        EndpointRelayAddress, EndpointRelaySet, Keypair, NetworkBuildError, WssTransportConfig,
    };

    struct FailingOutput;

    #[test]
    fn pre_auth_convergence_is_tighter_than_each_frozen_message_timeout() {
        assert_eq!(PRE_AUTH_QUIESCENCE_TIMEOUT, Duration::from_secs(3));
        assert_eq!(EXCHANGE_TIMEOUT, Duration::from_secs(10));
        assert!(PRE_AUTH_QUIESCENCE_TIMEOUT < EXCHANGE_TIMEOUT);
    }

    impl std::io::Write for FailingOutput {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed output",
            ))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed output",
            ))
        }
    }

    #[test]
    fn connection_code_output_is_flushed_and_failures_are_recoverable() {
        let code = ConnectionCode::new(Locator::new(0).unwrap(), PakeSecret::from_u64(0).unwrap());
        let mut output = Vec::new();
        report_connection_code_to(&mut output, &code).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "Connection code: 0000-0000-0000-0000\n"
        );
        assert_eq!(
            report_connection_code_to(&mut FailingOutput, &code)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn replacement_notice_makes_the_previous_code_state_explicit() {
        let mut output = Vec::new();
        report_replacement_notice_to(&mut output).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "Connection code changed; the previous code is no longer valid.\n"
        );
        assert_eq!(
            report_replacement_notice_to(&mut FailingOutput)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn terminal_stream_pair_preserves_whichever_arrives_first() {
        let mut data_first = PendingPair::new();
        data_first.insert_data(1_u8);
        assert_eq!(data_first.take_complete(), None);
        assert!(!data_first.needs_data());
        data_first.insert_data(9_u8);
        data_first.insert_control(2_u8);
        assert_eq!(data_first.take_complete(), Some((1, 2)));

        let mut control_first = PendingPair::new();
        control_first.insert_control(4_u8);
        assert_eq!(control_first.take_complete(), None);
        assert!(!control_first.needs_control());
        control_first.insert_control(8_u8);
        control_first.insert_data(3_u8);
        assert_eq!(control_first.take_complete(), Some((3, 4)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_ready_is_written_to_the_data_stream() {
        let (mut host_data, mut controller_data) = tokio::io::duplex(1);
        let write = write_terminal_ready_io(&mut host_data);
        let read = async {
            let mut ready = [0_u8; 1];
            controller_data.read_exact(&mut ready).await.unwrap();
            ready
        };
        let (result, ready) = tokio::join!(write, read);
        result.unwrap();
        assert_eq!(ready, yonder_core::wire::terminal::TerminalReady::ENCODED);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_acknowledgement_is_written_without_waiting_for_stream_close() {
        let (mut host_auth, mut controller_auth) = tokio::io::duplex(1);
        let write = write_authenticated_io(&mut host_auth);
        let read = async {
            let mut acknowledgement = [0_u8; 1];
            controller_auth
                .read_exact(&mut acknowledgement)
                .await
                .unwrap();
            acknowledgement
        };
        let (result, acknowledgement) = tokio::join!(write, read);
        result.unwrap();
        assert_eq!(
            acknowledgement,
            yonder_core::wire::auth::Authenticated::ENCODED
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn auth_hello_reader_accepts_exact_messages_and_times_out() {
        let encoded = AuthClientHello::new([7; 32], [9; 96]).encode();
        let mut exact = encoded.as_slice();
        assert_eq!(
            read_auth_hello_io(&mut exact, Duration::from_secs(1))
                .await
                .unwrap()
                .nonce(),
            &[7; 32]
        );

        let truncated_bytes = [0_u8; CLIENT_HELLO_LEN - 1];
        let mut truncated = truncated_bytes.as_slice();
        assert!(matches!(
            read_auth_hello_io(&mut truncated, Duration::from_secs(1)).await,
            Err(HostError::Io(_))
        ));

        let (_writer, mut pending) = tokio::io::duplex(1);
        assert!(matches!(
            read_auth_hello_io(&mut pending, Duration::from_millis(1)).await,
            Err(HostError::Timeout)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn auth_retry_has_the_frozen_value_and_closes_the_stream() {
        let (mut host, mut controller) = tokio::io::duplex(5);
        let write = send_auth_retry_io(&mut host);
        let read = async {
            let mut response = Vec::new();
            controller.read_to_end(&mut response).await.unwrap();
            response
        };
        let (result, response) = tokio::join!(write, read);
        result.unwrap();
        let decoded = AuthServerResponse::decode(&response).unwrap();
        assert_eq!(decoded.retry_after().unwrap().millis(), 1_000);

        let (mut rejected, peer) = tokio::io::duplex(1);
        drop(peer);
        assert!(matches!(
            send_auth_retry_io(&mut rejected).await,
            Err(HostError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_hello_reader_enforces_both_length_bounds() {
        let hello = TerminalHello::new(
            TerminalSize::new(80, 24).unwrap(),
            TerminalValue::new("xterm").unwrap(),
            TerminalValue::new("truecolor").unwrap(),
        );
        let encoded = hello.encode();
        let mut exact = encoded.as_slice();
        assert_eq!(read_terminal_hello_io(&mut exact).await.unwrap(), hello);

        let mut oversized_term = [0_u8; 6];
        oversized_term[5] = (MAX_HELLO_LEN - 6) as u8;
        assert!(matches!(
            read_terminal_hello_io(&mut oversized_term.as_slice()).await,
            Err(HostError::Protocol(_))
        ));

        let mut oversized_color = [0_u8; 71];
        oversized_color[0] = 0x01;
        oversized_color[1..3].copy_from_slice(&80_u16.to_be_bytes());
        oversized_color[3..5].copy_from_slice(&24_u16.to_be_bytes());
        oversized_color[5] = 64;
        oversized_color[70] = 65;
        assert!(matches!(
            read_terminal_hello_io(&mut oversized_color.as_slice()).await,
            Err(HostError::Protocol(_))
        ));

        let mut truncated = [0x01_u8, 0].as_slice();
        assert!(matches!(
            read_terminal_hello_io(&mut truncated).await,
            Err(HostError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_ready_write_propagates_closed_peer() {
        let (mut host, peer) = tokio::io::duplex(1);
        drop(peer);
        assert!(matches!(
            write_terminal_ready_io(&mut host).await,
            Err(HostError::Io(_))
        ));
    }

    #[test]
    fn endpoint_failures_map_to_the_only_legal_session_events() {
        assert_eq!(
            binding_event(&EndpointError::AdditionalBoundConnection),
            SessionEvent::ExtraConnection
        );
        assert_eq!(
            binding_event(&EndpointError::BoundConnectionLost),
            SessionEvent::ConnectionLost
        );
        assert_eq!(
            host_error_event(
                &HostError::Endpoint(EndpointError::AdditionalBoundConnection),
                SessionEvent::TerminalStartFailed,
            ),
            SessionEvent::ExtraConnection
        );
        assert_eq!(
            host_error_event(&HostError::Timeout, SessionEvent::TerminalStartFailed),
            SessionEvent::TerminalStartFailed
        );
    }

    #[test]
    fn relay_recovery_only_retries_transient_or_resource_failures() {
        for error in [
            RelayProtocolError::Endpoint(EndpointError::RelayUnavailable),
            RelayProtocolError::Timeout,
            RelayProtocolError::Io(std::io::Error::other("transient")),
            RelayProtocolError::Capacity,
            RelayProtocolError::ReservationRequired,
            RelayProtocolError::RetryExhausted,
        ] {
            assert!(retryable_relay_error(&error));
        }
        for error in [
            RelayProtocolError::Conflict,
            RelayProtocolError::LocatorMismatch,
            RelayProtocolError::Unavailable,
            RelayProtocolError::InvalidPeerId,
            RelayProtocolError::UnexpectedResponse,
        ] {
            assert!(!retryable_relay_error(&error));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_start_preserves_root_error_and_cleans_open_session() {
        let hello = TerminalHello::new(
            TerminalSize::new(80, 24).unwrap(),
            TerminalValue::new("xterm").unwrap(),
            TerminalValue::new("truecolor").unwrap(),
        )
        .encode();

        let shutdowns = Arc::new(AtomicUsize::new(0));
        let mut control = hello.as_slice();
        let (mut data, data_peer) = tokio::io::duplex(1);
        drop(data_peer);
        let error = start_terminal_io(
            &TestBackend::session(Arc::clone(&shutdowns), false),
            &mut data,
            &mut control,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, HostError::Io(_)));
        assert_eq!(shutdowns.load(Ordering::Relaxed), 1);

        let mut control = hello.as_slice();
        let (mut data, data_peer) = tokio::io::duplex(1);
        drop(data_peer);
        let error = start_terminal_io(
            &TestBackend::session(Arc::clone(&shutdowns), true),
            &mut data,
            &mut control,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, HostError::Io(_)));
        assert_eq!(shutdowns.load(Ordering::Relaxed), 2);

        let mut control = hello.as_slice();
        let (mut data, _data_peer) = tokio::io::duplex(1);
        let error = start_terminal_io(&TestBackend::open_failure(), &mut data, &mut control)
            .await
            .unwrap_err();
        assert!(matches!(error, HostError::Terminal(TerminalError::Open)));
        assert_eq!(shutdowns.load(Ordering::Relaxed), 2);

        let mut control = hello.as_slice();
        let (mut data, mut data_peer) = tokio::io::duplex(1);
        let backend = TestBackend::session(Arc::clone(&shutdowns), false);
        let started = start_terminal_io(&backend, &mut data, &mut control);
        let ready = async {
            let mut byte = [0_u8; 1];
            data_peer.read_exact(&mut byte).await.unwrap();
            byte
        };
        let (session, ready) = tokio::join!(started, ready);
        assert_eq!(ready, yonder_core::wire::terminal::TerminalReady::ENCODED);
        TerminalSession::shutdown(session.unwrap()).await.unwrap();
        assert_eq!(shutdowns.load(Ordering::Relaxed), 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_pumps_make_progress_under_bidirectional_backpressure() {
        const PAYLOAD_LEN: usize = 128 * 1024;
        const EXIT_CODE: u32 = 37;
        let controller_payload = patterned_bytes(PAYLOAD_LEN, 3);
        let terminal_payload = patterned_bytes(PAYLOAD_LEN, 11);
        let mut events = terminal_payload
            .chunks(16 * 1024)
            .map(|bytes| {
                let mut chunk = TerminalChunk::new();
                chunk.writable()[..bytes.len()].copy_from_slice(bytes);
                chunk.set_len(bytes.len()).unwrap();
                PtyEvent::output(chunk)
            })
            .collect::<VecDeque<_>>();
        events.push_back(PtyEvent::exited(EXIT_CODE));
        let mut session = PumpSession { events };

        let (host_data, controller_data) = tokio::io::duplex(31);
        let (mut host_data_read, mut host_data_write) = tokio::io::split(host_data);
        let (mut controller_data_read, mut controller_data_write) =
            tokio::io::split(controller_data);
        let (host_control, controller_control) = tokio::io::duplex(31);
        let (mut host_control_read, mut host_control_write) = tokio::io::split(host_control);
        let (mut controller_control_read, controller_control_write) =
            tokio::io::split(controller_control);
        let (pty_input, mut captured_input) = tokio::io::duplex(31);
        let mut pty_input = DuplexInput(pty_input);

        let host = async {
            let input = copy_controller_input(&mut host_data_read, &mut pty_input);
            let output = copy_terminal_output(
                &mut session,
                &mut host_data_write,
                &mut host_control_read,
                &mut host_control_write,
            );
            tokio::pin!(input);
            tokio::pin!(output);
            tokio::select! {
                result = &mut input => match result {
                    Ok(never) => match never {},
                    Err(error) => Err(error),
                },
                result = &mut output => result,
            }
        };
        let controller = async {
            let _control_writer = controller_control_write;
            controller_data_write.write_all(&controller_payload).await?;
            controller_data_write.shutdown().await?;
            let mut output = Vec::with_capacity(PAYLOAD_LEN);
            controller_data_read.read_to_end(&mut output).await?;
            let mut exit = [0_u8; 5];
            controller_control_read.read_exact(&mut exit).await?;
            Ok::<_, std::io::Error>((output, TerminalExit::decode(&exit).unwrap()))
        };
        let capture = async {
            let mut input = vec![0_u8; PAYLOAD_LEN];
            captured_input.read_exact(&mut input).await?;
            Ok::<_, std::io::Error>(input)
        };

        let (host, controller, captured) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(host, controller, capture)
        })
        .await
        .expect("full-duplex terminal pumps deadlocked");
        assert_eq!(host.unwrap(), EXIT_CODE);
        let (output, exit) = controller.unwrap();
        assert_eq!(output, terminal_payload);
        assert_eq!(exit.code(), EXIT_CODE);
        assert_eq!(captured.unwrap(), controller_payload);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_output_applies_resize_before_reporting_exit() {
        const EXIT_CODE: u32 = 41;
        let resized = TerminalSize::new(117, 41).unwrap();
        let mut session = ResizeThenExitSession {
            resized: None,
            exit_code: EXIT_CODE,
        };
        let (host_data, mut controller_data) = tokio::io::duplex(8);
        let (_host_data_read, mut host_data_write) = tokio::io::split(host_data);
        let (host_control, controller_control) = tokio::io::duplex(8);
        let (mut host_control_read, mut host_control_write) = tokio::io::split(host_control);
        let (mut controller_control_read, mut controller_control_write) =
            tokio::io::split(controller_control);
        controller_control_write
            .write_all(&TerminalResize::new(resized).encode())
            .await
            .unwrap();

        let host = copy_terminal_output(
            &mut session,
            &mut host_data_write,
            &mut host_control_read,
            &mut host_control_write,
        );
        let controller = async {
            let mut terminal_bytes = Vec::new();
            controller_data
                .read_to_end(&mut terminal_bytes)
                .await
                .unwrap();
            let mut exit = [0_u8; 5];
            controller_control_read.read_exact(&mut exit).await.unwrap();
            (terminal_bytes, TerminalExit::decode(&exit).unwrap())
        };
        let (exit, (terminal_bytes, remote_exit)) = tokio::join!(host, controller);

        assert_eq!(exit.unwrap(), EXIT_CODE);
        assert!(terminal_bytes.is_empty());
        assert_eq!(remote_exit.code(), EXIT_CODE);
        assert_eq!(session.resized, Some(resized));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn every_public_host_entry_rejects_invalid_tls_before_network_activity() {
        let invalid_config = || {
            let relay_identity = Keypair::generate_ed25519();
            let relay: EndpointRelayAddress = format!(
                "/dns4/localhost/tcp/443/tls/ws/p2p/{}",
                relay_identity.public().to_peer_id()
            )
            .parse()
            .unwrap();
            HostConfig::new(
                Keypair::generate_ed25519(),
                EndpointRelaySet::new(vec![relay]).unwrap(),
                WssTransportConfig::client(Some(vec![1])),
            )
        };
        let assert_invalid = |result| {
            assert!(matches!(
                result,
                Err(HostError::Endpoint(EndpointError::Build(
                    NetworkBuildError::WssTls(_)
                )))
            ));
        };

        assert_invalid(run_host(invalid_config()).await);
        let mut progress = NoopProgress;
        assert_invalid(run_host_with_progress(invalid_config(), &mut progress).await);
        assert_invalid(run_host_with(invalid_config(), TestBackend::open_failure()).await);
    }

    struct TestBackend {
        shutdowns: Arc<AtomicUsize>,
        fail_open: bool,
        fail_shutdown: bool,
    }

    impl TestBackend {
        fn session(shutdowns: Arc<AtomicUsize>, fail_shutdown: bool) -> Self {
            Self {
                shutdowns,
                fail_open: false,
                fail_shutdown,
            }
        }

        fn open_failure() -> Self {
            Self {
                shutdowns: Arc::new(AtomicUsize::new(0)),
                fail_open: true,
                fail_shutdown: false,
            }
        }
    }

    impl TerminalBackend for TestBackend {
        type Session = TestSession;

        async fn open(&self, _hello: TerminalHello) -> Result<Self::Session, TerminalError> {
            if self.fail_open {
                return Err(TerminalError::Open);
            }
            Ok(TestSession {
                shutdowns: Arc::clone(&self.shutdowns),
                fail_shutdown: self.fail_shutdown,
            })
        }
    }

    #[derive(Debug)]
    struct TestSession {
        shutdowns: Arc<AtomicUsize>,
        fail_shutdown: bool,
    }

    #[derive(Debug)]
    struct TestInput;

    struct DuplexInput(tokio::io::DuplexStream);

    impl AsyncWrite for DuplexInput {
        fn poll_write(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            Pin::new(&mut self.0).poll_write(context, bytes)
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.0).poll_flush(context)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            context: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Pin::new(&mut self.0).poll_shutdown(context)
        }
    }

    impl TerminalInput for DuplexInput {
        fn close(&mut self) {}
    }

    struct PumpSession {
        events: VecDeque<PtyEvent>,
    }

    struct ResizeThenExitSession {
        resized: Option<TerminalSize>,
        exit_code: u32,
    }

    impl TerminalSession for PumpSession {
        type Input = TestInput;

        fn take_input(&mut self) -> Result<Self::Input, TerminalError> {
            Ok(TestInput)
        }

        async fn resize(&mut self, _size: TerminalSize) -> Result<(), TerminalError> {
            Ok(())
        }

        async fn next(&mut self) -> Result<PtyEvent, TerminalError> {
            self.events.pop_front().ok_or(TerminalError::TaskStopped)
        }

        async fn shutdown(self) -> Result<(), TerminalError> {
            Ok(())
        }
    }

    impl TerminalSession for ResizeThenExitSession {
        type Input = TestInput;

        fn take_input(&mut self) -> Result<Self::Input, TerminalError> {
            Ok(TestInput)
        }

        async fn resize(&mut self, size: TerminalSize) -> Result<(), TerminalError> {
            self.resized = Some(size);
            Ok(())
        }

        async fn next(&mut self) -> Result<PtyEvent, TerminalError> {
            if self.resized.is_some() {
                Ok(PtyEvent::exited(self.exit_code))
            } else {
                std::future::pending().await
            }
        }

        async fn shutdown(self) -> Result<(), TerminalError> {
            Ok(())
        }
    }

    impl AsyncWrite for TestInput {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            Poll::Ready(Ok(bytes.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl TerminalInput for TestInput {
        fn close(&mut self) {}
    }

    impl TerminalSession for TestSession {
        type Input = TestInput;

        fn take_input(&mut self) -> Result<Self::Input, TerminalError> {
            Ok(TestInput)
        }

        async fn resize(&mut self, _size: TerminalSize) -> Result<(), TerminalError> {
            Ok(())
        }

        fn next(&mut self) -> impl Future<Output = Result<PtyEvent, TerminalError>> + Send {
            std::future::pending()
        }

        async fn shutdown(self) -> Result<(), TerminalError> {
            self.shutdowns.fetch_add(1, Ordering::Relaxed);
            if self.fail_shutdown {
                Err(TerminalError::CleanupTimeout)
            } else {
                Ok(())
            }
        }
    }

    fn patterned_bytes(length: usize, seed: usize) -> Vec<u8> {
        (0..length)
            .map(|index| ((index + seed) % 251) as u8)
            .collect()
    }
}

/// Host-side failures, all of which preserve the one-use state machine semantics.
#[derive(Debug, Error)]
pub enum HostError {
    #[error(transparent)]
    Endpoint(#[from] EndpointError),
    #[error(transparent)]
    Relay(#[from] RelayProtocolError),
    #[error("failed to register an endpoint application protocol")]
    Application(#[from] ApplicationStreamError),
    #[error("secure random generation failed")]
    Random(#[from] RandomError),
    #[error("OPAQUE authentication failed")]
    Pake(#[from] OpaquePakeError),
    #[error("an endpoint identity could not be represented on the wire")]
    PeerIdentity,
    #[error("an authentication or terminal exchange timed out")]
    Timeout,
    #[error("endpoint protocol I/O failed")]
    Io(#[from] std::io::Error),
    #[error("an endpoint sent an invalid protocol message")]
    Protocol(#[from] ProtocolError),
    #[error("the target session state transition was rejected")]
    Session(#[from] TransitionError),
    #[error(transparent)]
    Terminal(#[from] TerminalError),
    #[error("the controller connection was lost")]
    ConnectionLost,
    #[error("a required inbound application protocol registration ended")]
    ProtocolRegistrationEnded,
    #[error("the host was interrupted")]
    Interrupted,
    #[error("failed to report the connection code")]
    Output(#[source] std::io::Error),
}

/// Runs one advertised code through at most one committed terminal session.
pub async fn run_host(config: HostConfig) -> Result<u32, HostError> {
    let mut progress = NoopProgress;
    run_host_session(config, PortablePtyBackend, &mut progress).await
}

/// Runs one host session while reporting bounded, non-secret lifecycle milestones.
pub async fn run_host_with_progress(
    config: HostConfig,
    progress: &mut impl OperationProgress<HostStage>,
) -> Result<u32, HostError> {
    run_host_session(config, PortablePtyBackend, progress).await
}

/// Runs the host state machine with a statically dispatched terminal backend.
pub async fn run_host_with<B: TerminalBackend>(
    config: HostConfig,
    backend: B,
) -> Result<u32, HostError> {
    let mut progress = NoopProgress;
    run_host_session(config, backend, &mut progress).await
}

async fn run_host_session<B: TerminalBackend>(
    config: HostConfig,
    backend: B,
    progress: &mut impl OperationProgress<HostStage>,
) -> Result<u32, HostError> {
    let HostConfig {
        identity,
        relays,
        wss,
    } = config;
    let (mut driver, mut streams) = build_endpoint(identity, wss)?;
    let mut auth_incoming = streams.accept(AUTH_PROTOCOL)?;
    let mut data_incoming = streams.accept(TERMINAL_DATA_PROTOCOL)?;
    let mut control_incoming = streams.accept(TERMINAL_CONTROL_PROTOCOL)?;
    let target = peer_id_bytes(driver.peer_id()).map_err(|_| HostError::PeerIdentity)?;
    let mut pake = OpaquePake;
    let (relay_lease, advertised) = initialize_host_relay(
        &mut driver,
        &mut streams,
        &relays,
        &target,
        &mut pake,
        progress,
    )
    .await?;

    let mut session = HostSession {
        driver: &mut driver,
        streams: &mut streams,
        auth_incoming: &mut auth_incoming,
        data_incoming: &mut data_incoming,
        control_incoming: &mut control_incoming,
        relays: &relays,
        relay_lease,
        advertised,
        target,
        pake: &mut pake,
        backend: &backend,
    };
    let result = session.run(progress).await;
    let relay = session.relay_lease.relay().peer();
    let locator = session.advertised.locator;
    let listener = session.relay_lease.listener();
    if let Err(error) = release_locator(session.driver, session.streams, relay, locator).await {
        tracing::debug!(%error, "host locator cleanup was not acknowledged");
    }
    session.driver.remove_reservation(listener);
    result
}

struct AdvertisedLease {
    locator: yonder_core::Locator,
    registration: OpaqueRegistration,
}

async fn establish_host_relay(
    driver: &mut EndpointDriver,
    relays: &EndpointRelaySet,
    backoff: &mut impl Iterator<Item = Duration>,
    stage: HostStage,
    progress: &mut impl OperationProgress<HostStage>,
) -> Result<ReservationLease, HostError> {
    loop {
        let relay = tokio::select! {
            result = wait_with_progress(
                progress,
                stage,
                connect_configured_relay(driver, relays),
            ) => match result {
                Ok(relay) => relay,
                Err(error) => {
                    tracing::debug!(%error, "host relay connection attempt failed");
                    wait_for_host_retry(backoff, stage, progress).await?;
                    continue;
                }
            },
            signal = crate::shutdown::endpoint_shutdown_signal() => {
                signal?;
                return Err(HostError::Interrupted);
            }
        };
        let listener = match driver.reserve(relay.address()) {
            Ok(listener) => listener,
            Err(error) => {
                tracing::debug!(%error, "host relay reservation listener failed");
                wait_for_host_retry(backoff, stage, progress).await?;
                continue;
            }
        };
        let reservation = tokio::select! {
            result = wait_with_progress(
                progress,
                HostStage::ReservingRelay,
                wait_for_reservation(driver, relay, listener),
            ) => result,
            signal = crate::shutdown::endpoint_shutdown_signal() => {
                signal?;
                driver.remove_reservation(listener);
                return Err(HostError::Interrupted);
            }
        };
        match reservation {
            Ok(reservation) => return Ok(reservation),
            Err(error) => {
                driver.remove_reservation(listener);
                tracing::debug!(%error, "host relay reservation attempt failed");
                wait_for_host_retry(backoff, stage, progress).await?;
            }
        }
    }
}

async fn initialize_host_relay(
    driver: &mut EndpointDriver,
    streams: &mut Libp2pApplicationStreams,
    relays: &EndpointRelaySet,
    target: &PeerIdBytes,
    pake: &mut OpaquePake,
    progress: &mut impl OperationProgress<HostStage>,
) -> Result<(ReservationLease, AdvertisedLease), HostError> {
    let mut backoff = relay_backoff();
    loop {
        let candidate = establish_host_relay(
            driver,
            relays,
            &mut backoff,
            HostStage::ConnectingRelay,
            progress,
        )
        .await?;
        let allocation = tokio::select! {
            result = allocate_advertisement(
                driver,
                streams,
                candidate.relay(),
                target,
                pake,
                progress,
                AdvertisementNotice::Initial,
            ) => Some(result),
            signal = crate::shutdown::endpoint_shutdown_signal() => {
                signal?;
                None
            }
        };
        let Some(allocation) = allocation else {
            driver.remove_reservation(candidate.listener());
            return Err(HostError::Interrupted);
        };
        match allocation {
            Ok(advertised) => return Ok((candidate, advertised)),
            Err(HostError::Relay(error)) if retryable_relay_error(&error) => {
                tracing::debug!(%error, "initial locator allocation will be retried after reconnect");
                driver.remove_reservation(candidate.listener());
                wait_for_host_retry(&mut backoff, HostStage::ConnectingRelay, progress).await?;
            }
            Err(error) => {
                driver.remove_reservation(candidate.listener());
                return Err(error);
            }
        }
    }
}

async fn wait_for_host_retry(
    backoff: &mut impl Iterator<Item = Duration>,
    stage: HostStage,
    progress: &mut impl OperationProgress<HostStage>,
) -> Result<(), HostError> {
    let delay = backoff
        .next()
        .expect("the frozen host relay backoff is unbounded");
    tokio::select! {
        () = wait_with_progress(progress, stage, tokio::time::sleep(delay)) => Ok(()),
        signal = crate::shutdown::endpoint_shutdown_signal() => {
            signal?;
            Err(HostError::Interrupted)
        }
    }
}

async fn allocate_advertisement(
    driver: &mut EndpointDriver,
    streams: &mut Libp2pApplicationStreams,
    relay: &RelayConnection,
    target: &PeerIdBytes,
    pake: &mut OpaquePake,
    progress: &mut impl OperationProgress<HostStage>,
    notice: AdvertisementNotice,
) -> Result<AdvertisedLease, HostError> {
    let locator = wait_with_progress(
        progress,
        HostStage::RegisteringHost,
        allocate_locator(driver, streams, relay),
    )
    .await?;
    let created = create_advertisement(locator, target, pake);
    let (advertised, code) = match created {
        Ok(created) => created,
        Err(error) => {
            release_failed_advertisement(driver, streams, relay, locator).await;
            return Err(error);
        }
    };
    progress.clear();
    if notice == AdvertisementNotice::Replacement
        && let Err(error) = report_replacement_notice()
    {
        tracing::debug!(%error, "replacement connection-code notice could not be displayed");
    }
    if let Err(error) = report_connection_code(&code) {
        release_failed_advertisement(driver, streams, relay, locator).await;
        return Err(HostError::Output(error));
    }
    drop(code);
    Ok(advertised)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdvertisementNotice {
    Initial,
    Replacement,
}

fn create_advertisement(
    locator: yonder_core::Locator,
    target: &PeerIdBytes,
    pake: &mut OpaquePake,
) -> Result<(AdvertisedLease, ConnectionCode), HostError> {
    let code = ConnectionCode::generate(locator, &mut OsSecureRandom)?;
    let registration = pake.register(target, code.secret())?;
    Ok((
        AdvertisedLease {
            locator,
            registration,
        },
        code,
    ))
}

async fn release_failed_advertisement(
    driver: &mut EndpointDriver,
    streams: &mut Libp2pApplicationStreams,
    relay: &RelayConnection,
    locator: yonder_core::Locator,
) {
    if let Err(error) =
        release_locator_bound(driver, streams, relay.binding(), relay.peer(), locator).await
    {
        tracing::debug!(%error, "failed advertisement cleanup was not acknowledged");
    }
}

fn report_connection_code(code: &ConnectionCode) -> std::io::Result<()> {
    let stdout = std::io::stdout();
    report_connection_code_to(&mut stdout.lock(), code)
}

fn report_replacement_notice() -> std::io::Result<()> {
    let stderr = std::io::stderr();
    report_replacement_notice_to(&mut stderr.lock())
}

fn report_replacement_notice_to(output: &mut impl std::io::Write) -> std::io::Result<()> {
    writeln!(
        output,
        "Connection code changed; the previous code is no longer valid."
    )?;
    output.flush()
}

fn report_connection_code_to(
    output: &mut impl std::io::Write,
    code: &ConnectionCode,
) -> std::io::Result<()> {
    writeln!(output, "Connection code: {}", code.expose())?;
    output.flush()
}

struct RelayRecovery<'a> {
    driver: &'a mut EndpointDriver,
    streams: &'a mut Libp2pApplicationStreams,
    relays: &'a EndpointRelaySet,
    relay_lease: &'a mut ReservationLease,
    advertised: &'a mut AdvertisedLease,
    target: &'a PeerIdBytes,
    pake: &'a mut OpaquePake,
}

impl RelayRecovery<'_> {
    async fn run(
        &mut self,
        progress: &mut impl OperationProgress<HostStage>,
    ) -> Result<(), HostError> {
        self.driver.remove_reservation(self.relay_lease.listener());
        let mut backoff = relay_backoff();
        loop {
            let candidate = establish_host_relay(
                self.driver,
                self.relays,
                &mut backoff,
                HostStage::ReconnectingRelay,
                progress,
            )
            .await?;
            let reclaim = tokio::select! {
                result = wait_with_progress(
                    progress,
                    HostStage::ReconnectingRelay,
                    reclaim_locator(
                        self.driver,
                        self.streams,
                        candidate.relay(),
                        self.advertised.locator,
                    ),
                ) => Some(result),
                signal = crate::shutdown::endpoint_shutdown_signal() => {
                    signal?;
                    None
                }
            };
            let Some(reclaim) = reclaim else {
                self.driver.remove_reservation(candidate.listener());
                return Err(HostError::Interrupted);
            };
            match reclaim {
                Ok(ReclaimResponse::Reclaimed) => {
                    tracing::debug!("host relay locator was reclaimed");
                    *self.relay_lease = candidate;
                    return Ok(());
                }
                Ok(ReclaimResponse::Conflict) => {
                    tracing::debug!("host relay locator reclaim conflicted");
                    let allocation = tokio::select! {
                        result = allocate_advertisement(
                            self.driver,
                            self.streams,
                            candidate.relay(),
                            self.target,
                            self.pake,
                            progress,
                            AdvertisementNotice::Replacement,
                        ) => Some(result),
                        signal = crate::shutdown::endpoint_shutdown_signal() => {
                            signal?;
                            None
                        }
                    };
                    let Some(allocation) = allocation else {
                        self.driver.remove_reservation(candidate.listener());
                        return Err(HostError::Interrupted);
                    };
                    match allocation {
                        Ok(replacement) => {
                            tracing::debug!("host replacement locator was allocated");
                            *self.advertised = replacement;
                            *self.relay_lease = candidate;
                            return Ok(());
                        }
                        Err(HostError::Relay(error)) if retryable_relay_error(&error) => {
                            tracing::debug!(%error, "replacement locator allocation will be retried");
                        }
                        Err(error) => {
                            self.driver.remove_reservation(candidate.listener());
                            return Err(error);
                        }
                    }
                }
                Err(error) if retryable_relay_error(&error) => {
                    tracing::debug!(%error, "host locator reclaim will be retried after reconnect");
                }
                Err(error) => {
                    self.driver.remove_reservation(candidate.listener());
                    return Err(error.into());
                }
            }
            self.driver.remove_reservation(candidate.listener());
            wait_for_host_retry(&mut backoff, HostStage::ReconnectingRelay, progress).await?;
        }
    }
}

fn retryable_relay_error(error: &RelayProtocolError) -> bool {
    matches!(
        error,
        RelayProtocolError::Endpoint(_)
            | RelayProtocolError::Timeout
            | RelayProtocolError::Io(_)
            | RelayProtocolError::Capacity
            | RelayProtocolError::ReservationRequired
            | RelayProtocolError::RetryExhausted
    )
}

struct HostSession<'a, B> {
    driver: &'a mut EndpointDriver,
    streams: &'a mut Libp2pApplicationStreams,
    auth_incoming: &'a mut IncomingApplicationStreams,
    data_incoming: &'a mut IncomingApplicationStreams,
    control_incoming: &'a mut IncomingApplicationStreams,
    relays: &'a EndpointRelaySet,
    relay_lease: ReservationLease,
    advertised: AdvertisedLease,
    target: PeerIdBytes,
    pake: &'a mut OpaquePake,
    backend: &'a B,
}

struct InboundProtocols<'a> {
    auth: &'a mut IncomingApplicationStreams,
    data: &'a mut IncomingApplicationStreams,
    control: &'a mut IncomingApplicationStreams,
}

impl<B: TerminalBackend> HostSession<'_, B> {
    async fn run(
        &mut self,
        progress: &mut impl OperationProgress<HostStage>,
    ) -> Result<u32, HostError> {
        let Self {
            driver,
            streams,
            auth_incoming,
            data_incoming,
            control_incoming,
            relays,
            relay_lease,
            advertised,
            target,
            pake,
            backend,
        } = self;
        let limiter = DirectRateLimiter::new(RateLimit::authentication());
        let mut session = TargetSession::new();
        let mut incoming = InboundProtocols {
            auth: auth_incoming,
            data: data_incoming,
            control: control_incoming,
        };
        loop {
            progress.update(HostStage::WaitingForController);
            if !relay_lease.is_usable(driver) {
                tracing::debug!("host relay lease became unusable");
                RelayRecovery {
                    driver,
                    streams,
                    relays,
                    relay_lease,
                    advertised,
                    target,
                    pake,
                }
                .run(progress)
                .await?;
                progress.update(HostStage::WaitingForController);
            }
            let (controller, mut auth_stream) =
                match wait_for_auth(driver, &mut incoming, relay_lease).await? {
                    Some(incoming) => incoming,
                    None => continue,
                };
            progress.update(HostStage::AuthenticatingController);
            let binding =
                match wait_for_controller_quiescence(driver, &mut incoming, controller).await {
                    Ok(binding) => binding,
                    Err(error) => {
                        tracing::debug!(%error, "controller direct upgrade had not converged");
                        drop(auth_stream);
                        continue;
                    }
                };
            let hello = drive_session_inputs(
                driver,
                binding,
                &mut incoming,
                read_auth_hello(&mut auth_stream),
            )
            .await;
            let hello = match hello {
                Ok(Ok(hello)) => hello,
                Ok(Err(error)) => {
                    tracing::debug!(%error, "malformed controller authentication start was rejected");
                    continue;
                }
                Err(HostError::Endpoint(error)) => {
                    settle_binding_change(driver, binding, &error).await?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if !limiter.check() {
                let retry = drive_session_inputs(
                    driver,
                    binding,
                    &mut incoming,
                    send_auth_retry(auth_stream),
                )
                .await;
                match retry {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::debug!(%error, "authentication retry response failed");
                    }
                    Err(HostError::Endpoint(error)) => {
                        settle_binding_change(driver, binding, &error).await?;
                    }
                    Err(error) => return Err(error),
                }
                continue;
            }
            session.apply(SessionEvent::BeginAuthentication)?;
            let authenticated = drive_session_inputs(
                driver,
                binding,
                &mut incoming,
                authenticate(
                    &mut auth_stream,
                    hello,
                    advertised.locator,
                    target,
                    controller,
                    &advertised.registration,
                    pake,
                ),
            )
            .await;
            match authenticated {
                Ok(Ok(())) => progress.update(HostStage::StartingTerminal),
                Ok(Err(error)) => {
                    session.apply(SessionEvent::AuthenticationFailed)?;
                    tracing::debug!(%error, "controller authentication was rejected");
                    continue;
                }
                Err(error) => {
                    let HostError::Endpoint(endpoint) = error else {
                        return Err(error);
                    };
                    session.apply(binding_event(&endpoint))?;
                    tracing::debug!(%endpoint, "controller connection changed during authentication");
                    settle_binding_change(driver, binding, &endpoint).await?;
                    continue;
                }
            }
            session.apply(SessionEvent::AuthenticationSucceeded)?;

            let terminal_streams = acknowledge_and_wait_for_terminal_streams(
                driver,
                binding,
                &mut incoming,
                controller,
                auth_stream,
            )
            .await;
            let (data, control) = match terminal_streams {
                Ok(streams) => streams,
                Err(HostError::Endpoint(error)) => {
                    session.apply(binding_event(&error))?;
                    tracing::debug!(%error, "controller connection changed before terminal startup");
                    settle_binding_change(driver, binding, &error).await?;
                    continue;
                }
                Err(error) => {
                    session.apply(SessionEvent::ConnectionLost)?;
                    tracing::debug!(%error, "authenticated controller did not establish terminal streams");
                    continue;
                }
            };
            session.apply(SessionEvent::TerminalStreamsReady)?;

            let result = drive_session_inputs(
                driver,
                binding,
                &mut incoming,
                start_terminal(*backend, data, control),
            )
            .await;
            let (mut pty, data, control) = match result {
                Ok(Ok(result)) => result,
                Ok(Err(error)) => {
                    session.apply(host_error_event(&error, SessionEvent::TerminalStartFailed))?;
                    tracing::debug!(%error, "controller terminal startup failed");
                    if let HostError::Endpoint(endpoint) = &error {
                        settle_binding_change(driver, binding, endpoint).await?;
                    }
                    continue;
                }
                Err(error) => {
                    session.apply(host_error_event(&error, SessionEvent::TerminalStartFailed))?;
                    if let HostError::Endpoint(endpoint) = &error {
                        settle_binding_change(driver, binding, endpoint).await?;
                        continue;
                    }
                    return Err(error);
                }
            };
            session.apply(SessionEvent::TerminalReadyFlushed)?;
            progress.update(HostStage::TerminalActive);
            if let Err(error) = release_locator_bound(
                driver,
                streams,
                binding,
                relay_lease.relay().peer(),
                advertised.locator,
            )
            .await
            {
                tracing::warn!(%error, "one-use locator release was not acknowledged after commit");
            }

            let outcome =
                bridge_terminal(driver, binding, &mut incoming, &mut pty, data, control).await;
            let shutdown = pty.shutdown().await;
            match outcome {
                Ok(code) => {
                    session.apply(SessionEvent::ShellExited)?;
                    shutdown?;
                    return Ok(code);
                }
                Err(error) => {
                    session.apply(host_error_event(&error, SessionEvent::ConnectionLost))?;
                    if let Err(cleanup) = shutdown {
                        tracing::warn!(%cleanup, "terminal cleanup failed after the root session error");
                    }
                    return Err(error);
                }
            }
        }
    }
}

async fn wait_for_controller_quiescence(
    driver: &mut EndpointDriver,
    incoming: &mut InboundProtocols<'_>,
    controller: PeerId,
) -> Result<ConnectionBinding, HostError> {
    let deadline = tokio::time::Instant::now() + PRE_AUTH_QUIESCENCE_TIMEOUT;
    loop {
        if driver.direct_upgrade_ready(&controller) && driver.has_unique_connection(&controller) {
            return driver.bind(controller).map_err(HostError::from);
        }
        tokio::select! {
            biased;
            _ = driver.next() => {}
            stream = incoming.auth.next() => {
                drop(stream.ok_or(HostError::ProtocolRegistrationEnded)?);
            }
            stream = incoming.data.next() => {
                drop(stream.ok_or(HostError::ProtocolRegistrationEnded)?);
            }
            stream = incoming.control.next() => {
                drop(stream.ok_or(HostError::ProtocolRegistrationEnded)?);
            }
            () = tokio::time::sleep_until(deadline) => {
                driver.close_peer_and_wait(controller).await?;
                return Err(EndpointError::TargetUpgradeDidNotSettle.into());
            }
            signal = crate::shutdown::endpoint_shutdown_signal() => {
                signal?;
                return Err(HostError::Interrupted);
            }
        }
    }
}

async fn wait_for_auth(
    driver: &mut EndpointDriver,
    incoming: &mut InboundProtocols<'_>,
    relay: &ReservationLease,
) -> Result<Option<(PeerId, ApplicationStream)>, HostError> {
    loop {
        if !relay.is_usable(driver) {
            return Ok(None);
        }
        if driver.connection_count(&relay.relay().peer()) > 1
            && let Err(error) = reconverge_relay(driver, relay.relay()).await
        {
            tracing::debug!(%error, "relay connection roster did not reconverge before authentication");
            return Ok(None);
        }
        tokio::select! {
            biased;
            _ = driver.next() => {}
            stream = incoming.auth.next() => {
                let (peer, stream) = stream.ok_or(HostError::ProtocolRegistrationEnded)?;
                return Ok(Some((peer, stream)));
            }
            stream = incoming.data.next() => drop(stream.ok_or(HostError::ProtocolRegistrationEnded)?),
            stream = incoming.control.next() => drop(stream.ok_or(HostError::ProtocolRegistrationEnded)?),
            signal = crate::shutdown::endpoint_shutdown_signal() => {
                signal?;
                return Err(HostError::Interrupted);
            }
        }
    }
}

async fn drive_session_inputs<F: Future>(
    driver: &mut EndpointDriver,
    binding: ConnectionBinding,
    incoming: &mut InboundProtocols<'_>,
    future: F,
) -> Result<F::Output, HostError> {
    tokio::pin!(future);
    loop {
        tokio::select! {
            biased;
            event = driver.next() => match event {
                EndpointEvent::Established { peer, .. } | EndpointEvent::Closed { peer, .. }
                    if peer == binding.peer() => driver.enforce_binding(binding)?,
                _ => {}
            },
            stream = incoming.auth.next() => {
                let (peer, stream) = stream.ok_or(HostError::ProtocolRegistrationEnded)?;
                reject_extra_auth(driver, binding, peer, stream).await?;
            }
            stream = incoming.data.next() => {
                drop(stream.ok_or(HostError::ProtocolRegistrationEnded)?);
            }
            stream = incoming.control.next() => {
                drop(stream.ok_or(HostError::ProtocolRegistrationEnded)?);
            }
            output = &mut future => {
                driver.enforce_binding(binding)?;
                return Ok(output);
            }
            signal = crate::shutdown::endpoint_shutdown_signal() => {
                signal?;
                return Err(HostError::Interrupted);
            }
        }
    }
}

async fn reject_extra_auth(
    driver: &mut EndpointDriver,
    binding: ConnectionBinding,
    peer: PeerId,
    stream: ApplicationStream,
) -> Result<(), HostError> {
    if !driver.has_unique_connection(&peer) {
        return Ok(());
    }
    match tokio::time::timeout(
        EXCHANGE_TIMEOUT,
        drive_bound(driver, binding, send_auth_retry(stream)),
    )
    .await
    {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(error))) => {
            tracing::debug!(%peer, %error, "extra authentication Retry response failed");
            Ok(())
        }
        Ok(Err(error)) => Err(error.into()),
        Err(_) => {
            tracing::debug!(%peer, "extra authentication Retry response timed out");
            Ok(())
        }
    }
}

async fn read_auth_hello(stream: &mut ApplicationStream) -> Result<AuthClientHello, HostError> {
    let mut stream = stream.compat();
    read_auth_hello_io(&mut stream, EXCHANGE_TIMEOUT).await
}

async fn read_auth_hello_io(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
    timeout: Duration,
) -> Result<AuthClientHello, HostError> {
    let mut hello = [0_u8; CLIENT_HELLO_LEN];
    tokio::time::timeout(timeout, stream.read_exact(&mut hello))
        .await
        .map_err(|_| HostError::Timeout)??;
    AuthClientHello::decode(&hello).map_err(HostError::from)
}

async fn send_auth_retry(stream: ApplicationStream) -> Result<(), HostError> {
    let mut stream = stream.into_tokio();
    send_auth_retry_io(&mut stream).await
}

async fn send_auth_retry_io(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> Result<(), HostError> {
    let retry = AuthServerResponse::retry(
        yonder_core::RetryAfter::from_millis(1_000).expect("frozen retry is valid"),
    )
    .encode();
    stream.write_all(retry.as_slice()).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn authenticate(
    stream: &mut ApplicationStream,
    hello: AuthClientHello,
    locator: yonder_core::Locator,
    target: &PeerIdBytes,
    controller: PeerId,
    registration: &OpaqueRegistration,
    pake: &mut OpaquePake,
) -> Result<(), HostError> {
    tokio::time::timeout(EXCHANGE_TIMEOUT, async move {
        let mut stream = stream.compat();
        let controller = peer_id_bytes(controller).map_err(|_| HostError::PeerIdentity)?;
        let mut target_nonce = [0_u8; 32];
        OsSecureRandom.try_fill(&mut target_nonce)?;
        let context = PakeContext::new(locator, &controller, target, hello.nonce(), &target_nonce);
        let (state, ke2) = pake.server_start(registration, hello.ke1(), context.as_bytes())?;
        let response = AuthServerResponse::proceed(target_nonce, ke2).encode();
        stream.write_all(response.as_slice()).await?;
        stream.flush().await?;

        let mut finish = [0_u8; KE3_LEN];
        stream.read_exact(&mut finish).await?;
        let finish = AuthClientFinish::decode(&finish)?;
        let session_key = pake.server_finish(state, finish.ke3())?;
        drop(session_key);
        Ok(())
    })
    .await
    .map_err(|_| HostError::Timeout)?
}

async fn acknowledge_and_wait_for_terminal_streams(
    driver: &mut EndpointDriver,
    binding: ConnectionBinding,
    incoming: &mut InboundProtocols<'_>,
    controller: PeerId,
    mut auth_stream: ApplicationStream,
) -> Result<(ApplicationStream, ApplicationStream), HostError> {
    let acknowledgement_deadline = tokio::time::Instant::now() + EXCHANGE_TIMEOUT;
    let mut terminal_deadline = None;
    let mut acknowledgement = Box::pin(write_authenticated(&mut auth_stream));
    let mut pending = PendingPair::new();
    loop {
        let deadline = terminal_deadline.unwrap_or(acknowledgement_deadline);
        tokio::select! {
            biased;
            event = driver.next() => match event {
                EndpointEvent::Established { peer, .. } | EndpointEvent::Closed { peer, .. }
                    if peer == binding.peer() => driver.enforce_binding(binding)?,
                _ => {}
            },
            stream = incoming.auth.next() => {
                let (peer, stream) = stream.ok_or(HostError::ProtocolRegistrationEnded)?;
                reject_extra_auth(driver, binding, peer, stream).await?;
            }
            stream = incoming.data.next() => {
                let (peer, stream) = stream.ok_or(HostError::ProtocolRegistrationEnded)?;
                if peer == controller && pending.needs_data() {
                    pending.insert_data(stream);
                }
            }
            stream = incoming.control.next() => {
                let (peer, stream) = stream.ok_or(HostError::ProtocolRegistrationEnded)?;
                if peer == controller && pending.needs_control() {
                    pending.insert_control(stream);
                }
            }
            result = &mut acknowledgement, if terminal_deadline.is_none() => {
                result?;
                terminal_deadline = Some(tokio::time::Instant::now() + EXCHANGE_TIMEOUT);
            }
            () = tokio::time::sleep_until(deadline) => return Err(HostError::Timeout),
            signal = crate::shutdown::endpoint_shutdown_signal() => {
                signal?;
                return Err(HostError::Interrupted);
            }
        }
        if terminal_deadline.is_some()
            && let Some(streams) = pending.take_complete()
        {
            drop(acknowledgement);
            drop(auth_stream);
            return Ok(streams);
        }
    }
}

async fn write_authenticated(stream: &mut ApplicationStream) -> Result<(), HostError> {
    let mut stream = stream.compat();
    write_authenticated_io(&mut stream).await
}

async fn write_authenticated_io(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> Result<(), HostError> {
    stream.write_all(&Authenticated::ENCODED).await?;
    stream.flush().await?;
    Ok(())
}

struct PendingPair<D, C> {
    data: Option<D>,
    control: Option<C>,
}

impl<D, C> PendingPair<D, C> {
    const fn new() -> Self {
        Self {
            data: None,
            control: None,
        }
    }

    const fn needs_data(&self) -> bool {
        self.data.is_none()
    }

    const fn needs_control(&self) -> bool {
        self.control.is_none()
    }

    fn insert_data(&mut self, data: D) {
        if self.data.is_none() {
            self.data = Some(data);
        }
    }

    fn insert_control(&mut self, control: C) {
        if self.control.is_none() {
            self.control = Some(control);
        }
    }

    fn take_complete(&mut self) -> Option<(D, C)> {
        if self.needs_data() || self.needs_control() {
            return None;
        }
        Some((
            self.data.take().expect("data presence was checked"),
            self.control.take().expect("control presence was checked"),
        ))
    }
}

async fn start_terminal<B: TerminalBackend>(
    backend: &B,
    mut data: ApplicationStream,
    mut control: ApplicationStream,
) -> Result<(B::Session, ApplicationStream, ApplicationStream), HostError> {
    let pty = {
        let mut data_io = (&mut data).compat();
        let mut control_io = (&mut control).compat();
        start_terminal_io(backend, &mut data_io, &mut control_io).await?
    };
    Ok((pty, data, control))
}

async fn start_terminal_io<B, D, C>(
    backend: &B,
    data: &mut D,
    control: &mut C,
) -> Result<B::Session, HostError>
where
    B: TerminalBackend,
    D: tokio::io::AsyncWrite + Unpin,
    C: tokio::io::AsyncRead + Unpin,
{
    let hello = tokio::time::timeout(EXCHANGE_TIMEOUT, read_terminal_hello_io(control))
        .await
        .map_err(|_| HostError::Timeout)??;
    let pty = backend.open(hello).await?;
    if let Err(error) = write_terminal_ready_io(data).await {
        if let Err(cleanup) = pty.shutdown().await {
            tracing::warn!(%cleanup, "failed to clean up PTY after TerminalReady failure");
        }
        return Err(error);
    }
    Ok(pty)
}

async fn read_terminal_hello_io(
    stream: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<TerminalHello, HostError> {
    let mut bytes = [0_u8; MAX_HELLO_LEN];
    stream.read_exact(&mut bytes[..6]).await?;
    let term_end = 6 + usize::from(bytes[5]);
    if term_end >= MAX_HELLO_LEN {
        return Err(ProtocolError::InvalidLength {
            expected: MAX_HELLO_LEN,
            actual: term_end + 1,
        }
        .into());
    }
    stream.read_exact(&mut bytes[6..=term_end]).await?;
    let end = term_end + 1 + usize::from(bytes[term_end]);
    if end > MAX_HELLO_LEN {
        return Err(ProtocolError::InvalidLength {
            expected: MAX_HELLO_LEN,
            actual: end,
        }
        .into());
    }
    stream.read_exact(&mut bytes[term_end + 1..end]).await?;
    TerminalHello::decode(&bytes[..end]).map_err(HostError::from)
}

async fn write_terminal_ready_io(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> Result<(), HostError> {
    stream.write_all(&TerminalReady::ENCODED).await?;
    stream.flush().await?;
    Ok(())
}

async fn bridge_terminal<S: TerminalSession>(
    driver: &mut EndpointDriver,
    binding: ConnectionBinding,
    incoming: &mut InboundProtocols<'_>,
    pty: &mut S,
    data: ApplicationStream,
    control: ApplicationStream,
) -> Result<u32, HostError> {
    let (mut data_read, mut data_write) = tokio::io::split(data.into_tokio());
    let (mut control_read, mut control_write) = tokio::io::split(control.into_tokio());
    let mut pty_input = pty.take_input()?;
    let result = {
        let controller_input = copy_controller_input(&mut data_read, &mut pty_input);
        let terminal_output =
            copy_terminal_output(pty, &mut data_write, &mut control_read, &mut control_write);
        tokio::pin!(controller_input);
        tokio::pin!(terminal_output);
        loop {
            driver.enforce_binding(binding)?;
            tokio::select! {
            event = driver.next() => match event {
                EndpointEvent::Established { peer, .. } | EndpointEvent::Closed { peer, .. }
                    if peer == binding.peer() => driver.enforce_binding(binding)?,
                _ => {}
            },
            stream = incoming.auth.next() => {
                let (peer, stream) = stream.ok_or(HostError::ProtocolRegistrationEnded)?;
                reject_extra_auth(driver, binding, peer, stream).await?;
            }
            stream = incoming.data.next() => {
                drop(stream.ok_or(HostError::ProtocolRegistrationEnded)?);
            }
            stream = incoming.control.next() => {
                drop(stream.ok_or(HostError::ProtocolRegistrationEnded)?);
            }
            result = &mut controller_input => match result {
                Ok(never) => match never {},
                Err(error) => break Err(error),
            },
            result = &mut terminal_output => {
                break result;
            }
            signal = crate::shutdown::endpoint_shutdown_signal() => {
                signal?;
                break Err(HostError::Interrupted);
            }
            }
        }
    };
    drop(pty_input);
    result
}

async fn copy_controller_input(
    data_read: &mut (impl tokio::io::AsyncRead + Unpin),
    pty_input: &mut impl TerminalInput,
) -> Result<Infallible, HostError> {
    tokio::io::copy(data_read, pty_input).await?;
    pty_input.flush().await?;
    pty_input.close();
    std::future::pending().await
}

async fn copy_terminal_output<S: TerminalSession>(
    pty: &mut S,
    data_write: &mut (impl tokio::io::AsyncWrite + Unpin),
    control_read: &mut (impl tokio::io::AsyncRead + Unpin),
    control_write: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> Result<u32, HostError> {
    loop {
        let mut resize = [0_u8; 5];
        tokio::select! {
            read = control_read.read_exact(&mut resize) => {
                read?;
                let resize = TerminalResize::decode(&resize)?;
                pty.resize(resize.size()).await?;
                tokio::task::yield_now().await;
            }
            event = pty.next() => {
                let event = event?;
                match event.kind() {
                    PtyEventKind::Output => {
                        let output = event.into_output();
                        data_write.write_all(output.as_slice()).await?;
                        data_write.flush().await?;
                        tokio::task::yield_now().await;
                    }
                    PtyEventKind::Exited(code) => {
                        data_write.shutdown().await?;
                        control_write
                            .write_all(&TerminalExit::new(code).encode())
                            .await?;
                        control_write.shutdown().await?;
                        return Ok(code);
                    }
                }
            }
        }
    }
}

fn binding_event(error: &EndpointError) -> SessionEvent {
    if matches!(error, EndpointError::AdditionalBoundConnection) {
        SessionEvent::ExtraConnection
    } else {
        SessionEvent::ConnectionLost
    }
}

async fn settle_binding_change(
    driver: &mut EndpointDriver,
    binding: ConnectionBinding,
    error: &EndpointError,
) -> Result<(), HostError> {
    if matches!(error, EndpointError::AdditionalBoundConnection) {
        driver.close_peer_and_wait(binding.peer()).await?;
    }
    Ok(())
}

fn host_error_event(error: &HostError, fallback: SessionEvent) -> SessionEvent {
    match error {
        HostError::Endpoint(error) => binding_event(error),
        _ => fallback,
    }
}
