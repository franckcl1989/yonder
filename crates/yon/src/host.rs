use crate::audit::observer::{
    AUDIT_CHECKPOINT_POLL, AUDIT_ESTABLISH_TIMEOUT, AuditObserver, CloseNoticeHandling, FrameEvent,
};
use crate::audit::session::{AuditError, DIRECTION_CTRL_TO_HOST, DIRECTION_HOST_TO_CTRL};
use crate::file_semantics::BaseDirectory;
use crate::network::{
    ConnectionBinding, EndpointDriver, EndpointError, EndpointEvent, RelayAccessMode,
    RelayConnection, ReservationLease, build_endpoint, connect_configured_relay, drive_bound,
    reconverge_relay, relay_backoff, wait_for_reservation,
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
use crate::transfer::{TransferConfig, handle_download_from_open, handle_upload_from_open};
use sha2::{Digest as _, Sha256};
use std::convert::Infallible;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::mpsc;
use tokio_util::compat::FuturesAsyncReadCompatExt as _;
use yonder_core::wire::audit::{
    AUDIT_PROTOCOL, AuditCloseReason, AuditRole, Digest32, ManifestEnding,
};
use yonder_core::wire::auth::{
    AuthClientFinish, AuthClientHello, AuthServerResponse, Authenticated, CLIENT_HELLO_LEN,
    KE3_LEN, PakeContext,
};
use yonder_core::wire::file_transfer::{
    FRAME_HEADER_LEN, FileTransferErrorCode, FileTransferMessage, MAX_CONTROL_FRAME_LEN,
    TransferTag, decode_frame_header, validate_payload_len,
};
use yonder_core::wire::terminal::{
    MAX_HELLO_LEN, TerminalComplete, TerminalExit, TerminalHello, TerminalReady, TerminalResize,
};
use yonder_core::wire::{
    AUTH_PROTOCOL, FILE_TRANSFER_PROTOCOL, TERMINAL_CONTROL_PROTOCOL, TERMINAL_DATA_PROTOCOL,
};
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
const TERMINAL_COMPLETION_TIMEOUT: Duration = Duration::from_secs(2);

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
        EXCHANGE_TIMEOUT, FILE_SUBSTREAM_QUEUE, FileOpenError, FileOpenFrame, HostConfig,
        HostError, HostStage, OpaquePake, PRE_AUTH_QUIESCENCE_TIMEOUT, PendingPair, binding_event,
        classify_file_open_io, complete_terminal_exit_io, copy_controller_input,
        copy_terminal_output, create_advertisement, file_substream_coordinator, host_error_event,
        read_auth_hello_io, read_file_open_frame, read_terminal_hello_io,
        report_connection_code_to, report_replacement_notice_to, retryable_relay_error, run_host,
        run_host_with, run_host_with_progress, send_auth_retry_io, send_busy_reply,
        serve_one_file_substream, start_terminal_io, wait_for_audit_frame, wait_for_host_retry,
        write_authenticated_io, write_terminal_ready_io,
    };
    use crate::audit::observer::{
        AUDIT_CHECKPOINT_POLL, AuditObserver, CloseNoticeHandling, FrameEvent,
    };
    use crate::audit::session::{
        AuditError, DIRECTION_CTRL_TO_HOST, FILE_DIRECTION_DOWNLOAD, FILE_DIRECTION_UPLOAD,
        FILE_KIND_START, FILE_KIND_SUCCESS, FileTransferFacts, OUTCOME_FAILED,
    };
    use crate::audit::verify::{StreamAction, stream_frames};
    use crate::file_semantics::BaseDirectory;
    use crate::network::{EndpointError, RelayAccessMode, relay_backoff};
    use crate::progress::NoopProgress;
    use crate::protocol::RelayProtocolError;
    use crate::terminal::{
        PtyEvent, TerminalBackend, TerminalChunk, TerminalError, TerminalInput, TerminalSession,
    };
    use crate::transfer::TransferConfig;
    use sha2::{Digest, Sha256};
    use std::collections::VecDeque;
    use std::fs;
    use std::future::Future;
    use std::io::Write as _;
    use std::path::Path;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
    use tokio::sync::{Notify, mpsc};
    use yonder_core::wire::audit::{
        AUDIT_PROTOCOL, AuditCloseReason, AuditErrorCode, AuditMessage, AuditRole, Digest32,
        ManifestEnding,
    };
    use yonder_core::wire::audit_container::RecordType;
    use yonder_core::wire::auth::{
        AuthClientHello, AuthServerResponse, CLIENT_HELLO_LEN, PakeContext,
    };
    use yonder_core::wire::file_transfer::{
        FRAME_HEADER_LEN, FileTransferErrorCode, FileTransferMessage, Sha256Digest, TransferTag,
        decode_frame_header, encode_frame_header,
    };
    use yonder_core::wire::terminal::{
        MAX_HELLO_LEN, TerminalComplete, TerminalExit, TerminalHello, TerminalResize,
    };
    use yonder_core::{
        ConnectionCode, Locator, OsSecureRandom, Pake, PakeSecret, RetryAfter, SessionEvent,
        TerminalSize, TerminalValue,
    };
    use yonder_net::{
        EndpointRelayAddress, EndpointRelaySet, Keypair, NetworkBuildError, WssTransportConfig,
        peer_id_bytes,
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

    /// An async writer that accepts every write but fails every flush, so a
    /// code path whose write succeeded can still observe the flush failure.
    struct FlushFailingWriter;

    impl AsyncWrite for FlushFailingWriter {
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
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed output",
            )))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    struct FailingAsyncWriter;

    impl AsyncWrite for FailingAsyncWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _bytes: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed async output",
            )))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed async output",
            )))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl TerminalInput for FailingAsyncWriter {
        fn close(&mut self) {}
    }

    /// An async pty input that records how often it was flushed and closed.
    struct RecordingInput {
        flushes: Arc<AtomicUsize>,
        closes: Arc<AtomicUsize>,
    }

    impl AsyncWrite for RecordingInput {
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
            self.flushes.fetch_add(1, Ordering::Relaxed);
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl TerminalInput for RecordingInput {
        fn close(&mut self) {
            self.closes.fetch_add(1, Ordering::Relaxed);
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
    fn advertisement_creation_registers_the_printed_code_for_authentication() {
        let locator = Locator::new(12_345).unwrap();
        let target = peer_id_bytes(Keypair::generate_ed25519().public().to_peer_id()).unwrap();
        let mut host = OpaquePake;
        let (advertised, code) = create_advertisement(locator, &target, &mut host).unwrap();
        assert_eq!(advertised.locator, locator);
        assert_eq!(code.locator(), locator);

        // The user-facing code round-trips through its printed representation,
        // so the controller can look the advertisement up with exactly what
        // the host printed.
        let parsed: ConnectionCode = code.expose().to_string().parse().unwrap();
        assert_eq!(parsed.locator(), locator);
        assert_eq!(parsed.secret().expose_bytes(), code.secret().expose_bytes());

        // A client that knows the code completes the full PAKE exchange
        // against the registration the host created.
        let controller = peer_id_bytes(Keypair::generate_ed25519().public().to_peer_id()).unwrap();
        let context = PakeContext::new(locator, &controller, &target, &[9; 32], &[11; 32]);
        let mut client = OpaquePake;
        let (client_state, ke1) = client.client_start(&target, code.secret()).unwrap();
        let (server_state, ke2) = host
            .server_start(&advertised.registration, &ke1, context.as_bytes())
            .unwrap();
        let (ke3, client_key) = client
            .client_finish(client_state, &ke2, context.as_bytes())
            .unwrap();
        let server_key = host.server_finish(server_state, &ke3).unwrap();
        assert_eq!(client_key.as_ref(), server_key.as_ref());
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
    async fn host_retry_delay_waits_before_the_next_attempt() {
        let mut backoff = relay_backoff();
        let started = tokio::time::Instant::now();
        wait_for_host_retry(&mut backoff, HostStage::ConnectingRelay, &mut NoopProgress)
            .await
            .unwrap();
        // The frozen first backoff is 250 ms; jitter only extends it.
        assert!(
            started.elapsed() >= Duration::from_millis(250),
            "first retry delay was {:?}",
            started.elapsed()
        );
        // The retry schedule is unbounded, so every reconnect keeps a next
        // delay available (the invariant the production `expect` relies on).
        assert!(backoff.next().is_some());
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

    #[test]
    fn terminal_pumps_make_progress_under_bidirectional_backpressure() {
        // The combined pump, transfer and audit futures exceed the default
        // test-thread stack; the project pattern runs the scenario on a
        // 64 MiB stack thread.
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
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
                    let (mut host_control_read, mut host_control_write) =
                        tokio::io::split(host_control);
                    let (mut controller_control_read, mut controller_control_write) =
                        tokio::io::split(controller_control);
                    let (pty_input, mut captured_input) = tokio::io::duplex(31);
                    let mut pty_input = DuplexInput(pty_input);

                    let host = async {
                        let input =
                            copy_controller_input(&mut host_data_read, &mut pty_input, None);
                        let output = copy_terminal_output(
                            &mut session,
                            &mut host_data_write,
                            &mut host_control_read,
                            &mut host_control_write,
                            None,
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
                        controller_data_write.write_all(&controller_payload).await?;
                        controller_data_write.shutdown().await?;
                        let mut output = Vec::with_capacity(PAYLOAD_LEN);
                        controller_data_read.read_to_end(&mut output).await?;
                        let mut exit = [0_u8; 5];
                        controller_control_read.read_exact(&mut exit).await?;
                        controller_control_write
                            .write_all(&TerminalComplete::ENCODED)
                            .await?;
                        controller_control_write.flush().await?;
                        Ok::<_, std::io::Error>((output, TerminalExit::decode(&exit).unwrap()))
                    };
                    let capture = async {
                        let mut input = vec![0_u8; PAYLOAD_LEN];
                        captured_input.read_exact(&mut input).await?;
                        Ok::<_, std::io::Error>(input)
                    };

                    let (host, controller, captured) =
                        tokio::time::timeout(Duration::from_secs(5), async {
                            tokio::join!(host, controller, capture)
                        })
                        .await
                        .expect("full-duplex terminal pumps deadlocked");
                    assert_eq!(host.unwrap(), EXIT_CODE);
                    let (output, exit) = controller.unwrap();
                    assert_eq!(output, terminal_payload);
                    assert_eq!(exit.code(), EXIT_CODE);
                    assert_eq!(captured.unwrap(), controller_payload);
                });
            })
            .unwrap()
            .join()
            .unwrap();
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
        let digest = Digest32::new([0xCD; 32]);
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
    fn audit_failure_stops_further_input_from_reaching_the_pty() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let (_controller_audit, host_audit, _controller_dir, _host_dir) =
                        establish_audit_pair().await;
                    let pump_audit = Arc::clone(&host_audit);
                    let (host_half, controller_half) = tokio::io::duplex(64 * 1024);
                    let (mut host_data_read, _host_data_write) = tokio::io::split(host_half);
                    let (_controller_data_read, mut controller_data_write) =
                        tokio::io::split(controller_half);
                    let (pty_write, mut pty_read) = tokio::io::duplex(64 * 1024);

                    let pump = tokio::task::spawn(async move {
                        copy_controller_input(
                            &mut host_data_read,
                            &mut DuplexInput(pty_write),
                            Some(&pump_audit),
                        )
                        .await
                    });

                    let first = b"first-input-chunk";
                    controller_data_write.write_all(first).await.unwrap();
                    let mut captured = vec![0_u8; first.len()];
                    pty_read.read_exact(&mut captured).await.unwrap();
                    assert_eq!(captured, first);

                    host_audit
                        .fail_closed(None, AuditCloseReason::AuditFailure)
                        .await;
                    assert!(host_audit.has_failed().await);

                    controller_data_write
                        .write_all(b"second-input-chunk")
                        .await
                        .unwrap();
                    let result = tokio::time::timeout(Duration::from_secs(10), pump)
                        .await
                        .expect("the input pump must stop after audit failure")
                        .expect("the input pump must not panic");
                    assert!(matches!(result, Err(HostError::Audit(_))));
                    let mut trailing = Vec::new();
                    pty_read.read_to_end(&mut trailing).await.unwrap();
                    assert!(trailing.is_empty());
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn audited_terminal_effect_failures_record_failed_outcomes() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let (controller_audit, host_audit, controller_dir, host_dir) =
                        establish_audit_pair().await;

                    let (host_data, mut controller_data) = tokio::io::duplex(64);
                    let (mut host_data_read, _host_data_write) = tokio::io::split(host_data);
                    controller_data.write_all(b"input").await.unwrap();
                    controller_data.flush().await.unwrap();
                    assert!(matches!(
                        copy_controller_input(
                            &mut host_data_read,
                            &mut FailingAsyncWriter,
                            Some(&host_audit),
                        )
                        .await,
                        Err(HostError::Io(_))
                    ));

                    let mut chunk = TerminalChunk::new();
                    chunk.writable()[..6].copy_from_slice(b"output");
                    chunk.set_len(6).unwrap();
                    let mut session = PumpSession {
                        events: VecDeque::from([PtyEvent::output(chunk)]),
                    };
                    let (host_control, _controller_control) = tokio::io::duplex(8);
                    let (mut host_control_read, mut host_control_write) =
                        tokio::io::split(host_control);
                    assert!(matches!(
                        copy_terminal_output(
                            &mut session,
                            &mut FlushFailingWriter,
                            &mut host_control_read,
                            &mut host_control_write,
                            Some(&host_audit),
                        )
                        .await,
                        Err(HostError::Io(_))
                    ));

                    host_audit
                        .close_interrupted(AuditCloseReason::ConnectionLost)
                        .await;
                    drop(host_audit);
                    drop(controller_audit);

                    let record = fs::read_dir(host_dir.path().join("audit").join("records"))
                        .unwrap()
                        .next()
                        .unwrap()
                        .unwrap()
                        .path();
                    let mut failed_pty = false;
                    let mut failed_send = false;
                    stream_frames(&record, &mut |record_type, payload| {
                        let local = payload.get(40..).unwrap_or_default();
                        match record_type {
                            RecordType::LocalPtyWriteOutcome => {
                                failed_pty |= local.first() == Some(&OUTCOME_FAILED);
                            }
                            RecordType::LocalSendOutcome => {
                                failed_send |= local.get(1) == Some(&OUTCOME_FAILED);
                            }
                            _ => {}
                        }
                        Ok(StreamAction::Continue)
                    })
                    .unwrap();
                    assert!(failed_pty, "the failed PTY write must be recorded");
                    assert!(failed_send, "the failed substream flush must be recorded");
                    drop(controller_dir);
                });
            })
            .unwrap()
            .join()
            .unwrap();
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
            None,
        );
        let controller = async {
            let mut terminal_bytes = Vec::new();
            controller_data
                .read_to_end(&mut terminal_bytes)
                .await
                .unwrap();
            let mut exit = [0_u8; 5];
            controller_control_read.read_exact(&mut exit).await.unwrap();
            controller_control_write
                .write_all(&TerminalComplete::ENCODED)
                .await
                .unwrap();
            controller_control_write.flush().await.unwrap();
            let mut trailing = [0_u8; 1];
            assert_eq!(
                controller_control_read.read(&mut trailing).await.unwrap(),
                0
            );
            (terminal_bytes, TerminalExit::decode(&exit).unwrap())
        };
        let (exit, (terminal_bytes, remote_exit)) = tokio::join!(host, controller);

        assert_eq!(exit.unwrap(), EXIT_CODE);
        assert!(terminal_bytes.is_empty());
        assert_eq!(remote_exit.code(), EXIT_CODE);
        assert_eq!(session.resized, Some(resized));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_output_waits_for_controller_to_observe_completion() {
        const EXIT_CODE: u32 = 43;
        let mut session = PumpSession {
            events: VecDeque::from([PtyEvent::exited(EXIT_CODE)]),
        };
        let (host_data, mut controller_data) = tokio::io::duplex(8);
        let (_host_data_read, mut host_data_write) = tokio::io::split(host_data);
        let (host_control, controller_control) = tokio::io::duplex(8);
        let (mut host_control_read, mut host_control_write) = tokio::io::split(host_control);
        let (mut controller_control_read, mut controller_control_write) =
            tokio::io::split(controller_control);
        let controller_observed = Arc::new(AtomicBool::new(false));
        let controller_observed_in_task = Arc::clone(&controller_observed);

        let host = copy_terminal_output(
            &mut session,
            &mut host_data_write,
            &mut host_control_read,
            &mut host_control_write,
            None,
        );
        let controller = async {
            let mut terminal_bytes = Vec::new();
            controller_data
                .read_to_end(&mut terminal_bytes)
                .await
                .unwrap();
            let mut exit = [0_u8; 5];
            controller_control_read.read_exact(&mut exit).await.unwrap();
            controller_observed_in_task.store(true, Ordering::Relaxed);
            controller_control_write.shutdown().await.unwrap();
            (terminal_bytes, TerminalExit::decode(&exit).unwrap())
        };
        tokio::pin!(host);
        tokio::pin!(controller);

        let (host, terminal_bytes, remote_exit) = tokio::select! {
            biased;
            result = &mut host => {
                assert!(
                    controller_observed.load(Ordering::Relaxed),
                    "host completed before the controller observed terminal completion: {result:?}"
                );
                let (terminal_bytes, remote_exit) = controller.await;
                (result, terminal_bytes, remote_exit)
            }
            observed = &mut controller => {
                let host = host.await;
                (host, observed.0, observed.1)
            }
        };

        assert!(terminal_bytes.is_empty());
        assert_eq!(remote_exit.code(), EXIT_CODE);
        assert_eq!(host.unwrap(), EXIT_CODE);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_output_completion_ack_closes_the_host_control_half() {
        const EXIT_CODE: u32 = 47;
        let mut session = PumpSession {
            events: VecDeque::from([PtyEvent::exited(EXIT_CODE)]),
        };
        let (host_data, mut controller_data) = tokio::io::duplex(8);
        let (_host_data_read, mut host_data_write) = tokio::io::split(host_data);
        let (host_control, controller_control) = tokio::io::duplex(8);
        let (mut host_control_read, mut host_control_write) = tokio::io::split(host_control);
        let (mut controller_control_read, mut controller_control_write) =
            tokio::io::split(controller_control);

        let host = copy_terminal_output(
            &mut session,
            &mut host_data_write,
            &mut host_control_read,
            &mut host_control_write,
            None,
        );
        let controller = async {
            let mut terminal_bytes = Vec::new();
            controller_data
                .read_to_end(&mut terminal_bytes)
                .await
                .unwrap();
            let mut exit = [0_u8; 5];
            controller_control_read.read_exact(&mut exit).await.unwrap();
            controller_control_write
                .write_all(&TerminalComplete::ENCODED)
                .await
                .unwrap();
            controller_control_write.flush().await.unwrap();
            let mut trailing = [0_u8; 1];
            assert_eq!(
                controller_control_read.read(&mut trailing).await.unwrap(),
                0
            );
            (terminal_bytes, TerminalExit::decode(&exit).unwrap())
        };

        let (host, (terminal_bytes, remote_exit)) = tokio::join!(host, controller);
        assert_eq!(host.unwrap(), EXIT_CODE);
        assert!(terminal_bytes.is_empty());
        assert_eq!(remote_exit.code(), EXIT_CODE);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_completion_drains_a_queued_resize_before_acknowledgement() {
        let resized = TerminalSize::new(132, 43).unwrap();
        let (host_control, controller_control) = tokio::io::duplex(8);
        let (mut host_read, mut host_write) = tokio::io::split(host_control);
        let (mut controller_read, mut controller_write) = tokio::io::split(controller_control);
        let host = complete_terminal_exit_io(
            &mut host_read,
            &mut host_write,
            Duration::from_secs(1),
            None,
        );
        let controller = async {
            controller_write
                .write_all(&TerminalResize::new(resized).encode())
                .await
                .unwrap();
            controller_write
                .write_all(&TerminalComplete::ENCODED)
                .await
                .unwrap();
            controller_write.flush().await.unwrap();
            let mut trailing = [0_u8; 1];
            assert_eq!(controller_read.read(&mut trailing).await.unwrap(), 0);
        };

        let (result, ()) = tokio::join!(host, controller);
        result.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_completion_rejects_invalid_and_truncated_queued_resizes() {
        let (host_control, mut controller_control) = tokio::io::duplex(8);
        let (mut host_read, mut host_write) = tokio::io::split(host_control);
        controller_control
            .write_all(&[0xff, 0, 0, 0, 0])
            .await
            .unwrap();
        assert!(matches!(
            complete_terminal_exit_io(
                &mut host_read,
                &mut host_write,
                Duration::from_secs(1),
                None
            )
            .await,
            Err(HostError::Protocol(_))
        ));

        let (host_control, mut controller_control) = tokio::io::duplex(8);
        let (mut host_read, mut host_write) = tokio::io::split(host_control);
        controller_control.write_all(&[0x02, 0, 0]).await.unwrap();
        controller_control.shutdown().await.unwrap();
        assert!(matches!(
            complete_terminal_exit_io(
                &mut host_read,
                &mut host_write,
                Duration::from_secs(1),
                None
            )
            .await,
            Err(HostError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_completion_has_a_bounded_acknowledgement_wait() {
        let (host_control, _controller_control) = tokio::io::duplex(1);
        let (mut host_read, mut host_write) = tokio::io::split(host_control);

        assert!(matches!(
            complete_terminal_exit_io(
                &mut host_read,
                &mut host_write,
                Duration::from_millis(10),
                None
            )
            .await,
            Err(HostError::Timeout)
        ));
    }

    struct ErroringReader;

    impl tokio::io::AsyncRead for ErroringReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            _buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed input",
            )))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn controller_input_read_error_ends_the_pump_with_an_io_error() {
        let mut failing = ErroringReader;
        let mut input = TestInput;
        assert!(matches!(
            copy_controller_input(&mut failing, &mut input, None).await,
            Err(HostError::Io(_))
        ));
    }

    #[test]
    fn every_public_host_entry_rejects_invalid_tls_before_network_activity() {
        // The host future (with the 0.2.0 audit observer state) exceeds the
        // default test-thread stack, so the scenario runs on a dedicated
        // thread with a large stack.
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
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
                    assert_invalid(
                        run_host_with(invalid_config(), TestBackend::open_failure()).await,
                    );
                });
            })
            .unwrap()
            .join()
            .unwrap();
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

    // ------------------------------------------------------------------
    // File-transfer integration helpers: the host session layer is
    // exercised with duplex streams and real file I/O, mirroring how the
    // existing host tests drive the terminal pumps (no swarm needed).
    // ------------------------------------------------------------------

    fn file_transfer_config() -> TransferConfig {
        TransferConfig {
            control_timeout: Duration::from_secs(2),
            data_progress_timeout: Duration::from_secs(5),
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

    /// Writes one control frame from the scripted controller.
    async fn send_wire_frame<S: AsyncWrite + Unpin>(
        stream: &mut S,
        message: &FileTransferMessage<'_>,
    ) {
        let encoded = message.encode().unwrap();
        stream.write_all(encoded.as_slice()).await.unwrap();
        stream.flush().await.unwrap();
    }

    /// Writes one `Data` frame from the scripted controller.
    async fn send_wire_data<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) {
        let header = encode_frame_header(TransferTag::Data.code(), bytes.len() as u32);
        stream.write_all(&header).await.unwrap();
        stream.write_all(bytes).await.unwrap();
        stream.flush().await.unwrap();
    }

    /// Reads one complete frame from the wire and returns the raw bytes.
    async fn read_wire_frame<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Vec<u8> {
        let mut header = [0_u8; FRAME_HEADER_LEN];
        stream.read_exact(&mut header).await.unwrap();
        let (_, payload_len) = decode_frame_header(&header).unwrap();
        let mut payload = vec![0_u8; payload_len as usize];
        stream.read_exact(&mut payload).await.unwrap();
        let mut frame = header.to_vec();
        frame.extend_from_slice(&payload);
        frame
    }

    /// Reads the next frame and asserts it is exactly `expected`.
    async fn expect_wire_control<S: tokio::io::AsyncRead + Unpin>(
        stream: &mut S,
        expected: &FileTransferMessage<'_>,
    ) {
        let frame = read_wire_frame(stream).await;
        assert_eq!(
            FileTransferMessage::decode_frame(&frame).unwrap(),
            *expected
        );
    }

    /// Reads the frames of a download until `Finish` and returns the
    /// received `Data` payload bytes.
    async fn receive_download_bytes<S: tokio::io::AsyncRead + Unpin>(
        stream: &mut S,
        expected_size: u64,
    ) -> Vec<u8> {
        let mut received = Vec::new();
        loop {
            let frame = read_wire_frame(stream).await;
            if frame[0] == TransferTag::Data.code() {
                received.extend_from_slice(&frame[FRAME_HEADER_LEN..]);
                continue;
            }
            match FileTransferMessage::decode_frame(&frame).unwrap() {
                FileTransferMessage::Finish {
                    actual_size,
                    digest,
                } => {
                    assert_eq!(actual_size, expected_size);
                    assert_eq!(digest, sha256_bytes(&received));
                    return received;
                }
                other => panic!("unexpected host message: {other:?}"),
            }
        }
    }

    // ------------------------------------------------------------------
    // Opening-frame read (capability probing, design 9.3).
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn file_open_frame_read_distinguishes_probe_open_and_protocol() {
        let budget = file_transfer_config().control_timeout;
        // EOF before any byte: a zero-side-effect capability probe.
        let (mut host, peer) = tokio::io::duplex(1);
        drop(peer);
        assert_eq!(
            read_file_open_frame(&mut host, budget).await.unwrap(),
            FileOpenFrame::Probe
        );

        // A complete UploadOpen decodes as an upload.
        let (mut host, mut peer) = tokio::io::duplex(64 * 1024);
        let open = FileTransferMessage::UploadOpen {
            destination: "dir/f",
            file_name: "n.bin",
            declared_size: 7,
        };
        send_wire_frame(&mut peer, &open).await;
        assert_eq!(
            read_file_open_frame(&mut host, budget).await.unwrap(),
            FileOpenFrame::Upload {
                destination: "dir/f".to_owned(),
                file_name: "n.bin".to_owned(),
                declared_size: 7,
            }
        );

        // A complete DownloadOpen decodes as a download.
        let (mut host, mut peer) = tokio::io::duplex(64 * 1024);
        send_wire_frame(
            &mut peer,
            &FileTransferMessage::DownloadOpen { source: "in/f" },
        )
        .await;
        assert_eq!(
            read_file_open_frame(&mut host, budget).await.unwrap(),
            FileOpenFrame::Download {
                source: "in/f".to_owned()
            }
        );

        // An unknown tag is a protocol violation.
        let (mut host, mut peer) = tokio::io::duplex(64 * 1024);
        peer.write_all(&[0x0A, 0, 0, 0, 0]).await.unwrap();
        peer.flush().await.unwrap();
        assert_eq!(
            read_file_open_frame(&mut host, budget).await.unwrap_err(),
            FileOpenError::Protocol
        );

        // A frame that cannot open a transfer (Ready) is a protocol
        // violation.
        let (mut host, mut peer) = tokio::io::duplex(64 * 1024);
        send_wire_frame(&mut peer, &FileTransferMessage::Ready).await;
        assert_eq!(
            read_file_open_frame(&mut host, budget).await.unwrap_err(),
            FileOpenError::Protocol
        );

        // A Data first frame is a protocol violation even with a legal
        // payload length.
        let (mut host, mut peer) = tokio::io::duplex(64 * 1024);
        send_wire_data(&mut peer, &[1, 2, 3]).await;
        assert_eq!(
            read_file_open_frame(&mut host, budget).await.unwrap_err(),
            FileOpenError::Protocol
        );

        // A truncated header is a protocol violation: EOF inside a frame.
        let (mut host, mut peer) = tokio::io::duplex(64 * 1024);
        peer.write_all(&[0x01, 0, 0]).await.unwrap();
        peer.flush().await.unwrap();
        drop(peer);
        assert_eq!(
            read_file_open_frame(&mut host, budget).await.unwrap_err(),
            FileOpenError::Protocol
        );

        // A frame declaring more payload than arrives is a protocol
        // violation (EOF mid-frame).
        let (mut host, mut peer) = tokio::io::duplex(64 * 1024);
        let header = encode_frame_header(TransferTag::UploadOpen.code(), 100);
        peer.write_all(&header).await.unwrap();
        peer.write_all(&[0; 10]).await.unwrap();
        peer.flush().await.unwrap();
        drop(peer);
        assert_eq!(
            read_file_open_frame(&mut host, budget).await.unwrap_err(),
            FileOpenError::Protocol
        );

        // Silence until the control deadline is a timeout.
        let (mut host, _peer) = tokio::io::duplex(1);
        assert_eq!(
            read_file_open_frame(&mut host, Duration::from_millis(20))
                .await
                .unwrap_err(),
            FileOpenError::Timeout
        );
    }

    #[test]
    fn file_open_io_failures_are_classified_by_eof_kind() {
        // EOF inside a frame is a protocol violation; every other I/O
        // failure of the substream stays an I/O failure.
        assert_eq!(
            classify_file_open_io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated frame",
            )),
            FileOpenError::Protocol
        );
        assert_eq!(
            classify_file_open_io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "substream failure",
            )),
            FileOpenError::Io
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn capability_probe_creates_no_state_or_error() {
        let config = file_transfer_config();
        let directory = tempdir().unwrap();
        let base = Some(BaseDirectory::capture().unwrap());

        // An Active-slot probe: the controller opens a substream and closes
        // it without a single byte. The host must reply with nothing and
        // close without creating any state (design 9.3).
        let cancel = Arc::new(AtomicBool::new(false));
        let (host_half, mut peer_half) = tokio::io::duplex(1);
        let served = serve_one_file_substream(
            host_half,
            base.as_ref(),
            Arc::clone(&cancel),
            &config,
            super::FileSubstreamRole::Active,
            None,
        );
        let peer = async {
            peer_half.shutdown().await.unwrap();
            let mut buffer = [0_u8; 8];
            let read = peer_half.read(&mut buffer).await.unwrap();
            (read, buffer)
        };
        let ((), (read, buffer)) = tokio::join!(served, peer);
        assert_eq!(read, 0, "a probe must not produce any byte");
        assert!(buffer.iter().all(|byte| *byte == 0));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);

        // The same holds while another transfer is active (Busy role): the
        // probe is answered with silence, not with Error(Busy).
        let (host_half, mut peer_half) = tokio::io::duplex(1);
        let served = serve_one_file_substream(
            host_half,
            base.as_ref(),
            Arc::clone(&cancel),
            &config,
            super::FileSubstreamRole::Busy,
            None,
        );
        let peer = async {
            peer_half.shutdown().await.unwrap();
            let mut buffer = [0_u8; 8];
            let read = peer_half.read(&mut buffer).await.unwrap();
            (read, buffer)
        };
        let ((), (read, buffer)) = tokio::join!(served, peer);
        assert_eq!(read, 0, "a busy probe must still be silent");
        assert!(buffer.iter().all(|byte| *byte == 0));

        // And when the session base directory is unavailable, a real
        // opening still leaves no trace and no reply.
        let (host_half, mut peer_half) = tokio::io::duplex(1);
        let served = serve_one_file_substream(
            host_half,
            None,
            Arc::clone(&cancel),
            &config,
            super::FileSubstreamRole::Active,
            None,
        );
        let peer = async {
            send_wire_frame(
                &mut peer_half,
                &FileTransferMessage::UploadOpen {
                    destination: "",
                    file_name: "f.bin",
                    declared_size: 1,
                },
            )
            .await;
            let mut buffer = [0_u8; 8];
            let read = peer_half.read(&mut buffer).await.unwrap();
            (read, buffer)
        };
        let ((), (read, buffer)) = tokio::join!(served, peer);
        assert_eq!(read, 0, "an unresolvable request must not produce bytes");
        assert!(buffer.iter().all(|byte| *byte == 0));
    }

    // ------------------------------------------------------------------
    // Real transfers over one live substream (probe read + dispatch).
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn upload_over_a_live_substream_succeeds() {
        let config = file_transfer_config();
        let directory = tempdir().unwrap();
        let base = Some(BaseDirectory::capture().unwrap());
        for size in [0_u64, 1, 65535, 65536, 65537] {
            let source_dir = tempdir().unwrap();
            let source_path = source_dir.path().join(format!("source-{size}.bin"));
            write_pattern_file(&source_path, size);
            let bytes = fs::read(&source_path).unwrap();
            let final_path = directory.path().join(format!("final-{size}.bin"));
            let destination = final_path.to_str().unwrap().to_owned();
            let (host_half, mut peer_half) = tokio::io::duplex(64 * 1024);
            let cancel = Arc::new(AtomicBool::new(false));
            let served = serve_one_file_substream(
                host_half,
                base.as_ref(),
                cancel,
                &config,
                super::FileSubstreamRole::Active,
                None,
            );
            let controller = async {
                send_wire_frame(
                    &mut peer_half,
                    &FileTransferMessage::UploadOpen {
                        destination: &destination,
                        file_name: "up.bin",
                        declared_size: bytes.len() as u64,
                    },
                )
                .await;
                expect_wire_control(&mut peer_half, &FileTransferMessage::Ready).await;
                for chunk in bytes.chunks(65536) {
                    send_wire_data(&mut peer_half, chunk).await;
                }
                send_wire_frame(
                    &mut peer_half,
                    &FileTransferMessage::Finish {
                        actual_size: bytes.len() as u64,
                        digest: sha256_bytes(&bytes),
                    },
                )
                .await;
                expect_wire_control(&mut peer_half, &FileTransferMessage::Committed).await;
                let mut trailing = [0_u8; 1];
                assert_eq!(
                    peer_half.read(&mut trailing).await.unwrap(),
                    0,
                    "the host must close the substream after Committed"
                );
            };
            tokio::time::timeout(Duration::from_secs(10), async {
                tokio::join!(served, controller)
            })
            .await
            .expect("upload over the live substream deadlocked");
            assert_eq!(
                fs::read(&final_path).unwrap(),
                bytes,
                "content for size {size}"
            );
            assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
            fs::remove_file(&final_path).unwrap();
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn download_over_a_live_substream_succeeds() {
        let config = file_transfer_config();
        let directory = tempdir().unwrap();
        let base = Some(BaseDirectory::capture().unwrap());
        for size in [0_u64, 1, 65535, 65536, 65537] {
            let source_path = directory.path().join(format!("source-{size}.bin"));
            write_pattern_file(&source_path, size);
            let bytes = fs::read(&source_path).unwrap();
            let source = source_path.to_str().unwrap().to_owned();
            let (host_half, mut peer_half) = tokio::io::duplex(64 * 1024);
            let cancel = Arc::new(AtomicBool::new(false));
            let served = serve_one_file_substream(
                host_half,
                base.as_ref(),
                cancel,
                &config,
                super::FileSubstreamRole::Active,
                None,
            );
            let controller = async {
                send_wire_frame(
                    &mut peer_half,
                    &FileTransferMessage::DownloadOpen { source: &source },
                )
                .await;
                let offer = read_wire_frame(&mut peer_half).await;
                let message = FileTransferMessage::decode_frame(&offer).unwrap();
                let (name, declared) = match &message {
                    FileTransferMessage::DownloadOffer {
                        file_name,
                        declared_size,
                    } => (*file_name, *declared_size),
                    other => panic!("expected DownloadOffer, got {other:?}"),
                };
                assert_eq!(name, format!("source-{size}.bin"));
                assert_eq!(declared, size);
                send_wire_frame(&mut peer_half, &FileTransferMessage::Ready).await;
                let received = receive_download_bytes(&mut peer_half, size).await;
                send_wire_frame(&mut peer_half, &FileTransferMessage::Committed).await;
                let mut trailing = [0_u8; 1];
                assert_eq!(
                    peer_half.read(&mut trailing).await.unwrap(),
                    0,
                    "the host must close the substream after the transfer"
                );
                received
            };
            let ((), received) = tokio::time::timeout(Duration::from_secs(10), async {
                tokio::join!(served, controller)
            })
            .await
            .expect("download over the live substream deadlocked");
            assert_eq!(received, bytes, "received bytes for size {size}");
        }
    }

    // ------------------------------------------------------------------
    // Single-transfer mutual exclusion (design 15.3): the coordinator
    // answers a second substream with Error(Busy) while a transfer runs.
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn coordinator_alone_completes_a_transfer() {
        let config = file_transfer_config();
        let directory = tempdir().unwrap();
        let base = Some(BaseDirectory::capture().unwrap());
        let cancel = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::channel::<tokio::io::DuplexStream>(FILE_SUBSTREAM_QUEUE);
        let coordinator =
            file_substream_coordinator(receiver, base.as_ref(), cancel, &config, None);
        let (host_half, mut peer_half) = tokio::io::duplex(64 * 1024);
        sender.try_send(host_half).unwrap();
        // The coordinator ends when the sender is dropped, which the real
        // bridge does at session teardown.
        drop(sender);
        let final_path = directory.path().join("out.bin");
        let destination = final_path.to_str().unwrap().to_owned();
        let bytes = patterned_bytes(200 * 1024, 5);
        let controller = async {
            send_wire_frame(
                &mut peer_half,
                &FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "out.bin",
                    declared_size: bytes.len() as u64,
                },
            )
            .await;
            expect_wire_control(&mut peer_half, &FileTransferMessage::Ready).await;
            for chunk in bytes.chunks(65536) {
                send_wire_data(&mut peer_half, chunk).await;
            }
            send_wire_frame(
                &mut peer_half,
                &FileTransferMessage::Finish {
                    actual_size: bytes.len() as u64,
                    digest: sha256_bytes(&bytes),
                },
            )
            .await;
            expect_wire_control(&mut peer_half, &FileTransferMessage::Committed).await;
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(coordinator, controller)
        })
        .await
        .expect("coordinator-served transfer deadlocked");
        assert_eq!(fs::read(&final_path).unwrap(), bytes);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn second_substream_during_a_transfer_is_answered_busy() {
        let config = file_transfer_config();
        let directory = tempdir().unwrap();
        let base = Some(BaseDirectory::capture().unwrap());
        let cancel = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::channel::<tokio::io::DuplexStream>(FILE_SUBSTREAM_QUEUE);
        let coordinator =
            file_substream_coordinator(receiver, base.as_ref(), cancel, &config, None);

        let (host_first, mut peer_first) = tokio::io::duplex(64 * 1024);
        let (host_second, mut peer_second) = tokio::io::duplex(64 * 1024);
        sender.try_send(host_first).unwrap();
        let first_started = Arc::new(Notify::new());
        let busy_done = Arc::new(Notify::new());

        let final_path = directory.path().join("out.bin");
        let destination = final_path.to_str().unwrap().to_owned();
        const SIZE: usize = 200 * 1024;
        let bytes = patterned_bytes(SIZE, 5);

        let first = {
            let first_started = Arc::clone(&first_started);
            let busy_done = Arc::clone(&busy_done);
            let bytes = &bytes;
            async move {
                send_wire_frame(
                    &mut peer_first,
                    &FileTransferMessage::UploadOpen {
                        destination: &destination,
                        file_name: "out.bin",
                        declared_size: SIZE as u64,
                    },
                )
                .await;
                expect_wire_control(&mut peer_first, &FileTransferMessage::Ready).await;
                send_wire_data(&mut peer_first, &bytes[..65536]).await;
                // The host is now inside the data phase; let the second
                // substream be opened while this transfer is active.
                first_started.notify_one();
                busy_done.notified().await;
                for chunk in bytes[65536..].chunks(65536) {
                    send_wire_data(&mut peer_first, chunk).await;
                }
                send_wire_frame(
                    &mut peer_first,
                    &FileTransferMessage::Finish {
                        actual_size: SIZE as u64,
                        digest: sha256_bytes(bytes),
                    },
                )
                .await;
                expect_wire_control(&mut peer_first, &FileTransferMessage::Committed).await;
            }
        };
        let second = async {
            first_started.notified().await;
            // The coordinator has consumed the first substream, so the
            // bounded queue is empty and the second one is accepted — then
            // answered with Error(Busy) because the transfer is active.
            sender.try_send(host_second).unwrap();
            // The coordinator ends when the sender is dropped, which the
            // real bridge does at session teardown.
            drop(sender);
            send_wire_frame(
                &mut peer_second,
                &FileTransferMessage::UploadOpen {
                    destination: "",
                    file_name: "other.bin",
                    declared_size: 1,
                },
            )
            .await;
            expect_wire_control(
                &mut peer_second,
                &FileTransferMessage::Error {
                    code: FileTransferErrorCode::Busy,
                },
            )
            .await;
            let mut trailing = [0_u8; 1];
            assert_eq!(
                peer_second.read(&mut trailing).await.unwrap(),
                0,
                "the busy substream must be closed after the reply"
            );
            busy_done.notify_one();
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(coordinator, first, second)
        })
        .await
        .expect("busy rejection deadlocked");
        // The first transfer completed untouched and committed its target.
        assert_eq!(fs::read(&final_path).unwrap(), bytes);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn third_substream_while_both_slots_are_occupied_is_dropped() {
        let config = file_transfer_config();
        let directory = tempdir().unwrap();
        let base = Some(BaseDirectory::capture().unwrap());
        let cancel = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::channel::<tokio::io::DuplexStream>(FILE_SUBSTREAM_QUEUE);
        let coordinator =
            file_substream_coordinator(receiver, base.as_ref(), cancel, &config, None);

        let (host_first, mut peer_first) = tokio::io::duplex(64 * 1024);
        let (host_second, mut peer_second) = tokio::io::duplex(64 * 1024);
        let (mut host_third, mut peer_third) = tokio::io::duplex(64 * 1024);
        sender.try_send(host_first).unwrap();
        let first_started = Arc::new(Notify::new());
        let second_answered = Arc::new(Notify::new());

        let final_path = directory.path().join("first.bin");
        let destination = final_path.to_str().unwrap().to_owned();
        const SIZE: usize = 200 * 1024;
        let bytes = patterned_bytes(SIZE, 29);

        let first = {
            let first_started = Arc::clone(&first_started);
            let second_answered = Arc::clone(&second_answered);
            let bytes = &bytes;
            async move {
                send_wire_frame(
                    &mut peer_first,
                    &FileTransferMessage::UploadOpen {
                        destination: &destination,
                        file_name: "first.bin",
                        declared_size: SIZE as u64,
                    },
                )
                .await;
                expect_wire_control(&mut peer_first, &FileTransferMessage::Ready).await;
                send_wire_data(&mut peer_first, &bytes[..65536]).await;
                first_started.notify_one();
                second_answered.notified().await;
                for chunk in bytes[65536..].chunks(65536) {
                    send_wire_data(&mut peer_first, chunk).await;
                }
                send_wire_frame(
                    &mut peer_first,
                    &FileTransferMessage::Finish {
                        actual_size: SIZE as u64,
                        digest: sha256_bytes(bytes),
                    },
                )
                .await;
                expect_wire_control(&mut peer_first, &FileTransferMessage::Committed).await;
            }
        };
        let second = async {
            first_started.notified().await;
            // The second substream occupies the busy slot: its serving is
            // blocked reading the opening frame, so both slots stay taken
            // until that frame arrives.
            sender.try_send(host_second).unwrap();
            let mut queued = false;
            for _ in 0..100 {
                match sender.try_send(host_third) {
                    Ok(()) => {
                        queued = true;
                        break;
                    }
                    Err(error) => {
                        host_third = match error {
                            tokio::sync::mpsc::error::TrySendError::Full(stream) => stream,
                            tokio::sync::mpsc::error::TrySendError::Closed(stream) => stream,
                        }
                    }
                }
                tokio::task::yield_now().await;
            }
            assert!(queued, "the coordinator must drain the queue");
            // The coordinator ends when the sender is dropped, which the
            // real bridge does at session teardown.
            drop(sender);
            // Both slots are occupied: the third substream is dropped
            // without any reply, so its peer observes a closed substream.
            let mut trailing = [0_u8; 8];
            assert_eq!(
                peer_third.read(&mut trailing).await.unwrap(),
                0,
                "a substream beyond the active and busy slots must be closed silently"
            );
            // Now let the busy reply proceed.
            send_wire_frame(
                &mut peer_second,
                &FileTransferMessage::UploadOpen {
                    destination: "",
                    file_name: "second.bin",
                    declared_size: 1,
                },
            )
            .await;
            expect_wire_control(
                &mut peer_second,
                &FileTransferMessage::Error {
                    code: FileTransferErrorCode::Busy,
                },
            )
            .await;
            let mut trailing = [0_u8; 1];
            assert_eq!(
                peer_second.read(&mut trailing).await.unwrap(),
                0,
                "the busy substream must be closed after the reply"
            );
            second_answered.notify_one();
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(coordinator, first, second)
        })
        .await
        .expect("three-substream coordination deadlocked");
        // The first transfer completed untouched and committed its target.
        assert_eq!(fs::read(&final_path).unwrap(), bytes);
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    // ------------------------------------------------------------------
    // Session teardown (design 16.4, 16.5): the shared cancel flag aborts
    // the active transfer; no uncommitted target appears.
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn session_teardown_cancels_the_active_transfer() {
        let config = file_transfer_config();
        let directory = tempdir().unwrap();
        let base = Some(BaseDirectory::capture().unwrap());
        let cancel = Arc::new(AtomicBool::new(false));
        let final_path = directory.path().join("f.bin");
        let destination = final_path.to_str().unwrap().to_owned();
        let (host_half, mut peer_half) = tokio::io::duplex(64 * 1024);
        let served = serve_one_file_substream(
            host_half,
            base.as_ref(),
            Arc::clone(&cancel),
            &config,
            super::FileSubstreamRole::Active,
            None,
        );
        let controller = async {
            send_wire_frame(
                &mut peer_half,
                &FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "f.bin",
                    declared_size: 200 * 1024,
                },
            )
            .await;
            expect_wire_control(&mut peer_half, &FileTransferMessage::Ready).await;
            send_wire_data(&mut peer_half, &[7; 65536]).await;
            // The shell exits or the connection is lost: the bridge sets
            // the cancel flag and abandons the substream. The host sends
            // Error(SessionClosing) best-effort and closes.
            cancel.store(true, Ordering::Relaxed);
            expect_wire_control(
                &mut peer_half,
                &FileTransferMessage::Error {
                    code: FileTransferErrorCode::SessionClosing,
                },
            )
            .await;
            let mut trailing = [0_u8; 1];
            assert_eq!(
                peer_half.read(&mut trailing).await.unwrap(),
                0,
                "the cancelled substream must be closed"
            );
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(served, controller)
        })
        .await
        .expect("teardown cancellation deadlocked");
        // No final target and no leftover temporary file.
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    // ------------------------------------------------------------------
    // Error mapping (design 10.4) and lifecycle isolation (design 17.2):
    // a file failure only terminates its substream; the terminal session
    // stays usable.
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn file_errors_leave_the_session_usable() {
        let config = file_transfer_config();
        let directory = tempdir().unwrap();
        let base = Some(BaseDirectory::capture().unwrap());
        let cancel = Arc::new(AtomicBool::new(false));

        // An upload into an existing destination fails with
        // Error(DestinationExists) and never touches the target.
        let final_path = directory.path().join("exists.bin");
        fs::write(&final_path, b"pre-existing").unwrap();
        let destination = final_path.to_str().unwrap().to_owned();
        let (host_half, mut peer_half) = tokio::io::duplex(64 * 1024);
        let served = serve_one_file_substream(
            host_half,
            base.as_ref(),
            Arc::clone(&cancel),
            &config,
            super::FileSubstreamRole::Active,
            None,
        );
        let controller = async {
            send_wire_frame(
                &mut peer_half,
                &FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "f.bin",
                    declared_size: 4,
                },
            )
            .await;
            expect_wire_control(
                &mut peer_half,
                &FileTransferMessage::Error {
                    code: FileTransferErrorCode::DestinationExists,
                },
            )
            .await;
            let mut trailing = [0_u8; 1];
            assert_eq!(peer_half.read(&mut trailing).await.unwrap(), 0);
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(served, controller)
        })
        .await
        .expect("destination-exists rejection deadlocked");
        assert_eq!(fs::read(&final_path).unwrap(), b"pre-existing");

        // A download of a missing source fails with Error(SourceNotFound).
        let missing = directory.path().join("nope.bin");
        let source = missing.to_str().unwrap().to_owned();
        let (host_half, mut peer_half) = tokio::io::duplex(64 * 1024);
        let served = serve_one_file_substream(
            host_half,
            base.as_ref(),
            Arc::clone(&cancel),
            &config,
            super::FileSubstreamRole::Active,
            None,
        );
        let controller = async {
            send_wire_frame(
                &mut peer_half,
                &FileTransferMessage::DownloadOpen { source: &source },
            )
            .await;
            expect_wire_control(
                &mut peer_half,
                &FileTransferMessage::Error {
                    code: FileTransferErrorCode::SourceNotFound,
                },
            )
            .await;
            let mut trailing = [0_u8; 1];
            assert_eq!(peer_half.read(&mut trailing).await.unwrap(), 0);
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(served, controller)
        })
        .await
        .expect("source-not-found rejection deadlocked");

        // The session is still usable: a full upload now succeeds.
        let final_path = directory.path().join("after.bin");
        let destination = final_path.to_str().unwrap().to_owned();
        let (host_half, mut peer_half) = tokio::io::duplex(64 * 1024);
        let served = serve_one_file_substream(
            host_half,
            base.as_ref(),
            cancel,
            &config,
            super::FileSubstreamRole::Active,
            None,
        );
        let bytes = patterned_bytes(4096, 11);
        let controller = async {
            send_wire_frame(
                &mut peer_half,
                &FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "after.bin",
                    declared_size: bytes.len() as u64,
                },
            )
            .await;
            expect_wire_control(&mut peer_half, &FileTransferMessage::Ready).await;
            send_wire_data(&mut peer_half, &bytes).await;
            send_wire_frame(
                &mut peer_half,
                &FileTransferMessage::Finish {
                    actual_size: bytes.len() as u64,
                    digest: sha256_bytes(&bytes),
                },
            )
            .await;
            expect_wire_control(&mut peer_half, &FileTransferMessage::Committed).await;
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(served, controller)
        })
        .await
        .expect("post-error upload deadlocked");
        assert_eq!(fs::read(&final_path).unwrap(), bytes);
    }

    // ------------------------------------------------------------------
    // Terminal fairness (design 15.2, 23.5): the terminal output pump
    // keeps running while a file transfer is in flight.
    // ------------------------------------------------------------------

    #[test]
    fn terminal_pump_runs_concurrently_with_a_file_transfer() {
        // The combined pump, transfer and audit futures exceed the default
        // test-thread stack; the project pattern runs the scenario on a
        // 64 MiB stack thread.
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    const EXIT_CODE: u32 = 53;
                    const TRANSFER_SIZE: usize = 200 * 1024;
                    let config = file_transfer_config();
                    let directory = tempdir().unwrap();
                    let base = Some(BaseDirectory::capture().unwrap());
                    let cancel = Arc::new(AtomicBool::new(false));

                    let mut events = VecDeque::new();
                    let terminal_bytes = patterned_bytes(16 * 1024, 13);
                    for chunk in terminal_bytes.chunks(4096) {
                        let mut terminal_chunk = TerminalChunk::new();
                        terminal_chunk.writable()[..chunk.len()].copy_from_slice(chunk);
                        terminal_chunk.set_len(chunk.len()).unwrap();
                        events.push_back(PtyEvent::output(terminal_chunk));
                    }
                    events.push_back(PtyEvent::exited(EXIT_CODE));
                    let mut session = PumpSession { events };

                    let (host_data, mut controller_data) = tokio::io::duplex(8);
                    let (_host_data_read, mut host_data_write) = tokio::io::split(host_data);
                    let (host_control, controller_control) = tokio::io::duplex(8);
                    let (mut host_control_read, mut host_control_write) =
                        tokio::io::split(host_control);
                    let (mut controller_control_read, mut controller_control_write) =
                        tokio::io::split(controller_control);
                    let (host_half, mut peer_half) = tokio::io::duplex(64 * 1024);

                    let final_path = directory.path().join("during.bin");
                    let destination = final_path.to_str().unwrap().to_owned();
                    let transfer_bytes = patterned_bytes(TRANSFER_SIZE, 17);

                    let pump = copy_terminal_output(
                        &mut session,
                        &mut host_data_write,
                        &mut host_control_read,
                        &mut host_control_write,
                        None,
                    );
                    let served = serve_one_file_substream(
                        host_half,
                        base.as_ref(),
                        cancel,
                        &config,
                        super::FileSubstreamRole::Active,
                        None,
                    );
                    let controller = async {
                        // Drive the file transfer to completion.
                        send_wire_frame(
                            &mut peer_half,
                            &FileTransferMessage::UploadOpen {
                                destination: &destination,
                                file_name: "during.bin",
                                declared_size: TRANSFER_SIZE as u64,
                            },
                        )
                        .await;
                        expect_wire_control(&mut peer_half, &FileTransferMessage::Ready).await;
                        for chunk in transfer_bytes.chunks(65536) {
                            send_wire_data(&mut peer_half, chunk).await;
                        }
                        send_wire_frame(
                            &mut peer_half,
                            &FileTransferMessage::Finish {
                                actual_size: TRANSFER_SIZE as u64,
                                digest: sha256_bytes(&transfer_bytes),
                            },
                        )
                        .await;
                        expect_wire_control(&mut peer_half, &FileTransferMessage::Committed).await;
                        // Observe the terminal output and complete the session.
                        let mut observed = Vec::new();
                        controller_data.read_to_end(&mut observed).await.unwrap();
                        let mut exit = [0_u8; 5];
                        controller_control_read.read_exact(&mut exit).await.unwrap();
                        controller_control_write
                            .write_all(&TerminalComplete::ENCODED)
                            .await
                            .unwrap();
                        controller_control_write.flush().await.unwrap();
                        (observed, TerminalExit::decode(&exit).unwrap())
                    };
                    let (pump_result, (observed, exit), ()) =
                        tokio::time::timeout(Duration::from_secs(10), async {
                            tokio::join!(pump, controller, served)
                        })
                        .await
                        .expect("terminal pump and file transfer deadlocked");
                    assert_eq!(pump_result.unwrap(), EXIT_CODE);
                    assert_eq!(exit.code(), EXIT_CODE);
                    assert_eq!(observed, terminal_bytes);
                    assert_eq!(fs::read(&final_path).unwrap(), transfer_bytes);
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }

    // ------------------------------------------------------------------
    // Coverage closure: error propagation, fragmented reads and write
    // side effects for the io helpers exercised above.
    // ------------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn authenticated_write_propagates_write_and_flush_failures() {
        let (mut closed, peer) = tokio::io::duplex(1);
        drop(peer);
        assert!(matches!(
            write_authenticated_io(&mut closed).await,
            Err(HostError::Io(_))
        ));
        let mut flush_failing = FlushFailingWriter;
        assert!(matches!(
            write_authenticated_io(&mut flush_failing).await,
            Err(HostError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn start_terminal_io_times_out_when_the_hello_never_arrives() {
        // The frozen hello deadline is EXCHANGE_TIMEOUT (ten seconds), so
        // this test genuinely waits it out on a silent control stream.
        let (mut data, _data_peer) = tokio::io::duplex(1);
        let (mut control, _control_peer) = tokio::io::duplex(1);
        let backend = TestBackend::open_failure();
        assert!(matches!(
            start_terminal_io(&backend, &mut data, &mut control).await,
            Err(HostError::Timeout)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_hello_reader_accepts_a_fragmented_hello() {
        let hello = TerminalHello::new(
            TerminalSize::new(80, 24).unwrap(),
            TerminalValue::new("xterm").unwrap(),
            TerminalValue::new("truecolor").unwrap(),
        );
        let encoded = hello.encode().as_slice().to_vec();
        let (mut host, mut peer) = tokio::io::duplex(1);
        let read = read_terminal_hello_io(&mut host);
        let write = async {
            for byte in encoded {
                peer.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        };
        let (result, ()) = tokio::join!(read, write);
        assert_eq!(result.unwrap(), hello);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_ready_write_propagates_a_flush_failure() {
        let mut host = FlushFailingWriter;
        assert!(matches!(
            write_terminal_ready_io(&mut host).await,
            Err(HostError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn auth_retry_writes_the_frozen_bytes_and_shuts_the_stream_down() {
        let (mut host, mut controller) = tokio::io::duplex(8);
        let expected = AuthServerResponse::retry(RetryAfter::from_millis(1_000).unwrap()).encode();
        let expected_len = expected.as_slice().len();
        let write = send_auth_retry_io(&mut host);
        let read = async move {
            let mut response = vec![0_u8; expected_len];
            controller.read_exact(&mut response).await.unwrap();
            // The shutdown side effect: once the frozen bytes are drained,
            // the peer observes EOF (a written-but-open stream would not).
            let mut trailing = [0_u8; 1];
            let trailing_len = controller.read(&mut trailing).await.unwrap();
            (response, trailing_len)
        };
        let (result, (response, trailing_len)) = tokio::join!(write, read);
        result.unwrap();
        assert_eq!(response, expected.as_slice());
        assert_eq!(
            trailing_len, 0,
            "the retry stream must be shut down after the reply"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn file_open_frame_read_rejects_invalid_lengths_and_bad_bodies() {
        let budget = file_transfer_config().control_timeout;
        // A payload length below the tag's structural minimum is rejected
        // before any payload byte is read.
        let (mut host, mut peer) = tokio::io::duplex(64 * 1024);
        peer.write_all(&encode_frame_header(TransferTag::UploadOpen.code(), 5))
            .await
            .unwrap();
        peer.flush().await.unwrap();
        assert_eq!(
            read_file_open_frame(&mut host, budget).await.unwrap_err(),
            FileOpenError::Protocol
        );

        // A payload length above the tag's bound is equally rejected.
        let (mut host, mut peer) = tokio::io::duplex(64 * 1024);
        peer.write_all(&encode_frame_header(
            TransferTag::UploadOpen.code(),
            u32::MAX,
        ))
        .await
        .unwrap();
        peer.flush().await.unwrap();
        assert_eq!(
            read_file_open_frame(&mut host, budget).await.unwrap_err(),
            FileOpenError::Protocol
        );

        // A legal length whose payload never begins is a truncated frame:
        // EOF exactly at the payload boundary.
        let (mut host, mut peer) = tokio::io::duplex(64 * 1024);
        peer.write_all(&encode_frame_header(TransferTag::UploadOpen.code(), 13))
            .await
            .unwrap();
        peer.flush().await.unwrap();
        drop(peer);
        assert_eq!(
            read_file_open_frame(&mut host, budget).await.unwrap_err(),
            FileOpenError::Protocol
        );

        // A complete frame whose body cannot be decoded as UploadOpen: the
        // two-byte length prefix claims a 13-byte destination with only 11
        // payload bytes remaining.
        let (mut host, mut peer) = tokio::io::duplex(64 * 1024);
        peer.write_all(&encode_frame_header(TransferTag::UploadOpen.code(), 13))
            .await
            .unwrap();
        peer.write_all(&[0, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        peer.flush().await.unwrap();
        assert_eq!(
            read_file_open_frame(&mut host, budget).await.unwrap_err(),
            FileOpenError::Protocol
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn file_open_frame_read_tolerates_byte_fragmented_writes() {
        let budget = file_transfer_config().control_timeout;
        let (mut host, mut peer) = tokio::io::duplex(1);
        let open = FileTransferMessage::UploadOpen {
            destination: "dir/f",
            file_name: "n.bin",
            declared_size: 7,
        };
        let encoded = open.encode().unwrap().as_slice().to_vec();
        let read = read_file_open_frame(&mut host, budget);
        let write = async {
            for byte in encoded {
                peer.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
        };
        let (result, ()) = tokio::join!(read, write);
        assert_eq!(
            result.unwrap(),
            FileOpenFrame::Upload {
                destination: "dir/f".to_owned(),
                file_name: "n.bin".to_owned(),
                declared_size: 7,
            }
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unresolvable_download_requests_close_without_state_or_reply() {
        let config = file_transfer_config();
        let directory = tempdir().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let (host_half, mut peer_half) = tokio::io::duplex(1);
        let served = serve_one_file_substream(
            host_half,
            None,
            cancel,
            &config,
            super::FileSubstreamRole::Active,
            None,
        );
        let peer = async {
            send_wire_frame(
                &mut peer_half,
                &FileTransferMessage::DownloadOpen { source: "in/f" },
            )
            .await;
            let mut buffer = [0_u8; 8];
            let read = peer_half.read(&mut buffer).await.unwrap();
            (read, buffer)
        };
        let ((), (read, buffer)) = tokio::join!(served, peer);
        assert_eq!(read, 0, "an unresolvable download must not produce bytes");
        assert!(buffer.iter().all(|byte| *byte == 0));
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn busy_reply_writes_the_canonical_frame_then_shuts_the_substream_down() {
        let config = file_transfer_config();
        let (mut host, mut peer) = tokio::io::duplex(64 * 1024);
        let reply = send_busy_reply(&mut host, &config);
        let read = async {
            let frame = read_wire_frame(&mut peer).await;
            let mut trailing = [0_u8; 1];
            let trailing_len = peer.read(&mut trailing).await.unwrap();
            (frame, trailing_len)
        };
        let ((), (frame, trailing_len)) = tokio::join!(reply, read);
        let expected = FileTransferMessage::Error {
            code: FileTransferErrorCode::Busy,
        }
        .encode()
        .unwrap();
        assert_eq!(
            frame,
            expected.as_slice(),
            "the busy reply must be exactly the canonical error frame"
        );
        assert_eq!(
            trailing_len, 0,
            "the busy substream must be shut down after the reply"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn coordinator_reuses_the_active_slot_after_a_transfer_completes() {
        let config = file_transfer_config();
        let directory = tempdir().unwrap();
        let base = Some(BaseDirectory::capture().unwrap());
        let cancel = Arc::new(AtomicBool::new(false));
        let (sender, receiver) = mpsc::channel::<tokio::io::DuplexStream>(FILE_SUBSTREAM_QUEUE);
        let coordinator =
            file_substream_coordinator(receiver, base.as_ref(), cancel, &config, None);

        let first_bytes = patterned_bytes(64 * 1024, 5);
        let second_bytes = patterned_bytes(64 * 1024, 7);
        let first_path = directory.path().join("first.bin");
        let second_path = directory.path().join("second.bin");
        let first_destination = first_path.to_str().unwrap().to_owned();
        let second_destination = second_path.to_str().unwrap().to_owned();

        let (host_first, mut peer_first) = tokio::io::duplex(64 * 1024);
        sender.try_send(host_first).unwrap();
        let first_done = Arc::new(Notify::new());

        let first = {
            let first_done = Arc::clone(&first_done);
            let first_bytes = &first_bytes;
            let first_destination = &first_destination;
            async move {
                send_wire_frame(
                    &mut peer_first,
                    &FileTransferMessage::UploadOpen {
                        destination: first_destination,
                        file_name: "first.bin",
                        declared_size: first_bytes.len() as u64,
                    },
                )
                .await;
                expect_wire_control(&mut peer_first, &FileTransferMessage::Ready).await;
                send_wire_data(&mut peer_first, first_bytes).await;
                send_wire_frame(
                    &mut peer_first,
                    &FileTransferMessage::Finish {
                        actual_size: first_bytes.len() as u64,
                        digest: sha256_bytes(first_bytes),
                    },
                )
                .await;
                expect_wire_control(&mut peer_first, &FileTransferMessage::Committed).await;
                let mut trailing = [0_u8; 1];
                assert_eq!(
                    peer_first.read(&mut trailing).await.unwrap(),
                    0,
                    "the first substream must be closed by the host"
                );
                first_done.notify_one();
            }
        };
        let second = {
            let first_done = Arc::clone(&first_done);
            let second_bytes = &second_bytes;
            let second_destination = &second_destination;
            async move {
                first_done.notified().await;
                // Let the coordinator observe the completed serve future and
                // free the active slot before the next substream arrives.
                for _ in 0..16 {
                    tokio::task::yield_now().await;
                }
                let (host_second, mut peer_second) = tokio::io::duplex(64 * 1024);
                sender.try_send(host_second).unwrap();
                send_wire_frame(
                    &mut peer_second,
                    &FileTransferMessage::UploadOpen {
                        destination: second_destination,
                        file_name: "second.bin",
                        declared_size: second_bytes.len() as u64,
                    },
                )
                .await;
                expect_wire_control(&mut peer_second, &FileTransferMessage::Ready).await;
                send_wire_data(&mut peer_second, second_bytes).await;
                send_wire_frame(
                    &mut peer_second,
                    &FileTransferMessage::Finish {
                        actual_size: second_bytes.len() as u64,
                        digest: sha256_bytes(second_bytes),
                    },
                )
                .await;
                expect_wire_control(&mut peer_second, &FileTransferMessage::Committed).await;
                drop(sender);
            }
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(coordinator, first, second)
        })
        .await
        .expect("coordinator slot reuse deadlocked");
        assert_eq!(fs::read(&first_path).unwrap(), first_bytes);
        assert_eq!(fs::read(&second_path).unwrap(), second_bytes);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn controller_input_flush_and_close_are_invoked_at_stream_end() {
        let (mut host_data, peer) = tokio::io::duplex(8);
        drop(peer);
        let flushes = Arc::new(AtomicUsize::new(0));
        let closes = Arc::new(AtomicUsize::new(0));
        let mut input = RecordingInput {
            flushes: Arc::clone(&flushes),
            closes: Arc::clone(&closes),
        };
        let copy = copy_controller_input(&mut host_data, &mut input, None);
        tokio::pin!(copy);
        // The peer half is dropped, so the read side reports EOF on the
        // first poll; the copy then flushes, closes the pty input and
        // parks in `pending()`. Poll the future directly (it never
        // resolves) until the close is observed.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        loop {
            if closes.load(Ordering::Relaxed) > 0 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the pty input was not closed at EOF"
            );
            let _ = copy.as_mut().poll(&mut context);
            tokio::task::yield_now().await;
        }
        assert_eq!(
            closes.load(Ordering::Relaxed),
            1,
            "the pty input must be closed at EOF"
        );
        assert_eq!(
            flushes.load(Ordering::Relaxed),
            1,
            "the explicit flush after the input EOF"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_output_applies_a_resize_split_across_writes_then_exits() {
        const EXIT_CODE: u32 = 41;
        let resized = TerminalSize::new(117, 41).unwrap();
        let encoded = TerminalResize::new(resized).encode();
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

        let host = copy_terminal_output(
            &mut session,
            &mut host_data_write,
            &mut host_control_read,
            &mut host_control_write,
            None,
        );
        let controller = async {
            // Deliver the five-byte resize in two fragments so the control
            // read has to complete across several rounds.
            controller_control_write
                .write_all(&encoded[..2])
                .await
                .unwrap();
            tokio::task::yield_now().await;
            controller_control_write
                .write_all(&encoded[2..])
                .await
                .unwrap();
            let mut terminal_bytes = Vec::new();
            controller_data
                .read_to_end(&mut terminal_bytes)
                .await
                .unwrap();
            let mut exit = [0_u8; 5];
            controller_control_read.read_exact(&mut exit).await.unwrap();
            controller_control_write
                .write_all(&TerminalComplete::ENCODED)
                .await
                .unwrap();
            controller_control_write.flush().await.unwrap();
            let mut trailing = [0_u8; 1];
            assert_eq!(
                controller_control_read.read(&mut trailing).await.unwrap(),
                0
            );
            (terminal_bytes, TerminalExit::decode(&exit).unwrap())
        };
        let (exit, (terminal_bytes, remote_exit)) = tokio::join!(host, controller);

        assert_eq!(exit.unwrap(), EXIT_CODE);
        assert!(terminal_bytes.is_empty());
        assert_eq!(remote_exit.code(), EXIT_CODE);
        assert_eq!(session.resized, Some(resized));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_output_rejects_an_invalid_resize_tag() {
        let mut session = ResizeThenExitSession {
            resized: None,
            exit_code: 0,
        };
        let (host_data, _controller_data) = tokio::io::duplex(8);
        let (_host_data_read, mut host_data_write) = tokio::io::split(host_data);
        let (host_control, mut controller_control) = tokio::io::duplex(8);
        let (mut host_control_read, mut host_control_write) = tokio::io::split(host_control);
        controller_control
            .write_all(&[0xff, 0, 0, 0, 0])
            .await
            .unwrap();
        assert!(matches!(
            copy_terminal_output(
                &mut session,
                &mut host_data_write,
                &mut host_control_read,
                &mut host_control_write,
                None,
            )
            .await,
            Err(HostError::Protocol(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_output_propagates_a_failed_data_flush() {
        let mut chunk = TerminalChunk::new();
        chunk.writable()[..4].copy_from_slice(b"data");
        chunk.set_len(4).unwrap();
        let mut session = PumpSession {
            events: VecDeque::from([PtyEvent::output(chunk), PtyEvent::exited(9)]),
        };
        let (host_control, _controller_control) = tokio::io::duplex(8);
        let (mut host_control_read, mut host_control_write) = tokio::io::split(host_control);
        let mut host_data_write = FlushFailingWriter;
        assert!(matches!(
            copy_terminal_output(
                &mut session,
                &mut host_data_write,
                &mut host_control_read,
                &mut host_control_write,
                None,
            )
            .await,
            Err(HostError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_output_propagates_a_failed_control_flush_when_reporting_exit() {
        const EXIT_CODE: u32 = 13;
        let mut session = PumpSession {
            events: VecDeque::from([PtyEvent::exited(EXIT_CODE)]),
        };
        let (host_data, _controller_data) = tokio::io::duplex(8);
        let (_host_data_read, mut host_data_write) = tokio::io::split(host_data);
        let (host_control, _controller_control) = tokio::io::duplex(8);
        let (mut host_control_read, _host_control_peer) = tokio::io::split(host_control);
        let mut host_control_write = FlushFailingWriter;
        assert!(matches!(
            copy_terminal_output(
                &mut session,
                &mut host_data_write,
                &mut host_control_read,
                &mut host_control_write,
                None,
            )
            .await,
            Err(HostError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_output_propagates_a_control_read_error() {
        let mut session = ResizeThenExitSession {
            resized: None,
            exit_code: 0,
        };
        let (host_data, _controller_data) = tokio::io::duplex(8);
        let (_host_data_read, mut host_data_write) = tokio::io::split(host_data);
        let mut failing = ErroringReader;
        let mut host_control_write = FlushFailingWriter;
        assert!(matches!(
            copy_terminal_output(
                &mut session,
                &mut host_data_write,
                &mut failing,
                &mut host_control_write,
                None,
            )
            .await,
            Err(HostError::Io(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_output_propagates_a_session_error() {
        let mut session = PumpSession {
            events: VecDeque::new(),
        };
        let (host_data, _controller_data) = tokio::io::duplex(8);
        let (_host_data_read, mut host_data_write) = tokio::io::split(host_data);
        let (host_control, _controller_control) = tokio::io::duplex(8);
        let (mut host_control_read, mut host_control_write) = tokio::io::split(host_control);
        assert!(matches!(
            copy_terminal_output(
                &mut session,
                &mut host_data_write,
                &mut host_control_read,
                &mut host_control_write,
                None,
            )
            .await,
            Err(HostError::Terminal(TerminalError::TaskStopped))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_completion_drains_several_resizes_before_shutting_down_the_control_half() {
        let first = TerminalSize::new(100, 30).unwrap();
        let second = TerminalSize::new(132, 43).unwrap();
        let (host_control, controller_control) = tokio::io::duplex(8);
        let (mut host_read, mut host_write) = tokio::io::split(host_control);
        let (mut controller_read, mut controller_write) = tokio::io::split(controller_control);
        let host = complete_terminal_exit_io(
            &mut host_read,
            &mut host_write,
            Duration::from_secs(1),
            None,
        );
        let controller = async {
            controller_write
                .write_all(&TerminalResize::new(first).encode())
                .await
                .unwrap();
            controller_write
                .write_all(&TerminalResize::new(second).encode())
                .await
                .unwrap();
            controller_write
                .write_all(&TerminalComplete::ENCODED)
                .await
                .unwrap();
            controller_write.flush().await.unwrap();
            let mut trailing = [0_u8; 1];
            assert_eq!(
                controller_read.read(&mut trailing).await.unwrap(),
                0,
                "the control half must be shut down after the completion"
            );
        };
        let (result, ()) = tokio::join!(host, controller);
        result.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn terminal_completion_propagates_a_control_read_error() {
        let mut failing = ErroringReader;
        let mut host_write = FlushFailingWriter;
        assert!(matches!(
            complete_terminal_exit_io(&mut failing, &mut host_write, Duration::from_secs(1), None)
                .await,
            Err(HostError::Io(_))
        ));
    }

    // ------------------------------------------------------------------
    // In-process session harness: a real relay service, a real host
    // session and a scripted controller all live in the test runtime, so
    // the 0.1.1 session state machine (hello -> auth -> terminal streams
    // -> bridge -> shell exit) runs over the real libp2p loopback stack
    // without spawning any binaries. The connection code is the only
    // secret-bearing host output, so the tests synchronize on the host
    // milestones instead of reading the printed code; the authenticated
    // happy path drives the same private session functions directly with
    // a code the test itself created.
    // ------------------------------------------------------------------

    use super::{FileSubstreamIo, HostSession, run_host_session};
    use crate::network::{
        EndpointDriver, RelayConnection, build_endpoint, connect_configured_relay,
        wait_for_reservation,
    };
    use crate::pake::OpaqueClientState;
    use crate::progress::OperationProgress;
    use crate::protocol::allocate_locator;
    use std::sync::Mutex;
    use tokio::io::DuplexStream;
    use tokio::sync::oneshot;
    use yon_relay::{RelayServeConfig, RelayServiceError, run_relay_until};
    use yonder_core::wire::auth::{Authenticated, KE3_LEN, PROCEED_LEN, RETRY_LEN};
    use yonder_core::wire::resolve::{ResolveRequest, ResolveResponse};
    use yonder_core::wire::terminal::TerminalReady;
    use yonder_core::wire::{
        AUTH_PROTOCOL, FILE_TRANSFER_PROTOCOL, RESOLVE_PROTOCOL, TERMINAL_CONTROL_PROTOCOL,
        TERMINAL_DATA_PROTOCOL,
    };
    use yonder_net::{
        ApplicationStream, ApplicationStreams, DirectUpgradePolicy, EndpointNode,
        Libp2pApplicationStreams, PeerId, RelayExternalAddress, RelayListenAddress,
        swarm::SwarmEvent,
    };

    fn available_tcp_port() -> u16 {
        crate::available_test_tcp_port()
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

    /// A real relay service running inside the test runtime on a pinned
    /// port, restartable with the same identity for the recovery scenario.
    struct InProcessRelay {
        task: Option<tokio::task::JoinHandle<Result<(), RelayServiceError>>>,
        shutdown: Option<oneshot::Sender<()>>,
    }

    impl InProcessRelay {
        fn start(identity: Keypair, port: u16) -> Self {
            let listen: RelayListenAddress = format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap();
            let external: RelayExternalAddress =
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

    /// Records every host milestone so the tests can synchronize on
    /// registration and relay recovery without reading the connection
    /// code from the printed output.
    #[derive(Clone, Default)]
    struct SharedSessionProgress {
        stages: Arc<Mutex<Vec<HostStage>>>,
    }

    impl OperationProgress<HostStage> for SharedSessionProgress {
        fn update(&mut self, stage: HostStage) {
            self.stages.lock().unwrap().push(stage);
        }

        fn clear(&mut self) {}
    }

    impl SharedSessionProgress {
        async fn wait_for(&self, stage: HostStage) {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            loop {
                if self.stages.lock().unwrap().contains(&stage) {
                    return;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the host session never reached {stage:?}; stages: {:?}",
                    *self.stages.lock().unwrap()
                );
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }

        async fn wait_for_count(&self, stage: HostStage, count: usize) {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            loop {
                let seen = self
                    .stages
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|seen| **seen == stage)
                    .count();
                if seen >= count {
                    return;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the host session never reached {stage:?} {count} times; stages: {:?}",
                    *self.stages.lock().unwrap()
                );
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    }

    /// The scripted controller: a real yonder endpoint with DCUtR
    /// disabled, so the host's direct-upgrade attempt fails fast and the
    /// pre-auth quiescence settles on the unique relayed connection
    /// (design 0.1.1). It reaches the host through the relay circuit,
    /// resolves the locator over the wire, and drives the OPAQUE client
    /// side with `OpaquePake`.
    struct ScriptedController {
        node: EndpointNode,
        streams: Libp2pApplicationStreams,
        relay: EndpointRelayAddress,
        relay_peer: PeerId,
        pake: OpaquePake,
    }

    impl ScriptedController {
        async fn connect(relay_address: &EndpointRelayAddress) -> Self {
            let relay_peer = relay_address.relay().get();
            let mut node = EndpointNode::with_direct_upgrade(
                Keypair::generate_ed25519(),
                WssTransportConfig::client(None),
                DirectUpgradePolicy::Disabled,
            )
            .unwrap();
            node.listen_on_defaults().unwrap();
            let streams = node.streams().clone();
            let _ = node.dial_relay(relay_address);
            // The resolve substream and the circuit dial both need the
            // relay connection to exist first.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
            loop {
                match tokio::time::timeout_at(deadline, node.next_event()).await {
                    Ok(SwarmEvent::ConnectionEstablished { peer_id, .. })
                        if peer_id == relay_peer =>
                    {
                        break;
                    }
                    Ok(SwarmEvent::OutgoingConnectionError { .. }) => {
                        // The relay may still be starting under parallel
                        // test load; re-dial and keep waiting for the
                        // deadline instead of failing the harness.
                        let _ = node.dial_relay(relay_address);
                    }
                    Ok(_) => {}
                    Err(_) => panic!("the controller never reached the relay"),
                }
            }
            Self {
                node,
                streams,
                relay: relay_address.clone(),
                relay_peer,
                pake: OpaquePake,
            }
        }

        /// Resolves the locator through the in-process relay: the
        /// controller-side lookup of the 0.1.1 session flow, driven over
        /// the real resolve substream protocol.
        async fn resolve_locator(&mut self, locator: Locator) -> PeerId {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            loop {
                let open = self.streams.open(self.relay_peer, RESOLVE_PROTOCOL);
                let stream =
                    match tokio::time::timeout_at(deadline, drive_test_node(&mut self.node, open))
                        .await
                    {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(_)) => {
                            drive_test_node(
                                &mut self.node,
                                tokio::time::sleep(Duration::from_millis(200)),
                            )
                            .await;
                            continue;
                        }
                        Err(_) => panic!("locator resolve substream never opened"),
                    };
                let mut stream = stream.into_tokio();
                let mut response = Vec::new();
                drive_test_node(&mut self.node, async {
                    stream
                        .write_all(&ResolveRequest::new(locator).encode())
                        .await
                        .unwrap();
                    stream.shutdown().await.unwrap();
                    stream.read_to_end(&mut response).await.unwrap();
                })
                .await;
                match ResolveResponse::decode(&response).unwrap() {
                    ResolveResponse::Resolved(peer) => {
                        return PeerId::from_bytes(peer.as_bytes()).unwrap();
                    }
                    ResolveResponse::Unavailable => {
                        drive_test_node(
                            &mut self.node,
                            tokio::time::sleep(Duration::from_millis(200)),
                        )
                        .await;
                    }
                    ResolveResponse::Retry(after) => {
                        drive_test_node(
                            &mut self.node,
                            tokio::time::sleep(Duration::from_millis(u64::from(after.millis()))),
                        )
                        .await;
                    }
                }
            }
        }

        /// Establishes the relayed connection to the host's reservation.
        /// The dial fails while the host has no live reservation (relay
        /// restart recovery), so the attempt is retried with backoff.
        async fn reach_host(&mut self, host: PeerId) {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            loop {
                let _ = self.node.dial(self.relay.circuit_to(host));
                if let Some(()) =
                    tokio::time::timeout_at(deadline, self.wait_for_relayed_connection(host))
                        .await
                        .ok()
                        .flatten()
                {
                    return;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the controller could not reach the host through the relay"
                );
                drive_test_node(
                    &mut self.node,
                    tokio::time::sleep(Duration::from_millis(250)),
                )
                .await;
            }
        }

        async fn wait_for_relayed_connection(&mut self, host: PeerId) -> Option<()> {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                match tokio::time::timeout_at(deadline, self.node.next_event()).await {
                    Ok(SwarmEvent::ConnectionEstablished {
                        peer_id, endpoint, ..
                    }) if peer_id == host && endpoint.is_relayed() => {
                        return Some(());
                    }
                    Ok(_) => {}
                    Err(_) => return None,
                }
            }
        }

        async fn open(&mut self, peer: PeerId, protocol: &'static str) -> ApplicationStream {
            let open = self.streams.open(peer, protocol);
            tokio::pin!(open);
            loop {
                tokio::select! {
                    result = &mut open => {
                        return result.expect("the host must accept the substream");
                    }
                    _ = self.node.next_event() => {}
                }
            }
        }

        /// Sends the OPAQUE client hello and reads the host's response.
        /// Streams that die before any answer (the host was still settling
        /// the pre-auth quiescence and drops early auth starts) are
        /// retried on a fresh substream.
        async fn auth_start(
            &mut self,
            host: PeerId,
            code: &ConnectionCode,
        ) -> Result<AuthStart, ()> {
            let target = peer_id_bytes(host).map_err(|_| ())?;
            let nonce = [0_u8; 32];
            let deadline = tokio::time::Instant::now() + Duration::from_secs(25);
            loop {
                let stream = self.open(host, AUTH_PROTOCOL).await;
                let mut stream = stream.into_tokio();
                let (state, ke1) = self
                    .pake
                    .client_start(&target, code.secret())
                    .map_err(|_| ())?;
                let hello = AuthClientHello::new(nonce, ke1).encode();
                match drive_test_node(&mut self.node, stream.write_all(&hello)).await {
                    Ok(()) => {}
                    Err(_) => {
                        if tokio::time::Instant::now() >= deadline {
                            return Err(());
                        }
                        drive_test_node(
                            &mut self.node,
                            tokio::time::sleep(Duration::from_millis(200)),
                        )
                        .await;
                        continue;
                    }
                }
                drive_test_node(&mut self.node, stream.flush())
                    .await
                    .map_err(|_| ())?;
                let mut tag = [0_u8; 1];
                match tokio::time::timeout_at(
                    deadline,
                    drive_test_node(&mut self.node, stream.read_exact(&mut tag)),
                )
                .await
                {
                    Ok(Ok(_)) => {}
                    _ => {
                        if tokio::time::Instant::now() >= deadline {
                            return Err(());
                        }
                        drive_test_node(
                            &mut self.node,
                            tokio::time::sleep(Duration::from_millis(200)),
                        )
                        .await;
                        continue;
                    }
                }
                let response = match tag[0] {
                    0x01 => {
                        let mut rest = [0_u8; PROCEED_LEN - 1];
                        tokio::time::timeout_at(
                            deadline,
                            drive_test_node(&mut self.node, stream.read_exact(&mut rest)),
                        )
                        .await
                        .map_err(|_| ())?
                        .map_err(|_| ())?;
                        let mut frame = [0_u8; PROCEED_LEN];
                        frame[0] = tag[0];
                        frame[1..].copy_from_slice(&rest);
                        AuthServerResponse::decode(&frame).map_err(|_| ())?
                    }
                    0x02 => {
                        let mut rest = [0_u8; RETRY_LEN - 1];
                        tokio::time::timeout_at(
                            deadline,
                            drive_test_node(&mut self.node, stream.read_exact(&mut rest)),
                        )
                        .await
                        .map_err(|_| ())?
                        .map_err(|_| ())?;
                        let mut frame = [0_u8; RETRY_LEN];
                        frame[0] = tag[0];
                        frame[1..].copy_from_slice(&rest);
                        AuthServerResponse::decode(&frame).map_err(|_| ())?
                    }
                    _other => return Err(()),
                };
                return Ok(AuthStart {
                    state,
                    stream: Box::new(stream),
                    nonce,
                    response,
                    host,
                });
            }
        }

        /// Completes the started exchange: a matching secret confirms the
        /// session key and reads the `Authenticated` acknowledgement; a
        /// mismatched secret cannot confirm, so a bogus KE3 makes the host
        /// reject the attempt cleanly (design 0.1.1).
        async fn finish_auth(
            &mut self,
            started: AuthStart,
            code: &ConnectionCode,
        ) -> Result<AuthServerResponse, ()> {
            let AuthStart {
                state,
                mut stream,
                nonce,
                response,
                host,
            } = started;
            if response.proceed_parts().is_none() {
                return Ok(response);
            }
            let (target_nonce, ke2) = response
                .proceed_parts()
                .expect("the proceed parts were checked above");
            let controller = peer_id_bytes(self.node.peer_id()).map_err(|_| ())?;
            let target = peer_id_bytes(host).map_err(|_| ())?;
            let context =
                PakeContext::new(code.locator(), &controller, &target, &nonce, target_nonce);
            match self.pake.client_finish(state, ke2, context.as_bytes()) {
                Ok((ke3, session_key)) => {
                    drive_test_node(&mut self.node, async {
                        stream.write_all(&ke3).await?;
                        stream.flush().await
                    })
                    .await
                    .map_err(|_| ())?;
                    let mut acknowledgement = [0_u8; 1];
                    tokio::time::timeout(
                        Duration::from_secs(10),
                        drive_test_node(&mut self.node, stream.read_exact(&mut acknowledgement)),
                    )
                    .await
                    .map_err(|_| ())?
                    .map_err(|_| ())?;
                    if acknowledgement != Authenticated::ENCODED {
                        return Err(());
                    }
                    drop(session_key);
                }
                Err(_) => {
                    drive_test_node(&mut self.node, async {
                        stream.write_all(&[0xAB; KE3_LEN]).await?;
                        stream.flush().await
                    })
                    .await
                    .map_err(|_| ())?;
                }
            }
            Ok(response)
        }

        /// One complete OPAQUE client exchange: start, response, and the
        /// KE3 that either confirms the session key or provokes a clean
        /// rejection. The response tells the caller which path ran.
        async fn auth_exchange(
            &mut self,
            host: PeerId,
            code: &ConnectionCode,
        ) -> Result<AuthServerResponse, ()> {
            let started = self.auth_start(host, code).await?;
            self.finish_auth(started, code).await
        }
    }

    /// The in-flight part of one OPAQUE client exchange.
    struct AuthStart {
        state: OpaqueClientState,
        stream: Box<dyn FileSubstreamIo>,
        nonce: [u8; 32],
        response: AuthServerResponse,
        host: PeerId,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum EnterpriseControllerEnding {
        Complete,
        CheckpointThenComplete,
        ControllerDetach,
        AuditFailure,
        AuditStreamEnd,
        AuditFinalizeStreamEnd,
    }

    // This is the aggregate harness bound, not a product timeout. The case
    // deliberately composes relay setup, OPAQUE, terminal startup, two file
    // transfers and bilateral audit finalization, each of which retains its
    // own shorter protocol deadline. Instrumented and contended CI runners
    // need enough aggregate room to exercise that complete sequence.
    const ENTERPRISE_HOST_CASE_TIMEOUT: Duration = Duration::from_secs(300);

    async fn drive_test_node<F: Future>(node: &mut EndpointNode, future: F) -> F::Output {
        tokio::pin!(future);
        loop {
            tokio::select! {
                result = &mut future => return result,
                _ = node.next_event() => {}
            }
        }
    }

    async fn drive_active_audit_checkpoint(
        controller: &mut ScriptedController,
        audit: &AuditObserver,
    ) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut frames = Box::pin(wait_for_audit_frame(Some(audit)));
        let mut local_checkpoint_sent = false;
        let mut local_checkpoint_acknowledged = false;
        let mut peer_checkpoint_received = false;
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    panic!("the bilateral active checkpoint did not converge");
                }
                _ = controller.node.next_event() => {}
                result = tokio::time::timeout(AUDIT_CHECKPOINT_POLL, &mut frames) => {
                    match result {
                        Err(_) => {
                            if !local_checkpoint_sent && audit.checkpoint_due().await {
                                drive_test_node(
                                    &mut controller.node,
                                    audit.send_due_checkpoint(),
                                )
                                .await
                                .unwrap();
                                local_checkpoint_sent = true;
                            }
                        }
                        Ok(Ok(Some(frame))) => {
                            match AuditMessage::decode_frame(&frame).unwrap() {
                                AuditMessage::Checkpoint(_) => peer_checkpoint_received = true,
                                AuditMessage::CheckpointAck(_) => {
                                    local_checkpoint_acknowledged = true;
                                }
                                _ => {}
                            }
                            let event = drive_test_node(
                                &mut controller.node,
                                audit.handle_frame(&frame),
                            )
                            .await
                            .unwrap();
                            assert_eq!(event, FrameEvent::None);
                            frames = Box::pin(wait_for_audit_frame(Some(audit)));
                        }
                        Ok(Ok(None)) => panic!("the active audit stream ended"),
                        Ok(Err(error)) => panic!("the active audit stream failed: {error}"),
                    }
                }
            }
            if local_checkpoint_sent && local_checkpoint_acknowledged && peer_checkpoint_received {
                break;
            }
        }
    }

    /// A backend whose session records controller input on a duplex and
    /// emits one scripted output block before waiting for the shared exit
    /// flag, so a real bridge can drive a full terminal lifecycle.
    struct ScriptedBackend {
        output: Vec<u8>,
        exit_flag: Arc<AtomicBool>,
        exit_code: u32,
        input_write: Mutex<Option<DuplexStream>>,
        resized: Arc<Mutex<Option<TerminalSize>>>,
    }

    impl TerminalBackend for ScriptedBackend {
        type Session = ScriptedSession;

        async fn open(&self, _hello: TerminalHello) -> Result<Self::Session, TerminalError> {
            Ok(ScriptedSession {
                output: self.output.clone(),
                exit_flag: Arc::clone(&self.exit_flag),
                exit_code: self.exit_code,
                input_write: self.input_write.lock().unwrap().take(),
                resized: Arc::clone(&self.resized),
                exited: false,
            })
        }
    }

    struct ScriptedSession {
        output: Vec<u8>,
        exit_flag: Arc<AtomicBool>,
        exit_code: u32,
        input_write: Option<DuplexStream>,
        resized: Arc<Mutex<Option<TerminalSize>>>,
        exited: bool,
    }

    impl TerminalSession for ScriptedSession {
        type Input = DuplexInput;

        fn take_input(&mut self) -> Result<Self::Input, TerminalError> {
            Ok(DuplexInput(
                self.input_write
                    .take()
                    .expect("the scripted session input is taken once"),
            ))
        }

        async fn resize(&mut self, size: TerminalSize) -> Result<(), TerminalError> {
            *self.resized.lock().unwrap() = Some(size);
            Ok(())
        }

        async fn next(&mut self) -> Result<PtyEvent, TerminalError> {
            if !self.output.is_empty() {
                let output = std::mem::take(&mut self.output);
                let mut chunk = TerminalChunk::new();
                chunk.writable()[..output.len()].copy_from_slice(&output);
                chunk.set_len(output.len()).unwrap();
                return Ok(PtyEvent::output(chunk));
            }
            // The shell may only exit after the scripted resize has been
            // applied, so the bridge processes the resize before the
            // completion handshake regardless of select ordering.
            if self.resized.lock().unwrap().is_some()
                && self.exit_flag.load(Ordering::Relaxed)
                && !self.exited
            {
                self.exited = true;
                return Ok(PtyEvent::exited(self.exit_code));
            }
            std::future::pending().await
        }

        async fn shutdown(self) -> Result<(), TerminalError> {
            Ok(())
        }
    }

    // ------------------------------------------------------------------
    // The session-level scenarios. The host runs the real
    // `run_host_session` state machine; the scripted controller proves
    // the session's behaviour over the wire and then the host task is
    // aborted, which is the in-process equivalent of a forced exit.
    // ------------------------------------------------------------------

    #[test]
    fn in_process_host_session_rejects_an_unknown_secret_and_keeps_serving() {
        let _test_guard = crate::in_process_test_guard();
        // The combined host session and audit futures exceed the
        // default test-thread stack; the project pattern runs the
        // scenario on a 64 MiB stack thread.
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let _permit = crate::IN_PROCESS_NETWORK_GUARD.acquire().await;
                    // The host session future is not Send: the production bridge owns
                    // `Box<dyn FileSubstreamIo>` and `Pin<Box<dyn Future>>` trait
                    // objects, so the session runs on a LocalSet instead of a spawned
                    // Send task (the relay service stays a regular Send spawn).
                    let local = tokio::task::LocalSet::new();
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
                let relays = EndpointRelaySet::new(vec![relay_address.clone()]).unwrap();
                let relay = InProcessRelay::start(relay_identity, port);

                let host_identity = Keypair::generate_ed25519();
                let host_peer = host_identity.public().to_peer_id();
                let progress = SharedSessionProgress::default();
                let mut observed = progress.clone();
                let host = tokio::task::spawn_local(async move {
                    run_host_session(
                        HostConfig::new(host_identity, relays, WssTransportConfig::client(None)),
                        TestBackend::session(Arc::new(AtomicUsize::new(0)), false),
                        &mut observed,
                    )
                    .await
                });
                progress.wait_for(HostStage::WaitingForController).await;

                let wrong_code = ConnectionCode::new(
                    Locator::new(1).unwrap(),
                    PakeSecret::from_u64(0x1234).unwrap(),
                );
                let controller = tokio::task::spawn_local(async move {
                    let mut controller = ScriptedController::connect(&relay_address).await;
                    controller.reach_host(host_peer).await;
                    for attempt in 1..=2 {
                        let response = loop {
                            let response = controller
                                .auth_exchange(host_peer, &wrong_code)
                                .await
                                .expect("the host must answer the authentication start");
                            if response.proceed_parts().is_some() {
                                break response;
                            }
                            // The host answers with a transient Retry while it
                            // drains the previous failed exchange; honor a
                            // bounded wait and retry, mirroring the production
                            // controller's retry semantics.
                            tokio::time::sleep(Duration::from_millis(300)).await;
                        };
                        assert!(
                            response.proceed_parts().is_some(),
                            "attempt {attempt} must proceed before the bogus KE3 is rejected"
                        );
                    }
                });

                controller.await.unwrap();
                assert!(
                    !host.is_finished(),
                    "the host session must keep waiting after rejected authentication"
                );
                host.abort();
                relay.stop().await;
                        }),
                    )
                    .await
                    .expect("the in-process rejection scenario must finish");
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }
    #[test]
    fn in_process_host_session_answers_retry_after_the_auth_burst() {
        let _test_guard = crate::in_process_test_guard();
        // The combined host session and audit futures exceed the
        // default test-thread stack; the project pattern runs the
        // scenario on a 64 MiB stack thread.
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
                let relays = EndpointRelaySet::new(vec![relay_address.clone()]).unwrap();
                let relay = InProcessRelay::start(relay_identity, port);

                let host_identity = Keypair::generate_ed25519();
                let host_peer = host_identity.public().to_peer_id();
                let progress = SharedSessionProgress::default();
                let mut observed = progress.clone();
                let host = tokio::task::spawn_local(async move {
                    run_host_session(
                        HostConfig::new(host_identity, relays, WssTransportConfig::client(None)),
                        TestBackend::session(Arc::new(AtomicUsize::new(0)), false),
                        &mut observed,
                    )
                    .await
                });
                progress.wait_for(HostStage::WaitingForController).await;

                // The authentication-start limit is 1/s with a burst of 4
                // (design 0.1.1). One real OPAQUE exchange first proves the
                // quiescence settled; then fast starts with an invalid KE1
                // (rejected without the OPAQUE KSF on either side) drain the
                // burst, and the first start beyond it is answered with Retry.
                let wrong_code = ConnectionCode::new(
                    Locator::new(1).unwrap(),
                    PakeSecret::from_u64(0x5678).unwrap(),
                );
                let controller = tokio::task::spawn_local(async move {
                    let mut controller = ScriptedController::connect(&relay_address).await;
                    controller.reach_host(host_peer).await;
                    let response = controller
                        .auth_exchange(host_peer, &wrong_code)
                        .await
                        .expect("the host must answer the authentication start");
                    assert!(
                        response.proceed_parts().is_some(),
                        "the first attempt must proceed before the bogus KE3 is rejected"
                    );

                    let hello = AuthClientHello::new([0x11; 32], [0xAB; 96]).encode();
                    let mut retry = None;
                    for _ in 0..8 {
                        let mut stream =
                            controller.open(host_peer, AUTH_PROTOCOL).await.into_tokio();
                        stream.write_all(&hello).await.unwrap();
                        stream.flush().await.unwrap();
                        let mut tag = [0_u8; 1];
                        match tokio::time::timeout(
                            Duration::from_secs(10),
                            stream.read_exact(&mut tag),
                        )
                        .await
                        {
                            Ok(Ok(_)) if tag[0] == 0x02 => {
                                let mut rest = [0_u8; RETRY_LEN - 1];
                                stream.read_exact(&mut rest).await.unwrap();
                                let mut frame = [0_u8; RETRY_LEN];
                                frame[0] = tag[0];
                                frame[1..].copy_from_slice(&rest);
                                retry = Some(AuthServerResponse::decode(&frame).unwrap());
                                break;
                            }
                            Ok(Ok(_)) if tag[0] == 0x01 => {
                                let mut rest = [0_u8; PROCEED_LEN - 1];
                                stream.read_exact(&mut rest).await.unwrap();
                                stream.write_all(&[0xAB; KE3_LEN]).await.unwrap();
                                stream.flush().await.unwrap();
                            }
                            _ => {
                                // The invalid KE1 was rejected (or the start
                                // was dropped mid-quiescence): try again.
                            }
                        }
                    }
                    let response =
                        retry.expect("the burst must be exhausted within the fast-start loop");
                    assert!(
                        response.retry_after().is_some(),
                        "a start beyond the burst must be answered with Retry"
                    );
                });

                controller.await.unwrap();
                host.abort();
                relay.stop().await;
                        }),
                    )
                    .await
                    .expect("the in-process rate-limit scenario must finish");
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }
    #[test]
    fn in_process_host_session_answers_an_extra_auth_stream_with_retry() {
        let _test_guard = crate::in_process_test_guard();
        // The combined host session and audit futures exceed the
        // default test-thread stack; the project pattern runs the
        // scenario on a 64 MiB stack thread.
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

                            let host_identity = Keypair::generate_ed25519();
                            let host_peer = host_identity.public().to_peer_id();
                            let progress = SharedSessionProgress::default();
                            let mut observed = progress.clone();
                            let host = tokio::task::spawn_local(async move {
                                run_host_session(
                                    HostConfig::new(
                                        host_identity,
                                        relays,
                                        WssTransportConfig::client(None),
                                    ),
                                    TestBackend::session(Arc::new(AtomicUsize::new(0)), false),
                                    &mut observed,
                                )
                                .await
                            });
                            progress.wait_for(HostStage::WaitingForController).await;

                            // While one auth exchange is in flight, a second auth stream
                            // from the same controller must be answered with Retry and
                            // closed without disturbing the active exchange (design 0.1.1
                            // extra-auth rejection).
                            let wrong_code = ConnectionCode::new(
                                Locator::new(1).unwrap(),
                                PakeSecret::from_u64(0x9ABC).unwrap(),
                            );
                            let controller = tokio::task::spawn_local(async move {
                                let mut controller =
                                    ScriptedController::connect(&relay_address).await;
                                controller.reach_host(host_peer).await;
                                let first = controller
                                    .auth_start(host_peer, &wrong_code)
                                    .await
                                    .expect("the first auth stream must be answered");
                                assert!(
                                    first.response.proceed_parts().is_some(),
                                    "the first stream must proceed"
                                );
                                let extra = controller
                                    .auth_start(host_peer, &wrong_code)
                                    .await
                                    .expect("the extra auth stream must be answered");
                                assert!(
                                    extra.response.retry_after().is_some(),
                                    "the extra auth stream must be answered with Retry"
                                );
                                controller.finish_auth(first, &wrong_code).await.expect(
                                    "the active exchange must finish after the extra rejection",
                                );
                            });

                            controller.await.unwrap();
                            host.abort();
                            relay.stop().await;
                        }),
                    )
                    .await
                    .expect("the in-process extra-auth scenario must finish");
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }
    #[test]
    fn in_process_host_session_recovers_when_the_relay_restarts() {
        let _test_guard = crate::in_process_test_guard();
        // The combined host session and audit futures exceed the
        // default test-thread stack; the project pattern runs the
        // scenario on a 64 MiB stack thread.
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
                            let relay = InProcessRelay::start(relay_identity.clone(), port);

                            let host_identity = Keypair::generate_ed25519();
                            let host_peer = host_identity.public().to_peer_id();
                            let progress = SharedSessionProgress::default();
                            let mut observed = progress.clone();
                            let host = tokio::task::spawn_local(async move {
                                run_host_session(
                                    HostConfig::new(
                                        host_identity,
                                        relays,
                                        WssTransportConfig::client(None),
                                    ),
                                    TestBackend::session(Arc::new(AtomicUsize::new(0)), false),
                                    &mut observed,
                                )
                                .await
                            });
                            progress.wait_for(HostStage::WaitingForController).await;

                            // The relay dies mid-session: the host must notice the lost
                            // lease, reconnect to a restarted relay on the same identity
                            // and port, reclaim the locator, and keep waiting for a
                            // controller (design 0.1.1 relay recovery).
                            relay.stop().await;
                            tokio::time::sleep(Duration::from_millis(300)).await;
                            let relay = InProcessRelay::start(relay_identity, port);
                            progress.wait_for(HostStage::ReconnectingRelay).await;
                            progress
                                .wait_for_count(HostStage::WaitingForController, 3)
                                .await;

                            let wrong_code = ConnectionCode::new(
                                Locator::new(1).unwrap(),
                                PakeSecret::from_u64(0xDEF0).unwrap(),
                            );
                            let controller = tokio::task::spawn_local(async move {
                                let mut controller =
                                    ScriptedController::connect(&relay_address).await;
                                controller.reach_host(host_peer).await;
                                let response = controller
                                    .auth_exchange(host_peer, &wrong_code)
                                    .await
                                    .expect("the recovered session must answer authentication");
                                assert!(
                                    response.proceed_parts().is_some(),
                                    "the recovered session must still serve the exchange"
                                );
                            });

                            controller.await.unwrap();
                            host.abort();
                            relay.stop().await;
                        }),
                    )
                    .await
                    .expect("the in-process relay recovery scenario must finish");
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }
    fn run_enterprise_host_case(ending: EnterpriseControllerEnding) {
        let _test_guard = crate::in_process_test_guard();
        // The combined host and controller futures (with the 0.2.0 audit
        // observer state) exceed the default test-thread stack; the project
        // pattern runs the scenario on a 64 MiB stack thread.
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let local = tokio::task::LocalSet::new();
                    let _permit = crate::IN_PROCESS_NETWORK_GUARD.acquire().await;
                    let stage = Arc::new(Mutex::new("starting"));
                    let scenario_stage = Arc::clone(&stage);
                    let result = tokio::time::timeout(
                        ENTERPRISE_HOST_CASE_TIMEOUT,
                        local.run_until(async move {
                            const EXIT_CODE: u32 = 7;
                            const OUTPUT: &[u8] = b"scripted-host-output";
                            const INPUT: &[u8] = b"scripted-controller-input";
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

                            let upload_directory = tempdir().unwrap();
                            let upload_source = upload_directory.path().join("upload-source.bin");
                            write_pattern_file(&upload_source, 128 * 1024);
                            let upload_bytes = fs::read(&upload_source).unwrap();
                            let destination = upload_directory.path().join("upload-final.bin");
                            let destination = destination.to_str().unwrap().to_owned();
                            let download_source =
                                upload_directory.path().join("download-source.bin");
                            write_pattern_file(&download_source, 64 * 1024);
                            let download_bytes = fs::read(&download_source).unwrap();
                            let download_source = download_source.to_str().unwrap().to_owned();

                            let host_identity = Keypair::generate_ed25519();
                            let host_peer = host_identity.public().to_peer_id();
                            let (input_write, input_read) = tokio::io::duplex(64 * 1024);
                            let exit_flag = Arc::new(AtomicBool::new(false));
                            let input_read = Arc::new(Mutex::new(Some(input_read)));
                            let resized = Arc::new(Mutex::new(None));
                            let backend = ScriptedBackend {
                                output: OUTPUT.to_vec(),
                                exit_flag: Arc::clone(&exit_flag),
                                exit_code: EXIT_CODE,
                                input_write: Mutex::new(Some(input_write)),
                                resized: Arc::clone(&resized),
                            };

                            let (mut driver, mut streams) =
                                build_endpoint(host_identity, WssTransportConfig::client(None))
                                    .unwrap();
                            let relay_connection =
                                connect_relay_with_retry(&mut driver, &relays).await;
                            let listener = driver.reserve(relay_connection.address()).unwrap();
                            let lease =
                                wait_for_reservation(&mut driver, relay_connection, listener)
                                    .await
                                    .unwrap();
                            let locator =
                                allocate_locator(&mut driver, &mut streams, lease.relay())
                                    .await
                                    .unwrap();
                            let target = peer_id_bytes(driver.peer_id()).unwrap();
                            let mut pake = OpaquePake;
                            let (advertised, code) =
                                create_advertisement(locator, &target, &mut pake).unwrap();
                            *scenario_stage.lock().unwrap() = "host-advertised";

                            let mut auth_incoming = streams.accept(AUTH_PROTOCOL).unwrap();
                            let mut data_incoming = streams.accept(TERMINAL_DATA_PROTOCOL).unwrap();
                            let mut control_incoming =
                                streams.accept(TERMINAL_CONTROL_PROTOCOL).unwrap();
                            let mut file_incoming = streams.accept(FILE_TRANSFER_PROTOCOL).unwrap();
                            let mut audit_incoming = streams.accept(AUDIT_PROTOCOL).unwrap();
                            let controller_audit_dir = tempdir().unwrap();
                            let controller_audit_root =
                                controller_audit_dir.path().join("audit");
                            let host_audit_dir = tempdir().unwrap();
                            let host_audit_root = host_audit_dir.path().join("audit");
                            if ending == EnterpriseControllerEnding::CheckpointThenComplete {
                                crate::audit::ledger::Ledger::open(
                                    &controller_audit_root,
                                    &mut OsSecureRandom,
                                )
                                .unwrap();
                                crate::audit::ledger::Ledger::open(
                                    &host_audit_root,
                                    &mut OsSecureRandom,
                                )
                                .unwrap();
                            }
                            let (host_done_tx, mut host_done_rx) = oneshot::channel();

                            let controller_stage = Arc::clone(&scenario_stage);
                            let controller = tokio::task::spawn_local(async move {
                                let mark = |next| {
                                    *controller_stage.lock().unwrap() = next;
                                };
                                let mut controller =
                                    ScriptedController::connect(&relay_address).await;
                                mark("controller-connected");
                                let resolved = controller.resolve_locator(locator).await;
                                assert_eq!(
                                    resolved, host_peer,
                                    "the locator must resolve to the host"
                                );
                                controller.reach_host(host_peer).await;
                                mark("controller-reached-host");
                                let response = controller
                                    .auth_exchange(host_peer, &code)
                                    .await
                                    .expect("the real code must authenticate");
                                assert!(
                                    response.proceed_parts().is_some(),
                                    "the authentication must proceed and confirm"
                                );
                                mark("controller-authenticated");

                                let mut data = controller
                                    .open(host_peer, TERMINAL_DATA_PROTOCOL)
                                    .await
                                    .into_tokio();
                                let mut control = controller
                                    .open(host_peer, TERMINAL_CONTROL_PROTOCOL)
                                    .await
                                    .into_tokio();
                                mark("terminal-streams-open");
                                let hello = TerminalHello::new(
                                    TerminalSize::new(80, 24).unwrap(),
                                    TerminalValue::new("xterm").unwrap(),
                                    TerminalValue::new("truecolor").unwrap(),
                                );
                                drive_test_node(&mut controller.node, async {
                                    control.write_all(hello.encode().as_slice()).await?;
                                    control.flush().await
                                })
                                .await
                                .unwrap();
                                // The mandatory audit handshake (design sections 13 and
                                // 14): the audit substream is opened and the handshake
                                // completes before TerminalReady is awaited.
                                let hello_digest =
                                    Digest32::new(Sha256::digest(hello.encode().as_slice()).into());
                                let audit_stream = controller.open(host_peer, AUDIT_PROTOCOL).await;
                                let controller_peer = controller.node.peer_id();
                                let audit = drive_test_node(
                                    &mut controller.node,
                                    AuditObserver::establish(
                                        audit_stream.into_tokio(),
                                        AuditRole::Controller,
                                        controller_peer,
                                        host_peer,
                                        crate::audit::observer::utc_start_seconds(),
                                        hello_digest,
                                        &controller_audit_root,
                                        &mut OsSecureRandom,
                                    ),
                                )
                                .await
                                .unwrap();
                                mark("audit-established");
                                drive_test_node(
                                    &mut controller.node,
                                    audit.record_terminal_hello(hello_digest),
                                )
                                .await
                                .unwrap();
                                let mut ready = [0_u8; 1];
                                drive_test_node(&mut controller.node, data.read_exact(&mut ready))
                                    .await
                                    .unwrap();
                                assert_eq!(
                                    ready,
                                    TerminalReady::ENCODED,
                                    "the host must flush TerminalReady"
                                );
                                mark("terminal-ready");
                                drive_test_node(
                                    &mut controller.node,
                                    audit.record_terminal_ready(),
                                )
                                .await
                                .unwrap();

                                if ending == EnterpriseControllerEnding::CheckpointThenComplete {
                                    drive_active_audit_checkpoint(&mut controller, &audit).await;
                                }

                                if ending == EnterpriseControllerEnding::ControllerDetach {
                                    let mut output = [0_u8; OUTPUT.len()];
                                    drive_test_node(
                                        &mut controller.node,
                                        data.read_exact(&mut output),
                                    )
                                    .await
                                    .unwrap();
                                    assert_eq!(&output, OUTPUT);
                                    drive_test_node(&mut controller.node, async {
                                        audit.record_raw_output(&output).await?;
                                        audit.record_display_bytes(&output).await?;
                                        audit
                                            .record_display_write_outcome(
                                                true,
                                                output.len() as u64,
                                            )
                                            .await
                                    })
                                    .await
                                    .unwrap();
                                    let finalize = audit.close_and_finalize(
                                        ManifestEnding::CloseReason(
                                            AuditCloseReason::ControllerDetach,
                                        ),
                                        false,
                                        CloseNoticeHandling::Sender(
                                            AuditCloseReason::ControllerDetach,
                                        ),
                                    );
                                    tokio::pin!(finalize);
                                    let mut finalized = false;
                                    let mut host_done = false;
                                    tokio::time::timeout(Duration::from_secs(30), async {
                                        while !finalized || !host_done {
                                            tokio::select! {
                                                result = &mut finalize, if !finalized => {
                                                    result.unwrap();
                                                    finalized = true;
                                                }
                                                result = &mut host_done_rx, if !host_done => {
                                                    result.expect("the host completion signal must arrive");
                                                    host_done = true;
                                                }
                                                _ = controller.node.next_event() => {}
                                            }
                                        }
                                    })
                                    .await
                                    .expect("controller detach must finalize both audit records");
                                    return;
                                }

                                if ending == EnterpriseControllerEnding::AuditFailure {
                                    let fail = audit.fail_closed(
                                        Some(AuditErrorCode::AuditRecordWriteFailed),
                                        AuditCloseReason::AuditFailure,
                                    );
                                    tokio::pin!(fail);
                                    tokio::time::timeout(Duration::from_secs(20), async {
                                        loop {
                                            tokio::select! {
                                                () = &mut fail => break,
                                                _ = controller.node.next_event() => {}
                                            }
                                        }
                                    })
                                    .await
                                    .expect("the controller audit failure notice must be sent");
                                    tokio::time::timeout(Duration::from_secs(30), async {
                                        loop {
                                            tokio::select! {
                                                result = &mut host_done_rx => {
                                                    result.expect("the host completion signal must arrive");
                                                    return;
                                                }
                                                _ = controller.node.next_event() => {}
                                            }
                                        }
                                    })
                                    .await
                                    .expect("the host must fail closed after the audit notice");
                                    return;
                                }
                                if ending == EnterpriseControllerEnding::AuditStreamEnd {
                                    drop(audit);
                                    loop {
                                        tokio::select! {
                                            result = &mut host_done_rx => {
                                                result.expect("the host completion signal must arrive");
                                                return;
                                            }
                                            _ = controller.node.next_event() => {}
                                        }
                                    }
                                }

                                // Controller input is legal only after TerminalReady and
                                // the mandatory audit path remain healthy. The matching
                                // records preserve the host receive chain (section 18.1).
                                drive_test_node(
                                    &mut controller.node,
                                    audit.record_input(INPUT),
                                )
                                .await
                                .unwrap();
                                drive_test_node(&mut controller.node, async {
                                    data.write_all(INPUT).await?;
                                    data.flush().await?;
                                    Ok::<(), std::io::Error>(())
                                })
                                .await
                                .unwrap();
                                drive_test_node(
                                    &mut controller.node,
                                    audit.record_send_outcome(
                                        DIRECTION_CTRL_TO_HOST,
                                        true,
                                        INPUT.len() as u64,
                                    ),
                                )
                                .await
                                .unwrap();
                                mark("terminal-input-sent");

                                // File transfer over the real session connection (0.2.0
                                // file-transfer semantics on the bridge substream queue).
                                // The shared file transfer events are recorded on the
                                // controller side too (design section 18.6).
                                let upload_id = crate::audit::observer::file_transfer_id(
                                    FILE_DIRECTION_UPLOAD,
                                    &destination,
                                    "upload-source.bin",
                                    upload_bytes.len() as u64,
                                );
                                let mut file = controller
                                    .open(host_peer, FILE_TRANSFER_PROTOCOL)
                                    .await
                                    .into_tokio();
                                drive_test_node(
                                    &mut controller.node,
                                    send_wire_frame(
                                        &mut file,
                                        &FileTransferMessage::UploadOpen {
                                            destination: &destination,
                                            file_name: "upload-source.bin",
                                            declared_size: upload_bytes.len() as u64,
                                        },
                                    ),
                                )
                                .await;
                                let upload_start = FileTransferFacts {
                                    transfer_id: upload_id,
                                    direction: FILE_DIRECTION_UPLOAD,
                                    kind: FILE_KIND_START,
                                    declared_size: upload_bytes.len() as u64,
                                    final_size: 0,
                                    digest: Digest32::new([0; 32]),
                                    remote_path: &destination,
                                    file_name: "upload-source.bin",
                                    error_code: 0,
                                };
                                drive_test_node(
                                    &mut controller.node,
                                    audit.record_file_transfer(&upload_start, None),
                                )
                                .await
                                .unwrap();
                                drive_test_node(
                                    &mut controller.node,
                                    expect_wire_control(&mut file, &FileTransferMessage::Ready),
                                )
                                .await;
                                mark("upload-ready");
                                for chunk in upload_bytes.chunks(65536) {
                                    drive_test_node(
                                        &mut controller.node,
                                        send_wire_data(&mut file, chunk),
                                    )
                                    .await;
                                }
                                drive_test_node(
                                    &mut controller.node,
                                    send_wire_frame(
                                        &mut file,
                                        &FileTransferMessage::Finish {
                                            actual_size: upload_bytes.len() as u64,
                                            digest: sha256_bytes(&upload_bytes),
                                        },
                                    ),
                                )
                                .await;
                                drive_test_node(
                                    &mut controller.node,
                                    expect_wire_control(&mut file, &FileTransferMessage::Committed),
                                )
                                .await;
                                mark("upload-committed");
                                let upload_end = FileTransferFacts {
                                    transfer_id: upload_id,
                                    direction: FILE_DIRECTION_UPLOAD,
                                    kind: FILE_KIND_SUCCESS,
                                    declared_size: upload_bytes.len() as u64,
                                    final_size: upload_bytes.len() as u64,
                                    digest: Digest32::new(*sha256_bytes(&upload_bytes).as_bytes()),
                                    remote_path: &destination,
                                    file_name: "upload-source.bin",
                                    error_code: 0,
                                };
                                drive_test_node(
                                    &mut controller.node,
                                    audit.record_file_transfer(&upload_end, None),
                                )
                                .await
                                .unwrap();
                                mark("upload-audit-recorded");
                                drop(file);

                                let mut file = controller
                                    .open(host_peer, FILE_TRANSFER_PROTOCOL)
                                    .await
                                    .into_tokio();
                                mark("download-stream-opened");
                                drive_test_node(
                                    &mut controller.node,
                                    send_wire_frame(
                                        &mut file,
                                        &FileTransferMessage::DownloadOpen {
                                            source: &download_source,
                                        },
                                    ),
                                )
                                .await;
                                let offer = drive_test_node(
                                    &mut controller.node,
                                    read_wire_frame(&mut file),
                                )
                                .await;
                                mark("download-offered");
                                let download_name =
                                    match FileTransferMessage::decode_frame(&offer).unwrap() {
                                        FileTransferMessage::DownloadOffer {
                                            file_name,
                                            declared_size,
                                        } => {
                                            assert_eq!(declared_size, download_bytes.len() as u64);
                                            file_name.to_owned()
                                        }
                                        other => panic!("expected DownloadOffer, got {other:?}"),
                                    };
                                let download_id = crate::audit::observer::file_transfer_id(
                                    FILE_DIRECTION_DOWNLOAD,
                                    &download_source,
                                    &download_name,
                                    download_bytes.len() as u64,
                                );
                                let download_start = FileTransferFacts {
                                    transfer_id: download_id,
                                    direction: FILE_DIRECTION_DOWNLOAD,
                                    kind: FILE_KIND_START,
                                    declared_size: download_bytes.len() as u64,
                                    final_size: 0,
                                    digest: Digest32::new([0; 32]),
                                    remote_path: &download_source,
                                    file_name: &download_name,
                                    error_code: 0,
                                };
                                drive_test_node(
                                    &mut controller.node,
                                    audit.record_file_transfer(&download_start, None),
                                )
                                .await
                                .unwrap();
                                drive_test_node(
                                    &mut controller.node,
                                    send_wire_frame(&mut file, &FileTransferMessage::Ready),
                                )
                                .await;
                                let received = drive_test_node(
                                    &mut controller.node,
                                    receive_download_bytes(
                                        &mut file,
                                        download_bytes.len() as u64,
                                    ),
                                )
                                .await;
                                mark("download-received");
                                drive_test_node(
                                    &mut controller.node,
                                    send_wire_frame(&mut file, &FileTransferMessage::Committed),
                                )
                                .await;
                                let download_end = FileTransferFacts {
                                    transfer_id: download_id,
                                    direction: FILE_DIRECTION_DOWNLOAD,
                                    kind: FILE_KIND_SUCCESS,
                                    declared_size: download_bytes.len() as u64,
                                    final_size: download_bytes.len() as u64,
                                    digest: Digest32::new(
                                        *sha256_bytes(&download_bytes).as_bytes(),
                                    ),
                                    remote_path: &download_source,
                                    file_name: &download_name,
                                    error_code: 0,
                                };
                                drive_test_node(
                                    &mut controller.node,
                                    audit.record_file_transfer(&download_end, None),
                                )
                                .await
                                .unwrap();
                                drop(file);
                                assert_eq!(
                                    received, download_bytes,
                                    "the downloaded bytes must match"
                                );
                                mark("file-transfers-complete");

                                // The pty output, one resize, and the controller-completion
                                // handshake that lets the host return the exit code.
                                let mut output = [0_u8; OUTPUT.len()];
                                drive_test_node(
                                    &mut controller.node,
                                    data.read_exact(&mut output),
                                )
                                .await
                                .unwrap();
                                assert_eq!(&output, OUTPUT);
                                mark("terminal-output-received");
                                // The controller output records (design section 18.4) so
                                // the shared chains match the host's send records.
                                drive_test_node(&mut controller.node, async {
                                    audit.record_raw_output(&output).await?;
                                    audit.record_display_bytes(&output).await?;
                                    audit
                                        .record_display_write_outcome(true, output.len() as u64)
                                        .await
                                })
                                .await
                                .unwrap();
                                let resize = TerminalSize::new(100, 30).unwrap();
                                drive_test_node(
                                    &mut controller.node,
                                    audit.record_resize(
                                        DIRECTION_CTRL_TO_HOST,
                                        resize.columns(),
                                        resize.rows(),
                                    ),
                                )
                                .await
                                .unwrap();
                                drive_test_node(&mut controller.node, async {
                                    control
                                        .write_all(&TerminalResize::new(resize).encode())
                                        .await?;
                                    control.flush().await
                                })
                                .await
                                .unwrap();
                                exit_flag.store(true, Ordering::Relaxed);
                                let mut exit = [0_u8; 5];
                                drive_test_node(
                                    &mut controller.node,
                                    control.read_exact(&mut exit),
                                )
                                .await
                                .unwrap();
                                assert_eq!(TerminalExit::decode(&exit).unwrap().code(), EXIT_CODE);
                                mark("terminal-exit-received");
                                drive_test_node(&mut controller.node, async {
                                    audit.record_terminal_exit(EXIT_CODE as u8).await?;
                                    audit.record_terminal_complete().await
                                })
                                .await
                                .unwrap();
                                drive_test_node(&mut controller.node, async {
                                    control.write_all(&TerminalComplete::ENCODED).await?;
                                    control.flush().await
                                })
                                .await
                                .unwrap();
                                let mut trailing = [0_u8; 1];
                                assert_eq!(
                                    drive_test_node(
                                        &mut controller.node,
                                        control.read(&mut trailing),
                                    )
                                    .await
                                    .unwrap(),
                                    0,
                                    "the host must shut down the control half after the completion"
                                );
                                assert_eq!(
                                    drive_test_node(
                                        &mut controller.node,
                                        data.read(&mut trailing),
                                    )
                                    .await
                                    .unwrap(),
                                    0,
                                    "the host must shut down the data half after the shell exit"
                                );
                                mark("terminal-streams-closed");
                                if ending == EnterpriseControllerEnding::AuditFinalizeStreamEnd {
                                    drop(audit);
                                    loop {
                                        tokio::select! {
                                            result = &mut host_done_rx => {
                                                result.expect("the host completion signal must arrive");
                                                return;
                                            }
                                            _ = controller.node.next_event() => {}
                                        }
                                    }
                                }
                                // The mandatory audit finalization (design sections 21
                                // and 22.1). The scripted endpoint node is polled
                                // throughout so the peer's finalization frames arrive.
                                let finalize = audit.close_and_finalize(
                                    ManifestEnding::ShellExit(EXIT_CODE as u8),
                                    true,
                                    CloseNoticeHandling::Sender(AuditCloseReason::NormalShellExit),
                                );
                                tokio::pin!(finalize);
                                loop {
                                    tokio::select! {
                                        result = &mut finalize => {
                                            result.unwrap();
                                            break;
                                        }
                                        _ = controller.node.next_event() => {}
                                    }
                                }
                                mark("audit-finalized");
                                loop {
                                    tokio::select! {
                                        result = &mut host_done_rx => {
                                            result.expect("the host completion signal must arrive");
                                            break;
                                        }
                                        _ = controller.node.next_event() => {}
                                    }
                                }
                                mark("host-completed");
                            });

                            let mut progress = NoopProgress;
                            let mut session = HostSession {
                                driver: &mut driver,
                                streams: &mut streams,
                                auth_incoming: &mut auth_incoming,
                                data_incoming: &mut data_incoming,
                                control_incoming: &mut control_incoming,
                                file_incoming: &mut file_incoming,
                                audit_incoming: &mut audit_incoming,
                                relays: &relays,
                                relay_lease: lease,
                                relay_access: RelayAccessMode::Enterprise,
                                advertised,
                                target,
                                pake: &mut pake,
                                backend: &backend,
                                audit_root_override: Some(host_audit_root),
                            };
                            let session_result = session.run(&mut progress).await;
                            drop(session);
                            host_done_tx
                                .send(())
                                .expect("the scripted controller must remain alive");
                            match ending {
                                EnterpriseControllerEnding::Complete
                                | EnterpriseControllerEnding::CheckpointThenComplete => {
                                    assert_eq!(
                                        session_result.unwrap(),
                                        EXIT_CODE,
                                        "the shell exit code must reach the host"
                                    );
                                }
                                EnterpriseControllerEnding::AuditFailure
                                | EnterpriseControllerEnding::AuditStreamEnd => {
                                    assert!(matches!(
                                        session_result,
                                        Err(HostError::Audit(AuditError::FailedClosed))
                                    ));
                                }
                                EnterpriseControllerEnding::AuditFinalizeStreamEnd => {
                                    assert!(matches!(session_result, Err(HostError::Audit(_))));
                                }
                                EnterpriseControllerEnding::ControllerDetach => {
                                    assert!(
                                        matches!(&session_result, Err(HostError::ConnectionLost)),
                                        "unexpected host result: {session_result:?}"
                                    );
                                }
                            }

                            controller
                                .await
                                .expect("the scripted controller must finish");
                            *scenario_stage.lock().unwrap() = "controller-joined";
                            if matches!(
                                ending,
                                EnterpriseControllerEnding::Complete
                                    | EnterpriseControllerEnding::CheckpointThenComplete
                                    | EnterpriseControllerEnding::AuditFinalizeStreamEnd
                            ) {
                                assert_eq!(
                                    *resized.lock().unwrap(),
                                    Some(TerminalSize::new(100, 30).unwrap()),
                                    "the resize must reach the session before the completion"
                                );
                            } else {
                                assert!(resized.lock().unwrap().is_none());
                            }

                            let mut recorded = Vec::new();
                            let mut captured_input = input_read
                                .lock()
                                .unwrap()
                                .take()
                                .expect("the input capture exists");
                            captured_input.read_to_end(&mut recorded).await.unwrap();
                            if matches!(
                                ending,
                                EnterpriseControllerEnding::Complete
                                    | EnterpriseControllerEnding::CheckpointThenComplete
                                    | EnterpriseControllerEnding::AuditFinalizeStreamEnd
                            ) {
                                assert_eq!(
                                    recorded, INPUT,
                                    "the controller input must reach the session"
                                );
                            } else {
                                assert!(recorded.is_empty());
                            }

                            relay.stop().await;
                            *scenario_stage.lock().unwrap() = "relay-stopped";
                        }),
                    )
                    .await;
                    if result.is_err() {
                        panic!(
                            "the in-process happy path must finish (last stage: {})",
                            *stage.lock().unwrap()
                        );
                    }
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn in_process_controller_completes_an_authenticated_terminal_session() {
        run_enterprise_host_case(EnterpriseControllerEnding::Complete);
    }

    #[test]
    fn in_process_host_checkpoints_while_active() {
        run_enterprise_host_case(EnterpriseControllerEnding::CheckpointThenComplete);
    }

    #[test]
    fn in_process_host_finalizes_a_controller_detach() {
        run_enterprise_host_case(EnterpriseControllerEnding::ControllerDetach);
    }

    #[test]
    fn in_process_host_rejects_incomplete_audit_finalization() {
        run_enterprise_host_case(EnterpriseControllerEnding::AuditFinalizeStreamEnd);
    }

    #[test]
    fn in_process_host_fails_closed_with_the_controller_audit() {
        run_enterprise_host_case(EnterpriseControllerEnding::AuditFailure);
    }

    #[test]
    fn in_process_host_fails_closed_when_the_audit_stream_ends() {
        run_enterprise_host_case(EnterpriseControllerEnding::AuditStreamEnd);
    }

    #[test]
    fn in_process_standard_host_completes_a_terminal_session() {
        let _test_guard = crate::in_process_test_guard();
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
                        Duration::from_secs(90),
                        local.run_until(async {
                            const EXIT_CODE: u32 = 23;
                            const OUTPUT: &[u8] = b"standard-host-output";
                            const INPUT: &[u8] = b"standard-controller-input";

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

                            let host_identity = Keypair::generate_ed25519();
                            let host_peer = host_identity.public().to_peer_id();
                            let (input_write, input_read) = tokio::io::duplex(64 * 1024);
                            let exit_flag = Arc::new(AtomicBool::new(false));
                            let input_read = Arc::new(Mutex::new(Some(input_read)));
                            let resized = Arc::new(Mutex::new(None));
                            let backend = ScriptedBackend {
                                output: OUTPUT.to_vec(),
                                exit_flag: Arc::clone(&exit_flag),
                                exit_code: EXIT_CODE,
                                input_write: Mutex::new(Some(input_write)),
                                resized: Arc::clone(&resized),
                            };

                            let (mut driver, mut streams) =
                                build_endpoint(host_identity, WssTransportConfig::client(None))
                                    .unwrap();
                            let relay_connection =
                                connect_relay_with_retry(&mut driver, &relays).await;
                            let listener = driver.reserve(relay_connection.address()).unwrap();
                            let lease =
                                wait_for_reservation(&mut driver, relay_connection, listener)
                                    .await
                                    .unwrap();
                            let locator =
                                allocate_locator(&mut driver, &mut streams, lease.relay())
                                    .await
                                    .unwrap();
                            let target = peer_id_bytes(driver.peer_id()).unwrap();
                            let mut pake = OpaquePake;
                            let (advertised, code) =
                                create_advertisement(locator, &target, &mut pake).unwrap();

                            let mut auth_incoming = streams.accept(AUTH_PROTOCOL).unwrap();
                            let mut data_incoming = streams.accept(TERMINAL_DATA_PROTOCOL).unwrap();
                            let mut control_incoming =
                                streams.accept(TERMINAL_CONTROL_PROTOCOL).unwrap();
                            let mut file_incoming = streams.accept(FILE_TRANSFER_PROTOCOL).unwrap();
                            let mut audit_incoming = streams.accept(AUDIT_PROTOCOL).unwrap();

                            let controller = tokio::task::spawn_local(async move {
                                let mut controller =
                                    ScriptedController::connect(&relay_address).await;
                                assert_eq!(controller.resolve_locator(locator).await, host_peer);
                                controller.reach_host(host_peer).await;
                                let response = controller
                                    .auth_exchange(host_peer, &code)
                                    .await
                                    .expect("the real code must authenticate");
                                assert!(response.proceed_parts().is_some());

                                let mut data = controller
                                    .open(host_peer, TERMINAL_DATA_PROTOCOL)
                                    .await
                                    .into_tokio();
                                let mut control = controller
                                    .open(host_peer, TERMINAL_CONTROL_PROTOCOL)
                                    .await
                                    .into_tokio();
                                let hello = TerminalHello::new(
                                    TerminalSize::new(80, 24).unwrap(),
                                    TerminalValue::new("xterm").unwrap(),
                                    TerminalValue::new("truecolor").unwrap(),
                                );
                                control.write_all(hello.encode().as_slice()).await.unwrap();
                                control.flush().await.unwrap();

                                let mut ready = [0_u8; 1];
                                data.read_exact(&mut ready).await.unwrap();
                                assert_eq!(ready, TerminalReady::ENCODED);
                                let mut output = [0_u8; OUTPUT.len()];
                                data.read_exact(&mut output).await.unwrap();
                                assert_eq!(&output, OUTPUT);
                                data.write_all(INPUT).await.unwrap();
                                data.flush().await.unwrap();

                                let size = TerminalSize::new(100, 30).unwrap();
                                control
                                    .write_all(&TerminalResize::new(size).encode())
                                    .await
                                    .unwrap();
                                control.flush().await.unwrap();
                                exit_flag.store(true, Ordering::Relaxed);
                                let mut exit = [0_u8; 5];
                                control.read_exact(&mut exit).await.unwrap();
                                assert_eq!(TerminalExit::decode(&exit).unwrap().code(), EXIT_CODE);
                                control.write_all(&TerminalComplete::ENCODED).await.unwrap();
                                control.flush().await.unwrap();

                                let mut trailing = [0_u8; 1];
                                assert_eq!(control.read(&mut trailing).await.unwrap(), 0);
                                assert_eq!(data.read(&mut trailing).await.unwrap(), 0);
                            });

                            let mut progress = NoopProgress;
                            let mut session = HostSession {
                                driver: &mut driver,
                                streams: &mut streams,
                                auth_incoming: &mut auth_incoming,
                                data_incoming: &mut data_incoming,
                                control_incoming: &mut control_incoming,
                                file_incoming: &mut file_incoming,
                                audit_incoming: &mut audit_incoming,
                                relays: &relays,
                                relay_lease: lease,
                                relay_access: RelayAccessMode::Standard,
                                advertised,
                                target,
                                pake: &mut pake,
                                backend: &backend,
                                audit_root_override: None,
                            };
                            assert_eq!(session.run(&mut progress).await.unwrap(), EXIT_CODE);
                            controller.await.unwrap();
                            assert_eq!(
                                *resized.lock().unwrap(),
                                Some(TerminalSize::new(100, 30).unwrap())
                            );
                            let mut recorded = Vec::new();
                            let mut captured_input = input_read.lock().unwrap().take().unwrap();
                            captured_input.read_to_end(&mut recorded).await.unwrap();
                            assert_eq!(recorded, INPUT);
                            relay.stop().await;
                        }),
                    )
                    .await
                    .expect("the standard host session must finish");
                });
            })
            .unwrap()
            .join()
            .unwrap();
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
    #[error("the relay did not advertise a supported access policy")]
    RelayAccessUnavailable,
    #[error("the relay access policy changed while recovering the host connection")]
    RelayAccessChanged,
    #[error("a required inbound application protocol registration ended")]
    ProtocolRegistrationEnded,
    #[error("the host was interrupted")]
    Interrupted,
    #[error("failed to report the connection code")]
    Output(#[source] std::io::Error),
    #[error(transparent)]
    Audit(#[from] AuditError),
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
    let mut file_incoming = streams.accept(FILE_TRANSFER_PROTOCOL)?;
    let mut audit_incoming = streams.accept(AUDIT_PROTOCOL)?;
    let target = peer_id_bytes(driver.peer_id()).map_err(|_| HostError::PeerIdentity)?;
    let mut pake = OpaquePake;
    let (relay_lease, advertised, relay_access) = initialize_host_relay(
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
        file_incoming: &mut file_incoming,
        audit_incoming: &mut audit_incoming,
        relays: &relays,
        relay_lease,
        relay_access,
        advertised,
        target,
        pake: &mut pake,
        backend: &backend,
        audit_root_override: None,
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
) -> Result<(ReservationLease, AdvertisedLease, RelayAccessMode), HostError> {
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
        let access = match wait_for_relay_access(driver, candidate.relay().peer()).await {
            Ok(access) => access,
            Err(error) => {
                tracing::debug!(%error, "relay access policy discovery will be retried");
                driver.remove_reservation(candidate.listener());
                wait_for_host_retry(&mut backoff, HostStage::ConnectingRelay, progress).await?;
                continue;
            }
        };
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
            Ok(advertised) => return Ok((candidate, advertised, access)),
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

async fn wait_for_relay_access(
    driver: &mut EndpointDriver,
    relay: PeerId,
) -> Result<RelayAccessMode, HostError> {
    tokio::time::timeout(EXCHANGE_TIMEOUT, async {
        loop {
            if let Some(mode) = driver.relay_access_mode(&relay) {
                return Ok(mode);
            }
            let _ = driver.next().await;
            if driver.connection_count(&relay) == 0 {
                return Err(HostError::RelayAccessUnavailable);
            }
        }
    })
    .await
    .map_err(|_| HostError::RelayAccessUnavailable)?
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
    access: RelayAccessMode,
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
            let candidate_access = match wait_for_relay_access(
                self.driver,
                candidate.relay().peer(),
            )
            .await
            {
                Ok(access) => access,
                Err(error) => {
                    tracing::debug!(%error, "relay access policy discovery failed during recovery");
                    self.driver.remove_reservation(candidate.listener());
                    wait_for_host_retry(&mut backoff, HostStage::ReconnectingRelay, progress)
                        .await?;
                    continue;
                }
            };
            if candidate_access != self.access {
                self.driver.remove_reservation(candidate.listener());
                return Err(HostError::RelayAccessChanged);
            }
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
    file_incoming: &'a mut IncomingApplicationStreams,
    audit_incoming: &'a mut IncomingApplicationStreams,
    relays: &'a EndpointRelaySet,
    relay_lease: ReservationLease,
    relay_access: RelayAccessMode,
    advertised: AdvertisedLease,
    target: PeerIdBytes,
    pake: &'a mut OpaquePake,
    backend: &'a B,
    /// Test and embedding seam for isolating audit artifacts. Production
    /// sessions leave this unset and use the platform audit directory.
    audit_root_override: Option<PathBuf>,
}

struct InboundProtocols<'a> {
    auth: &'a mut IncomingApplicationStreams,
    data: &'a mut IncomingApplicationStreams,
    control: &'a mut IncomingApplicationStreams,
    file: &'a mut IncomingApplicationStreams,
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
            file_incoming,
            audit_incoming,
            relays,
            relay_lease,
            relay_access,
            advertised,
            target,
            pake,
            backend,
            audit_root_override,
        } = self;
        let limiter = DirectRateLimiter::new(RateLimit::authentication());
        let mut session = TargetSession::new();
        let mut incoming = InboundProtocols {
            auth: auth_incoming,
            data: data_incoming,
            control: control_incoming,
            file: file_incoming,
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
                    access: *relay_access,
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

            let self_peer = driver.peer_id();
            let audit_root = match relay_access {
                RelayAccessMode::Standard => None,
                RelayAccessMode::Enterprise => Some(match audit_root_override.as_ref() {
                    Some(root) => root.clone(),
                    None => crate::audit::observer::platform_audit_root()?,
                }),
            };
            let result = drive_session_inputs(
                driver,
                binding,
                &mut incoming,
                start_terminal(
                    *backend,
                    data,
                    control,
                    audit_incoming,
                    binding,
                    self_peer,
                    *relay_access,
                    audit_root.as_deref(),
                ),
            )
            .await;
            let (mut pty, base, data, control, audit) = match result {
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

            let outcome = bridge_terminal(
                driver,
                binding,
                &mut incoming,
                &mut pty,
                data,
                control,
                base.as_ref(),
                audit.as_ref(),
            )
            .await;
            if let Err(error) = &outcome {
                tracing::debug!(%error, "terminal bridge failed before shell completion");
            }
            let shutdown = pty.shutdown().await;
            match outcome {
                Ok(code) => {
                    // The mandatory audit finalization runs before the
                    // session ends (design sections 21 and 22.1); a
                    // finalization failure is never hidden behind the shell
                    // exit code.
                    // The finalization exchange reads and writes the audit
                    // substream, so the endpoint driver is polled
                    // throughout (drive_bound); without it the peer's
                    // finalization frames would never be delivered.
                    let finalized = match audit.as_ref() {
                        Some(audit) => {
                            drive_bound(
                                driver,
                                binding,
                                audit.close_and_finalize(
                                    ManifestEnding::ShellExit(code as u8),
                                    true,
                                    CloseNoticeHandling::Receiver,
                                ),
                            )
                            .await
                        }
                        None => Ok(Ok(())),
                    };
                    match finalized {
                        Ok(Ok(())) => {
                            session.apply(SessionEvent::ShellExited)?;
                            shutdown?;
                            return Ok(code);
                        }
                        Ok(Err(error)) => {
                            session.apply(SessionEvent::ConnectionLost)?;
                            if let Err(cleanup) = shutdown {
                                tracing::warn!(%cleanup, "terminal cleanup failed after the audit finalization error");
                            }
                            return Err(HostError::Audit(error));
                        }
                        Err(endpoint) => {
                            session.apply(SessionEvent::ConnectionLost)?;
                            if let Err(cleanup) = shutdown {
                                tracing::warn!(%cleanup, "terminal cleanup failed after the audit finalization error");
                            }
                            return Err(endpoint.into());
                        }
                    }
                }
                Err(error) => {
                    // The interrupted close: the peer's audit failure was
                    // already handled by the bridge; every other failure
                    // completes the local tail without a manifest (design
                    // section 22.4).
                    if !matches!(error, HostError::Audit(_))
                        && let Some(audit) = audit.as_ref()
                    {
                        audit
                            .close_interrupted(AuditCloseReason::ConnectionLost)
                            .await;
                    }
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
            stream = incoming.file.next() => {
                // The session is not Active yet; file requests are invalid
                // and are dropped without creating any transfer state
                // (design 9.2: only Active sessions accept file substreams).
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
            stream = incoming.file.next() => drop(stream.ok_or(HostError::ProtocolRegistrationEnded)?),
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
            stream = incoming.file.next() => {
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
            stream = incoming.file.next() => {
                // The session is not Active yet (TerminalReady has not been
                // flushed); file requests are dropped without state.
                drop(stream.ok_or(HostError::ProtocolRegistrationEnded)?);
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

#[allow(clippy::too_many_arguments)]
async fn start_terminal<B: TerminalBackend>(
    backend: &B,
    mut data: ApplicationStream,
    mut control: ApplicationStream,
    audit_incoming: &mut IncomingApplicationStreams,
    binding: ConnectionBinding,
    self_peer: PeerId,
    access: RelayAccessMode,
    audit_root: Option<&Path>,
) -> Result<
    (
        B::Session,
        Option<BaseDirectory>,
        ApplicationStream,
        ApplicationStream,
        Option<AuditObserver>,
    ),
    HostError,
> {
    // 1. The terminal hello (bounded), which the controller conveyed before
    //    the audit handshake so both sides share its digest (design
    //    section 13.5).
    let hello = {
        let mut control_io = (&mut control).compat();
        tokio::time::timeout(EXCHANGE_TIMEOUT, read_terminal_hello_io(&mut control_io))
            .await
            .map_err(|_| HostError::Timeout)??
    };
    let digest = Digest32::new(Sha256::digest(hello.encode().as_slice()).into());
    let audit = match access {
        RelayAccessMode::Standard => None,
        RelayAccessMode::Enterprise => {
            let audit_root = audit_root.ok_or(HostError::RelayAccessUnavailable)?;
            let audit_stream = match tokio::time::timeout(EXCHANGE_TIMEOUT, async {
                loop {
                    let (peer, stream) = audit_incoming
                        .next()
                        .await
                        .ok_or(HostError::ProtocolRegistrationEnded)?;
                    if peer == binding.peer() {
                        return Ok::<_, HostError>(stream);
                    }
                    drop(stream);
                }
            })
            .await
            {
                Ok(stream) => stream?,
                Err(_) => return Err(HostError::Audit(AuditError::peer_unsupported())),
            };
            let audit = tokio::time::timeout(
                AUDIT_ESTABLISH_TIMEOUT,
                AuditObserver::establish(
                    audit_stream.into_tokio(),
                    AuditRole::Host,
                    binding.peer(),
                    self_peer,
                    crate::audit::observer::utc_start_seconds(),
                    digest,
                    audit_root,
                    &mut OsSecureRandom,
                ),
            )
            .await
            .map_err(|_| HostError::Timeout)??;
            audit.record_terminal_hello(digest).await?;
            Some(audit)
        }
    };
    // 3. The remote terminal is only opened and made active after the
    //    audit handshake (design section 13.2).
    let pty = {
        let mut data_io = (&mut data).compat();
        let pty = backend.open(hello).await?;
        if let Some(audit) = audit.as_ref()
            && let Err(error) = audit.record_terminal_ready().await
        {
            if let Err(cleanup) = pty.shutdown().await {
                tracing::warn!(%cleanup, "failed to clean up PTY after the audit failure");
            }
            return Err(error.into());
        }
        if let Err(error) = write_terminal_ready_io(&mut data_io).await {
            if let Err(cleanup) = pty.shutdown().await {
                tracing::warn!(%cleanup, "failed to clean up PTY after TerminalReady failure");
            }
            return Err(error);
        }
        pty
    };
    // 4. The session base directory is captured once, when the session
    //    shell starts; every remote path resolves against it for the whole
    //    session (design 8.5). The shell spawns with the process working
    //    directory (design 21), so the capture equals the shell's initial
    //    directory. The portable-pty session does not expose the directory,
    //    so the process working directory is captured here instead. If the
    //    working directory is unavailable (for example deleted), the
    //    terminal session continues and every file request fails closed
    //    without state.
    let base = match BaseDirectory::capture() {
        Ok(base) => Some(base),
        Err(error) => {
            tracing::debug!(%error, "host session base directory is unavailable; file transfers are refused");
            None
        }
    };
    Ok((pty, base, data, control, audit))
}

#[cfg(test)]
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

async fn wait_for_audit_frame(
    audit: Option<&AuditObserver>,
) -> Result<Option<Vec<u8>>, AuditError> {
    match audit {
        Some(audit) => audit.wait_for_frame().await,
        None => std::future::pending().await,
    }
}

#[allow(clippy::too_many_arguments)]
async fn bridge_terminal<S: TerminalSession>(
    driver: &mut EndpointDriver,
    binding: ConnectionBinding,
    incoming: &mut InboundProtocols<'_>,
    pty: &mut S,
    data: ApplicationStream,
    control: ApplicationStream,
    base: Option<&BaseDirectory>,
    audit: Option<&AuditObserver>,
) -> Result<u32, HostError> {
    let (mut data_read, mut data_write) = tokio::io::split(data.into_tokio());
    let (mut control_read, mut control_write) = tokio::io::split(control.into_tokio());
    let mut pty_input = pty.take_input()?;
    // One cancellation flag shared with the file coordinator: any session
    // ending (shell exit, connection loss, shutdown signal) sets it so the
    // active transfer aborts promptly and no uncommitted target appears
    // (design 16.4, 16.5).
    let cancel = Arc::new(AtomicBool::new(false));
    let config = TransferConfig::defaults();
    let (file_sender, file_receiver) = mpsc::channel::<FileSubstreamIoBox>(FILE_SUBSTREAM_QUEUE);
    let mut file_coordinator = Box::pin(file_substream_coordinator(
        file_receiver,
        base,
        Arc::clone(&cancel),
        &config,
        audit,
    ));
    let result = {
        let controller_input = copy_controller_input(&mut data_read, &mut pty_input, audit);
        let terminal_output = copy_terminal_output(
            pty,
            &mut data_write,
            &mut control_read,
            &mut control_write,
            audit,
        );
        let mut audit_frames = Box::pin(wait_for_audit_frame(audit));
        tokio::pin!(controller_input);
        tokio::pin!(terminal_output);
        loop {
            driver.enforce_binding(binding)?;
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
            stream = incoming.file.next() => {
                let (peer, stream) = stream.ok_or(HostError::ProtocolRegistrationEnded)?;
                if peer != binding.peer() {
                    // Only the authenticated controller of this session may
                    // open file substreams (design 9.2); other peers are
                    // rejected without any state.
                    drop(stream);
                } else {
                    // The boxed substream is dropped (closing it) when the
                    // bounded queue is full: the coordinator serves one
                    // transfer and at most one busy reply at a time
                    // (design 15.1, 15.3).
                    let _ = file_sender.try_send(Box::new(stream.into_tokio()));
                }
            }
            result = tokio::time::timeout(AUDIT_CHECKPOINT_POLL, &mut audit_frames),
                if audit.is_some() => {
                let audit = audit
                    .expect("the audit branch is enabled only for enterprise sessions");
                match result {
                    // The periodic poll: send a due checkpoint (design
                    // sections 20.1 and 27.4). The substream send is driven
                    // with the swarm so a full muxer queue cannot stall the
                    // pump.
                    Err(_elapsed) => {
                        match drive_bound(driver, binding, audit.send_due_checkpoint()).await {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => {
                                cancel.store(true, Ordering::Relaxed);
                                break Err(HostError::Audit(error));
                            }
                            Err(endpoint) => {
                                cancel.store(true, Ordering::Relaxed);
                                break Err(endpoint.into());
                            }
                        }
                    }
                    Ok(Ok(Some(frame))) => {
                        let handled = match drive_bound(driver, binding, audit.handle_frame(&frame))
                            .await
                        {
                            Ok(Ok(event)) => event,
                            Ok(Err(error)) => {
                                cancel.store(true, Ordering::Relaxed);
                                break Err(HostError::Audit(error));
                            }
                            Err(endpoint) => {
                                cancel.store(true, Ordering::Relaxed);
                                break Err(endpoint.into());
                            }
                        };
                        match handled {
                            FrameEvent::None => {}
                            FrameEvent::Close(reason) => {
                                cancel.store(true, Ordering::Relaxed);
                                match reason {
                                    // The controller's own audit failed:
                                    // fail closed locally (design 18.7).
                                    AuditCloseReason::AuditFailure => {
                                        drive_bound(
                                            driver,
                                            binding,
                                            audit.fail_closed(None, reason),
                                        )
                                        .await
                                        .ok();
                                        break Err(HostError::Audit(AuditError::FailedClosed));
                                    }
                                    // The controller closed the session
                                    // (detach or local interrupt): finalize
                                    // with the received reason (design
                                    // sections 22.2 and 22.3). The driver is
                                    // polled throughout so the peer's
                                    // finalization frames arrive.
                                    reason => {
                                        let finalized = drive_bound(
                                            driver,
                                            binding,
                                            audit.close_and_finalize(
                                                ManifestEnding::CloseReason(reason),
                                                false,
                                                CloseNoticeHandling::AlreadyReceived(reason),
                                            ),
                                        )
                                        .await;
                                        match finalized {
                                            Ok(Ok(())) => {}
                                            Ok(Err(error)) => {
                                                break Err(HostError::Audit(error));
                                            }
                                            Err(endpoint) => {
                                                break Err(endpoint.into());
                                            }
                                        }
                                        break Err(HostError::ConnectionLost);
                                    }
                                }
                            }
                            FrameEvent::PeerAuditError(code) => {
                                cancel.store(true, Ordering::Relaxed);
                                drive_bound(
                                    driver,
                                    binding,
                                    audit.fail_closed(Some(code), AuditCloseReason::AuditFailure),
                                )
                                .await
                                .ok();
                                break Err(HostError::Audit(AuditError::FailedClosed));
                            }
                        }
                        audit_frames = Box::pin(wait_for_audit_frame(Some(audit)));
                    }
                    // The audit substream ended: the connection is gone.
                    Ok(Ok(None)) => {
                        cancel.store(true, Ordering::Relaxed);
                        break Err(HostError::Audit(AuditError::FailedClosed));
                    }
                    Ok(Err(error)) => {
                        cancel.store(true, Ordering::Relaxed);
                        break Err(HostError::Audit(error));
                    }
                }
            }
            result = &mut controller_input => match result {
                Ok(never) => match never {},
                Err(error) => {
                    cancel.store(true, Ordering::Relaxed);
                    break Err(error);
                }
            },
            result = &mut terminal_output => {
                cancel.store(true, Ordering::Relaxed);
                break result;
            }
            _ = &mut file_coordinator => {
                // The coordinator ends only when the sender is dropped,
                // which happens only after this loop breaks; reaching this
                // arm is an internal invariant failure.
                break Err(HostError::ProtocolRegistrationEnded);
            }
            signal = crate::shutdown::endpoint_shutdown_signal() => {
                cancel.store(true, Ordering::Relaxed);
                signal?;
                break Err(HostError::Interrupted);
            }
            }
        }
    };
    drop(pty_input);
    result
}

/// The hard cap on file substreams waiting for the single active slot.
const FILE_SUBSTREAM_QUEUE: usize = 1;

/// The erased file-substream I/O. `ApplicationStream::into_tokio` returns
/// an opaque type that cannot be named, so the bounded file queue carries
/// boxed trait objects instead (one bounded allocation per substream). The
/// trait exists only to give the object a name; every tokio stream
/// implements it.
trait FileSubstreamIo: AsyncRead + AsyncWrite + Unpin {}
impl<T: AsyncRead + AsyncWrite + Unpin> FileSubstreamIo for T {}

/// The boxed carrier type used by the bounded file-substream queue.
type FileSubstreamIoBox = Box<dyn FileSubstreamIo>;

/// Whether a file substream is served as the single active transfer or as
/// a busy rejection (design 15.3: at most one file operation per active
/// session).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileSubstreamRole {
    /// The single active slot: the opening frame dispatches a real upload
    /// or download.
    Active,
    /// Another transfer is already running: the opening frame is answered
    /// with `Error(Busy)` and the substream is closed.
    Busy,
}

/// The bounded, zero-side-effect result of the first-frame read of a file
/// substream (design 9.3: an EOF before any byte is a capability probe).
#[derive(Debug, PartialEq, Eq)]
enum FileOpenFrame {
    /// EOF at a message boundary before any byte: a capability probe. No
    /// transfer state, error output or log entry may be produced.
    Probe,
    /// A complete opening frame of an upload.
    Upload {
        destination: String,
        file_name: String,
        declared_size: u64,
    },
    /// A complete opening frame of a download.
    Download { source: String },
}

/// Why the first frame of a file substream could not be read. The serving
/// path closes the substream without state for every variant; the variants
/// exist so the failure category is explicit and testable.
#[derive(Debug, PartialEq, Eq)]
enum FileOpenError {
    /// The bounded control deadline expired (design 15.4).
    Timeout,
    /// The underlying substream I/O failed.
    Io,
    /// Unknown tag, invalid length, truncated frame or a frame that cannot
    /// open a transfer: a protocol violation (design 10.1).
    Protocol,
}

/// Reads exactly one complete opening frame from a file substream, bounded
/// by the control timeout (design 15.4). An EOF at a message boundary
/// before any byte is a capability probe ([`FileOpenFrame::Probe`]); an
/// EOF inside a frame is a protocol violation. Only `UploadOpen` and
/// `DownloadOpen` can open a transfer; any other tag (including `Data`) is
/// a protocol violation (design 10.1). The payload is decoded into a
/// bounded stack buffer (at most 8 KiB, design 15.1) and never allocated
/// from a peer-declared size.
async fn read_file_open_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    budget: Duration,
) -> Result<FileOpenFrame, FileOpenError> {
    tokio::time::timeout(budget, async {
        let mut header = [0_u8; FRAME_HEADER_LEN];
        if !read_file_frame_bytes(stream, &mut header)
            .await
            .map_err(classify_file_open_io)?
        {
            return Ok(FileOpenFrame::Probe);
        }
        let (tag, payload_len) =
            decode_frame_header(&header).map_err(|_| FileOpenError::Protocol)?;
        if tag == TransferTag::Data.code() {
            return Err(FileOpenError::Protocol);
        }
        let payload_len = usize::try_from(payload_len).map_err(|_| FileOpenError::Protocol)?;
        validate_payload_len(tag, payload_len).map_err(|_| FileOpenError::Protocol)?;
        let mut frame = [0_u8; MAX_CONTROL_FRAME_LEN];
        frame[..FRAME_HEADER_LEN].copy_from_slice(&header);
        if !read_file_frame_bytes(
            stream,
            &mut frame[FRAME_HEADER_LEN..FRAME_HEADER_LEN + payload_len],
        )
        .await
        .map_err(classify_file_open_io)?
        {
            return Err(FileOpenError::Protocol);
        }
        let message = FileTransferMessage::decode_frame(&frame[..FRAME_HEADER_LEN + payload_len])
            .map_err(|_| FileOpenError::Protocol)?;
        match message {
            FileTransferMessage::UploadOpen {
                destination,
                file_name,
                declared_size,
            } => Ok(FileOpenFrame::Upload {
                destination: destination.to_owned(),
                file_name: file_name.to_owned(),
                declared_size,
            }),
            FileTransferMessage::DownloadOpen { source } => Ok(FileOpenFrame::Download {
                source: source.to_owned(),
            }),
            _ => Err(FileOpenError::Protocol),
        }
    })
    .await
    .map_err(|_| FileOpenError::Timeout)?
}

/// Reads exactly `buffer.len()` bytes from the substream. Returns
/// `Ok(false)` when EOF arrives before any byte of the buffer (a message
/// boundary); an EOF inside the buffer is a truncated frame and fails.
async fn read_file_frame_bytes<S: AsyncRead + Unpin>(
    stream: &mut S,
    buffer: &mut [u8],
) -> Result<bool, std::io::Error> {
    let mut filled = 0;
    while filled < buffer.len() {
        let read = stream.read(&mut buffer[filled..]).await?;
        if read == 0 {
            if filled == 0 {
                return Ok(false);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "truncated file transfer frame",
            ));
        }
        filled += read;
    }
    Ok(true)
}

/// Maps an I/O failure of the opening-frame read: a truncated frame is a
/// protocol violation (EOF must only occur at a message boundary, design
/// 10.1), everything else stays an I/O failure. The original error is
/// deliberately not carried: the serving path closes the substream without
/// any state, error output or log entry (design 9.3).
fn classify_file_open_io(error: std::io::Error) -> FileOpenError {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        FileOpenError::Protocol
    } else {
        FileOpenError::Io
    }
}

/// Serves one file substream for the active session: reads the opening
/// frame with the bounded capability-probe semantics (design 9.3), then
/// dispatches a real upload or download, answers with `Error(Busy)` while
/// another transfer is active (design 15.3), or closes the substream
/// without any state. The terminal session is never touched: a file
/// failure only terminates the current substream and the remote terminal
/// stays Active (design 17.2).
async fn serve_one_file_substream<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    base: Option<&BaseDirectory>,
    cancel: Arc<AtomicBool>,
    config: &TransferConfig,
    role: FileSubstreamRole,
    audit: Option<&AuditObserver>,
) {
    match read_file_open_frame(&mut stream, config.control_timeout).await {
        Ok(FileOpenFrame::Probe) | Err(_) => {
            // A capability probe (EOF before any byte) or a failed opening
            // frame: close the substream without any transfer state, error
            // output or log entry (design 9.3).
        }
        Ok(FileOpenFrame::Upload {
            destination,
            file_name,
            declared_size,
        }) if role == FileSubstreamRole::Active => {
            let Some(base) = base else {
                // The session base directory is unavailable; the request
                // cannot be resolved and the substream closes without
                // state.
                return;
            };
            let open = FileTransferMessage::UploadOpen {
                destination: &destination,
                file_name: &file_name,
                declared_size,
            };
            handle_upload_from_open(&mut stream, config, base, &cancel, &open, audit).await;
        }
        Ok(FileOpenFrame::Download { source }) if role == FileSubstreamRole::Active => {
            let Some(base) = base else {
                // The session base directory is unavailable; the request
                // cannot be resolved and the substream closes without
                // state.
                return;
            };
            let open = FileTransferMessage::DownloadOpen { source: &source };
            handle_download_from_open(&mut stream, config, base, &cancel, &open, audit).await;
        }
        Ok(_) => {
            // Another file operation is active: answer the opening frame
            // with `Error(Busy)` and close (design 10.4, 15.3).
            send_busy_reply(&mut stream, config).await;
        }
    }
}

/// Answers an opening frame with `Error(Busy)` and closes the substream
/// (design 15.3: a second file operation during an active transfer is
/// rejected, never queued). The whole exchange is bounded by the control
/// timeout.
async fn send_busy_reply<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    config: &TransferConfig,
) {
    let Ok(encoded) = FileTransferMessage::Error {
        code: FileTransferErrorCode::Busy,
    }
    .encode() else {
        return;
    };
    let _ = tokio::time::timeout(config.control_timeout, async {
        stream.write_all(encoded.as_slice()).await?;
        stream.flush().await?;
        stream.shutdown().await
    })
    .await;
}

/// The session's file-substream coordinator: processes the substreams
/// handed over by the bridge loop with a hard cap of one active transfer
/// and one busy reply at a time (design 15.3). Each substream is probed
/// with the bounded first-frame read; capability probes (EOF before any
/// byte) are closed without side effects, real openings dispatch a
/// transfer, and openings while a transfer is active are answered with
/// `Error(Busy)`. Substreams beyond the caps are dropped (bounded
/// resources, design 15.1). The coordinator ends when the sender is
/// dropped, which happens when the session bridge tears down; the shared
/// cancel flag then aborts the active transfer and no uncommitted target
/// appears (design 16.4, 16.5).
async fn file_substream_coordinator<S>(
    mut pending: mpsc::Receiver<S>,
    base: Option<&BaseDirectory>,
    cancel: Arc<AtomicBool>,
    config: &TransferConfig,
    audit: Option<&AuditObserver>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut active: Option<Pin<Box<dyn Future<Output = ()> + '_>>> = None;
    let mut busy_reply: Option<Pin<Box<dyn Future<Output = ()> + '_>>> = None;
    loop {
        tokio::select! {
            stream = pending.recv() => {
                match stream {
                    None => {
                        // The queue is closed (the bridge dropped the
                        // sender at session teardown): finish any in-flight
                        // work, then end.
                        if active.is_none() && busy_reply.is_none() {
                            return;
                        }
                    }
                    Some(stream) => {
                        if active.is_none() && busy_reply.is_none() {
                            active = Some(Box::pin(serve_one_file_substream(
                                stream,
                                base,
                                cancel.clone(),
                                config,
                                FileSubstreamRole::Active,
                                audit,
                            )
                        ));
                        } else if busy_reply.is_none() {
                            // A transfer is active: answer this opening
                            // with `Error(Busy)` (design 15.3).
                            busy_reply = Some(Box::pin(serve_one_file_substream(
                                stream,
                                base,
                                cancel.clone(),
                                config,
                                FileSubstreamRole::Busy,
                                audit,
                            )
                        ));
                        }
                        // Else both slots are occupied; the substream is
                        // dropped.
                    }
                }
            }
            _ = async {
                if let Some(future) = active.as_mut() {
                    future.await;
                }
            }, if active.is_some() => {
                active = None;
            }
            _ = async {
                if let Some(future) = busy_reply.as_mut() {
                    future.await;
                }
            }, if busy_reply.is_some() => {
                busy_reply = None;
            }
        }
    }
}

async fn copy_controller_input(
    data_read: &mut (impl tokio::io::AsyncRead + Unpin),
    pty_input: &mut impl TerminalInput,
    audit: Option<&AuditObserver>,
) -> Result<Infallible, HostError> {
    // Design sections 18.2: the input commitment is appended before the
    // PTY write and the write outcome after it.
    let mut buffer = [0_u8; 8192];
    loop {
        let read = data_read.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let bytes = &buffer[..read];
        if let Some(audit) = audit {
            audit.record_input(bytes).await?;
        }
        if let Err(error) = pty_input.write_all(bytes).await {
            if let Some(audit) = audit {
                let _ = audit.record_pty_write_outcome(false, read as u64).await;
            }
            return Err(error.into());
        }
        if let Some(audit) = audit {
            audit.record_pty_write_outcome(true, read as u64).await?;
        }
    }
    pty_input.flush().await?;
    pty_input.close();
    std::future::pending().await
}

async fn copy_terminal_output<S: TerminalSession>(
    pty: &mut S,
    data_write: &mut (impl tokio::io::AsyncWrite + Unpin),
    control_read: &mut (impl tokio::io::AsyncRead + Unpin),
    control_write: &mut (impl tokio::io::AsyncWrite + Unpin),
    audit: Option<&AuditObserver>,
) -> Result<u32, HostError> {
    loop {
        let mut resize = [0_u8; 5];
        tokio::select! {
            read = control_read.read_exact(&mut resize) => {
                read?;
                let resize = TerminalResize::decode(&resize)?;
                // Design section 18.5: both sides record the resize with
                // the sender's direction before it is applied.
                if let Some(audit) = audit {
                    audit
                        .record_resize(
                            DIRECTION_CTRL_TO_HOST,
                            resize.size().columns(),
                            resize.size().rows(),
                        )
                        .await?;
                }
                pty.resize(resize.size()).await?;
                tokio::task::yield_now().await;
            }
            event = pty.next() => {
                let event = event?;
                match event.kind() {
                    PtyEventKind::Output => {
                        let output = event.into_output();
                        // Design section 18.3: the raw output is appended
                        // before it is sent, the send outcome after it.
                        if let Some(audit) = audit {
                            audit.record_raw_output(output.as_slice()).await?;
                        }
                        let length = output.as_slice().len() as u64;
                        let sent = async {
                            data_write.write_all(output.as_slice()).await?;
                            data_write.flush().await
                        }
                        .await;
                        if let Err(error) = sent {
                            if let Some(audit) = audit {
                                let _ =
                                    audit.record_send_outcome(DIRECTION_HOST_TO_CTRL, false, length).await;
                            }
                            return Err(error.into());
                        }
                        if let Some(audit) = audit {
                            audit
                                .record_send_outcome(DIRECTION_HOST_TO_CTRL, true, length)
                                .await?;
                        }
                        tokio::task::yield_now().await;
                    }
                    PtyEventKind::Exited(code) => {
                        // Design section 15.2: the shared TerminalExit event
                        // before it is conveyed.
                        if let Some(audit) = audit {
                            audit.record_terminal_exit(code as u8).await?;
                        }
                        data_write.shutdown().await?;
                        control_write
                            .write_all(&TerminalExit::new(code).encode())
                            .await?;
                        control_write.flush().await?;
                        complete_terminal_exit_io(
                            control_read,
                            control_write,
                            TERMINAL_COMPLETION_TIMEOUT,
                            audit,
                        )
                        .await?;
                        return Ok(code);
                    }
                }
            }
        }
    }
}

async fn complete_terminal_exit_io(
    control_read: &mut (impl tokio::io::AsyncRead + Unpin),
    control_write: &mut (impl tokio::io::AsyncWrite + Unpin),
    timeout: Duration,
    audit: Option<&AuditObserver>,
) -> Result<(), HostError> {
    tokio::time::timeout(timeout, async {
        loop {
            let mut tag = [0_u8; 1];
            let length = control_read.read(&mut tag).await?;
            if length == 0 {
                return Ok(());
            }
            if tag == TerminalComplete::ENCODED {
                TerminalComplete::decode(&tag)?;
                // Design section 15.2: the shared TerminalComplete event
                // once the controller conveyed it.
                if let Some(audit) = audit {
                    audit.record_terminal_complete().await?;
                }
                control_write.shutdown().await?;
                return Ok(());
            }

            let mut resize = [0_u8; 5];
            resize[0] = tag[0];
            control_read.read_exact(&mut resize[1..]).await?;
            TerminalResize::decode(&resize)?;
        }
    })
    .await
    .map_err(|_| HostError::Timeout)?
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
