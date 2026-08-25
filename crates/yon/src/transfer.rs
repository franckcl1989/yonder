//! Native file transfer orchestration for the 0.2.0 controller and host
//! (design sections 10.3, 10.5, 11, 12, 13, 14, 15, 16 and 17).
//!
//! This module owns the complete run of one file transfer over an already
//! established application substream. The substream is generic over
//! `tokio::io::AsyncRead + AsyncWrite + Unpin`; the session layer opens it
//! (after capability probing) and passes it in. Each run is self-contained:
//! a [`WireSession`] drives the wire-level state machine, the file-semantics
//! layer ([`crate::file_semantics`]) owns every file-system decision, and the
//! four orchestrators only sequence messages, timeouts, cancellation and the
//! local outcome.
//!
//! # Roles
//!
//! - [`run_upload`] / [`run_download`]: controller side. `run_upload`
//!   streams a locally opened [`TransferSource`]; `run_download` receives into a
//!   locally resolved destination. `run_upload` resolves nothing locally;
//!   only receive paths need a session base directory.
//! - [`handle_upload`] / [`handle_download`]: host side. `handle_upload`
//!   receives into a destination resolved from the wire; `handle_download`
//!   resolves and opens the wire-provided source and streams it.
//! - [`handle_upload_from_open`] / [`handle_download_from_open`]: host side,
//!   entries whose opening frame was already read by the session layer
//!   during capability probing (design 9.3). They continue from the
//!   recorded `UploadOpen` / `DownloadOpen` with the same post-open logic
//!   as [`handle_upload`] / [`handle_download`]; any other opening message
//!   is a protocol violation. The four original orchestrators keep reading
//!   the opening frame themselves; the `*_from_open` entries exist so the
//!   live host session never reads a frame twice.
//!
//! # Success, failure and cancellation semantics
//!
//! `Committed` means the receiver verified the byte count and SHA-256 digest,
//! committed the temporary file with a no-replace commit, sent `Committed`,
//! and the sender received it (design 13, 14). The two unavoidable commit
//! uncertainty windows are represented explicitly: a receiver returns
//! `CommittedUnconfirmed` if its local commit succeeded but the acknowledgement
//! could not be delivered, while a sender returns `CommitStatusUnknown` if it
//! delivered `Finish` but did not receive a conclusive response. Before those
//! windows, failure or cancellation removes the temporary file by `Drop` and
//! no final target appears. A local `Cancel` or peer `Cancel` returns
//! `Cancelled`; peer-reported and local failures return `Failed(code)`. After
//! receiving `Cancel` the receiver replies `Error(Cancelled)` best-effort
//! (design 10.5). The host in a download can never send `Cancel` (direction
//! table, design 10.3); its own cancellation is expressed as
//! `Error(SessionClosing)`.
//!
//! # Error mapping
//!
//! - File-semantics failures with a fixed 1.0.0 wire code become an `Error`
//!   message; failures without a wire code close the substream silently and
//!   report the nearest fixed code locally (`InvalidRequest` for destination
//!   resolution and temporary-file creation, `ReadFailed` for source reads,
//!   `WriteFailed` for temporary-file writes, `CommitFailed` for commit
//!   cleanup failures).
//! - Protocol violations (unknown tag, invalid length, decode failure,
//!   illegal sequence) close the substream and fail with `InvalidRequest`
//!   (design 10.1).
//! - A peer EOF at a message boundary before the terminal state, a stream
//!   I/O failure, a control-exchange deadline and a data no-progress deadline
//!   are local failures without a fixed wire code; the closest fixed code is
//!   `SessionClosing` (the transfer session is over because the peer went
//!   away or stopped making progress). An EOF in the middle of a frame is a
//!   protocol violation (`InvalidRequest`).
//!
//! # Resources, concurrency and logging
//!
//! Control frames are decoded in a bounded stack buffer (payload at most
//! 8 KiB); each transfer allocates exactly one `Box<[u8; MAX_DATA_LEN]>`
//! (64 KiB) that serves both the source reads and the wire data blocks
//! (design 15.1). Nothing is ever allocated proportional to the file size.
//! After every bounded data block the orchestrator yields to the async
//! scheduler (design 15.2); the cancel flag is checked between blocks and
//! every blocked read races a bounded-interval cancel poll, so a large
//! transfer stays interruptible. Control exchanges are bounded by
//! `config.control_timeout`; the data phase has no total deadline but each
//! byte of a frame must make progress within `config.data_progress_timeout`.
//! Logging records only categories, stages, byte counts and durations;
//! never paths, file names, digests or temporary file names (design 18.4).

use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use yonder_core::wire::file_transfer::{
    FRAME_HEADER_LEN, FileTransferErrorCode, FileTransferMessage, MAX_CONTROL_FRAME_LEN,
    MAX_DATA_LEN, Sha256Digest, TransferDirection, TransferSide, TransferTag, WireSession,
    encode_frame_header, validate_payload_len,
};

use crate::audit::observer::{AuditObserver, file_transfer_id};
use crate::audit::session::{
    AuditError, FILE_DIRECTION_DOWNLOAD, FILE_DIRECTION_UPLOAD, FILE_KIND_CANCELLED,
    FILE_KIND_FAILED, FILE_KIND_START, FILE_KIND_SUCCESS, FILE_LOCAL_KIND_COMMIT_STATUS_UNKNOWN,
    FILE_LOCAL_KIND_COMMITTED_UNCONFIRMED, FileTransferFacts,
};
#[cfg(test)]
use crate::file_semantics::SourceFile;
use crate::file_semantics::{
    BaseDirectory, FileSemanticsError, FileTransferBackend, SealedTransferTempFile,
    TokioFileTransferBackend, TransferSource, TransferTempFile,
};
use yonder_core::wire::audit::Digest32;

/// Timeout configuration of one transfer (design 15.4: the exact durations
/// are fixed implementation constants, not operator configuration).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferConfig {
    /// The bounded deadline of every control exchange (awaiting `Ready`,
    /// `DownloadOffer`, `Committed` or `Error`; the first frame of a
    /// transfer).
    pub control_timeout: Duration,
    /// The no-progress deadline of the data phase: a single frame read that
    /// delivers no byte within this budget fails the transfer. The data
    /// phase itself has no total duration limit.
    pub data_progress_timeout: Duration,
}

impl TransferConfig {
    /// The fixed implementation constants (design 15.4).
    #[must_use]
    pub const fn defaults() -> Self {
        Self {
            control_timeout: Duration::from_secs(30),
            data_progress_timeout: Duration::from_secs(30),
        }
    }
}

/// The final outcome of one transfer (design 10.5, 13).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferOutcome {
    /// The receiver committed the verified file and the sender received
    /// `Committed`. `bytes` is the transferred size. The only success.
    Committed { bytes: u64 },
    /// The local receiver atomically committed the verified file, but the
    /// `Committed` acknowledgement could not be delivered. The local target
    /// exists; the sender's view is necessarily uncertain.
    CommittedUnconfirmed { bytes: u64 },
    /// The sender successfully delivered `Finish`, then lost the exchange
    /// before receiving a valid `Committed` or `Error`. The receiver may or
    /// may not have committed the file, so retrying blindly can duplicate it.
    CommitStatusUnknown { bytes: u64 },
    /// The wire commit completed, but the mandatory enterprise audit terminal
    /// record failed. A receiver's atomic target may already exist; the
    /// enclosing enterprise session is FailedClosed and must terminate.
    AuditFailed { bytes: u64 },
    /// The mandatory enterprise audit start record failed before either side
    /// could commit a final target. The enclosing enterprise session is
    /// FailedClosed and must terminate.
    AuditFailedBeforeCommit,
    /// The transfer was cancelled locally or by the peer before the commit
    /// uncertainty window; no final target was committed by this endpoint.
    Cancelled,
    /// The transfer failed with a fixed 1.0.0 wire error code before a local
    /// commit or an uncertain post-`Finish` result.
    Failed(FileTransferErrorCode),
}

/// The protocol facts of one transfer that the audit observer records
/// (design section 18.6), filled progressively by the orchestrators: only
/// fields both sides verify from the 0.2.0 file protocol enter the shared
/// record. The local source/target path is retained separately for the
/// endpoint-local record and is never copied into the shared chain.
#[derive(Default)]
struct TransferAuditFacts {
    /// Whether the shared start event was recorded (the transfer really
    /// began on the wire); the end event is only recorded for started
    /// transfers, so a failed open never leaves an unmatched tail.
    started: bool,
    /// The remote protocol path.
    remote_path: Option<String>,
    /// The protocol base file name.
    file_name: Option<String>,
    /// The size announced by the transfer open.
    declared_size: Option<u64>,
    /// The SHA-256 of the transferred file, set at the success point.
    digest: Option<Sha256Digest>,
    /// This endpoint's source or final target path when it has an exact UTF-8
    /// representation. Non-UTF-8 platform paths are intentionally omitted.
    local_path: Option<String>,
}

/// The audit observer and progressively collected wire facts travel as one
/// responsibility through the transfer implementation.
struct TransferAuditContext<'a> {
    observer: Option<&'a AuditObserver>,
    facts: &'a mut TransferAuditFacts,
}

fn local_audit_path(path: &Path) -> Option<String> {
    path.to_str().map(str::to_owned)
}

/// The three fields carried by `UploadOpen`, kept together after decoding so
/// send and receive paths cannot accidentally mix metadata from two opens.
#[derive(Clone, Copy)]
struct UploadParameters<'a> {
    destination: &'a str,
    file_name: &'a str,
    declared_size: u64,
}

/// Appends the shared file transfer start event (design section 18.6) and
/// remembers the protocol facts for the end event. A failed append fails
/// the session closed inside the observer; the transfer must then abort.
async fn record_transfer_start(
    audit: Option<&AuditObserver>,
    facts: &mut TransferAuditFacts,
    direction: u8,
    remote_path: &str,
    file_name: &str,
    declared_size: u64,
) -> Result<(), AuditError> {
    let Some(audit) = audit else {
        return Ok(());
    };
    let shared = FileTransferFacts {
        transfer_id: file_transfer_id(direction, remote_path, file_name, declared_size),
        direction,
        kind: FILE_KIND_START,
        declared_size,
        final_size: 0,
        digest: Digest32::new([0; 32]),
        remote_path,
        file_name,
        error_code: 0,
    };
    audit
        .record_file_transfer(&shared, facts.local_path.as_deref())
        .await?;
    facts.started = true;
    facts.remote_path = Some(remote_path.to_owned());
    facts.file_name = Some(file_name.to_owned());
    facts.declared_size = Some(declared_size);
    Ok(())
}

/// Appends the shared file transfer end event (design section 18.6) from
/// the recorded facts and the final outcome. The observer fails the session
/// closed internally on a recording failure; the explicit result prevents
/// the transfer UI from reporting a successful commit first.
async fn record_transfer_end(
    audit: Option<&AuditObserver>,
    direction: u8,
    facts: &TransferAuditFacts,
    outcome: TransferOutcome,
) -> Result<(), AuditError> {
    let Some(audit) = audit else {
        return Ok(());
    };
    if !facts.started {
        return Ok(());
    }
    let (Some(remote_path), Some(file_name), Some(declared_size)) = (
        facts.remote_path.as_deref(),
        facts.file_name.as_deref(),
        facts.declared_size,
    ) else {
        return Ok(());
    };
    let transfer_id = file_transfer_id(direction, remote_path, file_name, declared_size);
    let (kind, final_size, error_code) = match outcome {
        TransferOutcome::Committed { bytes } => (FILE_KIND_SUCCESS, bytes, 0),
        TransferOutcome::CommittedUnconfirmed { bytes } => {
            let Some(digest) = facts.digest else {
                return Ok(());
            };
            audit
                .record_local_file_transfer_result(
                    FILE_LOCAL_KIND_COMMITTED_UNCONFIRMED,
                    transfer_id,
                    bytes,
                    Digest32::new(*digest.as_bytes()),
                    facts.local_path.as_deref(),
                )
                .await?;
            return Ok(());
        }
        TransferOutcome::CommitStatusUnknown { bytes } => {
            let Some(digest) = facts.digest else {
                return Ok(());
            };
            audit
                .record_local_file_transfer_result(
                    FILE_LOCAL_KIND_COMMIT_STATUS_UNKNOWN,
                    transfer_id,
                    bytes,
                    Digest32::new(*digest.as_bytes()),
                    facts.local_path.as_deref(),
                )
                .await?;
            return Ok(());
        }
        TransferOutcome::AuditFailed { .. } | TransferOutcome::AuditFailedBeforeCommit => {
            return Err(AuditError::InvalidState(
                "an audit-failed transfer cannot be recorded again",
            ));
        }
        TransferOutcome::Cancelled => (FILE_KIND_CANCELLED, 0, 0),
        TransferOutcome::Failed(code) => (FILE_KIND_FAILED, 0, code.code()),
    };
    let shared = FileTransferFacts {
        transfer_id,
        direction,
        kind,
        declared_size,
        final_size,
        digest: facts.digest.map_or(Digest32::new([0; 32]), |digest| {
            Digest32::new(*digest.as_bytes())
        }),
        remote_path,
        file_name,
        error_code,
    };
    audit
        .record_file_transfer(&shared, facts.local_path.as_deref())
        .await
}

/// Keeps an already non-successful or uncertain wire result authoritative,
/// while preserving the completed wire byte count in the typed audit failure.
fn apply_transfer_audit_result(
    outcome: TransferOutcome,
    audit: Result<(), AuditError>,
) -> TransferOutcome {
    match (outcome, audit) {
        (TransferOutcome::Committed { bytes }, Err(_)) => TransferOutcome::AuditFailed { bytes },
        (outcome, _) => outcome,
    }
}

/// The interval at which a blocked control exchange re-checks the cancel
/// flag (design 15.2: cancellation must keep making bounded progress).
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// One decoded frame, fully owned (the wire decoder borrows the frame
/// buffer, which is a local stack allocation).
#[derive(Debug, Clone, PartialEq, Eq)]
enum OwnedMessage {
    UploadOpen {
        destination: String,
        file_name: String,
        declared_size: u64,
    },
    DownloadOpen {
        source: String,
    },
    DownloadOffer {
        file_name: String,
        declared_size: u64,
    },
    Ready,
    /// A `Data` frame; the payload lives in the caller-provided bounded sink
    /// and only the length is carried here.
    Data {
        len: usize,
    },
    Finish {
        actual_size: u64,
        digest: Sha256Digest,
    },
    Committed,
    Cancel,
    Error {
        code: FileTransferErrorCode,
    },
}

/// How a frame read is bounded (design 15.4).
#[derive(Debug, Clone, Copy)]
enum ReadMode {
    /// A control exchange: the whole frame must arrive within the fixed
    /// budget.
    Control { budget: Duration },
    /// The data phase: no total deadline, but every byte must make progress
    /// within the budget (refreshed on each partial read).
    Data { budget: Duration },
}

/// Why a frame read failed.
#[derive(Debug)]
enum FrameReadError {
    /// EOF at a complete message boundary.
    Eof,
    /// EOF in the middle of a frame: a protocol violation.
    Truncated,
    /// Unknown tag, invalid length, decode failure or a `Data` frame where
    /// none is allowed: a protocol violation.
    Protocol,
    /// No progress (or no full control exchange) within the budget.
    Timeout,
    /// Underlying stream I/O failure.
    Io(io::Error),
}

/// Why a frame write failed.
#[derive(Debug)]
enum WriteFrameError {
    /// The wire session rejected the send: an illegal local transition.
    Protocol,
    /// The configured write/progress budget elapsed. `started` is true once
    /// at least one frame byte reached the stream.
    Timeout { started: bool },
    /// Session cancellation won the write race. `started` has the same
    /// meaning as for [`WriteFrameError::Timeout`].
    Cancelled { started: bool },
    /// Underlying stream I/O failure.
    Io { error: io::Error, started: bool },
}

#[derive(Debug, Clone, Copy)]
enum WriteMode {
    /// One absolute budget covers the complete control frame and its flush.
    Control { budget: Duration },
    /// Every successful partial write refreshes the no-progress budget.
    Data { budget: Duration },
}

/// Runs the controller side of an upload (design 11.1): streams the opened
/// `source` to the host and finishes only on `Committed`.
///
/// `destination` is the remote destination; an empty string selects the
/// default remote destination directory, in which case `file_name` names the
/// file there. `file_name` is the base name announced to the host and may
/// differ from the local source name. The controller resolves nothing
/// locally on this path.
///
/// The local cancel flag is checked before the transfer, after every data
/// block and while any control exchange is pending; a cancel sends `Cancel`
/// whenever the direction table allows it (every stage except after
/// `Finish`, where the controller abandons the wait locally).
pub async fn run_upload(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    config: &TransferConfig,
    source: &mut impl TransferSource,
    destination: &str,
    file_name: &str,
    cancel: &AtomicBool,
) -> TransferOutcome {
    let mut facts = TransferAuditFacts::default();
    let parameters = UploadParameters {
        destination,
        file_name,
        declared_size: source.size(),
    };
    run_upload_impl(
        stream,
        config,
        source,
        parameters,
        cancel,
        TransferAuditContext {
            observer: None,
            facts: &mut facts,
        },
    )
    .await
}

/// The audited controller upload path (design section 18.6): the shared
/// start and end events are appended around the wire transfer.
#[allow(clippy::too_many_arguments)]
pub async fn run_upload_audited(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    config: &TransferConfig,
    source: &mut impl TransferSource,
    destination: &str,
    file_name: &str,
    local_source: Option<&str>,
    cancel: &AtomicBool,
    audit: Option<&AuditObserver>,
) -> TransferOutcome {
    let mut facts = TransferAuditFacts {
        local_path: local_source.map(str::to_owned),
        ..TransferAuditFacts::default()
    };
    let parameters = UploadParameters {
        destination,
        file_name,
        declared_size: source.size(),
    };
    let outcome = run_upload_impl(
        stream,
        config,
        source,
        parameters,
        cancel,
        TransferAuditContext {
            observer: audit,
            facts: &mut facts,
        },
    )
    .await;
    let audit = record_transfer_end(audit, FILE_DIRECTION_UPLOAD, &facts, outcome).await;
    apply_transfer_audit_result(outcome, audit)
}

/// Runs the controller side of a download (design 12.1): receives the file
/// announced by the host's `DownloadOffer` into a local destination.
///
/// `remote_source` is the required remote source path. `local_target` is
/// `None` for the default local destination (the base directory joined with
/// the host-announced file name) or an explicit file path or existing
/// directory. A local cancel sends `Cancel` (the controller may cancel at
/// any non-terminal stage) and deletes the temporary file.
pub async fn run_download(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    config: &TransferConfig,
    base: &BaseDirectory,
    remote_source: &str,
    local_target: Option<&str>,
    cancel: &AtomicBool,
) -> TransferOutcome {
    let mut facts = TransferAuditFacts::default();
    let backend = TokioFileTransferBackend;
    run_download_impl(
        stream,
        config,
        base,
        remote_source,
        local_target,
        cancel,
        TransferAuditContext {
            observer: None,
            facts: &mut facts,
        },
        &backend,
    )
    .await
}

/// The audited controller download path (design section 18.6): the shared
/// start and end events are appended around the wire transfer.
pub async fn run_download_audited(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    config: &TransferConfig,
    base: &BaseDirectory,
    remote_source: &str,
    local_target: Option<&str>,
    cancel: &AtomicBool,
    audit: Option<&AuditObserver>,
) -> TransferOutcome {
    let mut facts = TransferAuditFacts::default();
    let backend = TokioFileTransferBackend;
    let outcome = run_download_impl(
        stream,
        config,
        base,
        remote_source,
        local_target,
        cancel,
        TransferAuditContext {
            observer: audit,
            facts: &mut facts,
        },
        &backend,
    )
    .await;
    let audit = record_transfer_end(audit, FILE_DIRECTION_DOWNLOAD, &facts, outcome).await;
    apply_transfer_audit_result(outcome, audit)
}

/// Runs the host side of an upload (design 11.2): receives the file into a
/// destination resolved from the wire's `UploadOpen`, verifies size and
/// digest and commits before sending `Committed`.
///
/// The session layer has already handled capability probing on a separate
/// substream; this function assumes a real transfer begins (design 9.3,
/// 10.5). A host-side cancel (session teardown) sends `Error(SessionClosing)`
/// and deletes the temporary file.
pub async fn handle_upload(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    config: &TransferConfig,
    base: &BaseDirectory,
    cancel: &AtomicBool,
) -> TransferOutcome {
    let started = Instant::now();
    tracing::debug!(
        direction = ?TransferDirection::Upload,
        side = ?TransferSide::Host,
        "file transfer started"
    );
    let backend = TokioFileTransferBackend;
    let outcome = handle_upload_impl(stream, config, base, cancel, &backend).await;
    tracing::debug!(?outcome, elapsed = ?started.elapsed(), "file transfer finished");
    outcome
}

/// Runs the host side of a download (design 12.2): resolves and opens the
/// wire-provided source, announces it with `DownloadOffer` and streams it;
/// the transfer succeeds only when `Committed` is received.
///
/// The host in a download never sends `Cancel` (direction table, design
/// 10.3); a host-side cancel is expressed as `Error(SessionClosing)`.
pub async fn handle_download(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    config: &TransferConfig,
    base: &BaseDirectory,
    cancel: &AtomicBool,
) -> TransferOutcome {
    let started = Instant::now();
    tracing::debug!(
        direction = ?TransferDirection::Download,
        side = ?TransferSide::Host,
        "file transfer started"
    );
    let backend = TokioFileTransferBackend;
    let outcome = handle_download_impl(stream, config, base, cancel, &backend).await;
    tracing::debug!(?outcome, elapsed = ?started.elapsed(), "file transfer finished");
    outcome
}

/// Runs the host side of an upload whose opening frame was already read by
/// the session layer during capability probing (design 9.3): continues from
/// the recorded `UploadOpen` and receives the file into a destination
/// resolved from the wire, verifying size and digest and committing before
/// sending `Committed`.
///
/// `open` must be an `UploadOpen`; any other message is a protocol
/// violation that closes the substream with `InvalidRequest`. The cancel
/// flag is checked before any work and then raced against every control
/// exchange and polled between data blocks, exactly as in
/// [`handle_upload`].
pub async fn handle_upload_from_open(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    config: &TransferConfig,
    base: &BaseDirectory,
    cancel: &AtomicBool,
    open: &FileTransferMessage<'_>,
    audit: Option<&AuditObserver>,
) -> TransferOutcome {
    handle_upload_from_open_with_settlement(stream, config, base, cancel, open, audit, None).await
}

/// The session-coordinator variant of [`handle_upload_from_open`]. Once the
/// upload leaves its wire state machine, `wire_settled` is published before
/// the local audit end record is appended. This lets the bounded coordinator
/// distinguish a truly concurrent substream from the next sequential
/// transfer without weakening audit ordering or adding a protocol frame.
pub(crate) async fn handle_upload_from_open_with_settlement(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    config: &TransferConfig,
    base: &BaseDirectory,
    cancel: &AtomicBool,
    open: &FileTransferMessage<'_>,
    audit: Option<&AuditObserver>,
    wire_settled: Option<&AtomicBool>,
) -> TransferOutcome {
    let started = Instant::now();
    tracing::debug!(
        direction = ?TransferDirection::Upload,
        side = ?TransferSide::Host,
        "file transfer started"
    );
    let mut session = WireSession::new(TransferDirection::Upload, TransferSide::Host);
    if cancel.load(Ordering::Relaxed) {
        session.close();
        return TransferOutcome::Cancelled;
    }
    let (destination, file_name, declared_size) = match open {
        &FileTransferMessage::UploadOpen {
            destination,
            file_name,
            declared_size,
        } => {
            let owned = OwnedMessage::UploadOpen {
                destination: destination.to_owned(),
                file_name: file_name.to_owned(),
                declared_size,
            };
            if let Err(outcome) = record_received(&mut session, &owned, &[]) {
                return outcome;
            }
            (destination, file_name, declared_size)
        }
        _ => return protocol_violation(&mut session),
    };
    // Design section 18.6: the shared start event once the opening frame
    // announced the protocol facts; a failed append aborts the transfer.
    let mut facts = TransferAuditFacts::default();
    if record_transfer_start(
        audit,
        &mut facts,
        FILE_DIRECTION_UPLOAD,
        destination,
        file_name,
        declared_size,
    )
    .await
    .is_err()
    {
        session.close();
        return TransferOutcome::AuditFailedBeforeCommit;
    }
    let parameters = UploadParameters {
        destination,
        file_name,
        declared_size,
    };
    let backend = TokioFileTransferBackend;
    let outcome = upload_receive_tail(
        stream,
        config,
        base,
        cancel,
        &mut session,
        parameters,
        &mut facts,
        &backend,
    )
    .await;
    if let Some(wire_settled) = wire_settled {
        wire_settled.store(true, Ordering::Release);
    }
    let audit = record_transfer_end(audit, FILE_DIRECTION_UPLOAD, &facts, outcome).await;
    let outcome = apply_transfer_audit_result(outcome, audit);
    tracing::debug!(?outcome, elapsed = ?started.elapsed(), "file transfer finished");
    outcome
}

/// Runs the host side of a download whose opening frame was already read by
/// the session layer during capability probing (design 9.3): continues from
/// the recorded `DownloadOpen`, resolves and opens the wire-provided
/// source, announces it with `DownloadOffer` and streams it; the transfer
/// succeeds only when `Committed` is received.
///
/// `open` must be a `DownloadOpen`; any other message is a protocol
/// violation that closes the substream with `InvalidRequest`. The host in a
/// download never sends `Cancel` (direction table, design 10.3); a host-side
/// cancel is expressed as `Error(SessionClosing)`.
pub async fn handle_download_from_open(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    config: &TransferConfig,
    base: &BaseDirectory,
    cancel: &AtomicBool,
    open: &FileTransferMessage<'_>,
    audit: Option<&AuditObserver>,
) -> TransferOutcome {
    handle_download_from_open_with_settlement(stream, config, base, cancel, open, audit, None).await
}

/// The session-coordinator variant of [`handle_download_from_open`]. See
/// [`handle_upload_from_open_with_settlement`] for the bounded sequential
/// hand-off invariant.
pub(crate) async fn handle_download_from_open_with_settlement(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    config: &TransferConfig,
    base: &BaseDirectory,
    cancel: &AtomicBool,
    open: &FileTransferMessage<'_>,
    audit: Option<&AuditObserver>,
    wire_settled: Option<&AtomicBool>,
) -> TransferOutcome {
    let started = Instant::now();
    tracing::debug!(
        direction = ?TransferDirection::Download,
        side = ?TransferSide::Host,
        "file transfer started"
    );
    let mut session = WireSession::new(TransferDirection::Download, TransferSide::Host);
    if cancel.load(Ordering::Relaxed) {
        session.close();
        return TransferOutcome::Cancelled;
    }
    let source = match open {
        &FileTransferMessage::DownloadOpen { source } => {
            let owned = OwnedMessage::DownloadOpen {
                source: source.to_owned(),
            };
            if let Err(outcome) = record_received(&mut session, &owned, &[]) {
                return outcome;
            }
            source
        }
        _ => return protocol_violation(&mut session),
    };
    let mut facts = TransferAuditFacts::default();
    let backend = TokioFileTransferBackend;
    let outcome = download_send_tail(
        stream,
        config,
        base,
        cancel,
        &mut session,
        source,
        audit,
        &mut facts,
        &backend,
    )
    .await;
    if let Some(wire_settled) = wire_settled {
        wire_settled.store(true, Ordering::Release);
    }
    let audit = record_transfer_end(audit, FILE_DIRECTION_DOWNLOAD, &facts, outcome).await;
    let outcome = apply_transfer_audit_result(outcome, audit);
    tracing::debug!(?outcome, elapsed = ?started.elapsed(), "file transfer finished");
    outcome
}

async fn run_upload_impl<Stream, Source>(
    stream: &mut Stream,
    config: &TransferConfig,
    source: &mut Source,
    parameters: UploadParameters<'_>,
    cancel: &AtomicBool,
    audit: TransferAuditContext<'_>,
) -> TransferOutcome
where
    Stream: AsyncRead + AsyncWrite + Unpin,
    Source: TransferSource,
{
    let mut session = WireSession::new(TransferDirection::Upload, TransferSide::Controller);

    if cancel.load(Ordering::Relaxed) {
        session.close();
        return TransferOutcome::Cancelled;
    }

    // UploadOpen announces the initial size recorded at open time (design
    // 14: only this many bytes are ever read).
    let open = FileTransferMessage::UploadOpen {
        destination: parameters.destination,
        file_name: parameters.file_name,
        declared_size: parameters.declared_size,
    };
    if let Err(error) = write_frame_bounded(
        stream,
        &mut session,
        &open,
        WriteMode::Control {
            budget: config.control_timeout,
        },
        cancel,
    )
    .await
    {
        return send_failure(&mut session, error);
    }

    // Design section 18.6: the shared start event once the transfer really
    // began on the wire; a failed append aborts the transfer.
    if record_transfer_start(
        audit.observer,
        audit.facts,
        FILE_DIRECTION_UPLOAD,
        parameters.destination,
        parameters.file_name,
        parameters.declared_size,
    )
    .await
    .is_err()
    {
        session.close();
        return TransferOutcome::AuditFailedBeforeCommit;
    }

    // Await Ready (bounded; a user cancel sends Cancel).
    let ready = tokio::select! {
        frame = read_frame(&mut *stream, ReadMode::Control { budget: config.control_timeout }, None) => {
            match frame {
                Err(error) => {
                    session.close();
                    return read_failure_outcome(error);
                }
                Ok(message) => message,
            }
        }
        _ = cancel_signal(cancel) => {
            best_effort_send(stream, &mut session, config, FileTransferMessage::Cancel).await;
            return TransferOutcome::Cancelled;
        }
    };
    match &ready {
        OwnedMessage::Ready => {
            if let Err(outcome) = record_received(&mut session, &ready, &[]) {
                return outcome;
            }
        }
        OwnedMessage::Error { code } => {
            if let Err(outcome) = record_received(&mut session, &ready, &[]) {
                return outcome;
            }
            return TransferOutcome::Failed(*code);
        }
        // A peer `Cancel` here is illegal for the host (direction table) and
        // lands in the protocol-violation arm.
        _ => return protocol_violation(&mut session),
    }

    // Stream the source in bounded blocks, hashing in lock-step (design
    // 14, 15.1). The single bounded data buffer serves both source reads and
    // wire frames.
    let mut hasher = Sha256::new();
    let mut data = Box::new([0_u8; MAX_DATA_LEN]);
    loop {
        if cancel.load(Ordering::Relaxed) {
            best_effort_send(stream, &mut session, config, FileTransferMessage::Cancel).await;
            return TransferOutcome::Cancelled;
        }
        let n = match source.read_block(&mut *data).await {
            Ok(n) => n,
            Err(error) => {
                return fail_local(
                    stream,
                    &mut session,
                    config,
                    error,
                    FileTransferErrorCode::ReadFailed,
                )
                .await;
            }
        };
        if n == 0 {
            break;
        }
        hasher.update(&data[..n]);
        if let Err(error) = write_frame_bounded(
            stream,
            &mut session,
            &FileTransferMessage::Data { bytes: &data[..n] },
            WriteMode::Data {
                budget: config.data_progress_timeout,
            },
            cancel,
        )
        .await
        {
            return send_failure(&mut session, error);
        }
        // Design 15.2: hand the executor back after every bounded block so
        // terminal output, control and cancellation keep making progress.
        tokio::task::yield_now().await;
    }

    // The source must not have changed while it was read (design 14).
    if let Err(error) = source.recheck_source().await {
        return fail_local(
            stream,
            &mut session,
            config,
            error,
            FileTransferErrorCode::ReadFailed,
        )
        .await;
    }
    let finish_digest = Sha256Digest::new(hasher.finalize().into());
    let finish = FileTransferMessage::Finish {
        actual_size: source.bytes_read(),
        digest: finish_digest,
    };
    let transferred = source.bytes_read();
    if let Err(error) = write_frame_bounded(
        stream,
        &mut session,
        &finish,
        WriteMode::Control {
            budget: config.control_timeout,
        },
        cancel,
    )
    .await
    {
        return finish_send_failure(&mut session, error, transferred);
    }
    audit.facts.digest = Some(finish_digest);

    // Await Committed (bounded). Once Finish has been delivered, losing the
    // exchange cannot prove whether the receiver committed the file.
    let committed = tokio::select! {
        frame = read_frame(&mut *stream, ReadMode::Control { budget: config.control_timeout }, None) => {
            match frame {
                Err(error) => {
                    session.close();
                    trace_uncertain_commit_read(error);
                    return TransferOutcome::CommitStatusUnknown { bytes: transferred };
                }
                Ok(message) => message,
            }
        }
        _ = cancel_signal(cancel) => {
            session.close();
            return TransferOutcome::CommitStatusUnknown { bytes: transferred };
        }
    };
    match &committed {
        OwnedMessage::Committed => {
            if let Err(outcome) = record_received(&mut session, &committed, &[]) {
                return outcome;
            }
            TransferOutcome::Committed { bytes: transferred }
        }
        OwnedMessage::Error { code } => {
            if let Err(outcome) = record_received(&mut session, &committed, &[]) {
                return outcome;
            }
            TransferOutcome::Failed(*code)
        }
        _ => {
            session.close();
            TransferOutcome::CommitStatusUnknown { bytes: transferred }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_download_impl<S, Backend>(
    stream: &mut S,
    config: &TransferConfig,
    base: &BaseDirectory,
    remote_source: &str,
    local_target: Option<&str>,
    cancel: &AtomicBool,
    audit: TransferAuditContext<'_>,
    backend: &Backend,
) -> TransferOutcome
where
    S: AsyncRead + AsyncWrite + Unpin,
    Backend: FileTransferBackend,
{
    let mut session = WireSession::new(TransferDirection::Download, TransferSide::Controller);

    if cancel.load(Ordering::Relaxed) {
        session.close();
        return TransferOutcome::Cancelled;
    }

    let open = FileTransferMessage::DownloadOpen {
        source: remote_source,
    };
    if let Err(error) = write_frame_bounded(
        stream,
        &mut session,
        &open,
        WriteMode::Control {
            budget: config.control_timeout,
        },
        cancel,
    )
    .await
    {
        return send_failure(&mut session, error);
    }

    // Await the host's DownloadOffer (bounded; a user cancel sends Cancel).
    let offer_message = tokio::select! {
        frame = read_frame(&mut *stream, ReadMode::Control { budget: config.control_timeout }, None) => {
            match frame {
                Err(error) => {
                    session.close();
                    return read_failure_outcome(error);
                }
                Ok(message) => message,
            }
        }
        _ = cancel_signal(cancel) => {
            best_effort_send(stream, &mut session, config, FileTransferMessage::Cancel).await;
            return TransferOutcome::Cancelled;
        }
    };
    let (file_name, declared_size) = match &offer_message {
        OwnedMessage::DownloadOffer {
            file_name,
            declared_size,
        } => {
            if let Err(outcome) = record_received(&mut session, &offer_message, &[]) {
                return outcome;
            }
            (file_name.as_str(), *declared_size)
        }
        OwnedMessage::Error { code } => {
            if let Err(outcome) = record_received(&mut session, &offer_message, &[]) {
                return outcome;
            }
            return TransferOutcome::Failed(*code);
        }
        _ => return protocol_violation(&mut session),
    };

    // Design section 18.6: the shared start event once the offer announced
    // the protocol facts; a failed append aborts the transfer.
    if record_transfer_start(
        audit.observer,
        audit.facts,
        FILE_DIRECTION_DOWNLOAD,
        remote_source,
        file_name,
        declared_size,
    )
    .await
    .is_err()
    {
        session.close();
        return TransferOutcome::AuditFailedBeforeCommit;
    }

    // Resolve the local destination and create the private temporary file
    // (design 8.3, 8.4, 13).
    let plan = match backend
        .resolve_destination(
            base.clone(),
            local_target.map(str::to_owned),
            Some(file_name.to_owned()),
        )
        .await
    {
        Ok(plan) => plan,
        Err(error) => {
            return fail_local(
                stream,
                &mut session,
                config,
                error,
                FileTransferErrorCode::InvalidRequest,
            )
            .await;
        }
    };
    audit.facts.local_path = local_audit_path(plan.final_path());
    let mut temp = match backend.create_temp(plan.temp_dir().to_path_buf()).await {
        Ok(temp) => temp,
        Err(error) => {
            return fail_local(
                stream,
                &mut session,
                config,
                error,
                FileTransferErrorCode::InvalidRequest,
            )
            .await;
        }
    };
    if let Err(error) = write_frame_bounded(
        stream,
        &mut session,
        &FileTransferMessage::Ready,
        WriteMode::Control {
            budget: config.control_timeout,
        },
        cancel,
    )
    .await
    {
        return send_failure(&mut session, error);
    }

    // Receive Data blocks, then the terminal Finish (design 14). The
    // receiver may cancel at any time with a Cancel message.
    let mut data = Box::new([0_u8; MAX_DATA_LEN]);
    let finish = loop {
        let message = tokio::select! {
            frame = read_frame(&mut *stream, ReadMode::Data { budget: config.data_progress_timeout }, Some(&mut *data)) => {
                match frame {
                    Err(error) => {
                        session.close();
                        return read_failure_outcome(error);
                    }
                    Ok(message) => message,
                }
            }
            _ = cancel_signal(cancel) => {
                best_effort_send(stream, &mut session, config, FileTransferMessage::Cancel).await;
                return TransferOutcome::Cancelled;
            }
        };
        match &message {
            OwnedMessage::Data { len } => {
                if let Err(outcome) = record_received(&mut session, &message, &data[..*len]) {
                    return outcome;
                }
                if let Err(error) = temp.write_block_async(&data[..*len]).await {
                    return fail_local(
                        stream,
                        &mut session,
                        config,
                        error,
                        FileTransferErrorCode::WriteFailed,
                    )
                    .await;
                }
                tokio::task::yield_now().await;
            }
            OwnedMessage::Finish {
                actual_size,
                digest,
            } => {
                if let Err(outcome) = record_received(&mut session, &message, &[]) {
                    return outcome;
                }
                break (*actual_size, *digest);
            }
            OwnedMessage::Error { code } => {
                if let Err(outcome) = record_received(&mut session, &message, &[]) {
                    return outcome;
                }
                return TransferOutcome::Failed(*code);
            }
            // A peer Cancel is illegal for the host in a download (direction
            // table) and lands here as a protocol violation.
            _ => return protocol_violation(&mut session),
        }
    };

    // Seal, verify and commit (design 13, 14): the written byte count must
    // equal the declared size, the Finish's actual size must equal it, and
    // the digests must agree.
    let sealed = match temp.finish_async().await {
        Ok(sealed) => sealed,
        Err(error) => {
            return fail_local(
                stream,
                &mut session,
                config,
                error,
                FileTransferErrorCode::WriteFailed,
            )
            .await;
        }
    };
    let (actual_size, digest) = finish;
    let verify = if actual_size != declared_size {
        Err(FileSemanticsError::SizeMismatch {
            declared: declared_size,
            received: actual_size,
        })
    } else {
        sealed.verify_finish(declared_size, digest)
    };
    if let Err(error) = verify {
        return fail_local(
            stream,
            &mut session,
            config,
            error,
            FileTransferErrorCode::SizeMismatch,
        )
        .await;
    }
    let written = sealed.written();
    if let Err(error) = sealed.commit_async(plan.final_path().to_path_buf()).await {
        return fail_local(
            stream,
            &mut session,
            config,
            error,
            FileTransferErrorCode::CommitFailed,
        )
        .await;
    }
    audit.facts.digest = Some(digest);
    if let Err(error) = write_frame_bounded(
        stream,
        &mut session,
        &FileTransferMessage::Committed,
        WriteMode::Control {
            budget: config.control_timeout,
        },
        cancel,
    )
    .await
    {
        return committed_ack_failure(&mut session, error, written);
    }
    TransferOutcome::Committed { bytes: written }
}

async fn handle_upload_impl<S, Backend>(
    stream: &mut S,
    config: &TransferConfig,
    base: &BaseDirectory,
    cancel: &AtomicBool,
    backend: &Backend,
) -> TransferOutcome
where
    S: AsyncRead + AsyncWrite + Unpin,
    Backend: FileTransferBackend,
{
    let mut session = WireSession::new(TransferDirection::Upload, TransferSide::Host);

    if cancel.load(Ordering::Relaxed) {
        session.close();
        return TransferOutcome::Cancelled;
    }

    // Receive UploadOpen (bounded). The session layer has already handled
    // capability probing on a separate substream; an EOF before this first
    // frame is an ordinary transfer failure (design 9.3, 10.5).
    let open_message = tokio::select! {
        frame = read_frame(&mut *stream, ReadMode::Control { budget: config.control_timeout }, None) => {
            match frame {
                Err(error) => {
                    session.close();
                    return read_failure_outcome(error);
                }
                Ok(message) => message,
            }
        }
        _ = cancel_signal(cancel) => {
            session.close();
            return TransferOutcome::Cancelled;
        }
    };
    let parameters = match &open_message {
        OwnedMessage::UploadOpen {
            destination,
            file_name,
            declared_size,
        } => {
            if let Err(outcome) = record_received(&mut session, &open_message, &[]) {
                return outcome;
            }
            UploadParameters {
                destination,
                file_name,
                declared_size: *declared_size,
            }
        }
        _ => return protocol_violation(&mut session),
    };

    // Continue with the shared post-`UploadOpen` receive path. Keeping the
    // opening-frame read (with its EOF-before-first-frame semantics) in this
    // entry lets [`handle_upload_from_open`] reuse the identical
    // continuation for the live session, where the host already read the
    // frame during capability probing (design 9.3).
    upload_receive_tail(
        stream,
        config,
        base,
        cancel,
        &mut session,
        parameters,
        &mut TransferAuditFacts::default(),
        backend,
    )
    .await
}

/// The shared post-`UploadOpen` host receive path: resolves the destination,
/// creates the private temporary file, sends `Ready`, receives the `Data`
/// blocks and the terminal `Finish`, verifies size and digest and commits
/// with a no-replace commit before sending `Committed` (design 11.2, 13,
/// 14). `session` must be an upload host session that already recorded the
/// received `UploadOpen`.
#[allow(clippy::too_many_arguments)]
async fn upload_receive_tail<S, Backend>(
    stream: &mut S,
    config: &TransferConfig,
    base: &BaseDirectory,
    cancel: &AtomicBool,
    session: &mut WireSession,
    parameters: UploadParameters<'_>,
    facts: &mut TransferAuditFacts,
    backend: &Backend,
) -> TransferOutcome
where
    S: AsyncRead + AsyncWrite + Unpin,
    Backend: FileTransferBackend,
{
    // Resolve the destination (an empty destination selects the default
    // directory) and create the private temporary file (design 8.3, 8.4,
    // 13). Parents are never created automatically.
    let explicit_target = if parameters.destination.is_empty() {
        None
    } else {
        Some(parameters.destination)
    };
    let plan = match backend
        .resolve_destination(
            base.clone(),
            explicit_target.map(str::to_owned),
            Some(parameters.file_name.to_owned()),
        )
        .await
    {
        Ok(plan) => plan,
        Err(error) => {
            return fail_local(
                stream,
                session,
                config,
                error,
                FileTransferErrorCode::InvalidRequest,
            )
            .await;
        }
    };
    facts.local_path = local_audit_path(plan.final_path());
    let mut temp = match backend.create_temp(plan.temp_dir().to_path_buf()).await {
        Ok(temp) => temp,
        Err(error) => {
            return fail_local(
                stream,
                session,
                config,
                error,
                FileTransferErrorCode::InvalidRequest,
            )
            .await;
        }
    };
    if let Err(error) = write_frame_bounded(
        stream,
        session,
        &FileTransferMessage::Ready,
        WriteMode::Control {
            budget: config.control_timeout,
        },
        cancel,
    )
    .await
    {
        return send_failure(session, error);
    }

    // Receive Data blocks and the terminal Finish. The temporary file is
    // dropped (and removed) on every failure path.
    let mut data = Box::new([0_u8; MAX_DATA_LEN]);
    let finish = loop {
        let message = tokio::select! {
            frame = read_frame(&mut *stream, ReadMode::Data { budget: config.data_progress_timeout }, Some(&mut *data)) => {
                match frame {
                    Err(error) => {
                        session.close();
                        return read_failure_outcome(error);
                    }
                    Ok(message) => message,
                }
            }
            _ = cancel_signal(cancel) => {
                // Host-side cancellation in an upload is expressed with
                // `Error`; the host may never send `Cancel` in any role.
                best_effort_send(
                    stream,
                    session,
                    config,
                    FileTransferMessage::Error { code: FileTransferErrorCode::SessionClosing },
                ).await;
                return TransferOutcome::Cancelled;
            }
        };
        match &message {
            OwnedMessage::Data { len } => {
                if let Err(outcome) = record_received(session, &message, &data[..*len]) {
                    return outcome;
                }
                if let Err(error) = temp.write_block_async(&data[..*len]).await {
                    return fail_local(
                        stream,
                        session,
                        config,
                        error,
                        FileTransferErrorCode::WriteFailed,
                    )
                    .await;
                }
                tokio::task::yield_now().await;
            }
            OwnedMessage::Finish {
                actual_size,
                digest,
            } => {
                if let Err(outcome) = record_received(session, &message, &[]) {
                    return outcome;
                }
                break (*actual_size, *digest);
            }
            OwnedMessage::Cancel => {
                // Design 10.5: stop, delete the temporary file (Drop) and
                // reply `Error(Cancelled)` best-effort. The reply is sent
                // while the session is still open (sending `Error` closes
                // it); recording the `Cancel` afterwards is then a no-op
                // because the session is already closed.
                best_effort_send(
                    stream,
                    session,
                    config,
                    FileTransferMessage::Error {
                        code: FileTransferErrorCode::Cancelled,
                    },
                )
                .await;
                let _ = session.receive(&FileTransferMessage::Cancel);
                return TransferOutcome::Cancelled;
            }
            OwnedMessage::Error { code } => {
                if let Err(outcome) = record_received(session, &message, &[]) {
                    return outcome;
                }
                return TransferOutcome::Failed(*code);
            }
            _ => return protocol_violation(session),
        }
    };

    // Seal, verify and commit (design 13, 14): the written byte count must
    // equal the declared size, the Finish's actual size must equal it, and
    // the digests must agree.
    let sealed = match temp.finish_async().await {
        Ok(sealed) => sealed,
        Err(error) => {
            return fail_local(
                stream,
                session,
                config,
                error,
                FileTransferErrorCode::WriteFailed,
            )
            .await;
        }
    };
    let (actual_size, digest) = finish;
    let verify = if actual_size != parameters.declared_size {
        Err(FileSemanticsError::SizeMismatch {
            declared: parameters.declared_size,
            received: actual_size,
        })
    } else {
        sealed.verify_finish(parameters.declared_size, digest)
    };
    if let Err(error) = verify {
        return fail_local(
            stream,
            session,
            config,
            error,
            FileTransferErrorCode::SizeMismatch,
        )
        .await;
    }
    let written = sealed.written();
    if let Err(error) = sealed.commit_async(plan.final_path().to_path_buf()).await {
        return fail_local(
            stream,
            session,
            config,
            error,
            FileTransferErrorCode::CommitFailed,
        )
        .await;
    }
    facts.digest = Some(digest);
    if let Err(error) = write_frame_bounded(
        stream,
        session,
        &FileTransferMessage::Committed,
        WriteMode::Control {
            budget: config.control_timeout,
        },
        cancel,
    )
    .await
    {
        return committed_ack_failure(session, error, written);
    }
    TransferOutcome::Committed { bytes: written }
}

async fn handle_download_impl<S, Backend>(
    stream: &mut S,
    config: &TransferConfig,
    base: &BaseDirectory,
    cancel: &AtomicBool,
    backend: &Backend,
) -> TransferOutcome
where
    S: AsyncRead + AsyncWrite + Unpin,
    Backend: FileTransferBackend,
{
    let mut session = WireSession::new(TransferDirection::Download, TransferSide::Host);

    if cancel.load(Ordering::Relaxed) {
        session.close();
        return TransferOutcome::Cancelled;
    }

    // Receive DownloadOpen (bounded).
    let open_message = tokio::select! {
        frame = read_frame(&mut *stream, ReadMode::Control { budget: config.control_timeout }, None) => {
            match frame {
                Err(error) => {
                    session.close();
                    return read_failure_outcome(error);
                }
                Ok(message) => message,
            }
        }
        _ = cancel_signal(cancel) => {
            session.close();
            return TransferOutcome::Cancelled;
        }
    };
    let source_path = match &open_message {
        OwnedMessage::DownloadOpen { source } => {
            if let Err(outcome) = record_received(&mut session, &open_message, &[]) {
                return outcome;
            }
            source.clone()
        }
        _ => return protocol_violation(&mut session),
    };

    // Continue with the shared post-`DownloadOpen` send path. Keeping the
    // opening-frame read (with its EOF-before-first-frame semantics) in this
    // entry lets [`handle_download_from_open`] reuse the identical
    // continuation for the live session, where the host already read the
    // frame during capability probing (design 9.3).
    download_send_tail(
        stream,
        config,
        base,
        cancel,
        &mut session,
        &source_path,
        None,
        &mut TransferAuditFacts::default(),
        backend,
    )
    .await
}

/// The shared post-`DownloadOpen` host send path: resolves and opens the
/// wire-provided source, announces it with `DownloadOffer`, streams it in
/// bounded blocks and succeeds only when `Committed` is received (design
/// 12.2, 14). `session` must be a download host session that already
/// recorded the received `DownloadOpen`. The host in a download never sends
/// `Cancel` (direction table, design 10.3); a host-side cancel is expressed
/// as `Error(SessionClosing)`.
#[allow(clippy::too_many_arguments)]
async fn download_send_tail<S, Backend>(
    stream: &mut S,
    config: &TransferConfig,
    base: &BaseDirectory,
    cancel: &AtomicBool,
    session: &mut WireSession,
    source_path: &str,
    audit: Option<&AuditObserver>,
    facts: &mut TransferAuditFacts,
    backend: &Backend,
) -> TransferOutcome
where
    S: AsyncRead + AsyncWrite + Unpin,
    Backend: FileTransferBackend,
{
    // Resolve and open the source; type and size are judged exclusively
    // from the opened handle (design 8.2).
    let path = match base.resolve(source_path) {
        Ok(path) => path,
        Err(error) => {
            return fail_local(
                stream,
                session,
                config,
                error,
                FileTransferErrorCode::InvalidRequest,
            )
            .await;
        }
    };
    let mut source = match backend.open_source(path.clone()).await {
        Ok(source) => source,
        Err(error) => {
            return fail_local(
                stream,
                session,
                config,
                error,
                FileTransferErrorCode::SourceNotFound,
            )
            .await;
        }
    };
    facts.local_path = local_audit_path(&path);

    // The offer announces the source's base name and its initial size. The
    // name field is UTF-8 on the wire; a local name that cannot be encoded
    // is approximated lossily, and names containing forbidden control
    // characters fail the encode below (fail-closed). A path without a final
    // component cannot name a regular file and is rejected defensively.
    let offer_name = match path.file_name() {
        Some(name) => name.to_string_lossy().into_owned(),
        None => {
            session.close();
            return TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest);
        }
    };
    let offer = FileTransferMessage::DownloadOffer {
        file_name: &offer_name,
        declared_size: source.size(),
    };
    // Design section 18.6: the shared start event once the protocol facts
    // are known; a failed append aborts the transfer.
    if record_transfer_start(
        audit,
        facts,
        FILE_DIRECTION_DOWNLOAD,
        source_path,
        &offer_name,
        source.size(),
    )
    .await
    .is_err()
    {
        session.close();
        return TransferOutcome::AuditFailedBeforeCommit;
    }
    if let Err(error) = write_frame_bounded(
        stream,
        session,
        &offer,
        WriteMode::Control {
            budget: config.control_timeout,
        },
        cancel,
    )
    .await
    {
        return send_failure(session, error);
    }

    // Await Ready (bounded). The controller may cancel here; the host sends
    // no message (the direction table allows none in this state) and no
    // target has been created.
    let ready_message = tokio::select! {
        frame = read_frame(&mut *stream, ReadMode::Control { budget: config.control_timeout }, None) => {
            match frame {
                Err(error) => {
                    session.close();
                    return read_failure_outcome(error);
                }
                Ok(message) => message,
            }
        }
        _ = cancel_signal(cancel) => {
            session.close();
            return TransferOutcome::Cancelled;
        }
    };
    match &ready_message {
        OwnedMessage::Ready => {
            if let Err(outcome) = record_received(session, &ready_message, &[]) {
                return outcome;
            }
        }
        OwnedMessage::Cancel => {
            // The direction table allows no reply in this state; the
            // best-effort send below is silently rejected and the Cancel
            // closes the session.
            best_effort_send(
                stream,
                session,
                config,
                FileTransferMessage::Error {
                    code: FileTransferErrorCode::Cancelled,
                },
            )
            .await;
            let _ = session.receive(&FileTransferMessage::Cancel);
            return TransferOutcome::Cancelled;
        }
        OwnedMessage::Error { code } => {
            if let Err(outcome) = record_received(session, &ready_message, &[]) {
                return outcome;
            }
            return TransferOutcome::Failed(*code);
        }
        _ => return protocol_violation(session),
    }

    // Stream the source in bounded blocks, hashing in lock-step. The host in
    // a download can only express cancellation as `Error(SessionClosing)`,
    // never as `Cancel` (design 10.3).
    let mut hasher = Sha256::new();
    let mut data = Box::new([0_u8; MAX_DATA_LEN]);
    loop {
        if cancel.load(Ordering::Relaxed) {
            best_effort_send(
                stream,
                session,
                config,
                FileTransferMessage::Error {
                    code: FileTransferErrorCode::SessionClosing,
                },
            )
            .await;
            return TransferOutcome::Cancelled;
        }
        let n = match source.read_block(&mut *data).await {
            Ok(n) => n,
            Err(error) => {
                return fail_local(
                    stream,
                    session,
                    config,
                    error,
                    FileTransferErrorCode::ReadFailed,
                )
                .await;
            }
        };
        if n == 0 {
            break;
        }
        hasher.update(&data[..n]);
        if let Err(error) = write_frame_bounded(
            stream,
            session,
            &FileTransferMessage::Data { bytes: &data[..n] },
            WriteMode::Data {
                budget: config.data_progress_timeout,
            },
            cancel,
        )
        .await
        {
            if matches!(error, WriteFrameError::Cancelled { started: false }) {
                best_effort_send(
                    stream,
                    session,
                    config,
                    FileTransferMessage::Error {
                        code: FileTransferErrorCode::SessionClosing,
                    },
                )
                .await;
                return TransferOutcome::Cancelled;
            }
            return send_failure(session, error);
        }
        tokio::task::yield_now().await;
    }

    // The source must not have changed while it was read (design 14).
    if let Err(error) = source.recheck_source().await {
        return fail_local(
            stream,
            session,
            config,
            error,
            FileTransferErrorCode::ReadFailed,
        )
        .await;
    }
    let finish_digest = Sha256Digest::new(hasher.finalize().into());
    let finish = FileTransferMessage::Finish {
        actual_size: source.bytes_read(),
        digest: finish_digest,
    };
    let transferred = source.bytes_read();
    if let Err(error) = write_frame_bounded(
        stream,
        session,
        &finish,
        WriteMode::Control {
            budget: config.control_timeout,
        },
        cancel,
    )
    .await
    {
        return finish_send_failure(session, error, transferred);
    }
    facts.digest = Some(finish_digest);

    // Await Committed (bounded). A lost post-Finish exchange leaves the
    // receiver's commit status unknowable to this sender.
    let committed_message = tokio::select! {
        frame = read_frame(&mut *stream, ReadMode::Control { budget: config.control_timeout }, None) => {
            match frame {
                Err(error) => {
                    session.close();
                    trace_uncertain_commit_read(error);
                    return TransferOutcome::CommitStatusUnknown { bytes: transferred };
                }
                Ok(message) => message,
            }
        }
        _ = cancel_signal(cancel) => {
            session.close();
            return TransferOutcome::CommitStatusUnknown { bytes: transferred };
        }
    };
    match &committed_message {
        OwnedMessage::Committed => {
            if let Err(outcome) = record_received(session, &committed_message, &[]) {
                return outcome;
            }
            TransferOutcome::Committed { bytes: transferred }
        }
        OwnedMessage::Cancel => {
            let _ = session.receive(&FileTransferMessage::Cancel);
            TransferOutcome::CommitStatusUnknown { bytes: transferred }
        }
        OwnedMessage::Error { code } => {
            if let Err(outcome) = record_received(session, &committed_message, &[]) {
                return outcome;
            }
            TransferOutcome::Failed(*code)
        }
        _ => {
            session.close();
            TransferOutcome::CommitStatusUnknown { bytes: transferred }
        }
    }
}

/// Reads exactly one complete frame.
///
/// In [`ReadMode::Control`] the whole frame must arrive within the fixed
/// budget; in [`ReadMode::Data`] every byte must make progress within the
/// budget (the deadline refreshes on each partial read) and `Data` payloads
/// are copied into `data_sink` (which must cover at least `MAX_DATA_LEN`
/// bytes). A `Data` frame outside the data phase is a protocol violation.
/// The wire session is not touched here; the caller records the message
/// after deciding how to react (for example the best-effort `Error(Cancelled)`
/// reply must be sent before the `Cancel` is recorded).
async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    mode: ReadMode,
    data_sink: Option<&mut [u8]>,
) -> Result<OwnedMessage, FrameReadError> {
    match mode {
        ReadMode::Control { budget } => {
            match tokio::time::timeout(budget, read_frame_inner(stream, data_sink, None)).await {
                Err(_) => Err(FrameReadError::Timeout),
                Ok(result) => result,
            }
        }
        ReadMode::Data { budget } => read_frame_inner(stream, data_sink, Some(budget)).await,
    }
}

async fn read_frame_inner<S: AsyncRead + Unpin>(
    stream: &mut S,
    data_sink: Option<&mut [u8]>,
    chunk_budget: Option<Duration>,
) -> Result<OwnedMessage, FrameReadError> {
    let mut header = [0_u8; FRAME_HEADER_LEN];
    read_exact(stream, &mut header, chunk_budget).await?;
    let tag = header[0];
    let payload_len = usize::try_from(u32::from_be_bytes([
        header[1], header[2], header[3], header[4],
    ]))
    .unwrap_or(usize::MAX);
    // The length is validated against the tag's fixed bounds before any
    // payload byte is read or any buffer is filled (design 10.1).
    validate_payload_len(tag, payload_len).map_err(|_| FrameReadError::Protocol)?;
    if tag == TransferTag::Data.code() {
        let sink = data_sink
            .filter(|sink| sink.len() >= payload_len)
            .ok_or(FrameReadError::Protocol)?;
        read_exact(stream, &mut sink[..payload_len], chunk_budget).await?;
        return Ok(OwnedMessage::Data { len: payload_len });
    }
    // Control frames decode from a bounded stack buffer (payload at most
    // 8 KiB, design 15.1).
    let mut frame = [0_u8; MAX_CONTROL_FRAME_LEN];
    frame[..FRAME_HEADER_LEN].copy_from_slice(&header);
    read_exact(
        stream,
        &mut frame[FRAME_HEADER_LEN..FRAME_HEADER_LEN + payload_len],
        chunk_budget,
    )
    .await?;
    let message = FileTransferMessage::decode_frame(&frame[..FRAME_HEADER_LEN + payload_len])
        .map_err(|_| FrameReadError::Protocol)?;
    owned_message(message)
}

/// Reads exactly `buf.len()` bytes. With a `chunk_budget` every partial read
/// restarts the budget (no-progress semantics); without one the caller owns
/// the deadline. EOF at the start of the read is a boundary EOF, EOF in the
/// middle is a truncated frame.
async fn read_exact<S: AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut [u8],
    chunk_budget: Option<Duration>,
) -> Result<(), FrameReadError> {
    let mut filled = 0;
    while filled < buf.len() {
        let read = match chunk_budget {
            Some(budget) => {
                match tokio::time::timeout(budget, stream.read(&mut buf[filled..])).await {
                    Ok(read) => read,
                    Err(_) => {
                        return Err(FrameReadError::Timeout);
                    }
                }
            }
            None => stream.read(&mut buf[filled..]).await,
        };
        match read {
            Ok(0) => {
                return Err(if filled == 0 {
                    FrameReadError::Eof
                } else {
                    FrameReadError::Truncated
                });
            }
            Ok(n) => filled += n,
            Err(error) => return Err(FrameReadError::Io(error)),
        }
    }
    Ok(())
}

/// Converts a decoded control message into its owned form. `Data` never
/// reaches the decoder (the tag dispatch streams it into the sink); the arm
/// is kept total and defensive instead of panicking.
fn owned_message(message: FileTransferMessage<'_>) -> Result<OwnedMessage, FrameReadError> {
    match message {
        FileTransferMessage::UploadOpen {
            destination,
            file_name,
            declared_size,
        } => Ok(OwnedMessage::UploadOpen {
            destination: destination.to_owned(),
            file_name: file_name.to_owned(),
            declared_size,
        }),
        FileTransferMessage::DownloadOpen { source } => Ok(OwnedMessage::DownloadOpen {
            source: source.to_owned(),
        }),
        FileTransferMessage::DownloadOffer {
            file_name,
            declared_size,
        } => Ok(OwnedMessage::DownloadOffer {
            file_name: file_name.to_owned(),
            declared_size,
        }),
        FileTransferMessage::Ready => Ok(OwnedMessage::Ready),
        FileTransferMessage::Data { .. } => Err(FrameReadError::Protocol),
        FileTransferMessage::Finish {
            actual_size,
            digest,
        } => Ok(OwnedMessage::Finish {
            actual_size,
            digest,
        }),
        FileTransferMessage::Committed => Ok(OwnedMessage::Committed),
        FileTransferMessage::Cancel => Ok(OwnedMessage::Cancel),
        FileTransferMessage::Error { code } => Ok(OwnedMessage::Error { code }),
    }
}

/// Writes one complete frame (header plus payload, then a flush). The wire
/// session records the send before any byte is written, so an illegal local
/// send never reaches the substream.
async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    session: &mut WireSession,
    message: &FileTransferMessage<'_>,
) -> Result<(), WriteFrameError> {
    session
        .send(message)
        .map_err(|_| WriteFrameError::Protocol)?;
    write_frame_raw(stream, message)
        .await
        .map_err(|error| WriteFrameError::Io {
            error,
            started: true,
        })
}

/// Writes one legal frame with the configured bounded control/data semantics
/// and session cancellation. The wire transition is committed before external
/// bytes, while `started` preserves the post-`Finish` uncertainty boundary.
async fn write_frame_bounded<S: AsyncWrite + Unpin>(
    stream: &mut S,
    session: &mut WireSession,
    message: &FileTransferMessage<'_>,
    mode: WriteMode,
    cancel: &AtomicBool,
) -> Result<(), WriteFrameError> {
    if cancel.load(Ordering::Relaxed) {
        return Err(WriteFrameError::Cancelled { started: false });
    }
    session
        .send(message)
        .map_err(|_| WriteFrameError::Protocol)?;

    let control_deadline = match mode {
        WriteMode::Control { budget } => Some(tokio::time::Instant::now() + budget),
        WriteMode::Data { .. } => None,
    };
    let mut started = false;
    match message {
        FileTransferMessage::Data { bytes } => {
            let header = encode_frame_header(
                TransferTag::Data.code(),
                u32::try_from(bytes.len()).map_err(|_| WriteFrameError::Protocol)?,
            );
            write_bytes_bounded(
                stream,
                &header,
                mode,
                control_deadline,
                cancel,
                &mut started,
            )
            .await?;
            write_bytes_bounded(stream, bytes, mode, control_deadline, cancel, &mut started)
                .await?;
        }
        _ => {
            let encoded = message.encode().map_err(|_| WriteFrameError::Protocol)?;
            write_bytes_bounded(
                stream,
                encoded.as_slice(),
                mode,
                control_deadline,
                cancel,
                &mut started,
            )
            .await?;
        }
    }
    write_flush_bounded(stream, mode, control_deadline, cancel, started).await
}

async fn write_bytes_bounded<S: AsyncWrite + Unpin>(
    stream: &mut S,
    bytes: &[u8],
    mode: WriteMode,
    control_deadline: Option<tokio::time::Instant>,
    cancel: &AtomicBool,
    started: &mut bool,
) -> Result<(), WriteFrameError> {
    let mut written = 0;
    while written < bytes.len() {
        let deadline = match mode {
            WriteMode::Control { .. } => {
                control_deadline.expect("a control write owns one absolute deadline")
            }
            WriteMode::Data { budget } => tokio::time::Instant::now() + budget,
        };
        let result = tokio::select! {
            biased;
            _ = cancel_signal(cancel) => {
                return Err(WriteFrameError::Cancelled { started: *started });
            }
            result = tokio::time::timeout_at(deadline, stream.write(&bytes[written..])) => result,
        };
        let count = match result {
            Err(_) => return Err(WriteFrameError::Timeout { started: *started }),
            Ok(Err(error)) => {
                return Err(WriteFrameError::Io {
                    error,
                    started: *started,
                });
            }
            Ok(Ok(0)) => {
                return Err(WriteFrameError::Io {
                    error: io::Error::new(
                        io::ErrorKind::WriteZero,
                        "file transfer write made no progress",
                    ),
                    started: *started,
                });
            }
            Ok(Ok(count)) => count,
        };
        *started = true;
        written += count;
    }
    Ok(())
}

async fn write_flush_bounded<S: AsyncWrite + Unpin>(
    stream: &mut S,
    mode: WriteMode,
    control_deadline: Option<tokio::time::Instant>,
    cancel: &AtomicBool,
    started: bool,
) -> Result<(), WriteFrameError> {
    let deadline = match mode {
        WriteMode::Control { .. } => {
            control_deadline.expect("a control write owns one absolute deadline")
        }
        WriteMode::Data { budget } => tokio::time::Instant::now() + budget,
    };
    tokio::select! {
        biased;
        _ = cancel_signal(cancel) => Err(WriteFrameError::Cancelled { started }),
        result = tokio::time::timeout_at(deadline, stream.flush()) => match result {
            Err(_) => Err(WriteFrameError::Timeout { started }),
            Ok(Err(error)) => Err(WriteFrameError::Io { error, started }),
            Ok(Ok(())) => Ok(()),
        },
    }
}

/// Writes a frame without the session transition. Used by the best-effort
/// notifications (the session state around them is already decided) and by
/// the fault-injection tests.
async fn write_frame_raw<S: AsyncWrite + Unpin>(
    stream: &mut S,
    message: &FileTransferMessage<'_>,
) -> Result<(), io::Error> {
    match message {
        FileTransferMessage::Data { bytes } => {
            let header = encode_frame_header(
                TransferTag::Data.code(),
                u32::try_from(bytes.len()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "data block exceeds u32")
                })?,
            );
            stream.write_all(&header).await?;
            stream.write_all(bytes).await?;
        }
        _ => {
            let encoded = message.encode().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "control frame encoding")
            })?;
            stream.write_all(encoded.as_slice()).await?;
        }
    }
    stream.flush().await
}

/// Sends one frame without propagating failure: bounded by the control
/// budget and any error (including a wire-session rejection) ignored. Used
/// for `Cancel` and `Error` notifications, which are best effort (design
/// 10.5, 16.2).
async fn best_effort_send<S: AsyncWrite + Unpin>(
    stream: &mut S,
    session: &mut WireSession,
    config: &TransferConfig,
    message: FileTransferMessage<'_>,
) {
    let _ = tokio::time::timeout(
        config.control_timeout,
        write_frame(stream, session, &message),
    )
    .await;
}

/// Maps a local file-semantics failure: a fixed wire code becomes an `Error`
/// message, a purely local failure closes the substream silently and reports
/// the fallback code (design 10.4: local failures without a fixed code are
/// never told to the peer).
async fn fail_local<S: AsyncWrite + Unpin>(
    stream: &mut S,
    session: &mut WireSession,
    config: &TransferConfig,
    error: FileSemanticsError,
    fallback: FileTransferErrorCode,
) -> TransferOutcome {
    match error.wire_code() {
        Some(code) => {
            let message = FileTransferMessage::Error { code };
            // The frame is written before the session transition: the
            // frozen wire session records `Error` sends only from a subset
            // of stages, while the design's direction table allows `Error`
            // in any non-terminal stage and the peer accepts it wherever it
            // reads. When the session rejects the send (a pre-`Ready` or
            // post-`Finish` receiver failure), the frame is still written
            // and the session is closed explicitly.
            let recorded = session.send(&message).is_ok();
            let _ = tokio::time::timeout(config.control_timeout, write_frame_raw(stream, &message))
                .await;
            if !recorded {
                session.close();
            }
            TransferOutcome::Failed(code)
        }
        None => {
            session.close();
            TransferOutcome::Failed(fallback)
        }
    }
}

/// A failed frame write aborts the transfer: the substream is closed and the
/// failure is reported locally (a stream I/O failure maps to `SessionClosing`,
/// an illegal local send to `InvalidRequest`).
fn send_failure(session: &mut WireSession, error: WriteFrameError) -> TransferOutcome {
    session.close();
    match error {
        WriteFrameError::Protocol => TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest),
        WriteFrameError::Cancelled { .. } => TransferOutcome::Cancelled,
        WriteFrameError::Timeout { .. } => {
            tracing::debug!("file transfer substream write timed out");
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        }
        WriteFrameError::Io { error, .. } => {
            tracing::debug!(%error, "file transfer substream write failure");
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        }
    }
}

/// The receiver has already committed the verified file. A failure while
/// sending `Committed` can no longer be represented as an ordinary failed
/// transfer because the local target exists.
fn committed_ack_failure(
    session: &mut WireSession,
    error: WriteFrameError,
    bytes: u64,
) -> TransferOutcome {
    session.close();
    match error {
        WriteFrameError::Protocol => {
            tracing::debug!("wire state rejected the post-commit acknowledgement");
        }
        WriteFrameError::Timeout { .. } => {
            tracing::debug!("post-commit acknowledgement write timed out");
        }
        WriteFrameError::Cancelled { .. } => {
            tracing::debug!("post-commit acknowledgement was cancelled");
        }
        WriteFrameError::Io { error, .. } => {
            tracing::debug!(%error, "post-commit acknowledgement write failed");
        }
    }
    TransferOutcome::CommittedUnconfirmed { bytes }
}

fn finish_send_failure(
    session: &mut WireSession,
    error: WriteFrameError,
    bytes: u64,
) -> TransferOutcome {
    session.close();
    match error {
        WriteFrameError::Protocol => TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest),
        WriteFrameError::Cancelled { started: false } => TransferOutcome::Cancelled,
        WriteFrameError::Cancelled { started: true }
        | WriteFrameError::Timeout { started: true } => {
            TransferOutcome::CommitStatusUnknown { bytes }
        }
        WriteFrameError::Timeout { started: false } => {
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        }
        WriteFrameError::Io { error, started } => {
            tracing::debug!(%error, "Finish frame write failed");
            if started {
                TransferOutcome::CommitStatusUnknown { bytes }
            } else {
                TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
            }
        }
    }
}

fn trace_uncertain_commit_read(error: FrameReadError) {
    match error {
        FrameReadError::Io(error) => {
            tracing::debug!(%error, "post-Finish commit acknowledgement read failed");
        }
        FrameReadError::Protocol => {
            tracing::debug!("post-Finish commit acknowledgement was invalid");
        }
        FrameReadError::Truncated => {
            tracing::debug!("post-Finish commit acknowledgement was truncated");
        }
        FrameReadError::Eof => {
            tracing::debug!("post-Finish commit acknowledgement reached EOF");
        }
        FrameReadError::Timeout => {
            tracing::debug!("post-Finish commit acknowledgement timed out");
        }
    }
}

/// A failed frame read aborts the transfer; the substream is already closed
/// by the caller. Protocol violations (unknown tag, invalid length, decode
/// failure, truncated frame) fail with `InvalidRequest`; boundary EOF,
/// deadlines and stream I/O failures fail with `SessionClosing` (the closest
/// fixed code for a peer that went away or stopped making progress).
fn read_failure_outcome(error: FrameReadError) -> TransferOutcome {
    let code = match error {
        FrameReadError::Protocol | FrameReadError::Truncated => {
            FileTransferErrorCode::InvalidRequest
        }
        FrameReadError::Eof | FrameReadError::Timeout => FileTransferErrorCode::SessionClosing,
        FrameReadError::Io(error) => {
            tracing::debug!(%error, "file transfer substream read failure");
            FileTransferErrorCode::SessionClosing
        }
    };
    TransferOutcome::Failed(code)
}

/// A protocol violation in the wire session or the frame stream: the
/// substream is closed and the transfer fails with `InvalidRequest` (design
/// 10.1, 10.5).
fn protocol_violation(session: &mut WireSession) -> TransferOutcome {
    session.close();
    TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
}

/// Records a received message in the wire session; an illegal sequence is a
/// protocol violation. The data slice carries the payload of a `Data`
/// message and is ignored for every other variant.
fn record_received(
    session: &mut WireSession,
    message: &OwnedMessage,
    data: &[u8],
) -> Result<(), TransferOutcome> {
    let wire = match message {
        OwnedMessage::UploadOpen {
            destination,
            file_name,
            declared_size,
        } => FileTransferMessage::UploadOpen {
            destination,
            file_name,
            declared_size: *declared_size,
        },
        OwnedMessage::DownloadOpen { source } => FileTransferMessage::DownloadOpen { source },
        OwnedMessage::DownloadOffer {
            file_name,
            declared_size,
        } => FileTransferMessage::DownloadOffer {
            file_name,
            declared_size: *declared_size,
        },
        OwnedMessage::Ready => FileTransferMessage::Ready,
        OwnedMessage::Data { .. } => FileTransferMessage::Data { bytes: data },
        OwnedMessage::Finish {
            actual_size,
            digest,
        } => FileTransferMessage::Finish {
            actual_size: *actual_size,
            digest: *digest,
        },
        OwnedMessage::Committed => FileTransferMessage::Committed,
        OwnedMessage::Cancel => FileTransferMessage::Cancel,
        OwnedMessage::Error { code } => FileTransferMessage::Error { code: *code },
    };
    match session.receive(&wire) {
        Ok(()) => Ok(()),
        Err(_) => Err(protocol_violation(session)),
    }
}

/// Resolves once the cancel flag is set, polling at a bounded interval so a
/// blocked read stays interruptible (design 15.2).
async fn cancel_signal(cancel: &AtomicBool) {
    if cancel.load(Ordering::Relaxed) {
        return;
    }
    let mut interval = tokio::time::interval(CANCEL_POLL_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if cancel.load(Ordering::Relaxed) {
            return;
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant, SystemTime};

    use tempfile::tempdir;
    use tokio::io::{ReadBuf, duplex};
    use tokio::sync::Notify;

    use crate::audit::observer::AuditObserver;
    use crate::audit::session::SPLIT_PREFIX_LEN;
    use crate::file_semantics::CHUNK_SIZE;
    use yonder_core::OsSecureRandom;
    use yonder_core::wire::audit::{AuditCloseReason, AuditRole, Digest32};
    use yonder_core::wire::audit_container::{ContainerReader, RecordType};
    use yonder_net::Keypair;

    // ------------------------------------------------------------------
    // Shared fixtures.
    // ------------------------------------------------------------------

    fn test_config() -> TransferConfig {
        TransferConfig {
            // Successful filesystem exchanges must not depend on a subsecond
            // scheduler slot while the complete suite is saturating the
            // native test host. Production retains its fixed 30 s budgets;
            // timeout-specific tests use `timeout_config` below.
            control_timeout: Duration::from_secs(5),
            data_progress_timeout: Duration::from_secs(5),
        }
    }

    fn timeout_config() -> TransferConfig {
        TransferConfig {
            control_timeout: Duration::from_millis(200),
            data_progress_timeout: Duration::from_millis(200),
        }
    }

    fn base_in_directory(directory: &Path) -> BaseDirectory {
        BaseDirectory::from_absolute_path_for_test(directory)
    }

    fn pattern_byte(index: u64) -> u8 {
        ((index * 31) + (index / 251) + (index >> 3)) as u8
    }

    fn write_pattern_file(path: &Path, size: u64) {
        let mut file = fs::File::create(path).unwrap();
        let mut buffer = [0_u8; CHUNK_SIZE];
        let mut remaining = size;
        let mut offset = 0_u64;
        while remaining > 0 {
            let n = remaining.min(CHUNK_SIZE as u64) as usize;
            for (i, byte) in buffer[..n].iter_mut().enumerate() {
                *byte = pattern_byte(offset + i as u64);
            }
            file.write_all(&buffer[..n]).unwrap();
            remaining -= n as u64;
            offset += n as u64;
        }
        file.sync_all().unwrap();
    }

    fn sha256(bytes: &[u8]) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Sha256Digest::new(hasher.finalize().into())
    }

    /// A deterministic source used to prove that transfer orchestration
    /// consumes the backend's associated source type instead of reopening a
    /// production filesystem handle behind the trait boundary.
    struct MemorySource {
        bytes: Vec<u8>,
        offset: usize,
    }

    impl TransferSource for MemorySource {
        fn size(&self) -> u64 {
            u64::try_from(self.bytes.len()).expect("the test payload fits in u64")
        }

        fn bytes_read(&self) -> u64 {
            u64::try_from(self.offset).expect("the test offset fits in u64")
        }

        async fn read_block(&mut self, buffer: &mut [u8]) -> Result<usize, FileSemanticsError> {
            let remaining = &self.bytes[self.offset..];
            let len = remaining.len().min(buffer.len());
            buffer[..len].copy_from_slice(&remaining[..len]);
            self.offset += len;
            Ok(len)
        }

        async fn recheck_source(&self) -> Result<(), FileSemanticsError> {
            Ok(())
        }
    }

    /// Replaces source opening while delegating the receiver-only backend
    /// capabilities. The nonexistent path used by the regression below makes
    /// an accidental fallback to Tokio's production opener fail immediately.
    struct MemorySourceBackend {
        payload: Vec<u8>,
        opened: AtomicBool,
    }

    impl FileTransferBackend for MemorySourceBackend {
        type Source = MemorySource;
        type Temp = <TokioFileTransferBackend as FileTransferBackend>::Temp;

        async fn open_source(&self, _path: PathBuf) -> Result<Self::Source, FileSemanticsError> {
            self.opened.store(true, Ordering::Release);
            Ok(MemorySource {
                bytes: self.payload.clone(),
                offset: 0,
            })
        }

        async fn resolve_destination(
            &self,
            base: BaseDirectory,
            explicit_target: Option<String>,
            default_name: Option<String>,
        ) -> Result<crate::file_semantics::DestinationPlan, FileSemanticsError> {
            TokioFileTransferBackend
                .resolve_destination(base, explicit_target, default_name)
                .await
        }

        async fn create_temp(&self, directory: PathBuf) -> Result<Self::Temp, FileSemanticsError> {
            TokioFileTransferBackend.create_temp(directory).await
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ReceiverFault {
        Create,
        Write,
        Finish,
        Commit,
    }

    struct FaultingReceiverBackend {
        fault: ReceiverFault,
    }

    struct FaultingTempFile {
        fault: ReceiverFault,
        bytes: Vec<u8>,
    }

    struct FaultingSealedTempFile {
        fault: ReceiverFault,
        bytes: Vec<u8>,
    }

    impl TransferTempFile for FaultingTempFile {
        type Sealed = FaultingSealedTempFile;

        async fn write_block_async(&mut self, bytes: &[u8]) -> Result<(), FileSemanticsError> {
            if self.fault == ReceiverFault::Write {
                return Err(FileSemanticsError::WriteFailed(io::Error::other(
                    "injected block write failure",
                )));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(())
        }

        async fn finish_async(self) -> Result<Self::Sealed, FileSemanticsError> {
            if self.fault == ReceiverFault::Finish {
                return Err(FileSemanticsError::WriteFailed(io::Error::other(
                    "injected finish failure",
                )));
            }
            Ok(FaultingSealedTempFile {
                fault: self.fault,
                bytes: self.bytes,
            })
        }
    }

    impl SealedTransferTempFile for FaultingSealedTempFile {
        fn written(&self) -> u64 {
            u64::try_from(self.bytes.len()).expect("the test payload fits in u64")
        }

        fn verify_finish(
            &self,
            declared_size: u64,
            declared_digest: Sha256Digest,
        ) -> Result<(), FileSemanticsError> {
            let written = self.written();
            if written != declared_size {
                return Err(FileSemanticsError::SizeMismatch {
                    declared: declared_size,
                    received: written,
                });
            }
            if sha256(&self.bytes) != declared_digest {
                return Err(FileSemanticsError::DigestMismatch);
            }
            Ok(())
        }

        async fn commit_async(self, _final_path: PathBuf) -> Result<(), FileSemanticsError> {
            if self.fault == ReceiverFault::Commit {
                return Err(FileSemanticsError::CommitFailed(io::Error::other(
                    "injected commit failure",
                )));
            }
            Ok(())
        }
    }

    impl FileTransferBackend for FaultingReceiverBackend {
        type Source = MemorySource;
        type Temp = FaultingTempFile;

        async fn open_source(&self, _path: PathBuf) -> Result<Self::Source, FileSemanticsError> {
            Ok(MemorySource {
                bytes: Vec::new(),
                offset: 0,
            })
        }

        async fn resolve_destination(
            &self,
            base: BaseDirectory,
            explicit_target: Option<String>,
            default_name: Option<String>,
        ) -> Result<crate::file_semantics::DestinationPlan, FileSemanticsError> {
            TokioFileTransferBackend
                .resolve_destination(base, explicit_target, default_name)
                .await
        }

        async fn create_temp(&self, _directory: PathBuf) -> Result<Self::Temp, FileSemanticsError> {
            if self.fault == ReceiverFault::Create {
                return Err(FileSemanticsError::TempFileCreateFailed(io::Error::other(
                    "injected temporary-file creation failure",
                )));
            }
            Ok(FaultingTempFile {
                fault: self.fault,
                bytes: Vec::new(),
            })
        }
    }

    #[test]
    fn non_utf8_local_paths_are_omitted_from_audit_without_lossy_conversion() {
        #[cfg(unix)]
        let path = {
            use std::os::unix::ffi::OsStringExt as _;
            PathBuf::from(std::ffi::OsString::from_vec(vec![0xFF]))
        };
        #[cfg(windows)]
        let path = {
            use std::os::windows::ffi::OsStringExt as _;
            PathBuf::from(std::ffi::OsString::from_wide(&[0xD800]))
        };
        assert_eq!(local_audit_path(&path), None);
    }

    fn recorded_local_file_paths(root: &tempfile::TempDir) -> Vec<String> {
        let records = root
            .path()
            .join("audit")
            .join(crate::audit::identity::RECORDS_DIR_NAME);
        let record = fs::read_dir(records)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.is_file())
            .expect("the observer created its session container");
        let bytes = fs::read(record).unwrap();
        let mut reader = ContainerReader::new(&bytes).unwrap();
        let mut paths = Vec::new();
        while let Some(frame) = reader.next_frame().unwrap() {
            if frame.record_type != RecordType::LocalFileTransferEvent {
                continue;
            }
            let event = &frame.payload[SPLIT_PREFIX_LEN..];
            if !matches!(event[0], FILE_KIND_START | FILE_KIND_SUCCESS) {
                continue;
            }
            let path_len = u16::from_be_bytes(event[9..11].try_into().unwrap()) as usize;
            paths.push(
                std::str::from_utf8(&event[11..11 + path_len])
                    .unwrap()
                    .to_owned(),
            );
        }
        paths
    }

    fn assert_dir_entries(path: &Path, expected: &[&Path]) {
        let mut entries: Vec<PathBuf> = fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        entries.sort();
        let mut expected: Vec<PathBuf> = expected.iter().map(|p| p.to_path_buf()).collect();
        expected.sort();
        assert_eq!(entries, expected, "directory {:?} contents", path);
    }

    fn assert_dir_empty(path: &Path) {
        assert_eq!(
            fs::read_dir(path).unwrap().count(),
            0,
            "directory {:?} is not empty",
            path
        );
    }

    fn path_string(path: &Path) -> String {
        path.to_str().unwrap().to_owned()
    }

    async fn establish_audit_pair() -> (
        Arc<AuditObserver>,
        Arc<AuditObserver>,
        tempfile::TempDir,
        tempfile::TempDir,
    ) {
        let controller = Keypair::generate_ed25519().public().to_peer_id();
        let host = Keypair::generate_ed25519().public().to_peer_id();
        let (host_half, controller_half) = duplex(256 * 1024);
        let binding = Digest32::new([0xCF; 32]);
        let started_at = crate::audit::observer::utc_start_seconds();
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
                started_at,
                binding,
                &controller_root,
                &mut controller_random,
            )),
            Box::pin(AuditObserver::establish(
                host_half,
                AuditRole::Host,
                controller,
                host,
                started_at,
                binding,
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

    /// Reads a file into a `Vec` and chunks it for wire `Data` frames.
    fn file_chunks(path: &Path) -> (Vec<u8>, Vec<Vec<u8>>) {
        let bytes = fs::read(path).unwrap();
        let chunks = bytes
            .chunks(MAX_DATA_LEN)
            .map(|chunk| chunk.to_vec())
            .collect();
        (bytes, chunks)
    }

    // ------------------------------------------------------------------
    // A scripted peer for fault-injection tests, driven with the module's
    // own frame helpers over one duplex half while the real orchestrator
    // runs on the other.
    // ------------------------------------------------------------------

    struct ScriptedPeer<S> {
        stream: S,
        session: WireSession,
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> ScriptedPeer<S> {
        fn new(stream: S, direction: TransferDirection, side: TransferSide) -> Self {
            Self {
                stream,
                session: WireSession::new(direction, side),
            }
        }

        /// Sends a message through the scripted session (legal sends).
        async fn send(&mut self, message: FileTransferMessage<'_>) {
            write_frame(&mut self.stream, &mut self.session, &message)
                .await
                .unwrap();
        }

        /// Sends a frame without the wire-session transition, for illegal
        /// sequence injection.
        async fn send_fault(&mut self, message: FileTransferMessage<'_>) {
            write_frame_raw(&mut self.stream, &message).await.unwrap();
        }

        /// Writes raw bytes straight to the substream (fault injection).
        async fn raw_send(&mut self, bytes: &[u8]) {
            self.stream.write_all(bytes).await.unwrap();
        }

        /// Reads the next control frame and records it in the scripted
        /// session.
        async fn read_control(&mut self) -> OwnedMessage {
            let message = read_frame(
                &mut self.stream,
                ReadMode::Control {
                    budget: Duration::from_secs(10),
                },
                None,
            )
            .await
            .unwrap();
            record_received(&mut self.session, &message, &[])
                .expect("scripted peer violated the wire sequence");
            message
        }

        /// Reads the next frame in the data phase (payload copied into
        /// `sink`) and records it in the scripted session.
        async fn read_data(&mut self, sink: &mut [u8]) -> OwnedMessage {
            let message = read_frame(
                &mut self.stream,
                ReadMode::Data {
                    budget: Duration::from_secs(10),
                },
                Some(sink),
            )
            .await
            .unwrap();
            record_received(&mut self.session, &message, &[])
                .expect("scripted peer violated the wire sequence");
            message
        }

        /// Reads the next control frame without recording it, for assertions
        /// on messages that are illegal for the scripted role (for example a
        /// `Cancel` the real controller sent to the download host).
        async fn read_unchecked(&mut self) -> OwnedMessage {
            read_frame(
                &mut self.stream,
                ReadMode::Control {
                    budget: Duration::from_secs(10),
                },
                None,
            )
            .await
            .unwrap()
        }
    }

    #[tokio::test]
    async fn download_send_orchestration_uses_the_selected_backend_source() {
        let root = tempdir().unwrap();
        let base = base_in_directory(root.path());
        let payload = (0..(MAX_DATA_LEN + 17))
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        let payload_len = u64::try_from(payload.len()).unwrap();
        let expected_digest = sha256(&payload);
        let backend = MemorySourceBackend {
            payload: payload.clone(),
            opened: AtomicBool::new(false),
        };
        let cancel = AtomicBool::new(false);
        let config = test_config();
        let source_path = "virtual-source.bin";
        assert!(!root.path().join(source_path).exists());

        let (mut host_stream, controller_stream) = duplex(2 * MAX_DATA_LEN);
        let mut host_session = WireSession::new(TransferDirection::Download, TransferSide::Host);
        host_session
            .receive(&FileTransferMessage::DownloadOpen {
                source: source_path,
            })
            .unwrap();
        let mut peer = ScriptedPeer::new(
            controller_stream,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        peer.session
            .send(&FileTransferMessage::DownloadOpen {
                source: source_path,
            })
            .unwrap();
        let mut facts = TransferAuditFacts::default();

        let (outcome, received) = tokio::join!(
            download_send_tail(
                &mut host_stream,
                &config,
                &base,
                &cancel,
                &mut host_session,
                source_path,
                None,
                &mut facts,
                &backend,
            ),
            async {
                assert_eq!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOffer {
                        file_name: source_path.to_owned(),
                        declared_size: payload_len,
                    }
                );
                peer.send(FileTransferMessage::Ready).await;
                let mut received = Vec::with_capacity(payload.len());
                let mut data = Box::new([0_u8; MAX_DATA_LEN]);
                loop {
                    match peer.read_data(&mut *data).await {
                        OwnedMessage::Data { len } => received.extend_from_slice(&data[..len]),
                        OwnedMessage::Finish {
                            actual_size,
                            digest,
                        } => {
                            assert_eq!(actual_size, payload_len);
                            assert_eq!(digest, expected_digest);
                            peer.send(FileTransferMessage::Committed).await;
                            break;
                        }
                        message => panic!("unexpected download frame: {message:?}"),
                    }
                }
                received
            },
        );

        assert_eq!(outcome, TransferOutcome::Committed { bytes: payload_len });
        assert_eq!(received, payload);
        assert!(backend.opened.load(Ordering::Acquire));
        assert_eq!(facts.digest, Some(expected_digest));
    }

    #[tokio::test]
    async fn transfer_receivers_reject_a_peer_error_as_an_invalid_opening_frame() {
        let root = tempdir().unwrap();
        let base = base_in_directory(root.path());
        let config = test_config();
        let cancel = AtomicBool::new(false);
        let backend = FaultingReceiverBackend {
            fault: ReceiverFault::Commit,
        };

        let (mut upload_host, mut upload_peer) = duplex(1024);
        write_frame_raw(
            &mut upload_peer,
            &FileTransferMessage::Error {
                code: FileTransferErrorCode::PermissionDenied,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            handle_upload_impl(&mut upload_host, &config, &base, &cancel, &backend).await,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );

        let (mut download_host, mut download_peer) = duplex(1024);
        write_frame_raw(
            &mut download_peer,
            &FileTransferMessage::Error {
                code: FileTransferErrorCode::SourceNotFound,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            handle_download_impl(&mut download_host, &config, &base, &cancel, &backend).await,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
    }

    #[tokio::test]
    async fn download_source_without_a_final_name_is_rejected_before_an_offer() {
        let root = tempdir().unwrap();
        let base = base_in_directory(root.path());
        let source_root = root
            .path()
            .ancestors()
            .last()
            .and_then(Path::to_str)
            .expect("the platform root is representable as UTF-8");
        let backend = MemorySourceBackend {
            payload: b"must not be offered".to_vec(),
            opened: AtomicBool::new(false),
        };
        let cancel = AtomicBool::new(false);
        let config = test_config();
        let (mut host_stream, _peer_stream) = duplex(1024);
        let mut session = WireSession::new(TransferDirection::Download, TransferSide::Host);
        session
            .receive(&FileTransferMessage::DownloadOpen {
                source: source_root,
            })
            .unwrap();

        let outcome = download_send_tail(
            &mut host_stream,
            &config,
            &base,
            &cancel,
            &mut session,
            source_root,
            None,
            &mut TransferAuditFacts::default(),
            &backend,
        )
        .await;

        assert!(backend.opened.load(Ordering::Acquire));
        assert!(session.is_closed());
        assert_eq!(
            outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
    }

    async fn controller_download_receiver_fault(
        fault: ReceiverFault,
    ) -> (TransferOutcome, Option<OwnedMessage>) {
        let root = tempdir().unwrap();
        let base = base_in_directory(root.path());
        let target = path_string(&root.path().join("received.bin"));
        let payload = b"receiver-fault";
        let config = test_config();
        let cancel = AtomicBool::new(false);
        let backend = FaultingReceiverBackend { fault };
        let (mut controller_stream, host_stream) = duplex(64 * 1024);
        let mut peer =
            ScriptedPeer::new(host_stream, TransferDirection::Download, TransferSide::Host);
        let mut facts = TransferAuditFacts::default();

        let (outcome, response) = tokio::join!(
            run_download_impl(
                &mut controller_stream,
                &config,
                &base,
                "remote.bin",
                Some(&target),
                &cancel,
                TransferAuditContext {
                    observer: None,
                    facts: &mut facts,
                },
                &backend,
            ),
            async {
                assert_eq!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOpen {
                        source: "remote.bin".to_owned(),
                    }
                );
                peer.send(FileTransferMessage::DownloadOffer {
                    file_name: "remote.bin",
                    declared_size: payload.len() as u64,
                })
                .await;
                if fault == ReceiverFault::Create {
                    return None;
                }
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                peer.send(FileTransferMessage::Data { bytes: payload })
                    .await;
                if fault != ReceiverFault::Write {
                    peer.send(FileTransferMessage::Finish {
                        actual_size: payload.len() as u64,
                        digest: sha256(payload),
                    })
                    .await;
                }
                Some(peer.read_unchecked().await)
            },
        );
        assert!(!Path::new(&target).exists());
        (outcome, response)
    }

    async fn host_upload_receiver_fault(
        fault: ReceiverFault,
    ) -> (TransferOutcome, Option<OwnedMessage>) {
        let root = tempdir().unwrap();
        let base = base_in_directory(root.path());
        let target = path_string(&root.path().join("received.bin"));
        let payload = b"receiver-fault";
        let config = test_config();
        let cancel = AtomicBool::new(false);
        let backend = FaultingReceiverBackend { fault };
        let (controller_stream, mut host_stream) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_stream,
            TransferDirection::Upload,
            TransferSide::Controller,
        );

        let (outcome, response) = tokio::join!(
            handle_upload_impl(&mut host_stream, &config, &base, &cancel, &backend),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &target,
                    file_name: "remote.bin",
                    declared_size: payload.len() as u64,
                })
                .await;
                if fault == ReceiverFault::Create {
                    return None;
                }
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                peer.send(FileTransferMessage::Data { bytes: payload })
                    .await;
                if fault != ReceiverFault::Write {
                    peer.send(FileTransferMessage::Finish {
                        actual_size: payload.len() as u64,
                        digest: sha256(payload),
                    })
                    .await;
                }
                Some(peer.read_unchecked().await)
            },
        );
        assert!(!Path::new(&target).exists());
        (outcome, response)
    }

    #[tokio::test]
    async fn controller_download_receiver_maps_every_backend_failure_boundary() {
        for (fault, expected) in [
            (ReceiverFault::Create, FileTransferErrorCode::InvalidRequest),
            (ReceiverFault::Write, FileTransferErrorCode::WriteFailed),
            (ReceiverFault::Finish, FileTransferErrorCode::WriteFailed),
            (ReceiverFault::Commit, FileTransferErrorCode::CommitFailed),
        ] {
            let (outcome, response) = controller_download_receiver_fault(fault).await;
            assert_eq!(outcome, TransferOutcome::Failed(expected), "{fault:?}");
            if fault == ReceiverFault::Create {
                assert_eq!(response, None);
            } else {
                assert_eq!(response, Some(OwnedMessage::Error { code: expected }));
            }
        }
    }

    #[tokio::test]
    async fn host_upload_receiver_maps_every_backend_failure_boundary() {
        for (fault, expected) in [
            (ReceiverFault::Create, FileTransferErrorCode::InvalidRequest),
            (ReceiverFault::Write, FileTransferErrorCode::WriteFailed),
            (ReceiverFault::Finish, FileTransferErrorCode::WriteFailed),
            (ReceiverFault::Commit, FileTransferErrorCode::CommitFailed),
        ] {
            let (outcome, response) = host_upload_receiver_fault(fault).await;
            assert_eq!(outcome, TransferOutcome::Failed(expected), "{fault:?}");
            if fault == ReceiverFault::Create {
                assert_eq!(response, None);
            } else {
                assert_eq!(response, Some(OwnedMessage::Error { code: expected }));
            }
        }
    }

    /// Wraps a duplex half and fires a one-shot notification the first time
    /// a single read returns at least `threshold` bytes, letting tests
    /// synchronize on the peer entering the data phase (the opening control
    /// frames are far smaller than any data block).
    struct ReadThresholdNotify<S> {
        inner: S,
        threshold: usize,
        notify: Option<Arc<Notify>>,
    }

    impl<S> ReadThresholdNotify<S> {
        fn new(inner: S, threshold: usize, notify: Arc<Notify>) -> Self {
            Self {
                inner,
                threshold,
                notify: Some(notify),
            }
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for ReadThresholdNotify<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let result = Pin::new(&mut self.inner).poll_read(cx, buf);
            if result.is_ready()
                && buf.filled().len() >= self.threshold
                && let Some(notify) = self.notify.take()
            {
                notify.notify_one();
            }
            result
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for ReadThresholdNotify<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    // ------------------------------------------------------------------
    // Unit tests of the private helpers.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn local_failure_mapping_sends_wire_codes_and_closes_for_local_codes() {
        // A failure with a fixed wire code produces an Error frame and the
        // corresponding outcome. The controller session is moved into the
        // data phase first, where sending `Error` is legal.
        let mut session = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        session
            .send(&FileTransferMessage::UploadOpen {
                destination: "",
                file_name: "f",
                declared_size: 0,
            })
            .unwrap();
        session.receive(&FileTransferMessage::Ready).unwrap();
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(host_half, TransferDirection::Upload, TransferSide::Host);
        let mut controller_stream = controller_half;
        let config = test_config();
        let outcome = fail_local(
            &mut controller_stream,
            &mut session,
            &config,
            FileSemanticsError::DestinationExists,
            FileTransferErrorCode::InvalidRequest,
        )
        .await;
        assert_eq!(
            outcome,
            TransferOutcome::Failed(FileTransferErrorCode::DestinationExists)
        );
        assert!(session.is_closed());
        assert_eq!(
            peer.read_unchecked().await,
            OwnedMessage::Error {
                code: FileTransferErrorCode::DestinationExists
            }
        );

        // A purely local failure (no wire code) closes the substream without
        // a message and reports the fallback code.
        let mut session = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        session
            .send(&FileTransferMessage::UploadOpen {
                destination: "",
                file_name: "f",
                declared_size: 0,
            })
            .unwrap();
        session.receive(&FileTransferMessage::Ready).unwrap();
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(host_half, TransferDirection::Upload, TransferSide::Host);
        let mut controller_stream = controller_half;
        let outcome = fail_local(
            &mut controller_stream,
            &mut session,
            &config,
            FileSemanticsError::Io(io::Error::other("local failure")),
            FileTransferErrorCode::InvalidRequest,
        )
        .await;
        assert_eq!(
            outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
        assert!(session.is_closed());
        let frame = tokio::time::timeout(Duration::from_millis(50), peer.read_unchecked()).await;
        assert!(frame.is_err(), "no frame may reach the peer");
    }

    #[test]
    fn read_failure_outcome_maps_categories() {
        for error in [
            FrameReadError::Eof,
            FrameReadError::Timeout,
            FrameReadError::Io(io::Error::other("test")),
        ] {
            assert_eq!(
                read_failure_outcome(error),
                TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
            );
        }
        for error in [FrameReadError::Protocol, FrameReadError::Truncated] {
            assert_eq!(
                read_failure_outcome(error),
                TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
            );
        }
    }

    #[test]
    fn uncertain_commit_diagnostics_cover_every_structured_failure() {
        for error in [
            FrameReadError::Io(io::Error::other("injected read failure")),
            FrameReadError::Protocol,
            FrameReadError::Truncated,
            FrameReadError::Eof,
            FrameReadError::Timeout,
        ] {
            trace_uncertain_commit_read(error);
        }

        let mut session = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        assert_eq!(
            committed_ack_failure(&mut session, WriteFrameError::Protocol, 17),
            TransferOutcome::CommittedUnconfirmed { bytes: 17 }
        );
        assert!(session.is_closed());
    }

    #[tokio::test]
    async fn audited_transfer_end_records_every_terminal_outcome() {
        let (controller, host, _controller_dir, _host_dir) = establish_audit_pair().await;
        record_transfer_end(
            Some(controller.as_ref()),
            FILE_DIRECTION_UPLOAD,
            &TransferAuditFacts::default(),
            TransferOutcome::Cancelled,
        )
        .await
        .unwrap();
        let incomplete = TransferAuditFacts {
            started: true,
            remote_path: Some("remote/path".to_owned()),
            ..TransferAuditFacts::default()
        };
        record_transfer_end(
            Some(controller.as_ref()),
            FILE_DIRECTION_UPLOAD,
            &incomplete,
            TransferOutcome::Cancelled,
        )
        .await
        .unwrap();
        assert!(!controller.has_failed().await);

        let facts = TransferAuditFacts {
            started: true,
            remote_path: Some("remote/path".to_owned()),
            file_name: Some("file.bin".to_owned()),
            declared_size: Some(17),
            digest: Some(sha256(b"audited payload")),
            local_path: Some("local/path/file.bin".to_owned()),
        };

        for outcome in [
            TransferOutcome::Committed { bytes: 17 },
            TransferOutcome::Cancelled,
            TransferOutcome::Failed(FileTransferErrorCode::WriteFailed),
        ] {
            let (controller_end, host_end) = tokio::join!(
                record_transfer_end(
                    Some(controller.as_ref()),
                    FILE_DIRECTION_UPLOAD,
                    &facts,
                    outcome,
                ),
                record_transfer_end(Some(host.as_ref()), FILE_DIRECTION_UPLOAD, &facts, outcome,),
            );
            controller_end.unwrap();
            host_end.unwrap();
            assert!(!controller.has_failed().await);
            assert!(!host.has_failed().await);
        }

        let (controller, host, _controller_dir, _host_dir) = establish_audit_pair().await;
        let mut controller_facts = TransferAuditFacts {
            digest: facts.digest,
            local_path: Some("controller/source.bin".to_owned()),
            ..TransferAuditFacts::default()
        };
        let mut host_facts = TransferAuditFacts {
            digest: facts.digest,
            local_path: Some("host/target.bin".to_owned()),
            ..TransferAuditFacts::default()
        };
        let (controller_start, host_start) = tokio::join!(
            record_transfer_start(
                Some(controller.as_ref()),
                &mut controller_facts,
                FILE_DIRECTION_UPLOAD,
                "remote/path",
                "file.bin",
                17,
            ),
            record_transfer_start(
                Some(host.as_ref()),
                &mut host_facts,
                FILE_DIRECTION_UPLOAD,
                "remote/path",
                "file.bin",
                17,
            ),
        );
        controller_start.unwrap();
        host_start.unwrap();
        let (controller_end, host_end) = tokio::join!(
            record_transfer_end(
                Some(controller.as_ref()),
                FILE_DIRECTION_UPLOAD,
                &controller_facts,
                TransferOutcome::CommitStatusUnknown { bytes: 17 },
            ),
            record_transfer_end(
                Some(host.as_ref()),
                FILE_DIRECTION_UPLOAD,
                &host_facts,
                TransferOutcome::CommittedUnconfirmed { bytes: 17 },
            ),
        );
        controller_end.unwrap();
        host_end.unwrap();
        assert!(!controller.has_failed().await);
        assert!(!host.has_failed().await);
    }

    #[tokio::test]
    async fn failed_abort_audit_is_reported_without_replacing_the_primary_outcome() {
        let (audit, peer_audit, _audit_dir, _peer_dir) = establish_audit_pair().await;
        let facts = TransferAuditFacts {
            started: true,
            remote_path: Some("remote/path".to_owned()),
            file_name: Some("file.bin".to_owned()),
            declared_size: Some(17),
            digest: None,
            local_path: Some("local/path/file.bin".to_owned()),
        };
        audit
            .fail_closed(None, AuditCloseReason::AuditFailure)
            .await;
        let primary = TransferOutcome::Failed(FileTransferErrorCode::WriteFailed);
        let audit_result =
            record_transfer_end(Some(audit.as_ref()), FILE_DIRECTION_UPLOAD, &facts, primary).await;
        assert!(audit_result.is_err());
        assert_eq!(apply_transfer_audit_result(primary, audit_result), primary);
        drop(peer_audit);
    }

    #[test]
    fn audit_outcome_mapping_changes_only_an_unrecorded_success() {
        let committed = TransferOutcome::Committed { bytes: 17 };
        assert_eq!(apply_transfer_audit_result(committed, Ok(())), committed);
        assert_eq!(
            apply_transfer_audit_result(committed, Err(AuditError::FailedClosed)),
            TransferOutcome::AuditFailed { bytes: 17 }
        );
        for primary in [
            TransferOutcome::Cancelled,
            TransferOutcome::Failed(FileTransferErrorCode::WriteFailed),
            TransferOutcome::CommittedUnconfirmed { bytes: 17 },
            TransferOutcome::CommitStatusUnknown { bytes: 17 },
        ] {
            assert_eq!(
                apply_transfer_audit_result(primary, Err(AuditError::FailedClosed)),
                primary
            );
        }
    }

    #[tokio::test]
    async fn audit_failure_after_wire_commit_cannot_report_transfer_complete() {
        let payload = b"audit-end-failure".to_vec();
        let payload_len = payload.len() as u64;
        let mut source = MemorySource {
            bytes: payload,
            offset: 0,
        };
        let config = test_config();
        let cancel = AtomicBool::new(false);
        let (controller_audit, peer_audit, _controller_dir, _peer_dir) =
            establish_audit_pair().await;
        let (mut controller_stream, peer_stream) = duplex(64 * 1024);
        let mut peer =
            ScriptedPeer::new(peer_stream, TransferDirection::Upload, TransferSide::Host);

        let (outcome, ()) = tokio::join!(
            run_upload_audited(
                &mut controller_stream,
                &config,
                &mut source,
                "remote.bin",
                "source.bin",
                Some("source.bin"),
                &cancel,
                Some(controller_audit.as_ref()),
            ),
            async {
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::UploadOpen { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
                let mut data = Box::new([0_u8; MAX_DATA_LEN]);
                loop {
                    match peer.read_data(&mut *data).await {
                        OwnedMessage::Data { .. } => {}
                        OwnedMessage::Finish {
                            actual_size,
                            digest: _,
                        } => {
                            assert_eq!(actual_size, payload_len);
                            controller_audit
                                .fail_closed(None, AuditCloseReason::AuditFailure)
                                .await;
                            peer.send(FileTransferMessage::Committed).await;
                            break;
                        }
                        message => panic!("unexpected upload frame: {message:?}"),
                    }
                }
            },
        );

        assert!(controller_audit.has_failed().await);
        assert_eq!(outcome, TransferOutcome::AuditFailed { bytes: payload_len });
        drop(peer_audit);
    }

    #[tokio::test]
    async fn every_transfer_role_aborts_before_file_effects_when_audit_has_failed() {
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let cancel = AtomicBool::new(false);
        let (audit, peer_audit, _audit_dir, _peer_audit_dir) = establish_audit_pair().await;
        audit
            .fail_closed(None, AuditCloseReason::AuditFailure)
            .await;
        assert!(audit.has_failed().await);

        let upload_dir = tempdir().unwrap();
        let upload_destination = path_string(&upload_dir.path().join("host-target.bin"));
        let upload_open = FileTransferMessage::UploadOpen {
            destination: &upload_destination,
            file_name: "source.bin",
            declared_size: 1,
        };
        let (mut host_upload, _controller_upload) = duplex(64 * 1024);
        assert_eq!(
            handle_upload_from_open(
                &mut host_upload,
                &config,
                &base,
                &cancel,
                &upload_open,
                Some(audit.as_ref()),
            )
            .await,
            TransferOutcome::AuditFailedBeforeCommit
        );
        assert!(!upload_dir.path().join("host-target.bin").exists());

        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("source.bin");
        write_pattern_file(&source_path, 1);
        let source_name = path_string(&source_path);
        let download_open = FileTransferMessage::DownloadOpen {
            source: &source_name,
        };
        let (mut host_download, _controller_download) = duplex(64 * 1024);
        assert_eq!(
            handle_download_from_open(
                &mut host_download,
                &config,
                &base,
                &cancel,
                &download_open,
                Some(audit.as_ref()),
            )
            .await,
            TransferOutcome::AuditFailedBeforeCommit
        );

        let mut source = SourceFile::open(&source_path).unwrap();
        let (mut controller_upload, _host_upload) = duplex(64 * 1024);
        assert_eq!(
            run_upload_audited(
                &mut controller_upload,
                &config,
                &mut source,
                "remote.bin",
                "source.bin",
                None,
                &cancel,
                Some(audit.as_ref()),
            )
            .await,
            TransferOutcome::AuditFailedBeforeCommit
        );
        assert_eq!(source.bytes_read(), 0);

        let target_dir = tempdir().unwrap();
        let target_path = path_string(&target_dir.path().join("download.bin"));
        let (mut controller_download, host_download) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            host_download,
            TransferDirection::Download,
            TransferSide::Host,
        );
        let (outcome, ()) = tokio::join!(
            run_download_audited(
                &mut controller_download,
                &config,
                &base,
                "remote/source.bin",
                Some(&target_path),
                &cancel,
                Some(audit.as_ref()),
            ),
            async {
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOpen { .. }
                ));
                peer.send(FileTransferMessage::DownloadOffer {
                    file_name: "source.bin",
                    declared_size: 1,
                })
                .await;
            },
        );
        assert_eq!(outcome, TransferOutcome::AuditFailedBeforeCommit);
        assert!(!target_dir.path().join("download.bin").exists());
        drop(peer_audit);
    }

    #[tokio::test]
    async fn upload_and_download_complete_through_bilateral_audit() {
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let cancel = AtomicBool::new(false);

        let upload_source_dir = tempdir().unwrap();
        let upload_host_dir = tempdir().unwrap();
        let upload_source_path = upload_source_dir.path().join("source.bin");
        write_pattern_file(&upload_source_path, 4097);
        let mut upload_source = SourceFile::open(&upload_source_path).unwrap();
        let upload_destination = path_string(&upload_host_dir.path().join("received.bin"));
        let (controller_audit, host_audit, controller_audit_dir, host_audit_dir) =
            establish_audit_pair().await;
        let (mut controller_stream, mut host_stream) = duplex(64 * 1024);
        let upload_wire_settled = AtomicBool::new(false);
        let (controller_outcome, host_outcome) = tokio::join!(
            run_upload_audited(
                &mut controller_stream,
                &config,
                &mut upload_source,
                &upload_destination,
                "source.bin",
                upload_source_path.to_str(),
                &cancel,
                Some(controller_audit.as_ref()),
            ),
            async {
                let open = read_frame(
                    &mut host_stream,
                    ReadMode::Control {
                        budget: config.control_timeout,
                    },
                    None,
                )
                .await
                .unwrap();
                let OwnedMessage::UploadOpen {
                    destination,
                    file_name,
                    declared_size,
                } = open
                else {
                    panic!("expected upload open");
                };
                let open = FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: &file_name,
                    declared_size,
                };
                handle_upload_from_open_with_settlement(
                    &mut host_stream,
                    &config,
                    &base,
                    &cancel,
                    &open,
                    Some(host_audit.as_ref()),
                    Some(&upload_wire_settled),
                )
                .await
            },
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::Committed { bytes: 4097 }
        );
        assert_eq!(host_outcome, controller_outcome);
        assert!(
            upload_wire_settled.load(Ordering::Acquire),
            "the coordinator must observe the upload wire terminal state"
        );
        assert_eq!(
            fs::read(&upload_destination).unwrap(),
            fs::read(&upload_source_path).unwrap()
        );
        assert!(!controller_audit.has_failed().await);
        assert!(!host_audit.has_failed().await);
        assert_eq!(
            recorded_local_file_paths(&controller_audit_dir),
            vec![
                path_string(&upload_source_path),
                path_string(&upload_source_path)
            ]
        );
        assert_eq!(
            recorded_local_file_paths(&host_audit_dir),
            vec![upload_destination.clone()]
        );

        let download_source_dir = tempdir().unwrap();
        let download_target_dir = tempdir().unwrap();
        let download_source_path = download_source_dir.path().join("remote.bin");
        write_pattern_file(&download_source_path, 8193);
        let download_source = path_string(&download_source_path);
        let download_target = path_string(&download_target_dir.path().join("local.bin"));
        let (controller_audit, host_audit, controller_audit_dir, host_audit_dir) =
            establish_audit_pair().await;
        let (mut controller_stream, mut host_stream) = duplex(64 * 1024);
        let download_wire_settled = AtomicBool::new(false);
        let (controller_outcome, host_outcome) = tokio::join!(
            run_download_audited(
                &mut controller_stream,
                &config,
                &base,
                &download_source,
                Some(&download_target),
                &cancel,
                Some(controller_audit.as_ref()),
            ),
            async {
                let open = read_frame(
                    &mut host_stream,
                    ReadMode::Control {
                        budget: config.control_timeout,
                    },
                    None,
                )
                .await
                .unwrap();
                let OwnedMessage::DownloadOpen { source } = open else {
                    panic!("expected download open");
                };
                let open = FileTransferMessage::DownloadOpen { source: &source };
                handle_download_from_open_with_settlement(
                    &mut host_stream,
                    &config,
                    &base,
                    &cancel,
                    &open,
                    Some(host_audit.as_ref()),
                    Some(&download_wire_settled),
                )
                .await
            },
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::Committed { bytes: 8193 }
        );
        assert_eq!(host_outcome, controller_outcome);
        assert!(
            download_wire_settled.load(Ordering::Acquire),
            "the coordinator must observe the download wire terminal state"
        );
        assert_eq!(
            fs::read(&download_target).unwrap(),
            fs::read(&download_source_path).unwrap()
        );
        assert!(!controller_audit.has_failed().await);
        assert!(!host_audit.has_failed().await);
        assert_eq!(
            recorded_local_file_paths(&controller_audit_dir),
            vec![download_target.clone()]
        );
        assert_eq!(
            recorded_local_file_paths(&host_audit_dir),
            vec![download_source.clone(), download_source.clone()]
        );
    }

    // ------------------------------------------------------------------
    // Success paths: upload and download across the fixed size matrix
    // (0, 1, 65535, 65536, 65537 and above 16 MiB).
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn upload_success_all_sizes() {
        let source_dir = tempdir().unwrap();
        let host_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        for size in [0_u64, 1, 65535, 65536, 65537, 17 * 1024 * 1024] {
            let source_path = source_dir.path().join(format!("source-{size}.bin"));
            write_pattern_file(&source_path, size);
            let mut source = SourceFile::open(&source_path).unwrap();
            let (controller_half, host_half) = duplex(64 * 1024);
            let mut controller_stream = controller_half;
            let mut host_stream = host_half;
            let cancel = AtomicBool::new(false);
            let final_path = host_dir.path().join(format!("final-{size}.bin"));
            let destination = path_string(&final_path);
            let (controller_outcome, host_outcome) = tokio::join!(
                run_upload(
                    &mut controller_stream,
                    &config,
                    &mut source,
                    &destination,
                    "uploaded.bin",
                    &cancel,
                ),
                handle_upload(&mut host_stream, &config, &base, &cancel,),
            );
            assert_eq!(
                controller_outcome,
                TransferOutcome::Committed { bytes: size },
                "controller outcome for size {size}"
            );
            assert_eq!(
                host_outcome,
                TransferOutcome::Committed { bytes: size },
                "host outcome for size {size}"
            );
            assert_eq!(
                fs::read(&final_path).unwrap(),
                fs::read(&source_path).unwrap(),
                "content for size {size}"
            );
            assert_dir_entries(host_dir.path(), &[&final_path]);
            fs::remove_file(&final_path).unwrap();
        }
    }

    #[tokio::test]
    async fn download_success_all_sizes() {
        let source_dir = tempdir().unwrap();
        let controller_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        for size in [0_u64, 1, 65535, 65536, 65537, 17 * 1024 * 1024] {
            let source_path = source_dir.path().join(format!("source-{size}.bin"));
            write_pattern_file(&source_path, size);
            let (controller_half, host_half) = duplex(64 * 1024);
            let mut controller_stream = controller_half;
            let mut host_stream = host_half;
            let cancel = AtomicBool::new(false);
            let final_path = controller_dir.path().join(format!("final-{size}.bin"));
            let source_string = path_string(&source_path);
            let target_string = path_string(&final_path);
            let (controller_outcome, host_outcome) = tokio::join!(
                run_download(
                    &mut controller_stream,
                    &config,
                    &base,
                    &source_string,
                    Some(&target_string),
                    &cancel,
                ),
                handle_download(&mut host_stream, &config, &base, &cancel,),
            );
            assert_eq!(
                controller_outcome,
                TransferOutcome::Committed { bytes: size },
                "controller outcome for size {size}"
            );
            assert_eq!(
                host_outcome,
                TransferOutcome::Committed { bytes: size },
                "host outcome for size {size}"
            );
            assert_eq!(
                fs::read(&final_path).unwrap(),
                fs::read(&source_path).unwrap(),
                "content for size {size}"
            );
            assert_dir_entries(controller_dir.path(), &[&final_path]);
            fs::remove_file(&final_path).unwrap();
        }
    }

    #[tokio::test]
    async fn upload_uses_default_remote_destination_directory() {
        let directory = tempdir().unwrap();
        let base = base_in_directory(directory.path());
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 4096);
        let mut source = SourceFile::open(&source_path).unwrap();
        let config = test_config();
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut controller_stream = controller_half;
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, host_outcome) = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                "",
                "src.bin",
                &cancel,
            ),
            handle_upload(&mut host_stream, &config, &base, &cancel),
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::Committed { bytes: 4096 }
        );
        assert_eq!(host_outcome, TransferOutcome::Committed { bytes: 4096 });
        let final_path = directory.path().join("src.bin");
        assert_eq!(
            fs::read(&final_path).unwrap(),
            fs::read(&source_path).unwrap()
        );
        assert_dir_entries(directory.path(), &[&final_path]);
    }

    #[tokio::test]
    async fn download_uses_default_local_target_with_offer_file_name() {
        let directory = tempdir().unwrap();
        let base = base_in_directory(directory.path());
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("offer-name.bin");
        write_pattern_file(&source_path, 8192);
        let config = test_config();
        let host_base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut controller_stream = controller_half;
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, host_outcome) = tokio::join!(
            run_download(
                &mut controller_stream,
                &config,
                &base,
                &source_string,
                None,
                &cancel,
            ),
            handle_download(&mut host_stream, &config, &host_base, &cancel),
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::Committed { bytes: 8192 }
        );
        assert_eq!(host_outcome, TransferOutcome::Committed { bytes: 8192 });
        let final_path = directory.path().join("offer-name.bin");
        assert_eq!(
            fs::read(&final_path).unwrap(),
            fs::read(&source_path).unwrap()
        );
        assert_dir_entries(directory.path(), &[&final_path]);
    }

    #[tokio::test]
    async fn upload_into_existing_directory_appends_the_file_name() {
        let source_dir = tempdir().unwrap();
        let host_dir = tempdir().unwrap();
        let out_dir = host_dir.path().join("out");
        fs::create_dir(&out_dir).unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 2048);
        let mut source = SourceFile::open(&source_path).unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&out_dir);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut controller_stream = controller_half;
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, host_outcome) = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                &destination,
                "inside.bin",
                &cancel,
            ),
            handle_upload(&mut host_stream, &config, &base, &cancel),
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::Committed { bytes: 2048 }
        );
        assert_eq!(host_outcome, TransferOutcome::Committed { bytes: 2048 });
        let final_path = out_dir.join("inside.bin");
        assert_eq!(
            fs::read(&final_path).unwrap(),
            fs::read(&source_path).unwrap()
        );
        assert_dir_entries(&out_dir, &[&final_path]);
    }

    #[tokio::test]
    async fn download_into_existing_directory_appends_the_offer_name() {
        let source_dir = tempdir().unwrap();
        let controller_dir = tempdir().unwrap();
        let out_dir = controller_dir.path().join("out");
        fs::create_dir(&out_dir).unwrap();
        let source_path = source_dir.path().join("data.bin");
        write_pattern_file(&source_path, 2048);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let target_string = path_string(&out_dir);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut controller_stream = controller_half;
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, host_outcome) = tokio::join!(
            run_download(
                &mut controller_stream,
                &config,
                &base,
                &source_string,
                Some(&target_string),
                &cancel,
            ),
            handle_download(&mut host_stream, &config, &base, &cancel),
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::Committed { bytes: 2048 }
        );
        assert_eq!(host_outcome, TransferOutcome::Committed { bytes: 2048 });
        let final_path = out_dir.join("data.bin");
        assert_eq!(
            fs::read(&final_path).unwrap(),
            fs::read(&source_path).unwrap()
        );
        assert_dir_entries(&out_dir, &[&final_path]);
    }

    // ------------------------------------------------------------------
    // Bidirectional error mapping (design 10.4).
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn upload_destination_exists_fails_both_sides_and_never_overwrites() {
        let source_dir = tempdir().unwrap();
        let host_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 1024);
        let final_path = host_dir.path().join("exists.bin");
        fs::write(&final_path, b"pre-existing").unwrap();
        let mut source = SourceFile::open(&source_path).unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&final_path);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut controller_stream = controller_half;
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, host_outcome) = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                &destination,
                "src.bin",
                &cancel,
            ),
            handle_upload(&mut host_stream, &config, &base, &cancel),
        );
        let expected = TransferOutcome::Failed(FileTransferErrorCode::DestinationExists);
        assert_eq!(controller_outcome, expected);
        assert_eq!(host_outcome, expected);
        assert_eq!(fs::read(&final_path).unwrap(), b"pre-existing");
    }

    #[tokio::test]
    async fn upload_missing_parent_fails_both_sides() {
        let source_dir = tempdir().unwrap();
        let host_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 1024);
        let mut source = SourceFile::open(&source_path).unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let missing = host_dir.path().join("missing").join("sub");
        let destination = path_string(&missing.join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut controller_stream = controller_half;
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, host_outcome) = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                &destination,
                "src.bin",
                &cancel,
            ),
            handle_upload(&mut host_stream, &config, &base, &cancel),
        );
        let expected = TransferOutcome::Failed(FileTransferErrorCode::DestinationParentNotFound);
        assert_eq!(controller_outcome, expected);
        assert_eq!(host_outcome, expected);
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn download_source_not_found_fails_both_sides() {
        let source_dir = tempdir().unwrap();
        let controller_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let missing = source_dir.path().join("nope.bin");
        let source_string = path_string(&missing);
        let target_string = path_string(&controller_dir.path().join("out.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut controller_stream = controller_half;
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, host_outcome) = tokio::join!(
            run_download(
                &mut controller_stream,
                &config,
                &base,
                &source_string,
                Some(&target_string),
                &cancel,
            ),
            handle_download(&mut host_stream, &config, &base, &cancel),
        );
        let expected = TransferOutcome::Failed(FileTransferErrorCode::SourceNotFound);
        assert_eq!(controller_outcome, expected);
        assert_eq!(host_outcome, expected);
        assert_dir_empty(controller_dir.path());
    }

    #[tokio::test]
    async fn download_directory_source_fails_both_sides() {
        let source_dir = tempdir().unwrap();
        let controller_dir = tempdir().unwrap();
        let directory_source = source_dir.path().join("adir");
        fs::create_dir(&directory_source).unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&directory_source);
        let target_string = path_string(&controller_dir.path().join("out.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut controller_stream = controller_half;
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, host_outcome) = tokio::join!(
            run_download(
                &mut controller_stream,
                &config,
                &base,
                &source_string,
                Some(&target_string),
                &cancel,
            ),
            handle_download(&mut host_stream, &config, &base, &cancel),
        );
        let expected = TransferOutcome::Failed(FileTransferErrorCode::SourceNotRegularFile);
        assert_eq!(controller_outcome, expected);
        assert_eq!(host_outcome, expected);
        assert_dir_empty(controller_dir.path());
    }

    #[tokio::test]
    async fn download_destination_exists_fails_both_sides() {
        let source_dir = tempdir().unwrap();
        let controller_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 1024);
        let final_path = controller_dir.path().join("exists.bin");
        fs::write(&final_path, b"pre-existing").unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let target_string = path_string(&final_path);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut controller_stream = controller_half;
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, host_outcome) = tokio::join!(
            run_download(
                &mut controller_stream,
                &config,
                &base,
                &source_string,
                Some(&target_string),
                &cancel,
            ),
            handle_download(&mut host_stream, &config, &base, &cancel),
        );
        let expected = TransferOutcome::Failed(FileTransferErrorCode::DestinationExists);
        assert_eq!(controller_outcome, expected);
        assert_eq!(host_outcome, expected);
        assert_eq!(fs::read(&final_path).unwrap(), b"pre-existing");
    }

    #[tokio::test]
    async fn download_missing_local_parent_fails_both_sides() {
        let source_dir = tempdir().unwrap();
        let controller_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 1024);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let missing = controller_dir.path().join("missing").join("sub");
        let source_string = path_string(&source_path);
        let target_string = path_string(&missing.join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut controller_stream = controller_half;
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, host_outcome) = tokio::join!(
            run_download(
                &mut controller_stream,
                &config,
                &base,
                &source_string,
                Some(&target_string),
                &cancel,
            ),
            handle_download(&mut host_stream, &config, &base, &cancel),
        );
        let expected = TransferOutcome::Failed(FileTransferErrorCode::DestinationParentNotFound);
        assert_eq!(controller_outcome, expected);
        assert_eq!(host_outcome, expected);
        assert_dir_empty(controller_dir.path());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn upload_permission_denied_fails_both_sides() {
        use std::os::unix::fs::PermissionsExt;
        let source_dir = tempdir().unwrap();
        let host_dir = tempdir().unwrap();
        let locked = host_dir.path().join("locked");
        fs::create_dir(&locked).unwrap();
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).unwrap();
        let permission_probe = locked.join("permission-probe");
        if let Ok(probe) = fs::File::create(&permission_probe) {
            drop(probe);
            fs::remove_file(permission_probe).unwrap();
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 1024);
        let mut source = SourceFile::open(&source_path).unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&locked.join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut controller_stream = controller_half;
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, host_outcome) = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                &destination,
                "src.bin",
                &cancel,
            ),
            handle_upload(&mut host_stream, &config, &base, &cancel),
        );
        let expected = TransferOutcome::Failed(FileTransferErrorCode::PermissionDenied);
        assert_eq!(controller_outcome, expected);
        assert_eq!(host_outcome, expected);
    }

    // ------------------------------------------------------------------
    // Peer-provided base file names (design 8.4).
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn upload_rejects_invalid_peer_file_names() {
        let host_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        for name in ["a/b", ".."] {
            let (controller_half, host_half) = duplex(64 * 1024);
            let mut peer = ScriptedPeer::new(
                controller_half,
                TransferDirection::Upload,
                TransferSide::Controller,
            );
            let mut host_stream = host_half;
            let cancel = AtomicBool::new(false);
            let (host_outcome, error_message) = tokio::join!(
                handle_upload(&mut host_stream, &config, &base, &cancel),
                async {
                    peer.send(FileTransferMessage::UploadOpen {
                        destination: "",
                        file_name: name,
                        declared_size: 0,
                    })
                    .await;
                    peer.read_control().await
                },
            );
            assert_eq!(
                host_outcome,
                TransferOutcome::Failed(FileTransferErrorCode::InvalidFileName),
                "host outcome for name {name:?}"
            );
            assert_eq!(
                error_message,
                OwnedMessage::Error {
                    code: FileTransferErrorCode::InvalidFileName
                },
                "wire error for name {name:?}"
            );
            assert_dir_empty(host_dir.path());
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn upload_rejects_windows_reserved_peer_file_names() {
        let host_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (host_outcome, error_message) = tokio::join!(
            handle_upload(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: "",
                    file_name: "CON",
                    declared_size: 0,
                })
                .await;
                peer.read_control().await
            },
        );
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidFileName)
        );
        assert_eq!(
            error_message,
            OwnedMessage::Error {
                code: FileTransferErrorCode::InvalidFileName
            }
        );
        assert_dir_empty(host_dir.path());
    }

    // ------------------------------------------------------------------
    // Integrity failures: size and digest mismatch (design 14).
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn upload_digest_mismatch_fails_receiver_and_cleans_up() {
        let source_dir = tempdir().unwrap();
        let host_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 200 * 1024);
        let (bytes, chunks) = file_chunks(&source_path);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (host_outcome, error_message) = tokio::join!(
            handle_upload(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "src.bin",
                    declared_size: bytes.len() as u64,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                for chunk in &chunks {
                    peer.send(FileTransferMessage::Data { bytes: chunk }).await;
                }
                peer.send(FileTransferMessage::Finish {
                    actual_size: bytes.len() as u64,
                    digest: Sha256Digest::new([0xAA; 32]),
                })
                .await;
                peer.read_control().await
            },
        );
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::DigestMismatch)
        );
        assert_eq!(
            error_message,
            OwnedMessage::Error {
                code: FileTransferErrorCode::DigestMismatch
            }
        );
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn upload_size_mismatch_in_finish_fails_receiver() {
        let source_dir = tempdir().unwrap();
        let host_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 4096);
        let (bytes, chunks) = file_chunks(&source_path);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (host_outcome, error_message) = tokio::join!(
            handle_upload(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "src.bin",
                    declared_size: bytes.len() as u64,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                for chunk in &chunks {
                    peer.send(FileTransferMessage::Data { bytes: chunk }).await;
                }
                peer.send(FileTransferMessage::Finish {
                    actual_size: bytes.len() as u64 + 1,
                    digest: sha256(&bytes),
                })
                .await;
                peer.read_control().await
            },
        );
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SizeMismatch)
        );
        assert_eq!(
            error_message,
            OwnedMessage::Error {
                code: FileTransferErrorCode::SizeMismatch
            }
        );
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn download_digest_mismatch_fails_controller_and_cleans_up() {
        let source_dir = tempdir().unwrap();
        let controller_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 200 * 1024);
        let (bytes, chunks) = file_chunks(&source_path);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let target_string = path_string(&controller_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer =
            ScriptedPeer::new(host_half, TransferDirection::Download, TransferSide::Host);
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, error_message) = tokio::join!(
            run_download(
                &mut controller_stream,
                &config,
                &base,
                &source_string,
                Some(&target_string),
                &cancel,
            ),
            async {
                assert_eq!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOpen {
                        source: source_string.clone()
                    }
                );
                peer.send(FileTransferMessage::DownloadOffer {
                    file_name: "f.bin",
                    declared_size: bytes.len() as u64,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                for chunk in &chunks {
                    peer.send(FileTransferMessage::Data { bytes: chunk }).await;
                }
                peer.send(FileTransferMessage::Finish {
                    actual_size: bytes.len() as u64,
                    digest: Sha256Digest::new([0xBB; 32]),
                })
                .await;
                peer.read_control().await
            },
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::DigestMismatch)
        );
        assert_eq!(
            error_message,
            OwnedMessage::Error {
                code: FileTransferErrorCode::DigestMismatch
            }
        );
        assert_dir_empty(controller_dir.path());
    }

    #[tokio::test]
    async fn download_size_mismatch_in_finish_fails_controller() {
        let source_dir = tempdir().unwrap();
        let controller_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 4096);
        let (bytes, chunks) = file_chunks(&source_path);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let target_string = path_string(&controller_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer =
            ScriptedPeer::new(host_half, TransferDirection::Download, TransferSide::Host);
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, error_message) = tokio::join!(
            run_download(
                &mut controller_stream,
                &config,
                &base,
                &source_string,
                Some(&target_string),
                &cancel,
            ),
            async {
                assert_eq!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOpen {
                        source: source_string.clone()
                    }
                );
                peer.send(FileTransferMessage::DownloadOffer {
                    file_name: "f.bin",
                    declared_size: bytes.len() as u64,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                for chunk in &chunks {
                    peer.send(FileTransferMessage::Data { bytes: chunk }).await;
                }
                peer.send(FileTransferMessage::Finish {
                    actual_size: bytes.len() as u64 - 1,
                    digest: sha256(&bytes),
                })
                .await;
                peer.read_control().await
            },
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SizeMismatch)
        );
        assert_eq!(
            error_message,
            OwnedMessage::Error {
                code: FileTransferErrorCode::SizeMismatch
            }
        );
        assert_dir_empty(controller_dir.path());
    }

    // ------------------------------------------------------------------
    // Source change detection (design 14).
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn upload_source_growth_fails_with_source_changed() {
        let source_dir = tempdir().unwrap();
        let host_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 2 * 1024 * 1024);
        let mut source = SourceFile::open(&source_path).unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let notify = Arc::new(Notify::new());
        let mut host_stream = ReadThresholdNotify::new(host_half, 1024, notify.clone());
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let grow_path = source_path.clone();
        let grow_task = tokio::spawn(async move {
            notify.notified().await;
            let mut file = fs::OpenOptions::new()
                .append(true)
                .open(&grow_path)
                .unwrap();
            file.write_all(&[0x5A; 4096]).unwrap();
            file.sync_all().unwrap();
        });
        let (controller_outcome, host_outcome) = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                &destination,
                "src.bin",
                &cancel,
            ),
            handle_upload(&mut host_stream, &config, &base, &cancel),
        );
        grow_task.await.unwrap();
        let expected = TransferOutcome::Failed(FileTransferErrorCode::SourceChanged);
        assert_eq!(controller_outcome, expected);
        assert_eq!(host_outcome, expected);
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn upload_source_shrink_fails_with_source_changed() {
        let source_dir = tempdir().unwrap();
        let host_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 2 * 1024 * 1024);
        let mut source = SourceFile::open(&source_path).unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let notify = Arc::new(Notify::new());
        let mut host_stream = ReadThresholdNotify::new(host_half, 1024, notify.clone());
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let shrink_path = source_path.clone();
        let shrink_task = tokio::spawn(async move {
            notify.notified().await;
            let file = fs::OpenOptions::new()
                .write(true)
                .open(&shrink_path)
                .unwrap();
            file.set_len(1024 * 1024).unwrap();
            file.sync_all().unwrap();
        });
        let (controller_outcome, host_outcome) = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                &destination,
                "src.bin",
                &cancel,
            ),
            handle_upload(&mut host_stream, &config, &base, &cancel),
        );
        shrink_task.await.unwrap();
        let expected = TransferOutcome::Failed(FileTransferErrorCode::SourceChanged);
        assert_eq!(controller_outcome, expected);
        assert_eq!(host_outcome, expected);
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn download_source_growth_fails_with_source_changed() {
        let source_dir = tempdir().unwrap();
        let controller_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 2 * 1024 * 1024);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let grow_path = source_path.clone();
        let (host_outcome, error_message) = tokio::join!(
            handle_download(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::DownloadOpen {
                    source: &source_string,
                })
                .await;
                // The offer proves the host's source handle is open; the
                // source may now grow before any byte is read.
                let offer = peer.read_control().await;
                assert!(matches!(
                    offer,
                    OwnedMessage::DownloadOffer {
                        file_name,
                        declared_size,
                    } if file_name == "src.bin" && declared_size == 2 * 1024 * 1024
                ));
                let mut file = fs::OpenOptions::new()
                    .append(true)
                    .open(&grow_path)
                    .unwrap();
                file.write_all(&[0x5A; 4096]).unwrap();
                file.sync_all().unwrap();
                peer.send(FileTransferMessage::Ready).await;
                let mut sink = Box::new([0_u8; MAX_DATA_LEN]);
                loop {
                    match peer.read_data(&mut *sink).await {
                        OwnedMessage::Data { .. } => continue,
                        OwnedMessage::Error { code } => {
                            assert_eq!(code, FileTransferErrorCode::SourceChanged);
                            break code;
                        }
                        message => panic!("unexpected message from the host: {message:?}"),
                    }
                }
            },
        );
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SourceChanged)
        );
        assert_eq!(error_message, FileTransferErrorCode::SourceChanged);
        assert_dir_empty(controller_dir.path());
    }

    // ------------------------------------------------------------------
    // Cancellation (design 10.5, 16.2).
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn controller_cancel_mid_upload_cancels_both_sides_and_cleans_up() {
        let source_dir = tempdir().unwrap();
        let host_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("big.bin");
        write_pattern_file(&source_path, 32 * 1024 * 1024);
        let mut source = SourceFile::open(&source_path).unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("big.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let notify = Arc::new(Notify::new());
        let mut host_stream = ReadThresholdNotify::new(host_half, 1024, notify.clone());
        let mut controller_stream = controller_half;
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_for_peer = cancel.clone();
        let cancel_task = tokio::spawn(async move {
            // Fires when the host has consumed the first data block, so the
            // controller is provably inside its data loop (design 15.2: the
            // flag must interrupt a large transfer promptly).
            notify.notified().await;
            cancel_for_peer.store(true, Ordering::Relaxed);
        });
        let (controller_outcome, host_outcome) = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                &destination,
                "big.bin",
                &cancel,
            ),
            handle_upload(&mut host_stream, &config, &base, &cancel),
        );
        cancel_task.await.unwrap();
        assert_eq!(controller_outcome, TransferOutcome::Cancelled);
        assert_eq!(host_outcome, TransferOutcome::Cancelled);
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn controller_cancel_mid_download_sends_cancel() {
        let source_dir = tempdir().unwrap();
        let controller_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 200 * 1024);
        let (bytes, chunks) = file_chunks(&source_path);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let target_string = path_string(&controller_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer =
            ScriptedPeer::new(host_half, TransferDirection::Download, TransferSide::Host);
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, peer_message) = tokio::join!(
            run_download(
                &mut controller_stream,
                &config,
                &base,
                &source_string,
                Some(&target_string),
                &cancel,
            ),
            async {
                assert_eq!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOpen {
                        source: source_string.clone()
                    }
                );
                peer.send(FileTransferMessage::DownloadOffer {
                    file_name: "f.bin",
                    declared_size: bytes.len() as u64,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                peer.send(FileTransferMessage::Data { bytes: &chunks[0] })
                    .await;
                // One block, then cancel the controller mid-receive.
                cancel.store(true, Ordering::Relaxed);
                peer.read_unchecked().await
            },
        );
        assert_eq!(controller_outcome, TransferOutcome::Cancelled);
        assert_eq!(peer_message, OwnedMessage::Cancel);
        assert_dir_empty(controller_dir.path());
    }

    #[tokio::test]
    async fn host_cancel_mid_upload_sends_session_closing() {
        let source_dir = tempdir().unwrap();
        let host_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 200 * 1024);
        let (_, chunks) = file_chunks(&source_path);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (host_outcome, error_message) = tokio::join!(
            handle_upload(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "src.bin",
                    declared_size: 200 * 1024,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                peer.send(FileTransferMessage::Data { bytes: &chunks[0] })
                    .await;
                // One block, then cancel the host mid-receive. The upload
                // controller never reads in the data phase, so the scripted
                // session cannot record the reply; assert it unchecked.
                cancel.store(true, Ordering::Relaxed);
                peer.read_unchecked().await
            },
        );
        assert_eq!(host_outcome, TransferOutcome::Cancelled);
        assert_eq!(
            error_message,
            OwnedMessage::Error {
                code: FileTransferErrorCode::SessionClosing
            }
        );
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn host_cancel_mid_download_sends_error_not_cancel() {
        let source_dir = tempdir().unwrap();
        let controller_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 200 * 1024);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        let cancel = Arc::new(AtomicBool::new(false));
        let mut host_stream = CancelAfterFlush {
            inner: host_half,
            cancel: Arc::clone(&cancel),
            trigger_at: 2,
            flushes: 0,
        };
        let (host_outcome, error_message) = tokio::join!(
            handle_download(&mut host_stream, &config, &base, cancel.as_ref()),
            async {
                peer.send(FileTransferMessage::DownloadOpen {
                    source: &source_string,
                })
                .await;
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOffer { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
                let mut sink = Box::new([0_u8; MAX_DATA_LEN]);
                let mut saw_data = false;
                loop {
                    match peer.read_data(&mut *sink).await {
                        OwnedMessage::Data { .. } => {
                            assert!(!saw_data);
                            saw_data = true;
                        }
                        message => {
                            assert!(saw_data);
                            break message;
                        }
                    }
                }
            },
        );
        assert_eq!(host_outcome, TransferOutcome::Cancelled);
        assert_eq!(
            error_message,
            OwnedMessage::Error {
                code: FileTransferErrorCode::SessionClosing
            }
        );
        assert_dir_empty(controller_dir.path());
    }

    #[tokio::test]
    async fn cancel_before_start_returns_cancelled_without_wire_exchange() {
        let source_dir = tempdir().unwrap();
        let host_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 1024);
        let mut source = SourceFile::open(&source_path).unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut controller_stream = controller_half;
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(true);
        let (controller_outcome, host_outcome) = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                &destination,
                "src.bin",
                &cancel,
            ),
            handle_upload(&mut host_stream, &config, &base, &cancel),
        );
        assert_eq!(controller_outcome, TransferOutcome::Cancelled);
        assert_eq!(host_outcome, TransferOutcome::Cancelled);
        assert_dir_empty(host_dir.path());
    }

    // ------------------------------------------------------------------
    // The peer Cancel reply (design 10.5: `Error(Cancelled)` best-effort).
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn host_receiving_cancel_replies_cancelled_error_and_cleans_up() {
        let source_dir = tempdir().unwrap();
        let host_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 200 * 1024);
        let (bytes, chunks) = file_chunks(&source_path);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (host_outcome, error_message) = tokio::join!(
            handle_upload(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "src.bin",
                    declared_size: bytes.len() as u64,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                for chunk in &chunks {
                    peer.send(FileTransferMessage::Data { bytes: chunk }).await;
                }
                peer.send(FileTransferMessage::Cancel).await;
                peer.read_unchecked().await
            },
        );
        assert_eq!(host_outcome, TransferOutcome::Cancelled);
        assert_eq!(
            error_message,
            OwnedMessage::Error {
                code: FileTransferErrorCode::Cancelled
            }
        );
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn controller_receiving_cancel_in_download_is_a_protocol_failure() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 200 * 1024);
        let (bytes, chunks) = file_chunks(&source_path);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer =
            ScriptedPeer::new(host_half, TransferDirection::Download, TransferSide::Host);
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let controller_dir = tempdir().unwrap();
        let target_string = path_string(&controller_dir.path().join("f.bin"));
        let (controller_outcome, _) = tokio::join!(
            run_download(
                &mut controller_stream,
                &config,
                &base,
                &source_string,
                Some(&target_string),
                &cancel,
            ),
            async {
                assert_eq!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOpen {
                        source: source_string.clone()
                    }
                );
                peer.send(FileTransferMessage::DownloadOffer {
                    file_name: "f.bin",
                    declared_size: bytes.len() as u64,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                peer.send(FileTransferMessage::Data { bytes: &chunks[0] })
                    .await;
                // The host may never send Cancel in a download; the
                // controller must treat it as a protocol violation.
                peer.send_fault(FileTransferMessage::Cancel).await;
            },
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
    }

    // ------------------------------------------------------------------
    // Illegal sequences and malformed frames (design 10.1, 10.5).
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn committed_before_finish_is_a_protocol_failure() {
        let host_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let host_outcome = tokio::join!(
            handle_upload(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "src.bin",
                    declared_size: 1,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                peer.send_fault(FileTransferMessage::Committed).await;
            },
        )
        .0;
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn wrong_opening_message_is_a_protocol_failure() {
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let host_outcome = tokio::join!(
            handle_upload(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send_fault(FileTransferMessage::DownloadOpen { source: "x" })
                    .await;
            },
        )
        .0;
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
    }

    #[tokio::test]
    async fn duplicate_open_after_ready_is_a_protocol_failure() {
        let host_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let host_outcome = tokio::join!(
            handle_upload(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "src.bin",
                    declared_size: 10,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                peer.send_fault(FileTransferMessage::UploadOpen {
                    destination: "",
                    file_name: "other.bin",
                    declared_size: 1,
                })
                .await;
            },
        )
        .0;
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn unknown_tag_is_a_protocol_failure() {
        let host_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let host_outcome = tokio::join!(
            handle_upload(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "src.bin",
                    declared_size: 10,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                peer.raw_send(&[0x0A, 0, 0, 0, 0]).await;
            },
        )
        .0;
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn oversized_data_declaration_is_a_protocol_failure() {
        let host_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let host_outcome = tokio::join!(
            handle_upload(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "src.bin",
                    declared_size: 10,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                let header = encode_frame_header(TransferTag::Data.code(), 100_000);
                let mut frame = header.to_vec();
                frame.extend_from_slice(&[1; 100]);
                peer.raw_send(&frame).await;
            },
        )
        .0;
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn zero_length_data_frame_is_a_protocol_failure() {
        let host_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let host_outcome = tokio::join!(
            handle_upload(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "src.bin",
                    declared_size: 10,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                peer.raw_send(&[TransferTag::Data.code(), 0, 0, 0, 0]).await;
            },
        )
        .0;
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn error_frame_with_undefined_code_is_a_protocol_failure() {
        let host_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let host_outcome = tokio::join!(
            handle_upload(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "src.bin",
                    declared_size: 10,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                peer.raw_send(&[TransferTag::Error.code(), 0, 0, 0, 2, 0xFF, 0xFF])
                    .await;
            },
        )
        .0;
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn control_frame_with_wrong_length_is_a_protocol_failure() {
        let host_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let host_outcome = tokio::join!(
            handle_upload(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "src.bin",
                    declared_size: 10,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                // A Ready frame declaring a one-byte payload.
                peer.raw_send(&[TransferTag::Ready.code(), 0, 0, 0, 1, 0])
                    .await;
            },
        )
        .0;
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
        assert_dir_empty(host_dir.path());
    }

    // ------------------------------------------------------------------
    // Timeouts (design 15.4).
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn control_timeout_fails_controller_awaiting_ready() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 1024);
        let mut source = SourceFile::open(&source_path).unwrap();
        let config = timeout_config();
        let destination = path_string(&tempdir().unwrap().path().join("f.bin"));
        let (mut controller_stream, _silent_peer) = duplex(64 * 1024);
        let cancel = AtomicBool::new(false);
        let outcome = run_upload(
            &mut controller_stream,
            &config,
            &mut source,
            &destination,
            "src.bin",
            &cancel,
        )
        .await;
        assert_eq!(
            outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        );
    }

    #[tokio::test]
    async fn control_timeout_fails_host_awaiting_open() {
        let config = timeout_config();
        let base = BaseDirectory::capture().unwrap();
        let (mut host_stream, _silent_peer) = duplex(64 * 1024);
        let cancel = AtomicBool::new(false);
        let outcome = handle_upload(&mut host_stream, &config, &base, &cancel).await;
        assert_eq!(
            outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        );
    }

    #[tokio::test]
    async fn control_timeout_fails_host_awaiting_ready() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 1024);
        let config = timeout_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let (controller_half, mut host_stream) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        let cancel = AtomicBool::new(false);
        let outcome = tokio::join!(
            handle_download(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::DownloadOpen {
                    source: &source_string,
                })
                .await;
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOffer { .. }
                ));
                // The scripted controller goes silent instead of sending
                // Ready.
            },
        )
        .0;
        assert_eq!(
            outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        );
    }

    #[tokio::test]
    async fn data_no_progress_timeout_fails_upload_receiver() {
        let host_dir = tempdir().unwrap();
        let config = timeout_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let host_outcome = tokio::join!(
            handle_upload(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "src.bin",
                    declared_size: 200 * 1024,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                // One block, then silence: the data no-progress budget must
                // fail the receiver.
                peer.send(FileTransferMessage::Data { bytes: &[1; 4096] })
                    .await;
            },
        )
        .0;
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        );
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn data_no_progress_timeout_fails_download_receiver() {
        let source_dir = tempdir().unwrap();
        let controller_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 200 * 1024);
        let (bytes, _) = file_chunks(&source_path);
        let config = timeout_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let target_string = path_string(&controller_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer =
            ScriptedPeer::new(host_half, TransferDirection::Download, TransferSide::Host);
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let controller_outcome = tokio::join!(
            run_download(
                &mut controller_stream,
                &config,
                &base,
                &source_string,
                Some(&target_string),
                &cancel,
            ),
            async {
                assert_eq!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOpen {
                        source: source_string.clone()
                    }
                );
                peer.send(FileTransferMessage::DownloadOffer {
                    file_name: "f.bin",
                    declared_size: bytes.len() as u64,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                peer.send(FileTransferMessage::Data { bytes: &[1; 4096] })
                    .await;
            },
        )
        .0;
        assert_eq!(
            controller_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        );
        assert_dir_empty(controller_dir.path());
    }

    #[tokio::test]
    async fn control_timeout_leaves_controller_commit_status_unknown() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 200 * 1024);
        let config = timeout_config();
        let destination = path_string(&tempdir().unwrap().path().join("f.bin"));
        let mut source = SourceFile::open(&source_path).unwrap();
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(host_half, TransferDirection::Upload, TransferSide::Host);
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let controller_outcome = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                &destination,
                "src.bin",
                &cancel,
            ),
            async {
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::UploadOpen { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
                let mut sink = Box::new([0_u8; MAX_DATA_LEN]);
                loop {
                    match peer.read_data(&mut *sink).await {
                        OwnedMessage::Data { .. } => continue,
                        OwnedMessage::Finish { .. } => break,
                        message => panic!("unexpected message: {message:?}"),
                    }
                }
                // The scripted host goes silent instead of sending
                // Committed.
            },
        )
        .0;
        assert_eq!(
            controller_outcome,
            TransferOutcome::CommitStatusUnknown { bytes: 200 * 1024 }
        );
    }

    // ------------------------------------------------------------------
    // EOF handling (design 10.5, 16.4).
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn eof_before_first_frame_fails_host() {
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let (mut host_stream, peer) = duplex(64 * 1024);
        drop(peer);
        let cancel = AtomicBool::new(false);
        let outcome = handle_upload(&mut host_stream, &config, &base, &cancel).await;
        assert_eq!(
            outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        );
    }

    #[tokio::test]
    async fn eof_after_first_frame_fails_upload_host_and_cleans_up() {
        let host_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let host_outcome = tokio::join!(
            handle_upload(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "src.bin",
                    declared_size: 200 * 1024,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                // The controller vanishes without any data frame.
                drop(peer);
            },
        )
        .0;
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        );
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn eof_mid_frame_is_a_protocol_failure() {
        let host_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let host_outcome = tokio::join!(
            handle_upload(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "src.bin",
                    declared_size: 200 * 1024,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                // A frame declaring 100 payload bytes of which only three
                // arrive before EOF: a truncated frame.
                let header = encode_frame_header(TransferTag::Data.code(), 100);
                peer.raw_send(&header).await;
                peer.raw_send(&[1, 2, 3]).await;
                drop(peer);
            },
        )
        .0;
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn eof_awaiting_committed_leaves_controller_status_unknown() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 200 * 1024);
        let config = test_config();
        let destination = path_string(&tempdir().unwrap().path().join("f.bin"));
        let mut source = SourceFile::open(&source_path).unwrap();
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(host_half, TransferDirection::Upload, TransferSide::Host);
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let controller_outcome = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                &destination,
                "src.bin",
                &cancel,
            ),
            async {
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::UploadOpen { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
                let mut sink = Box::new([0_u8; MAX_DATA_LEN]);
                loop {
                    match peer.read_data(&mut *sink).await {
                        OwnedMessage::Data { .. } => continue,
                        OwnedMessage::Finish { .. } => break,
                        message => panic!("unexpected message: {message:?}"),
                    }
                }
                // The scripted host terminates without Committed.
                drop(peer);
            },
        )
        .0;
        assert_eq!(
            controller_outcome,
            TransferOutcome::CommitStatusUnknown { bytes: 200 * 1024 }
        );
    }

    #[tokio::test]
    async fn eof_after_first_frame_fails_download_host() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 1024);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let host_outcome = tokio::join!(
            handle_download(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::DownloadOpen {
                    source: &source_string,
                })
                .await;
                // The controller vanishes instead of sending Ready.
                drop(peer);
            },
        )
        .0;
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        );
    }

    // ------------------------------------------------------------------
    // The session-layer entries whose opening frame was already read
    // (design 9.3: the live host reads the first frame during capability
    // probing and continues with `*_from_open`).
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn upload_from_open_success_all_sizes() {
        let source_dir = tempdir().unwrap();
        let host_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        for size in [0_u64, 1, 65535, 65536, 65537] {
            let source_path = source_dir.path().join(format!("source-{size}.bin"));
            write_pattern_file(&source_path, size);
            let (bytes, chunks) = file_chunks(&source_path);
            let (controller_half, mut host_half) = duplex(64 * 1024);
            let mut peer = ScriptedPeer::new(
                controller_half,
                TransferDirection::Upload,
                TransferSide::Controller,
            );
            // The session layer consumed the opening frame off the wire
            // before this entry; the scripted session records the same
            // transition so the rest of the exchange stays legal.
            peer.session
                .send(&FileTransferMessage::UploadOpen {
                    destination: "",
                    file_name: "consumed",
                    declared_size: 0,
                })
                .unwrap();
            let cancel = AtomicBool::new(false);
            let final_path = host_dir.path().join(format!("final-{size}.bin"));
            let destination = path_string(&final_path);
            let open = FileTransferMessage::UploadOpen {
                destination: &destination,
                file_name: "uploaded.bin",
                declared_size: bytes.len() as u64,
            };
            let (host_outcome, peer_observed) = tokio::join!(
                handle_upload_from_open(&mut host_half, &config, &base, &cancel, &open, None),
                async {
                    assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                    for chunk in &chunks {
                        peer.send(FileTransferMessage::Data { bytes: chunk }).await;
                    }
                    peer.send(FileTransferMessage::Finish {
                        actual_size: bytes.len() as u64,
                        digest: sha256(&bytes),
                    })
                    .await;
                    peer.read_control().await
                },
            );
            assert_eq!(
                host_outcome,
                TransferOutcome::Committed { bytes: size },
                "host outcome for size {size}"
            );
            assert_eq!(
                peer_observed,
                OwnedMessage::Committed,
                "wire outcome for size {size}"
            );
            assert_eq!(
                fs::read(&final_path).unwrap(),
                fs::read(&source_path).unwrap(),
                "content for size {size}"
            );
            assert_dir_entries(host_dir.path(), &[&final_path]);
            fs::remove_file(&final_path).unwrap();
        }
    }

    #[tokio::test]
    async fn download_from_open_success_all_sizes() {
        let source_dir = tempdir().unwrap();
        let controller_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        for size in [0_u64, 1, 65535, 65536, 65537] {
            let source_path = source_dir.path().join(format!("source-{size}.bin"));
            write_pattern_file(&source_path, size);
            let (bytes, _) = file_chunks(&source_path);
            let (controller_half, mut host_half) = duplex(64 * 1024);
            let mut peer = ScriptedPeer::new(
                controller_half,
                TransferDirection::Download,
                TransferSide::Controller,
            );
            // The session layer consumed the opening frame off the wire
            // before this entry; the scripted session records the same
            // transition so the rest of the exchange stays legal.
            peer.session
                .send(&FileTransferMessage::DownloadOpen { source: "consumed" })
                .unwrap();
            let cancel = AtomicBool::new(false);
            let source_string = path_string(&source_path);
            let open = FileTransferMessage::DownloadOpen {
                source: &source_string,
            };
            let (host_outcome, peer_observed) = tokio::join!(
                handle_download_from_open(&mut host_half, &config, &base, &cancel, &open, None),
                async {
                    let offer = peer.read_control().await;
                    assert!(matches!(
                        offer,
                        OwnedMessage::DownloadOffer {
                            file_name,
                            declared_size,
                        } if file_name == format!("source-{size}.bin") && declared_size == size
                    ));
                    peer.send(FileTransferMessage::Ready).await;
                    let mut sink = Box::new([0_u8; MAX_DATA_LEN]);
                    let mut received = Vec::new();
                    loop {
                        match peer.read_data(&mut *sink).await {
                            OwnedMessage::Data { len } => {
                                received.extend_from_slice(&sink[..len]);
                            }
                            OwnedMessage::Finish { .. } => break,
                            message => panic!("unexpected message: {message:?}"),
                        }
                    }
                    peer.send(FileTransferMessage::Committed).await;
                    received
                },
            );
            assert_eq!(
                host_outcome,
                TransferOutcome::Committed { bytes: size },
                "host outcome for size {size}"
            );
            // The scripted controller receives into memory; the real
            // controller would commit the target itself.
            assert_eq!(peer_observed, bytes, "received bytes for size {size}");
            assert_dir_empty(controller_dir.path());
        }
    }

    #[tokio::test]
    async fn upload_from_open_rejects_non_open_first_frames() {
        let host_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        // A Ready first frame is a protocol violation for an upload host.
        let (mut host_half, mut peer_half) = duplex(64 * 1024);
        let cancel = AtomicBool::new(false);
        let open = FileTransferMessage::Ready;
        let outcome =
            handle_upload_from_open(&mut host_half, &config, &base, &cancel, &open, None).await;
        assert_eq!(
            outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
        // The substream was closed without any frame being written.
        let frame = tokio::time::timeout(Duration::from_millis(50), async {
            let mut byte = [0_u8; 1];
            peer_half.read(&mut byte).await.unwrap()
        })
        .await;
        assert!(frame.is_err(), "no frame may reach the peer");
        assert_dir_empty(host_dir.path());

        // A DownloadOpen first frame on an upload substream is equally a
        // protocol violation.
        let (mut host_half, mut peer_half) = duplex(64 * 1024);
        let open = FileTransferMessage::DownloadOpen { source: "x" };
        let outcome =
            handle_upload_from_open(&mut host_half, &config, &base, &cancel, &open, None).await;
        assert_eq!(
            outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
        let frame = tokio::time::timeout(Duration::from_millis(50), async {
            let mut byte = [0_u8; 1];
            peer_half.read(&mut byte).await.unwrap()
        })
        .await;
        assert!(frame.is_err(), "no frame may reach the peer");
    }

    #[tokio::test]
    async fn download_from_open_rejects_non_open_first_frames() {
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let (mut host_half, mut peer_half) = duplex(64 * 1024);
        let cancel = AtomicBool::new(false);
        let open = FileTransferMessage::UploadOpen {
            destination: "",
            file_name: "f.bin",
            declared_size: 1,
        };
        let outcome =
            handle_download_from_open(&mut host_half, &config, &base, &cancel, &open, None).await;
        assert_eq!(
            outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
        let frame = tokio::time::timeout(Duration::from_millis(50), async {
            let mut byte = [0_u8; 1];
            peer_half.read(&mut byte).await.unwrap()
        })
        .await;
        assert!(frame.is_err(), "no frame may reach the peer");
    }

    #[tokio::test]
    async fn upload_from_open_checks_cancel_before_any_work() {
        let host_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let (mut host_half, mut peer_half) = duplex(64 * 1024);
        let cancel = AtomicBool::new(true);
        let destination = path_string(&host_dir.path().join("f.bin"));
        let open = FileTransferMessage::UploadOpen {
            destination: &destination,
            file_name: "f.bin",
            declared_size: 1,
        };
        let outcome =
            handle_upload_from_open(&mut host_half, &config, &base, &cancel, &open, None).await;
        assert_eq!(outcome, TransferOutcome::Cancelled);
        let frame = tokio::time::timeout(Duration::from_millis(50), async {
            let mut byte = [0_u8; 1];
            peer_half.read(&mut byte).await.unwrap()
        })
        .await;
        assert!(frame.is_err(), "no frame may reach the peer");
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn upload_from_open_destination_exists_fails_and_cleans_up() {
        let source_dir = tempdir().unwrap();
        let host_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 1024);
        let (bytes, _) = file_chunks(&source_path);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let final_path = host_dir.path().join("exists.bin");
        fs::write(&final_path, b"pre-existing").unwrap();
        let (controller_half, mut host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let cancel = AtomicBool::new(false);
        let wire_settled = AtomicBool::new(false);
        let destination = path_string(&final_path);
        let open = FileTransferMessage::UploadOpen {
            destination: &destination,
            file_name: "src.bin",
            declared_size: bytes.len() as u64,
        };
        let (host_outcome, error_message) = tokio::join!(
            handle_upload_from_open_with_settlement(
                &mut host_half,
                &config,
                &base,
                &cancel,
                &open,
                None,
                Some(&wire_settled),
            ),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "src.bin",
                    declared_size: bytes.len() as u64,
                })
                .await;
                peer.read_unchecked().await
            },
        );
        let expected = TransferOutcome::Failed(FileTransferErrorCode::DestinationExists);
        assert_eq!(host_outcome, expected);
        assert!(wire_settled.load(Ordering::Acquire));
        assert_eq!(
            error_message,
            OwnedMessage::Error {
                code: FileTransferErrorCode::DestinationExists
            }
        );
        assert_eq!(fs::read(&final_path).unwrap(), b"pre-existing");
    }

    #[tokio::test]
    async fn download_from_open_source_not_found_fails_and_keeps_no_state() {
        let source_dir = tempdir().unwrap();
        let controller_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let missing = source_dir.path().join("nope.bin");
        let source_string = path_string(&missing);
        let (controller_half, mut host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        // The session layer consumed the opening frame off the wire before
        // this entry; the scripted session records the same transition.
        peer.session
            .send(&FileTransferMessage::DownloadOpen { source: "consumed" })
            .unwrap();
        let cancel = AtomicBool::new(false);
        let wire_settled = AtomicBool::new(false);
        let open = FileTransferMessage::DownloadOpen {
            source: &source_string,
        };
        let (host_outcome, error_message) = tokio::join!(
            handle_download_from_open_with_settlement(
                &mut host_half,
                &config,
                &base,
                &cancel,
                &open,
                None,
                Some(&wire_settled),
            ),
            async { peer.read_control().await },
        );
        let expected = TransferOutcome::Failed(FileTransferErrorCode::SourceNotFound);
        assert_eq!(host_outcome, expected);
        assert!(wire_settled.load(Ordering::Acquire));
        assert_eq!(
            error_message,
            OwnedMessage::Error {
                code: FileTransferErrorCode::SourceNotFound
            }
        );
        assert_dir_empty(controller_dir.path());
    }

    // ------------------------------------------------------------------
    // Coverage-closure tests: orchestrator failure paths, cancellation
    // windows, protocol violations, wire-frame fault injection and helper
    // unit tests (design 10.3, 10.4, 10.5, 14, 15.2, 15.4).
    // ------------------------------------------------------------------

    /// Wraps a stream and fails the `fail_on_call`-th `poll_write` with a
    /// broken-pipe error, placing a deterministic write failure on a chosen
    /// frame while all earlier frames pass through.
    struct WriteFailAfter<S> {
        inner: S,
        fail_on_call: usize,
        calls: usize,
    }

    impl<S> WriteFailAfter<S> {
        fn new(inner: S, fail_on_call: usize) -> Self {
            Self {
                inner,
                fail_on_call,
                calls: 0,
            }
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for WriteFailAfter<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.calls += 1;
            if self.calls == self.fail_on_call {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "injected write failure",
                )));
            }
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for WriteFailAfter<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    #[derive(Clone, Copy)]
    enum OpeningWriteFault {
        WriteZero,
        FlushPending,
        FlushError,
    }

    struct OpeningFaultStream(OpeningWriteFault);

    impl AsyncRead for OpeningFaultStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for OpeningFaultStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            match self.0 {
                OpeningWriteFault::WriteZero => Poll::Ready(Ok(0)),
                OpeningWriteFault::FlushPending | OpeningWriteFault::FlushError => {
                    Poll::Ready(Ok(bytes.len()))
                }
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.0 {
                OpeningWriteFault::WriteZero => Poll::Ready(Ok(())),
                OpeningWriteFault::FlushPending => Poll::Pending,
                OpeningWriteFault::FlushError => {
                    Poll::Ready(Err(io::Error::other("injected flush failure")))
                }
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    struct CancelAfterBytesRead<S> {
        inner: S,
        cancel: Arc<AtomicBool>,
        trigger_at: usize,
        read: usize,
    }

    impl<S> CancelAfterBytesRead<S> {
        fn new(inner: S, cancel: Arc<AtomicBool>, trigger_at: usize) -> Self {
            Self {
                inner,
                cancel,
                trigger_at,
                read: 0,
            }
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for CancelAfterBytesRead<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let before = buf.filled().len();
            let result = Pin::new(&mut self.inner).poll_read(cx, buf);
            if matches!(result, Poll::Ready(Ok(()))) {
                self.read += buf.filled().len() - before;
                if self.read >= self.trigger_at {
                    self.cancel.store(true, Ordering::Release);
                }
            }
            result
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for CancelAfterBytesRead<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, bytes)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    struct CancelAfterFirstWrite<S> {
        inner: S,
        cancel: Arc<AtomicBool>,
        wrote: bool,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for CancelAfterFirstWrite<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for CancelAfterFirstWrite<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            let limit = if self.wrote { bytes.len() } else { 1 };
            let result = Pin::new(&mut self.inner).poll_write(cx, &bytes[..limit]);
            if matches!(result, Poll::Ready(Ok(written)) if written > 0) && !self.wrote {
                self.wrote = true;
                self.cancel.store(true, Ordering::Release);
            }
            result
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    struct FlushPendingAfter<S> {
        inner: S,
        pending_at: usize,
        flushes: usize,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for FlushPendingAfter<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for FlushPendingAfter<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, bytes)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.flushes + 1 == self.pending_at {
                return Poll::Pending;
            }
            self.flushes += 1;
            Pin::new(&mut self.inner).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    struct CancelAfterFlush<S> {
        inner: S,
        cancel: Arc<AtomicBool>,
        trigger_at: usize,
        flushes: usize,
    }

    struct CancellingSource {
        bytes: Vec<u8>,
        offset: usize,
        cancel: Arc<AtomicBool>,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for CancelAfterFlush<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for CancelAfterFlush<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, bytes)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let result = Pin::new(&mut self.inner).poll_flush(cx);
            if matches!(result, Poll::Ready(Ok(()))) {
                self.flushes += 1;
                if self.flushes == self.trigger_at {
                    self.cancel.store(true, Ordering::Release);
                }
            }
            result
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    impl TransferSource for CancellingSource {
        fn size(&self) -> u64 {
            self.bytes.len() as u64
        }

        fn bytes_read(&self) -> u64 {
            self.offset as u64
        }

        async fn read_block(&mut self, buffer: &mut [u8]) -> Result<usize, FileSemanticsError> {
            let remaining = &self.bytes[self.offset..];
            let length = remaining.len().min(buffer.len());
            buffer[..length].copy_from_slice(&remaining[..length]);
            self.offset += length;
            Ok(length)
        }

        async fn recheck_source(&self) -> Result<(), FileSemanticsError> {
            self.cancel.store(true, Ordering::Release);
            Ok(())
        }
    }

    /// A stream whose reads always fail with an I/O error.
    struct ReadErrorStream;

    impl AsyncRead for ReadErrorStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other("injected read failure")))
        }
    }

    /// Asserts that no frame reaches `stream` within a short window. A clean
    /// EOF is also proof that the peer received no frame.
    async fn assert_no_wire_frame(stream: &mut (impl AsyncRead + Unpin)) {
        let frame = tokio::time::timeout(Duration::from_millis(50), async {
            let mut byte = [0_u8; 1];
            stream.read(&mut byte).await
        })
        .await;
        match frame {
            Err(_) | Ok(Ok(0)) => {}
            Ok(Ok(_)) => panic!("no frame may reach the peer"),
            Ok(Err(error)) => panic!("the peer read failed unexpectedly: {error}"),
        }
    }

    /// Drains the sender's `Data` frames until the terminal `Finish` arrives.
    async fn drain_data_until_finish<S: AsyncRead + AsyncWrite + Unpin>(
        peer: &mut ScriptedPeer<S>,
        sink: &mut [u8],
    ) {
        loop {
            match peer.read_data(sink).await {
                OwnedMessage::Data { .. } => continue,
                OwnedMessage::Finish { .. } => break,
                message => panic!("unexpected message while draining: {message:?}"),
            }
        }
    }

    /// The one data block used by the small-file transfer tests, patterned
    /// exactly like `write_pattern_file` so the receiver's digest check
    /// matches the wire bytes.
    fn one_block_bytes(size: usize) -> Vec<u8> {
        (0..size).map(|index| pattern_byte(index as u64)).collect()
    }

    // -- Helper unit tests ------------------------------------------------

    #[test]
    fn transfer_config_defaults_are_the_fixed_durations() {
        let defaults = TransferConfig::defaults();
        assert_eq!(defaults.control_timeout, Duration::from_secs(30));
        assert_eq!(defaults.data_progress_timeout, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn write_frame_rejects_illegal_local_sends_and_send_failure_maps_them() {
        // In AwaitingOpen an upload controller may only send UploadOpen, so
        // a Ready send is rejected by the wire session before any byte is
        // written; send_failure maps the rejection to InvalidRequest.
        let mut session = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        let (mut stream, _peer) = duplex(64 * 1024);
        let error = write_frame(&mut stream, &mut session, &FileTransferMessage::Ready)
            .await
            .expect_err("the wire session must reject an illegal local send");
        assert!(matches!(error, WriteFrameError::Protocol));
        assert_eq!(
            send_failure(&mut session, error),
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
        assert!(session.is_closed());
    }

    #[tokio::test]
    async fn bounded_frame_write_times_out_after_partial_progress() {
        let cancel = AtomicBool::new(false);
        let mut session = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        let (mut stream, _peer) = duplex(1);
        let error = write_frame_bounded(
            &mut stream,
            &mut session,
            &FileTransferMessage::UploadOpen {
                destination: "remote",
                file_name: "source.bin",
                declared_size: 1,
            },
            WriteMode::Control {
                budget: Duration::from_millis(20),
            },
            &cancel,
        )
        .await
        .expect_err("a peer that stops reading must not stall the transfer owner");

        assert!(matches!(error, WriteFrameError::Timeout { started: true }));
    }

    #[tokio::test]
    async fn public_upload_bounds_zero_progress_and_opening_flush_faults() {
        for fault in [
            OpeningWriteFault::WriteZero,
            OpeningWriteFault::FlushPending,
            OpeningWriteFault::FlushError,
        ] {
            let mut stream = OpeningFaultStream(fault);
            let mut source = MemorySource {
                bytes: Vec::new(),
                offset: 0,
            };
            let cancel = AtomicBool::new(false);

            assert_eq!(
                run_upload(
                    &mut stream,
                    &timeout_config(),
                    &mut source,
                    "",
                    "empty.bin",
                    &cancel,
                )
                .await,
                TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
            );
        }
    }

    #[tokio::test]
    async fn public_upload_cancels_after_a_partial_opening_write() {
        let (controller, _host) = duplex(64 * 1024);
        let cancel = Arc::new(AtomicBool::new(false));
        let mut stream = CancelAfterFirstWrite {
            inner: controller,
            cancel: Arc::clone(&cancel),
            wrote: false,
        };
        let mut source = MemorySource {
            bytes: Vec::new(),
            offset: 0,
        };

        assert_eq!(
            run_upload(
                &mut stream,
                &test_config(),
                &mut source,
                "",
                "empty.bin",
                cancel.as_ref(),
            )
            .await,
            TransferOutcome::Cancelled
        );
    }

    #[tokio::test]
    async fn public_upload_sends_cancel_after_a_completed_data_block() {
        let bytes = b"cancel-after-this-block".to_vec();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut source = MemorySource {
            bytes: bytes.clone(),
            offset: 0,
        };
        let (controller, host) = duplex(64 * 1024);
        let mut controller = CancelAfterFlush {
            inner: controller,
            cancel: Arc::clone(&cancel),
            trigger_at: 2,
            flushes: 0,
        };
        let mut peer = ScriptedPeer::new(host, TransferDirection::Upload, TransferSide::Host);
        let config = test_config();

        let (outcome, ()) = tokio::join!(
            run_upload(
                &mut controller,
                &config,
                &mut source,
                "",
                "source.bin",
                cancel.as_ref(),
            ),
            async {
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::UploadOpen { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
                let mut sink = Box::new([0_u8; MAX_DATA_LEN]);
                assert_eq!(
                    peer.read_data(&mut *sink).await,
                    OwnedMessage::Data { len: bytes.len() }
                );
                assert_eq!(peer.read_control().await, OwnedMessage::Cancel);
            },
        );
        assert_eq!(outcome, TransferOutcome::Cancelled);
    }

    #[tokio::test]
    async fn public_upload_cancels_before_the_first_finish_byte() {
        let cancel = Arc::new(AtomicBool::new(false));
        let mut source = CancellingSource {
            bytes: Vec::new(),
            offset: 0,
            cancel: Arc::clone(&cancel),
        };
        let (mut controller, host) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(host, TransferDirection::Upload, TransferSide::Host);
        let config = test_config();

        let (outcome, ()) = tokio::join!(
            run_upload(
                &mut controller,
                &config,
                &mut source,
                "",
                "empty.bin",
                cancel.as_ref(),
            ),
            async {
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::UploadOpen { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
            },
        );
        assert_eq!(outcome, TransferOutcome::Cancelled);
    }

    #[tokio::test]
    async fn host_download_notifies_session_closing_after_ready_time_cancel() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("source.bin");
        write_pattern_file(&source_path, 4096);
        let source = path_string(&source_path);
        let base = BaseDirectory::capture().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let (controller, host) = duplex(64 * 1024);
        let mut host = CancelAfterBytesRead::new(host, Arc::clone(&cancel), 1);
        let mut peer = ScriptedPeer::new(
            controller,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        peer.session
            .send(&FileTransferMessage::DownloadOpen { source: &source })
            .unwrap();
        let open = FileTransferMessage::DownloadOpen { source: &source };
        let config = test_config();

        let (outcome, message) = tokio::join!(
            handle_download_from_open(&mut host, &config, &base, cancel.as_ref(), &open, None,),
            async {
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOffer { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
                peer.read_control().await
            },
        );
        assert_eq!(outcome, TransferOutcome::Cancelled);
        assert_eq!(
            message,
            OwnedMessage::Error {
                code: FileTransferErrorCode::SessionClosing
            }
        );
    }

    #[tokio::test]
    async fn host_download_cancel_survives_a_closing_notification_write_failure() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("source.bin");
        write_pattern_file(&source_path, 4096);
        let source = path_string(&source_path);
        let base = BaseDirectory::capture().unwrap();
        let cancel = Arc::new(AtomicBool::new(false));
        let (controller, host) = duplex(64 * 1024);
        let host = CancelAfterBytesRead::new(host, Arc::clone(&cancel), 1);
        let mut host = WriteFailAfter::new(host, 2);
        let mut peer = ScriptedPeer::new(
            controller,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        peer.session
            .send(&FileTransferMessage::DownloadOpen { source: &source })
            .unwrap();
        let open = FileTransferMessage::DownloadOpen { source: &source };
        let config = test_config();

        let (outcome, ()) = tokio::join!(
            handle_download_from_open(&mut host, &config, &base, cancel.as_ref(), &open, None,),
            async {
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOffer { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
            },
        );
        assert_eq!(outcome, TransferOutcome::Cancelled);
    }

    #[tokio::test]
    async fn committed_upload_reports_unconfirmed_when_ack_is_cancelled() {
        let host_dir = tempdir().unwrap();
        let destination = path_string(&host_dir.path().join("empty.bin"));
        let digest = sha256(&[]);
        let open_len = FileTransferMessage::UploadOpen {
            destination: &destination,
            file_name: "empty.bin",
            declared_size: 0,
        }
        .encode()
        .unwrap()
        .as_slice()
        .len();
        let finish_len = FileTransferMessage::Finish {
            actual_size: 0,
            digest,
        }
        .encode()
        .unwrap()
        .as_slice()
        .len();
        let cancel = Arc::new(AtomicBool::new(false));
        let (controller, host) = duplex(64 * 1024);
        let mut host = CancelAfterBytesRead::new(host, Arc::clone(&cancel), open_len + finish_len);
        let mut peer = ScriptedPeer::new(
            controller,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();

        let (outcome, ()) = tokio::join!(
            handle_upload(&mut host, &config, &base, cancel.as_ref()),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "empty.bin",
                    declared_size: 0,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                peer.send(FileTransferMessage::Finish {
                    actual_size: 0,
                    digest,
                })
                .await;
            },
        );
        assert_eq!(outcome, TransferOutcome::CommittedUnconfirmed { bytes: 0 });
        assert_eq!(fs::read(host_dir.path().join("empty.bin")).unwrap(), b"");
    }

    #[tokio::test]
    async fn committed_upload_reports_unconfirmed_when_ack_flush_times_out() {
        let host_dir = tempdir().unwrap();
        let destination = path_string(&host_dir.path().join("empty.bin"));
        let digest = sha256(&[]);
        let cancel = AtomicBool::new(false);
        let (controller, host) = duplex(64 * 1024);
        let mut host = FlushPendingAfter {
            inner: host,
            pending_at: 2,
            flushes: 0,
        };
        let mut peer = ScriptedPeer::new(
            controller,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let config = timeout_config();
        let base = BaseDirectory::capture().unwrap();

        let (outcome, ()) =
            tokio::join!(handle_upload(&mut host, &config, &base, &cancel), async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "empty.bin",
                    declared_size: 0,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                peer.send(FileTransferMessage::Finish {
                    actual_size: 0,
                    digest,
                })
                .await;
            },);
        assert_eq!(outcome, TransferOutcome::CommittedUnconfirmed { bytes: 0 });
        assert_eq!(fs::read(host_dir.path().join("empty.bin")).unwrap(), b"");
    }

    #[test]
    fn finish_write_failure_preserves_the_commit_uncertainty_boundary() {
        let cases = [
            WriteFrameError::Timeout { started: true },
            WriteFrameError::Cancelled { started: true },
            WriteFrameError::Io {
                error: io::Error::new(io::ErrorKind::BrokenPipe, "partial Finish"),
                started: true,
            },
        ];
        for error in cases {
            let mut session = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
            assert_eq!(
                finish_send_failure(&mut session, error, 73),
                TransferOutcome::CommitStatusUnknown { bytes: 73 }
            );
            assert!(session.is_closed());
        }

        let mut session = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        assert_eq!(
            finish_send_failure(
                &mut session,
                WriteFrameError::Timeout { started: false },
                73,
            ),
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        );
    }

    #[tokio::test]
    async fn write_frame_raw_control_write_failure_is_an_io_error() {
        // A control frame that encodes fine but cannot be written maps to
        // an I/O error (the encode succeeded; the stream failed).
        let (mut stream, _peer) = duplex(64 * 1024);
        let mut failing = WriteFailAfter::new(&mut stream, 1);
        let error = write_frame_raw(&mut failing, &FileTransferMessage::Ready)
            .await
            .expect_err("the injected write failure must surface");
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);

        let source = "x".repeat(yonder_core::wire::file_transfer::MAX_PATH_LEN + 1);
        let (mut stream, _peer) = duplex(64 * 1024);
        let error = write_frame_raw(
            &mut stream,
            &FileTransferMessage::DownloadOpen { source: &source },
        )
        .await
        .expect_err("an oversized control field must fail before writing");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn owned_message_maps_every_control_variant_and_rejects_data() {
        let digest = Sha256Digest::new([0x5A; 32]);
        assert_eq!(
            owned_message(FileTransferMessage::UploadOpen {
                destination: "d",
                file_name: "f",
                declared_size: 3,
            })
            .unwrap(),
            OwnedMessage::UploadOpen {
                destination: "d".to_owned(),
                file_name: "f".to_owned(),
                declared_size: 3,
            }
        );
        assert_eq!(
            owned_message(FileTransferMessage::DownloadOpen { source: "s" }).unwrap(),
            OwnedMessage::DownloadOpen {
                source: "s".to_owned()
            }
        );
        assert_eq!(
            owned_message(FileTransferMessage::DownloadOffer {
                file_name: "f",
                declared_size: 4,
            })
            .unwrap(),
            OwnedMessage::DownloadOffer {
                file_name: "f".to_owned(),
                declared_size: 4,
            }
        );
        assert_eq!(
            owned_message(FileTransferMessage::Ready).unwrap(),
            OwnedMessage::Ready
        );
        assert_eq!(
            owned_message(FileTransferMessage::Finish {
                actual_size: 5,
                digest,
            })
            .unwrap(),
            OwnedMessage::Finish {
                actual_size: 5,
                digest,
            }
        );
        assert_eq!(
            owned_message(FileTransferMessage::Committed).unwrap(),
            OwnedMessage::Committed
        );
        assert_eq!(
            owned_message(FileTransferMessage::Cancel).unwrap(),
            OwnedMessage::Cancel
        );
        assert_eq!(
            owned_message(FileTransferMessage::Error {
                code: FileTransferErrorCode::NoSpace,
            })
            .unwrap(),
            OwnedMessage::Error {
                code: FileTransferErrorCode::NoSpace,
            }
        );
        // Data never reaches the decoder through read_frame (the tag
        // dispatch streams it into the sink); the defensive arm rejects it.
        assert!(matches!(
            owned_message(FileTransferMessage::Data { bytes: &[] }),
            Err(FrameReadError::Protocol)
        ));
    }

    #[test]
    fn record_received_accepts_every_variant_in_a_legal_state() {
        let digest = Sha256Digest::new([0x5A; 32]);

        // Upload host: UploadOpen, then Data and Cancel in the transfer
        // phase (Finish moves the session out of the transfer phase), and
        // Error in any open stage.
        let mut session = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        record_received(
            &mut session,
            &OwnedMessage::UploadOpen {
                destination: "d".to_owned(),
                file_name: "f".to_owned(),
                declared_size: 3,
            },
            &[],
        )
        .expect("UploadOpen is the legal opening frame");
        session.send(&FileTransferMessage::Ready).unwrap();
        record_received(&mut session, &OwnedMessage::Data { len: 3 }, &[1, 2, 3])
            .expect("Data is legal in the upload transfer phase");
        record_received(&mut session, &OwnedMessage::Cancel, &[])
            .expect("a peer Cancel is legal in the transfer phase");
        let mut session = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        session
            .receive(&FileTransferMessage::UploadOpen {
                destination: "",
                file_name: "f",
                declared_size: 3,
            })
            .unwrap();
        session.send(&FileTransferMessage::Ready).unwrap();
        record_received(
            &mut session,
            &OwnedMessage::Finish {
                actual_size: 3,
                digest,
            },
            &[],
        )
        .expect("Finish is legal in the upload transfer phase");
        let mut session = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        session
            .receive(&FileTransferMessage::UploadOpen {
                destination: "",
                file_name: "f",
                declared_size: 0,
            })
            .unwrap();
        record_received(
            &mut session,
            &OwnedMessage::Error {
                code: FileTransferErrorCode::SessionClosing,
            },
            &[],
        )
        .expect("a peer Error is legal in any open stage");

        // Download host: DownloadOpen then Ready.
        let mut session = WireSession::new(TransferDirection::Download, TransferSide::Host);
        record_received(
            &mut session,
            &OwnedMessage::DownloadOpen {
                source: "s".to_owned(),
            },
            &[],
        )
        .expect("DownloadOpen is the legal opening frame");
        session
            .send(&FileTransferMessage::DownloadOffer {
                file_name: "f",
                declared_size: 0,
            })
            .unwrap();
        record_received(&mut session, &OwnedMessage::Ready, &[])
            .expect("Ready is legal after the offer");

        // Download controller: DownloadOffer after DownloadOpen.
        let mut session = WireSession::new(TransferDirection::Download, TransferSide::Controller);
        session
            .send(&FileTransferMessage::DownloadOpen { source: "s" })
            .unwrap();
        record_received(
            &mut session,
            &OwnedMessage::DownloadOffer {
                file_name: "f".to_owned(),
                declared_size: 0,
            },
            &[],
        )
        .expect("DownloadOffer is the legal offer frame");

        // Upload controller: Committed after Finish.
        let mut session = WireSession::new(TransferDirection::Upload, TransferSide::Controller);
        session
            .send(&FileTransferMessage::UploadOpen {
                destination: "",
                file_name: "f",
                declared_size: 0,
            })
            .unwrap();
        session.receive(&FileTransferMessage::Ready).unwrap();
        session
            .send(&FileTransferMessage::Finish {
                actual_size: 0,
                digest,
            })
            .unwrap();
        record_received(&mut session, &OwnedMessage::Committed, &[])
            .expect("Committed is the legal terminal frame");
    }

    #[test]
    fn record_received_rejects_illegal_sequences_as_protocol_violations() {
        // Committed before the opening frame on an upload host.
        let mut session = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        let outcome = record_received(&mut session, &OwnedMessage::Committed, &[])
            .expect_err("Committed before the opening frame is illegal");
        assert_eq!(
            outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
        assert!(session.is_closed());

        // Data before Ready on an upload host (OpenSent accepts only Cancel
        // and Error).
        let mut session = WireSession::new(TransferDirection::Upload, TransferSide::Host);
        session
            .receive(&FileTransferMessage::UploadOpen {
                destination: "",
                file_name: "f",
                declared_size: 0,
            })
            .unwrap();
        let outcome = record_received(&mut session, &OwnedMessage::Data { len: 0 }, &[])
            .expect_err("Data before Ready is illegal");
        assert_eq!(
            outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
        assert!(session.is_closed());
    }

    #[tokio::test]
    async fn cancel_signal_resolves_immediately_when_already_set() {
        let cancel = AtomicBool::new(true);
        let started = Instant::now();
        cancel_signal(&cancel).await;
        assert!(
            started.elapsed() < CANCEL_POLL_INTERVAL,
            "a set flag must not wait for the poll interval"
        );
    }

    #[tokio::test]
    async fn cancel_signal_polls_until_the_flag_is_set() {
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        let setter = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            flag.store(true, Ordering::Relaxed);
        });
        let started = Instant::now();
        cancel_signal(&cancel).await;
        setter.await.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(5));
    }

    #[tokio::test]
    async fn read_exact_maps_eof_truncation_and_io_errors() {
        // EOF at the start of the read is a boundary EOF.
        let (peer, mut stream) = duplex(64);
        drop(peer);
        let mut buf = [0_u8; 5];
        assert!(matches!(
            read_exact(&mut stream, &mut buf, None).await,
            Err(FrameReadError::Eof)
        ));

        // EOF in the middle of the frame is a truncated frame.
        let (mut peer, mut stream) = duplex(64);
        peer.write_all(&[1, 2]).await.unwrap();
        drop(peer);
        let mut buf = [0_u8; 5];
        assert!(matches!(
            read_exact(&mut stream, &mut buf, None).await,
            Err(FrameReadError::Truncated)
        ));

        // A stream I/O failure is reported as-is.
        let mut stream = ReadErrorStream;
        let mut buf = [0_u8; 5];
        assert!(matches!(
            read_exact(&mut stream, &mut buf, None).await,
            Err(FrameReadError::Io(_))
        ));
    }

    #[tokio::test]
    async fn read_frame_surfaces_stream_io_errors() {
        let mut stream = ReadErrorStream;
        let result = read_frame(
            &mut stream,
            ReadMode::Control {
                budget: Duration::from_secs(5),
            },
            None,
        )
        .await;
        assert!(matches!(result, Err(FrameReadError::Io(_))));
    }

    #[tokio::test]
    async fn read_frame_rejects_data_declared_larger_than_the_sink() {
        let (mut peer_half, mut stream) = duplex(64 * 1024);
        write_frame_raw(
            &mut peer_half,
            &FileTransferMessage::Data {
                bytes: &[0xAB; 100],
            },
        )
        .await
        .unwrap();
        // The declared length is within the wire bounds but exceeds the
        // caller's sink: a protocol violation, never a buffer overflow.
        let mut sink = [0_u8; 10];
        let result = read_frame(
            &mut stream,
            ReadMode::Control {
                budget: Duration::from_secs(5),
            },
            Some(&mut sink),
        )
        .await;
        assert!(matches!(result, Err(FrameReadError::Protocol)));
    }

    // -- Peer Error frames instead of the expected message -----------------

    #[tokio::test]
    async fn run_upload_receives_error_instead_of_ready() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 4096);
        let mut source = SourceFile::open(&source_path).unwrap();
        let config = test_config();
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(host_half, TransferDirection::Upload, TransferSide::Host);
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, _) = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                "",
                "src.bin",
                &cancel,
            ),
            async {
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::UploadOpen { .. }
                ));
                // The host may not send Error in this state; inject it raw.
                peer.send_fault(FileTransferMessage::Error {
                    code: FileTransferErrorCode::SourceNotFound,
                })
                .await;
            },
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SourceNotFound)
        );
    }

    #[tokio::test]
    async fn run_upload_receives_error_instead_of_committed() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 200 * 1024);
        let mut source = SourceFile::open(&source_path).unwrap();
        let config = test_config();
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(host_half, TransferDirection::Upload, TransferSide::Host);
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, _) = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                "",
                "src.bin",
                &cancel,
            ),
            async {
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::UploadOpen { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
                let mut sink = Box::new([0_u8; MAX_DATA_LEN]);
                drain_data_until_finish(&mut peer, &mut *sink).await;
                peer.send_fault(FileTransferMessage::Error {
                    code: FileTransferErrorCode::DigestMismatch,
                })
                .await;
            },
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::DigestMismatch)
        );
    }

    #[tokio::test]
    async fn run_download_receives_error_in_the_data_phase() {
        let source_dir = tempdir().unwrap();
        let controller_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 200 * 1024);
        let (bytes, chunks) = file_chunks(&source_path);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let target_string = path_string(&controller_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer =
            ScriptedPeer::new(host_half, TransferDirection::Download, TransferSide::Host);
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, _) = tokio::join!(
            run_download(
                &mut controller_stream,
                &config,
                &base,
                &source_string,
                Some(&target_string),
                &cancel,
            ),
            async {
                assert_eq!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOpen {
                        source: source_string.clone()
                    }
                );
                peer.send(FileTransferMessage::DownloadOffer {
                    file_name: "f.bin",
                    declared_size: bytes.len() as u64,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                peer.send(FileTransferMessage::Data { bytes: &chunks[0] })
                    .await;
                // The host may report a peer-visible failure mid-data.
                peer.send(FileTransferMessage::Error {
                    code: FileTransferErrorCode::NoSpace,
                })
                .await;
            },
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::NoSpace)
        );
        assert_dir_empty(controller_dir.path());
    }

    #[tokio::test]
    async fn handle_upload_error_as_opening_frame_is_a_protocol_failure() {
        // The wire session accepts Error only after the opening frame; an
        // Error first frame is a protocol violation, not a reported code.
        let host_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let host_outcome = tokio::join!(
            handle_upload(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send_fault(FileTransferMessage::Error {
                    code: FileTransferErrorCode::SourceNotFound,
                })
                .await;
            },
        )
        .0;
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn handle_download_error_as_opening_frame_is_a_protocol_failure() {
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let host_outcome = tokio::join!(
            handle_download(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send_fault(FileTransferMessage::Error {
                    code: FileTransferErrorCode::SourceNotFound,
                })
                .await;
            },
        )
        .0;
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
    }

    #[tokio::test]
    async fn handle_download_ready_as_opening_frame_is_a_protocol_failure() {
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let host_outcome = tokio::join!(
            handle_download(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send_fault(FileTransferMessage::Ready).await;
            },
        )
        .0;
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
    }

    // -- Protocol violations in the Ready and Committed phases --------------

    #[tokio::test]
    async fn run_upload_peer_cancel_while_awaiting_ready_is_a_protocol_failure() {
        // The host may never send Cancel in an upload (direction table); the
        // controller treats it as a protocol violation.
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 4096);
        let mut source = SourceFile::open(&source_path).unwrap();
        let config = test_config();
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(host_half, TransferDirection::Upload, TransferSide::Host);
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, _) = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                "",
                "src.bin",
                &cancel,
            ),
            async {
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::UploadOpen { .. }
                ));
                peer.send_fault(FileTransferMessage::Cancel).await;
            },
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
    }

    #[tokio::test]
    async fn run_upload_peer_cancel_after_finish_leaves_commit_status_unknown() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 200 * 1024);
        let mut source = SourceFile::open(&source_path).unwrap();
        let config = test_config();
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(host_half, TransferDirection::Upload, TransferSide::Host);
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, _) = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                "",
                "src.bin",
                &cancel,
            ),
            async {
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::UploadOpen { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
                let mut sink = Box::new([0_u8; MAX_DATA_LEN]);
                drain_data_until_finish(&mut peer, &mut *sink).await;
                peer.send_fault(FileTransferMessage::Cancel).await;
            },
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::CommitStatusUnknown { bytes: 200 * 1024 }
        );
    }

    #[tokio::test]
    async fn run_download_ready_instead_of_offer_is_a_protocol_failure() {
        let source_dir = tempdir().unwrap();
        let controller_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 1024);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let target_string = path_string(&controller_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer =
            ScriptedPeer::new(host_half, TransferDirection::Download, TransferSide::Host);
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, _) = tokio::join!(
            run_download(
                &mut controller_stream,
                &config,
                &base,
                &source_string,
                Some(&target_string),
                &cancel,
            ),
            async {
                assert_eq!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOpen {
                        source: source_string.clone()
                    }
                );
                // The host may not send Ready before the offer.
                peer.send_fault(FileTransferMessage::Ready).await;
            },
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
        assert_dir_empty(controller_dir.path());
    }

    #[tokio::test]
    async fn download_host_committed_while_awaiting_ready_is_a_protocol_failure() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 1024);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let host_outcome = tokio::join!(
            handle_download(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::DownloadOpen {
                    source: &source_string,
                })
                .await;
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOffer { .. }
                ));
                // The controller may not commit before Ready.
                peer.send_fault(FileTransferMessage::Committed).await;
            },
        )
        .0;
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
    }

    #[tokio::test]
    async fn download_host_receives_error_while_awaiting_committed() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 200 * 1024);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let host_outcome = tokio::join!(
            handle_download(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::DownloadOpen {
                    source: &source_string,
                })
                .await;
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOffer { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
                let mut sink = Box::new([0_u8; MAX_DATA_LEN]);
                drain_data_until_finish(&mut peer, &mut *sink).await;
                peer.send_fault(FileTransferMessage::Error {
                    code: FileTransferErrorCode::CommitFailed,
                })
                .await;
            },
        )
        .0;
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::CommitFailed)
        );
    }

    #[tokio::test]
    async fn download_host_invalid_ack_leaves_commit_status_unknown() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 200 * 1024);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let host_outcome = tokio::join!(
            handle_download(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::DownloadOpen {
                    source: &source_string,
                })
                .await;
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOffer { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
                let mut sink = Box::new([0_u8; MAX_DATA_LEN]);
                drain_data_until_finish(&mut peer, &mut *sink).await;
                peer.send_fault(FileTransferMessage::Ready).await;
            },
        )
        .0;
        assert_eq!(
            host_outcome,
            TransferOutcome::CommitStatusUnknown { bytes: 200 * 1024 }
        );
    }

    // -- Cancellation in every await window ----------------------------------

    #[tokio::test]
    async fn run_upload_cancel_during_await_ready_sends_cancel() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 4096);
        let mut source = SourceFile::open(&source_path).unwrap();
        let config = test_config();
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(host_half, TransferDirection::Upload, TransferSide::Host);
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, peer_message) = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                "",
                "src.bin",
                &cancel,
            ),
            async {
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::UploadOpen { .. }
                ));
                // The host goes silent and the operator cancels the wait.
                cancel.store(true, Ordering::Relaxed);
                peer.read_control().await
            },
        );
        assert_eq!(controller_outcome, TransferOutcome::Cancelled);
        assert_eq!(peer_message, OwnedMessage::Cancel);
    }

    #[tokio::test]
    async fn run_download_cancel_during_await_offer_sends_cancel() {
        let source_dir = tempdir().unwrap();
        let controller_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 1024);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let target_string = path_string(&controller_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer =
            ScriptedPeer::new(host_half, TransferDirection::Download, TransferSide::Host);
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, peer_message) = tokio::join!(
            run_download(
                &mut controller_stream,
                &config,
                &base,
                &source_string,
                Some(&target_string),
                &cancel,
            ),
            async {
                assert_eq!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOpen {
                        source: source_string.clone()
                    }
                );
                cancel.store(true, Ordering::Relaxed);
                // The host may not record a Cancel in this state; assert it
                // unchecked.
                peer.read_unchecked().await
            },
        );
        assert_eq!(controller_outcome, TransferOutcome::Cancelled);
        assert_eq!(peer_message, OwnedMessage::Cancel);
        assert_dir_empty(controller_dir.path());
    }

    #[tokio::test]
    async fn run_download_cancel_before_start_closes_without_wire_exchange() {
        let (mut controller_stream, mut peer_half) = duplex(64 * 1024);
        let cancel = AtomicBool::new(true);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let outcome = run_download(
            &mut controller_stream,
            &config,
            &base,
            "src.bin",
            Some("out.bin"),
            &cancel,
        )
        .await;
        assert_eq!(outcome, TransferOutcome::Cancelled);
        assert_no_wire_frame(&mut peer_half).await;
    }

    #[tokio::test]
    async fn run_upload_cancel_after_finish_reports_unknown_without_a_cancel_frame() {
        // After Finish the direction table forbids Cancel; the controller
        // abandons the Committed wait locally and writes nothing.
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 200 * 1024);
        let mut source = SourceFile::open(&source_path).unwrap();
        let config = test_config();
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(host_half, TransferDirection::Upload, TransferSide::Host);
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, _) = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                "",
                "src.bin",
                &cancel,
            ),
            async {
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::UploadOpen { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
                let mut sink = Box::new([0_u8; MAX_DATA_LEN]);
                drain_data_until_finish(&mut peer, &mut *sink).await;
                cancel.store(true, Ordering::Relaxed);
                assert_no_wire_frame(&mut peer.stream).await;
            },
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::CommitStatusUnknown { bytes: 200 * 1024 }
        );
    }

    #[tokio::test]
    async fn handle_upload_cancel_during_await_open_leaves_no_frame() {
        // The host cannot send anything before the opening frame; a cancel
        // closes the substream silently.
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let (mut host_stream, mut peer_half) = duplex(64 * 1024);
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        let cancel_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            flag.store(true, Ordering::Relaxed);
        });
        let outcome = handle_upload(&mut host_stream, &config, &base, &cancel).await;
        cancel_task.await.unwrap();
        assert_eq!(outcome, TransferOutcome::Cancelled);
        assert_no_wire_frame(&mut peer_half).await;
    }

    #[tokio::test]
    async fn handle_download_cancel_before_start_closes_without_wire_exchange() {
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let (mut host_stream, mut peer_half) = duplex(64 * 1024);
        let cancel = AtomicBool::new(true);
        let outcome = handle_download(&mut host_stream, &config, &base, &cancel).await;
        assert_eq!(outcome, TransferOutcome::Cancelled);
        assert_no_wire_frame(&mut peer_half).await;
    }

    #[tokio::test]
    async fn handle_download_cancel_during_await_open_leaves_no_frame() {
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let (mut host_stream, mut peer_half) = duplex(64 * 1024);
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        let cancel_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            flag.store(true, Ordering::Relaxed);
        });
        let outcome = handle_download(&mut host_stream, &config, &base, &cancel).await;
        cancel_task.await.unwrap();
        assert_eq!(outcome, TransferOutcome::Cancelled);
        assert_no_wire_frame(&mut peer_half).await;
    }

    #[tokio::test]
    async fn handle_download_from_open_cancel_before_start_closes_without_wire_exchange() {
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let (mut host_half, mut peer_half) = duplex(64 * 1024);
        let cancel = AtomicBool::new(true);
        let open = FileTransferMessage::DownloadOpen { source: "s" };
        let outcome =
            handle_download_from_open(&mut host_half, &config, &base, &cancel, &open, None).await;
        assert_eq!(outcome, TransferOutcome::Cancelled);
        assert_no_wire_frame(&mut peer_half).await;
    }

    #[tokio::test]
    async fn download_host_cancel_during_await_ready_leaves_no_frame() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 1024);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (host_outcome, _) = tokio::join!(
            handle_download(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::DownloadOpen {
                    source: &source_string,
                })
                .await;
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOffer { .. }
                ));
                cancel.store(true, Ordering::Relaxed);
                assert_no_wire_frame(&mut peer.stream).await;
            },
        );
        assert_eq!(host_outcome, TransferOutcome::Cancelled);
    }

    #[tokio::test]
    async fn download_host_cancel_after_finish_reports_unknown_without_a_frame() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 200 * 1024);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (host_outcome, _) = tokio::join!(
            handle_download(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::DownloadOpen {
                    source: &source_string,
                })
                .await;
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOffer { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
                let mut sink = Box::new([0_u8; MAX_DATA_LEN]);
                drain_data_until_finish(&mut peer, &mut *sink).await;
                cancel.store(true, Ordering::Relaxed);
                assert_no_wire_frame(&mut peer.stream).await;
            },
        );
        assert_eq!(
            host_outcome,
            TransferOutcome::CommitStatusUnknown { bytes: 200 * 1024 }
        );
    }

    #[tokio::test]
    async fn download_host_receiving_cancel_awaiting_ready_cancels_without_reply() {
        // The direction table allows no reply in this state; the best-effort
        // Error is silently rejected by the session and nothing reaches the
        // wire.
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 1024);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (host_outcome, _) = tokio::join!(
            handle_download(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::DownloadOpen {
                    source: &source_string,
                })
                .await;
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOffer { .. }
                ));
                peer.send(FileTransferMessage::Cancel).await;
                assert_no_wire_frame(&mut peer.stream).await;
            },
        );
        assert_eq!(host_outcome, TransferOutcome::Cancelled);
    }

    #[tokio::test]
    async fn download_host_receiving_cancel_after_finish_reports_unknown() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 200 * 1024);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let host_outcome = tokio::join!(
            handle_download(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::DownloadOpen {
                    source: &source_string,
                })
                .await;
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOffer { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
                let mut sink = Box::new([0_u8; MAX_DATA_LEN]);
                drain_data_until_finish(&mut peer, &mut *sink).await;
                // The controller may not send Cancel from AwaitingCommitted;
                // inject it raw.
                peer.send_fault(FileTransferMessage::Cancel).await;
            },
        )
        .0;
        assert_eq!(
            host_outcome,
            TransferOutcome::CommitStatusUnknown { bytes: 200 * 1024 }
        );
    }

    // -- EOF while awaiting a control exchange ------------------------------

    #[tokio::test]
    async fn eof_before_first_frame_fails_download_host() {
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let (mut host_stream, peer) = duplex(64 * 1024);
        drop(peer);
        let cancel = AtomicBool::new(false);
        let outcome = handle_download(&mut host_stream, &config, &base, &cancel).await;
        assert_eq!(
            outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        );
    }

    #[tokio::test]
    async fn run_download_eof_awaiting_offer_fails_controller() {
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer =
            ScriptedPeer::new(host_half, TransferDirection::Download, TransferSide::Host);
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let controller_outcome = tokio::join!(
            run_download(
                &mut controller_stream,
                &config,
                &base,
                "src.bin",
                Some("out.bin"),
                &cancel,
            ),
            async {
                assert_eq!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOpen {
                        source: "src.bin".to_owned()
                    }
                );
                // The host terminates without an offer.
                drop(peer);
            },
        )
        .0;
        assert_eq!(
            controller_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        );
    }

    #[tokio::test]
    async fn download_host_eof_awaiting_committed_reports_unknown() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 200 * 1024);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let host_outcome = tokio::join!(
            handle_download(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::DownloadOpen {
                    source: &source_string,
                })
                .await;
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOffer { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
                let mut sink = Box::new([0_u8; MAX_DATA_LEN]);
                drain_data_until_finish(&mut peer, &mut *sink).await;
                // The controller terminates without Committed.
                drop(peer);
            },
        )
        .0;
        assert_eq!(
            host_outcome,
            TransferOutcome::CommitStatusUnknown { bytes: 200 * 1024 }
        );
    }

    // -- Source failures: mid-stream read and the pre-Finish recheck ---------

    #[tokio::test]
    async fn run_upload_source_shrunk_before_start_fails_with_source_changed() {
        // The source shrank between open and the first read: the first
        // chunked read hits EOF and the recheck reports the change, so the
        // data loop fails with SourceChanged.
        let source_dir = tempdir().unwrap();
        let host_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 2 * 1024 * 1024);
        let mut source = SourceFile::open(&source_path).unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&source_path)
            .unwrap()
            .set_len(0)
            .unwrap();
        let config = test_config();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(host_half, TransferDirection::Upload, TransferSide::Host);
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, error_message) = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                &destination,
                "src.bin",
                &cancel,
            ),
            async {
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::UploadOpen { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
                peer.read_control().await
            },
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SourceChanged)
        );
        assert_eq!(
            error_message,
            OwnedMessage::Error {
                code: FileTransferErrorCode::SourceChanged
            }
        );
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn download_host_source_shrunk_after_offer_fails_with_source_changed() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 2 * 1024 * 1024);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (host_outcome, error_message) = tokio::join!(
            handle_download(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::DownloadOpen {
                    source: &source_string,
                })
                .await;
                // The offer proves the host's source handle is open; shrink
                // the file before any byte is read.
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOffer { .. }
                ));
                fs::OpenOptions::new()
                    .write(true)
                    .open(&source_path)
                    .unwrap()
                    .set_len(0)
                    .unwrap();
                peer.send(FileTransferMessage::Ready).await;
                peer.read_control().await
            },
        );
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SourceChanged)
        );
        assert_eq!(
            error_message,
            OwnedMessage::Error {
                code: FileTransferErrorCode::SourceChanged
            }
        );
    }

    #[tokio::test]
    async fn run_upload_source_mtime_changed_before_transfer_fails_at_recheck() {
        // The size is unchanged so every read succeeds; the modification
        // identity change is only detected by the recheck before Finish.
        let source_dir = tempdir().unwrap();
        let host_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 1024 * 1024);
        let mut source = SourceFile::open(&source_path).unwrap();
        fs::File::options()
            .write(true)
            .open(&source_path)
            .unwrap()
            .set_modified(SystemTime::now() - Duration::from_secs(3600))
            .unwrap();
        let config = test_config();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(host_half, TransferDirection::Upload, TransferSide::Host);
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, error_message) = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                &destination,
                "src.bin",
                &cancel,
            ),
            async {
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::UploadOpen { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
                let mut sink = Box::new([0_u8; MAX_DATA_LEN]);
                loop {
                    match peer.read_data(&mut *sink).await {
                        OwnedMessage::Data { .. } => continue,
                        OwnedMessage::Error { code } => break code,
                        message => panic!("unexpected message: {message:?}"),
                    }
                }
            },
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SourceChanged)
        );
        assert_eq!(error_message, FileTransferErrorCode::SourceChanged);
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn download_host_source_mtime_changed_after_offer_fails_at_recheck() {
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 1024 * 1024);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (host_outcome, error_message) = tokio::join!(
            handle_download(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::DownloadOpen {
                    source: &source_string,
                })
                .await;
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOffer { .. }
                ));
                fs::File::options()
                    .write(true)
                    .open(&source_path)
                    .unwrap()
                    .set_modified(SystemTime::now() - Duration::from_secs(3600))
                    .unwrap();
                peer.send(FileTransferMessage::Ready).await;
                let mut sink = Box::new([0_u8; MAX_DATA_LEN]);
                loop {
                    match peer.read_data(&mut *sink).await {
                        OwnedMessage::Data { .. } => continue,
                        OwnedMessage::Error { code } => break code,
                        message => panic!("unexpected message: {message:?}"),
                    }
                }
            },
        );
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SourceChanged)
        );
        assert_eq!(error_message, FileTransferErrorCode::SourceChanged);
    }

    // -- Wire write failures on the opening, data, Ready, Finish and
    //    Committed frames ----------------------------------------------------

    #[tokio::test]
    async fn run_upload_opening_frame_write_failure_fails_controller() {
        // The peer is gone before the transfer starts: the UploadOpen write
        // fails and the transfer aborts with SessionClosing.
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 4096);
        let mut source = SourceFile::open(&source_path).unwrap();
        let config = test_config();
        let (mut controller_stream, peer) = duplex(64 * 1024);
        drop(peer);
        let cancel = AtomicBool::new(false);
        let outcome = run_upload(
            &mut controller_stream,
            &config,
            &mut source,
            "",
            "src.bin",
            &cancel,
        )
        .await;
        assert_eq!(
            outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        );
    }

    #[tokio::test]
    async fn run_download_opening_frame_write_failure_fails_controller() {
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let (mut controller_stream, peer) = duplex(64 * 1024);
        drop(peer);
        let cancel = AtomicBool::new(false);
        let outcome = run_download(
            &mut controller_stream,
            &config,
            &base,
            "src.bin",
            Some("out.bin"),
            &cancel,
        )
        .await;
        assert_eq!(
            outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        );
    }

    #[tokio::test]
    async fn run_upload_data_frame_write_failure_fails_controller() {
        // The third write is the single data block's payload (opening frame,
        // data header, data payload): the data loop write fails.
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 4096);
        let mut source = SourceFile::open(&source_path).unwrap();
        let config = test_config();
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(host_half, TransferDirection::Upload, TransferSide::Host);
        let mut controller_stream = WriteFailAfter::new(controller_half, 3);
        let cancel = AtomicBool::new(false);
        let (controller_outcome, _) = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                "",
                "src.bin",
                &cancel,
            ),
            async {
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::UploadOpen { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
            },
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        );
    }

    #[tokio::test]
    async fn run_upload_finish_frame_write_failure_fails_controller() {
        // The fourth write is the Finish frame: the terminal write fails.
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 4096);
        let mut source = SourceFile::open(&source_path).unwrap();
        let config = test_config();
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(host_half, TransferDirection::Upload, TransferSide::Host);
        let mut controller_stream = WriteFailAfter::new(controller_half, 4);
        let cancel = AtomicBool::new(false);
        let (controller_outcome, _) = tokio::join!(
            run_upload(
                &mut controller_stream,
                &config,
                &mut source,
                "",
                "src.bin",
                &cancel,
            ),
            async {
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::UploadOpen { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
                let mut sink = Box::new([0_u8; MAX_DATA_LEN]);
                assert!(matches!(
                    peer.read_data(&mut *sink).await,
                    OwnedMessage::Data { .. }
                ));
            },
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        );
    }

    #[tokio::test]
    async fn run_download_ready_write_failure_fails_controller() {
        // The second write is the Ready frame after the offer.
        let source_dir = tempdir().unwrap();
        let controller_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 1024);
        let (bytes, _) = file_chunks(&source_path);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let target_string = path_string(&controller_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer =
            ScriptedPeer::new(host_half, TransferDirection::Download, TransferSide::Host);
        let mut controller_stream = WriteFailAfter::new(controller_half, 2);
        let cancel = AtomicBool::new(false);
        let (controller_outcome, _) = tokio::join!(
            run_download(
                &mut controller_stream,
                &config,
                &base,
                &source_string,
                Some(&target_string),
                &cancel,
            ),
            async {
                assert_eq!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOpen {
                        source: source_string.clone()
                    }
                );
                peer.send(FileTransferMessage::DownloadOffer {
                    file_name: "f.bin",
                    declared_size: bytes.len() as u64,
                })
                .await;
            },
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        );
        assert_dir_empty(controller_dir.path());
    }

    #[tokio::test]
    async fn run_download_committed_write_failure_reports_local_commit() {
        // The third write is the Committed frame: the commit has already
        // happened, so the final file exists and the acknowledgement status
        // is represented explicitly.
        let source_dir = tempdir().unwrap();
        let controller_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        let bytes = one_block_bytes(4096);
        fs::write(&source_path, &bytes).unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let target_string = path_string(&controller_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer =
            ScriptedPeer::new(host_half, TransferDirection::Download, TransferSide::Host);
        let mut controller_stream = WriteFailAfter::new(controller_half, 3);
        let cancel = AtomicBool::new(false);
        let (controller_outcome, _) = tokio::join!(
            run_download(
                &mut controller_stream,
                &config,
                &base,
                &source_string,
                Some(&target_string),
                &cancel,
            ),
            async {
                assert_eq!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOpen {
                        source: source_string.clone()
                    }
                );
                peer.send(FileTransferMessage::DownloadOffer {
                    file_name: "f.bin",
                    declared_size: bytes.len() as u64,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                peer.send(FileTransferMessage::Data { bytes: &bytes }).await;
                peer.send(FileTransferMessage::Finish {
                    actual_size: bytes.len() as u64,
                    digest: sha256(&bytes),
                })
                .await;
            },
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::CommittedUnconfirmed { bytes: 4096 }
        );
        let final_path = controller_dir.path().join("f.bin");
        assert_eq!(fs::read(&final_path).unwrap(), bytes);
        assert_dir_entries(controller_dir.path(), &[&final_path]);
    }

    #[tokio::test]
    async fn upload_host_ready_write_failure_fails_host() {
        // The host's only write before the data phase is Ready.
        let host_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let mut host_stream = WriteFailAfter::new(host_half, 1);
        let cancel = AtomicBool::new(false);
        let (host_outcome, _) = tokio::join!(
            handle_upload(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "src.bin",
                    declared_size: 4096,
                })
                .await;
            },
        );
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        );
        assert_dir_empty(host_dir.path());
    }

    #[tokio::test]
    async fn upload_host_committed_write_failure_reports_local_commit() {
        // The host's second write is Committed: the commit has already
        // happened, so the final file exists and the acknowledgement status
        // is represented explicitly.
        let host_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let bytes = one_block_bytes(4096);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let mut host_stream = WriteFailAfter::new(host_half, 2);
        let cancel = AtomicBool::new(false);
        let (host_outcome, _) = tokio::join!(
            handle_upload(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "src.bin",
                    declared_size: bytes.len() as u64,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                peer.send(FileTransferMessage::Data { bytes: &bytes }).await;
                peer.send(FileTransferMessage::Finish {
                    actual_size: bytes.len() as u64,
                    digest: sha256(&bytes),
                })
                .await;
            },
        );
        assert_eq!(
            host_outcome,
            TransferOutcome::CommittedUnconfirmed { bytes: 4096 }
        );
        let final_path = host_dir.path().join("f.bin");
        assert_eq!(fs::read(&final_path).unwrap(), bytes);
        assert_dir_entries(host_dir.path(), &[&final_path]);
    }

    #[tokio::test]
    async fn download_host_offer_write_failure_fails_host() {
        // The host's first write is the DownloadOffer.
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 4096);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        let mut host_stream = WriteFailAfter::new(host_half, 1);
        let cancel = AtomicBool::new(false);
        let (host_outcome, _) = tokio::join!(
            handle_download(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::DownloadOpen {
                    source: &source_string,
                })
                .await;
            },
        );
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        );
    }

    #[tokio::test]
    async fn download_host_data_write_failure_fails_host() {
        // The third write is the data block's payload (offer, data header,
        // data payload): the data loop write fails.
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 4096);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        let mut host_stream = WriteFailAfter::new(host_half, 3);
        let cancel = AtomicBool::new(false);
        let (host_outcome, _) = tokio::join!(
            handle_download(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::DownloadOpen {
                    source: &source_string,
                })
                .await;
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOffer { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
            },
        );
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        );
    }

    #[tokio::test]
    async fn download_host_finish_write_failure_fails_host() {
        // The fourth write is the Finish frame.
        let source_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        write_pattern_file(&source_path, 4096);
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        let mut host_stream = WriteFailAfter::new(host_half, 4);
        let cancel = AtomicBool::new(false);
        let (host_outcome, _) = tokio::join!(
            handle_download(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::DownloadOpen {
                    source: &source_string,
                })
                .await;
                assert!(matches!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOffer { .. }
                ));
                peer.send(FileTransferMessage::Ready).await;
                let mut sink = Box::new([0_u8; MAX_DATA_LEN]);
                assert!(matches!(
                    peer.read_data(&mut *sink).await,
                    OwnedMessage::Data { .. }
                ));
            },
        );
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::SessionClosing)
        );
    }

    // -- Local file failures: temporary-file creation, writes, finish and
    //    the no-replace commit -----------------------------------------------

    #[tokio::test]
    async fn upload_host_commit_fails_when_final_appears_concurrently() {
        // The destination is resolved and the temporary file exists before
        // Ready; a concurrent writer claiming the final path afterwards must
        // be refused by the no-replace commit.
        let host_dir = tempdir().unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let destination = path_string(&host_dir.path().join("f.bin"));
        let bytes = one_block_bytes(4096);
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Upload,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (host_outcome, error_message) = tokio::join!(
            handle_upload(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::UploadOpen {
                    destination: &destination,
                    file_name: "src.bin",
                    declared_size: bytes.len() as u64,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                let final_path = host_dir.path().join("f.bin");
                fs::write(&final_path, b"concurrent").unwrap();
                peer.send(FileTransferMessage::Data { bytes: &bytes }).await;
                peer.send(FileTransferMessage::Finish {
                    actual_size: bytes.len() as u64,
                    digest: sha256(&bytes),
                })
                .await;
                peer.read_unchecked().await
            },
        );
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::DestinationExists)
        );
        assert_eq!(
            error_message,
            OwnedMessage::Error {
                code: FileTransferErrorCode::DestinationExists
            }
        );
        let final_path = host_dir.path().join("f.bin");
        assert_eq!(fs::read(&final_path).unwrap(), b"concurrent");
        assert_dir_entries(host_dir.path(), &[&final_path]);
    }

    #[tokio::test]
    async fn download_controller_commit_fails_when_final_appears_concurrently() {
        let source_dir = tempdir().unwrap();
        let controller_dir = tempdir().unwrap();
        let source_path = source_dir.path().join("src.bin");
        let bytes = one_block_bytes(4096);
        fs::write(&source_path, &bytes).unwrap();
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let source_string = path_string(&source_path);
        let target_string = path_string(&controller_dir.path().join("f.bin"));
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer =
            ScriptedPeer::new(host_half, TransferDirection::Download, TransferSide::Host);
        let mut controller_stream = controller_half;
        let cancel = AtomicBool::new(false);
        let (controller_outcome, error_message) = tokio::join!(
            run_download(
                &mut controller_stream,
                &config,
                &base,
                &source_string,
                Some(&target_string),
                &cancel,
            ),
            async {
                assert_eq!(
                    peer.read_control().await,
                    OwnedMessage::DownloadOpen {
                        source: source_string.clone()
                    }
                );
                peer.send(FileTransferMessage::DownloadOffer {
                    file_name: "f.bin",
                    declared_size: bytes.len() as u64,
                })
                .await;
                assert_eq!(peer.read_control().await, OwnedMessage::Ready);
                let final_path = controller_dir.path().join("f.bin");
                fs::write(&final_path, b"concurrent").unwrap();
                peer.send(FileTransferMessage::Data { bytes: &bytes }).await;
                peer.send(FileTransferMessage::Finish {
                    actual_size: bytes.len() as u64,
                    digest: sha256(&bytes),
                })
                .await;
                peer.read_unchecked().await
            },
        );
        assert_eq!(
            controller_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::DestinationExists)
        );
        assert_eq!(
            error_message,
            OwnedMessage::Error {
                code: FileTransferErrorCode::DestinationExists
            }
        );
        let final_path = controller_dir.path().join("f.bin");
        assert_eq!(fs::read(&final_path).unwrap(), b"concurrent");
        assert_dir_entries(controller_dir.path(), &[&final_path]);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn download_host_drive_relative_source_fails_with_invalid_request() {
        // A drive-relative source ("C:foo") is valid on the wire but cannot
        // resolve against the base directory on Windows; resolution fails
        // and both sides learn InvalidRequest. (On Unix every encodable
        // source resolves, so this path is Windows-only.)
        let config = test_config();
        let base = BaseDirectory::capture().unwrap();
        let (controller_half, host_half) = duplex(64 * 1024);
        let mut peer = ScriptedPeer::new(
            controller_half,
            TransferDirection::Download,
            TransferSide::Controller,
        );
        let mut host_stream = host_half;
        let cancel = AtomicBool::new(false);
        let (host_outcome, error_message) = tokio::join!(
            handle_download(&mut host_stream, &config, &base, &cancel),
            async {
                peer.send(FileTransferMessage::DownloadOpen { source: "C:foo" })
                    .await;
                peer.read_unchecked().await
            },
        );
        assert_eq!(
            host_outcome,
            TransferOutcome::Failed(FileTransferErrorCode::InvalidRequest)
        );
        assert_eq!(
            error_message,
            OwnedMessage::Error {
                code: FileTransferErrorCode::InvalidRequest
            }
        );
    }
}
