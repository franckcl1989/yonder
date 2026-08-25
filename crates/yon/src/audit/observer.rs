//! The narrow audit observer, Yonder 0.2.0 design sections 8 (the allowed
//! code modification list), 13 (session establishment), 15 (event model),
//! 18 (recording timing and failure closing), 19 (writing model), 20
//! (bilateral checkpoints), 21 (joint manifest and local record seal) and
//! 22 (close and exit semantics).
//!
//! The observer wraps the [`AuditSession`] state machine, the
//! [`AuditWriter`] and the `/yonder/audit/3.0.0` substream halves behind a
//! narrow interface the controller and host call at the exact boundary
//! points of design section 8: before an input send, before a PTY write,
//! before an output send, before a display write, at resize, lifecycle and
//! file transfer events, and during the close and finalization flows.
//!
//! # Append-before-effect
//!
//! Every record method appends the whole batch through the bounded writer
//! and waits for the acknowledgement (design section 18 and 19.1) before
//! returning; the caller then produces the external effect. A failed
//! append fails the session closed internally (design section 18.7):
//! the failure-close records are appended best-effort and the
//! `CloseNotice(AuditFailure)` is conveyed best-effort, so the pump can
//! stop producing effects and return an explicit error.
//!
//! # Threading
//!
//! All methods take `&self`: the session state machine lives behind an
//! async mutex so the pump loops can share one observer across their select
//! branches (local input, remote output, resizes, transfers and the audit
//! frame reader) without mutable aliasing. The audit substream halves are
//! owned by the observer; [`AuditObserver::wait_for_frame`] is the
//! non-session pump branch, and [`AuditObserver::handle_frame`] processes
//! one received frame (checkpoint, checkpoint ack, close notice or
//! structured audit failure).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::sync::Mutex;
use yonder_core::wire::audit::{
    AuditCloseReason, AuditErrorCode, AuditMessage, AuditRole, BindingDigest, Checkpoint, Digest32,
    FRAME_HEADER_LEN, IdentityFingerprint, JointManifest, LedgerCommit, LedgerRoot, ManifestEnding,
    ManifestSignature, SecretContribution, SecretContributionMessage, SharedStream,
    decode_frame_header, validate_payload_len,
};
use yonder_core::{OsSecureRandom, SecureRandom};
use yonder_net::{PeerId, peer_id_bytes};

use crate::audit::identity::{AuditIdentity, AuditIdentityError, AuditRoot, PlatformAuditRoot};
use crate::audit::ledger;
use crate::audit::session::{
    AuditError, AuditSession, CONNECTION_STATE_ESTABLISHED, ConnectionSecret,
    DIRECTION_CTRL_TO_HOST, FileTransferFacts, MAX_LOCAL_OUTPUT_SEGMENT, PendingLedgerCommit,
    RecordBatch,
};
use crate::audit::writer::{AuditWriter, WRITER_OPERATION_TIMEOUT};

/// How often the terminal pumps poll the audit substream for peer frames
/// and due checkpoints. Checkpoints are non-urgent traffic (design
/// section 27.4: terminal traffic keeps priority), so a bounded poll
/// interval is enough; the 1-second checkpoint time trigger fires within
/// one poll of its deadline.
pub const AUDIT_CHECKPOINT_POLL: Duration = Duration::from_millis(250);
/// The bounded deadline of every finalization frame read and of the
/// handshake exchange (the same frozen exchange bound as the terminal
/// protocol).
pub const AUDIT_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
/// The complete enterprise audit establishment bound. Unlike one wire
/// exchange, establishment also opens the persistent ledger, creates the
/// session record and durably syncs its header before `AuditReady`; those
/// local storage steps must not consume the peer's individual 10-second
/// message allowance.
pub const AUDIT_ESTABLISH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckpointPhase {
    Running,
    Closing,
}

/// The fixed connection-binding domain label (design section 13.3).
const CONNECTION_BINDING_LABEL: &[u8] = b"yonder-audit-connection-binding-v3";
/// The fixed file-transfer identity domain label (design section 18.6:
/// the 0.2.0 file protocol carries no transfer ID, so both sides derive
/// one deterministically from the protocol facts they both verify).
const FILE_TRANSFER_ID_LABEL: &[u8] = b"yonder-audit-file-transfer-id-v3";

/// Resolves the platform audit root (design section 10), mapping the
/// identity errors to the fixed [`AuditError`] categories.
pub fn platform_audit_root() -> Result<PathBuf, AuditError> {
    PlatformAuditRoot.audit_root().map_err(map_audit_root_error)
}

fn map_audit_root_error(error: AuditIdentityError) -> AuditError {
    match error {
        AuditIdentityError::InvalidAuditDirectoryEnv => {
            AuditError::DirectoryUnavailable(io::Error::other(
                "the audit directory environment variable must be a non-empty absolute path",
            ))
        }
        _ => {
            AuditError::DirectoryUnavailable(io::Error::other("the audit directory is unavailable"))
        }
    }
}

/// The authenticated connection binding digest (design section 13.3): a
/// fixed-label SHA-256 over the two endpoint identities in fixed role
/// order, so both sides derive the identical value from facts they each
/// hold (their own and the peer's peer ID).
#[must_use]
pub fn connection_binding_digest(controller: PeerId, host: PeerId) -> BindingDigest {
    let controller =
        peer_id_bytes(controller).expect("a libp2p peer ID always fits the wire identity bound");
    let host = peer_id_bytes(host).expect("a libp2p peer ID always fits the wire identity bound");
    let mut hasher = Sha256::new();
    hasher.update(CONNECTION_BINDING_LABEL);
    hasher.update(controller.as_bytes());
    hasher.update(host.as_bytes());
    BindingDigest::new(hasher.finalize().into())
}

/// The deterministic transfer ID of one file transfer (design section
/// 18.6): the first eight bytes of a fixed-label SHA-256 over the protocol
/// facts both sides verify (`direction || remote_path || file_name ||
/// declared_size`). The 0.2.0 protocol carries no transfer ID, so this is
/// the only shared, independently derivable identity of a transfer.
#[must_use]
pub fn file_transfer_id(
    direction: u8,
    remote_path: &str,
    file_name: &str,
    declared_size: u64,
) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(FILE_TRANSFER_ID_LABEL);
    hasher.update([direction]);
    hasher.update(remote_path.as_bytes());
    hasher.update(file_name.as_bytes());
    hasher.update(declared_size.to_be_bytes());
    let digest = hasher.finalize();
    u64::from_be_bytes(digest[..8].try_into().expect("eight-byte digest slice"))
}

/// The UTC wall-clock second at session start (design section 15.4).
#[must_use]
pub fn utc_start_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// The persistent local identity adapted to the session trait
/// (design section 9).
struct IdentityAdapter(AuditIdentity);

impl crate::audit::session::PersistentIdentity for IdentityAdapter {
    fn public_key(&self) -> yonder_core::wire::audit::Ed25519PublicKey {
        self.0.public_key()
    }

    fn fingerprint(&self) -> IdentityFingerprint {
        self.0.fingerprint()
    }

    fn sign(&self, input: &[u8]) -> Result<yonder_core::wire::audit::Ed25519Signature, AuditError> {
        Ok(self.0.sign(input))
    }
}

/// The local ledger adapted to the session trait (design section 12). The
/// owned commit session bridges the borrow-free session trait calls with
/// the lock-guarded finalization of the real ledger: `begin_commit` takes
/// the ledger and the lock, `finish_commit` advances and returns it.
struct LedgerAdapter {
    inner: Option<ledger::Ledger>,
    pending: Option<ledger::OwnedCommitSession>,
}

impl LedgerAdapter {
    fn new(inner: ledger::Ledger) -> Self {
        Self {
            inner: Some(inner),
            pending: None,
        }
    }
}

impl crate::audit::session::Ledger for LedgerAdapter {
    fn snapshot(&self) -> Result<(u64, LedgerRoot), AuditError> {
        let inner = self
            .inner
            .as_ref()
            .ok_or(AuditError::InvalidState("the ledger is mid-commit"))?;
        let head = inner.head();
        Ok((head.sequence(), head.root()))
    }

    fn begin_commit(&mut self) -> Result<(u64, LedgerRoot), AuditError> {
        let inner = self
            .inner
            .take()
            .ok_or(AuditError::InvalidState("the ledger is mid-commit"))?;
        let session = inner.begin_owned_commit().map_err(map_ledger_error)?;
        let head = session.head();
        self.pending = Some(session);
        // The trait contract returns the commit's sequence, one past the
        // head read under the lock (design section 12.1), matching the
        // in-memory test ledger.
        let sequence = head
            .sequence()
            .checked_add(1)
            .ok_or(AuditError::LedgerInvalid)?;
        Ok((sequence, head.root()))
    }

    fn finish_commit(&mut self, commit: &LedgerCommit) -> Result<(), AuditError> {
        let session = self
            .pending
            .take()
            .ok_or(AuditError::InvalidState("no ledger commit is pending"))?;
        let inner = session.advance(commit).map_err(map_ledger_error)?;
        self.inner = Some(inner);
        Ok(())
    }
}

/// Maps a real ledger failure to the fixed session error categories
/// (design section 30).
fn map_ledger_error(error: ledger::AuditLedgerError) -> AuditError {
    use crate::audit::identity::AuditIdentityError;
    use ledger::AuditLedgerError as LedgerError;
    match error {
        LedgerError::AuditLedgerInvalid => AuditError::LedgerInvalid,
        LedgerError::AuditLedgerConflict => AuditError::LedgerConflict,
        LedgerError::AuditLedgerPermissions => AuditError::LedgerInvalid,
        LedgerError::Identity(error) => match error {
            AuditIdentityError::AuditIdentityMissing => AuditError::IdentityMissing,
            AuditIdentityError::AuditIdentityInvalid => AuditError::IdentityInvalid,
            AuditIdentityError::AuditIdentityPermissions => AuditError::IdentityPermissions,
            _ => AuditError::DirectoryUnavailable(io::Error::other(
                "the audit directory is unavailable",
            )),
        },
        LedgerError::LockFailed(error) => AuditError::DirectoryUnavailable(error),
        LedgerError::UnlockFailed(error) => AuditError::DirectoryUnavailable(error),
        LedgerError::StateReadFailed(error) => AuditError::DirectoryUnavailable(error),
        LedgerError::RecordReadFailed(error) => AuditError::DirectoryUnavailable(error),
        LedgerError::AuditLedgerCommitFailed(_) => AuditError::LedgerCommitFailed,
    }
}

fn blocking_storage_error() -> AuditError {
    AuditError::DirectoryUnavailable(io::Error::other(
        "the audit storage worker terminated unexpectedly",
    ))
}

async fn begin_ledger_commit(
    core: Arc<Mutex<AuditCore>>,
    pending: PendingLedgerCommit,
) -> Result<LedgerCommit, AuditError> {
    tokio::task::spawn_blocking(move || {
        let mut core = core.blocking_lock();
        core.session.begin_ledger_commit(pending)
    })
    .await
    .map_err(|_| blocking_storage_error())?
}

async fn finish_ledger_commit(
    core: Arc<Mutex<AuditCore>>,
    commit: LedgerCommit,
) -> Result<(), AuditError> {
    tokio::task::spawn_blocking(move || {
        let mut core = core.blocking_lock();
        core.session.finish_ledger_commit(&commit)
    })
    .await
    .map_err(|_| blocking_storage_error())?
}

/// What one received audit frame means for the pump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameEvent {
    /// A `CloseNotice` from the peer; the session close should begin with
    /// the carried reason.
    Close(AuditCloseReason),
    /// A structured audit failure from the peer; the session must fail
    /// closed.
    PeerAuditError(AuditErrorCode),
    /// A checkpoint or checkpoint ack was processed.
    None,
}

/// What one frame means for the finalization phase readers (the close is
/// asymmetric when one side initiates, so the phases tolerate the peer's
/// interleaved final checkpoint, late ack and redundant close notice).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FinalizationKind {
    /// The peer's final checkpoint: acknowledged by the receiver.
    Checkpoint,
    /// The ack of our final checkpoint.
    CheckpointAck,
    /// The peer's close notice: already handled by the close-reason step.
    CloseNotice,
    /// The peer's joint manifest.
    JointManifest,
    /// The peer's manifest signature.
    ManifestSignature,
    /// Anything else: a protocol violation in the finalization.
    Other,
}

impl FinalizationKind {
    fn classify(message: AuditMessage) -> Self {
        match message {
            AuditMessage::Checkpoint(_) => Self::Checkpoint,
            AuditMessage::CheckpointAck(_) => Self::CheckpointAck,
            AuditMessage::CloseNotice(_) => Self::CloseNotice,
            AuditMessage::JointManifest(_) => Self::JointManifest,
            AuditMessage::ManifestSignature(_) => Self::ManifestSignature,
            _ => Self::Other,
        }
    }
}

/// How the shared close reason is conveyed during finalization (design
/// section 15.2: the shared close event forms only after the reason was
/// successfully conveyed to the peer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseNoticeHandling {
    /// This side sends the `CloseNotice` and then records the shared close
    /// event (the controller side of every close it initiates).
    Sender(AuditCloseReason),
    /// The `CloseNotice` was already received by the frame pump; record the
    /// shared close event from it (the host side of a controller-initiated
    /// close).
    AlreadyReceived(AuditCloseReason),
    /// Read the peer's `CloseNotice` from the audit substream and then
    /// record the shared close event (the host side of a normal shell
    /// exit).
    Receiver,
}

/// The session state guarded by the observer's async mutex: the state
/// machine and the writer share the lock so every recording step is
/// serialized with the checkpoint and finalization steps.
struct AuditCore {
    session: AuditSession,
    writer: AuditWriter,
    /// Whether a checkpoint was sent and its ack has not yet arrived. A
    /// second checkpoint is never sent while one is pending, so an
    /// unanswered checkpoint can never be followed by a sequence mismatch
    /// (design section 20.3).
    awaiting_ack: bool,
}

/// Cancellation-safe frame state for the long-lived audit pump. Tokio's
/// single-read operation is cancellation safe, but `read_exact` and a frame
/// parser whose progress lives in the calling future are not: dropping that
/// future after a partial read would discard the byte count while leaving the
/// bytes consumed from the stream. Keeping both header and body progress here
/// lets the next `wait_for_frame` call resume the same frame.
struct IncrementalFrameReader {
    stream: Box<dyn AsyncRead + Send + Unpin>,
    header: [u8; FRAME_HEADER_LEN],
    header_filled: usize,
    frame: Option<Vec<u8>>,
    frame_filled: usize,
}

impl IncrementalFrameReader {
    fn new(stream: Box<dyn AsyncRead + Send + Unpin>) -> Self {
        Self {
            stream,
            header: [0_u8; FRAME_HEADER_LEN],
            header_filled: 0,
            frame: None,
            frame_filled: 0,
        }
    }

    async fn read_next(&mut self) -> Result<Option<Vec<u8>>, AuditError> {
        while self.header_filled < FRAME_HEADER_LEN {
            let filled = self.header_filled;
            let read = self
                .stream
                .read(&mut self.header[filled..])
                .await
                .map_err(AuditError::Substream)?;
            if read == 0 {
                if filled == 0 {
                    return Ok(None);
                }
                return Err(AuditError::Protocol(
                    yonder_core::error::ProtocolError::InvalidLength {
                        expected: FRAME_HEADER_LEN,
                        actual: filled,
                    },
                ));
            }
            self.header_filled += read;
        }

        if self.frame.is_none() {
            let (tag, payload_len) = decode_frame_header(&self.header)?;
            let payload_len = usize::try_from(payload_len).map_err(|_| {
                AuditError::Protocol(yonder_core::error::ProtocolError::InvalidLength {
                    expected: 0,
                    actual: usize::MAX,
                })
            })?;
            validate_payload_len(tag, payload_len)?;
            let mut frame = vec![0_u8; FRAME_HEADER_LEN + payload_len];
            frame[..FRAME_HEADER_LEN].copy_from_slice(&self.header);
            self.frame_filled = FRAME_HEADER_LEN;
            self.frame = Some(frame);
        }

        let frame = self
            .frame
            .as_mut()
            .ok_or(AuditError::InvalidState("audit frame body is unavailable"))?;
        while self.frame_filled < frame.len() {
            let filled = self.frame_filled;
            let read = self
                .stream
                .read(&mut frame[filled..])
                .await
                .map_err(AuditError::Substream)?;
            if read == 0 {
                return Err(AuditError::Substream(io::Error::from(
                    io::ErrorKind::UnexpectedEof,
                )));
            }
            self.frame_filled += read;
        }

        let frame = self
            .frame
            .take()
            .ok_or(AuditError::InvalidState("audit frame body is unavailable"))?;
        self.header = [0_u8; FRAME_HEADER_LEN];
        self.header_filled = 0;
        self.frame_filled = 0;
        Ok(Some(frame))
    }
}

/// The narrow audit observer of one endpoint session (design sections 8 and
/// 32.2). `Debug` is deliberately not implemented: the session carries
/// secrets and the redacted session `Debug` is reachable through the
/// observer's internals only.
pub struct AuditObserver {
    core: Arc<Mutex<AuditCore>>,
    read: Mutex<IncrementalFrameReader>,
    write: Mutex<Box<dyn AsyncWrite + Send + Unpin>>,
    /// The monotonic time base at `AuditReady` (design section 15.4).
    base: tokio::time::Instant,
}

impl AuditObserver {
    /// The full audit session establishment (design section 13): the
    /// `AuditHello` and secret-contribution exchange, the session ID and
    /// input commitment key derivation, the local audit file creation and
    /// header sync, and the `AuditReady` exchange. Only after this returns
    /// may the terminal become active (design sections 13.2 and 14).
    ///
    /// `controller` and `host` are the two endpoint identities in role
    /// order; every side derives the identical authenticated connection
    /// binding from them (design section 13.3).
    #[allow(clippy::too_many_arguments)]
    pub async fn establish(
        stream: impl AsyncRead + AsyncWrite + Send + Unpin + 'static,
        role: AuditRole,
        controller: PeerId,
        host: PeerId,
        utc_start_seconds: u64,
        terminal_hello_digest: Digest32,
        root: &Path,
        random: &mut impl SecureRandom,
    ) -> Result<Self, AuditError> {
        let binding = connection_binding_digest(controller, host);
        let ledger_root = root.to_path_buf();
        let ledger = tokio::task::spawn_blocking(move || {
            ledger::Ledger::open(&ledger_root, &mut OsSecureRandom)
        })
        .await
        .map_err(|_| blocking_storage_error())?
        .map_err(map_ledger_error)?;
        let identity = ledger.identity().clone();
        let mut session = AuditSession::new(
            role,
            Box::new(IdentityAdapter(identity)),
            Box::new(LedgerAdapter::new(ledger)),
            binding,
            utc_start_seconds,
            random,
        )?;
        let mut stream = stream;

        // 1. The hello and secret contribution exchange (section 13.3).
        let hello = *session.local_hello();
        write_frame_to(&mut stream, &AuditMessage::AuditHello(hello)).await?;
        let peer_hello = expect_frame(&mut stream, |message| match message {
            AuditMessage::AuditHello(hello) => Some(hello),
            _ => None,
        })
        .await?;
        let contribution = session.local_contribution().clone();
        write_frame_to(
            &mut stream,
            &AuditMessage::SecretContribution(SecretContributionMessage::new(contribution)),
        )
        .await?;
        let peer_contribution = expect_frame(&mut stream, |message| match message {
            AuditMessage::SecretContribution(contribution) => {
                Some(*contribution.contribution().as_bytes())
            }
            _ => None,
        })
        .await?;

        // 2. Validate the peer hello and contribution, derive the session
        //    ID and the input commitment key (sections 13.3-13.5).
        session.receive_peer_hello(&peer_hello, &SecretContribution::new(peer_contribution))?;
        let ready = session.compute_ready(ConnectionSecret::NotExportable)?;

        // 3. Create the local audit file and sync the header (section 13.5
        //    steps 5-6 and 19.2).
        let session_id = session
            .session_id()
            .ok_or(AuditError::InvalidState("session ID not computed"))?;
        let writer = AuditWriter::open(
            &root.join(crate::audit::identity::RECORDS_DIR_NAME),
            &session_id,
            role,
        )?;
        let header = session.build_header(&ready, terminal_hello_digest)?;
        writer.initialize(&header).await?;

        // 4. The ready exchange (section 13.5 steps 7-8).
        write_frame_to(&mut stream, &AuditMessage::AuditReady(ready)).await?;
        let peer_ready = expect_frame(&mut stream, |message| match message {
            AuditMessage::AuditReady(ready) => Some(ready),
            _ => None,
        })
        .await?;
        session.receive_peer_ready(&peer_ready)?;

        let base = tokio::time::Instant::now();
        let (read, write) = tokio::io::split(stream);
        let observer = Self {
            core: Arc::new(Mutex::new(AuditCore {
                session,
                writer,
                awaiting_ack: false,
            })),
            read: Mutex::new(IncrementalFrameReader::new(Box::new(read))),
            write: Mutex::new(Box::new(write)),
            base,
        };
        observer
            .record_connection_state(CONNECTION_STATE_ESTABLISHED)
            .await?;
        Ok(observer)
    }

    /// The monotonic nanoseconds since `AuditReady` (design section 15.4).
    #[must_use]
    pub fn now_ns(&self) -> u64 {
        self.base.elapsed().as_nanos() as u64
    }

    /// Whether the session failed closed and no further recording is
    /// possible.
    pub async fn has_failed(&self) -> bool {
        self.core.lock().await.session.has_failed()
    }

    /// The session ID, once the handshake derived it.
    pub async fn session_id(&self) -> Option<yonder_core::wire::audit::SessionId> {
        self.core.lock().await.session.session_id()
    }

    // -----------------------------------------------------------------
    // Recording (design sections 18.1-18.6). Every method appends the
    // whole batch and waits for the buffered write before returning; the
    // caller then produces the external effect. On failure the session
    // fails closed internally (design section 18.7).
    // -----------------------------------------------------------------

    /// Design section 18.1/18.2: one controller input send step or one
    /// host input receive step.
    pub async fn record_input(&self, bytes: &[u8]) -> Result<(), AuditError> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.record(|session, now| session.record_input(bytes, now))
            .await
    }

    /// Design section 18.1/18.3: the local outcome of a network send.
    pub async fn record_send_outcome(
        &self,
        direction: u8,
        confirmed: bool,
        bytes: u64,
    ) -> Result<(), AuditError> {
        self.record(|session, now| session.record_send_outcome(direction, confirmed, bytes, now))
            .await
    }

    /// Design section 18.2: the local outcome of a PTY/ConPTY write.
    pub async fn record_pty_write_outcome(
        &self,
        confirmed: bool,
        bytes: u64,
    ) -> Result<(), AuditError> {
        self.record(|session, now| session.record_pty_write_outcome(confirmed, bytes, now))
            .await
    }

    /// Design section 18.3: one host PTY output read step (the raw output
    /// record and the completed shared output blocks). One record frame
    /// holds at most 64 KiB of raw output (design section 23.3), so a
    /// larger burst is split into segment-sized records; the canonical
    /// stream is byte-identical either way.
    pub async fn record_raw_output(&self, bytes: &[u8]) -> Result<(), AuditError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let mut offset = 0;
        while offset < bytes.len() {
            let end = (offset + MAX_LOCAL_OUTPUT_SEGMENT).min(bytes.len());
            self.record(|session, now| session.record_output(&bytes[offset..end], now))
                .await?;
            offset = end;
        }
        Ok(())
    }

    /// Design section 18.4: the display bytes handed to the local display
    /// write path after the platform output adapter. Like the raw output
    /// records, a larger burst is split into segment-sized records.
    pub async fn record_display_bytes(&self, bytes: &[u8]) -> Result<(), AuditError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let mut offset = 0;
        while offset < bytes.len() {
            let end = (offset + MAX_LOCAL_OUTPUT_SEGMENT).min(bytes.len());
            self.record(|session, now| session.record_display_bytes(&bytes[offset..end], now))
                .await?;
            offset = end;
        }
        Ok(())
    }

    /// Design section 18.4: the local outcome of a display write.
    pub async fn record_display_write_outcome(
        &self,
        confirmed: bool,
        bytes: u64,
    ) -> Result<(), AuditError> {
        self.record(|session, now| session.record_display_write_outcome(confirmed, bytes, now))
            .await
    }

    /// Design section 18.5: one resize observation with the sender's
    /// direction.
    pub async fn record_resize(
        &self,
        direction: u8,
        cols: u16,
        rows: u16,
    ) -> Result<(), AuditError> {
        self.record(|session, now| session.record_resize(direction, cols, rows, now))
            .await
    }

    /// Design section 15.2: the shared `TerminalHello` digest event.
    pub async fn record_terminal_hello(&self, digest: Digest32) -> Result<(), AuditError> {
        self.record(|session, now| session.record_terminal_hello(digest, now))
            .await
    }

    /// Design section 15.2: the shared `TerminalReady` event.
    pub async fn record_terminal_ready(&self) -> Result<(), AuditError> {
        self.record(|session, now| session.record_terminal_ready(now))
            .await
    }

    /// Design section 15.2: the shared `TerminalExit` event.
    pub async fn record_terminal_exit(&self, exit_code: u32) -> Result<(), AuditError> {
        self.record(|session, now| session.record_terminal_exit(exit_code, now))
            .await
    }

    /// Design section 15.2: the shared `TerminalComplete` event.
    pub async fn record_terminal_complete(&self) -> Result<(), AuditError> {
        self.record(|session, now| session.record_terminal_complete(now))
            .await
    }

    /// Design section 15.3: one local keyboard shortcut action.
    pub async fn record_key_action(&self, action: u8) -> Result<(), AuditError> {
        self.record(|session, now| session.record_key_action(action, now))
            .await
    }

    /// Design section 15.3: one local lifecycle observation (active detach,
    /// local interrupt), related to the last shared control event.
    pub async fn record_lifecycle(&self, kind: u8) -> Result<(), AuditError> {
        self.record(|session, now| {
            let related = session.shared_snapshot().get(SharedStream::Control).head();
            session.record_local_lifecycle(kind, related, now)
        })
        .await
    }

    /// Design section 15.3: one local connection state change.
    pub async fn record_connection_state(&self, state: u8) -> Result<(), AuditError> {
        self.record(|session, now| session.record_connection_state(state, now))
            .await
    }

    /// Design section 18.6: one shared file transfer event plus the local
    /// record.
    pub async fn record_file_transfer(
        &self,
        facts: &FileTransferFacts<'_>,
        local_path: Option<&str>,
    ) -> Result<(), AuditError> {
        self.record(|session, now| session.record_file_transfer(facts, local_path, now))
            .await
    }

    /// Records a post-`Finish` result that is knowable only by this endpoint
    /// and therefore cannot enter the shared file-transfer chain.
    pub async fn record_local_file_transfer_result(
        &self,
        kind: u8,
        transfer_id: u64,
        final_size: u64,
        digest: Digest32,
        local_path: Option<&str>,
    ) -> Result<(), AuditError> {
        self.record(|session, now| {
            session.record_local_file_transfer_result(
                kind,
                transfer_id,
                final_size,
                digest,
                local_path,
                now,
            )
        })
        .await
    }

    /// One recording step with the append-before-effect contract and the
    /// internal failure close (design sections 18 and 18.7).
    async fn record<'a>(
        &self,
        step: impl FnOnce(&mut AuditSession, u64) -> Result<RecordBatch<'a>, AuditError>,
    ) -> Result<(), AuditError> {
        let mut core = self.core.lock().await;
        let error = match step(&mut core.session, self.now_ns()) {
            Ok(batch) => match core.writer.append_batch(batch).await {
                Ok(()) => return Ok(()),
                Err(error) => error,
            },
            Err(error) => error,
        };
        if !core.session.has_failed() {
            let failure_deadline = tokio::time::Instant::now() + WRITER_OPERATION_TIMEOUT;
            let code = error
                .code()
                .unwrap_or(AuditErrorCode::AuditRecordWriteFailed);
            if let Ok(batch) = core.session.fail_closed_records(
                code,
                AuditCloseReason::AuditFailure,
                self.now_ns(),
            ) {
                let _ = tokio::time::timeout_at(failure_deadline, core.writer.append_batch(batch))
                    .await;
            }
            drop(core);
            self.send_failure_notice_until(code, AuditCloseReason::AuditFailure, failure_deadline)
                .await;
        }
        Err(error)
    }

    // -----------------------------------------------------------------
    // Checkpoints (design section 20)
    // -----------------------------------------------------------------

    /// Whether a checkpoint is due and no exchange is pending.
    pub async fn checkpoint_due(&self) -> bool {
        let core = self.core.lock().await;
        core.session.is_active() && !core.awaiting_ack && core.session.checkpoint_due(self.now_ns())
    }

    /// Design sections 20.1 and 20.2: when a checkpoint is due, builds it,
    /// appends and syncs the evidence, and sends the signed checkpoint.
    /// While an earlier checkpoint is awaiting its ack, nothing is sent.
    pub async fn send_due_checkpoint(&self) -> Result<(), AuditError> {
        let mut core = self.core.lock().await;
        if core.awaiting_ack
            || !core.session.is_active()
            || !core.session.checkpoint_due(self.now_ns())
        {
            return Ok(());
        }
        let (checkpoint, evidence) = core.session.build_checkpoint(self.now_ns())?;
        core.awaiting_ack = true;
        core.writer.append_batch(evidence).await?;
        core.writer.sync_all().await?;
        drop(core);
        self.send_frame(&AuditMessage::Checkpoint(checkpoint)).await
    }

    /// Waits for the next audit frame, completing with `None` when the
    /// substream closes cleanly at a message boundary. The pump uses this
    /// as one select branch; the returned frame is processed by
    /// [`AuditObserver::handle_frame`].
    pub async fn wait_for_frame(&self) -> Result<Option<Vec<u8>>, AuditError> {
        let mut read = self.read.lock().await;
        read.read_next().await
    }

    /// Processes one received frame (design sections 20.3 and 15.2): a
    /// peer checkpoint is verified, evidenced, synced and acknowledged; an
    /// ack confirms the pending checkpoint; a close notice or a structured
    /// audit failure is surfaced to the pump.
    pub async fn handle_frame(&self, frame: &[u8]) -> Result<FrameEvent, AuditError> {
        let message = AuditMessage::decode_frame(frame)?;
        match message {
            AuditMessage::Checkpoint(checkpoint) => {
                self.handle_checkpoint(checkpoint, CheckpointPhase::Running)
                    .await
            }
            AuditMessage::CheckpointAck(ack) => {
                let mut core = self.core.lock().await;
                let evidence = core.session.receive_checkpoint_ack(&ack, self.now_ns())?;
                core.awaiting_ack = false;
                if let Some(batch) = evidence {
                    core.writer.append_batch(batch).await?;
                }
                drop(core);
                Ok(FrameEvent::None)
            }
            AuditMessage::CloseNotice(reason) => Ok(FrameEvent::Close(reason)),
            AuditMessage::AuditError(code) => Ok(FrameEvent::PeerAuditError(code)),
            _ => Err(AuditError::InvalidState(
                "unexpected audit frame during the session",
            )),
        }
    }

    async fn handle_checkpoint(
        &self,
        checkpoint: Checkpoint,
        phase: CheckpointPhase,
    ) -> Result<FrameEvent, AuditError> {
        let mut core = self.core.lock().await;
        let (ack, evidence) = match phase {
            CheckpointPhase::Running => core
                .session
                .receive_checkpoint(&checkpoint, self.now_ns())?,
            CheckpointPhase::Closing => core
                .session
                .receive_final_checkpoint(&checkpoint, self.now_ns())?,
        };
        core.writer.append_batch(evidence).await?;
        core.writer.sync_all().await?;
        drop(core);
        self.send_frame(&AuditMessage::CheckpointAck(ack)).await?;
        Ok(FrameEvent::None)
    }

    // -----------------------------------------------------------------
    // Close and finalization (design sections 21 and 22)
    // -----------------------------------------------------------------

    /// The normal close flow: the final bilateral checkpoint, the direction
    /// close, the shared close reason, the joint manifest exchange and the
    /// acyclic footer with the serialized ledger commit (design sections
    /// 20.1, 21 and 12.3). Both sides run the same steps; the
    /// [`CloseNoticeHandling`] selects how the close reason is conveyed.
    /// Any failure returns an explicit error so the caller never reports
    /// only the remote exit code (design section 22.1).
    pub async fn close_and_finalize(
        &self,
        ending: ManifestEnding,
        ended_normally: bool,
        close: CloseNoticeHandling,
    ) -> Result<(), AuditError> {
        // 0. Convey or receive the close reason first. A receiver may find
        //    running checkpoint traffic ahead of the notice on the ordered
        //    audit substream; that traffic is settled as observation
        //    evidence, not mistaken for the final checkpoint.
        let reason = match close {
            CloseNoticeHandling::Sender(reason) => {
                self.send_frame(&AuditMessage::CloseNotice(reason)).await?;
                reason
            }
            CloseNoticeHandling::AlreadyReceived(reason) => reason,
            CloseNoticeHandling::Receiver => self.receive_close_reason().await?,
        };

        // 1. Establish the shared close barrier before constructing the
        //    final checkpoint. Closing the normalizers commits any final
        //    partial input/output blocks, after which the shared snapshot is
        //    stable and exact comparison is meaningful.
        self.record_shared_close(reason).await?;
        self.close_directions().await?;

        // 2. Settle any running checkpoint already awaiting an ack, then
        //    send a fresh final checkpoint from the stable snapshot. A peer
        //    observation whose snapshot differs is an older running
        //    checkpoint delayed across substreams; acknowledge it and keep
        //    waiting for the exact final checkpoint.
        let mut own_final_sent = false;
        let mut peer_final_seen = false;
        loop {
            if !own_final_sent {
                let checkpoint = {
                    let mut core = self.core.lock().await;
                    if core.awaiting_ack {
                        None
                    } else {
                        let (checkpoint, evidence) =
                            core.session.build_final_checkpoint(self.now_ns())?;
                        core.awaiting_ack = true;
                        core.writer.append_batch(evidence).await?;
                        core.writer.sync_all().await?;
                        Some(checkpoint)
                    }
                };
                if let Some(checkpoint) = checkpoint {
                    self.send_frame(&AuditMessage::Checkpoint(checkpoint))
                        .await?;
                    own_final_sent = true;
                }
            }

            let core = self.core.lock().await;
            let confirmed = own_final_sent && !core.awaiting_ack && peer_final_seen;
            drop(core);
            if confirmed {
                break;
            }

            let frame = self.read_finalization_frame().await?;
            let Some(frame) = frame else {
                return Err(AuditError::FailedClosed);
            };
            match AuditMessage::decode_frame(&frame)? {
                AuditMessage::Checkpoint(checkpoint) => {
                    let exact = {
                        let core = self.core.lock().await;
                        checkpoint.snapshot() == core.session.shared_snapshot()
                    };
                    let phase = if exact {
                        CheckpointPhase::Closing
                    } else {
                        CheckpointPhase::Running
                    };
                    let event = self.handle_checkpoint(checkpoint, phase).await?;
                    if !matches!(event, FrameEvent::None) {
                        return Err(AuditError::InvalidState(
                            "unexpected audit frame during finalization",
                        ));
                    }
                    peer_final_seen |= exact;
                }
                AuditMessage::CheckpointAck(_) => {
                    let event = self.handle_frame(&frame).await?;
                    if !matches!(event, FrameEvent::None) {
                        return Err(AuditError::InvalidState(
                            "unexpected audit frame during finalization",
                        ));
                    }
                }
                AuditMessage::CloseNotice(peer_reason) => {
                    if peer_reason != reason {
                        return Err(AuditError::InvalidState(
                            "the peer close reason changed during finalization",
                        ));
                    }
                }
                AuditMessage::JointManifest(_) | AuditMessage::ManifestSignature(_) => {
                    return Err(AuditError::InvalidState(
                        "the peer manifest arrived before the final checkpoint",
                    ));
                }
                _ => {
                    return Err(AuditError::InvalidState(
                        "unexpected audit frame during finalization",
                    ));
                }
            }
        }
        // 3. The joint manifest and the dual session signatures (design
        //    sections 21.1 and 21.2).
        let (manifest, own_signature) =
            self.build_and_send_manifest(ending, ended_normally).await?;
        let peer_signature = self.read_peer_manifest_pair(&manifest).await?;
        // 4. The acyclic footer and the serialized ledger commit (design
        //    sections 21.3, 21.4 and 12.3).
        let pending = {
            let mut core = self.core.lock().await;
            let AuditCore {
                session,
                writer,
                awaiting_ack: _,
            } = &mut *core;
            session
                .write_footer_prefix(writer, &manifest, own_signature, peer_signature)
                .await?
        };
        let commit = begin_ledger_commit(Arc::clone(&self.core), pending).await?;
        {
            let core = self.core.lock().await;
            core.writer.write_ledger_commit(&commit).await?;
        }
        finish_ledger_commit(Arc::clone(&self.core), commit).await?;
        Ok(())
    }

    /// Design section 22.4: the connection-lost close. The local tail is
    /// completed best-effort and the shared close event records the reason;
    /// no wire exchange is possible and no manifest is fabricated. The
    /// records are best-effort because the writer may already have failed.
    pub async fn close_interrupted(&self, reason: AuditCloseReason) {
        let mut core = self.core.lock().await;
        if core.session.has_failed() {
            return;
        }
        if let Ok(batch) =
            core.session
                .record_shared_close_reason(DIRECTION_CTRL_TO_HOST, reason, self.now_ns())
        {
            let _ = core.writer.append_batch(batch).await;
        }
        if let Ok(batch) = core.session.close_directions() {
            let _ = core.writer.append_batch(batch).await;
        }
    }

    /// Design section 18.7: one audit failure closes the session. The
    /// failure-close records are appended best-effort (the file keeps a
    /// verifiable interrupted prefix) and the failure notice is conveyed
    /// best-effort. `code` is the peer's structured code when one was
    /// received; the local category of a record failure is used otherwise.
    pub async fn fail_closed(&self, code: Option<AuditErrorCode>, reason: AuditCloseReason) {
        let code = code.unwrap_or(AuditErrorCode::AuditRecordWriteFailed);
        let mut core = self.core.lock().await;
        let deadline = tokio::time::Instant::now() + WRITER_OPERATION_TIMEOUT;
        if !core.session.has_failed()
            && let Ok(batch) = core
                .session
                .fail_closed_records(code, reason, self.now_ns())
        {
            let _ = tokio::time::timeout_at(deadline, core.writer.append_batch(batch)).await;
        }
        drop(core);
        self.send_failure_notice_until(code, reason, deadline).await;
    }

    /// Failure notification is best-effort and shares the writer's absolute
    /// fail-closed deadline. A peer that stopped reading the audit substream
    /// must not hold terminal recovery behind two ordinary wire timeouts.
    async fn send_failure_notice_until(
        &self,
        code: AuditErrorCode,
        reason: AuditCloseReason,
        deadline: tokio::time::Instant,
    ) {
        let notify = async {
            let _ = self.send_frame(&AuditMessage::AuditError(code)).await;
            let _ = self.send_frame(&AuditMessage::CloseNotice(reason)).await;
        };
        let _ = tokio::time::timeout_at(deadline, notify).await;
    }

    // -----------------------------------------------------------------
    // Finalization internals
    // -----------------------------------------------------------------

    async fn close_directions(&self) -> Result<(), AuditError> {
        let mut core = self.core.lock().await;
        let batch = core.session.close_directions()?;
        core.writer.append_batch(batch).await
    }

    async fn record_shared_close(&self, reason: AuditCloseReason) -> Result<(), AuditError> {
        self.record(|session, now| {
            session.record_shared_close_reason(DIRECTION_CTRL_TO_HOST, reason, now)
        })
        .await
    }

    /// Reads through running checkpoint traffic until the peer's close
    /// notice arrives. The audit substream is ordered, but the terminal and
    /// file substreams are independent, so their pumps may enter the close
    /// path while an earlier checkpoint exchange is still in flight.
    async fn receive_close_reason(&self) -> Result<AuditCloseReason, AuditError> {
        loop {
            let frame = self.read_finalization_frame().await?;
            let Some(frame) = frame else {
                return Err(AuditError::FailedClosed);
            };
            match AuditMessage::decode_frame(&frame)? {
                AuditMessage::Checkpoint(checkpoint) => {
                    self.handle_checkpoint(checkpoint, CheckpointPhase::Running)
                        .await?;
                }
                AuditMessage::CheckpointAck(_) => {
                    self.handle_frame(&frame).await?;
                }
                AuditMessage::CloseNotice(reason) => return Ok(reason),
                AuditMessage::AuditError(_) => return Err(AuditError::FailedClosed),
                _ => {
                    return Err(AuditError::InvalidState(
                        "unexpected audit frame before the close notice",
                    ));
                }
            }
        }
    }

    /// The local manifest with its session signature (design section 21.2),
    /// the evidence records appended and the two frames sent.
    async fn build_and_send_manifest(
        &self,
        ending: ManifestEnding,
        ended_normally: bool,
    ) -> Result<(JointManifest, ManifestSignature), AuditError> {
        let mut core = self.core.lock().await;
        let (manifest, signature, evidence) =
            core.session
                .build_manifest(ending, ended_normally, self.now_ns())?;
        core.writer.append_batch(evidence).await?;
        drop(core);
        self.send_frame(&AuditMessage::JointManifest(manifest.clone()))
            .await?;
        self.send_frame(&AuditMessage::ManifestSignature(signature))
            .await?;
        Ok((manifest, signature))
    }

    /// Reads the peer's manifest and signature pair, verifies them against
    /// the local manifest (design section 21.2) and returns the peer's
    /// signature for the footer.
    ///
    /// The reads are tolerant of the frames the asymmetric close leaves
    /// between the phases: the peer's final checkpoint (acked here), its
    /// late checkpoint ack and its redundant close notice are consumed
    /// without failing the finalization.
    async fn read_peer_manifest_pair(
        &self,
        own: &JointManifest,
    ) -> Result<ManifestSignature, AuditError> {
        let manifest_frame = self
            .read_until_kind(&[FinalizationKind::JointManifest])
            .await?;
        let Some(manifest_frame) = manifest_frame else {
            return Err(AuditError::FailedClosed);
        };
        let peer = match AuditMessage::decode_frame(&manifest_frame)? {
            AuditMessage::JointManifest(peer) => peer,
            _ => unreachable!("read_until_kind only stops on the manifest"),
        };
        let signature_frame = self
            .read_until_kind(&[FinalizationKind::ManifestSignature])
            .await?;
        let Some(signature_frame) = signature_frame else {
            return Err(AuditError::FailedClosed);
        };
        let signature = match AuditMessage::decode_frame(&signature_frame)? {
            AuditMessage::ManifestSignature(signature) => signature,
            _ => unreachable!("read_until_kind only stops on the signature"),
        };
        let mut core = self.core.lock().await;
        let evidence =
            core.session
                .receive_peer_manifest_pair(own, &peer, &signature, self.now_ns())?;
        core.writer.append_batch(evidence).await?;
        drop(core);
        Ok(signature)
    }

    /// One finalization frame read bounded by the frozen exchange timeout,
    /// with the fixed exchange timeout.
    async fn read_finalization_frame(&self) -> Result<Option<Vec<u8>>, AuditError> {
        self.read_frame_timeout().await
    }

    /// Consumes frames until one of the wanted kinds arrives, handling the
    /// interleaved checkpoint, checkpoint ack and close notice frames of
    /// the asymmetric close. Returns the wanted frame; `None` means a clean
    /// EOF at a message boundary.
    async fn read_until_kind(
        &self,
        wanted: &[FinalizationKind],
    ) -> Result<Option<Vec<u8>>, AuditError> {
        loop {
            let frame = self.read_finalization_frame().await?;
            let Some(frame) = frame else {
                return Ok(None);
            };
            let kind = FinalizationKind::classify(AuditMessage::decode_frame(&frame)?);
            if wanted.contains(&kind) {
                return Ok(Some(frame));
            }
            match kind {
                FinalizationKind::Checkpoint | FinalizationKind::CheckpointAck => {
                    let event = self.handle_frame(&frame).await?;
                    if !matches!(event, FrameEvent::None) {
                        return Err(AuditError::InvalidState(
                            "unexpected audit frame during finalization",
                        ));
                    }
                }
                FinalizationKind::CloseNotice
                | FinalizationKind::JointManifest
                | FinalizationKind::ManifestSignature => {
                    // The close notice is redundant here (the close reason
                    // was already handled by the Sender, AlreadyReceived or
                    // Receiver step); the manifest and its signature are the
                    // wanted frames the caller matches below.
                }
                FinalizationKind::Other => {
                    return Err(AuditError::InvalidState(
                        "unexpected audit frame during finalization",
                    ));
                }
            }
        }
    }

    /// One frame read bounded by the frozen exchange timeout.
    async fn read_frame_timeout(&self) -> Result<Option<Vec<u8>>, AuditError> {
        tokio::time::timeout(AUDIT_EXCHANGE_TIMEOUT, self.wait_for_frame())
            .await
            .map_err(|_| AuditError::FailedClosed)?
    }

    /// Encodes and writes one framed message, flushing the substream.
    async fn send_frame(&self, message: &AuditMessage) -> Result<(), AuditError> {
        let frame = message.encode()?;
        write_frame_with_timeout(&self.write, frame.as_slice(), AUDIT_EXCHANGE_TIMEOUT).await
    }
}

/// Writes and flushes one complete frame under one absolute budget. The lock
/// wait is part of that budget so a stalled earlier writer cannot make a later
/// finalization exchange wait without bound.
async fn write_frame_with_timeout(
    write: &Mutex<Box<dyn AsyncWrite + Send + Unpin>>,
    frame: &[u8],
    timeout: Duration,
) -> Result<(), AuditError> {
    tokio::time::timeout(timeout, async {
        let mut write = write.lock().await;
        write
            .write_all(frame)
            .await
            .map_err(AuditError::Substream)?;
        write.flush().await.map_err(AuditError::Substream)
    })
    .await
    .map_err(|_| AuditError::Substream(io::Error::from(io::ErrorKind::TimedOut)))?
}

/// Reads one complete audit frame from a plain stream. `None` means a
/// clean EOF at a message boundary; an EOF inside a frame is a protocol
/// violation.
async fn read_one_frame(
    stream: &mut (impl AsyncRead + Unpin + ?Sized),
) -> Result<Option<Vec<u8>>, AuditError> {
    let mut header = [0_u8; FRAME_HEADER_LEN];
    let mut filled = 0;
    while filled < FRAME_HEADER_LEN {
        let read = stream
            .read(&mut header[filled..])
            .await
            .map_err(AuditError::Substream)?;
        if read == 0 {
            if filled == 0 {
                return Ok(None);
            }
            return Err(AuditError::Protocol(
                yonder_core::error::ProtocolError::InvalidLength {
                    expected: FRAME_HEADER_LEN,
                    actual: filled,
                },
            ));
        }
        filled += read;
    }
    let (tag, payload_len) = decode_frame_header(&header)?;
    let payload_len = usize::try_from(payload_len).map_err(|_| {
        AuditError::Protocol(yonder_core::error::ProtocolError::InvalidLength {
            expected: 0,
            actual: usize::MAX,
        })
    })?;
    validate_payload_len(tag, payload_len)?;
    let mut frame = vec![0_u8; FRAME_HEADER_LEN + payload_len];
    frame[..FRAME_HEADER_LEN].copy_from_slice(&header);
    stream
        .read_exact(&mut frame[FRAME_HEADER_LEN..])
        .await
        .map_err(AuditError::Substream)?;
    Ok(Some(frame))
}

/// Writes one framed message to a plain stream.
async fn write_frame_to(
    stream: &mut (impl AsyncWrite + Unpin),
    message: &AuditMessage,
) -> Result<(), AuditError> {
    let frame = message.encode()?;
    stream
        .write_all(frame.as_slice())
        .await
        .map_err(AuditError::Substream)?;
    stream.flush().await.map_err(AuditError::Substream)?;
    Ok(())
}

/// Reads one frame and extracts exactly the expected message kind.
async fn expect_frame<T>(
    stream: &mut (impl AsyncRead + Unpin),
    extract: impl FnOnce(AuditMessage) -> Option<T>,
) -> Result<T, AuditError> {
    let frame = read_one_frame(stream)
        .await?
        .ok_or(AuditError::FailedClosed)?;
    let message = AuditMessage::decode_frame(&frame)?;
    extract(message).ok_or(AuditError::HandshakeInvalid)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::audit::session::{
        CONNECTION_STATE_LOST, FILE_DIRECTION_DOWNLOAD, FILE_DIRECTION_UPLOAD, FILE_KIND_SUCCESS,
        KEY_ACTION_DETACH, LIFECYCLE_KIND_ACTIVE_DETACH, MAX_INPUT_SEGMENT,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tempfile::tempdir;
    use tokio::io::duplex;
    use yonder_core::OsSecureRandom;
    use yonder_core::wire::audit::{
        AUDIT_FORMAT_VERSION, AUDIT_PROTOCOL, AuditCloseReason, ManifestEnding,
    };
    use yonder_core::wire::audit_container::ContainerReader;
    use yonder_net::Keypair;

    fn test_peers() -> (PeerId, PeerId) {
        let controller = Keypair::generate_ed25519().public().to_peer_id();
        let host = Keypair::generate_ed25519().public().to_peer_id();
        (controller, host)
    }

    fn test_root() -> PathBuf {
        tempdir().unwrap().path().join("audit")
    }

    #[test]
    fn audit_root_errors_keep_their_fixed_operator_diagnostics() {
        let invalid = map_audit_root_error(AuditIdentityError::InvalidAuditDirectoryEnv);
        let unavailable = map_audit_root_error(AuditIdentityError::AuditDirectoryUnavailable);

        match invalid {
            AuditError::DirectoryUnavailable(error) => assert_eq!(
                error.to_string(),
                "the audit directory environment variable must be a non-empty absolute path"
            ),
            other => panic!("unexpected mapped error: {other}"),
        }
        match unavailable {
            AuditError::DirectoryUnavailable(error) => {
                assert_eq!(error.to_string(), "the audit directory is unavailable");
            }
            other => panic!("unexpected mapped error: {other}"),
        }
    }

    #[test]
    fn platform_audit_root_is_absolute_when_the_platform_environment_is_available() {
        let root = platform_audit_root().unwrap();
        assert!(root.is_absolute());
    }

    /// Establishes two observers (controller and host) over one duplex
    /// stream pair. Both sides exchange their hellos concurrently; a
    /// sequential await would deadlock on the first read. The futures are
    /// boxed so their combined inline state stays off the test thread's
    /// stack (the project's known large-future pattern).
    async fn establish_pair(
        controller_root: &Path,
        host_root: &Path,
    ) -> (Arc<AuditObserver>, Arc<AuditObserver>) {
        let (controller, host) = test_peers();
        let (host_half, controller_half) = duplex(256 * 1024);
        let digest = Digest32::new([0xAB; 32]);
        let mut controller_random = OsSecureRandom;
        let mut host_random = OsSecureRandom;
        let (controller_result, host_result) = tokio::join!(
            Box::pin(AuditObserver::establish(
                controller_half,
                AuditRole::Controller,
                controller,
                host,
                utc_start_seconds(),
                digest,
                controller_root,
                &mut controller_random,
            )),
            Box::pin(AuditObserver::establish(
                host_half,
                AuditRole::Host,
                controller,
                host,
                utc_start_seconds(),
                digest,
                host_root,
                &mut host_random,
            )),
        );
        (
            Arc::new(controller_result.unwrap()),
            Arc::new(host_result.unwrap()),
        )
    }

    #[derive(Clone, Copy)]
    enum UnexpectedHandshakeStage {
        Hello,
        Contribution,
        Ready,
    }

    async fn establish_with_unexpected_handshake_message(
        stage: UnexpectedHandshakeStage,
    ) -> Result<AuditObserver, AuditError> {
        let controller_root = test_root();
        let host_root = test_root();
        let (controller, host) = test_peers();
        let binding = connection_binding_digest(controller, host);
        let ledger = ledger::Ledger::open(&host_root, &mut OsSecureRandom).unwrap();
        let identity = ledger.identity().clone();
        let mut peer_session = AuditSession::new(
            AuditRole::Host,
            Box::new(IdentityAdapter(identity)),
            Box::new(LedgerAdapter::new(ledger)),
            binding,
            utc_start_seconds(),
            &mut OsSecureRandom,
        )
        .unwrap();
        let (mut peer, local) = duplex(256 * 1024);
        let digest = Digest32::new([0xAB; 32]);
        let mut random = OsSecureRandom;
        let establish = Box::pin(AuditObserver::establish(
            local,
            AuditRole::Controller,
            controller,
            host,
            utc_start_seconds(),
            digest,
            &controller_root,
            &mut random,
        ));
        let scripted_peer = async move {
            let frame = read_one_frame(&mut peer).await.unwrap().unwrap();
            let controller_hello = match AuditMessage::decode_frame(&frame).unwrap() {
                AuditMessage::AuditHello(hello) => hello,
                _ => panic!("the controller must start with AuditHello"),
            };
            if matches!(stage, UnexpectedHandshakeStage::Hello) {
                write_frame_to(
                    &mut peer,
                    &AuditMessage::CloseNotice(AuditCloseReason::AuditFailure),
                )
                .await
                .unwrap();
                return;
            }
            write_frame_to(
                &mut peer,
                &AuditMessage::AuditHello(*peer_session.local_hello()),
            )
            .await
            .unwrap();

            let frame = read_one_frame(&mut peer).await.unwrap().unwrap();
            let controller_contribution = match AuditMessage::decode_frame(&frame).unwrap() {
                AuditMessage::SecretContribution(contribution) => {
                    contribution.contribution().clone()
                }
                _ => panic!("the controller must send its secret contribution"),
            };
            if matches!(stage, UnexpectedHandshakeStage::Contribution) {
                write_frame_to(
                    &mut peer,
                    &AuditMessage::CloseNotice(AuditCloseReason::AuditFailure),
                )
                .await
                .unwrap();
                return;
            }
            write_frame_to(
                &mut peer,
                &AuditMessage::SecretContribution(SecretContributionMessage::new(
                    peer_session.local_contribution().clone(),
                )),
            )
            .await
            .unwrap();
            peer_session
                .receive_peer_hello(&controller_hello, &controller_contribution)
                .unwrap();
            peer_session
                .compute_ready(ConnectionSecret::NotExportable)
                .unwrap();

            let frame = read_one_frame(&mut peer).await.unwrap().unwrap();
            assert!(matches!(
                AuditMessage::decode_frame(&frame).unwrap(),
                AuditMessage::AuditReady(_)
            ));
            assert!(matches!(stage, UnexpectedHandshakeStage::Ready));
            write_frame_to(
                &mut peer,
                &AuditMessage::CloseNotice(AuditCloseReason::AuditFailure),
            )
            .await
            .unwrap();
        };
        let (result, ()) = tokio::join!(establish, scripted_peer);
        result
    }

    #[test]
    fn observer_handshake_rejects_wrong_message_at_every_stage() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        for stage in [
                            UnexpectedHandshakeStage::Hello,
                            UnexpectedHandshakeStage::Contribution,
                            UnexpectedHandshakeStage::Ready,
                        ] {
                            assert!(matches!(
                                establish_with_unexpected_handshake_message(stage).await,
                                Err(AuditError::HandshakeInvalid)
                            ));
                        }
                    });
            })
            .unwrap()
            .join()
            .unwrap();
    }

    /// Records the terminal lifecycle on both sides.
    async fn record_lifecycle(controller: &AuditObserver, host: &AuditObserver, digest: Digest32) {
        controller.record_terminal_hello(digest).await.unwrap();
        host.record_terminal_hello(digest).await.unwrap();
        host.record_terminal_ready().await.unwrap();
        controller.record_terminal_ready().await.unwrap();
    }

    /// Runs the running-phase checkpoint exchange between the two sides.
    /// Both sides record 1 MiB of shared input so the size trigger fires
    /// (design section 20.1).
    async fn checkpoint_exchange(controller: &AuditObserver, host: &AuditObserver) {
        let chunk = vec![0x5A; 16 * 1024];
        for _ in 0..64 {
            controller.record_input(&chunk).await.unwrap();
            host.record_input(&chunk).await.unwrap();
        }
        assert!(controller.checkpoint_due().await);
        assert!(host.checkpoint_due().await);
        controller.send_due_checkpoint().await.unwrap();
        host.send_due_checkpoint().await.unwrap();
        // Each side handles the peer's checkpoint (replying with an ack)
        // and the peer's ack. The frames cross in a fixed order because
        // both sides sent before reading.
        let host_checkpoint = host.wait_for_frame().await.unwrap().unwrap();
        let event = host.handle_frame(&host_checkpoint).await.unwrap();
        assert_eq!(event, FrameEvent::None);
        let controller_checkpoint = controller.wait_for_frame().await.unwrap().unwrap();
        let event = controller
            .handle_frame(&controller_checkpoint)
            .await
            .unwrap();
        assert_eq!(event, FrameEvent::None);
        let controller_ack = controller.wait_for_frame().await.unwrap().unwrap();
        let event = controller.handle_frame(&controller_ack).await.unwrap();
        assert_eq!(event, FrameEvent::None);
        let host_ack = host.wait_for_frame().await.unwrap().unwrap();
        let event = host.handle_frame(&host_ack).await.unwrap();
        assert_eq!(event, FrameEvent::None);
    }

    /// Walks one container, returning the decoded shared control and file
    /// transfer events per stream.
    fn walk_shared(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut reader = ContainerReader::new(bytes).unwrap();
        let mut control = Vec::new();
        let mut file = Vec::new();
        while let Some(frame) = reader.next_frame().unwrap() {
            match frame.record_type {
                yonder_core::wire::audit_container::RecordType::SharedControlEvent => {
                    control.extend_from_slice(frame.payload)
                }
                yonder_core::wire::audit_container::RecordType::SharedFileTransferEvent => {
                    file.extend_from_slice(frame.payload)
                }
                _ => {}
            }
        }
        (control, file)
    }

    #[test]
    fn connection_binding_digest_is_deterministic_and_role_ordered() {
        let (controller, host) = test_peers();
        let digest = connection_binding_digest(controller, host);
        assert_eq!(digest, connection_binding_digest(controller, host));
        assert_ne!(
            digest,
            connection_binding_digest(host, controller),
            "the role order is part of the binding"
        );
    }

    #[test]
    fn file_transfer_id_is_deterministic_from_protocol_facts() {
        let first = file_transfer_id(
            FILE_DIRECTION_UPLOAD,
            "/home/alice/notes.txt",
            "notes.txt",
            100,
        );
        assert_eq!(
            first,
            file_transfer_id(
                FILE_DIRECTION_UPLOAD,
                "/home/alice/notes.txt",
                "notes.txt",
                100
            )
        );
        assert_ne!(
            first,
            file_transfer_id(
                FILE_DIRECTION_UPLOAD,
                "/home/alice/notes.txt",
                "notes.txt",
                101
            ),
            "the declared size is part of the identity"
        );
        assert_ne!(
            first,
            file_transfer_id(
                FILE_DIRECTION_DOWNLOAD,
                "/home/alice/notes.txt",
                "notes.txt",
                100
            ),
            "the direction is part of the identity"
        );
    }

    // The combined session futures stay inline in `close_and_finalize` and
    // the observer is driven through an in-memory duplex; the whole test
    // runs on a 64 MiB stack thread like the other in-process harnesses.
    #[test]
    fn bilateral_observer_session_finalizes_matching_files() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let controller_root = test_root();
                    let host_root = test_root();
                    let (controller, host) = establish_pair(&controller_root, &host_root).await;
                    let digest = Digest32::new([0xAB; 32]);
                    record_lifecycle(&controller, &host, digest).await;

                    // Input: the controller sends, the host receives (same bytes).
                    let input = b"echo hello\n";
                    controller.record_input(input).await.unwrap();
                    host.record_input(input).await.unwrap();
                    // Output: the host sends, the controller receives and displays.
                    let output = b"hello\r\n";
                    host.record_raw_output(output).await.unwrap();
                    controller.record_raw_output(output).await.unwrap();
                    controller.record_display_bytes(output).await.unwrap();
                    // Resize on both sides (design section 18.5).
                    controller
                        .record_resize(DIRECTION_CTRL_TO_HOST, 120, 40)
                        .await
                        .unwrap();
                    host.record_resize(DIRECTION_CTRL_TO_HOST, 120, 40)
                        .await
                        .unwrap();
                    // A running-phase checkpoint exchange.
                    checkpoint_exchange(&controller, &host).await;

                    // The terminal lifecycle ends on both sides.
                    host.record_terminal_exit(0).await.unwrap();
                    controller.record_terminal_exit(0).await.unwrap();
                    controller.record_terminal_complete().await.unwrap();
                    host.record_terminal_complete().await.unwrap();

                    // The normal close: the controller sends the notice, the host
                    // receives it; both finalize. The futures are boxed so their
                    // combined inline state stays off the test thread's stack.
                    let controller_close = controller.clone();
                    let host_close = host.clone();
                    let (controller_result, host_result) = tokio::join!(
                        Box::pin(controller_close.close_and_finalize(
                            ManifestEnding::ShellExit(0),
                            true,
                            CloseNoticeHandling::Sender(AuditCloseReason::NormalShellExit),
                        )),
                        Box::pin(host_close.close_and_finalize(
                            ManifestEnding::ShellExit(0),
                            true,
                            CloseNoticeHandling::Receiver,
                        )),
                    );
                    controller_result.unwrap();
                    host_result.unwrap();

                    // Both files parse with a footer and their shared chains agree.
                    let controller_path =
                        controller_root.join(crate::audit::identity::RECORDS_DIR_NAME);
                    let host_path = host_root.join(crate::audit::identity::RECORDS_DIR_NAME);
                    let controller_files = std::fs::read_dir(&controller_path).unwrap().count();
                    let host_files = std::fs::read_dir(&host_path).unwrap().count();
                    assert_eq!(controller_files, 1, "one controller record file");
                    assert_eq!(host_files, 1, "one host record file");
                    let controller_file = std::fs::read_dir(&controller_path)
                        .unwrap()
                        .next()
                        .unwrap()
                        .unwrap()
                        .path();
                    let host_file = std::fs::read_dir(&host_path)
                        .unwrap()
                        .next()
                        .unwrap()
                        .unwrap()
                        .path();
                    let controller_bytes = std::fs::read(&controller_file).unwrap();
                    let host_bytes = std::fs::read(&host_file).unwrap();
                    let (controller_control, controller_file_events) =
                        walk_shared(&controller_bytes);
                    let (host_control, host_file_events) = walk_shared(&host_bytes);
                    assert_eq!(
                        controller_control, host_control,
                        "both sides record identical shared control chains"
                    );
                    assert_eq!(
                        controller_file_events, host_file_events,
                        "both sides record identical shared file transfer chains"
                    );
                    let mut controller_reader = ContainerReader::new(&controller_bytes).unwrap();
                    let mut host_reader = ContainerReader::new(&host_bytes).unwrap();
                    while let Some(_frame) = controller_reader.next_frame().unwrap() {}
                    while let Some(_frame) = host_reader.next_frame().unwrap() {}
                    let controller_footer = controller_reader
                        .footer()
                        .expect("the controller file has a footer");
                    let host_footer = host_reader.footer().expect("the host file has a footer");
                    // The manifest ending and the session ID agree.
                    assert_eq!(
                        controller_footer.footer.manifest.ending(),
                        ManifestEnding::ShellExit(0)
                    );
                    assert_eq!(
                        host_footer.footer.manifest.ending(),
                        ManifestEnding::ShellExit(0)
                    );
                    assert_eq!(
                        controller.session_id().await,
                        host.session_id().await,
                        "both sides derived the same session ID"
                    );
                    assert!(!controller.has_failed().await);
                    assert!(!host.has_failed().await);
                })
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn file_transfer_events_are_recorded_by_both_sides() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let controller_root = test_root();
                    let host_root = test_root();
                    let (controller, host) = establish_pair(&controller_root, &host_root).await;
                    let digest = Digest32::new([0xAB; 32]);
                    record_lifecycle(&controller, &host, digest).await;

                    // The same transfer facts on both sides (design section 18.6).
                    let transfer_id = file_transfer_id(
                        FILE_DIRECTION_UPLOAD,
                        "/remote/notes.txt",
                        "notes.txt",
                        512,
                    );
                    let facts = FileTransferFacts {
                        transfer_id,
                        direction: FILE_DIRECTION_UPLOAD,
                        kind: FILE_KIND_SUCCESS,
                        declared_size: 512,
                        final_size: 512,
                        digest: Digest32::new([7; 32]),
                        remote_path: "/remote/notes.txt",
                        file_name: "notes.txt",
                        error_code: 0,
                    };
                    controller.record_file_transfer(&facts, None).await.unwrap();
                    host.record_file_transfer(&facts, None).await.unwrap();

                    host.record_terminal_exit(0).await.unwrap();
                    controller.record_terminal_exit(0).await.unwrap();
                    controller.record_terminal_complete().await.unwrap();
                    host.record_terminal_complete().await.unwrap();

                    let controller_close = controller.clone();
                    let host_close = host.clone();
                    let (controller_result, host_result) = tokio::join!(
                        Box::pin(controller_close.close_and_finalize(
                            ManifestEnding::ShellExit(0),
                            true,
                            CloseNoticeHandling::Sender(AuditCloseReason::NormalShellExit),
                        )),
                        Box::pin(host_close.close_and_finalize(
                            ManifestEnding::ShellExit(0),
                            true,
                            CloseNoticeHandling::Receiver,
                        )),
                    );
                    controller_result.unwrap();
                    host_result.unwrap();

                    let controller_file = std::fs::read_dir(
                        controller_root.join(crate::audit::identity::RECORDS_DIR_NAME),
                    )
                    .unwrap()
                    .next()
                    .unwrap()
                    .unwrap()
                    .path();
                    let host_file =
                        std::fs::read_dir(host_root.join(crate::audit::identity::RECORDS_DIR_NAME))
                            .unwrap()
                            .next()
                            .unwrap()
                            .unwrap()
                            .path();
                    let (_, controller_events) =
                        walk_shared(&std::fs::read(&controller_file).unwrap());
                    let (_, host_events) = walk_shared(&std::fs::read(&host_file).unwrap());
                    assert!(!controller_events.is_empty(), "the file event was recorded");
                    assert_eq!(controller_events, host_events);
                })
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn bilateral_finalization_settles_an_inflight_running_checkpoint() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        let controller_root = test_root();
                        let host_root = test_root();
                        let (controller, host) = establish_pair(&controller_root, &host_root).await;
                        record_lifecycle(&controller, &host, Digest32::new([0xAB; 32])).await;

                        let chunk = vec![0xC3; 16 * 1024];
                        for _ in 0..64 {
                            controller.record_input(&chunk).await.unwrap();
                            host.record_input(&chunk).await.unwrap();
                        }
                        controller.send_due_checkpoint().await.unwrap();

                        host.record_terminal_exit(0).await.unwrap();
                        controller.record_terminal_exit(0).await.unwrap();
                        controller.record_terminal_complete().await.unwrap();
                        host.record_terminal_complete().await.unwrap();

                        let controller_close = controller.clone();
                        let host_close = host.clone();
                        let (controller_result, host_result) = tokio::join!(
                            Box::pin(controller_close.close_and_finalize(
                                ManifestEnding::ShellExit(0),
                                true,
                                CloseNoticeHandling::Sender(AuditCloseReason::NormalShellExit,),
                            )),
                            Box::pin(host_close.close_and_finalize(
                                ManifestEnding::ShellExit(0),
                                true,
                                CloseNoticeHandling::Receiver,
                            )),
                        );
                        controller_result.unwrap();
                        host_result.unwrap();

                        let controller_record = std::fs::read_dir(
                            controller_root.join(crate::audit::identity::RECORDS_DIR_NAME),
                        )
                        .unwrap()
                        .next()
                        .unwrap()
                        .unwrap()
                        .path();
                        let host_record = std::fs::read_dir(
                            host_root.join(crate::audit::identity::RECORDS_DIR_NAME),
                        )
                        .unwrap()
                        .next()
                        .unwrap()
                        .unwrap()
                        .path();
                        let controller_bytes = std::fs::read(controller_record).unwrap();
                        let host_bytes = std::fs::read(host_record).unwrap();
                        let mut controller_reader =
                            ContainerReader::new(&controller_bytes).unwrap();
                        let mut host_reader = ContainerReader::new(&host_bytes).unwrap();
                        while controller_reader.next_frame().unwrap().is_some() {}
                        while host_reader.next_frame().unwrap().is_some() {}
                        assert!(controller_reader.footer().is_ok());
                        assert!(host_reader.footer().is_ok());
                    });
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn final_checkpoint_mismatch_fails_closed_and_preserves_the_prefix() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let controller_root = test_root();
                    let host_root = test_root();
                    let (controller, host) = establish_pair(&controller_root, &host_root).await;
                    let digest = Digest32::new([0xAB; 32]);
                    record_lifecycle(&controller, &host, digest).await;

                    // The controller commits 1 MiB of input (the checkpoint size
                    // trigger) while the host only recorded one block: the host's
                    // snapshot cannot match.
                    let chunk = vec![0x33; 16 * 1024];
                    for _ in 0..64 {
                        controller.record_input(&chunk).await.unwrap();
                    }
                    host.record_input(&chunk).await.unwrap();
                    assert!(controller.checkpoint_due().await);
                    controller.send_due_checkpoint().await.unwrap();
                    // The running receipt is valid even though the host has
                    // already observed a different cross-stream position.
                    let controller_checkpoint = host.wait_for_frame().await.unwrap().unwrap();
                    let checkpoint =
                        match AuditMessage::decode_frame(&controller_checkpoint).unwrap() {
                            AuditMessage::Checkpoint(checkpoint) => checkpoint,
                            _ => panic!("expected checkpoint"),
                        };
                    assert_eq!(
                        host.handle_frame(&controller_checkpoint).await.unwrap(),
                        FrameEvent::None
                    );
                    assert!(!host.has_failed().await);

                    // The same unequal snapshot is invalid once evaluated at
                    // the closing barrier, where both shared prefixes must be
                    // exact.
                    host.close_directions().await.unwrap();
                    let error = host
                        .handle_checkpoint(checkpoint, CheckpointPhase::Closing)
                        .await
                        .unwrap_err();
                    assert!(matches!(error, AuditError::CheckpointMismatch));
                    assert!(host.has_failed().await);
                    // No further recording is possible.
                    assert!(host.record_input(b"x").await.is_err());
                    // The controller's own records stay healthy.
                    assert!(!controller.has_failed().await);

                    // The host file keeps the verifiable interrupted prefix: the
                    // lifecycle records and the input commitment parse.
                    let host_file =
                        std::fs::read_dir(host_root.join(crate::audit::identity::RECORDS_DIR_NAME))
                            .unwrap()
                            .next()
                            .unwrap()
                            .unwrap()
                            .path();
                    let bytes = std::fs::read(&host_file).unwrap();
                    let mut reader = ContainerReader::new(&bytes).unwrap();
                    let mut frames = 0;
                    while let Some(frame) = reader.next_frame().unwrap() {
                        let _ = frame;
                        frames += 1;
                    }
                    assert!(
                        frames >= 3,
                        "the interrupted prefix keeps its records: {frames}"
                    );
                    assert!(
                        reader.footer().is_err(),
                        "no footer on an interrupted prefix"
                    );
                })
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn old_peer_without_audit_fails_before_terminal_active() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    // The host side: a controller that authenticates and opens the
                    // terminal streams but never opens the audit substream times out
                    // with the fixed message. The host-side wait is exercised through
                    // the timeout mapping used by start_terminal.
                    let root = test_root();
                    let (controller, host) = test_peers();
                    let digest = Digest32::new([0xAB; 32]);
                    // A stream that is established but never receives a frame: the
                    // controller never opens the audit substream.
                    let (_write, read) = duplex(1024);
                    let error = tokio::time::timeout(
                        AUDIT_EXCHANGE_TIMEOUT,
                        AuditObserver::establish(
                            read,
                            AuditRole::Host,
                            controller,
                            host,
                            utc_start_seconds(),
                            digest,
                            &root,
                            &mut OsSecureRandom,
                        ),
                    )
                    .await;
                    // The establish is bounded by the caller; the fixed unsupported
                    // message is produced by the caller mapping, asserted in the
                    // controller/host integration tests.
                    assert!(error.is_err(), "the handshake must not hang forever");
                })
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn key_and_lifecycle_constants_are_frozen() {
        assert_eq!(KEY_ACTION_DETACH, 0x05);
        assert_eq!(LIFECYCLE_KIND_ACTIVE_DETACH, 0x05);
        assert_eq!(AUDIT_PROTOCOL, "/yonder/audit/3.0.0");
        assert_eq!(AUDIT_FORMAT_VERSION, 3);
    }

    #[test]
    fn observer_recording_and_failure_boundaries_are_complete() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async {
                    let controller_root = test_root();
                    let host_root = test_root();
                    let (controller, host) = establish_pair(&controller_root, &host_root).await;
                    let digest = Digest32::new([0xAB; 32]);
                    record_lifecycle(&controller, &host, digest).await;

                    assert!(controller.record_input(&[]).await.is_ok());
                    assert!(controller.record_raw_output(&[]).await.is_ok());
                    assert!(controller.record_display_bytes(&[]).await.is_ok());
                    assert!(controller.send_due_checkpoint().await.is_ok());

                    controller.record_input(b"input").await.unwrap();
                    controller
                        .record_send_outcome(DIRECTION_CTRL_TO_HOST, true, 5)
                        .await
                        .unwrap();
                    host.record_input(b"input").await.unwrap();
                    host.record_pty_write_outcome(true, 5).await.unwrap();

                    let segmented = vec![0x5A; MAX_LOCAL_OUTPUT_SEGMENT + 1];
                    host.record_raw_output(&segmented).await.unwrap();
                    controller.record_raw_output(&segmented).await.unwrap();
                    controller.record_display_bytes(&segmented).await.unwrap();
                    controller
                        .record_display_write_outcome(true, segmented.len() as u64)
                        .await
                        .unwrap();
                    controller
                        .record_key_action(KEY_ACTION_DETACH)
                        .await
                        .unwrap();
                    controller
                        .record_lifecycle(LIFECYCLE_KIND_ACTIVE_DETACH)
                        .await
                        .unwrap();
                    controller
                        .record_connection_state(CONNECTION_STATE_LOST)
                        .await
                        .unwrap();

                    let close = AuditMessage::CloseNotice(AuditCloseReason::ConnectionLost)
                        .encode()
                        .unwrap();
                    assert_eq!(
                        controller.handle_frame(close.as_slice()).await.unwrap(),
                        FrameEvent::Close(AuditCloseReason::ConnectionLost)
                    );
                    assert_eq!(
                        FinalizationKind::classify(
                            AuditMessage::decode_frame(close.as_slice()).unwrap()
                        ),
                        FinalizationKind::CloseNotice
                    );

                    let failure =
                        AuditMessage::AuditError(AuditErrorCode::AuditSessionBindingMismatch)
                            .encode()
                            .unwrap();
                    assert_eq!(
                        controller.handle_frame(failure.as_slice()).await.unwrap(),
                        FrameEvent::PeerAuditError(AuditErrorCode::AuditSessionBindingMismatch)
                    );
                    let hello = {
                        let core = controller.core.lock().await;
                        *core.session.local_hello()
                    };
                    let unexpected = AuditMessage::AuditHello(hello).encode().unwrap();
                    assert!(matches!(
                        controller.handle_frame(unexpected.as_slice()).await,
                        Err(AuditError::InvalidState(_))
                    ));

                    controller
                        .close_interrupted(AuditCloseReason::ConnectionLost)
                        .await;
                    controller
                        .close_interrupted(AuditCloseReason::ConnectionLost)
                        .await;
                    host.fail_closed(
                        Some(AuditErrorCode::AuditCheckpointMismatch),
                        AuditCloseReason::AuditFailure,
                    )
                    .await;
                    assert!(host.has_failed().await);
                    let error = controller.wait_for_frame().await.unwrap().unwrap();
                    assert!(matches!(
                        AuditMessage::decode_frame(&error).unwrap(),
                        AuditMessage::AuditError(AuditErrorCode::AuditCheckpointMismatch)
                    ));
                    let close = controller.wait_for_frame().await.unwrap().unwrap();
                    assert!(matches!(
                        AuditMessage::decode_frame(&close).unwrap(),
                        AuditMessage::CloseNotice(AuditCloseReason::AuditFailure)
                    ));
                    host.fail_closed(None, AuditCloseReason::AuditFailure).await;
                });
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[tokio::test]
    async fn invalid_recording_transition_fails_the_observer_closed() {
        let controller_root = test_root();
        let host_root = test_root();
        let (controller, host) = establish_pair(&controller_root, &host_root).await;

        controller.close_directions().await.unwrap();
        assert!(matches!(
            controller.record_terminal_ready().await,
            Err(AuditError::InvalidState(_))
        ));
        assert!(controller.has_failed().await);
        let frame = host.wait_for_frame().await.unwrap().unwrap();
        assert!(matches!(
            AuditMessage::decode_frame(&frame).unwrap(),
            AuditMessage::AuditError(AuditErrorCode::AuditRecordWriteFailed)
        ));
        let frame = host.wait_for_frame().await.unwrap().unwrap();
        assert!(matches!(
            AuditMessage::decode_frame(&frame).unwrap(),
            AuditMessage::CloseNotice(AuditCloseReason::AuditFailure)
        ));
    }

    #[tokio::test]
    async fn oversized_record_fails_closed_with_structured_peer_notification() {
        let controller_root = test_root();
        let host_root = test_root();
        let (controller, host) = establish_pair(&controller_root, &host_root).await;

        let oversized = vec![0xA5; MAX_INPUT_SEGMENT + 1];
        assert!(matches!(
            controller.record_input(&oversized).await,
            Err(AuditError::SegmentTooLarge)
        ));
        assert!(controller.has_failed().await);
        assert!(matches!(
            controller.record_input(b"after failure").await,
            Err(AuditError::FailedClosed)
        ));

        let error = host.wait_for_frame().await.unwrap().unwrap();
        assert!(matches!(
            AuditMessage::decode_frame(&error).unwrap(),
            AuditMessage::AuditError(AuditErrorCode::AuditRecordWriteFailed)
        ));
        let close = host.wait_for_frame().await.unwrap().unwrap();
        assert!(matches!(
            AuditMessage::decode_frame(&close).unwrap(),
            AuditMessage::CloseNotice(AuditCloseReason::AuditFailure)
        ));
    }

    #[tokio::test]
    async fn writer_failure_during_recording_fails_closed_and_notifies_the_peer() {
        let controller_root = test_root();
        let host_root = test_root();
        let (controller, host) = establish_pair(&controller_root, &host_root).await;

        // Replace only the file sink with a controlled writer, initialize it
        // successfully, then fail its next Append with RecordWriteFailed.
        let fail_writes = Arc::new(AtomicBool::new(false));
        {
            let mut core = controller.core.lock().await;
            let bytes = std::fs::read(core.writer.record_path()).unwrap();
            let header = *ContainerReader::new(&bytes).unwrap().header();
            let writer = crate::audit::writer::AuditWriter::controlled_failure_for_test(
                core.writer.session_id(),
                core.writer.role(),
                Arc::clone(&fail_writes),
            );
            writer.initialize(&header).await.unwrap();
            core.writer = writer;
        }
        fail_writes.store(true, Ordering::Relaxed);

        assert!(matches!(
            controller
                .record_connection_state(CONNECTION_STATE_LOST)
                .await,
            Err(AuditError::RecordWriteFailed(_))
        ));
        assert!(controller.has_failed().await);
        let error = host.wait_for_frame().await.unwrap().unwrap();
        assert!(matches!(
            AuditMessage::decode_frame(&error).unwrap(),
            AuditMessage::AuditError(AuditErrorCode::AuditRecordWriteFailed)
        ));
        let close = host.wait_for_frame().await.unwrap().unwrap();
        assert!(matches!(
            AuditMessage::decode_frame(&close).unwrap(),
            AuditMessage::CloseNotice(AuditCloseReason::AuditFailure)
        ));
    }

    #[tokio::test]
    async fn writer_failure_does_not_wait_for_two_blocked_notification_exchanges() {
        let controller_root = test_root();
        let host_root = test_root();
        let (controller, _host) = establish_pair(&controller_root, &host_root).await;

        let fail_writes = Arc::new(AtomicBool::new(false));
        {
            let mut core = controller.core.lock().await;
            let bytes = std::fs::read(core.writer.record_path()).unwrap();
            let header = *ContainerReader::new(&bytes).unwrap().header();
            let writer = crate::audit::writer::AuditWriter::controlled_failure_for_test(
                core.writer.session_id(),
                core.writer.role(),
                Arc::clone(&fail_writes),
            );
            writer.initialize(&header).await.unwrap();
            core.writer = writer;
        }
        let (mut blocked, _blocked_peer) = duplex(1);
        blocked.write_all(&[0]).await.unwrap();
        *controller.write.lock().await = Box::new(blocked);
        fail_writes.store(true, Ordering::Relaxed);

        let started = tokio::time::Instant::now();
        let result = tokio::time::timeout(
            WRITER_OPERATION_TIMEOUT + Duration::from_secs(1),
            controller.record_connection_state(CONNECTION_STATE_LOST),
        )
        .await
        .expect("writer failure must retain one common fail-closed deadline");
        assert!(matches!(result, Err(AuditError::RecordWriteFailed(_))));
        assert!(controller.has_failed().await);
        assert!(started.elapsed() < WRITER_OPERATION_TIMEOUT + Duration::from_secs(1));
    }

    #[tokio::test]
    async fn close_and_finalization_readers_reject_unexpected_wire_states() {
        let controller_root = test_root();
        let host_root = test_root();
        let (controller, host) = establish_pair(&controller_root, &host_root).await;
        let hello = {
            let core = host.core.lock().await;
            *core.session.local_hello()
        };
        host.send_frame(&AuditMessage::AuditHello(hello))
            .await
            .unwrap();
        assert!(matches!(
            controller.receive_close_reason().await,
            Err(AuditError::InvalidState(_))
        ));

        let controller_root = test_root();
        let host_root = test_root();
        let (controller, host) = establish_pair(&controller_root, &host_root).await;
        host.send_frame(&AuditMessage::AuditError(
            AuditErrorCode::AuditRecordWriteFailed,
        ))
        .await
        .unwrap();
        assert!(matches!(
            controller.receive_close_reason().await,
            Err(AuditError::FailedClosed)
        ));

        let controller_root = test_root();
        let host_root = test_root();
        let (controller, host) = establish_pair(&controller_root, &host_root).await;
        let hello = {
            let core = host.core.lock().await;
            *core.session.local_hello()
        };
        host.send_frame(&AuditMessage::AuditHello(hello))
            .await
            .unwrap();
        assert!(matches!(
            controller
                .read_until_kind(&[FinalizationKind::JointManifest])
                .await,
            Err(AuditError::InvalidState(_))
        ));
    }

    #[tokio::test]
    async fn unexpected_finalization_message_is_rejected_before_manifest_processing() {
        let controller_root = test_root();
        let host_root = test_root();
        let (controller, host) = establish_pair(&controller_root, &host_root).await;
        host.send_frame(&AuditMessage::AuditError(
            AuditErrorCode::AuditRecordWriteFailed,
        ))
        .await
        .unwrap();
        assert!(matches!(
            controller
                .read_until_kind(&[FinalizationKind::JointManifest])
                .await,
            Err(AuditError::InvalidState(_))
        ));
    }

    #[tokio::test]
    async fn checkpoint_confirmation_phase_rejects_eof_and_unexpected_messages() {
        let controller_root = test_root();
        let host_root = test_root();
        let (controller, host) = establish_pair(&controller_root, &host_root).await;
        host.write.lock().await.shutdown().await.unwrap();
        assert!(matches!(
            controller
                .close_and_finalize(
                    ManifestEnding::ShellExit(0),
                    true,
                    CloseNoticeHandling::Sender(AuditCloseReason::NormalShellExit),
                )
                .await,
            Err(AuditError::FailedClosed)
        ));

        let controller_root = test_root();
        let host_root = test_root();
        let (controller, host) = establish_pair(&controller_root, &host_root).await;
        host.send_frame(&AuditMessage::AuditError(
            AuditErrorCode::AuditRecordWriteFailed,
        ))
        .await
        .unwrap();
        assert!(matches!(
            controller
                .close_and_finalize(
                    ManifestEnding::ShellExit(0),
                    true,
                    CloseNoticeHandling::Sender(AuditCloseReason::NormalShellExit),
                )
                .await,
            Err(AuditError::InvalidState(_))
        ));
    }

    #[tokio::test]
    async fn finalization_reader_consumes_checkpoint_and_redundant_close_before_manifest() {
        let controller_root = test_root();
        let host_root = test_root();
        let (controller, host) = establish_pair(&controller_root, &host_root).await;
        let checkpoint = {
            let mut core = host.core.lock().await;
            let (checkpoint, evidence) = core.session.build_checkpoint(host.now_ns()).unwrap();
            core.writer.append_batch(evidence).await.unwrap();
            checkpoint
        };
        host.send_frame(&AuditMessage::Checkpoint(checkpoint))
            .await
            .unwrap();
        host.send_frame(&AuditMessage::CloseNotice(
            AuditCloseReason::NormalShellExit,
        ))
        .await
        .unwrap();
        host.close_directions().await.unwrap();
        let (manifest, _) = host
            .build_and_send_manifest(ManifestEnding::ShellExit(0), true)
            .await
            .unwrap();

        let frame = controller
            .read_until_kind(&[FinalizationKind::JointManifest])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            AuditMessage::decode_frame(&frame).unwrap(),
            AuditMessage::JointManifest(manifest)
        );
    }

    #[tokio::test]
    async fn close_receiver_settles_running_checkpoint_and_ack_before_the_notice() {
        let controller_root = test_root();
        let host_root = test_root();
        let (controller, host) = establish_pair(&controller_root, &host_root).await;

        let checkpoint = {
            let mut core = host.core.lock().await;
            let (checkpoint, evidence) = core.session.build_checkpoint(host.now_ns()).unwrap();
            core.writer.append_batch(evidence).await.unwrap();
            checkpoint
        };
        host.send_frame(&AuditMessage::Checkpoint(checkpoint))
            .await
            .unwrap();
        host.send_frame(&AuditMessage::CloseNotice(
            AuditCloseReason::NormalShellExit,
        ))
        .await
        .unwrap();
        assert_eq!(
            controller.receive_close_reason().await.unwrap(),
            AuditCloseReason::NormalShellExit
        );

        let controller_root = test_root();
        let host_root = test_root();
        let (controller, host) = establish_pair(&controller_root, &host_root).await;
        let checkpoint = {
            let mut core = controller.core.lock().await;
            let (checkpoint, evidence) =
                core.session.build_checkpoint(controller.now_ns()).unwrap();
            core.awaiting_ack = true;
            core.writer.append_batch(evidence).await.unwrap();
            checkpoint
        };
        controller
            .send_frame(&AuditMessage::Checkpoint(checkpoint))
            .await
            .unwrap();
        let frame = host.wait_for_frame().await.unwrap().unwrap();
        assert_eq!(host.handle_frame(&frame).await.unwrap(), FrameEvent::None);
        host.send_frame(&AuditMessage::CloseNotice(
            AuditCloseReason::ControllerDetach,
        ))
        .await
        .unwrap();
        assert_eq!(
            controller.receive_close_reason().await.unwrap(),
            AuditCloseReason::ControllerDetach
        );
    }

    #[tokio::test]
    async fn final_checkpoint_phase_rejects_changed_close_and_early_manifest() {
        let controller_root = test_root();
        let host_root = test_root();
        let (controller, host) = establish_pair(&controller_root, &host_root).await;
        host.send_frame(&AuditMessage::CloseNotice(AuditCloseReason::ConnectionLost))
            .await
            .unwrap();
        assert!(matches!(
            controller
                .close_and_finalize(
                    ManifestEnding::ShellExit(0),
                    true,
                    CloseNoticeHandling::Sender(AuditCloseReason::NormalShellExit),
                )
                .await,
            Err(AuditError::InvalidState(_))
        ));

        let controller_root = test_root();
        let host_root = test_root();
        let (controller, host) = establish_pair(&controller_root, &host_root).await;
        host.close_directions().await.unwrap();
        let manifest = {
            let mut core = host.core.lock().await;
            let (manifest, _, evidence) = core
                .session
                .build_manifest(ManifestEnding::ShellExit(0), true, host.now_ns())
                .unwrap();
            core.writer.append_batch(evidence).await.unwrap();
            manifest
        };
        host.send_frame(&AuditMessage::JointManifest(manifest))
            .await
            .unwrap();
        assert!(matches!(
            controller
                .close_and_finalize(
                    ManifestEnding::ShellExit(0),
                    true,
                    CloseNoticeHandling::Sender(AuditCloseReason::NormalShellExit),
                )
                .await,
            Err(AuditError::InvalidState(_))
        ));
    }

    #[tokio::test]
    async fn peer_manifest_reader_rejects_eof_at_both_pair_boundaries() {
        let controller_root = test_root();
        let host_root = test_root();
        let (controller, host) = establish_pair(&controller_root, &host_root).await;
        drop(host);
        assert!(matches!(
            controller
                .read_until_kind(&[FinalizationKind::JointManifest])
                .await,
            Ok(None)
        ));

        let controller_root = test_root();
        let host_root = test_root();
        let (controller, host) = establish_pair(&controller_root, &host_root).await;
        controller.close_directions().await.unwrap();
        let own = {
            let mut core = controller.core.lock().await;
            let (manifest, _, evidence) = core
                .session
                .build_manifest(ManifestEnding::ShellExit(0), true, controller.now_ns())
                .unwrap();
            core.writer.append_batch(evidence).await.unwrap();
            manifest
        };
        drop(host);
        assert!(matches!(
            controller.read_peer_manifest_pair(&own).await,
            Err(AuditError::FailedClosed)
        ));

        let controller_root = test_root();
        let host_root = test_root();
        let (controller, host) = establish_pair(&controller_root, &host_root).await;
        controller.close_directions().await.unwrap();
        let own = {
            let mut core = controller.core.lock().await;
            let (manifest, _, evidence) = core
                .session
                .build_manifest(ManifestEnding::ShellExit(0), true, controller.now_ns())
                .unwrap();
            core.writer.append_batch(evidence).await.unwrap();
            manifest
        };
        host.send_frame(&AuditMessage::JointManifest(own.clone()))
            .await
            .unwrap();
        drop(host);
        assert!(matches!(
            controller.read_peer_manifest_pair(&own).await,
            Err(AuditError::FailedClosed)
        ));
    }

    #[tokio::test]
    async fn wait_for_frame_survives_cancellation_at_every_frame_boundary() {
        let controller_root = test_root();
        let host_root = test_root();
        let (controller, host) = establish_pair(&controller_root, &host_root).await;
        let frame = AuditMessage::AuditError(AuditErrorCode::AuditRecordWriteFailed)
            .encode()
            .unwrap();
        assert_eq!(frame.as_slice().len(), FRAME_HEADER_LEN + 2);

        for split in 1..frame.as_slice().len() {
            {
                let mut write = host.write.lock().await;
                write.write_all(&frame.as_slice()[..split]).await.unwrap();
                write.flush().await.unwrap();
            }

            assert!(
                tokio::time::timeout(Duration::from_millis(10), controller.wait_for_frame())
                    .await
                    .is_err(),
                "frame unexpectedly completed at cancellation boundary {split}"
            );

            {
                let mut write = host.write.lock().await;
                write.write_all(&frame.as_slice()[split..]).await.unwrap();
                write.flush().await.unwrap();
            }
            assert_eq!(
                controller.wait_for_frame().await.unwrap().unwrap(),
                frame.as_slice(),
                "frame changed after cancellation boundary {split}"
            );
        }
    }

    #[tokio::test]
    async fn send_frame_times_out_when_the_peer_stops_reading() {
        let (mut blocked, _peer) = duplex(1);
        blocked.write_all(&[0]).await.unwrap();
        let write: Mutex<Box<dyn AsyncWrite + Send + Unpin>> = Mutex::new(Box::new(blocked));
        let frame = AuditMessage::AuditError(AuditErrorCode::AuditRecordWriteFailed)
            .encode()
            .unwrap();

        let error = write_frame_with_timeout(&write, frame.as_slice(), Duration::from_millis(10))
            .await
            .unwrap_err();

        match error {
            AuditError::Substream(source) => {
                assert_eq!(source.kind(), io::ErrorKind::TimedOut);
            }
            other => panic!("unexpected blocked-write error: {other}"),
        }
    }

    #[tokio::test]
    async fn audit_frame_io_rejects_every_incomplete_boundary() {
        let (writer, mut reader) = duplex(64);
        drop(writer);
        assert!(read_one_frame(&mut reader).await.unwrap().is_none());

        let (mut writer, mut reader) = duplex(64);
        writer.write_all(&[1, 2]).await.unwrap();
        writer.shutdown().await.unwrap();
        assert!(matches!(
            read_one_frame(&mut reader).await,
            Err(AuditError::Protocol(_))
        ));

        let close = AuditMessage::CloseNotice(AuditCloseReason::ConnectionLost)
            .encode()
            .unwrap();
        let (mut writer, mut reader) = duplex(64);
        writer
            .write_all(&close.as_slice()[..FRAME_HEADER_LEN])
            .await
            .unwrap();
        writer.shutdown().await.unwrap();
        assert!(matches!(
            read_one_frame(&mut reader).await,
            Err(AuditError::Substream(_))
        ));

        let (mut writer, mut reader) = duplex(64);
        write_frame_to(
            &mut writer,
            &AuditMessage::CloseNotice(AuditCloseReason::ConnectionLost),
        )
        .await
        .unwrap();
        assert!(matches!(
            expect_frame(&mut reader, |message| match message {
                AuditMessage::AuditHello(hello) => Some(hello),
                _ => None,
            })
            .await,
            Err(AuditError::HandshakeInvalid)
        ));

        let (mut writer, reader) = duplex(64);
        drop(reader);
        assert!(matches!(
            write_frame_to(
                &mut writer,
                &AuditMessage::CloseNotice(AuditCloseReason::ConnectionLost),
            )
            .await,
            Err(AuditError::Substream(_))
        ));
    }

    #[tokio::test]
    async fn incremental_frame_reader_rejects_truncated_header_and_body() {
        let (mut writer, reader) = duplex(64);
        writer.write_all(&[1, 2]).await.unwrap();
        writer.shutdown().await.unwrap();
        let mut reader = IncrementalFrameReader::new(Box::new(reader));
        assert!(matches!(
            reader.read_next().await,
            Err(AuditError::Protocol(
                yonder_core::error::ProtocolError::InvalidLength {
                    expected: FRAME_HEADER_LEN,
                    actual: 2,
                }
            ))
        ));

        let frame = AuditMessage::CloseNotice(AuditCloseReason::ConnectionLost)
            .encode()
            .unwrap();
        let (mut writer, reader) = duplex(64);
        writer
            .write_all(&frame.as_slice()[..FRAME_HEADER_LEN])
            .await
            .unwrap();
        writer.shutdown().await.unwrap();
        let mut reader = IncrementalFrameReader::new(Box::new(reader));
        assert!(matches!(
            reader.read_next().await,
            Err(AuditError::Substream(ref error))
                if error.kind() == io::ErrorKind::UnexpectedEof
        ));
    }

    #[tokio::test]
    async fn finalization_classifier_and_interrupted_close_preserve_failed_state() {
        let controller_root = test_root();
        let host_root = test_root();
        let (controller, host) = establish_pair(&controller_root, &host_root).await;
        let checkpoint = {
            let mut core = controller.core.lock().await;
            core.session
                .build_checkpoint(controller.now_ns())
                .unwrap()
                .0
        };
        let ack = {
            let mut core = host.core.lock().await;
            core.session
                .receive_checkpoint(&checkpoint, host.now_ns())
                .unwrap()
                .0
        };
        assert_eq!(
            FinalizationKind::classify(AuditMessage::CheckpointAck(ack)),
            FinalizationKind::CheckpointAck
        );

        {
            let mut core = controller.core.lock().await;
            let batch = core
                .session
                .fail_closed_records(
                    AuditErrorCode::AuditRecordWriteFailed,
                    AuditCloseReason::AuditFailure,
                    controller.now_ns(),
                )
                .unwrap();
            core.writer.append_batch(batch).await.unwrap();
        }
        controller
            .close_interrupted(AuditCloseReason::ConnectionLost)
            .await;
        assert!(controller.has_failed().await);
    }

    #[test]
    fn observer_storage_errors_map_to_the_fixed_public_categories() {
        use crate::audit::identity::AuditIdentityError;
        use crate::audit::ledger::AuditLedgerError;

        assert!(matches!(
            map_ledger_error(AuditLedgerError::AuditLedgerInvalid),
            AuditError::LedgerInvalid
        ));
        assert!(matches!(
            map_ledger_error(AuditLedgerError::AuditLedgerConflict),
            AuditError::LedgerConflict
        ));
        assert!(matches!(
            map_ledger_error(AuditLedgerError::AuditLedgerPermissions),
            AuditError::LedgerInvalid
        ));
        for (identity, expected) in [
            (
                AuditIdentityError::AuditIdentityMissing,
                AuditErrorCode::AuditIdentityMissing,
            ),
            (
                AuditIdentityError::AuditIdentityInvalid,
                AuditErrorCode::AuditIdentityInvalid,
            ),
            (
                AuditIdentityError::AuditIdentityPermissions,
                AuditErrorCode::AuditIdentityPermissions,
            ),
            (
                AuditIdentityError::AuditDirectoryUnavailable,
                AuditErrorCode::AuditDirectoryUnavailable,
            ),
        ] {
            assert_eq!(
                map_ledger_error(AuditLedgerError::Identity(identity)).code(),
                Some(expected)
            );
        }
        for error in [
            AuditLedgerError::LockFailed(io::Error::other("lock")),
            AuditLedgerError::UnlockFailed(io::Error::other("unlock")),
            AuditLedgerError::StateReadFailed(io::Error::other("state")),
            AuditLedgerError::RecordReadFailed(io::Error::other("record")),
        ] {
            assert!(matches!(
                map_ledger_error(error),
                AuditError::DirectoryUnavailable(_)
            ));
        }
        assert!(matches!(
            map_ledger_error(AuditLedgerError::AuditLedgerCommitFailed(io::Error::other(
                "commit"
            ))),
            AuditError::LedgerCommitFailed
        ));
        assert!(matches!(
            blocking_storage_error(),
            AuditError::DirectoryUnavailable(_)
        ));
    }
}
