//! The bounded asynchronous audit record writer, Yonder 0.2.0 design
//! sections 10.4 (file layout), 11 (local file protection), 19 (writing
//! model), 12.3 (acyclic finalization) and 23 (audit file format).
//!
//! The writer owns one exclusive `.yonaudit` record file
//! (`records/<session-id>.<role>.yonaudit`, design section 10.4) and runs a
//! single task that performs all container I/O through the
//! `yonder_core::wire::audit_container` primitives: the fixed header, the
//! framed record stream and the ordered footer components with the final
//! container digest (design section 23).
//!
//! # Writing model (design section 19)
//!
//! - The request queue is **bounded**; a full queue makes the caller wait
//!   (backpressure on the terminal), events are never dropped and never
//!   redirected to ordinary logs.
//! - Every append is acknowledged only after the record bytes were handed
//!   to the operating system file buffer, so the caller can produce the
//!   external effect only after the append succeeded
//!   (append-before-effect, design section 18). This is not a per-event
//!   `fsync`.
//! - The header is written and `sync_all`-ed by
//!   [`AuditWriter::initialize`] before Terminal Active (design
//!   section 19.2).
//! - [`AuditWriter::sync_all`] makes the complete current audit block
//!   durable before checkpoints (design section 19.2).
//! - Finalization writes the footer components in the fixed order of design
//!   section 23.4 and computes the three digest boundaries without copying
//!   the file: the sealed prefix digest, the sealed record digest and the
//!   final container digest. The final `sync_all` happens after the ledger
//!   commit is appended; the ledger state is then advanced atomically by
//!   the ledger, never by the writer.
//! - A writer error is returned synchronously to the caller that caused it
//!   and poisons the writer: every later request is answered with the same
//!   error and nothing is ever silently lost. The session then fails closed
//!   (design section 18.7) and the file keeps a verifiable interrupted
//!   prefix.
//!
//! # File protection (design section 11)
//!
//! On Unix the records directory is created `0700` and the record file
//! `0600`, both at creation time. Every record file is created exclusively
//! (`create_new`), so an existing name, hard link or symbolic link is never
//! followed or overwritten. The audit root directory itself is resolved by
//! the identity module; this writer receives the `records` directory from
//! the integration layer.

use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};
use yonder_core::wire::audit::{
    AuditRole, Digest32, JointManifest, LedgerCommit, LocalRecordSeal, ManifestSignature, SessionId,
};
use yonder_core::wire::audit_container::{
    AuditContainerHeader, FOOTER_MAGIC, MAX_RECORD_FRAME_LEN, RecordType, encode_frame_header,
    validate_frame_len,
};
use yonder_core::{
    PrivateDirectoryPolicy as _, SecretFileError, SecretFilePolicy as _,
    SystemPrivateDirectoryPolicy, SystemSecretFilePolicy,
};

use crate::audit::session::{AuditError, Payload, RecordBatch};

/// The bounded request queue capacity (design section 19.1: bounded,
/// backpressuring, never unbounded).
pub const WRITER_QUEUE_CAPACITY: usize = 256;

/// The record file mode (design section 11.1).
#[cfg(unix)]
const RECORD_FILE_MODE: u32 = 0o600;

/// The audit record file extension (design section 10.4).
pub const RECORD_FILE_EXTENSION: &str = "yonaudit";

/// The file I/O surface of the writer task. The production implementation
/// wraps a `std::fs::File` with direct blocking calls: every append is a
/// bounded kernel-buffered write (never a per-event `fsync`, design
/// section 19.2) and `sync_all` happens only at checkpoints and
/// finalization, so the writer task never blocks for long. Tests inject
/// blocking or failing implementations to exercise backpressure and failure
/// propagation deterministically.
trait AsyncFile {
    /// Writes the whole buffer or returns an error.
    fn write_all(
        &mut self,
        bytes: &[u8],
    ) -> impl std::future::Future<Output = io::Result<()>> + Send;
    /// Flushes all buffered data to stable storage.
    fn sync_all(&mut self) -> impl std::future::Future<Output = io::Result<()>> + Send;
}

impl AsyncFile for std::fs::File {
    async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        std::io::Write::write_all(self, bytes)
    }

    async fn sync_all(&mut self) -> io::Result<()> {
        std::fs::File::sync_all(self)
    }
}

/// One writer request; every request carries a reply channel so the caller
/// waits until the record bytes reached the OS file buffer (or an error).
enum Request {
    /// Write and sync the container header (design section 19.2).
    Initialize {
        header: Box<[u8]>,
        reply: oneshot::Sender<Result<(), AuditError>>,
    },
    /// Append one framed record.
    Append {
        record_type: RecordType,
        payload: Box<[u8]>,
        reply: oneshot::Sender<Result<(), AuditError>>,
    },
    /// Make the complete current audit block durable.
    Sync {
        reply: oneshot::Sender<Result<(), AuditError>>,
    },
    /// Write the footer magic, the joint manifest and both session
    /// signatures; replies with the sealed prefix digest (design
    /// section 23.4).
    WriteManifestAndSignatures {
        manifest: Box<[u8]>,
        controller: Box<[u8]>,
        host: Box<[u8]>,
        reply: oneshot::Sender<Result<Digest32, AuditError>>,
    },
    /// Write the `LocalRecordSeal` component; replies with the sealed
    /// record digest (design sections 21.3 and 12.3).
    WriteSeal {
        seal: Box<[u8]>,
        reply: oneshot::Sender<Result<Digest32, AuditError>>,
    },
    /// Write the `LedgerCommit` component and the final container digest,
    /// then `sync_all` the whole file (design section 12.3 steps 7-8).
    WriteLedgerCommit {
        commit: Box<[u8]>,
        reply: oneshot::Sender<Result<(), AuditError>>,
    },
}

/// The writer's container phase; the footer components are written in the
/// fixed order of design section 23.4 exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriterPhase {
    /// No header yet.
    Initializing,
    /// Header written; record frames may be appended.
    Recording,
    /// The manifest and both session signatures were written.
    Finalizing,
    /// The commit, the final digest and the final sync completed.
    Finished,
}

/// The bounded asynchronous audit record writer (design section 19).
#[derive(Debug)]
pub struct AuditWriter {
    tx: mpsc::Sender<Request>,
    path: PathBuf,
    session_id: SessionId,
    role: AuditRole,
}

impl AuditWriter {
    /// Opens (exclusively creates) the record file
    /// `records/<session-id>.<role>.yonaudit` inside the given records
    /// directory (design section 10.4), creating the directory if needed,
    /// and spawns the writer task. The header is written and synced by
    /// [`AuditWriter::initialize`].
    pub fn open(
        records_dir: &Path,
        session_id: &SessionId,
        role: AuditRole,
    ) -> Result<Self, AuditError> {
        ensure_records_dir(records_dir)?;
        let path = records_dir.join(record_file_name(session_id, role));
        let file = open_record_file(&path)?;
        Ok(Self::spawn(
            path,
            *session_id,
            role,
            file,
            WRITER_QUEUE_CAPACITY,
        ))
    }

    fn spawn(
        path: PathBuf,
        session_id: SessionId,
        role: AuditRole,
        file: impl AsyncFile + Send + 'static,
        capacity: usize,
    ) -> Self {
        let (tx, receiver) = mpsc::channel(capacity);
        // The writer performs blocking file I/O (`std::fs::File` writes and
        // syncs); it runs on the blocking pool so a slow disk can never
        // stall the current-thread terminal runtime (design section 19.1:
        // the writer is an independent task, and section 27.4: the audit
        // must not starve the terminal paths).
        tokio::task::spawn_blocking(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("the audit writer blocking runtime must build");
            runtime.block_on(writer_task(file, receiver));
        });
        Self {
            tx,
            path,
            session_id,
            role,
        }
    }

    /// The record file path.
    #[must_use]
    pub fn record_path(&self) -> &Path {
        &self.path
    }

    /// The session ID of this record.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// The local role of this record.
    #[must_use]
    pub const fn role(&self) -> AuditRole {
        self.role
    }

    /// Writes and `sync_all`s the container header (design sections 13.5
    /// and 19.2). Must complete before Terminal Active and before any
    /// append.
    pub async fn initialize(&self, header: &AuditContainerHeader) -> Result<(), AuditError> {
        let (reply, receiver) = oneshot::channel();
        let request = Request::Initialize {
            header: header.encode().as_slice().into(),
            reply,
        };
        self.send(request).await?;
        receiver.await.map_err(|_| AuditError::WriterTerminated)?
    }

    /// Appends one framed record and waits until the bytes reached the OS
    /// file buffer (append-before-effect, design sections 18 and 19.1).
    pub async fn append(&self, record_type: RecordType, payload: &[u8]) -> Result<(), AuditError> {
        let (reply, receiver) = oneshot::channel();
        let request = Request::Append {
            record_type,
            payload: payload.into(),
            reply,
        };
        self.send(request).await?;
        receiver.await.map_err(|_| AuditError::WriterTerminated)?
    }

    /// Appends one record batch in order, awaiting each buffered write
    /// (design section 16.1: local observation records first, then the
    /// completed shared blocks, before any external effect).
    pub async fn append_batch(&self, batch: RecordBatch<'_>) -> Result<(), AuditError> {
        for record in batch.iter() {
            let payload: Box<[u8]> = match &record.payload {
                Payload::Inline { bytes, len } => bytes[..*len].into(),
                Payload::Boxed(bytes) => bytes.clone(),
                Payload::Split { prefix, body } => {
                    let mut payload = Vec::with_capacity(prefix.len() + body.len());
                    payload.extend_from_slice(prefix);
                    payload.extend_from_slice(body);
                    payload.into_boxed_slice()
                }
            };
            self.append(record.record_type, &payload).await?;
        }
        Ok(())
    }

    /// Makes the complete current audit block durable before a checkpoint
    /// (design section 19.2).
    pub async fn sync_all(&self) -> Result<(), AuditError> {
        let (reply, receiver) = oneshot::channel();
        let request = Request::Sync { reply };
        self.send(request).await?;
        receiver.await.map_err(|_| AuditError::WriterTerminated)?
    }

    /// Writes the footer magic, the joint manifest and both session
    /// signatures and replies with the sealed prefix digest covering the
    /// header, all record frames, the manifest and both signatures
    /// (design sections 21.3 and 23.4). Exactly once, before the seal.
    pub async fn write_manifest_and_signatures(
        &self,
        manifest: &JointManifest,
        controller: &ManifestSignature,
        host: &ManifestSignature,
    ) -> Result<Digest32, AuditError> {
        let (reply, receiver) = oneshot::channel();
        let request = Request::WriteManifestAndSignatures {
            manifest: manifest.encode_payload()?.as_slice().into(),
            controller: controller.encode_payload().as_slice().into(),
            host: host.encode_payload().as_slice().into(),
            reply,
        };
        self.send(request).await?;
        receiver.await.map_err(|_| AuditError::WriterTerminated)?
    }

    /// Writes the `LocalRecordSeal` component and replies with the sealed
    /// record digest covering everything through the seal (design
    /// sections 21.3 and 12.3). Exactly once, after the manifest and
    /// signatures.
    pub async fn write_seal(&self, seal: &LocalRecordSeal) -> Result<Digest32, AuditError> {
        let (reply, receiver) = oneshot::channel();
        let request = Request::WriteSeal {
            seal: seal.encode_payload().as_slice().into(),
            reply,
        };
        self.send(request).await?;
        receiver.await.map_err(|_| AuditError::WriterTerminated)?
    }

    /// Writes the `LedgerCommit` component, appends the final container
    /// digest covering everything before it, and `sync_all`s the complete
    /// file (design section 12.3 steps 7-8). Exactly once, after the seal.
    /// The ledger state is advanced atomically by the ledger afterwards.
    pub async fn write_ledger_commit(&self, commit: &LedgerCommit) -> Result<(), AuditError> {
        let (reply, receiver) = oneshot::channel();
        let request = Request::WriteLedgerCommit {
            commit: commit.encode_payload().as_slice().into(),
            reply,
        };
        self.send(request).await?;
        receiver.await.map_err(|_| AuditError::WriterTerminated)?
    }

    async fn send(&self, request: Request) -> Result<(), AuditError> {
        self.tx
            .send(request)
            .await
            .map_err(|_| AuditError::WriterTerminated)
    }
}

/// The record file name `records/<session-id>.<role>.yonaudit`
/// (design section 10.4); the session ID is lowercase hex.
pub fn record_file_name(session_id: &SessionId, role: AuditRole) -> String {
    let role_name = match role {
        AuditRole::Controller => "controller",
        AuditRole::Host => "host",
    };
    let mut name =
        String::with_capacity(64 + 1 + role_name.len() + 1 + RECORD_FILE_EXTENSION.len());
    name.push_str(&hex_encode(session_id.as_bytes()));
    name.push('.');
    name.push_str(role_name);
    name.push('.');
    name.push_str(RECORD_FILE_EXTENSION);
    name
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

/// Creates the records directory with the platform private-directory policy
/// or validates the existing directory without repairing an anomaly.
fn ensure_records_dir(path: &Path) -> Result<(), AuditError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => SystemPrivateDirectoryPolicy
            .validate(path)
            .map_err(map_directory_policy),
        Err(error) if error.kind() == io::ErrorKind::NotFound => SystemPrivateDirectoryPolicy
            .protect(path)
            .map_err(map_directory_policy),
        Err(error) => Err(AuditError::DirectoryUnavailable(error)),
    }
}

/// Opens the record file exclusively with `0600` permissions on Unix
/// (design section 11.1: an existing name, link or directory is never
/// followed or overwritten).
fn open_record_file(path: &Path) -> Result<std::fs::File, AuditError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(RECORD_FILE_MODE);
    }
    let file = options.open(path).map_err(AuditError::RecordCreateFailed)?;
    if let Err(error) = SystemSecretFilePolicy.protect_new(path, &file) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(map_record_policy(error));
    }
    Ok(file)
}

fn map_directory_policy(error: SecretFileError) -> AuditError {
    AuditError::DirectoryUnavailable(policy_io_error(error))
}

fn map_record_policy(error: SecretFileError) -> AuditError {
    AuditError::RecordCreateFailed(policy_io_error(error))
}

fn policy_io_error(error: SecretFileError) -> io::Error {
    match error {
        SecretFileError::Insecure => io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the audit storage permissions are invalid",
        ),
        SecretFileError::Platform(error) => error,
    }
}

/// The writer task: processes one request at a time in order. After the
/// first fatal (I/O-class) error the writer is poisoned: every later
/// request is answered with the same error and nothing is dropped or
/// redirected. Ordering violations (`InvalidState`) are programming errors
/// that touch no file bytes and do not poison the writer.
async fn writer_task(mut file: impl AsyncFile, mut receiver: mpsc::Receiver<Request>) {
    let mut hasher = Sha256::new();
    let mut phase = WriterPhase::Initializing;
    let mut failed: Option<AuditError> = None;
    while let Some(request) = receiver.recv().await {
        if let Some(error) = &failed {
            let error = error.clone();
            reject(request, error);
            continue;
        }
        match request {
            Request::Initialize { header, reply } => {
                let result = run_initialize(&mut file, &mut hasher, &mut phase, &header).await;
                if let Err(error) = &result
                    && error.is_fatal()
                {
                    failed = Some(error.clone());
                }
                let _ = reply.send(result);
            }
            Request::Append {
                record_type,
                payload,
                reply,
            } => {
                let result =
                    run_append(&mut file, &mut hasher, &mut phase, record_type, &payload).await;
                if let Err(error) = &result
                    && error.is_fatal()
                {
                    failed = Some(error.clone());
                }
                let _ = reply.send(result);
            }
            Request::Sync { reply } => {
                let result = run_sync(&mut file, phase).await;
                if let Err(error) = &result
                    && error.is_fatal()
                {
                    failed = Some(error.clone());
                }
                let _ = reply.send(result);
            }
            Request::WriteManifestAndSignatures {
                manifest,
                controller,
                host,
                reply,
            } => {
                let result = run_write_manifest_and_signatures(
                    &mut file,
                    &mut hasher,
                    &mut phase,
                    &manifest,
                    &controller,
                    &host,
                )
                .await;
                if let Err(error) = &result
                    && error.is_fatal()
                {
                    failed = Some(error.clone());
                }
                let _ = reply.send(result);
            }
            Request::WriteSeal { seal, reply } => {
                let result = run_write_seal(&mut file, &mut hasher, &mut phase, &seal).await;
                if let Err(error) = &result
                    && error.is_fatal()
                {
                    failed = Some(error.clone());
                }
                let _ = reply.send(result);
            }
            Request::WriteLedgerCommit { commit, reply } => {
                let result =
                    run_write_ledger_commit(&mut file, &mut hasher, &mut phase, &commit).await;
                if let Err(error) = &result
                    && error.is_fatal()
                {
                    failed = Some(error.clone());
                }
                let _ = reply.send(result);
            }
        }
    }
}

impl AuditError {
    /// Whether the error indicates the file itself cannot be written any
    /// more, in which case the writer is poisoned. Ordering violations
    /// touch no file bytes and leave the writer usable.
    fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::DirectoryUnavailable(_)
                | Self::RecordCreateFailed(_)
                | Self::RecordWriteFailed(_)
                | Self::RecordSyncFailed(_)
        )
    }
}

/// Answers a request after the writer was poisoned, with the original
/// error.
fn reject(request: Request, error: AuditError) {
    match request {
        Request::Initialize { reply, .. }
        | Request::Append { reply, .. }
        | Request::Sync { reply }
        | Request::WriteLedgerCommit { reply, .. } => {
            let _ = reply.send(Err(error));
        }
        Request::WriteManifestAndSignatures { reply, .. } | Request::WriteSeal { reply, .. } => {
            let _ = reply.send(Err(error));
        }
    }
}

async fn run_initialize(
    file: &mut impl AsyncFile,
    hasher: &mut Sha256,
    phase: &mut WriterPhase,
    header: &[u8],
) -> Result<(), AuditError> {
    if *phase != WriterPhase::Initializing {
        return Err(AuditError::InvalidState(
            "the header is already initialized",
        ));
    }
    write_bytes(file, hasher, header).await?;
    // Design section 19.2: the header is synced before Terminal Active.
    sync_file(file).await?;
    *phase = WriterPhase::Recording;
    Ok(())
}

async fn run_append(
    file: &mut impl AsyncFile,
    hasher: &mut Sha256,
    phase: &mut WriterPhase,
    record_type: RecordType,
    payload: &[u8],
) -> Result<(), AuditError> {
    match phase {
        WriterPhase::Initializing => {
            return Err(AuditError::InvalidState(
                "records cannot be appended before the header",
            ));
        }
        WriterPhase::Finished | WriterPhase::Finalizing => {
            return Err(AuditError::InvalidState(
                "records cannot be appended after finalization started",
            ));
        }
        WriterPhase::Recording => {}
    }
    if payload.len() > MAX_RECORD_FRAME_LEN as usize - 1 {
        return Err(AuditError::InvalidState(
            "record payload exceeds the container frame bound",
        ));
    }
    let frame_len = 1 + payload.len() as u32;
    validate_frame_len(record_type, frame_len)
        .map_err(|_| AuditError::InvalidState("record frame exceeds the container bound"))?;
    let frame_header = encode_frame_header(frame_len);
    write_bytes(file, hasher, &frame_header).await?;
    write_bytes(file, hasher, &[record_type.code()]).await?;
    write_bytes(file, hasher, payload).await
}

async fn run_sync(file: &mut impl AsyncFile, phase: WriterPhase) -> Result<(), AuditError> {
    if phase == WriterPhase::Initializing {
        return Err(AuditError::InvalidState(
            "nothing to sync before the header",
        ));
    }
    sync_file(file).await
}

async fn run_write_manifest_and_signatures(
    file: &mut impl AsyncFile,
    hasher: &mut Sha256,
    phase: &mut WriterPhase,
    manifest: &[u8],
    controller: &[u8],
    host: &[u8],
) -> Result<Digest32, AuditError> {
    if *phase != WriterPhase::Recording {
        return Err(AuditError::InvalidState(
            "the manifest must be written before the seal and after the header",
        ));
    }
    write_bytes(file, hasher, &FOOTER_MAGIC).await?;
    write_prefixed(file, hasher, manifest).await?;
    write_prefixed(file, hasher, controller).await?;
    write_prefixed(file, hasher, host).await?;
    *phase = WriterPhase::Finalizing;
    // The sealed prefix digest covers everything through the host session
    // signature (design section 23.4).
    let digest: [u8; 32] = hasher.clone().finalize().into();
    Ok(Digest32::new(digest))
}

async fn run_write_seal(
    file: &mut impl AsyncFile,
    hasher: &mut Sha256,
    phase: &mut WriterPhase,
    seal: &[u8],
) -> Result<Digest32, AuditError> {
    if *phase != WriterPhase::Finalizing {
        return Err(AuditError::InvalidState(
            "the seal must follow the manifest and both signatures",
        ));
    }
    write_prefixed(file, hasher, seal).await?;
    // The sealed record digest covers everything through the seal and is
    // referenced by the ledger commit (design section 12.3).
    let digest: [u8; 32] = hasher.clone().finalize().into();
    Ok(Digest32::new(digest))
}

async fn run_write_ledger_commit(
    file: &mut impl AsyncFile,
    hasher: &mut Sha256,
    phase: &mut WriterPhase,
    commit: &[u8],
) -> Result<(), AuditError> {
    if *phase != WriterPhase::Finalizing {
        return Err(AuditError::InvalidState(
            "the ledger commit must follow the seal",
        ));
    }
    write_prefixed(file, hasher, commit).await?;
    // The final container digest covers everything through the commit and
    // excludes only itself (design section 23.4).
    let digest: [u8; 32] = hasher.clone().finalize().into();
    write_bytes(file, hasher, &digest).await?;
    // Design section 12.3 step 8: sync the complete audit file after the
    // commit; the ledger state is advanced atomically afterwards.
    sync_file(file).await?;
    *phase = WriterPhase::Finished;
    Ok(())
}

/// Writes one `u16`-prefixed footer component (design section 23.4, the
/// same layout `audit_container::decode_footer` reads).
async fn write_prefixed(
    file: &mut impl AsyncFile,
    hasher: &mut Sha256,
    bytes: &[u8],
) -> Result<(), AuditError> {
    let len = u16::try_from(bytes.len())
        .map_err(|_| AuditError::InvalidState("footer component exceeds the u16 length bound"))?;
    write_bytes(file, hasher, &len.to_be_bytes()).await?;
    write_bytes(file, hasher, bytes).await
}

async fn write_bytes(
    file: &mut impl AsyncFile,
    hasher: &mut Sha256,
    bytes: &[u8],
) -> Result<(), AuditError> {
    file.write_all(bytes)
        .await
        .map_err(AuditError::RecordWriteFailed)?;
    hasher.update(bytes);
    Ok(())
}

async fn sync_file(file: &mut impl AsyncFile) -> Result<(), AuditError> {
    file.sync_all().await.map_err(AuditError::RecordSyncFailed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::sync::Mutex as AsyncMutex;
    use yonder_core::wire::audit::{
        AUDIT_FORMAT_VERSION, AuditNonce, BindingDigest, ChainHead, CommitmentDigest, DIGEST_LEN,
        Ed25519PublicKey, Ed25519Signature, IdentityFingerprint, LedgerRoot, ManifestEnding,
        SessionResult, SharedSnapshot, StreamSnapshot,
    };
    use yonder_core::wire::audit_container::{
        CONTAINER_HEADER_LEN, ContainerReader, MAX_RAW_OUTPUT_PAYLOAD_LEN,
    };

    const ZERO_HEAD: ChainHead = ChainHead::new([0; DIGEST_LEN]);
    const ZERO_ROOT: LedgerRoot = LedgerRoot::new([0; DIGEST_LEN]);

    fn test_session_id() -> SessionId {
        SessionId::new([0x5A; DIGEST_LEN])
    }

    fn test_header() -> AuditContainerHeader {
        AuditContainerHeader::new(
            AuditRole::Controller,
            test_session_id(),
            Ed25519PublicKey::new([1; 32]),
            Ed25519PublicKey::new([2; 32]),
            Ed25519PublicKey::new([3; 32]),
            Ed25519PublicKey::new([4; 32]),
            7,
            ZERO_ROOT,
            1_700_000_000,
            yonder_core::wire::audit::AuthMode::Enterprise,
            Digest32::new([5; DIGEST_LEN]),
            yonder_core::wire::audit::AuditHello::new(
                AuditRole::Controller,
                Ed25519PublicKey::new([1; 32]),
                Ed25519PublicKey::new([2; 32]),
                AuditNonce::new([3; 32]),
                7,
                ZERO_ROOT,
                BindingDigest::new([4; DIGEST_LEN]),
                AUDIT_FORMAT_VERSION,
                CommitmentDigest::new([5; DIGEST_LEN]),
                Ed25519Signature::new([6; 64]),
            ),
            yonder_core::wire::audit::AuditReady::new(
                test_session_id(),
                Digest32::new([2; DIGEST_LEN]),
                AUDIT_FORMAT_VERSION,
                Ed25519Signature::new([3; 64]),
            ),
        )
        .with_header_signature(Ed25519Signature::new([9; 64]))
    }

    fn snapshot() -> SharedSnapshot {
        SharedSnapshot::new([
            StreamSnapshot::new(10, ZERO_HEAD),
            StreamSnapshot::new(20, ZERO_HEAD),
            StreamSnapshot::new(30, ZERO_HEAD),
            StreamSnapshot::new(40, ZERO_HEAD),
        ])
    }

    fn test_manifest() -> JointManifest {
        JointManifest::new(
            AUDIT_FORMAT_VERSION,
            test_session_id(),
            IdentityFingerprint::new([2; DIGEST_LEN]),
            IdentityFingerprint::new([3; DIGEST_LEN]),
            Ed25519PublicKey::new([4; 32]),
            Ed25519PublicKey::new([5; 32]),
            BindingDigest::new([6; DIGEST_LEN]),
            Digest32::new([7; DIGEST_LEN]),
            snapshot(),
            ManifestEnding::ShellExit(0),
            true,
            9,
        )
    }

    fn test_signature() -> ManifestSignature {
        ManifestSignature::new(Ed25519Signature::new([6; 64]))
    }

    fn test_seal() -> LocalRecordSeal {
        LocalRecordSeal::new(
            test_session_id(),
            AuditRole::Controller,
            ZERO_HEAD,
            12,
            [ZERO_HEAD; 4],
            Digest32::new([2; DIGEST_LEN]),
            Digest32::new([3; DIGEST_LEN]),
            Ed25519Signature::new([4; 64]),
        )
    }

    fn test_commit() -> LedgerCommit {
        LedgerCommit::new(
            13,
            ZERO_ROOT,
            test_session_id(),
            Digest32::new([2; DIGEST_LEN]),
            Digest32::new([3; DIGEST_LEN]),
            IdentityFingerprint::new([4; DIGEST_LEN]),
            SessionResult::Normal,
            Ed25519Signature::new([5; 64]),
        )
    }

    fn frame_bytes(record_type: RecordType, payload: &[u8]) -> Vec<u8> {
        let frame_len = 1 + payload.len() as u32;
        let mut frame = encode_frame_header(frame_len).to_vec();
        frame.push(record_type.code());
        frame.extend_from_slice(payload);
        frame
    }

    #[tokio::test]
    async fn full_container_round_trips_through_the_writer() {
        let dir = tempdir().unwrap();
        let records = dir.path().join("records");
        let writer =
            AuditWriter::open(&records, &test_session_id(), AuditRole::Controller).unwrap();
        // File layout: <session-id>.<role>.yonaudit.
        assert_eq!(
            writer.record_path().file_name().unwrap(),
            "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a.controller.yonaudit"
        );
        assert!(writer.record_path().is_absolute() || writer.record_path().is_relative());

        let header = test_header();
        writer.initialize(&header).await.unwrap();
        let payload_a = b"input block record";
        let payload_b = vec![0xAB; MAX_RAW_OUTPUT_PAYLOAD_LEN - 40];
        writer
            .append(RecordType::SharedInputCommitment, payload_a)
            .await
            .unwrap();
        writer
            .append(RecordType::LocalRawOutput, &payload_b)
            .await
            .unwrap();
        writer.sync_all().await.unwrap();

        let sealed_prefix_digest = writer
            .write_manifest_and_signatures(&test_manifest(), &test_signature(), &test_signature())
            .await
            .unwrap();
        let sealed_record_digest = writer.write_seal(&test_seal()).await.unwrap();
        writer.write_ledger_commit(&test_commit()).await.unwrap();

        let bytes = std::fs::read(writer.record_path()).unwrap();
        let mut reader = ContainerReader::new(&bytes).unwrap();
        assert_eq!(reader.header(), &header);
        let first = reader.next_frame().unwrap().unwrap();
        assert_eq!(first.record_type, RecordType::SharedInputCommitment);
        assert_eq!(first.payload, payload_a);
        let second = reader.next_frame().unwrap().unwrap();
        assert_eq!(second.record_type, RecordType::LocalRawOutput);
        assert_eq!(second.payload, &payload_b[..]);
        assert!(reader.next_frame().unwrap().is_none());
        let footer = reader.footer().unwrap();
        assert_eq!(footer.footer.manifest, test_manifest());
        assert_eq!(footer.footer.controller_session_signature, test_signature());
        assert_eq!(footer.footer.host_session_signature, test_signature());
        assert_eq!(footer.footer.seal, test_seal());
        assert_eq!(footer.footer.ledger_commit, test_commit());

        // The three digest boundaries match the returned digests.
        assert_eq!(
            sealed_prefix_digest.as_bytes(),
            &sha256_32(&bytes[..footer.sealed_prefix_end])[..],
            "the sealed prefix digest covers everything before the seal"
        );
        assert_eq!(
            sealed_record_digest.as_bytes(),
            &sha256_32(&bytes[..footer.seal_end])[..],
            "the sealed record digest covers everything through the seal"
        );
        assert_eq!(
            footer.final_container_digest.as_bytes(),
            &sha256_32(&bytes[..footer.ledger_end])[..],
            "the final container digest covers everything before itself"
        );
        // The footer is the last component; nothing follows the digest.
        assert_eq!(reader.position(), bytes.len());
    }

    fn sha256_32(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    #[test]
    fn record_file_name_layout_is_frozen() {
        let mut bytes = [0_u8; DIGEST_LEN];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let session_id = SessionId::new(bytes);
        let mut expected = String::new();
        for byte in session_id.as_bytes() {
            use std::fmt::Write as _;
            write!(expected, "{byte:02x}").unwrap();
        }
        assert_eq!(
            record_file_name(&session_id, AuditRole::Controller),
            format!("{expected}.controller.yonaudit")
        );
        assert_eq!(
            record_file_name(&session_id, AuditRole::Host),
            format!("{expected}.host.yonaudit")
        );
    }

    #[tokio::test]
    async fn exclusive_create_refuses_existing_files() {
        let dir = tempdir().unwrap();
        let records = dir.path().join("records");
        let _writer =
            AuditWriter::open(&records, &test_session_id(), AuditRole::Controller).unwrap();
        // The same path must not be opened twice (design section 11.1).
        let duplicate = AuditWriter::open(&records, &test_session_id(), AuditRole::Controller);
        assert!(matches!(duplicate, Err(AuditError::RecordCreateFailed(_))));
        // A second session with a different session ID is a different file.
        let other = SessionId::new([0x0F; DIGEST_LEN]);
        assert!(AuditWriter::open(&records, &other, AuditRole::Host).is_ok());
    }

    /// An instrumented file that blocks every write until released.
    struct BlockingFile {
        state: Arc<AsyncMutex<BlockingState>>,
        release: Arc<tokio::sync::Notify>,
    }

    #[derive(Default)]
    struct BlockingState {
        bytes: Vec<u8>,
        syncs: usize,
        blocking: bool,
        pending: usize,
    }

    impl BlockingFile {
        fn new(state: Arc<AsyncMutex<BlockingState>>, release: Arc<tokio::sync::Notify>) -> Self {
            Self { state, release }
        }
    }

    impl AsyncFile for BlockingFile {
        async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
            loop {
                // Create the wake-up future inside the guard scope so the
                // lock is released before waiting.
                let notify = {
                    let mut state = self.state.lock().await;
                    if !state.blocking {
                        state.bytes.extend_from_slice(bytes);
                        return Ok(());
                    }
                    state.pending += 1;
                    self.release.notified()
                };
                notify.await;
            }
        }

        async fn sync_all(&mut self) -> io::Result<()> {
            self.state.lock().await.syncs += 1;
            Ok(())
        }
    }

    #[tokio::test]
    async fn queue_backpressure_blocks_and_preserves_order() {
        let state = Arc::new(AsyncMutex::new(BlockingState::default()));
        let release = Arc::new(tokio::sync::Notify::new());
        let path = PathBuf::from("backpressure.yonaudit");
        let writer = AuditWriter::spawn(
            path,
            test_session_id(),
            AuditRole::Controller,
            BlockingFile::new(state.clone(), release.clone()),
            1,
        );
        let header = test_header();
        writer.initialize(&header).await.unwrap();
        writer.sync_all().await.unwrap();

        // Block the writer task in the middle of a write. The first append
        // is in flight: the send reaches the task, the task blocks, the
        // reply never arrives and the caller waits.
        state.lock().await.blocking = true;
        let first = writer.append(RecordType::LocalKeyAction, b"first");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), first)
                .await
                .is_err(),
            "the first append waits for the blocked writer"
        );
        // A second queued append fills the capacity-one queue and a third
        // must backpressure: the send cannot complete while the writer is
        // still blocked, and nothing is dropped.
        let second = writer.append(RecordType::LocalKeyAction, b"second");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), second)
                .await
                .is_err(),
            "the second append waits for its buffered write"
        );
        assert_eq!(state.lock().await.pending, 1, "the writer is still blocked");
        let third = writer.append(RecordType::LocalKeyAction, b"third");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), third)
                .await
                .is_err(),
            "a full bounded queue must exert backpressure instead of dropping"
        );

        // Release the writer: the in-flight and queued records are written
        // in order. The canceled third send never entered the queue, so it
        // is appended again after the release.
        {
            let mut state = state.lock().await;
            state.blocking = false;
        }
        release.notify_one();
        writer
            .append(RecordType::LocalKeyAction, b"third")
            .await
            .unwrap();

        let state = state.lock().await;
        let mut expected = Vec::new();
        expected.extend_from_slice(header.encode().as_slice());
        expected.extend_from_slice(&frame_bytes(RecordType::LocalKeyAction, b"first"));
        expected.extend_from_slice(&frame_bytes(RecordType::LocalKeyAction, b"second"));
        expected.extend_from_slice(&frame_bytes(RecordType::LocalKeyAction, b"third"));
        assert_eq!(
            state.bytes, expected,
            "records are written in order, none dropped"
        );
        assert!(state.syncs >= 1, "the header sync happened");
    }

    /// An instrumented file that fails every write after `fail_after` bytes.
    struct FailingFile {
        written: usize,
        fail_after: usize,
    }

    impl AsyncFile for FailingFile {
        async fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
            if self.written >= self.fail_after {
                return Err(io::Error::other("test disk full"));
            }
            self.written += bytes.len();
            Ok(())
        }

        async fn sync_all(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn writer_errors_propagate_and_poison_all_later_requests() {
        let writer = AuditWriter::spawn(
            PathBuf::from("failing.yonaudit"),
            test_session_id(),
            AuditRole::Host,
            FailingFile {
                written: 0,
                fail_after: CONTAINER_HEADER_LEN,
            },
            8,
        );
        let header = test_header();
        writer.initialize(&header).await.unwrap();
        // The next write fails and the error is returned synchronously.
        let error = writer
            .append(RecordType::LocalKeyAction, b"boom")
            .await
            .unwrap_err();
        assert!(matches!(error, AuditError::RecordWriteFailed(_)));
        // Every later request is answered with the same error: nothing is
        // dropped, nothing falls back to ordinary logs.
        for _ in 0..4 {
            let error = writer
                .append(RecordType::LocalKeyAction, b"more")
                .await
                .unwrap_err();
            assert!(matches!(error, AuditError::RecordWriteFailed(_)));
        }
        let error = writer.sync_all().await.unwrap_err();
        assert!(matches!(error, AuditError::RecordWriteFailed(_)));
        let error = writer
            .write_manifest_and_signatures(&test_manifest(), &test_signature(), &test_signature())
            .await
            .unwrap_err();
        assert!(matches!(error, AuditError::RecordWriteFailed(_)));
    }

    #[tokio::test]
    async fn header_is_synced_before_initialize_returns() {
        let state = Arc::new(AsyncMutex::new(BlockingState::default()));
        let release = Arc::new(tokio::sync::Notify::new());
        let writer = AuditWriter::spawn(
            PathBuf::from("sync.yonaudit"),
            test_session_id(),
            AuditRole::Controller,
            BlockingFile::new(state.clone(), release.clone()),
            8,
        );
        let header = test_header();
        writer.initialize(&header).await.unwrap();
        let state = state.lock().await;
        assert_eq!(
            state.bytes,
            header.encode().as_slice().to_vec(),
            "the header bytes were written"
        );
        assert_eq!(
            state.syncs, 1,
            "the header was synced before initialize returned"
        );
    }

    #[tokio::test]
    async fn finalize_steps_are_order_enforced() {
        let state = Arc::new(AsyncMutex::new(BlockingState::default()));
        let release = Arc::new(tokio::sync::Notify::new());
        let writer = AuditWriter::spawn(
            PathBuf::from("order.yonaudit"),
            test_session_id(),
            AuditRole::Host,
            BlockingFile::new(state.clone(), release.clone()),
            8,
        );
        writer.initialize(&test_header()).await.unwrap();

        // The seal before the manifest is refused.
        let error = writer.write_seal(&test_seal()).await.unwrap_err();
        assert!(matches!(error, AuditError::InvalidState(_)));
        // The manifest then the seal succeeds.
        writer
            .write_manifest_and_signatures(&test_manifest(), &test_signature(), &test_signature())
            .await
            .unwrap();
        writer.write_seal(&test_seal()).await.unwrap();
        // Records after finalization started are refused.
        let error = writer
            .append(RecordType::LocalKeyAction, b"late")
            .await
            .unwrap_err();
        assert!(matches!(error, AuditError::InvalidState(_)));
        // The commit completes the footer; a second commit is refused.
        writer.write_ledger_commit(&test_commit()).await.unwrap();
        let error = writer
            .write_ledger_commit(&test_commit())
            .await
            .unwrap_err();
        assert!(matches!(error, AuditError::InvalidState(_)));
        // Appends before the header are refused.
        let writer = AuditWriter::spawn(
            PathBuf::from("order2.yonaudit"),
            test_session_id(),
            AuditRole::Host,
            BlockingFile::new(state.clone(), release.clone()),
            8,
        );
        let error = writer
            .append(RecordType::LocalKeyAction, b"early")
            .await
            .unwrap_err();
        assert!(matches!(error, AuditError::InvalidState(_)));
    }

    #[tokio::test]
    async fn record_frame_bounds_are_enforced() {
        let state = Arc::new(AsyncMutex::new(BlockingState::default()));
        let release = Arc::new(tokio::sync::Notify::new());
        let writer = AuditWriter::spawn(
            PathBuf::from("bounds.yonaudit"),
            test_session_id(),
            AuditRole::Host,
            BlockingFile::new(state.clone(), release.clone()),
            8,
        );
        writer.initialize(&test_header()).await.unwrap();
        // A raw output payload beyond the 64 KiB bound is refused.
        let oversized = vec![0_u8; MAX_RAW_OUTPUT_PAYLOAD_LEN + 1];
        let error = writer
            .append(RecordType::LocalRawOutput, &oversized)
            .await
            .unwrap_err();
        assert!(matches!(error, AuditError::InvalidState(_)));
        // A payload beyond the frame bound is refused.
        let huge = vec![0_u8; MAX_RECORD_FRAME_LEN as usize];
        let error = writer
            .append(RecordType::SharedControlEvent, &huge)
            .await
            .unwrap_err();
        assert!(matches!(error, AuditError::InvalidState(_)));
    }
}
