//! The verifiable session audit state machine, Yonder 0.2.0 design sections
//! 5 (input confidentiality), 13 (session establishment), 15-17 (event
//! model, normalization and hash chains), 18 (recording timing and failure
//! closing), 20 (bilateral checkpoints), 21 (joint manifest and local record
//! seal) and 12.3 (acyclic finalization).
//!
//! [`AuditSession`] is a synchronous state machine: it performs no I/O
//! itself. The integration layer drives it step by step, performs the framed
//! message exchange over the existing authenticated end-to-end substream
//! (`/yonder/audit/2.0.0`, design sections 13.1 and 28) and persists the
//! encoded record batches through the bounded async
//! [`crate::audit::writer::AuditWriter`] before any external terminal effect
//! (append-before-effect, design section 18).
//!
//! Dependencies on the local persistent identity and the local audit ledger
//! are expressed as the narrow [`PersistentIdentity`] and [`Ledger`] traits
//! so the concrete implementations (`audit::identity`, `audit::ledger`) are
//! injected by the integration layer.
//!
//! # Frozen record payload layouts
//!
//! All integers are big-endian. Every shared record payload is
//!
//! ```text
//! direction || sequence || canonical_payload || previous_chain_head || new_chain_head
//! ```
//!
//! and the shared chain event hash (design section 17.1) is
//!
//! ```text
//! SHA-256(chain_domain_label || previous_shared_hash || stream_kind
//!        || direction || sequence || event_kind || canonical_payload)
//! ```
//!
//! where `chain_domain_label` is the per-stream label of section 17.3,
//! `stream_kind` is the fixed [`SharedStream`] index byte, `event_kind` is
//! the per-event kind byte and `canonical_payload` is the record payload
//! without the direction, sequence and chain-head fields. Every shared
//! record therefore determines its own chain hash input given the previous
//! head, so the verify layer can re-walk the chain from the file alone.
//!
//! Every local record payload is
//!
//! ```text
//! monotonic_time_ns || related_shared_event_hash || kind_specific_payload
//! ```
//!
//! and the local event hash (design section 17.2) is
//!
//! ```text
//! SHA-256("yonder-audit-chain-local-v2" || previous_local_hash
//!         || local_sequence || monotonic_time_ns || record_type_code
//!         || kind_specific_payload || related_shared_event_hash)
//! ```
//!
//! `related_shared_event_hash` is the hash of the last shared event the
//! local observation contributed to, or 32 zero bytes when the observation
//! completed no shared event (design section 16.1: partial tails stay in
//! local records only). For raw output and display records the
//! kind-specific payload is the full bytes. The zero head `[0; 32]` is the
//! initial head of every chain. Shared chain sequences and the local
//! sequence start at 1.
//!
//! The kind-specific payloads are:
//!
//! ```text
//! SharedInputCommitment      (0x01): length(u64) || hmac[32]
//! SharedOutputBlock          (0x02): length(u64) || sha256[32]
//! SharedControlEvent         (0x03): event_kind || control_payload
//!   resize:            cols(u16) || rows(u16)
//!   terminal_hello:    digest[32]
//!   terminal_ready:    (empty)
//!   terminal_exit:     exit_code(u8)
//!   terminal_complete: (empty)
//!   close_reason:      reason(u8)
//! SharedFileTransferEvent   (0x04): event_kind || transfer_id(u64)
//!   || declared_size(u64) || final_size(u64) || digest[32]
//!   || remote_path_len(u16) || remote_path || file_name_len(u16)
//!   || file_name || error_code(u16)
//! LocalInputCommitment      (0x13): direction(u8) || length(u64)
//! LocalRawOutput            (0x11): bytes
//! LocalDisplayBytes         (0x12): bytes
//! LocalSendOutcome          (0x14): direction(u8) || outcome(u8) || bytes(u64)
//! LocalPtyWriteOutcome      (0x15): outcome(u8) || bytes(u64)
//! LocalDisplayWriteOutcome  (0x16): outcome(u8) || bytes(u64)
//! LocalResizeEvent          (0x17): direction(u8) || cols(u16) || rows(u16)
//! LocalLifecycleEvent       (0x18): lifecycle_kind(u8)
//! LocalKeyAction            (0x19): action(u8)
//! LocalFileTransferEvent    (0x1A): event_kind || transfer_id(u64)
//!   || local_path_len(u16) || local_path
//! LocalConnectionState      (0x1B): state(u8)
//! LocalAuditError           (0x1C): error_code(u16)
//! CheckpointEvidence        (0x1D): evidence_kind || payload_len(u32) || payload
//! LocalCloseEvent           (0x1E): close_reason(u8) || outcome(u8)
//! ```
//!
//! Raw output and display bodies are capped so the enclosing container frame
//! stays inside the 64 KiB raw-output bound of design section 23.3
//! ([`MAX_LOCAL_OUTPUT_SEGMENT`]).

use std::io;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use thiserror::Error;
use yonder_core::error::ProtocolError;
use yonder_core::random::{RandomError, SecureRandom};
use yonder_core::wire::audit::{
    AUDIT_FORMAT_VERSION, AuditCloseReason, AuditErrorCode, AuditHello, AuditNonce, AuditReady,
    AuditRole, AuthMode, BindingDigest, ChainHead, Checkpoint, CheckpointAck, CommitmentDigest,
    DIGEST_LEN, Digest32, ED25519_SIGNATURE_LEN, Ed25519PublicKey, Ed25519Signature,
    IdentityFingerprint, JointManifest, LedgerCommit, LedgerRoot, LocalRecordSeal, ManifestEnding,
    ManifestSignature, NONCE_LEN, PEER_AUDIT_UNSUPPORTED_MESSAGE, SECRET_CONTRIBUTION_LEN,
    SHARED_STREAMS, SecretContribution, SessionId, SessionResult, SharedSnapshot, SharedStream,
    StreamSnapshot,
};
use yonder_core::wire::audit_container::{
    AuditContainerHeader, MAX_RAW_OUTPUT_PAYLOAD_LEN, RecordType,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::audit::writer::AuditWriter;

// ---------------------------------------------------------------------------
// Frozen constants and domain labels
// ---------------------------------------------------------------------------

/// The canonical shared block size, 16 KiB (design section 16.1).
pub const CANONICAL_BLOCK_LEN: usize = 16 * 1024;
/// Checkpoint time trigger: one second since the last checkpoint
/// (design section 20.1).
pub const CHECKPOINT_INTERVAL_NS: u64 = 1_000_000_000;
/// Checkpoint size trigger: 1 MiB of new shared facts (design section 20.1).
pub const CHECKPOINT_SIZE_TRIGGER: u64 = 1024 * 1024;
/// The input commitment key derivation label (design section 5.3).
pub const INPUT_COMMITMENT_LABEL: &[u8] = b"yonder-audit-input-commitment-v2";
/// The session ID binding label (design section 13.4).
pub const SESSION_ID_LABEL: &[u8] = b"yonder-audit-session-v2";
/// Shared input chain domain label (design sections 16.2 and 17.3).
pub const CHAIN_INPUT_DOMAIN: &[u8] = b"yonder-audit-chain-input-v2";
/// Shared output chain domain label (design sections 16.3 and 17.3).
pub const CHAIN_OUTPUT_DOMAIN: &[u8] = b"yonder-audit-chain-output-v2";
/// Shared terminal control chain domain label (design sections 15.2 and 17.3).
pub const CHAIN_CONTROL_DOMAIN: &[u8] = b"yonder-audit-chain-control-v2";
/// Shared file transfer chain domain label (design sections 18.6 and 17.3).
pub const CHAIN_FILE_DOMAIN: &[u8] = b"yonder-audit-chain-file-v2";
/// Local observation chain domain label (design sections 15.3 and 17.3).
pub const CHAIN_LOCAL_DOMAIN: &[u8] = b"yonder-audit-chain-local-v2";

/// Direction: bytes flow from the controller to the host.
pub const DIRECTION_CTRL_TO_HOST: u8 = 0x01;
/// Direction: bytes flow from the host to the controller.
pub const DIRECTION_HOST_TO_CTRL: u8 = 0x02;

/// Shared input event kind (the input stream records only input commitments).
pub const INPUT_EVENT_KIND: u8 = 0x01;
/// Shared output event kind (the output stream records only block digests).
pub const OUTPUT_EVENT_KIND: u8 = 0x01;
/// Shared control event kinds (design section 15.2).
pub const CONTROL_KIND_RESIZE: u8 = 0x01;
pub const CONTROL_KIND_TERMINAL_HELLO: u8 = 0x02;
pub const CONTROL_KIND_TERMINAL_READY: u8 = 0x03;
pub const CONTROL_KIND_TERMINAL_EXIT: u8 = 0x04;
pub const CONTROL_KIND_TERMINAL_COMPLETE: u8 = 0x05;
pub const CONTROL_KIND_CLOSE_REASON: u8 = 0x06;
/// Shared file transfer event kinds (design section 18.6).
pub const FILE_KIND_START: u8 = 0x01;
pub const FILE_KIND_SUCCESS: u8 = 0x02;
pub const FILE_KIND_CANCELLED: u8 = 0x03;
pub const FILE_KIND_FAILED: u8 = 0x04;
/// File transfer directions: upload is controller-to-host, download is
/// host-to-controller.
pub const FILE_DIRECTION_UPLOAD: u8 = DIRECTION_CTRL_TO_HOST;
pub const FILE_DIRECTION_DOWNLOAD: u8 = DIRECTION_HOST_TO_CTRL;
/// Local lifecycle kinds (design section 15.3).
pub const LIFECYCLE_KIND_TERMINAL_HELLO: u8 = 0x01;
pub const LIFECYCLE_KIND_TERMINAL_READY: u8 = 0x02;
pub const LIFECYCLE_KIND_TERMINAL_EXIT: u8 = 0x03;
pub const LIFECYCLE_KIND_TERMINAL_COMPLETE: u8 = 0x04;
pub const LIFECYCLE_KIND_ACTIVE_DETACH: u8 = 0x05;
pub const LIFECYCLE_KIND_LOCAL_INTERRUPT: u8 = 0x06;
/// Local keyboard action kinds (design section 15.3).
pub const KEY_ACTION_HELP: u8 = 0x01;
pub const KEY_ACTION_UPLOAD: u8 = 0x02;
pub const KEY_ACTION_DOWNLOAD: u8 = 0x03;
pub const KEY_ACTION_STATUS: u8 = 0x04;
pub const KEY_ACTION_DETACH: u8 = 0x05;
pub const KEY_ACTION_INTERRUPT: u8 = 0x06;
/// Local connection states (design section 15.3).
pub const CONNECTION_STATE_ESTABLISHED: u8 = 0x01;
pub const CONNECTION_STATE_LOST: u8 = 0x02;
pub const CONNECTION_STATE_CLOSED: u8 = 0x03;
/// Local outcome values (design section 18).
pub const OUTCOME_OK: u8 = 0x01;
pub const OUTCOME_FAILED: u8 = 0x02;
/// Checkpoint evidence kinds (design sections 15.2, 20.2 and 20.3).
pub const EVIDENCE_SENT_CHECKPOINT: u8 = 0x01;
pub const EVIDENCE_RECEIVED_CHECKPOINT: u8 = 0x02;
pub const EVIDENCE_SENT_CHECKPOINT_ACK: u8 = 0x03;
pub const EVIDENCE_RECEIVED_CHECKPOINT_ACK: u8 = 0x04;
pub const EVIDENCE_SENT_MANIFEST: u8 = 0x06;
pub const EVIDENCE_RECEIVED_MANIFEST: u8 = 0x07;
pub const EVIDENCE_SENT_MANIFEST_SIGNATURE: u8 = 0x08;
pub const EVIDENCE_RECEIVED_MANIFEST_SIGNATURE: u8 = 0x09;

/// Largest inline record payload: a checkpoint evidence record carrying a
/// maximal joint manifest (time + related + kind + length + manifest).
pub const MAX_INLINE_PAYLOAD_LEN: usize = 8 + DIGEST_LEN + 1 + 4 + 911;
/// The fixed local record envelope before a borrowed raw body: monotonic
/// time plus the related shared event hash.
pub const SPLIT_PREFIX_LEN: usize = 8 + DIGEST_LEN;
/// The largest raw output or display body in one local record: the 64 KiB
/// container payload bound minus the local envelope (design section 23.3).
pub const MAX_LOCAL_OUTPUT_SEGMENT: usize = MAX_RAW_OUTPUT_PAYLOAD_LEN - SPLIT_PREFIX_LEN;
/// The largest input segment accepted in one recording step. Input content
/// is never persisted; the bound keeps the number of completed canonical
/// blocks per step at four.
pub const MAX_INPUT_SEGMENT: usize = 64 * 1024;
/// The largest number of records one recording step can produce: one local
/// raw-output record, up to four completed shared blocks and one local
/// display-bytes record (design section 18.4).
pub const MAX_RECORDS_PER_STEP: usize = 6;

/// The maximum protocol path length mirrored from the file transfer
/// protocol (design section 18.6).
pub const MAX_PROTOCOL_PATH_LEN: usize = 4096;
/// The maximum protocol base file name length mirrored from the file
/// transfer protocol (design section 18.6).
pub const MAX_PROTOCOL_FILE_NAME_LEN: usize = 1024;
/// The maximum local path length recorded in a local file transfer event.
pub const MAX_LOCAL_PATH_LEN: usize = 4096;

/// The fixed byte length of one shared input commitment record payload.
pub const SHARED_INPUT_RECORD_LEN: usize = 1 + 8 + 8 + 32 + 32 + 32;
/// The fixed byte length of one shared output block record payload.
pub const SHARED_OUTPUT_RECORD_LEN: usize = 1 + 8 + 8 + 32 + 32 + 32;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A structured audit failure, one per design section 30 category where
/// applicable. Error text is fixed and redacted: no raw input, no secrets,
/// no connection codes and no audit file content are ever printed.
#[derive(Debug, Error)]
pub enum AuditError {
    /// The operating system secure random source failed during a handshake.
    #[error("the operating system secure random source failed")]
    RandomSource(#[from] RandomError),
    /// `AuditIdentityMissing` (design section 30).
    #[error("audit history exists but the persistent audit identity is missing")]
    IdentityMissing,
    /// `AuditIdentityInvalid` (design section 30).
    #[error("the persistent audit identity is invalid")]
    IdentityInvalid,
    /// `AuditIdentityPermissions` (design section 30).
    #[error("the persistent audit identity permissions are invalid")]
    IdentityPermissions,
    /// `AuditLedgerInvalid` (design section 30).
    #[error("the local audit ledger is invalid")]
    LedgerInvalid,
    /// `AuditLedgerConflict` (design section 30).
    #[error("the local audit ledger has conflicting pending commits")]
    LedgerConflict,
    /// `AuditDirectoryUnavailable` (design section 30).
    #[error("the audit directory is unavailable")]
    DirectoryUnavailable(#[source] io::Error),
    /// `AuditRecordCreateFailed` (design section 30).
    #[error("the local audit record file could not be created")]
    RecordCreateFailed(#[source] io::Error),
    /// `AuditRecordWriteFailed` (design section 30).
    #[error("the local audit record write failed")]
    RecordWriteFailed(#[source] io::Error),
    /// `AuditRecordSyncFailed` (design section 30).
    #[error("the local audit record sync failed")]
    RecordSyncFailed(#[source] io::Error),
    /// `AuditProtocolUnsupported`: the peer cannot open the mandatory audit
    /// substream (design section 14). The message is the frozen fixed text.
    #[error("{0}")]
    ProtocolUnsupported(&'static str),
    /// `AuditHandshakeInvalid` (design section 30).
    #[error("the audit handshake is invalid")]
    HandshakeInvalid,
    /// `AuditSessionBindingMismatch` (design section 30).
    #[error("the audit session binding does not match the authenticated connection")]
    SessionBindingMismatch,
    /// `AuditCheckpointMismatch` (design section 30).
    #[error("the peer checkpoint is invalid")]
    CheckpointMismatch,
    /// `AuditPeerSignatureInvalid` (design section 30).
    #[error("the peer audit signature is invalid")]
    PeerSignatureInvalid,
    /// `AuditFinalManifestMismatch` (design section 30).
    #[error("the final joint manifest does not match the peer manifest")]
    FinalManifestMismatch,
    /// `AuditLedgerCommitFailed` (design section 30).
    #[error("the local audit ledger commit failed")]
    LedgerCommitFailed,
    /// `AuditReplayUnsafe` (design section 30; used by the verify and replay
    /// layers).
    #[error("audit replay contains prohibited terminal content")]
    ReplayUnsafe,
    /// `AuditContainerInvalid` (design section 30; used by the verify
    /// layer).
    #[error("the audit container is invalid")]
    ContainerInvalid,
    /// A peer audit frame could not be decoded.
    #[error("the audit protocol message is invalid")]
    Protocol(#[from] ProtocolError),
    /// The audit substream I/O failed: the connection or the peer ended it
    /// mid-exchange.
    #[error("the audit substream I/O failed")]
    Substream(#[source] std::io::Error),
    /// A recording step exceeded the bounded segment size.
    #[error("the audit segment exceeds the bounded record size")]
    SegmentTooLarge,
    /// The session state does not permit the requested operation.
    #[error("the audit session is in an invalid state for this operation")]
    InvalidState(&'static str),
    /// The session already failed closed and cannot continue.
    #[error("the audit session has failed closed")]
    FailedClosed,
    /// The audit writer task terminated unexpectedly.
    #[error("the audit writer is not running")]
    WriterTerminated,
}

impl AuditError {
    /// The design section 30 failure category of this error, when one
    /// applies.
    #[must_use]
    pub const fn code(&self) -> Option<AuditErrorCode> {
        match self {
            Self::IdentityMissing => Some(AuditErrorCode::AuditIdentityMissing),
            Self::IdentityInvalid => Some(AuditErrorCode::AuditIdentityInvalid),
            Self::IdentityPermissions => Some(AuditErrorCode::AuditIdentityPermissions),
            Self::LedgerInvalid => Some(AuditErrorCode::AuditLedgerInvalid),
            Self::LedgerConflict => Some(AuditErrorCode::AuditLedgerConflict),
            Self::DirectoryUnavailable(_) => Some(AuditErrorCode::AuditDirectoryUnavailable),
            Self::RecordCreateFailed(_) => Some(AuditErrorCode::AuditRecordCreateFailed),
            Self::RecordWriteFailed(_) => Some(AuditErrorCode::AuditRecordWriteFailed),
            Self::RecordSyncFailed(_) => Some(AuditErrorCode::AuditRecordSyncFailed),
            Self::ProtocolUnsupported(_) => Some(AuditErrorCode::AuditProtocolUnsupported),
            Self::HandshakeInvalid => Some(AuditErrorCode::AuditHandshakeInvalid),
            Self::SessionBindingMismatch => Some(AuditErrorCode::AuditSessionBindingMismatch),
            Self::CheckpointMismatch => Some(AuditErrorCode::AuditCheckpointMismatch),
            Self::PeerSignatureInvalid => Some(AuditErrorCode::AuditPeerSignatureInvalid),
            Self::FinalManifestMismatch => Some(AuditErrorCode::AuditFinalManifestMismatch),
            Self::LedgerCommitFailed => Some(AuditErrorCode::AuditLedgerCommitFailed),
            Self::ReplayUnsafe => Some(AuditErrorCode::AuditReplayUnsafe),
            Self::ContainerInvalid => Some(AuditErrorCode::AuditContainerInvalid),
            Self::RandomSource(_)
            | Self::Protocol(_)
            | Self::Substream(_)
            | Self::SegmentTooLarge
            | Self::InvalidState(_)
            | Self::FailedClosed
            | Self::WriterTerminated => None,
        }
    }

    /// The fixed peer-unsupported error of design section 14, with the
    /// frozen message text.
    #[must_use]
    pub const fn peer_unsupported() -> Self {
        Self::ProtocolUnsupported(PEER_AUDIT_UNSUPPORTED_MESSAGE)
    }
}

/// `std::io::Error` is not `Clone`, so the writer's poison path clones the
/// error by kind: the category, the fixed redacted message and the variant
/// are preserved; the underlying I/O detail is deliberately not duplicated
/// (design section 30: error text is fixed and redacted).
impl Clone for AuditError {
    fn clone(&self) -> Self {
        match self {
            Self::RandomSource(_) => Self::RandomSource(RandomError),
            Self::IdentityMissing => Self::IdentityMissing,
            Self::IdentityInvalid => Self::IdentityInvalid,
            Self::IdentityPermissions => Self::IdentityPermissions,
            Self::LedgerInvalid => Self::LedgerInvalid,
            Self::LedgerConflict => Self::LedgerConflict,
            Self::DirectoryUnavailable(_) => {
                Self::DirectoryUnavailable(io::Error::other("the audit directory is unavailable"))
            }
            Self::RecordCreateFailed(_) => Self::RecordCreateFailed(io::Error::other(
                "the local audit record file could not be created",
            )),
            Self::RecordWriteFailed(_) => {
                Self::RecordWriteFailed(io::Error::other("the local audit record write failed"))
            }
            Self::RecordSyncFailed(_) => {
                Self::RecordSyncFailed(io::Error::other("the local audit record sync failed"))
            }
            Self::ProtocolUnsupported(message) => Self::ProtocolUnsupported(message),
            Self::HandshakeInvalid => Self::HandshakeInvalid,
            Self::SessionBindingMismatch => Self::SessionBindingMismatch,
            Self::CheckpointMismatch => Self::CheckpointMismatch,
            Self::PeerSignatureInvalid => Self::PeerSignatureInvalid,
            Self::FinalManifestMismatch => Self::FinalManifestMismatch,
            Self::LedgerCommitFailed => Self::LedgerCommitFailed,
            Self::ReplayUnsafe => Self::ReplayUnsafe,
            Self::ContainerInvalid => Self::ContainerInvalid,
            Self::Protocol(error) => Self::Protocol(*error),
            Self::Substream(_) => {
                Self::Substream(io::Error::other("the audit substream I/O failed"))
            }
            Self::SegmentTooLarge => Self::SegmentTooLarge,
            Self::InvalidState(message) => Self::InvalidState(message),
            Self::FailedClosed => Self::FailedClosed,
            Self::WriterTerminated => Self::WriterTerminated,
        }
    }
}

// ---------------------------------------------------------------------------
// Injected dependencies
// ---------------------------------------------------------------------------

/// The local persistent audit identity (design section 9). The integration
/// layer supplies the implementation (`audit::identity`); the session only
/// signs handshake, header, seal and ledger commit inputs with it.
pub trait PersistentIdentity: Send {
    /// The persistent Ed25519 public key.
    fn public_key(&self) -> Ed25519PublicKey;
    /// The SHA-256 fingerprint of the persistent public key.
    fn fingerprint(&self) -> IdentityFingerprint;
    /// Signs one canonical signing input with the persistent identity.
    fn sign(&self, input: &[u8]) -> Result<Ed25519Signature, AuditError>;
}

/// The local audit ledger (design section 12). The integration layer
/// supplies the implementation (`audit::ledger`); the session reads the
/// session-start snapshot and drives one serialized final commit.
pub trait Ledger: Send {
    /// The local ledger head at session start: sequence and root, without
    /// the cross-process lock (design section 12.2: this is only the
    /// "session start snapshot" carried by the `AuditHello`).
    fn snapshot(&self) -> Result<(u64, LedgerRoot), AuditError>;
    /// Acquires the cross-process `ledger.lock`, recovers the single
    /// pending committed record and reads the latest ledger head, returning
    /// the sequence and previous root the final commit must use (design
    /// section 12.2: the final commit always chains from the latest head
    /// under the lock, never from the session-start snapshot).
    fn begin_commit(&mut self) -> Result<(u64, LedgerRoot), AuditError>;
    /// Appends the signed commit and atomically advances `ledger.state`,
    /// synchronizing the ledger file and its parent directory, then
    /// releases the lock (design sections 12.2 and 12.3). Must follow
    /// [`Ledger::begin_commit`] on the same lock acquisition.
    fn finish_commit(&mut self, commit: &LedgerCommit) -> Result<(), AuditError>;
}

/// Digests fixed by the durable footer prefix before the serialized ledger
/// transaction begins. This value is small, copyable, and contains no
/// terminal content or secret material.
#[derive(Debug, Clone, Copy)]
pub struct PendingLedgerCommit {
    manifest_digest: Digest32,
    sealed_record_digest: Digest32,
}

// ---------------------------------------------------------------------------
// Secrets
// ---------------------------------------------------------------------------

/// The session-private input commitment key derived by HKDF-SHA-256
/// (design section 5.3). It is never persisted and never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct InputCommitmentKey([u8; DIGEST_LEN]);

impl InputCommitmentKey {
    /// The key bytes, for the HMAC computation only.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for InputCommitmentKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("InputCommitmentKey([REDACTED])")
    }
}

/// The source of the HKDF input key material for the input commitment key
/// (design section 5.3).
#[derive(Debug, Clone, Copy)]
pub enum ConnectionSecret<'a> {
    /// The preferred form: an authenticated secret exportable from the
    /// existing authenticated end-to-end connection is the HKDF input key
    /// material; the two secret contributions form the HKDF salt and the
    /// context is the fixed label plus the session ID.
    Authenticated(&'a [u8]),
    /// The fallback when the connection cannot export an authenticated
    /// secret: the two secret contributions form the input key material and
    /// the authenticated connection binding, both nonces and the session ID
    /// are placed into the HKDF context.
    NotExportable,
}

// ---------------------------------------------------------------------------
// Record batches
// ---------------------------------------------------------------------------

/// One encoded record payload ready for container framing. Payloads are
/// carried in a session-owned stack buffer, a box (rare, long file paths),
/// or split into a small fixed prefix and a borrowed raw body to avoid
/// copying terminal output bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Payload<'a> {
    /// A fixed-size payload in a stack buffer.
    Inline {
        /// The payload bytes.
        bytes: [u8; MAX_INLINE_PAYLOAD_LEN],
        /// The used length.
        len: usize,
    },
    /// A heap payload (shared file transfer records and local file paths).
    Boxed(Box<[u8]>),
    /// A payload written as a small fixed prefix (monotonic time and the
    /// related shared event hash) followed by a borrowed raw output or
    /// display body.
    Split {
        /// The fixed prefix bytes.
        prefix: [u8; SPLIT_PREFIX_LEN],
        /// The raw body, up to [`MAX_LOCAL_OUTPUT_SEGMENT`] bytes.
        body: &'a [u8],
    },
}

impl Payload<'_> {
    /// The total payload byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Inline { len, .. } => *len,
            Self::Boxed(bytes) => bytes.len(),
            Self::Split { body, .. } => SPLIT_PREFIX_LEN + body.len(),
        }
    }

    /// Whether the payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// One encoded record: the container record type plus the payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedRecord<'a> {
    /// The container record type (design section 23.3).
    pub record_type: RecordType,
    /// The record payload.
    pub payload: Payload<'a>,
}

/// The records produced by one recording step, in append order: local
/// observation records first, then the shared blocks they completed
/// (design section 16.1). The caller persists the whole batch through the
/// bounded writer before producing the corresponding external effect.
#[derive(Debug)]
pub struct RecordBatch<'a> {
    records: [Option<EncodedRecord<'a>>; MAX_RECORDS_PER_STEP],
    len: usize,
}

impl<'a> RecordBatch<'a> {
    /// An empty batch.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: [const { None }; MAX_RECORDS_PER_STEP],
            len: 0,
        }
    }

    /// The number of records in the batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the batch is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Iterates the records in append order.
    pub fn iter(&self) -> impl Iterator<Item = &EncodedRecord<'a>> {
        self.records[..self.len].iter().map(|record| {
            record
                .as_ref()
                .expect("every slot below the batch length is filled")
        })
    }

    fn push_inline(&mut self, record_type: RecordType, payload: &[u8]) -> Result<(), AuditError> {
        if payload.len() > MAX_INLINE_PAYLOAD_LEN {
            return Err(AuditError::InvalidState(
                "record payload exceeds the inline bound",
            ));
        }
        let mut bytes = [0_u8; MAX_INLINE_PAYLOAD_LEN];
        bytes[..payload.len()].copy_from_slice(payload);
        self.push(EncodedRecord {
            record_type,
            payload: Payload::Inline {
                bytes,
                len: payload.len(),
            },
        })
    }

    fn push_boxed(
        &mut self,
        record_type: RecordType,
        payload: Box<[u8]>,
    ) -> Result<(), AuditError> {
        self.push(EncodedRecord {
            record_type,
            payload: Payload::Boxed(payload),
        })
    }

    fn push_split<'b>(
        &mut self,
        record_type: RecordType,
        prefix: &[u8; SPLIT_PREFIX_LEN],
        body: &'b [u8],
    ) -> Result<(), AuditError>
    where
        'b: 'a,
    {
        self.push(EncodedRecord {
            record_type,
            payload: Payload::Split {
                prefix: *prefix,
                body,
            },
        })
    }

    fn push(&mut self, record: EncodedRecord<'a>) -> Result<(), AuditError> {
        if self.len >= MAX_RECORDS_PER_STEP {
            return Err(AuditError::InvalidState(
                "a recording step exceeded the record batch bound",
            ));
        }
        self.records[self.len] = Some(record);
        self.len += 1;
        Ok(())
    }
}

impl Default for RecordBatch<'_> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Byte-stream normalizers
// ---------------------------------------------------------------------------

/// A canonical byte-stream normalizer (design section 16.1): bytes are
/// appended in stream order and every full 16 KiB forms one shared block.
/// The direction close finalizes the trailing partial block. The buffer is
/// fixed at 16 KiB and lives only in memory until its block completes.
#[derive(Debug)]
pub struct Normalizer {
    buffer: [u8; CANONICAL_BLOCK_LEN],
    len: usize,
    closed: bool,
}

impl Normalizer {
    /// A fresh empty normalizer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            buffer: [0; CANONICAL_BLOCK_LEN],
            len: 0,
            closed: false,
        }
    }

    /// The number of buffered partial bytes.
    #[must_use]
    pub const fn partial_len(&self) -> usize {
        self.len
    }

    /// Appends a segment in stream order, invoking `on_block` for every
    /// completed 16 KiB block. The callback receives the exact block bytes.
    pub fn feed(
        &mut self,
        bytes: &[u8],
        mut on_block: impl FnMut(&[u8; CANONICAL_BLOCK_LEN]),
    ) -> Result<(), AuditError> {
        if self.closed {
            return Err(AuditError::InvalidState(
                "the canonical stream is already closed",
            ));
        }
        if bytes.len() >= CANONICAL_BLOCK_LEN {
            // Fill the current partial block first, then emit whole blocks
            // directly from the segment.
            if self.len > 0 {
                let take = CANONICAL_BLOCK_LEN - self.len;
                self.buffer[self.len..CANONICAL_BLOCK_LEN].copy_from_slice(&bytes[..take]);
                on_block(&self.buffer);
                self.len = 0;
                let rest = &bytes[take..];
                let whole = rest.len() / CANONICAL_BLOCK_LEN;
                for index in 0..whole {
                    let start = index * CANONICAL_BLOCK_LEN;
                    let block: &[u8; CANONICAL_BLOCK_LEN] = rest
                        [start..start + CANONICAL_BLOCK_LEN]
                        .try_into()
                        .expect("exact canonical block slice");
                    on_block(block);
                }
                let tail = rest.len() % CANONICAL_BLOCK_LEN;
                self.buffer[..tail].copy_from_slice(&rest[whole * CANONICAL_BLOCK_LEN..]);
                self.len = tail;
            } else {
                let whole = bytes.len() / CANONICAL_BLOCK_LEN;
                for index in 0..whole {
                    let start = index * CANONICAL_BLOCK_LEN;
                    let block: &[u8; CANONICAL_BLOCK_LEN] = bytes
                        [start..start + CANONICAL_BLOCK_LEN]
                        .try_into()
                        .expect("exact canonical block slice");
                    on_block(block);
                }
                let tail = bytes.len() % CANONICAL_BLOCK_LEN;
                self.buffer[..tail].copy_from_slice(&bytes[whole * CANONICAL_BLOCK_LEN..]);
                self.len = tail;
            }
        } else if bytes.len() + self.len >= CANONICAL_BLOCK_LEN {
            let take = CANONICAL_BLOCK_LEN - self.len;
            self.buffer[self.len..CANONICAL_BLOCK_LEN].copy_from_slice(&bytes[..take]);
            on_block(&self.buffer);
            let tail = bytes.len() - take;
            self.buffer[..tail].copy_from_slice(&bytes[take..]);
            self.len = tail;
        } else {
            self.buffer[self.len..self.len + bytes.len()].copy_from_slice(bytes);
            self.len += bytes.len();
        }
        Ok(())
    }

    /// Closes the direction, invoking `on_block` with the exact partial
    /// bytes when the stream is non-empty (design section 16.1: "empty
    /// directions produce no blocks"). Returns whether a final block was
    /// emitted.
    pub fn finish(&mut self, mut on_block: impl FnMut(&[u8])) -> Result<bool, AuditError> {
        if self.closed {
            return Err(AuditError::InvalidState(
                "the canonical stream is already closed",
            ));
        }
        self.closed = true;
        if self.len == 0 {
            return Ok(false);
        }
        let partial = self.len;
        on_block(&self.buffer[..partial]);
        self.len = 0;
        Ok(true)
    }
}

impl Default for Normalizer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

fn append(destination: &mut [u8], cursor: &mut usize, source: &[u8]) {
    let end = *cursor + source.len();
    destination[*cursor..end].copy_from_slice(source);
    *cursor = end;
}

fn write_u64(destination: &mut [u8], cursor: &mut usize, value: u64) {
    append(destination, cursor, &value.to_be_bytes());
}

fn write_u32(destination: &mut [u8], cursor: &mut usize, value: u32) {
    append(destination, cursor, &value.to_be_bytes());
}

fn write_u16(destination: &mut [u8], cursor: &mut usize, value: u16) {
    append(destination, cursor, &value.to_be_bytes());
}

fn sha256_32(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// The shared chain event hash (design section 17.1).
fn shared_event_hash(
    domain: &[u8],
    previous: &[u8; DIGEST_LEN],
    stream_kind: u8,
    direction: u8,
    sequence: u64,
    event_kind: u8,
    canonical_payload: &[u8],
) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(previous);
    hasher.update([stream_kind]);
    hasher.update([direction]);
    hasher.update(sequence.to_be_bytes());
    hasher.update([event_kind]);
    hasher.update(canonical_payload);
    hasher.finalize().into()
}

/// The local chain event hash (design section 17.2).
fn local_event_hash(
    previous: &[u8; DIGEST_LEN],
    local_sequence: u64,
    time_ns: u64,
    event_kind: u8,
    kind_payload: &[u8],
    related: &[u8; DIGEST_LEN],
) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(CHAIN_LOCAL_DOMAIN);
    hasher.update(previous);
    hasher.update(local_sequence.to_be_bytes());
    hasher.update(time_ns.to_be_bytes());
    hasher.update([event_kind]);
    hasher.update(kind_payload);
    hasher.update(related);
    hasher.finalize().into()
}

/// The zero chain head, the initial head of every chain.
pub fn zero_head() -> ChainHead {
    ChainHead::new([0; DIGEST_LEN])
}

/// Builds one shared input commitment block record and its chain head
/// (design section 16.2). `canonical_payload` is `length || hmac`.
fn build_input_block(
    key: &InputCommitmentKey,
    direction: u8,
    sequence: u64,
    length: u64,
    block: &[u8],
    previous: ChainHead,
) -> ([u8; SHARED_INPUT_RECORD_LEN], ChainHead) {
    // HMAC-SHA-256(key, chain_domain || direction || sequence || length ||
    // block), design section 5.4.
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .expect("a 32-byte key is always a valid HMAC key");
    mac.update(CHAIN_INPUT_DOMAIN);
    mac.update(&[direction]);
    mac.update(&sequence.to_be_bytes());
    mac.update(&length.to_be_bytes());
    mac.update(block);
    let hmac = mac.finalize().into_bytes();

    let mut canonical = [0_u8; 8 + 32];
    let mut cursor = 0;
    write_u64(&mut canonical, &mut cursor, length);
    append(&mut canonical, &mut cursor, hmac.as_slice());
    let head = shared_event_hash(
        CHAIN_INPUT_DOMAIN,
        previous.as_bytes(),
        SharedStream::Input.index() as u8,
        direction,
        sequence,
        INPUT_EVENT_KIND,
        &canonical,
    );

    let mut payload = [0_u8; SHARED_INPUT_RECORD_LEN];
    let mut cursor = 0;
    append(&mut payload, &mut cursor, &[direction]);
    write_u64(&mut payload, &mut cursor, sequence);
    write_u64(&mut payload, &mut cursor, length);
    append(&mut payload, &mut cursor, hmac.as_slice());
    append(&mut payload, &mut cursor, previous.as_bytes());
    append(&mut payload, &mut cursor, &head);
    (payload, ChainHead::new(head))
}

/// Builds one shared output block record and its chain head (design
/// section 16.3). `canonical_payload` is `length || sha256`.
fn build_output_block(
    direction: u8,
    sequence: u64,
    length: u64,
    digest: [u8; DIGEST_LEN],
    previous: ChainHead,
) -> ([u8; SHARED_OUTPUT_RECORD_LEN], ChainHead) {
    let mut canonical = [0_u8; 8 + 32];
    let mut cursor = 0;
    write_u64(&mut canonical, &mut cursor, length);
    append(&mut canonical, &mut cursor, &digest);
    let head = shared_event_hash(
        CHAIN_OUTPUT_DOMAIN,
        previous.as_bytes(),
        SharedStream::Output.index() as u8,
        direction,
        sequence,
        OUTPUT_EVENT_KIND,
        &canonical,
    );

    let mut payload = [0_u8; SHARED_OUTPUT_RECORD_LEN];
    let mut cursor = 0;
    append(&mut payload, &mut cursor, &[direction]);
    write_u64(&mut payload, &mut cursor, sequence);
    write_u64(&mut payload, &mut cursor, length);
    append(&mut payload, &mut cursor, &digest);
    append(&mut payload, &mut cursor, previous.as_bytes());
    append(&mut payload, &mut cursor, &head);
    (payload, ChainHead::new(head))
}

/// A completed canonical block in the shared input or output stream.
#[derive(Clone, Copy)]
struct CompletedBlock {
    /// The record payload, exactly [`SHARED_INPUT_RECORD_LEN`] bytes (the
    /// input and output payloads share the same fixed length).
    payload: [u8; SHARED_INPUT_RECORD_LEN],
    /// The new chain head (the event hash).
    head: ChainHead,
}

/// The maximum number of completed blocks one segment can produce: a
/// 64 KiB segment fits four 16 KiB blocks exactly.
const MAX_BLOCKS_PER_SEGMENT: usize = 4;

/// Collects the completed blocks of one segment into a stack array.
struct BlockCollector {
    blocks: [Option<CompletedBlock>; MAX_BLOCKS_PER_SEGMENT],
    len: usize,
}

impl BlockCollector {
    const fn new() -> Self {
        Self {
            blocks: [const { None }; MAX_BLOCKS_PER_SEGMENT],
            len: 0,
        }
    }

    fn push(&mut self, block: CompletedBlock) -> Result<(), AuditError> {
        if self.len >= MAX_BLOCKS_PER_SEGMENT {
            return Err(AuditError::InvalidState(
                "a segment completed more than four canonical blocks",
            ));
        }
        self.blocks[self.len] = Some(block);
        self.len += 1;
        Ok(())
    }

    fn last_head(&self) -> Option<ChainHead> {
        self.blocks[self.len.saturating_sub(1)].map(|block| block.head)
    }
}

// ---------------------------------------------------------------------------
// Session phases
// ---------------------------------------------------------------------------

/// The session lifecycle phases. Recordings are only possible while
/// `Active`; finalization proceeds through `Finalizing` to `Finished`;
/// every failure path lands in `Failed` (design sections 13, 18 and 21).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Local `AuditHello` built; waiting for the peer hello.
    Fresh,
    /// Peer hello and contribution verified; ready to derive the session
    /// ID and the input commitment key.
    Handshake,
    /// Session ID and key derived, `AuditReady` built; waiting for the peer
    /// ready.
    Ready,
    /// Handshake complete; recording and checkpoints are possible.
    Active,
    /// Directions closed; finalization exchanges in progress.
    Finalizing,
    /// The record was fully finalized and committed to the ledger.
    Finished,
    /// The session failed closed; no further operations.
    Failed,
}

/// Whether a received checkpoint is an asynchronously delivered running
/// observation or the exact shared prefix after the closing barrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckpointPolicy {
    Observation,
    ExactPrefix,
}

// ---------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------

/// One per-stream shared chain: event count and chain head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SharedChain {
    count: u64,
    head: ChainHead,
}

/// The verifiable session audit state machine (design sections 5, 13,
/// 15-18, 20, 21 and 12.3). Sync except for the final footer flow which
/// drives the async writer and ledger. `Debug` is redacted: secrets never
/// print.
pub struct AuditSession {
    role: AuditRole,
    identity: Box<dyn PersistentIdentity>,
    ledger: Box<dyn Ledger>,
    // Handshake facts.
    ledger_sequence: u64,
    ledger_root: LedgerRoot,
    ledger_snapshot_digest: Digest32,
    session_key: SigningKey,
    session_pubkey: Ed25519PublicKey,
    nonce: AuditNonce,
    contribution: SecretContribution,
    commitment: CommitmentDigest,
    binding: BindingDigest,
    hello: AuditHello,
    peer_hello: Option<AuditHello>,
    peer_contribution: Option<SecretContribution>,
    peer_fingerprint: Option<IdentityFingerprint>,
    session_id: Option<SessionId>,
    input_key: Option<InputCommitmentKey>,
    ready: Option<AuditReady>,
    peer_ready: Option<AuditReady>,
    // Session facts for the header and the manifest.
    terminal_hello_digest: Option<Digest32>,
    utc_start_seconds: u64,
    // Chains.
    shared: [SharedChain; SHARED_STREAMS],
    local_head: ChainHead,
    local_count: u64,
    normalizers: [Normalizer; 2],
    last_block: [Option<ChainHead>; SHARED_STREAMS],
    // Checkpoints.
    next_checkpoint_sequence: u64,
    last_checkpoint_time_ns: u64,
    last_confirmed_sent_checkpoint_sequence: u64,
    last_confirmed_received_checkpoint_sequence: u64,
    last_received_checkpoint: Option<(u64, Digest32)>,
    last_sent_checkpoint: Option<Checkpoint>,
    checkpoint_shared_bytes: u64,
    checkpoint_due_flag: bool,
    // Finalization.
    peer_manifest_received: bool,
    phase: Phase,
}

impl AuditSession {
    /// Builds a fresh session: the local ephemeral Ed25519 session key
    /// (design section 9.3), the nonce and the input commitment secret
    /// contribution (design section 13.3), the session-start ledger
    /// snapshot (design section 12.2) and the signed local `AuditHello`.
    ///
    /// The 32-byte nonce, the 32-byte secret contribution and the ephemeral
    /// session seed all come from the injected secure random source.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: AuditRole,
        identity: Box<dyn PersistentIdentity>,
        ledger: Box<dyn Ledger>,
        binding: BindingDigest,
        utc_start_seconds: u64,
        random: &mut impl SecureRandom,
    ) -> Result<Self, AuditError> {
        let mut nonce = [0_u8; NONCE_LEN];
        random.try_fill(&mut nonce)?;
        let mut contribution_bytes = [0_u8; SECRET_CONTRIBUTION_LEN];
        random.try_fill(&mut contribution_bytes)?;
        let mut session_seed = [0_u8; 32];
        random.try_fill(&mut session_seed)?;
        let session_key = SigningKey::from_bytes(&session_seed);
        session_seed.zeroize();

        let (ledger_sequence, ledger_root) = ledger.snapshot()?;
        let mut snapshot_bytes = [0_u8; 8 + DIGEST_LEN];
        let mut cursor = 0;
        write_u64(&mut snapshot_bytes, &mut cursor, ledger_sequence);
        append(&mut snapshot_bytes, &mut cursor, ledger_root.as_bytes());
        let ledger_snapshot_digest = Digest32::new(sha256_32(&snapshot_bytes));

        let contribution = SecretContribution::new(contribution_bytes);
        let commitment = CommitmentDigest::new(sha256_32(contribution.as_bytes()));
        let session_pubkey = Ed25519PublicKey::new(session_key.verifying_key().to_bytes());

        let hello = AuditHello::new(
            role,
            identity.public_key(),
            session_pubkey,
            AuditNonce::new(nonce),
            ledger_sequence,
            ledger_root,
            binding,
            AUDIT_FORMAT_VERSION,
            commitment,
            Ed25519Signature::new([0; ED25519_SIGNATURE_LEN]),
        );
        let signature = identity.sign(hello.signing_input().as_slice())?;
        let hello = hello.with_signature(signature);

        Ok(Self {
            role,
            identity,
            ledger,
            ledger_sequence,
            ledger_root,
            ledger_snapshot_digest,
            session_key,
            session_pubkey,
            nonce: AuditNonce::new(nonce),
            contribution,
            commitment,
            binding,
            hello,
            peer_hello: None,
            peer_contribution: None,
            peer_fingerprint: None,
            session_id: None,
            input_key: None,
            ready: None,
            peer_ready: None,
            terminal_hello_digest: None,
            utc_start_seconds,
            shared: [SharedChain {
                count: 0,
                head: zero_head(),
            }; SHARED_STREAMS],
            local_head: zero_head(),
            local_count: 0,
            normalizers: [Normalizer::new(), Normalizer::new()],
            last_block: [None; SHARED_STREAMS],
            next_checkpoint_sequence: 1,
            last_checkpoint_time_ns: 0,
            last_confirmed_sent_checkpoint_sequence: 0,
            last_confirmed_received_checkpoint_sequence: 0,
            last_received_checkpoint: None,
            last_sent_checkpoint: None,
            checkpoint_shared_bytes: 0,
            checkpoint_due_flag: false,
            peer_manifest_received: false,
            phase: Phase::Fresh,
        })
    }

    /// The local role.
    #[must_use]
    pub const fn role(&self) -> AuditRole {
        self.role
    }

    /// The signed local `AuditHello` to send first (design section 13.3).
    #[must_use]
    pub fn local_hello(&self) -> &AuditHello {
        &self.hello
    }

    /// The raw 32-byte input commitment secret contribution to send second
    /// (design section 13.3). The contribution itself is never persisted.
    #[must_use]
    pub fn local_contribution(&self) -> &SecretContribution {
        &self.contribution
    }

    /// The computed session ID, once the handshake derived it
    /// (design section 13.4).
    #[must_use]
    pub fn session_id(&self) -> Option<SessionId> {
        self.session_id
    }

    /// The derived session-private input commitment key, once computed
    /// (design section 5.3).
    #[must_use]
    pub fn input_key(&self) -> Option<&InputCommitmentKey> {
        self.input_key.as_ref()
    }

    /// The current local observation chain head.
    #[must_use]
    pub const fn local_chain_head(&self) -> ChainHead {
        self.local_head
    }

    /// The current local observation event count.
    #[must_use]
    pub const fn local_event_count(&self) -> u64 {
        self.local_count
    }

    /// The current shared chain snapshot: counts and heads of all four
    /// streams.
    #[must_use]
    pub fn shared_snapshot(&self) -> SharedSnapshot {
        SharedSnapshot::new(
            self.shared
                .map(|chain| StreamSnapshot::new(chain.count, chain.head)),
        )
    }

    /// The greatest sequence confirmed in either independent direction, or
    /// zero when no checkpoint was confirmed. The manifest retains this
    /// compact wire summary; sent and received confirmation state remains
    /// separate internally.
    #[must_use]
    pub const fn last_confirmed_checkpoint_sequence(&self) -> u64 {
        if self.last_confirmed_sent_checkpoint_sequence
            >= self.last_confirmed_received_checkpoint_sequence
        {
            self.last_confirmed_sent_checkpoint_sequence
        } else {
            self.last_confirmed_received_checkpoint_sequence
        }
    }

    /// Whether the handshake completed (design section 13.5): the session
    /// may only enter Terminal Active after this is true.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.phase == Phase::Active
    }

    /// Whether the session failed closed.
    #[must_use]
    pub fn has_failed(&self) -> bool {
        self.phase == Phase::Failed
    }

    // -----------------------------------------------------------------
    // Handshake (design section 13)
    // -----------------------------------------------------------------

    /// Verifies the peer `AuditHello` and the raw secret contribution
    /// (design section 13.3): the role must be the other role, the
    /// authenticated connection binding must match, the offered format must
    /// be supported, the persistent identity signature must verify and the
    /// contribution's SHA-256 must equal the signed commitment.
    pub fn receive_peer_hello(
        &mut self,
        hello: &AuditHello,
        contribution: &SecretContribution,
    ) -> Result<(), AuditError> {
        self.require_phase(Phase::Fresh)?;
        if hello.role() == self.role {
            return Err(AuditError::HandshakeInvalid);
        }
        if hello.connection_binding() != &self.binding {
            return Err(AuditError::SessionBindingMismatch);
        }
        if hello.format_version() != AUDIT_FORMAT_VERSION {
            return Err(AuditError::HandshakeInvalid);
        }
        verify_signature(
            hello.persistent_audit_key(),
            hello.signing_input().as_slice(),
            hello.signature(),
        )?;
        let commitment = sha256_32(contribution.as_bytes());
        if commitment != *hello.input_commitment().as_bytes() {
            return Err(AuditError::HandshakeInvalid);
        }
        self.peer_hello = Some(*hello);
        self.peer_contribution = Some(contribution.clone());
        self.peer_fingerprint = Some(IdentityFingerprint::new(sha256_32(
            hello.persistent_audit_key().as_bytes(),
        )));
        self.phase = Phase::Handshake;
        Ok(())
    }

    /// Computes the session ID (design section 13.4), derives the
    /// session-private input commitment key (design section 5.3) and builds
    /// the signed local `AuditReady` (design section 13.5). Must follow
    /// [`AuditSession::receive_peer_hello`].
    pub fn compute_ready(
        &mut self,
        connection_secret: ConnectionSecret<'_>,
    ) -> Result<AuditReady, AuditError> {
        self.require_phase(Phase::Handshake)?;
        let peer = self
            .peer_hello
            .as_ref()
            .ok_or(AuditError::InvalidState("peer hello not received"))?;
        let session_id = self.compute_session_id();
        let key = derive_input_commitment_key(
            connection_secret,
            self.controller_contribution(),
            self.host_contribution(),
            self.binding,
            self.controller_nonce(),
            self.host_nonce(),
            session_id,
        );
        let peer_digest = Digest32::new(sha256_32(peer.encode_payload().as_slice()));
        let ready = AuditReady::new(
            session_id,
            peer_digest,
            AUDIT_FORMAT_VERSION,
            Ed25519Signature::new([0; ED25519_SIGNATURE_LEN]),
        );
        let signature = self.sign_with_session_key(ready.signing_input().as_slice());
        let ready = ready.with_signature(signature);
        self.session_id = Some(session_id);
        self.input_key = Some(key);
        self.ready = Some(ready);
        self.phase = Phase::Ready;
        Ok(ready)
    }

    /// Builds the signed container header embedding the local `AuditHello`
    /// and `AuditReady` (design sections 23.2 and 13.5). The integration
    /// writes and syncs it through the writer before sending `AuditReady`.
    pub fn build_header(
        &mut self,
        ready: &AuditReady,
        terminal_hello_digest: Digest32,
    ) -> Result<AuditContainerHeader, AuditError> {
        self.require_phase(Phase::Ready)?;
        let session_id = self
            .session_id
            .ok_or(AuditError::InvalidState("session ID not computed"))?;
        let peer = self
            .peer_hello
            .as_ref()
            .ok_or(AuditError::InvalidState("peer hello not received"))?;
        let header = AuditContainerHeader::new(
            self.role,
            session_id,
            self.identity.public_key(),
            self.session_pubkey,
            *peer.persistent_audit_key(),
            *peer.session_key(),
            self.ledger_sequence,
            self.ledger_root,
            self.utc_start_seconds,
            AuthMode::Enterprise,
            terminal_hello_digest,
            self.hello,
            *ready,
        );
        let signature = self.identity.sign(header.signing_input().as_slice())?;
        let header = header.with_header_signature(signature);
        self.terminal_hello_digest = Some(terminal_hello_digest);
        Ok(header)
    }

    /// Verifies the peer `AuditReady` (design section 13.5): the session
    /// ID, the digest of our own `AuditHello`, the format agreement and the
    /// ephemeral session signature must all match. Only after this returns
    /// successfully may the terminal become active.
    pub fn receive_peer_ready(&mut self, ready: &AuditReady) -> Result<(), AuditError> {
        self.require_phase(Phase::Ready)?;
        let session_id = self
            .session_id
            .ok_or(AuditError::InvalidState("session ID not computed"))?;
        if *ready.session_id() != session_id {
            return Err(AuditError::HandshakeInvalid);
        }
        let own_hello_digest = Digest32::new(sha256_32(self.hello.encode_payload().as_slice()));
        if *ready.peer_audit_hello_digest() != own_hello_digest {
            return Err(AuditError::HandshakeInvalid);
        }
        if ready.format_version() != AUDIT_FORMAT_VERSION {
            return Err(AuditError::HandshakeInvalid);
        }
        let peer = self
            .peer_hello
            .as_ref()
            .ok_or(AuditError::InvalidState("peer hello not received"))?;
        verify_signature(
            peer.session_key(),
            ready.signing_input().as_slice(),
            ready.signature(),
        )?;
        self.peer_ready = Some(*ready);
        self.phase = Phase::Active;
        Ok(())
    }

    // -----------------------------------------------------------------
    // Recording (design sections 15-18)
    // -----------------------------------------------------------------

    /// Design sections 18.1 and 18.2: one controller input send step or
    /// one host input receive step. Appends the local input commitment
    /// event, feeds the canonical input stream and returns the completed
    /// shared input block records. The external effect (sending the bytes
    /// or writing them to the PTY) may only happen after the whole batch
    /// was persisted.
    pub fn record_input<'a>(
        &mut self,
        bytes: &'a [u8],
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        self.require_recordable()?;
        if bytes.len() > MAX_INPUT_SEGMENT {
            return Err(AuditError::SegmentTooLarge);
        }
        if bytes.is_empty() {
            return Ok(RecordBatch::new());
        }
        let mut batch = RecordBatch::new();
        let stream_index = SharedStream::Input.index();
        let key = self
            .input_key
            .as_ref()
            .ok_or(AuditError::InvalidState("input commitment key not derived"))?;
        let chain = &mut self.shared[stream_index];
        let normalizer = &mut self.normalizers[0];
        let last_block = &mut self.last_block[stream_index];
        let checkpoint_bytes = &mut self.checkpoint_shared_bytes;
        let due_flag = &mut self.checkpoint_due_flag;
        let mut completed = BlockCollector::new();
        normalizer.feed(bytes, |block| {
            let length = block.len() as u64;
            let sequence = chain.count + 1;
            let (payload, head) = build_input_block(
                key,
                DIRECTION_CTRL_TO_HOST,
                sequence,
                length,
                block,
                chain.head,
            );
            chain.count += 1;
            chain.head = head;
            *last_block = Some(head);
            *checkpoint_bytes += length;
            if *checkpoint_bytes >= CHECKPOINT_SIZE_TRIGGER {
                *due_flag = true;
            }
            completed
                .push(CompletedBlock { payload, head })
                .expect("an input segment completes at most four blocks");
        })?;
        let related = completed.last_head().unwrap_or(zero_head());
        let mut kind_payload = [0_u8; 1 + 8];
        let mut cursor = 0;
        append(&mut kind_payload, &mut cursor, &[DIRECTION_CTRL_TO_HOST]);
        write_u64(&mut kind_payload, &mut cursor, bytes.len() as u64);
        self.push_local(
            &mut batch,
            RecordType::LocalInputCommitment,
            &kind_payload,
            related,
            now_ns,
        )?;
        for index in 0..completed.len {
            let block = completed.blocks[index].as_ref().expect("filled block slot");
            batch.push_inline(RecordType::SharedInputCommitment, &block.payload)?;
        }
        Ok(batch)
    }

    /// Design sections 18.3 and 18.4: one host PTY output read step or one
    /// controller raw network receive step. Appends the local raw-output
    /// record (the full bytes, for replay), feeds the canonical output
    /// stream and returns the completed shared output block records. The
    /// external effect (sending or displaying) may only happen after the
    /// whole batch was persisted.
    pub fn record_output<'a>(
        &mut self,
        bytes: &'a [u8],
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        self.record_output_step(bytes, now_ns, None)
    }

    /// Design section 18.4: the controller variant of an output receive
    /// step. The raw bytes feed the canonical output stream and the
    /// display bytes (after the platform output adapter) are recorded as a
    /// local-only display-bytes record in the same batch, in the file order
    /// raw record, completed shared blocks, display record. The display
    /// write effect may only happen after the whole batch was persisted.
    pub fn record_controller_output<'a>(
        &mut self,
        raw: &'a [u8],
        display: &'a [u8],
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        self.record_output_step(raw, now_ns, Some(display))
    }

    fn record_output_step<'a>(
        &mut self,
        bytes: &'a [u8],
        now_ns: u64,
        display: Option<&'a [u8]>,
    ) -> Result<RecordBatch<'a>, AuditError> {
        self.require_recordable()?;
        if bytes.len() > MAX_LOCAL_OUTPUT_SEGMENT
            || display.is_some_and(|display| display.len() > MAX_LOCAL_OUTPUT_SEGMENT)
        {
            return Err(AuditError::SegmentTooLarge);
        }
        let mut batch = RecordBatch::new();
        let stream_index = SharedStream::Output.index();
        let chain = &mut self.shared[stream_index];
        let normalizer = &mut self.normalizers[1];
        let last_block = &mut self.last_block[stream_index];
        let checkpoint_bytes = &mut self.checkpoint_shared_bytes;
        let due_flag = &mut self.checkpoint_due_flag;
        let mut completed = BlockCollector::new();
        normalizer.feed(bytes, |block| {
            let length = block.len() as u64;
            let sequence = chain.count + 1;
            let digest = sha256_32(block);
            let (payload, head) =
                build_output_block(DIRECTION_HOST_TO_CTRL, sequence, length, digest, chain.head);
            chain.count += 1;
            chain.head = head;
            *last_block = Some(head);
            *checkpoint_bytes += length;
            if *checkpoint_bytes >= CHECKPOINT_SIZE_TRIGGER {
                *due_flag = true;
            }
            completed
                .push(CompletedBlock { payload, head })
                .expect("an output segment completes at most four blocks");
        })?;
        let related = completed.last_head().unwrap_or(zero_head());
        // The local raw-output record advances the local chain over the
        // full raw bytes, then the borrowed body is framed.
        self.commit_local(RecordType::LocalRawOutput, bytes, &related, now_ns);
        let prefix = self.local_prefix(now_ns, &related);
        batch.push_split(RecordType::LocalRawOutput, &prefix, bytes)?;
        for index in 0..completed.len {
            let block = completed.blocks[index].as_ref().expect("filled block slot");
            batch.push_inline(RecordType::SharedOutputBlock, &block.payload)?;
        }
        if let Some(display) = display {
            self.commit_local(RecordType::LocalDisplayBytes, display, &related, now_ns);
            batch.push_split(RecordType::LocalDisplayBytes, &prefix, display)?;
        }
        Ok(batch)
    }

    /// Design section 18.4: the controller records the display bytes after
    /// the platform output adapter, when the raw and display steps are
    /// driven separately. The record relates to the block the preceding
    /// raw segment completed; call it immediately after
    /// [`AuditSession::record_output`] for the same segment.
    pub fn record_display_bytes<'a>(
        &mut self,
        display: &'a [u8],
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        self.require_recordable()?;
        if display.len() > MAX_LOCAL_OUTPUT_SEGMENT {
            return Err(AuditError::SegmentTooLarge);
        }
        let mut batch = RecordBatch::new();
        let related = self.last_block[SharedStream::Output.index()].unwrap_or(zero_head());
        self.commit_local(RecordType::LocalDisplayBytes, display, &related, now_ns);
        let prefix = self.local_prefix(now_ns, &related);
        batch.push_split(RecordType::LocalDisplayBytes, &prefix, display)?;
        Ok(batch)
    }

    /// Design section 18: the local outcome of sending bytes to the
    /// network. `direction` is the flow direction of the bytes. Recorded
    /// after the send effect.
    pub fn record_send_outcome<'a>(
        &mut self,
        direction: u8,
        succeeded: bool,
        bytes: u64,
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        let mut kind_payload = [0_u8; 1 + 1 + 8];
        let mut cursor = 0;
        append(&mut kind_payload, &mut cursor, &[direction]);
        append(&mut kind_payload, &mut cursor, &[outcome_code(succeeded)]);
        write_u64(&mut kind_payload, &mut cursor, bytes);
        self.record_local_only(
            RecordType::LocalSendOutcome,
            &kind_payload,
            self.related_for_direction(direction),
            now_ns,
        )
    }

    /// Design section 18.2: the local outcome of writing bytes to the
    /// PTY/ConPTY. Recorded after the write effect.
    pub fn record_pty_write_outcome<'a>(
        &mut self,
        succeeded: bool,
        bytes: u64,
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        let mut kind_payload = [0_u8; 1 + 8];
        let mut cursor = 0;
        append(&mut kind_payload, &mut cursor, &[outcome_code(succeeded)]);
        write_u64(&mut kind_payload, &mut cursor, bytes);
        self.record_local_only(
            RecordType::LocalPtyWriteOutcome,
            &kind_payload,
            self.last_block[SharedStream::Input.index()].unwrap_or(zero_head()),
            now_ns,
        )
    }

    /// Design section 18.4: the local outcome of writing display bytes to
    /// the local terminal. Recorded after the write effect.
    pub fn record_display_write_outcome<'a>(
        &mut self,
        succeeded: bool,
        bytes: u64,
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        let mut kind_payload = [0_u8; 1 + 8];
        let mut cursor = 0;
        append(&mut kind_payload, &mut cursor, &[outcome_code(succeeded)]);
        write_u64(&mut kind_payload, &mut cursor, bytes);
        self.record_local_only(
            RecordType::LocalDisplayWriteOutcome,
            &kind_payload,
            self.last_block[SharedStream::Output.index()].unwrap_or(zero_head()),
            now_ns,
        )
    }

    /// Design section 18.5: one resize observation. Both sides record the
    /// same shared control event (the resize with the sender's direction)
    /// and a local resize record. The size change effect may only happen
    /// after the batch was persisted.
    pub fn record_resize<'a>(
        &mut self,
        direction: u8,
        cols: u16,
        rows: u16,
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        self.require_recordable()?;
        let mut batch = RecordBatch::new();
        let mut control_payload = [0_u8; 4];
        let mut cursor = 0;
        write_u16(&mut control_payload, &mut cursor, cols);
        write_u16(&mut control_payload, &mut cursor, rows);
        let shared_head = self.commit_shared_control(
            &mut batch,
            direction,
            CONTROL_KIND_RESIZE,
            &control_payload,
        )?;
        let mut kind_payload = [0_u8; 1 + 2 + 2];
        let mut cursor = 0;
        append(&mut kind_payload, &mut cursor, &[direction]);
        write_u16(&mut kind_payload, &mut cursor, cols);
        write_u16(&mut kind_payload, &mut cursor, rows);
        self.push_local(
            &mut batch,
            RecordType::LocalResizeEvent,
            &kind_payload,
            shared_head,
            now_ns,
        )?;
        Ok(batch)
    }

    /// Design section 15.2: the shared `TerminalHello` digest event and the
    /// local lifecycle record.
    pub fn record_terminal_hello<'a>(
        &mut self,
        digest: Digest32,
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        self.record_control_lifecycle(
            CONTROL_KIND_TERMINAL_HELLO,
            LIFECYCLE_KIND_TERMINAL_HELLO,
            DIRECTION_CTRL_TO_HOST,
            digest.as_bytes(),
            now_ns,
        )
    }

    /// Design section 15.2: the shared `TerminalReady` event and the local
    /// lifecycle record.
    pub fn record_terminal_ready<'a>(
        &mut self,
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        self.record_control_lifecycle(
            CONTROL_KIND_TERMINAL_READY,
            LIFECYCLE_KIND_TERMINAL_READY,
            DIRECTION_HOST_TO_CTRL,
            &[],
            now_ns,
        )
    }

    /// Design section 15.2: the shared `TerminalExit` event with the exit
    /// code and the local lifecycle record.
    pub fn record_terminal_exit<'a>(
        &mut self,
        exit_code: u8,
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        self.record_control_lifecycle(
            CONTROL_KIND_TERMINAL_EXIT,
            LIFECYCLE_KIND_TERMINAL_EXIT,
            DIRECTION_HOST_TO_CTRL,
            &[exit_code],
            now_ns,
        )
    }

    /// Design section 15.2: the shared `TerminalComplete` event and the
    /// local lifecycle record.
    pub fn record_terminal_complete<'a>(
        &mut self,
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        self.record_control_lifecycle(
            CONTROL_KIND_TERMINAL_COMPLETE,
            LIFECYCLE_KIND_TERMINAL_COMPLETE,
            DIRECTION_CTRL_TO_HOST,
            &[],
            now_ns,
        )
    }

    /// Design section 15.2: the shared close event, recorded only after the
    /// close reason was successfully conveyed to the peer. Also records the
    /// local close event.
    pub fn record_shared_close_reason<'a>(
        &mut self,
        direction: u8,
        reason: AuditCloseReason,
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        self.require_recordable()?;
        let mut batch = RecordBatch::new();
        let shared_head = self.commit_shared_control(
            &mut batch,
            direction,
            CONTROL_KIND_CLOSE_REASON,
            &[reason.code()],
        )?;
        let mut kind_payload = [0_u8; 2];
        let mut cursor = 0;
        append(&mut kind_payload, &mut cursor, &[reason.code()]);
        append(&mut kind_payload, &mut cursor, &[OUTCOME_OK]);
        self.push_local(
            &mut batch,
            RecordType::LocalCloseEvent,
            &kind_payload,
            shared_head,
            now_ns,
        )?;
        Ok(batch)
    }

    /// Design section 15.3: one local lifecycle observation (hello, ready,
    /// exit, complete, active detach, local interrupt) with the related
    /// shared control event hash.
    pub fn record_local_lifecycle<'a>(
        &mut self,
        kind: u8,
        related: ChainHead,
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        self.record_local_only(RecordType::LocalLifecycleEvent, &[kind], related, now_ns)
    }

    /// Design section 15.3: one local keyboard shortcut action.
    pub fn record_key_action<'a>(
        &mut self,
        action: u8,
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        self.record_local_only(RecordType::LocalKeyAction, &[action], zero_head(), now_ns)
    }

    /// Design section 15.3: one local connection state change.
    pub fn record_connection_state<'a>(
        &mut self,
        state: u8,
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        self.record_local_only(
            RecordType::LocalConnectionState,
            &[state],
            zero_head(),
            now_ns,
        )
    }

    /// Design section 15.3: one local audit error.
    pub fn record_local_audit_error<'a>(
        &mut self,
        code: AuditErrorCode,
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        self.record_local_only(
            RecordType::LocalAuditError,
            &code.code().to_be_bytes(),
            zero_head(),
            now_ns,
        )
    }

    /// Design section 18.6: one shared file transfer event plus the local
    /// file transfer record with the local path. The shared record only
    /// carries fields both sides verify from the file protocol; the local
    /// path exists only on the side that holds it. The transfer result may
    /// only be shown to the user after the batch was persisted.
    pub fn record_file_transfer<'a>(
        &mut self,
        facts: &FileTransferFacts<'a>,
        local_path: Option<&'a str>,
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        self.require_recordable()?;
        if facts.remote_path.len() > MAX_PROTOCOL_PATH_LEN {
            return Err(AuditError::SegmentTooLarge);
        }
        if facts.file_name.len() > MAX_PROTOCOL_FILE_NAME_LEN {
            return Err(AuditError::SegmentTooLarge);
        }
        let mut batch = RecordBatch::new();
        let stream_index = SharedStream::FileTransfer.index();
        let sequence = self.shared[stream_index].count + 1;
        let previous = self.shared[stream_index].head;
        // Shared record: direction, sequence, canonical (kind, id, sizes,
        // digest, paths, error) and both heads.
        let canonical_len = 1
            + 8
            + 8
            + 8
            + DIGEST_LEN
            + 2
            + facts.remote_path.len()
            + 2
            + facts.file_name.len()
            + 2;
        let payload_len = 1 + 8 + canonical_len + 2 * DIGEST_LEN;
        let mut payload = vec![0_u8; payload_len];
        let mut cursor = 0;
        append(&mut payload, &mut cursor, &[facts.direction]);
        write_u64(&mut payload, &mut cursor, sequence);
        let canonical_start = cursor;
        append(&mut payload, &mut cursor, &[facts.kind]);
        write_u64(&mut payload, &mut cursor, facts.transfer_id);
        write_u64(&mut payload, &mut cursor, facts.declared_size);
        write_u64(&mut payload, &mut cursor, facts.final_size);
        append(&mut payload, &mut cursor, facts.digest.as_bytes());
        write_u16(&mut payload, &mut cursor, facts.remote_path.len() as u16);
        append(&mut payload, &mut cursor, facts.remote_path.as_bytes());
        write_u16(&mut payload, &mut cursor, facts.file_name.len() as u16);
        append(&mut payload, &mut cursor, facts.file_name.as_bytes());
        write_u16(&mut payload, &mut cursor, facts.error_code);
        let canonical = &payload[canonical_start..];
        let head = ChainHead::new(shared_event_hash(
            CHAIN_FILE_DOMAIN,
            previous.as_bytes(),
            stream_index as u8,
            facts.direction,
            sequence,
            facts.kind,
            canonical,
        ));
        append(&mut payload, &mut cursor, previous.as_bytes());
        append(&mut payload, &mut cursor, head.as_bytes());
        debug_assert_eq!(payload_len, cursor);
        self.shared[stream_index].count += 1;
        self.shared[stream_index].head = head;
        self.last_block[stream_index] = Some(head);
        self.checkpoint_shared_bytes += payload_len as u64;
        if self.checkpoint_shared_bytes >= CHECKPOINT_SIZE_TRIGGER {
            self.checkpoint_due_flag = true;
        }
        batch.push_boxed(
            RecordType::SharedFileTransferEvent,
            payload.into_boxed_slice(),
        )?;
        // Local file transfer record with the local path.
        if let Some(local_path) = local_path {
            if local_path.len() > MAX_LOCAL_PATH_LEN {
                return Err(AuditError::SegmentTooLarge);
            }
            let mut kind_payload = vec![0_u8; 1 + 8 + 2 + local_path.len()];
            let mut cursor = 0;
            append(&mut kind_payload, &mut cursor, &[facts.kind]);
            write_u64(&mut kind_payload, &mut cursor, facts.transfer_id);
            write_u16(&mut kind_payload, &mut cursor, local_path.len() as u16);
            append(&mut kind_payload, &mut cursor, local_path.as_bytes());
            self.push_local(
                &mut batch,
                RecordType::LocalFileTransferEvent,
                &kind_payload,
                head,
                now_ns,
            )?;
        }
        Ok(batch)
    }

    // -----------------------------------------------------------------
    // Checkpoints (design section 20)
    // -----------------------------------------------------------------

    /// Whether a checkpoint is due (design section 20.1): the 1 MiB size
    /// trigger fired during recording, or one second elapsed since the last
    /// checkpoint per the caller-provided monotonic time.
    pub fn checkpoint_due(&self, now_ns: u64) -> bool {
        self.checkpoint_due_flag
            || now_ns.saturating_sub(self.last_checkpoint_time_ns) >= CHECKPOINT_INTERVAL_NS
    }

    /// Design section 20.2: builds the next signed checkpoint from the
    /// state *before* it, together with the local evidence record to append
    /// before sending. The checkpoint's local chain head is the
    /// pre-evidence head, so the evidence record can never reference the
    /// checkpoint itself (non-self-referencing).
    ///
    /// The snapshot is the sender's signed observation. Independent libp2p
    /// substreams do not provide cross-stream ordering, so a running-phase
    /// receiver may already have observed later terminal or file facts when
    /// this checkpoint arrives.
    pub fn build_checkpoint<'a>(
        &mut self,
        now_ns: u64,
    ) -> Result<(Checkpoint, RecordBatch<'a>), AuditError> {
        self.build_checkpoint_with_policy(now_ns, CheckpointPolicy::Observation)
    }

    /// Builds the exact checkpoint after both byte directions have crossed
    /// the close barrier and the final shared snapshot is stable.
    pub fn build_final_checkpoint<'a>(
        &mut self,
        now_ns: u64,
    ) -> Result<(Checkpoint, RecordBatch<'a>), AuditError> {
        self.build_checkpoint_with_policy(now_ns, CheckpointPolicy::ExactPrefix)
    }

    fn build_checkpoint_with_policy<'a>(
        &mut self,
        now_ns: u64,
        policy: CheckpointPolicy,
    ) -> Result<(Checkpoint, RecordBatch<'a>), AuditError> {
        match policy {
            CheckpointPolicy::Observation => self.require_recordable()?,
            CheckpointPolicy::ExactPrefix => self.require_phase(Phase::Finalizing)?,
        }
        let session_id = self
            .session_id
            .ok_or(AuditError::InvalidState("session ID not computed"))?;
        let sequence = self.next_checkpoint_sequence;
        let snapshot = self.shared_snapshot();
        let local_head = self.local_head;
        let checkpoint = Checkpoint::new(
            session_id,
            sequence,
            snapshot,
            local_head,
            self.ledger_snapshot_digest,
            Ed25519Signature::new([0; ED25519_SIGNATURE_LEN]),
        );
        let signature = self.sign_with_session_key(checkpoint.signing_input().as_slice());
        let checkpoint = checkpoint.with_signature(signature);
        let mut batch = RecordBatch::new();
        self.push_evidence(
            &mut batch,
            EVIDENCE_SENT_CHECKPOINT,
            checkpoint.encode_payload().as_slice(),
            now_ns,
        )?;
        self.last_sent_checkpoint = Some(checkpoint);
        self.next_checkpoint_sequence = sequence.wrapping_add(1);
        self.last_checkpoint_time_ns = now_ns;
        self.checkpoint_shared_bytes = 0;
        self.checkpoint_due_flag = false;
        Ok((checkpoint, batch))
    }

    /// Design section 20.3 (receiver side): verifies a running-phase peer
    /// checkpoint (signature, session ID and independent sender sequence),
    /// appends the received-checkpoint evidence and returns the signed
    /// `CheckpointAck` over the sender's snapshot together with the sent-ack
    /// evidence record.
    ///
    /// A duplicate retransmission of the last received checkpoint is
    /// acknowledged again without new evidence; a skipped or mismatching
    /// sequence, session ID or signature records the mismatch and fails the
    /// session closed (design section 20.3). The receiver deliberately does
    /// not compare the snapshot with its current chains: terminal, file and
    /// audit traffic use independent substreams and have no cross-stream
    /// arrival order.
    pub fn receive_checkpoint<'a>(
        &mut self,
        checkpoint: &Checkpoint,
        now_ns: u64,
    ) -> Result<(CheckpointAck, RecordBatch<'a>), AuditError> {
        self.receive_checkpoint_with_policy(checkpoint, now_ns, CheckpointPolicy::Observation)
    }

    /// Receives the closing checkpoint after the terminal and file streams
    /// have reached their close barrier. At that point no shared fact may be
    /// in flight, so the peer snapshot must equal the local final snapshot.
    pub fn receive_final_checkpoint<'a>(
        &mut self,
        checkpoint: &Checkpoint,
        now_ns: u64,
    ) -> Result<(CheckpointAck, RecordBatch<'a>), AuditError> {
        self.receive_checkpoint_with_policy(checkpoint, now_ns, CheckpointPolicy::ExactPrefix)
    }

    fn receive_checkpoint_with_policy<'a>(
        &mut self,
        checkpoint: &Checkpoint,
        now_ns: u64,
        policy: CheckpointPolicy,
    ) -> Result<(CheckpointAck, RecordBatch<'a>), AuditError> {
        match policy {
            CheckpointPolicy::Observation => {
                if !matches!(self.phase, Phase::Active | Phase::Finalizing) {
                    return Err(AuditError::InvalidState(
                        "checkpoint observation outside an active session",
                    ));
                }
            }
            CheckpointPolicy::ExactPrefix => self.require_phase(Phase::Finalizing)?,
        }
        let session_id = self
            .session_id
            .ok_or(AuditError::InvalidState("session ID not computed"))?;
        if *checkpoint.session_id() != session_id {
            return self.fail_checkpoint();
        }
        let peer = self
            .peer_hello
            .as_ref()
            .ok_or(AuditError::InvalidState("peer hello not received"))?;
        if verify_signature(
            peer.session_key(),
            checkpoint.signing_input().as_slice(),
            checkpoint.signature(),
        )
        .is_err()
        {
            return self.fail_checkpoint();
        }
        if policy == CheckpointPolicy::ExactPrefix
            && checkpoint.snapshot() != self.shared_snapshot()
        {
            return self.fail_checkpoint();
        }
        let digest = Digest32::new(sha256_32(checkpoint.encode_payload().as_slice()));
        let expected = self
            .last_received_checkpoint
            .map_or(0, |(sequence, _)| sequence)
            .wrapping_add(1);
        if checkpoint.sequence() != expected {
            if let Some((sequence, last_digest)) = self.last_received_checkpoint
                && sequence == checkpoint.sequence()
                && last_digest == digest
            {
                // Duplicate retransmission: re-ack without new evidence.
                let ack = self.build_ack(checkpoint, digest);
                return Ok((ack, RecordBatch::new()));
            }
            return self.fail_checkpoint();
        }
        self.last_received_checkpoint = Some((checkpoint.sequence(), digest));
        // The receiver commits to this sender-direction checkpoint with its
        // ack. The direction remains independent until manifest summary.
        self.last_confirmed_received_checkpoint_sequence = checkpoint.sequence();
        let mut batch = RecordBatch::new();
        self.push_evidence(
            &mut batch,
            EVIDENCE_RECEIVED_CHECKPOINT,
            checkpoint.encode_payload().as_slice(),
            now_ns,
        )?;
        let ack = self.build_ack(checkpoint, digest);
        self.push_evidence(
            &mut batch,
            EVIDENCE_SENT_CHECKPOINT_ACK,
            ack.encode_payload().as_slice(),
            now_ns,
        )?;
        Ok((ack, batch))
    }

    /// Design section 20.3 (sender side): verifies the peer `CheckpointAck`
    /// against the last sent checkpoint: session ID, sequence, checkpoint
    /// digest and the receiver's signed copy of the sender snapshot. On success the
    /// checkpoint becomes a bilaterally confirmed checkpoint and the
    /// received-ack evidence is returned for appending. A duplicate ack is
    /// ignored; any mismatch records the mismatch and fails the session
    /// closed.
    pub fn receive_checkpoint_ack<'a>(
        &mut self,
        ack: &CheckpointAck,
        now_ns: u64,
    ) -> Result<Option<RecordBatch<'a>>, AuditError> {
        if !matches!(self.phase, Phase::Active | Phase::Finalizing) {
            return match self.phase {
                Phase::Failed => Err(AuditError::FailedClosed),
                _ => Err(AuditError::InvalidState(
                    "checkpoint acknowledgment outside an active session",
                )),
            };
        }
        let session_id = self
            .session_id
            .ok_or(AuditError::InvalidState("session ID not computed"))?;
        if *ack.session_id() != session_id {
            return self.fail_checkpoint();
        }
        let sent = self.last_sent_checkpoint.ok_or(AuditError::InvalidState(
            "no checkpoint awaiting confirmation",
        ))?;
        if ack.sequence() != sent.sequence() {
            return self.fail_checkpoint();
        }
        let digest = Digest32::new(sha256_32(sent.encode_payload().as_slice()));
        if *ack.checkpoint_digest() != digest || ack.snapshot() != sent.snapshot() {
            return self.fail_checkpoint();
        }
        let peer = self
            .peer_hello
            .as_ref()
            .ok_or(AuditError::InvalidState("peer hello not received"))?;
        if verify_signature(
            peer.session_key(),
            ack.signing_input().as_slice(),
            ack.signature(),
        )
        .is_err()
        {
            return self.fail_checkpoint();
        }
        if self.last_confirmed_sent_checkpoint_sequence >= ack.sequence() {
            // Duplicate ack for an already confirmed checkpoint: ignore.
            return Ok(None);
        }
        self.last_confirmed_sent_checkpoint_sequence = ack.sequence();
        let mut batch = RecordBatch::new();
        self.push_evidence(
            &mut batch,
            EVIDENCE_RECEIVED_CHECKPOINT_ACK,
            ack.encode_payload().as_slice(),
            now_ns,
        )?;
        Ok(Some(batch))
    }

    // -----------------------------------------------------------------
    // Finalization (design sections 21 and 12.3)
    // -----------------------------------------------------------------

    /// Design section 16.1 and 22.1: closes both byte directions, forming
    /// the final partial blocks as shared records. The trailing bytes were
    /// already recorded locally, so no local records are produced here.
    /// Returns an empty batch when a direction is empty. No further input
    /// or output recording is allowed afterwards.
    pub fn close_directions<'a>(&mut self) -> Result<RecordBatch<'a>, AuditError> {
        self.require_recordable()?;
        let mut batch = RecordBatch::new();
        // Input direction.
        {
            let stream_index = SharedStream::Input.index();
            let chain = &mut self.shared[stream_index];
            let key = self
                .input_key
                .as_ref()
                .ok_or(AuditError::InvalidState("input commitment key not derived"))?;
            let normalizer = &mut self.normalizers[0];
            let last_block = &mut self.last_block[stream_index];
            let checkpoint_bytes = &mut self.checkpoint_shared_bytes;
            let due_flag = &mut self.checkpoint_due_flag;
            let mut completed = BlockCollector::new();
            normalizer.finish(|block| {
                let length = block.len() as u64;
                let sequence = chain.count + 1;
                let (payload, head) = build_input_block(
                    key,
                    DIRECTION_CTRL_TO_HOST,
                    sequence,
                    length,
                    block,
                    chain.head,
                );
                chain.count += 1;
                chain.head = head;
                *last_block = Some(head);
                *checkpoint_bytes += length;
                if *checkpoint_bytes >= CHECKPOINT_SIZE_TRIGGER {
                    *due_flag = true;
                }
                completed
                    .push(CompletedBlock { payload, head })
                    .expect("a final partial block fits the collector");
            })?;
            for index in 0..completed.len {
                let block = completed.blocks[index].as_ref().expect("filled block slot");
                batch.push_inline(RecordType::SharedInputCommitment, &block.payload)?;
            }
        }
        // Output direction.
        {
            let stream_index = SharedStream::Output.index();
            let chain = &mut self.shared[stream_index];
            let normalizer = &mut self.normalizers[1];
            let last_block = &mut self.last_block[stream_index];
            let checkpoint_bytes = &mut self.checkpoint_shared_bytes;
            let due_flag = &mut self.checkpoint_due_flag;
            let mut completed = BlockCollector::new();
            normalizer.finish(|block| {
                let length = block.len() as u64;
                let sequence = chain.count + 1;
                let digest = sha256_32(block);
                let (payload, head) = build_output_block(
                    DIRECTION_HOST_TO_CTRL,
                    sequence,
                    length,
                    digest,
                    chain.head,
                );
                chain.count += 1;
                chain.head = head;
                *last_block = Some(head);
                *checkpoint_bytes += length;
                if *checkpoint_bytes >= CHECKPOINT_SIZE_TRIGGER {
                    *due_flag = true;
                }
                completed
                    .push(CompletedBlock { payload, head })
                    .expect("a final partial block fits the collector");
            })?;
            for index in 0..completed.len {
                let block = completed.blocks[index].as_ref().expect("filled block slot");
                batch.push_inline(RecordType::SharedOutputBlock, &block.payload)?;
            }
        }
        self.phase = Phase::Finalizing;
        Ok(batch)
    }

    /// Design section 21.1 and 21.2: constructs the final joint manifest
    /// from state both sides share, signs it with the local ephemeral
    /// session key and returns the manifest, the local signature and the
    /// sent-manifest and sent-signature evidence records to append before
    /// sending. Must follow [`AuditSession::close_directions`].
    pub fn build_manifest(
        &mut self,
        ending: ManifestEnding,
        ended_normally: bool,
        now_ns: u64,
    ) -> Result<(JointManifest, ManifestSignature, RecordBatch<'static>), AuditError> {
        self.require_phase(Phase::Finalizing)?;
        let session_id = self
            .session_id
            .ok_or(AuditError::InvalidState("session ID not computed"))?;
        let peer = self
            .peer_hello
            .as_ref()
            .ok_or(AuditError::InvalidState("peer hello not received"))?;
        let terminal_hello_digest = self.terminal_hello_digest.ok_or(AuditError::InvalidState(
            "terminal hello digest not recorded",
        ))?;
        let (controller_fingerprint, host_fingerprint, controller_key, host_key) = match self.role {
            AuditRole::Controller => (
                self.identity.fingerprint(),
                self.peer_fingerprint
                    .ok_or(AuditError::InvalidState("peer fingerprint missing"))?,
                self.session_pubkey,
                *peer.session_key(),
            ),
            AuditRole::Host => (
                self.peer_fingerprint
                    .ok_or(AuditError::InvalidState("peer fingerprint missing"))?,
                self.identity.fingerprint(),
                *peer.session_key(),
                self.session_pubkey,
            ),
        };
        let manifest = JointManifest::new(
            AUDIT_FORMAT_VERSION,
            session_id,
            controller_fingerprint,
            host_fingerprint,
            controller_key,
            host_key,
            self.binding,
            terminal_hello_digest,
            self.shared_snapshot(),
            ending,
            ended_normally,
            self.last_confirmed_checkpoint_sequence(),
        );
        manifest.encode_payload()?;
        let signature = self.sign_with_session_key(manifest.signing_input()?.as_slice());
        let signature = ManifestSignature::new(signature);
        let mut batch = RecordBatch::new();
        self.push_evidence(
            &mut batch,
            EVIDENCE_SENT_MANIFEST,
            manifest.encode_payload()?.as_slice(),
            now_ns,
        )?;
        self.push_evidence(
            &mut batch,
            EVIDENCE_SENT_MANIFEST_SIGNATURE,
            signature.encode_payload().as_slice(),
            now_ns,
        )?;
        Ok((manifest, signature, batch))
    }

    /// Design section 21.1 and 21.2: verifies that the peer constructed the
    /// identical joint manifest and that its ephemeral session signature is
    /// valid, and returns the received-manifest and received-signature
    /// evidence records to append.
    pub fn receive_peer_manifest_pair(
        &mut self,
        own: &JointManifest,
        peer: &JointManifest,
        signature: &ManifestSignature,
        now_ns: u64,
    ) -> Result<RecordBatch<'static>, AuditError> {
        self.require_phase(Phase::Finalizing)?;
        if peer != own {
            return Err(AuditError::FinalManifestMismatch);
        }
        let peer_session_key = self
            .peer_hello
            .as_ref()
            .ok_or(AuditError::InvalidState("peer hello not received"))?
            .session_key();
        verify_signature(
            peer_session_key,
            peer.signing_input()?.as_slice(),
            signature.signature(),
        )?;
        let mut batch = RecordBatch::new();
        self.push_evidence(
            &mut batch,
            EVIDENCE_RECEIVED_MANIFEST,
            peer.encode_payload()?.as_slice(),
            now_ns,
        )?;
        self.push_evidence(
            &mut batch,
            EVIDENCE_RECEIVED_MANIFEST_SIGNATURE,
            signature.encode_payload().as_slice(),
            now_ns,
        )?;
        self.peer_manifest_received = true;
        Ok(batch)
    }

    /// Design sections 21.3, 21.4 and 12.3: the acyclic footer flow. Writes
    /// the footer magic, the joint manifest and both session signatures,
    /// obtains the sealed prefix digest, writes the `LocalRecordSeal`
    /// (signed by the local ephemeral session key), obtains the sealed
    /// record digest, creates the persistent-identity-signed `LedgerCommit`
    /// under the ledger lock from the latest ledger head, writes the commit
    /// and the final container digest, syncs the whole file, then atomically
    /// advances the ledger state of the session's own ledger.
    ///
    /// All local evidence records must already be appended: the seal binds
    /// the final local chain root, which includes the manifest and
    /// signature evidence records.
    pub async fn finalize_footer(
        &mut self,
        writer: &mut AuditWriter,
        manifest: &JointManifest,
        own_signature: ManifestSignature,
        peer_signature: ManifestSignature,
    ) -> Result<(), AuditError> {
        let pending = self
            .write_footer_prefix(writer, manifest, own_signature, peer_signature)
            .await?;
        let commit = self.begin_ledger_commit(pending)?;
        writer.write_ledger_commit(&commit).await?;
        self.finish_ledger_commit(&commit)
    }

    /// Writes and syncs every footer component before the ledger commit.
    /// The integration layer separates this async writer phase from the
    /// blocking ledger transaction on production runtimes.
    pub async fn write_footer_prefix(
        &mut self,
        writer: &mut AuditWriter,
        manifest: &JointManifest,
        own_signature: ManifestSignature,
        peer_signature: ManifestSignature,
    ) -> Result<PendingLedgerCommit, AuditError> {
        self.require_phase(Phase::Finalizing)?;
        if !self.peer_manifest_received {
            return Err(AuditError::InvalidState(
                "the peer manifest was not received and verified",
            ));
        }
        // The footer signature slots are positional (design section 21.2):
        // the controller slot always holds the controller session signature
        // and the host slot the host session signature, in both files.
        let (controller_signature, host_signature) = match self.role {
            AuditRole::Controller => (&own_signature, &peer_signature),
            AuditRole::Host => (&peer_signature, &own_signature),
        };
        let sealed_prefix_digest = writer
            .write_manifest_and_signatures(manifest, controller_signature, host_signature)
            .await?;
        let manifest_digest = Digest32::new(sha256_32(manifest.encode_payload()?.as_slice()));
        let seal = self.build_seal(sealed_prefix_digest, manifest_digest);
        let sealed_record_digest = writer.write_seal(&seal).await?;
        Ok(PendingLedgerCommit {
            manifest_digest,
            sealed_record_digest,
        })
    }

    /// Starts the short blocking ledger transaction and builds its signed
    /// commit. Production calls this only from Tokio's blocking pool.
    pub fn begin_ledger_commit(
        &mut self,
        pending: PendingLedgerCommit,
    ) -> Result<LedgerCommit, AuditError> {
        self.require_phase(Phase::Finalizing)?;
        let (sequence, previous_root) = self.ledger.begin_commit()?;
        self.build_ledger_commit(
            sequence,
            previous_root,
            pending.manifest_digest,
            pending.sealed_record_digest,
        )
    }

    /// Atomically advances the ledger after the record commit and final
    /// container digest are durable. Production calls this only from
    /// Tokio's blocking pool.
    pub fn finish_ledger_commit(&mut self, commit: &LedgerCommit) -> Result<(), AuditError> {
        self.require_phase(Phase::Finalizing)?;
        self.ledger.finish_commit(commit)?;
        self.phase = Phase::Finished;
        Ok(())
    }

    /// Design section 18.7: the failure-close records for an interrupted
    /// prefix: a local audit error, the closed connection state and the
    /// local close event. The session refuses any further recording
    /// afterwards. The file keeps every record appended before the failure
    /// as a verifiable interrupted prefix (design sections 18.7 and 20.4).
    pub fn fail_closed_records<'a>(
        &mut self,
        code: AuditErrorCode,
        reason: AuditCloseReason,
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        if self.phase == Phase::Failed {
            return Err(AuditError::FailedClosed);
        }
        let mut batch = RecordBatch::new();
        self.push_local(
            &mut batch,
            RecordType::LocalAuditError,
            &code.code().to_be_bytes(),
            zero_head(),
            now_ns,
        )?;
        self.push_local(
            &mut batch,
            RecordType::LocalConnectionState,
            &[CONNECTION_STATE_CLOSED],
            zero_head(),
            now_ns,
        )?;
        let mut kind_payload = [0_u8; 2];
        let mut cursor = 0;
        append(&mut kind_payload, &mut cursor, &[reason.code()]);
        append(&mut kind_payload, &mut cursor, &[OUTCOME_FAILED]);
        self.push_local(
            &mut batch,
            RecordType::LocalCloseEvent,
            &kind_payload,
            zero_head(),
            now_ns,
        )?;
        self.phase = Phase::Failed;
        Ok(batch)
    }

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    fn require_phase(&self, expected: Phase) -> Result<(), AuditError> {
        if self.phase == Phase::Failed {
            return Err(AuditError::FailedClosed);
        }
        if self.phase != expected {
            return Err(AuditError::InvalidState(
                "the session is not in the required phase",
            ));
        }
        Ok(())
    }

    fn require_recordable(&self) -> Result<(), AuditError> {
        match self.phase {
            Phase::Active => Ok(()),
            Phase::Failed => Err(AuditError::FailedClosed),
            Phase::Finalizing => Err(AuditError::InvalidState(
                "recording is closed after direction finalization",
            )),
            _ => Err(AuditError::InvalidState("the session is not active")),
        }
    }

    fn sign_with_session_key(&self, input: &[u8]) -> Ed25519Signature {
        Ed25519Signature::new(self.session_key.sign(input).to_bytes())
    }

    fn controller_contribution(&self) -> &SecretContribution {
        match self.role {
            AuditRole::Controller => &self.contribution,
            AuditRole::Host => self
                .peer_contribution
                .as_ref()
                .expect("peer contribution verified before session ID derivation"),
        }
    }

    fn host_contribution(&self) -> &SecretContribution {
        match self.role {
            AuditRole::Controller => self
                .peer_contribution
                .as_ref()
                .expect("peer contribution verified before session ID derivation"),
            AuditRole::Host => &self.contribution,
        }
    }

    fn controller_nonce(&self) -> AuditNonce {
        match self.role {
            AuditRole::Controller => self.nonce,
            AuditRole::Host => *self
                .peer_hello
                .as_ref()
                .expect("peer hello verified before session ID derivation")
                .nonce(),
        }
    }

    fn host_nonce(&self) -> AuditNonce {
        match self.role {
            AuditRole::Controller => *self
                .peer_hello
                .as_ref()
                .expect("peer hello verified before session ID derivation")
                .nonce(),
            AuditRole::Host => self.nonce,
        }
    }

    fn compute_session_id(&self) -> SessionId {
        let peer = self
            .peer_hello
            .as_ref()
            .expect("peer hello verified before session ID derivation");
        let (controller_identity, host_identity, controller_key, host_key) = match self.role {
            AuditRole::Controller => (
                self.identity.public_key(),
                *peer.persistent_audit_key(),
                self.session_pubkey,
                *peer.session_key(),
            ),
            AuditRole::Host => (
                *peer.persistent_audit_key(),
                self.identity.public_key(),
                *peer.session_key(),
                self.session_pubkey,
            ),
        };
        let (controller_commitment, host_commitment) = match self.role {
            AuditRole::Controller => (self.commitment, *peer.input_commitment()),
            AuditRole::Host => (*peer.input_commitment(), self.commitment),
        };
        let mut bytes = [0_u8; SESSION_ID_LABEL.len() + 8 * DIGEST_LEN + 2 * NONCE_LEN];
        let mut cursor = 0;
        append(&mut bytes, &mut cursor, SESSION_ID_LABEL);
        append(&mut bytes, &mut cursor, self.binding.as_bytes());
        append(&mut bytes, &mut cursor, self.controller_nonce().as_bytes());
        append(&mut bytes, &mut cursor, self.host_nonce().as_bytes());
        append(&mut bytes, &mut cursor, controller_identity.as_bytes());
        append(&mut bytes, &mut cursor, host_identity.as_bytes());
        append(&mut bytes, &mut cursor, controller_key.as_bytes());
        append(&mut bytes, &mut cursor, host_key.as_bytes());
        append(&mut bytes, &mut cursor, controller_commitment.as_bytes());
        append(&mut bytes, &mut cursor, host_commitment.as_bytes());
        SessionId::new(sha256_32(&bytes[..cursor]))
    }

    /// The local record payload envelope: time and related shared hash.
    fn local_prefix(&self, now_ns: u64, related: &ChainHead) -> [u8; SPLIT_PREFIX_LEN] {
        let mut prefix = [0_u8; SPLIT_PREFIX_LEN];
        let mut cursor = 0;
        write_u64(&mut prefix, &mut cursor, now_ns);
        append(&mut prefix, &mut cursor, related.as_bytes());
        prefix
    }

    /// Appends a local-only record to the batch and advances the local
    /// chain.
    fn record_local_only<'a>(
        &mut self,
        record_type: RecordType,
        kind_payload: &[u8],
        related: ChainHead,
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        self.require_recordable()?;
        let mut batch = RecordBatch::new();
        self.push_local(&mut batch, record_type, kind_payload, related, now_ns)?;
        Ok(batch)
    }

    /// Encodes one local record, advances the local chain and pushes it
    /// into the batch. The record payload is `time || related || payload`.
    fn push_local(
        &mut self,
        batch: &mut RecordBatch<'_>,
        record_type: RecordType,
        kind_payload: &[u8],
        related: ChainHead,
        now_ns: u64,
    ) -> Result<(), AuditError> {
        let head = self.commit_local(record_type, kind_payload, &related, now_ns);
        let mut payload = [0_u8; SPLIT_PREFIX_LEN + MAX_INLINE_PAYLOAD_LEN];
        let mut cursor = 0;
        append(
            &mut payload,
            &mut cursor,
            &self.local_prefix(now_ns, &related),
        );
        append(&mut payload, &mut cursor, kind_payload);
        let _ = head;
        batch.push_inline(record_type, &payload[..cursor])
    }

    /// Advances the local chain over one record and returns the new head.
    fn commit_local(
        &mut self,
        record_type: RecordType,
        kind_payload: &[u8],
        related: &ChainHead,
        now_ns: u64,
    ) -> ChainHead {
        let head = local_event_hash(
            self.local_head.as_bytes(),
            self.local_count + 1,
            now_ns,
            record_type.code(),
            kind_payload,
            related.as_bytes(),
        );
        self.local_count += 1;
        self.local_head = ChainHead::new(head);
        self.local_head
    }

    /// Encodes one checkpoint evidence record and pushes it into the batch.
    fn push_evidence(
        &mut self,
        batch: &mut RecordBatch<'_>,
        evidence_kind: u8,
        evidence_payload: &[u8],
        now_ns: u64,
    ) -> Result<(), AuditError> {
        if evidence_payload.len() > u32::MAX as usize {
            return Err(AuditError::InvalidState(
                "evidence payload exceeds the length bound",
            ));
        }
        let mut kind_payload = [0_u8; 1 + 4 + 911];
        let mut cursor = 0;
        append(&mut kind_payload, &mut cursor, &[evidence_kind]);
        write_u32(
            &mut kind_payload,
            &mut cursor,
            evidence_payload.len() as u32,
        );
        append(&mut kind_payload, &mut cursor, evidence_payload);
        self.push_local(
            batch,
            RecordType::CheckpointEvidence,
            &kind_payload[..cursor],
            zero_head(),
            now_ns,
        )
    }

    /// Commits one shared control event and pushes its record into the
    /// batch, returning the new shared chain head.
    fn commit_shared_control(
        &mut self,
        batch: &mut RecordBatch<'_>,
        direction: u8,
        control_kind: u8,
        control_payload: &[u8],
    ) -> Result<ChainHead, AuditError> {
        let stream_index = SharedStream::Control.index();
        let sequence = self.shared[stream_index].count + 1;
        let previous = self.shared[stream_index].head;
        let canonical_len = 1 + control_payload.len();
        let payload_len = 1 + 8 + canonical_len + 2 * DIGEST_LEN;
        // The largest control payload is the 32-byte TerminalHello digest.
        let mut payload = [0_u8; 1 + 8 + 1 + 32 + 2 * DIGEST_LEN];
        let mut cursor = 0;
        append(&mut payload, &mut cursor, &[direction]);
        write_u64(&mut payload, &mut cursor, sequence);
        let canonical_start = cursor;
        append(&mut payload, &mut cursor, &[control_kind]);
        append(&mut payload, &mut cursor, control_payload);
        let canonical = &payload[canonical_start..];
        let head = ChainHead::new(shared_event_hash(
            CHAIN_CONTROL_DOMAIN,
            previous.as_bytes(),
            stream_index as u8,
            direction,
            sequence,
            control_kind,
            canonical,
        ));
        append(&mut payload, &mut cursor, previous.as_bytes());
        append(&mut payload, &mut cursor, head.as_bytes());
        debug_assert_eq!(payload_len, cursor);
        self.shared[stream_index].count += 1;
        self.shared[stream_index].head = head;
        self.last_block[stream_index] = Some(head);
        self.checkpoint_shared_bytes += payload_len as u64;
        if self.checkpoint_shared_bytes >= CHECKPOINT_SIZE_TRIGGER {
            self.checkpoint_due_flag = true;
        }
        batch.push_inline(RecordType::SharedControlEvent, &payload[..cursor])?;
        Ok(head)
    }

    fn record_control_lifecycle<'a>(
        &mut self,
        control_kind: u8,
        lifecycle_kind: u8,
        direction: u8,
        control_payload: &[u8],
        now_ns: u64,
    ) -> Result<RecordBatch<'a>, AuditError> {
        self.require_recordable()?;
        let mut batch = RecordBatch::new();
        let shared_head =
            self.commit_shared_control(&mut batch, direction, control_kind, control_payload)?;
        self.push_local(
            &mut batch,
            RecordType::LocalLifecycleEvent,
            &[lifecycle_kind],
            shared_head,
            now_ns,
        )?;
        Ok(batch)
    }

    fn related_for_direction(&self, direction: u8) -> ChainHead {
        let stream = if direction == DIRECTION_CTRL_TO_HOST {
            SharedStream::Input
        } else {
            SharedStream::Output
        };
        self.last_block[stream.index()].unwrap_or(zero_head())
    }

    fn build_ack(&self, checkpoint: &Checkpoint, digest: Digest32) -> CheckpointAck {
        let session_id = self
            .session_id
            .expect("session ID derived before checkpoints");
        let ack = CheckpointAck::new(
            session_id,
            checkpoint.sequence(),
            digest,
            checkpoint.snapshot(),
            Ed25519Signature::new([0; ED25519_SIGNATURE_LEN]),
        );
        let signature = self.sign_with_session_key(ack.signing_input().as_slice());
        ack.with_signature(signature)
    }

    /// Fails the session closed on a checkpoint mismatch (design
    /// section 20.3): the caller persists the failure-close records
    /// best-effort through [`AuditSession::fail_closed_records`].
    fn fail_checkpoint<T>(&mut self) -> Result<T, AuditError> {
        self.phase = Phase::Failed;
        Err(AuditError::CheckpointMismatch)
    }

    fn build_seal(
        &self,
        sealed_prefix_digest: Digest32,
        joint_manifest_digest: Digest32,
    ) -> LocalRecordSeal {
        let session_id = self
            .session_id
            .expect("session ID derived before finalization");
        let seal = LocalRecordSeal::new(
            session_id,
            self.role,
            self.local_head,
            self.local_count,
            self.shared.map(|chain| chain.head),
            joint_manifest_digest,
            sealed_prefix_digest,
            Ed25519Signature::new([0; ED25519_SIGNATURE_LEN]),
        );
        let signature = self.sign_with_session_key(seal.signing_input().as_slice());
        seal.with_signature(signature)
    }

    fn build_ledger_commit(
        &self,
        sequence: u64,
        previous_root: LedgerRoot,
        manifest_digest: Digest32,
        sealed_record_digest: Digest32,
    ) -> Result<LedgerCommit, AuditError> {
        let session_id = self
            .session_id
            .ok_or(AuditError::InvalidState("session ID not computed"))?;
        let peer_fingerprint = self
            .peer_fingerprint
            .ok_or(AuditError::InvalidState("peer fingerprint missing"))?;
        let commit = LedgerCommit::new(
            sequence,
            previous_root,
            session_id,
            manifest_digest,
            sealed_record_digest,
            peer_fingerprint,
            SessionResult::Normal,
            Ed25519Signature::new([0; ED25519_SIGNATURE_LEN]),
        );
        let signature = self.identity.sign(commit.signing_input().as_slice())?;
        Ok(commit.with_signature(signature))
    }
}

impl std::fmt::Debug for AuditSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuditSession")
            .field("role", &self.role)
            .field("phase", &self.phase)
            .field("session_id", &self.session_id)
            .field("session_pubkey", &self.session_pubkey)
            .field("local_event_count", &self.local_count)
            .field("local_chain_head", &self.local_head)
            .field("input_commitment_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// One shared file transfer fact (design section 18.6). Only fields both
/// sides can verify from the 0.2.0 file protocol enter the shared chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileTransferFacts<'a> {
    /// The transfer ID of the file protocol.
    pub transfer_id: u64,
    /// The transfer direction: [`FILE_DIRECTION_UPLOAD`] or
    /// [`FILE_DIRECTION_DOWNLOAD`].
    pub direction: u8,
    /// The event kind: [`FILE_KIND_START`], [`FILE_KIND_SUCCESS`],
    /// [`FILE_KIND_CANCELLED`] or [`FILE_KIND_FAILED`].
    pub kind: u8,
    /// The size announced by the transfer open.
    pub declared_size: u64,
    /// The final transferred size, zero for start events.
    pub final_size: u64,
    /// The SHA-256 of the transferred file, zeros for start events.
    pub digest: Digest32,
    /// The remote protocol path (design section 18.6).
    pub remote_path: &'a str,
    /// The protocol base file name.
    pub file_name: &'a str,
    /// The structured file transfer error code, zero when none.
    pub error_code: u16,
}

/// Verifies one Ed25519 signature over a canonical signing input.
fn verify_signature(
    public_key: &Ed25519PublicKey,
    input: &[u8],
    signature: &Ed25519Signature,
) -> Result<(), AuditError> {
    let verifying_key = VerifyingKey::from_bytes(public_key.as_bytes())
        .map_err(|_| AuditError::PeerSignatureInvalid)?;
    let signature = Signature::from_bytes(signature.as_bytes());
    verifying_key
        .verify_strict(input, &signature)
        .map_err(|_| AuditError::PeerSignatureInvalid)
}

/// Derives the session-private input commitment key (design section 5.3):
/// HKDF-SHA-256 with the authenticated connection secret as input key
/// material, the two secret contributions in fixed role order as the salt
/// and the fixed label plus the session ID as the context. When the
/// connection cannot export an authenticated secret, the two contributions
/// form the input key material and the connection binding, both nonces and
/// the session ID are placed into the context.
fn derive_input_commitment_key(
    secret: ConnectionSecret<'_>,
    controller_contribution: &SecretContribution,
    host_contribution: &SecretContribution,
    binding: BindingDigest,
    controller_nonce: AuditNonce,
    host_nonce: AuditNonce,
    session_id: SessionId,
) -> InputCommitmentKey {
    let mut salt = [0_u8; 2 * SECRET_CONTRIBUTION_LEN];
    salt[..SECRET_CONTRIBUTION_LEN].copy_from_slice(controller_contribution.as_bytes());
    salt[SECRET_CONTRIBUTION_LEN..].copy_from_slice(host_contribution.as_bytes());
    let mut key = [0_u8; DIGEST_LEN];
    match secret {
        ConnectionSecret::Authenticated(connection_secret) => {
            let hkdf = Hkdf::<Sha256>::new(Some(&salt), connection_secret);
            hkdf.expand_multi_info(&[INPUT_COMMITMENT_LABEL, session_id.as_bytes()], &mut key)
                .expect("a 32-byte output always fits the HKDF expand bound");
        }
        ConnectionSecret::NotExportable => {
            let hkdf = Hkdf::<Sha256>::new(None, &salt);
            hkdf.expand_multi_info(
                &[
                    INPUT_COMMITMENT_LABEL,
                    binding.as_bytes(),
                    controller_nonce.as_bytes(),
                    host_nonce.as_bytes(),
                    session_id.as_bytes(),
                ],
                &mut key,
            )
            .expect("a 32-byte output always fits the HKDF expand bound");
        }
    }
    InputCommitmentKey(key)
}

fn outcome_code(succeeded: bool) -> u8 {
    if succeeded {
        OUTCOME_OK
    } else {
        OUTCOME_FAILED
    }
}

// ---------------------------------------------------------------------------
// Decoders (shared with the verify layer)
// ---------------------------------------------------------------------------

/// The decoded fields of one shared input commitment record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedSharedInput {
    /// The flow direction.
    pub direction: u8,
    /// The per-stream sequence.
    pub sequence: u64,
    /// The block byte length.
    pub length: u64,
    /// The input commitment HMAC.
    pub hmac: [u8; DIGEST_LEN],
    /// The previous chain head.
    pub previous_head: ChainHead,
    /// The new chain head.
    pub new_head: ChainHead,
}

/// Decodes one shared input commitment record payload.
pub fn decode_shared_input(payload: &[u8]) -> Result<DecodedSharedInput, AuditError> {
    if payload.len() != SHARED_INPUT_RECORD_LEN {
        return Err(AuditError::ContainerInvalid);
    }
    Ok(DecodedSharedInput {
        direction: payload[0],
        sequence: u64::from_be_bytes(payload[1..9].try_into().expect("fixed slice")),
        length: u64::from_be_bytes(payload[9..17].try_into().expect("fixed slice")),
        hmac: payload[17..49].try_into().expect("fixed slice"),
        previous_head: ChainHead::new(payload[49..81].try_into().expect("fixed slice")),
        new_head: ChainHead::new(payload[81..113].try_into().expect("fixed slice")),
    })
}

/// The decoded fields of one shared output block record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedSharedOutput {
    /// The flow direction.
    pub direction: u8,
    /// The per-stream sequence.
    pub sequence: u64,
    /// The block byte length.
    pub length: u64,
    /// The SHA-256 block digest.
    pub digest: [u8; DIGEST_LEN],
    /// The previous chain head.
    pub previous_head: ChainHead,
    /// The new chain head.
    pub new_head: ChainHead,
}

/// Decodes one shared output block record payload.
pub fn decode_shared_output(payload: &[u8]) -> Result<DecodedSharedOutput, AuditError> {
    if payload.len() != SHARED_OUTPUT_RECORD_LEN {
        return Err(AuditError::ContainerInvalid);
    }
    Ok(DecodedSharedOutput {
        direction: payload[0],
        sequence: u64::from_be_bytes(payload[1..9].try_into().expect("fixed slice")),
        length: u64::from_be_bytes(payload[9..17].try_into().expect("fixed slice")),
        digest: payload[17..49].try_into().expect("fixed slice"),
        previous_head: ChainHead::new(payload[49..81].try_into().expect("fixed slice")),
        new_head: ChainHead::new(payload[81..113].try_into().expect("fixed slice")),
    })
}

/// The decoded fields of one shared control record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSharedControl {
    /// The flow direction.
    pub direction: u8,
    /// The per-stream sequence.
    pub sequence: u64,
    /// The control event kind.
    pub kind: u8,
    /// The kind-specific payload.
    pub control_payload: Vec<u8>,
    /// The previous chain head.
    pub previous_head: ChainHead,
    /// The new chain head.
    pub new_head: ChainHead,
}

/// Decodes one shared control record payload.
pub fn decode_shared_control(payload: &[u8]) -> Result<DecodedSharedControl, AuditError> {
    if payload.len() < 1 + 8 + 1 + 2 * DIGEST_LEN {
        return Err(AuditError::ContainerInvalid);
    }
    let payload_end = payload.len() - 2 * DIGEST_LEN;
    Ok(DecodedSharedControl {
        direction: payload[0],
        sequence: u64::from_be_bytes(payload[1..9].try_into().expect("fixed slice")),
        kind: payload[9],
        control_payload: payload[10..payload_end].to_vec(),
        previous_head: ChainHead::new(
            payload[payload_end..payload_end + DIGEST_LEN]
                .try_into()
                .expect("fixed slice"),
        ),
        new_head: ChainHead::new(
            payload[payload_end + DIGEST_LEN..]
                .try_into()
                .expect("fixed slice"),
        ),
    })
}

/// The decoded fields of one shared file transfer record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSharedFile {
    /// The flow direction.
    pub direction: u8,
    /// The per-stream sequence.
    pub sequence: u64,
    /// The transfer event kind.
    pub kind: u8,
    /// The transfer ID.
    pub transfer_id: u64,
    /// The declared size.
    pub declared_size: u64,
    /// The final size.
    pub final_size: u64,
    /// The file digest.
    pub digest: [u8; DIGEST_LEN],
    /// The remote protocol path.
    pub remote_path: String,
    /// The protocol base file name.
    pub file_name: String,
    /// The structured error code.
    pub error_code: u16,
    /// The previous chain head.
    pub previous_head: ChainHead,
    /// The new chain head.
    pub new_head: ChainHead,
}

/// Decodes one shared file transfer record payload.
pub fn decode_shared_file(payload: &[u8]) -> Result<DecodedSharedFile, AuditError> {
    let mut cursor = 0;
    let direction = *payload.first().ok_or(AuditError::ContainerInvalid)?;
    cursor += 1;
    let sequence = read_u64(payload, &mut cursor)?;
    let kind = *payload.get(cursor).ok_or(AuditError::ContainerInvalid)?;
    cursor += 1;
    let transfer_id = read_u64(payload, &mut cursor)?;
    let declared_size = read_u64(payload, &mut cursor)?;
    let final_size = read_u64(payload, &mut cursor)?;
    let digest: [u8; DIGEST_LEN] = read_fixed(payload, &mut cursor)?;
    let remote_path = read_str(payload, &mut cursor)?;
    let file_name = read_str(payload, &mut cursor)?;
    let error_code = read_u16(payload, &mut cursor)?;
    let previous_head = ChainHead::new(read_fixed(payload, &mut cursor)?);
    let new_head = ChainHead::new(read_fixed(payload, &mut cursor)?);
    if cursor != payload.len() {
        return Err(AuditError::ContainerInvalid);
    }
    Ok(DecodedSharedFile {
        direction,
        sequence,
        kind,
        transfer_id,
        declared_size,
        final_size,
        digest,
        remote_path,
        file_name,
        error_code,
        previous_head,
        new_head,
    })
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, AuditError> {
    let fixed: [u8; 8] = read_fixed(bytes, cursor)?;
    Ok(u64::from_be_bytes(fixed))
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, AuditError> {
    let fixed: [u8; 2] = read_fixed(bytes, cursor)?;
    Ok(u16::from_be_bytes(fixed))
}

fn read_fixed<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], AuditError> {
    let end = cursor.checked_add(N).ok_or(AuditError::ContainerInvalid)?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or(AuditError::ContainerInvalid)?;
    *cursor = end;
    Ok(slice.try_into().expect("exact fixed slice"))
}

fn read_str(bytes: &[u8], cursor: &mut usize) -> Result<String, AuditError> {
    let len = usize::from(read_u16(bytes, cursor)?);
    let end = cursor
        .checked_add(len)
        .ok_or(AuditError::ContainerInvalid)?;
    let slice = bytes
        .get(*cursor..end)
        .ok_or(AuditError::ContainerInvalid)?;
    *cursor = end;
    std::str::from_utf8(slice)
        .map(str::to_owned)
        .map_err(|_| AuditError::ContainerInvalid)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::audit::writer::AuditWriter;
    use ed25519_dalek::SigningKey as DalekSigningKey;
    use std::sync::Arc;
    use tempfile::tempdir;
    use yonder_core::wire::audit::{IdentityFingerprint, ManifestEnding};
    use yonder_core::wire::audit_container::{ContainerReader, DecodedFooter};

    const CONNECTION_SECRET: &[u8] = b"authenticated-connection-secret-for-tests";

    struct SequentialRandom {
        counter: u8,
    }

    impl SecureRandom for SequentialRandom {
        fn try_fill(&mut self, destination: &mut [u8]) -> Result<(), RandomError> {
            for byte in destination {
                *byte = self.counter;
                self.counter = self.counter.wrapping_add(1);
            }
            Ok(())
        }
    }

    #[derive(Clone)]
    struct TestIdentity(DalekSigningKey);

    impl TestIdentity {
        fn generate(counter: u8) -> Self {
            let mut random = SequentialRandom { counter };
            let mut seed = [0_u8; 32];
            random.try_fill(&mut seed).unwrap();
            Self(DalekSigningKey::from_bytes(&seed))
        }
    }

    impl PersistentIdentity for TestIdentity {
        fn public_key(&self) -> Ed25519PublicKey {
            Ed25519PublicKey::new(self.0.verifying_key().to_bytes())
        }

        fn fingerprint(&self) -> IdentityFingerprint {
            IdentityFingerprint::new(sha256_32(&self.0.verifying_key().to_bytes()))
        }

        fn sign(&self, input: &[u8]) -> Result<Ed25519Signature, AuditError> {
            Ok(Ed25519Signature::new(self.0.sign(input).to_bytes()))
        }
    }

    #[derive(Debug)]
    struct TestLedgerState {
        sequence: u64,
        root: LedgerRoot,
        commits: Vec<LedgerCommit>,
    }

    impl Default for TestLedgerState {
        fn default() -> Self {
            Self {
                sequence: 0,
                root: LedgerRoot::new([0; DIGEST_LEN]),
                commits: Vec::new(),
            }
        }
    }

    /// A test ledger with shared state so the session-owned ledger can be
    /// inspected after finalization.
    #[derive(Debug, Clone, Default)]
    struct TestLedger {
        state: Arc<std::sync::Mutex<TestLedgerState>>,
    }

    impl TestLedger {
        fn new() -> Self {
            Self::default()
        }
    }

    impl Ledger for TestLedger {
        fn snapshot(&self) -> Result<(u64, LedgerRoot), AuditError> {
            let state = self.state.lock().expect("test ledger lock");
            Ok((state.sequence, state.root))
        }

        fn begin_commit(&mut self) -> Result<(u64, LedgerRoot), AuditError> {
            let state = self.state.lock().expect("test ledger lock");
            Ok((state.sequence + 1, state.root))
        }

        fn finish_commit(&mut self, commit: &LedgerCommit) -> Result<(), AuditError> {
            let mut state = self.state.lock().expect("test ledger lock");
            state.sequence = commit.sequence();
            state.root = LedgerRoot::new(sha256_32(commit.encode_payload().as_slice()));
            state.commits.push(*commit);
            Ok(())
        }
    }

    fn test_binding(seed: u8) -> BindingDigest {
        BindingDigest::new([seed; DIGEST_LEN])
    }

    fn test_session(role: AuditRole, random_counter: u8, binding: BindingDigest) -> AuditSession {
        test_session_with_ledger(role, random_counter, binding, TestLedger::new())
    }

    fn test_session_with_ledger(
        role: AuditRole,
        random_counter: u8,
        binding: BindingDigest,
        ledger: TestLedger,
    ) -> AuditSession {
        AuditSession::new(
            role,
            Box::new(TestIdentity::generate(random_counter.wrapping_add(10))),
            Box::new(ledger),
            binding,
            1_700_000_000,
            &mut SequentialRandom {
                counter: random_counter,
            },
        )
        .unwrap()
    }

    /// Performs the full synchronous handshake between two sessions.
    fn handshake(controller: &mut AuditSession, host: &mut AuditSession) {
        let hello_c = *controller.local_hello();
        let contrib_c = controller.local_contribution().clone();
        let hello_h = *host.local_hello();
        let contrib_h = host.local_contribution().clone();
        controller.receive_peer_hello(&hello_h, &contrib_h).unwrap();
        host.receive_peer_hello(&hello_c, &contrib_c).unwrap();
        let ready_c = controller
            .compute_ready(ConnectionSecret::Authenticated(CONNECTION_SECRET))
            .unwrap();
        let ready_h = host
            .compute_ready(ConnectionSecret::Authenticated(CONNECTION_SECRET))
            .unwrap();
        controller.receive_peer_ready(&ready_h).unwrap();
        host.receive_peer_ready(&ready_c).unwrap();
    }

    /// The handshake up to and including the `AuditReady` computation,
    /// leaving the header build and the ready exchange to the caller.
    fn handshake_until_readies(
        controller: &mut AuditSession,
        host: &mut AuditSession,
    ) -> (AuditReady, AuditReady) {
        let hello_c = *controller.local_hello();
        let contrib_c = controller.local_contribution().clone();
        let hello_h = *host.local_hello();
        let contrib_h = host.local_contribution().clone();
        controller.receive_peer_hello(&hello_h, &contrib_h).unwrap();
        host.receive_peer_hello(&hello_c, &contrib_c).unwrap();
        let ready_c = controller
            .compute_ready(ConnectionSecret::Authenticated(CONNECTION_SECRET))
            .unwrap();
        let ready_h = host
            .compute_ready(ConnectionSecret::Authenticated(CONNECTION_SECRET))
            .unwrap();
        (ready_c, ready_h)
    }

    /// The full handshake including the signed container header, which the
    /// manifest tests need for the terminal hello digest.
    fn handshake_with_header(controller: &mut AuditSession, host: &mut AuditSession) {
        let (ready_c, ready_h) = handshake_until_readies(controller, host);
        let hello_digest = Digest32::new([1; DIGEST_LEN]);
        let header_c = controller.build_header(&ready_c, hello_digest).unwrap();
        let header_h = host.build_header(&ready_h, hello_digest).unwrap();
        controller.receive_peer_ready(&ready_h).unwrap();
        host.receive_peer_ready(&ready_c).unwrap();
        let _ = (header_c, header_h);
    }

    fn batch_payload(batch: &RecordBatch<'_>) -> Vec<(RecordType, Vec<u8>)> {
        batch
            .iter()
            .map(|record| {
                let payload = match &record.payload {
                    Payload::Inline { bytes, len } => bytes[..*len].to_vec(),
                    Payload::Boxed(bytes) => bytes.to_vec(),
                    Payload::Split { prefix, body } => {
                        let mut payload = prefix.to_vec();
                        payload.extend_from_slice(body);
                        payload
                    }
                };
                (record.record_type, payload)
            })
            .collect()
    }

    fn shared_payloads(batch: &RecordBatch<'_>, record_type: RecordType) -> Vec<Vec<u8>> {
        batch_payload(batch)
            .into_iter()
            .filter(|(kind, _)| *kind == record_type)
            .map(|(_, payload)| payload)
            .collect()
    }

    #[test]
    fn handshake_round_trip_derives_identical_session_ids_and_keys() {
        let binding = test_binding(0x41);
        let mut controller = test_session(AuditRole::Controller, 1, binding);
        let mut host = test_session(AuditRole::Host, 101, binding);
        handshake(&mut controller, &mut host);

        let session_id_c = controller.session_id().unwrap();
        let session_id_h = host.session_id().unwrap();
        assert_eq!(
            session_id_c, session_id_h,
            "both sides derive the same session ID"
        );
        assert_ne!(session_id_c.as_bytes(), &[0; DIGEST_LEN]);

        let key_c = controller.input_key().unwrap();
        let key_h = host.input_key().unwrap();
        assert_eq!(
            key_c.as_bytes(),
            key_h.as_bytes(),
            "both sides derive the same input commitment key"
        );
        assert_ne!(key_c.as_bytes(), &[0; DIGEST_LEN]);
        assert!(controller.is_active());
        assert!(host.is_active());
    }

    #[test]
    fn session_id_uses_the_frozen_formula() {
        let binding = test_binding(0x55);
        let mut controller = test_session(AuditRole::Controller, 7, binding);
        let mut host = test_session(AuditRole::Host, 177, binding);
        let hello_c = *controller.local_hello();
        let contrib_c = *controller.local_contribution().as_bytes();
        let hello_h = *host.local_hello();
        let contrib_h = *host.local_contribution().as_bytes();
        controller
            .receive_peer_hello(&hello_h, &SecretContribution::new(contrib_h))
            .unwrap();
        host.receive_peer_hello(&hello_c, &SecretContribution::new(contrib_c))
            .unwrap();
        controller
            .compute_ready(ConnectionSecret::Authenticated(CONNECTION_SECRET))
            .unwrap();
        host.compute_ready(ConnectionSecret::Authenticated(CONNECTION_SECRET))
            .unwrap();

        let mut bytes = [0_u8; SESSION_ID_LABEL.len() + 8 * DIGEST_LEN + 2 * NONCE_LEN];
        let mut cursor = 0;
        append(&mut bytes, &mut cursor, SESSION_ID_LABEL);
        append(&mut bytes, &mut cursor, binding.as_bytes());
        append(&mut bytes, &mut cursor, hello_c.nonce().as_bytes());
        append(&mut bytes, &mut cursor, hello_h.nonce().as_bytes());
        append(
            &mut bytes,
            &mut cursor,
            hello_c.persistent_audit_key().as_bytes(),
        );
        append(
            &mut bytes,
            &mut cursor,
            hello_h.persistent_audit_key().as_bytes(),
        );
        append(&mut bytes, &mut cursor, hello_c.session_key().as_bytes());
        append(&mut bytes, &mut cursor, hello_h.session_key().as_bytes());
        append(
            &mut bytes,
            &mut cursor,
            hello_c.input_commitment().as_bytes(),
        );
        append(
            &mut bytes,
            &mut cursor,
            hello_h.input_commitment().as_bytes(),
        );
        let expected = SessionId::new(sha256_32(&bytes[..cursor]));
        assert_eq!(controller.session_id().unwrap(), expected);
        assert_eq!(host.session_id().unwrap(), expected);
    }

    #[test]
    fn hkdf_derivation_matches_a_reference_implementation() {
        let binding = test_binding(0x21);
        let mut controller = test_session(AuditRole::Controller, 3, binding);
        let mut host = test_session(AuditRole::Host, 103, binding);
        handshake(&mut controller, &mut host);
        let session_id = controller.session_id().unwrap();
        let key = *controller.input_key().unwrap().as_bytes();

        // Reference HKDF-SHA-256 (RFC 5869) over the exact same inputs.
        let contrib_c = *controller.local_contribution().as_bytes();
        let contrib_h = *host.local_contribution().as_bytes();
        let mut salt = [0_u8; 64];
        salt[..32].copy_from_slice(&contrib_c);
        salt[32..].copy_from_slice(&contrib_h);
        let mut prk = Hmac::<Sha256>::new_from_slice(&salt).unwrap();
        prk.update(CONNECTION_SECRET);
        let prk = prk.finalize().into_bytes();
        let mut expand = Hmac::<Sha256>::new_from_slice(&prk).unwrap();
        expand.update(INPUT_COMMITMENT_LABEL);
        expand.update(session_id.as_bytes());
        expand.update(&[0x01]);
        let expected: [u8; 32] = expand.finalize().into_bytes().into();
        assert_eq!(key, expected, "the derived key matches the reference HKDF");
    }

    #[test]
    fn fallback_derivation_differs_and_binds_context() {
        let binding = test_binding(0x22);
        let mut controller = test_session(AuditRole::Controller, 4, binding);
        let mut host = test_session(AuditRole::Host, 104, binding);
        handshake_until_readies(&mut controller, &mut host);
        // Re-run with the fallback connection secret mode.
        let hello_c = *controller.local_hello();
        let contrib_c = controller.local_contribution().clone();
        let hello_h = *host.local_hello();
        let contrib_h = host.local_contribution().clone();
        let mut controller = test_session(AuditRole::Controller, 4, binding);
        let mut host = test_session(AuditRole::Host, 104, binding);
        controller.receive_peer_hello(&hello_h, &contrib_h).unwrap();
        host.receive_peer_hello(&hello_c, &contrib_c).unwrap();
        let ready_c = controller
            .compute_ready(ConnectionSecret::NotExportable)
            .unwrap();
        let ready_h = host.compute_ready(ConnectionSecret::NotExportable).unwrap();
        controller.receive_peer_ready(&ready_h).unwrap();
        host.receive_peer_ready(&ready_c).unwrap();
        let fallback_key = *controller.input_key().unwrap().as_bytes();
        let preferred_key = {
            let mut controller = test_session(AuditRole::Controller, 4, binding);
            let mut host = test_session(AuditRole::Host, 104, binding);
            handshake(&mut controller, &mut host);
            *controller.input_key().unwrap().as_bytes()
        };
        assert_ne!(
            fallback_key, preferred_key,
            "the fallback derivation must differ from the preferred one"
        );
    }

    #[test]
    fn receive_peer_hello_rejects_invalid_peers() {
        let binding = test_binding(0x30);
        let mut controller = test_session(AuditRole::Controller, 5, binding);
        let host = test_session(AuditRole::Host, 105, binding);
        let hello_h = *host.local_hello();
        let contrib_h = host.local_contribution().clone();

        // Wrong role: build a hello with the controller's role.
        let mut bytes = hello_h.encode_payload().as_slice().to_vec();
        bytes[0] = AuditRole::Controller.code();
        let role_tampered = AuditHello::decode_payload(&bytes).unwrap();
        assert!(matches!(
            controller.receive_peer_hello(&role_tampered, &contrib_h),
            Err(AuditError::HandshakeInvalid)
        ));

        // Wrong binding.
        let mut bytes = hello_h.encode_payload().as_slice().to_vec();
        bytes[137] ^= 0x01;
        let wrong_binding = AuditHello::decode_payload(&bytes).unwrap();
        assert!(matches!(
            controller.receive_peer_hello(&wrong_binding, &contrib_h),
            Err(AuditError::SessionBindingMismatch)
        ));

        // Unsupported format (version three is structurally decodable but
        // not offered by this endpoint).
        let mut bytes = hello_h.encode_payload().as_slice().to_vec();
        bytes[169..171].copy_from_slice(&3_u16.to_be_bytes());
        let wrong_format = AuditHello::decode_payload(&bytes).unwrap();
        assert!(matches!(
            controller.receive_peer_hello(&wrong_format, &contrib_h),
            Err(AuditError::HandshakeInvalid)
        ));

        // Tampered public key breaks the persistent signature.
        let mut bytes = hello_h.encode_payload().as_slice().to_vec();
        bytes[33] ^= 0x01;
        let tampered = AuditHello::decode_payload(&bytes).unwrap();
        assert!(matches!(
            controller.receive_peer_hello(&tampered, &contrib_h),
            Err(AuditError::PeerSignatureInvalid)
        ));

        // A contribution that does not match the signed commitment.
        let mut wrong = *contrib_h.as_bytes();
        wrong[0] ^= 0x01;
        let wrong_contrib = SecretContribution::new(wrong);
        assert!(matches!(
            controller.receive_peer_hello(&hello_h, &wrong_contrib),
            Err(AuditError::HandshakeInvalid)
        ));

        // A valid hello plus contribution advances the session.
        controller.receive_peer_hello(&hello_h, &contrib_h).unwrap();
    }

    #[test]
    fn receive_peer_ready_rejects_invalid_confirmations() {
        let binding = test_binding(0x31);
        let mut controller = test_session(AuditRole::Controller, 6, binding);
        let mut host = test_session(AuditRole::Host, 106, binding);
        handshake_until_readies(&mut controller, &mut host);
        let ready_h = host.ready.unwrap();

        // Wrong session ID.
        let mut bytes = ready_h.encode_payload().as_slice().to_vec();
        bytes[0] ^= 0x01;
        let wrong_session = AuditReady::decode_payload(&bytes).unwrap();
        assert!(matches!(
            controller.receive_peer_ready(&wrong_session),
            Err(AuditError::HandshakeInvalid)
        ));

        // Wrong peer hello digest.
        let mut bytes = ready_h.encode_payload().as_slice().to_vec();
        bytes[32] ^= 0x01;
        let wrong_digest = AuditReady::decode_payload(&bytes).unwrap();
        assert!(matches!(
            controller.receive_peer_ready(&wrong_digest),
            Err(AuditError::HandshakeInvalid)
        ));

        // Wrong format (version three is structurally decodable but not
        // offered by this endpoint).
        let mut bytes = ready_h.encode_payload().as_slice().to_vec();
        bytes[64..66].copy_from_slice(&3_u16.to_be_bytes());
        let wrong_format = AuditReady::decode_payload(&bytes).unwrap();
        assert!(matches!(
            controller.receive_peer_ready(&wrong_format),
            Err(AuditError::HandshakeInvalid)
        ));

        // Tampered signature.
        let mut bytes = ready_h.encode_payload().as_slice().to_vec();
        bytes[66] ^= 0x01;
        let bad_signature = AuditReady::decode_payload(&bytes).unwrap();
        assert!(matches!(
            controller.receive_peer_ready(&bad_signature),
            Err(AuditError::PeerSignatureInvalid)
        ));

        let ready_c = controller.ready.unwrap();
        controller.receive_peer_ready(&ready_h).unwrap();
        assert!(controller.is_active());
        let _ = ready_c;
    }

    #[test]
    fn input_commitments_match_across_different_chunkings() {
        let binding = test_binding(0x40);
        let mut controller = test_session(AuditRole::Controller, 8, binding);
        let mut host = test_session(AuditRole::Host, 108, binding);
        handshake(&mut controller, &mut host);

        let payload: Vec<u8> = (0..17 * 1024).map(|index| (index % 251) as u8).collect();
        let mut controller_blocks = Vec::new();
        for chunk in payload.chunks(3001) {
            let batch = controller.record_input(chunk, 1_000).unwrap();
            controller_blocks.extend(shared_payloads(&batch, RecordType::SharedInputCommitment));
        }
        let mut host_blocks = Vec::new();
        for chunk in payload.chunks(8191) {
            let batch = host.record_input(chunk, 900).unwrap();
            host_blocks.extend(shared_payloads(&batch, RecordType::SharedInputCommitment));
        }
        assert_eq!(controller_blocks.len(), 1, "17 KiB produces one full block");
        assert_eq!(host_blocks.len(), 1);
        let decoded_c = decode_shared_input(&controller_blocks[0]).unwrap();
        let decoded_h = decode_shared_input(&host_blocks[0]).unwrap();
        assert_eq!(
            decoded_c, decoded_h,
            "both sides record identical input blocks"
        );
        assert_eq!(decoded_c.sequence, 1);
        assert_eq!(decoded_c.length, 16 * 1024);
        // The HMAC must match the manual computation over the block bytes.
        let mut mac = Hmac::<Sha256>::new_from_slice(host.input_key().unwrap().as_bytes()).unwrap();
        mac.update(CHAIN_INPUT_DOMAIN);
        mac.update(&[DIRECTION_CTRL_TO_HOST]);
        mac.update(&1_u64.to_be_bytes());
        mac.update(&(16 * 1024_u64).to_be_bytes());
        mac.update(&payload[..16 * 1024]);
        let expected_hmac: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(decoded_c.hmac, expected_hmac);
    }

    #[test]
    fn output_blocks_commit_sha256_and_chunk_identically() {
        let binding = test_binding(0x41);
        let mut controller = test_session(AuditRole::Controller, 9, binding);
        let mut host = test_session(AuditRole::Host, 109, binding);
        handshake(&mut controller, &mut host);

        let raw: Vec<u8> = (0..16 * 1024 + 200)
            .map(|index| (index % 199) as u8)
            .collect();
        let batch = host.record_output(&raw, 500).unwrap();
        let host_blocks = shared_payloads(&batch, RecordType::SharedOutputBlock);
        assert_eq!(host_blocks.len(), 1);
        let decoded_h = decode_shared_output(&host_blocks[0]).unwrap();
        assert_eq!(decoded_h.length, 16 * 1024);
        assert_eq!(decoded_h.digest, sha256_32(&raw[..16 * 1024]));

        // The controller receives the same bytes in two chunks and computes
        // the same block.
        let batch_a = controller.record_output(&raw[..7000], 600).unwrap();
        let batch_b = controller
            .record_output(&raw[7000..16 * 1024], 610)
            .unwrap();
        let mut controller_blocks = shared_payloads(&batch_a, RecordType::SharedOutputBlock);
        controller_blocks.extend(shared_payloads(&batch_b, RecordType::SharedOutputBlock));
        assert_eq!(controller_blocks.len(), 1);
        let decoded_c = decode_shared_output(&controller_blocks[0]).unwrap();
        assert_eq!(
            decoded_c, decoded_h,
            "both sides commit identical output blocks"
        );

        // The tail is not committed until the direction closes.
        let close = host.close_directions().unwrap();
        let tail_blocks = shared_payloads(&close, RecordType::SharedOutputBlock);
        assert_eq!(tail_blocks.len(), 1);
        let tail = decode_shared_output(&tail_blocks[0]).unwrap();
        assert_eq!(tail.sequence, 2);
        assert_eq!(tail.length, 200);
        assert_eq!(tail.digest, sha256_32(&raw[16 * 1024..]));
    }

    #[test]
    fn normalizer_splits_at_16k_boundaries() {
        let mut normalizer = Normalizer::new();
        let mut completed = Vec::new();
        // 16 KiB - 1 then 1: exactly one block ending with the second byte.
        normalizer
            .feed(&[0xAA; CANONICAL_BLOCK_LEN - 1], |block| {
                completed.push(block.to_vec())
            })
            .unwrap();
        normalizer
            .feed(&[0xBB], |block| completed.push(block.to_vec()))
            .unwrap();
        assert_eq!(completed.len(), 1);
        let mut expected_first = vec![0xAA; CANONICAL_BLOCK_LEN];
        expected_first[CANONICAL_BLOCK_LEN - 1] = 0xBB;
        assert_eq!(completed[0], expected_first);
        assert_eq!(normalizer.partial_len(), 0);
        // 32 KiB in one call: two blocks.
        normalizer
            .feed(&[0xCC; 2 * CANONICAL_BLOCK_LEN], |block| {
                completed.push(block.to_vec())
            })
            .unwrap();
        assert_eq!(completed.len(), 3);
        assert_eq!(completed[1], vec![0xCC; CANONICAL_BLOCK_LEN]);
        assert_eq!(completed[2], vec![0xCC; CANONICAL_BLOCK_LEN]);
        // A partial tail stays buffered.
        normalizer
            .feed(&[0xDD; 5], |block| completed.push(block.to_vec()))
            .unwrap();
        assert_eq!(normalizer.partial_len(), 5);
        assert_eq!(completed.len(), 3);
        // Closing emits the tail as one final block.
        let mut final_blocks = Vec::new();
        assert!(
            normalizer
                .finish(|block| final_blocks.push(block.to_vec()))
                .unwrap()
        );
        assert_eq!(final_blocks.len(), 1);
        assert_eq!(final_blocks[0][..5], [0xDD; 5]);
        // An empty normalizer closes without blocks.
        let mut empty = Normalizer::new();
        assert!(!empty.finish(|_| panic!("no block")).unwrap());
        // A closed normalizer rejects more input.
        assert!(normalizer.feed(&[0], |_| ()).is_err());
        assert!(normalizer.finish(|_| ()).is_err());
    }

    #[test]
    fn normalizer_completes_a_partial_block_then_streams_whole_blocks() {
        let mut normalizer = Normalizer::new();
        normalizer.feed(&[0x11; 7], |_| unreachable!()).unwrap();
        let bytes = vec![0x22; 2 * CANONICAL_BLOCK_LEN];
        let mut completed = Vec::new();
        normalizer
            .feed(&bytes, |block| completed.push(block.to_vec()))
            .unwrap();
        assert_eq!(completed.len(), 2);
        assert_eq!(&completed[0][..7], &[0x11; 7]);
        assert_eq!(normalizer.partial_len(), 7);
        assert!(
            normalizer
                .finish(|block| completed.push(block.to_vec()))
                .unwrap()
        );
        assert_eq!(completed.len(), 3);
    }

    #[test]
    fn empty_directions_produce_no_blocks() {
        let binding = test_binding(0x42);
        let mut session = test_session(AuditRole::Controller, 10, binding);
        let mut host = test_session(AuditRole::Host, 110, binding);
        handshake(&mut session, &mut host);
        let batch = session.close_directions().unwrap();
        assert!(batch.is_empty());
        assert!(host.close_directions().unwrap().is_empty());
    }

    #[test]
    fn every_local_observation_has_a_typed_record() {
        let binding = test_binding(0x42);
        let mut session = test_session(AuditRole::Controller, 71, binding);
        let mut host = test_session(AuditRole::Host, 171, binding);
        handshake(&mut session, &mut host);

        let lifecycle = session
            .record_local_lifecycle(0x7f, ChainHead::new([3; DIGEST_LEN]), 1)
            .unwrap();
        let key = session.record_key_action(0x7e, 2).unwrap();
        let connection = session.record_connection_state(0x7d, 3).unwrap();
        let error = session
            .record_local_audit_error(AuditErrorCode::AuditRecordWriteFailed, 4)
            .unwrap();
        assert_eq!(
            lifecycle.iter().next().unwrap().record_type,
            RecordType::LocalLifecycleEvent
        );
        assert_eq!(
            key.iter().next().unwrap().record_type,
            RecordType::LocalKeyAction
        );
        assert_eq!(
            connection.iter().next().unwrap().record_type,
            RecordType::LocalConnectionState
        );
        assert_eq!(
            error.iter().next().unwrap().record_type,
            RecordType::LocalAuditError
        );
    }

    #[test]
    fn checkpoint_is_non_self_referencing() {
        let binding = test_binding(0x43);
        let mut session = test_session(AuditRole::Controller, 11, binding);
        let mut host = test_session(AuditRole::Host, 111, binding);
        handshake(&mut session, &mut host);

        session.record_input(&[1, 2, 3], 100).unwrap();
        let local_head_before = session.local_chain_head();
        let shared_before = session.shared_snapshot();
        let (checkpoint, evidence) = session.build_checkpoint(1_000_000_000).unwrap();
        assert_eq!(checkpoint.sequence(), 1);
        assert_eq!(
            checkpoint.local_chain_head(),
            &local_head_before,
            "the checkpoint snapshots the pre-evidence local head"
        );
        assert_eq!(
            checkpoint.snapshot(),
            shared_before,
            "the checkpoint snapshots the pre-checkpoint shared chains"
        );
        assert_eq!(evidence.len(), 1);
        // Appending the evidence advances the local chain over the evidence
        // payload, whose previous head is the pre-evidence head.
        let payload = batch_payload(&evidence);
        let (_kind, evidence_bytes) = &payload[0];
        let head = local_event_hash(
            local_head_before.as_bytes(),
            2,
            1_000_000_000,
            RecordType::CheckpointEvidence.code(),
            &evidence_bytes[SPLIT_PREFIX_LEN..],
            &[0; DIGEST_LEN],
        );
        assert_eq!(ChainHead::new(head), session.local_chain_head());
        // The checkpoint signature verifies with the local session key.
        verify_signature(
            &session.session_pubkey,
            checkpoint.signing_input().as_slice(),
            checkpoint.signature(),
        )
        .unwrap();
        // The checkpoint payload is embedded in the evidence record.
        let mut expected = Vec::new();
        expected.push(EVIDENCE_SENT_CHECKPOINT);
        expected.extend_from_slice(
            &(checkpoint.encode_payload().as_slice().len() as u32).to_be_bytes(),
        );
        expected.extend_from_slice(checkpoint.encode_payload().as_slice());
        assert_eq!(&evidence_bytes[SPLIT_PREFIX_LEN..], &expected[..]);
    }

    #[test]
    fn checkpoint_exchange_confirms_on_both_sides() {
        let binding = test_binding(0x44);
        let mut controller = test_session(AuditRole::Controller, 12, binding);
        let mut host = test_session(AuditRole::Host, 112, binding);
        handshake(&mut controller, &mut host);

        // The same facts on both sides.
        let input = b"echo hello\n";
        controller.record_input(input, 10).unwrap();
        host.record_input(input, 12).unwrap();
        let output = b"hello\r\n";
        host.record_output(output, 20).unwrap();
        controller.record_output(output, 22).unwrap();

        // The controller builds and sends a checkpoint; the host receives.
        let (checkpoint, evidence) = controller.build_checkpoint(1_000_000_000).unwrap();
        assert_eq!(evidence.len(), 1);
        let (ack, host_evidence) = host.receive_checkpoint(&checkpoint, 1_000_000_005).unwrap();
        assert_eq!(
            host_evidence.len(),
            2,
            "received checkpoint and sent ack evidence"
        );
        assert_eq!(ack.sequence(), 1);
        assert_eq!(ack.snapshot(), checkpoint.snapshot());
        let confirmed = controller
            .receive_checkpoint_ack(&ack, 1_000_000_010)
            .unwrap();
        assert!(confirmed.is_some());
        assert_eq!(controller.last_confirmed_checkpoint_sequence(), 1);
        // The host did not fail, and both sides still record.
        assert!(!host.has_failed());
        let more = host.record_output(b"x", 30).unwrap();
        assert_eq!(more.len(), 1);
    }

    #[test]
    fn running_checkpoint_tolerates_cross_stream_progress_but_final_mismatch_fails_closed() {
        let binding = test_binding(0x45);
        let mut controller = test_session(AuditRole::Controller, 13, binding);
        let mut host = test_session(AuditRole::Host, 113, binding);
        handshake(&mut controller, &mut host);

        // The controller commits a completed shared input block the host
        // has not observed.
        let chunk = vec![0x33; 16 * 1024];
        controller.record_input(&chunk, 10).unwrap();
        let (checkpoint, _) = controller.build_checkpoint(1_000_000_000).unwrap();
        let (ack, _) = host.receive_checkpoint(&checkpoint, 1_000_000_000).unwrap();
        assert_eq!(ack.snapshot(), checkpoint.snapshot());
        assert!(!host.has_failed());

        host.close_directions().unwrap();
        let result = host.receive_final_checkpoint(&checkpoint, 1_000_000_001);
        assert!(matches!(result, Err(AuditError::CheckpointMismatch)));
        assert!(host.has_failed());
        assert!(matches!(
            host.record_input(b"x", 20),
            Err(AuditError::FailedClosed)
        ));

        // A skipped or wrong-digest ack also fails the sender closed.
        let mut controller = test_session(AuditRole::Controller, 14, binding);
        let mut host = test_session(AuditRole::Host, 114, binding);
        handshake(&mut controller, &mut host);
        let (checkpoint, _) = controller.build_checkpoint(1_000_000_000).unwrap();
        let (ack, _) = host.receive_checkpoint(&checkpoint, 1_000_000_000).unwrap();
        let mut bytes = ack.encode_payload().as_slice().to_vec();
        bytes[40] ^= 0x01; // corrupt the checkpoint digest
        let bad_ack = CheckpointAck::decode_payload(&bytes).unwrap();
        assert!(matches!(
            controller.receive_checkpoint_ack(&bad_ack, 1_000_000_010),
            Err(AuditError::CheckpointMismatch)
        ));
        assert!(controller.has_failed());
    }

    #[test]
    fn checkpoint_and_ack_security_fields_fail_closed_independently() {
        fn exchange(
            binding: BindingDigest,
        ) -> (AuditSession, AuditSession, Checkpoint, CheckpointAck) {
            let mut controller = test_session(AuditRole::Controller, 70, binding);
            let mut host = test_session(AuditRole::Host, 170, binding);
            handshake(&mut controller, &mut host);
            let (checkpoint, _) = controller.build_checkpoint(1).unwrap();
            let (ack, _) = host.receive_checkpoint(&checkpoint, 2).unwrap();
            (controller, host, checkpoint, ack)
        }

        let binding = test_binding(0x71);

        // The same endpoint keys on a different authenticated connection
        // produce a valid signature over a different session ID.
        let (_, mut receiver, _, _) = exchange(binding);
        let (_, _, foreign_checkpoint, _) = exchange(test_binding(0x72));
        assert!(matches!(
            receiver.receive_checkpoint(&foreign_checkpoint, 3),
            Err(AuditError::CheckpointMismatch)
        ));
        assert!(receiver.has_failed());

        // A correctly signed checkpoint may not skip the expected sequence.
        let mut controller = test_session(AuditRole::Controller, 70, binding);
        let mut host = test_session(AuditRole::Host, 170, binding);
        handshake(&mut controller, &mut host);
        controller.build_checkpoint(1).unwrap();
        let (skipped, _) = controller.build_checkpoint(2).unwrap();
        assert!(matches!(
            host.receive_checkpoint(&skipped, 3),
            Err(AuditError::CheckpointMismatch)
        ));

        // A payload-preserving decode with a changed signature is rejected.
        let (_, mut host, checkpoint, _) = exchange(binding);
        let mut bytes = checkpoint.encode_payload().as_slice().to_vec();
        *bytes.last_mut().unwrap() ^= 1;
        let forged = Checkpoint::decode_payload(&bytes).unwrap();
        assert!(matches!(
            host.receive_checkpoint(&forged, 3),
            Err(AuditError::CheckpointMismatch)
        ));

        // Ack checks are deliberately ordered so each independent security
        // field is rejected before a later signature failure can mask it.
        let (mut controller, _, _, ack) = exchange(binding);
        let mut bytes = ack.encode_payload().as_slice().to_vec();
        bytes[0] ^= 1;
        let wrong_session = CheckpointAck::decode_payload(&bytes).unwrap();
        assert!(matches!(
            controller.receive_checkpoint_ack(&wrong_session, 4),
            Err(AuditError::CheckpointMismatch)
        ));

        let (mut controller, _, _, ack) = exchange(binding);
        let mut bytes = ack.encode_payload().as_slice().to_vec();
        bytes[39] ^= 1;
        let wrong_sequence = CheckpointAck::decode_payload(&bytes).unwrap();
        assert!(matches!(
            controller.receive_checkpoint_ack(&wrong_sequence, 4),
            Err(AuditError::CheckpointMismatch)
        ));

        for offset in [40, 72] {
            let (mut controller, _, _, ack) = exchange(binding);
            let mut bytes = ack.encode_payload().as_slice().to_vec();
            bytes[offset] ^= 1;
            let wrong_commitment = CheckpointAck::decode_payload(&bytes).unwrap();
            assert!(matches!(
                controller.receive_checkpoint_ack(&wrong_commitment, 4),
                Err(AuditError::CheckpointMismatch)
            ));
        }

        let (mut controller, _, _, ack) = exchange(binding);
        let mut bytes = ack.encode_payload().as_slice().to_vec();
        *bytes.last_mut().unwrap() ^= 1;
        let forged = CheckpointAck::decode_payload(&bytes).unwrap();
        assert!(matches!(
            controller.receive_checkpoint_ack(&forged, 4),
            Err(AuditError::CheckpointMismatch)
        ));

        // An otherwise valid ack is invalid without an outstanding local
        // checkpoint, while an exact duplicate after confirmation is benign.
        let (_, _, _, ack) = exchange(binding);
        let mut no_pending = test_session(AuditRole::Controller, 70, binding);
        let mut peer = test_session(AuditRole::Host, 170, binding);
        handshake(&mut no_pending, &mut peer);
        assert!(matches!(
            no_pending.receive_checkpoint_ack(&ack, 4),
            Err(AuditError::InvalidState(
                "no checkpoint awaiting confirmation"
            ))
        ));

        let (mut controller, _, _, ack) = exchange(binding);
        assert!(
            controller
                .receive_checkpoint_ack(&ack, 4)
                .unwrap()
                .is_some()
        );
        assert!(
            controller
                .receive_checkpoint_ack(&ack, 5)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn duplicate_checkpoint_retransmission_is_re_acked_without_evidence() {
        let binding = test_binding(0x46);
        let mut controller = test_session(AuditRole::Controller, 15, binding);
        let mut host = test_session(AuditRole::Host, 115, binding);
        handshake(&mut controller, &mut host);
        let (checkpoint, _) = controller.build_checkpoint(1_000_000_000).unwrap();
        let (ack, host_evidence) = host.receive_checkpoint(&checkpoint, 1).unwrap();
        assert_eq!(host_evidence.len(), 2);
        // The sender lost the ack and retransmits the identical checkpoint.
        let (ack2, evidence2) = host.receive_checkpoint(&checkpoint, 2).unwrap();
        assert!(evidence2.is_empty(), "no new evidence for a duplicate");
        assert_eq!(ack2, ack, "the duplicate ack is byte-identical");
        assert!(!host.has_failed());
    }

    #[test]
    fn checkpoint_time_trigger_fires_after_one_second() {
        let binding = test_binding(0x48);
        let mut session = test_session(AuditRole::Controller, 27, binding);
        let mut host = test_session(AuditRole::Host, 127, binding);
        handshake(&mut session, &mut host);
        session.record_input(b"x", 0).unwrap();
        // The checkpoint resets the time base.
        let (_, _) = session.build_checkpoint(1_000_000_000).unwrap();
        assert!(!session.checkpoint_due(1_000_000_000));
        assert!(!session.checkpoint_due(1_999_999_999));
        assert!(session.checkpoint_due(2_000_000_000), "one second elapsed");
    }

    #[test]
    fn peer_unsupported_error_uses_the_frozen_message() {
        let error = AuditError::peer_unsupported();
        assert_eq!(
            error.to_string(),
            PEER_AUDIT_UNSUPPORTED_MESSAGE,
            "design section 14 fixed error text"
        );
        assert_eq!(error.code(), Some(AuditErrorCode::AuditProtocolUnsupported));
    }

    #[test]
    fn checkpoint_size_trigger_fires_at_one_mebibyte() {
        let binding = test_binding(0x47);
        let mut session = test_session(AuditRole::Controller, 16, binding);
        let mut host = test_session(AuditRole::Host, 116, binding);
        handshake(&mut session, &mut host);
        assert!(session.record_input(&[], 0).unwrap().is_empty());
        // 64 chunks of 16 KiB of input complete 64 blocks, far past 1 MiB.
        let chunk = vec![0x5A; 16 * 1024];
        let mut due = false;
        for _ in 0..64 {
            session.record_input(&chunk, 1).unwrap();
            due |= session.checkpoint_due(1);
        }
        assert!(due, "the 1 MiB size trigger marks a checkpoint due");

        let mut output = test_session(AuditRole::Controller, 17, binding);
        let mut output_host = test_session(AuditRole::Host, 117, binding);
        handshake(&mut output, &mut output_host);
        for _ in 0..64 {
            output.record_output(&chunk, 1).unwrap();
        }
        assert!(
            output.checkpoint_due(1),
            "output bytes share the same 1 MiB checkpoint trigger"
        );
    }

    #[test]
    fn checkpoint_messages_are_rejected_outside_active_or_finalizing_phases() {
        let binding = test_binding(0x49);
        let mut controller = test_session(AuditRole::Controller, 18, binding);
        let mut host = test_session(AuditRole::Host, 118, binding);
        handshake(&mut controller, &mut host);
        let (checkpoint, _) = controller.build_checkpoint(1).unwrap();
        let (ack, _) = host.receive_checkpoint(&checkpoint, 2).unwrap();

        let mut fresh = test_session(AuditRole::Host, 119, binding);
        assert!(matches!(
            fresh.receive_checkpoint(&checkpoint, 3),
            Err(AuditError::InvalidState(
                "checkpoint observation outside an active session"
            ))
        ));
        assert!(matches!(
            fresh.receive_checkpoint_ack(&ack, 4),
            Err(AuditError::InvalidState(
                "checkpoint acknowledgment outside an active session"
            ))
        ));
        fresh
            .fail_closed_records(
                AuditErrorCode::AuditRecordWriteFailed,
                AuditCloseReason::AuditFailure,
                5,
            )
            .unwrap();
        assert!(matches!(
            fresh.receive_checkpoint_ack(&ack, 6),
            Err(AuditError::FailedClosed)
        ));
    }

    #[tokio::test]
    async fn footer_prefix_requires_a_verified_peer_manifest() {
        let dir = tempdir().unwrap();
        let records = dir.path().join("records");
        let binding = test_binding(0x4A);
        let mut controller = test_session(AuditRole::Controller, 19, binding);
        let mut host = test_session(AuditRole::Host, 120, binding);
        handshake_with_header(&mut controller, &mut host);
        controller.close_directions().unwrap();
        host.close_directions().unwrap();
        let (manifest, signature, _) = controller
            .build_manifest(ManifestEnding::ShellExit(0), true, 1)
            .unwrap();
        let session_id = *manifest.session_id();
        let mut writer = AuditWriter::open(&records, &session_id, AuditRole::Controller).unwrap();

        assert!(matches!(
            controller
                .write_footer_prefix(&mut writer, &manifest, signature, signature)
                .await,
            Err(AuditError::InvalidState(
                "the peer manifest was not received and verified"
            ))
        ));
    }

    #[test]
    fn manifest_round_trip_and_dual_signature_exchange() {
        let binding = test_binding(0x50);
        let mut controller = test_session(AuditRole::Controller, 17, binding);
        let mut host = test_session(AuditRole::Host, 117, binding);
        handshake_with_header(&mut controller, &mut host);

        // Identical facts on both sides, then finalization preparation.
        let input = b"ls -la\n";
        controller.record_input(input, 10).unwrap();
        host.record_input(input, 12).unwrap();
        controller.close_directions().unwrap();
        host.close_directions().unwrap();

        let (manifest_c, signature_c, _) = controller
            .build_manifest(ManifestEnding::ShellExit(0), true, 30)
            .unwrap();
        let (manifest_h, signature_h, _) = host
            .build_manifest(ManifestEnding::ShellExit(0), true, 31)
            .unwrap();
        assert_eq!(
            manifest_c, manifest_h,
            "both sides construct the identical manifest"
        );
        assert_eq!(
            manifest_c.controller_fingerprint(),
            manifest_h.controller_fingerprint()
        );
        assert_eq!(manifest_c.ending(), ManifestEnding::ShellExit(0));
        assert_eq!(manifest_c.final_checkpoint_sequence(), 0);

        // Each side verifies the peer's manifest and signature.
        let batch_c = controller
            .receive_peer_manifest_pair(&manifest_c, &manifest_h, &signature_h, 40)
            .unwrap();
        let batch_h = host
            .receive_peer_manifest_pair(&manifest_h, &manifest_c, &signature_c, 41)
            .unwrap();
        assert_eq!(batch_c.len(), 2);
        assert_eq!(batch_h.len(), 2);
        // The manifest signature verifies over the manifest signing input.
        verify_signature(
            host.local_hello().session_key(),
            manifest_h.signing_input().unwrap().as_slice(),
            signature_h.signature(),
        )
        .unwrap();
    }

    #[test]
    fn peer_manifest_mismatch_and_bad_signature_are_rejected() {
        let binding = test_binding(0x51);
        let mut controller = test_session(AuditRole::Controller, 18, binding);
        let mut host = test_session(AuditRole::Host, 118, binding);
        handshake_with_header(&mut controller, &mut host);
        controller.close_directions().unwrap();
        host.close_directions().unwrap();
        let (manifest_c, signature_c, _) = controller
            .build_manifest(ManifestEnding::ShellExit(0), true, 2)
            .unwrap();
        let (manifest_h, signature_h, _) = host
            .build_manifest(ManifestEnding::ShellExit(1), false, 2)
            .unwrap();

        // A different ending is a final manifest mismatch.
        assert!(matches!(
            controller.receive_peer_manifest_pair(&manifest_c, &manifest_h, &signature_h, 3),
            Err(AuditError::FinalManifestMismatch)
        ));
        // A signature from the wrong session key is invalid.
        let forged = ManifestSignature::new(*signature_c.signature());
        assert!(matches!(
            controller.receive_peer_manifest_pair(&manifest_c, &manifest_c, &forged, 3),
            Err(AuditError::PeerSignatureInvalid)
        ));
    }

    #[test]
    fn fail_closed_records_preserve_an_interrupted_prefix() {
        let binding = test_binding(0x60);
        let mut session = test_session(AuditRole::Controller, 19, binding);
        let mut host = test_session(AuditRole::Host, 119, binding);
        handshake(&mut session, &mut host);
        session.record_input(b"data", 10).unwrap();
        let batch = session
            .fail_closed_records(
                AuditErrorCode::AuditCheckpointMismatch,
                AuditCloseReason::AuditFailure,
                20,
            )
            .unwrap();
        assert_eq!(
            batch.len(),
            3,
            "audit error, connection state and close event"
        );
        let kinds: Vec<RecordType> = batch.iter().map(|record| record.record_type).collect();
        assert_eq!(
            kinds,
            vec![
                RecordType::LocalAuditError,
                RecordType::LocalConnectionState,
                RecordType::LocalCloseEvent
            ]
        );
        assert!(session.has_failed());
        assert!(matches!(
            session.record_input(b"more", 30),
            Err(AuditError::FailedClosed)
        ));
        assert!(matches!(
            session.fail_closed_records(
                AuditErrorCode::AuditCheckpointMismatch,
                AuditCloseReason::AuditFailure,
                30
            ),
            Err(AuditError::FailedClosed)
        ));
    }

    #[test]
    fn secrets_are_never_printed() {
        let binding = test_binding(0x61);
        let mut session = test_session(AuditRole::Controller, 20, binding);
        let mut host = test_session(AuditRole::Host, 120, binding);
        handshake(&mut session, &mut host);
        let debug = format!("{session:?}");
        assert!(!debug.contains("InputCommitmentKey"));
        assert!(!debug.contains("SecretContribution"));
        assert!(debug.contains("REDACTED"));
        let key_debug = format!("{:?}", session.input_key().unwrap());
        assert_eq!(key_debug, "InputCommitmentKey([REDACTED])");
        let contribution_debug = format!("{:?}", session.local_contribution());
        assert!(contribution_debug.contains("REDACTED"));
    }

    #[test]
    fn resize_and_file_transfer_events_are_shared_and_structured() {
        let binding = test_binding(0x62);
        let mut controller = test_session(AuditRole::Controller, 21, binding);
        let mut host = test_session(AuditRole::Host, 121, binding);
        handshake(&mut controller, &mut host);

        let resize = controller
            .record_resize(DIRECTION_CTRL_TO_HOST, 120, 40, 1)
            .unwrap();
        let kinds: Vec<RecordType> = resize.iter().map(|record| record.record_type).collect();
        assert_eq!(
            kinds,
            vec![RecordType::SharedControlEvent, RecordType::LocalResizeEvent]
        );
        let shared = shared_payloads(&resize, RecordType::SharedControlEvent);
        let control = decode_shared_control(&shared[0]).unwrap();
        assert_eq!(control.kind, CONTROL_KIND_RESIZE);
        assert_eq!(control.control_payload, vec![0, 120, 0, 40]);

        let facts = FileTransferFacts {
            transfer_id: 7,
            direction: FILE_DIRECTION_UPLOAD,
            kind: FILE_KIND_SUCCESS,
            declared_size: 1000,
            final_size: 1000,
            digest: Digest32::new([9; DIGEST_LEN]),
            remote_path: "/home/alice/notes.txt",
            file_name: "notes.txt",
            error_code: 0,
        };
        let file = controller
            .record_file_transfer(&facts, Some(r"C:\local\notes.txt"), 2)
            .unwrap();
        let kinds: Vec<RecordType> = file.iter().map(|record| record.record_type).collect();
        assert_eq!(
            kinds,
            vec![
                RecordType::SharedFileTransferEvent,
                RecordType::LocalFileTransferEvent
            ]
        );
        let shared = shared_payloads(&file, RecordType::SharedFileTransferEvent);
        let decoded = decode_shared_file(&shared[0]).unwrap();
        assert_eq!(decoded.sequence, 1);
        assert_eq!(decoded.transfer_id, 7);
        assert_eq!(decoded.remote_path, "/home/alice/notes.txt");
        assert_eq!(decoded.file_name, "notes.txt");
        assert_eq!(decoded.final_size, 1000);
    }

    #[test]
    fn file_transfer_audit_rejects_every_unbounded_path_field() {
        fn facts<'a>(remote_path: &'a str, file_name: &'a str) -> FileTransferFacts<'a> {
            FileTransferFacts {
                transfer_id: 8,
                direction: FILE_DIRECTION_DOWNLOAD,
                kind: FILE_KIND_SUCCESS,
                declared_size: 1,
                final_size: 1,
                digest: Digest32::new([8; DIGEST_LEN]),
                remote_path,
                file_name,
                error_code: 0,
            }
        }

        let binding = test_binding(0x63);
        let mut controller = test_session(AuditRole::Controller, 23, binding);
        let mut host = test_session(AuditRole::Host, 123, binding);
        handshake(&mut controller, &mut host);

        let remote_path = "r".repeat(MAX_PROTOCOL_PATH_LEN + 1);
        let file_name = "f".repeat(MAX_PROTOCOL_FILE_NAME_LEN + 1);
        assert!(matches!(
            controller.record_file_transfer(&facts(&remote_path, "ok"), None, 1),
            Err(AuditError::SegmentTooLarge)
        ));
        assert!(matches!(
            controller.record_file_transfer(&facts("/ok", &file_name), None, 2),
            Err(AuditError::SegmentTooLarge)
        ));

        let local_path = "l".repeat(MAX_LOCAL_PATH_LEN + 1);
        assert!(matches!(
            controller.record_file_transfer(&facts("/ok", "ok"), Some(&local_path), 3),
            Err(AuditError::SegmentTooLarge)
        ));
    }

    #[test]
    fn terminal_segments_and_shared_decoders_enforce_every_size_boundary() {
        let binding = test_binding(0x64);
        let mut controller = test_session(AuditRole::Controller, 24, binding);
        let mut host = test_session(AuditRole::Host, 124, binding);
        handshake(&mut controller, &mut host);

        let oversized_input = vec![0; MAX_INPUT_SEGMENT + 1];
        assert!(matches!(
            controller.record_input(&oversized_input, 1),
            Err(AuditError::SegmentTooLarge)
        ));
        let oversized_output = vec![0; MAX_LOCAL_OUTPUT_SEGMENT + 1];
        assert!(matches!(
            controller.record_output(&oversized_output, 2),
            Err(AuditError::SegmentTooLarge)
        ));
        assert!(matches!(
            controller.record_controller_output(&[], &oversized_output, 3),
            Err(AuditError::SegmentTooLarge)
        ));
        assert!(matches!(
            controller.record_display_bytes(&oversized_output, 4),
            Err(AuditError::SegmentTooLarge)
        ));

        assert!(matches!(
            decode_shared_input(&[]),
            Err(AuditError::ContainerInvalid)
        ));
        assert!(matches!(
            decode_shared_output(&[]),
            Err(AuditError::ContainerInvalid)
        ));
        assert!(matches!(
            decode_shared_control(&[]),
            Err(AuditError::ContainerInvalid)
        ));

        let facts = FileTransferFacts {
            transfer_id: 9,
            direction: FILE_DIRECTION_UPLOAD,
            kind: FILE_KIND_SUCCESS,
            declared_size: 1,
            final_size: 1,
            digest: Digest32::new([9; DIGEST_LEN]),
            remote_path: "/ok",
            file_name: "ok",
            error_code: 0,
        };
        let batch = controller.record_file_transfer(&facts, None, 5).unwrap();
        let mut payload = shared_payloads(&batch, RecordType::SharedFileTransferEvent)
            .pop()
            .unwrap();
        payload.push(0);
        assert!(matches!(
            decode_shared_file(&payload),
            Err(AuditError::ContainerInvalid)
        ));
    }

    /// A full bilateral session through real writers: handshake, recording,
    /// checkpoint exchange, direction close, manifest exchange and acyclic
    /// finalization. The two containers must agree on every shared chain.
    #[tokio::test]
    async fn full_bilateral_session_finalizes_matching_containers() {
        let dir = tempdir().unwrap();
        let records = dir.path().join("records");
        let binding = test_binding(0x70);
        let ledger_c = TestLedger::new();
        let ledger_h = TestLedger::new();
        let mut controller =
            test_session_with_ledger(AuditRole::Controller, 22, binding, ledger_c.clone());
        let mut host = test_session_with_ledger(AuditRole::Host, 122, binding, ledger_h.clone());
        let (ready_c, ready_h) = handshake_until_readies(&mut controller, &mut host);
        let session_id = controller.session_id().unwrap();

        let mut controller_writer =
            AuditWriter::open(&records, &session_id, AuditRole::Controller).unwrap();
        let mut host_writer = AuditWriter::open(&records, &session_id, AuditRole::Host).unwrap();
        let header_c = controller
            .build_header(&ready_c, Digest32::new([1; DIGEST_LEN]))
            .unwrap();
        let header_h = host
            .build_header(&ready_h, Digest32::new([1; DIGEST_LEN]))
            .unwrap();
        controller_writer.initialize(&header_c).await.unwrap();
        host_writer.initialize(&header_h).await.unwrap();
        controller.receive_peer_ready(&ready_h).unwrap();
        host.receive_peer_ready(&ready_c).unwrap();

        // Terminal lifecycle on both sides.
        let ready_batch = controller.record_terminal_ready(100).unwrap();
        controller_writer.append_batch(ready_batch).await.unwrap();
        let ready_batch = host.record_terminal_ready(110).unwrap();
        host_writer.append_batch(ready_batch).await.unwrap();

        // Input: controller sends, host receives the same bytes in chunks.
        let input: Vec<u8> = (0..20 * 1024).map(|index| (index % 7) as u8).collect();
        for chunk in input.chunks(4096) {
            let batch = controller.record_input(chunk, 200).unwrap();
            controller_writer.append_batch(batch).await.unwrap();
        }
        for chunk in input.chunks(2048) {
            let batch = host.record_input(chunk, 210).unwrap();
            host_writer.append_batch(batch).await.unwrap();
        }
        // Output: host reads, controller receives and displays.
        let output: Vec<u8> = (0..18 * 1024).map(|index| (index % 11) as u8).collect();
        let batch = host.record_output(&output, 300).unwrap();
        host_writer.append_batch(batch).await.unwrap();
        let display: Vec<u8> = output.iter().map(|byte| byte | 0x80).collect();
        let batch = controller
            .record_controller_output(&output, &display, 310)
            .unwrap();
        controller_writer.append_batch(batch).await.unwrap();
        let outcome = controller
            .record_display_write_outcome(true, display.len() as u64, 320)
            .unwrap();
        controller_writer.append_batch(outcome).await.unwrap();

        // A bilateral checkpoint with synced files.
        controller_writer.sync_all().await.unwrap();
        let (checkpoint, evidence) = controller.build_checkpoint(1_000_000_000).unwrap();
        controller_writer.append_batch(evidence).await.unwrap();
        let (ack, host_evidence) = host.receive_checkpoint(&checkpoint, 1_000_000_000).unwrap();
        host_writer.append_batch(host_evidence).await.unwrap();
        host_writer.sync_all().await.unwrap();
        let ack_evidence = controller
            .receive_checkpoint_ack(&ack, 1_000_000_010)
            .unwrap()
            .unwrap();
        controller_writer.append_batch(ack_evidence).await.unwrap();

        // Terminal exit, direction close and final manifest exchange.
        let exit = controller.record_terminal_exit(0, 400).unwrap();
        controller_writer.append_batch(exit).await.unwrap();
        let exit = host.record_terminal_exit(0, 410).unwrap();
        host_writer.append_batch(exit).await.unwrap();
        let close = controller.close_directions().unwrap();
        controller_writer.append_batch(close).await.unwrap();
        let close = host.close_directions().unwrap();
        host_writer.append_batch(close).await.unwrap();

        let (manifest_c, signature_c, evidence) = controller
            .build_manifest(ManifestEnding::ShellExit(0), true, 500)
            .unwrap();
        controller_writer.append_batch(evidence).await.unwrap();
        let (manifest_h, signature_h, evidence) = host
            .build_manifest(ManifestEnding::ShellExit(0), true, 501)
            .unwrap();
        host_writer.append_batch(evidence).await.unwrap();
        assert_eq!(manifest_c, manifest_h);
        let evidence = controller
            .receive_peer_manifest_pair(&manifest_c, &manifest_h, &signature_h, 510)
            .unwrap();
        controller_writer.append_batch(evidence).await.unwrap();
        let evidence = host
            .receive_peer_manifest_pair(&manifest_h, &manifest_c, &signature_c, 511)
            .unwrap();
        host_writer.append_batch(evidence).await.unwrap();

        // Acyclic finalization with ledger commits.
        let controller_local_root = controller.local_chain_head();
        let host_local_root = host.local_chain_head();
        controller
            .finalize_footer(
                &mut controller_writer,
                &manifest_c,
                signature_c,
                signature_h,
            )
            .await
            .unwrap();
        host.finalize_footer(&mut host_writer, &manifest_h, signature_h, signature_c)
            .await
            .unwrap();
        let ledger_c_state = ledger_c.state.lock().unwrap();
        let ledger_h_state = ledger_h.state.lock().unwrap();
        assert_eq!(ledger_c_state.commits.len(), 1);
        assert_eq!(ledger_h_state.commits.len(), 1);
        assert_eq!(
            ledger_c_state.commits[0].manifest_digest(),
            ledger_h_state.commits[0].manifest_digest()
        );
        assert_eq!(ledger_c_state.commits[0].session_id(), &session_id);

        // Both files parse and their shared chains agree.
        let controller_bytes = std::fs::read(controller_writer.record_path()).unwrap();
        let host_bytes = std::fs::read(host_writer.record_path()).unwrap();
        let (controller_chains, controller_manifest, controller_footer) =
            walk_container(&controller_bytes);
        let (host_chains, host_manifest, host_footer) = walk_container(&host_bytes);
        assert_eq!(controller_chains, host_chains, "all shared chains agree");
        assert_eq!(controller_manifest, host_manifest);
        assert_eq!(controller_manifest.final_checkpoint_sequence(), 1);
        assert_eq!(
            controller_footer.footer.seal.final_local_event_root(),
            &controller_local_root,
            "the seal binds the final local chain root"
        );
        assert_eq!(
            host_footer.footer.seal.final_local_event_root(),
            &host_local_root,
            "the seal binds the final local chain root"
        );
        // The sealed record digest covers everything through the seal.
        let expected_sealed = sha256_32(&controller_bytes[..controller_footer.seal_end]);
        assert_eq!(
            controller_footer
                .footer
                .ledger_commit
                .sealed_record_digest()
                .as_bytes(),
            &expected_sealed
        );
        // The final container digest covers everything before itself.
        let expected_final = sha256_32(&controller_bytes[..controller_footer.ledger_end]);
        assert_eq!(
            controller_footer.final_container_digest.as_bytes(),
            &expected_final
        );
    }

    #[test]
    fn audit_error_codes_and_clones_preserve_every_public_category() {
        let categorized = [
            (
                AuditError::IdentityMissing,
                AuditErrorCode::AuditIdentityMissing,
            ),
            (
                AuditError::IdentityInvalid,
                AuditErrorCode::AuditIdentityInvalid,
            ),
            (
                AuditError::IdentityPermissions,
                AuditErrorCode::AuditIdentityPermissions,
            ),
            (
                AuditError::LedgerInvalid,
                AuditErrorCode::AuditLedgerInvalid,
            ),
            (
                AuditError::LedgerConflict,
                AuditErrorCode::AuditLedgerConflict,
            ),
            (
                AuditError::DirectoryUnavailable(io::Error::other("directory")),
                AuditErrorCode::AuditDirectoryUnavailable,
            ),
            (
                AuditError::RecordCreateFailed(io::Error::other("create")),
                AuditErrorCode::AuditRecordCreateFailed,
            ),
            (
                AuditError::RecordWriteFailed(io::Error::other("write")),
                AuditErrorCode::AuditRecordWriteFailed,
            ),
            (
                AuditError::RecordSyncFailed(io::Error::other("sync")),
                AuditErrorCode::AuditRecordSyncFailed,
            ),
            (
                AuditError::peer_unsupported(),
                AuditErrorCode::AuditProtocolUnsupported,
            ),
            (
                AuditError::HandshakeInvalid,
                AuditErrorCode::AuditHandshakeInvalid,
            ),
            (
                AuditError::SessionBindingMismatch,
                AuditErrorCode::AuditSessionBindingMismatch,
            ),
            (
                AuditError::CheckpointMismatch,
                AuditErrorCode::AuditCheckpointMismatch,
            ),
            (
                AuditError::PeerSignatureInvalid,
                AuditErrorCode::AuditPeerSignatureInvalid,
            ),
            (
                AuditError::FinalManifestMismatch,
                AuditErrorCode::AuditFinalManifestMismatch,
            ),
            (
                AuditError::LedgerCommitFailed,
                AuditErrorCode::AuditLedgerCommitFailed,
            ),
            (AuditError::ReplayUnsafe, AuditErrorCode::AuditReplayUnsafe),
            (
                AuditError::ContainerInvalid,
                AuditErrorCode::AuditContainerInvalid,
            ),
        ];
        for (error, code) in categorized {
            assert_eq!(error.code(), Some(code));
            assert_eq!(error.clone().code(), Some(code));
        }

        let uncategorized = [
            AuditError::RandomSource(RandomError),
            AuditError::Protocol(ProtocolError::InvalidLength {
                expected: 1,
                actual: 0,
            }),
            AuditError::Substream(io::Error::other("stream")),
            AuditError::SegmentTooLarge,
            AuditError::InvalidState("state"),
            AuditError::FailedClosed,
            AuditError::WriterTerminated,
        ];
        for error in uncategorized {
            assert_eq!(error.code(), None);
            assert_eq!(error.clone().code(), None);
        }
    }

    #[test]
    fn record_payloads_and_bounded_collectors_enforce_their_limits() {
        let inline = Payload::Inline {
            bytes: [0; MAX_INLINE_PAYLOAD_LEN],
            len: 3,
        };
        let boxed = Payload::Boxed(vec![1, 2, 3, 4].into_boxed_slice());
        let split = Payload::Split {
            prefix: [0; SPLIT_PREFIX_LEN],
            body: &[1, 2],
        };
        assert_eq!(inline.len(), 3);
        assert_eq!(boxed.len(), 4);
        assert_eq!(split.len(), SPLIT_PREFIX_LEN + 2);
        assert!(!inline.is_empty());
        assert!(
            Payload::Inline {
                bytes: [0; MAX_INLINE_PAYLOAD_LEN],
                len: 0,
            }
            .is_empty()
        );

        let mut batch = RecordBatch::default();
        assert!(batch.is_empty());
        assert!(matches!(
            batch.push_inline(RecordType::LocalKeyAction, &[0; MAX_INLINE_PAYLOAD_LEN + 1]),
            Err(AuditError::InvalidState(_))
        ));
        for _ in 0..MAX_RECORDS_PER_STEP {
            batch
                .push_inline(RecordType::LocalKeyAction, &[KEY_ACTION_HELP])
                .unwrap();
        }
        assert_eq!(batch.len(), MAX_RECORDS_PER_STEP);
        assert!(matches!(
            batch.push_inline(RecordType::LocalKeyAction, &[KEY_ACTION_HELP]),
            Err(AuditError::InvalidState(_))
        ));
        assert_eq!(batch.iter().count(), MAX_RECORDS_PER_STEP);

        let block = CompletedBlock {
            payload: [0; SHARED_INPUT_RECORD_LEN],
            head: ChainHead::new([7; DIGEST_LEN]),
        };
        let mut collector = BlockCollector::new();
        assert_eq!(collector.last_head(), None);
        for _ in 0..MAX_BLOCKS_PER_SEGMENT {
            collector.push(block).unwrap();
        }
        assert_eq!(collector.last_head(), Some(block.head));
        assert!(matches!(
            collector.push(block),
            Err(AuditError::InvalidState(_))
        ));
    }

    #[test]
    fn normalizer_and_session_phases_reject_operations_after_their_boundary() {
        let mut normalizer = Normalizer::default();
        normalizer.feed(b"partial", |_| {}).unwrap();
        let mut tail = Vec::new();
        assert!(
            normalizer
                .finish(|bytes| tail.extend_from_slice(bytes))
                .unwrap()
        );
        assert_eq!(tail, b"partial");
        assert!(matches!(
            normalizer.feed(b"late", |_| {}),
            Err(AuditError::InvalidState(_))
        ));
        assert!(matches!(
            normalizer.finish(|_| {}),
            Err(AuditError::InvalidState(_))
        ));

        let mut session = test_session(AuditRole::Controller, 88, test_binding(88));
        assert_eq!(session.role(), AuditRole::Controller);
        assert_eq!(session.session_id(), None);
        assert!(session.input_key().is_none());
        assert_eq!(session.local_event_count(), 0);
        assert_eq!(session.local_chain_head(), zero_head());
        assert!(matches!(
            session.record_key_action(KEY_ACTION_HELP, 1),
            Err(AuditError::InvalidState(_))
        ));
        let records = session
            .fail_closed_records(
                AuditErrorCode::AuditRecordWriteFailed,
                AuditCloseReason::AuditFailure,
                2,
            )
            .unwrap();
        assert_eq!(records.len(), 3);
        assert!(matches!(
            session.record_connection_state(CONNECTION_STATE_LOST, 3),
            Err(AuditError::FailedClosed)
        ));
        assert!(matches!(
            session.fail_closed_records(
                AuditErrorCode::AuditRecordWriteFailed,
                AuditCloseReason::AuditFailure,
                4,
            ),
            Err(AuditError::FailedClosed)
        ));
    }

    /// Walks one container, collecting the decoded shared chains per
    /// stream, the manifest and the footer.
    fn walk_container(
        bytes: &[u8],
    ) -> (
        Vec<(SharedStream, Vec<DecodedShared>)>,
        JointManifest,
        DecodedFooter,
    ) {
        let mut reader = ContainerReader::new(bytes).unwrap();
        let mut chains: Vec<(SharedStream, Vec<DecodedShared>)> = Vec::new();
        while let Some(frame) = reader.next_frame().unwrap() {
            let decoded = match frame.record_type {
                RecordType::SharedInputCommitment => {
                    decode_shared_input(frame.payload).map(DecodedShared::Input)
                }
                RecordType::SharedOutputBlock => {
                    decode_shared_output(frame.payload).map(DecodedShared::Output)
                }
                RecordType::SharedControlEvent => {
                    decode_shared_control(frame.payload).map(|control| {
                        DecodedShared::Control(
                            control.kind,
                            control.previous_head,
                            control.new_head,
                        )
                    })
                }
                _ => continue,
            }
            .unwrap();
            let stream = match frame.record_type {
                RecordType::SharedInputCommitment => SharedStream::Input,
                RecordType::SharedOutputBlock => SharedStream::Output,
                _ => SharedStream::Control,
            };
            let entry =
                if let Some(entry) = chains.iter_mut().find(|(existing, _)| *existing == stream) {
                    entry
                } else {
                    chains.push((stream, Vec::new()));
                    chains.last_mut().expect("the entry was just pushed")
                };
            entry.1.push(decoded);
        }
        let footer = reader.footer().unwrap();
        (chains, footer.footer.manifest.clone(), footer)
    }

    #[derive(Debug, PartialEq, Eq, Clone)]
    enum DecodedShared {
        Input(DecodedSharedInput),
        Output(DecodedSharedOutput),
        Control(u8, ChainHead, ChainHead),
    }
}
