//! Bounded wire messages for the Yonder verifiable session audit protocol,
//! Yonder 0.2.0 design sections 13 (audit session establishment), 20
//! (bilateral checkpoints), 21 (final joint manifest and local record seal),
//! 12 (local ledger) and 23 (audit file format).
//!
//! Every wire message uses the unified frame:
//!
//! ```text
//! 1 byte  tag
//! 4 bytes payload_length, unsigned big-endian
//! N bytes payload
//! ```
//!
//! All integers are big-endian, strings carry an explicit `u16` byte length
//! and must be UTF-8, and message bodies never repeat the protocol version:
//! the negotiated protocol ID `/yonder/audit/3.0.0` already carries it, the
//! same convention as [`super::auth`]. The one exception is the audit file
//! format version, which is a separate version space from the protocol ID
//! and is carried explicitly where the design requires it.
//!
//! The fixed 3.0.0 message set:
//!
//! ```text
//! tag   message            payload
//! 0x01  AuditHello         fixed 267 bytes (audit identity and session facts)
//! 0x02  SecretContribution fixed 32 bytes (the raw input commitment secret)
//! 0x03  AuditReady         fixed 130 bytes (session confirmation, signed)
//! 0x04  Checkpoint         fixed 328 bytes (pre-checkpoint snapshot, signed)
//! 0x05  CheckpointAck      fixed 296 bytes (checkpoint confirmation, signed)
//! 0x06  JointManifest      400 bytes (final joint manifest)
//! 0x07  ManifestSignature  fixed 64 bytes (ephemeral session signature)
//! 0x08  LocalRecordSeal    fixed 329 bytes (local record seal, signed)
//! 0x09  LedgerCommit       fixed 233 bytes (persistent ledger commit, signed)
//! 0x0A  CloseNotice        fixed 1 byte (session close reason)
//! 0x0B  AuditError         fixed 2 bytes (structured audit failure code)
//! ```
//!
//! This layer is pure byte structure: it never hashes, derives keys or
//! verifies signatures. Every signed message exposes its canonical signing
//! input (a fixed domain-separation label plus the message fields without
//! the signature field) so the session layer can sign and verify without
//! re-deriving the byte layout. Domain labels here are distinct per message
//! kind; the hash-chain domain labels of design section 17.3 belong to the
//! chain layer and never appear on the wire.
//!
//! Decoders validate lengths before reading payloads, reject unknown tags,
//! reject trailing bytes and never allocate from peer-declared sizes.

use super::WireBytes;
use crate::error::{ProtocolError, ProtocolField};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The negotiated application protocol ID for verifiable session audit.
pub const AUDIT_PROTOCOL: &str = "/yonder/audit/3.0.0";

/// The frozen audit file format version carried by the container header, the
/// `AuditHello`/`AuditReady` format offers and the `JointManifest`.
pub const AUDIT_FORMAT_VERSION: u16 = 3;

/// SHA-256 digest byte length.
pub const DIGEST_LEN: usize = 32;
/// Audit nonce byte length (design section 13.3).
pub const NONCE_LEN: usize = 32;
/// Ed25519 public key byte length.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// Ed25519 signature byte length.
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// The number of shared fact chains (design sections 15.2 and 16).
pub const SHARED_STREAMS: usize = 4;
/// Frame header: tag plus big-endian payload length.
pub const FRAME_HEADER_LEN: usize = 5;
/// `AuditHello` payload: role, two public keys, nonce, ledger snapshot,
/// connection binding, format offer, input commitment and signature.
pub const AUDIT_HELLO_LEN: usize = 1
    + ED25519_PUBLIC_KEY_LEN * 2
    + NONCE_LEN
    + 8
    + DIGEST_LEN * 2
    + 2
    + DIGEST_LEN
    + ED25519_SIGNATURE_LEN;
/// `AuditReady` payload: session ID, peer `AuditHello` digest, format
/// agreement and signature.
pub const AUDIT_READY_LEN: usize = DIGEST_LEN * 2 + 2 + ED25519_SIGNATURE_LEN;
/// `Checkpoint` payload: session ID, sequence, the four-stream shared
/// snapshot, the local chain head, the ledger snapshot digest and signature.
pub const CHECKPOINT_LEN: usize =
    DIGEST_LEN + 8 + SHARED_STREAMS * (8 + DIGEST_LEN) + DIGEST_LEN * 2 + ED25519_SIGNATURE_LEN;
/// `CheckpointAck` payload: session ID, sequence, checkpoint digest, the
/// receiver's shared snapshot and signature.
pub const CHECKPOINT_ACK_LEN: usize =
    DIGEST_LEN * 2 + 8 + SHARED_STREAMS * (8 + DIGEST_LEN) + ED25519_SIGNATURE_LEN;
/// Fixed `JointManifest` payload.
pub const MANIFEST_LEN: usize = 2
    + DIGEST_LEN * 4
    + ED25519_PUBLIC_KEY_LEN * 2
    + DIGEST_LEN
    + SHARED_STREAMS * (DIGEST_LEN + 8)
    + 1
    + 4
    + 1
    + 8;
/// `LocalRecordSeal` payload.
pub const LOCAL_RECORD_SEAL_LEN: usize = DIGEST_LEN
    + 1
    + DIGEST_LEN
    + 8
    + SHARED_STREAMS * DIGEST_LEN
    + DIGEST_LEN * 2
    + ED25519_SIGNATURE_LEN;
/// `LedgerCommit` payload.
pub const LEDGER_COMMIT_LEN: usize = 8 + DIGEST_LEN * 5 + 1 + ED25519_SIGNATURE_LEN;
/// `SecretContribution` payload.
pub const SECRET_CONTRIBUTION_LEN: usize = NONCE_LEN;
/// `ManifestSignature` payload.
pub const MANIFEST_SIGNATURE_LEN: usize = ED25519_SIGNATURE_LEN;
/// `CloseNotice` payload.
pub const CLOSE_NOTICE_LEN: usize = 1;
/// `AuditError` payload.
pub const AUDIT_ERROR_LEN: usize = 2;
/// Every audit payload fits under this bound.
pub const MAX_AUDIT_PAYLOAD_LEN: usize = 1024;
/// A complete framed audit message: header plus the maximum payload.
pub const MAX_AUDIT_FRAME_LEN: usize = FRAME_HEADER_LEN + MAX_AUDIT_PAYLOAD_LEN;

/// Fixed domain-separation labels for signed audit messages. Each label is
/// distinct per message kind and versioned; signatures cover the label
/// followed by the message fields without the signature field itself.
pub const AUDIT_HELLO_DOMAIN: &[u8] = b"yonder-audit-hello-v3";
pub const AUDIT_READY_DOMAIN: &[u8] = b"yonder-audit-ready-v3";
pub const CHECKPOINT_DOMAIN: &[u8] = b"yonder-audit-checkpoint-v3";
pub const CHECKPOINT_ACK_DOMAIN: &[u8] = b"yonder-audit-checkpoint-ack-v3";
pub const MANIFEST_DOMAIN: &[u8] = b"yonder-audit-manifest-v3";
pub const SEAL_DOMAIN: &[u8] = b"yonder-audit-seal-v3";
pub const LEDGER_COMMIT_DOMAIN: &[u8] = b"yonder-audit-ledger-commit-v3";

/// Signing input lengths: domain label plus the unsigned message fields.
pub const AUDIT_HELLO_SIGNING_LEN: usize =
    AUDIT_HELLO_DOMAIN.len() + AUDIT_HELLO_LEN - ED25519_SIGNATURE_LEN;
pub const AUDIT_READY_SIGNING_LEN: usize =
    AUDIT_READY_DOMAIN.len() + AUDIT_READY_LEN - ED25519_SIGNATURE_LEN;
pub const CHECKPOINT_SIGNING_LEN: usize =
    CHECKPOINT_DOMAIN.len() + CHECKPOINT_LEN - ED25519_SIGNATURE_LEN;
pub const CHECKPOINT_ACK_SIGNING_LEN: usize =
    CHECKPOINT_ACK_DOMAIN.len() + CHECKPOINT_ACK_LEN - ED25519_SIGNATURE_LEN;
pub const MANIFEST_SIGNING_INPUT_LEN: usize = MANIFEST_DOMAIN.len() + MANIFEST_LEN;
pub const SEAL_SIGNING_LEN: usize =
    SEAL_DOMAIN.len() + LOCAL_RECORD_SEAL_LEN - ED25519_SIGNATURE_LEN;
pub const LEDGER_COMMIT_SIGNING_LEN: usize =
    LEDGER_COMMIT_DOMAIN.len() + LEDGER_COMMIT_LEN - ED25519_SIGNATURE_LEN;

/// The fixed error a 0.2.0 endpoint reports when the peer cannot open the
/// mandatory audit substream (design section 14).
pub const PEER_AUDIT_UNSUPPORTED_MESSAGE: &str =
    "peer does not support mandatory verifiable session audit";

/// Fixed 3.0.0 audit message tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditTag {
    AuditHello = 0x01,
    SecretContribution = 0x02,
    AuditReady = 0x03,
    Checkpoint = 0x04,
    CheckpointAck = 0x05,
    JointManifest = 0x06,
    ManifestSignature = 0x07,
    LocalRecordSeal = 0x08,
    LedgerCommit = 0x09,
    CloseNotice = 0x0A,
    AuditError = 0x0B,
}

impl AuditTag {
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::AuditHello),
            0x02 => Some(Self::SecretContribution),
            0x03 => Some(Self::AuditReady),
            0x04 => Some(Self::Checkpoint),
            0x05 => Some(Self::CheckpointAck),
            0x06 => Some(Self::JointManifest),
            0x07 => Some(Self::ManifestSignature),
            0x08 => Some(Self::LocalRecordSeal),
            0x09 => Some(Self::LedgerCommit),
            0x0A => Some(Self::CloseNotice),
            0x0B => Some(Self::AuditError),
            _ => None,
        }
    }
}

/// The role a session side plays; the controller and the host record their
/// own roles in their local audit files (design section 13.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditRole {
    Controller = 0x01,
    Host = 0x02,
}

impl AuditRole {
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Controller),
            0x02 => Some(Self::Host),
            _ => None,
        }
    }
}

/// The authentication mode recorded in the container header (design
/// section 23.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthMode {
    Enterprise = 0x02,
}

impl AuthMode {
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x02 => Some(Self::Enterprise),
            _ => None,
        }
    }
}

/// The session result recorded in a ledger commit (design section 12.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionResult {
    /// The session finalized normally with a joint manifest and seal.
    Normal = 0x01,
    /// The session was interrupted without a final joint manifest.
    Interrupted = 0x02,
    /// The session was terminated because audit finalization failed.
    AuditFailed = 0x03,
}

impl SessionResult {
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Normal),
            0x02 => Some(Self::Interrupted),
            0x03 => Some(Self::AuditFailed),
            _ => None,
        }
    }
}

/// A structured session close reason (design sections 15.2 and 22). The
/// shared close event enters the shared fact chain only after the reason was
/// successfully conveyed to the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditCloseReason {
    /// The remote shell exited normally (design section 22.1).
    NormalShellExit = 0x01,
    /// The controller detached with `Ctrl+] .` (design section 22.2).
    ControllerDetach = 0x02,
    /// The session was interrupted locally, for example by `Ctrl+C`
    /// (design section 22.3).
    LocalInterrupt = 0x03,
    /// The end-to-end connection was lost (design section 22.4).
    ConnectionLost = 0x04,
    /// The session failed closed because recording could not continue
    /// (design section 18.7).
    AuditFailure = 0x05,
}

impl AuditCloseReason {
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::NormalShellExit),
            0x02 => Some(Self::ControllerDetach),
            0x03 => Some(Self::LocalInterrupt),
            0x04 => Some(Self::ConnectionLost),
            0x05 => Some(Self::AuditFailure),
            _ => None,
        }
    }
}

/// Fixed 3.0.0 structured audit failure codes, one per category of design
/// section 30. Values `0` and undefined values are protocol errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AuditErrorCode {
    AuditIdentityMissing = 1,
    AuditIdentityInvalid = 2,
    AuditIdentityPermissions = 3,
    AuditLedgerInvalid = 4,
    AuditLedgerConflict = 5,
    AuditDirectoryUnavailable = 6,
    AuditRecordCreateFailed = 7,
    AuditRecordWriteFailed = 8,
    AuditRecordSyncFailed = 9,
    AuditProtocolUnsupported = 10,
    AuditHandshakeInvalid = 11,
    AuditSessionBindingMismatch = 12,
    AuditCheckpointMismatch = 13,
    AuditPeerSignatureInvalid = 14,
    AuditFinalManifestMismatch = 15,
    AuditLedgerCommitFailed = 16,
    AuditReplayUnsafe = 17,
    AuditContainerInvalid = 18,
}

impl AuditErrorCode {
    #[must_use]
    pub const fn code(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::AuditIdentityMissing),
            2 => Some(Self::AuditIdentityInvalid),
            3 => Some(Self::AuditIdentityPermissions),
            4 => Some(Self::AuditLedgerInvalid),
            5 => Some(Self::AuditLedgerConflict),
            6 => Some(Self::AuditDirectoryUnavailable),
            7 => Some(Self::AuditRecordCreateFailed),
            8 => Some(Self::AuditRecordWriteFailed),
            9 => Some(Self::AuditRecordSyncFailed),
            10 => Some(Self::AuditProtocolUnsupported),
            11 => Some(Self::AuditHandshakeInvalid),
            12 => Some(Self::AuditSessionBindingMismatch),
            13 => Some(Self::AuditCheckpointMismatch),
            14 => Some(Self::AuditPeerSignatureInvalid),
            15 => Some(Self::AuditFinalManifestMismatch),
            16 => Some(Self::AuditLedgerCommitFailed),
            17 => Some(Self::AuditReplayUnsafe),
            18 => Some(Self::AuditContainerInvalid),
            _ => None,
        }
    }
}

/// How a session ended, as recorded in the joint manifest: either the
/// terminal exited with a code or the session was closed with a reason
/// (design section 21.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestEnding {
    ShellExit(u32),
    CloseReason(AuditCloseReason),
}

impl ManifestEnding {
    /// The fixed one-byte wire tag of the ending variant.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::ShellExit(_) => 0x01,
            Self::CloseReason(_) => 0x02,
        }
    }

    /// The four-byte unsigned payload of the ending variant.
    #[must_use]
    pub const fn value(self) -> u32 {
        match self {
            Self::ShellExit(code) => code,
            Self::CloseReason(reason) => reason.code() as u32,
        }
    }

    #[must_use]
    pub const fn from_bytes(tag: u8, value: u32) -> Option<Self> {
        match tag {
            0x01 => Some(Self::ShellExit(value)),
            0x02 => Some(Self::CloseReason(match value {
                0x01 => AuditCloseReason::NormalShellExit,
                0x02 => AuditCloseReason::ControllerDetach,
                0x03 => AuditCloseReason::LocalInterrupt,
                0x04 => AuditCloseReason::ConnectionLost,
                0x05 => AuditCloseReason::AuditFailure,
                _ => return None,
            })),
            _ => None,
        }
    }
}

/// One shared fact chain: the input commitment chain, the output digest
/// chain, the terminal control chain and the file transfer event chain
/// (design sections 15.2 and 16). The wire order is fixed by
/// [`SharedStream::ALL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedStream {
    /// Controller-to-host terminal input commitments (design section 16.2).
    Input,
    /// Host-to-controller terminal output block digests (design section 16.3).
    Output,
    /// Terminal control events: resize, lifecycle digests, close reasons.
    Control,
    /// File transfer events (design section 18.6).
    FileTransfer,
}

impl SharedStream {
    /// Every stream in the fixed wire order.
    pub const ALL: [Self; SHARED_STREAMS] =
        [Self::Input, Self::Output, Self::Control, Self::FileTransfer];

    /// The fixed zero-based wire position of the stream.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Input => 0,
            Self::Output => 1,
            Self::Control => 2,
            Self::FileTransfer => 3,
        }
    }

    #[must_use]
    pub const fn from_index(index: usize) -> Option<Self> {
        match index {
            0 => Some(Self::Input),
            1 => Some(Self::Output),
            2 => Some(Self::Control),
            3 => Some(Self::FileTransfer),
            _ => None,
        }
    }
}

/// The count and pre-checkpoint (or final) chain head of one shared stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamSnapshot {
    count: u64,
    head: ChainHead,
}

impl StreamSnapshot {
    #[must_use]
    pub const fn new(count: u64, head: ChainHead) -> Self {
        Self { count, head }
    }

    /// The number of events committed to the stream.
    #[must_use]
    pub const fn count(self) -> u64 {
        self.count
    }

    /// The stream chain head covered by this snapshot.
    #[must_use]
    pub const fn head(self) -> ChainHead {
        self.head
    }
}

/// The fixed per-stream snapshots of all shared fact chains. The wire
/// encoding is `count || head` for each stream in [`SharedStream::ALL`]
/// order, so the stream identity is positional and never repeated on the
/// wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedSnapshot {
    streams: [StreamSnapshot; SHARED_STREAMS],
}

impl SharedSnapshot {
    #[must_use]
    pub const fn new(streams: [StreamSnapshot; SHARED_STREAMS]) -> Self {
        Self { streams }
    }

    /// The snapshot of one named stream.
    #[must_use]
    pub const fn get(self, stream: SharedStream) -> StreamSnapshot {
        self.streams[stream.index()]
    }

    /// Every stream snapshot in wire order.
    #[must_use]
    pub const fn streams(self) -> [StreamSnapshot; SHARED_STREAMS] {
        self.streams
    }

    /// Every stream count in wire order.
    #[must_use]
    pub const fn counts(self) -> [u64; SHARED_STREAMS] {
        [
            self.streams[0].count,
            self.streams[1].count,
            self.streams[2].count,
            self.streams[3].count,
        ]
    }

    /// Every stream chain head in wire order.
    #[must_use]
    pub const fn roots(self) -> [ChainHead; SHARED_STREAMS] {
        [
            self.streams[0].head,
            self.streams[1].head,
            self.streams[2].head,
            self.streams[3].head,
        ]
    }
}

macro_rules! fixed_bytes_newtype {
    ($(#[$meta:meta])* $name:ident, $len:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name([u8; $len]);

        impl $name {
            #[must_use]
            pub const fn new(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }
    };
}

fixed_bytes_newtype! {
    /// The 32-byte session ID computed by both sides from the design
    /// section 13.4 binding formula.
    SessionId, DIGEST_LEN
}
fixed_bytes_newtype! {
    /// A 32-byte random session nonce contributed by one side
    /// (design section 13.3).
    AuditNonce, NONCE_LEN
}
fixed_bytes_newtype! {
    /// A 32-byte SHA-256 fingerprint of one side's persistent audit identity
    /// public key (design sections 9.4 and 21.1).
    IdentityFingerprint, DIGEST_LEN
}
fixed_bytes_newtype! {
    /// A 32-byte shared or local observation hash chain head (design
    /// section 17).
    ChainHead, DIGEST_LEN
}
fixed_bytes_newtype! {
    /// A 32-byte local audit ledger root (design section 12).
    LedgerRoot, DIGEST_LEN
}
fixed_bytes_newtype! {
    /// The 32-byte authenticated connection binding digest carried by the
    /// audit handshake (design section 13.3).
    BindingDigest, DIGEST_LEN
}
fixed_bytes_newtype! {
    /// The 32-byte SHA-256 commitment to one side's input commitment secret
    /// contribution (design section 13.3). The raw secret contribution is
    /// never persisted.
    CommitmentDigest, DIGEST_LEN
}
fixed_bytes_newtype! {
    /// A generic 32-byte SHA-256 digest: the peer `AuditHello` digest, the
    /// `Checkpoint` digest, the `TerminalHello` digest, the ledger snapshot
    /// digest, the joint manifest digest, the sealed prefix digest and the
    /// final container digest.
    Digest32, DIGEST_LEN
}
fixed_bytes_newtype! {
    /// A 32-byte Ed25519 public key: the persistent audit identity key or a
    /// per-session ephemeral signing key (design sections 9.1 and 9.3).
    Ed25519PublicKey, ED25519_PUBLIC_KEY_LEN
}
fixed_bytes_newtype! {
    /// A 64-byte Ed25519 signature. Signing itself lives in the session,
    /// ledger and verify layers; the wire layer only carries and bounds the
    /// signature bytes.
    Ed25519Signature, ED25519_SIGNATURE_LEN
}

/// The raw 32-byte input commitment secret contribution exchanged once over
/// the authenticated audit substream (design section 13.3). The receiver
/// verifies that its SHA-256 equals the commitment signed inside the peer's
/// `AuditHello`. The contribution is session-private, is never written to an
/// audit file and is destroyed with the session.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretContribution([u8; NONCE_LEN]);

impl SecretContribution {
    #[must_use]
    pub const fn new(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for SecretContribution {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SecretContribution([REDACTED])")
    }
}

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

/// The controller's (or host's) audit handshake opener, design section 13.3.
///
/// The payload carries the role, the persistent audit public key, the
/// per-session ephemeral signing public key, a 32-byte nonce, the local
/// ledger sequence and root snapshot at session start, the authenticated
/// connection binding digest, the offered audit file format version, the
/// SHA-256 commitment to the local input commitment secret contribution, and
/// the persistent audit identity signature over all public fields
/// (see [`AuditHello::signing_input`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditHello {
    role: AuditRole,
    persistent_audit_key: Ed25519PublicKey,
    session_key: Ed25519PublicKey,
    nonce: AuditNonce,
    ledger_sequence: u64,
    ledger_root: LedgerRoot,
    connection_binding: BindingDigest,
    format_version: u16,
    input_commitment: CommitmentDigest,
    signature: Ed25519Signature,
}

impl AuditHello {
    /// Builds a hello with a placeholder signature; the caller signs
    /// [`AuditHello::signing_input`] with the persistent audit identity and
    /// attaches the signature with [`AuditHello::with_signature`].
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        role: AuditRole,
        persistent_audit_key: Ed25519PublicKey,
        session_key: Ed25519PublicKey,
        nonce: AuditNonce,
        ledger_sequence: u64,
        ledger_root: LedgerRoot,
        connection_binding: BindingDigest,
        format_version: u16,
        input_commitment: CommitmentDigest,
        signature: Ed25519Signature,
    ) -> Self {
        Self {
            role,
            persistent_audit_key,
            session_key,
            nonce,
            ledger_sequence,
            ledger_root,
            connection_binding,
            format_version,
            input_commitment,
            signature,
        }
    }

    #[must_use]
    pub const fn role(&self) -> AuditRole {
        self.role
    }

    #[must_use]
    pub const fn persistent_audit_key(&self) -> &Ed25519PublicKey {
        &self.persistent_audit_key
    }

    #[must_use]
    pub const fn session_key(&self) -> &Ed25519PublicKey {
        &self.session_key
    }

    #[must_use]
    pub const fn nonce(&self) -> &AuditNonce {
        &self.nonce
    }

    #[must_use]
    pub const fn ledger_sequence(&self) -> u64 {
        self.ledger_sequence
    }

    #[must_use]
    pub const fn ledger_root(&self) -> &LedgerRoot {
        &self.ledger_root
    }

    #[must_use]
    pub const fn connection_binding(&self) -> &BindingDigest {
        &self.connection_binding
    }

    #[must_use]
    pub const fn format_version(&self) -> u16 {
        self.format_version
    }

    #[must_use]
    pub const fn input_commitment(&self) -> &CommitmentDigest {
        &self.input_commitment
    }

    #[must_use]
    pub const fn signature(&self) -> &Ed25519Signature {
        &self.signature
    }

    /// Attaches the persistent identity signature computed over
    /// [`AuditHello::signing_input`].
    #[must_use]
    pub const fn with_signature(mut self, signature: Ed25519Signature) -> Self {
        self.signature = signature;
        self
    }

    /// The canonical signed bytes: the domain label followed by every public
    /// field except the signature. The persistent audit identity signs these
    /// bytes (design section 13.3).
    #[must_use]
    pub fn signing_input(&self) -> WireBytes<AUDIT_HELLO_SIGNING_LEN> {
        let mut bytes = [0_u8; AUDIT_HELLO_SIGNING_LEN];
        let mut cursor = 0;
        append(&mut bytes, &mut cursor, AUDIT_HELLO_DOMAIN);
        append(&mut bytes, &mut cursor, &[self.role.code()]);
        append(
            &mut bytes,
            &mut cursor,
            self.persistent_audit_key.as_bytes(),
        );
        append(&mut bytes, &mut cursor, self.session_key.as_bytes());
        append(&mut bytes, &mut cursor, self.nonce.as_bytes());
        write_u64(&mut bytes, &mut cursor, self.ledger_sequence);
        append(&mut bytes, &mut cursor, self.ledger_root.as_bytes());
        append(&mut bytes, &mut cursor, self.connection_binding.as_bytes());
        write_u16(&mut bytes, &mut cursor, self.format_version);
        append(&mut bytes, &mut cursor, self.input_commitment.as_bytes());
        WireBytes::new(bytes, cursor)
    }

    #[must_use]
    pub fn encode_payload(&self) -> WireBytes<MAX_AUDIT_PAYLOAD_LEN> {
        let mut bytes = [0_u8; MAX_AUDIT_PAYLOAD_LEN];
        let mut cursor = 0;
        append(&mut bytes, &mut cursor, &[self.role.code()]);
        append(
            &mut bytes,
            &mut cursor,
            self.persistent_audit_key.as_bytes(),
        );
        append(&mut bytes, &mut cursor, self.session_key.as_bytes());
        append(&mut bytes, &mut cursor, self.nonce.as_bytes());
        write_u64(&mut bytes, &mut cursor, self.ledger_sequence);
        append(&mut bytes, &mut cursor, self.ledger_root.as_bytes());
        append(&mut bytes, &mut cursor, self.connection_binding.as_bytes());
        write_u16(&mut bytes, &mut cursor, self.format_version);
        append(&mut bytes, &mut cursor, self.input_commitment.as_bytes());
        append(&mut bytes, &mut cursor, self.signature.as_bytes());
        WireBytes::new(bytes, cursor)
    }

    /// Decodes an exact [`AUDIT_HELLO_LEN`]-byte payload.
    pub fn decode_payload(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let bytes: [u8; AUDIT_HELLO_LEN] =
            bytes.try_into().map_err(|_| ProtocolError::InvalidLength {
                expected: AUDIT_HELLO_LEN,
                actual: bytes.len(),
            })?;
        let role = AuditRole::from_byte(bytes[0])
            .ok_or(ProtocolError::InvalidField(ProtocolField::Reserved))?;
        let format_version = u16::from_be_bytes([bytes[169], bytes[170]]);
        if format_version == 0 {
            return Err(ProtocolError::InvalidField(ProtocolField::Reserved));
        }
        let mut persistent_audit_key = [0_u8; ED25519_PUBLIC_KEY_LEN];
        persistent_audit_key.copy_from_slice(&bytes[1..33]);
        let mut session_key = [0_u8; ED25519_PUBLIC_KEY_LEN];
        session_key.copy_from_slice(&bytes[33..65]);
        let mut nonce = [0_u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[65..97]);
        let ledger_sequence =
            u64::from_be_bytes(bytes[97..105].try_into().expect("fixed eight-byte slice"));
        let mut ledger_root = [0_u8; DIGEST_LEN];
        ledger_root.copy_from_slice(&bytes[105..137]);
        let mut connection_binding = [0_u8; DIGEST_LEN];
        connection_binding.copy_from_slice(&bytes[137..169]);
        let mut input_commitment = [0_u8; DIGEST_LEN];
        input_commitment.copy_from_slice(&bytes[171..203]);
        let mut signature = [0_u8; ED25519_SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[203..267]);
        Ok(Self::new(
            role,
            Ed25519PublicKey::new(persistent_audit_key),
            Ed25519PublicKey::new(session_key),
            AuditNonce::new(nonce),
            ledger_sequence,
            LedgerRoot::new(ledger_root),
            BindingDigest::new(connection_binding),
            format_version,
            CommitmentDigest::new(input_commitment),
            Ed25519Signature::new(signature),
        ))
    }
}

/// The raw input commitment secret contribution, design section 13.3. The
/// receiver verifies that `SHA-256(contribution)` equals the commitment
/// signed inside the peer's `AuditHello`; the contribution itself is never
/// persisted.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SecretContributionMessage(SecretContribution);

impl SecretContributionMessage {
    #[must_use]
    pub const fn new(contribution: SecretContribution) -> Self {
        Self(contribution)
    }

    #[must_use]
    pub const fn contribution(&self) -> &SecretContribution {
        &self.0
    }

    #[must_use]
    pub fn encode_payload(&self) -> WireBytes<MAX_AUDIT_PAYLOAD_LEN> {
        let mut bytes = [0_u8; MAX_AUDIT_PAYLOAD_LEN];
        bytes[..SECRET_CONTRIBUTION_LEN].copy_from_slice(self.0.as_bytes());
        WireBytes::new(bytes, SECRET_CONTRIBUTION_LEN)
    }

    /// Decodes an exact [`SECRET_CONTRIBUTION_LEN`]-byte payload.
    pub fn decode_payload(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let contribution: [u8; SECRET_CONTRIBUTION_LEN] =
            bytes.try_into().map_err(|_| ProtocolError::InvalidLength {
                expected: SECRET_CONTRIBUTION_LEN,
                actual: bytes.len(),
            })?;
        Ok(Self::new(SecretContribution::new(contribution)))
    }
}

/// The audit handshake confirmation, design section 13.5: each side sends
/// its session ID, a digest of the peer's encoded `AuditHello` (binding the
/// peer's identity keys, format offer and input commitment), the negotiated
/// format version, and a signature by the local ephemeral session key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditReady {
    session_id: SessionId,
    peer_audit_hello_digest: Digest32,
    format_version: u16,
    signature: Ed25519Signature,
}

impl AuditReady {
    /// Builds a ready with a placeholder signature; the caller signs
    /// [`AuditReady::signing_input`] with the local ephemeral session key.
    #[must_use]
    pub const fn new(
        session_id: SessionId,
        peer_audit_hello_digest: Digest32,
        format_version: u16,
        signature: Ed25519Signature,
    ) -> Self {
        Self {
            session_id,
            peer_audit_hello_digest,
            format_version,
            signature,
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn peer_audit_hello_digest(&self) -> &Digest32 {
        &self.peer_audit_hello_digest
    }

    #[must_use]
    pub const fn format_version(&self) -> u16 {
        self.format_version
    }

    #[must_use]
    pub const fn signature(&self) -> &Ed25519Signature {
        &self.signature
    }

    /// Attaches the ephemeral session signature computed over
    /// [`AuditReady::signing_input`].
    #[must_use]
    pub const fn with_signature(mut self, signature: Ed25519Signature) -> Self {
        self.signature = signature;
        self
    }

    /// The canonical signed bytes: the domain label, the session ID, the
    /// peer `AuditHello` digest and the format version.
    #[must_use]
    pub fn signing_input(&self) -> WireBytes<AUDIT_READY_SIGNING_LEN> {
        let mut bytes = [0_u8; AUDIT_READY_SIGNING_LEN];
        let mut cursor = 0;
        append(&mut bytes, &mut cursor, AUDIT_READY_DOMAIN);
        append(&mut bytes, &mut cursor, self.session_id.as_bytes());
        append(
            &mut bytes,
            &mut cursor,
            self.peer_audit_hello_digest.as_bytes(),
        );
        write_u16(&mut bytes, &mut cursor, self.format_version);
        WireBytes::new(bytes, cursor)
    }

    #[must_use]
    pub fn encode_payload(&self) -> WireBytes<MAX_AUDIT_PAYLOAD_LEN> {
        let mut bytes = [0_u8; MAX_AUDIT_PAYLOAD_LEN];
        let mut cursor = 0;
        append(&mut bytes, &mut cursor, self.session_id.as_bytes());
        append(
            &mut bytes,
            &mut cursor,
            self.peer_audit_hello_digest.as_bytes(),
        );
        write_u16(&mut bytes, &mut cursor, self.format_version);
        append(&mut bytes, &mut cursor, self.signature.as_bytes());
        WireBytes::new(bytes, cursor)
    }

    /// Decodes an exact [`AUDIT_READY_LEN`]-byte payload.
    pub fn decode_payload(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let bytes: [u8; AUDIT_READY_LEN] =
            bytes.try_into().map_err(|_| ProtocolError::InvalidLength {
                expected: AUDIT_READY_LEN,
                actual: bytes.len(),
            })?;
        let format_version = u16::from_be_bytes([bytes[64], bytes[65]]);
        if format_version == 0 {
            return Err(ProtocolError::InvalidField(ProtocolField::Reserved));
        }
        let mut session_id = [0_u8; DIGEST_LEN];
        session_id.copy_from_slice(&bytes[..32]);
        let mut peer_digest = [0_u8; DIGEST_LEN];
        peer_digest.copy_from_slice(&bytes[32..64]);
        let mut signature = [0_u8; ED25519_SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[66..130]);
        Ok(Self::new(
            SessionId::new(session_id),
            Digest32::new(peer_digest),
            format_version,
            Ed25519Signature::new(signature),
        ))
    }
}

/// A bilateral checkpoint, design section 20.2: a signed, non-self-referencing
/// snapshot of the state *before* the checkpoint was generated. The sender
/// signs it with the local ephemeral session key, then appends the checkpoint
/// evidence to the local observation chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    session_id: SessionId,
    sequence: u64,
    snapshot: SharedSnapshot,
    local_chain_head: ChainHead,
    ledger_snapshot_digest: Digest32,
    signature: Ed25519Signature,
}

impl Checkpoint {
    /// Builds a checkpoint with a placeholder signature; the caller signs
    /// [`Checkpoint::signing_input`] with the local ephemeral session key.
    #[must_use]
    pub const fn new(
        session_id: SessionId,
        sequence: u64,
        snapshot: SharedSnapshot,
        local_chain_head: ChainHead,
        ledger_snapshot_digest: Digest32,
        signature: Ed25519Signature,
    ) -> Self {
        Self {
            session_id,
            sequence,
            snapshot,
            local_chain_head,
            ledger_snapshot_digest,
            signature,
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn snapshot(&self) -> SharedSnapshot {
        self.snapshot
    }

    #[must_use]
    pub const fn local_chain_head(&self) -> &ChainHead {
        &self.local_chain_head
    }

    #[must_use]
    pub const fn ledger_snapshot_digest(&self) -> &Digest32 {
        &self.ledger_snapshot_digest
    }

    #[must_use]
    pub const fn signature(&self) -> &Ed25519Signature {
        &self.signature
    }

    /// Attaches the ephemeral session signature computed over
    /// [`Checkpoint::signing_input`].
    #[must_use]
    pub const fn with_signature(mut self, signature: Ed25519Signature) -> Self {
        self.signature = signature;
        self
    }

    /// The canonical signed bytes: the domain label and every field except
    /// the signature.
    #[must_use]
    pub fn signing_input(&self) -> WireBytes<CHECKPOINT_SIGNING_LEN> {
        let mut bytes = [0_u8; CHECKPOINT_SIGNING_LEN];
        let mut cursor = 0;
        append(&mut bytes, &mut cursor, CHECKPOINT_DOMAIN);
        append(&mut bytes, &mut cursor, self.session_id.as_bytes());
        write_u64(&mut bytes, &mut cursor, self.sequence);
        write_snapshot(&mut bytes, &mut cursor, self.snapshot);
        append(&mut bytes, &mut cursor, self.local_chain_head.as_bytes());
        append(
            &mut bytes,
            &mut cursor,
            self.ledger_snapshot_digest.as_bytes(),
        );
        WireBytes::new(bytes, cursor)
    }

    #[must_use]
    pub fn encode_payload(&self) -> WireBytes<MAX_AUDIT_PAYLOAD_LEN> {
        let mut bytes = [0_u8; MAX_AUDIT_PAYLOAD_LEN];
        let mut cursor = 0;
        append(&mut bytes, &mut cursor, self.session_id.as_bytes());
        write_u64(&mut bytes, &mut cursor, self.sequence);
        write_snapshot(&mut bytes, &mut cursor, self.snapshot);
        append(&mut bytes, &mut cursor, self.local_chain_head.as_bytes());
        append(
            &mut bytes,
            &mut cursor,
            self.ledger_snapshot_digest.as_bytes(),
        );
        append(&mut bytes, &mut cursor, self.signature.as_bytes());
        WireBytes::new(bytes, cursor)
    }

    /// Decodes an exact [`CHECKPOINT_LEN`]-byte payload.
    pub fn decode_payload(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let bytes: [u8; CHECKPOINT_LEN] =
            bytes.try_into().map_err(|_| ProtocolError::InvalidLength {
                expected: CHECKPOINT_LEN,
                actual: bytes.len(),
            })?;
        let mut session_id = [0_u8; DIGEST_LEN];
        session_id.copy_from_slice(&bytes[..32]);
        let sequence =
            u64::from_be_bytes(bytes[32..40].try_into().expect("fixed eight-byte slice"));
        let snapshot = decode_snapshot(&bytes[40..200]);
        let mut local_chain_head = [0_u8; DIGEST_LEN];
        local_chain_head.copy_from_slice(&bytes[200..232]);
        let mut ledger_snapshot_digest = [0_u8; DIGEST_LEN];
        ledger_snapshot_digest.copy_from_slice(&bytes[232..264]);
        let mut signature = [0_u8; ED25519_SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[264..328]);
        Ok(Self::new(
            SessionId::new(session_id),
            sequence,
            snapshot,
            ChainHead::new(local_chain_head),
            Digest32::new(ledger_snapshot_digest),
            Ed25519Signature::new(signature),
        ))
    }
}

fn write_snapshot(destination: &mut [u8], cursor: &mut usize, snapshot: SharedSnapshot) {
    for stream in SharedStream::ALL {
        let entry = snapshot.get(stream);
        write_u64(destination, cursor, entry.count());
        append(destination, cursor, entry.head().as_bytes());
    }
}

fn decode_snapshot(bytes: &[u8]) -> SharedSnapshot {
    let mut streams = [StreamSnapshot::new(0, ChainHead::new([0; DIGEST_LEN])); SHARED_STREAMS];
    for (index, entry) in streams.iter_mut().enumerate() {
        let offset = index * (8 + DIGEST_LEN);
        let count = u64::from_be_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("fixed eight-byte slice"),
        );
        let mut head = [0_u8; DIGEST_LEN];
        head.copy_from_slice(&bytes[offset + 8..offset + 8 + DIGEST_LEN]);
        *entry = StreamSnapshot::new(count, ChainHead::new(head));
    }
    SharedSnapshot::new(streams)
}

/// The confirmation of one checkpoint, design section 20.3: the receiver
/// echoes the session ID, the checkpoint sequence, a digest of the received
/// `Checkpoint` payload and its own same-stream snapshot, then signs the
/// whole with the local ephemeral session key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointAck {
    session_id: SessionId,
    sequence: u64,
    checkpoint_digest: Digest32,
    snapshot: SharedSnapshot,
    signature: Ed25519Signature,
}

impl CheckpointAck {
    /// Builds an ack with a placeholder signature; the caller signs
    /// [`CheckpointAck::signing_input`] with the local ephemeral session key.
    #[must_use]
    pub const fn new(
        session_id: SessionId,
        sequence: u64,
        checkpoint_digest: Digest32,
        snapshot: SharedSnapshot,
        signature: Ed25519Signature,
    ) -> Self {
        Self {
            session_id,
            sequence,
            checkpoint_digest,
            snapshot,
            signature,
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn checkpoint_digest(&self) -> &Digest32 {
        &self.checkpoint_digest
    }

    #[must_use]
    pub const fn snapshot(&self) -> SharedSnapshot {
        self.snapshot
    }

    #[must_use]
    pub const fn signature(&self) -> &Ed25519Signature {
        &self.signature
    }

    /// Attaches the ephemeral session signature computed over
    /// [`CheckpointAck::signing_input`].
    #[must_use]
    pub const fn with_signature(mut self, signature: Ed25519Signature) -> Self {
        self.signature = signature;
        self
    }

    /// The canonical signed bytes: the domain label and every field except
    /// the signature.
    #[must_use]
    pub fn signing_input(&self) -> WireBytes<CHECKPOINT_ACK_SIGNING_LEN> {
        let mut bytes = [0_u8; CHECKPOINT_ACK_SIGNING_LEN];
        let mut cursor = 0;
        append(&mut bytes, &mut cursor, CHECKPOINT_ACK_DOMAIN);
        append(&mut bytes, &mut cursor, self.session_id.as_bytes());
        write_u64(&mut bytes, &mut cursor, self.sequence);
        append(&mut bytes, &mut cursor, self.checkpoint_digest.as_bytes());
        write_snapshot(&mut bytes, &mut cursor, self.snapshot);
        WireBytes::new(bytes, cursor)
    }

    #[must_use]
    pub fn encode_payload(&self) -> WireBytes<MAX_AUDIT_PAYLOAD_LEN> {
        let mut bytes = [0_u8; MAX_AUDIT_PAYLOAD_LEN];
        let mut cursor = 0;
        append(&mut bytes, &mut cursor, self.session_id.as_bytes());
        write_u64(&mut bytes, &mut cursor, self.sequence);
        append(&mut bytes, &mut cursor, self.checkpoint_digest.as_bytes());
        write_snapshot(&mut bytes, &mut cursor, self.snapshot);
        append(&mut bytes, &mut cursor, self.signature.as_bytes());
        WireBytes::new(bytes, cursor)
    }

    /// Decodes an exact [`CHECKPOINT_ACK_LEN`]-byte payload.
    pub fn decode_payload(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let bytes: [u8; CHECKPOINT_ACK_LEN] =
            bytes.try_into().map_err(|_| ProtocolError::InvalidLength {
                expected: CHECKPOINT_ACK_LEN,
                actual: bytes.len(),
            })?;
        let mut session_id = [0_u8; DIGEST_LEN];
        session_id.copy_from_slice(&bytes[..32]);
        let sequence =
            u64::from_be_bytes(bytes[32..40].try_into().expect("fixed eight-byte slice"));
        let mut checkpoint_digest = [0_u8; DIGEST_LEN];
        checkpoint_digest.copy_from_slice(&bytes[40..72]);
        let snapshot = decode_snapshot(&bytes[72..232]);
        let mut signature = [0_u8; ED25519_SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[232..296]);
        Ok(Self::new(
            SessionId::new(session_id),
            sequence,
            Digest32::new(checkpoint_digest),
            snapshot,
            Ed25519Signature::new(signature),
        ))
    }
}

/// The final joint manifest, design section 21.1: the identical manifest
/// both sides construct at normal session end. Both sides sign it with their
/// ephemeral session keys; the two signatures travel in separate
/// `ManifestSignature` messages covering [`JointManifest::signing_input`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JointManifest {
    format_version: u16,
    session_id: SessionId,
    controller_fingerprint: IdentityFingerprint,
    host_fingerprint: IdentityFingerprint,
    controller_session_key: Ed25519PublicKey,
    host_session_key: Ed25519PublicKey,
    connection_binding: BindingDigest,
    terminal_hello_digest: Digest32,
    final_snapshot: SharedSnapshot,
    ending: ManifestEnding,
    ended_normally: bool,
    final_checkpoint_sequence: u64,
}

impl JointManifest {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        format_version: u16,
        session_id: SessionId,
        controller_fingerprint: IdentityFingerprint,
        host_fingerprint: IdentityFingerprint,
        controller_session_key: Ed25519PublicKey,
        host_session_key: Ed25519PublicKey,
        connection_binding: BindingDigest,
        terminal_hello_digest: Digest32,
        final_snapshot: SharedSnapshot,
        ending: ManifestEnding,
        ended_normally: bool,
        final_checkpoint_sequence: u64,
    ) -> Self {
        Self {
            format_version,
            session_id,
            controller_fingerprint,
            host_fingerprint,
            controller_session_key,
            host_session_key,
            connection_binding,
            terminal_hello_digest,
            final_snapshot,
            ending,
            ended_normally,
            final_checkpoint_sequence,
        }
    }

    #[must_use]
    pub const fn format_version(&self) -> u16 {
        self.format_version
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn controller_fingerprint(&self) -> &IdentityFingerprint {
        &self.controller_fingerprint
    }

    #[must_use]
    pub const fn host_fingerprint(&self) -> &IdentityFingerprint {
        &self.host_fingerprint
    }

    #[must_use]
    pub const fn controller_session_key(&self) -> &Ed25519PublicKey {
        &self.controller_session_key
    }

    #[must_use]
    pub const fn host_session_key(&self) -> &Ed25519PublicKey {
        &self.host_session_key
    }

    #[must_use]
    pub const fn connection_binding(&self) -> &BindingDigest {
        &self.connection_binding
    }

    #[must_use]
    pub const fn terminal_hello_digest(&self) -> &Digest32 {
        &self.terminal_hello_digest
    }

    #[must_use]
    pub const fn final_snapshot(&self) -> SharedSnapshot {
        self.final_snapshot
    }

    #[must_use]
    pub const fn ending(&self) -> ManifestEnding {
        self.ending
    }

    #[must_use]
    pub const fn ended_normally(&self) -> bool {
        self.ended_normally
    }

    #[must_use]
    pub const fn final_checkpoint_sequence(&self) -> u64 {
        self.final_checkpoint_sequence
    }

    /// The canonical signed bytes: the manifest domain label followed by the
    /// complete manifest payload. Both ephemeral session keys sign these
    /// exact bytes (design section 21.2).
    pub fn signing_input(&self) -> Result<WireBytes<MANIFEST_SIGNING_INPUT_LEN>, ProtocolError> {
        let mut bytes = [0_u8; MANIFEST_SIGNING_INPUT_LEN];
        let mut cursor = 0;
        append(&mut bytes, &mut cursor, MANIFEST_DOMAIN);
        append(&mut bytes, &mut cursor, self.encode_payload()?.as_slice());
        Ok(WireBytes::new(bytes, cursor))
    }

    /// Encodes the manifest payload, validating the frozen format version.
    pub fn encode_payload(&self) -> Result<WireBytes<MAX_AUDIT_PAYLOAD_LEN>, ProtocolError> {
        if self.format_version != AUDIT_FORMAT_VERSION {
            return Err(ProtocolError::InvalidField(ProtocolField::Reserved));
        }
        let mut bytes = [0_u8; MAX_AUDIT_PAYLOAD_LEN];
        let mut cursor = 0;
        write_u16(&mut bytes, &mut cursor, self.format_version);
        append(&mut bytes, &mut cursor, self.session_id.as_bytes());
        append(
            &mut bytes,
            &mut cursor,
            self.controller_fingerprint.as_bytes(),
        );
        append(&mut bytes, &mut cursor, self.host_fingerprint.as_bytes());
        append(
            &mut bytes,
            &mut cursor,
            self.controller_session_key.as_bytes(),
        );
        append(&mut bytes, &mut cursor, self.host_session_key.as_bytes());
        append(&mut bytes, &mut cursor, self.connection_binding.as_bytes());
        append(
            &mut bytes,
            &mut cursor,
            self.terminal_hello_digest.as_bytes(),
        );
        write_snapshot(&mut bytes, &mut cursor, self.final_snapshot);
        append(&mut bytes, &mut cursor, &[self.ending.tag()]);
        write_u32(&mut bytes, &mut cursor, self.ending.value());
        append(&mut bytes, &mut cursor, &[self.ended_normally as u8]);
        write_u64(&mut bytes, &mut cursor, self.final_checkpoint_sequence);
        Ok(WireBytes::new(bytes, cursor))
    }

    /// Decodes one fixed-length manifest payload.
    pub fn decode_payload(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() != MANIFEST_LEN {
            return Err(ProtocolError::InvalidLength {
                expected: MANIFEST_LEN,
                actual: bytes.len(),
            });
        }
        let format_version = u16::from_be_bytes([bytes[0], bytes[1]]);
        if format_version != AUDIT_FORMAT_VERSION {
            return Err(ProtocolError::InvalidField(ProtocolField::Reserved));
        }
        let mut session_id = [0_u8; DIGEST_LEN];
        session_id.copy_from_slice(&bytes[2..34]);
        let mut controller_fingerprint = [0_u8; DIGEST_LEN];
        controller_fingerprint.copy_from_slice(&bytes[34..66]);
        let mut host_fingerprint = [0_u8; DIGEST_LEN];
        host_fingerprint.copy_from_slice(&bytes[66..98]);
        let mut controller_session_key = [0_u8; ED25519_PUBLIC_KEY_LEN];
        controller_session_key.copy_from_slice(&bytes[98..130]);
        let mut host_session_key = [0_u8; ED25519_PUBLIC_KEY_LEN];
        host_session_key.copy_from_slice(&bytes[130..162]);
        let mut connection_binding = [0_u8; DIGEST_LEN];
        connection_binding.copy_from_slice(&bytes[162..194]);
        let tail = &bytes[194..];
        let mut terminal_hello_digest = [0_u8; DIGEST_LEN];
        terminal_hello_digest.copy_from_slice(&tail[..32]);
        let final_snapshot = decode_snapshot(&tail[32..192]);
        let ending_value = u32::from_be_bytes(
            tail[193..197]
                .try_into()
                .expect("fixed four-byte ending value"),
        );
        let ending = ManifestEnding::from_bytes(tail[192], ending_value)
            .ok_or(ProtocolError::UnknownTag(tail[192]))?;
        let ended_normally = tail[197];
        if ended_normally > 1 {
            return Err(ProtocolError::InvalidField(ProtocolField::Reserved));
        }
        let final_checkpoint_sequence =
            u64::from_be_bytes(tail[198..206].try_into().expect("fixed eight-byte slice"));
        Ok(Self::new(
            format_version,
            SessionId::new(session_id),
            IdentityFingerprint::new(controller_fingerprint),
            IdentityFingerprint::new(host_fingerprint),
            Ed25519PublicKey::new(controller_session_key),
            Ed25519PublicKey::new(host_session_key),
            BindingDigest::new(connection_binding),
            Digest32::new(terminal_hello_digest),
            final_snapshot,
            ending,
            ended_normally != 0,
            final_checkpoint_sequence,
        ))
    }
}

/// One ephemeral session signature over the accepted joint manifest
/// (design section 21.2). The signed bytes are exactly
/// [`JointManifest::signing_input`] of the manifest, produced by the
/// controller's or host's ephemeral session key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestSignature {
    signature: Ed25519Signature,
}

impl ManifestSignature {
    #[must_use]
    pub const fn new(signature: Ed25519Signature) -> Self {
        Self { signature }
    }

    #[must_use]
    pub const fn signature(&self) -> &Ed25519Signature {
        &self.signature
    }

    #[must_use]
    pub fn encode_payload(&self) -> WireBytes<MAX_AUDIT_PAYLOAD_LEN> {
        let mut bytes = [0_u8; MAX_AUDIT_PAYLOAD_LEN];
        bytes[..MANIFEST_SIGNATURE_LEN].copy_from_slice(self.signature.as_bytes());
        WireBytes::new(bytes, MANIFEST_SIGNATURE_LEN)
    }

    /// Decodes an exact [`MANIFEST_SIGNATURE_LEN`]-byte payload.
    pub fn decode_payload(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let signature: [u8; MANIFEST_SIGNATURE_LEN] =
            bytes.try_into().map_err(|_| ProtocolError::InvalidLength {
                expected: MANIFEST_SIGNATURE_LEN,
                actual: bytes.len(),
            })?;
        Ok(Self::new(Ed25519Signature::new(signature)))
    }
}

/// The local record seal, design section 21.3: binds the local observation
/// chain root, the local event count, the final shared roots, the joint
/// manifest digest and the sealed prefix digest, signed by the local
/// ephemeral session key.
///
/// `sealed_prefix_digest` covers the header and every record frame plus the
/// joint manifest and both manifest signatures — everything before the seal.
/// The seal itself sits in the footer and never enters the local event chain,
/// so it cannot reference itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalRecordSeal {
    session_id: SessionId,
    role: AuditRole,
    final_local_event_root: ChainHead,
    local_event_count: u64,
    final_shared_roots: [ChainHead; SHARED_STREAMS],
    joint_manifest_digest: Digest32,
    sealed_prefix_digest: Digest32,
    signature: Ed25519Signature,
}

impl LocalRecordSeal {
    /// Builds a seal with a placeholder signature; the caller signs
    /// [`LocalRecordSeal::signing_input`] with the local ephemeral session
    /// key.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        session_id: SessionId,
        role: AuditRole,
        final_local_event_root: ChainHead,
        local_event_count: u64,
        final_shared_roots: [ChainHead; SHARED_STREAMS],
        joint_manifest_digest: Digest32,
        sealed_prefix_digest: Digest32,
        signature: Ed25519Signature,
    ) -> Self {
        Self {
            session_id,
            role,
            final_local_event_root,
            local_event_count,
            final_shared_roots,
            joint_manifest_digest,
            sealed_prefix_digest,
            signature,
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn role(&self) -> AuditRole {
        self.role
    }

    #[must_use]
    pub const fn final_local_event_root(&self) -> &ChainHead {
        &self.final_local_event_root
    }

    #[must_use]
    pub const fn local_event_count(&self) -> u64 {
        self.local_event_count
    }

    #[must_use]
    pub const fn final_shared_roots(&self) -> &[ChainHead; SHARED_STREAMS] {
        &self.final_shared_roots
    }

    #[must_use]
    pub const fn joint_manifest_digest(&self) -> &Digest32 {
        &self.joint_manifest_digest
    }

    #[must_use]
    pub const fn sealed_prefix_digest(&self) -> &Digest32 {
        &self.sealed_prefix_digest
    }

    #[must_use]
    pub const fn signature(&self) -> &Ed25519Signature {
        &self.signature
    }

    /// Attaches the ephemeral session signature computed over
    /// [`LocalRecordSeal::signing_input`].
    #[must_use]
    pub const fn with_signature(mut self, signature: Ed25519Signature) -> Self {
        self.signature = signature;
        self
    }

    /// The canonical signed bytes: the domain label and every field except
    /// the signature.
    #[must_use]
    pub fn signing_input(&self) -> WireBytes<SEAL_SIGNING_LEN> {
        let mut bytes = [0_u8; SEAL_SIGNING_LEN];
        let mut cursor = 0;
        append(&mut bytes, &mut cursor, SEAL_DOMAIN);
        append(&mut bytes, &mut cursor, self.session_id.as_bytes());
        append(&mut bytes, &mut cursor, &[self.role.code()]);
        append(
            &mut bytes,
            &mut cursor,
            self.final_local_event_root.as_bytes(),
        );
        write_u64(&mut bytes, &mut cursor, self.local_event_count);
        for root in self.final_shared_roots.iter() {
            append(&mut bytes, &mut cursor, root.as_bytes());
        }
        append(
            &mut bytes,
            &mut cursor,
            self.joint_manifest_digest.as_bytes(),
        );
        append(
            &mut bytes,
            &mut cursor,
            self.sealed_prefix_digest.as_bytes(),
        );
        WireBytes::new(bytes, cursor)
    }

    #[must_use]
    pub fn encode_payload(&self) -> WireBytes<MAX_AUDIT_PAYLOAD_LEN> {
        let mut bytes = [0_u8; MAX_AUDIT_PAYLOAD_LEN];
        let mut cursor = 0;
        append(&mut bytes, &mut cursor, self.session_id.as_bytes());
        append(&mut bytes, &mut cursor, &[self.role.code()]);
        append(
            &mut bytes,
            &mut cursor,
            self.final_local_event_root.as_bytes(),
        );
        write_u64(&mut bytes, &mut cursor, self.local_event_count);
        for root in self.final_shared_roots.iter() {
            append(&mut bytes, &mut cursor, root.as_bytes());
        }
        append(
            &mut bytes,
            &mut cursor,
            self.joint_manifest_digest.as_bytes(),
        );
        append(
            &mut bytes,
            &mut cursor,
            self.sealed_prefix_digest.as_bytes(),
        );
        append(&mut bytes, &mut cursor, self.signature.as_bytes());
        WireBytes::new(bytes, cursor)
    }

    /// Decodes an exact [`LOCAL_RECORD_SEAL_LEN`]-byte payload.
    pub fn decode_payload(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let bytes: [u8; LOCAL_RECORD_SEAL_LEN] =
            bytes.try_into().map_err(|_| ProtocolError::InvalidLength {
                expected: LOCAL_RECORD_SEAL_LEN,
                actual: bytes.len(),
            })?;
        let mut session_id = [0_u8; DIGEST_LEN];
        session_id.copy_from_slice(&bytes[..32]);
        let role = AuditRole::from_byte(bytes[32])
            .ok_or(ProtocolError::InvalidField(ProtocolField::Reserved))?;
        let mut final_local_event_root = [0_u8; DIGEST_LEN];
        final_local_event_root.copy_from_slice(&bytes[33..65]);
        let local_event_count =
            u64::from_be_bytes(bytes[65..73].try_into().expect("fixed eight-byte slice"));
        let mut final_shared_roots = [[0_u8; DIGEST_LEN]; SHARED_STREAMS];
        for (index, root) in final_shared_roots.iter_mut().enumerate() {
            let offset = 73 + index * DIGEST_LEN;
            root.copy_from_slice(&bytes[offset..offset + DIGEST_LEN]);
        }
        let mut joint_manifest_digest = [0_u8; DIGEST_LEN];
        joint_manifest_digest.copy_from_slice(&bytes[201..233]);
        let mut sealed_prefix_digest = [0_u8; DIGEST_LEN];
        sealed_prefix_digest.copy_from_slice(&bytes[233..265]);
        let mut signature = [0_u8; ED25519_SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[265..329]);
        Ok(Self::new(
            SessionId::new(session_id),
            role,
            ChainHead::new(final_local_event_root),
            local_event_count,
            final_shared_roots.map(ChainHead::new),
            Digest32::new(joint_manifest_digest),
            Digest32::new(sealed_prefix_digest),
            Ed25519Signature::new(signature),
        ))
    }
}

/// The local ledger commit, design section 12.1: binds the local ledger
/// sequence and previous root, the session ID, the final joint manifest
/// digest, the local sealed record digest, the peer audit identity
/// fingerprint and the session result, signed by the persistent audit
/// identity. The commit references the sealed record digest, never the final
/// container digest that covers the commit itself, so no circular dependency
/// exists (design section 12.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerCommit {
    sequence: u64,
    previous_root: LedgerRoot,
    session_id: SessionId,
    manifest_digest: Digest32,
    sealed_record_digest: Digest32,
    peer_identity_fingerprint: IdentityFingerprint,
    result: SessionResult,
    signature: Ed25519Signature,
}

impl LedgerCommit {
    /// Builds a commit with a placeholder signature; the caller signs
    /// [`LedgerCommit::signing_input`] with the persistent audit identity.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        sequence: u64,
        previous_root: LedgerRoot,
        session_id: SessionId,
        manifest_digest: Digest32,
        sealed_record_digest: Digest32,
        peer_identity_fingerprint: IdentityFingerprint,
        result: SessionResult,
        signature: Ed25519Signature,
    ) -> Self {
        Self {
            sequence,
            previous_root,
            session_id,
            manifest_digest,
            sealed_record_digest,
            peer_identity_fingerprint,
            result,
            signature,
        }
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn previous_root(&self) -> &LedgerRoot {
        &self.previous_root
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn manifest_digest(&self) -> &Digest32 {
        &self.manifest_digest
    }

    #[must_use]
    pub const fn sealed_record_digest(&self) -> &Digest32 {
        &self.sealed_record_digest
    }

    #[must_use]
    pub const fn peer_identity_fingerprint(&self) -> &IdentityFingerprint {
        &self.peer_identity_fingerprint
    }

    #[must_use]
    pub const fn result(&self) -> SessionResult {
        self.result
    }

    #[must_use]
    pub const fn signature(&self) -> &Ed25519Signature {
        &self.signature
    }

    /// Attaches the persistent identity signature computed over
    /// [`LedgerCommit::signing_input`].
    #[must_use]
    pub const fn with_signature(mut self, signature: Ed25519Signature) -> Self {
        self.signature = signature;
        self
    }

    /// The canonical signed bytes: the domain label and every field except
    /// the signature.
    #[must_use]
    pub fn signing_input(&self) -> WireBytes<LEDGER_COMMIT_SIGNING_LEN> {
        let mut bytes = [0_u8; LEDGER_COMMIT_SIGNING_LEN];
        let mut cursor = 0;
        append(&mut bytes, &mut cursor, LEDGER_COMMIT_DOMAIN);
        write_u64(&mut bytes, &mut cursor, self.sequence);
        append(&mut bytes, &mut cursor, self.previous_root.as_bytes());
        append(&mut bytes, &mut cursor, self.session_id.as_bytes());
        append(&mut bytes, &mut cursor, self.manifest_digest.as_bytes());
        append(
            &mut bytes,
            &mut cursor,
            self.sealed_record_digest.as_bytes(),
        );
        append(
            &mut bytes,
            &mut cursor,
            self.peer_identity_fingerprint.as_bytes(),
        );
        append(&mut bytes, &mut cursor, &[self.result.code()]);
        WireBytes::new(bytes, cursor)
    }

    #[must_use]
    pub fn encode_payload(&self) -> WireBytes<MAX_AUDIT_PAYLOAD_LEN> {
        let mut bytes = [0_u8; MAX_AUDIT_PAYLOAD_LEN];
        let mut cursor = 0;
        write_u64(&mut bytes, &mut cursor, self.sequence);
        append(&mut bytes, &mut cursor, self.previous_root.as_bytes());
        append(&mut bytes, &mut cursor, self.session_id.as_bytes());
        append(&mut bytes, &mut cursor, self.manifest_digest.as_bytes());
        append(
            &mut bytes,
            &mut cursor,
            self.sealed_record_digest.as_bytes(),
        );
        append(
            &mut bytes,
            &mut cursor,
            self.peer_identity_fingerprint.as_bytes(),
        );
        append(&mut bytes, &mut cursor, &[self.result.code()]);
        append(&mut bytes, &mut cursor, self.signature.as_bytes());
        WireBytes::new(bytes, cursor)
    }

    /// Decodes an exact [`LEDGER_COMMIT_LEN`]-byte payload.
    pub fn decode_payload(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let bytes: [u8; LEDGER_COMMIT_LEN] =
            bytes.try_into().map_err(|_| ProtocolError::InvalidLength {
                expected: LEDGER_COMMIT_LEN,
                actual: bytes.len(),
            })?;
        let sequence = u64::from_be_bytes(bytes[..8].try_into().expect("fixed eight-byte slice"));
        let mut previous_root = [0_u8; DIGEST_LEN];
        previous_root.copy_from_slice(&bytes[8..40]);
        let mut session_id = [0_u8; DIGEST_LEN];
        session_id.copy_from_slice(&bytes[40..72]);
        let mut manifest_digest = [0_u8; DIGEST_LEN];
        manifest_digest.copy_from_slice(&bytes[72..104]);
        let mut sealed_record_digest = [0_u8; DIGEST_LEN];
        sealed_record_digest.copy_from_slice(&bytes[104..136]);
        let mut peer_identity_fingerprint = [0_u8; DIGEST_LEN];
        peer_identity_fingerprint.copy_from_slice(&bytes[136..168]);
        let result = SessionResult::from_byte(bytes[168])
            .ok_or(ProtocolError::InvalidField(ProtocolField::Reserved))?;
        let mut signature = [0_u8; ED25519_SIGNATURE_LEN];
        signature.copy_from_slice(&bytes[169..233]);
        Ok(Self::new(
            sequence,
            LedgerRoot::new(previous_root),
            SessionId::new(session_id),
            Digest32::new(manifest_digest),
            Digest32::new(sealed_record_digest),
            IdentityFingerprint::new(peer_identity_fingerprint),
            result,
            Ed25519Signature::new(signature),
        ))
    }
}

/// One decoded audit substream message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditMessage {
    /// The audit handshake opener (tag `0x01`).
    AuditHello(AuditHello),
    /// The raw input commitment secret contribution (tag `0x02`).
    SecretContribution(SecretContributionMessage),
    /// The signed audit handshake confirmation (tag `0x03`).
    AuditReady(AuditReady),
    /// A signed bilateral checkpoint (tag `0x04`).
    Checkpoint(Checkpoint),
    /// The signed confirmation of one checkpoint (tag `0x05`).
    CheckpointAck(CheckpointAck),
    /// The final joint manifest (tag `0x06`).
    JointManifest(JointManifest),
    /// One ephemeral session signature over the joint manifest (tag `0x07`).
    ManifestSignature(ManifestSignature),
    /// The local record seal with its ephemeral session signature
    /// (tag `0x08`).
    LocalRecordSeal(LocalRecordSeal),
    /// The persistent-identity-signed ledger commit (tag `0x09`).
    LedgerCommit(LedgerCommit),
    /// The session close reason (tag `0x0A`).
    CloseNotice(AuditCloseReason),
    /// A structured audit failure (tag `0x0B`).
    AuditError(AuditErrorCode),
}

impl AuditMessage {
    /// Encodes a complete frame: tag, big-endian payload length and payload.
    pub fn encode(&self) -> Result<WireBytes<MAX_AUDIT_FRAME_LEN>, ProtocolError> {
        let (tag, payload) = match self {
            Self::AuditHello(message) => (AuditTag::AuditHello.code(), message.encode_payload()),
            Self::SecretContribution(contribution) => (
                AuditTag::SecretContribution.code(),
                contribution.encode_payload(),
            ),
            Self::AuditReady(message) => (AuditTag::AuditReady.code(), message.encode_payload()),
            Self::Checkpoint(message) => (AuditTag::Checkpoint.code(), message.encode_payload()),
            Self::CheckpointAck(message) => {
                (AuditTag::CheckpointAck.code(), message.encode_payload())
            }
            Self::JointManifest(message) => {
                (AuditTag::JointManifest.code(), message.encode_payload()?)
            }
            Self::ManifestSignature(message) => {
                (AuditTag::ManifestSignature.code(), message.encode_payload())
            }
            Self::LocalRecordSeal(message) => {
                (AuditTag::LocalRecordSeal.code(), message.encode_payload())
            }
            Self::LedgerCommit(message) => {
                (AuditTag::LedgerCommit.code(), message.encode_payload())
            }
            Self::CloseNotice(reason) => {
                (AuditTag::CloseNotice.code(), close_notice_payload(*reason))
            }
            Self::AuditError(code) => (AuditTag::AuditError.code(), audit_error_payload(*code)),
        };
        let payload_len = payload.as_slice().len();
        let mut frame = [0_u8; MAX_AUDIT_FRAME_LEN];
        frame[..FRAME_HEADER_LEN].copy_from_slice(&encode_frame_header(
            tag,
            u32::try_from(payload_len).map_err(|_| ProtocolError::InvalidLength {
                expected: MAX_AUDIT_PAYLOAD_LEN,
                actual: payload_len,
            })?,
        ));
        frame[FRAME_HEADER_LEN..FRAME_HEADER_LEN + payload_len].copy_from_slice(payload.as_slice());
        Ok(WireBytes::new(frame, FRAME_HEADER_LEN + payload_len))
    }

    /// Decodes one complete frame, validating the tag, the payload length
    /// bound, the exact payload structure and the absence of trailing bytes.
    pub fn decode_frame(frame: &[u8]) -> Result<AuditMessage, ProtocolError> {
        if frame.len() < FRAME_HEADER_LEN {
            return Err(ProtocolError::InvalidLength {
                expected: FRAME_HEADER_LEN,
                actual: frame.len(),
            });
        }
        let (tag, payload_len) = decode_frame_header(&frame[..FRAME_HEADER_LEN])?;
        let payload_len =
            usize::try_from(payload_len).map_err(|_| ProtocolError::InvalidLength {
                expected: usize::MAX,
                actual: frame.len(),
            })?;
        validate_payload_len(tag, payload_len)?;
        let expected =
            FRAME_HEADER_LEN
                .checked_add(payload_len)
                .ok_or(ProtocolError::InvalidLength {
                    expected: FRAME_HEADER_LEN,
                    actual: frame.len(),
                })?;
        if frame.len() < expected {
            return Err(ProtocolError::InvalidLength {
                expected,
                actual: frame.len(),
            });
        }
        if frame.len() > expected {
            return Err(ProtocolError::TrailingBytes);
        }
        Self::decode_payload(tag, &frame[FRAME_HEADER_LEN..])
    }

    fn decode_payload(tag: u8, payload: &[u8]) -> Result<AuditMessage, ProtocolError> {
        let code = AuditTag::from_byte(tag).ok_or(ProtocolError::UnknownTag(tag))?;
        match code {
            AuditTag::AuditHello => {
                AuditHello::decode_payload(payload).map(AuditMessage::AuditHello)
            }
            AuditTag::SecretContribution => SecretContributionMessage::decode_payload(payload)
                .map(AuditMessage::SecretContribution),
            AuditTag::AuditReady => {
                AuditReady::decode_payload(payload).map(AuditMessage::AuditReady)
            }
            AuditTag::Checkpoint => {
                Checkpoint::decode_payload(payload).map(AuditMessage::Checkpoint)
            }
            AuditTag::CheckpointAck => {
                CheckpointAck::decode_payload(payload).map(AuditMessage::CheckpointAck)
            }
            AuditTag::JointManifest => {
                JointManifest::decode_payload(payload).map(AuditMessage::JointManifest)
            }
            AuditTag::ManifestSignature => {
                ManifestSignature::decode_payload(payload).map(AuditMessage::ManifestSignature)
            }
            AuditTag::LocalRecordSeal => {
                LocalRecordSeal::decode_payload(payload).map(AuditMessage::LocalRecordSeal)
            }
            AuditTag::LedgerCommit => {
                LedgerCommit::decode_payload(payload).map(AuditMessage::LedgerCommit)
            }
            AuditTag::CloseNotice => decode_close_notice(payload),
            AuditTag::AuditError => decode_audit_error(payload),
        }
    }
}

fn close_notice_payload(reason: AuditCloseReason) -> WireBytes<MAX_AUDIT_PAYLOAD_LEN> {
    let mut bytes = [0_u8; MAX_AUDIT_PAYLOAD_LEN];
    bytes[0] = reason.code();
    WireBytes::new(bytes, CLOSE_NOTICE_LEN)
}

fn decode_close_notice(payload: &[u8]) -> Result<AuditMessage, ProtocolError> {
    let [reason] = payload else {
        return Err(ProtocolError::InvalidLength {
            expected: CLOSE_NOTICE_LEN,
            actual: payload.len(),
        });
    };
    let reason = AuditCloseReason::from_byte(*reason)
        .ok_or(ProtocolError::InvalidField(ProtocolField::Reserved))?;
    Ok(AuditMessage::CloseNotice(reason))
}

fn audit_error_payload(code: AuditErrorCode) -> WireBytes<MAX_AUDIT_PAYLOAD_LEN> {
    let mut bytes = [0_u8; MAX_AUDIT_PAYLOAD_LEN];
    bytes[..2].copy_from_slice(&code.code().to_be_bytes());
    WireBytes::new(bytes, AUDIT_ERROR_LEN)
}

fn decode_audit_error(payload: &[u8]) -> Result<AuditMessage, ProtocolError> {
    let bytes: [u8; AUDIT_ERROR_LEN] =
        payload
            .try_into()
            .map_err(|_| ProtocolError::InvalidLength {
                expected: AUDIT_ERROR_LEN,
                actual: payload.len(),
            })?;
    let code = AuditErrorCode::from_u16(u16::from_be_bytes(bytes))
        .ok_or(ProtocolError::InvalidField(ProtocolField::Reserved))?;
    Ok(AuditMessage::AuditError(code))
}

/// Encodes the 5-byte frame header.
#[must_use]
pub const fn encode_frame_header(tag: u8, payload_len: u32) -> [u8; FRAME_HEADER_LEN] {
    let len = payload_len.to_be_bytes();
    [tag, len[0], len[1], len[2], len[3]]
}

/// Decodes exactly five header bytes into `(tag, payload_length)`.
pub fn decode_frame_header(bytes: &[u8]) -> Result<(u8, u32), ProtocolError> {
    if bytes.len() != FRAME_HEADER_LEN {
        return Err(ProtocolError::InvalidLength {
            expected: FRAME_HEADER_LEN,
            actual: bytes.len(),
        });
    }
    let tag = bytes[0];
    if AuditTag::from_byte(tag).is_none() {
        return Err(ProtocolError::UnknownTag(tag));
    }
    Ok((
        tag,
        u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]),
    ))
}

/// Validates a payload length against the fixed bounds of its tag before any
/// read.
pub fn validate_payload_len(tag: u8, len: usize) -> Result<(), ProtocolError> {
    let code = AuditTag::from_byte(tag).ok_or(ProtocolError::UnknownTag(tag))?;
    let valid = match code {
        AuditTag::AuditHello => len == AUDIT_HELLO_LEN,
        AuditTag::SecretContribution => len == SECRET_CONTRIBUTION_LEN,
        AuditTag::AuditReady => len == AUDIT_READY_LEN,
        AuditTag::Checkpoint => len == CHECKPOINT_LEN,
        AuditTag::CheckpointAck => len == CHECKPOINT_ACK_LEN,
        AuditTag::JointManifest => len == MANIFEST_LEN,
        AuditTag::ManifestSignature => len == MANIFEST_SIGNATURE_LEN,
        AuditTag::LocalRecordSeal => len == LOCAL_RECORD_SEAL_LEN,
        AuditTag::LedgerCommit => len == LEDGER_COMMIT_LEN,
        AuditTag::CloseNotice => len == CLOSE_NOTICE_LEN,
        AuditTag::AuditError => len == AUDIT_ERROR_LEN,
    };
    if valid {
        Ok(())
    } else {
        Err(ProtocolError::InvalidLength {
            expected: 0,
            actual: len,
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::error::ProtocolError;

    const ZERO_HEAD: ChainHead = ChainHead::new([0; DIGEST_LEN]);
    const ZERO_ROOT: LedgerRoot = LedgerRoot::new([0; DIGEST_LEN]);

    fn snapshot(counts: [u64; SHARED_STREAMS]) -> SharedSnapshot {
        let streams = counts.map(|count| StreamSnapshot::new(count, ZERO_HEAD));
        SharedSnapshot::new(streams)
    }

    fn hello() -> AuditHello {
        AuditHello::new(
            AuditRole::Controller,
            Ed25519PublicKey::new([1; ED25519_PUBLIC_KEY_LEN]),
            Ed25519PublicKey::new([2; ED25519_PUBLIC_KEY_LEN]),
            AuditNonce::new([3; NONCE_LEN]),
            7,
            ZERO_ROOT,
            BindingDigest::new([4; DIGEST_LEN]),
            AUDIT_FORMAT_VERSION,
            CommitmentDigest::new([5; DIGEST_LEN]),
            Ed25519Signature::new([6; ED25519_SIGNATURE_LEN]),
        )
    }

    fn ready() -> AuditReady {
        AuditReady::new(
            SessionId::new([1; DIGEST_LEN]),
            Digest32::new([2; DIGEST_LEN]),
            AUDIT_FORMAT_VERSION,
            Ed25519Signature::new([3; ED25519_SIGNATURE_LEN]),
        )
    }

    fn checkpoint() -> Checkpoint {
        Checkpoint::new(
            SessionId::new([1; DIGEST_LEN]),
            4,
            snapshot([10, 20, 30, 40]),
            ZERO_HEAD,
            Digest32::new([2; DIGEST_LEN]),
            Ed25519Signature::new([3; ED25519_SIGNATURE_LEN]),
        )
    }

    fn checkpoint_ack() -> CheckpointAck {
        CheckpointAck::new(
            SessionId::new([1; DIGEST_LEN]),
            4,
            Digest32::new([2; DIGEST_LEN]),
            snapshot([10, 20, 30, 40]),
            Ed25519Signature::new([3; ED25519_SIGNATURE_LEN]),
        )
    }

    fn manifest_with_version(format_version: u16) -> JointManifest {
        JointManifest::new(
            format_version,
            SessionId::new([1; DIGEST_LEN]),
            IdentityFingerprint::new([2; DIGEST_LEN]),
            IdentityFingerprint::new([3; DIGEST_LEN]),
            Ed25519PublicKey::new([4; ED25519_PUBLIC_KEY_LEN]),
            Ed25519PublicKey::new([5; ED25519_PUBLIC_KEY_LEN]),
            BindingDigest::new([6; DIGEST_LEN]),
            Digest32::new([7; DIGEST_LEN]),
            snapshot([10, 20, 30, 40]),
            ManifestEnding::ShellExit(0),
            true,
            9,
        )
    }

    fn manifest() -> JointManifest {
        manifest_with_version(AUDIT_FORMAT_VERSION)
    }

    fn seal() -> LocalRecordSeal {
        LocalRecordSeal::new(
            SessionId::new([1; DIGEST_LEN]),
            AuditRole::Controller,
            ZERO_HEAD,
            12,
            [ZERO_HEAD; SHARED_STREAMS],
            Digest32::new([2; DIGEST_LEN]),
            Digest32::new([3; DIGEST_LEN]),
            Ed25519Signature::new([4; ED25519_SIGNATURE_LEN]),
        )
    }

    fn ledger_commit() -> LedgerCommit {
        LedgerCommit::new(
            13,
            ZERO_ROOT,
            SessionId::new([1; DIGEST_LEN]),
            Digest32::new([2; DIGEST_LEN]),
            Digest32::new([3; DIGEST_LEN]),
            IdentityFingerprint::new([4; DIGEST_LEN]),
            SessionResult::Normal,
            Ed25519Signature::new([5; ED25519_SIGNATURE_LEN]),
        )
    }

    fn frame(message: &AuditMessage) -> Vec<u8> {
        message.encode().unwrap().as_slice().to_vec()
    }

    #[test]
    fn audit_messages_round_trip_at_frozen_lengths() {
        let messages = [
            AuditMessage::AuditHello(hello()),
            AuditMessage::SecretContribution(SecretContributionMessage::new(
                SecretContribution::new([1; NONCE_LEN]),
            )),
            AuditMessage::AuditReady(ready()),
            AuditMessage::Checkpoint(checkpoint()),
            AuditMessage::CheckpointAck(checkpoint_ack()),
            AuditMessage::JointManifest(manifest()),
            AuditMessage::ManifestSignature(ManifestSignature::new(Ed25519Signature::new(
                [1; ED25519_SIGNATURE_LEN],
            ))),
            AuditMessage::LocalRecordSeal(seal()),
            AuditMessage::LedgerCommit(ledger_commit()),
            AuditMessage::CloseNotice(AuditCloseReason::ControllerDetach),
            AuditMessage::AuditError(AuditErrorCode::AuditCheckpointMismatch),
        ];
        for message in messages {
            let encoded = frame(&message);
            assert_eq!(
                AuditMessage::decode_frame(&encoded).unwrap(),
                message,
                "round trip for {message:?}"
            );
        }
    }

    #[test]
    fn signed_messages_round_trip_through_signature_input() {
        // The signing input must decode to the same unsigned fields and the
        // encoded payload must be the signing input fields plus the signature.
        let hello = hello();
        let signing = hello.signing_input();
        let input = signing.as_slice();
        assert_eq!(input.len(), AUDIT_HELLO_SIGNING_LEN);
        assert_eq!(
            &input[..AUDIT_HELLO_DOMAIN.len()],
            AUDIT_HELLO_DOMAIN,
            "hello signing input starts with its domain label"
        );
        let payload = hello.encode_payload();
        assert_eq!(
            &input[AUDIT_HELLO_DOMAIN.len()..],
            &payload.as_slice()[..AUDIT_HELLO_LEN - ED25519_SIGNATURE_LEN],
            "hello signing input is the unsigned fields"
        );

        for signed in [
            AuditMessage::AuditReady(ready()),
            AuditMessage::Checkpoint(checkpoint()),
            AuditMessage::CheckpointAck(checkpoint_ack()),
            AuditMessage::JointManifest(manifest()),
            AuditMessage::LocalRecordSeal(seal()),
            AuditMessage::LedgerCommit(ledger_commit()),
        ] {
            let encoded = frame(&signed);
            let decoded = AuditMessage::decode_frame(&encoded).unwrap();
            assert_eq!(decoded, signed);
            assert!(
                encoded.len() > FRAME_HEADER_LEN,
                "every signed message has a body"
            );
        }
    }

    #[test]
    fn audit_hello_signing_input_has_the_exact_frozen_layout() {
        let hello = hello();
        let mut expected = Vec::new();
        expected.extend_from_slice(AUDIT_HELLO_DOMAIN);
        expected.push(AuditRole::Controller.code());
        expected.extend_from_slice(&[1; ED25519_PUBLIC_KEY_LEN]);
        expected.extend_from_slice(&[2; ED25519_PUBLIC_KEY_LEN]);
        expected.extend_from_slice(&[3; NONCE_LEN]);
        expected.extend_from_slice(&7_u64.to_be_bytes());
        expected.extend_from_slice(&[0; DIGEST_LEN]);
        expected.extend_from_slice(&[4; DIGEST_LEN]);
        expected.extend_from_slice(&AUDIT_FORMAT_VERSION.to_be_bytes());
        expected.extend_from_slice(&[5; DIGEST_LEN]);
        assert_eq!(hello.signing_input().as_slice(), expected);
    }

    #[test]
    fn shared_snapshots_preserve_stream_order_and_bounds() {
        let snapshot = snapshot([1, 2, 3, 4]);
        assert_eq!(snapshot.get(SharedStream::Input).count(), 1);
        assert_eq!(snapshot.get(SharedStream::Output).count(), 2);
        assert_eq!(snapshot.get(SharedStream::Control).count(), 3);
        assert_eq!(snapshot.get(SharedStream::FileTransfer).count(), 4);
        assert_eq!(snapshot.counts(), [1, 2, 3, 4]);
        assert_eq!(snapshot.roots(), [ZERO_HEAD; SHARED_STREAMS]);
        for (index, stream) in SharedStream::ALL.into_iter().enumerate() {
            assert_eq!(stream.index(), index);
            assert_eq!(SharedStream::from_index(index), Some(stream));
        }
        assert_eq!(SharedStream::from_index(SHARED_STREAMS), None);
    }

    #[test]
    fn frame_headers_validate_tags_and_lengths() {
        let header = encode_frame_header(AuditTag::Checkpoint.code(), CHECKPOINT_LEN as u32);
        assert_eq!(header, [0x04, 0, 0, 1, 72]);
        assert_eq!(
            decode_frame_header(&header),
            Ok((AuditTag::Checkpoint.code(), CHECKPOINT_LEN as u32))
        );
        assert!(matches!(
            decode_frame_header(&[]),
            Err(ProtocolError::InvalidLength { .. })
        ));
        let mut long = header.to_vec();
        long.push(0);
        assert!(matches!(
            decode_frame_header(&long),
            Err(ProtocolError::InvalidLength { .. })
        ));
        assert_eq!(
            decode_frame_header(&[0x0C, 0, 0, 0, 0]),
            Err(ProtocolError::UnknownTag(0x0C))
        );
    }

    #[test]
    fn payload_length_bounds_are_enforced_per_tag() {
        assert!(validate_payload_len(AuditTag::AuditHello.code(), AUDIT_HELLO_LEN).is_ok());
        assert!(validate_payload_len(AuditTag::AuditHello.code(), AUDIT_HELLO_LEN - 1).is_err());
        assert!(validate_payload_len(AuditTag::AuditHello.code(), AUDIT_HELLO_LEN + 1).is_err());
        assert!(validate_payload_len(AuditTag::Checkpoint.code(), CHECKPOINT_LEN).is_ok());
        assert!(validate_payload_len(AuditTag::CheckpointAck.code(), CHECKPOINT_ACK_LEN).is_ok());
        assert!(
            validate_payload_len(AuditTag::LocalRecordSeal.code(), LOCAL_RECORD_SEAL_LEN).is_ok()
        );
        assert!(validate_payload_len(AuditTag::LedgerCommit.code(), LEDGER_COMMIT_LEN).is_ok());
        assert!(validate_payload_len(AuditTag::AuditReady.code(), AUDIT_READY_LEN).is_ok());
        assert!(
            validate_payload_len(AuditTag::ManifestSignature.code(), MANIFEST_SIGNATURE_LEN)
                .is_ok()
        );
        assert!(
            validate_payload_len(AuditTag::SecretContribution.code(), SECRET_CONTRIBUTION_LEN)
                .is_ok()
        );
        assert!(validate_payload_len(AuditTag::CloseNotice.code(), 1).is_ok());
        assert!(validate_payload_len(AuditTag::CloseNotice.code(), 2).is_err());
        assert!(validate_payload_len(AuditTag::AuditError.code(), 2).is_ok());
        assert!(validate_payload_len(AuditTag::AuditError.code(), 3).is_err());
        assert!(validate_payload_len(AuditTag::JointManifest.code(), MANIFEST_LEN).is_ok());
        assert!(validate_payload_len(AuditTag::JointManifest.code(), MANIFEST_LEN - 1).is_err());
        assert!(validate_payload_len(AuditTag::JointManifest.code(), MANIFEST_LEN + 1).is_err());
        assert_eq!(
            validate_payload_len(0xFF, 0),
            Err(ProtocolError::UnknownTag(0xFF))
        );
    }

    #[test]
    fn declared_length_mismatches_are_rejected() {
        let message = AuditMessage::Checkpoint(checkpoint());
        let mut encoded = frame(&message);
        encoded.truncate(encoded.len() - 1);
        assert!(matches!(
            AuditMessage::decode_frame(&encoded),
            Err(ProtocolError::InvalidLength { .. })
        ));
        encoded.push(0);
        encoded.push(0);
        assert_eq!(
            AuditMessage::decode_frame(&encoded),
            Err(ProtocolError::TrailingBytes)
        );
        // A frame shorter than the header is rejected outright.
        for len in 0..FRAME_HEADER_LEN {
            assert_eq!(
                AuditMessage::decode_frame(&vec![0_u8; len]),
                Err(ProtocolError::InvalidLength {
                    expected: FRAME_HEADER_LEN,
                    actual: len,
                }),
                "frame of {len} bytes"
            );
        }
        // A frame declaring more payload than its bound fails before reading.
        let mut oversized = encode_frame_header(AuditTag::AuditHello.code(), 4096).to_vec();
        oversized.extend_from_slice(&[0_u8; 4096]);
        assert_eq!(
            AuditMessage::decode_frame(&oversized),
            Err(ProtocolError::InvalidLength {
                expected: 0,
                actual: 4096,
            })
        );
    }

    #[test]
    fn unknown_tags_are_rejected() {
        let mut frame = [0_u8; FRAME_HEADER_LEN];
        frame[0] = 0x0C;
        assert_eq!(
            AuditMessage::decode_frame(&frame),
            Err(ProtocolError::UnknownTag(0x0C))
        );
        assert_eq!(
            AuditMessage::decode_frame(&[]),
            Err(ProtocolError::InvalidLength {
                expected: FRAME_HEADER_LEN,
                actual: 0,
            })
        );
    }

    #[test]
    fn malformed_fixed_payloads_fail_closed() {
        // Wrong-length payloads for every fixed message: the decoder reports
        // the exact frozen length as expected.
        for (tag, expected, len) in [
            (
                AuditTag::AuditHello.code(),
                AUDIT_HELLO_LEN,
                AUDIT_HELLO_LEN + 1,
            ),
            (
                AuditTag::SecretContribution.code(),
                SECRET_CONTRIBUTION_LEN,
                SECRET_CONTRIBUTION_LEN + 1,
            ),
            (
                AuditTag::AuditReady.code(),
                AUDIT_READY_LEN,
                AUDIT_READY_LEN - 1,
            ),
            (
                AuditTag::Checkpoint.code(),
                CHECKPOINT_LEN,
                CHECKPOINT_LEN - 1,
            ),
            (
                AuditTag::CheckpointAck.code(),
                CHECKPOINT_ACK_LEN,
                CHECKPOINT_ACK_LEN + 1,
            ),
            (
                AuditTag::ManifestSignature.code(),
                MANIFEST_SIGNATURE_LEN,
                MANIFEST_SIGNATURE_LEN - 1,
            ),
            (
                AuditTag::LocalRecordSeal.code(),
                LOCAL_RECORD_SEAL_LEN,
                LOCAL_RECORD_SEAL_LEN + 1,
            ),
            (
                AuditTag::LedgerCommit.code(),
                LEDGER_COMMIT_LEN,
                LEDGER_COMMIT_LEN - 1,
            ),
        ] {
            assert_eq!(
                AuditMessage::decode_payload(tag, &vec![0_u8; len]),
                Err(ProtocolError::InvalidLength {
                    expected,
                    actual: len
                }),
                "tag {tag:02X} with payload length {len}"
            );
        }
        // An unknown role byte inside a fixed hello.
        let mut hello_bytes = hello().encode_payload().as_slice().to_vec();
        hello_bytes[0] = 0x03;
        assert_eq!(
            AuditMessage::decode_payload(AuditTag::AuditHello.code(), &hello_bytes),
            Err(ProtocolError::InvalidField(ProtocolField::Reserved))
        );
        let mut ready_bytes = ready().encode_payload().as_slice().to_vec();
        ready_bytes[64..66].copy_from_slice(&0_u16.to_be_bytes());
        assert_eq!(
            AuditMessage::decode_payload(AuditTag::AuditReady.code(), &ready_bytes),
            Err(ProtocolError::InvalidField(ProtocolField::Reserved))
        );
        // A zero format offer is structurally invalid.
        hello_bytes[0] = AuditRole::Controller.code();
        hello_bytes[169..171].copy_from_slice(&0_u16.to_be_bytes());
        assert_eq!(
            AuditMessage::decode_payload(AuditTag::AuditHello.code(), &hello_bytes),
            Err(ProtocolError::InvalidField(ProtocolField::Reserved))
        );
        // Undefined close reasons, error codes and results are rejected.
        assert_eq!(
            AuditMessage::decode_payload(AuditTag::CloseNotice.code(), &[0x06]),
            Err(ProtocolError::InvalidField(ProtocolField::Reserved))
        );
        assert_eq!(
            AuditMessage::decode_payload(AuditTag::CloseNotice.code(), &[]),
            Err(ProtocolError::InvalidLength {
                expected: CLOSE_NOTICE_LEN,
                actual: 0,
            })
        );
        assert_eq!(
            AuditMessage::decode_payload(AuditTag::AuditError.code(), &19_u16.to_be_bytes()),
            Err(ProtocolError::InvalidField(ProtocolField::Reserved))
        );
        assert_eq!(
            AuditMessage::decode_payload(AuditTag::AuditError.code(), &[0, 1, 2]),
            Err(ProtocolError::InvalidLength {
                expected: AUDIT_ERROR_LEN,
                actual: 3,
            })
        );
        let mut commit = ledger_commit().encode_payload().as_slice().to_vec();
        commit[168] = 0x04;
        assert_eq!(
            AuditMessage::decode_payload(AuditTag::LedgerCommit.code(), &commit),
            Err(ProtocolError::InvalidField(ProtocolField::Reserved))
        );
        // An unknown manifest ending tag is rejected.
        let mut manifest_bytes = manifest().encode_payload().unwrap().as_slice().to_vec();
        let tail_start = manifest_bytes.len() - 206;
        manifest_bytes[tail_start + 192] = 0x03;
        assert_eq!(
            AuditMessage::decode_payload(AuditTag::JointManifest.code(), &manifest_bytes),
            Err(ProtocolError::UnknownTag(0x03))
        );
        manifest_bytes[tail_start + 192] = 0x02;
        manifest_bytes[tail_start + 193..tail_start + 197].copy_from_slice(&9_u32.to_be_bytes());
        assert_eq!(
            AuditMessage::decode_payload(AuditTag::JointManifest.code(), &manifest_bytes),
            Err(ProtocolError::UnknownTag(0x02))
        );
        // A reserved "ended normally" byte is rejected.
        manifest_bytes[tail_start + 193..tail_start + 197]
            .copy_from_slice(&(AuditCloseReason::ControllerDetach.code() as u32).to_be_bytes());
        manifest_bytes[tail_start + 197] = 0x02;
        assert_eq!(
            AuditMessage::decode_payload(AuditTag::JointManifest.code(), &manifest_bytes),
            Err(ProtocolError::InvalidField(ProtocolField::Reserved))
        );
    }

    #[test]
    fn manifest_is_fixed_length_and_versioned() {
        let manifest = manifest();
        let encoded = frame(&AuditMessage::JointManifest(manifest.clone()));
        assert_eq!(encoded.len(), FRAME_HEADER_LEN + MANIFEST_LEN);
        assert_eq!(
            AuditMessage::decode_frame(&encoded).unwrap(),
            AuditMessage::JointManifest(manifest.clone())
        );

        let mut bytes = manifest.encode_payload().unwrap().as_slice().to_vec();
        bytes[0..2].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            JointManifest::decode_payload(&bytes),
            Err(ProtocolError::InvalidField(ProtocolField::Reserved))
        );

        let mut trailing = manifest.encode_payload().unwrap().as_slice().to_vec();
        trailing.push(0xAA);
        assert_eq!(
            JointManifest::decode_payload(&trailing),
            Err(ProtocolError::InvalidLength {
                expected: MANIFEST_LEN,
                actual: MANIFEST_LEN + 1,
            })
        );
        assert_eq!(
            manifest_with_version(AUDIT_FORMAT_VERSION - 1).encode_payload(),
            Err(ProtocolError::InvalidField(ProtocolField::Reserved))
        );
    }

    #[test]
    fn audit_error_codes_cover_the_frozen_failure_table() {
        let codes = [
            (1, AuditErrorCode::AuditIdentityMissing),
            (2, AuditErrorCode::AuditIdentityInvalid),
            (3, AuditErrorCode::AuditIdentityPermissions),
            (4, AuditErrorCode::AuditLedgerInvalid),
            (5, AuditErrorCode::AuditLedgerConflict),
            (6, AuditErrorCode::AuditDirectoryUnavailable),
            (7, AuditErrorCode::AuditRecordCreateFailed),
            (8, AuditErrorCode::AuditRecordWriteFailed),
            (9, AuditErrorCode::AuditRecordSyncFailed),
            (10, AuditErrorCode::AuditProtocolUnsupported),
            (11, AuditErrorCode::AuditHandshakeInvalid),
            (12, AuditErrorCode::AuditSessionBindingMismatch),
            (13, AuditErrorCode::AuditCheckpointMismatch),
            (14, AuditErrorCode::AuditPeerSignatureInvalid),
            (15, AuditErrorCode::AuditFinalManifestMismatch),
            (16, AuditErrorCode::AuditLedgerCommitFailed),
            (17, AuditErrorCode::AuditReplayUnsafe),
            (18, AuditErrorCode::AuditContainerInvalid),
        ];
        for (code, expected) in codes {
            assert_eq!(
                AuditErrorCode::from_u16(code),
                Some(expected),
                "from_u16({code})"
            );
            assert_eq!(expected.code(), code, "{expected:?}.code()");
        }
        assert_eq!(AuditErrorCode::from_u16(0), None);
        assert_eq!(AuditErrorCode::from_u16(19), None);
        assert_eq!(AuditErrorCode::from_u16(u16::MAX), None);
    }

    #[test]
    fn close_reasons_roles_modes_and_endings_round_trip() {
        for reason in [
            AuditCloseReason::NormalShellExit,
            AuditCloseReason::ControllerDetach,
            AuditCloseReason::LocalInterrupt,
            AuditCloseReason::ConnectionLost,
            AuditCloseReason::AuditFailure,
        ] {
            assert_eq!(AuditCloseReason::from_byte(reason.code()), Some(reason));
            let message = AuditMessage::CloseNotice(reason);
            assert_eq!(
                AuditMessage::decode_frame(&frame(&message)).unwrap(),
                message
            );
        }
        assert_eq!(AuditCloseReason::from_byte(0), None);
        for role in [AuditRole::Controller, AuditRole::Host] {
            assert_eq!(AuditRole::from_byte(role.code()), Some(role));
        }
        assert_eq!(AuditRole::from_byte(0), None);
        assert_eq!(
            AuthMode::from_byte(AuthMode::Enterprise.code()),
            Some(AuthMode::Enterprise)
        );
        assert_eq!(AuthMode::from_byte(1), None);
        assert_eq!(AuthMode::from_byte(0), None);
        for result in [
            SessionResult::Normal,
            SessionResult::Interrupted,
            SessionResult::AuditFailed,
        ] {
            assert_eq!(SessionResult::from_byte(result.code()), Some(result));
        }
        assert_eq!(SessionResult::from_byte(0), None);
        for ending in [
            ManifestEnding::ShellExit(0),
            ManifestEnding::ShellExit(255),
            ManifestEnding::ShellExit(256),
            ManifestEnding::ShellExit(0xC000_013A),
            ManifestEnding::ShellExit(u32::MAX),
            ManifestEnding::CloseReason(AuditCloseReason::NormalShellExit),
            ManifestEnding::CloseReason(AuditCloseReason::ConnectionLost),
            ManifestEnding::CloseReason(AuditCloseReason::AuditFailure),
        ] {
            assert_eq!(
                ManifestEnding::from_bytes(ending.tag(), ending.value()),
                Some(ending)
            );
        }
        assert_eq!(ManifestEnding::from_bytes(0x03, 0), None);
        assert_eq!(ManifestEnding::from_bytes(0x02, 0x0100_0001), None);
        assert_eq!(
            ManifestEnding::from_bytes(0x02, 0x09),
            None,
            "an undefined close reason inside an ending is rejected"
        );
    }

    #[test]
    fn secret_contributions_are_redacted_in_debug() {
        let contribution = SecretContributionMessage::new(SecretContribution::new([7; NONCE_LEN]));
        assert_eq!(contribution.contribution().as_bytes(), &[7; NONCE_LEN]);
        assert_eq!(
            format!("{contribution:?}"),
            "SecretContributionMessage(SecretContribution([REDACTED]))"
        );
    }

    #[test]
    fn peer_unsupported_message_is_the_frozen_string() {
        assert_eq!(
            PEER_AUDIT_UNSUPPORTED_MESSAGE,
            "peer does not support mandatory verifiable session audit"
        );
    }

    /// Property tests are compiled out under Miri (see `wire::enterprise`).
    #[cfg(not(miri))]
    mod property_tests {
        use super::*;
        use proptest::prelude::*;

        fn arbitrary_snapshot() -> impl Strategy<Value = SharedSnapshot> {
            (any::<[u64; SHARED_STREAMS]>(), any::<[u8; 32]>()).prop_map(|(counts, head)| {
                SharedSnapshot::new(
                    counts.map(|count| StreamSnapshot::new(count, ChainHead::new(head))),
                )
            })
        }

        fn arbitrary_signature() -> impl Strategy<Value = Ed25519Signature> {
            (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(hi, lo)| {
                let mut bytes = [0_u8; ED25519_SIGNATURE_LEN];
                bytes[..32].copy_from_slice(&hi);
                bytes[32..].copy_from_slice(&lo);
                Ed25519Signature::new(bytes)
            })
        }

        fn arbitrary_hello() -> impl Strategy<Value = AuditHello> {
            (
                prop_oneof![Just(AuditRole::Controller), Just(AuditRole::Host),],
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                any::<u64>(),
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                (1_u16..),
                any::<[u8; 32]>(),
                arbitrary_signature(),
            )
                .prop_map(
                    |(
                        role,
                        key,
                        session_key,
                        nonce,
                        sequence,
                        root,
                        binding,
                        format,
                        commitment,
                        signature,
                    )| {
                        AuditHello::new(
                            role,
                            Ed25519PublicKey::new(key),
                            Ed25519PublicKey::new(session_key),
                            AuditNonce::new(nonce),
                            sequence,
                            LedgerRoot::new(root),
                            BindingDigest::new(binding),
                            format,
                            CommitmentDigest::new(commitment),
                            signature,
                        )
                    },
                )
        }

        fn arbitrary_manifest() -> impl Strategy<Value = JointManifest> {
            (
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                arbitrary_snapshot(),
                any::<u32>(),
                any::<bool>(),
                any::<u64>(),
            )
                .prop_map(
                    |(
                        session,
                        ctrl_fp,
                        host_fp,
                        ctrl_key,
                        host_key,
                        binding,
                        hello_digest,
                        snapshot,
                        exit_code,
                        ended_normally,
                        checkpoint_sequence,
                    )| {
                        JointManifest::new(
                            AUDIT_FORMAT_VERSION,
                            SessionId::new(session),
                            IdentityFingerprint::new(ctrl_fp),
                            IdentityFingerprint::new(host_fp),
                            Ed25519PublicKey::new(ctrl_key),
                            Ed25519PublicKey::new(host_key),
                            BindingDigest::new(binding),
                            Digest32::new(hello_digest),
                            snapshot,
                            ManifestEnding::ShellExit(exit_code),
                            ended_normally,
                            checkpoint_sequence,
                        )
                    },
                )
        }

        /// The documented encoded payload length of every message kind.
        fn documented_len(message: &AuditMessage) -> usize {
            match message {
                AuditMessage::AuditHello(_) => AUDIT_HELLO_LEN,
                AuditMessage::SecretContribution(_) => SECRET_CONTRIBUTION_LEN,
                AuditMessage::AuditReady(_) => AUDIT_READY_LEN,
                AuditMessage::Checkpoint(_) => CHECKPOINT_LEN,
                AuditMessage::CheckpointAck(_) => CHECKPOINT_ACK_LEN,
                AuditMessage::JointManifest(_) => MANIFEST_LEN,
                AuditMessage::ManifestSignature(_) => MANIFEST_SIGNATURE_LEN,
                AuditMessage::LocalRecordSeal(_) => LOCAL_RECORD_SEAL_LEN,
                AuditMessage::LedgerCommit(_) => LEDGER_COMMIT_LEN,
                AuditMessage::CloseNotice(_) => CLOSE_NOTICE_LEN,
                AuditMessage::AuditError(_) => AUDIT_ERROR_LEN,
            }
        }

        fn arbitrary_message() -> impl Strategy<Value = AuditMessage> {
            prop_oneof![
                arbitrary_hello().prop_map(AuditMessage::AuditHello),
                any::<[u8; 32]>().prop_map(|bytes| {
                    AuditMessage::SecretContribution(SecretContributionMessage::new(
                        SecretContribution::new(bytes),
                    ))
                }),
                (any::<[u8; 32]>(), any::<[u8; 32]>(), (1_u16..)).prop_map(
                    |(session, digest, format)| {
                        AuditMessage::AuditReady(AuditReady::new(
                            SessionId::new(session),
                            Digest32::new(digest),
                            format,
                            Ed25519Signature::new([0; ED25519_SIGNATURE_LEN]),
                        ))
                    },
                ),
                (
                    any::<[u8; 32]>(),
                    any::<u64>(),
                    arbitrary_snapshot(),
                    any::<[u8; 32]>(),
                    any::<[u8; 32]>(),
                )
                    .prop_map(|(session, sequence, snapshot, head, ledger)| {
                        AuditMessage::Checkpoint(Checkpoint::new(
                            SessionId::new(session),
                            sequence,
                            snapshot,
                            ChainHead::new(head),
                            Digest32::new(ledger),
                            Ed25519Signature::new([0; ED25519_SIGNATURE_LEN]),
                        ))
                    }),
                (
                    any::<[u8; 32]>(),
                    any::<u64>(),
                    any::<[u8; 32]>(),
                    arbitrary_snapshot(),
                )
                    .prop_map(|(session, sequence, digest, snapshot)| {
                        AuditMessage::CheckpointAck(CheckpointAck::new(
                            SessionId::new(session),
                            sequence,
                            Digest32::new(digest),
                            snapshot,
                            Ed25519Signature::new([0; ED25519_SIGNATURE_LEN]),
                        ))
                    }),
                arbitrary_manifest().prop_map(AuditMessage::JointManifest),
                arbitrary_signature().prop_map(|signature| {
                    AuditMessage::ManifestSignature(ManifestSignature::new(signature))
                }),
                (
                    any::<[u8; 32]>(),
                    any::<u8>(),
                    any::<[u8; 32]>(),
                    any::<u64>(),
                    arbitrary_snapshot(),
                    any::<[u8; 32]>(),
                    any::<[u8; 32]>(),
                )
                    .prop_map(
                        |(session, role, root, count, snapshot, manifest_digest, sealed_digest)| {
                            AuditMessage::LocalRecordSeal(LocalRecordSeal::new(
                                SessionId::new(session),
                                AuditRole::from_byte(role).unwrap_or(AuditRole::Controller),
                                ChainHead::new(root),
                                count,
                                snapshot.roots(),
                                Digest32::new(manifest_digest),
                                Digest32::new(sealed_digest),
                                Ed25519Signature::new([0; ED25519_SIGNATURE_LEN]),
                            ))
                        },
                    ),
                (
                    any::<u64>(),
                    any::<[u8; 32]>(),
                    any::<[u8; 32]>(),
                    any::<[u8; 32]>(),
                    any::<[u8; 32]>(),
                    any::<[u8; 32]>(),
                    any::<u8>(),
                )
                    .prop_map(
                        |(sequence, root, session, manifest, sealed, peer, result)| {
                            AuditMessage::LedgerCommit(LedgerCommit::new(
                                sequence,
                                LedgerRoot::new(root),
                                SessionId::new(session),
                                Digest32::new(manifest),
                                Digest32::new(sealed),
                                IdentityFingerprint::new(peer),
                                SessionResult::from_byte(result).unwrap_or(SessionResult::Normal),
                                Ed25519Signature::new([0; ED25519_SIGNATURE_LEN]),
                            ))
                        },
                    ),
                prop::bool::ANY.prop_flat_map(|is_close_notice| {
                    if is_close_notice {
                        (1_u8..=5)
                            .prop_map(|code| {
                                AuditMessage::CloseNotice(
                                    AuditCloseReason::from_byte(code)
                                        .expect("codes one through five are legal close reasons"),
                                )
                            })
                            .boxed()
                    } else {
                        (1_u16..=18)
                            .prop_map(|code| {
                                AuditMessage::AuditError(
                                    AuditErrorCode::from_u16(code)
                                        .expect("codes one through eighteen are legal error codes"),
                                )
                            })
                            .boxed()
                    }
                }),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig {
                failure_persistence: None,
                ..ProptestConfig::default()
            })]

            #[test]
            fn audit_messages_round_trip_arbitrary_instances(message in arbitrary_message()) {
                let encoded = message.encode().unwrap();
                prop_assert_eq!(AuditMessage::decode_frame(encoded.as_slice()), Ok(message));
            }

            #[test]
            fn audit_encodings_respect_length_bounds(message in arbitrary_message()) {
                let encoded = message.encode().unwrap();
                prop_assert_eq!(encoded.as_slice().len(), FRAME_HEADER_LEN + documented_len(&message));
                prop_assert!(encoded.as_slice().len() <= MAX_AUDIT_FRAME_LEN);
            }

            #[test]
            fn audit_hello_signatures_inputs_are_well_formed(hello in arbitrary_hello()) {
                let signing = hello.signing_input();
                let payload = hello.encode_payload();
                prop_assert_eq!(
                    &signing.as_slice()[..AUDIT_HELLO_DOMAIN.len()],
                    AUDIT_HELLO_DOMAIN
                );
                prop_assert_eq!(signing.as_slice().len(), AUDIT_HELLO_SIGNING_LEN);
                prop_assert_eq!(
                    &signing.as_slice()[AUDIT_HELLO_DOMAIN.len()..],
                    &payload.as_slice()[..AUDIT_HELLO_LEN - ED25519_SIGNATURE_LEN]
                );
            }

        }
    }
}
