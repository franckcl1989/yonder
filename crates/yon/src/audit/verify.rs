//! Offline verification of `.yonaudit` container pairs, Yonder 0.2.0 design
//! sections 25 (CLI), 27.1 (streaming, bounded) and 31 (threat model).
//!
//! [`verify_files`] verifies both containers, both local event chains, the
//! four shared fact chains (input commitments by HMAC comparison, output
//! blocks, terminal control events and file transfer events), the bilateral
//! checkpoints, the ephemeral session signatures, the final joint manifest,
//! the embedded persistent identity signatures and, when the current machine
//! holds a matching protected audit identity, the optional local ledger
//! continuity anchor (design sections 25.1 and 9.4).
//!
//! Verification is fully streaming and bounded: only one record frame, the
//! footer (at most [`MAX_FOOTER_PREFIX_LEN`] plus the final digest) and the
//! fixed chain state live in memory at once. Files are never loaded whole
//! (design section 27.1). The anchor walk over the local ledger chain is
//! capped so a pathological history cannot stall verification.
//!
//! # Offline boundary
//!
//! This module performs no network I/O, reads no OPAQUE state and never
//! prints input commitments, private keys, connection codes or raw audit
//! content (design section 30: error text is fixed and redacted). Input
//! commitment verification compares only the HMAC values that are already
//! protected by the hash chains and signatures of both files; the input
//! commitment key is never needed offline (design section 5.4).
//!
//! # Result classification (design section 25.2)
//!
//! - [`VerificationState::VerifiedComplete`]: both files complete, identical
//!   joint manifest, valid embedded identity and session signatures on both
//!   sides, all shared chains consistent, both local chains and
//!   `LocalRecordSeal`s valid, and at least one end matches the current
//!   machine's protected persistent audit identity with ledger continuity.
//! - [`VerificationState::ConsistentCompleteUnanchored`]: the same checks
//!   pass but no trusted identity or ledger anchor exists on this machine.
//! - [`VerificationState::MatchedInterruptedPrefix`]: the session ended
//!   without a complete joint manifest; both files cross-confirm the same
//!   directional checkpoint evidence, and each selected snapshot is a
//!   verified prefix of both shared-chain records.
//! - [`VerificationState::IntactUnpaired`]: a single file is self-consistent
//!   but no peer file was provided.
//! - [`VerificationState::Mismatch`]: the two files are internally valid but
//!   inconsistent with each other.
//! - [`VerificationState::Tampered`]: a container, hash chain,
//!   `LocalRecordSeal`, signature or the ledger proof is invalid.
//!
//! Exit codes (design section 25.3) are exposed by
//! [`VerificationState::exit_code`].

use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;
use yonder_core::OsSecureRandom;
use yonder_core::wire::audit::{
    AUDIT_FORMAT_VERSION, AuditHello, AuditRole, ChainHead, Checkpoint, CheckpointAck, DIGEST_LEN,
    Digest32, Ed25519PublicKey, Ed25519Signature, IdentityFingerprint, JointManifest,
    LEDGER_COMMIT_LEN, LOCAL_RECORD_SEAL_LEN, LedgerRoot, MANIFEST_LEN, MANIFEST_SIGNATURE_LEN,
    ManifestEnding, ManifestSignature, SessionId, SharedSnapshot, SharedStream, StreamSnapshot,
};
use yonder_core::wire::audit_container::{
    AuditContainerHeader, CONTAINER_DIGEST_LEN, CONTAINER_HEADER_LEN, CONTAINER_MAGIC,
    FOOTER_MAGIC, MAX_FOOTER_PREFIX_LEN, RECORD_FRAME_HEADER_LEN, RecordType, decode_footer,
    validate_frame_len,
};

use crate::audit::identity::{self, AuditIdentity};
use crate::audit::ledger;
use crate::audit::session::{
    CHAIN_CONTROL_DOMAIN, CHAIN_FILE_DOMAIN, CHAIN_INPUT_DOMAIN, CHAIN_LOCAL_DOMAIN,
    CHAIN_OUTPUT_DOMAIN, CONTROL_KIND_CLOSE_REASON, CONTROL_KIND_RESIZE,
    CONTROL_KIND_TERMINAL_COMPLETE, CONTROL_KIND_TERMINAL_EXIT, CONTROL_KIND_TERMINAL_HELLO,
    CONTROL_KIND_TERMINAL_READY, DIRECTION_CTRL_TO_HOST, DIRECTION_HOST_TO_CTRL,
    EVIDENCE_RECEIVED_CHECKPOINT, EVIDENCE_RECEIVED_CHECKPOINT_ACK, EVIDENCE_RECEIVED_MANIFEST,
    EVIDENCE_RECEIVED_MANIFEST_SIGNATURE, EVIDENCE_SENT_CHECKPOINT, EVIDENCE_SENT_CHECKPOINT_ACK,
    EVIDENCE_SENT_MANIFEST, EVIDENCE_SENT_MANIFEST_SIGNATURE, FILE_KIND_CANCELLED,
    FILE_KIND_FAILED, FILE_KIND_START, FILE_KIND_SUCCESS, FILE_LOCAL_KIND_COMMIT_STATUS_UNKNOWN,
    FILE_LOCAL_KIND_COMMITTED_UNCONFIRMED, INPUT_EVENT_KIND, LOCAL_FILE_AMBIGUITY_PAYLOAD_LEN,
    OUTPUT_EVENT_KIND, SPLIT_PREFIX_LEN, decode_shared_control, decode_shared_file,
    decode_shared_input, decode_shared_output, expected_local_file_ambiguity_kind, zero_head,
};

/// The number of shared fact streams.
const SHARED_STREAMS: usize = 4;

/// The smallest complete footer: footer magic, the smallest manifest, both
/// manifest signatures, the seal, the ledger commit and the final digest. A
/// file ending inside a footer shorter than this can never be complete, so it
/// is a truncated interrupted prefix (design section 22.5).
const MIN_LEGAL_FOOTER_LEN: usize = FOOTER_MAGIC.len()
    + 2
    + MANIFEST_LEN
    + (2 + MANIFEST_SIGNATURE_LEN) * 2
    + 2
    + LOCAL_RECORD_SEAL_LEN
    + 2
    + LEDGER_COMMIT_LEN
    + CONTAINER_DIGEST_LEN;

/// The bounded tail parsed when walking the local ledger chain backwards.
const ANCHOR_TAIL_LEN: usize = MAX_FOOTER_PREFIX_LEN + CONTAINER_DIGEST_LEN;
/// The maximum number of ledger links walked backward when anchoring.
const MAX_ANCHOR_STEPS: u64 = 1024;
/// The maximum number of records scanned per ledger link when anchoring.
const MAX_ANCHOR_SCAN: usize = 8192;

/// The fixed ledger state file layout mirrored read-only from `audit::ledger`
/// (magic, version, sequence, root, checksum). Verify only ever reads this
/// file; it never creates or advances anything.
const LEDGER_STATE_LEN: usize = 8 + 2 + 8 + 32 + 32;
const LEDGER_STATE_CHECKSUM_OFFSET: usize = LEDGER_STATE_LEN - 32;

/// The six verification states of design section 25.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationState {
    /// Both files complete and consistent, anchored to at least one known
    /// endpoint identity and ledger.
    VerifiedComplete,
    /// Both files complete and cryptographically self-consistent, but no
    /// trusted identity or ledger anchor exists on this machine.
    ConsistentCompleteUnanchored,
    /// The session was interrupted; both files cross-confirm compatible
    /// directional checkpoint prefixes and there is no complete joint
    /// manifest.
    MatchedInterruptedPrefix,
    /// A single file is self-consistent; no peer file was provided, so
    /// bilateral consistency cannot be certified.
    IntactUnpaired,
    /// The two files' shared chains, counts, identities, checkpoints or
    /// joint manifests are inconsistent with each other.
    Mismatch,
    /// A container, hash chain, `LocalRecordSeal`, signature or ledger proof
    /// is invalid.
    Tampered,
}

impl VerificationState {
    /// The CLI exit code of this state (design section 25.3): `0` verified
    /// complete, `1` format or I/O errors (see [`VerifyError`]), `2`
    /// consistent-but-unanchored or interrupted or unpaired, `3` mismatch,
    /// `4` tampered.
    #[must_use]
    pub const fn exit_code(self) -> u32 {
        match self {
            Self::VerifiedComplete => 0,
            Self::ConsistentCompleteUnanchored
            | Self::MatchedInterruptedPrefix
            | Self::IntactUnpaired => 2,
            Self::Mismatch => 3,
            Self::Tampered => 4,
        }
    }

    /// The fixed display name of the state.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::VerifiedComplete => "VERIFIED_COMPLETE",
            Self::ConsistentCompleteUnanchored => "CONSISTENT_COMPLETE_UNANCHORED",
            Self::MatchedInterruptedPrefix => "MATCHED_INTERRUPTED_PREFIX",
            Self::IntactUnpaired => "INTACT_UNPAIRED",
            Self::Mismatch => "MISMATCH",
            Self::Tampered => "TAMPERED",
        }
    }
}

/// Fixed facts about one verified file, for reporting.
#[derive(Debug, Clone)]
pub struct FileReport {
    /// The verified file path.
    pub path: PathBuf,
    /// The role recorded in the container header.
    pub role: AuditRole,
    /// The SHA-256 fingerprint of the embedded persistent audit identity.
    pub fingerprint: IdentityFingerprint,
    /// The UTC wall-clock session start recorded in the header. Wall-clock
    /// time is display metadata, not a trusted timestamp (design
    /// section 15.4).
    pub utc_start_seconds: u64,
    /// The final event counts of the four shared chains.
    pub shared_counts: [u64; SHARED_STREAMS],
    /// The final local observation chain event count.
    pub local_event_count: u64,
    /// Whether the file has a complete footer (joint manifest, signatures,
    /// seal and ledger commit).
    pub finalized: bool,
    /// Whether the file ends in a truncated tail (a partial frame or an
    /// incomplete footer). The verified prefix stays valid.
    pub truncated_tail: bool,
    /// The last locally sent checkpoint whose peer acknowledgment is in
    /// this record: sequence and checkpoint payload digest.
    pub last_confirmed_sent_checkpoint: Option<(u64, [u8; DIGEST_LEN])>,
    /// The last peer checkpoint for which this endpoint recorded a signed
    /// acknowledgment: sequence and checkpoint payload digest.
    pub last_confirmed_received_checkpoint: Option<(u64, [u8; DIGEST_LEN])>,
    /// The manifest ending, when the file is finalized.
    pub ending: Option<ManifestEnding>,
    /// The manifest's normal-completion flag, when the file is finalized.
    pub ended_normally: bool,
}

/// The optional local anchor outcome (design sections 9.4 and 25.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AnchorReport {
    /// The current machine's protected persistent audit identity matches the
    /// embedded identity of at least one provided file.
    pub identity_matched: bool,
    /// The matching file's ledger commit is part of the current local ledger
    /// chain (the continuity walk reached the commit without a gap).
    pub ledger_continuous: bool,
}

/// The result of one offline verification.
#[derive(Debug, Clone)]
pub struct VerificationReport {
    /// The classification state.
    pub state: VerificationState,
    /// The session ID, when a container header parsed.
    pub session_id: Option<SessionId>,
    /// Facts about the controller file, when provided and parseable.
    pub controller: Option<FileReport>,
    /// Facts about the host file, when provided and parseable.
    pub host: Option<FileReport>,
    /// The local anchor outcome (only meaningful for complete pairs).
    pub anchor: AnchorReport,
    /// A fixed, redacted reason for `Mismatch` and `Tampered` states.
    pub reason: Option<&'static str>,
}

/// Errors that prevent verification entirely: I/O failures and files that are
/// not audit containers. Both map to exit code `1` (design section 25.3);
/// verification outcomes with cryptographic or structural defects are
/// reported as [`VerificationState`] results instead.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// An I/O error while reading a file.
    #[error("the audit file could not be read")]
    Io(#[from] io::Error),
    /// The file is not a `.yonaudit` container (too short, bad magic, bad
    /// format version or bad embedded handshake structure).
    #[error("the file is not a valid audit container")]
    NotAnAuditContainer,
    /// The file has Yonder audit magic but uses a different container
    /// version. This is an interoperability result, not evidence of tampering.
    #[error("the audit file format is not supported")]
    UnsupportedAuditFormat,
}

/// Errors surfaced by the streaming frame walk shared with the replay layer.
#[derive(Debug, Error)]
pub enum StreamError {
    /// An I/O error while reading.
    #[error("the audit file could not be read")]
    Io(#[from] io::Error),
    /// The file is not a `.yonaudit` container.
    #[error("the file is not a valid audit container")]
    NotAnAuditContainer,
    /// The file is a Yonder audit container with an unsupported format.
    #[error("the audit file format is not supported")]
    UnsupportedAuditFormat,
    /// The container structure or cryptography is invalid. The fixed reason
    /// text is redacted and never contains file content.
    #[error("the audit container is invalid: {0}")]
    Tampered(&'static str),
}

/// The local anchor lookup: the current machine's protected persistent audit
/// identity and its audit root. The production implementation is
/// [`PlatformAnchorLookup`]; tests inject a temporary root.
pub trait AnchorLookup {
    /// The local audit root and its protected persistent identity, or `None`
    /// when this machine has no audit identity (design section 9.2: an
    /// existing identity is loaded read-only; nothing is ever created).
    fn local_anchor(&self) -> Option<(PathBuf, AuditIdentity)>;
}

/// Resolves the platform audit root and loads the local protected identity
/// read-only.
pub struct PlatformAnchorLookup;

impl AnchorLookup for PlatformAnchorLookup {
    fn local_anchor(&self) -> Option<(PathBuf, AuditIdentity)> {
        use crate::audit::identity::AuditRoot as _;
        let root = identity::PlatformAuditRoot.audit_root().ok()?;
        let identity = load_anchor_identity(&root)?;
        Some((root, identity))
    }
}

/// Loads the persistent audit identity of the given root without creating
/// anything: the identity file must already exist.
fn load_anchor_identity(root: &Path) -> Option<AuditIdentity> {
    if !root.join(identity::IDENTITY_FILE_NAME).is_file() {
        return None;
    }
    // The identity file exists, so this only loads and validates the file
    // and its permissions; it never generates a new identity.
    identity::open_or_create_identity(root, &mut OsSecureRandom).ok()
}

/// A streaming action request from the frame visitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamAction {
    /// Continue with the next frame.
    Continue,
    /// Stop the walk; the current frame was the last one delivered.
    Stop,
}

/// The summary of one streaming frame walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamSummary {
    /// The total file length in bytes.
    pub file_len: u64,
    /// Whether the file ends in a truncated tail (a partial frame or an
    /// incomplete footer). Frames before the tail were delivered.
    pub truncated_tail: bool,
}

/// The visitor signature of [`stream_frames`]: the record type and payload of
/// each frame in file order.
pub type FrameVisitor<'a> = dyn FnMut(RecordType, &[u8]) -> Result<StreamAction, StreamError> + 'a;

/// Streams the record frames of one container in file order, stopping at the
/// footer (if any) or at a truncated tail. The visitor receives the record
/// type and payload; the payload buffer is reused between frames, so the
/// visitor must not retain the slice. Memory stays bounded: at most one frame
/// (up to the container's 1 MiB frame bound) is in memory at once. The
/// container header is validated structurally but not cryptographically here
/// (callers that need full verification use [`verify_files`]).
pub fn stream_frames(
    path: &Path,
    visit: &mut FrameVisitor<'_>,
) -> Result<StreamSummary, StreamError> {
    let mut walker = FrameWalker::open(path)?;
    walker.skip_header()?;
    loop {
        let Some((record_type, payload)) = walker.next_frame()? else {
            return Ok(walker.summary());
        };
        match visit(record_type, payload)? {
            StreamAction::Continue => {}
            StreamAction::Stop => return Ok(walker.summary()),
        }
    }
}

/// A bounded streaming frame reader over one container file.
struct FrameWalker {
    reader: BufReader<File>,
    pos: u64,
    len: u64,
    buffer: Vec<u8>,
    truncated_tail: bool,
}

impl FrameWalker {
    fn open(path: &Path) -> Result<Self, StreamError> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        if len < CONTAINER_HEADER_LEN as u64 {
            return Err(StreamError::NotAnAuditContainer);
        }
        Ok(Self {
            reader: BufReader::with_capacity(64 * 1024, file),
            pos: 0,
            len,
            buffer: Vec::with_capacity(64 * 1024),
            truncated_tail: false,
        })
    }

    /// Consumes and structurally validates the fixed header, returning its
    /// bytes.
    fn skip_header(&mut self) -> Result<[u8; CONTAINER_HEADER_LEN], StreamError> {
        let mut header = [0_u8; CONTAINER_HEADER_LEN];
        self.reader.read_exact(&mut header)?;
        self.pos = CONTAINER_HEADER_LEN as u64;
        if header[..CONTAINER_MAGIC.len()] == CONTAINER_MAGIC
            && u16::from_be_bytes([header[8], header[9]]) != AUDIT_FORMAT_VERSION
        {
            return Err(StreamError::UnsupportedAuditFormat);
        }
        AuditContainerHeader::decode(&header).map_err(|_| StreamError::NotAnAuditContainer)?;
        Ok(header)
    }

    fn summary(&self) -> StreamSummary {
        StreamSummary {
            file_len: self.len,
            truncated_tail: self.truncated_tail,
        }
    }

    /// The absolute offset of the footer magic, when the walk stopped at a
    /// footer.
    fn footer_start(&self) -> Option<u64> {
        (self.pos >= RECORD_FRAME_HEADER_LEN as u64)
            .then_some(self.pos - RECORD_FRAME_HEADER_LEN as u64)
    }

    /// Reads the next frame, or `Ok(None)` when the footer begins or the
    /// walk ended (cleanly or at a truncated tail). The footer magic bytes
    /// are consumed; [`FrameWalker::footer_start`] points at them.
    fn next_frame(&mut self) -> Result<Option<(RecordType, &[u8])>, StreamError> {
        let remaining = self.len - self.pos;
        if remaining < RECORD_FRAME_HEADER_LEN as u64 + 1 {
            self.truncated_tail = remaining > 0;
            return Ok(None);
        }
        let mut length_bytes = [0_u8; 4];
        self.reader.read_exact(&mut length_bytes)?;
        self.pos += 4;
        if length_bytes == FOOTER_MAGIC {
            // The remaining bytes are the footer; frames end here.
            return Ok(None);
        }
        let mut type_byte = [0_u8; 1];
        self.reader.read_exact(&mut type_byte)?;
        self.pos += 1;
        let frame_len = u32::from_be_bytes(length_bytes);
        let record_type = RecordType::from_byte(type_byte[0]).ok_or(StreamError::Tampered(
            "the audit container has an unknown record type",
        ))?;
        validate_frame_len(record_type, frame_len).map_err(|_| {
            StreamError::Tampered("the audit container has an invalid record frame")
        })?;
        let payload_len = usize::try_from(frame_len).map_err(|_| {
            StreamError::Tampered("the audit container has an invalid record frame")
        })? - 1;
        if remaining < RECORD_FRAME_HEADER_LEN as u64 + 1 + payload_len as u64 {
            // The frame is cut off: everything before it is a valid
            // prefix (design sections 22.5 and 23.3).
            self.truncated_tail = true;
            return Ok(None);
        }
        self.buffer.resize(payload_len, 0);
        self.reader.read_exact(&mut self.buffer)?;
        self.pos += payload_len as u64;
        Ok(Some((record_type, &self.buffer)))
    }
}

/// The per-stream shared chain state maintained during the walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SharedChainState {
    count: u64,
    head: ChainHead,
}

/// The latest decoded shared file event and the local observations already
/// associated with it. This mirrors the recording-side state so a verifier
/// cannot accept records that the producer would reject.
#[derive(Debug, Clone, Copy)]
struct LatestFileEvent {
    head: ChainHead,
    transfer_id: u64,
    direction: u8,
    kind: u8,
    local_path_recorded: bool,
    ambiguity_recorded: bool,
}

/// The pending relation of one canonical input or output batch: the local
/// observation record is followed by the shared blocks it completed.
#[derive(Debug, Clone, Copy)]
struct BatchState {
    related: ChainHead,
    saw_block: bool,
}

/// One checkpoint or acknowledgment reference.
#[derive(Debug, Clone, Copy)]
struct CheckpointRef {
    sequence: u64,
    digest: [u8; DIGEST_LEN],
    snapshot: SharedSnapshot,
}

/// One checkpoint confirmed in one sender-to-receiver direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Confirmed {
    sequence: u64,
    digest: [u8; DIGEST_LEN],
    snapshot: SharedSnapshot,
}

/// The verified facts of one file after the streaming walk.
struct VerifiedFile {
    path: PathBuf,
    header: AuditContainerHeader,
    hello: AuditHello,
    shared: [SharedChainState; SHARED_STREAMS],
    local_head: ChainHead,
    local_count: u64,
    last_confirmed_sent: Option<Confirmed>,
    prev_confirmed_sent: Option<Confirmed>,
    last_confirmed_received: Option<Confirmed>,
    prev_confirmed_received: Option<Confirmed>,
    footer: Option<FooterFacts>,
    truncated_tail: bool,
    manifest_evidence: Option<Vec<u8>>,
    received_manifest_evidence: Option<Vec<u8>>,
    sent_manifest_signature: Option<ManifestSignature>,
    received_manifest_signature: Option<ManifestSignature>,
}

/// The decoded footer facts with the absolute digest boundaries.
#[derive(Debug, Clone)]
struct FooterFacts {
    manifest_bytes: Vec<u8>,
    controller_signature: ManifestSignature,
    host_signature: ManifestSignature,
    seal: yonder_core::wire::audit::LocalRecordSeal,
    commit: yonder_core::wire::audit::LedgerCommit,
    sealed_prefix_end: u64,
    seal_end: u64,
    ledger_end: u64,
    final_digest: Digest32,
}

/// Verifies one file pair (or a single file when `peer` is `None`).
///
/// `anchor` supplies the optional local identity and ledger root for
/// anchoring; the production caller passes [`PlatformAnchorLookup`].
pub fn verify_files(
    local: &Path,
    peer: Option<&Path>,
    anchor: &dyn AnchorLookup,
) -> Result<VerificationReport, VerifyError> {
    let local_walk = match walk_file(local) {
        Ok(walk) => walk,
        Err(error) => return map_walk_error(error),
    };
    let Some(peer_path) = peer else {
        return Ok(single_report(local_walk));
    };
    let peer_walk = match walk_file(peer_path) {
        Ok(walk) => walk,
        Err(StreamError::Tampered(reason)) => {
            return Ok(report_pair(
                Some(&local_walk),
                None,
                VerificationState::Tampered,
                Some(reason),
                AnchorReport::default(),
                Some(*local_walk.header.session_id()),
            ));
        }
        Err(error) => {
            return Err(map_walk_error(error).expect_err("only tampered maps to a report"));
        }
    };
    verify_walk_pair(local_walk, peer_walk, anchor)
}

/// Applies the bilateral consistency rules after both containers have
/// independently passed their cryptographic and structural walk. Keeping
/// this decision boundary separate makes every cross-file binding directly
/// testable without weakening the per-file verifier.
fn verify_walk_pair(
    local_walk: VerifiedFile,
    peer_walk: VerifiedFile,
    anchor: &dyn AnchorLookup,
) -> Result<VerificationReport, VerifyError> {
    let (controller, host) = match (local_walk.header.role(), peer_walk.header.role()) {
        (AuditRole::Controller, AuditRole::Host) => (local_walk, peer_walk),
        (AuditRole::Host, AuditRole::Controller) => (peer_walk, local_walk),
        _ => {
            return Ok(report_pair(
                Some(&local_walk),
                Some(&peer_walk),
                VerificationState::Mismatch,
                Some("the two files have the same role"),
                AnchorReport::default(),
                Some(*local_walk.header.session_id()),
            ));
        }
    };
    // -----------------------------------------------------------------
    // Pair identity bindings (design section 25.1).
    // -----------------------------------------------------------------
    if controller.header.session_id() != host.header.session_id() {
        return Ok(mismatch_report(
            &controller,
            &host,
            "the session IDs do not match",
        ));
    }
    if controller.header.peer_identity_pubkey() != host.header.identity_pubkey()
        || host.header.peer_identity_pubkey() != controller.header.identity_pubkey()
    {
        return Ok(mismatch_report(
            &controller,
            &host,
            "the embedded identities do not match",
        ));
    }
    if controller.header.peer_session_pubkey() != host.header.session_pubkey()
        || host.header.peer_session_pubkey() != controller.header.session_pubkey()
    {
        return Ok(mismatch_report(
            &controller,
            &host,
            "the embedded session keys do not match",
        ));
    }
    if controller.hello.connection_binding() != host.hello.connection_binding() {
        return Ok(mismatch_report(
            &controller,
            &host,
            "the connection binding does not match",
        ));
    }
    // Each `AuditReady` carries a digest of the peer's encoded `AuditHello`,
    // so the two files cross-bind each other's identities and session facts.
    let expected = sha256_32(host.hello.encode_payload().as_slice());
    if controller
        .header
        .audit_ready()
        .peer_audit_hello_digest()
        .as_bytes()
        != &expected
    {
        return Ok(mismatch_report(
            &controller,
            &host,
            "the audit handshake confirmations do not match",
        ));
    }
    let expected = sha256_32(controller.hello.encode_payload().as_slice());
    if host
        .header
        .audit_ready()
        .peer_audit_hello_digest()
        .as_bytes()
        != &expected
    {
        return Ok(mismatch_report(
            &controller,
            &host,
            "the audit handshake confirmations do not match",
        ));
    }

    match (&controller.footer, &host.footer) {
        (Some(_), Some(_)) => {
            // Complete pair (design sections 21 and 25.2). Both files' chains
            // already match the shared manifest snapshot (checked per file),
            // so manifest equality implies shared chain equality.
            if controller
                .footer
                .as_ref()
                .expect("matched above")
                .manifest_bytes
                != host.footer.as_ref().expect("matched above").manifest_bytes
            {
                return Ok(mismatch_report(
                    &controller,
                    &host,
                    "the joint manifests differ",
                ));
            }
            let manifest_bytes = &controller
                .footer
                .as_ref()
                .expect("matched above")
                .manifest_bytes;
            let manifest = match JointManifest::decode_payload(manifest_bytes) {
                Ok(manifest) => manifest,
                Err(_) => {
                    return Ok(tampered_report(
                        &controller,
                        &host,
                        "the joint manifest is invalid",
                    ));
                }
            };
            // The manifest fingerprints must match the embedded identities of
            // both files.
            let controller_fingerprint = sha256_32(controller.header.identity_pubkey().as_bytes());
            let host_fingerprint = sha256_32(host.header.identity_pubkey().as_bytes());
            if manifest.controller_fingerprint().as_bytes() != &controller_fingerprint
                || manifest.host_fingerprint().as_bytes() != &host_fingerprint
            {
                return Ok(mismatch_report(
                    &controller,
                    &host,
                    "the embedded identities do not match the joint manifest",
                ));
            }
            // Both footers carry both manifest signatures in the same
            // positional slots (design section 21.2): the controller slot
            // holds the controller session signature and the host slot the
            // host session signature in both files. The two files must
            // agree on both signatures.
            let controller_footer = controller.footer.as_ref().expect("matched above");
            let host_footer = host.footer.as_ref().expect("matched above");
            if controller_footer.controller_signature != host_footer.controller_signature
                || controller_footer.host_signature != host_footer.host_signature
            {
                return Ok(mismatch_report(
                    &controller,
                    &host,
                    "the manifest signatures differ",
                ));
            }
            // The ledger commits reference the peer's identity fingerprint.
            let controller_commit = &controller.footer.as_ref().expect("matched above").commit;
            let host_commit = &host.footer.as_ref().expect("matched above").commit;
            if controller_commit.peer_identity_fingerprint().as_bytes() != &host_fingerprint
                || host_commit.peer_identity_fingerprint().as_bytes() != &controller_fingerprint
            {
                return Ok(mismatch_report(
                    &controller,
                    &host,
                    "the ledger commits do not match the peer identities",
                ));
            }
            let anchor = anchor_pair(&controller, &host, anchor);
            let state = if anchor.identity_matched && anchor.ledger_continuous {
                VerificationState::VerifiedComplete
            } else {
                VerificationState::ConsistentCompleteUnanchored
            };
            Ok(report_pair(
                Some(&controller),
                Some(&host),
                state,
                None,
                anchor,
                Some(*controller.header.session_id()),
            ))
        }
        (_, _) => {
            // Interrupted pair (design sections 20.4 and 22.4): certify only
            // checkpoints cross-confirmed in each independent direction.
            let common = match last_common_confirmed(&controller, &host) {
                Ok(common) => common,
                Err(reason) => return Ok(mismatch_report(&controller, &host, reason)),
            };
            for confirmed in common.into_iter().flatten() {
                for file in [&controller, &host] {
                    match snapshot_is_prefix(&file.path, confirmed.snapshot) {
                        Ok(true) => {}
                        Ok(false) => {
                            return Ok(mismatch_report(
                                &controller,
                                &host,
                                "the confirmed checkpoint is not a shared prefix",
                            ));
                        }
                        Err(StreamError::Tampered(reason)) => {
                            return Ok(tampered_report(&controller, &host, reason));
                        }
                        Err(StreamError::Io(error)) => return Err(VerifyError::Io(error)),
                        Err(StreamError::NotAnAuditContainer) => {
                            return Err(VerifyError::NotAnAuditContainer);
                        }
                        Err(StreamError::UnsupportedAuditFormat) => {
                            return Err(VerifyError::UnsupportedAuditFormat);
                        }
                    }
                }
            }
            // A complete file's footer manifest must agree with the
            // interrupted side's manifest evidence, when the evidence exists.
            // The signature slots are positional: the interrupted side's own
            // signature lives in the slot of its own role in the complete
            // file, and the peer signature it received in the peer-role
            // slot (design section 21.2).
            for (complete, interrupted, interrupted_is_host) in
                [(&controller, &host, true), (&host, &controller, false)]
            {
                if let (Some(footer), Some(evidence)) =
                    (&complete.footer, &interrupted.manifest_evidence)
                    && footer.manifest_bytes != *evidence
                {
                    return Ok(mismatch_report(
                        &controller,
                        &host,
                        "the joint manifests differ",
                    ));
                }
                if let (Some(footer), Some(signature)) =
                    (&complete.footer, &interrupted.sent_manifest_signature)
                {
                    let own_slot = if interrupted_is_host {
                        &footer.host_signature
                    } else {
                        &footer.controller_signature
                    };
                    if signature != own_slot {
                        return Ok(mismatch_report(
                            &controller,
                            &host,
                            "the manifest signatures differ",
                        ));
                    }
                }
                if let (Some(footer), Some(signature)) =
                    (&complete.footer, &interrupted.received_manifest_signature)
                {
                    let peer_slot = if interrupted_is_host {
                        &footer.controller_signature
                    } else {
                        &footer.host_signature
                    };
                    if signature != peer_slot {
                        return Ok(mismatch_report(
                            &controller,
                            &host,
                            "the manifest signatures differ",
                        ));
                    }
                }
            }
            Ok(report_pair(
                Some(&controller),
                Some(&host),
                VerificationState::MatchedInterruptedPrefix,
                None,
                AnchorReport::default(),
                Some(*controller.header.session_id()),
            ))
        }
    }
}

/// The last checkpoint cross-confirmed by both files in each independent
/// sender-to-receiver direction, or the fixed mismatch reason.
fn last_common_confirmed(
    controller: &VerifiedFile,
    host: &VerifiedFile,
) -> Result<[Option<Confirmed>; 2], &'static str> {
    Ok([
        common_direction(
            controller.last_confirmed_sent,
            controller.prev_confirmed_sent,
            host.last_confirmed_received,
            host.prev_confirmed_received,
        )?,
        common_direction(
            host.last_confirmed_sent,
            host.prev_confirmed_sent,
            controller.last_confirmed_received,
            controller.prev_confirmed_received,
        )?,
    ])
}

fn common_direction(
    sender_last: Option<Confirmed>,
    sender_previous: Option<Confirmed>,
    receiver_last: Option<Confirmed>,
    receiver_previous: Option<Confirmed>,
) -> Result<Option<Confirmed>, &'static str> {
    let reason = "the directional checkpoint confirmations do not match";
    if sender_last.is_none() || receiver_last.is_none() {
        return Ok(None);
    }
    let mut common = None;
    for sender in [sender_last, sender_previous].into_iter().flatten() {
        for receiver in [receiver_last, receiver_previous].into_iter().flatten() {
            if sender.sequence == receiver.sequence
                && sender.digest == receiver.digest
                && sender.snapshot == receiver.snapshot
                && common.is_none_or(|current: Confirmed| sender.sequence > current.sequence)
            {
                common = Some(sender);
            }
        }
    }
    common.ok_or(reason).map(Some)
}

/// Replays the bounded shared-chain state to the four counts in a confirmed
/// checkpoint. This second streaming pass avoids retaining an unbounded
/// history of chain heads while still proving that an asynchronously
/// received sender observation is a prefix of both endpoint records.
fn snapshot_is_prefix(path: &Path, target: SharedSnapshot) -> Result<bool, StreamError> {
    let mut walker = FrameWalker::open(path)?;
    let header_bytes = walker.skip_header()?;
    let header = AuditContainerHeader::decode(&header_bytes)
        .map_err(|_| StreamError::NotAnAuditContainer)?;
    let hello = *header.audit_hello();
    let mut verifier = ChainVerifier::new(header, hello);
    let mut reached = [false; SHARED_STREAMS];
    for stream in SharedStream::ALL {
        let expected = target.get(stream);
        if expected.count() == 0 {
            if expected.head() != zero_head() {
                return Ok(false);
            }
            reached[stream.index()] = true;
        }
    }
    while let Some((record_type, payload)) = walker.next_frame()? {
        verifier.process_frame(record_type, payload)?;
        for stream in SharedStream::ALL {
            let index = stream.index();
            if reached[index] {
                continue;
            }
            let expected = target.get(stream);
            let actual = verifier.shared[index];
            if actual.count == expected.count() {
                if actual.head != expected.head() {
                    return Ok(false);
                }
                reached[index] = true;
            } else if actual.count > expected.count() {
                return Ok(false);
            }
        }
    }
    Ok(reached.into_iter().all(|value| value))
}

fn mismatch_report(
    controller: &VerifiedFile,
    host: &VerifiedFile,
    reason: &'static str,
) -> VerificationReport {
    report_pair(
        Some(controller),
        Some(host),
        VerificationState::Mismatch,
        Some(reason),
        AnchorReport::default(),
        Some(*controller.header.session_id()),
    )
}

fn tampered_report(
    controller: &VerifiedFile,
    host: &VerifiedFile,
    reason: &'static str,
) -> VerificationReport {
    report_pair(
        Some(controller),
        Some(host),
        VerificationState::Tampered,
        Some(reason),
        AnchorReport::default(),
        Some(*controller.header.session_id()),
    )
}

fn report_pair(
    controller: Option<&VerifiedFile>,
    host: Option<&VerifiedFile>,
    state: VerificationState,
    reason: Option<&'static str>,
    anchor: AnchorReport,
    session_id: Option<SessionId>,
) -> VerificationReport {
    VerificationReport {
        state,
        session_id,
        controller: controller.map(file_report),
        host: host.map(file_report),
        anchor,
        reason,
    }
}

fn file_report(file: &VerifiedFile) -> FileReport {
    let footer = file.footer.as_ref();
    let manifest =
        footer.and_then(|footer| JointManifest::decode_payload(&footer.manifest_bytes).ok());
    FileReport {
        path: file.path.clone(),
        role: file.header.role(),
        fingerprint: IdentityFingerprint::new(sha256_32(file.header.identity_pubkey().as_bytes())),
        utc_start_seconds: file.header.utc_start_seconds(),
        shared_counts: file.shared.map(|chain| chain.count),
        local_event_count: file.local_count,
        finalized: footer.is_some(),
        truncated_tail: file.truncated_tail,
        last_confirmed_sent_checkpoint: file
            .last_confirmed_sent
            .map(|confirmed| (confirmed.sequence, confirmed.digest)),
        last_confirmed_received_checkpoint: file
            .last_confirmed_received
            .map(|confirmed| (confirmed.sequence, confirmed.digest)),
        ending: manifest.as_ref().map(|manifest| manifest.ending()),
        ended_normally: manifest
            .as_ref()
            .is_some_and(|manifest| manifest.ended_normally()),
    }
}

fn single_report(file: VerifiedFile) -> VerificationReport {
    let session_id = Some(*file.header.session_id());
    match file.header.role() {
        AuditRole::Controller => report_pair(
            Some(&file),
            None,
            VerificationState::IntactUnpaired,
            None,
            AnchorReport::default(),
            session_id,
        ),
        AuditRole::Host => report_pair(
            None,
            Some(&file),
            VerificationState::IntactUnpaired,
            None,
            AnchorReport::default(),
            session_id,
        ),
    }
}

fn map_walk_error(error: StreamError) -> Result<VerificationReport, VerifyError> {
    match error {
        StreamError::Tampered(reason) => Ok(VerificationReport {
            state: VerificationState::Tampered,
            session_id: None,
            controller: None,
            host: None,
            anchor: AnchorReport::default(),
            reason: Some(reason),
        }),
        StreamError::Io(error) => Err(VerifyError::Io(error)),
        StreamError::NotAnAuditContainer => Err(VerifyError::NotAnAuditContainer),
        StreamError::UnsupportedAuditFormat => Err(VerifyError::UnsupportedAuditFormat),
    }
}

/// Walks one container file: header bindings, record frames, chains,
/// checkpoints, footer and prefix digests.
fn walk_file(path: &Path) -> Result<VerifiedFile, StreamError> {
    let mut walker = FrameWalker::open(path)?;
    let header_bytes = walker.skip_header()?;
    let header = AuditContainerHeader::decode(&header_bytes)
        .map_err(|_| StreamError::NotAnAuditContainer)?;
    let hello = *header.audit_hello();
    check_header_bindings(&header, &hello)?;

    let mut verifier = ChainVerifier::new(header, hello);
    while let Some((record_type, payload)) = walker.next_frame()? {
        verifier.process_frame(record_type, payload)?;
    }
    let mut verified = verifier.finish(walker.summary().truncated_tail, path.to_path_buf())?;

    // The footer: bounded tail read, digest verification and seal checks.
    if let Some(footer_start) = walker.footer_start() {
        let footer_len = walker.len - footer_start - RECORD_FRAME_HEADER_LEN as u64;
        let max_footer_len =
            MAX_FOOTER_PREFIX_LEN as u64 - FOOTER_MAGIC.len() as u64 + CONTAINER_DIGEST_LEN as u64;
        if footer_len > max_footer_len {
            return Err(StreamError::Tampered(
                "the audit container has trailing bytes",
            ));
        }
        // The footer buffer starts with the footer magic, which the frame
        // walker already consumed.
        let mut footer_buf = vec![0_u8; footer_len as usize + FOOTER_MAGIC.len()];
        footer_buf[..FOOTER_MAGIC.len()].copy_from_slice(&FOOTER_MAGIC);
        walker
            .reader
            .read_exact(&mut footer_buf[FOOTER_MAGIC.len()..])?;
        match decode_footer(&footer_buf) {
            Ok(decoded) => {
                let manifest_bytes = decoded
                    .footer
                    .manifest
                    .encode_payload()
                    .map_err(|_| StreamError::Tampered("the joint manifest is invalid"))?
                    .as_slice()
                    .to_vec();
                let footer = FooterFacts {
                    manifest_bytes,
                    controller_signature: decoded.footer.controller_session_signature,
                    host_signature: decoded.footer.host_session_signature,
                    seal: decoded.footer.seal,
                    commit: decoded.footer.ledger_commit,
                    sealed_prefix_end: footer_start + decoded.sealed_prefix_end as u64,
                    seal_end: footer_start + decoded.seal_end as u64,
                    ledger_end: footer_start + decoded.ledger_end as u64,
                    final_digest: decoded.final_container_digest,
                };
                let footer = verify_footer(path, &verified, footer)?;
                verified.footer = Some(footer);
            }
            Err(_) if footer_len as usize + FOOTER_MAGIC.len() >= MIN_LEGAL_FOOTER_LEN => {
                // The footer is long enough to be complete but does not
                // decode: the container footer is invalid.
                return Err(StreamError::Tampered("the container footer is invalid"));
            }
            Err(_) => {
                // The footer is incomplete: the file is an interrupted
                // prefix with a truncated tail (design section 22.5).
                verified.truncated_tail = true;
            }
        }
    }
    verify_manifest_evidence(&verified)?;
    Ok(verified)
}

/// The header-level bindings of design sections 13.3, 13.5 and 23.2: the
/// embedded handshake messages must match the header fields, and all three
/// signatures must verify.
fn check_header_bindings(
    header: &AuditContainerHeader,
    hello: &AuditHello,
) -> Result<(), StreamError> {
    if hello.role() != header.role()
        || hello.persistent_audit_key() != header.identity_pubkey()
        || hello.session_key() != header.session_pubkey()
        || hello.ledger_sequence() != header.ledger_sequence()
        || hello.ledger_root() != header.previous_ledger_root()
        || hello.format_version() != AUDIT_FORMAT_VERSION
    {
        return Err(StreamError::Tampered(
            "the embedded audit handshake does not match the container header",
        ));
    }
    let ready = header.audit_ready();
    if ready.session_id() != header.session_id() || ready.format_version() != AUDIT_FORMAT_VERSION {
        return Err(StreamError::Tampered(
            "the audit handshake confirmation does not match the container header",
        ));
    }
    if !verify_ed25519(
        hello.persistent_audit_key(),
        hello.signing_input().as_slice(),
        hello.signature(),
    ) {
        return Err(StreamError::Tampered(
            "the embedded audit handshake signature is invalid",
        ));
    }
    if !verify_ed25519(
        header.session_pubkey(),
        ready.signing_input().as_slice(),
        ready.signature(),
    ) {
        return Err(StreamError::Tampered(
            "the audit handshake confirmation signature is invalid",
        ));
    }
    if !verify_ed25519(
        header.identity_pubkey(),
        header.signing_input().as_slice(),
        header.header_signature(),
    ) {
        return Err(StreamError::Tampered(
            "the container header signature is invalid",
        ));
    }
    Ok(())
}

/// Verifies the footer against the walked chains, the signatures and the
/// three prefix digests (design sections 21 and 23.4). Returns the verified
/// footer facts for the report.
fn verify_footer(
    path: &Path,
    verified: &VerifiedFile,
    footer: FooterFacts,
) -> Result<FooterFacts, StreamError> {
    let tampered = |reason| StreamError::Tampered(reason);
    let manifest = JointManifest::decode_payload(&footer.manifest_bytes)
        .map_err(|_| tampered("the joint manifest is invalid"))?;
    if manifest.format_version() != AUDIT_FORMAT_VERSION
        || manifest.session_id() != verified.header.session_id()
    {
        return Err(tampered("the joint manifest is invalid"));
    }
    let is_controller = verified.header.role() == AuditRole::Controller;
    if is_controller {
        if manifest.controller_session_key() != verified.header.session_pubkey()
            || manifest.host_session_key() != verified.header.peer_session_pubkey()
        {
            return Err(tampered(
                "the joint manifest does not match the container keys",
            ));
        }
        if manifest.controller_fingerprint().as_bytes()
            != &sha256_32(verified.header.identity_pubkey().as_bytes())
            || manifest.host_fingerprint().as_bytes()
                != &sha256_32(verified.header.peer_identity_pubkey().as_bytes())
        {
            return Err(tampered(
                "the joint manifest does not match the container identities",
            ));
        }
    } else {
        if manifest.controller_session_key() != verified.header.peer_session_pubkey()
            || manifest.host_session_key() != verified.header.session_pubkey()
        {
            return Err(tampered(
                "the joint manifest does not match the container keys",
            ));
        }
        if manifest.controller_fingerprint().as_bytes()
            != &sha256_32(verified.header.peer_identity_pubkey().as_bytes())
            || manifest.host_fingerprint().as_bytes()
                != &sha256_32(verified.header.identity_pubkey().as_bytes())
        {
            return Err(tampered(
                "the joint manifest does not match the container identities",
            ));
        }
    }
    if manifest.connection_binding() != verified.hello.connection_binding() {
        return Err(tampered(
            "the joint manifest does not match the container binding",
        ));
    }
    if manifest.terminal_hello_digest() != verified.header.terminal_hello_digest() {
        return Err(tampered(
            "the joint manifest does not match the container header",
        ));
    }
    let snapshot = SharedSnapshot::new(
        verified
            .shared
            .map(|chain| StreamSnapshot::new(chain.count, chain.head)),
    );
    if manifest.final_snapshot() != snapshot {
        return Err(tampered(
            "the joint manifest does not match the recorded chains",
        ));
    }
    let confirmed_sequence = verified
        .last_confirmed_sent
        .into_iter()
        .chain(verified.last_confirmed_received)
        .map(|confirmed| confirmed.sequence)
        .max()
        .unwrap_or(0);
    if manifest.final_checkpoint_sequence() != confirmed_sequence {
        return Err(tampered(
            "the joint manifest does not match the recorded checkpoints",
        ));
    }
    let manifest_input = manifest
        .signing_input()
        .map_err(|_| tampered("the joint manifest is invalid"))?;
    // The footer signature slots are positional (design section 21.2): the
    // controller slot always holds the controller session signature and the
    // host slot the host session signature, in both files, matching the
    // positional key fields of the joint manifest (design section 21.1).
    if !verify_ed25519(
        manifest.controller_session_key(),
        manifest_input.as_slice(),
        footer.controller_signature.signature(),
    ) {
        return Err(tampered("the controller session signature is invalid"));
    }
    if !verify_ed25519(
        manifest.host_session_key(),
        manifest_input.as_slice(),
        footer.host_signature.signature(),
    ) {
        return Err(tampered("the host session signature is invalid"));
    }

    // LocalRecordSeal (design section 21.3).
    let seal = footer.seal;
    if seal.session_id() != manifest.session_id() || seal.role() != verified.header.role() {
        return Err(tampered("the local record seal is invalid"));
    }
    if seal.final_local_event_root() != &verified.local_head
        || seal.local_event_count() != verified.local_count
    {
        return Err(tampered(
            "the local record seal does not match the local chain",
        ));
    }
    if seal.final_shared_roots() != &verified.shared.map(|chain| chain.head) {
        return Err(tampered(
            "the local record seal does not match the shared chains",
        ));
    }
    let manifest_digest = sha256_32(&footer.manifest_bytes);
    if seal.joint_manifest_digest().as_bytes() != &manifest_digest {
        return Err(tampered(
            "the local record seal does not match the joint manifest",
        ));
    }
    if !verify_ed25519(
        verified.header.session_pubkey(),
        seal.signing_input().as_slice(),
        seal.signature(),
    ) {
        return Err(tampered("the local record seal signature is invalid"));
    }

    // Ledger commit (design section 12.1).
    let commit = footer.commit;
    if commit.session_id() != manifest.session_id() {
        return Err(tampered("the ledger commit is invalid"));
    }
    if commit.manifest_digest().as_bytes() != &manifest_digest {
        return Err(tampered(
            "the ledger commit does not match the joint manifest",
        ));
    }
    if !verify_ed25519(
        verified.header.identity_pubkey(),
        commit.signing_input().as_slice(),
        commit.signature(),
    ) {
        return Err(tampered("the ledger commit signature is invalid"));
    }

    // The manifest evidence records must agree with the footer manifest.
    if let Some(evidence) = &verified.manifest_evidence
        && evidence != &footer.manifest_bytes
    {
        return Err(tampered("the joint manifest is invalid"));
    }

    // The three prefix digests in one streaming pass (design section 23.4).
    let digests = compute_prefix_digests(path, &footer)?;
    if seal.sealed_prefix_digest().as_bytes() != &digests.sealed_prefix {
        return Err(tampered("the local record seal digest is invalid"));
    }
    if commit.sealed_record_digest().as_bytes() != &digests.sealed_record {
        return Err(tampered("the ledger commit digest is invalid"));
    }
    if footer.final_digest.as_bytes() != &digests.final_digest {
        return Err(tampered("the container digest does not match its contents"));
    }
    Ok(footer)
}

/// The three prefix digests of a completed container: `[0, sealed_prefix_end)`,
/// `[0, seal_end)` and `[0, ledger_end)`.
struct PrefixDigests {
    sealed_prefix: [u8; DIGEST_LEN],
    sealed_record: [u8; DIGEST_LEN],
    final_digest: [u8; DIGEST_LEN],
}

fn compute_prefix_digests(path: &Path, footer: &FooterFacts) -> Result<PrefixDigests, StreamError> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut sealed_prefix: Option<[u8; DIGEST_LEN]> = None;
    let mut sealed_record: Option<[u8; DIGEST_LEN]> = None;
    let mut buffer = [0_u8; 64 * 1024];
    let mut position = 0_u64;
    loop {
        if position == footer.sealed_prefix_end && sealed_prefix.is_none() {
            sealed_prefix = Some(hasher.clone().finalize().into());
        }
        if position == footer.seal_end && sealed_record.is_none() {
            sealed_record = Some(hasher.clone().finalize().into());
        }
        let remaining = footer.ledger_end.saturating_sub(position);
        if remaining == 0 {
            break;
        }
        let want = remaining.min(buffer.len() as u64) as usize;
        let read = file.read(&mut buffer[..want])?;
        if read == 0 {
            break;
        }
        let mut offset = 0;
        if sealed_prefix.is_none() && position < footer.sealed_prefix_end {
            let take = (footer.sealed_prefix_end - position).min(read as u64) as usize;
            hasher.update(&buffer[..take]);
            offset = take;
            if take < read {
                sealed_prefix = Some(hasher.clone().finalize().into());
            }
        }
        if sealed_record.is_none() && (position + offset as u64) < footer.seal_end {
            let take =
                (footer.seal_end - (position + offset as u64)).min((read - offset) as u64) as usize;
            hasher.update(&buffer[offset..offset + take]);
            offset += take;
            if offset < read {
                sealed_record = Some(hasher.clone().finalize().into());
            }
        }
        hasher.update(&buffer[offset..read]);
        position += read as u64;
    }
    if position != footer.ledger_end || sealed_prefix.is_none() || sealed_record.is_none() {
        return Err(StreamError::Tampered("the audit container is truncated"));
    }
    Ok(PrefixDigests {
        sealed_prefix: sealed_prefix.expect("the prefix snapshot was taken"),
        sealed_record: sealed_record.expect("the seal snapshot was taken"),
        final_digest: hasher.finalize().into(),
    })
}

/// Cross-checks the manifest evidence records at the end of the walk: the
/// sent and received manifests must agree and their signatures must verify.
fn verify_manifest_evidence(verified: &VerifiedFile) -> Result<(), StreamError> {
    let Some(sent) = &verified.manifest_evidence else {
        return Ok(());
    };
    if let Some(received) = &verified.received_manifest_evidence
        && sent != received
    {
        return Err(StreamError::Tampered("the audit manifests do not match"));
    }
    if let Some(signature) = &verified.sent_manifest_signature {
        let manifest = JointManifest::decode_payload(sent)
            .map_err(|_| StreamError::Tampered("the audit manifest is invalid"))?;
        let input = manifest
            .signing_input()
            .map_err(|_| StreamError::Tampered("the audit manifest is invalid"))?;
        if !verify_ed25519(
            verified.header.session_pubkey(),
            input.as_slice(),
            signature.signature(),
        ) {
            return Err(StreamError::Tampered(
                "the audit manifest signature is invalid",
            ));
        }
    }
    if let Some(signature) = &verified.received_manifest_signature {
        let received =
            verified
                .received_manifest_evidence
                .as_ref()
                .ok_or(StreamError::Tampered(
                    "the audit manifest signature is invalid",
                ))?;
        let manifest = JointManifest::decode_payload(received)
            .map_err(|_| StreamError::Tampered("the audit manifest is invalid"))?;
        let input = manifest
            .signing_input()
            .map_err(|_| StreamError::Tampered("the audit manifest is invalid"))?;
        if !verify_ed25519(
            verified.header.peer_session_pubkey(),
            input.as_slice(),
            signature.signature(),
        ) {
            return Err(StreamError::Tampered(
                "the audit manifest signature is invalid",
            ));
        }
    }
    Ok(())
}

/// The per-file chain and checkpoint verifier.
struct ChainVerifier {
    header: AuditContainerHeader,
    hello: AuditHello,
    shared: [SharedChainState; SHARED_STREAMS],
    local_head: ChainHead,
    local_count: u64,
    last_block: [ChainHead; SHARED_STREAMS],
    latest_file_event: Option<LatestFileEvent>,
    input_batch: Option<BatchState>,
    output_batch: Option<BatchState>,
    last_sent_checkpoint_seq: u64,
    last_received_checkpoint_seq: u64,
    last_received_checkpoint: Option<CheckpointRef>,
    last_sent_checkpoint: Option<CheckpointRef>,
    last_received_ack_seq: u64,
    last_sent_ack_seq: u64,
    last_confirmed_sent: Option<Confirmed>,
    prev_confirmed_sent: Option<Confirmed>,
    last_confirmed_received: Option<Confirmed>,
    prev_confirmed_received: Option<Confirmed>,
    manifest_evidence: Option<Vec<u8>>,
    received_manifest_evidence: Option<Vec<u8>>,
    sent_manifest_signature: Option<ManifestSignature>,
    received_manifest_signature: Option<ManifestSignature>,
}

impl ChainVerifier {
    fn new(header: AuditContainerHeader, hello: AuditHello) -> Self {
        Self {
            header,
            hello,
            shared: [SharedChainState {
                count: 0,
                head: zero_head(),
            }; SHARED_STREAMS],
            local_head: zero_head(),
            local_count: 0,
            last_block: [zero_head(); SHARED_STREAMS],
            latest_file_event: None,
            input_batch: None,
            output_batch: None,
            last_sent_checkpoint_seq: 0,
            last_received_checkpoint_seq: 0,
            last_received_checkpoint: None,
            last_sent_checkpoint: None,
            last_received_ack_seq: 0,
            last_sent_ack_seq: 0,
            last_confirmed_sent: None,
            prev_confirmed_sent: None,
            last_confirmed_received: None,
            prev_confirmed_received: None,
            manifest_evidence: None,
            received_manifest_evidence: None,
            sent_manifest_signature: None,
            received_manifest_signature: None,
        }
    }

    fn finish(mut self, truncated_tail: bool, path: PathBuf) -> Result<VerifiedFile, StreamError> {
        self.flush_batches()?;
        Ok(VerifiedFile {
            path,
            header: self.header,
            hello: self.hello,
            shared: self.shared,
            local_head: self.local_head,
            local_count: self.local_count,
            last_confirmed_sent: self.last_confirmed_sent,
            prev_confirmed_sent: self.prev_confirmed_sent,
            last_confirmed_received: self.last_confirmed_received,
            prev_confirmed_received: self.prev_confirmed_received,
            footer: None,
            truncated_tail,
            manifest_evidence: self.manifest_evidence,
            received_manifest_evidence: self.received_manifest_evidence,
            sent_manifest_signature: self.sent_manifest_signature,
            received_manifest_signature: self.received_manifest_signature,
        })
    }

    fn process_frame(
        &mut self,
        record_type: RecordType,
        payload: &[u8],
    ) -> Result<(), StreamError> {
        match record_type {
            RecordType::SharedInputCommitment => {
                if let Some(batch) = self.input_batch.as_mut() {
                    batch.saw_block = true;
                }
                self.process_shared_input(payload)
            }
            RecordType::SharedOutputBlock => {
                if let Some(batch) = self.output_batch.as_mut() {
                    batch.saw_block = true;
                }
                self.process_shared_output(payload)
            }
            RecordType::SharedControlEvent => {
                self.flush_batches()?;
                self.process_shared_control(payload)
            }
            RecordType::SharedFileTransferEvent => {
                self.flush_batches()?;
                self.process_shared_file(payload)
            }
            RecordType::LocalDisplayBytes => self.process_display(payload),
            _ => {
                self.flush_batches()?;
                self.process_local(record_type, payload)
            }
        }
    }

    fn shared_snapshot(&self) -> SharedSnapshot {
        SharedSnapshot::new(
            self.shared
                .map(|chain| StreamSnapshot::new(chain.count, chain.head)),
        )
    }

    fn flush_batches(&mut self) -> Result<(), StreamError> {
        self.flush_input_batch()?;
        self.flush_output_batch()
    }

    fn flush_input_batch(&mut self) -> Result<(), StreamError> {
        let Some(batch) = self.input_batch.take() else {
            return Ok(());
        };
        let stream = SharedStream::Input.index();
        if batch.saw_block {
            if self.last_block[stream] != batch.related {
                return Err(StreamError::Tampered(
                    "the local audit chain is inconsistent",
                ));
            }
        } else if batch.related != zero_head() {
            return Err(StreamError::Tampered(
                "the local audit chain is inconsistent",
            ));
        }
        Ok(())
    }

    fn flush_output_batch(&mut self) -> Result<(), StreamError> {
        let Some(batch) = self.output_batch.take() else {
            return Ok(());
        };
        let stream = SharedStream::Output.index();
        if batch.saw_block {
            if self.last_block[stream] != batch.related {
                return Err(StreamError::Tampered(
                    "the local audit chain is inconsistent",
                ));
            }
        } else if batch.related != zero_head() {
            return Err(StreamError::Tampered(
                "the local audit chain is inconsistent",
            ));
        }
        Ok(())
    }

    /// The display-bytes record relates to the last completed output block of
    /// its batch (design section 18.4): the batch's last block, or zero when
    /// the batch completed no block.
    fn process_display(&mut self, payload: &[u8]) -> Result<(), StreamError> {
        if payload.len() < SPLIT_PREFIX_LEN {
            return Err(StreamError::Tampered(
                "the local audit chain is inconsistent",
            ));
        }
        let related = ChainHead::new(payload[8..40].try_into().expect("fixed slice"));
        let stream = SharedStream::Output.index();
        let ok = match &self.output_batch {
            Some(batch) => {
                related == batch.related
                    || related == self.last_block[stream]
                    || related == zero_head()
            }
            None => related == self.last_block[stream] || related == zero_head(),
        };
        if !ok {
            return Err(StreamError::Tampered(
                "the local audit chain is inconsistent",
            ));
        }
        self.flush_output_batch()?;
        self.commit_local(RecordType::LocalDisplayBytes, payload)
    }

    fn process_shared_input(&mut self, payload: &[u8]) -> Result<(), StreamError> {
        let decoded = decode_shared_input(payload)
            .map_err(|_| StreamError::Tampered("the shared audit chain is inconsistent"))?;
        if decoded.direction != DIRECTION_CTRL_TO_HOST {
            return Err(StreamError::Tampered(
                "the shared audit chain is inconsistent",
            ));
        }
        let stream = SharedStream::Input;
        let chain = &mut self.shared[stream.index()];
        if decoded.sequence != chain.count + 1 || decoded.previous_head != chain.head {
            return Err(StreamError::Tampered(
                "the shared audit chain is inconsistent",
            ));
        }
        let mut canonical = [0_u8; 8 + DIGEST_LEN];
        canonical[..8].copy_from_slice(&decoded.length.to_be_bytes());
        canonical[8..].copy_from_slice(&decoded.hmac);
        let expected = shared_event_hash(
            CHAIN_INPUT_DOMAIN,
            chain.head,
            stream.index() as u8,
            decoded.direction,
            decoded.sequence,
            INPUT_EVENT_KIND,
            &canonical,
        );
        if ChainHead::new(expected) != decoded.new_head {
            return Err(StreamError::Tampered(
                "the shared audit chain is inconsistent",
            ));
        }
        chain.count += 1;
        chain.head = decoded.new_head;
        self.last_block[stream.index()] = decoded.new_head;
        Ok(())
    }

    fn process_shared_output(&mut self, payload: &[u8]) -> Result<(), StreamError> {
        let decoded = decode_shared_output(payload)
            .map_err(|_| StreamError::Tampered("the shared audit chain is inconsistent"))?;
        if decoded.direction != DIRECTION_HOST_TO_CTRL {
            return Err(StreamError::Tampered(
                "the shared audit chain is inconsistent",
            ));
        }
        let stream = SharedStream::Output;
        let chain = &mut self.shared[stream.index()];
        if decoded.sequence != chain.count + 1 || decoded.previous_head != chain.head {
            return Err(StreamError::Tampered(
                "the shared audit chain is inconsistent",
            ));
        }
        let mut canonical = [0_u8; 8 + DIGEST_LEN];
        canonical[..8].copy_from_slice(&decoded.length.to_be_bytes());
        canonical[8..].copy_from_slice(&decoded.digest);
        let expected = shared_event_hash(
            CHAIN_OUTPUT_DOMAIN,
            chain.head,
            stream.index() as u8,
            decoded.direction,
            decoded.sequence,
            OUTPUT_EVENT_KIND,
            &canonical,
        );
        if ChainHead::new(expected) != decoded.new_head {
            return Err(StreamError::Tampered(
                "the shared audit chain is inconsistent",
            ));
        }
        chain.count += 1;
        chain.head = decoded.new_head;
        self.last_block[stream.index()] = decoded.new_head;
        Ok(())
    }

    fn process_shared_control(&mut self, payload: &[u8]) -> Result<(), StreamError> {
        let decoded = decode_shared_control(payload)
            .map_err(|_| StreamError::Tampered("the shared audit chain is inconsistent"))?;
        if decoded.direction != DIRECTION_CTRL_TO_HOST
            && decoded.direction != DIRECTION_HOST_TO_CTRL
        {
            return Err(StreamError::Tampered(
                "the shared audit chain is inconsistent",
            ));
        }
        if !control_kind_payload_len(decoded.kind, decoded.control_payload.len()) {
            return Err(StreamError::Tampered("the shared control event is invalid"));
        }
        let stream = SharedStream::Control;
        let chain = &mut self.shared[stream.index()];
        if decoded.sequence != chain.count + 1 || decoded.previous_head != chain.head {
            return Err(StreamError::Tampered(
                "the shared audit chain is inconsistent",
            ));
        }
        // The session's committed canonical slice covers the whole fixed
        // 106-byte stack array from the kind byte on (97 bytes): the hash
        // input is kind || control_payload || deterministic zero padding.
        let mut canonical = Vec::with_capacity(97);
        canonical.push(decoded.kind);
        canonical.extend_from_slice(&decoded.control_payload);
        canonical.resize(97, 0);
        let expected = shared_event_hash(
            CHAIN_CONTROL_DOMAIN,
            chain.head,
            stream.index() as u8,
            decoded.direction,
            decoded.sequence,
            decoded.kind,
            &canonical,
        );
        if ChainHead::new(expected) != decoded.new_head {
            return Err(StreamError::Tampered(
                "the shared audit chain is inconsistent",
            ));
        }
        chain.count += 1;
        chain.head = decoded.new_head;
        self.last_block[stream.index()] = decoded.new_head;
        Ok(())
    }

    fn process_shared_file(&mut self, payload: &[u8]) -> Result<(), StreamError> {
        let decoded = decode_shared_file(payload)
            .map_err(|_| StreamError::Tampered("the shared audit chain is inconsistent"))?;
        if (decoded.direction != DIRECTION_CTRL_TO_HOST
            && decoded.direction != DIRECTION_HOST_TO_CTRL)
            || !matches!(
                decoded.kind,
                FILE_KIND_START | FILE_KIND_SUCCESS | FILE_KIND_CANCELLED | FILE_KIND_FAILED
            )
        {
            return Err(StreamError::Tampered(
                "the shared file transfer event is invalid",
            ));
        }
        let stream = SharedStream::FileTransfer;
        let chain = &mut self.shared[stream.index()];
        if decoded.sequence != chain.count + 1 || decoded.previous_head != chain.head {
            return Err(StreamError::Tampered(
                "the shared audit chain is inconsistent",
            ));
        }
        let mut canonical = Vec::with_capacity(
            1 + 8 * 3
                + DIGEST_LEN
                + 2
                + decoded.remote_path.len()
                + 2
                + decoded.file_name.len()
                + 2,
        );
        canonical.push(decoded.kind);
        canonical.extend_from_slice(&decoded.transfer_id.to_be_bytes());
        canonical.extend_from_slice(&decoded.declared_size.to_be_bytes());
        canonical.extend_from_slice(&decoded.final_size.to_be_bytes());
        canonical.extend_from_slice(&decoded.digest);
        canonical.extend_from_slice(&(decoded.remote_path.len() as u16).to_be_bytes());
        canonical.extend_from_slice(decoded.remote_path.as_bytes());
        canonical.extend_from_slice(&(decoded.file_name.len() as u16).to_be_bytes());
        canonical.extend_from_slice(decoded.file_name.as_bytes());
        canonical.extend_from_slice(&decoded.error_code.to_be_bytes());
        // The session's committed canonical slice runs to the end of the
        // exact-sized record vec, covering the not-yet-written previous and
        // new head fields: 64 deterministic zero bytes of padding.
        canonical.extend_from_slice(&[0_u8; 2 * DIGEST_LEN]);
        let expected = shared_event_hash(
            CHAIN_FILE_DOMAIN,
            chain.head,
            stream.index() as u8,
            decoded.direction,
            decoded.sequence,
            decoded.kind,
            &canonical,
        );
        if ChainHead::new(expected) != decoded.new_head {
            return Err(StreamError::Tampered(
                "the shared audit chain is inconsistent",
            ));
        }
        chain.count += 1;
        chain.head = decoded.new_head;
        self.last_block[stream.index()] = decoded.new_head;
        self.latest_file_event = Some(LatestFileEvent {
            head: decoded.new_head,
            transfer_id: decoded.transfer_id,
            direction: decoded.direction,
            kind: decoded.kind,
            local_path_recorded: false,
            ambiguity_recorded: false,
        });
        Ok(())
    }

    /// One local observation record: validates the envelope, the kind
    /// structure and the related shared event, then advances the local chain.
    fn process_local(
        &mut self,
        record_type: RecordType,
        payload: &[u8],
    ) -> Result<(), StreamError> {
        if payload.len() < SPLIT_PREFIX_LEN {
            return Err(StreamError::Tampered(
                "the local audit chain is inconsistent",
            ));
        }
        let related = ChainHead::new(payload[8..40].try_into().expect("fixed slice"));
        let kind = &payload[SPLIT_PREFIX_LEN..];
        let inconsistent = || StreamError::Tampered("the local audit chain is inconsistent");
        let mut file_path_recorded = false;
        let mut file_ambiguity_recorded = false;
        match record_type {
            RecordType::LocalInputCommitment => {
                if kind.len() < 9 || kind[0] != DIRECTION_CTRL_TO_HOST {
                    return Err(inconsistent());
                }
                self.input_batch = Some(BatchState {
                    related,
                    saw_block: false,
                });
            }
            RecordType::LocalRawOutput => {
                self.output_batch = Some(BatchState {
                    related,
                    saw_block: false,
                });
            }
            RecordType::LocalSendOutcome => {
                if kind.len() < 10
                    || (kind[0] != DIRECTION_CTRL_TO_HOST && kind[0] != DIRECTION_HOST_TO_CTRL)
                {
                    return Err(inconsistent());
                }
                let stream = if kind[0] == DIRECTION_CTRL_TO_HOST {
                    SharedStream::Input
                } else {
                    SharedStream::Output
                };
                if related != self.last_block[stream.index()] {
                    return Err(inconsistent());
                }
            }
            RecordType::LocalPtyWriteOutcome => {
                if kind.len() < 9 {
                    return Err(inconsistent());
                }
                if related != self.last_block[SharedStream::Input.index()] {
                    return Err(inconsistent());
                }
            }
            RecordType::LocalDisplayWriteOutcome => {
                if kind.len() < 9 {
                    return Err(inconsistent());
                }
                if related != self.last_block[SharedStream::Output.index()] {
                    return Err(inconsistent());
                }
            }
            RecordType::LocalResizeEvent => {
                if kind.len() < 5
                    || (kind[0] != DIRECTION_CTRL_TO_HOST && kind[0] != DIRECTION_HOST_TO_CTRL)
                {
                    return Err(inconsistent());
                }
                if related != self.last_block[SharedStream::Control.index()] {
                    return Err(inconsistent());
                }
            }
            RecordType::LocalLifecycleEvent => {
                if kind.is_empty()
                    || (related != self.last_block[SharedStream::Control.index()]
                        && related != zero_head())
                {
                    return Err(inconsistent());
                }
            }
            RecordType::LocalKeyAction | RecordType::LocalConnectionState => {
                if kind.is_empty() || related != zero_head() {
                    return Err(inconsistent());
                }
            }
            RecordType::LocalAuditError => {
                if kind.len() < 2 || related != zero_head() {
                    return Err(inconsistent());
                }
            }
            RecordType::LocalFileTransferEvent => {
                let latest = self.latest_file_event.ok_or_else(inconsistent)?;
                if related != latest.head {
                    return Err(inconsistent());
                }
                match kind.first().copied() {
                    Some(
                        FILE_KIND_START | FILE_KIND_SUCCESS | FILE_KIND_CANCELLED
                        | FILE_KIND_FAILED,
                    ) => {
                        if kind.len() < 11
                            || latest.local_path_recorded
                            || kind[0] != latest.kind
                            || u64::from_be_bytes(kind[1..9].try_into().expect("fixed transfer id"))
                                != latest.transfer_id
                        {
                            return Err(inconsistent());
                        }
                        let path_len =
                            u16::from_be_bytes(kind[9..11].try_into().expect("fixed path length"))
                                as usize;
                        if kind.len() != 11 + path_len || std::str::from_utf8(&kind[11..]).is_err()
                        {
                            return Err(inconsistent());
                        }
                        file_path_recorded = true;
                    }
                    Some(
                        FILE_LOCAL_KIND_COMMITTED_UNCONFIRMED
                        | FILE_LOCAL_KIND_COMMIT_STATUS_UNKNOWN,
                    ) => {
                        if kind.len() != LOCAL_FILE_AMBIGUITY_PAYLOAD_LEN
                            || latest.kind != FILE_KIND_START
                            || latest.ambiguity_recorded
                            || u64::from_be_bytes(kind[1..9].try_into().expect("fixed transfer id"))
                                != latest.transfer_id
                            || expected_local_file_ambiguity_kind(
                                self.header.role(),
                                latest.direction,
                            ) != Some(kind[0])
                            || kind[49..51] != [0, 0]
                        {
                            return Err(inconsistent());
                        }
                        file_ambiguity_recorded = true;
                    }
                    _ => return Err(inconsistent()),
                }
            }
            RecordType::LocalCloseEvent => {
                if kind.len() < 2
                    || (related != self.last_block[SharedStream::Control.index()]
                        && related != zero_head())
                {
                    return Err(inconsistent());
                }
            }
            RecordType::CheckpointEvidence => {
                if related != zero_head() {
                    return Err(inconsistent());
                }
                self.process_evidence(kind)?;
            }
            RecordType::SharedInputCommitment
            | RecordType::SharedOutputBlock
            | RecordType::SharedControlEvent
            | RecordType::SharedFileTransferEvent
            | RecordType::LocalDisplayBytes => {
                return Err(inconsistent());
            }
        }
        self.commit_local(record_type, payload)?;
        if file_path_recorded {
            self.latest_file_event
                .as_mut()
                .expect("the validated latest file event remains present")
                .local_path_recorded = true;
        }
        if file_ambiguity_recorded {
            self.latest_file_event
                .as_mut()
                .expect("the validated latest file event remains present")
                .ambiguity_recorded = true;
        }
        Ok(())
    }

    /// Advances the local observation chain over one record (design
    /// section 17.2).
    fn commit_local(&mut self, record_type: RecordType, payload: &[u8]) -> Result<(), StreamError> {
        let time = u64::from_be_bytes(payload[..8].try_into().expect("fixed slice"));
        let related = ChainHead::new(payload[8..40].try_into().expect("fixed slice"));
        let kind = &payload[SPLIT_PREFIX_LEN..];
        let head = local_event_hash(
            self.local_head,
            self.local_count + 1,
            time,
            record_type.code(),
            kind,
            related,
        );
        self.local_count += 1;
        self.local_head = ChainHead::new(head);
        Ok(())
    }

    /// One checkpoint evidence record (design sections 15.2, 20.2 and 20.3).
    fn process_evidence(&mut self, kind_payload: &[u8]) -> Result<(), StreamError> {
        if kind_payload.len() < 5 {
            return Err(StreamError::Tampered("the checkpoint evidence is invalid"));
        }
        let kind = kind_payload[0];
        let len = u32::from_be_bytes(kind_payload[1..5].try_into().expect("fixed slice")) as usize;
        if kind_payload.len() != 5 + len {
            return Err(StreamError::Tampered("the checkpoint evidence is invalid"));
        }
        let evidence = &kind_payload[5..];
        match kind {
            EVIDENCE_SENT_CHECKPOINT | EVIDENCE_RECEIVED_CHECKPOINT => {
                let checkpoint = Checkpoint::decode_payload(evidence)
                    .map_err(|_| StreamError::Tampered("the checkpoint is invalid"))?;
                let key = if kind == EVIDENCE_SENT_CHECKPOINT {
                    self.header.session_pubkey()
                } else {
                    self.header.peer_session_pubkey()
                };
                if !verify_ed25519(
                    key,
                    checkpoint.signing_input().as_slice(),
                    checkpoint.signature(),
                ) {
                    return Err(StreamError::Tampered("the checkpoint signature is invalid"));
                }
                let previous_sequence = if kind == EVIDENCE_SENT_CHECKPOINT {
                    self.last_sent_checkpoint_seq
                } else {
                    self.last_received_checkpoint_seq
                };
                let expected_sequence = previous_sequence
                    .checked_add(1)
                    .ok_or(StreamError::Tampered("the checkpoint is invalid"))?;
                if checkpoint.session_id() != self.header.session_id()
                    || checkpoint.sequence() != expected_sequence
                {
                    return Err(StreamError::Tampered("the checkpoint is invalid"));
                }
                if kind == EVIDENCE_SENT_CHECKPOINT
                    && checkpoint.snapshot() != self.shared_snapshot()
                {
                    return Err(StreamError::Tampered(
                        "the checkpoint does not match the shared chains",
                    ));
                }
                let mut snapshot_bytes = [0_u8; 8 + DIGEST_LEN];
                snapshot_bytes[..8].copy_from_slice(&self.header.ledger_sequence().to_be_bytes());
                snapshot_bytes[8..].copy_from_slice(self.header.previous_ledger_root().as_bytes());
                let expected_snapshot = sha256_32(&snapshot_bytes);
                // The ledger snapshot digest refers to the sender's ledger,
                // which only the sender's own file can verify: the received
                // copy is bound to the sent copy by the pair-level checkpoint
                // digest comparison.
                if checkpoint.ledger_snapshot_digest().as_bytes() != &expected_snapshot
                    && kind == EVIDENCE_SENT_CHECKPOINT
                {
                    return Err(StreamError::Tampered("the checkpoint is invalid"));
                }
                if kind == EVIDENCE_SENT_CHECKPOINT {
                    self.last_sent_checkpoint_seq = checkpoint.sequence();
                } else {
                    self.last_received_checkpoint_seq = checkpoint.sequence();
                }
                let digest = sha256_32(evidence);
                let reference = CheckpointRef {
                    sequence: checkpoint.sequence(),
                    digest,
                    snapshot: checkpoint.snapshot(),
                };
                if kind == EVIDENCE_SENT_CHECKPOINT {
                    if checkpoint.local_chain_head() != &self.local_head {
                        return Err(StreamError::Tampered(
                            "the checkpoint does not match the local chain",
                        ));
                    }
                    self.last_sent_checkpoint = Some(reference);
                } else {
                    self.last_received_checkpoint = Some(reference);
                }
            }
            EVIDENCE_SENT_CHECKPOINT_ACK | EVIDENCE_RECEIVED_CHECKPOINT_ACK => {
                let ack = CheckpointAck::decode_payload(evidence).map_err(|_| {
                    StreamError::Tampered("the checkpoint acknowledgment is invalid")
                })?;
                let key = if kind == EVIDENCE_SENT_CHECKPOINT_ACK {
                    self.header.session_pubkey()
                } else {
                    self.header.peer_session_pubkey()
                };
                if !verify_ed25519(key, ack.signing_input().as_slice(), ack.signature()) {
                    return Err(StreamError::Tampered(
                        "the checkpoint acknowledgment signature is invalid",
                    ));
                }
                let checkpoint_sequence = if kind == EVIDENCE_SENT_CHECKPOINT_ACK {
                    self.last_received_checkpoint_seq
                } else {
                    self.last_sent_checkpoint_seq
                };
                if ack.session_id() != self.header.session_id()
                    || ack.sequence() == 0
                    || ack.sequence() > checkpoint_sequence
                {
                    return Err(StreamError::Tampered(
                        "the checkpoint acknowledgment is invalid",
                    ));
                }
                if kind == EVIDENCE_SENT_CHECKPOINT_ACK {
                    if ack.sequence() <= self.last_sent_ack_seq {
                        return Err(StreamError::Tampered(
                            "the checkpoint acknowledgment is invalid",
                        ));
                    }
                    self.last_sent_ack_seq = ack.sequence();
                    let Some(last) = &self.last_received_checkpoint else {
                        return Err(StreamError::Tampered(
                            "the checkpoint acknowledgment is invalid",
                        ));
                    };
                    if ack.sequence() != last.sequence
                        || ack.checkpoint_digest().as_bytes() != &last.digest
                        || ack.snapshot() != last.snapshot
                    {
                        return Err(StreamError::Tampered(
                            "the checkpoint acknowledgment is invalid",
                        ));
                    }
                    self.confirm_received(*last)?;
                } else {
                    if ack.sequence() <= self.last_received_ack_seq {
                        return Err(StreamError::Tampered(
                            "the checkpoint acknowledgment is invalid",
                        ));
                    }
                    self.last_received_ack_seq = ack.sequence();
                    let Some(last) = &self.last_sent_checkpoint else {
                        return Err(StreamError::Tampered(
                            "the checkpoint acknowledgment is invalid",
                        ));
                    };
                    if ack.sequence() != last.sequence
                        || ack.checkpoint_digest().as_bytes() != &last.digest
                        || ack.snapshot() != last.snapshot
                    {
                        return Err(StreamError::Tampered(
                            "the checkpoint acknowledgment is invalid",
                        ));
                    }
                    self.confirm_sent(*last)?;
                }
            }
            EVIDENCE_SENT_MANIFEST | EVIDENCE_RECEIVED_MANIFEST => {
                let manifest = JointManifest::decode_payload(evidence)
                    .map_err(|_| StreamError::Tampered("the audit manifest is invalid"))?;
                if manifest.session_id() != self.header.session_id()
                    || manifest.connection_binding() != self.hello.connection_binding()
                    || manifest.terminal_hello_digest() != self.header.terminal_hello_digest()
                    || manifest.final_snapshot() != self.shared_snapshot()
                {
                    return Err(StreamError::Tampered("the audit manifest is invalid"));
                }
                let bytes = manifest
                    .encode_payload()
                    .map_err(|_| StreamError::Tampered("the audit manifest is invalid"))?
                    .as_slice()
                    .to_vec();
                if kind == EVIDENCE_SENT_MANIFEST {
                    self.manifest_evidence = Some(bytes);
                } else {
                    self.received_manifest_evidence = Some(bytes);
                }
            }
            EVIDENCE_SENT_MANIFEST_SIGNATURE | EVIDENCE_RECEIVED_MANIFEST_SIGNATURE => {
                let signature = ManifestSignature::decode_payload(evidence).map_err(|_| {
                    StreamError::Tampered("the audit manifest signature is invalid")
                })?;
                if kind == EVIDENCE_SENT_MANIFEST_SIGNATURE {
                    self.sent_manifest_signature = Some(signature);
                } else {
                    self.received_manifest_signature = Some(signature);
                }
            }
            _ => {
                return Err(StreamError::Tampered(
                    "the audit container has an unknown checkpoint evidence kind",
                ));
            }
        }
        Ok(())
    }

    fn confirm_sent(&mut self, checkpoint: CheckpointRef) -> Result<(), StreamError> {
        confirm_direction(
            &mut self.last_confirmed_sent,
            &mut self.prev_confirmed_sent,
            checkpoint,
        )
    }

    fn confirm_received(&mut self, checkpoint: CheckpointRef) -> Result<(), StreamError> {
        confirm_direction(
            &mut self.last_confirmed_received,
            &mut self.prev_confirmed_received,
            checkpoint,
        )
    }
}

/// Advances one independent checkpoint direction. Only the last two are
/// needed because at most one checkpoint may await acknowledgment on a
/// direction, so honest peer records can differ by at most one confirmation.
fn confirm_direction(
    last: &mut Option<Confirmed>,
    previous: &mut Option<Confirmed>,
    checkpoint: CheckpointRef,
) -> Result<(), StreamError> {
    let confirmed = Confirmed {
        sequence: checkpoint.sequence,
        digest: checkpoint.digest,
        snapshot: checkpoint.snapshot,
    };
    match *last {
        None => *last = Some(confirmed),
        Some(current) if current.sequence == confirmed.sequence => {
            if current.digest != confirmed.digest || current.snapshot != confirmed.snapshot {
                return Err(StreamError::Tampered(
                    "the checkpoint confirmations are inconsistent",
                ));
            }
        }
        Some(current) if confirmed.sequence > current.sequence => {
            *previous = Some(current);
            *last = Some(confirmed);
        }
        Some(_) => {
            return Err(StreamError::Tampered(
                "the checkpoint confirmations are out of order",
            ));
        }
    }
    Ok(())
}

/// The fixed payload length of one shared control event kind.
fn control_kind_payload_len(kind: u8, len: usize) -> bool {
    match kind {
        CONTROL_KIND_RESIZE => len == 4,
        CONTROL_KIND_TERMINAL_HELLO => len == DIGEST_LEN,
        CONTROL_KIND_TERMINAL_READY | CONTROL_KIND_TERMINAL_COMPLETE => len == 0,
        CONTROL_KIND_TERMINAL_EXIT => len == 4,
        CONTROL_KIND_CLOSE_REASON => len == 1,
        _ => false,
    }
}

/// The shared chain event hash (design section 17.1).
fn shared_event_hash(
    domain: &[u8],
    previous: ChainHead,
    stream_kind: u8,
    direction: u8,
    sequence: u64,
    event_kind: u8,
    canonical_payload: &[u8],
) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(previous.as_bytes());
    hasher.update([stream_kind]);
    hasher.update([direction]);
    hasher.update(sequence.to_be_bytes());
    hasher.update([event_kind]);
    hasher.update(canonical_payload);
    hasher.finalize().into()
}

/// The local chain event hash (design section 17.2).
fn local_event_hash(
    previous: ChainHead,
    local_sequence: u64,
    time_ns: u64,
    event_kind: u8,
    kind_payload: &[u8],
    related: ChainHead,
) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(CHAIN_LOCAL_DOMAIN);
    hasher.update(previous.as_bytes());
    hasher.update(local_sequence.to_be_bytes());
    hasher.update(time_ns.to_be_bytes());
    hasher.update([event_kind]);
    hasher.update(kind_payload);
    hasher.update(related.as_bytes());
    hasher.finalize().into()
}

fn sha256_32(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn verify_ed25519(
    public_key: &Ed25519PublicKey,
    input: &[u8],
    signature: &Ed25519Signature,
) -> bool {
    identity::verify_ed25519_signature(public_key, input, signature)
}

// ---------------------------------------------------------------------------
// Local ledger continuity anchoring (design sections 9.4 and 25.1)
// ---------------------------------------------------------------------------

/// Verifies that at least one provided file's ledger commit is part of the
/// current machine's local ledger chain.
fn anchor_pair(
    controller: &VerifiedFile,
    host: &VerifiedFile,
    lookup: &dyn AnchorLookup,
) -> AnchorReport {
    let Some((root, identity)) = lookup.local_anchor() else {
        return AnchorReport::default();
    };
    let local_fingerprint = identity.fingerprint();
    let mut matched = false;
    for file in [controller, host] {
        let embedded = sha256_32(file.header.identity_pubkey().as_bytes());
        if embedded != *local_fingerprint.as_bytes() {
            continue;
        }
        matched = true;
        if ledger_continuous(&root, &identity, file) {
            return AnchorReport {
                identity_matched: true,
                ledger_continuous: true,
            };
        }
    }
    AnchorReport {
        identity_matched: matched,
        ledger_continuous: false,
    }
}

/// Walks the local ledger chain backward from the current head to the file's
/// commit. Every link must be a complete record signed by the local identity
/// whose digests verify; a gap (deleted session), a fork or a tampered link
/// fails the continuity check (design sections 12.4 and 12.5).
fn ledger_continuous(root: &Path, identity: &AuditIdentity, file: &VerifiedFile) -> bool {
    let Some(commit) = file.footer.as_ref().map(|footer| footer.commit) else {
        return false;
    };
    if !identity.verify(commit.signing_input().as_slice(), commit.signature()) {
        return false;
    }
    let Some((head_sequence, head_root)) = read_ledger_head(root) else {
        return false;
    };
    let commit_sequence = commit.sequence();
    let commit_root = ledger::ledger_root_of(&commit);
    if commit_sequence == head_sequence {
        return commit_root == head_root;
    }
    let Some(next_sequence) = head_sequence.checked_add(1) else {
        return false;
    };
    if commit_sequence == next_sequence && commit.previous_root() == &head_root {
        // The commit awaits the crash recovery of design section 12.4: it
        // chains directly from the current head.
        return true;
    }
    if commit_sequence > head_sequence {
        return false;
    }
    let records = root.join(identity::RECORDS_DIR_NAME);
    let mut target_sequence = head_sequence;
    let mut target_root = head_root;
    let mut steps = 0_u64;
    while target_sequence > commit_sequence {
        if steps >= MAX_ANCHOR_STEPS {
            return false;
        }
        let Some(previous_root) = find_chain_link(&records, identity, target_sequence, target_root)
        else {
            return false;
        };
        target_sequence -= 1;
        target_root = previous_root;
        steps += 1;
    }
    commit_root == target_root
}

/// Finds the single record whose embedded commit is exactly the ledger link
/// `(sequence, root)`, verifies its digests and signature and returns the
/// previous root the link chains from.
fn find_chain_link(
    records: &Path,
    identity: &AuditIdentity,
    sequence: u64,
    root: LedgerRoot,
) -> Option<LedgerRoot> {
    let entries = fs::read_dir(records).ok()?;
    let mut previous_root: Option<LedgerRoot> = None;
    let mut scanned = 0_usize;
    for entry in entries {
        let entry = entry.ok()?;
        scanned += 1;
        if scanned > MAX_ANCHOR_SCAN {
            return None;
        }
        let path = entry.path();
        if path
            .extension()
            .is_none_or(|extension| extension != "yonaudit")
        {
            continue;
        }
        let Some((commit, seal_end, ledger_end, sealed_digest, final_digest)) =
            inspect_anchor_record(&path)
        else {
            continue;
        };
        if commit.sequence() != sequence {
            continue;
        }
        if ledger::ledger_root_of(&commit) != root {
            // A legal commit at the right sequence with the wrong root means
            // the chain diverged: fail closed.
            return None;
        }
        // The link must be intact and signed by the local identity.
        if !identity.verify(commit.signing_input().as_slice(), commit.signature()) {
            return None;
        }
        if !verify_anchor_digests(&path, seal_end, ledger_end, &sealed_digest, &final_digest) {
            return None;
        }
        if previous_root.is_some() {
            // Two records claim the same chain position: a fork.
            return None;
        }
        previous_root = Some(*commit.previous_root());
    }
    previous_root
}

/// Parses the bounded tail of one record file for its embedded commit and
/// digest boundaries.
fn inspect_anchor_record(
    path: &Path,
) -> Option<(
    yonder_core::wire::audit::LedgerCommit,
    u64,
    u64,
    Digest32,
    Digest32,
)> {
    let meta = fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return None;
    }
    let len = meta.len();
    if len < CONTAINER_HEADER_LEN as u64 {
        return None;
    }
    let tail_len = usize::try_from(len.min(ANCHOR_TAIL_LEN as u64)).ok()?;
    let mut file = File::open(path).ok()?;
    file.seek(SeekFrom::End(-(tail_len as i64))).ok()?;
    let mut tail = [0_u8; ANCHOR_TAIL_LEN];
    file.read_exact(&mut tail[..tail_len]).ok()?;
    let mut scan = tail_len;
    while let Some(index) = tail[..scan]
        .iter()
        .rposition(|&byte| byte == FOOTER_MAGIC[0])
    {
        scan = index;
        if !tail[scan..].starts_with(&FOOTER_MAGIC) {
            continue;
        }
        let Ok(decoded) = decode_footer(&tail[scan..]) else {
            continue;
        };
        let footer_start = usize::try_from(len).ok()? - tail_len + scan;
        let seal_end = (footer_start + decoded.seal_end) as u64;
        let ledger_end = (footer_start + decoded.ledger_end) as u64;
        let commit = decoded.footer.ledger_commit;
        return Some((
            commit,
            seal_end,
            ledger_end,
            *commit.sealed_record_digest(),
            decoded.final_container_digest,
        ));
    }
    None
}

/// Verifies the two prefix digests of one anchor record in a single streaming
/// pass.
fn verify_anchor_digests(
    path: &Path,
    seal_end: u64,
    ledger_end: u64,
    expected_sealed: &Digest32,
    expected_final: &Digest32,
) -> bool {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let mut hasher = Sha256::new();
    let mut sealed_snapshot: Option<[u8; DIGEST_LEN]> = None;
    let mut buffer = [0_u8; 64 * 1024];
    let mut position = 0_u64;
    loop {
        if position == seal_end && sealed_snapshot.is_none() {
            sealed_snapshot = Some(hasher.clone().finalize().into());
        }
        let remaining = ledger_end.saturating_sub(position);
        if remaining == 0 {
            break;
        }
        let want = remaining.min(buffer.len() as u64) as usize;
        let Ok(read) = file.read(&mut buffer[..want]) else {
            return false;
        };
        if read == 0 {
            break;
        }
        if sealed_snapshot.is_none() && position < seal_end {
            let take = (seal_end - position).min(read as u64) as usize;
            hasher.update(&buffer[..take]);
            if take < read {
                sealed_snapshot = Some(hasher.clone().finalize().into());
                hasher.update(&buffer[take..read]);
            }
        } else {
            hasher.update(&buffer[..read]);
        }
        position += read as u64;
    }
    if position != ledger_end || sealed_snapshot.is_none() {
        return false;
    }
    let sealed = sealed_snapshot.expect("the seal snapshot was taken");
    sealed == *expected_sealed.as_bytes()
        && hasher.finalize().as_slice() == expected_final.as_bytes()
}

/// Reads the current local ledger head from `ledger.state`, read-only. The
/// layout mirrors the private codec of `audit::ledger`; verify never writes
/// ledger state.
fn read_ledger_head(root: &Path) -> Option<(u64, LedgerRoot)> {
    let path = root.join(identity::LEDGER_STATE_FILE_NAME);
    let meta = fs::symlink_metadata(&path).ok()?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return None;
    }
    if meta.len() != LEDGER_STATE_LEN as u64 {
        return None;
    }
    let mut bytes = [0_u8; LEDGER_STATE_LEN];
    File::open(&path).ok()?.read_exact(&mut bytes).ok()?;
    if bytes[..8] != *b"YONLEDG\0" {
        return None;
    }
    if u16::from_be_bytes([bytes[8], bytes[9]]) != 1 {
        return None;
    }
    let checksum = Sha256::digest(&bytes[..LEDGER_STATE_CHECKSUM_OFFSET]);
    if checksum.as_slice() != &bytes[LEDGER_STATE_CHECKSUM_OFFSET..] {
        return None;
    }
    let sequence = u64::from_be_bytes(bytes[10..18].try_into().ok()?);
    let root = LedgerRoot::new(bytes[18..50].try_into().ok()?);
    Some((sequence, root))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use super::*;
    use crate::audit::session::{
        AuditError, ConnectionSecret, FILE_DIRECTION_UPLOAD, FileTransferFacts,
        Ledger as SessionLedger, Payload, PersistentIdentity, RecordBatch,
    };
    use crate::audit::writer::AuditWriter;
    use ed25519_dalek::{Signer as _, SigningKey as DalekSigningKey};
    use tempfile::tempdir;
    use yonder_core::wire::audit::{
        AuditRole as WireRole, BindingDigest, LedgerRoot as WireRoot, ManifestEnding,
    };
    use yonder_core::wire::audit_container::ContainerReader;

    const CONNECTION_SECRET: &[u8] = b"authenticated-connection-secret-for-verify-tests";

    // -----------------------------------------------------------------
    // Session driver helpers
    // -----------------------------------------------------------------

    #[derive(Clone)]
    pub struct TestIdentity(DalekSigningKey);

    impl TestIdentity {
        pub fn generate(counter: u8) -> Self {
            let seed = [counter; 32];
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

    struct IdentityAdapter(AuditIdentity);

    impl PersistentIdentity for IdentityAdapter {
        fn public_key(&self) -> Ed25519PublicKey {
            self.0.public_key()
        }

        fn fingerprint(&self) -> IdentityFingerprint {
            self.0.fingerprint()
        }

        fn sign(&self, input: &[u8]) -> Result<Ed25519Signature, AuditError> {
            Ok(self.0.sign(input))
        }
    }

    /// An in-memory ledger for unanchored test sessions.
    #[derive(Debug)]
    pub struct MemoryLedger {
        sequence: u64,
        root: WireRoot,
    }

    impl Default for MemoryLedger {
        fn default() -> Self {
            Self {
                sequence: 0,
                root: WireRoot::new([0; DIGEST_LEN]),
            }
        }
    }

    impl SessionLedger for MemoryLedger {
        fn snapshot(&self) -> Result<(u64, WireRoot), AuditError> {
            Ok((self.sequence, self.root))
        }

        fn begin_commit(&mut self) -> Result<(u64, WireRoot), AuditError> {
            Ok((self.sequence + 1, self.root))
        }

        fn finish_commit(
            &mut self,
            commit: &yonder_core::wire::audit::LedgerCommit,
        ) -> Result<(), AuditError> {
            self.sequence = commit.sequence();
            self.root = WireRoot::new(sha256_32(commit.signing_input().as_slice()));
            Ok(())
        }
    }

    /// A ledger backed by the real on-disk ledger of an audit root. This test
    /// adapter mirrors the production owned-commit lifecycle: the ledger is
    /// moved into the lock guard and returned after the state advances.
    struct RealLedgerAdapter {
        inner: Option<crate::audit::ledger::Ledger>,
        pending: Option<crate::audit::ledger::OwnedCommitSession>,
    }

    impl RealLedgerAdapter {
        fn open(root: &Path) -> Self {
            Self {
                inner: Some(crate::audit::ledger::Ledger::open(root, &mut OsSecureRandom).unwrap()),
                pending: None,
            }
        }
    }

    impl SessionLedger for RealLedgerAdapter {
        fn snapshot(&self) -> Result<(u64, WireRoot), AuditError> {
            let ledger = self
                .inner
                .as_ref()
                .ok_or(AuditError::InvalidState("the ledger is mid-commit"))?;
            let head = ledger.head();
            Ok((head.sequence(), head.root()))
        }

        fn begin_commit(&mut self) -> Result<(u64, WireRoot), AuditError> {
            let ledger = self
                .inner
                .take()
                .ok_or(AuditError::InvalidState("the ledger is mid-commit"))?;
            let session = ledger
                .begin_owned_commit()
                .map_err(|_| AuditError::LedgerCommitFailed)?;
            let head = session.head();
            self.pending = Some(session);
            // The trait contract: the sequence and previous root the final
            // commit itself must carry, i.e. the head advanced by one.
            Ok((head.sequence() + 1, head.root()))
        }

        fn finish_commit(
            &mut self,
            commit: &yonder_core::wire::audit::LedgerCommit,
        ) -> Result<(), AuditError> {
            let session = self
                .pending
                .take()
                .ok_or(AuditError::InvalidState("no pending commit session"))?;
            let ledger = session
                .advance(commit)
                .map_err(|_| AuditError::LedgerCommitFailed)?;
            self.inner = Some(ledger);
            Ok(())
        }
    }

    /// The identity and ledger wiring of one endpoint.
    pub enum Endpoint {
        /// Fresh identity plus an in-memory ledger.
        Memory(u8),
        /// The real protected identity and ledger of the given audit root.
        Real(PathBuf),
    }

    pub struct SessionPair {
        pub controller_path: PathBuf,
        pub host_path: PathBuf,
        pub records: PathBuf,
    }

    /// Opens one endpoint session with the given role.
    fn open_endpoint(
        endpoint: Endpoint,
        role: WireRole,
        binding: BindingDigest,
    ) -> crate::audit::session::AuditSession {
        match endpoint {
            Endpoint::Memory(counter) => crate::audit::session::AuditSession::new(
                role,
                Box::new(TestIdentity::generate(counter)),
                Box::new(MemoryLedger::default()),
                binding,
                1_700_000_000,
                &mut SequentialRandom { counter },
            )
            .unwrap(),
            Endpoint::Real(root) => {
                let identity = IdentityAdapter(load_anchor_identity(&root).unwrap());
                crate::audit::session::AuditSession::new(
                    role,
                    Box::new(identity),
                    Box::new(RealLedgerAdapter::open(&root)),
                    binding,
                    1_700_000_000,
                    &mut SequentialRandom { counter: 1 },
                )
                .unwrap()
            }
        }
    }

    fn handshake_until_readies(
        controller: &mut crate::audit::session::AuditSession,
        host: &mut crate::audit::session::AuditSession,
    ) -> (
        yonder_core::wire::audit::AuditReady,
        yonder_core::wire::audit::AuditReady,
    ) {
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

    async fn append(writer: &AuditWriter, batch: RecordBatch<'_>) {
        writer.append_batch(batch).await.unwrap();
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(out, "{byte:02x}").unwrap();
        }
        out
    }

    struct SequentialRandom {
        counter: u8,
    }

    impl yonder_core::SecureRandom for SequentialRandom {
        fn try_fill(&mut self, destination: &mut [u8]) -> Result<(), yonder_core::RandomError> {
            for byte in destination {
                *byte = self.counter;
                self.counter = self.counter.wrapping_add(1);
            }
            Ok(())
        }
    }

    struct RootAnchor(PathBuf);

    impl AnchorLookup for RootAnchor {
        fn local_anchor(&self) -> Option<(PathBuf, AuditIdentity)> {
            let identity = load_anchor_identity(&self.0)?;
            Some((self.0.clone(), identity))
        }
    }

    struct NoAnchor;

    impl AnchorLookup for NoAnchor {
        fn local_anchor(&self) -> Option<(PathBuf, AuditIdentity)> {
            None
        }
    }

    /// Runs a complete bilateral session with the default display timeline
    /// and finalizes both containers.
    pub async fn build_full_pair(dir: &Path, controller: Endpoint, host: Endpoint) -> SessionPair {
        let output: Vec<u8> = (0..18 * 1024).map(|index| (index % 11) as u8).collect();
        let display: Vec<u8> = output.iter().map(|byte| byte | 0x80).collect();
        Box::pin(build_pair_inner(dir, controller, host, &[display])).await
    }

    /// Runs a complete bilateral session whose controller display timeline is
    /// exactly the given bytes.
    pub async fn build_pair_with_controller_display(
        dir: &Path,
        controller: Endpoint,
        host: Endpoint,
        display: &[u8],
    ) -> SessionPair {
        Box::pin(build_pair_inner(dir, controller, host, &[display.to_vec()])).await
    }

    /// Runs a complete bilateral session whose controller display timeline is
    /// recorded as the given chunks, one display record each.
    pub async fn build_pair_with_controller_display_chunks(
        dir: &Path,
        controller: Endpoint,
        host: Endpoint,
        chunks: &[Vec<u8>],
    ) -> SessionPair {
        Box::pin(build_pair_inner(dir, controller, host, chunks)).await
    }

    /// The shared bilateral session driver: handshake, header, terminal
    /// lifecycle, input, the display timeline (one shared output stream plus
    /// one display record per chunk), a resize, a bilaterally confirmed
    /// checkpoint, terminal exit, direction close, joint manifest exchange
    /// and acyclic finalization.
    async fn build_pair_inner(
        dir: &Path,
        controller: Endpoint,
        host: Endpoint,
        display_chunks: &[Vec<u8>],
    ) -> SessionPair {
        let binding = BindingDigest::new([0x42; DIGEST_LEN]);
        // Real endpoints write their records inside the audit root, so the
        // ledger continuity walk can find them; otherwise a scratch records
        // directory is used.
        let records = match (&controller, &host) {
            (Endpoint::Real(root), _) | (_, Endpoint::Real(root)) => {
                root.join(identity::RECORDS_DIR_NAME)
            }
            _ => dir.join("records"),
        };
        let mut controller = open_endpoint(controller, WireRole::Controller, binding);
        let mut host = open_endpoint(host, WireRole::Host, binding);

        let (ready_c, ready_h) = handshake_until_readies(&mut controller, &mut host);
        let session_id = controller.session_id().unwrap();
        let mut controller_writer =
            AuditWriter::open(&records, &session_id, WireRole::Controller).unwrap();
        let mut host_writer = AuditWriter::open(&records, &session_id, WireRole::Host).unwrap();
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

        append(
            &controller_writer,
            controller.record_terminal_ready(100).unwrap(),
        )
        .await;
        append(&host_writer, host.record_terminal_ready(110).unwrap()).await;

        let input: Vec<u8> = (0..20 * 1024).map(|index| (index % 7) as u8).collect();
        for chunk in input.chunks(4096) {
            append(
                &controller_writer,
                controller.record_input(chunk, 200).unwrap(),
            )
            .await;
        }
        for chunk in input.chunks(2048) {
            append(&host_writer, host.record_input(chunk, 210).unwrap()).await;
        }
        // The host's raw output and the controller's display timeline share
        // the same canonical stream; the display records carry the chunks.
        let raw: Vec<u8> = display_chunks.concat();
        append(&host_writer, host.record_output(&raw, 300).unwrap()).await;
        for chunk in display_chunks {
            append(
                &controller_writer,
                controller
                    .record_controller_output(chunk, chunk, 310)
                    .unwrap(),
            )
            .await;
        }
        append(
            &controller_writer,
            controller
                .record_display_write_outcome(true, raw.len() as u64, 320)
                .unwrap(),
        )
        .await;
        // A recorded resize on both sides.
        append(
            &controller_writer,
            controller
                .record_resize(DIRECTION_CTRL_TO_HOST, 100, 30, 330)
                .unwrap(),
        )
        .await;
        append(
            &host_writer,
            host.record_resize(DIRECTION_CTRL_TO_HOST, 100, 30, 331)
                .unwrap(),
        )
        .await;

        // A completed file transfer exercises the fourth shared chain in
        // every complete-pair fixture. Box this additional async fixture
        // step so the already-large test future remains below the native
        // test-thread stack bound on Windows.
        Box::pin(async {
            let file = FileTransferFacts {
                transfer_id: 7,
                direction: FILE_DIRECTION_UPLOAD,
                kind: FILE_KIND_SUCCESS,
                declared_size: 4096,
                final_size: 4096,
                digest: Digest32::new([0xA7; DIGEST_LEN]),
                remote_path: "remote/final.bin",
                file_name: "source.bin",
                error_code: 0,
            };
            append(
                &controller_writer,
                controller
                    .record_file_transfer(&file, Some("local/source.bin"), 340)
                    .unwrap(),
            )
            .await;
            append(
                &host_writer,
                host.record_file_transfer(&file, Some("local/final.bin"), 341)
                    .unwrap(),
            )
            .await;
        })
        .await;

        // Independent, bilaterally confirmed checkpoints in both
        // directions. Their snapshots match, but their sender-local heads,
        // ledger digests and signatures deliberately make the payload
        // digests different.
        controller_writer.sync_all().await.unwrap();
        let (checkpoint, evidence) = controller.build_checkpoint(1_000_000_000).unwrap();
        append(&controller_writer, evidence).await;
        let (ack, host_evidence) = host.receive_checkpoint(&checkpoint, 1_000_000_000).unwrap();
        append(&host_writer, host_evidence).await;
        host_writer.sync_all().await.unwrap();
        let ack_evidence = controller
            .receive_checkpoint_ack(&ack, 1_000_000_010)
            .unwrap()
            .unwrap();
        append(&controller_writer, ack_evidence).await;

        host_writer.sync_all().await.unwrap();
        let (checkpoint, evidence) = host.build_checkpoint(1_000_000_020).unwrap();
        append(&host_writer, evidence).await;
        let (ack, controller_evidence) = controller
            .receive_checkpoint(&checkpoint, 1_000_000_020)
            .unwrap();
        append(&controller_writer, controller_evidence).await;
        controller_writer.sync_all().await.unwrap();
        let ack_evidence = host
            .receive_checkpoint_ack(&ack, 1_000_000_030)
            .unwrap()
            .unwrap();
        append(&host_writer, ack_evidence).await;

        append(
            &controller_writer,
            controller.record_terminal_exit(0, 400).unwrap(),
        )
        .await;
        append(&host_writer, host.record_terminal_exit(0, 410).unwrap()).await;
        append(&controller_writer, controller.close_directions().unwrap()).await;
        append(&host_writer, host.close_directions().unwrap()).await;

        let (manifest_c, signature_c, evidence) = controller
            .build_manifest(ManifestEnding::ShellExit(0), true, 500)
            .unwrap();
        append(&controller_writer, evidence).await;
        let (manifest_h, signature_h, evidence) = host
            .build_manifest(ManifestEnding::ShellExit(0), true, 501)
            .unwrap();
        append(&host_writer, evidence).await;
        assert_eq!(manifest_c, manifest_h);
        let evidence = controller
            .receive_peer_manifest_pair(&manifest_c, &manifest_h, &signature_h, 510)
            .unwrap();
        append(&controller_writer, evidence).await;
        let evidence = host
            .receive_peer_manifest_pair(&manifest_h, &manifest_c, &signature_c, 511)
            .unwrap();
        append(&host_writer, evidence).await;

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
        drop(controller_writer);
        drop(host_writer);
        SessionPair {
            controller_path: records.join(format!(
                "{}.controller.yonaudit",
                hex(session_id.as_bytes())
            )),
            host_path: records.join(format!("{}.host.yonaudit", hex(session_id.as_bytes()))),
            records,
        }
    }

    /// Runs a session up to a bilaterally confirmed checkpoint and stops,
    /// leaving both files as verifiable interrupted prefixes (design
    /// sections 20.4 and 22.4). The controller records one additional output
    /// tail the host never saw.
    pub async fn build_interrupted_pair(dir: &Path) -> SessionPair {
        build_interrupted_pair_with(dir, 0x43).await
    }

    /// Builds an interrupted pair with a distinct binding seed, so different
    /// calls produce different sessions.
    pub async fn build_interrupted_pair_with(dir: &Path, seed: u8) -> SessionPair {
        let binding = BindingDigest::new([seed; DIGEST_LEN]);
        let records = dir.join("records");
        let mut controller = open_endpoint(Endpoint::Memory(1), WireRole::Controller, binding);
        let mut host = open_endpoint(Endpoint::Memory(101), WireRole::Host, binding);
        let (ready_c, ready_h) = handshake_until_readies(&mut controller, &mut host);
        let session_id = controller.session_id().unwrap();
        let controller_writer =
            AuditWriter::open(&records, &session_id, WireRole::Controller).unwrap();
        let host_writer = AuditWriter::open(&records, &session_id, WireRole::Host).unwrap();
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

        append(
            &controller_writer,
            controller.record_terminal_ready(100).unwrap(),
        )
        .await;
        append(&host_writer, host.record_terminal_ready(110).unwrap()).await;
        let input = b"ls -la\n";
        append(
            &controller_writer,
            controller.record_input(input, 200).unwrap(),
        )
        .await;
        append(&host_writer, host.record_input(input, 210).unwrap()).await;
        let output = b"total 4\r\n";
        append(&host_writer, host.record_output(output, 300).unwrap()).await;
        append(
            &controller_writer,
            controller
                .record_controller_output(output, output, 310)
                .unwrap(),
        )
        .await;

        controller_writer.sync_all().await.unwrap();
        let (checkpoint, evidence) = controller.build_checkpoint(1_000_000_000).unwrap();
        append(&controller_writer, evidence).await;
        let (ack, host_evidence) = host.receive_checkpoint(&checkpoint, 1_000_000_000).unwrap();
        append(&host_writer, host_evidence).await;
        host_writer.sync_all().await.unwrap();
        let ack_evidence = controller
            .receive_checkpoint_ack(&ack, 1_000_000_010)
            .unwrap()
            .unwrap();
        append(&controller_writer, ack_evidence).await;

        // The controller's unconfirmed local tail.
        let tail = b"tail output only the controller saw\r\n";
        append(
            &controller_writer,
            controller
                .record_controller_output(tail, tail, 400)
                .unwrap(),
        )
        .await;
        drop(controller_writer);
        drop(host_writer);
        SessionPair {
            controller_path: records.join(format!(
                "{}.controller.yonaudit",
                hex(session_id.as_bytes())
            )),
            host_path: records.join(format!("{}.host.yonaudit", hex(session_id.as_bytes()))),
            records,
        }
    }

    // -----------------------------------------------------------------
    // Verification state matrix tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn complete_pair_with_anchor_is_verified_complete() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("audit-root");
        // The real identity and ledger exist at the root.
        crate::audit::ledger::Ledger::open(&root, &mut OsSecureRandom).unwrap();
        let pair = build_full_pair(
            dir.path(),
            Endpoint::Real(root.clone()),
            Endpoint::Memory(2),
        )
        .await;
        let report = verify_files(
            &pair.controller_path,
            Some(&pair.host_path),
            &RootAnchor(root),
        )
        .unwrap();
        assert_eq!(report.state, VerificationState::VerifiedComplete);
        assert!(report.anchor.identity_matched);
        assert!(report.anchor.ledger_continuous);
        assert_eq!(report.state.exit_code(), 0);
        assert!(report.controller.as_ref().unwrap().finalized);
        assert!(report.host.as_ref().unwrap().finalized);
        assert!(!report.controller.as_ref().unwrap().truncated_tail);
        let controller = report.controller.as_ref().unwrap();
        assert_eq!(
            controller.shared_counts[0], 2,
            "one completed input block plus the final partial block"
        );
        assert!(controller.local_event_count > 0);
        assert_eq!(
            report.controller.as_ref().unwrap().role,
            WireRole::Controller
        );
        assert_eq!(report.host.as_ref().unwrap().role, WireRole::Host);
        assert!(report.session_id.is_some());
    }

    #[tokio::test]
    async fn complete_pair_without_anchor_is_consistent_complete_unanchored() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(3), Endpoint::Memory(103)).await;
        let report = verify_files(&pair.controller_path, Some(&pair.host_path), &NoAnchor).unwrap();
        assert_eq!(
            report.state,
            VerificationState::ConsistentCompleteUnanchored
        );
        assert!(!report.anchor.identity_matched);
        assert_eq!(report.state.exit_code(), 2);

        let report = verify_files(&pair.host_path, Some(&pair.controller_path), &NoAnchor).unwrap();
        assert_eq!(
            report.state,
            VerificationState::ConsistentCompleteUnanchored
        );
        assert_eq!(
            report.controller.as_ref().unwrap().role,
            WireRole::Controller
        );
        assert_eq!(report.host.as_ref().unwrap().role, WireRole::Host);

        let missing_peer = dir.path().join("missing-peer.yonaudit");
        assert!(matches!(
            verify_files(&pair.controller_path, Some(&missing_peer), &NoAnchor),
            Err(VerifyError::Io(_))
        ));
    }

    #[tokio::test]
    async fn complete_pair_with_foreign_identity_is_unanchored() {
        // A forged pair with fresh identities can never be anchored to a
        // machine whose identity differs (design sections 9.4 and 25.2).
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(4), Endpoint::Memory(104)).await;
        let other = dir.path().join("other-root");
        crate::audit::ledger::Ledger::open(&other, &mut OsSecureRandom).unwrap();
        let report = verify_files(
            &pair.controller_path,
            Some(&pair.host_path),
            &RootAnchor(other),
        )
        .unwrap();
        assert_eq!(
            report.state,
            VerificationState::ConsistentCompleteUnanchored
        );
        assert!(!report.anchor.identity_matched);
    }

    #[tokio::test]
    async fn interrupted_pair_is_matched_interrupted_prefix() {
        let dir = tempdir().unwrap();
        let pair = build_interrupted_pair(dir.path()).await;
        let report = verify_files(&pair.controller_path, Some(&pair.host_path), &NoAnchor).unwrap();
        assert_eq!(report.state, VerificationState::MatchedInterruptedPrefix);
        assert!(!report.controller.as_ref().unwrap().finalized);
        assert!(!report.host.as_ref().unwrap().finalized);
        let (sequence, _) = report
            .controller
            .as_ref()
            .unwrap()
            .last_confirmed_sent_checkpoint
            .unwrap();
        assert_eq!(sequence, 1);
        assert_eq!(report.state.exit_code(), 2);
    }

    #[tokio::test]
    async fn complete_single_file_is_intact_unpaired() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(5), Endpoint::Memory(105)).await;
        let report = verify_files(&pair.controller_path, None, &NoAnchor).unwrap();
        assert_eq!(report.state, VerificationState::IntactUnpaired);
        assert!(report.host.is_none());
        assert_eq!(report.state.exit_code(), 2);
    }

    #[tokio::test]
    async fn interrupted_single_file_is_intact_unpaired() {
        let dir = tempdir().unwrap();
        let pair = build_interrupted_pair(dir.path()).await;
        let report = verify_files(&pair.controller_path, None, &NoAnchor).unwrap();
        assert_eq!(report.state, VerificationState::IntactUnpaired);
    }

    #[tokio::test]
    async fn swapped_peer_file_is_mismatch() {
        let dir = tempdir().unwrap();
        let first = build_full_pair(dir.path(), Endpoint::Memory(6), Endpoint::Memory(106)).await;
        let dir = tempdir().unwrap();
        let second = build_full_pair(dir.path(), Endpoint::Memory(7), Endpoint::Memory(107)).await;
        let report =
            verify_files(&first.controller_path, Some(&second.host_path), &NoAnchor).unwrap();
        assert_eq!(report.state, VerificationState::Mismatch);
        assert_eq!(report.state.exit_code(), 3);
        assert!(report.reason.is_some());
    }

    #[tokio::test]
    async fn same_role_pair_is_mismatch() {
        let dir = tempdir().unwrap();
        let first = build_full_pair(dir.path(), Endpoint::Memory(8), Endpoint::Memory(108)).await;
        let dir = tempdir().unwrap();
        let second = build_full_pair(dir.path(), Endpoint::Memory(9), Endpoint::Memory(109)).await;
        let report = verify_files(
            &first.controller_path,
            Some(&second.controller_path),
            &NoAnchor,
        )
        .unwrap();
        assert_eq!(report.state, VerificationState::Mismatch);
        assert_eq!(report.reason, Some("the two files have the same role"));
    }

    // -----------------------------------------------------------------
    // Tamper and truncation tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn modified_event_is_tampered() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(10), Endpoint::Memory(110)).await;
        let mut bytes = std::fs::read(&pair.controller_path).unwrap();
        // Flip one byte inside the first record frame payload (after the
        // frame header and the local record envelope).
        let frame_offset = CONTAINER_HEADER_LEN + 4 + 1 + 40;
        bytes[frame_offset] ^= 0x01;
        std::fs::write(&pair.controller_path, &bytes).unwrap();
        let report = verify_files(&pair.controller_path, Some(&pair.host_path), &NoAnchor).unwrap();
        assert_eq!(report.state, VerificationState::Tampered);
        assert_eq!(report.state.exit_code(), 4);
        assert!(report.reason.is_some());
    }

    #[tokio::test]
    async fn modified_footer_digest_is_tampered() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(11), Endpoint::Memory(111)).await;
        let mut bytes = std::fs::read(&pair.controller_path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&pair.controller_path, &bytes).unwrap();
        let report = verify_files(&pair.controller_path, Some(&pair.host_path), &NoAnchor).unwrap();
        assert_eq!(report.state, VerificationState::Tampered);
    }

    #[tokio::test]
    async fn truncated_mid_frame_is_an_interrupted_prefix() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(12), Endpoint::Memory(112)).await;
        let bytes = std::fs::read(&pair.controller_path).unwrap();
        // Cut the controller file inside the first record frame: the prefix
        // stays verifiable and the tail is reported truncated.
        let cut = CONTAINER_HEADER_LEN + 10;
        std::fs::write(&pair.controller_path, &bytes[..cut]).unwrap();
        let report = verify_files(&pair.controller_path, None, &NoAnchor).unwrap();
        assert_eq!(report.state, VerificationState::IntactUnpaired);
        assert!(report.controller.as_ref().unwrap().truncated_tail);
    }

    #[tokio::test]
    async fn interrupted_pair_from_different_sessions_is_mismatch() {
        // Two interrupted sessions paired crosswise: the confirmed
        // checkpoint prefixes cannot match.
        let dir = tempdir().unwrap();
        let first = build_interrupted_pair(dir.path()).await;
        let dir = tempdir().unwrap();
        let second = build_interrupted_pair_with(dir.path(), 0x44).await;
        let report =
            verify_files(&first.controller_path, Some(&second.host_path), &NoAnchor).unwrap();
        assert_eq!(report.state, VerificationState::Mismatch);
    }

    // -----------------------------------------------------------------
    // Ledger continuity tests
    // -----------------------------------------------------------------

    /// The double-session ledger walk needs slightly more than the default
    /// Windows test thread stack; run it on the project's 8 MiB runtime
    /// thread size (the same size `yon` uses for its runtime thread).
    #[test]
    fn older_sessions_anchor_through_the_ledger_chain() {
        let handle = std::thread::Builder::new()
            .name("older-sessions-anchor".to_owned())
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(older_sessions_anchor_through_the_ledger_chain_async());
            })
            .unwrap();
        handle.join().unwrap();
    }

    async fn older_sessions_anchor_through_the_ledger_chain_async() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("audit-root");
        crate::audit::ledger::Ledger::open(&root, &mut OsSecureRandom).unwrap();
        let first = build_full_pair(
            dir.path(),
            Endpoint::Real(root.clone()),
            Endpoint::Memory(13),
        )
        .await;
        let second = build_full_pair(
            dir.path(),
            Endpoint::Real(root.clone()),
            Endpoint::Memory(14),
        )
        .await;
        // The first session's controller commit is two links below the head;
        // the walk reaches it through the second session's commit.
        let report = verify_files(
            &first.controller_path,
            Some(&first.host_path),
            &RootAnchor(root.clone()),
        )
        .unwrap();
        assert_eq!(report.state, VerificationState::VerifiedComplete);
        assert!(report.anchor.ledger_continuous);

        // Deleting the intermediate session breaks the chain: the anchor
        // fails and the pair is reported consistent but unanchored.
        let _ = second;
        let records = first.records.clone();
        for entry in std::fs::read_dir(&records).unwrap() {
            let path = entry.unwrap().path();
            if path != first.controller_path && path != first.host_path {
                std::fs::remove_file(path).unwrap();
            }
        }
        let report = verify_files(
            &first.controller_path,
            Some(&first.host_path),
            &RootAnchor(root),
        )
        .unwrap();
        assert_eq!(
            report.state,
            VerificationState::ConsistentCompleteUnanchored
        );
        assert!(!report.anchor.ledger_continuous);
    }

    #[tokio::test]
    async fn missing_local_identity_skips_anchoring() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(15), Endpoint::Memory(115)).await;
        // An audit root without an identity file provides no anchor.
        let empty = dir.path().join("empty-root");
        std::fs::create_dir_all(&empty).unwrap();
        let report = verify_files(
            &pair.controller_path,
            Some(&pair.host_path),
            &RootAnchor(empty),
        )
        .unwrap();
        assert_eq!(
            report.state,
            VerificationState::ConsistentCompleteUnanchored
        );
        assert!(!report.anchor.identity_matched);
    }

    #[tokio::test]
    async fn corrupted_ledger_state_skips_anchoring() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("audit-root");
        crate::audit::ledger::Ledger::open(&root, &mut OsSecureRandom).unwrap();
        let pair = build_full_pair(
            dir.path(),
            Endpoint::Real(root.clone()),
            Endpoint::Memory(16),
        )
        .await;
        // Corrupt the ledger state checksum: the anchor must fail closed to
        // the unanchored state instead of trusting the file.
        let state = root.join(identity::LEDGER_STATE_FILE_NAME);
        let mut bytes = std::fs::read(&state).unwrap();
        bytes[10] ^= 0xFF;
        std::fs::write(&state, &bytes).unwrap();
        let report = verify_files(
            &pair.controller_path,
            Some(&pair.host_path),
            &RootAnchor(root),
        )
        .unwrap();
        assert_eq!(
            report.state,
            VerificationState::ConsistentCompleteUnanchored
        );
        assert!(!report.anchor.ledger_continuous);
    }

    // -----------------------------------------------------------------
    // Streaming and structural tests
    // -----------------------------------------------------------------

    #[tokio::test]
    async fn non_audit_files_are_format_errors() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("not-an-audit");
        std::fs::write(&path, b"this is not an audit container").unwrap();
        assert!(matches!(
            verify_files(&path, None, &NoAnchor),
            Err(VerifyError::NotAnAuditContainer)
        ));
        let missing = dir.path().join("missing.yonaudit");
        assert!(matches!(
            verify_files(&missing, None, &NoAnchor),
            Err(VerifyError::Io(_))
        ));
    }

    #[tokio::test]
    async fn old_audit_format_is_unsupported_not_tampered() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(88), Endpoint::Memory(188)).await;
        let path = dir.path().join("format-v2.yonaudit");
        let mut bytes = std::fs::read(&pair.controller_path).unwrap();
        bytes[8..10].copy_from_slice(&2_u16.to_be_bytes());
        std::fs::write(&path, bytes).unwrap();

        assert!(matches!(
            verify_files(&path, None, &NoAnchor),
            Err(VerifyError::UnsupportedAuditFormat)
        ));
        assert!(matches!(
            stream_frames(&path, &mut |_, _| Ok(StreamAction::Continue)),
            Err(StreamError::UnsupportedAuditFormat)
        ));
    }

    #[tokio::test]
    async fn unknown_record_types_and_trailing_bytes_are_tampered() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(17), Endpoint::Memory(117)).await;
        // An unknown record type injected after the header.
        let mut bytes = std::fs::read(&pair.controller_path).unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(&1_u32.to_be_bytes());
        frame.push(0x1F); // unknown critical type
        bytes.splice(CONTAINER_HEADER_LEN..CONTAINER_HEADER_LEN, frame);
        std::fs::write(&pair.controller_path, &bytes).unwrap();
        let report = verify_files(&pair.controller_path, None, &NoAnchor).unwrap();
        assert_eq!(report.state, VerificationState::Tampered);

        // Trailing garbage after a valid container.
        let pair = build_full_pair(dir.path(), Endpoint::Memory(18), Endpoint::Memory(118)).await;
        let mut bytes = std::fs::read(&pair.controller_path).unwrap();
        bytes.extend_from_slice(b"garbage");
        std::fs::write(&pair.controller_path, &bytes).unwrap();
        let report = verify_files(&pair.controller_path, None, &NoAnchor).unwrap();
        assert_eq!(report.state, VerificationState::Tampered);
    }

    #[tokio::test]
    async fn known_record_type_with_invalid_length_is_tampered() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(19), Endpoint::Memory(119)).await;
        let mut bytes = std::fs::read(&pair.controller_path).unwrap();
        let mut frame = Vec::new();
        frame.extend_from_slice(&0_u32.to_be_bytes());
        frame.push(RecordType::LocalLifecycleEvent.code());
        bytes.splice(CONTAINER_HEADER_LEN..CONTAINER_HEADER_LEN, frame);
        std::fs::write(&pair.controller_path, &bytes).unwrap();
        let report = verify_files(&pair.controller_path, None, &NoAnchor).unwrap();
        assert_eq!(report.state, VerificationState::Tampered);
    }

    #[tokio::test]
    async fn complete_but_invalid_footer_is_tampered() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(20), Endpoint::Memory(120)).await;
        let mut walker = FrameWalker::open(&pair.controller_path).unwrap();
        walker.skip_header().unwrap();
        while walker.next_frame().unwrap().is_some() {}
        let footer_start = usize::try_from(walker.footer_start().unwrap()).unwrap();
        let mut bytes = std::fs::read(&pair.controller_path).unwrap();
        bytes[footer_start + FOOTER_MAGIC.len()..footer_start + FOOTER_MAGIC.len() + 2]
            .copy_from_slice(&u16::MAX.to_be_bytes());
        std::fs::write(&pair.controller_path, &bytes).unwrap();
        let report = verify_files(&pair.controller_path, None, &NoAnchor).unwrap();
        assert_eq!(report.state, VerificationState::Tampered);
    }

    #[tokio::test]
    async fn stream_frames_delivers_records_and_reports_truncation() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(19), Endpoint::Memory(119)).await;
        let mut types = Vec::new();
        let summary = stream_frames(&pair.controller_path, &mut |record_type, _| {
            types.push(record_type);
            Ok(StreamAction::Continue)
        })
        .unwrap();
        assert!(!summary.truncated_tail);
        assert!(types.contains(&RecordType::LocalDisplayBytes));
        assert!(types.contains(&RecordType::SharedInputCommitment));

        // A truncated file stops at the last complete frame.
        let bytes = std::fs::read(&pair.controller_path).unwrap();
        let cut = bytes.len() / 2;
        let truncated = dir.path().join("truncated.yonaudit");
        std::fs::write(&truncated, &bytes[..cut]).unwrap();
        let mut count = 0;
        let summary = stream_frames(&truncated, &mut |_, _| {
            count += 1;
            Ok(StreamAction::Continue)
        })
        .unwrap();
        assert!(summary.truncated_tail);
        assert!(count > 0);
    }

    #[tokio::test]
    async fn stream_and_peer_reads_propagate_real_io_and_format_failures() {
        let dir = tempdir().unwrap();
        let pair = build_interrupted_pair(dir.path()).await;
        let missing = dir.path().join("missing.yonaudit");
        assert!(matches!(
            stream_frames(&missing, &mut |_, _| Ok(StreamAction::Continue)),
            Err(StreamError::Io(_))
        ));

        let mut delivered = 0;
        let summary = stream_frames(&pair.controller_path, &mut |_, _| {
            delivered += 1;
            Ok(StreamAction::Stop)
        })
        .unwrap();
        assert_eq!(delivered, 1);
        assert!(!summary.truncated_tail);
        assert!(matches!(
            stream_frames(&pair.controller_path, &mut |_, _| {
                Err(StreamError::Tampered("visitor rejected the frame"))
            }),
            Err(StreamError::Tampered("visitor rejected the frame"))
        ));

        let invalid_peer = dir.path().join("invalid-peer.yonaudit");
        fs::write(&invalid_peer, b"not an audit container").unwrap();
        assert!(matches!(
            verify_files(&pair.controller_path, Some(&invalid_peer), &NoAnchor,),
            Err(VerifyError::NotAnAuditContainer)
        ));
    }

    fn walked_pair(pair: &SessionPair) -> (VerifiedFile, VerifiedFile) {
        (
            walk_file(&pair.controller_path).unwrap(),
            walk_file(&pair.host_path).unwrap(),
        )
    }

    fn replace_header(
        file: &VerifiedFile,
        session_id: Option<SessionId>,
        peer_identity: Option<Ed25519PublicKey>,
        peer_session: Option<Ed25519PublicKey>,
        ready: Option<yonder_core::wire::audit::AuditReady>,
    ) -> AuditContainerHeader {
        let header = &file.header;
        AuditContainerHeader::new(
            header.role(),
            session_id.unwrap_or(*header.session_id()),
            *header.identity_pubkey(),
            *header.session_pubkey(),
            peer_identity.unwrap_or(*header.peer_identity_pubkey()),
            peer_session.unwrap_or(*header.peer_session_pubkey()),
            header.ledger_sequence(),
            *header.previous_ledger_root(),
            header.utc_start_seconds(),
            header.auth_mode(),
            *header.terminal_hello_digest(),
            *header.audit_hello(),
            ready.unwrap_or(*header.audit_ready()),
        )
        .with_header_signature(*header.header_signature())
    }

    fn hello_with_binding(hello: &AuditHello, binding: BindingDigest) -> AuditHello {
        AuditHello::new(
            hello.role(),
            *hello.persistent_audit_key(),
            *hello.session_key(),
            *hello.nonce(),
            hello.ledger_sequence(),
            *hello.ledger_root(),
            binding,
            hello.format_version(),
            *hello.input_commitment(),
            *hello.signature(),
        )
    }

    #[test]
    fn verification_state_names_and_walk_errors_are_stable() {
        let states = [
            (VerificationState::VerifiedComplete, "VERIFIED_COMPLETE", 0),
            (
                VerificationState::ConsistentCompleteUnanchored,
                "CONSISTENT_COMPLETE_UNANCHORED",
                2,
            ),
            (
                VerificationState::MatchedInterruptedPrefix,
                "MATCHED_INTERRUPTED_PREFIX",
                2,
            ),
            (VerificationState::IntactUnpaired, "INTACT_UNPAIRED", 2),
            (VerificationState::Mismatch, "MISMATCH", 3),
            (VerificationState::Tampered, "TAMPERED", 4),
        ];
        for (state, name, exit_code) in states {
            assert_eq!(state.name(), name);
            assert_eq!(state.exit_code(), exit_code);
        }

        let report = map_walk_error(StreamError::Tampered("changed")).unwrap();
        assert_eq!(report.state, VerificationState::Tampered);
        assert_eq!(report.reason, Some("changed"));
        assert!(matches!(
            map_walk_error(StreamError::NotAnAuditContainer),
            Err(VerifyError::NotAnAuditContainer)
        ));
        assert!(matches!(
            map_walk_error(StreamError::UnsupportedAuditFormat),
            Err(VerifyError::UnsupportedAuditFormat)
        ));
        assert!(matches!(
            map_walk_error(StreamError::Io(io::Error::other("read failed"))),
            Err(VerifyError::Io(_))
        ));
    }

    #[tokio::test]
    async fn pair_decision_rejects_each_header_and_handshake_mismatch() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(20), Endpoint::Memory(120)).await;

        let (mut controller, host) = walked_pair(&pair);
        controller.header = replace_header(
            &controller,
            Some(SessionId::new([0xA1; DIGEST_LEN])),
            None,
            None,
            None,
        );
        let report = verify_walk_pair(controller, host, &NoAnchor).unwrap();
        assert_eq!(report.reason, Some("the session IDs do not match"));

        let (mut controller, host) = walked_pair(&pair);
        controller.header = replace_header(
            &controller,
            None,
            Some(Ed25519PublicKey::new([0xA2; DIGEST_LEN])),
            None,
            None,
        );
        let report = verify_walk_pair(controller, host, &NoAnchor).unwrap();
        assert_eq!(report.reason, Some("the embedded identities do not match"));

        let (mut controller, host) = walked_pair(&pair);
        controller.header = replace_header(
            &controller,
            None,
            None,
            Some(Ed25519PublicKey::new([0xA3; DIGEST_LEN])),
            None,
        );
        let report = verify_walk_pair(controller, host, &NoAnchor).unwrap();
        assert_eq!(
            report.reason,
            Some("the embedded session keys do not match")
        );

        let (mut controller, host) = walked_pair(&pair);
        controller.hello = hello_with_binding(&controller.hello, BindingDigest::new([0xA4; 32]));
        let report = verify_walk_pair(controller, host, &NoAnchor).unwrap();
        assert_eq!(report.reason, Some("the connection binding does not match"));

        for mutate_controller in [true, false] {
            let (mut controller, mut host) = walked_pair(&pair);
            let file = if mutate_controller {
                &mut controller
            } else {
                &mut host
            };
            let old = *file.header.audit_ready();
            let ready = yonder_core::wire::audit::AuditReady::new(
                *old.session_id(),
                Digest32::new([0xA5; DIGEST_LEN]),
                old.format_version(),
                *old.signature(),
            );
            file.header = replace_header(file, None, None, None, Some(ready));
            let report = verify_walk_pair(controller, host, &NoAnchor).unwrap();
            assert_eq!(
                report.reason,
                Some("the audit handshake confirmations do not match")
            );
        }
    }

    #[tokio::test]
    async fn pair_decision_rejects_each_footer_mismatch() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(21), Endpoint::Memory(121)).await;

        let (controller, mut host) = walked_pair(&pair);
        host.footer.as_mut().unwrap().manifest_bytes[0] ^= 1;
        let report = verify_walk_pair(controller, host, &NoAnchor).unwrap();
        assert_eq!(report.reason, Some("the joint manifests differ"));

        let (mut controller, mut host) = walked_pair(&pair);
        controller.footer.as_mut().unwrap().manifest_bytes = vec![0];
        host.footer.as_mut().unwrap().manifest_bytes = vec![0];
        let report = verify_walk_pair(controller, host, &NoAnchor).unwrap();
        assert_eq!(report.state, VerificationState::Tampered);
        assert_eq!(report.reason, Some("the joint manifest is invalid"));

        let (mut controller, mut host) = walked_pair(&pair);
        controller.footer.as_mut().unwrap().manifest_bytes[34] ^= 1;
        host.footer.as_mut().unwrap().manifest_bytes[34] ^= 1;
        let report = verify_walk_pair(controller, host, &NoAnchor).unwrap();
        assert_eq!(
            report.reason,
            Some("the embedded identities do not match the joint manifest")
        );

        let (controller, mut host) = walked_pair(&pair);
        host.footer.as_mut().unwrap().host_signature = ManifestSignature::new(
            Ed25519Signature::new([0xA6; yonder_core::wire::audit::ED25519_SIGNATURE_LEN]),
        );
        let report = verify_walk_pair(controller, host, &NoAnchor).unwrap();
        assert_eq!(report.reason, Some("the manifest signatures differ"));

        let (mut controller, host) = walked_pair(&pair);
        let footer = controller.footer.as_mut().unwrap();
        let commit = footer.commit;
        footer.commit = yonder_core::wire::audit::LedgerCommit::new(
            commit.sequence(),
            *commit.previous_root(),
            *commit.session_id(),
            *commit.manifest_digest(),
            *commit.sealed_record_digest(),
            IdentityFingerprint::new([0xA7; DIGEST_LEN]),
            commit.result(),
            *commit.signature(),
        );
        let report = verify_walk_pair(controller, host, &NoAnchor).unwrap();
        assert_eq!(
            report.reason,
            Some("the ledger commits do not match the peer identities")
        );
    }

    #[tokio::test]
    async fn interrupted_pair_decision_checks_manifest_evidence_and_signature_slots() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(22), Endpoint::Memory(122)).await;
        let bad_signature = ManifestSignature::new(Ed25519Signature::new(
            [0xA8; yonder_core::wire::audit::ED25519_SIGNATURE_LEN],
        ));

        let (controller, mut host) = walked_pair(&pair);
        host.footer = None;
        let report = verify_walk_pair(controller, host, &NoAnchor).unwrap();
        assert_eq!(report.state, VerificationState::MatchedInterruptedPrefix);

        let (controller, mut host) = walked_pair(&pair);
        host.footer = None;
        host.manifest_evidence = Some(vec![0]);
        let report = verify_walk_pair(controller, host, &NoAnchor).unwrap();
        assert_eq!(report.reason, Some("the joint manifests differ"));

        let (controller, mut host) = walked_pair(&pair);
        host.footer = None;
        host.sent_manifest_signature = Some(bad_signature);
        let report = verify_walk_pair(controller, host, &NoAnchor).unwrap();
        assert_eq!(report.reason, Some("the manifest signatures differ"));

        let (controller, mut host) = walked_pair(&pair);
        host.footer = None;
        host.received_manifest_signature = Some(bad_signature);
        let report = verify_walk_pair(controller, host, &NoAnchor).unwrap();
        assert_eq!(report.reason, Some("the manifest signatures differ"));

        let (mut controller, host) = walked_pair(&pair);
        controller.footer = None;
        controller.sent_manifest_signature = Some(bad_signature);
        let report = verify_walk_pair(controller, host, &NoAnchor).unwrap();
        assert_eq!(report.reason, Some("the manifest signatures differ"));

        let (mut controller, host) = walked_pair(&pair);
        controller.footer = None;
        controller.received_manifest_signature = Some(bad_signature);
        let report = verify_walk_pair(controller, host, &NoAnchor).unwrap();
        assert_eq!(report.reason, Some("the manifest signatures differ"));
    }

    #[tokio::test]
    async fn common_checkpoint_selection_accepts_only_the_bilateral_prefix() {
        let dir = tempdir().unwrap();
        let pair = build_interrupted_pair(dir.path()).await;
        let (mut controller, mut host) = walked_pair(&pair);
        let confirmed = controller.last_confirmed_sent.unwrap();
        assert!(snapshot_is_prefix(&controller.path, confirmed.snapshot).unwrap());
        assert!(snapshot_is_prefix(&host.path, confirmed.snapshot).unwrap());
        let mut wrong_streams = confirmed.snapshot.streams();
        wrong_streams[0] =
            StreamSnapshot::new(wrong_streams[0].count(), ChainHead::new([0xB0; DIGEST_LEN]));
        assert!(!snapshot_is_prefix(&host.path, SharedSnapshot::new(wrong_streams)).unwrap());

        controller.last_confirmed_sent = None;
        host.last_confirmed_received = None;
        assert_eq!(last_common_confirmed(&controller, &host), Ok([None, None]));

        controller.last_confirmed_sent = Some(confirmed);
        assert_eq!(last_common_confirmed(&controller, &host), Ok([None, None]));
        host.last_confirmed_received = Some(Confirmed {
            sequence: confirmed.sequence,
            digest: [0xB1; DIGEST_LEN],
            snapshot: confirmed.snapshot,
        });
        assert!(last_common_confirmed(&controller, &host).is_err());

        host.last_confirmed_received = Some(confirmed);
        assert_eq!(
            last_common_confirmed(&controller, &host),
            Ok([Some(confirmed), None])
        );

        controller.prev_confirmed_sent = Some(confirmed);
        controller.last_confirmed_sent = Some(Confirmed {
            sequence: confirmed.sequence + 1,
            digest: [0xB2; DIGEST_LEN],
            snapshot: confirmed.snapshot,
        });
        assert_eq!(
            last_common_confirmed(&controller, &host),
            Ok([Some(confirmed), None])
        );
        controller.prev_confirmed_sent = None;
        assert!(last_common_confirmed(&controller, &host).is_err());

        controller.last_confirmed_sent = Some(confirmed);
        host.prev_confirmed_received = Some(confirmed);
        host.last_confirmed_received = Some(Confirmed {
            sequence: confirmed.sequence + 1,
            digest: [0xB3; DIGEST_LEN],
            snapshot: confirmed.snapshot,
        });
        assert_eq!(
            last_common_confirmed(&controller, &host),
            Ok([Some(confirmed), None])
        );
        host.prev_confirmed_received = None;
        assert!(last_common_confirmed(&controller, &host).is_err());
    }

    #[tokio::test]
    async fn interrupted_pair_rechecks_confirmed_prefixes_fail_closed() {
        let dir = tempdir().unwrap();
        let pair = build_interrupted_pair(dir.path()).await;
        let (controller, mut host) = walked_pair(&pair);
        let confirmed = controller.last_confirmed_sent.unwrap();
        host.last_confirmed_received = Some(Confirmed {
            digest: [0xB4; DIGEST_LEN],
            ..confirmed
        });
        let report = verify_walk_pair(controller, host, &NoAnchor).unwrap();
        assert_eq!(report.state, VerificationState::Mismatch);
        assert_eq!(
            report.reason,
            Some("the directional checkpoint confirmations do not match")
        );

        let (mut controller, mut host) = walked_pair(&pair);
        controller.last_confirmed_sent = None;
        host.last_confirmed_received = None;
        host.last_confirmed_sent = Some(confirmed);
        controller.last_confirmed_received = Some(Confirmed {
            digest: [0xB5; DIGEST_LEN],
            ..confirmed
        });
        let report = verify_walk_pair(controller, host, &NoAnchor).unwrap();
        assert_eq!(report.state, VerificationState::Mismatch);
        assert_eq!(
            report.reason,
            Some("the directional checkpoint confirmations do not match")
        );

        let (mut controller, mut host) = walked_pair(&pair);
        let mut streams = confirmed.snapshot.streams();
        let stream = streams
            .iter_mut()
            .find(|snapshot| snapshot.count() != 0)
            .expect("the fixture confirms at least one non-empty stream");
        *stream = StreamSnapshot::new(stream.count(), ChainHead::new([0xB6; DIGEST_LEN]));
        let divergent = Confirmed {
            snapshot: SharedSnapshot::new(streams),
            ..confirmed
        };
        controller.last_confirmed_sent = Some(divergent);
        host.last_confirmed_received = Some(divergent);
        let report = verify_walk_pair(controller, host, &NoAnchor).unwrap();
        assert_eq!(report.state, VerificationState::Mismatch);
        assert_eq!(
            report.reason,
            Some("the confirmed checkpoint is not a shared prefix")
        );

        let (controller, host) = walked_pair(&pair);
        let mut bytes = fs::read(&pair.controller_path).unwrap();
        bytes[CONTAINER_HEADER_LEN + RECORD_FRAME_HEADER_LEN + SPLIT_PREFIX_LEN] ^= 1;
        fs::write(&pair.controller_path, bytes).unwrap();
        let report = verify_walk_pair(controller, host, &NoAnchor).unwrap();
        assert_eq!(report.state, VerificationState::Tampered);

        let dir = tempdir().unwrap();
        let pair = build_interrupted_pair(dir.path()).await;
        let (controller, host) = walked_pair(&pair);
        fs::remove_file(&pair.controller_path).unwrap();
        assert!(matches!(
            verify_walk_pair(controller, host, &NoAnchor),
            Err(VerifyError::Io(_))
        ));

        let dir = tempdir().unwrap();
        let pair = build_interrupted_pair(dir.path()).await;
        let (controller, host) = walked_pair(&pair);
        fs::write(&pair.controller_path, b"replaced after the initial walk").unwrap();
        assert!(matches!(
            verify_walk_pair(controller, host, &NoAnchor),
            Err(VerifyError::NotAnAuditContainer)
        ));
    }

    fn first_payload(path: &Path, wanted: RecordType) -> Vec<u8> {
        let mut found = None;
        stream_frames(path, &mut |record_type, payload| {
            if record_type == wanted && found.is_none() {
                found = Some(payload.to_vec());
            }
            Ok(StreamAction::Continue)
        })
        .unwrap();
        found.expect("the complete fixture contains the requested record")
    }

    fn assert_tampered(result: Result<(), StreamError>) {
        assert!(matches!(result, Err(StreamError::Tampered(_))));
    }

    fn session_signing_key(counter: u8) -> DalekSigningKey {
        let mut seed = [0_u8; 32];
        for (offset, byte) in seed.iter_mut().enumerate() {
            *byte = counter
                .wrapping_add(64)
                .wrapping_add(u8::try_from(offset).unwrap());
        }
        DalekSigningKey::from_bytes(&seed)
    }

    fn checkpoint_evidence(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut evidence = Vec::with_capacity(5 + payload.len());
        evidence.push(kind);
        evidence.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        evidence.extend_from_slice(payload);
        evidence
    }

    fn signed_checkpoint(
        signer: u8,
        session_id: SessionId,
        sequence: u64,
        snapshot: SharedSnapshot,
        local_chain_head: ChainHead,
        ledger_snapshot_digest: Digest32,
    ) -> Checkpoint {
        let checkpoint = Checkpoint::new(
            session_id,
            sequence,
            snapshot,
            local_chain_head,
            ledger_snapshot_digest,
            Ed25519Signature::new([0; yonder_core::wire::audit::ED25519_SIGNATURE_LEN]),
        );
        checkpoint.with_signature(Ed25519Signature::new(
            session_signing_key(signer)
                .sign(checkpoint.signing_input().as_slice())
                .to_bytes(),
        ))
    }

    fn signed_checkpoint_ack(
        signer: u8,
        session_id: SessionId,
        sequence: u64,
        checkpoint_digest: Digest32,
        snapshot: SharedSnapshot,
    ) -> CheckpointAck {
        let ack = CheckpointAck::new(
            session_id,
            sequence,
            checkpoint_digest,
            snapshot,
            Ed25519Signature::new([0; yonder_core::wire::audit::ED25519_SIGNATURE_LEN]),
        );
        ack.with_signature(Ed25519Signature::new(
            session_signing_key(signer)
                .sign(ack.signing_input().as_slice())
                .to_bytes(),
        ))
    }

    fn ledger_snapshot_digest(verifier: &ChainVerifier) -> Digest32 {
        let mut bytes = [0_u8; 8 + DIGEST_LEN];
        bytes[..8].copy_from_slice(&verifier.header.ledger_sequence().to_be_bytes());
        bytes[8..].copy_from_slice(verifier.header.previous_ledger_root().as_bytes());
        Digest32::new(sha256_32(&bytes))
    }

    #[tokio::test]
    async fn header_binding_checks_reject_each_independent_signature_boundary() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(23), Endpoint::Memory(123)).await;
        let walked = walk_file(&pair.controller_path).unwrap();
        assert!(check_header_bindings(&walked.header, &walked.hello).is_ok());

        let mismatched_hello = hello_with_binding(&walked.hello, BindingDigest::new([0xC1; 32]));
        assert_tampered(check_header_bindings(&walked.header, &mismatched_hello));

        let hello = walked.hello;
        let mismatched_hello = AuditHello::new(
            WireRole::Host,
            *hello.persistent_audit_key(),
            *hello.session_key(),
            *hello.nonce(),
            hello.ledger_sequence(),
            *hello.ledger_root(),
            *hello.connection_binding(),
            hello.format_version(),
            *hello.input_commitment(),
            *hello.signature(),
        );
        assert_tampered(check_header_bindings(&walked.header, &mismatched_hello));

        let ready = yonder_core::wire::audit::AuditReady::new(
            SessionId::new([0xC2; 32]),
            *walked.header.audit_ready().peer_audit_hello_digest(),
            walked.header.audit_ready().format_version(),
            *walked.header.audit_ready().signature(),
        );
        let header = replace_header(&walked, None, None, None, Some(ready));
        assert_tampered(check_header_bindings(&header, header.audit_hello()));

        let old = walked.header.audit_ready();
        let ready = yonder_core::wire::audit::AuditReady::new(
            *old.session_id(),
            *old.peer_audit_hello_digest(),
            old.format_version(),
            Ed25519Signature::new([0xC3; yonder_core::wire::audit::ED25519_SIGNATURE_LEN]),
        );
        let header = replace_header(&walked, None, None, None, Some(ready));
        assert_tampered(check_header_bindings(&header, header.audit_hello()));

        let header = replace_header(&walked, None, None, None, None).with_header_signature(
            Ed25519Signature::new([0xC4; yonder_core::wire::audit::ED25519_SIGNATURE_LEN]),
        );
        assert_tampered(check_header_bindings(&header, header.audit_hello()));
    }

    #[tokio::test]
    async fn chain_verifier_rejects_corruption_in_every_shared_stream() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(24), Endpoint::Memory(124)).await;
        let walked = walk_file(&pair.controller_path).unwrap();
        let make = || ChainVerifier::new(walked.header, walked.hello);

        for record_type in [
            RecordType::SharedInputCommitment,
            RecordType::SharedOutputBlock,
        ] {
            let original = first_payload(&pair.controller_path, record_type);
            let mut payload = original.clone();
            payload[0] = 0;
            assert_tampered(make().process_frame(record_type, &payload));

            let mut payload = original.clone();
            payload[8] ^= 1;
            assert_tampered(make().process_frame(record_type, &payload));

            let mut payload = original.clone();
            payload[49] ^= 1;
            assert_tampered(make().process_frame(record_type, &payload));

            let mut payload = original;
            payload[81] ^= 1;
            assert_tampered(make().process_frame(record_type, &payload));
        }

        let original = first_payload(&pair.controller_path, RecordType::SharedControlEvent);
        let mut payload = original.clone();
        payload[0] = 0;
        assert_tampered(make().process_frame(RecordType::SharedControlEvent, &payload));
        let mut payload = original.clone();
        payload[8] ^= 1;
        assert_tampered(make().process_frame(RecordType::SharedControlEvent, &payload));
        let mut payload = original.clone();
        payload[9] = 0xFF;
        assert_tampered(make().process_frame(RecordType::SharedControlEvent, &payload));
        let mut payload = original;
        let last = payload.len() - 1;
        payload[last] ^= 1;
        assert_tampered(make().process_frame(RecordType::SharedControlEvent, &payload));

        let mut file = Vec::new();
        file.push(0);
        file.extend_from_slice(&1_u64.to_be_bytes());
        file.push(FILE_KIND_SUCCESS);
        file.extend_from_slice(&7_u64.to_be_bytes());
        file.extend_from_slice(&8_u64.to_be_bytes());
        file.extend_from_slice(&8_u64.to_be_bytes());
        file.extend_from_slice(&[0xD1; DIGEST_LEN]);
        file.extend_from_slice(&1_u16.to_be_bytes());
        file.extend_from_slice(b"r");
        file.extend_from_slice(&1_u16.to_be_bytes());
        file.extend_from_slice(b"f");
        file.extend_from_slice(&0_u16.to_be_bytes());
        file.extend_from_slice(&[0; 2 * DIGEST_LEN]);
        assert_tampered(make().process_frame(RecordType::SharedFileTransferEvent, &file));
        file[0] = DIRECTION_CTRL_TO_HOST;
        file[9] = 0xFF;
        assert_tampered(make().process_frame(RecordType::SharedFileTransferEvent, &file));
        file[9] = FILE_LOCAL_KIND_COMMITTED_UNCONFIRMED;
        assert_tampered(make().process_frame(RecordType::SharedFileTransferEvent, &file));
        file[9] = FILE_LOCAL_KIND_COMMIT_STATUS_UNKNOWN;
        assert_tampered(make().process_frame(RecordType::SharedFileTransferEvent, &file));
        file[9] = FILE_KIND_SUCCESS;
        file[8] = 2;
        assert_tampered(make().process_frame(RecordType::SharedFileTransferEvent, &file));
        file[8] = 1;
        let last = file.len() - 1;
        file[last] ^= 1;
        assert_tampered(make().process_frame(RecordType::SharedFileTransferEvent, &file));
    }

    #[tokio::test]
    async fn chain_verifier_strictly_correlates_local_file_observations() {
        fn payload(record: &crate::audit::session::EncodedRecord<'_>) -> Vec<u8> {
            match &record.payload {
                Payload::Inline { bytes, len } => bytes[..*len].to_vec(),
                Payload::Boxed(bytes) => bytes.to_vec(),
                Payload::Split { prefix, body } => [prefix.as_slice(), body].concat(),
            }
        }

        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(64), Endpoint::Memory(164)).await;
        let walked = walk_file(&pair.controller_path).unwrap();
        let make = || ChainVerifier::new(walked.header, walked.hello);

        let binding = BindingDigest::new([0x42; DIGEST_LEN]);
        let mut controller = open_endpoint(Endpoint::Memory(65), WireRole::Controller, binding);
        let mut host = open_endpoint(Endpoint::Memory(165), WireRole::Host, binding);
        let (ready_c, ready_h) = handshake_until_readies(&mut controller, &mut host);
        controller.receive_peer_ready(&ready_h).unwrap();
        host.receive_peer_ready(&ready_c).unwrap();

        let start = FileTransferFacts {
            transfer_id: 73,
            direction: FILE_DIRECTION_UPLOAD,
            kind: FILE_KIND_START,
            declared_size: 4096,
            final_size: 0,
            digest: Digest32::new([0; DIGEST_LEN]),
            remote_path: "remote/final.bin",
            file_name: "source.bin",
            error_code: 0,
        };
        let start_batch = controller
            .record_file_transfer(&start, Some("local/source.bin"), 1)
            .unwrap();
        let start_shared = payload(start_batch.iter().next().unwrap());
        let start_local = payload(start_batch.iter().nth(1).unwrap());
        let ambiguity_batch = controller
            .record_local_file_transfer_result(
                FILE_LOCAL_KIND_COMMIT_STATUS_UNKNOWN,
                73,
                4096,
                Digest32::new([0xA7; DIGEST_LEN]),
                None,
                2,
            )
            .unwrap();
        let ambiguity = payload(ambiguity_batch.iter().next().unwrap());

        let initialize = || {
            let mut verifier = make();
            verifier
                .process_frame(RecordType::SharedFileTransferEvent, &start_shared)
                .unwrap();
            verifier
                .process_frame(RecordType::LocalFileTransferEvent, &start_local)
                .unwrap();
            verifier
        };

        let mut verifier = initialize();
        verifier
            .process_frame(RecordType::LocalFileTransferEvent, &ambiguity)
            .unwrap();
        assert_tampered(verifier.process_frame(RecordType::LocalFileTransferEvent, &ambiguity));

        let mut wrong_id = ambiguity.clone();
        wrong_id[SPLIT_PREFIX_LEN + 8] ^= 1;
        assert_tampered(initialize().process_frame(RecordType::LocalFileTransferEvent, &wrong_id));

        let mut wrong_role = ambiguity.clone();
        wrong_role[SPLIT_PREFIX_LEN] = FILE_LOCAL_KIND_COMMITTED_UNCONFIRMED;
        assert_tampered(
            initialize().process_frame(RecordType::LocalFileTransferEvent, &wrong_role),
        );

        let mut nonzero_path = ambiguity.clone();
        nonzero_path[SPLIT_PREFIX_LEN + 49..SPLIT_PREFIX_LEN + 51]
            .copy_from_slice(&1_u16.to_be_bytes());
        nonzero_path.push(b'x');
        assert_tampered(
            initialize().process_frame(RecordType::LocalFileTransferEvent, &nonzero_path),
        );

        let mut wrong_path_id = start_local.clone();
        wrong_path_id[SPLIT_PREFIX_LEN + 8] ^= 1;
        let mut verifier = make();
        verifier
            .process_frame(RecordType::SharedFileTransferEvent, &start_shared)
            .unwrap();
        assert_tampered(verifier.process_frame(RecordType::LocalFileTransferEvent, &wrong_path_id));
        let mut verifier = make();
        verifier
            .process_frame(RecordType::SharedFileTransferEvent, &start_shared)
            .unwrap();
        verifier
            .process_frame(RecordType::LocalFileTransferEvent, &start_local)
            .unwrap();
        assert_tampered(verifier.process_frame(RecordType::LocalFileTransferEvent, &start_local));

        let mut invalid_utf8_path = start_local.clone();
        invalid_utf8_path[SPLIT_PREFIX_LEN + 11] = 0xFF;
        let mut verifier = make();
        verifier
            .process_frame(RecordType::SharedFileTransferEvent, &start_shared)
            .unwrap();
        assert_tampered(
            verifier.process_frame(RecordType::LocalFileTransferEvent, &invalid_utf8_path),
        );

        let mut unknown_local_kind = start_local.clone();
        unknown_local_kind[SPLIT_PREFIX_LEN] = 0xFF;
        let mut verifier = make();
        verifier
            .process_frame(RecordType::SharedFileTransferEvent, &start_shared)
            .unwrap();
        assert_tampered(
            verifier.process_frame(RecordType::LocalFileTransferEvent, &unknown_local_kind),
        );

        let terminal = FileTransferFacts {
            kind: FILE_KIND_SUCCESS,
            final_size: 4096,
            digest: Digest32::new([0xA7; DIGEST_LEN]),
            ..start
        };
        let terminal_batch = controller.record_file_transfer(&terminal, None, 3).unwrap();
        let terminal_shared = payload(terminal_batch.iter().next().unwrap());
        let mut verifier = initialize();
        verifier
            .process_frame(RecordType::SharedFileTransferEvent, &terminal_shared)
            .unwrap();
        assert_tampered(verifier.process_frame(RecordType::LocalFileTransferEvent, &ambiguity));
    }

    #[tokio::test]
    async fn chain_verifier_rejects_each_local_envelope_and_batch_mismatch() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(25), Endpoint::Memory(125)).await;
        let walked = walk_file(&pair.controller_path).unwrap();
        let make = || ChainVerifier::new(walked.header, walked.hello);

        assert_tampered(make().process_frame(RecordType::LocalDisplayBytes, &[0; 39]));
        let mut display = vec![0; SPLIT_PREFIX_LEN];
        display[8] = 1;
        assert_tampered(make().process_frame(RecordType::LocalDisplayBytes, &display));

        for record_type in [
            RecordType::LocalInputCommitment,
            RecordType::LocalSendOutcome,
            RecordType::LocalPtyWriteOutcome,
            RecordType::LocalDisplayWriteOutcome,
            RecordType::LocalResizeEvent,
            RecordType::LocalLifecycleEvent,
            RecordType::LocalKeyAction,
            RecordType::LocalConnectionState,
            RecordType::LocalAuditError,
            RecordType::LocalFileTransferEvent,
            RecordType::LocalCloseEvent,
            RecordType::CheckpointEvidence,
        ] {
            assert_tampered(make().process_frame(record_type, &[0; SPLIT_PREFIX_LEN]));
        }
        assert_tampered(
            make().process_local(RecordType::LocalKeyAction, &[0; SPLIT_PREFIX_LEN - 1]),
        );

        let mut send = vec![0; SPLIT_PREFIX_LEN + 10];
        send[SPLIT_PREFIX_LEN] = DIRECTION_CTRL_TO_HOST;
        send[8] = 1;
        assert_tampered(make().process_frame(RecordType::LocalSendOutcome, &send));
        send[SPLIT_PREFIX_LEN] = DIRECTION_HOST_TO_CTRL;
        assert_tampered(make().process_frame(RecordType::LocalSendOutcome, &send));

        let mut pty = vec![0; SPLIT_PREFIX_LEN + 9];
        pty[8] = 1;
        assert_tampered(make().process_frame(RecordType::LocalPtyWriteOutcome, &pty));
        assert_tampered(make().process_frame(RecordType::LocalDisplayWriteOutcome, &pty));

        let mut resize = vec![0; SPLIT_PREFIX_LEN + 5];
        resize[SPLIT_PREFIX_LEN] = DIRECTION_CTRL_TO_HOST;
        resize[8] = 1;
        assert_tampered(make().process_frame(RecordType::LocalResizeEvent, &resize));

        for record_type in [
            RecordType::LocalLifecycleEvent,
            RecordType::LocalKeyAction,
            RecordType::LocalConnectionState,
        ] {
            let mut payload = vec![0; SPLIT_PREFIX_LEN + 1];
            payload[8] = 1;
            payload[SPLIT_PREFIX_LEN] = 1;
            assert_tampered(make().process_frame(record_type, &payload));
        }
        let mut audit_error = vec![0; SPLIT_PREFIX_LEN + 2];
        audit_error[8] = 1;
        assert_tampered(make().process_frame(RecordType::LocalAuditError, &audit_error));
        let mut local_file = vec![0; SPLIT_PREFIX_LEN + 12];
        local_file[SPLIT_PREFIX_LEN + 9..SPLIT_PREFIX_LEN + 11]
            .copy_from_slice(&1_u16.to_be_bytes());
        local_file[SPLIT_PREFIX_LEN + 11] = 0xFF;
        assert_tampered(make().process_frame(RecordType::LocalFileTransferEvent, &local_file));
        let mut close = vec![0; SPLIT_PREFIX_LEN + 2];
        close[8] = 1;
        assert_tampered(make().process_frame(RecordType::LocalCloseEvent, &close));
        let mut evidence = vec![0; SPLIT_PREFIX_LEN + 5];
        evidence[8] = 1;
        assert_tampered(make().process_frame(RecordType::CheckpointEvidence, &evidence));
        for record_type in [
            RecordType::SharedInputCommitment,
            RecordType::SharedOutputBlock,
            RecordType::SharedControlEvent,
            RecordType::SharedFileTransferEvent,
        ] {
            assert_tampered(make().process_local(record_type, &[0; SPLIT_PREFIX_LEN]));
        }

        let mut verifier = make();
        verifier.input_batch = Some(BatchState {
            related: ChainHead::new([1; DIGEST_LEN]),
            saw_block: false,
        });
        assert_tampered(verifier.flush_input_batch());
        let mut verifier = make();
        verifier.output_batch = Some(BatchState {
            related: ChainHead::new([2; DIGEST_LEN]),
            saw_block: true,
        });
        assert_tampered(verifier.flush_output_batch());
        let mut verifier = make();
        verifier.input_batch = Some(BatchState {
            related: ChainHead::new([3; DIGEST_LEN]),
            saw_block: true,
        });
        assert_tampered(verifier.flush_input_batch());
        let mut verifier = make();
        verifier.output_batch = Some(BatchState {
            related: ChainHead::new([4; DIGEST_LEN]),
            saw_block: false,
        });
        assert_tampered(verifier.flush_output_batch());

        let mut verifier = make();
        assert_tampered(verifier.process_evidence(&[]));
        assert_tampered(verifier.process_evidence(&[EVIDENCE_SENT_CHECKPOINT, 0, 0, 0, 1]));
        assert_tampered(verifier.process_evidence(&[0xFF, 0, 0, 0, 0]));
        assert_tampered(
            verifier.process_evidence(&checkpoint_evidence(EVIDENCE_SENT_CHECKPOINT_ACK, &[0])),
        );
        assert_tampered(
            verifier.process_evidence(&checkpoint_evidence(EVIDENCE_SENT_MANIFEST, &[0])),
        );
        assert_tampered(
            verifier.process_evidence(&checkpoint_evidence(EVIDENCE_SENT_MANIFEST_SIGNATURE, &[0])),
        );
        let manifest = walked.footer.as_ref().unwrap().manifest_bytes.as_slice();
        assert_tampered(
            make().process_evidence(&checkpoint_evidence(EVIDENCE_SENT_MANIFEST, manifest)),
        );

        let snapshot = SharedSnapshot::new([StreamSnapshot::new(0, zero_head()); SHARED_STREAMS]);
        let reference = |sequence, digest| CheckpointRef {
            sequence,
            digest: [digest; DIGEST_LEN],
            snapshot,
        };
        let mut verifier = make();
        verifier.confirm_sent(reference(1, 1)).unwrap();
        verifier.confirm_sent(reference(1, 1)).unwrap();
        assert_tampered(verifier.confirm_sent(reference(1, 2)));
        verifier.confirm_sent(reference(2, 3)).unwrap();
        assert_tampered(verifier.confirm_sent(reference(1, 1)));

        for (kind, len, expected) in [
            (CONTROL_KIND_RESIZE, 4, true),
            (CONTROL_KIND_TERMINAL_HELLO, DIGEST_LEN, true),
            (CONTROL_KIND_TERMINAL_READY, 0, true),
            (CONTROL_KIND_TERMINAL_COMPLETE, 0, true),
            (CONTROL_KIND_TERMINAL_EXIT, 4, true),
            (CONTROL_KIND_CLOSE_REASON, 1, true),
            (0xFF, 0, false),
            (CONTROL_KIND_RESIZE, 3, false),
        ] {
            assert_eq!(control_kind_payload_len(kind, len), expected);
        }
    }

    #[tokio::test]
    async fn checkpoint_verifier_rejects_every_signed_binding_mismatch() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(27), Endpoint::Memory(127)).await;
        let walked = walk_file(&pair.controller_path).unwrap();
        let header = walked.header;
        let hello = walked.hello;
        let fresh = || ChainVerifier::new(header, hello);
        let verifier = fresh();
        let session_id = *verifier.header.session_id();
        let snapshot = verifier.shared_snapshot();
        let local_head = verifier.local_head;
        let ledger_digest = ledger_snapshot_digest(&verifier);

        let valid = signed_checkpoint(27, session_id, 1, snapshot, local_head, ledger_digest);
        let mut accepted = fresh();
        accepted
            .process_evidence(&checkpoint_evidence(
                EVIDENCE_SENT_CHECKPOINT,
                valid.encode_payload().as_slice(),
            ))
            .unwrap();

        let invalid_signature = Checkpoint::new(
            session_id,
            1,
            snapshot,
            local_head,
            ledger_digest,
            Ed25519Signature::new([0; yonder_core::wire::audit::ED25519_SIGNATURE_LEN]),
        );
        assert_tampered(fresh().process_evidence(&checkpoint_evidence(
            EVIDENCE_SENT_CHECKPOINT,
            invalid_signature.encode_payload().as_slice(),
        )));

        let mut different_streams = [StreamSnapshot::new(0, zero_head()); SHARED_STREAMS];
        different_streams[0] = StreamSnapshot::new(1, ChainHead::new([0x71; DIGEST_LEN]));
        for checkpoint in [
            signed_checkpoint(
                27,
                SessionId::new([0x72; DIGEST_LEN]),
                1,
                snapshot,
                local_head,
                ledger_digest,
            ),
            signed_checkpoint(27, session_id, 2, snapshot, local_head, ledger_digest),
            signed_checkpoint(
                27,
                session_id,
                1,
                SharedSnapshot::new(different_streams),
                local_head,
                ledger_digest,
            ),
            signed_checkpoint(
                27,
                session_id,
                1,
                snapshot,
                local_head,
                Digest32::new([0x73; DIGEST_LEN]),
            ),
            signed_checkpoint(
                27,
                session_id,
                1,
                snapshot,
                ChainHead::new([0x74; DIGEST_LEN]),
                ledger_digest,
            ),
        ] {
            assert_tampered(fresh().process_evidence(&checkpoint_evidence(
                EVIDENCE_SENT_CHECKPOINT,
                checkpoint.encode_payload().as_slice(),
            )));
        }
    }

    #[tokio::test]
    async fn checkpoint_ack_verifier_rejects_every_sequence_and_reference_mismatch() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(28), Endpoint::Memory(128)).await;
        let walked = walk_file(&pair.controller_path).unwrap();
        let header = walked.header;
        let hello = walked.hello;
        let session_id = *header.session_id();
        let snapshot = SharedSnapshot::new([StreamSnapshot::new(0, zero_head()); SHARED_STREAMS]);
        let digest = Digest32::new([0x81; DIGEST_LEN]);
        let reference = CheckpointRef {
            sequence: 1,
            digest: *digest.as_bytes(),
            snapshot,
        };
        let sent_ack = signed_checkpoint_ack(28, session_id, 1, digest, snapshot);
        let received_ack = signed_checkpoint_ack(128, session_id, 1, digest, snapshot);

        let sent_state = || {
            let mut verifier = ChainVerifier::new(header, hello);
            verifier.last_received_checkpoint_seq = 1;
            verifier.last_received_checkpoint = Some(reference);
            verifier
        };
        sent_state()
            .process_evidence(&checkpoint_evidence(
                EVIDENCE_SENT_CHECKPOINT_ACK,
                sent_ack.encode_payload().as_slice(),
            ))
            .unwrap();

        let invalid_signature = CheckpointAck::new(
            session_id,
            1,
            digest,
            snapshot,
            Ed25519Signature::new([0; yonder_core::wire::audit::ED25519_SIGNATURE_LEN]),
        );
        assert_tampered(sent_state().process_evidence(&checkpoint_evidence(
            EVIDENCE_SENT_CHECKPOINT_ACK,
            invalid_signature.encode_payload().as_slice(),
        )));

        for ack in [
            signed_checkpoint_ack(28, SessionId::new([0x82; DIGEST_LEN]), 1, digest, snapshot),
            signed_checkpoint_ack(28, session_id, 0, digest, snapshot),
            signed_checkpoint_ack(28, session_id, 2, digest, snapshot),
            signed_checkpoint_ack(
                28,
                session_id,
                1,
                Digest32::new([0x83; DIGEST_LEN]),
                snapshot,
            ),
        ] {
            assert_tampered(sent_state().process_evidence(&checkpoint_evidence(
                EVIDENCE_SENT_CHECKPOINT_ACK,
                ack.encode_payload().as_slice(),
            )));
        }
        let mut duplicate = sent_state();
        duplicate.last_sent_ack_seq = 1;
        assert_tampered(duplicate.process_evidence(&checkpoint_evidence(
            EVIDENCE_SENT_CHECKPOINT_ACK,
            sent_ack.encode_payload().as_slice(),
        )));
        let mut missing = sent_state();
        missing.last_received_checkpoint = None;
        assert_tampered(missing.process_evidence(&checkpoint_evidence(
            EVIDENCE_SENT_CHECKPOINT_ACK,
            sent_ack.encode_payload().as_slice(),
        )));

        let received_state = || {
            let mut verifier = ChainVerifier::new(header, hello);
            verifier.last_sent_checkpoint_seq = 1;
            verifier.last_sent_checkpoint = Some(reference);
            verifier
        };
        received_state()
            .process_evidence(&checkpoint_evidence(
                EVIDENCE_RECEIVED_CHECKPOINT_ACK,
                received_ack.encode_payload().as_slice(),
            ))
            .unwrap();
        let mut duplicate = received_state();
        duplicate.last_received_ack_seq = 1;
        assert_tampered(duplicate.process_evidence(&checkpoint_evidence(
            EVIDENCE_RECEIVED_CHECKPOINT_ACK,
            received_ack.encode_payload().as_slice(),
        )));
        let mut missing = received_state();
        missing.last_sent_checkpoint = None;
        assert_tampered(missing.process_evidence(&checkpoint_evidence(
            EVIDENCE_RECEIVED_CHECKPOINT_ACK,
            received_ack.encode_payload().as_slice(),
        )));
        let wrong_snapshot = signed_checkpoint_ack(
            128,
            session_id,
            1,
            digest,
            SharedSnapshot::new(different_snapshot()),
        );
        assert_tampered(received_state().process_evidence(&checkpoint_evidence(
            EVIDENCE_RECEIVED_CHECKPOINT_ACK,
            wrong_snapshot.encode_payload().as_slice(),
        )));
    }

    fn different_snapshot() -> [StreamSnapshot; SHARED_STREAMS] {
        let mut streams = [StreamSnapshot::new(0, zero_head()); SHARED_STREAMS];
        streams[1] = StreamSnapshot::new(1, ChainHead::new([0x84; DIGEST_LEN]));
        streams
    }

    fn frame_spans(bytes: &[u8]) -> Vec<(usize, usize, RecordType)> {
        let mut reader = ContainerReader::new(bytes).unwrap();
        let mut spans = Vec::new();
        while let Some(frame) = reader.next_frame().unwrap() {
            let frame_len = RECORD_FRAME_HEADER_LEN + 1 + frame.payload.len();
            let end = reader.position();
            spans.push((end - frame_len, end, frame.record_type));
        }
        spans
    }

    #[tokio::test]
    async fn tampered_peer_file_is_reported_without_discarding_the_local_report() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(29), Endpoint::Memory(129)).await;
        let mut bytes = fs::read(&pair.host_path).unwrap();
        let frame_offset = CONTAINER_HEADER_LEN + RECORD_FRAME_HEADER_LEN + SPLIT_PREFIX_LEN;
        bytes[frame_offset] ^= 1;
        fs::write(&pair.host_path, bytes).unwrap();

        let report = verify_files(&pair.controller_path, Some(&pair.host_path), &NoAnchor).unwrap();
        assert_eq!(report.state, VerificationState::Tampered);
        assert!(report.controller.is_some());
        assert!(report.host.is_none());
    }

    #[tokio::test]
    async fn byte_level_header_seal_and_commit_mutations_are_tampered() {
        for (counter, target) in [(30, "header"), (31, "seal"), (32, "commit")] {
            let dir = tempdir().unwrap();
            let pair = build_full_pair(
                dir.path(),
                Endpoint::Memory(counter),
                Endpoint::Memory(counter.wrapping_add(100)),
            )
            .await;
            let mut bytes = fs::read(&pair.controller_path).unwrap();
            match target {
                "header" => {
                    let utc_offset = 8 + 2 + 1 + 32 + 4 * 32 + 8 + 32;
                    bytes[utc_offset] ^= 1;
                }
                "seal" => {
                    let mut reader = ContainerReader::new(&bytes).unwrap();
                    while reader.next_frame().unwrap().is_some() {}
                    let seal_end = reader.footer().unwrap().seal_end;
                    bytes[seal_end - LOCAL_RECORD_SEAL_LEN + 12] ^= 1;
                }
                "commit" => {
                    let mut reader = ContainerReader::new(&bytes).unwrap();
                    while reader.next_frame().unwrap().is_some() {}
                    let ledger_end = reader.footer().unwrap().ledger_end;
                    bytes[ledger_end - LEDGER_COMMIT_LEN + 7] ^= 1;
                }
                _ => unreachable!(),
            }
            fs::write(&pair.controller_path, bytes).unwrap();
            let report =
                verify_files(&pair.controller_path, Some(&pair.host_path), &NoAnchor).unwrap();
            assert_eq!(report.state, VerificationState::Tampered, "{target}");
        }
    }

    #[tokio::test]
    async fn deleted_and_reordered_record_frames_are_tampered() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(33), Endpoint::Memory(133)).await;
        let bytes = fs::read(&pair.controller_path).unwrap();
        let spans = frame_spans(&bytes);
        let mut deleted = bytes.clone();
        deleted.drain(spans[1].0..spans[1].1);
        fs::write(&pair.controller_path, deleted).unwrap();
        assert_eq!(
            verify_files(&pair.controller_path, Some(&pair.host_path), &NoAnchor)
                .unwrap()
                .state,
            VerificationState::Tampered
        );

        let pair = build_full_pair(dir.path(), Endpoint::Memory(34), Endpoint::Memory(134)).await;
        let bytes = fs::read(&pair.controller_path).unwrap();
        let input_spans: Vec<_> = frame_spans(&bytes)
            .into_iter()
            .filter(|(_, _, kind)| *kind == RecordType::SharedInputCommitment)
            .map(|(start, end, _)| (start, end))
            .collect();
        assert_eq!(input_spans.len(), 2);
        assert_eq!(
            input_spans[0].1 - input_spans[0].0,
            input_spans[1].1 - input_spans[1].0
        );
        let mut reordered = bytes.clone();
        let first = bytes[input_spans[0].0..input_spans[0].1].to_vec();
        let second = bytes[input_spans[1].0..input_spans[1].1].to_vec();
        reordered.splice(input_spans[1].0..input_spans[1].1, first);
        reordered.splice(input_spans[0].0..input_spans[0].1, second);
        fs::write(&pair.controller_path, reordered).unwrap();
        assert_eq!(
            verify_files(&pair.controller_path, Some(&pair.host_path), &NoAnchor)
                .unwrap()
                .state,
            VerificationState::Tampered
        );
    }

    #[tokio::test]
    async fn footer_verifier_rejects_each_manifest_seal_and_commit_binding() {
        use yonder_core::wire::audit::{LedgerCommit, LocalRecordSeal};

        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(26), Endpoint::Memory(126)).await;
        let mut controller = walk_file(&pair.controller_path).unwrap();

        for offset in [2, 34, 98, 162, 194, 226, MANIFEST_LEN - 1] {
            let mut footer = controller.footer.clone().unwrap();
            footer.manifest_bytes[offset] ^= 1;
            assert!(matches!(
                verify_footer(&pair.controller_path, &controller, footer),
                Err(StreamError::Tampered(_))
            ));
        }
        let host = walk_file(&pair.host_path).unwrap();
        for offset in [34, 98] {
            let mut footer = host.footer.clone().unwrap();
            footer.manifest_bytes[offset] ^= 1;
            assert!(matches!(
                verify_footer(&pair.host_path, &host, footer),
                Err(StreamError::Tampered(_))
            ));
        }

        let mut footer = controller.footer.clone().unwrap();
        footer.controller_signature = ManifestSignature::new(Ed25519Signature::new(
            [0xD2; yonder_core::wire::audit::ED25519_SIGNATURE_LEN],
        ));
        assert!(matches!(
            verify_footer(&pair.controller_path, &controller, footer),
            Err(StreamError::Tampered(_))
        ));
        let mut footer = controller.footer.clone().unwrap();
        footer.host_signature = ManifestSignature::new(Ed25519Signature::new(
            [0xD3; yonder_core::wire::audit::ED25519_SIGNATURE_LEN],
        ));
        assert!(matches!(
            verify_footer(&pair.controller_path, &controller, footer),
            Err(StreamError::Tampered(_))
        ));

        let original = controller.footer.as_ref().unwrap().seal;
        let make_seal =
            |session_id, role, local_head, local_count, shared, manifest, prefix, signature| {
                LocalRecordSeal::new(
                    session_id,
                    role,
                    local_head,
                    local_count,
                    shared,
                    manifest,
                    prefix,
                    signature,
                )
            };
        let cases = [
            make_seal(
                SessionId::new([0xD4; DIGEST_LEN]),
                original.role(),
                *original.final_local_event_root(),
                original.local_event_count(),
                *original.final_shared_roots(),
                *original.joint_manifest_digest(),
                *original.sealed_prefix_digest(),
                *original.signature(),
            ),
            make_seal(
                *original.session_id(),
                AuditRole::Host,
                *original.final_local_event_root(),
                original.local_event_count(),
                *original.final_shared_roots(),
                *original.joint_manifest_digest(),
                *original.sealed_prefix_digest(),
                *original.signature(),
            ),
            make_seal(
                *original.session_id(),
                original.role(),
                ChainHead::new([0xD5; DIGEST_LEN]),
                original.local_event_count(),
                *original.final_shared_roots(),
                *original.joint_manifest_digest(),
                *original.sealed_prefix_digest(),
                *original.signature(),
            ),
            make_seal(
                *original.session_id(),
                original.role(),
                *original.final_local_event_root(),
                original.local_event_count() + 1,
                *original.final_shared_roots(),
                *original.joint_manifest_digest(),
                *original.sealed_prefix_digest(),
                *original.signature(),
            ),
            make_seal(
                *original.session_id(),
                original.role(),
                *original.final_local_event_root(),
                original.local_event_count(),
                [ChainHead::new([0xD6; DIGEST_LEN]); 4],
                *original.joint_manifest_digest(),
                *original.sealed_prefix_digest(),
                *original.signature(),
            ),
            make_seal(
                *original.session_id(),
                original.role(),
                *original.final_local_event_root(),
                original.local_event_count(),
                *original.final_shared_roots(),
                Digest32::new([0xD7; DIGEST_LEN]),
                *original.sealed_prefix_digest(),
                *original.signature(),
            ),
            make_seal(
                *original.session_id(),
                original.role(),
                *original.final_local_event_root(),
                original.local_event_count(),
                *original.final_shared_roots(),
                *original.joint_manifest_digest(),
                *original.sealed_prefix_digest(),
                Ed25519Signature::new([0xD8; yonder_core::wire::audit::ED25519_SIGNATURE_LEN]),
            ),
        ];
        for seal in cases {
            let mut footer = controller.footer.clone().unwrap();
            footer.seal = seal;
            assert!(matches!(
                verify_footer(&pair.controller_path, &controller, footer),
                Err(StreamError::Tampered(_))
            ));
        }

        let unsigned = make_seal(
            *original.session_id(),
            original.role(),
            *original.final_local_event_root(),
            original.local_event_count(),
            *original.final_shared_roots(),
            *original.joint_manifest_digest(),
            Digest32::new([0xDE; DIGEST_LEN]),
            Ed25519Signature::new([0; yonder_core::wire::audit::ED25519_SIGNATURE_LEN]),
        );
        let seal = make_seal(
            *original.session_id(),
            original.role(),
            *original.final_local_event_root(),
            original.local_event_count(),
            *original.final_shared_roots(),
            *original.joint_manifest_digest(),
            *unsigned.sealed_prefix_digest(),
            Ed25519Signature::new(
                session_signing_key(26)
                    .sign(unsigned.signing_input().as_slice())
                    .to_bytes(),
            ),
        );
        let mut footer = controller.footer.clone().unwrap();
        footer.seal = seal;
        assert!(matches!(
            verify_footer(&pair.controller_path, &controller, footer),
            Err(StreamError::Tampered(_))
        ));

        let original = controller.footer.as_ref().unwrap().commit;
        let make_commit = |session_id, manifest_digest, signature| {
            LedgerCommit::new(
                original.sequence(),
                *original.previous_root(),
                session_id,
                manifest_digest,
                *original.sealed_record_digest(),
                *original.peer_identity_fingerprint(),
                original.result(),
                signature,
            )
        };
        for commit in [
            make_commit(
                SessionId::new([0xD9; DIGEST_LEN]),
                *original.manifest_digest(),
                *original.signature(),
            ),
            make_commit(
                *original.session_id(),
                Digest32::new([0xDA; DIGEST_LEN]),
                *original.signature(),
            ),
            make_commit(
                *original.session_id(),
                *original.manifest_digest(),
                Ed25519Signature::new([0xDB; yonder_core::wire::audit::ED25519_SIGNATURE_LEN]),
            ),
        ] {
            let mut footer = controller.footer.clone().unwrap();
            footer.commit = commit;
            assert!(matches!(
                verify_footer(&pair.controller_path, &controller, footer),
                Err(StreamError::Tampered(_))
            ));
        }

        let original = controller.footer.as_ref().unwrap().commit;
        let unsigned = LedgerCommit::new(
            original.sequence(),
            *original.previous_root(),
            *original.session_id(),
            *original.manifest_digest(),
            Digest32::new([0xDF; DIGEST_LEN]),
            *original.peer_identity_fingerprint(),
            original.result(),
            Ed25519Signature::new([0; yonder_core::wire::audit::ED25519_SIGNATURE_LEN]),
        );
        let commit = LedgerCommit::new(
            unsigned.sequence(),
            *unsigned.previous_root(),
            *unsigned.session_id(),
            *unsigned.manifest_digest(),
            *unsigned.sealed_record_digest(),
            *unsigned.peer_identity_fingerprint(),
            unsigned.result(),
            TestIdentity::generate(26)
                .sign(unsigned.signing_input().as_slice())
                .unwrap(),
        );
        let mut footer = controller.footer.clone().unwrap();
        footer.commit = commit;
        assert!(matches!(
            verify_footer(&pair.controller_path, &controller, footer),
            Err(StreamError::Tampered(_))
        ));

        let mut footer = controller.footer.clone().unwrap();
        footer.final_digest = Digest32::new([0xE0; DIGEST_LEN]);
        assert!(matches!(
            verify_footer(&pair.controller_path, &controller, footer),
            Err(StreamError::Tampered(_))
        ));

        let footer = controller.footer.clone().unwrap();
        controller.manifest_evidence = Some(vec![0]);
        assert!(matches!(
            verify_footer(&pair.controller_path, &controller, footer),
            Err(StreamError::Tampered(_))
        ));
    }

    #[tokio::test]
    async fn manifest_evidence_requires_matching_payloads_and_both_signatures() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(27), Endpoint::Memory(127)).await;

        let mut verified = walk_file(&pair.controller_path).unwrap();
        verified.received_manifest_evidence = Some(vec![0]);
        assert_tampered(verify_manifest_evidence(&verified));

        let mut verified = walk_file(&pair.controller_path).unwrap();
        verified.sent_manifest_signature = Some(ManifestSignature::new(Ed25519Signature::new(
            [0xDC; yonder_core::wire::audit::ED25519_SIGNATURE_LEN],
        )));
        assert_tampered(verify_manifest_evidence(&verified));

        let mut verified = walk_file(&pair.controller_path).unwrap();
        verified.received_manifest_evidence = None;
        assert_tampered(verify_manifest_evidence(&verified));

        let mut verified = walk_file(&pair.controller_path).unwrap();
        verified.received_manifest_signature = Some(ManifestSignature::new(Ed25519Signature::new(
            [0xDD; yonder_core::wire::audit::ED25519_SIGNATURE_LEN],
        )));
        assert_tampered(verify_manifest_evidence(&verified));
    }

    #[tokio::test]
    async fn prefix_digest_reader_rejects_missing_and_truncated_storage() {
        let dir = tempdir().unwrap();
        let pair = build_full_pair(dir.path(), Endpoint::Memory(66), Endpoint::Memory(166)).await;
        let verified = walk_file(&pair.controller_path).unwrap();
        let mut footer = verified.footer.unwrap();
        let missing = dir.path().join("missing-prefix.yonaudit");
        assert!(matches!(
            compute_prefix_digests(&missing, &footer),
            Err(StreamError::Io(_))
        ));

        footer.ledger_end = fs::metadata(&pair.controller_path).unwrap().len() + 1;
        assert!(matches!(
            compute_prefix_digests(&pair.controller_path, &footer),
            Err(StreamError::Tampered("the audit container is truncated"))
        ));
    }

    fn write_test_ledger_head(root: &Path, sequence: u64, ledger_root: LedgerRoot) {
        let mut state = [0_u8; LEDGER_STATE_LEN];
        state[..8].copy_from_slice(b"YONLEDG\0");
        state[8..10].copy_from_slice(&1_u16.to_be_bytes());
        state[10..18].copy_from_slice(&sequence.to_be_bytes());
        state[18..50].copy_from_slice(ledger_root.as_bytes());
        let checksum = Sha256::digest(&state[..LEDGER_STATE_CHECKSUM_OFFSET]);
        state[LEDGER_STATE_CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        fs::write(root.join(identity::LEDGER_STATE_FILE_NAME), state).unwrap();
    }

    #[tokio::test]
    async fn ledger_continuity_and_chain_scan_fail_closed_at_each_boundary() {
        use yonder_core::wire::audit::LedgerCommit;

        let dir = tempdir().unwrap();
        let root = dir.path().join("audit-root");
        crate::audit::ledger::Ledger::open(&root, &mut OsSecureRandom).unwrap();
        let pair = build_full_pair(
            dir.path(),
            Endpoint::Real(root.clone()),
            Endpoint::Memory(167),
        )
        .await;
        let identity = load_anchor_identity(&root).unwrap();

        let mut without_footer = walk_file(&pair.controller_path).unwrap();
        without_footer.footer = None;
        assert!(!ledger_continuous(&root, &identity, &without_footer));

        let mut invalid_signature = walk_file(&pair.controller_path).unwrap();
        let commit = invalid_signature.footer.as_ref().unwrap().commit;
        invalid_signature.footer.as_mut().unwrap().commit = LedgerCommit::new(
            commit.sequence(),
            *commit.previous_root(),
            *commit.session_id(),
            *commit.manifest_digest(),
            *commit.sealed_record_digest(),
            *commit.peer_identity_fingerprint(),
            commit.result(),
            Ed25519Signature::new([0; yonder_core::wire::audit::ED25519_SIGNATURE_LEN]),
        );
        assert!(!ledger_continuous(&root, &identity, &invalid_signature));

        let verified = walk_file(&pair.controller_path).unwrap();
        let commit = verified.footer.as_ref().unwrap().commit;
        write_test_ledger_head(&root, u64::MAX, LedgerRoot::new([0xE1; DIGEST_LEN]));
        assert!(!ledger_continuous(&root, &identity, &verified));

        let previous_sequence = commit.sequence().checked_sub(1).unwrap();
        write_test_ledger_head(&root, previous_sequence, *commit.previous_root());
        assert!(ledger_continuous(&root, &identity, &verified));

        let unsigned = LedgerCommit::new(
            commit.sequence() + 1,
            *commit.previous_root(),
            *commit.session_id(),
            *commit.manifest_digest(),
            *commit.sealed_record_digest(),
            *commit.peer_identity_fingerprint(),
            commit.result(),
            Ed25519Signature::new([0; yonder_core::wire::audit::ED25519_SIGNATURE_LEN]),
        );
        let ahead = LedgerCommit::new(
            unsigned.sequence(),
            *unsigned.previous_root(),
            *unsigned.session_id(),
            *unsigned.manifest_digest(),
            *unsigned.sealed_record_digest(),
            *unsigned.peer_identity_fingerprint(),
            unsigned.result(),
            identity.sign(unsigned.signing_input().as_slice()),
        );
        let mut ahead_file = walk_file(&pair.controller_path).unwrap();
        ahead_file.footer.as_mut().unwrap().commit = ahead;
        assert!(!ledger_continuous(&root, &identity, &ahead_file));

        let original_bytes = fs::read(&pair.controller_path).unwrap();
        let original_root = ledger::ledger_root_of(&commit);

        let divergent = dir.path().join("divergent");
        fs::create_dir(&divergent).unwrap();
        fs::write(divergent.join("00-ignore.txt"), b"ignored").unwrap();
        fs::write(divergent.join("01-broken.yonaudit"), b"broken").unwrap();
        fs::write(divergent.join("02-valid.yonaudit"), &original_bytes).unwrap();
        assert!(
            find_chain_link(
                &divergent,
                &identity,
                commit.sequence(),
                LedgerRoot::new([0xE2; DIGEST_LEN]),
            )
            .is_none()
        );

        let bad_signature = dir.path().join("bad-signature");
        fs::create_dir(&bad_signature).unwrap();
        let mut bytes = original_bytes.clone();
        let ledger_end = usize::try_from(verified.footer.as_ref().unwrap().ledger_end).unwrap();
        bytes[ledger_end - 1] ^= 1;
        fs::write(bad_signature.join("record.yonaudit"), bytes).unwrap();
        assert!(
            find_chain_link(&bad_signature, &identity, commit.sequence(), original_root,).is_none()
        );

        let bad_digest = dir.path().join("bad-digest");
        fs::create_dir(&bad_digest).unwrap();
        let mut bytes = original_bytes.clone();
        bytes[0] ^= 1;
        fs::write(bad_digest.join("record.yonaudit"), bytes).unwrap();
        assert!(
            find_chain_link(&bad_digest, &identity, commit.sequence(), original_root,).is_none()
        );

        let fork = dir.path().join("fork");
        fs::create_dir(&fork).unwrap();
        fs::write(fork.join("first.yonaudit"), &original_bytes).unwrap();
        fs::write(fork.join("second.yonaudit"), &original_bytes).unwrap();
        assert!(find_chain_link(&fork, &identity, commit.sequence(), original_root,).is_none());
    }

    #[test]
    fn local_ledger_head_rejects_every_structural_boundary() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(identity::LEDGER_STATE_FILE_NAME);
        assert!(read_ledger_head(dir.path()).is_none());

        fs::create_dir(&path).unwrap();
        assert!(read_ledger_head(dir.path()).is_none());
        fs::remove_dir(&path).unwrap();

        fs::write(&path, [0_u8; LEDGER_STATE_LEN - 1]).unwrap();
        assert!(read_ledger_head(dir.path()).is_none());

        let mut state = [0_u8; LEDGER_STATE_LEN];
        state[..8].copy_from_slice(b"YONLEDG\0");
        state[8..10].copy_from_slice(&1_u16.to_be_bytes());
        state[10..18].copy_from_slice(&17_u64.to_be_bytes());
        state[18..50].copy_from_slice(&[0xA5; DIGEST_LEN]);
        let checksum = Sha256::digest(&state[..LEDGER_STATE_CHECKSUM_OFFSET]);
        state[LEDGER_STATE_CHECKSUM_OFFSET..].copy_from_slice(&checksum);
        fs::write(&path, state).unwrap();
        assert_eq!(
            read_ledger_head(dir.path()),
            Some((17, LedgerRoot::new([0xA5; DIGEST_LEN])))
        );

        let mut invalid = state;
        invalid[0] ^= 1;
        fs::write(&path, invalid).unwrap();
        assert!(read_ledger_head(dir.path()).is_none());

        let mut invalid = state;
        invalid[8..10].copy_from_slice(&2_u16.to_be_bytes());
        fs::write(&path, invalid).unwrap();
        assert!(read_ledger_head(dir.path()).is_none());

        let mut invalid = state;
        invalid[LEDGER_STATE_CHECKSUM_OFFSET] ^= 1;
        fs::write(&path, invalid).unwrap();
        assert!(read_ledger_head(dir.path()).is_none());
    }

    #[test]
    fn anchor_record_and_digest_boundaries_fail_closed() {
        let dir = tempdir().unwrap();
        let record = dir.path().join("record.yonaudit");
        assert!(inspect_anchor_record(&record).is_none());
        assert!(!verify_anchor_digests(
            &record,
            0,
            0,
            &Digest32::new([0; DIGEST_LEN]),
            &Digest32::new([0; DIGEST_LEN]),
        ));

        fs::create_dir(&record).unwrap();
        assert!(inspect_anchor_record(&record).is_none());
        fs::remove_dir(&record).unwrap();

        fs::write(&record, [0_u8; CONTAINER_HEADER_LEN - 1]).unwrap();
        assert!(inspect_anchor_record(&record).is_none());

        let mut invalid_footer = vec![0_u8; CONTAINER_HEADER_LEN + FOOTER_MAGIC.len()];
        let footer_start = invalid_footer.len() - FOOTER_MAGIC.len();
        invalid_footer[footer_start..].copy_from_slice(&FOOTER_MAGIC);
        fs::write(&record, invalid_footer).unwrap();
        assert!(inspect_anchor_record(&record).is_none());

        let bytes = b"0123456789";
        fs::write(&record, bytes).unwrap();
        let empty = Digest32::new(Sha256::digest([]).into());
        let whole = Digest32::new(Sha256::digest(bytes).into());
        assert!(verify_anchor_digests(
            &record,
            0,
            bytes.len() as u64,
            &empty,
            &whole,
        ));
        let first = Digest32::new(Sha256::digest(&bytes[..5]).into());
        assert!(verify_anchor_digests(
            &record,
            5,
            bytes.len() as u64,
            &first,
            &whole,
        ));
        assert!(!verify_anchor_digests(
            &record,
            5,
            bytes.len() as u64 + 1,
            &first,
            &whole,
        ));
        assert!(!verify_anchor_digests(
            &record,
            bytes.len() as u64 + 1,
            bytes.len() as u64,
            &whole,
            &whole,
        ));
    }
}
