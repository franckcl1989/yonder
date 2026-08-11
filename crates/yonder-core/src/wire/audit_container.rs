//! The versioned `.yonaudit` container format, Yonder 0.1.4 design
//! section 23. The container is a binary file: a fixed-size header, a stream
//! of record frames, and an optional footer written only by normal
//! finalization. Files without a footer are valid interrupted prefixes
//! (design sections 22.4, 22.5 and 23.4).
//!
//! ```text
//! header:  fixed 713 bytes (magic, format version, roles and keys, ledger
//!          snapshot, authentication mode, the embedded AuditHello and
//!          AuditReady payloads, and the persistent identity header
//!          signature)
//! frames:  u32 big-endian frame_length (includes the record type byte and
//!          payload; 1..=1_048_576), u8 record_type, payload
//! footer:  "YFTR", u16-prefixed JointManifest, u16-prefixed controller
//!          session signature, u16-prefixed host session signature,
//!          u16-prefixed LocalRecordSeal, u16-prefixed LedgerCommit, and the
//!          32-byte final container digest
//! ```
//!
//! The container is built on the `wire::audit` message types: the header
//! embeds the exact `AuditHello` and `AuditReady` payloads exchanged on the
//! audit substream, and the footer embeds the exact `JointManifest`,
//! `ManifestSignature`, `LocalRecordSeal` and `LedgerCommit` payloads, so a
//! single type set and encoding covers both the substream and the files.
//!
//! Digest rules (design sections 23.4 and 12.3) — no circular dependencies:
//!
//! - The seal's `sealed_prefix_digest` covers everything through the end of
//!   the host session signature (the "sealed prefix"): header, record
//!   frames, joint manifest and both session signatures.
//! - The ledger commit references the sealed record digest, which extends
//!   that prefix through the `LocalRecordSeal` component. The commit never
//!   references the final container digest.
//! - The final container digest covers everything through the end of the
//!   ledger commit and excludes only itself (the last 32 bytes of the file).
//!
//! The three boundaries are exposed as absolute offsets by
//! [`DecodedFooter`], so the verify layer can hash exactly those byte ranges
//! without duplicating the layout. No digest is computed in this layer: the
//! wire modules are pure byte structure, and SHA-256, HMAC and Ed25519 live
//! in the session, ledger and verify layers (design section 32.1).
//!
//! Decoding is strict: magic and format version must match, frame lengths
//! must satisfy `1 <= frame_length <= 1_048_576`, raw output payloads are
//! capped at 64 KiB (design sections 23.3 and 27.1), unknown record types
//! are rejected, trailing bytes are rejected, and no allocation ever happens
//! from declared sizes. The four-byte footer magic can never collide with a
//! legal frame length: its value exceeds the maximum frame length.
//!
//! Record types: 2.0.0 defines no non-critical record types. Every
//! recognized type is critical, so any unrecognized type invalidates the
//! container, per section 23.3's rejection of unknown critical types. The
//! payload codecs of the event kinds belong to the audit event layer; this
//! module frames and bounds the payloads without interpreting them.

use super::WireBytes;
use super::audit::{
    AUDIT_FORMAT_VERSION, AUDIT_HELLO_LEN, AUDIT_READY_LEN, AuditHello, AuditReady, AuditRole,
    AuthMode, DIGEST_LEN, Digest32, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN,
    Ed25519PublicKey, Ed25519Signature, JointManifest, LEDGER_COMMIT_LEN, LOCAL_RECORD_SEAL_LEN,
    LedgerCommit, LedgerRoot, LocalRecordSeal, MANIFEST_SIGNATURE_LEN, MAX_MANIFEST_LEN,
    ManifestSignature, SessionId,
};
use crate::error::{ProtocolError, ProtocolField};

/// The fixed eight-byte container magic.
pub const CONTAINER_MAGIC: [u8; 8] = *b"YONDAUD\0";
/// The four-byte footer marker. The value `0x59_46_54_52` exceeds
/// [`MAX_RECORD_FRAME_LEN`], so no legal frame can begin with these bytes.
pub const FOOTER_MAGIC: [u8; 4] = *b"YFTR";
/// The domain label of the header signature: the persistent audit identity
/// signs the header fields, binding the ephemeral session key to the
/// session (design sections 9.3 and 23.2).
pub const CONTAINER_HEADER_DOMAIN: &[u8] = b"yonder-audit-container-header-v2";

/// Record frame header: the big-endian `frame_length` field. The one-byte
/// record type follows it (design section 23.3).
pub const RECORD_FRAME_HEADER_LEN: usize = 4;
/// `frame_length` bounds (design section 23.3): the value includes the
/// record type byte and the payload.
pub const MIN_RECORD_FRAME_LEN: u32 = 1;
pub const MAX_RECORD_FRAME_LEN: u32 = 1_048_576;
/// Raw terminal output payload bound for output-bearing record types
/// (design sections 23.3 and 27.1).
pub const MAX_RAW_OUTPUT_PAYLOAD_LEN: usize = 65_536;
/// `frame_length` bound for output-bearing record types: type byte plus the
/// maximum raw output payload.
pub const MAX_RAW_OUTPUT_FRAME_LEN: u32 = MAX_RAW_OUTPUT_PAYLOAD_LEN as u32 + 1;
/// The final container digest length.
pub const CONTAINER_DIGEST_LEN: usize = DIGEST_LEN;

/// Total header size: magic, format version, role, session ID, four public
/// keys, ledger sequence and root, UTC start, authentication mode, terminal
/// hello digest, the embedded `AuditHello` and `AuditReady` payloads and the
/// header signature.
pub const CONTAINER_HEADER_LEN: usize = CONTAINER_MAGIC.len()
    + 2
    + 1
    + DIGEST_LEN
    + ED25519_PUBLIC_KEY_LEN * 4
    + 8
    + DIGEST_LEN
    + 8
    + 1
    + DIGEST_LEN
    + AUDIT_HELLO_LEN
    + AUDIT_READY_LEN
    + ED25519_SIGNATURE_LEN;
/// Header signing input: the domain label plus every header field except the
/// magic, the format version and the header signature.
pub const CONTAINER_HEADER_SIGNING_LEN: usize = CONTAINER_HEADER_DOMAIN.len()
    + CONTAINER_HEADER_LEN
    - CONTAINER_MAGIC.len()
    - 2
    - ED25519_SIGNATURE_LEN;

/// Largest footer prefix: the footer magic and the five `u16`-prefixed
/// components.
pub const MAX_FOOTER_PREFIX_LEN: usize = FOOTER_MAGIC.len()
    + (2 + MAX_MANIFEST_LEN)
    + (2 + MANIFEST_SIGNATURE_LEN) * 2
    + (2 + LOCAL_RECORD_SEAL_LEN)
    + (2 + LEDGER_COMMIT_LEN);

/// Fixed 2.0.0 record types, one per event category of the audit design.
/// and 15.3. Every type is critical; an unknown record type invalidates the
/// container (design section 23.3). The payload codecs of the event kinds
/// belong to the audit event layer; this module frames and bounds the
/// payloads without interpreting them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    /// A shared input commitment block (design section 16.2).
    SharedInputCommitment = 0x01,
    /// A shared output block digest (design section 16.3).
    SharedOutputBlock = 0x02,
    /// A shared terminal control event: resize, lifecycle digests, close
    /// reasons (design section 15.2).
    SharedControlEvent = 0x03,
    /// A shared file transfer event (design section 18.6).
    SharedFileTransferEvent = 0x04,
    /// The raw network output block observed locally (design section 15.3).
    LocalRawOutput = 0x11,
    /// The display bytes committed to the local display path after platform
    /// adaptation (design section 18.4).
    LocalDisplayBytes = 0x12,
    /// The local input commitment event (design sections 18.1 and 18.2).
    LocalInputCommitment = 0x13,
    /// The local outcome of sending bytes to the network (design sections
    /// 18.1, 18.3 and 18.4).
    LocalSendOutcome = 0x14,
    /// The local outcome of writing bytes to the PTY or ConPTY (design
    /// section 18.2).
    LocalPtyWriteOutcome = 0x15,
    /// The local outcome of writing display bytes to the local terminal
    /// (design section 18.4).
    LocalDisplayWriteOutcome = 0x16,
    /// A local resize event (design section 18.5).
    LocalResizeEvent = 0x17,
    /// A local terminal lifecycle event (design section 15.2).
    LocalLifecycleEvent = 0x18,
    /// A local keyboard shortcut action (design section 15.3).
    LocalKeyAction = 0x19,
    /// A local file transfer event with local paths (design section 15.3).
    LocalFileTransferEvent = 0x1A,
    /// A local connection state change (design section 15.3).
    LocalConnectionState = 0x1B,
    /// A local audit error (design section 15.3).
    LocalAuditError = 0x1C,
    /// A checkpoint or checkpoint acknowledgment evidence record (design
    /// sections 15.2, 20.2 and 20.3).
    CheckpointEvidence = 0x1D,
    /// A local session close event (design section 22).
    LocalCloseEvent = 0x1E,
}

impl RecordType {
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::SharedInputCommitment),
            0x02 => Some(Self::SharedOutputBlock),
            0x03 => Some(Self::SharedControlEvent),
            0x04 => Some(Self::SharedFileTransferEvent),
            0x11 => Some(Self::LocalRawOutput),
            0x12 => Some(Self::LocalDisplayBytes),
            0x13 => Some(Self::LocalInputCommitment),
            0x14 => Some(Self::LocalSendOutcome),
            0x15 => Some(Self::LocalPtyWriteOutcome),
            0x16 => Some(Self::LocalDisplayWriteOutcome),
            0x17 => Some(Self::LocalResizeEvent),
            0x18 => Some(Self::LocalLifecycleEvent),
            0x19 => Some(Self::LocalKeyAction),
            0x1A => Some(Self::LocalFileTransferEvent),
            0x1B => Some(Self::LocalConnectionState),
            0x1C => Some(Self::LocalAuditError),
            0x1D => Some(Self::CheckpointEvidence),
            0x1E => Some(Self::LocalCloseEvent),
            _ => None,
        }
    }

    /// Whether the record type carries raw terminal output bytes and is
    /// therefore capped at [`MAX_RAW_OUTPUT_PAYLOAD_LEN`] (design
    /// section 23.3).
    #[must_use]
    pub const fn carries_raw_output(self) -> bool {
        matches!(self, Self::LocalRawOutput | Self::LocalDisplayBytes)
    }
}

/// One decoded record frame. `frame_len` includes the record type byte and
/// the payload (design section 23.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordFrame<'a> {
    /// The validated `frame_length` value from the frame header.
    pub frame_len: u32,
    /// The validated record type.
    pub record_type: RecordType,
    /// The payload of `frame_len - 1` bytes.
    pub payload: &'a [u8],
}

impl RecordFrame<'_> {
    /// The total encoded frame size: header plus `frame_length`.
    #[must_use]
    pub fn total_len(&self) -> usize {
        RECORD_FRAME_HEADER_LEN + self.frame_len as usize
    }
}

/// Encodes the four-byte `frame_length` field (design section 23.3). The
/// record type byte follows it in the frame.
#[must_use]
pub const fn encode_frame_header(frame_len: u32) -> [u8; RECORD_FRAME_HEADER_LEN] {
    frame_len.to_be_bytes()
}

/// Validates a `frame_length` value against the fixed bounds of its record
/// type before any read.
pub fn validate_frame_len(record_type: RecordType, frame_len: u32) -> Result<(), ProtocolError> {
    if !(MIN_RECORD_FRAME_LEN..=MAX_RECORD_FRAME_LEN).contains(&frame_len) {
        return Err(ProtocolError::InvalidLength {
            expected: 0,
            actual: frame_len as usize,
        });
    }
    if record_type.carries_raw_output() && frame_len > MAX_RAW_OUTPUT_FRAME_LEN {
        return Err(ProtocolError::InvalidLength {
            expected: MAX_RAW_OUTPUT_FRAME_LEN as usize,
            actual: frame_len as usize,
        });
    }
    Ok(())
}

/// Decodes one complete record frame: the four-byte `frame_length`, the
/// record type byte and exactly `frame_length - 1` payload bytes, rejecting
/// unknown types, out-of-bounds lengths and trailing bytes.
pub fn decode_frame(frame: &[u8]) -> Result<RecordFrame<'_>, ProtocolError> {
    if frame.len() < RECORD_FRAME_HEADER_LEN + 1 {
        return Err(ProtocolError::InvalidLength {
            expected: RECORD_FRAME_HEADER_LEN + 1,
            actual: frame.len(),
        });
    }
    let frame_len = u32::from_be_bytes(
        frame[..RECORD_FRAME_HEADER_LEN]
            .try_into()
            .expect("fixed four-byte slice"),
    );
    let record_type = RecordType::from_byte(frame[RECORD_FRAME_HEADER_LEN])
        .ok_or(ProtocolError::UnknownTag(frame[RECORD_FRAME_HEADER_LEN]))?;
    validate_frame_len(record_type, frame_len)?;
    let frame_len = usize::try_from(frame_len).map_err(|_| ProtocolError::InvalidLength {
        expected: usize::MAX,
        actual: frame.len(),
    })?;
    let expected =
        RECORD_FRAME_HEADER_LEN
            .checked_add(frame_len)
            .ok_or(ProtocolError::InvalidLength {
                expected: RECORD_FRAME_HEADER_LEN,
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
    Ok(RecordFrame {
        frame_len: frame_len as u32,
        record_type,
        payload: &frame[RECORD_FRAME_HEADER_LEN + 1..expected],
    })
}

/// The container header, design section 23.2: role, session ID, the local
/// persistent and ephemeral public keys, the peer keys, the local ledger
/// snapshot, the UTC start time, the authentication mode, the TerminalHello
/// digest, the embedded `AuditHello` and `AuditReady` payloads and the
/// header signature. The magic and the format version are frozen constants
/// validated at decode time and never stored as fields.
///
/// The header signature is produced by the local persistent audit identity
/// over [`AuditContainerHeader::signing_input`], attesting the session
/// binding of the ephemeral session key (design sections 9.3 and 23.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditContainerHeader {
    role: AuditRole,
    session_id: SessionId,
    identity_pubkey: Ed25519PublicKey,
    session_pubkey: Ed25519PublicKey,
    peer_identity_pubkey: Ed25519PublicKey,
    peer_session_pubkey: Ed25519PublicKey,
    ledger_sequence: u64,
    previous_ledger_root: LedgerRoot,
    utc_start_seconds: u64,
    auth_mode: AuthMode,
    terminal_hello_digest: Digest32,
    audit_hello: AuditHello,
    audit_ready: AuditReady,
    header_signature: Ed25519Signature,
}

impl AuditContainerHeader {
    /// Builds a header with a placeholder signature; the caller signs
    /// [`AuditContainerHeader::signing_input`] with the local persistent
    /// audit identity and attaches the signature with
    /// [`AuditContainerHeader::with_header_signature`].
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        role: AuditRole,
        session_id: SessionId,
        identity_pubkey: Ed25519PublicKey,
        session_pubkey: Ed25519PublicKey,
        peer_identity_pubkey: Ed25519PublicKey,
        peer_session_pubkey: Ed25519PublicKey,
        ledger_sequence: u64,
        previous_ledger_root: LedgerRoot,
        utc_start_seconds: u64,
        auth_mode: AuthMode,
        terminal_hello_digest: Digest32,
        audit_hello: AuditHello,
        audit_ready: AuditReady,
    ) -> Self {
        Self {
            role,
            session_id,
            identity_pubkey,
            session_pubkey,
            peer_identity_pubkey,
            peer_session_pubkey,
            ledger_sequence,
            previous_ledger_root,
            utc_start_seconds,
            auth_mode,
            terminal_hello_digest,
            audit_hello,
            audit_ready,
            header_signature: Ed25519Signature::new([0; ED25519_SIGNATURE_LEN]),
        }
    }

    #[must_use]
    pub const fn role(&self) -> AuditRole {
        self.role
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn identity_pubkey(&self) -> &Ed25519PublicKey {
        &self.identity_pubkey
    }

    #[must_use]
    pub const fn session_pubkey(&self) -> &Ed25519PublicKey {
        &self.session_pubkey
    }

    #[must_use]
    pub const fn peer_identity_pubkey(&self) -> &Ed25519PublicKey {
        &self.peer_identity_pubkey
    }

    #[must_use]
    pub const fn peer_session_pubkey(&self) -> &Ed25519PublicKey {
        &self.peer_session_pubkey
    }

    #[must_use]
    pub const fn ledger_sequence(&self) -> u64 {
        self.ledger_sequence
    }

    #[must_use]
    pub const fn previous_ledger_root(&self) -> &LedgerRoot {
        &self.previous_ledger_root
    }

    #[must_use]
    pub const fn utc_start_seconds(&self) -> u64 {
        self.utc_start_seconds
    }

    #[must_use]
    pub const fn auth_mode(&self) -> AuthMode {
        self.auth_mode
    }

    #[must_use]
    pub const fn terminal_hello_digest(&self) -> &Digest32 {
        &self.terminal_hello_digest
    }

    #[must_use]
    pub const fn audit_hello(&self) -> &AuditHello {
        &self.audit_hello
    }

    #[must_use]
    pub const fn audit_ready(&self) -> &AuditReady {
        &self.audit_ready
    }

    #[must_use]
    pub const fn header_signature(&self) -> &Ed25519Signature {
        &self.header_signature
    }

    /// Attaches the persistent identity signature computed over
    /// [`AuditContainerHeader::signing_input`].
    #[must_use]
    pub const fn with_header_signature(mut self, signature: Ed25519Signature) -> Self {
        self.header_signature = signature;
        self
    }

    /// The canonical signed bytes: the domain label followed by every header
    /// field except the header signature.
    #[must_use]
    pub fn signing_input(&self) -> WireBytes<CONTAINER_HEADER_SIGNING_LEN> {
        let mut bytes = [0_u8; CONTAINER_HEADER_SIGNING_LEN];
        let mut cursor = 0;
        append(&mut bytes, &mut cursor, CONTAINER_HEADER_DOMAIN);
        append_header_fields(&mut bytes, &mut cursor, self);
        WireBytes::new(bytes, cursor)
    }

    /// Encodes the complete fixed-size header.
    #[must_use]
    pub fn encode(&self) -> WireBytes<CONTAINER_HEADER_LEN> {
        let mut bytes = [0_u8; CONTAINER_HEADER_LEN];
        let mut cursor = 0;
        append(&mut bytes, &mut cursor, &CONTAINER_MAGIC);
        append(&mut bytes, &mut cursor, &AUDIT_FORMAT_VERSION.to_be_bytes());
        append_header_fields(&mut bytes, &mut cursor, self);
        append(&mut bytes, &mut cursor, self.header_signature.as_bytes());
        WireBytes::new(bytes, cursor)
    }

    /// Decodes an exact [`CONTAINER_HEADER_LEN`]-byte header, validating the
    /// magic, the format version, the role, the authentication mode and both
    /// embedded handshake payloads.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let bytes: [u8; CONTAINER_HEADER_LEN] =
            bytes.try_into().map_err(|_| ProtocolError::InvalidLength {
                expected: CONTAINER_HEADER_LEN,
                actual: bytes.len(),
            })?;
        if bytes[..8] != CONTAINER_MAGIC {
            return Err(ProtocolError::InvalidField(ProtocolField::Reserved));
        }
        if u16::from_be_bytes([bytes[8], bytes[9]]) != AUDIT_FORMAT_VERSION {
            return Err(ProtocolError::InvalidField(ProtocolField::Reserved));
        }
        let role = AuditRole::from_byte(bytes[10])
            .ok_or(ProtocolError::InvalidField(ProtocolField::Reserved))?;
        let auth_mode = AuthMode::from_byte(bytes[219])
            .ok_or(ProtocolError::InvalidField(ProtocolField::Reserved))?;
        let mut session_id = [0_u8; DIGEST_LEN];
        session_id.copy_from_slice(&bytes[11..43]);
        let mut identity_pubkey = [0_u8; ED25519_PUBLIC_KEY_LEN];
        identity_pubkey.copy_from_slice(&bytes[43..75]);
        let mut session_pubkey = [0_u8; ED25519_PUBLIC_KEY_LEN];
        session_pubkey.copy_from_slice(&bytes[75..107]);
        let mut peer_identity_pubkey = [0_u8; ED25519_PUBLIC_KEY_LEN];
        peer_identity_pubkey.copy_from_slice(&bytes[107..139]);
        let mut peer_session_pubkey = [0_u8; ED25519_PUBLIC_KEY_LEN];
        peer_session_pubkey.copy_from_slice(&bytes[139..171]);
        let ledger_sequence =
            u64::from_be_bytes(bytes[171..179].try_into().expect("fixed eight-byte slice"));
        let mut previous_ledger_root = [0_u8; DIGEST_LEN];
        previous_ledger_root.copy_from_slice(&bytes[179..211]);
        let utc_start_seconds =
            u64::from_be_bytes(bytes[211..219].try_into().expect("fixed eight-byte slice"));
        let mut terminal_hello_digest = [0_u8; DIGEST_LEN];
        terminal_hello_digest.copy_from_slice(&bytes[220..252]);
        let audit_hello = AuditHello::decode_payload(&bytes[252..519])?;
        let audit_ready = AuditReady::decode_payload(&bytes[519..649])?;
        let mut header_signature = [0_u8; ED25519_SIGNATURE_LEN];
        header_signature.copy_from_slice(&bytes[649..713]);
        Ok(Self {
            role,
            session_id: SessionId::new(session_id),
            identity_pubkey: Ed25519PublicKey::new(identity_pubkey),
            session_pubkey: Ed25519PublicKey::new(session_pubkey),
            peer_identity_pubkey: Ed25519PublicKey::new(peer_identity_pubkey),
            peer_session_pubkey: Ed25519PublicKey::new(peer_session_pubkey),
            ledger_sequence,
            previous_ledger_root: LedgerRoot::new(previous_ledger_root),
            utc_start_seconds,
            auth_mode,
            terminal_hello_digest: Digest32::new(terminal_hello_digest),
            audit_hello,
            audit_ready,
            header_signature: Ed25519Signature::new(header_signature),
        })
    }
}

fn append(destination: &mut [u8], cursor: &mut usize, source: &[u8]) {
    let end = *cursor + source.len();
    destination[*cursor..end].copy_from_slice(source);
    *cursor = end;
}

fn append_header_fields(destination: &mut [u8], cursor: &mut usize, header: &AuditContainerHeader) {
    append(destination, cursor, &[header.role.code()]);
    append(destination, cursor, header.session_id.as_bytes());
    append(destination, cursor, header.identity_pubkey.as_bytes());
    append(destination, cursor, header.session_pubkey.as_bytes());
    append(destination, cursor, header.peer_identity_pubkey.as_bytes());
    append(destination, cursor, header.peer_session_pubkey.as_bytes());
    append(destination, cursor, &header.ledger_sequence.to_be_bytes());
    append(destination, cursor, header.previous_ledger_root.as_bytes());
    append(destination, cursor, &header.utc_start_seconds.to_be_bytes());
    append(destination, cursor, &[header.auth_mode.code()]);
    append(destination, cursor, header.terminal_hello_digest.as_bytes());
    append(
        destination,
        cursor,
        header.audit_hello.encode_payload().as_slice(),
    );
    append(
        destination,
        cursor,
        header.audit_ready.encode_payload().as_slice(),
    );
}

/// The five footer components in their fixed order, design section 23.4:
/// the joint manifest, the controller and host session signatures, the local
/// record seal and the ledger commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditContainerFooter<'a> {
    pub manifest: JointManifest<'a>,
    pub controller_session_signature: ManifestSignature,
    pub host_session_signature: ManifestSignature,
    pub seal: LocalRecordSeal,
    pub ledger_commit: LedgerCommit,
}

/// The decoded footer together with the final container digest and the three
/// digest boundaries as absolute container offsets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFooter<'a> {
    pub footer: AuditContainerFooter<'a>,
    /// The final container digest occupying `[ledger_end, ledger_end + 32)`.
    /// It covers every preceding container byte but excludes itself (design
    /// section 23.4).
    pub final_container_digest: Digest32,
    /// Absolute offset of the end of the host session signature: the sealed
    /// prefix covered by the seal's `sealed_prefix_digest` (header, record
    /// frames, joint manifest and both session signatures).
    pub sealed_prefix_end: usize,
    /// Absolute offset of the end of the `LocalRecordSeal` component: the
    /// sealed record covered by the ledger commit's `sealed_record_digest`.
    pub seal_end: usize,
    /// Absolute offset of the end of the `LedgerCommit` component: the
    /// prefix covered by the final container digest.
    pub ledger_end: usize,
}

/// Encodes the footer prefix: the footer magic and the five `u16`-prefixed
/// components. The final container digest is appended by the caller after
/// hashing the whole prefix (design section 12.3, step 7), so no circular
/// dependency exists.
pub fn encode_footer_prefix(
    footer: &AuditContainerFooter<'_>,
) -> Result<WireBytes<MAX_FOOTER_PREFIX_LEN>, ProtocolError> {
    let mut bytes = [0_u8; MAX_FOOTER_PREFIX_LEN];
    let mut cursor = 0;
    append(&mut bytes, &mut cursor, &FOOTER_MAGIC);
    write_prefixed(
        &mut bytes,
        &mut cursor,
        footer.manifest.encode_payload()?.as_slice(),
    );
    write_prefixed(
        &mut bytes,
        &mut cursor,
        footer
            .controller_session_signature
            .encode_payload()
            .as_slice(),
    );
    write_prefixed(
        &mut bytes,
        &mut cursor,
        footer.host_session_signature.encode_payload().as_slice(),
    );
    write_prefixed(
        &mut bytes,
        &mut cursor,
        footer.seal.encode_payload().as_slice(),
    );
    write_prefixed(
        &mut bytes,
        &mut cursor,
        footer.ledger_commit.encode_payload().as_slice(),
    );
    Ok(WireBytes::new(bytes, cursor))
}

fn write_prefixed(destination: &mut [u8], cursor: &mut usize, source: &[u8]) {
    append(destination, cursor, &(source.len() as u16).to_be_bytes());
    append(destination, cursor, source);
}

/// Decodes a complete footer: the footer magic, the five `u16`-prefixed
/// components and exactly the 32-byte final container digest, rejecting
/// trailing bytes. The returned offsets are measured from the start of the
/// footer magic.
pub fn decode_footer(bytes: &[u8]) -> Result<DecodedFooter<'_>, ProtocolError> {
    if bytes.len() < FOOTER_MAGIC.len() || !bytes.starts_with(&FOOTER_MAGIC) {
        return Err(ProtocolError::InvalidField(ProtocolField::Reserved));
    }
    let mut pos = FOOTER_MAGIC.len();
    let manifest_bytes = take_prefixed(bytes, &mut pos)?;
    let manifest = JointManifest::decode_payload(manifest_bytes)?;
    let controller_bytes = take_prefixed(bytes, &mut pos)?;
    let controller_session_signature = ManifestSignature::decode_payload(controller_bytes)?;
    let host_bytes = take_prefixed(bytes, &mut pos)?;
    let host_session_signature = ManifestSignature::decode_payload(host_bytes)?;
    let sealed_prefix_end = pos;
    let seal_bytes = take_prefixed(bytes, &mut pos)?;
    let seal = LocalRecordSeal::decode_payload(seal_bytes)?;
    let seal_end = pos;
    let ledger_bytes = take_prefixed(bytes, &mut pos)?;
    let ledger_commit = LedgerCommit::decode_payload(ledger_bytes)?;
    let ledger_end = pos;
    let digest_bytes = &bytes[pos..];
    if digest_bytes.len() > CONTAINER_DIGEST_LEN {
        return Err(ProtocolError::TrailingBytes);
    }
    if digest_bytes.len() < CONTAINER_DIGEST_LEN {
        return Err(ProtocolError::InvalidLength {
            expected: CONTAINER_DIGEST_LEN,
            actual: digest_bytes.len(),
        });
    }
    let final_container_digest =
        Digest32::new(digest_bytes.try_into().expect("exact 32-byte digest slice"));
    Ok(DecodedFooter {
        footer: AuditContainerFooter {
            manifest,
            controller_session_signature,
            host_session_signature,
            seal,
            ledger_commit,
        },
        final_container_digest,
        sealed_prefix_end,
        seal_end,
        ledger_end,
    })
}

fn take_prefixed<'a>(input: &'a [u8], pos: &mut usize) -> Result<&'a [u8], ProtocolError> {
    let len_bytes: [u8; 2] = input
        .get(*pos..*pos + 2)
        .ok_or(ProtocolError::InvalidLength {
            expected: *pos + 2,
            actual: input.len(),
        })?
        .try_into()
        .map_err(|_| ProtocolError::InvalidLength {
            expected: *pos + 2,
            actual: input.len(),
        })?;
    let len = usize::from(u16::from_be_bytes(len_bytes));
    let end = (*pos + 2)
        .checked_add(len)
        .ok_or(ProtocolError::InvalidLength {
            expected: *pos + 2,
            actual: input.len(),
        })?;
    let bytes = input
        .get(*pos + 2..end)
        .ok_or(ProtocolError::InvalidLength {
            expected: end,
            actual: input.len(),
        })?;
    *pos = end;
    Ok(bytes)
}

/// A streaming, zero-allocation parser over one `.yonaudit` container
/// buffer. The parser validates the header, walks the record frames one at a
/// time and finally decodes the footer, exposing the exact digest boundaries
/// for the verify layer. Files without a footer are accepted as valid
/// interrupted prefixes (design sections 22.5 and 23.4).
#[derive(Debug, Clone)]
pub struct ContainerReader<'a> {
    bytes: &'a [u8],
    pos: usize,
    header: AuditContainerHeader,
}

impl<'a> ContainerReader<'a> {
    /// Validates the container magic, format version and header structure.
    pub fn new(bytes: &'a [u8]) -> Result<Self, ProtocolError> {
        if bytes.len() < CONTAINER_HEADER_LEN {
            return Err(ProtocolError::InvalidLength {
                expected: CONTAINER_HEADER_LEN,
                actual: bytes.len(),
            });
        }
        let header = AuditContainerHeader::decode(&bytes[..CONTAINER_HEADER_LEN])?;
        Ok(Self {
            bytes,
            pos: CONTAINER_HEADER_LEN,
            header,
        })
    }

    /// The decoded header.
    #[must_use]
    pub fn header(&self) -> &AuditContainerHeader {
        &self.header
    }

    /// The raw header bytes (covered by the header signature and the sealed
    /// prefix digests).
    #[must_use]
    pub fn header_bytes(&self) -> &'a [u8] {
        &self.bytes[..CONTAINER_HEADER_LEN]
    }

    /// The current parse offset in the container.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Whether the next bytes begin the footer.
    #[must_use]
    pub fn has_footer(&self) -> bool {
        self.bytes[self.pos..].starts_with(&FOOTER_MAGIC)
    }

    /// Reads the next record frame, or `Ok(None)` when the footer begins or
    /// the container ends cleanly. A partially written frame header or frame
    /// body is a truncated-container error.
    pub fn next_frame(&mut self) -> Result<Option<RecordFrame<'a>>, ProtocolError> {
        let remaining = &self.bytes[self.pos..];
        if remaining.len() < RECORD_FRAME_HEADER_LEN + 1 {
            if remaining.is_empty() {
                return Ok(None);
            }
            return Err(ProtocolError::InvalidLength {
                expected: RECORD_FRAME_HEADER_LEN + 1,
                actual: remaining.len(),
            });
        }
        if remaining.starts_with(&FOOTER_MAGIC) {
            return Ok(None);
        }
        let frame_len = u32::from_be_bytes(
            remaining[..RECORD_FRAME_HEADER_LEN]
                .try_into()
                .expect("fixed four-byte slice"),
        );
        let record_type = RecordType::from_byte(remaining[RECORD_FRAME_HEADER_LEN]).ok_or(
            ProtocolError::UnknownTag(remaining[RECORD_FRAME_HEADER_LEN]),
        )?;
        validate_frame_len(record_type, frame_len)?;
        let frame_len = usize::try_from(frame_len).map_err(|_| ProtocolError::InvalidLength {
            expected: usize::MAX,
            actual: remaining.len(),
        })?;
        let expected =
            RECORD_FRAME_HEADER_LEN
                .checked_add(frame_len)
                .ok_or(ProtocolError::InvalidLength {
                    expected: RECORD_FRAME_HEADER_LEN,
                    actual: remaining.len(),
                })?;
        if remaining.len() < expected {
            return Err(ProtocolError::InvalidLength {
                expected,
                actual: remaining.len(),
            });
        }
        let payload = &remaining[RECORD_FRAME_HEADER_LEN + 1..expected];
        self.pos += expected;
        Ok(Some(RecordFrame {
            frame_len: frame_len as u32,
            record_type,
            payload,
        }))
    }

    /// Decodes the footer, which must begin with the footer magic and end
    /// exactly with the 32-byte final container digest. The digest
    /// boundaries in the returned [`DecodedFooter`] are absolute container
    /// offsets.
    pub fn footer(&mut self) -> Result<DecodedFooter<'a>, ProtocolError> {
        let footer_start = self.pos;
        let decoded = decode_footer(&self.bytes[footer_start..])?;
        self.pos = self.bytes.len();
        Ok(DecodedFooter {
            sealed_prefix_end: footer_start + decoded.sealed_prefix_end,
            seal_end: footer_start + decoded.seal_end,
            ledger_end: footer_start + decoded.ledger_end,
            ..decoded
        })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::wire::audit::{
        AuditNonce, BindingDigest, ChainHead, CommitmentDigest, IdentityFingerprint,
        ManifestEnding, SessionResult, SharedSnapshot, StreamSnapshot,
    };

    const ZERO_HEAD: ChainHead = ChainHead::new([0; DIGEST_LEN]);
    const ZERO_ROOT: LedgerRoot = LedgerRoot::new([0; DIGEST_LEN]);

    fn snapshot() -> SharedSnapshot {
        SharedSnapshot::new([
            StreamSnapshot::new(10, ZERO_HEAD),
            StreamSnapshot::new(20, ZERO_HEAD),
            StreamSnapshot::new(30, ZERO_HEAD),
            StreamSnapshot::new(40, ZERO_HEAD),
        ])
    }

    fn test_hello() -> AuditHello {
        AuditHello::new(
            AuditRole::Controller,
            Ed25519PublicKey::new([1; ED25519_PUBLIC_KEY_LEN]),
            Ed25519PublicKey::new([2; ED25519_PUBLIC_KEY_LEN]),
            AuditNonce::new([3; 32]),
            7,
            ZERO_ROOT,
            BindingDigest::new([4; DIGEST_LEN]),
            AUDIT_FORMAT_VERSION,
            CommitmentDigest::new([5; DIGEST_LEN]),
            Ed25519Signature::new([6; ED25519_SIGNATURE_LEN]),
        )
    }

    fn test_ready() -> AuditReady {
        AuditReady::new(
            SessionId::new([1; DIGEST_LEN]),
            Digest32::new([2; DIGEST_LEN]),
            AUDIT_FORMAT_VERSION,
            Ed25519Signature::new([3; ED25519_SIGNATURE_LEN]),
        )
    }

    fn test_header() -> AuditContainerHeader {
        AuditContainerHeader::new(
            AuditRole::Controller,
            SessionId::new([1; DIGEST_LEN]),
            Ed25519PublicKey::new([1; ED25519_PUBLIC_KEY_LEN]),
            Ed25519PublicKey::new([2; ED25519_PUBLIC_KEY_LEN]),
            Ed25519PublicKey::new([3; ED25519_PUBLIC_KEY_LEN]),
            Ed25519PublicKey::new([4; ED25519_PUBLIC_KEY_LEN]),
            7,
            ZERO_ROOT,
            1_700_000_000,
            AuthMode::Standard,
            Digest32::new([5; DIGEST_LEN]),
            test_hello(),
            test_ready(),
        )
        .with_header_signature(Ed25519Signature::new([9; ED25519_SIGNATURE_LEN]))
    }

    fn test_manifest() -> JointManifest<'static> {
        JointManifest::new(
            AUDIT_FORMAT_VERSION,
            SessionId::new([1; DIGEST_LEN]),
            IdentityFingerprint::new([2; DIGEST_LEN]),
            IdentityFingerprint::new([3; DIGEST_LEN]),
            Ed25519PublicKey::new([4; ED25519_PUBLIC_KEY_LEN]),
            Ed25519PublicKey::new([5; ED25519_PUBLIC_KEY_LEN]),
            BindingDigest::new([6; DIGEST_LEN]),
            "alice@wecom",
            Digest32::new([7; DIGEST_LEN]),
            snapshot(),
            ManifestEnding::ShellExit(0),
            true,
            9,
        )
    }

    fn test_seal() -> LocalRecordSeal {
        LocalRecordSeal::new(
            SessionId::new([1; DIGEST_LEN]),
            AuditRole::Controller,
            ZERO_HEAD,
            12,
            [ZERO_HEAD; 4],
            Digest32::new([2; DIGEST_LEN]),
            Digest32::new([3; DIGEST_LEN]),
            Ed25519Signature::new([4; ED25519_SIGNATURE_LEN]),
        )
    }

    fn test_ledger_commit() -> LedgerCommit {
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

    fn test_footer() -> AuditContainerFooter<'static> {
        AuditContainerFooter {
            manifest: test_manifest(),
            controller_session_signature: ManifestSignature::new(Ed25519Signature::new(
                [6; ED25519_SIGNATURE_LEN],
            )),
            host_session_signature: ManifestSignature::new(Ed25519Signature::new(
                [7; ED25519_SIGNATURE_LEN],
            )),
            seal: test_seal(),
            ledger_commit: test_ledger_commit(),
        }
    }

    /// Builds a complete container: header, the given frames and a footer
    /// with a plausible final digest.
    fn build_container(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut container = test_header().encode().as_slice().to_vec();
        for frame in frames {
            container.extend_from_slice(frame);
        }
        let prefix = encode_footer_prefix(&test_footer()).unwrap();
        container.extend_from_slice(prefix.as_slice());
        container.extend_from_slice(&[0xAB; CONTAINER_DIGEST_LEN]);
        container
    }

    fn frame_bytes(record_type: RecordType, payload: &[u8]) -> Vec<u8> {
        let frame_len = 1_u32 + payload.len() as u32;
        let mut frame = encode_frame_header(frame_len).to_vec();
        frame.push(record_type.code());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn container_header_round_trips_at_frozen_length() {
        let header = test_header();
        assert_eq!(
            header.encode().as_slice().len(),
            CONTAINER_HEADER_LEN,
            "the header has one exact frozen length"
        );
        let decoded = AuditContainerHeader::decode(header.encode().as_slice()).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(decoded.role(), AuditRole::Controller);
        assert_eq!(decoded.session_id(), &SessionId::new([1; DIGEST_LEN]));
        assert_eq!(decoded.ledger_sequence(), 7);
        assert_eq!(decoded.utc_start_seconds(), 1_700_000_000);
        assert_eq!(decoded.auth_mode(), AuthMode::Standard);
        assert_eq!(
            decoded.audit_hello().persistent_audit_key(),
            &Ed25519PublicKey::new([1; ED25519_PUBLIC_KEY_LEN])
        );
        assert_eq!(
            decoded.audit_ready().session_id(),
            &SessionId::new([1; DIGEST_LEN])
        );
        assert_eq!(
            decoded.header_signature(),
            &Ed25519Signature::new([9; ED25519_SIGNATURE_LEN])
        );
    }

    #[test]
    fn container_header_signing_input_has_the_exact_frozen_layout() {
        let header = test_header();
        let input = header.signing_input();
        assert_eq!(input.as_slice().len(), CONTAINER_HEADER_SIGNING_LEN);
        let mut expected = Vec::new();
        expected.extend_from_slice(CONTAINER_HEADER_DOMAIN);
        // The signature input covers every header field except the magic,
        // the format version and the header signature itself.
        expected.extend_from_slice(
            &header.encode().as_slice()
                [CONTAINER_MAGIC.len() + 2..CONTAINER_HEADER_LEN - ED25519_SIGNATURE_LEN],
        );
        assert_eq!(input.as_slice(), expected);
    }

    #[test]
    fn container_header_rejects_bad_magic_version_role_and_mode() {
        let mut bytes = test_header().encode().as_slice().to_vec();
        bytes[0] = b'X';
        assert_eq!(
            AuditContainerHeader::decode(&bytes),
            Err(ProtocolError::InvalidField(ProtocolField::Reserved))
        );
        bytes[0] = b'Y';
        bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            AuditContainerHeader::decode(&bytes),
            Err(ProtocolError::InvalidField(ProtocolField::Reserved))
        );
        bytes[8..10].copy_from_slice(&AUDIT_FORMAT_VERSION.to_be_bytes());
        bytes[10] = 0x03;
        assert_eq!(
            AuditContainerHeader::decode(&bytes),
            Err(ProtocolError::InvalidField(ProtocolField::Reserved))
        );
        bytes[10] = AuditRole::Controller.code();
        bytes[219] = 0x03;
        assert_eq!(
            AuditContainerHeader::decode(&bytes),
            Err(ProtocolError::InvalidField(ProtocolField::Reserved))
        );
        bytes[219] = AuthMode::Standard.code();
        bytes.truncate(bytes.len() - 1);
        assert_eq!(
            AuditContainerHeader::decode(&bytes),
            Err(ProtocolError::InvalidLength {
                expected: CONTAINER_HEADER_LEN,
                actual: CONTAINER_HEADER_LEN - 1,
            })
        );
        // A corrupted embedded AuditHello fails the header decode.
        let mut corrupted = test_header().encode().as_slice().to_vec();
        corrupted[252] = 0x03; // invalid role inside the embedded hello
        assert_eq!(
            AuditContainerHeader::decode(&corrupted),
            Err(ProtocolError::InvalidField(ProtocolField::Reserved))
        );
    }

    #[test]
    fn record_frame_headers_validate_lengths_and_types() {
        let header = encode_frame_header(65_537);
        assert_eq!(header, [0, 1, 0, 1]);
        assert!(matches!(
            decode_frame(&[]),
            Err(ProtocolError::InvalidLength { .. })
        ));
        assert!(matches!(
            decode_frame(&[0, 0, 0, 1, 0x1F]),
            Err(ProtocolError::UnknownTag(0x1F))
        ));
    }

    #[test]
    fn record_frame_length_bounds_are_enforced_per_type() {
        assert!(
            validate_frame_len(RecordType::SharedInputCommitment, MIN_RECORD_FRAME_LEN).is_ok()
        );
        assert!(
            validate_frame_len(RecordType::SharedInputCommitment, MAX_RECORD_FRAME_LEN).is_ok()
        );
        assert!(
            validate_frame_len(RecordType::SharedInputCommitment, MAX_RECORD_FRAME_LEN + 1)
                .is_err()
        );
        assert!(validate_frame_len(RecordType::SharedInputCommitment, 0).is_err());
        // Raw output payloads are capped at 64 KiB.
        assert!(validate_frame_len(RecordType::LocalRawOutput, MAX_RAW_OUTPUT_FRAME_LEN).is_ok());
        assert!(
            validate_frame_len(RecordType::LocalRawOutput, MAX_RAW_OUTPUT_FRAME_LEN + 1).is_err()
        );
        // Non-output types are bounded only by the global frame bound.
        assert!(validate_frame_len(RecordType::LocalKeyAction, MAX_RECORD_FRAME_LEN).is_ok());
        assert_eq!(
            validate_frame_len(RecordType::LocalRawOutput, MAX_RAW_OUTPUT_FRAME_LEN + 1),
            Err(ProtocolError::InvalidLength {
                expected: MAX_RAW_OUTPUT_FRAME_LEN as usize,
                actual: MAX_RAW_OUTPUT_FRAME_LEN as usize + 1,
            })
        );
    }

    #[test]
    fn record_frames_round_trip_with_exact_length_validation() {
        let frame = frame_bytes(RecordType::LocalLifecycleEvent, &[1, 2, 3]);
        let decoded = decode_frame(&frame).unwrap();
        assert_eq!(decoded.record_type, RecordType::LocalLifecycleEvent);
        assert_eq!(decoded.payload, &[1, 2, 3]);
        assert_eq!(decoded.frame_len, 4);
        assert_eq!(decoded.total_len(), 8);

        // Truncated frames fail with the precise expected length.
        for cut in 0..frame.len() {
            assert!(
                matches!(
                    decode_frame(&frame[..cut]),
                    Err(ProtocolError::InvalidLength { .. })
                ),
                "truncation at {cut}"
            );
        }
        // Trailing bytes are rejected.
        let mut trailing = frame.clone();
        trailing.push(0);
        assert_eq!(decode_frame(&trailing), Err(ProtocolError::TrailingBytes));
        // An unknown record type is rejected.
        let mut unknown = encode_frame_header(2).to_vec();
        unknown.push(0x1F);
        unknown.push(0);
        assert_eq!(decode_frame(&unknown), Err(ProtocolError::UnknownTag(0x1F)));
        // A zero frame length is rejected before any read.
        let mut zero = encode_frame_header(0).to_vec();
        zero.push(RecordType::LocalCloseEvent.code());
        assert_eq!(
            decode_frame(&zero),
            Err(ProtocolError::InvalidLength {
                expected: 0,
                actual: 0
            })
        );
        // A declared length beyond the remaining bytes is rejected.
        let mut oversized = encode_frame_header(10).to_vec();
        oversized.push(RecordType::SharedControlEvent.code());
        oversized.push(0);
        assert!(matches!(
            decode_frame(&oversized),
            Err(ProtocolError::InvalidLength { .. })
        ));
        // An over-long raw output frame is rejected before reading.
        let mut output = encode_frame_header(MAX_RAW_OUTPUT_FRAME_LEN + 1).to_vec();
        output.push(RecordType::LocalRawOutput.code());
        assert!(matches!(
            decode_frame(&output),
            Err(ProtocolError::InvalidLength { .. })
        ));
    }

    #[test]
    fn reader_walks_header_frames_and_footer() {
        let frame_a = frame_bytes(RecordType::SharedOutputBlock, &[1, 2]);
        let frame_b = frame_bytes(RecordType::LocalRawOutput, &[3, 4, 5]);
        let container = build_container(&[frame_a.clone(), frame_b.clone()]);

        let mut reader = ContainerReader::new(&container).unwrap();
        assert_eq!(reader.position(), CONTAINER_HEADER_LEN);
        assert_eq!(reader.header_bytes(), &container[..CONTAINER_HEADER_LEN]);
        assert!(!reader.has_footer());

        let first = reader.next_frame().unwrap().unwrap();
        assert_eq!(first.record_type, RecordType::SharedOutputBlock);
        assert_eq!(first.payload, &[1, 2]);
        assert_eq!(reader.position(), CONTAINER_HEADER_LEN + first.total_len());

        let second = reader.next_frame().unwrap().unwrap();
        assert_eq!(second.record_type, RecordType::LocalRawOutput);
        assert_eq!(second.payload, &[3, 4, 5]);

        assert!(reader.has_footer());
        assert!(reader.next_frame().unwrap().is_none());

        let decoded = reader.footer().unwrap();
        assert_eq!(
            decoded.footer.manifest.session_id(),
            &SessionId::new([1; DIGEST_LEN])
        );
        assert_eq!(
            decoded.footer.controller_session_signature.signature(),
            &Ed25519Signature::new([6; ED25519_SIGNATURE_LEN])
        );
        assert_eq!(
            decoded.footer.host_session_signature.signature(),
            &Ed25519Signature::new([7; ED25519_SIGNATURE_LEN])
        );
        assert_eq!(decoded.footer.seal.local_event_count(), 12);
        assert_eq!(decoded.footer.ledger_commit.sequence(), 13);
        assert_eq!(
            decoded.final_container_digest.as_bytes(),
            &[0xAB; DIGEST_LEN]
        );
        assert_eq!(reader.position(), container.len());

        // The final digest covers everything before it, so its offset is the
        // container length minus the digest.
        assert_eq!(decoded.ledger_end, container.len() - CONTAINER_DIGEST_LEN);
        assert!(decoded.ledger_end > decoded.seal_end);
        assert!(decoded.seal_end > decoded.sealed_prefix_end);
        assert_eq!(
            decoded.sealed_prefix_end,
            CONTAINER_HEADER_LEN
                + frame_a.len()
                + frame_b.len()
                + FOOTER_MAGIC.len()
                + 2
                + test_manifest().encode_payload().unwrap().as_slice().len()
                + (2 + MANIFEST_SIGNATURE_LEN) * 2
        );
    }

    #[test]
    fn reader_rejects_trailing_bytes_after_the_final_digest() {
        let container = build_container(&[]);
        let mut trailing = container.clone();
        trailing.push(0xAA);
        let mut reader = ContainerReader::new(&trailing).unwrap();
        assert!(reader.next_frame().unwrap().is_none());
        assert_eq!(reader.footer(), Err(ProtocolError::TrailingBytes));

        // A truncated final digest fails with the precise expected length.
        let mut truncated = container.clone();
        truncated.truncate(container.len() - 1);
        let mut reader = ContainerReader::new(&truncated).unwrap();
        assert!(reader.next_frame().unwrap().is_none());
        assert_eq!(
            reader.footer(),
            Err(ProtocolError::InvalidLength {
                expected: CONTAINER_DIGEST_LEN,
                actual: CONTAINER_DIGEST_LEN - 1,
            })
        );
    }

    #[test]
    fn interrupted_prefix_without_footer_is_valid() {
        let frame = frame_bytes(RecordType::LocalRawOutput, &[1, 2, 3]);
        let mut container = test_header().encode().as_slice().to_vec();
        container.extend_from_slice(&frame);
        let mut reader = ContainerReader::new(&container).unwrap();
        assert!(!reader.has_footer());
        let decoded = reader.next_frame().unwrap().unwrap();
        assert_eq!(decoded.record_type, RecordType::LocalRawOutput);
        assert!(reader.next_frame().unwrap().is_none());
        assert_eq!(
            reader.footer(),
            Err(ProtocolError::InvalidField(ProtocolField::Reserved))
        );
    }

    #[test]
    fn truncated_frames_and_headers_fail() {
        // A container cut inside a frame header is a truncated file.
        let frame = frame_bytes(RecordType::LocalKeyAction, &[1]);
        let mut container = test_header().encode().as_slice().to_vec();
        container.extend_from_slice(&frame[..2]);
        let mut reader = ContainerReader::new(&container).unwrap();
        assert!(matches!(
            reader.next_frame(),
            Err(ProtocolError::InvalidLength { .. })
        ));

        // A container cut inside a frame body reports the exact expected
        // length.
        let mut container = test_header().encode().as_slice().to_vec();
        container.extend_from_slice(&frame[..frame.len() - 1]);
        let mut reader = ContainerReader::new(&container).unwrap();
        assert!(matches!(
            reader.next_frame(),
            Err(ProtocolError::InvalidLength { .. })
        ));

        // A container shorter than the header is rejected outright.
        let short = vec![0_u8; CONTAINER_HEADER_LEN - 1];
        assert!(matches!(
            ContainerReader::new(&short),
            Err(ProtocolError::InvalidLength { .. })
        ));
    }

    #[test]
    fn footer_components_are_validated() {
        let prefix = encode_footer_prefix(&test_footer()).unwrap();
        // The exact prefix plus the digest decodes.
        let mut complete = prefix.as_slice().to_vec();
        complete.extend_from_slice(&[0xAB; CONTAINER_DIGEST_LEN]);
        let decoded = decode_footer(&complete).unwrap();
        assert_eq!(decoded.footer.manifest.enterprise_identity(), "alice@wecom");
        // Trailing bytes after the digest are rejected.
        let mut trailing = complete.clone();
        trailing.push(0);
        assert_eq!(decode_footer(&trailing), Err(ProtocolError::TrailingBytes));
        // A truncated component fails before reading.
        for cut in FOOTER_MAGIC.len()..complete.len() - CONTAINER_DIGEST_LEN {
            assert!(
                matches!(
                    decode_footer(&complete[..cut]),
                    Err(ProtocolError::InvalidLength { .. })
                ),
                "footer truncated at {cut}"
            );
        }
        // A footer without the magic is rejected.
        assert_eq!(
            decode_footer(&complete[FOOTER_MAGIC.len()..]),
            Err(ProtocolError::InvalidField(ProtocolField::Reserved))
        );
        // A corrupted manifest payload inside the footer fails the decode:
        // the first manifest bytes are its frozen format version.
        let mut bad_manifest = complete.clone();
        bad_manifest[FOOTER_MAGIC.len() + 2] = 0xFF;
        assert_eq!(
            decode_footer(&bad_manifest),
            Err(ProtocolError::InvalidField(ProtocolField::Reserved))
        );
    }

    /// Property tests are compiled out under Miri (see `wire::enterprise`).
    #[cfg(not(miri))]
    mod property_tests {
        use super::*;
        use crate::wire::audit::{
            AuditNonce, BindingDigest, ChainHead, CommitmentDigest, IdentityFingerprint,
            MAX_ENTERPRISE_IDENTITY_LEN, ManifestEnding, SessionResult, SharedSnapshot,
            StreamSnapshot,
        };
        use proptest::prelude::*;

        fn arbitrary_signature() -> impl Strategy<Value = Ed25519Signature> {
            (any::<[u8; 32]>(), any::<[u8; 32]>()).prop_map(|(hi, lo)| {
                let mut bytes = [0_u8; ED25519_SIGNATURE_LEN];
                bytes[..32].copy_from_slice(&hi);
                bytes[32..].copy_from_slice(&lo);
                Ed25519Signature::new(bytes)
            })
        }

        fn arbitrary_snapshot() -> impl Strategy<Value = SharedSnapshot> {
            (any::<[u64; 4]>(), any::<[u8; 32]>()).prop_map(|(counts, head)| {
                SharedSnapshot::new(
                    counts.map(|count| StreamSnapshot::new(count, ChainHead::new(head))),
                )
            })
        }

        fn arbitrary_hello() -> impl Strategy<Value = AuditHello> {
            (
                prop_oneof![Just(AuditRole::Controller), Just(AuditRole::Host)],
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

        fn arbitrary_ready() -> impl Strategy<Value = AuditReady> {
            (
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                (1_u16..),
                arbitrary_signature(),
            )
                .prop_map(|(session, digest, format, signature)| {
                    AuditReady::new(
                        SessionId::new(session),
                        Digest32::new(digest),
                        format,
                        signature,
                    )
                })
        }

        fn arbitrary_header() -> impl Strategy<Value = AuditContainerHeader> {
            (
                prop_oneof![Just(AuditRole::Controller), Just(AuditRole::Host)],
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                (
                    any::<[u8; 32]>(),
                    any::<[u8; 32]>(),
                    any::<u64>(),
                    any::<[u8; 32]>(),
                    any::<u64>(),
                    prop_oneof![Just(AuthMode::Standard), Just(AuthMode::Enterprise)],
                    any::<[u8; 32]>(),
                    arbitrary_hello(),
                    arbitrary_ready(),
                    arbitrary_signature(),
                ),
            )
                .prop_map(
                    |(
                        role,
                        session,
                        identity,
                        ephemeral,
                        (
                            peer_identity,
                            peer_ephemeral,
                            sequence,
                            root,
                            utc,
                            mode,
                            hello_digest,
                            audit_hello,
                            audit_ready,
                            signature,
                        ),
                    )| {
                        AuditContainerHeader::new(
                            role,
                            SessionId::new(session),
                            Ed25519PublicKey::new(identity),
                            Ed25519PublicKey::new(ephemeral),
                            Ed25519PublicKey::new(peer_identity),
                            Ed25519PublicKey::new(peer_ephemeral),
                            sequence,
                            LedgerRoot::new(root),
                            utc,
                            mode,
                            Digest32::new(hello_digest),
                            audit_hello,
                            audit_ready,
                        )
                        .with_header_signature(signature)
                    },
                )
        }

        fn arbitrary_manifest() -> impl Strategy<Value = JointManifest<'static>> {
            (
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                any::<[u8; 32]>(),
                arbitrary_snapshot(),
                any::<u8>(),
                any::<bool>(),
                any::<u64>(),
                prop::collection::vec(prop::char::range('a', 'z'), 0..=MAX_ENTERPRISE_IDENTITY_LEN),
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
                        enterprise_chars,
                    )| {
                        let enterprise = enterprise_chars.into_iter().collect::<String>();
                        JointManifest::new(
                            AUDIT_FORMAT_VERSION,
                            SessionId::new(session),
                            IdentityFingerprint::new(ctrl_fp),
                            IdentityFingerprint::new(host_fp),
                            Ed25519PublicKey::new(ctrl_key),
                            Ed25519PublicKey::new(host_key),
                            BindingDigest::new(binding),
                            Box::leak(enterprise.into_boxed_str()),
                            Digest32::new(hello_digest),
                            snapshot,
                            ManifestEnding::ShellExit(exit_code),
                            ended_normally,
                            checkpoint_sequence,
                        )
                    },
                )
        }

        fn arbitrary_footer() -> impl Strategy<Value = AuditContainerFooter<'static>> {
            (
                arbitrary_manifest(),
                arbitrary_signature(),
                arbitrary_signature(),
                (
                    any::<[u8; 32]>(),
                    any::<u8>(),
                    any::<[u8; 32]>(),
                    any::<u64>(),
                    arbitrary_snapshot(),
                    any::<[u8; 32]>(),
                    any::<[u8; 32]>(),
                    arbitrary_signature(),
                ),
                (
                    any::<u64>(),
                    any::<[u8; 32]>(),
                    any::<[u8; 32]>(),
                    any::<[u8; 32]>(),
                    any::<[u8; 32]>(),
                    any::<[u8; 32]>(),
                    any::<u8>(),
                    arbitrary_signature(),
                ),
            )
                .prop_map(
                    |(
                        manifest,
                        controller_sig,
                        host_sig,
                        (
                            session,
                            role,
                            root,
                            count,
                            snapshot,
                            manifest_digest,
                            sealed_digest,
                            seal_sig,
                        ),
                        (
                            sequence,
                            prev_root,
                            commit_session,
                            commit_manifest,
                            commit_sealed,
                            peer,
                            result,
                            commit_sig,
                        ),
                    )| {
                        AuditContainerFooter {
                            manifest,
                            controller_session_signature: ManifestSignature::new(controller_sig),
                            host_session_signature: ManifestSignature::new(host_sig),
                            seal: LocalRecordSeal::new(
                                SessionId::new(session),
                                AuditRole::from_byte(role).unwrap_or(AuditRole::Controller),
                                ChainHead::new(root),
                                count,
                                snapshot.roots(),
                                Digest32::new(manifest_digest),
                                Digest32::new(sealed_digest),
                                seal_sig,
                            ),
                            ledger_commit: LedgerCommit::new(
                                sequence,
                                LedgerRoot::new(prev_root),
                                SessionId::new(commit_session),
                                Digest32::new(commit_manifest),
                                Digest32::new(commit_sealed),
                                IdentityFingerprint::new(peer),
                                SessionResult::from_byte(result).unwrap_or(SessionResult::Normal),
                                commit_sig,
                            ),
                        }
                    },
                )
        }

        fn arbitrary_record_type() -> impl Strategy<Value = RecordType> {
            const RECORD_TYPES: [RecordType; 18] = [
                RecordType::SharedInputCommitment,
                RecordType::SharedOutputBlock,
                RecordType::SharedControlEvent,
                RecordType::SharedFileTransferEvent,
                RecordType::LocalRawOutput,
                RecordType::LocalDisplayBytes,
                RecordType::LocalInputCommitment,
                RecordType::LocalSendOutcome,
                RecordType::LocalPtyWriteOutcome,
                RecordType::LocalDisplayWriteOutcome,
                RecordType::LocalResizeEvent,
                RecordType::LocalLifecycleEvent,
                RecordType::LocalKeyAction,
                RecordType::LocalFileTransferEvent,
                RecordType::LocalConnectionState,
                RecordType::LocalAuditError,
                RecordType::CheckpointEvidence,
                RecordType::LocalCloseEvent,
            ];
            prop::sample::select(&RECORD_TYPES)
        }

        fn arbitrary_frames() -> impl Strategy<Value = Vec<Vec<u8>>> {
            prop::collection::vec(
                (
                    arbitrary_record_type(),
                    prop::collection::vec(any::<u8>(), 0..=100_usize),
                ),
                0..=8,
            )
            .prop_map(|frames| {
                frames
                    .into_iter()
                    .map(|(record_type, payload)| frame_bytes(record_type, &payload))
                    .collect()
            })
        }

        proptest! {
            #![proptest_config(ProptestConfig {
                failure_persistence: None,
                ..ProptestConfig::default()
            })]

            #[test]
            fn container_headers_round_trip_arbitrary_instances(header in arbitrary_header()) {
                let encoded = header.encode();
                prop_assert_eq!(encoded.as_slice().len(), CONTAINER_HEADER_LEN);
                prop_assert_eq!(AuditContainerHeader::decode(encoded.as_slice()), Ok(header));
                let input = header.signing_input();
                prop_assert_eq!(input.as_slice().len(), CONTAINER_HEADER_SIGNING_LEN);
                prop_assert_eq!(
                    &input.as_slice()[..CONTAINER_HEADER_DOMAIN.len()],
                    CONTAINER_HEADER_DOMAIN
                );
            }

            #[test]
            fn containers_round_trip_arbitrary_headers_frames_and_footers(
                header in arbitrary_header(),
                frames in arbitrary_frames(),
                footer in arbitrary_footer(),
            ) {
                let mut container = header.encode().as_slice().to_vec();
                for frame in &frames {
                    container.extend_from_slice(frame);
                }
                let prefix = encode_footer_prefix(&footer).unwrap();
                container.extend_from_slice(prefix.as_slice());
                container.extend_from_slice(&[0xCD; CONTAINER_DIGEST_LEN]);

                let mut reader = ContainerReader::new(&container).unwrap();
                prop_assert_eq!(reader.header(), &header);
                let mut walked = Vec::new();
                while let Some(frame) = reader.next_frame().unwrap() {
                    walked.push((frame.record_type, frame.payload.to_vec()));
                }
                prop_assert_eq!(walked.len(), frames.len());
                for (decoded, expected) in walked.iter().zip(frames.iter()) {
                    prop_assert_eq!(
                        decode_frame(expected).unwrap().payload,
                        decoded.1.as_slice()
                    );
                }
                let decoded = reader.footer().unwrap();
                prop_assert_eq!(
                    decoded.footer,
                    footer,
                    "the footer round-trips through its own encoding"
                );
                prop_assert_eq!(decoded.final_container_digest.as_bytes(), &[0xCD; DIGEST_LEN]);
                prop_assert_eq!(decoded.ledger_end, container.len() - CONTAINER_DIGEST_LEN);
                prop_assert_eq!(reader.position(), container.len());
            }

            #[test]
            fn footer_prefixes_fit_their_bound(footer in arbitrary_footer()) {
                let prefix = encode_footer_prefix(&footer).unwrap();
                prop_assert!(prefix.as_slice().len() <= MAX_FOOTER_PREFIX_LEN);
                prop_assert_eq!(&prefix.as_slice()[..4], &FOOTER_MAGIC[..]);
            }
        }
    }
}
